import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { createApp } from '../src/app.js';
import { ownerResolvers } from '../src/settings.js';
const APP_ID = 'cli_example_monitor_app';
const OWNER_OPEN_ID = 'ou_example_owner';
import type { AuthConfig } from '../src/contracts.js';

for (const requestedScope of ['feishu:read','mail:read']) test(`${requestedScope}: explicit consent, trusted proxy scopes, refresh isolation and replay revocation`, async t => {
  const initialTime = Date.now();
  t.mock.timers.enable({apis:['Date'],now:initialTime});
  const dir = mkdtempSync(join(tmpdir(),'dot-auth-flow-'));
  const {privateKey} = generateKeyPairSync('rsa',{modulusLength:2048});
  const key = {...privateKey.export({format:'jwk'}),kid:'flow-key',alg:'RS256',use:'sig'};
  const config: AuthConfig = {dcrRegistrationUntil:Date.now()+3600000,publicOrigin:'http://127.0.0.1',allowInsecureLoopback:true,feishuAppId:APP_ID,
    feishuAppSecret:'isolated-unit-test-value',allowedTenantKeys:['test-tenant'],oauthClientId:'',oauthRedirectUris:[],
    databasePath:join(dir,'auth.sqlite'),databaseKey:Buffer.alloc(32,42),cookieKeys:['x'.repeat(48)],jwks:{keys:[key]}};
  let upstreamCalls=0;
  const transport: typeof fetch = async (input,init) => {
    upstreamCalls++;
    if (String(input).includes('/oauth/token')) {
      const body = JSON.parse(String(init?.body));
      assert.equal(body.redirect_uri,'http://127.0.0.1/dot-feishu/auth/feishu/callback');
      assert.equal(body.code_verifier.length,43);
      return Response.json({code:0,access_token:'isolated-upstream-value'});
    }
    return Response.json({code:0,data:{open_id:OWNER_OPEN_ID,tenant_key:'test-tenant'}});
  };
  const backend = createServer((req,res) => {
    res.setHeader('content-type','application/json');
    res.end(JSON.stringify({scopes:req.headers['x-connector-scopes'],internalKeyVerified:req.headers['x-connector-key'] === 'k'.repeat(48)}));
  });
  backend.listen(0,'127.0.0.1'); await once(backend,'listening');
  const backendAddress = backend.address(); assert.ok(backendAddress && typeof backendAddress !== 'string');
  const {app,auth} = createApp({config,authHost:'127.0.0.1',authPort:8560,trustProxy:'loopback',internalKey:'k'.repeat(48),...ownerResolvers('test-tenant',APP_ID,OWNER_OPEN_ID)},transport,backendAddress.port);
  const server = app.listen(0,'127.0.0.1'); await once(server,'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}`;
  const jar = new Map<string,string>();
  async function browser(path: string,init: RequestInit = {}) {
    const url = new URL(path,base);
    const response = await fetch(base+url.pathname+url.search,{...init,redirect:'manual',headers:{cookie:[...jar].map(([k,v])=>`${k}=${v}`).join('; '),...init.headers}});
    for (const value of response.headers.getSetCookie()) {
      const pair=value.split(';')[0], separator=pair.indexOf('='); jar.set(pair.slice(0,separator),pair.slice(separator+1));
    }
    return response;
  }
  try {
    const reg = await browser('/dot-feishu/oauth/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:['https://chatgpt.com/connector/oauth/flow'],token_endpoint_auth_method:'none'})});
    assert.equal(reg.status,201); const client = await reg.json();
    const verifier='v'.repeat(43);
    const tokenRequest = async (body: Record<string,string>) => browser('/dot-feishu/oauth/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body).toString()});
    async function authorize(scope: string, forceConsent = false) {
      const params = new URLSearchParams({client_id:client.client_id,redirect_uri:client.redirect_uris[0],response_type:'code',scope,resource:'http://127.0.0.1/dot-feishu/mcp',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
      if (forceConsent) params.set('prompt','consent');
      let response = await browser('/dot-feishu/oauth/authorize?'+params);
      let authorizationCode='', sawConsent=false;
      for (let i=0;i<12;i++) {
        const location = response.headers.get('location');
        if (location?.startsWith('https://chatgpt.com/')) { authorizationCode=new URL(location).searchParams.get('code') || ''; break; }
        if (location?.startsWith('https://accounts.feishu.cn/')) {
          const state = new URL(location).searchParams.get('state')!;
          response = await browser('/dot-feishu/auth/feishu/callback?'+new URLSearchParams({state,code:'isolated-code'}));
        } else if (location) response = await browser(location);
        else {
          assert.equal(response.status,200); const html=await response.text();
          const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1];
          const action = /action="([^"]+)"/.exec(html)?.[1];
          assert.ok(csrf && action,'explicit consent form must be shown'); sawConsent=true;
          assert.ok(html.includes(`<strong>${scope}</strong>`));
          if(scope === 'mail:read') { assert.ok(html.includes('邮件头')); assert.ok(html.includes('新邮件事件订阅')); assert.ok(!html.includes('<strong>feishu:read</strong>')); }
          else assert.ok(!html.includes('<strong>mail:read</strong>'));
          response = await browser(action,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',origin:config.publicOrigin},body:new URLSearchParams({csrf,decision:'allow'}).toString()});
        }
      }
      assert.ok(authorizationCode,'authorization code returned only after owner login and consent'); assert.ok(sawConsent);
      const issued = await tokenRequest({grant_type:'authorization_code',client_id:client.client_id,redirect_uri:client.redirect_uris[0],code:authorizationCode,code_verifier:verifier});
      assert.equal(issued.status,200); return issued.json();
    }
    const tokens = await authorize(requestedScope);
    assert.equal(upstreamCalls,2);
    assert.deepEqual((await auth.verifyAccessToken(tokens.access_token))?.scopes,[requestedScope]);
    const forged = await browser('/dot-feishu/mcp',{headers:{authorization:`Bearer ${tokens.access_token}`,'x-connector-scopes':JSON.stringify(['feishu:read','mail:read']),'x-connector-key':'forged'}});
    assert.equal(forged.status,200); const forwarded=await forged.json();
    assert.equal(forwarded.scopes,JSON.stringify([requestedScope])); assert.equal(forwarded.internalKeyVerified,true);
    if (requestedScope === 'feishu:read') {
      const mailTokens = await authorize('mail:read');
      assert.deepEqual((await auth.verifyAccessToken(mailTokens.access_token))?.scopes,['mail:read']);
      assert.deepEqual((await auth.verifyAccessToken(tokens.access_token))?.scopes,['feishu:read'],'existing access grant must not grow after a separate mail consent');
    }
    // Move past both the temporary-client TTL and registration window.
    t.mock.timers.setTime(initialTime+3601000);
    const closed = await browser('/dot-feishu/oauth/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({redirect_uris:client.redirect_uris})});
    assert.equal(closed.status,403); assert.equal((await closed.json()).error,'registration_closed');
    const existingClientLogin = await authorize(requestedScope,true);
    assert.deepEqual((await auth.verifyAccessToken(existingClientLogin.access_token))?.scopes,[requestedScope],'approved client must keep login after registration window and TTL');
    const otherScope = requestedScope === 'feishu:read' ? 'mail:read' : 'feishu:read';
    const escalation = await tokenRequest({grant_type:'refresh_token',client_id:client.client_id,refresh_token:tokens.refresh_token,scope:otherScope});
    assert.equal(escalation.status,400,'refresh must not add another scope');
    assert.equal((await escalation.json()).error,'invalid_scope');
    assert.ok(tokens.refresh_token); assert.equal(tokens.access_token.split('.').length,1);
    const rotated = await tokenRequest({grant_type:'refresh_token',client_id:client.client_id,refresh_token:tokens.refresh_token});
    assert.equal(rotated.status,200); const current=await rotated.json();
    assert.notEqual(current.refresh_token,tokens.refresh_token);
    assert.deepEqual((await auth.verifyAccessToken(current.access_token))?.scopes,[requestedScope]);
    const replay = await tokenRequest({grant_type:'refresh_token',client_id:client.client_id,refresh_token:tokens.refresh_token});
    assert.equal(replay.status,400);
    assert.equal(await auth.verifyAccessToken(current.access_token),null);
  } finally { await new Promise<void>(resolve=>server.close(()=>resolve())); await new Promise<void>(resolve=>backend.close(()=>resolve())); await auth.close(); rmSync(dir,{recursive:true,force:true}); }
});
