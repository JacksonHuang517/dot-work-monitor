import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { once } from 'node:events';
import { createApp } from '../src/app.js';
import { ownerResolvers } from '../src/settings.js';
const APP_ID = 'cli_example_monitor_app';
const OWNER_OPEN_ID = 'ou_example_owner';
import { allowedRedirect, registrationMetadata } from '../src/auth/registration.js';
import { AuthStore } from '../src/auth/sqlite-adapter.js';
import type { AuthConfig } from '../src/contracts.js';

test('registration only permits approved public ChatGPT clients', () => {
  for (const uri of ['https://chatgpt.com/connector_platform_oauth_redirect','https://chatgpt.com/connector/oauth/Ab_12-x']) assert.ok(allowedRedirect(uri));
  for (const uri of ['http://chatgpt.com/connector/oauth/a','https://chatgpt.com.evil/connector/oauth/a','https://chatgpt.com/connector/oauth/a?x=1','https://chatgpt.com/connector/oauth/a#x','https://chatgpt.com:443/connector/oauth/a','https://user@chatgpt.com/connector/oauth/a','https://chatgpt.com/connector/oauth/%61']) assert.ok(!allowedRedirect(uri));
  const valid = {redirect_uris:['https://chatgpt.com/connector/oauth/test'],token_endpoint_auth_method:'none'};
  const metadata = registrationMetadata(valid);
  assert.match(metadata.client_id,/^dot_/); assert.equal(metadata.token_endpoint_auth_method,'none');
  assert.throws(() => registrationMetadata({...valid,token_endpoint_auth_method:'client_secret_post'}));
  assert.throws(() => registrationMetadata({...valid,grant_types:['client_credentials']}));
  assert.throws(() => registrationMetadata({...valid,response_types:['token']}));
  assert.throws(() => registrationMetadata({...valid,client_secret:'forbidden'}));
});

test('owner identity requires the exact app, tenant and open ID', async () => {
  const owner = ownerResolvers('test-tenant',APP_ID,OWNER_OPEN_ID);
  assert.deepEqual((await owner.resolveIdentity({appId:APP_ID,tenantKey:'test-tenant',openId:OWNER_OPEN_ID})).scopes,['feishu:read','mail:read']);
  for (const identity of [
    {appId:'other',tenantKey:'test-tenant',openId:OWNER_OPEN_ID},
    {appId:APP_ID,tenantKey:'other',openId:OWNER_OPEN_ID},
    {appId:APP_ID,tenantKey:'test-tenant',openId:'other'},
  ]) await assert.rejects(owner.resolveIdentity(identity));
  await assert.rejects(owner.validateIdentity('other'));
});

test('registration cap is atomic, persistent, and issuer-specific', async () => {
  const dir = mkdtempSync(join(tmpdir(),'dot-auth-store-'));
  try {
    const store = new AuthStore(join(dir,'auth.sqlite'),Buffer.alloc(32,39)); store.bindIssuer('https://test.example/dot-feishu/oauth');
    for (let i=0;i<10;i++) assert.equal(store.registerClient(`test-${i}`,{client_id:`test-${i}`}),true);
    assert.equal(store.registerClient('overflow',{}),false); store.close();
    const reopened = new AuthStore(join(dir,'auth.sqlite'),Buffer.alloc(32,39));
    assert.equal(reopened.registerClient('restart-overflow',{}),false);
    assert.throws(() => reopened.bindIssuer('https://other.example/oauth'));
    assert.ok(await reopened.adapter('Client').find('test-0')); reopened.close();
  } finally { rmSync(dir,{recursive:true,force:true}); }
});

test('unused registration exhaustion expires while owner-approved clients survive restart', async t => {
  const initialTime = Date.now();
  t.mock.timers.enable({apis:['Date'],now:initialTime});
  const dir = mkdtempSync(join(tmpdir(),'monitor-registration-expiry-'));
  const path = join(dir,'auth.sqlite'), key = Buffer.alloc(32,37);
  try {
    let store = new AuthStore(path,key);
    assert.equal(store.registerClient('approved-client',{client_id:'approved-client'}),true);
    await store.adapter('Grant').upsert('owner-grant',{clientId:'approved-client',accountId:'monitor-owner'},604800);
    for (let i=0;i<99;i++) {
      t.mock.timers.setTime(initialTime+Math.floor((i+1)/10)*61000);
      assert.equal(store.registerClient(`unused-${i}`,{client_id:`unused-${i}`}),true);
    }
    t.mock.timers.setTime(initialTime+610000);
    assert.equal(store.registerClient('cap-overflow',{}),false);
    t.mock.timers.setTime(initialTime+5000000);
    assert.equal(store.registerClient('recovered-client',{client_id:'recovered-client'}),true);
    assert.equal(await store.adapter('Client').find('unused-98'),undefined);
    assert.ok(await store.adapter('Client').find('approved-client'));
    store.close(); store = new AuthStore(path,key);
    assert.ok(await store.adapter('Client').find('approved-client'));
    assert.ok(await store.adapter('Grant').find('owner-grant'));
    store.close();
  } finally { rmSync(dir,{recursive:true,force:true}); }
});

test('encrypted SQLite hides credentials in payloads and every lookup index, surviving restart', async () => {
  const dir = mkdtempSync(join(tmpdir(),'dot-auth-encrypted-'));
  const path = join(dir,'auth.sqlite'), key = Buffer.alloc(32,77);
  const token='raw-access-token-must-never-appear', grant='raw-grant-id-must-never-appear';
  const uid='raw-interaction-uid-must-never-appear', code='raw-user-code-must-never-appear';
  try {
    let store = new AuthStore(path,key); store.bindIssuer('https://test.example/dot-feishu/oauth');
    await store.adapter('Grant').upsert(grant,{accountId:'private-owner-value'},600);
    await store.adapter('AccessToken').upsert(token,{grantId:grant,uid,userCode:code,accountId:'private-owner-value'},600);
    assert.equal((await store.adapter('AccessToken').findByUid(uid))?.grantId,grant);
    assert.equal((await store.adapter('AccessToken').findByUserCode(code))?.uid,uid);
    assert.equal(store.registerClient('raw-client-id',{client_id:'raw-client-id'}),true);
    store.close();
    const bytes=readFileSync(path);
    for (const text of [token,grant,uid,code,'private-owner-value','raw-client-id']) assert.equal(bytes.includes(Buffer.from(text)),false,text);
    assert.throws(() => new AuthStore(path,Buffer.alloc(32,78)));
    assert.throws(() => new AuthStore(path,undefined as unknown as Buffer));
    store = new AuthStore(path,key);
    assert.equal((await store.adapter('AccessToken').find(token))?.grantId,grant);
    assert.ok(await store.adapter('Client').find('raw-client-id'));
    await store.adapter('AccessToken').consume(token);
    assert.ok((await store.adapter('AccessToken').find(token))?.consumed);
    await store.adapter('Grant').revokeByGrantId(grant);
    assert.equal(await store.adapter('AccessToken').find(token),undefined);
    await assert.rejects(store.adapter('AccessToken').upsert(token,{grantId:grant},600));
    store.close();
    for (const text of [token,grant,uid,code]) assert.equal(readFileSync(path).includes(Buffer.from(text)),false);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});

test('path discovery, unauthenticated challenge, DCR persistence and mandatory PKCE', async () => {
  const dir = mkdtempSync(join(tmpdir(),'dot-auth-http-'));
  const {privateKey} = generateKeyPairSync('rsa',{modulusLength:2048});
  const key = {...privateKey.export({format:'jwk'}),kid:'test-key',alg:'RS256',use:'sig'};
  const config: AuthConfig = {dcrRegistrationUntil:Date.now()+3600000,publicOrigin:'http://127.0.0.1',allowInsecureLoopback:true,feishuAppId:APP_ID,
    feishuAppSecret:'isolated-unit-test-value',allowedTenantKeys:['test-tenant'],oauthClientId:'',oauthRedirectUris:[],
    databasePath:join(dir,'auth.sqlite'),databaseKey:Buffer.alloc(32,41),cookieKeys:['x'.repeat(48)],jwks:{keys:[key]}};
  const {app,auth} = createApp({config,authHost:'127.0.0.1',authPort:8560,trustProxy:'loopback',internalKey:'k'.repeat(48),...ownerResolvers('test-tenant',APP_ID,OWNER_OPEN_ID)});
  const server = app.listen(0,'127.0.0.1'); await once(server,'listening');
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}`;
  try {
    const metadata = await (await fetch(base+'/.well-known/oauth-authorization-server/dot-feishu/oauth')).json();
    assert.equal(metadata.issuer,'http://127.0.0.1/dot-feishu/oauth');
    assert.equal(metadata.registration_endpoint,'http://127.0.0.1/dot-feishu/oauth/register');
    assert.equal((await fetch(base+'/.well-known/oauth-authorization-server')).status,404);
    const resource = await (await fetch(base+'/.well-known/oauth-protected-resource/dot-feishu/mcp')).json();
    assert.deepEqual(resource.scopes_supported,['feishu:read','mail:read']);
    const challenge = await fetch(base+'/dot-feishu/mcp',{headers:{'X-Connector-Key':'attacker'}});
    assert.equal(challenge.status,401); assert.match(challenge.headers.get('www-authenticate')!,/oauth-protected-resource\/dot-feishu\/mcp/);
    const register = async (body: object) => fetch(base+'/dot-feishu/oauth/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    const registrationUntil = config.dcrRegistrationUntil;
    for (const closedUntil of [undefined,Date.now()-1]) {
      config.dcrRegistrationUntil = closedUntil;
      const closed = await register({redirect_uris:['https://chatgpt.com/connector/oauth/test']});
      assert.equal(closed.status,403); assert.deepEqual(await closed.json(),{error:'registration_closed'});
    }
    config.dcrRegistrationUntil = registrationUntil;
    assert.equal((await register({redirect_uris:['https://evil.example/callback']})).status,400);
    const registered = await register({redirect_uris:['https://chatgpt.com/connector/oauth/test'],token_endpoint_auth_method:'none'});
    assert.equal(registered.status,201); const client = await registered.json();
    const query = new URLSearchParams({client_id:client.client_id,redirect_uri:client.redirect_uris[0],response_type:'code',scope:'feishu:read',resource:'http://127.0.0.1/dot-feishu/mcp'});
    const missingPkce = await fetch(base+'/dot-feishu/oauth/authorize?'+query,{redirect:'manual'});
    const missingLocation = missingPkce.headers.get('location') || '';
    assert.ok(missingPkce.status >= 400 || missingLocation.includes('error=invalid_request'));
    query.set('code_challenge',createHash('sha256').update('v'.repeat(43)).digest('base64url')); query.set('code_challenge_method','S256');
    const start = await fetch(base+'/dot-feishu/oauth/authorize?'+query,{redirect:'manual'});
    assert.equal(start.status,303); assert.match(start.headers.get('location')!,/\/dot-feishu\/auth\/interaction\//);
    const cookie = start.headers.getSetCookie().map(v=>v.split(';')[0]).join('; ');
    const login = await fetch(base+start.headers.get('location'),{redirect:'manual',headers:{cookie}});
    assert.equal(login.status,303); const upstream = new URL(login.headers.get('location')!);
    assert.equal(upstream.origin,'https://accounts.feishu.cn');
    assert.equal(upstream.searchParams.get('redirect_uri'),'http://127.0.0.1/dot-feishu/auth/feishu/callback');
    assert.equal(upstream.searchParams.get('code_challenge_method'),'S256');
  } finally { await new Promise<void>(resolve=>server.close(()=>resolve())); await auth.close(); rmSync(dir,{recursive:true,force:true}); }
});
