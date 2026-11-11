import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadSettings, ownerResolvers } from '../src/settings.js';

test('public configuration requires explicit identity, protected keys and encrypted database', async () => {
  const identity = {PUBLIC_ORIGIN:'https://monitor.example.com',FEISHU_APP_ID:'cli_example_app',OWNER_OPEN_ID:'ou_example_owner',FEISHU_TENANT_KEY:'example-tenant'};
  for (const field of Object.keys(identity)) {
    const env: NodeJS.ProcessEnv = {...identity}; delete env[field];
    assert.throws(()=>loadSettings(env),new RegExp(`Missing ${field}`));
  }
  assert.throws(()=>ownerResolvers('','',''));
  const dir = mkdtempSync(join(tmpdir(),'monitor-config-test-'));
  try {
    const {privateKey} = generateKeyPairSync('rsa',{modulusLength:2048});
    const jwk = {...privateKey.export({format:'jwk'}),kid:'test-key',alg:'RS256'};
    const fixtureFile = (name: string, value: string) => {
      const path = join(dir,name); writeFileSync(path,value,{mode:0o600}); return path;
    };
    const env: NodeJS.ProcessEnv = {...identity,
      OAUTH_JWKS_FILE:fixtureFile('jwks.json',JSON.stringify({keys:[jwk]})),
      COOKIE_KEYS_FILE:fixtureFile('cookie-keys.json',JSON.stringify(['fixture-cookie-value'.repeat(3)])),
      INTERNAL_KEY_FILE:fixtureFile('internal-key','fixture-internal-value'.repeat(3)),
      AUTH_DB_KEY_FILE:fixtureFile('auth-db-key',Buffer.alloc(32,11).toString('base64')),
      FEISHU_APP_SECRET_FILE:fixtureFile('app-secret','isolated-test-fixture'),
      AUTH_DATABASE_PATH:join(dir,'auth.sqlite'),
    };
    const settings = loadSettings(env);
    assert.equal(settings.config.publicOrigin,identity.PUBLIC_ORIGIN);
    assert.equal(settings.authHost,'127.0.0.1'); assert.equal(settings.authPort,8560); assert.equal(settings.trustProxy,'loopback');
    assert.equal(settings.config.dcrRegistrationUntil,undefined);
    const registrationUntil = '2030-01-02T03:04:05Z';
    assert.equal(loadSettings({...env,DCR_REGISTRATION_UNTIL:registrationUntil}).config.dcrRegistrationUntil,Date.parse(registrationUntil));
    for (const invalid of ['tomorrow','2030-02-30T03:04:05Z','2030-01-02T03:04:05+00:00']) assert.throws(()=>loadSettings({...env,DCR_REGISTRATION_UNTIL:invalid}),/UTC ISO timestamp/);
    const owner = await settings.resolveIdentity({appId:identity.FEISHU_APP_ID,tenantKey:identity.FEISHU_TENANT_KEY,openId:identity.OWNER_OPEN_ID});
    assert.equal(owner.bindingId,'monitor-owner'); assert.equal(owner.displayName,'Owner');
    const container = loadSettings({...env,AUTH_HOST:'0.0.0.0',AUTH_PORT:'8562',AUTH_TRUST_PROXY:'1'});
    assert.equal(container.authHost,'0.0.0.0'); assert.equal(container.authPort,8562); assert.equal(container.trustProxy,1);
    for (const field of ['INTERNAL_KEY_FILE','AUTH_DB_KEY_FILE']) {
      const missing = {...env,INTERNAL_KEY:'legacy-env-value-does-not-enable-a-fallback'}; delete missing[field];
      assert.throws(()=>loadSettings(missing),new RegExp(`Missing ${field}`));
    }
    assert.throws(()=>loadSettings({...env,AUTH_PORT:'0'}),/Invalid AUTH_PORT/);
    chmodSync(env.AUTH_DB_KEY_FILE!,0o644);
    assert.throws(()=>loadSettings(env),/Protected file required: AUTH_DB_KEY_FILE/);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});
