import { readFileSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { canonicalOrigin } from './config.js';
import type { AuthConfig, AuthPrincipal, FeishuIdentity } from './contracts.js';

export const OWNER_BINDING = 'monitor-owner';
export function required(env: NodeJS.ProcessEnv, name: string) {
  const value = env[name]?.trim();
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}
function secretFile(env: NodeJS.ProcessEnv, name: string) {
  const path = required(env,name), stat = statSync(path);
  if (!isAbsolute(path) || !stat.isFile() || (stat.mode & 0o077)) throw new Error(`Protected file required: ${name}`);
  return readFileSync(path,'utf8').trim();
}
export function loadSettings(env: NodeJS.ProcessEnv = process.env) {
  const publicOrigin = canonicalOrigin(required(env,'PUBLIC_ORIGIN'));
  const appId = required(env,'FEISHU_APP_ID');
  const ownerOpenId = required(env,'OWNER_OPEN_ID');
  const tenantKey = required(env,'FEISHU_TENANT_KEY');
  const redirects: unknown = JSON.parse(env.OAUTH_REDIRECT_URIS || '[]');
  if (!Array.isArray(redirects) || redirects.some(uri => {
    if (typeof uri !== 'string') return true;
    try { const u = new URL(uri); return !!u.username || !!u.password || !!u.hash || (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['127.0.0.1','localhost','[::1]'].includes(u.hostname))); }
    catch { return true; }
  })) throw new Error('Explicit HTTPS or loopback OAuth callback URLs required');
  const cookieKeys: unknown = JSON.parse(secretFile(env,'COOKIE_KEYS_FILE'));
  if (!Array.isArray(cookieKeys) || !cookieKeys.length || cookieKeys.some(k => typeof k !== 'string' || Buffer.byteLength(k) < 32)) throw new Error('Cookie keys must contain at least 32 bytes');
  const jwks = JSON.parse(secretFile(env,'OAUTH_JWKS_FILE')) as AuthConfig['jwks'];
  if (!Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.some(k => k.kty !== 'RSA' || !k.d || !k.kid || (k.alg && k.alg !== 'RS256'))) throw new Error('Private RS256 OAuth JWKS required');
  const internalKey = secretFile(env,'INTERNAL_KEY_FILE');
  if (Buffer.byteLength(internalKey) < 32) throw new Error('Shared internal key must contain at least 32 bytes');
  const databasePath = required(env,'AUTH_DATABASE_PATH');
  if (!isAbsolute(databasePath)) throw new Error('Absolute AUTH_DATABASE_PATH required');
  const databaseKeyText = secretFile(env,'AUTH_DB_KEY_FILE');
  const databaseKey = Buffer.from(databaseKeyText,'base64');
  if (databaseKey.length !== 32 || databaseKey.toString('base64') !== databaseKeyText) throw new Error('AUTH_DB_KEY_FILE must contain base64 of 32 bytes');
  const registrationUntil = env.DCR_REGISTRATION_UNTIL?.trim();
  const dcrRegistrationUntil = registrationUntil ? Date.parse(registrationUntil) : undefined;
  if (registrationUntil && (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(registrationUntil)
    || !Number.isFinite(dcrRegistrationUntil)
    || new Date(dcrRegistrationUntil!).toISOString().slice(0,19) !== registrationUntil.slice(0,19))) throw new Error('DCR_REGISTRATION_UNTIL must be a UTC ISO timestamp');
  const config: AuthConfig = { publicOrigin, feishuAppId:appId,
    feishuAppSecret:secretFile(env,'FEISHU_APP_SECRET_FILE'), allowedTenantKeys:[tenantKey],
    oauthClientId:env.OAUTH_CLIENT_ID || '', oauthRedirectUris:redirects as string[],
    databasePath, databaseKey, dcrRegistrationUntil, cookieKeys:cookieKeys as string[], jwks };
  const authHost = env.AUTH_HOST || '127.0.0.1';
  const authPort = Number(env.AUTH_PORT || '8560');
  if (!Number.isInteger(authPort) || authPort < 1 || authPort > 65535) throw new Error('Invalid AUTH_PORT');
  const proxy = env.AUTH_TRUST_PROXY || 'loopback';
  const trustProxy = /^\d+$/.test(proxy) ? Number(proxy) : proxy;
  return { config, internalKey, authHost, authPort, trustProxy, ...ownerResolvers(tenantKey,appId,ownerOpenId,env.OWNER_DISPLAY_NAME?.trim() || 'Owner') };
}
export function ownerResolvers(tenantKey: string, appId: string, ownerOpenId: string, displayName = 'Owner') {
  if (![tenantKey,appId,ownerOpenId].every(value => typeof value === 'string' && value.trim())) throw new Error('Explicit owner identity required');
  const principal = (): AuthPrincipal => ({ bindingId:OWNER_BINDING, displayName, scopes:['feishu:read','mail:read'] });
  const resolveIdentity = async (identity: FeishuIdentity) => {
    if (identity.appId !== appId || identity.tenantKey !== tenantKey || identity.openId !== ownerOpenId) throw new Error('Owner identity required');
    return principal();
  };
  const validateIdentity = async (bindingId: string) => {
    if (bindingId !== OWNER_BINDING) throw new Error('Owner identity required');
    return principal();
  };
  return { resolveIdentity, validateIdentity };
}
