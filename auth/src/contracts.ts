import type { JSONWebKeySet } from 'jose';
export type FeishuIdentity = { appId: string; tenantKey: string; openId: string };
export type AuthPrincipal = { bindingId: string; displayName: string; scopes: string[] };
export type AuthConfig = { publicOrigin: string; feishuAppId: string; feishuAppSecret: string; allowedTenantKeys: string[]; oauthClientId: string; oauthRedirectUris: string[]; databasePath: string; databaseKey: Buffer; cookieKeys: string[]; jwks: JSONWebKeySet; dcrRegistrationUntil?: number; allowInsecureLoopback?: boolean; accessTokenTtlSeconds?: number; refreshTokenTtlSeconds?: number };
