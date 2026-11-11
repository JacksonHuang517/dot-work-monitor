import { randomBytes } from 'node:crypto';

export function allowedRedirect(value: unknown): value is string {
  return typeof value === 'string' && (value === 'https://chatgpt.com/connector_platform_oauth_redirect'
    || /^https:\/\/chatgpt\.com\/connector\/oauth\/[A-Za-z0-9_-]+$/.test(value));
}
export function registrationMetadata(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid client metadata');
  const input = value as Record<string,unknown>;
  if (!Array.isArray(input.redirect_uris) || !input.redirect_uris.length || input.redirect_uris.length > 5
    || !input.redirect_uris.every(allowedRedirect)
    || (input.token_endpoint_auth_method !== undefined && input.token_endpoint_auth_method !== 'none')
    || input.client_secret !== undefined || input.client_id !== undefined
    || (input.application_type !== undefined && input.application_type !== 'web')
    || (input.response_types !== undefined && (!Array.isArray(input.response_types) || input.response_types.length !== 1 || input.response_types[0] !== 'code'))
    || (input.grant_types !== undefined && (!Array.isArray(input.grant_types) || !input.grant_types.includes('authorization_code') || input.grant_types.some(t => t !== 'authorization_code' && t !== 'refresh_token')))
    || (input.scope !== undefined && (typeof input.scope !== 'string' || input.scope.split(' ').some(s => !['feishu:read','mail:read','openid','offline_access'].includes(s))))) throw new Error('Invalid client metadata');
  return { client_id:`dot_${randomBytes(24).toString('base64url')}`, client_id_issued_at:Math.floor(Date.now()/1000),
    client_name:typeof input.client_name === 'string' ? input.client_name.slice(0,100) : 'ChatGPT',
    application_type:'web' as const, token_endpoint_auth_method:'none' as const,
    grant_types:['authorization_code','refresh_token'], response_types:['code' as const],
    redirect_uris:[...new Set(input.redirect_uris as string[])] };
}
