import type { AuthConfig, FeishuIdentity } from '../contracts.js';
import { FeishuAuthenticationError } from './diagnostics.js';

export const FEISHU_AUTHORIZE = 'https://accounts.feishu.cn/open-apis/authen/v1/authorize';
// Explicit compatibility choice: v3 currently rejects valid S256 exchanges (20049).
// Keep PKCE intact; never retry a one-use authorization code on another endpoint.
export const FEISHU_TOKEN = 'https://open.feishu.cn/open-apis/authen/v2/oauth/token';
export const FEISHU_USERINFO = 'https://open.feishu.cn/open-apis/authen/v1/user_info';

async function readJson(fetcher: typeof fetch, url: string, init: RequestInit, stage: 'feishu_token'|'feishu_userinfo'): Promise<Record<string, unknown>> {
  let response: Response;
  try { response = await fetcher(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(10000) }); }
  catch { throw new FeishuAuthenticationError(stage,'upstream_unavailable'); }
  // Bound untrusted upstream data. Never retain or log the upstream body.
  const reader = response.body?.getReader();
  if (!reader) throw new FeishuAuthenticationError(stage,'upstream_response_invalid',response.status);
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 65536) throw new FeishuAuthenticationError(stage,'upstream_response_too_large',response.status);
      chunks.push(value);
    }
  } catch(error) {
    if(error instanceof FeishuAuthenticationError)throw error;
    throw new FeishuAuthenticationError(stage,'upstream_unavailable',response.status);
  } finally { await reader.cancel().catch(() => {}); }
  let data: unknown;
  try {data=JSON.parse(Buffer.concat(chunks).toString('utf8'));}
  catch {throw new FeishuAuthenticationError(stage,response.ok?'upstream_response_invalid':'upstream_http_error',response.status);}
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new FeishuAuthenticationError(stage,'upstream_response_invalid',response.status);
  if(!response.ok)throw new FeishuAuthenticationError(stage,'upstream_http_error',response.status,numericCode(data));
  return data as Record<string, unknown>;
}
function numericCode(data: object): number|undefined {
  const code='code' in data?data.code:undefined;
  return typeof code==='number'&&Number.isSafeInteger(code)?code:undefined;
}

/** Fixed official v2 JSON endpoint; fetch injection changes transport only, never validation. */
export async function exchangeFeishuIdentity(config: AuthConfig, code: string, verifier: string, fetcher = fetch): Promise<FeishuIdentity> {
  if(!config.feishuAppId||!config.feishuAppSecret||!config.allowedTenantKeys?.length)
    throw new FeishuAuthenticationError('feishu_token','unexpected_error');
  const token = await readJson(fetcher, FEISHU_TOKEN, {
    method: 'POST', headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: config.feishuAppId,
      client_secret: config.feishuAppSecret, code, code_verifier: verifier,
      redirect_uri: `${config.publicOrigin}/dot-feishu/auth/feishu/callback` }),
  },'feishu_token');
  if (token.code !== 0 || typeof token.access_token !== 'string' || !token.access_token || token.error) {
    throw new FeishuAuthenticationError('feishu_token','token_rejected',undefined,numericCode(token));
  }
  const info = await readJson(fetcher, FEISHU_USERINFO, {
    headers: { authorization: `Bearer ${token.access_token}` },
  },'feishu_userinfo');
  const user = info.data as Record<string, unknown> | undefined;
  if(info.code!==0)throw new FeishuAuthenticationError('feishu_userinfo','userinfo_rejected',undefined,numericCode(info));
  if (!user || typeof user.open_id !== 'string' || !user.open_id || typeof user.tenant_key !== 'string')
    throw new FeishuAuthenticationError('feishu_userinfo','identity_fields_missing');
  if(!config.allowedTenantKeys.includes(user.tenant_key))throw new FeishuAuthenticationError('feishu_userinfo','tenant_not_allowed');
  return { appId: config.feishuAppId, openId: user.open_id, tenantKey: user.tenant_key };
}
