/** Only allowlisted fields may enter auth diagnostics. Never attach raw errors. */
export type AuthDiagnostic = {
  event: 'dot_feishu_auth_failure';
  requestId: string;
  stage: 'interaction'|'consent'|'callback_state'|'oauth_token'|'interaction_lookup'|'feishu_token'|'feishu_userinfo'|'identity_resolve'|'interaction_finish';
  reason: 'unexpected_error'|'invalid_state'|'state_missing'|'browser_cookie_missing'|'browser_cookie_mismatch'|'interaction_mismatch'|'authorization_denied'|'code_missing'|'source_unavailable'
    |'upstream_unavailable'|'upstream_http_error'|'upstream_response_invalid'|'upstream_response_too_large'|'token_rejected'|'userinfo_rejected'|'identity_fields_missing'|'tenant_not_allowed'
    |'origin_missing'|'origin_null'|'origin_mismatch'|'csrf_missing'|'csrf_invalid'|'grant_missing'
    |'refresh_not_found'|'refresh_expired'|'refresh_reused'|'client_mismatch'|'account_unavailable'|'invalid_scope'|'invalid_target'|'invalid_request';
  httpStatus?: number;
  upstreamCode?: number;
  oauthScope?: 'omitted'|'empty'|'feishu-only'|'with-openid'|'with-offline-access'|'other';
};

/** Classify provider failures without logging request bodies or raw error text. */
export function oauthTokenFailureReason(error: unknown): AuthDiagnostic['reason'] {
  if (!error || typeof error !== 'object') return 'unexpected_error';
  const value = error as { error?: unknown; error_detail?: unknown };
  const detail = value.error_detail;
  if (detail === 'refresh token not found') return 'refresh_not_found';
  if (detail === 'refresh token is expired') return 'refresh_expired';
  if (detail === 'refresh token already used') return 'refresh_reused';
  if (detail === 'client mismatch' || value.error === 'invalid_client') return 'client_mismatch';
  if (detail === 'refresh token invalid (referenced account not found)') return 'account_unavailable';
  if (typeof detail === 'string' && detail.startsWith('grant ')) return 'grant_missing';
  if (value.error === 'invalid_scope') return 'invalid_scope';
  if (value.error === 'invalid_target') return 'invalid_target';
  if (value.error === 'invalid_request') return 'invalid_request';
  if (value.error === 'invalid_grant') return 'token_rejected';
  if (value.error === 'temporarily_unavailable') return 'source_unavailable';
  return 'unexpected_error';
}

export class FeishuAuthenticationError extends Error {
  constructor(
    readonly stage: 'feishu_token'|'feishu_userinfo',
    readonly reason: AuthDiagnostic['reason'],
    readonly httpStatus?: number,
    readonly upstreamCode?: number,
  ) {
    super('Feishu authentication failed');
    this.name = 'FeishuAuthenticationError';
  }
}
