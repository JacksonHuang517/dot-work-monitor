import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import express, { type Request, type Response } from 'express';
import Provider, { errors, type Configuration } from 'oidc-provider';
import type { AuthConfig, AuthPrincipal, FeishuIdentity } from '../contracts.js';
import { AuthStore } from './sqlite-adapter.js';
import { allowedRedirect, registrationMetadata } from './registration.js';
import { exchangeFeishuIdentity, FEISHU_AUTHORIZE } from './feishu.js';
import { FeishuAuthenticationError, oauthTokenFailureReason, type AuthDiagnostic } from './diagnostics.js';
import { renderAuthMessage, renderConsentPage } from './pages.js';

type Options = {
  config: AuthConfig;
  resolveIdentity?: (identity: FeishuIdentity) => Promise<AuthPrincipal>;
  validateIdentity: (bindingId: string) => Promise<AuthPrincipal>;
  /** Transport injection for isolated tests; all production checks remain enabled. */
  fetch?: typeof fetch;
  /** Receives only fixed diagnostic enums, correlation ID, and numeric status/code. */
  onAuthDiagnostic?: (event: AuthDiagnostic) => void;
};
const random = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
const equal = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
function cookie(req: Request, name: string) {
  const values = (req.headers.cookie ?? '').split(';').map(v => v.trim()).filter(v => v.startsWith(`${name}=`));
  return values.length === 1 ? values[0].slice(name.length + 1) : '';
}
function principal(value: AuthPrincipal, expected?: string) {
  if (!value || !value.bindingId || (expected && value.bindingId !== expected) || !['feishu:read','mail:read'].some(scope => value.scopes.includes(scope))) {
    throw new Error('Identity is unavailable');
  }
  return value;
}
function bridgeCode(error: unknown): unknown {
  return error && typeof error === 'object' && 'code' in error ? error.code : undefined;
}
function retryableBridgeFailure(error: unknown) {
  const code = bridgeCode(error);
  return (code === 'SOURCE_UNAVAILABLE' || code === 'RATE_LIMITED')
    && error !== null && typeof error === 'object' && 'retryable' in error && error.retryable === true;
}

export function createAuthorizationServer(options: Options) {
  const { config, resolveIdentity, validateIdentity } = options;
  const origin = new URL(config.publicOrigin);
  const loopback = ['localhost','127.0.0.1','[::1]'].includes(origin.hostname);
  if (origin.origin !== config.publicOrigin || origin.username || origin.password
      || (origin.protocol !== 'https:' && !(config.allowInsecureLoopback && loopback && origin.protocol === 'http:'))
      || !config.cookieKeys.length || config.cookieKeys.some(k => k.length < 32)) {
    throw new Error('Invalid authorization configuration');
  }
  if(!config.feishuAppId||!config.feishuAppSecret||!config.allowedTenantKeys?.length||!resolveIdentity)
    throw new Error('Invalid Feishu authorization configuration');
  const accessTtl = config.accessTokenTtlSeconds ?? 600;
  const refreshTtl = config.refreshTokenTtlSeconds ?? 604800;
  if (![accessTtl, refreshTtl].every(n => Number.isInteger(n) && n > 0) || accessTtl > 600 || refreshTtl > 604800) {
    throw new Error('Invalid authorization token lifetime');
  }
  const basePath = '/dot-feishu';
  const issuer = `${config.publicOrigin}${basePath}/oauth`, resource = `${config.publicOrigin}${basePath}/mcp`;
  const callbackSources = ['https://chatgpt.com', ...config.oauthRedirectUris.map(uri => {
    const url = new URL(uri);
    // Native loopback callbacks may choose an ephemeral port under RFC 8252.
    if (url.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname)) return `${url.protocol}//${url.hostname}:*`;
    return url.origin === 'null' ? url.protocol : url.origin;
  })];
  const secure = origin.protocol === 'https:';
  const stateCookie = secure ? '__Host-dot_feishu_login' : 'dot_feishu_login';
  const cookieOptions = { httpOnly: true, secure, sameSite: 'lax' as const, path: '/' };
  const store = new AuthStore(config.databasePath,config.databaseKey);
  store.bindIssuer(issuer);
  const configuration: Configuration = {
    adapter: store.adapter, jwks: config.jwks,
    clients: config.oauthClientId && config.oauthRedirectUris.length ? [{ client_id: config.oauthClientId, client_name: 'DotSignal for ChatGPT', application_type: 'native',
      token_endpoint_auth_method: 'none', grant_types: ['authorization_code','refresh_token'],
      response_types: ['code'], redirect_uris: config.oauthRedirectUris }] : [],
    scopes: ['openid','offline_access'],
    claims: { openid: ['sub'] },
    cookies: { keys: config.cookieKeys, short: cookieOptions, long: cookieOptions,
      names: { session: '_dot_feishu_session', interaction: '_dot_feishu_interaction', resume: '_dot_feishu_resume' } },
    pkce: { required: () => true },
    features: { devInteractions: { enabled: false }, userinfo: { enabled: false },
      revocation: { enabled: true, allowedPolicy: (_ctx, client, token) => token.clientId === client.clientId }, registration: { enabled: false },
      resourceIndicators: { enabled: true, defaultResource: () => resource, useGrantedResource: () => true,
        getResourceServerInfo: (_ctx, indicator) => {
          if (indicator !== resource) throw new errors.InvalidTarget();
          return { scope: 'feishu:read mail:read', audience: resource, accessTokenTTL: accessTtl, accessTokenFormat: 'opaque' };
        } } },
    routes: { authorization: '/authorize', token: '/token', revocation: '/revoke', jwks: '/jwks' },
    ttl: { AccessToken: accessTtl, IdToken: accessTtl, RefreshToken: refreshTtl, AuthorizationCode: 60, Interaction: 600, Grant: refreshTtl, Session: refreshTtl },
    // Native MCP clients are OAuth clients and need not request OIDC offline_access.
    // The explicit client consent grants this narrowly scoped refresh capability.
    issueRefreshToken: (_ctx, _client, source) => source.scopes.has('feishu:read') || source.scopes.has('mail:read'),
    rotateRefreshToken: true, revokeGrantPolicy: () => true,
    expiresWithSession: () => false,
    findAccount: async (_ctx, id) => {
      try {
        const current = principal(await validateIdentity(id), id);
        return { accountId: current.bindingId, claims: async () => ({ sub: current.bindingId }) };
      } catch (error) {
        if (retryableBridgeFailure(error)) {
          const unavailable = new errors.OIDCProviderError(503,'temporarily_unavailable');
          unavailable.expose = true;
          unavailable.error_description = 'Identity service temporarily unavailable';
          throw unavailable;
        }
        return undefined;
      }
    },
    interactions: { url: (_ctx, interaction) => `${basePath}/auth/interaction/${interaction.uid}` },
    renderError: async (ctx) => { ctx.type = 'html'; ctx.body = renderAuthMessage({ title: '授权未完成', message: '请返回 Codex，重新发起连接。' }); },
  };
  let provider: Provider;
  try { provider = new Provider(issuer, configuration); } catch (error) { store.close(); throw error; }
  // TLS terminates only at the separately configured trusted application proxy.
  provider.proxy = secure;
  // Suppress Koa's default error handler, which may serialize upstream error context.
  provider.addListener('server_error', () => {});
  // Koa's standard error event is not represented by oidc-provider's narrow typings.
  (provider as unknown as import('node:events').EventEmitter).on('error', () => {});
  const router = express.Router();
  const metadata: Record<string, unknown> = {
    issuer, authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`, revocation_endpoint: `${issuer}/revoke`, jwks_uri: `${issuer}/jwks`,
    response_types_supported: ['code'], grant_types_supported: ['authorization_code','refresh_token'],
    token_endpoint_auth_methods_supported: ['none'], revocation_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'], scopes_supported: ['openid','offline_access','feishu:read','mail:read'],
    authorization_response_iss_parameter_supported: true,
  };
  router.use((req, res, next) => {
    if (req.path.startsWith(`${basePath}/auth/`) || req.path.startsWith(`${basePath}/oauth`) || req.path.startsWith('/.well-known/oauth-authorization-server')) {
      res.set({ 'Cache-Control': 'no-store', 'Pragma': 'no-cache', 'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' ${callbackSources.join(' ')}; frame-ancestors 'none'; base-uri 'none'` });
    }
    next();
  });
  router.get(['/.well-known/oauth-authorization-server/dot-feishu/oauth'], (_req,res) => { res.json(metadata); });
  // Client objects are validated by oidc-provider, but registration is deliberately
  // narrower than its general purpose DCR feature (no metadata URLs or secrets).
  const approvedClient = async (id: unknown) => {
    if (typeof id !== 'string') return undefined;
    const client = await provider.Client.find(id);
    if (!client || client.tokenEndpointAuthMethod !== 'none') return undefined;
    if (id === config.oauthClientId && config.oauthRedirectUris.length) return client;
    return id.startsWith('dot_') && client.redirectUris?.every(allowedRedirect) ? client : undefined;
  };
  let registrationWindow = 0, registrationAttempts = 0;
  const registrationOpen = () => !!config.dcrRegistrationUntil && Number.isFinite(config.dcrRegistrationUntil) && Date.now() < config.dcrRegistrationUntil;
  router.post('/dot-feishu/oauth/register', (req,res,next) => {
    if (!registrationOpen()) {
      res.status(403).json({error:'registration_closed'}); return;
    }
    const minute = Math.floor(Date.now()/60000);
    if (minute !== registrationWindow) { registrationWindow = minute; registrationAttempts = 0; }
    if (++registrationAttempts > 20) { res.set('Retry-After','60').status(429).json({error:'temporarily_unavailable'}); return; }
    next();
  }, express.json({limit:'4kb',strict:true}), async (req,res) => {
    try {
      const metadata = registrationMetadata(req.body);
      await provider.Client.validate(metadata);
      if (!registrationOpen()) { res.status(403).json({error:'registration_closed'}); return; }
      if (!store.registerClient(metadata.client_id,metadata)) { res.set('Retry-After','60').status(429).json({error:'temporarily_unavailable'}); return; }
      res.status(201).json(metadata);
    } catch { res.status(400).json({error:'invalid_client_metadata'}); }
  });
  const reportFailure = (stage: AuthDiagnostic['stage'], reason: AuthDiagnostic['reason'], extra: Pick<AuthDiagnostic,'httpStatus'|'upstreamCode'|'oauthScope'> = {}) => {
    const event: AuthDiagnostic={event:'dot_feishu_auth_failure',requestId:randomBytes(12).toString('hex'),stage,reason,
      ...(Number.isSafeInteger(extra.httpStatus)?{httpStatus:extra.httpStatus}:{}),
      ...(Number.isSafeInteger(extra.upstreamCode)?{upstreamCode:extra.upstreamCode}:{}),
      ...(extra.oauthScope?{oauthScope:extra.oauthScope}:{})};
    try {
      if(options.onAuthDiagnostic)options.onAuthDiagnostic(event);
      else process.stderr.write(JSON.stringify(event)+'\n');
    } catch { /* Observability must not change authentication decisions. */ }
    return event.requestId;
  };
  provider.on('grant.error', (ctx, error) => {
    const scope: unknown=ctx.oidc.params?.scope;
    const parts=typeof scope==='string'?scope.split(' '):[];
    const oauthScope: AuthDiagnostic['oauthScope']=scope===undefined?'omitted':scope===''?'empty':
      scope==='feishu:read'?'feishu-only':parts.includes('offline_access')?'with-offline-access':parts.includes('openid')?'with-openid':'other';
    reportFailure('oauth_token', oauthTokenFailureReason(error),{oauthScope});
  });
  const fail = (res: Response, stage: AuthDiagnostic['stage']='interaction', reason: AuthDiagnostic['reason']='unexpected_error', extra: Pick<AuthDiagnostic,'httpStatus'|'upstreamCode'>={}) => {
    const requestId=reportFailure(stage,reason,extra);
    res.set('X-Request-Id',requestId).status(400).type('html').send(renderAuthMessage({
      title: reason === 'authorization_denied' ? '已拒绝授权' : '授权未完成',
      message: '授权失败或已过期，请重新连接。', reference: requestId,
    }));
  };
  const unavailable = (res: Response) => { res.set('Retry-After','30').status(503).type('html').send(renderAuthMessage({ title: '服务暂时不可用', message: '身份验证服务暂时不可用，请稍后重新连接。' })); };

  router.get('/dot-feishu/auth/interaction/:uid', async (req,res) => {
    try {
      const details = await provider.interactionDetails(req,res);
      if (details.uid !== req.params.uid || !(await approvedClient(details.params.client_id))) return fail(res);
      if (details.prompt.name === 'login') {
        const state = random(), verifier = random(), browser = random();
        await store.adapter('FeishuState').upsert(hash(state), { uid: details.uid, state: { verifier, browser: hash(browser) } }, 300);
        res.cookie(stateCookie, browser, { ...cookieOptions, maxAge: 300000 });
        const destination = new URL(FEISHU_AUTHORIZE);
        destination.search = new URLSearchParams({ client_id: config.feishuAppId!, response_type: 'code',
          redirect_uri: `${config.publicOrigin}/dot-feishu/auth/feishu/callback`,
          state, code_challenge: hash(verifier), code_challenge_method: 'S256' }).toString();
        return res.redirect(303,destination.href);
      }
      if (details.prompt.name !== 'consent' || !details.session?.accountId) return fail(res);
      const current = principal(await validateIdentity(details.session.accountId), details.session.accountId);
      const csrf = random();
      await store.adapter('Consent').upsert(details.uid, { state: { csrf: hash(csrf) } }, 600);
      // Keep cross-origin referrals suppressed while preserving the browser's
      // Origin on this same-origin form POST (no-referrer can turn it into null).
      return res.set('Referrer-Policy','same-origin').type('html').send(renderConsentPage({ displayName: current.displayName, uid: details.uid, csrf, scopes:String(details.params.scope ?? '').split(' ').filter(scope => current.scopes.includes(scope)) }));
    } catch { return fail(res); }
  });
  router.get('/dot-feishu/auth/feishu/callback', async (req,res) => {
    let stage:AuthDiagnostic['stage']='callback_state';
    try {
      if (typeof req.query.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(req.query.state)) return fail(res,stage,'invalid_state');
      const saved = await store.take('FeishuState',hash(req.query.state));
      const browser = cookie(req,stateCookie);
      res.clearCookie(stateCookie,cookieOptions);
      if(!saved?.state)return fail(res,stage,'state_missing');
      if(!browser)return fail(res,stage,'browser_cookie_missing');
      if(!equal(hash(browser),String(saved.state.browser)))return fail(res,stage,'browser_cookie_mismatch');
      stage='interaction_lookup';
      const details = await provider.interactionDetails(req,res);
      if(details.uid!==saved.uid||details.prompt.name!=='login'||!(await approvedClient(details.params.client_id)))return fail(res,stage,'interaction_mismatch');
      if(req.query.error)return fail(res,stage,'authorization_denied');
      if(typeof req.query.code!=='string'||!req.query.code||req.query.code.length>4096)return fail(res,stage,'code_missing');
      const identity = await exchangeFeishuIdentity(config,req.query.code,String(saved.state.verifier),options.fetch);
      stage='identity_resolve';
      const current = principal(await resolveIdentity!(identity));
      stage='interaction_finish';
      await provider.interactionFinished(req,res,{ login: { accountId: current.bindingId, amr: ['feishu'] } },{ mergeWithLastSubmission: false });
    } catch (error) {
      if(error instanceof FeishuAuthenticationError)return fail(res,error.stage,error.reason,error);
      if(retryableBridgeFailure(error)) {reportFailure(stage,'source_unavailable');return unavailable(res);}
      return fail(res,stage);
    }
  });
  router.post('/dot-feishu/auth/interaction/:uid/confirm', express.urlencoded({ extended:false, limit:'4kb' }), async (req,res) => {
    try {
      if (req.headers.origin !== config.publicOrigin) return fail(res,'consent',
        !req.headers.origin ? 'origin_missing' : req.headers.origin === 'null' ? 'origin_null' : 'origin_mismatch');
      if (typeof req.body.csrf !== 'string') return fail(res,'consent','csrf_missing');
      const details = await provider.interactionDetails(req,res);
      if (details.uid !== req.params.uid || details.prompt.name !== 'consent' || !details.session?.accountId) return fail(res,'consent','interaction_mismatch');
      const saved = await store.take('Consent', details.uid);
      if (!saved?.state || !equal(hash(req.body.csrf),String(saved.state.csrf))) return fail(res,'consent','csrf_invalid');
      if (req.body.decision !== 'allow') {
        await provider.interactionFinished(req,res,{ error:'access_denied' },{ mergeWithLastSubmission:false }); return;
      }
      const current = principal(await validateIdentity(details.session.accountId),details.session.accountId);
      const grant = details.grantId ? await provider.Grant.find(details.grantId) : new provider.Grant({ accountId:current.bindingId, clientId:String(details.params.client_id) });
      if (!grant || grant.clientId !== details.params.client_id || !(await approvedClient(details.params.client_id))) return fail(res,'consent','grant_missing');
      const requested = String(details.params.scope ?? '').split(' ');
      grant.addOIDCScope(requested.filter(s => s === 'openid' || s === 'offline_access').join(' '));
      const allowedRequested = requested.filter(scope => ['feishu:read','mail:read'].includes(scope) && current.scopes.includes(scope));
      if (allowedRequested.length) grant.addResourceScope(resource,allowedRequested.join(' '));
      await provider.interactionFinished(req,res,{ consent:{ grantId:await grant.save() } },{ mergeWithLastSubmission:true });
    } catch { return fail(res,'consent'); }
  });
  // OIDC requires explicit consent for offline_access. Native MCP clients may
  // request that scope without a prompt; add the consent step, never a grant.
  router.get('/dot-feishu/oauth/authorize', (req,res,next) => {
    const url=new URL(req.originalUrl,config.publicOrigin);
    const scopes=url.searchParams.getAll('scope');
    if(scopes.length===1 && scopes[0].split(' ').includes('offline_access') && !url.searchParams.has('prompt')) {
      url.searchParams.set('prompt','consent');
      res.redirect(303,url.pathname+url.search);return;
    }
    next();
  });
  router.use('/dot-feishu/oauth', provider.callback());
  router.use((error: unknown, _req: Request, res: Response, _next: express.NextFunction) => {
    // Do not let Express serialize body parser errors or their request context.
    void error;
    if (!res.headersSent) fail(res);
  });
  return {
    router, metadata,
    verifyAccessToken: async (token: string): Promise<AuthPrincipal|null> => {
      try {
        if (!token || token.length > 2048) return null;
        const access = await provider.AccessToken.find(token);
        if (!access || access.isExpired || !(await approvedClient(access.clientId)) || !access.accountId || !access.grantId
            || !['feishu:read','mail:read'].some(scope => access.scopes.has(scope)) || !(typeof access.aud === 'string' ? access.aud === resource : access.aud?.includes(resource))) return null;
        const grant = await provider.Grant.find(access.grantId);
        if (!grant || grant.accountId !== access.accountId || grant.clientId !== access.clientId) return null;
        const current = principal(await validateIdentity(access.accountId),access.accountId);
        const grantedScopes = current.scopes.filter(scope => ['feishu:read','mail:read'].includes(scope) && access.scopes.has(scope));
        return grantedScopes.length ? {...current,scopes:grantedScopes} : null;
      } catch (error) {
        if (retryableBridgeFailure(error)) throw error;
        return null;
      }
    },
    close: async () => { store.close(); },
  };
}
