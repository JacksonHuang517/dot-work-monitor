import express from 'express';
import { request } from 'node:http';
import { createAuthorizationServer } from './auth/index.js';
import { loadSettings } from './settings.js';

export function createApp(settings: ReturnType<typeof loadSettings>, transport?: typeof fetch, backendPort = 8561) {
const auth = createAuthorizationServer({...settings,fetch:transport});
const app = express();
app.disable('x-powered-by');
app.set('trust proxy',settings.trustProxy);
// Body parsing belongs to oidc-provider; preserve raw MCP streams.
app.use(auth.router);
const resourceMetadata = `${settings.config.publicOrigin}/.well-known/oauth-protected-resource/dot-feishu/mcp`;
app.get('/.well-known/oauth-protected-resource/dot-feishu/mcp', (_req,res) => {
  res.set('Cache-Control','no-store').json({ resource:`${settings.config.publicOrigin}/dot-feishu/mcp`,
    authorization_servers:[auth.metadata.issuer], bearer_methods_supported:['header'], scopes_supported:['feishu:read','mail:read'] });
});
app.get('/dot-feishu/health', (_req,res) => { res.json({ok:true}); });
const stripHeaders = new Set(['authorization','proxy-authorization','x-connector-key','x-connector-scopes','cookie','connection','keep-alive','proxy-authenticate','te','trailer','transfer-encoding','upgrade','host']);
app.all('/dot-feishu/mcp', async (req,res) => {
  try {
    const header = req.headers.authorization;
    const token = typeof header === 'string' ? /^Bearer ([A-Za-z0-9._~-]+)$/i.exec(header)?.[1] : undefined;
    const principal = token ? await auth.verifyAccessToken(token) : null;
    if (!principal) {
      res.set('WWW-Authenticate',`Bearer resource_metadata="${resourceMetadata}"`).status(401).json({error:'unauthorized'}); return;
    }
    const connectionTokens = new Set((req.headers.connection || '').split(',').map(s => s.trim().toLowerCase()));
    const headers = Object.fromEntries(Object.entries(req.headers).filter(([key]) => !stripHeaders.has(key) && !connectionTokens.has(key) && !key.startsWith('x-forwarded-')));
    headers['x-connector-key'] = settings.internalKey;
    headers['x-connector-scopes'] = JSON.stringify(principal.scopes);
    const upstream = request({hostname:'127.0.0.1',port:backendPort,path:req.originalUrl,method:req.method,headers}, response => {
      res.status(response.statusCode || 502);
      for (const [key,value] of Object.entries(response.headers)) if (value !== undefined && !stripHeaders.has(key) && key !== 'set-cookie') res.setHeader(key,value);
      response.on('error', () => res.destroy());
      response.pipe(res);
    });
    upstream.on('error', () => { if (!res.headersSent) res.status(502).json({error:'upstream_unavailable'}); else res.destroy(); });
    req.on('aborted', () => upstream.destroy());
    res.on('close', () => { if (!res.writableFinished) upstream.destroy(); });
    req.pipe(upstream);
  } catch {
    if (!res.headersSent) res.status(503).json({error:'temporarily_unavailable'});
  }
});
app.use((_req,res) => { res.status(404).json({error:'not_found'}); });

return { app, auth };
}
