# Third-party software

The project uses third-party software under its own license. MIT licensing of
this repository does not replace those licenses. No dependency source, private
configuration or production database is included in the repository.

| Component | Use | License / upstream |
| --- | --- | --- |
| oidc-provider | OAuth/OIDC authorization server | MIT — https://github.com/panva/node-oidc-provider |
| jose | JWK generation and verification | MIT — https://github.com/panva/jose |
| Express | HTTP front proxy | MIT — https://github.com/expressjs/express |
| aiohttp | Internal MCP HTTP server and signed webhook transport | Apache-2.0 and MIT — https://github.com/aio-libs/aiohttp |
| cryptography | Encrypted state and setup key generation | Apache-2.0 or BSD-3-Clause — https://github.com/pyca/cryptography |
| Lark CLI | Read-only Feishu user API access | MIT — https://github.com/larksuite/cli |
| Caddy | TLS reverse proxy | Apache-2.0 — https://github.com/caddyserver/caddy |

Node.js, Python, container base images and transitive dependencies retain their
respective notices. Inspect `auth/package-lock.json`, installed dependency
LICENSE files and the upstream distributions for the complete dependency tree.
