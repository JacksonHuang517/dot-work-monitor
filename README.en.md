# DotSignal for ChatGPT

[![CI](https://github.com/JacksonHuang517/dotsignal/actions/workflows/ci.yml/badge.svg)](https://github.com/JacksonHuang517/dotsignal/actions/workflows/ci.yml) · [MIT License](LICENSE)

[中文](README.md) · [Deployment guide (Chinese)](docs/deployment.md) · [Troubleshooting (Chinese)](docs/troubleshooting.md) · [Security](SECURITY.md)

**Let ChatGPT keep an eye on your work.**

DotSignal connects Feishu messages, tasks and calendars, plus optional NetEase enterprise-mail headers, to cloud events for ChatGPT Dot. Subscribed events help it remind you about replies, decisions and follow-ups. Collection runs on your self-hosted server, independently of your Mac. This is a single-owner MCP service.

Real cloud collection has been validated. A fresh deployment still needs its own credentials, permissions, OAuth connection, subscriptions and end-to-end notification test. A running service or successful tool call does not establish event delivery. Account and workspace access to custom MCP / Dot events depends on the platform; this project cannot enable it for every account. See the [official quickstart](https://developers.openai.com/plugins/build/app-quickstart).

## Coverage

| Source | Default coverage |
| --- | --- |
| Feishu messages | Authorized global time search, with at least 15 minutes of overlap; search indexing delays can cause gaps |
| Feishu tasks | Incomplete tasks owned by the user; changes, deadlines within 24 hours and daily overdue reminders |
| Feishu calendar | Primary calendar, next 48 hours; changes and meetings starting within 30 minutes |
| NetEase enterprise mail | `INBOX` only, approximately 48–72 hours, maximum 500 headers per snapshot |
| Health | Separate source-failure events for Feishu and mail |

Polling waits 300 seconds **after each attempt finishes**. The first successful snapshot establishes a baseline without flooding historical additions; current task/meeting reminders can still fire. Feishu recovery backfill is capped at 24 hours. There is no complete protocol replay guarantee.

Mail access uses TLS IMAP, a read-only mailbox selection and header-only fetches. It never fetches bodies or attachments, sends messages, deletes mail or marks it read. This adapter targets NetEase enterprise mail; other providers and account policies require independent validation. There is no native Gmail integration.

## Deploy

You need Docker Compose, a public domain with working HTTPS, a Feishu custom application and an eligible ChatGPT account. Caddy publishes ports 80/443. Node and Python share one `monitor` container: Node port 8560 is Docker-internal, and Python port 8561 binds to loopback only.

1. Run the local interactive setup from the repository root:

   ```bash
   git clone https://github.com/JacksonHuang517/dotsignal.git
   cd dotsignal
   python3 -m venv .venv
   .venv/bin/python -m pip install -r requirements.txt
   .venv/bin/python scripts/setup.py
   ```

   Enter your origin, for example `https://monitor.example.com`, Feishu app ID, tenant key and owner Open ID. Mail is optional. App secret and mail password use hidden terminal input. Generated `.env` and `.secrets/` files are ignored by Git. Never submit credentials through chat or Issues.

2. Register this Feishu web-login callback:

   ```text
   https://monitor.example.com/dot-feishu/auth/feishu/callback
   ```

3. Start the stack, then authorize the read collector:

   ```bash
   docker compose up -d --build
   ./scripts/lark.sh auth login --scope 'offline_access search:message im:message:readonly im:message.group_msg:get_as_user im:message.p2p_msg:get_as_user im:chat:read calendar:calendar:read calendar:calendar.event:read task:task:read' --no-wait --json
   ```

   Complete the returned browser flow and CLI device-code completion. Keep device codes and tokens private. See the [full deployment guide](docs/deployment.md).

4. Add a custom MCP server in ChatGPT with OAuth / dynamic client registration:

   ```text
   https://monitor.example.com/dot-feishu/mcp
   ```

   Log in as the configured owner. For both sources, request **both** `feishu:read` and `mail:read`. Refreshing an old token does not add mail scope. Feishu CLI read authorization and MCP owner login are independent.

5. As the user, refresh/rescan the plugin detail page. Dot cannot perform that UI control itself. Ask Dot to create **separate subscriptions**:

   - `feishu.attention`: kinds `message`, `task`, `calendar`, `health`.
   - `mail.attention`: kinds `mail`, `health` (only with mail enabled).

   Specify when you want to be notified and treat source text as untrusted data. The [official MCP Events guide](https://developers.openai.com/plugins/build/mcp-events) describes the host subscription lifecycle.

## Verify

Use `feishu_status` / `feishu_recent` and, when enabled, `mail_status` / `mail_recent`. Check recent successful collection, discovered events, stored subscriptions and successful delivery. Trigger a new matching item **after** the baseline. Final acceptance requires a real callback HTTP 200 (or another successful 2xx) **and a visible Dot notification**. Local tests do not replace this check. Public `/dot-feishu/health` only proves that the front service responds.

Source content, headers, subscriptions and the outbox are persisted. Subscribed events send relevant data to ChatGPT. Encrypted storage protects data at rest when keys are separately protected; it cannot protect against a compromised host with access to those keys. Back up state and the same keys together. Read [SECURITY.md](SECURITY.md) before operating an instance.

Python 3.11+ and Node.js 22 are used. See [CONTRIBUTING.md](CONTRIBUTING.md) for local checks. [MIT license](LICENSE).

## Client registration window

Setup opens OAuth DCR for 24 hours. Existing authorized clients continue to sign in and refresh after it closes. To admit a new client, run `.venv/bin/python scripts/setup.py --open-registration-hours 24` and `docker compose restart monitor`. Use `0` hours to close registration immediately. Unapproved client registrations expire after one hour and are reclaimed.
