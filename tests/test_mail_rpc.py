import asyncio, base64, json, tempfile, time, unittest
from cryptography.fernet import Fernet
from aiohttp.test_utils import TestClient, TestServer
from dot_feishu.store import Store
from dot_feishu.engine import Engine
from dot_feishu.server import Service, create_app, RpcError
from test_engine import Source, Delivery, row


class MailTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        key = Fernet.generate_key()
        self.fs = Store(self.tmp.name + "/f", key)
        self.ms = Store(self.tmp.name + "/m", key)
        self.mail_source = Source()
        self.delivery = Delivery()
        self.feishu = Engine(self.fs, Source(), self.delivery)
        self.mail = Engine(
            self.ms,
            self.mail_source,
            self.delivery,
            event_name="mail.attention",
            kinds=["mail"],
        )
        self.service = Service(self.feishu, "k" * 32, self.mail)
        self.client = TestClient(
            TestServer(create_app(self.feishu, "k" * 32, False, self.mail))
        )
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.fs.close()
        self.ms.close()
        self.tmp.cleanup()

    async def call(self, method, p, scopes):
        r = await self.client.post(
            "/dot-feishu/mcp",
            headers={
                "X-Connector-Key": "k" * 32,
                "X-Connector-Scopes": json.dumps(scopes),
            },
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": p},
        )
        return r, await r.json()

    async def test_metadata_exposes_separate_event_and_permission(self):
        x = await self.service.rpc("events/list", {})
        self.assertEqual(
            [e["name"] for e in x["events"]], ["feishu.attention", "mail.attention"]
        )
        x = await self.service.rpc("tools/list", {})
        self.assertEqual(len(x["tools"]), 4)
        m = next(t for t in x["tools"] if t["name"] == "mail_recent")
        self.assertIn("mail:read", m["securitySchemes"][0]["scopes"])

    async def test_feishu_token_cannot_read_mail(self):
        r, x = await self.call("tools/call", {"name": "mail_status"}, ["feishu:read"])
        self.assertTrue(x["result"]["isError"])
        self.assertIn("mail:read", str(x["result"]["_meta"]))

    async def test_mail_token_cannot_read_feishu(self):
        r, x = await self.call("tools/call", {"name": "feishu_recent"}, ["mail:read"])
        self.assertTrue(x["result"]["isError"])

    async def test_new_mail_subscription_requires_explicit_scope(self):
        r, x = await self.call(
            "events/subscribe", {"name": "mail.attention"}, ["feishu:read"]
        )
        self.assertEqual(r.status, 401)
        self.assertIn("mail:read", r.headers["WWW-Authenticate"])
        self.assertEqual(self.mail.active(), [])

    async def test_new_mail_event_and_old_feishu_state_isolated(self):
        now = time.time()
        self.mail_source.rows = [row(kind="mail")]
        await self.mail.poll(now)
        p = {
            "name": "mail.attention",
            "arguments": {"kinds": ["mail", "health"]},
            "delivery": {
                "mode": "webhook",
                "url": "https://example.com/callback",
                "secret": "whsec_" + base64.b64encode(b"x" * 32).decode(),
            },
        }
        await self.service.rpc("events/subscribe", p)
        self.mail_source.rows.append(
            {**row(kind="mail"), "id": "new", "revision": "new"}
        )
        await self.mail.poll(now + 300)
        await self.mail.deliver(now + 300)
        self.assertEqual(self.delivery.sent[-1][1]["name"], "mail.attention")
        self.assertEqual(self.feishu.active(), [])
        self.assertEqual(self.ms.get("meta", "status")["counts"], {"mail": 2})

    async def test_headers_only_cache_and_pagination(self):
        self.mail_source.rows = [
            {**row(kind="mail"), "raw": {"body": "must-not-be-returned"}}
        ]
        await self.mail.poll()
        r, x = await self.call(
            "tools/call",
            {"name": "mail_recent", "arguments": {"limit": 1}},
            ["mail:read"],
        )
        self.assertEqual(r.status, 200)
        self.assertNotIn("must-not-be-returned", json.dumps(x))

    async def test_mail_failure_does_not_stop_feishu(self):
        self.mail_source.fail = True
        await self.mail.poll()
        await self.feishu.poll()
        self.assertFalse(self.mail.healthy)
        self.assertTrue(self.feishu.healthy)
