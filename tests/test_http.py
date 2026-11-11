import tempfile
import unittest
from cryptography.fernet import Fernet
from aiohttp.test_utils import TestClient, TestServer
from dot_feishu.server import create_app
from dot_feishu.store import Store
from dot_feishu.engine import Engine
from test_engine import Source, Delivery


class HttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name + "/db", Fernet.generate_key())
        self.client = TestClient(
            TestServer(
                create_app(
                    Engine(self.store, Source(), Delivery()),
                    "k" * 32,
                    start_worker=False,
                )
            )
        )
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        self.store.close()
        self.tmp.cleanup()

    async def test_unauthorized(self):
        r = await self.client.post(
            "/dot-feishu/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        self.assertEqual(r.status, 401)

    async def test_protocol(self):
        for method in ["initialize", "tools/list", "events/list"]:
            r = await self.client.post(
                "/dot-feishu/mcp",
                headers={"X-Connector-Key": "k" * 32},
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": {}},
            )
            self.assertEqual(r.status, 200)
            self.assertIn("result", await r.json())

    async def test_notifications(self):
        r = await self.client.post(
            "/dot-feishu/mcp",
            headers={"X-Connector-Key": "k" * 32},
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        self.assertEqual(r.status, 202)

    async def test_invalid_json(self):
        r = await self.client.post(
            "/dot-feishu/mcp", headers={"X-Connector-Key": "k" * 32}, data=b"no"
        )
        self.assertEqual(r.status, 400)
