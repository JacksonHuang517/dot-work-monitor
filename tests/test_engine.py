import base64
import asyncio
import hashlib
import hmac
import json
import tempfile
import time
import unittest
from cryptography.fernet import Fernet
from dot_feishu.store import Store
from dot_feishu.engine import Engine
from dot_feishu.server import Service, RpcError
from dot_feishu.delivery import headers, validate_url, signing_key, DeliveryError


class Source:
    def __init__(self):
        self.rows = []
        self.fail = False

    async def snapshot(self, now):
        if self.fail:
            raise RuntimeError("secret must never escape")
        return self.rows


class Delivery:
    def __init__(self):
        self.sent = []
        self.code = 200
        self.verified = []

    async def verify(self, s):
        self.verified.append(s)

    async def post(self, s, e, eid):
        self.sent.append((s, e, eid))
        return self.code, b""


def row(kind="task", rev="1", at=None):
    return dict(
        kind=kind,
        id="item",
        revision=rev,
        title="Synthetic",
        text="test only",
        url="",
        at=at,
        raw={},
    )


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name + "/db", Fernet.generate_key())
        self.source = Source()
        self.delivery = Delivery()
        self.engine = Engine(self.store, self.source, self.delivery)
        self.svc = Service(self.engine, "k" * 32)
        self.now = time.time()
        self.params = {
            "name": "feishu.attention",
            "arguments": {"kinds": ["task", "calendar", "message", "health"]},
            "delivery": {
                "mode": "webhook",
                "url": "https://example.com/callback",
                "secret": "whsec_" + base64.b64encode(b"x" * 32).decode(),
            },
        }
        self.sub = await self.svc.rpc("events/subscribe", self.params)

    async def asyncTearDown(self):
        self.store.close()
        self.tmp.cleanup()

    async def test_baseline_and_change(self):
        self.source.rows = [row()]
        await self.engine.poll(self.now)
        self.assertEqual(self.store.pending(self.now), [])
        self.source.rows = [row(rev="2")]
        await self.engine.poll(self.now + 300)
        await self.engine.deliver(self.now + 300)
        self.assertEqual(len(self.delivery.sent), 1)
        self.assertEqual(self.delivery.sent[0][1]["data"]["reason"], "changed")
        await self.engine.poll(self.now + 600)
        self.assertEqual(self.store.pending(self.now + 600), [])

    async def test_due_without_change_and_restart(self):
        self.source.rows = [row(at=self.now + 87000)]
        await self.engine.poll(self.now)
        await self.engine.poll(self.now + 700)
        self.assertEqual(len(self.store.pending(self.now + 700)), 1)
        engine = Engine(self.store, self.source, self.delivery)
        await engine.poll(self.now + 1000)
        self.assertEqual(len(self.store.pending(self.now + 1000)), 1)

    async def test_deadline_reschedule(self):
        self.source.rows = [row(at=self.now + 1000)]
        await self.engine.poll(self.now)
        await self.engine.deliver(self.now)
        self.source.rows = [row(rev="2", at=self.now + 2000)]
        await self.engine.poll(self.now + 1)
        self.assertEqual(len(self.store.pending(self.now + 1)), 2)

    async def test_removed_task_does_not_remain_in_cache(self):
        self.source.rows = [row()]
        await self.engine.poll(self.now)
        self.source.rows = []
        await self.engine.poll(self.now + 300)
        self.assertEqual(self.store.all("records"), [])

    async def test_retry_stable_id(self):
        self.source.rows = [row(at=self.now + 10)]
        await self.engine.poll(self.now)
        self.delivery.code = 503
        await self.engine.deliver(self.now)
        eid = self.delivery.sent[0][2]
        self.delivery.code = 200
        await self.engine.deliver(self.now + 20)
        self.assertEqual(self.delivery.sent[-1][2], eid)
        self.assertEqual(self.store.pending(self.now + 20), [])

    async def test_retry_drops_completed_task(self):
        self.source.rows = [row(at=self.now + 100)]
        await self.engine.poll(self.now)
        self.delivery.code = 503
        await self.engine.deliver(self.now)
        self.source.rows = []
        await self.engine.poll(self.now + 300)
        self.delivery.code = 200
        await self.engine.deliver(self.now + 300)
        self.assertEqual(len(self.delivery.sent), 1)
        self.assertEqual(self.store.pending(self.now + 300), [])

    async def test_retry_drops_old_revision_after_reschedule(self):
        self.source.rows = [row(at=self.now + 1000)]
        await self.engine.poll(self.now)
        self.delivery.code = 503
        await self.engine.deliver(self.now)
        self.source.rows = [row(rev="2", at=self.now + 2000)]
        await self.engine.poll(self.now + 300)
        self.delivery.code = 200
        await self.engine.deliver(self.now + 300)
        retried = self.delivery.sent[1:]
        self.assertEqual(len(retried), 2)
        self.assertTrue(
            all(event["data"]["at"] == self.now + 2000 for _, event, _ in retried)
        )
        self.assertTrue(
            all("_revision" not in event for _, event, _ in self.delivery.sent)
        )

    async def test_retry_drops_calendar_reminder_after_start(self):
        self.source.rows = [row(kind="calendar", at=self.now + 10)]
        await self.engine.poll(self.now)
        self.delivery.code = 503
        await self.engine.deliver(self.now)
        self.delivery.code = 200
        await self.engine.deliver(self.now + 20)
        self.assertEqual(len(self.delivery.sent), 1)
        self.assertEqual(self.store.pending(self.now + 20), [])

    async def test_retry_drops_due_soon_then_emits_current_overdue(self):
        self.source.rows = [row(at=self.now + 10)]
        await self.engine.poll(self.now)
        self.delivery.code = 503
        await self.engine.deliver(self.now)
        await self.engine.poll(self.now + 20)
        self.delivery.code = 200
        await self.engine.deliver(self.now + 20)
        self.assertEqual(
            [event["data"]["reason"] for _, event, _ in self.delivery.sent],
            ["due_soon", "overdue"],
        )

    async def test_health_not_starved_by_hundred_pending_data_events(self):
        for index in range(100):
            self.store.enqueue(
                self.sub["id"],
                {"eventId": f"pending_{index}", "data": {"kind": "task"}},
            )
        self.source.fail = True
        await self.engine.poll(self.now)
        await self.engine.deliver(self.now)
        self.assertEqual(
            [event["data"]["kind"] for _, event, _ in self.delivery.sent], ["health"]
        )
        self.assertEqual(len(self.store.pending(self.now)), 100)

    async def test_slow_delivery_does_not_block_polling_or_overlap_delivery(self):
        started = asyncio.Event()
        polled_twice = asyncio.Event()
        blocked = asyncio.Event()
        calls = {"poll": 0, "delivery": 0}

        async def poll():
            calls["poll"] += 1
            if calls["poll"] >= 2:
                polled_twice.set()

        async def deliver():
            calls["delivery"] += 1
            started.set()
            await blocked.wait()

        self.engine.poll = poll
        self.engine.deliver = deliver
        self.engine.interval = 0.01
        self.engine.DELIVERY_INTERVAL_SECONDS = 0.01
        task = asyncio.create_task(self.engine.run())
        try:
            await asyncio.wait_for(started.wait(), 1)
            await asyncio.wait_for(polled_twice.wait(), 1)
            self.assertEqual(calls["delivery"], 1)
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertFalse(self.engine.running)

    async def test_background_loops_recover_and_errors_are_sanitized(self):
        recovered_poll = asyncio.Event()
        recovered_delivery = asyncio.Event()
        calls = {"poll": 0, "delivery": 0}

        async def poll():
            calls["poll"] += 1
            if calls["poll"] == 1:
                raise RuntimeError("private fixture contents")
            recovered_poll.set()

        async def deliver():
            calls["delivery"] += 1
            if calls["delivery"] == 1:
                raise RuntimeError("private fixture contents")
            recovered_delivery.set()

        self.engine.poll = poll
        self.engine.deliver = deliver
        self.engine.interval = 0.01
        self.engine.DELIVERY_INTERVAL_SECONDS = 0.01
        task = asyncio.create_task(self.engine.run())
        try:
            await asyncio.wait_for(
                asyncio.gather(recovered_poll.wait(), recovered_delivery.wait()), 1
            )
            self.assertEqual(
                self.store.get("meta", "status")["error"], "poll_loop_failure"
            )
            self.assertEqual(
                self.store.get("meta", "delivery_error")["error"],
                "delivery_loop_failure",
            )
            self.assertNotIn("private", json.dumps(self.store.all("meta")))
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    async def test_410_unsubscribes(self):
        self.source.rows = [row(at=self.now + 10)]
        await self.engine.poll(self.now)
        self.delivery.code = 410
        await self.engine.deliver(self.now)
        self.assertEqual(self.engine.active(), [])

    async def test_auth_failure_pauses_data(self):
        self.source.rows = [row(at=self.now + 10)]
        await self.engine.poll(self.now)
        self.source.fail = True
        await self.engine.poll(self.now + 1)
        await self.engine.deliver(self.now + 1)
        self.assertEqual([e[1]["data"]["kind"] for e in self.delivery.sent], ["health"])
        self.assertNotIn("secret", json.dumps(self.engine.status()))

    async def test_idempotent_subscribe_canonical_filters(self):
        p = {
            **self.params,
            "arguments": {"kinds": ["health", "message", "calendar", "task"]},
        }
        second = await self.svc.rpc("events/subscribe", p)
        self.assertEqual(second["id"], self.sub["id"])
        self.assertEqual(len(self.engine.active()), 1)

    async def test_ttl_and_unsubscribe(self):
        p = {**self.params, "ttlMs": 1}
        r = await self.svc.rpc("events/subscribe", p)
        await self.svc.rpc("events/unsubscribe", self.params)
        await self.svc.rpc("events/unsubscribe", self.params)
        self.assertEqual(self.engine.active(), [])

    async def test_invalid_filters(self):
        for kinds in [[], ["wrong"], ["task", "task"], "task"]:
            with self.assertRaises(RpcError):
                await self.svc.rpc(
                    "events/subscribe", {**self.params, "arguments": {"kinds": kinds}}
                )

    async def test_no_plaintext_in_store(self):
        self.store.put("test", "a", {"body": "confidential_body_string"})
        from pathlib import Path

        self.assertNotIn(
            b"confidential_body_string", Path(self.tmp.name + "/db").read_bytes()
        )


class DeliveryTests(unittest.TestCase):
    def test_standard_webhooks_signature(self):
        secret = "whsec_" + base64.b64encode(b"x" * 32).decode()
        body = b'{"a":1}'
        h = headers({"id": "sub", "secret": secret}, "evt", body, 123)
        expected = base64.b64encode(
            hmac.new(b"x" * 32, b"evt.123." + body, hashlib.sha256).digest()
        ).decode()
        self.assertEqual(h["webhook-signature"], "v1," + expected)

    def test_reject_private_or_unsafe_url(self):
        for u in [
            "http://example.com",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://169.254.169.254",
            "https://user:pass@example.com",
            "https://example.com:8080",
        ]:
            with self.assertRaises((DeliveryError, ValueError)):
                validate_url(u)

    def test_secret_length(self):
        for s in ["key", "whsec_???", "whsec_" + base64.b64encode(b"x").decode()]:
            with self.assertRaises(DeliveryError):
                signing_key(s)


if __name__ == "__main__":
    unittest.main()
