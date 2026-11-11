"""Five-minute cloud sampler, persistent deduplication and signed outbox."""

import asyncio
import hashlib
import json
import time
from datetime import datetime, timezone

EVENT = "feishu.attention"


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


class Engine:
    DELIVERY_INTERVAL_SECONDS = 5

    def __init__(
        self, store, source, delivery, interval=300, *, event_name=EVENT, kinds=None
    ):
        self.store, self.source, self.delivery = store, source, delivery
        self.event_name = event_name
        self.kinds = kinds or ["message", "task", "calendar"]
        self.interval = max(60, interval)
        self.healthy = False
        self.running = False
        self.lock = asyncio.Lock()

    def status(self):
        status = self.store.get("meta", "status", {})
        return {
            **status,
            "subscriptions": len(self.active()),
            "interval_seconds": self.interval,
            "healthy": self.healthy,
            "source_coverage": getattr(
                self.source,
                "coverage",
                {
                    "messages": getattr(self.source, "chat_ids", []),
                    "calendars": getattr(self.source, "calendar_ids", []),
                    "lookback_seconds": getattr(self.source, "lookback_seconds", 900),
                },
            ),
        }

    def active(self):
        now = time.time()
        return [
            (k, s) for k, s in self.store.all("subscriptions") if s["expires"] > now
        ]

    def emit(self, record, reason, key, now):
        eid = "evt_" + digest(key)
        data = {k: record.get(k) for k in ("kind", "id", "title", "text", "url", "at")}
        data["text"] = str(data.get("text") or "")[:6000]
        data["title"] = str(data.get("title") or "")[:1000]
        data.update(reason=reason, observed_at=iso(now))
        event = {
            "eventId": eid,
            "name": self.event_name,
            "timestamp": iso(now),
            "data": data,
            "cursor": None,
            "_revision": record.get("revision"),
        }
        for sid, sub in self.active():
            if record["kind"] in sub["arguments"]["kinds"]:
                self.store.enqueue(sid, event)

    async def poll(self, now=None):
        now = time.time() if now is None else now
        async with self.lock:
            try:
                last = self.store.get("meta", "last_success_unix")
                if hasattr(self.source, "lookback_seconds") and last:
                    self.source.lookback_seconds = max(
                        900, min(86400, int(now - last) + 300)
                    )
                records = await self.source.snapshot(now)
            except Exception as exc:
                self.healthy = False
                # Never log raw exceptions: CLI failures can contain credentials/content.
                self.store.put(
                    "meta",
                    "status",
                    {
                        "last_attempt": iso(now),
                        "last_success": self.store.get("meta", "status", {}).get(
                            "last_success"
                        ),
                        "error": type(exc).__name__,
                    },
                )
                # Health events can be delivered even while data delivery is paused.
                self.emit(
                    {
                        "kind": "health",
                        "id": "source",
                        "title": (
                            "邮箱" if self.event_name == "mail.attention" else "飞书"
                        )
                        + "采集失败，需要检查授权或连接",
                        "text": "本轮没有完成采集，消息与提醒覆盖可能有缺口。",
                        "url": "",
                        "at": None,
                    },
                    "source_unavailable",
                    f"health:{int(now // 3600)}",
                    now,
                )
                return
            self.healthy = True
            first = not self.store.get("meta", "initialized", False)
            present = set()
            for record in records:
                kind, rid = record["kind"], record["id"]
                rk = kind + ":" + rid
                present.add(rk)
                previous = self.store.get("records", rk)
                revision = record["revision"]
                if not first and (previous is None or previous["revision"] != revision):
                    self.emit(
                        record,
                        "new" if previous is None else "changed",
                        f"{rk}:{revision}",
                        now,
                    )
                at = record.get("at")
                if at is not None:
                    delta = at - now
                    if kind == "task" and delta <= 86400:
                        reason = "overdue" if delta < 0 else "due_soon"
                        day = int(now // 86400) if delta < 0 else "once"
                        key = f"{rk}:{at}:{reason}:{day}"
                        if not self.store.get("reminders", key):
                            self.emit(record, reason, key, now)
                            self.store.put("reminders", key, now)
                    if kind == "calendar" and 0 <= delta <= 1800:
                        key = f"{rk}:{at}:starting"
                        if not self.store.get("reminders", key):
                            self.emit(record, "starting_soon", key, now)
                            self.store.put("reminders", key, now)
                self.store.put(
                    "records", rk, {"revision": revision, "record": record, "seen": now}
                )
            # Removed tasks/cancelled meetings should not remain in the read-tool cache.
            for key, old in self.store.all("records"):
                if key not in present and (
                    not key.startswith("message:") or old["seen"] < now - 86400
                ):
                    self.store.delete("records", key)
            for key, stamp in self.store.all("reminders"):
                if stamp < now - 30 * 86400:
                    self.store.delete("reminders", key)
            self.store.put("meta", "initialized", True)
            self.store.put("meta", "last_success_unix", now)
            self.store.put(
                "meta",
                "status",
                {
                    "last_attempt": iso(now),
                    "last_success": iso(now),
                    "error": None,
                    "counts": {
                        k: sum(r["kind"] == k for r in records) for k in self.kinds
                    },
                },
            )

    async def deliver(self, now=None):
        now = time.time() if now is None else now
        for sid, eid, event, attempts in self.store.pending(
            now, only_health=not self.healthy
        ):
            sub = self.store.get("subscriptions", sid)
            if not sub or sub["expires"] <= now:
                self.store.done(sid, eid)
                continue
            if not self.healthy and event["data"]["kind"] != "health":
                continue
            data = event["data"]
            kind = data["kind"]
            if kind != "health":
                cached = self.store.get("records", kind + ":" + data["id"])
                current = cached["record"] if cached else None
                at = data.get("at")
                reason = data.get("reason")
                stale = (
                    current is None
                    or current.get("at") != at
                    or (
                        event.get("_revision") is not None
                        and cached["revision"] != event["_revision"]
                    )
                )
                if not stale and at is not None:
                    if (
                        kind == "calendar"
                        and reason in ("starting_soon", "current_reminder")
                        and not 0 < at - now <= 1800
                    ):
                        stale = True
                    if kind == "task" and (
                        (reason == "due_soon" and at < now)
                        or (reason == "overdue" and at > now)
                        or (reason == "current_reminder" and at - now > 86400)
                    ):
                        stale = True
                if stale:
                    self.store.done(sid, eid)
                    continue
            public_event = {
                key: value for key, value in event.items() if not key.startswith("_")
            }
            try:
                code, _ = await self.delivery.post(sub, public_event, eid)
            except Exception:
                code = 0
            if 200 <= code < 300:
                self.store.done(sid, eid)
                self.store.put(
                    "meta",
                    "last_delivery",
                    {"time": iso(now), "eventId": eid, "status": code},
                )
            elif code == 410:
                self.store.delete("subscriptions", sid)
                self.store.done(sid, eid)
            elif (
                code == 413
                or (400 <= code < 500 and code not in (408, 425, 429))
                or attempts >= 11
            ):
                self.store.done(sid, eid)
                self.store.put(
                    "meta",
                    "delivery_error",
                    {"time": iso(now), "status": code, "attempts": attempts + 1},
                )
            else:
                self.store.retry(sid, eid, attempts + 1, now)

    def loop_failure(self, area):
        # Persistence itself may be unavailable; never let diagnostics kill a loop.
        if area == "poll":
            self.healthy = False
        try:
            now = time.time()
            if area == "poll":
                previous = self.store.get("meta", "status", {})
                self.store.put(
                    "meta",
                    "status",
                    {
                        "last_attempt": iso(now),
                        "last_success": previous.get("last_success"),
                        "error": "poll_loop_failure",
                    },
                )
            else:
                self.store.put(
                    "meta",
                    "delivery_error",
                    {"time": iso(now), "error": "delivery_loop_failure"},
                )
        except Exception:
            pass

    async def poll_loop(self):
        while self.running:
            try:
                await self.poll()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.loop_failure("poll")
            # Interval starts after a completed attempt; slow callbacks are independent.
            await asyncio.sleep(self.interval)

    async def delivery_loop(self):
        while self.running:
            try:
                await self.deliver()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.loop_failure("delivery")
            await asyncio.sleep(self.DELIVERY_INTERVAL_SECONDS)

    async def run(self):
        self.running = True
        tasks = [
            asyncio.create_task(self.poll_loop()),
            asyncio.create_task(self.delivery_loop()),
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            self.running = False
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
