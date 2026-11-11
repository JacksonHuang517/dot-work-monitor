"""Read-only Feishu snapshots through an already-authorized official lark-cli.

Messages cover configured conversations (or a global authorized message search
for chat_ids=['*']) and the configured lookback, initially 15 minutes. Global
search requires search:message and can lag while Feishu indexes new messages;
the overlapping lookback tolerates a limited indexing delay. Older
message edits/recalls, and messages missed during longer outages, are not a
change feed. Completed tasks and cancelled events disappear from snapshots;
absence is not a deletion event. No attachments or thread expansion is fetched.
Configured owner/app bindings are verified before every snapshot reads data.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import time
from datetime import datetime, timezone
from typing import Any


class SourceError(RuntimeError):
    """A deliberately content-free error suitable for connector diagnostics."""


class LarkSource:
    LOOKBACK_SECONDS = 15 * 60
    CALENDAR_SECONDS = 48 * 60 * 60
    MAX_PAGES = 100
    MAX_RECORDS = 10_000
    MAX_OUTPUT_BYTES = 8 * 1024 * 1024
    COMMAND_TIMEOUT = 30
    IDENTITY_TIMEOUT = 10
    CHAT_CACHE_SECONDS = 60 * 60

    def __init__(
        self,
        chat_ids: list[str],
        calendar_ids: list[str],
        cli: str = "lark-cli",
        *,
        max_chats: int = 1000,
        lookback_seconds: int = 900,
        expected_open_id: str | None = None,
        expected_app_id: str | None = None,
    ):
        if not isinstance(cli, str) or not cli or "\x00" in cli:
            raise ValueError("invalid CLI executable")
        self.cli = cli
        for expected in (expected_open_id, expected_app_id):
            if expected is not None and (
                not isinstance(expected, str)
                or not expected.strip()
                or "\x00" in expected
            ):
                raise ValueError("invalid expected source identity")
        self.expected_open_id = expected_open_id
        self.expected_app_id = expected_app_id
        self.chat_ids = self._ids(chat_ids)
        self.calendar_ids = self._ids(calendar_ids) or ["primary"]
        if (
            isinstance(max_chats, bool)
            or not isinstance(max_chats, int)
            or not 1 <= max_chats <= 1000
        ):
            raise ValueError("max_chats must be between 1 and 1000")
        if (
            isinstance(lookback_seconds, bool)
            or not isinstance(lookback_seconds, int)
            or lookback_seconds < 900
        ):
            raise ValueError("lookback_seconds must be at least 900")
        if "*" in self.chat_ids and self.chat_ids != ["*"]:
            raise ValueError("wildcard must be the only chat identifier")
        if len(self.chat_ids) > max_chats:
            raise ValueError("configured chats exceed max_chats")
        self.max_chats = max_chats
        self.lookback_seconds = lookback_seconds
        self._chat_cache: list[str] | None = None
        self._chat_cache_at: float | None = None
        self._watched_chat_count = (
            len(self.chat_ids) if self.chat_ids != ["*"] else None
        )

    @staticmethod
    def _ids(values: list[str]) -> list[str]:
        if not isinstance(values, list) or any(
            not isinstance(value, str) or not value.strip() or "\x00" in value
            for value in values
        ):
            raise ValueError("invalid source identifiers")
        return list(dict.fromkeys(values))

    async def _read(self, stream: asyncio.StreamReader) -> bytes:
        chunks: list[bytes] = []
        size = 0
        while chunk := await stream.read(65536):
            size += len(chunk)
            if size > self.MAX_OUTPUT_BYTES:
                raise SourceError("lark-cli output limit exceeded")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _exec(self, args: list[str], *, timeout: float | None = None) -> Any:
        env = os.environ.copy()
        env.update(
            {
                "LARKSUITE_CLI_NO_UPDATE_NOTIFIER": "1",
                "LARKSUITE_CLI_NO_SKILLS_NOTIFIER": "1",
                "TZ": "UTC",
            }
        )
        try:
            process = await asyncio.create_subprocess_exec(
                self.cli,
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (OSError, ValueError):
            raise SourceError("lark-cli could not start") from None
        tasks = [
            asyncio.create_task(self._read(process.stdout)),
            asyncio.create_task(self._read(process.stderr)),
            asyncio.create_task(process.wait()),
        ]
        try:
            stdout, _stderr, returncode = await asyncio.wait_for(
                asyncio.gather(*tasks),
                timeout=self.COMMAND_TIMEOUT if timeout is None else timeout,
            )
        except BaseException as exc:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await process.wait()
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, SourceError):
                raise SourceError(str(exc)) from None
            if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
                raise SourceError("lark-cli timed out") from None
            raise SourceError("lark-cli output could not be read") from None
        if returncode != 0:
            raise SourceError("lark-cli command failed")
        try:
            envelope = json.loads(stdout)
        except (ValueError, UnicodeError, RecursionError):
            raise SourceError("lark-cli returned invalid JSON") from None
        return envelope

    async def _run(self, args: list[str]) -> dict[str, Any]:
        envelope = await self._exec(args + ["--as", "user", "--format", "json"])
        if not isinstance(envelope, dict) or envelope.get("ok") is not True:
            raise SourceError("lark-cli did not confirm success")
        if envelope.get("identity") != "user":
            raise SourceError("lark-cli user identity required")
        if envelope.get("dry_run") or not isinstance(envelope.get("data"), dict):
            raise SourceError("lark-cli returned an invalid data envelope")
        return envelope

    async def _verify_owner(self) -> None:
        if self.expected_open_id is None and self.expected_app_id is None:
            return
        # whoami emits its identity object directly, not the data/ok envelope.
        identity = await self._exec(
            ["whoami", "--as", "user"], timeout=self.IDENTITY_TIMEOUT
        )
        if (
            not isinstance(identity, dict)
            or identity.get("identity") != "user"
            or identity.get("ok") is False
            or identity.get("error")
            or identity.get("dry_run")
        ):
            raise SourceError("lark-cli source identity verification failed")
        owner = identity.get("onBehalfOf")
        if (
            not isinstance(owner, dict)
            or not isinstance(owner.get("openId"), str)
            or not owner["openId"]
        ):
            raise SourceError("lark-cli source identity verification failed")
        if (
            self.expected_open_id is not None
            and owner["openId"] != self.expected_open_id
        ):
            raise SourceError("lark-cli source identity verification failed")
        if (
            self.expected_app_id is not None
            and identity.get("appId") != self.expected_app_id
        ):
            raise SourceError("lark-cli source identity verification failed")

    @staticmethod
    def _items(envelope: dict, key: str) -> list[dict]:
        values = envelope["data"].get(key)
        if not isinstance(values, list) or any(
            not isinstance(item, dict) for item in values
        ):
            raise SourceError("lark-cli returned an invalid record list")
        return values

    @staticmethod
    def _next(envelope: dict, *, paginated: bool = True) -> str | None:
        data = envelope["data"]
        meta = envelope.get("meta", {})
        if not isinstance(meta, dict):
            raise SourceError("lark-cli returned invalid pagination")
        pagination = meta.get("pagination", {})
        if not isinstance(pagination, dict):
            raise SourceError("lark-cli returned invalid pagination")
        more = data.get("has_more")
        complete = pagination.get("complete")
        if more is not None and not isinstance(more, bool):
            raise SourceError("lark-cli returned invalid pagination")
        if complete is not None and not isinstance(complete, bool):
            raise SourceError("lark-cli returned invalid pagination")
        if more is None and isinstance(complete, bool):
            more = not complete
        if complete is False:
            more = True
        if more is None:
            if paginated:
                raise SourceError("lark-cli omitted pagination status")
            return None
        if not more:
            return None
        token = data.get("page_token") or pagination.get("next_token")
        if not paginated or not isinstance(token, str) or not token:
            raise SourceError("lark-cli returned an incomplete result")
        return token

    async def _pages(
        self, args: list[str], key: str, *, record_limit: int | None = None
    ) -> list[dict]:
        records: list[dict] = []
        seen: set[str] = set()
        token: str | None = None
        for _ in range(self.MAX_PAGES):
            envelope = await self._run(
                args + (["--page-token", token] if token else [])
            )
            records.extend(self._items(envelope, key))
            if len(records) > (
                self.MAX_RECORDS if record_limit is None else record_limit
            ):
                raise SourceError("lark-cli record limit exceeded")
            token = self._next(envelope)
            if token is None:
                return records
            if token in seen:
                raise SourceError("lark-cli pagination did not advance")
            seen.add(token)
        raise SourceError("lark-cli page limit exceeded; snapshot incomplete")

    async def _watched_chats(self, now: float) -> list[str]:
        if self.chat_ids != ["*"]:
            return list(self.chat_ids)
        if (
            self._chat_cache is not None
            and self._chat_cache_at is not None
            and 0 <= now - self._chat_cache_at < self.CHAT_CACHE_SECONDS
        ):
            return list(self._chat_cache)
        # Do not use --exclude-muted: muted conversations are part of coverage.
        chats = await self._pages(
            [
                "im",
                "+chat-list",
                "--types",
                "p2p,group",
                "--sort",
                "active_time",
                "--page-size",
                "100",
            ],
            "chats",
            record_limit=self.max_chats,
        )
        identifiers: list[str] = []
        for chat in chats:
            identifier = chat.get("chat_id")
            if (
                not isinstance(identifier, str)
                or not identifier.strip()
                or "\x00" in identifier
            ):
                raise SourceError(
                    "lark-cli returned a conversation without an identifier"
                )
            identifiers.append(identifier)
        identifiers = list(dict.fromkeys(identifiers))
        # Only replace a previous cache after the complete enumeration validates.
        self._chat_cache = identifiers
        self._chat_cache_at = now
        self._watched_chat_count = len(identifiers)
        return list(identifiers)

    @staticmethod
    def _timestamp(value: Any, *, milliseconds: bool = False) -> float | None:
        if value is None or value == "":
            return None
        if isinstance(value, dict):
            if value.get("timestamp") not in (None, ""):
                return LarkSource._timestamp(
                    value["timestamp"], milliseconds=milliseconds
                )
            if value.get("date"):
                # Feishu all-day calendar dates are explicitly UTC, not host time.
                try:
                    return (
                        datetime.strptime(value["date"], "%Y-%m-%d")
                        .replace(tzinfo=timezone.utc)
                        .timestamp()
                    )
                except (TypeError, ValueError):
                    raise SourceError(
                        "lark-cli returned an invalid timestamp"
                    ) from None
            return None
        if isinstance(value, bool):
            raise SourceError("lark-cli returned an invalid timestamp")
        try:
            number = float(value)
        except (TypeError, ValueError):
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    raise ValueError
                return dt.timestamp()
            except (AttributeError, TypeError, ValueError, OverflowError):
                raise SourceError("lark-cli returned an invalid timestamp") from None
        if not math.isfinite(number):
            raise SourceError("lark-cli returned an invalid timestamp")
        return number / 1000 if milliseconds else number

    @staticmethod
    def _string(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )

    @classmethod
    def _record(cls, kind: str, item: dict, *, scope: str = "") -> dict:
        if kind == "message":
            identifier = item.get("message_id")
            sender = item.get("sender") or {}
            title = (
                (sender.get("name") or "Feishu message")
                if isinstance(sender, dict)
                else "Feishu message"
            )
            text = cls._string(item.get("content"))
            url = item.get("message_app_link") or item.get("url") or ""
            # Official CLI common.FormatTime emits local "YYYY-MM-DD HH:MM".
            # _run fixes its timezone to UTC; do not infer the host timezone.
            value = item.get("create_time")
            formatted = None
            if isinstance(value, str):
                for pattern in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
                    try:
                        formatted = (
                            datetime.strptime(value, pattern)
                            .replace(tzinfo=timezone.utc)
                            .timestamp()
                        )
                        break
                    except ValueError:
                        pass
            numeric = isinstance(value, (int, float)) or (
                isinstance(value, str) and value.isdigit()
            )
            at = (
                formatted
                if formatted is not None
                else cls._timestamp(value, milliseconds=numeric)
            )
            relevant = {
                key: item.get(key)
                for key in (
                    "content",
                    "msg_type",
                    "sender",
                    "mentions",
                    "deleted",
                    "update_time",
                    "updated",
                )
            }
        elif kind == "task":
            identifier = item.get("guid")
            title, text, url = (
                item.get("summary"),
                item.get("description"),
                item.get("url"),
            )
            at = cls._timestamp(item.get("due"), milliseconds=True)
            relevant = {
                key: item.get(key)
                for key in (
                    "summary",
                    "description",
                    "due",
                    "start",
                    "completed_at",
                    "status",
                    "updated_at",
                    "members",
                    "url",
                )
            }
        else:
            identifier = item.get("event_id")
            title = item.get("summary")
            text = item.get("description_rich") or item.get("description")
            url = item.get("app_link")
            at = cls._timestamp(item.get("start_time"))
            relevant = {
                key: item.get(key)
                for key in (
                    "summary",
                    "description",
                    "description_rich",
                    "start_time",
                    "end_time",
                    "status",
                    "location",
                    "self_rsvp_status",
                    "app_link",
                )
            }
        if not isinstance(identifier, str) or not identifier:
            raise SourceError("lark-cli returned a record without an identifier")
        digest = hashlib.sha256(
            json.dumps(
                relevant, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode()
        ).hexdigest()
        raw = dict(item)
        if scope:
            raw["chat_id" if kind == "message" else "calendar_id"] = scope
        return {
            "kind": kind,
            "id": identifier,
            "revision": digest,
            "title": cls._string(title),
            "text": cls._string(text),
            "url": cls._string(url),
            "at": at,
            "raw": raw,
        }

    async def snapshot(self, now: float) -> list[dict]:
        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not math.isfinite(now)
        ):
            raise ValueError("invalid snapshot timestamp")
        await self._verify_owner()
        # Message search rejects fractional seconds (API error 99992402), even
        # though lark-cli accepts them locally and forwards the original string.
        iso = lambda value: datetime.fromtimestamp(value, timezone.utc).isoformat(
            timespec="seconds"
        )
        records: list[dict] = []
        if self.chat_ids == ["*"]:
            # One time-bounded search across authorized conversations avoids a
            # separate history request for every joined chat on every poll.
            items = await self._pages(
                [
                    "im",
                    "+messages-search",
                    "--query",
                    "",
                    "--start",
                    iso(now - self.lookback_seconds),
                    "--end",
                    iso(now),
                    "--page-size",
                    "50",
                    "--no-reactions",
                ],
                "messages",
            )
            for item in items:
                if item.get("deleted") is True:
                    continue
                chat_id = item.get("chat_id")
                if not isinstance(chat_id, str) or not chat_id.strip():
                    raise SourceError(
                        "lark-cli returned a search message without conversation context"
                    )
                records.append(self._record("message", item, scope=chat_id))
        for chat_id in [] if self.chat_ids == ["*"] else self.chat_ids:
            items = await self._pages(
                [
                    "im",
                    "+chat-messages-list",
                    "--chat-id",
                    chat_id,
                    "--start",
                    iso(now - self.lookback_seconds),
                    "--end",
                    iso(now),
                    "--order",
                    "asc",
                    "--page-size",
                    "50",
                    "--no-reactions",
                ],
                "messages",
            )
            for item in items:
                if item.get("deleted") is not True:
                    records.append(self._record("message", item, scope=chat_id))
        # Generic API keeps native task field types and exposes every page cursor.
        tasks = await self._pages(
            [
                "task",
                "tasks",
                "list",
                "--params",
                json.dumps({"completed": False, "type": "my_tasks", "page_size": 100}),
            ],
            "items",
        )
        for item in tasks:
            if item.get("status") == "done" or item.get("completed_at") not in (
                None,
                "",
                "0",
                0,
            ):
                continue
            records.append(self._record("task", item))
        for calendar_id in self.calendar_ids:
            envelope = await self._run(
                [
                    "calendar",
                    "events",
                    "instance_view",
                    "--calendar-id",
                    calendar_id,
                    "--start-time",
                    str(int(now)),
                    "--end-time",
                    str(int(now + self.CALENDAR_SECONDS)),
                ]
            )
            self._next(envelope, paginated=False)
            items = self._items(envelope, "items")
            if len(items) > self.MAX_RECORDS:
                raise SourceError("lark-cli record limit exceeded")
            for item in items:
                if item.get("status") != "cancelled":
                    records.append(self._record("calendar", item, scope=calendar_id))
        if len(records) > self.MAX_RECORDS:
            raise SourceError("lark-cli snapshot record limit exceeded")
        return records

    async def probe(self) -> dict:
        """Exercise configured reads; return counts only, never source contents."""
        records = await self.snapshot(time.time())
        counts = {
            kind: sum(record["kind"] == kind for record in records)
            for kind in ("message", "task", "calendar")
        }
        return {
            "ok": True,
            "identity": "user",
            "counts": counts,
            "configured_chats": len(self.chat_ids),
            "watched_chat_count": None
            if self.chat_ids == ["*"]
            else len(self.chat_ids),
            "coverage_mode": "global_search"
            if self.chat_ids == ["*"]
            else "configured_chats",
            "message_indexing_delay_possible": self.chat_ids == ["*"],
            "configured_calendars": len(self.calendar_ids),
            "message_lookback_seconds": self.lookback_seconds,
            "calendar_horizon_seconds": self.CALENDAR_SECONDS,
        }
