"""TLS IMAP sampler of headers only; never fetches bodies or changes flags.

SINCE uses mailbox INTERNALDATE (rounded down to a UTC calendar date), not
the sender-controlled Date header. The overlapping 48-hour window is not a
change feed: older mail and mail missed during a longer outage are not covered.
UIDVALIDITY is part of identity, so a mailbox reset cannot alias previous UIDs.
"""

from __future__ import annotations

import asyncio
import hashlib
import imaplib
import json
import math
import os
import re
import ssl
import stat
import time
from datetime import datetime, timedelta, timezone
from email import policy
from email.header import decode_header
from email.parser import BytesHeaderParser
from email.utils import parsedate_to_datetime
from pathlib import Path

from .source import SourceError

PASSWORD_ROOT = "/run"
MAX_HEADER_BYTES = 65536
MAX_RESPONSE_BYTES = 2 * MAX_HEADER_BYTES
SOCKET_TIMEOUT = 20
SNAPSHOT_TIMEOUT = 90
HEADER_FIELDS = "SUBJECT FROM TO DATE MESSAGE-ID"
MONTHS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


class _BoundedIMAP4SSL(imaplib.IMAP4_SSL):
    """Reject oversized literals before imaplib allocates/downloads them."""

    def __init__(self, *args, deadline, **kwargs):
        self.deadline = deadline
        self.response_bytes = 0
        super().__init__(*args, **kwargs)

    def _budget(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SourceError("mail:timeout")
        self.sock.settimeout(min(SOCKET_TIMEOUT, remaining))

    def _charge(self, value):
        self.response_bytes += len(value)
        if self.response_bytes > MAX_RESPONSE_BYTES:
            raise SourceError("mail:response_limit")
        return value

    def read(self, size):
        if size > MAX_HEADER_BYTES + 1:
            raise SourceError("mail:literal_limit")
        self._budget()
        return self._charge(super().read(size))

    def readline(self):
        self._budget()
        return self._charge(super().readline())


class MailSource:
    LOOKBACK_SECONDS = 48 * 60 * 60

    def __init__(
        self,
        host: str,
        username: str,
        password_file: str,
        folders: list[str] | None = None,
        max_headers: int = 500,
    ):
        if (
            not isinstance(host, str)
            or not host
            or len(host) > 253
            or re.fullmatch(r"[A-Za-z0-9.-]+", host) is None
        ):
            raise ValueError("invalid mail host")
        if (
            not isinstance(username, str)
            or not username
            or len(username) > 512
            or any(ord(c) < 32 or ord(c) == 127 for c in username)
        ):
            raise ValueError("invalid mail username")
        folders = ["INBOX"] if folders is None else folders
        # ASCII folder names only; callers can configure IMAP modified UTF-7.
        if (
            not isinstance(folders, list)
            or not 1 <= len(folders) <= 20
            or any(
                not isinstance(f, str)
                or not f
                or len(f) > 200
                or any(ord(c) < 32 or ord(c) > 126 for c in f)
                for f in folders
            )
        ):
            raise ValueError("invalid mail folders")
        if (
            isinstance(max_headers, bool)
            or not isinstance(max_headers, int)
            or not 1 <= max_headers <= 500
        ):
            raise ValueError("invalid mail header limit")
        if not isinstance(password_file, str) or not password_file:
            raise ValueError("invalid mail password file")
        self.host, self.username, self.password_file = host, username, password_file
        self.folders = list(dict.fromkeys(folders))
        self.max_headers = max_headers

    def _password(self) -> str:
        fd = None
        try:
            path = Path(self.password_file)
            root = Path(PASSWORD_ROOT).resolve()
            if not path.is_absolute() or not path.resolve().is_relative_to(root):
                raise ValueError
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid not in {0, os.geteuid()}
                or info.st_size > 8192
            ):
                raise ValueError
            value = os.read(fd, 8193)
            if len(value) > 8192:
                raise ValueError
            password = value.decode("utf-8").rstrip("\r\n")
            if not password or any(c in password for c in "\x00\r\n"):
                raise ValueError
            return password
        except (OSError, ValueError, UnicodeError):
            raise SourceError("mail:credential_file") from None
        finally:
            if fd is not None:
                os.close(fd)

    @staticmethod
    def _header(value: str | None) -> str:
        if value is None:
            return ""
        chunks = []
        try:
            decoded = decode_header(str(value))
        except (ValueError, LookupError, UnicodeError):
            decoded = [(str(value), None)]
        for part, encoding in decoded:
            if isinstance(part, bytes):
                try:
                    part = part.decode(encoding or "utf-8", "replace")
                except (LookupError, UnicodeError):
                    part = part.decode("utf-8", "replace")
            # Unfold headers and remove control characters from public strings.
            chunks.append(
                "".join(c if ord(c) >= 32 and ord(c) != 127 else " " for c in part)
            )
        return " ".join("".join(chunks).split())

    @staticmethod
    def _date(value: str) -> float | None:
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                return None
            stamp = parsed.timestamp()
            return stamp if math.isfinite(stamp) else None
        except (ValueError, TypeError, OverflowError, IndexError):
            return None

    @classmethod
    def _record(
        cls, folder: str, uidvalidity: str, uid: str, metadata: bytes, header: bytes
    ) -> dict:
        if len(header) > MAX_HEADER_BYTES:
            raise SourceError("mail:header_limit")
        message = BytesHeaderParser(policy=policy.compat32).parsebytes(header)
        values = {
            key: cls._header(message.get(key))
            for key in ("subject", "from", "to", "date", "message-id")
        }
        internal = re.search(rb'\bINTERNALDATE "([^"\r\n]+)"', metadata, re.I)
        at = None
        if internal:
            # Parse explicitly; Internaldate2tuple uses localtime and can obscure offsets.
            try:
                raw_date = internal.group(1).decode("ascii")
                match = re.fullmatch(
                    r" ?(\d{1,2})-([A-Za-z]{3})-(\d{4}) (\d{2}:\d{2}:\d{2}) ([+-]\d{4})",
                    raw_date,
                )
                if match:
                    day, month, year, clock, offset = match.groups()
                    month_number = MONTHS.index(month.title()) + 1
                    parsed = datetime.strptime(
                        f"{year}-{month_number:02d}-{int(day):02d} {clock} {offset}",
                        "%Y-%m-%d %H:%M:%S %z",
                    )
                    at = parsed.timestamp()
            except (ValueError, UnicodeError, OverflowError):
                pass
        if at is None:
            at = cls._date(values["date"])
        raw = {
            "folder": folder,
            "uidvalidity": uidvalidity,
            "uid": uid,
            "message_id": values["message-id"],
            "from": values["from"],
            "to": values["to"],
            "date": values["date"],
            "subject": values["subject"],
        }
        revision = hashlib.sha256(
            json.dumps(
                values, sort_keys=True, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        return {
            "kind": "mail",
            "id": f"{folder}:{uidvalidity}:{uid}",
            "revision": revision,
            "title": values["subject"],
            "text": f"From: {values['from']}\nTo: {values['to']}\nDate: {values['date']}",
            "url": "",
            "at": at,
            "raw": raw,
        }

    def _snapshot(self, now: float) -> list[dict]:
        password = self._password()
        client = None
        stage = "connect"
        deadline = time.monotonic() + SNAPSHOT_TIMEOUT - SOCKET_TIMEOUT
        try:
            client = _BoundedIMAP4SSL(
                self.host,
                993,
                ssl_context=ssl.create_default_context(),
                timeout=SOCKET_TIMEOUT,
                deadline=deadline,
            )
            client.debug = 0

            def command(name, *args, **kwargs):
                client.response_bytes = 0
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SourceError("mail:timeout")
                client.sock.settimeout(min(SOCKET_TIMEOUT, remaining))
                status, data = getattr(client, name)(*args, **kwargs)
                if status != "OK":
                    raise SourceError(f"mail:{stage}_failed")
                return data

            stage = "login"
            command("login", self.username, password)
            del password
            since = datetime.fromtimestamp(now, timezone.utc) - timedelta(
                seconds=self.LOOKBACK_SECONDS
            )
            since_text = f"{since.day:02d}-{MONTHS[since.month - 1]}-{since.year:04d}"
            records = []
            for folder in self.folders:
                stage = "select"
                quoted = '"' + folder.replace("\\", "\\\\").replace('"', '\\"') + '"'
                command("select", quoted, readonly=True)
                _, validity = client.response("UIDVALIDITY")
                if (
                    not isinstance(validity, list)
                    or len(validity) != 1
                    or not isinstance(validity[0], bytes)
                    or not re.fullmatch(rb"[1-9]\d{0,9}", validity[0])
                ):
                    raise SourceError("mail:uidvalidity_invalid")
                uidvalidity = validity[0].decode("ascii")
                stage = "search"
                found = command("uid", "SEARCH", None, "SINCE", since_text)
                if (
                    not isinstance(found, list)
                    or len(found) != 1
                    or not isinstance(found[0], bytes)
                ):
                    raise SourceError("mail:search_invalid")
                if len(found[0]) > self.max_headers * 11:
                    raise SourceError("mail:header_count_limit")
                uids = found[0].split()
                if len(records) + len(uids) > self.max_headers:
                    raise SourceError("mail:header_count_limit")
                if len(set(uids)) != len(uids) or any(
                    not re.fullmatch(rb"[1-9]\d{0,9}", uid) for uid in uids
                ):
                    raise SourceError("mail:uid_invalid")
                for uid in uids:
                    stage = "fetch"
                    data = command(
                        "uid",
                        "FETCH",
                        uid.decode("ascii"),
                        f"(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS ({HEADER_FIELDS})]<0.{MAX_HEADER_BYTES + 1}>)",
                    )
                    literals = (
                        [entry for entry in data if isinstance(entry, tuple)]
                        if isinstance(data, list)
                        else []
                    )
                    if (
                        len(literals) != 1
                        or len(literals[0]) != 2
                        or not all(isinstance(part, bytes) for part in literals[0])
                    ):
                        raise SourceError("mail:fetch_invalid")
                    metadata, header = literals[0]
                    returned_uid = re.search(rb"\bUID ([1-9]\d*)\b", metadata, re.I)
                    if returned_uid is None or returned_uid.group(1) != uid:
                        raise SourceError("mail:fetch_uid_invalid")
                    records.append(
                        self._record(
                            folder, uidvalidity, uid.decode("ascii"), metadata, header
                        )
                    )
            return records
        except SourceError:
            raise
        except Exception:
            # Server exception strings may contain credentials, names or subjects.
            raise SourceError(f"mail:{stage}_failed") from None
        finally:
            if client is not None:
                # shutdown() only closes the socket; CLOSE could expunge messages.
                try:
                    client.shutdown()
                except Exception:
                    pass

    async def snapshot(self, now: float) -> list[dict]:
        if (
            isinstance(now, bool)
            or not isinstance(now, (int, float))
            or not math.isfinite(now)
        ):
            raise SourceError("mail:time_invalid")
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._snapshot, now), timeout=SNAPSHOT_TIMEOUT
            )
        except asyncio.TimeoutError:
            raise SourceError("mail:timeout") from None
