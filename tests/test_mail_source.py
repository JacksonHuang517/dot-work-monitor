import asyncio
import imaplib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from dot_feishu.mail_source import MailSource, MAX_HEADER_BYTES, _BoundedIMAP4SSL
from dot_feishu.source import SourceError


NOW = 1700000000
HEADER = (
    b"Subject: =?UTF-8?B?5rWL6K+V?=\r\nFrom: Sender <a@example.test>\r\n"
    b"To: Receiver <b@example.test>\r\nDate: Fri, 01 Jan 1999 00:00:00 +0000\r\n"
    b"Message-ID: <fixture@example.test>\r\n\r\n"
)


class FakeIMAP:
    def __init__(
        self,
        *,
        uids=b"1",
        validity=b"200",
        header=HEADER,
        internal=b"14-Nov-2023 22:13:20 +0000",
    ):
        self.uids, self.validity, self.header, self.internal = (
            uids,
            validity,
            header,
            internal,
        )
        self.sock = Mock()
        self.calls = []
        self.closed = False

    def login(self, username, password):
        self.calls.append(("login", username, password))
        return "OK", [b"authenticated"]

    def select(self, folder, readonly=False):
        self.calls.append(("select", folder, readonly))
        return "OK", [b"1"]

    def response(self, name):
        self.calls.append(("response", name))
        return name, [self.validity]

    def uid(self, name, *args):
        self.calls.append((name, *args))
        if name == "SEARCH":
            return "OK", [self.uids]
        uid = args[0].encode()
        metadata = b"1 (UID " + uid
        if self.internal is not None:
            metadata += b' INTERNALDATE "' + self.internal + b'"'
        metadata += b" BODY[HEADER.FIELDS (SUBJECT FROM TO DATE MESSAGE-ID)]<0> {100}"
        return "OK", [(metadata, self.header), b")"]

    def shutdown(self):
        self.closed = True


class MailSourceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.source = MailSource(
            "imap.example.test", "fixture@example.test", "/run/fixture-password"
        )
        self.password = patch.object(
            self.source, "_password", return_value="fake-password"
        )
        self.password.start()
        self.addCleanup(self.password.stop)

    async def read(self, fake):
        with patch(
            "dot_feishu.mail_source._BoundedIMAP4SSL", return_value=fake
        ) as create:
            records = await self.source.snapshot(NOW)
        self.assertEqual(create.call_args.kwargs["timeout"], 20)
        self.assertTrue(create.call_args.kwargs["ssl_context"].check_hostname)
        return records

    async def test_readonly_select_peek_and_exact_header_metadata(self):
        fake = FakeIMAP()
        records = await self.read(fake)
        record = records[0]
        self.assertEqual(
            set(record), {"kind", "id", "revision", "title", "text", "url", "at", "raw"}
        )
        self.assertEqual(record["kind"], "mail")
        self.assertEqual(record["id"], "INBOX:200:1")
        self.assertEqual(record["title"], "测试")
        self.assertEqual(record["at"], NOW)
        self.assertEqual(record["url"], "")
        self.assertEqual(record["raw"]["message_id"], "<fixture@example.test>")
        self.assertIn(("select", '"INBOX"', True), fake.calls)
        fetch = next(call for call in fake.calls if call[0] == "FETCH")
        self.assertIn(
            "BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE MESSAGE-ID)]<0.65537>",
            fetch[2],
        )
        self.assertNotIn("RFC822", fetch[2])
        self.assertTrue(fake.closed)

    async def test_internaldate_search_catches_new_uid_with_old_sender_date(self):
        fake = FakeIMAP()
        record = (await self.read(fake))[0]
        self.assertEqual(record["at"], NOW)
        search = next(call for call in fake.calls if call[0] == "SEARCH")
        self.assertEqual(search, ("SEARCH", None, "SINCE", "12-Nov-2023"))
        self.assertNotIn("SENTSINCE", search)

    async def test_uidvalidity_rollover_changes_identity_not_revision(self):
        first = (await self.read(FakeIMAP(validity=b"200")))[0]
        second = (await self.read(FakeIMAP(validity=b"201")))[0]
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["revision"], second["revision"])

    async def test_revision_stable_and_tracks_header_changes(self):
        first = (await self.read(FakeIMAP()))[0]
        self.assertEqual(
            first["revision"], (await self.read(FakeIMAP()))[0]["revision"]
        )
        changed = (
            await self.read(
                FakeIMAP(
                    header=HEADER.replace(
                        b"Message-ID: <fixture", b"Message-ID: <changed"
                    )
                )
            )
        )[0]
        self.assertNotEqual(first["revision"], changed["revision"])

    async def test_malformed_mime_control_characters_and_bad_date_are_safe(self):
        header = (
            b"Subject: =?made-up-charset?Q?bad=FF?=\r\n folded\x00value\r\n"
            b"From: attacker\x01@example.test\r\nDate: Fri, 99 Nov 999999 99:99:99 +9999\r\n\r\n"
        )
        record = (await self.read(FakeIMAP(header=header, internal=None)))[0]
        self.assertIsNone(record["at"])
        self.assertNotIn("\x00", record["title"])
        self.assertNotIn("\x01", record["text"])
        self.assertIn("folded", record["title"])

    async def test_fallback_date_timezone_is_explicit_and_absence_never_uses_poll_time(
        self,
    ):
        record = (await self.read(FakeIMAP(internal=b"invalid")))[0]
        self.assertEqual(record["at"], 915148800)
        for date in (b"Date: 01 Jan 1999 00:00:00", b"Date: invalid", b""):
            record = (
                await self.read(FakeIMAP(header=date + b"\r\n\r\n", internal=None))
            )[0]
            self.assertIsNone(record["at"])

    async def test_internaldate_offset_ignores_host_timezone(self):
        record = (await self.read(FakeIMAP(internal=b"15-Nov-2023 06:13:20 +0800")))[0]
        self.assertEqual(record["at"], NOW)

    async def test_no_body_is_in_record_even_if_server_supplies_trailing_body(self):
        record = (await self.read(FakeIMAP(header=HEADER + b"SECRET BODY")))[0]
        self.assertNotIn("SECRET BODY", repr(record))

    async def test_login_exception_is_sanitized_and_connection_closed(self):
        fake = FakeIMAP()
        fake.login = Mock(
            side_effect=imaplib.IMAP4.error("fake-password PRIVATE SUBJECT")
        )
        with self.assertRaisesRegex(SourceError, "^mail:login_failed$"):
            await self.read(fake)
        self.assertTrue(fake.closed)

    async def test_non_ok_error_is_sanitized(self):
        fake = FakeIMAP()
        fake.uid = Mock(return_value=("NO", [b"PRIVATE SUBJECT fake-password"]))
        with self.assertRaisesRegex(SourceError, "^mail:search_failed$"):
            await self.read(fake)

    async def test_count_limit_rejects_before_any_fetch(self):
        fake = FakeIMAP(uids=b" ".join(str(i).encode() for i in range(1, 502)))
        with self.assertRaisesRegex(SourceError, "header_count_limit"):
            await self.read(fake)
        self.assertFalse(any(call[0] == "FETCH" for call in fake.calls))

    async def test_count_limit_applies_across_folders(self):
        self.source.folders = ["INBOX", "Archive"]
        self.source.max_headers = 1
        with self.assertRaisesRegex(SourceError, "header_count_limit"):
            await self.read(FakeIMAP())

    async def test_invalid_uids_and_uidvalidity_fail_closed(self):
        for uids in (b"1 1", b"0", b"1\r\nFETCH", b"99999999999"):
            with self.assertRaises(SourceError):
                await self.read(FakeIMAP(uids=uids))
        for validity in (b"0", b"private message", b"99999999999"):
            with self.assertRaisesRegex(SourceError, "uidvalidity_invalid"):
                await self.read(FakeIMAP(validity=validity))

    async def test_header_size_and_uid_mismatch_fail_closed(self):
        with self.assertRaisesRegex(SourceError, "header_limit"):
            await self.read(FakeIMAP(header=b"x" * (MAX_HEADER_BYTES + 1)))
        fake = FakeIMAP()
        original = fake.uid

        def wrong_uid(name, *args):
            if name == "FETCH":
                return "OK", [(b"1 (UID 2 BODY[HEADER] {5}", b"\r\n\r\n"), b")"]
            return original(name, *args)

        fake.uid = wrong_uid
        with self.assertRaisesRegex(SourceError, "fetch_uid_invalid"):
            await self.read(fake)

    async def test_empty_mailbox_is_successful(self):
        self.assertEqual(await self.read(FakeIMAP(uids=b"")), [])

    async def test_invalid_poll_time_is_sanitized(self):
        for value in (float("nan"), float("inf"), "private", True):
            with self.assertRaisesRegex(SourceError, "time_invalid"):
                await self.source.snapshot(value)

    async def test_timeout_is_sanitized(self):
        with patch(
            "dot_feishu.mail_source.asyncio.wait_for", side_effect=asyncio.TimeoutError
        ):
            # Close the unscheduled coroutine to avoid a test-only warning.
            with patch(
                "dot_feishu.mail_source.asyncio.to_thread", new=Mock(return_value=None)
            ):
                with self.assertRaisesRegex(SourceError, "^mail:timeout$"):
                    await self.source.snapshot(NOW)


class CredentialAndBoundTests(unittest.TestCase):
    def test_only_private_regular_file_under_run_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "password"
            path.write_text("fake-password\n")
            path.chmod(0o600)
            source = MailSource("imap.example.test", "user", str(path))
            with self.assertRaisesRegex(SourceError, "credential_file"):
                source._password()
            with patch("dot_feishu.mail_source.PASSWORD_ROOT", directory):
                self.assertEqual(source._password(), "fake-password")
                path.chmod(0o644)
                with self.assertRaisesRegex(SourceError, "credential_file"):
                    source._password()
                path.chmod(0o600)
                link = Path(directory) / "link"
                link.symlink_to(path)
                linked = MailSource("imap.example.test", "user", str(link))
                with self.assertRaisesRegex(SourceError, "credential_file"):
                    linked._password()

    def test_large_literal_rejected_before_read(self):
        client = object.__new__(_BoundedIMAP4SSL)
        with patch.object(imaplib.IMAP4_SSL, "read") as read:
            with self.assertRaisesRegex(SourceError, "literal_limit"):
                client.read(MAX_HEADER_BYTES + 2)
            read.assert_not_called()

    def test_response_budget_rejects_excessive_multiple_literals(self):
        client = object.__new__(_BoundedIMAP4SSL)
        client.response_bytes = 2 * MAX_HEADER_BYTES
        with self.assertRaisesRegex(SourceError, "response_limit"):
            client._charge(b"x")

    def test_invalid_configuration_never_echoes_values(self):
        for kwargs in (
            {"host": "private\nsubject"},
            {"username": "private\x00subject"},
            {"folders": ["private\r\nsubject"]},
            {"max_headers": 501},
        ):
            args = {
                "host": "imap.example.test",
                "username": "user",
                "password_file": "/run/example",
                **kwargs,
            }
            with self.assertRaises(ValueError) as caught:
                MailSource(**args)
            self.assertNotIn("private", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
