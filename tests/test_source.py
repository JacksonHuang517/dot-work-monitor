import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from dot_feishu.source import LarkSource, SourceError


def envelope(data, **extra):
    return {"ok": True, "identity": "user", "data": data, **extra}


def page(items, key="items", token=None):
    return envelope(
        {key: items, "has_more": token is not None, "page_token": token or ""}
    )


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0, hang=False):
        self.stdout, self.stderr = asyncio.StreamReader(), asyncio.StreamReader()
        self.returncode = None if hang else returncode
        self.killed = False
        self.stdout.feed_data(stdout)
        self.stderr.feed_data(stderr)
        if not hang:
            self.stdout.feed_eof()
            self.stderr.feed_eof()

    async def wait(self):
        if self.returncode is None:
            await asyncio.Future()
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.stdout.feed_eof()
        self.stderr.feed_eof()


class SourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_bound_source_verifies_raw_whoami_before_data_reads(self):
        source = LarkSource(
            [],
            [],
            expected_open_id="ou_fixture_owner",
            expected_app_id="cli_fixture_app",
        )
        source._run = AsyncMock(side_effect=[page([]), envelope({"items": []})])
        identity = {
            "identity": "user",
            "appId": "cli_fixture_app",
            "onBehalfOf": {"openId": "ou_fixture_owner"},
        }
        process = FakeProcess(json.dumps(identity).encode())
        with patch(
            "dot_feishu.source.asyncio.create_subprocess_exec",
            AsyncMock(return_value=process),
        ) as spawn:
            self.assertEqual(await source.snapshot(1700000000), [])
        self.assertEqual(spawn.call_args.args, ("lark-cli", "whoami", "--as", "user"))
        self.assertEqual(spawn.call_args.kwargs["env"]["TZ"], "UTC")
        self.assertEqual(source._run.await_count, 2)
        self.assertEqual(source.IDENTITY_TIMEOUT, 10)

    async def test_owner_app_bot_or_malformed_identity_blocks_all_data_reads(self):
        valid = {
            "identity": "user",
            "appId": "cli_fixture_app",
            "onBehalfOf": {"openId": "ou_fixture_owner"},
        }
        invalid = [
            {**valid, "onBehalfOf": {"openId": "ou_different_fixture"}},
            {**valid, "appId": "cli_different_fixture"},
            {**valid, "identity": "bot"},
            {**valid, "onBehalfOf": None},
            {**valid, "onBehalfOf": {}},
            {**valid, "onBehalfOf": "private fixture metadata"},
            {**valid, "ok": False},
            envelope(valid),
            [],
            None,
        ]
        for identity in invalid:
            source = LarkSource(
                ["*"],
                [],
                expected_open_id="ou_fixture_owner",
                expected_app_id="cli_fixture_app",
            )
            source._run = AsyncMock()
            process = FakeProcess(json.dumps(identity).encode())
            with patch(
                "dot_feishu.source.asyncio.create_subprocess_exec",
                AsyncMock(return_value=process),
            ):
                with self.assertRaises(SourceError) as caught:
                    await source.snapshot(1700000000)
            source._run.assert_not_awaited()
            for metadata in (
                "ou_fixture_owner",
                "cli_fixture_app",
                "different_fixture",
                "private fixture",
            ):
                self.assertNotIn(metadata, str(caught.exception))

    async def test_identity_is_rechecked_on_every_snapshot(self):
        source = LarkSource(
            [],
            [],
            expected_open_id="ou_fixture_owner",
            expected_app_id="cli_fixture_app",
        )
        source._run = AsyncMock(side_effect=[page([]), envelope({"items": []})])
        identities = [
            {
                "identity": "user",
                "appId": "cli_fixture_app",
                "onBehalfOf": {"openId": "ou_fixture_owner"},
            },
            {
                "identity": "user",
                "appId": "cli_fixture_app",
                "onBehalfOf": {"openId": "ou_changed_fixture"},
            },
        ]
        processes = [
            FakeProcess(json.dumps(identity).encode()) for identity in identities
        ]
        with patch(
            "dot_feishu.source.asyncio.create_subprocess_exec",
            AsyncMock(side_effect=processes),
        ) as spawn:
            await source.snapshot(1700000000)
            with self.assertRaises(SourceError):
                await source.snapshot(1700000300)
        self.assertEqual(spawn.await_count, 2)
        self.assertEqual(source._run.await_count, 2)

    async def test_identity_cli_failures_are_sanitized_before_data_read(self):
        for process in [
            FakeProcess(b"private fixture stdout", b"private fixture stderr"),
            FakeProcess(b"{}", b"private fixture stderr", returncode=1),
        ]:
            source = LarkSource([], [], expected_open_id="ou_fixture_owner")
            source._run = AsyncMock()
            with patch(
                "dot_feishu.source.asyncio.create_subprocess_exec",
                AsyncMock(return_value=process),
            ):
                with self.assertRaises(SourceError) as caught:
                    await source.snapshot(1700000000)
            source._run.assert_not_awaited()
            self.assertNotIn("private", str(caught.exception))

    async def test_identity_timeout_and_output_limit_kill_cli(self):
        for oversized in (False, True):
            source = LarkSource([], [], expected_app_id="cli_fixture_app")
            source.IDENTITY_TIMEOUT = 0.01
            source.MAX_OUTPUT_BYTES = 3
            source._run = AsyncMock()
            process = FakeProcess(b"oversized fixture" if oversized else b"", hang=True)
            with patch(
                "dot_feishu.source.asyncio.create_subprocess_exec",
                AsyncMock(return_value=process),
            ):
                with self.assertRaises(SourceError):
                    await source.snapshot(1700000000)
            self.assertTrue(process.killed)
            source._run.assert_not_awaited()

    async def test_unconfigured_constructor_keeps_low_level_behavior(self):
        source = LarkSource([], [])
        source._exec = AsyncMock()
        source._run = AsyncMock(side_effect=[page([]), envelope({"items": []})])
        self.assertEqual(await source.snapshot(1700000000), [])
        source._exec.assert_not_awaited()

    async def test_expected_identity_configuration_validation(self):
        for expected in ("", "  ", 123, "invalid\x00fixture"):
            with self.assertRaises(ValueError):
                LarkSource([], [], expected_open_id=expected)
            with self.assertRaises(ValueError):
                LarkSource([], [], expected_app_id=expected)

    async def test_normalized_snapshot_and_strict_scope(self):
        source = LarkSource(["oc_allowed"], [])
        message = {
            "message_id": "om_example",
            "msg_type": "text",
            "content": "fixture text",
            "sender": {"name": "Example"},
            "create_time": "1700000000000",
            "deleted": False,
        }
        task = {
            "guid": "task-example",
            "summary": "fixture task",
            "description": "fixture detail",
            "due": {"timestamp": "1700000100000"},
            "status": "todo",
            "completed_at": "0",
        }
        event = {
            "event_id": "event-example_1700000200",
            "summary": "fixture event",
            "start_time": {"timestamp": "1700000200"},
            "status": "confirmed",
        }
        source._run = AsyncMock(
            side_effect=[
                page([message], "messages"),
                page([task]),
                envelope({"items": [event]}),
            ]
        )
        records = await source.snapshot(1700000000)
        self.assertEqual([r["kind"] for r in records], ["message", "task", "calendar"])
        self.assertEqual(
            [r["at"] for r in records], [1700000000, 1700000100, 1700000200]
        )
        self.assertEqual(records[0]["raw"]["chat_id"], "oc_allowed")
        self.assertEqual(records[2]["raw"]["calendar_id"], "primary")
        self.assertEqual(
            set(records[0]),
            {"kind", "id", "revision", "title", "text", "url", "at", "raw"},
        )
        args = source._run.call_args_list[0].args[0]
        self.assertEqual(args[args.index("--chat-id") + 1], "oc_allowed")
        self.assertIn("2023-11-14T21:58:20+00:00", args)
        task_args = source._run.call_args_list[1].args[0]
        params = json.loads(task_args[task_args.index("--params") + 1])
        self.assertEqual(
            params, {"completed": False, "type": "my_tasks", "page_size": 100}
        )
        calendar_args = source._run.call_args_list[2].args[0]
        self.assertEqual(
            calendar_args[calendar_args.index("--end-time") + 1], "1700172800"
        )

    async def test_no_chats_means_no_message_reads(self):
        source = LarkSource([], [])
        source._run = AsyncMock(side_effect=[page([]), envelope({"items": []})])
        self.assertEqual(await source.snapshot(1700000000), [])
        self.assertEqual(source._run.call_count, 2)
        self.assertTrue(
            all("im" not in call.args[0] for call in source._run.call_args_list)
        )

    async def test_pages_are_followed_and_cursor_is_passed(self):
        source = LarkSource([], [])
        source._run = AsyncMock(
            side_effect=[page([{"guid": "a"}], token="next"), page([{"guid": "b"}])]
        )
        values = await source._pages(["task", "tasks", "list"], "items")
        self.assertEqual([value["guid"] for value in values], ["a", "b"])
        self.assertEqual(
            source._run.call_args_list[1].args[0][-2:], ["--page-token", "next"]
        )

    async def test_incomplete_page_fails_closed(self):
        source = LarkSource([], [])
        for response in [
            envelope({"items": [], "has_more": True}),
            envelope({"items": []}),
        ]:
            source._run = AsyncMock(return_value=response)
            with self.assertRaises(SourceError):
                await source._pages(["task", "tasks", "list"], "items")

    async def test_repeated_cursor_and_page_limit_fail(self):
        source = LarkSource([], [])
        source._run = AsyncMock(return_value=page([], token="repeated"))
        with self.assertRaisesRegex(SourceError, "did not advance"):
            await source._pages([], "items")
        source.MAX_PAGES = 1
        with self.assertRaisesRegex(SourceError, "page limit"):
            await source._pages([], "items")

    async def test_record_limit_fails(self):
        source = LarkSource([], [])
        source.MAX_RECORDS = 1
        source._run = AsyncMock(return_value=page([{}, {}]))
        with self.assertRaisesRegex(SourceError, "record limit"):
            await source._pages([], "items")

    async def test_completion_recall_and_cancellation_are_omitted(self):
        source = LarkSource(["oc_example"], [])
        source._run = AsyncMock(
            side_effect=[
                page([{"deleted": True}], "messages"),
                page([{"status": "done"}, {"completed_at": "1234"}]),
                envelope({"items": [{"status": "cancelled"}]}),
            ]
        )
        self.assertEqual(await source.snapshot(1700000000), [])

    async def test_calendar_incomplete_is_rejected(self):
        source = LarkSource([], [])
        source._run = AsyncMock(
            side_effect=[
                page([]),
                envelope({"items": [], "has_more": True, "page_token": "x"}),
            ]
        )
        with self.assertRaisesRegex(SourceError, "incomplete"):
            await source.snapshot(1700000000)

    async def test_meta_pagination_is_supported(self):
        self.assertEqual(
            LarkSource._next(
                envelope(
                    {"items": []},
                    meta={"pagination": {"complete": False, "next_token": "next"}},
                )
            ),
            "next",
        )
        self.assertIsNone(
            LarkSource._next(
                envelope({"items": []}, meta={"pagination": {"complete": True}})
            )
        )

    async def test_revision_tracks_content_not_query_or_ephemeral_fields(self):
        task = {
            "guid": "task-example",
            "summary": "fixture",
            "due": {"timestamp": "1700000000000"},
        }
        first = LarkSource._record("task", task)
        self.assertEqual(
            first["revision"],
            LarkSource._record("task", {**task, "attachments": [{"url": "temporary"}]})[
                "revision"
            ],
        )
        self.assertNotEqual(
            first["revision"],
            LarkSource._record("task", {**task, "summary": "changed"})["revision"],
        )

    async def test_timezone_and_missing_task_due(self):
        self.assertEqual(
            LarkSource._timestamp({"date": "2023-11-14", "timezone": "UTC"}), 1699920000
        )
        self.assertEqual(LarkSource._timestamp("2023-11-14T22:13:20+00:00"), 1700000000)
        self.assertIsNone(LarkSource._record("task", {"guid": "task-example"})["at"])
        for invalid in ["2023-11-14T22:13:20", "private fixture", float("nan"), True]:
            with self.assertRaises(SourceError):
                LarkSource._timestamp(invalid)

    async def test_success_requires_true_and_user_identity(self):
        source = LarkSource([], [])
        responses = [
            {"code": 0},
            {"ok": 1, "identity": "user", "data": {}},
            {"ok": True, "identity": "bot", "data": {}},
            {"ok": True, "identity": "user", "data": {}, "dry_run": True},
            {"ok": True, "identity": "user", "data": []},
        ]
        for response in responses:
            process = FakeProcess(json.dumps(response).encode())
            with patch(
                "dot_feishu.source.asyncio.create_subprocess_exec",
                AsyncMock(return_value=process),
            ):
                with self.assertRaises(SourceError):
                    await source._run(["task", "tasks", "list"])

    async def test_spawn_is_shell_free_and_user_json_forced(self):
        source = LarkSource([], [], cli="/example/lark-cli")
        process = FakeProcess(json.dumps(envelope({})).encode())
        with patch(
            "dot_feishu.source.asyncio.create_subprocess_exec",
            AsyncMock(return_value=process),
        ) as spawn:
            self.assertEqual(await source._run(["task", "tasks", "list"]), envelope({}))
            self.assertEqual(
                spawn.call_args.args,
                (
                    "/example/lark-cli",
                    "task",
                    "tasks",
                    "list",
                    "--as",
                    "user",
                    "--format",
                    "json",
                ),
            )
            self.assertEqual(
                spawn.call_args.kwargs["stdin"], asyncio.subprocess.DEVNULL
            )
            self.assertEqual(spawn.call_args.kwargs["env"]["TZ"], "UTC")

    async def test_official_cli_message_minute_format_is_explicit_utc(self):
        message = {"message_id": "om_example", "create_time": "2023-11-14 22:13"}
        self.assertEqual(LarkSource._record("message", message)["at"], 1699999980)
        message["create_time"] = "2023-11-14 22:13:20"
        self.assertEqual(LarkSource._record("message", message)["at"], 1700000000)
        # Only the CLI message formatter receives this interpretation.
        with self.assertRaises(SourceError):
            LarkSource._timestamp("2023-11-14 22:13")

    async def test_errors_never_include_stdout_or_stderr(self):
        source = LarkSource([], [])
        private = b"fixture-private-token-content"
        for process in [
            FakeProcess(private, private),
            FakeProcess(private, private, returncode=1),
        ]:
            with patch(
                "dot_feishu.source.asyncio.create_subprocess_exec",
                AsyncMock(return_value=process),
            ):
                with self.assertRaises(SourceError) as caught:
                    await source._run([])
                self.assertNotIn(private.decode(), str(caught.exception))

    async def test_oversized_output_and_timeout_kill_process(self):
        source = LarkSource([], [])
        source.MAX_OUTPUT_BYTES = 3
        process = FakeProcess(b"oversized", hang=True)
        with patch(
            "dot_feishu.source.asyncio.create_subprocess_exec",
            AsyncMock(return_value=process),
        ):
            with self.assertRaisesRegex(SourceError, "output limit"):
                await source._run([])
        self.assertTrue(process.killed)
        source.COMMAND_TIMEOUT = 0.01
        process = FakeProcess(hang=True)
        with patch(
            "dot_feishu.source.asyncio.create_subprocess_exec",
            AsyncMock(return_value=process),
        ):
            with self.assertRaisesRegex(SourceError, "timed out"):
                await source._run([])
        self.assertTrue(process.killed)

    async def test_missing_executable_is_sanitized(self):
        source = LarkSource([], [])
        with patch(
            "dot_feishu.source.asyncio.create_subprocess_exec",
            AsyncMock(side_effect=FileNotFoundError("private path")),
        ):
            with self.assertRaisesRegex(SourceError, "could not start") as caught:
                await source._run([])
        self.assertNotIn("private", str(caught.exception))

    async def test_probe_returns_metadata_only(self):
        source = LarkSource([], [])
        source.snapshot = AsyncMock(
            return_value=[{"kind": "task", "text": "private fixture"}]
        )
        result = await source.probe()
        self.assertEqual(result["counts"], {"message": 0, "task": 1, "calendar": 0})
        self.assertNotIn("private", json.dumps(result))

    async def test_invalid_shapes_and_identifiers(self):
        for values in [[""], [None], "oc_example"]:
            with self.assertRaises(ValueError):
                LarkSource(values, [])
        with self.assertRaises(SourceError):
            LarkSource._items(envelope({"items": ["bad"]}), "items")
        with self.assertRaises(SourceError):
            LarkSource._record("task", {})
        with self.assertRaises(ValueError):
            await LarkSource([], []).snapshot(float("inf"))

    async def test_wildcard_global_search_paginates_without_chat_enumeration(self):
        source = LarkSource(["*"], [])
        source._run = AsyncMock(
            side_effect=[
                page(
                    [
                        {
                            "message_id": "om_one",
                            "chat_id": "oc_p2p",
                            "content": "fixture one",
                        }
                    ],
                    "messages",
                    token="next",
                ),
                page(
                    [
                        {
                            "message_id": "om_two",
                            "chat_id": "oc_group",
                            "content": "fixture two",
                        }
                    ],
                    "messages",
                ),
                page([]),
                envelope({"items": []}),
            ]
        )
        records = await source.snapshot(1700000000)
        self.assertEqual([record["id"] for record in records], ["om_one", "om_two"])
        self.assertEqual(
            [record["raw"]["chat_id"] for record in records], ["oc_p2p", "oc_group"]
        )
        first_args = source._run.call_args_list[0].args[0]
        self.assertEqual(first_args[:2], ["im", "+messages-search"])
        self.assertEqual(first_args[first_args.index("--query") + 1], "")
        self.assertEqual(first_args[first_args.index("--page-size") + 1], "50")
        self.assertIn("--no-reactions", first_args)
        self.assertIn("2023-11-14T21:58:20+00:00", first_args)
        self.assertIn("2023-11-14T22:13:20+00:00", first_args)
        self.assertEqual(
            source._run.call_args_list[1].args[0][-2:], ["--page-token", "next"]
        )
        for call in source._run.call_args_list:
            self.assertNotIn("+chat-list", call.args[0])
            self.assertNotIn("+chat-messages-list", call.args[0])

    async def test_global_search_incomplete_fails_before_other_source_reads(self):
        source = LarkSource(["*"], [])
        source._run = AsyncMock(
            return_value=envelope({"messages": [], "has_more": True})
        )
        with self.assertRaises(SourceError):
            await source.snapshot(1700000000)
        self.assertEqual(source._run.call_count, 1)

    async def test_global_search_requires_context_and_omits_recalls(self):
        source = LarkSource(["*"], [])
        source._run = AsyncMock(
            return_value=page([{"message_id": "om_example"}], "messages")
        )
        with self.assertRaisesRegex(SourceError, "conversation context"):
            await source.snapshot(1700000000)
        source._run = AsyncMock(
            side_effect=[
                page([{"deleted": True}], "messages"),
                page([]),
                envelope({"items": []}),
            ]
        )
        self.assertEqual(await source.snapshot(1700000000), [])

    async def test_discovery_cache_contains_ids_only_and_refreshes_after_hour(self):
        source = LarkSource(["*"], [])
        source._run = AsyncMock(
            side_effect=[
                page([{"chat_id": "oc_one", "name": "private fixture"}], "chats"),
                page([{"chat_id": "oc_two"}], "chats"),
            ]
        )
        self.assertEqual(await source._watched_chats(10000), ["oc_one"])
        self.assertEqual(await source._watched_chats(13599), ["oc_one"])
        self.assertEqual(source._run.call_count, 1)
        self.assertEqual(source._chat_cache, ["oc_one"])
        self.assertEqual(await source._watched_chats(13600), ["oc_two"])
        self.assertEqual(source._run.call_count, 2)

    async def test_discovery_cap_is_visible_and_never_silently_truncates(self):
        source = LarkSource(["*"], [], max_chats=1)
        source._run = AsyncMock(
            return_value=page([{"chat_id": "oc_one"}, {"chat_id": "oc_two"}], "chats")
        )
        with self.assertRaisesRegex(SourceError, "record limit"):
            await source._watched_chats(10000)
        self.assertIsNone(source._chat_cache)

    async def test_discovery_incomplete_does_not_replace_or_use_stale_cache(self):
        source = LarkSource(["*"], [])
        source._run = AsyncMock(
            side_effect=[
                page([{"chat_id": "oc_one"}], "chats"),
                envelope({"chats": [{"chat_id": "oc_two"}], "has_more": True}),
            ]
        )
        await source._watched_chats(10000)
        with self.assertRaises(SourceError):
            await source._watched_chats(13600)
        self.assertEqual(source._chat_cache, ["oc_one"])
        self.assertEqual(source._chat_cache_at, 10000)

    async def test_discovery_invalid_chat_is_rejected(self):
        source = LarkSource(["*"], [])
        source._run = AsyncMock(return_value=page([{"name": "fixture"}], "chats"))
        with self.assertRaisesRegex(SourceError, "without an identifier"):
            await source._watched_chats(10000)

    async def test_wildcard_probe_reports_effective_coverage(self):
        source = LarkSource(["*"], [])
        source._run = AsyncMock(
            side_effect=[page([], "messages"), page([]), envelope({"items": []})]
        )
        result = await source.probe()
        self.assertEqual(result["coverage_mode"], "global_search")
        self.assertIsNone(result["watched_chat_count"])
        self.assertTrue(result["message_indexing_delay_possible"])
        self.assertEqual(source._run.call_count, 3)

    async def test_configurable_lookback_uses_requested_window(self):
        source = LarkSource(["oc_example"], [], lookback_seconds=1800)
        source._run = AsyncMock(
            side_effect=[page([], "messages"), page([]), envelope({"items": []})]
        )
        await source.snapshot(1700000000)
        self.assertIn(
            "2023-11-14T21:43:20+00:00", source._run.call_args_list[0].args[0]
        )

    async def test_fractional_snapshot_clock_uses_api_compatible_whole_seconds(self):
        # Reproduced against Feishu: fractional ISO timestamps return 99992402;
        # the identical empty-query/time-only search succeeds at whole seconds.
        for chats in (["*"], ["oc_example"]):
            source = LarkSource(chats, [])
            source._run = AsyncMock(
                side_effect=[page([], "messages"), page([]), envelope({"items": []})]
            )
            await source.snapshot(1700000000.123456)
            args = source._run.call_args_list[0].args[0]
            self.assertEqual(
                args[args.index("--start") + 1], "2023-11-14T21:58:20+00:00"
            )
            self.assertEqual(args[args.index("--end") + 1], "2023-11-14T22:13:20+00:00")

    async def test_discovery_config_validation(self):
        for kwargs in [
            {"max_chats": 0},
            {"max_chats": 1001},
            {"max_chats": True},
            {"lookback_seconds": 899},
            {"lookback_seconds": True},
        ]:
            with self.assertRaises(ValueError):
                LarkSource(["*"], [], **kwargs)
        with self.assertRaises(ValueError):
            LarkSource(["*", "oc_example"], [])
        with self.assertRaises(ValueError):
            LarkSource(["oc_one", "oc_two"], [], max_chats=1)


if __name__ == "__main__":
    unittest.main()
