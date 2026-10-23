from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path

from support import PROJECT, Config, Observer, ObserverCase, PRIVATE, SECRET, event, jsonl, metadata, write


class SessionTests(ObserverCase):
    def test_internal_channel_metadata_is_refused_before_title_search_or_output(self):
        for location in ("event", "payload"):
            meta = metadata("meta-channel", self.extra, title=PRIVATE)
            (meta if location == "event" else meta["payload"])["channel"] = "analysis"
            jsonl(self.extra / "meta-channel.jsonl", [meta])
            for tool, args in (
                ("session_list", {"sources": ["cases"]}),
                ("session_read", {"source": "cases", "session_id": "meta-channel"}),
                ("session_search", {"sources": ["cases"], "query": PRIVATE}),
                ("session_state", {"source": "cases", "session_id": "meta-channel"}),
            ):
                self.assertEqual(self.denied(tool, **args)["error"], "invalid_session_metadata")

    def test_internal_channels_are_omitted_before_search_state_and_call_pairing(self):
        records = [metadata("channels", self.extra)]
        for channel in ("analysis", "reasoning", "internal", "justify", "future_private", {}, ["analysis"]):
            records.extend([
                event("response_item", {"type": "message", "role": "assistant", "channel": channel,
                      "content": [{"type": "output_text", "text": PRIVATE}]}),
                event("event_msg", {"type": "agent_message", "channel": channel, "message": PRIVATE}),
                {**event("execution", {"call_id": "hidden-call", "command": PRIVATE, "exit_code": 0}), "channel": channel},
                event("event_msg", {"type": "turn_completed", "channel": channel}),
            ])
        records.extend([
            event("response_item", {"type": "function_call_output", "call_id": "hidden-call", "output": PRIVATE}),
            event("response_item", {"type": "message", "role": "assistant", "channel": "final",
                  "content": [{"type": "output_text", "text": "public final"},
                              {"type": "output_text", "channel": "analysis", "text": PRIVATE}]}),
            event("event_msg", {"type": "agent_message", "channel": "commentary", "message": "public commentary"}),
        ])
        jsonl(self.extra / "channels.jsonl", records)
        read = self.good("session_read", source="cases", session_id="channels")
        self.assertEqual([item["text"] for item in read["events"]], ["public final", "public commentary"])
        self.assertEqual(self.good("session_search", sources=["cases"], query=PRIVATE)["matches"], [])
        state = self.good("session_state", source="cases", session_id="channels")
        self.assertEqual(state["state"], "unknown")
        self.assertIsNone(state["last_explicit_lifecycle"])

    def test_multifile_session_search_uses_one_global_byte_budget_without_loss(self):
        for source_index in range(3):
            records = [metadata("page-" + str(source_index), self.extra)]
            records.extend(event("event_msg", {"type": "user_message", "message": "public-match " + str(i) + " " + "x" * 2800}) for i in range(10))
            jsonl(self.extra / (str(source_index) + ".jsonl"), records)
        cursor, seen, page_count = None, [], 0
        for _ in range(10):
            args = {"sources": ["cases"], "query": "public-match", "limit": 50}
            if cursor:
                args["cursor"] = cursor
            page = self.good("session_search", **args)
            page_count += 1
            self.assertTrue(page["matches"], "empty page failed to make output progress")
            seen.extend((item["evidence"]["path"], item["evidence"]["line"]) for item in page["matches"])
            cursor = page["next_cursor"]
            if not cursor:
                break
        self.assertIsNone(cursor)
        self.assertGreater(page_count, 1)
        self.assertEqual(len(seen), 30)
        self.assertEqual(len(set(seen)), 30)

    def test_session_search_scan_budget_paginates_even_without_matches(self):
        for i in range(20):
            jsonl(self.extra / (f"{i:02d}.jsonl"), [metadata("scan-" + str(i), self.extra),
                  event("event_msg", {"type": "user_message", "message": "x" * 230000})])
        first = self.good("session_search", sources=["cases"], query="absent-public-query")
        self.assertEqual(first["matches"], [])
        self.assertIsNotNone(first["next_cursor"])
        second = self.good("session_search", sources=["cases"], query="absent-public-query", cursor=first["next_cursor"])
        self.assertEqual(second["matches"], [])
        self.assertIsNone(second["next_cursor"])

    def test_session_search_skips_pending_tail_and_continues_finite_pass(self):
        jsonl(self.extra / "a-partial.jsonl", [metadata("partial-first", self.extra),
              event("event_msg", {"type": "user_message", "message": "visible-before-pending"})],
              b'{"type":"event_msg","payload":')
        jsonl(self.extra / "b-later.jsonl", [metadata("later-session", self.extra),
              event("event_msg", {"type": "user_message", "message": "target-after-partial"})])

        earlier = self.good("session_search", sources=["cases"], query="visible-before-pending")
        self.assertEqual([item["text"] for item in earlier["matches"]], ["visible-before-pending"])
        self.assertIsNone(earlier["next_cursor"])

        later = self.good("session_search", sources=["cases"], query="target-after-partial")
        self.assertEqual([item["text"] for item in later["matches"]], ["target-after-partial"])
        self.assertIsNone(later["next_cursor"])

        absent = self.good("session_search", sources=["cases"], query="no-such-public-text")
        self.assertEqual(absent["matches"], [])
        self.assertIsNone(absent["next_cursor"])

    def test_long_shell_commands_keep_fixed_size_cursor_and_cross_page_pairing(self):
        records = [metadata("long-commands", self.extra)]
        for i in range(4):
            records.append(event("response_item", {"type": "function_call", "name": "exec_command", "call_id": "long-" + str(i),
                           "arguments": json.dumps({"cmd": "echo " + "\x01" * 2000})}))
        for i in range(4):
            records.append(event("response_item", {"type": "function_call_output", "call_id": "long-" + str(i),
                           "output": {"exit_code": 0, "output": "public result"}}))
        jsonl(self.extra / "long-commands.jsonl", records)
        first = self.good("session_read", source="cases", session_id="long-commands", limit=4)
        self.assertEqual(len(first["events"]), 4)
        self.assertEqual(len(first["next_cursor"]), 46)
        second = self.good("session_read", source="cases", session_id="long-commands", limit=4, cursor=first["next_cursor"])
        self.assertTrue(second["at_eof"])
        self.assertEqual(len(second["next_cursor"]), 46)
        self.assertEqual([item["call_id"] for item in second["events"]], ["long-" + str(i) for i in range(4)])
        self.assertTrue(all(item["command"] and item["exit_status"] == 0 for item in second["events"]))

    def test_exact_metadata_ids_not_filenames_or_rollout_path(self):
        result = self.good("session_list", sources=["synthetic"])
        ids = {s["session_id"] for s in result["sessions"]}
        self.assertIn("synth-main", ids)
        self.assertIn("synth-archive", ids)
        for sid in ("synth", "main", "filename-is-not-the-id"):
            self.assertEqual(self.denied("session_read", source="synthetic", session_id=sid)["error"], "session_not_found")
        good = self.good("session_read", source="synthetic", session_id="synth-main")
        self.assertEqual(good["metadata"]["session_id"], "synth-main")

    def test_archive_discovery_and_pagination(self):
        cursor, ids = None, []
        for _ in range(20):
            args = {"sources": ["synthetic"], "limit": 1}
            if cursor:
                args["cursor"] = cursor
            page = self.good("session_list", **args)
            ids += [s["session_id"] for s in page["sessions"]]
            cursor = page["next_cursor"]
            if not cursor:
                break
        self.assertEqual(len(ids), len(set(ids)))
        archived = self.good("session_read", source="synthetic", session_id="synth-archive")
        self.assertEqual(archived["metadata"]["storage"], "archived")

    def test_direct_archive_root_labels_storage_without_establishing_activity(self):
        for name in ("archived_sessions", "archived"):
            with self.subTest(root=name):
                root = self.extra / name
                jsonl(root / "direct.jsonl", [metadata("direct-archive", self.extra)])
                config = Config(PROJECT, {"workspaces": {}, "sessions": {"history": str(root)},
                                          "strict_hardlinks": True})
                self.addCleanup(config.close)
                self.observer = Observer(config)
                listed = self.good("session_list", sources=["history"])["sessions"]
                self.assertEqual(len(listed), 1)
                self.assertEqual(listed[0]["storage"], "archived")
                read = self.good("session_read", source="history", session_id="direct-archive")
                self.assertEqual(read["metadata"]["path"], "direct.jsonl")
                self.assertEqual(read["metadata"]["storage"], "archived")
                self.assertEqual(read["metadata"]["activity_authority"], "unavailable_passive_jsonl")
                state = self.good("session_state", source="history", session_id="direct-archive")
                self.assertEqual(state["state"], "unknown")
                self.assertIsNone(state["last_explicit_lifecycle"])
                self.assertEqual(state["task_verified"], "unknown")
                self.assertEqual(state["authoritative_current_activity"], "unavailable_passive_jsonl")

    def test_nested_archive_directory_conventions(self):
        for name in ("archived", "archived_sessions"):
            with self.subTest(directory=name):
                sid = "nested-" + name
                jsonl(self.extra / "older" / name / "direct.jsonl", [metadata(sid, self.extra)])
                read = self.good("session_read", source="cases", session_id=sid)
                self.assertEqual(read["metadata"]["storage"], "archived")

    def test_archive_alias_ancestors_substrings_and_content_do_not_label_active_storage(self):
        root = self.extra / "archived" / "archived_sessions" / "active_archived_sessions"
        paths = ("direct.jsonl", "archived.jsonl", "archived_sessions.jsonl", "contains-archived_sessions.jsonl",
                 "not_archived/direct.jsonl", "archived_sessions_backup/direct.jsonl")
        now = datetime.now(timezone.utc).isoformat()
        for index, path in enumerate(paths):
            meta = metadata("active-" + str(index), self.extra / "archived_sessions", title="archived and completed")
            meta["timestamp"] = now
            jsonl(root / path, [meta, event("event_msg", {"type": "agent_message", "message": "archived; all tasks complete"}, now)])
        config = Config(PROJECT, {"workspaces": {}, "sessions": {"archived_sessions": str(root)},
                                  "strict_hardlinks": True})
        self.addCleanup(config.close)
        self.observer = Observer(config)
        listed = self.good("session_list", sources=["archived_sessions"])["sessions"]
        self.assertEqual(len(listed), len(paths))
        self.assertTrue(all(item["storage"] == "active_directory" for item in listed))
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                read = self.good("session_read", source="archived_sessions", session_id="active-" + str(index))
                self.assertEqual(read["metadata"]["storage"], "active_directory")

    def test_projection_omits_reasoning_unknown_events_environment(self):
        result = self.good("session_read", source="synthetic", session_id="synth-main")
        self.assertGreaterEqual(result["omitted_nonprojected_records"], 4)
        self.assertTrue("environment" not in json.dumps(result))
        self.assertTrue(all(e["kind"] in {"message", "execution", "lifecycle"} for e in result["events"]))

    def test_execution_evidence_and_cross_page_call_pairing(self):
        cursor, events = None, []
        for _ in range(20):
            args = {"source": "synthetic", "session_id": "synth-main", "limit": 1}
            if cursor:
                args["cursor"] = cursor
            page = self.good("session_read", **args)
            events.extend(page["events"])
            cursor = page["next_cursor"]
            if page["at_eof"]:
                break
        execution = [e for e in events if e["kind"] == "execution" and e["phase"] == "result"]
        self.assertEqual(len(execution), 1)
        evidence = execution[0]
        self.assertEqual(evidence["exit_status"], 0)
        self.assertEqual(evidence["call_id"], "call-1")
        self.assertIsNotNone(evidence["timestamp"])
        self.assertIsNotNone(evidence["command"])
        self.assertGreater(evidence["evidence"]["byte_end"], evidence["evidence"]["byte_start"])
        self.assertGreater(evidence["evidence"]["line"], 1)

    def test_custom_exec_wrapper_projects_only_paired_allowlisted_text_result(self):
        call_id = "custom-wrapper-call"
        jsonl(self.extra / "custom-wrapper.jsonl", [
            metadata("custom-wrapper", self.extra),
            event("response_item", {"type": "custom_tool_call", "name": "exec", "call_id": call_id,
                                     "input": "private wrapper input " + PRIVATE, "status": "completed"}),
            event("response_item", {"type": "custom_tool_call_output", "call_id": call_id,
                                     "output": [{"type": "input_text", "text": "public tool result"},
                                                {"type": "input_text", "text": "token=" + SECRET}]}),
        ])
        first = self.good("session_read", source="cases", session_id="custom-wrapper", limit=1)
        self.assertEqual(len(first["events"]), 1)
        self.assertEqual(first["events"][0]["kind"], "execution")
        self.assertEqual(first["events"][0]["phase"], "call")
        self.assertEqual(first["events"][0]["command"], "functions.exec wrapper")
        second = self.good("session_read", source="cases", session_id="custom-wrapper",
                           limit=1, cursor=first["next_cursor"])
        self.assertEqual(len(second["events"]), 1)
        self.assertEqual(second["events"][0]["kind"], "execution")
        self.assertEqual(second["events"][0]["phase"], "result")
        self.assertEqual(second["events"][0]["command"], "functions.exec wrapper")
        self.assertIn("public tool result", second["events"][0]["output"])
        self.assertIn("REDACTED", second["events"][0]["output"])
        self.assertNotIn("private wrapper input", json.dumps(first["events"] + second["events"]))

        jsonl(self.extra / "unapproved-custom-tool.jsonl", [
            metadata("unapproved-custom-tool", self.extra),
            event("response_item", {"type": "custom_tool_call", "name": "unapproved", "call_id": "other-call",
                                     "input": "not allowed", "status": "completed"}),
            event("response_item", {"type": "custom_tool_call_output", "call_id": "other-call",
                                     "output": [{"type": "input_text", "text": "not projected"}]}),
        ])
        refused = self.good("session_read", source="cases", session_id="unapproved-custom-tool")
        self.assertEqual(refused["events"], [])
        self.assertEqual(refused["omitted_nonprojected_records"], 3)

        jsonl(self.extra / "malformed-custom-output.jsonl", [
            metadata("malformed-custom-output", self.extra),
            event("response_item", {"type": "custom_tool_call", "name": "exec", "call_id": "shape-call",
                                     "input": "synthetic wrapper", "status": "completed"}),
            event("response_item", {"type": "custom_tool_call_output", "call_id": "shape-call",
                                     "output": [{"type": "input_text", "text": "not projected", "unapproved": PRIVATE}]}),
        ])
        malformed = self.good("session_read", source="cases", session_id="malformed-custom-output")
        self.assertEqual([(e["kind"], e["phase"]) for e in malformed["events"]], [("execution", "call")])
        self.assertEqual(malformed["omitted_nonprojected_records"], 2)

    def test_incremental_append_polls_only_delta(self):
        path = self.extra / "append.jsonl"
        jsonl(path, [metadata("append", self.base / "repo"), event("event_msg", {"type": "user_message", "message": "before"})])
        first = self.good("session_read", source="cases", session_id="append")
        self.assertTrue(first["at_eof"])
        with path.open("ab") as stream:
            stream.write((json.dumps(event("event_msg", {"type": "agent_message", "message": "delta"})) + "\n").encode())
        delta = self.good("session_read", source="cases", session_id="append", cursor=first["next_cursor"])
        self.assertEqual([e["text"] for e in delta["events"]], ["delta"])
        poll = self.good("session_read", source="cases", session_id="append", cursor=delta["next_cursor"])
        self.assertEqual(poll["events"], [])

    def test_rotation_and_truncation_detected(self):
        path = self.extra / "rotate.jsonl"
        records = [metadata("rotate", self.base / "repo"), event("event_msg", {"type": "user_message", "message": "before"})]
        jsonl(path, records)
        first = self.good("session_read", source="cases", session_id="rotate")
        replacement = self.extra / "replacement"
        jsonl(replacement, records)
        os.replace(replacement, path)
        self.assertEqual(self.denied("session_read", source="cases", session_id="rotate", cursor=first["next_cursor"])["error"], "source_rotated")
        first = self.good("session_read", source="cases", session_id="rotate")
        jsonl(path, records[:1])
        self.assertEqual(self.denied("session_read", source="cases", session_id="rotate", cursor=first["next_cursor"])["error"], "source_truncated")

    def test_same_inode_rewrite_detected(self):
        path = self.extra / "rewrite.jsonl"
        records = [metadata("rewrite", self.base / "repo"), event("event_msg", {"type": "user_message", "message": "before"})]
        jsonl(path, records)
        first = self.good("session_read", source="cases", session_id="rewrite")
        records[-1]["payload"]["message"] = "edited"
        jsonl(path, records)
        self.assertEqual(self.denied("session_read", source="cases", session_id="rewrite", cursor=first["next_cursor"])["error"], "source_changed")

    def test_partial_final_line_left_pending_until_complete(self):
        path = self.extra / "partial.jsonl"
        jsonl(path, [metadata("partial", self.base / "repo")], b'{"type":"event_msg","payload":')
        first = self.good("session_read", source="cases", session_id="partial")
        self.assertTrue(first["partial_final_line_pending"])
        self.assertFalse(first["at_eof"])
        with path.open("ab") as stream:
            stream.write(b'{"type":"agent_message","message":"completed tail"}}\n')
        second = self.good("session_read", source="cases", session_id="partial", cursor=first["next_cursor"])
        self.assertEqual([e["text"] for e in second["events"]], ["completed tail"])

    def test_complete_malformed_and_oversized_records_explicit_errors(self):
        for sid, expected in (("synth-malformed", "malformed_jsonl"), ("synth-oversize", "oversized_jsonl_record")):
            result = self.denied("session_read", source="variants", session_id=sid)
            self.assertEqual(result["error"], expected)
        path = self.extra / "oversized-tail.jsonl"
        jsonl(path, [metadata("oversized-tail", self.extra)], b"x" * (262144 + 1))
        self.assertEqual(self.denied("session_read", source="cases", session_id="oversized-tail")["error"], "oversized_jsonl_record")

    def test_duplicate_exact_id_is_ambiguous(self):
        for name in ("one", "two"):
            jsonl(self.extra / (name + ".jsonl"), [metadata("duplicate", self.extra)])
        self.assertEqual(self.denied("session_read", source="cases", session_id="duplicate")["error"], "ambiguous_session_id")

    def test_lifecycle_terminal_blocked_aborted_and_unknown(self):
        cases = [("synth-main", "explicit_terminal_turn"), ("synth-blocked", "explicit_blocked"),
                 ("synth-archive", "explicit_aborted"), ("synth-unknown", "unknown"), ("synth-partial", "unknown")]
        for sid, expected in cases:
            result = self.good("session_state", source="synthetic", session_id=sid)
            self.assertEqual(result["state"], expected)
            self.assertEqual(result["task_verified"], "unknown")
            self.assertEqual(result["authoritative_current_activity"], "unavailable_passive_jsonl")

    def test_recency_uses_event_time_not_metadata_mtime_claims_or_notloaded(self):
        now = datetime.now(timezone.utc).isoformat()
        jsonl(self.extra / "recent.jsonl", [metadata("recent", self.extra), event("event_msg", {"type": "user_message", "message": "hello"}, now)])
        self.assertEqual(self.good("session_state", source="cases", session_id="recent")["state"], "recently_observed_event")
        jsonl(self.extra / "notloaded.jsonl", [metadata("notloaded", self.extra), event("event_msg", {"type": "notLoaded", "status": "stopped"}, now), event("event_msg", {"type": "agent_message", "message": "everything completed"})])
        self.assertEqual(self.good("session_state", source="cases", session_id="notloaded")["state"], "unknown")
        jsonl(self.extra / "future.jsonl", [metadata("future", self.extra), event("event_msg", {"type": "user_message", "message": "hello"}, (datetime.now(timezone.utc) + timedelta(days=1)).isoformat())])
        self.assertEqual(self.good("session_state", source="cases", session_id="future")["state"], "unknown")

    def test_large_jsonl_paginates_without_loading_whole_source(self):
        path = self.extra / "large.jsonl"
        records = [metadata("large", self.extra)] + [event("event_msg", {"type": "user_message", "message": f"message {i}"}) for i in range(1100)]
        jsonl(path, records)
        page = self.good("session_state", source="cases", session_id="large")
        self.assertFalse(page["scan_complete"])
        page = self.good("session_state", source="cases", session_id="large", cursor=page["next_cursor"])
        self.assertTrue(page["scan_complete"])

    def test_keyword_regex_and_multiple_sources(self):
        jsonl(self.extra / "match.jsonl", [metadata("match", self.extra), event("event_msg", {"type": "user_message", "message": "synthetic custom source"})])
        result = self.good("session_search", sources=["synthetic", "cases"], query="synthetic", regex=False)
        self.assertGreater(len(result["matches"]), 1)
        result = self.good("session_search", sources=["synthetic"], session_id="synth-main", query="tests.*passed", regex=True)
        self.assertEqual(len(result["matches"]), 1)

    def test_session_schema_ignores_unapproved_fields(self):
        jsonl(self.extra / "shape.jsonl", [metadata("shape", self.extra), event("execution", {"command": "echo safe", "call_id": "call-x", "exit_code": 0, "environment": PRIVATE, "reasoning": PRIVATE}), event("response_item", {"type": "message", "role": "assistant", "content": [{"type": "reasoning_text", "text": PRIVATE}, {"type": "output_text", "text": "public"}]})])
        result = self.good("session_read", source="cases", session_id="shape")
        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(result["events"][1]["text"], "public")

    def test_event_after_terminal_does_not_prove_current_completion(self):
        jsonl(self.extra / "after-terminal.jsonl", [metadata("after-terminal", self.extra),
              event("event_msg", {"type": "turn_completed"}),
              event("event_msg", {"type": "user_message", "message": "another task"})])
        result = self.good("session_state", source="cases", session_id="after-terminal")
        self.assertEqual(result["last_explicit_lifecycle"], "turn_completed")
        self.assertEqual(result["state"], "unknown")
