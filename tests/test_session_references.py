"""Exact references, bounded evidence continuation and no implicit source expansion."""
import json
from unittest.mock import patch

from support import ObserverCase, PRIVATE, event, init_repo, jsonl, metadata
from observer.registry import ApprovalRegistry, effective_config
from observer.service import Observer

SID = "00000000-0000-7000-8000-000000000032"
LINK = "https://chatgpt.com/codex/tasks/task_synthetic_reference"


class SessionReferenceTests(ObserverCase):
    def registered(self, extra_events=(), second=False):
        self.path = self.extra / "logs/chosen.jsonl"
        records = [metadata(SID, self.extra)]
        records += [event("event_msg", {"type": "user_message", "message": "reference needle " + str(n)}) for n in range(3)]
        records += list(extra_events)
        jsonl(self.path, records)
        jsonl(self.path.parent / "sibling.jsonl", [metadata("unapproved-sibling", self.extra),
              event("event_msg", {"type": "user_message", "message": PRIVATE})])
        registry = ApprovalRegistry(self.extra)
        registry.register_session("chosen", str(self.path), LINK, lambda _: True)
        if second:
            other = self.extra / "second/other.jsonl"
            jsonl(other, [metadata("other-session", self.extra),
                  event("event_msg", {"type": "user_message", "message": "reference needle other"})])
            registry.register_session("second", str(other), None, lambda _: True)
        config = effective_config(self.extra, {"workspaces": {"code": str(self.extra)},
                                  "sessions": {}, "strict_hardlinks": True})
        self.addCleanup(config.close)
        self.observer = Observer(config)

    def test_search_all_supported_references_match_same_exact_session(self):
        self.registered()
        for reference in (SID, "codex://threads/" + SID, LINK, "task_synthetic_reference"):
            with self.subTest(reference=reference):
                page = self.good("session_search", sources=["chosen"], session_id=reference, query="needle")
                self.assertEqual(len(page["matches"]), 3)
                self.assertIsNone(page["next_cursor"])
                self.assertTrue(all(e["evidence"]["source"] == "chosen" for e in page["matches"]))

    def test_mapped_search_pagination_and_cursor_reference_binding(self):
        self.registered()
        first = self.good("session_search", sources=["chosen"], session_id=LINK, query="needle", limit=1)
        self.assertEqual(len(first["matches"]), 1)
        self.assertIsNotNone(first["next_cursor"])
        self.denied("session_search", sources=["chosen"], session_id=SID, query="needle", limit=1, cursor=first["next_cursor"])
        cursor, matches = first["next_cursor"], list(first["matches"])
        for _ in range(5):
            if cursor is None:
                break
            page = self.good("session_search", sources=["chosen"], session_id=LINK, query="needle", limit=1, cursor=cursor)
            matches.extend(page["matches"])
            cursor = page["next_cursor"]
        self.assertIsNone(cursor)
        self.assertEqual(len(matches), 3)
        self.assertEqual(len({e["evidence"]["line"] for e in matches}), 3)

    def test_unmapped_reference_refused_before_inventory(self):
        self.registered()
        with patch.object(self.observer.sessions, "inventory", side_effect=AssertionError("no discovery")):
            denied = self.denied("session_search", sources=["chosen"], session_id="task_unmapped", query="needle")
        self.assertEqual(denied["error"], "session_reference_unmapped")

    def test_mapping_never_opens_other_selected_or_unapproved_files(self):
        self.registered(second=True)
        reader = self.observer.sessions
        original = reader.metadata
        opened = []
        def checked(source, path, budget):
            opened.append((source, path))
            self.assertEqual((source, path), ("chosen", "chosen.jsonl"))
            return original(source, path, budget)
        with patch.object(reader, "metadata", side_effect=checked):
            page = self.good("session_search", sources=["chosen", "second"], session_id=LINK, query="needle")
        self.assertEqual(len(page["matches"]), 3)
        self.assertTrue(opened)
        self.assertEqual(self.denied("session_search", sources=["second"], session_id=LINK, query="needle")["error"], "session_reference_unmapped")
        self.assertEqual(self.denied("session_search", sources=["chosen", "unknown"], session_id=LINK, query="needle")["error"], "unknown_alias")

    def test_unfiltered_search_still_searches_explicit_selected_sources(self):
        self.registered(second=True)
        result = self.good("session_search", sources=["chosen", "second"], query="needle")
        self.assertEqual(len(result["matches"]), 4)

    def evidence_fixture(self):
        init_repo(self.extra, False)
        later = [event("event_msg", {"type": "agent_message", "message": "public step " + str(n)}) for n in range(55)]
        later += [event("event_msg", {"type": "exec_command_end", "call_id": "late-result", "exit_code": 0,
                                     "aggregated_output": "synthetic checks passed"}),
                  event("event_msg", {"type": "turn_completed"})]
        self.registered(later)

    def test_evidence_continuation_reaches_late_execution_without_correctness_claim(self):
        self.evidence_fixture()
        result = self.good("evidence_link", source="chosen", session_id=LINK, alias="code", path="tracked.txt")
        self.assertFalse(result["execution_scan_complete"])
        self.assertEqual(result["execution_evidence"], [])
        self.assertEqual(result["session_source"], "chosen")
        self.assertEqual(result["execution_evidence_scope"], "bounded_first_session_page; continue_session_read")
        self.assertEqual(result["task_verified"], "unknown")
        page = self.good("session_read", source=result["session_source"], session_id=result["session_id"], cursor=result["session_next_cursor"])
        execution = next(e for e in page["events"] if e["kind"] == "execution")
        self.assertEqual(execution["exit_status"], 0)
        self.assertTrue(page["at_eof"])
        state = self.good("session_state", source="chosen", session_id=LINK)
        self.assertEqual(state["historical_state"], "explicit_terminal_turn")
        self.assertEqual(state["current_activity"], "unknown")
        self.assertEqual(state["task_verified"], "unknown")

    def test_evidence_continuation_rejects_rewritten_prefix(self):
        self.evidence_fixture()
        result = self.good("evidence_link", source="chosen", session_id=SID, alias="code", path="tracked.txt")
        self.path.write_bytes(self.path.read_bytes().replace(b"public step 0", b"public step X"))
        self.assertEqual(self.denied("session_read", source="chosen", session_id=SID, cursor=result["session_next_cursor"])["error"], "source_changed")

    def test_evidence_at_eof_reports_append_polling_and_no_verification(self):
        init_repo(self.extra, False)
        self.registered()
        result = self.good("evidence_link", source="chosen", session_id=SID, alias="code", path="tracked.txt")
        self.assertTrue(result["execution_scan_complete"])
        self.assertTrue(result["session_scan"]["at_eof"])
        self.assertIsNotNone(result["session_next_cursor"])
        self.assertEqual(result["task_verified"], "unknown")
        self.assertFalse(result["exit_zero_alone_verifies_task"])

    def test_evidence_partial_record_does_not_claim_complete_scan(self):
        init_repo(self.extra, False)
        self.registered()
        with self.path.open("ab") as stream:
            stream.write(b'{"type":"event_msg","payload":')
        result = self.good("evidence_link", source="chosen", session_id=SID, alias="code", path="tracked.txt")
        self.assertFalse(result["execution_scan_complete"])
        self.assertTrue(result["session_scan"]["partial_final_line_pending"])
