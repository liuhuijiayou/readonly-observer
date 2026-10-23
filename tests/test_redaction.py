import json
import time
from unittest.mock import patch

from support import ObserverCase, PRIVATE, SECRET, event, git, init_repo, jsonl, metadata, write
from observer.security import Matcher, Redactor, Refusal


class RedactionTests(ObserverCase):
    def test_adversarial_redaction_finishes_or_returns_static_error_across_readers(self):
        text = "eyJ-" * 40000
        write(self.extra / "adversarial.txt", text)
        jsonl(self.extra / "adversarial.jsonl", [metadata("adversarial", self.extra),
              event("event_msg", {"type": "user_message", "message": text})])
        for tool, args in (
            ("workspace_read", {"alias": "other", "path": "adversarial.txt"}),
            ("workspace_search", {"aliases": ["other"], "pattern": "adversarial.txt", "query": "absent-public-query"}),
            ("session_read", {"source": "cases", "session_id": "adversarial"}),
            ("session_search", {"sources": ["cases"], "query": "absent-public-query"}),
        ):
            start = time.monotonic()
            result = self.call(tool, **args)
            self.assertLess(time.monotonic() - start, 1.0)
            self.assertTrue(result.get("ok") or result.get("error") == "redaction_timeout")
        from observer.gitreader import Snapshot
        with patch_object_run(Snapshot, text.encode()):
            result = self.denied("git_status", alias="fixture_git")
        self.assertIn(result["error"], {"redaction_timeout", "git_query_failed"})

    def check_regression_all_surfaces(self, text):
        self.assertTrue(SECRET not in Redactor().text(text), "redaction regression")
        init_repo(self.extra, False)
        write(self.extra / "tracked.txt", text + "\n")
        jsonl(self.extra / "public.jsonl", [metadata("redaction", self.extra, title=text),
              event("event_msg", {"type": "user_message", "message": text}),
              event("execution", {"call_id": "redacted-call", "command": text, "output": text, "exit_code": 0})])
        git(self.extra, "commit", "--allow-empty", "-m", text)
        workspace = self.good("workspace_read", alias="other", path="tracked.txt")
        self.assertIn("REDACTED", workspace["lines"][0]["text"])
        self.assertEqual(self.good("workspace_search", aliases=["other"], pattern="tracked.txt", query=SECRET)["matches"], [])
        self.assertIn("REDACTED", self.good("session_list", sources=["cases"])["sessions"][0]["title"])
        session = self.good("session_read", source="cases", session_id="redaction")
        self.assertTrue(all("REDACTED" in e.get("text", e.get("command", "")) for e in session["events"]))
        self.assertEqual(self.good("session_search", sources=["cases"], query=SECRET)["matches"], [])
        self.assertTrue(any("REDACTED" in item["text"] for item in self.good("git_diff", alias="other")["lines"]))
        self.assertIn("REDACTED", self.good("git_history", alias="other")["commits"][0]["message"])
        self.denied("workspace_read", alias={"invalid": text}, path="tracked.txt")
        self.denied("observer_info", unexpected=text)
        self.denied(text)
        with patch("observer.fs.Root.read", side_effect=OSError(text)):
            self.denied("workspace_read", alias="other", path="tracked.txt")
        self.good("workspace_read", alias="fixture", path="tokenization.py")

    def test_generic_token_assignment_all_surfaces(self):
        self.check_regression_all_surfaces("token=" + SECRET)

    def test_json_token_field_all_surfaces(self):
        self.check_regression_all_surfaces(json.dumps({"token": SECRET}))

    def test_aws_secret_access_key_all_surfaces(self):
        self.check_regression_all_surfaces("AWS_SECRET_ACCESS_KEY=" + SECRET)

    def test_multiline_private_key_redacted_before_line_selection(self):
        result = self.good("workspace_read", alias="fixture", path="public-secret.txt", start_line=4, end_line=4)
        self.assertEqual(result["lines"][0]["line"], 4)
        self.assertEqual(result["lines"][0]["text"], "")
        self.assertEqual(result["source_line_count"], 6)

    def test_unterminated_private_key_and_common_secret_formats(self):
        redactor = Redactor()
        tokens = ["sk-proj-" + "A" * 30, "AKIA" + "B" * 16, "ghp_" + "C" * 25,
                  "eyJabcde.abcdefghi.abcdefghij", "Bearer " + SECRET,
                  "Authorization: Bearer " + SECRET, '"access_token": "' + SECRET + '"',
                  "https://user:" + SECRET + "@example.invalid", "-----BEGIN RSA PRIVATE KEY-----\n" + SECRET]
        for token in tokens:
            value = redactor.text(token)
            self.assertTrue(SECRET not in value, "synthetic credential leaked")
            self.assertTrue(value != token, "credential pattern not redacted")
        self.assertEqual(redactor.text("tokenization.py"), "tokenization.py")

    def test_redaction_precedes_search(self):
        result = self.good("workspace_search", aliases=["fixture"], pattern="public-secret.txt", query=SECRET)
        self.assertEqual(result["matches"], [])
        result = self.good("session_search", sources=["synthetic"], session_id="synth-main", query=SECRET)
        self.assertEqual(result["matches"], [])
        reasoning = self.good("session_search", sources=["synthetic"], session_id="synth-main", query=PRIVATE)
        self.assertEqual(reasoning["matches"], [])

    def test_redaction_precedes_clipping_and_serialization(self):
        write(self.extra / "long", "x" * 1790 + " password=" + SECRET + "\n")
        result = self.good("workspace_read", alias="other", path="long")
        self.assertTrue(result["lines"][0]["text_truncated"])
        self.assertTrue(SECRET[:8] not in json.dumps(result), "secret prefix survived truncation")

    def test_titles_paths_commands_metadata_outputs_and_errors(self):
        result = self.good("session_list", sources=["synthetic"])
        self.assertTrue(any("REDACTED" in s["title"] for s in result["sessions"]))
        result = self.good("session_read", source="synthetic", session_id="synth-main")
        self.assertTrue(any("REDACTED" in e.get("command", "") for e in result["events"] if e["kind"] == "execution"))
        filename = "password=" + SECRET + ".txt"
        write(self.extra / filename, "public\n")
        page = self.good("workspace_list", alias="other")
        self.assertTrue("REDACTED" in page["entries"][0]["path"])
        with patch("observer.fs.Root.read", side_effect=OSError("password=" + SECRET)):
            result = self.denied("workspace_read", alias="fixture", path="safe.txt")
        self.assertEqual(result["error"], "source_unavailable_or_invalid")

    def test_invalid_unknown_and_excessive_arguments_do_not_echo(self):
        requests = [
            ("workspace_read", {"alias": [SECRET], "path": "safe.txt"}),
            ("workspace_read", {"alias": "fixture", "path": "safe.txt", "password": SECRET}),
            ("workspace_read", {"alias": "fixture", "path": "safe.txt", "start_line": True}),
            ("workspace_search", {"aliases": ["fixture"], "query": SECRET + "[", "regex": True}),
            ("observer_info", {"password": SECRET}),
            ("password=" + SECRET, {}),
            ("workspace_search", {"aliases": ["fixture"], "query": "x" * 17000 + SECRET}),
        ]
        for tool, args in requests:
            self.denied(tool, **args)

    def test_response_caps_and_lossless_page_boundaries(self):
        write(self.extra / "many", "\n".join(str(i) + " " + "a" * 3000 for i in range(200)) + "\n")
        seen, cursor = [], None
        fragments = {}
        for _ in range(100):
            args = {"alias": "other", "path": "many", "start_line": 1, "end_line": 200}
            if cursor:
                args["cursor"] = cursor
            page = self.good("workspace_read", **args)
            for fragment in page["lines"]:
                number = fragment["line"]
                self.assertEqual(fragment["char_start"], len(fragments.get(number, "")))
                fragments[number] = fragments.get(number, "") + fragment["text"]
                if not fragment["text_truncated"]:
                    seen.append(number)
            cursor = page["next_cursor"]
            if not cursor:
                break
        self.assertEqual(seen, list(range(1, 201)))
        self.assertEqual(fragments, {i + 1: str(i) + " " + "a" * 3000 for i in range(200)})
        self.denied("workspace_list", alias="fixture", limit=51)

    def test_regex_timeout_is_enforced(self):
        matcher = Matcher("(a+)+$", True, Redactor())
        start = time.monotonic()
        with self.assertRaises(Refusal) as captured:
            matcher.matches("a" * 60000 + "!")
        self.assertEqual(captured.exception.code, "regex_timeout")
        self.assertLess(time.monotonic() - start, 0.5)

    def test_cursor_tamper_cross_operation_filter_and_restart(self):
        first = self.good("workspace_list", alias="fixture", limit=1)
        token = first["next_cursor"]
        self.denied("workspace_list", alias="fixture", limit=1, cursor="A" + token[1:])
        self.denied("workspace_list", alias="other", limit=1, cursor=token)
        self.denied("workspace_glob", aliases=["fixture"], pattern="**/*", cursor=token)
        from observer.service import Observer
        result = Observer(self.config).call("workspace_list", {"alias": "fixture", "cursor": token})
        self.assertEqual(result["error"], "invalid_cursor")

    def test_git_redaction_diff_history_and_errors(self):
        patch = self.good("git_diff", alias="fixture_git")
        self.assertTrue(any("REDACTED" in x["text"] for x in patch["lines"]))
        init_repo(self.extra, False)
        git(self.extra, "commit", "--allow-empty", "-m", "password=" + SECRET)
        history = self.good("git_history", alias="other")
        self.assertTrue("REDACTED" in history["commits"][0]["message"])
        from observer.gitreader import Snapshot
        with patch_object_run(Snapshot, b"password=" + SECRET.encode()):
            self.denied("git_status", alias="fixture_git")


def patch_object_run(cls, secret):
    return patch.object(cls, "run", return_value=(1, b"", secret))
