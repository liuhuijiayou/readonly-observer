import json
import os
from pathlib import Path
import shutil
import time
from unittest.mock import patch

from support import PROJECT, Config, Observer, ObserverCase, PRIVATE, SECRET, build, jsonl, metadata, snapshot, write
from observer.fs import Root, components
from observer.security import Budget, Refusal


class FilesystemTests(ObserverCase):
    def test_traversal_absolute_and_alias_isolation(self):
        for path in ("../safe.txt", "/etc/passwd", "sub/../../safe.txt", "sub\\safe.txt", "a//b", "a/./b", "bad\x00path"):
            with self.subTest(kind="invalid path"):
                self.denied("workspace_read", alias="fixture", path=path)
        self.denied("workspace_read", alias="unregistered", path="safe.txt")
        self.denied("workspace_read", alias="other", path="safe.txt")

    def test_sensitive_policy_and_normal_public_names(self):
        for path in (".env", ".env.production", "auth.json", ".local/credentials/private.log", ".venv/lib/x", ".git/HEAD", ".ssh/config", "key.pem", "credentials.json",
                     ".git-credentials", "secrets.toml", "credentials.toml"):
            self.assertEqual(self.denied("workspace_read", alias="fixture", path=path)["error"], "sensitive_path")
        result = self.good("workspace_read", alias="fixture", path="tokenization.py")
        self.assertEqual(result["source_line_count"], 1)
        names = [e["path"] for e in self.good("workspace_list", alias="fixture")["entries"]]
        self.assertNotIn(".env", names)
        self.assertNotIn("auth.json", names)

    def test_symlink_root_rejected(self):
        link = self.extra / "linked-root"
        link.symlink_to(self.base / "workspace", target_is_directory=True)
        with self.assertRaises(OSError):
            Root("linked", str(link))

    def test_symlink_intermediate_and_leaf_rejected(self):
        (self.extra / "sub").symlink_to(self.base / "workspace", target_is_directory=True)
        (self.extra / "leaf.txt").symlink_to(self.base / "workspace/safe.txt")
        self.denied("workspace_read", alias="other", path="sub/safe.txt")
        self.denied("workspace_read", alias="other", path="leaf.txt")
        self.denied("workspace_list", alias="other")

    def test_hardlinks_and_fifo_fail_closed(self):
        write(self.extra / "original", "public\n")
        os.link(self.extra / "original", self.extra / "hardlink")
        self.assertEqual(self.denied("workspace_read", alias="other", path="hardlink")["error"], "hardlink_denied")
        os.mkfifo(self.extra / "fifo")
        start = time.monotonic()
        self.denied("workspace_read", alias="other", path="fifo")
        self.assertLess(time.monotonic() - start, 0.5)

    def test_root_swap_uses_pinned_descriptor(self):
        write(self.extra / "source", "original authorized inode\n")
        original = self.extra.with_name(self.extra.name + "-original")
        self.extra.rename(original)
        self.addCleanup(lambda: shutil.rmtree(original, ignore_errors=True))
        self.extra.mkdir()
        write(self.extra / "source", "replacement\n")
        result = self.good("workspace_read", alias="other", path="source")
        self.assertEqual(result["lines"][0]["text"], "original authorized inode")

    def test_deterministic_intermediate_swap_cannot_follow_replacement(self):
        write(self.extra / "sub/source", "authorized\n")
        outside = self.extra / "outside"
        write(outside / "source", PRIVATE)
        real_open = os.open
        fired = False

        def raced(path, flags, *args, **kwargs):
            nonlocal fired
            fd = real_open(path, flags, *args, **kwargs)
            if path == "sub" and not fired:
                fired = True
                (self.extra / "sub").rename(self.extra / "sub-old")
                (self.extra / "sub").symlink_to(outside, target_is_directory=True)
            return fd

        with patch("observer.fs.os.open", side_effect=raced):
            result = self.good("workspace_read", alias="other", path="sub/source")
        self.assertTrue(fired)
        self.assertEqual(result["lines"][0]["text"], "authorized")

    def test_deterministic_leaf_swap_rejected(self):
        write(self.extra / "source", "authorized\n")
        write(self.extra / "outside", PRIVATE)
        real_open = os.open
        fired = False

        def raced(path, flags, *args, **kwargs):
            nonlocal fired
            if path == "source" and not fired:
                fired = True
                (self.extra / "source").unlink()
                (self.extra / "source").symlink_to(self.extra / "outside")
            return real_open(path, flags, *args, **kwargs)

        with patch("observer.fs.os.open", side_effect=raced):
            self.denied("workspace_read", alias="other", path="source")
        self.assertTrue(fired)

    def test_deterministic_mutation_during_read_rejected(self):
        write(self.extra / "source", "original\n")
        real_read = os.read
        fired = False

        def raced(fd, count):
            nonlocal fired
            raw = real_read(fd, count)
            if not fired:
                fired = True
                write(self.extra / "source", "changed source\n")
            return raw

        with patch("observer.fs.os.read", side_effect=raced):
            self.assertEqual(self.denied("workspace_read", alias="other", path="source")["error"], "source_changed")

    def test_reads_do_not_change_inventory_hashes_mtime_index_db_or_wal(self):
        before = snapshot(self.base)
        self.good("workspace_read", alias="fixture", path="safe.txt")
        self.good("workspace_glob", aliases=["fixture", "fixture_git"], pattern="**/*.txt")
        self.good("session_read", source="synthetic", session_id="synth-main")
        self.good("git_status", alias="fixture_git")
        self.good("git_diff", alias="fixture_git")
        self.good("git_history", alias="fixture_git")
        self.assertTrue(before == snapshot(self.base), "observed filesystem changed")

    def test_line_ranges_and_hash_evidence(self):
        result = self.good("workspace_read", alias="fixture", path="safe.txt", start_line=2, end_line=2)
        self.assertEqual([x["line"] for x in result["lines"]], [2])
        self.assertEqual(len(result["source_sha256"]), 64)
        self.denied("workspace_read", alias="fixture", path="safe.txt", start_line=1, end_line=201)

    def test_directory_and_glob_pagination(self):
        expected = []
        cursor = None
        for _ in range(20):
            args = {"alias": "fixture", "limit": 1}
            if cursor:
                args["cursor"] = cursor
            page = self.good("workspace_list", **args)
            expected.extend(e["path"] for e in page["entries"])
            cursor = page["next_cursor"]
            if not cursor:
                break
        self.assertEqual(len(expected), len(set(expected)))
        self.assertGreater(len(expected), 2)
        first = self.good("workspace_glob", aliases=["fixture"], pattern="**/*", limit=1)
        self.assertIsNotNone(first["next_cursor"])
        second = self.good("workspace_glob", aliases=["fixture"], pattern="**/*", limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(first["files"], second["files"])

    def test_ignored_untracked_and_multiroot_search(self):
        files = self.good("workspace_glob", aliases=["fixture_git"], pattern="**/*.txt")["files"]
        names = {x["path"] for x in files}
        self.assertIn("ignored.txt", names)
        self.assertIn("untracked.txt", names)
        write(self.extra / "public", "safe independently registered root\n")
        result = self.good("workspace_search", aliases=["other", "fixture_git"], query="safe")
        self.assertEqual({m["alias"] for m in result["matches"]}, {"other", "fixture_git"})
        self.assertTrue(all("source_sha256" in m and "line" in m for m in result["matches"]))

    def test_source_change_invalidates_cursor(self):
        write(self.extra / "long", "line\n" * 100)
        first = self.good("workspace_search", aliases=["other"], query="line", limit=1)
        write(self.extra / "long", "changed\n" * 100)
        self.assertEqual(self.denied("workspace_search", aliases=["other"], query="line", limit=1, cursor=first["next_cursor"])["error"], "source_changed")

    def test_config_frozen_maps_and_no_runtime_expansion(self):
        with self.assertRaises(TypeError):
            self.config.workspaces["new"] = self.config.workspaces["fixture"]
        self.denied("register_root", alias="new", path=str(self.extra))
        self.denied("observer_info", roots=[str(self.extra)])
        info = self.good("observer_info")
        self.assertTrue(str(self.base) not in json.dumps(info), "absolute root leaked")

    def test_single_session_file_scope_requires_exact_alias_path_and_id(self):
        values = {
            "workspaces": {},
            "sessions": {"exact": str(self.extra)},
            "session_files": {"exact": {"path": "only.jsonl", "session_id": "approved-session"}},
            "strict_hardlinks": True,
        }
        config = Config(PROJECT, values)
        try:
            self.assertEqual(config.session_files["exact"], ("only.jsonl", "approved-session"))
        finally:
            config.close()
        for scope in (
            {"unknown": {"path": "only.jsonl", "session_id": "approved-session"}},
            {"exact": {"path": "../outside.jsonl", "session_id": "approved-session"}},
            {"exact": {"path": "only.txt", "session_id": "approved-session"}},
            {"exact": {"path": "only.jsonl", "session_id": "bad/id"}},
            {"exact": {"path": "only.jsonl", "session_id": "approved-session", "extra": True}},
        ):
            with self.subTest(scope=scope), self.assertRaises(Refusal):
                Config(PROJECT, {**values, "session_files": scope})

    def test_workspace_only_and_session_only_startup(self):
        jsonl(self.extra / "only.jsonl", [metadata("only", self.extra)])
        write(self.extra / "only.txt", "public workspace text")
        for kind in ("workspaces", "sessions"):
            values = {"workspaces": {}, "sessions": {}, "strict_hardlinks": True}
            values[kind] = {"only": str(self.extra)}
            with self.subTest(reader=kind):
                config = Config(PROJECT, values)
                try:
                    observer = Observer(config)
                    info = observer.call("observer_info", {})
                    self.assertTrue(info["ok"])
                    if kind == "workspaces":
                        self.assertEqual(info["session_sources"], [])
                        self.assertTrue(observer.call("workspace_read", {"alias": "only", "path": "only.txt"})["ok"])
                        denied = observer.call("session_list", {"sources": ["only"]})
                    else:
                        self.assertEqual(info["workspaces"], [])
                        self.assertTrue(observer.call("session_read", {"source": "only", "session_id": "only"})["ok"])
                        denied = observer.call("workspace_list", {"alias": "only"})
                    self.assertEqual(denied["error"], "unknown_alias")
                finally:
                    config.close()
        with self.assertRaises(Refusal):
            Config(PROJECT, {"workspaces": {}, "sessions": {}, "strict_hardlinks": True})

    def test_fixture_builder_parent_traversal_rejected_before_any_access(self):
        # This path is never accessed. Patch the first possible filesystem step
        # to prove rejection is lexical, without creating anything outside scope.
        destination = PROJECT / ".local" / ".." / "unopened-fixture"
        with patch.object(Path, "absolute", side_effect=AssertionError("filesystem stage reached")):
            with self.assertRaisesRegex(RuntimeError, "fixture_parent_traversal_denied"):
                build(destination, reset=True)

    def test_scan_and_entry_budgets(self):
        with self.assertRaises(Refusal):
            Budget(remaining=1).check(2)
        with self.assertRaises(Refusal):
            Budget(deadline=time.monotonic() - 1).check()
        with self.assertRaises(Refusal):
            Budget().check(entries=4001)

    def test_workspace_search_scan_progress_paginates(self):
        for name in ("a", "b", "c"):
            write(self.extra / name, "a" * 1500000 + "\nneedle\n")
        first = self.good("workspace_search", aliases=["other"], query="needle")
        self.assertIsNotNone(first["next_cursor"])
        second = self.good("workspace_search", aliases=["other"], query="needle", cursor=first["next_cursor"])
        self.assertEqual(len(first["matches"]) + len(second["matches"]), 3)
