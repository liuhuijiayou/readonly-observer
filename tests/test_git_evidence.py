import os
from pathlib import Path
from unittest.mock import patch

from support import ObserverCase, PRIVATE, SECRET, event, git, init_repo, jsonl, metadata, snapshot, write
from observer.gitreader import FIXED_ARGS, Snapshot, parse_status, safe_env
from observer.security import Refusal


class GitEvidenceTests(ObserverCase):
    def test_clean_dirty_hidden_sensitive_conflicts_and_path_filters(self):
        clean = self.good("git_status", alias="clean")
        self.assertIs(clean["clean"], True)
        dirty = self.good("git_status", alias="fixture_git")
        self.assertIs(dirty["clean"], False)
        self.assertGreaterEqual(dirty["hidden_conflicts"], 1)
        self.assertGreaterEqual(dirty["hidden_status_entries"], 1)
        self.assertTrue(dirty["filtered"])
        filtered = self.good("git_status", alias="fixture_git", paths=["absent"])
        self.assertNotEqual(filtered["clean"], True)
        self.assertEqual(filtered["hidden_conflicts"], 0)
        self.assertTrue(all(not e["path"].startswith(".env") for e in dirty["entries"]))

    def test_sensitive_tracked_without_visible_changes_is_unknown(self):
        init_repo(self.extra, False)
        write(self.extra / ".env.hidden", "password=" + SECRET)
        git(self.extra, "add", "--", ".env.hidden")
        git(self.extra, "commit", "-m", "sensitive tracked fixture")
        result = self.good("git_status", alias="other")
        self.assertEqual(result["clean"], "unknown")
        self.assertGreater(result["hidden_status_entries"], 0)

    def test_status_nul_parser_with_space_and_rename_records(self):
        result = parse_status(b" M file with spaces.txt\0R  renamed.txt\0old.txt\0?? untracked\0")
        self.assertEqual(result[0]["path"], "file with spaces.txt")
        self.assertEqual(result[1]["origin"], "old.txt")
        for raw in (b"malformed", b" M ../escape\0", b"R  new\0"):
            with self.assertRaises(Refusal):
                parse_status(raw)

    def test_injected_helpers_and_env_are_not_executed_and_sources_unchanged(self):
        sentinel = self.base / "HELPER_EXECUTED"
        trace = self.extra / "trace-sentinel"
        before = snapshot(self.base)
        captured = []
        real_run = Snapshot.run

        def checked(snap, args):
            captured.append(args)
            return real_run(snap, args)

        injected = {
            "GIT_DIR": str(self.base / "repo/.git"), "GIT_WORK_TREE": str(self.extra),
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": str(self.base / "repo/helper-fixture.sh"),
            "GIT_EXTERNAL_DIFF": str(self.base / "repo/helper-fixture.sh"),
            "GIT_SSH_COMMAND": str(self.base / "repo/helper-fixture.sh"),
            "GIT_TRACE": str(trace), "GIT_CONFIG_GLOBAL": str(self.base / "repo/.git/config"),
            "DYLD_INSERT_LIBRARIES": str(self.extra / "not-a-library"),
        }
        with patch.dict(os.environ, injected), patch.object(Snapshot, "run", checked):
            self.good("git_status", alias="fixture_git")
            self.good("git_diff", alias="fixture_git")
            self.good("git_diff", alias="fixture_git", staged=True)
            self.good("git_history", alias="fixture_git")
        self.assertFalse(sentinel.exists())
        self.assertFalse(trace.exists())
        self.assertTrue(before == snapshot(self.base), "Git changed observed sources")
        self.assertTrue(any("--no-ext-diff" in a and "--no-textconv" in a for a in captured))
        env = safe_env(self.extra)
        self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "")
        self.assertEqual(env["GIT_NO_LAZY_FETCH"], "1")
        self.assertTrue("GIT_CONFIG_COUNT" not in env and "DYLD_INSERT_LIBRARIES" not in env)
        self.assertTrue(all(not any(a in {"fetch", "clone", "remote", "ls-remote", "submodule"} for a in args) for args in captured))

    def test_git_input_validation_and_no_arbitrary_args(self):
        for tool in ("git_status", "git_diff", "git_history"):
            self.denied(tool, alias="fixture_git", args=["--exec-path=" + SECRET])
            self.denied(tool, alias="fixture_git", paths=["../escape"])
            self.denied(tool, alias="fixture_git", paths=[".env.fixture"])
        self.denied("git_run", alias="fixture_git", command="status")
        self.denied("run_command", command="echo safe")

    def test_external_gitdir_rejected_main_worktree_management_ignored(self):
        write(self.extra / ".git", "gitdir: /outside/not-authorized\n")
        self.denied("git_status", alias="other")
        (self.extra / ".git").unlink()
        init_repo(self.extra, False)
        (self.extra / ".git/worktrees").mkdir()
        write(self.extra / ".git/worktrees/other/gitdir", "/outside/not-authorized\n")
        self.assertIs(self.good("git_status", alias="other")["clean"], True)

    def test_alternates_includes_and_symlink_controls_rejected(self):
        init_repo(self.extra, False)
        alternate = self.extra / ".git/objects/info/alternates"
        write(alternate, "/outside/not-authorized\n")
        self.assertEqual(self.denied("git_status", alias="other")["error"], "unsupported_git_layout")
        alternate.unlink()
        config = self.extra / ".git/config"
        original = config.read_text()
        write(config, original + '\n[includeIf "gitdir:*"]\npath = /outside/not-authorized\n')
        self.assertEqual(self.denied("git_status", alias="other")["error"], "unsupported_git_config")
        write(config, original)
        head = self.extra / ".git/HEAD"
        head.unlink()
        head.symlink_to(self.base / "clean_repo/.git/HEAD")
        self.denied("git_status", alias="other")

    def test_snapshot_contains_only_generated_config_and_is_sealed(self):
        before = snapshot(self.base)
        with self.observer.git.snapshot("fixture_git") as snap:
            text = (snap.path / ".git/config").read_text()
            self.assertTrue("include" not in text and "helper-fixture" not in text)
            self.assertFalse((snap.path / ".git/hooks").exists())
            self.assertFalse((snap.path / ".env.fixture").exists())
            self.assertEqual((snap.path / "tracked.txt").stat().st_mode & 0o222, 0)
            self.assertEqual(snap.path.stat().st_mode & 0o222, 0)
            snap.run(["status", "--porcelain=v1", "-z", "--ignore-submodules=all"])
        self.assertTrue(before == snapshot(self.base))

    def test_source_swap_after_snapshot_never_redirects_git(self):
        init_repo(self.extra, False)
        write(self.extra / "tracked.txt", "copied before source race\n")
        real_run = Snapshot.run
        fired = False

        def raced(snap, args):
            nonlocal fired
            if not fired:
                fired = True
                write(self.extra / "tracked.txt", PRIVATE)
            return real_run(snap, args)

        with patch.object(Snapshot, "run", raced):
            result = self.good("git_diff", alias="other")
        self.assertTrue(any("copied before source race" in x["text"] for x in result["lines"]))

    def test_snapshot_unavailable_fails_closed(self):
        with patch.object(Snapshot, "__enter__", side_effect=PermissionError("sealed snapshot unavailable")):
            self.denied("git_status", alias="fixture_git")

    def test_native_git_cwd_remains_pinned_after_snapshot_path_swap(self):
        self.observer.git.scratch = self.extra / ".local/tmp"
        moved = None
        with self.observer.git.snapshot("clean") as snap:
            moved = snap.path.with_name(snap.name + "-moved")
            # macOS requires a writable directory for this deliberate operator
            # rename. Restore the seal before Git observes the pinned FD.
            snap.path.chmod(0o700)
            snap.path.rename(moved)
            moved.chmod(0o500)
            snap.path.mkdir()
            code, raw, errors = snap.run(["status", "--porcelain=v1", "-z", "--ignore-submodules=all"])
            self.assertEqual(code, 0)
            self.assertEqual(raw, b"")
        import shutil
        shutil.rmtree(moved)

    def test_seal_failure_never_invokes_git(self):
        from observer.gitreader import seal

        def unavailable(root, executables, thaw=False, path=""):
            if not thaw:
                raise PermissionError("snapshot seal unavailable")
            return seal(root, executables, thaw, path)

        with patch("observer.gitreader.seal", side_effect=unavailable), patch("observer.gitreader.subprocess.Popen") as popen:
            self.denied("git_status", alias="fixture_git")
            popen.assert_not_called()

    def test_staged_diff_and_executable_file_modes(self):
        init_repo(self.extra, False)
        write(self.extra / "tracked.txt", "staged first\n")
        git(self.extra, "add", "--", "tracked.txt")
        write(self.extra / "tracked.txt", "working second\n")
        staged = self.good("git_diff", alias="other", staged=True)
        working = self.good("git_diff", alias="other")
        self.assertTrue(any("+staged first" == x["text"] for x in staged["lines"]))
        self.assertTrue(any("+working second" == x["text"] for x in working["lines"]))
        write(self.extra / "public-script.sh", "#!/bin/sh\nexit 0\n")
        (self.extra / "public-script.sh").chmod(0o700)
        git(self.extra, "add", "--all")
        git(self.extra, "commit", "-m", "fixture executable source")
        self.assertIs(self.good("git_status", alias="other")["clean"], True)
        (self.extra / "public-script.sh").chmod(0o600)
        result = self.good("git_status", alias="other")
        self.assertIs(result["clean"], False)

    def test_fresh_tracked_0755_is_clean_and_chmod_only_change_is_visible(self):
        init_repo(self.extra, False)
        script = self.extra / "run.sh"
        write(script, "#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        git(self.extra, "config", "core.filemode", "true")
        git(self.extra, "add", "--", "run.sh")
        git(self.extra, "commit", "-m", "Executable fixture")
        self.assertEqual(git(self.extra, "status", "--porcelain=v1", "-z"), b"")
        before = snapshot(self.extra)
        with self.observer.git.snapshot("other") as snap:
            self.assertEqual((snap.path / "run.sh").stat().st_mode & 0o777, 0o500)
            self.assertIn(b"filemode = true", (snap.path / ".git/config").read_bytes())
        self.assertIs(self.good("git_status", alias="other")["clean"], True)
        self.assertEqual(script.stat().st_mode & 0o777, 0o755)
        self.assertEqual(before, snapshot(self.extra))
        script.chmod(0o644)
        self.assertEqual(git(self.extra, "status", "--porcelain=v1", "-z"), b" M run.sh\0")
        before = snapshot(self.extra)
        changed = self.good("git_status", alias="other")
        self.assertIs(changed["clean"], False)
        self.assertEqual(changed["entries"], [{"path": "run.sh", "origin": None, "status": " M"}])
        patch_lines = [item["text"] for item in self.good("git_diff", alias="other")["lines"]]
        self.assertIn("old mode 100755", patch_lines)
        self.assertIn("new mode 100644", patch_lines)
        self.assertEqual(script.stat().st_mode & 0o777, 0o644)
        self.assertEqual(before, snapshot(self.extra))

    def test_git_diff_history_and_status_pagination(self):
        first = self.good("git_status", alias="fixture_git", limit=1)
        self.assertIsNotNone(first["next_cursor"])
        second = self.good("git_status", alias="fixture_git", limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(first["entries"], second["entries"])
        init_repo(self.extra, False)
        for i in range(2):
            git(self.extra, "commit", "--allow-empty", "-m", f"fixture history {i}")
        first = self.good("git_history", alias="other", limit=1)
        second = self.good("git_history", alias="other", limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(first["commits"][0]["commit"], second["commits"][0]["commit"])
        write(self.extra / "tracked.txt", "public patch line\n" * 300)
        first = self.good("git_diff", alias="other")
        self.assertIsNotNone(first["next_cursor"])
        self.good("git_diff", alias="other", cursor=first["next_cursor"])

    def test_evidence_exact_association_mismatch_and_no_causal_claims(self):
        result = self.good("evidence_link", source="synthetic", session_id="synth-main", alias="fixture_git", path="tracked.txt")
        self.assertEqual(result["association"], "exact_registered_cwd")
        self.assertEqual(result["execution_source_link"], "not_established")
        self.assertEqual(result["task_verified"], "unknown")
        self.assertEqual(result["agent_caused_edits"], "not_established")
        self.assertFalse(result["exit_zero_alone_verifies_task"])
        mismatch = self.good("evidence_link", source="synthetic", session_id="synth-main", alias="clean", path="tracked.txt")
        self.assertEqual(mismatch["association"], "cwd_mismatch_or_unknown")

    def test_trace_hash_evidence_is_labeled_as_reported(self):
        sha = self.good("workspace_read", alias="fixture_git", path="tracked.txt")["source_sha256"]
        jsonl(self.extra / "hashed.jsonl", [metadata("hashed", self.base / "repo"), event("execution", {"call_id": "hash-call", "command": "synthetic check", "exit_code": 0, "source_sha256": sha})])
        result = self.good("evidence_link", source="cases", session_id="hashed", alias="fixture_git", path="tracked.txt")
        self.assertEqual(result["execution_source_link"], "trace_reports_matching_source_hash")
        self.assertEqual(result["task_verified"], "unknown")


class GitCapabilityTests(ObserverCase):
    def test_remote_packed_refs_large_pack_and_derived_files(self):
        init_repo(self.extra, False)
        (self.extra / 'packed.bin').write_bytes(os.urandom(5 * 1024 * 1024))
        git(self.extra, 'add', '--', 'packed.bin')
        git(self.extra, 'commit', '-m', 'Large packed fixture')
        sha = git(self.extra, 'rev-parse', 'HEAD').decode().strip()
        git(self.extra, 'update-ref', 'refs/remotes/origin/main', sha)
        git(self.extra, 'symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main')
        git(self.extra, 'tag', '-a', 'public-tag', '-m', 'tag fixture')
        git(self.extra, 'pack-refs', '--all')
        git(self.extra, 'repack', '-ad')
        write(self.extra / '.git/objects/info/commit-graph', 'ignored derived data')
        write(self.extra / '.git/objects/pack/multi-pack-index', 'ignored derived data')
        with self.observer.git.snapshot('other', 'history') as snap:
            self.assertGreater(snap.budget_bytes, 4 * 1024 * 1024)
            self.assertFalse((snap.path / '.git/objects/info/commit-graph').exists())
            self.assertFalse((snap.path / '.git/objects/pack/multi-pack-index').exists())
        before = snapshot(self.extra)
        self.assertIs(self.good('git_status', alias='other')['clean'], True)
        self.assertEqual(self.good('git_history', alias='other')['head_commit'], sha)
        self.assertEqual(self.good('git_diff', alias='other', staged=True)['lines'], [])
        self.assertEqual(before, snapshot(self.extra))

    def test_untracked_large_file_enumerated_without_read_or_patch(self):
        init_repo(self.extra, False)
        with (self.extra / 'large-untracked.bin').open('wb') as f:
            f.truncate(40_000_000)
        # Version verification may stat the file through a descriptor, but must
        # never read its contents. Guard source reads instead of just results.
        original_read = os.read
        source_inode = (self.extra / 'large-untracked.bin').stat().st_ino

        def checked_read(fd, size):
            if os.fstat(fd).st_ino == source_inode:
                raise AssertionError('untracked content was read')
            return original_read(fd, size)

        with patch('observer.gitreader.os.read', side_effect=checked_read):
            status = self.good('git_status', alias='other')
            self.assertEqual(status['entries'], [{'status': '??', 'path': 'large-untracked.bin', 'origin': None}])
            self.assertEqual(self.good('git_diff', alias='other')['lines'], [])
            self.assertEqual(self.good('git_diff', alias='other', staged=True)['lines'], [])
        with self.observer.git.snapshot('other') as snap:
            self.assertEqual((snap.path / 'large-untracked.bin').stat().st_size, 0)

    def test_operation_and_literal_path_scope_exclude_unrelated_worktree(self):
        init_repo(self.extra, False)
        write(self.extra / 'selected/[file].txt', 'baseline\n')
        write(self.extra / 'unrelated/other.txt', 'untouched\n')
        git(self.extra, 'add', '--all')
        git(self.extra, 'commit', '-m', 'Path fixtures')
        write(self.extra / 'selected/[file].txt', 'staged\n')
        git(self.extra, 'add', '--', 'selected/[file].txt')
        write(self.extra / 'selected/[file].txt', 'working\n')
        with (self.extra / 'unrelated/other.txt').open('wb') as f:
            f.truncate(20_000_000)
        (self.extra / 'unrelated/link').symlink_to('/outside/not-authorized')
        selected = ['selected/[file].txt']
        result = self.good('git_status', alias='other', paths=selected)
        self.assertEqual(result['entries'], [{'status': 'MM', 'path': selected[0], 'origin': None}])
        for staged, text in ((True, '+staged'), (False, '+working')):
            result = self.good('git_diff', alias='other', paths=selected, staged=staged)
            self.assertIn(text, [line['text'] for line in result['lines']])
            self.assertFalse(any('unrelated' in line['text'] for line in result['lines']))
        with patch.object(Snapshot, 'worktree', side_effect=AssertionError('worktree accessed')):
            self.good('git_history', alias='other')
            self.good('git_diff', alias='other', staged=True)
        absent = self.good('git_status', alias='other', paths=['missing'])
        self.assertEqual(absent['entries'], [])
        self.assertEqual(absent['clean'], 'unknown')
        self.denied('git_status', alias='other')

    def test_deleted_files_visible_conflicts_and_staged_without_worktree(self):
        init_repo(self.extra, False)
        write(self.extra / 'deleted.txt', 'remove me\n')
        git(self.extra, 'add', '--all')
        git(self.extra, 'commit', '-m', 'delete fixture')
        (self.extra / 'deleted.txt').unlink()
        working = self.good('git_diff', alias='other', paths=['deleted.txt'])
        self.assertIn('-remove me', [line['text'] for line in working['lines']])
        git(self.extra, 'add', '--', 'deleted.txt')
        staged = self.good('git_diff', alias='other', staged=True)
        self.assertIn('-remove me', [line['text'] for line in staged['lines']])
        stages = b''
        for i in (1, 2, 3):
            sha = git(self.extra, 'hash-object', '-w', '--stdin', data=f'conflict {i}\n'.encode()).strip()
            stages += b'100644 ' + sha + f' {i}\tconflict.txt\n'.encode()
        git(self.extra, 'update-index', '--index-info', data=stages)
        write(self.extra / 'conflict.txt', 'unresolved working copy\n')
        self.assertIn({'status': 'UU', 'path': 'conflict.txt', 'origin': None}, self.good('git_status', alias='other')['entries'])
        self.good('git_diff', alias='other', paths=['conflict.txt'])
        self.good('git_diff', alias='other', paths=['conflict.txt'], staged=True)

    def test_snapshot_combined_exact_limit_and_failed_copy_cleanup(self):
        from observer import gitreader
        init_repo(self.extra, False)
        write(self.extra / 'tracked.txt', 'large working content\n' * 4000)
        with self.observer.git.snapshot('other') as snap:
            needed = snap.budget_bytes
        with patch.object(gitreader, 'GIT_SNAPSHOT_BYTES', needed):
            self.good('git_status', alias='other')
        before = set(self.observer.git.scratch.glob('git-snapshot-*'))
        with patch.object(gitreader, 'GIT_SNAPSHOT_BYTES', needed - 1):
            result = self.denied('git_status', alias='other')
            self.assertEqual(result['error'], 'git_snapshot_byte_limit')
        self.assertEqual(before, set(self.observer.git.scratch.glob('git-snapshot-*')))
        original = Snapshot.copy

        def failure(snap, source, destination, budget):
            if source == 'tracked.txt':
                snap.write(destination, b'partial')
                raise OSError('synthetic interrupted copy')
            return original(snap, source, destination, budget)

        with patch.object(Snapshot, 'copy', failure):
            self.denied('git_status', alias='other')
        self.assertEqual(before, set(self.observer.git.scratch.glob('git-snapshot-*')))

    def test_100mb_total_and_single_pack_boundaries(self):
        from observer.gitreader import GIT_SNAPSHOT_BYTES
        self.assertEqual(GIT_SNAPSHOT_BYTES, 100_000_000)
        init_repo(self.extra, False)
        # Opaque pack bytes test snapshot storage bounds. Actual Git pack parsing
        # and semantics are covered by the valid >4 MiB pack test above.
        pack = self.extra / ('.git/objects/pack/pack-' + 'a' * 40 + '.pack')
        index = pack.with_suffix('.idx')
        index.write_bytes(b'')
        with pack.open('wb') as f:
            f.truncate(99_900_000)
        with self.observer.git.snapshot('other', 'history') as snap:
            self.assertGreater(snap.budget_bytes, 99_900_000)
            self.assertLessEqual(snap.budget_bytes, 100_000_000)
        with pack.open('wb') as f:
            f.truncate(100_000_000)
        self.assertEqual(self.denied('git_history', alias='other')['error'], 'git_snapshot_byte_limit')
        with pack.open('wb') as f:
            f.truncate(100_000_001)
        self.assertEqual(self.denied('git_history', alias='other')['error'], 'git_snapshot_file_limit')
        pack.unlink()
        self.assertEqual(self.denied('git_history', alias='other')['error'], 'git_pack_pair_incomplete')

    def test_refs_changes_during_copy_and_paging_invalidate(self):
        init_repo(self.extra, False)
        original = Snapshot.copy
        fired = False

        def change_ref(snap, source, destination, budget):
            nonlocal fired
            result = original(snap, source, destination, budget)
            if not fired and source.startswith('.git/objects/'):
                fired = True
                write(self.extra / '.git/refs/heads/new-ref', 'a' * 40 + '\n')
            return result

        with patch.object(Snapshot, 'copy', change_ref):
            self.assertEqual(self.denied('git_history', alias='other')['error'], 'source_changed')
        (self.extra / '.git/refs/heads/new-ref').unlink()
        git(self.extra, 'commit', '--allow-empty', '-m', 'history page')
        first = self.good('git_history', alias='other', limit=1)
        write(self.extra / 'untracked.txt', 'irrelevant to history\n')
        self.good('git_history', alias='other', limit=1, cursor=first['next_cursor'])
        git(self.extra, 'commit', '--allow-empty', '-m', 'new head')
        self.assertEqual(self.denied('git_history', alias='other', limit=1, cursor=first['next_cursor'])['error'], 'source_changed')
        write(self.extra / 'tracked.txt', 'working\n' * 500)
        page = self.good('git_diff', alias='other')
        write(self.extra / 'tracked.txt', 'changed again\n')
        self.assertEqual(self.denied('git_diff', alias='other', cursor=page['next_cursor'])['error'], 'source_changed')

    def test_shallow_promisor_and_index_skip_flags_fail_explicitly(self):
        init_repo(self.extra, False)
        sha = git(self.extra, 'rev-parse', 'HEAD').decode()
        write(self.extra / '.git/shallow', sha)
        self.assertEqual(self.denied('git_history', alias='other')['error'], 'unsupported_git_layout')
        (self.extra / '.git/shallow').unlink()
        marker = self.extra / ('.git/objects/pack/pack-' + 'a' * 40 + '.promisor')
        write(marker, '')
        self.assertEqual(self.denied('git_history', alias='other')['error'], 'unsupported_git_objects')
        marker.unlink()
        git(self.extra, 'update-index', '--assume-unchanged', 'tracked.txt')
        write(self.extra / 'tracked.txt', 'must not claim clean\n')
        self.assertEqual(self.denied('git_status', alias='other')['error'], 'unsupported_git_index_flags')
        self.good('git_diff', alias='other', staged=True)
        self.good('git_history', alias='other')

    def test_budget_entry_timeout_worktree_and_output_refusals(self):
        from observer import gitreader
        init_repo(self.extra, False)
        for setting, value, code in (
            ('GIT_ENTRIES', 1, 'git_snapshot_entry_limit'),
            ('GIT_SNAPSHOT_SECONDS', -1, 'git_snapshot_timeout'),
            ('GIT_WORKTREE_BYTES', 1, 'git_snapshot_byte_limit'),
            ('MAX_SCAN', 1, 'git_output_limit'),
            ('GIT_QUERY_SECONDS', -1, 'git_timeout'),
        ):
            with self.subTest(setting=setting), patch.object(gitreader, setting, value):
                self.assertEqual(self.denied('git_status', alias='other')['error'], code)
