"""Bounded selections must not inventory unrelated large workspace trees."""
import os
import shutil
from unittest.mock import patch
from pathlib import Path

from support import PROJECT, Config, Observer, ObserverCase, write

class ScopedSearchTests(ObserverCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.large=cls.base/'large-workspace'
        cls.vendor=cls.large/'vendor'
        cls.vendor.mkdir(parents=True)
        # Larger than the unchanged 4000-entry request budget, all safe files.
        for number in range(4101):
            (cls.vendor/f'f{number:04}.txt').write_text('unrelated vendor data\n')
        for number in range(13):
            write(cls.large/'pkg/mps'/f'p{number:02}.go','target first\ntarget second\n')
        write(cls.large/'README.md','synthetic exact root selection\n')
        write(cls.large/'pkg/other/other.go','outside selected prefix\n')

    def setUp(self):
        super().setUp()
        config=Config(PROJECT,{'workspaces':{'large':str(self.large),'other':str(self.extra)},'sessions':{},'strict_hardlinks':True})
        self.addCleanup(config.close)
        self.observer=Observer(config)

    def test_literal_directory_glob_succeeds_with_unrelated_large_vendor(self):
        page=self.good('workspace_glob',aliases=['large'],pattern='pkg/mps/*.go',limit=5)
        self.assertEqual([p['path'] for p in page['files']],[f'pkg/mps/p{i:02}.go' for i in range(5)])
        self.assertIsNotNone(page['next_cursor'])

    def test_literal_directory_search_succeeds_with_unrelated_large_vendor(self):
        page=self.good('workspace_search',aliases=['large'],pattern='pkg/mps/*.go',query='target',limit=5)
        self.assertEqual(len(page['matches']),5)
        self.assertTrue(all(p['path'].startswith('pkg/mps/') for p in page['matches']))
        self.assertIsNotNone(page['next_cursor'])

    def test_absent_prefix_and_no_match_are_explicit_complete_empty_results(self):
        for tool, extra in (("workspace_glob", {}), ("workspace_search", {"query":"never matches"})):
            for pattern in ("absent/mps/*.go", "pkg/absent/*.go", "pkg/mps/*.rs"):
                with self.subTest(tool=tool,pattern=pattern):
                    result=self.good(tool,aliases=["large"],pattern=pattern,**extra)
                    self.assertEqual(result["files" if tool=="workspace_glob" else "matches"],[])
                    self.assertTrue(result["scan_complete"])
                    self.assertIsNone(result["next_cursor"])

    def test_exact_file_selections_never_enumerate_the_large_parent(self):
        for path in ("README.md","vendor/f0000.txt"):
            page=self.good("workspace_glob",aliases=["large"],pattern=path)
            self.assertEqual([p["path"] for p in page["files"]],[path])
            self.assertTrue(page["scan_complete"])
        page=self.good("workspace_search",aliases=["large"],pattern="vendor/f0000.txt",query="unrelated")
        self.assertEqual(len(page["matches"]),1)
        self.assertTrue(page["scan_complete"])
        for path in ("absent.go","vendor/absent.go","pkg/mps"):
            page=self.good("workspace_glob",aliases=["large"],pattern=path)
            self.assertEqual(page["files"],[])
            self.assertTrue(page["scan_complete"])

    def test_broad_or_still_oversized_selected_tree_refuses_with_narrowing_hint(self):
        for tool,extra in (("workspace_glob",{}),("workspace_search",{"query":"never matches"})):
            for pattern in ("**/*.go","*.go","vendor/*.go"):
                result=self.denied(tool,aliases=["large"],pattern=pattern,**extra)
                self.assertIn(result["error"],{"scan_limit","scan_timeout"})
                self.assertFalse(result["scan_complete"])
                self.assertIsNone(result["next_cursor"])
                self.assertIn("literal directory prefix",result["hint"])
        info=self.good("observer_info")
        self.assertEqual(info["limits"]["directory_entries_per_scan"],4000)
        self.assertEqual(info["limits"]["scan_bytes"],4194304)
        self.assertEqual(info["limits"]["scan_seconds"],1)

    def test_glob_pages_are_complete_without_crossing_selected_sibling(self):
        cursor,paths=None,[]
        while True:
            page=self.good("workspace_glob",aliases=["large"],pattern="pkg/mps/*.go",limit=3,**({"cursor":cursor} if cursor else {}))
            paths.extend(p["path"] for p in page["files"])
            cursor=page["next_cursor"]
            self.assertEqual(page["scan_complete"],cursor is None)
            if cursor is None:break
        self.assertEqual(paths,[f"pkg/mps/p{i:02}.go" for i in range(13)])

    def test_search_pages_keep_lines_without_duplicates_or_drops(self):
        cursor,matches=None,[]
        while True:
            page=self.good("workspace_search",aliases=["large"],pattern="pkg/mps/*.go",query="target",limit=3,**({"cursor":cursor} if cursor else {}))
            matches.extend((m["path"],m["line"]) for m in page["matches"])
            cursor=page["next_cursor"]
            self.assertEqual(page["scan_complete"],cursor is None)
            if cursor is None:break
        self.assertEqual(matches,[(f"pkg/mps/p{i:02}.go",line) for i in range(13) for line in (1,2)])

    def test_existing_fnmatch_nested_path_semantics_are_preserved(self):
        nested=self.large/"pkg/mps/nested"
        write(nested/"child.go","public nested target")
        self.addCleanup(lambda:shutil.rmtree(nested))
        paths=[p["path"] for p in self.good("workspace_glob",aliases=["large"],pattern="pkg/mps/*.go",limit=50)["files"]]
        self.assertIn("pkg/mps/nested/child.go",paths)
        self.assertNotIn("pkg/other/other.go",paths)

    def test_multiroot_scope_is_only_explicit_aliases_and_cursor_binding_is_unchanged(self):
        write(self.extra/"pkg/mps/other.go","target from second approved root")
        page=self.good("workspace_glob",aliases=["large","other"],pattern="pkg/mps/*.go",limit=50)
        self.assertEqual({p["alias"] for p in page["files"]},{"large","other"})
        first=self.good("workspace_glob",aliases=["large"],pattern="pkg/mps/*.go",limit=1)
        for aliases,pattern in ((["other"],"pkg/mps/*.go"),(["large"],"vendor/*.go")):
            self.assertEqual(self.denied("workspace_glob",aliases=aliases,pattern=pattern,cursor=first["next_cursor"])["error"],"invalid_cursor")
        self.denied("workspace_glob",aliases=[str(self.large.parent)],pattern="pkg/mps/*.go")

    def test_traversal_absolute_and_control_patterns_are_rejected(self):
        for tool,extra in (("workspace_glob",{}),("workspace_search",{"query":"target"})):
            for pattern in ("pkg/../vendor/*.go","/pkg/mps/*.go","pkg\\mps/*.go","pkg//mps/*.go","pkg/mps/../../*.go","bad\x00path"):
                self.assertIn(self.denied(tool,aliases=["large"],pattern=pattern,**extra)["error"],{"invalid_path","invalid_arguments"})

    def test_prefix_and_leaf_symlinks_remain_refused(self):
        (self.extra/"linked").symlink_to(self.large/"pkg/mps",target_is_directory=True)
        (self.extra/"leaf.go").symlink_to(self.large/"pkg/mps/p00.go")
        for tool,extra in (("workspace_glob",{}),("workspace_search",{"query":"target"})):
            for pattern in ("linked/*.go","leaf.go"):
                self.denied(tool,aliases=["other"],pattern=pattern,**extra)

    def test_selected_hardlinks_and_fifo_remain_refused(self):
        write(self.extra/"selected/original.go","public")
        os.link(self.extra/"selected/original.go",self.extra/"selected/linked.go")
        os.mkfifo(self.extra/"fifo")
        for tool,extra in (("workspace_glob",{}),("workspace_search",{"query":"public"})):
            for pattern in ("selected/*.go","selected/linked.go"):
                self.assertEqual(self.denied(tool,aliases=["other"],pattern=pattern,**extra)["error"],"hardlink_denied")
            self.denied(tool,aliases=["other"],pattern="fifo",**extra)

    def test_scope_preserves_workspace_sensitive_path_exclusions(self):
        write(self.extra/"selected/public.go","public")
        write(self.extra/"selected/.env","password=synthetic")
        write(self.extra/"selected/.ssh/private.go","private")
        page=self.good("workspace_glob",aliases=["other"],pattern="selected/*")
        self.assertEqual([p["path"] for p in page["files"]],["selected/public.go"])
        self.assertEqual(self.good("workspace_search",aliases=["other"],pattern="selected/*",query="private")["matches"],[])
        self.assertEqual(self.denied("workspace_glob",aliases=["other"],pattern="selected/.ssh/*.go")["error"],"sensitive_path")

    def test_unrelated_tree_change_does_not_invalidate_scoped_cursor(self):
        first=self.good("workspace_glob",aliases=["large"],pattern="pkg/mps/*.go",limit=1)
        changed=self.vendor/"unrelated-added.txt"
        write(changed,"outside scoped selection")
        self.addCleanup(changed.unlink)
        page=self.good("workspace_glob",aliases=["large"],pattern="pkg/mps/*.go",limit=1,cursor=first["next_cursor"])
        self.assertNotEqual(first["files"],page["files"])

    def test_selected_file_change_invalidates_both_query_cursors(self):
        path=self.large/"pkg/mps/p00.go"
        original=path.read_text()
        self.addCleanup(lambda:path.write_text(original))
        glob=self.good("workspace_glob",aliases=["large"],pattern="pkg/mps/*.go",limit=1)
        search=self.good("workspace_search",aliases=["large"],pattern="pkg/mps/*.go",query="target",limit=1)
        path.write_text("changed target\n")
        self.assertEqual(self.denied("workspace_glob",aliases=["large"],pattern="pkg/mps/*.go",limit=1,cursor=glob["next_cursor"])["error"],"source_changed")
        self.assertEqual(self.denied("workspace_search",aliases=["large"],pattern="pkg/mps/*.go",query="target",limit=1,cursor=search["next_cursor"])["error"],"source_changed")

    def test_selected_directory_race_is_refused_without_following_replacement(self):
        chosen=self.extra/"selected"
        write(chosen/"a.go","original target")
        outside=self.extra/"outside"
        write(outside/"outside.go","outside replacement")
        real_scandir=os.scandir
        fired=False
        def raced(fd):
            nonlocal fired
            if not fired:
                chosen.rename(self.extra/"selected-original")
                chosen.symlink_to(outside,target_is_directory=True)
                fired=True
            return real_scandir(fd)
        with patch("observer.fs.os.scandir",side_effect=raced):
            result=self.call("workspace_glob",aliases=["other"],pattern="selected/*.go")
        self.assertTrue(fired)
        self.assertFalse(result["ok"])
        self.assertNotIn("outside.go",str(result))

    def test_missing_descendant_during_walk_is_not_a_complete_empty_scan(self):
        chosen=self.extra/"selected"
        write(chosen/"a/public.go","public first")
        write(chosen/"b/public.go","public second")
        real_open=os.open
        fired=False
        def raced(path,flags,*args,**kwargs):
            nonlocal fired
            if path=="b" and not fired:
                fired=True
                shutil.rmtree(chosen/"b")
            return real_open(path,flags,*args,**kwargs)
        with patch("observer.fs.os.open",side_effect=raced):
            result=self.call("workspace_glob",aliases=["other"],pattern="selected/*.go")
        self.assertTrue(fired)
        self.assertFalse(result["ok"])
        self.assertNotIn("files",result)
