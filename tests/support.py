from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

PROJECT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
sys.path.insert(0, str(PROJECT / "scripts"))

from build_fixtures import PRIVATE, SECRET, build, event, git, init_repo, jsonl, metadata, snapshot, write
from observer.config import Config
from observer.service import Observer


class ObserverCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent = PROJECT / ".local/test-data"
        parent.mkdir(parents=True, exist_ok=True)
        cls.container = tempfile.TemporaryDirectory(prefix="unit-", dir=parent)
        cls.base = build(Path(cls.container.name) / "fixtures")

    @classmethod
    def tearDownClass(cls):
        cls.container.cleanup()

    def setUp(self):
        self.extra = Path(tempfile.mkdtemp(prefix="case-", dir=self.base))
        values = {
            "workspaces": {"fixture": str(self.base / "workspace"), "fixture_git": str(self.base / "repo"),
                           "clean": str(self.base / "clean_repo"), "other": str(self.extra)},
            "sessions": {"synthetic": str(self.base / "sessions"), "variants": str(self.base / "session_variants"),
                         "cases": str(self.extra)},
            "strict_hardlinks": True,
        }
        self.values = values
        self.config = Config(PROJECT, values)
        self.observer = Observer(self.config)
        self.addCleanup(lambda: shutil.rmtree(self.extra, ignore_errors=True))
        self.addCleanup(self.config.close)

    def call(self, tool, **args):
        result = self.observer.call(tool, args)
        self.secret_free(result)
        self.assertLessEqual(len(json.dumps(result).encode()), 32768)
        self.assertIs(result["observed_content_untrusted"], True)
        return result

    def good(self, tool, **args):
        result = self.call(tool, **args)
        self.assertTrue(result.get("ok"), "tool failed: " + str(result.get("error")))
        return result

    def denied(self, tool, **args):
        result = self.call(tool, **args)
        self.assertFalse(result.get("ok"), "unexpected tool success")
        return result

    def secret_free(self, value):
        serialized = json.dumps(value)
        self.assertTrue(SECRET not in serialized, "synthetic secret leaked")
        self.assertTrue(PRIVATE not in serialized, "reasoning canary leaked")
