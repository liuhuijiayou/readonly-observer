"""Public repository boundaries use only copied public files and synthetic data."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from support import PROJECT
from check_repository import export_repository, inspect_repository, public_files


class PublicRepositoryTests(unittest.TestCase):
    def test_documented_isolated_cli_checks_the_public_tree(self):
        result = subprocess.run(
            [sys.executable, '-I', '-B', str(PROJECT/'scripts/check_repository.py')],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])

    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix='observer-public-', dir=Path('/tmp').resolve())
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name)
        self.root = self.base/'source'
        self.root.mkdir()
        for name in public_files(PROJECT):
            target = self.root/name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(PROJECT/name, target)

    def test_private_files_are_neither_scanned_nor_exported(self):
        private = self.root/'.local/never-read.jsonl'
        private.parent.mkdir()
        private.write_text('sk-' + 'PRIVATE_CANARY_' * 3)
        report = export_repository(self.root, self.base/'export')
        self.assertTrue(report['ok'])
        self.assertNotIn('PRIVATE_CANARY', json.dumps(report))
        exported = {str(p.relative_to(self.base/'export')) for p in (self.base/'export').rglob('*') if p.is_file()}
        self.assertEqual(exported, set(public_files(self.root)))

    def test_public_pattern_reports_location_without_value_and_blocks_export(self):
        canary = 'sk-' + 'SYNTHETIC_CANARY_' * 3
        (self.root/'README.md').write_text(canary)
        report = inspect_repository(self.root)
        self.assertFalse(report['ok'])
        self.assertNotIn(canary, json.dumps(report))
        self.assertEqual(report['issues'][0]['location'], 'README.md')
        with self.assertRaises(ValueError):
            export_repository(self.root, self.base/'export')
        self.assertFalse((self.base/'export').exists())

    def test_public_symlink_and_hardlink_are_refused(self):
        path = self.root/'README.md'
        path.unlink()
        path.symlink_to(self.root/'README.zh-CN.md')
        self.assertFalse(inspect_repository(self.root)['ok'])
        path.unlink()
        os.link(self.root/'README.zh-CN.md', path)
        self.assertFalse(inspect_repository(self.root)['ok'])

    def test_public_parent_symlink_is_refused(self):
        source = self.root/'examples'
        source.rename(self.base/'external-examples')
        source.symlink_to(self.base/'external-examples', target_is_directory=True)
        self.assertFalse(inspect_repository(self.root)['ok'])

    def test_manifest_and_gitignore_policy_drift_is_reported(self):
        for name in ('.gitignore', 'MANIFEST.in'):
            with (self.root/name).open('a') as stream:
                stream.write('# unintended drift\n')
        report = inspect_repository(self.root)
        self.assertEqual({i['location'] for i in report['issues']}, {'.gitignore','MANIFEST.in'})

    def test_manifest_traversal_fails_before_any_export(self):
        (self.root/'PUBLIC_FILES.txt').write_text('../outside\n')
        with self.assertRaises(ValueError):
            export_repository(self.root, self.base/'export')
        self.assertFalse((self.base/'export').exists())

    def test_root_license_cannot_be_omitted_from_public_manifest(self):
        manifest = self.root/'PUBLIC_FILES.txt'
        manifest.write_text('\n'.join(p for p in manifest.read_text().splitlines() if p != 'LICENSE') + '\n')
        with self.assertRaises(ValueError):
            export_repository(self.root, self.base/'export')
        self.assertFalse((self.base/'export').exists())

    def test_existing_export_is_never_overwritten(self):
        target = self.base/'export'
        target.mkdir()
        (target/'keep').write_text('existing')
        with self.assertRaises(ValueError):
            export_repository(self.root, target)
        self.assertEqual((target/'keep').read_text(), 'existing')

    def test_symlink_export_is_refused(self):
        target = self.base/'export'
        target.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            export_repository(self.root, target)
        self.assertTrue(inspect_repository(self.root)['ok'])
