"""Public artifact boundaries, using synthetic archives only."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from support import PROJECT
from check_release import DIST_INFO, RESOURCE, WHEEL_LICENSE_MEMBERS, inspect

class ReleaseBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (PROJECT/".local/test-data").mkdir(parents=True, exist_ok=True)

    def archive(self, entries, source=False):
        holder = tempfile.TemporaryDirectory(dir=PROJECT/'.local/test-data')
        self.addCleanup(holder.cleanup)
        path = Path(holder.name)/('synthetic.tar.gz' if source else 'synthetic.whl')
        if source:
            with tarfile.open(path, 'w:gz') as out:
                for name, data in entries.items():
                    raw = data.encode()
                    item = tarfile.TarInfo('local_readonly_observer-0.3.3/' + name)
                    item.size = len(raw)
                    out.addfile(item, io.BytesIO(raw))
            return path
        with zipfile.ZipFile(path, 'w') as out:
            for name, data in entries.items():
                out.writestr(name, data)
        return path

    def base(self):
        return {'observer/cli.py':'# synthetic public code', 'observer/runtime.py':'# synthetic runtime',
                **{name: '# synthetic resource' for name in RESOURCE},
                **{name: '# synthetic license fixture' for name in WHEEL_LICENSE_MEMBERS},
                DIST_INFO + '/METADATA': self.metadata()}

    def metadata(self):
        return ('Metadata-Version: 2.4\nName: local-readonly-observer\nVersion: 0.3.3\n'
                'License-Expression: MIT\nLicense-File: LICENSE\nLicense-File: THIRD_PARTY_NOTICES.md\n\n')

    def test_root_license_and_metadata_are_required_in_both_archive_kinds(self):
        source = {name: '# synthetic public fixture' for name in (
            'LICENSE', 'THIRD_PARTY_NOTICES.md', 'README.md', 'README.zh-CN.md', 'SECURITY.md',
            'src/observer/cli.py', 'tests/test_product.py', *('src/' + p for p in RESOURCE))}
        source['PKG-INFO'] = self.metadata()
        for entries, is_source, license_path, metadata_path in (
                (self.base(), False, DIST_INFO + '/licenses/LICENSE', DIST_INFO + '/METADATA'),
                (source, True, 'LICENSE', 'PKG-INFO')):
            self.assertTrue(inspect(self.archive(entries, is_source))['checks_passed'])
            for missing in (license_path, metadata_path):
                changed = {k: v for k, v in entries.items() if k != missing}
                self.assertFalse(inspect(self.archive(changed, is_source))['checks_passed'])
            for metadata in (self.metadata().replace('License-Expression: MIT', 'License-Expression: Apache-2.0'),
                             self.metadata().replace('License-File: LICENSE\n', '')):
                changed = {**entries, metadata_path: metadata}
                report = inspect(self.archive(changed, is_source))
                self.assertFalse(report['checks_passed'])
                self.assertTrue(any(i['category'] == 'missing_or_invalid_license_metadata' for i in report['issues']))

    def test_dependency_license_and_notice_resources_are_required(self):
        for name in RESOURCE:
            entries = self.base()
            del entries[name]
            self.assertFalse(inspect(self.archive(entries))['checks_passed'])

    def test_allowlist_refuses_private_files_and_parent_traversal(self):
        for filename in ('.local/private.json', '../escape.py', '/absolute.py', 'observer/unreviewed.py', 'tests/real-session.jsonl', 'local_readonly_observer_UNREVIEWED.dist-info/METADATA', DIST_INFO + '/licenses/unreviewed.txt'):
            report = inspect(self.archive({**self.base(), filename:'SYNTHETIC_PRIVATE_CANARY'}))
            self.assertFalse(report['checks_passed'])
            self.assertTrue(any(i['category']=='member_outside_allowlist' for i in report['issues']))
            self.assertNotIn('SYNTHETIC_PRIVATE_CANARY', str(report))

    def test_pattern_findings_report_location_without_values(self):
        candidate = 'sk-' + 'SYNTHETIC_ONLY_' * 3
        report = inspect(self.archive({**self.base(), 'observer/cli.py':candidate}))
        self.assertFalse(report['checks_passed'])
        self.assertNotIn(candidate, str(report))
        self.assertEqual(report['issues'][0]['location'], 'observer/cli.py')

    def test_safe_candidate_and_missing_required_content(self):
        self.assertTrue(inspect(self.archive(self.base()))['checks_passed'])
        self.assertFalse(inspect(self.archive({'observer/cli.py':'pass'}))['checks_passed'])

    def test_oversized_or_symlink_members_are_not_accepted(self):
        with self.assertRaises(ValueError):
            inspect(self.archive({**self.base(), 'observer/cli.py':'x'*(1024*1024+1)}))
        path = self.archive(self.base())
        with zipfile.ZipFile(path, 'a') as out:
            item = zipfile.ZipInfo('observer/config.py')
            item.external_attr = 0o120777 << 16
            out.writestr(item, 'outside')
        with self.assertRaises(ValueError):
            inspect(path)
