"""Pure synthetic legacy staging; real systemd coverage is a separate script."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from support import PROJECT
from observer.security import Refusal

if sys.platform.startswith('linux'):
    from observer.linux import LinuxStore
    from observer.linux_credentials import stage
    from observer import linux_legacy as legacy
    from observer.linux_systemd import render, detect_version, features

KEY = 'SYNTHETIC_219_RUNTIME'
PROXY = 'http://test-user:test-password@proxy.invalid:8080'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux-only systemd adapter')
class VersionTests(unittest.TestCase):
    def test_version_comes_from_active_manager(self):
        for body, expected in [(b'Version=219\n', 219), (b'Version=249.11-0ubuntu3\n', 249), (b'Version=257 (257.4)\n', 257)]:
            result = subprocess.CompletedProcess([], 0, stdout=body)
            with patch('observer.linux_systemd.subprocess.run', return_value=result) as call:
                self.assertEqual(detect_version(), expected)
            self.assertEqual(call.call_args.args[0], ['/bin/systemctl', 'show', '--property=Version'])
            self.assertNotIn('CREDENTIALS_DIRECTORY', call.call_args.kwargs['env'])

    def test_unavailable_or_invalid_version_fails_closed(self):
        for code, body in [(1, b''), (0, b'Linux 219'), (0, b'Version=\n'), (0, b'Version=219\nOther=x\n')]:
            with patch('observer.linux_systemd.subprocess.run', return_value=subprocess.CompletedProcess([], code, stdout=body)):
                with self.assertRaises(Refusal): detect_version()
        for error in (OSError(), subprocess.TimeoutExpired('systemctl', 5)):
            with patch('observer.linux_systemd.subprocess.run', side_effect=error):
                with self.assertRaises(Refusal): detect_version()

    def test_feature_matrix_uses_each_directives_introduction_version(self):
        for version in (219, 220, 230, 231, 232, 246):
            self.assertFalse(features(version)['native_credentials'])
            self.assertEqual(features(version)['strict_paths'], version >= 232)
            self.assertEqual(features(version)['path_directives'], version >= 231)
        for version in (247, 249, 257):
            self.assertTrue(features(version)['native_credentials'])
        for version in (218, 0, True, '219'):
            with self.assertRaises(Refusal): features(version)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid() == 0, 'legacy staging is root-only')
class LegacyStagingTests(unittest.TestCase):
    def setUp(self):
        parent = PROJECT / '.local/test-data'
        parent.mkdir(parents=True, exist_ok=True)
        self.holder = tempfile.TemporaryDirectory(prefix='s219-', dir=parent)
        self.addCleanup(self.holder.cleanup)
        self.base = Path(self.holder.name)
        self.store = LinuxStore(self.base / 'i')
        self.store.initialize()
        self.store.set_transport({'kind': 'tunnel', 'client': '/synthetic/not-executed', 'tunnel_id': 'tunnel_' + 'e' * 32})
        self.store.set_proxy(True)
        stage(self.store, 'runtime', KEY)
        stage(self.store, 'proxy', PROXY)
        self.target = self.base / 'runtime'
        self.target.mkdir(mode=0o700)
        self.scope = patch.object(legacy, 'runtime_path', return_value=self.target)
        self.scope.start(); self.addCleanup(self.scope.stop)
        self.env = patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(self.target)}, clear=True)
        self.env.start(); self.addCleanup(self.env.stop)

    def prepare(self):
        with patch.object(legacy, 'is_tmpfs', return_value=True):
            return legacy.prepare(self.store)

    def assert_empty(self):
        self.assertEqual(list(self.target.iterdir()), [])

    def test_complete_enabled_copy_only_and_unchanged_provider(self):
        (self.store.home / 'credentials/ignored').write_text('not a credential')
        self.assertEqual(self.prepare()['prepared'], 2)
        self.assertEqual({p.name for p in self.target.iterdir()}, {self.store.credential_name(), self.store.credential_name('proxy')})
        for path in self.target.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(self.store.credential().get(), KEY)
        self.assertEqual(self.store.credential('proxy').get(), PROXY)
        self.assertEqual((self.target.stat().st_mode & 0o777), 0o700)

    def test_disabled_proxy_is_never_opened_or_copied(self):
        self.store.set_proxy(False)
        proxy = self.store.home / 'credentials/proxy'
        proxy.unlink(); proxy.symlink_to('/synthetic/never-follow')
        self.assertEqual(self.prepare()['prepared'], 1)
        self.assertEqual(len(list(self.target.iterdir())), 1)

    def test_no_tmpfs_no_root_or_wrong_directory_refuses_without_copy(self):
        with patch.object(legacy, 'is_tmpfs', return_value=False), self.assertRaises(Refusal): legacy.prepare(self.store)
        self.assert_empty()
        with patch('observer.linux_legacy.os.geteuid', return_value=1), self.assertRaises(Refusal): self.prepare()
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': '/run/wrong-instance'}), self.assertRaises(Refusal): self.prepare()
        self.assert_empty()

    def test_conflict_is_preserved_and_repeat_is_refused(self):
        conflict = self.target / self.store.credential_name()
        conflict.write_text('unexpected old startup')
        with self.assertRaises(Refusal): self.prepare()
        self.assertEqual(conflict.read_text(), 'unexpected old startup')
        conflict.unlink()
        self.prepare()
        before = {p.name: p.stat().st_ino for p in self.target.iterdir()}
        with self.assertRaises(Refusal): self.prepare()
        self.assertEqual(before, {p.name: p.stat().st_ino for p in self.target.iterdir()})

    def test_missing_invalid_or_public_source_leaves_no_partial_files(self):
        path = self.store.home / 'credentials/proxy'
        for value in (None, '', 'bad proxy', 'http://proxy.invalid\ninvalid', 'x' * 8194):
            if path.exists(): path.unlink()
            if value is not None: path.write_text(value); path.chmod(0o600)
            with self.assertRaises(Refusal): self.prepare()
            self.assert_empty()
        stage(self.store, 'proxy', PROXY)
        path.chmod(0o644)
        with self.assertRaises(Refusal): self.prepare()
        self.assert_empty()

    def test_symlink_fifo_hardlink_and_foreign_owner_refused(self):
        path = self.store.home / 'credentials/runtime'
        path.unlink(); path.symlink_to(self.store.home / 'credentials/proxy')
        with self.assertRaises(Refusal): self.prepare()
        self.assert_empty(); path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaises(Refusal): self.prepare()
        self.assert_empty(); path.unlink()
        os.link(self.store.home / 'credentials/proxy', path)
        with self.assertRaises(Refusal): self.prepare()
        self.assert_empty(); path.unlink()
        stage(self.store, 'runtime', KEY)
        os.chown(path, 12345, 12345)
        try:
            with self.assertRaises(Refusal): self.prepare()
            self.assert_empty()
        finally: os.chown(path, 0, 0)

    def test_source_replacement_during_read_is_detected(self):
        real = legacy.os.read
        def raced(fd, size):
            result = real(fd, size)
            path = self.store.home / 'credentials/runtime'
            if path.exists(): path.rename(path.with_name('replaced'))
            stage(self.store, 'runtime', KEY + '_CHANGED')
            return result
        with patch.object(legacy.os, 'read', side_effect=raced), self.assertRaises(Refusal): self.prepare()
        self.assert_empty()

    def test_second_publish_failure_rolls_back_first_credential(self):
        real = os.link
        calls = 0
        def fail(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('synthetic failure')
            return real(*args, **kwargs)
        with patch.object(legacy.os, 'link', side_effect=fail), self.assertRaises(Refusal): self.prepare()
        self.assert_empty()

    def test_write_and_fsync_failures_clean_all_created_files(self):
        for name in ('write', 'fsync'):
            with patch.object(legacy.os, name, side_effect=OSError('synthetic failure')), self.assertRaises(Refusal): self.prepare()
            self.assert_empty()

    def test_runtime_mode_and_symlink_refuse(self):
        self.target.chmod(0o755)
        with self.assertRaises(Refusal): self.prepare()
        self.target.chmod(0o700)
        self.target.rename(self.base / 'real-runtime')
        self.target.symlink_to(self.base / 'real-runtime', target_is_directory=True)
        with self.assertRaises(Refusal): self.prepare()

    def test_unit219_paths_backend_order_and_version_autodetection(self):
        with patch('observer.linux_systemd.detect_version', return_value=219) as detect:
            unit = render(self.store)
        detect.assert_called_once()
        for forbidden in ('LoadCredential=', 'ProtectSystem=strict', 'ReadWritePaths=', 'WorkingDirectory="'):
            self.assertNotIn(forbidden, unit)
        for required in ('RuntimeDirectory=', 'RuntimeDirectoryMode=0700', 'Environment=CREDENTIALS_DIRECTORY=',
                         'ReadOnlyDirectories=/', 'ReadWriteDirectories=', 'ProtectSystem=full', 'PrivateTmp=true',
                         'NoNewPrivileges=true', 'KillMode=control-group', 'UMask=0077', 'LimitCORE=0'):
            self.assertIn(required, unit)
        self.assertLess(unit.index('RuntimeDirectory='), unit.index(' recover --approve'))
        self.assertLess(unit.index(' recover --approve'), unit.index(' _stage-credentials'))
        self.assertLess(unit.index(' _stage-credentials'), unit.index(' run\n'))
        self.assertNotIn(KEY, unit); self.assertNotIn(PROXY, unit)

    def test_intermediate_units_select_directives_independently(self):
        for version in (219, 230, 231, 232, 246):
            unit = render(self.store, version=version)
            self.assertIn('_stage-credentials', unit)
            self.assertNotIn('LoadCredential=', unit)
            self.assertEqual('ReadWritePaths=' in unit, version >= 231)
            self.assertEqual('ReadWriteDirectories=' in unit, version < 231)
            self.assertEqual('ProtectSystem=strict' in unit, version >= 232)

    def test_source_directory_permissions_and_symlink_are_refused(self):
        directory = self.store.home / 'credentials'
        directory.chmod(0o755)
        with self.assertRaises(Refusal): self.prepare()
        self.assert_empty()
        directory.chmod(0o700)
        destination = self.store.home / 'saved-source'
        directory.rename(destination)
        directory.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(Refusal): self.prepare()
        self.assert_empty()

    def test_native247_has_no_staging_and_keeps_loadcredential(self):
        for version in (247, 249):
            unit = render(self.store, version=version)
            self.assertIn('LoadCredential=' + self.store.credential_name(), unit)
            self.assertIn('LoadCredential=' + self.store.credential_name('proxy'), unit)
            self.assertIn('ProtectSystem=strict', unit)
            self.assertNotIn('_stage-credentials', unit)
            self.assertNotIn('Environment=CREDENTIALS_DIRECTORY=', unit)

    def test_219_rejects_ambiguous_home_and_python_paths(self):
        for suffix in ('with space', 'percent%', 'dollar$', 'quote"', 'slash\\'):
            with patch.object(self.store, 'home', self.base / suffix), self.assertRaises(Refusal): render(self.store, version=219)
        with patch('observer.linux_systemd.sys.executable', '/bad path/python'), self.assertRaises(Refusal): render(self.store, version=219)
