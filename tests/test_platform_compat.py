"""Mac compatibility uses synthetic values only; native frameworks never read keys."""
import builtins
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from support import PROJECT
from observer.profile import Store, DEFAULTS, location
from observer.credentials import Keychain, validate_key
from observer import cli, runtime


class MacCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.holder = tempfile.TemporaryDirectory(prefix='ob-mac-', dir=Path('/tmp').resolve())
        self.addCleanup(self.holder.cleanup)
        self.store = Store(Path(self.holder.name) / 'mac')

    def test_mac_init_keeps_exact_v1_defaults_and_no_linux_imports(self):
        real_import = builtins.__import__
        def guarded(name, *args, **kwargs):
            if 'linux' in name:
                raise AssertionError('Mac imported Linux module')
            return real_import(name, *args, **kwargs)
        with patch('sys.platform', 'darwin'), patch('builtins.__import__', side_effect=guarded), redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--home', str(self.store.home), 'init', '--non-interactive']), 0)
            self.assertEqual(cli.main(['--home', str(self.store.home), 'credentials', 'info']), 0)
        self.assertEqual(self.store.settings(), DEFAULTS)
        self.assertEqual(list(self.store.home.joinpath('config').glob('node.json')), [])
        self.assertEqual(self.store.config.entries()['entries'], [])

    def test_mac_paths_keychain_namespace_and_upgrade_are_unchanged(self):
        with patch('sys.platform', 'darwin'), patch.dict('os.environ', {}, clear=True):
            self.assertEqual(location(), Path.home() / 'Library/Application Support/ReadOnlyObserver')
        self.store.initialize()
        expected = ('readonly-observer.' + hashlib.sha256(str(self.store.home).encode()).hexdigest()[:24] + '.tunnel-runtime').encode()
        self.assertEqual(self.store.keychain().service, expected)
        self.assertEqual(self.store.keychain().account, b'runtime')
        self.assertEqual(self.store.upgrade(), {'upgraded': False, 'format': 1})
        self.assertEqual(self.store.settings(), DEFAULTS)

    def test_mac_cli_dispatch_still_uses_original_manager(self):
        self.store.initialize()
        with patch('sys.platform', 'darwin'), patch('observer.runtime.start', return_value={'ready': False}) as start:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['--home', str(self.store.home), 'start']), 0)
        start.assert_called_once()
        self.assertIs(type(start.call_args.args[0]), Store)

    def test_keychain_find_add_modify_free_use_original_api_with_synthetic_value(self):
        keychain = self.store.keychain()
        sec, cf = Mock(), Mock()
        sec.SecKeychainFindGenericPassword.return_value = -25300
        sec.SecKeychainAddGenericPassword.return_value = 0
        with patch.object(keychain, '_libraries', return_value=(sec, cf)):
            keychain.save_from_local_settings('SYNTHETIC_MAC_KEY', confirmed=True)
        sec.SecKeychainAddGenericPassword.assert_called_once()
        self.assertEqual(sec.SecKeychainFindGenericPassword.call_args.args[2], keychain.service)
        sec.reset_mock()
        sec.SecKeychainFindGenericPassword.return_value = 0
        sec.SecKeychainItemModifyAttributesAndData.return_value = 0
        with patch.object(keychain, '_libraries', return_value=(sec, cf)):
            keychain.save_from_local_settings('SYNTHETIC_ROTATED_MAC_KEY', confirmed=True)
        sec.SecKeychainItemModifyAttributesAndData.assert_called_once()
        cf.CFRelease.assert_called_once()

    def test_mac_tunnel_config_and_worker_clean_boundary_remain_original(self):
        value = runtime.client_config(self.store, {'tunnel_id': 'tunnel_' + 'a' * 32})
        self.assertEqual(set(value['control_plane']), {'base_url', 'tunnel_id', 'api_key'})
        self.assertIn('_serve-active', value['mcp']['commands'][0]['command'])
        self.assertIn('env -i', value['mcp']['commands'][0]['command'])
        self.assertNotIn('CREDENTIALS_DIRECTORY', runtime.environment())

    @unittest.skipUnless(sys.platform == 'darwin', 'native macOS frameworks unverified on Linux; no real credential access')
    def test_native_keychain_framework_signatures_load_without_accessing_any_item(self):
        sec, cf = Keychain()._libraries()
        self.assertIsNotNone(sec.SecKeychainFindGenericPassword.argtypes)
        self.assertIsNotNone(cf.CFRelease.argtypes)
