"""Linux-only synthetic credentials, processes, nodes and systemd rendering."""
import asyncio
from contextlib import redirect_stdout, redirect_stderr
from datetime import timedelta
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from support import event, jsonl, metadata
from observer import nodes, runtime as common
from observer.cli import main
from observer.security import Refusal

if sys.platform.startswith('linux'):
    from observer.linux import LinuxStore
    from observer import linux_runtime as runtime
    from observer.linux_credentials import SystemdCredentials, stage, validate_proxy
    from observer.linux_systemd import render

CANARY = 'SYNTHETIC_RUNTIME_CANARY'
PROXY = 'http://synthetic-user:synthetic-password@proxy.invalid:8080'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux adapter; macOS uses its original implementation')
class LinuxTests(unittest.TestCase):
    def setUp(self):
        self.holder = tempfile.TemporaryDirectory(prefix='ob-', dir=Path('/tmp').resolve())
        self.addCleanup(self.holder.cleanup)
        self.base = Path(self.holder.name)
        self.stores = []
        self.addCleanup(self.stop_all)
        self.store = self.instance('one')

    def instance(self, name):
        store = LinuxStore(self.base / name)
        store.initialize()
        project = self.base / (name + '-code')
        project.mkdir()
        (project / 'public.txt').write_text(name + ' public marker\n')
        store.config.register_workspace('code', str(project), lambda _: True)
        self.stores.append(store)
        return store

    def stop_all(self):
        for store in self.stores:
            try:
                runtime.stop(store)
            except Exception:
                pass

    def cli(self, store, *args, code=0):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            result = main(['--home', str(store.home), *args])
        self.assertEqual(result, code, out.getvalue())
        self.assertNotIn(CANARY, out.getvalue() + err.getvalue())
        return json.loads(out.getvalue())

    def credential_dir(self, store, key=CANARY, proxy=None):
        directory = self.base / ('load-' + store.home.name)
        directory.mkdir(mode=0o700, exist_ok=True)
        for kind, value in [('runtime', key)] + ([('proxy', proxy)] if proxy else []):
            path = directory / store.credential_name(kind)
            path.write_text(value)
            path.chmod(0o400)
        return directory

    def fake_client(self):
        path = self.base / 'synthetic-client'
        path.write_text('''#!''' + sys.executable + '''
import hashlib,json,os,pathlib,signal,sys,time
home=pathlib.Path.cwd()
config=json.loads(pathlib.Path(sys.argv[sys.argv.index('--config')+1]).read_text())
record={'key':hashlib.sha256(os.environ['CONTROL_PLANE_API_KEY'].encode()).hexdigest(),
        'proxy':hashlib.sha256(os.environ.get('OBSERVER_TUNNEL_PROXY','').encode()).hexdigest(),
        'ambient_proxy':any(k in os.environ for k in ['HTTPS_PROXY','HTTP_PROXY','ALL_PROXY']),
        'credential_directory':'CREDENTIALS_DIRECTORY' in os.environ,
        'tunnel':config['control_plane']['tunnel_id']}
(home/'cache/client.json').write_text(json.dumps(record))
def stop(*args):
    (home/'cache/client-stopped').write_text('stopped')
    raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
while not (home/'cache/exit-client').exists(): time.sleep(.03)
raise SystemExit(3)
''')
        path.chmod(0o700)
        return path

    def wait_until(self, predicate, seconds=6):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.03)
        self.fail('synthetic process condition timed out')

    async def call(self, store, name='observer_info', args=None):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        argv = common.argv(store, 'connect')
        params = StdioServerParameters(command=argv[0], args=argv[1:], env=common.environment(), cwd=str(store.home))
        with open(os.devnull, 'w') as err:
            async with stdio_client(params, errlog=err) as (read, write):
                async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=5)) as session:
                    await session.initialize()
                    tools = (await session.list_tools()).tools
                    self.assertEqual(len(tools), 13)
                    self.assertTrue(all(t.annotations.readOnlyHint and not t.annotations.destructiveHint for t in tools))
                    result = await session.call_tool(name, args or {})
                    return json.loads(result.content[0].text)

    def test_provider_fails_closed_without_systemd_even_with_ambient_key(self):
        with patch.dict(os.environ, {'CONTROL_PLANE_API_KEY': CANARY, 'OPENAI_API_KEY': CANARY}, clear=True):
            with self.assertRaises(Refusal):
                self.store.credential().get()
        stage(self.store, 'runtime', CANARY)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(Refusal):
            self.store.credential().get()

    def test_provider_reads_only_exact_instance_id_and_accepts_one_newline(self):
        other = self.instance('two')
        directory = self.credential_dir(self.store, CANARY + '\n')
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(directory)}, clear=True):
            self.assertEqual(self.store.credential().get(), CANARY)
            with self.assertRaises(Refusal):
                other.credential().get()
        self.assertNotEqual(self.store.credential_name(), other.credential_name())

    def test_provider_refuses_public_directory_modes_symlinks_hardlinks_fifo_and_bad_values(self):
        directory = self.credential_dir(self.store)
        path = directory / self.store.credential_name()
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(directory)}, clear=True):
            directory.chmod(0o755)
            with self.assertRaises(Refusal): self.store.credential().get()
            directory.chmod(0o700)
            for mode in (0o644, 0o440, 0o000):
                path.chmod(mode)
                with self.assertRaises(Refusal): self.store.credential().get()
            path.chmod(0o400)
            target = self.base / 'value'
            path.rename(target)
            path.symlink_to(target)
            with self.assertRaises(Refusal): self.store.credential().get()
            path.unlink()
            os.link(target, path)
            with self.assertRaises(Refusal): self.store.credential().get()
            path.unlink()
            os.mkfifo(path, 0o600)
            with self.assertRaises(Refusal): self.store.credential().get()
            path.unlink()
            for value in ('', 'bad\nvalue', 'x' * 8194, '\u4e2d\u6587'):
                path.write_text(value)
                path.chmod(0o400)
                with self.assertRaises(Refusal): self.store.credential().get()

    def test_provider_refuses_symlink_parent_and_foreign_uid(self):
        directory = self.credential_dir(self.store)
        link = self.base / 'link'
        link.symlink_to(directory, target_is_directory=True)
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(link)}, clear=True), self.assertRaises(Refusal):
            self.store.credential().get()
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(directory)}, clear=True), patch('observer.linux_credentials.os.getuid', return_value=os.getuid() + 1):
            with self.assertRaises(Refusal): self.store.credential().get()

    def test_staging_rotation_is_private_atomic_and_not_normal_config(self):
        stage(self.store, 'runtime', CANARY)
        source = self.store.home / 'credentials/runtime'
        first_inode = source.stat().st_ino
        stage(self.store, 'runtime', CANARY + '_NEW')
        self.assertNotEqual(source.stat().st_ino, first_inode)
        self.assertEqual(source.stat().st_mode & 0o777, 0o600)
        self.assertEqual(source.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(CANARY, json.dumps(self.store.snapshot()))
        self.assertFalse(list(source.parent.glob('.pending-*')))

    def test_proxy_url_validation(self):
        self.assertEqual(validate_proxy(PROXY), PROXY)
        for value in ('socks5://proxy.invalid:1', 'https://', 'https://proxy.invalid/path', 'http://proxy.invalid:99999',
                      'http://proxy.invalid?token=bad', 'http://proxy.invalid\n'):
            with self.subTest(value=value), self.assertRaises(Refusal): validate_proxy(value)

    def test_systemd_unit_is_instance_specific_and_contains_references_only(self):
        binary = self.fake_client()
        self.store.set_transport({'kind': 'tunnel', 'client': str(binary), 'tunnel_id': 'tunnel_' + 'a' * 32})
        self.store.set_proxy(True)
        unit = render(self.store, version=247)
        self.assertIn('LoadCredential=' + self.store.credential_name(), unit)
        self.assertIn('LoadCredential=' + self.store.credential_name('proxy'), unit)
        self.assertIn('KillMode=control-group', unit)
        self.assertIn(' recover --approve', unit)
        self.assertIn(' run', unit)
        self.assertNotIn(CANARY, unit)
        self.assertNotIn(PROXY, unit)
        self.assertNotIn('tunnel_' + 'a' * 32, unit)
        self.assertNotIn('LoadCredential=', render(self.instance('stdio'), version=247))

    def test_three_simulated_nodes_parallel_mcp_isolation_and_stop_one(self):
        stores = [self.store, self.instance('linux1'), self.instance('linux2')]
        for store, name in zip(stores, ['codex-observer-mac', 'codex-observer-linux1', 'codex-observer-linux2']):
            nodes.configure(store, name=name)
            runtime.start(store)
        async def check():
            infos = await asyncio.gather(*(self.call(s) for s in stores))
            reads = await asyncio.gather(*(self.call(s, 'workspace_read', {'alias': 'code', 'path': 'public.txt'}) for s in stores))
            return infos, reads
        infos, reads = asyncio.run(check())
        self.assertEqual(len({i['node']['id'] for i in infos}), 3)
        self.assertEqual([i['node']['name'] for i in infos], ['codex-observer-mac', 'codex-observer-linux1', 'codex-observer-linux2'])
        for store, read in zip(stores, reads):
            self.assertIn(store.home.name + ' public marker', json.dumps(read))
        self.assertEqual(len({common.socket_path(s, 'mcp.sock') for s in stores}), 3)
        self.assertEqual(len({s.keychain().service for s in stores}), 3)
        runtime.stop(stores[1])
        self.assertEqual(runtime.status(stores[0])['manager'], 'running')
        self.assertEqual(runtime.status(stores[2])['manager'], 'running')
        self.assertTrue(asyncio.run(self.call(stores[2]))['ok'])
        for info in infos:
            self.assertNotIn(str(self.base), json.dumps(info['node']))

    def test_two_synthetic_tunnels_distinct_credentials_and_proxy_isolation(self):
        stores = [self.store, self.instance('two')]
        binary = self.fake_client()
        for index, store in enumerate(stores):
            store.set_transport({'kind': 'tunnel', 'client': str(binary), 'tunnel_id': 'tunnel_' + str(index) * 32})
            store.set_proxy(True)
            directory = self.credential_dir(store, CANARY + str(index), PROXY)
            with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(directory), 'HTTPS_PROXY': PROXY}):
                runtime.start(store)
        for index, store in enumerate(stores):
            record_path = store.home / 'cache/client.json'
            self.wait_until(record_path.exists)
            record = json.loads(record_path.read_text())
            self.assertEqual(record['key'], hashlib.sha256((CANARY + str(index)).encode()).hexdigest())
            self.assertEqual(record['proxy'], hashlib.sha256(PROXY.encode()).hexdigest())
            self.assertFalse(record['ambient_proxy'])
            self.assertFalse(record['credential_directory'])
            config = store.state.read_file('transport.json')
            self.assertEqual(config['control_plane']['http_proxy'], 'env:OBSERVER_TUNNEL_PROXY')
            self.assertIn('env -i', config['mcp']['commands'][0]['command'])
            self.assertNotIn(CANARY, json.dumps(config))
            self.assertTrue(asyncio.run(self.call(store))['ok'])
        runtime.stop(stores[0])
        self.assertEqual(runtime.status(stores[1])['manager'], 'running')

    def test_actual_worker_spawn_environment_excludes_all_transport_credentials_and_proxy(self):
        import threading
        binary = self.fake_client()
        self.store.set_transport({'kind': 'tunnel', 'client': str(binary), 'tunnel_id': 'tunnel_' + '6' * 32})
        self.store.set_proxy(True)
        directory = self.credential_dir(self.store, CANARY, PROXY)
        real_spawn = subprocess.Popen
        captured, errors = [], []
        def launch(args, **kwargs):
            if '_serve-active' in args:
                captured.append(dict(kwargs['env']))
            return real_spawn(args, **kwargs)
        def drive():
            try:
                self.wait_until(lambda: common.status(self.store)['manager'] == 'running')
                self.assertTrue(asyncio.run(self.call(self.store))['ok'])
            except BaseException as error:
                errors.append(error)
            finally:
                try: common.request(self.store, 'stop')
                except Exception: pass
        driver = threading.Thread(target=drive, daemon=True)
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(directory), 'HTTPS_PROXY': PROXY,
                                     'OPENAI_API_KEY': CANARY}), patch('observer.linux_runtime.subprocess.Popen', side_effect=launch):
            driver.start()
            result = runtime.manage(self.store)
        driver.join(timeout=8)
        self.assertEqual(result, 0)
        self.assertFalse(driver.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(captured)
        self.assertTrue(all(env == common.environment() for env in captured))
        for folder in ('config', 'state', 'logs', 'cache'):
            for path in (self.store.home / folder).rglob('*'):
                if path.is_file():
                    self.assertNotIn(CANARY.encode(), path.read_bytes())
                    self.assertNotIn(PROXY.encode(), path.read_bytes())

    def test_duplicate_tunnel_lease_fails_closed(self):
        identifier = 'tunnel_' + 'b' * 32
        fd = runtime.tunnel_lease(identifier)
        try:
            with self.assertRaises(Refusal): runtime.tunnel_lease(identifier)
            other = runtime.tunnel_lease('tunnel_' + 'c' * 32)
            os.close(other)
        finally:
            os.close(fd)
        os.close(runtime.tunnel_lease(identifier))

    def test_missing_key_or_proxy_never_launches_client_or_leaves_active_state(self):
        binary = self.fake_client()
        self.store.set_transport({'kind': 'tunnel', 'client': str(binary), 'tunnel_id': 'tunnel_' + 'd' * 32})
        with patch.dict(os.environ, {}, clear=True), patch('observer.linux_runtime.subprocess.Popen') as spawn:
            self.assertEqual(runtime.manage(self.store), 2)
        spawn.assert_not_called()
        self.store.set_proxy(True)
        directory = self.credential_dir(self.store)
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(directory)}, clear=True), patch('observer.linux_runtime.subprocess.Popen') as spawn:
            self.assertEqual(runtime.manage(self.store), 2)
        spawn.assert_not_called()
        self.assertFalse((self.store.home / 'state/active.json').exists())
        self.assertFalse(common.locked(self.store))

    def test_crash_worker_lease_cleanup_recovery_and_restart(self):
        manager = subprocess.Popen(common.argv(self.store, 'run'), env=common.environment(), cwd=self.store.home,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: manager.poll() is None and manager.kill())
        self.wait_until(lambda: runtime.status(self.store)['manager'] == 'running')
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.connect(common.endpoint(self.store, 'mcp.sock'))
        connection.sendall(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"synthetic","version":"1"}}}\n')
        connection.settimeout(5)
        self.assertIn(b'"id":1', connection.recv(8192))
        with self.assertRaises(Refusal): runtime.recover(self.store)
        manager.kill()
        manager.wait(timeout=5)
        self.assertEqual(connection.recv(8192), b'')
        self.wait_until(lambda: not common.locked(self.store))
        result = runtime.recover(self.store)
        self.assertGreaterEqual(result['recovered_files'], 3)
        runtime.start(self.store)
        self.assertTrue(asyncio.run(self.call(self.store))['ok'])

    def test_crash_manager_closes_synthetic_tunnel_and_releases_lease(self):
        binary = self.fake_client()
        self.store.set_transport({'kind': 'tunnel', 'client': str(binary), 'tunnel_id': 'tunnel_' + 'e' * 32})
        directory = self.credential_dir(self.store)
        env = {**common.environment(), 'CREDENTIALS_DIRECTORY': str(directory)}
        manager = subprocess.Popen(common.argv(self.store, 'run'), env=env, cwd=self.store.home,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: manager.poll() is None and manager.kill())
        self.wait_until((self.store.home / 'cache/client.json').exists)
        manager.kill()
        manager.wait(timeout=5)
        self.wait_until((self.store.home / 'cache/client-stopped').exists)
        self.wait_until(lambda: not common.locked(self.store))
        runtime.recover(self.store)
        os.close(runtime.tunnel_lease(self.store.settings()['transport']['tunnel_id']))

    def test_synthetic_transport_exit_cleans_state_and_supports_restart(self):
        binary = self.fake_client()
        self.store.set_transport({'kind': 'tunnel', 'client': str(binary), 'tunnel_id': 'tunnel_' + 'f' * 32})
        directory = self.credential_dir(self.store)
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(directory)}):
            runtime.start(self.store)
            self.wait_until((self.store.home / 'cache/client.json').exists)
            (self.store.home / 'cache/exit-client').touch()
            self.wait_until(lambda: runtime.status(self.store)['manager'] == 'not_running')
            self.assertFalse((self.store.home / 'state/active.json').exists())
            (self.store.home / 'cache/exit-client').unlink()
            runtime.start(self.store)
            self.assertTrue(asyncio.run(self.call(self.store))['ok'])

    def test_recovery_refuses_unknown_or_symlink_artifacts(self):
        path = self.store.home / 'state/active.json'
        path.symlink_to(self.base / 'absent')
        with self.assertRaises(Refusal): runtime.recover(self.store)
        self.assertTrue(path.is_symlink())

    def test_revoke_and_retire_stop_workers_clear_grants_and_do_not_claim_remote_revocation(self):
        runtime.start(self.store)
        revoked = self.cli(self.store, 'revoke', '--approve')
        self.assertEqual(revoked['runtime_key'], 'not_revoked')
        self.assertEqual(revoked['platform_permissions'], 'not_revoked')
        self.assertEqual(revoked['chatgpt_connection'], 'unchanged')
        self.assertFalse(self.store.config.entries()['entries'])
        self.assertEqual(runtime.status(self.store)['manager'], 'not_running')
        with self.assertRaises(Refusal): runtime.start(self.store)
        self.cli(self.store, 'node', 'retire', '--approve')
        self.assertEqual(nodes.identity(self.store)['status'], 'retired')
        self.cli(self.store, 'node', 'activate', '--approve')
        self.assertEqual(nodes.identity(self.store)['status'], 'active')
        self.assertFalse(self.store.config.entries()['entries'])

    def test_replacement_preserves_tunnel_and_public_node_but_never_copies_grants_or_keys(self):
        replacement = LinuxStore(self.base / 'replacement')
        replacement.initialize()
        old = nodes.identity(self.store)
        nodes.configure(replacement, name=old['name'], identifier=old['id'])
        self.assertEqual(nodes.identity(replacement), old)
        self.assertEqual(replacement.config.entries()['entries'], [])
        self.assertNotEqual(replacement.credential_name(), self.store.credential_name())
        tunnel = {'kind': 'tunnel', 'client': str(self.fake_client()), 'tunnel_id': 'tunnel_' + '9' * 32}
        self.store.set_transport(tunnel)
        replacement.set_transport(tunnel)
        self.assertEqual(replacement.settings()['transport']['tunnel_id'], self.store.settings()['transport']['tunnel_id'])
        self.assertFalse((replacement.home / 'credentials/runtime').exists())
        self.assertFalse((replacement.home / 'state/active.json').exists())
        with self.assertRaises(Refusal): replacement.configuration()

    def test_exact_session_authorization_does_not_expose_siblings_or_reasoning(self):
        path = self.base / 'sessions/chosen.jsonl'
        jsonl(path, [metadata('chosen', self.base), event('event_msg', {'type': 'user_message', 'message': 'public marker'}),
                     event('response_item', {'type': 'message', 'role': 'assistant', 'channel': 'analysis',
                                             'content': [{'type': 'output_text', 'text': 'SYNTHETIC_HIDDEN_REASONING'}]})])
        jsonl(path.parent / 'sibling.jsonl', [metadata('sibling', self.base)])
        self.store.config.register_session('exact', str(path), '', lambda _: True)
        runtime.start(self.store)
        read = asyncio.run(self.call(self.store, 'session_read', {'source': 'exact', 'session_id': 'chosen'}))
        self.assertTrue(read['ok'])
        self.assertNotIn('SYNTHETIC_HIDDEN_REASONING', json.dumps(read))
        denied = asyncio.run(self.call(self.store, 'session_read', {'source': 'exact', 'session_id': 'sibling'}))
        self.assertFalse(denied['ok'])
