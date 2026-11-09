"""Real systemd integration with synthetic instances and a network-free client.

Only this opt-in root script links uniquely named temporary test units using
systemctl --runtime. Unit sources and fixtures stay under the repository's
.local directory. No production config/credential or existing unit is accessed.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).absolute().parents[1]

FAKE = r'''
import hashlib,json,os,pathlib,selectors,shlex,signal,subprocess,sys,time
home=pathlib.Path.cwd()
config=json.loads(pathlib.Path(sys.argv[sys.argv.index('--config')+1]).read_text())
record={'key':hashlib.sha256(os.environ['CONTROL_PLANE_API_KEY'].encode()).hexdigest(),
        'proxy':hashlib.sha256(os.environ.get('OBSERVER_TUNNEL_PROXY','').encode()).hexdigest(),
        'ambient_proxy':any(k in os.environ for k in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY']),
        'credentials_directory':'CREDENTIALS_DIRECTORY' in os.environ}
try:
    with (home.parent/'project/public.txt').open('a') as out: out.write('FORBIDDEN_WRITE')
    record['source_readonly']=False
except OSError: record['source_readonly']=True
probe=pathlib.Path('/tmp')/('observer-private-probe-'+str(os.getpid()))
try:
    probe.write_text('synthetic tmp write probe'); probe.unlink()
    record['tmp_readonly']=False
except OSError: record['tmp_readonly']=True
count=home/'cache/start-count'
number=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(number))
client=subprocess.Popen(shlex.split(config['mcp']['commands'][0]['command']),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
def send(value):
    client.stdin.write(json.dumps(value).encode()+b'\n'); client.stdin.flush()
def receive(identifier):
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        with selectors.DefaultSelector() as selector:
            selector.register(client.stdout,selectors.EVENT_READ)
            if not selector.select(.2):continue
        raw=client.stdout.readline()
        if not raw:raise RuntimeError('synthetic MCP EOF')
        item=json.loads(raw)
        if item.get('id')==identifier:return item
    raise RuntimeError('synthetic MCP timeout')
stopped=False
def stop(*args):
    global stopped
    stopped=True
signal.signal(signal.SIGTERM,stop)
try:
    send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'synthetic','version':'1'}}})
    receive(1)
    send({'jsonrpc':'2.0','method':'notifications/initialized'})
    send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
    tools=receive(2)['result']['tools']
    record['readonly_tools']=len(tools)
    record['readonly_annotations']=all(t['annotations']['readOnlyHint'] and not t['annotations']['destructiveHint'] for t in tools)
    send({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'observer_info','arguments':{}}})
    record['observer_info_ok']=json.loads(receive(3)['result']['content'][0]['text'])['ok']
    (home/'cache/client.json').write_text(json.dumps(record))
    while not stopped:
        if (home/'cache/exit-client').exists():
            (home/'cache/exit-client').unlink()
            raise SystemExit(3)
        time.sleep(.03)
finally:
    client.terminate()
    try:client.wait(timeout=3)
    except subprocess.TimeoutExpired:client.kill();client.wait(timeout=3)
'''


class SystemdSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not sys.platform.startswith('linux') or os.geteuid() != 0:
            raise unittest.SkipTest('requires Linux root and active systemd >=219')
        from observer.linux_systemd import detect_version
        cls.version = detect_version()
        if cls.version < 219:
            raise unittest.SkipTest('requires systemd >=219')

    def setUp(self):
        from observer.linux import LinuxStore
        from observer.linux_credentials import stage
        from observer.linux_systemd import render
        from observer.linux_legacy import runtime_path
        parent = ROOT / '.local/verification/systemd219'
        parent.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix='test-', dir=parent))
        self.name = 'observer-synthetic-' + self.root.name.removeprefix('test-') + '.service'
        self.unit = self.root / self.name
        self.link = Path('/run/systemd/system') / self.name
        self.store = LinuxStore(self.root / 'i')
        self.store.initialize()
        project = self.root / 'project'
        project.mkdir()
        (project / 'public.txt').write_text('synthetic systemd marker\n')
        self.original = (project / 'public.txt').read_bytes()
        self.store.config.register_workspace('code', str(project), lambda _: True)
        binary = self.root / 'fake-client'
        binary.write_text('#!' + sys.executable + '\n' + FAKE)
        binary.chmod(0o700)
        self.store.set_transport({'kind': 'tunnel', 'client': str(binary), 'tunnel_id': 'tunnel_' + '7' * 32})
        self.store.set_proxy(True)
        self.key = 'SYNTHETIC_SYSTEMD_RUNTIME'
        self.proxy = 'http://synthetic:synthetic@proxy.invalid:8080'
        stage(self.store, 'runtime', self.key)
        stage(self.store, 'proxy', self.proxy)
        (self.store.home / 'credentials/not-enabled').write_text('ignored synthetic source')
        self.runtime = runtime_path(self.store) if self.version < 247 else Path('/run/credentials') / self.name
        self.unit.write_text(render(self.store))
        self.assertFalse(self.link.exists())
        self.assertFalse(self.runtime.exists())
        self.addCleanup(self.cleanup)
        verify = subprocess.run(['/bin/systemd-analyze', 'verify', str(self.unit)], capture_output=True, text=True, timeout=20)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertNotIn('not an absolute path', verify.stderr)
        self.control('--runtime', 'link', str(self.unit))
        self.control('daemon-reload')

    def control(self, *args, check=True):
        result = subprocess.run(['/bin/systemctl', *args], capture_output=True, text=True, timeout=30)
        if check:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def properties(self):
        result = self.control('show', self.name, '--property=ActiveState', '--property=MainPID',
                              '--property=Result', '--property=ControlGroup', '--property=ExecMainStatus')
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

    def wait(self, check, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if check(): return
            time.sleep(.05)
        self.fail('synthetic systemd timeout; ' + str(self.properties()))

    def record(self):
        try: return json.loads((self.store.home / 'cache/client.json').read_text())
        except (FileNotFoundError, ValueError): return None

    def cleanup(self):
        self.control('stop', self.name, check=False)
        self.control('--runtime', 'disable', self.name, check=False)
        self.control('daemon-reload', check=False)
        self.control('reset-failed', self.name, check=False)
        if self.link.exists() or self.link.is_symlink():
            raise AssertionError('temporary runtime unit link was not removed')
        if self.runtime.exists():
            raise AssertionError('systemd did not remove its RuntimeDirectory')
        shutil.rmtree(self.root)

    def assert_worker_environment(self):
        group = self.properties()['ControlGroup']
        # Inspect only members of this unique synthetic test unit, not any
        # existing Observer or arbitrary host processes.
        tasks = Path('/sys/fs/cgroup/systemd') / group.lstrip('/') / 'tasks'
        if not tasks.exists():
            tasks = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cgroup.procs'
        found = 0
        for pid in tasks.read_text().splitlines():
            try:
                cmd = Path('/proc', pid, 'cmdline').read_bytes().split(b'\0')
                if b'_serve-active' not in cmd: continue
                values = Path('/proc', pid, 'environ').read_bytes()
            except FileNotFoundError: continue
            found += 1
            for forbidden in (b'CREDENTIALS_DIRECTORY=', b'CONTROL_PLANE_API_KEY=', b'OBSERVER_TUNNEL_PROXY=',
                              self.key.encode(), self.proxy.encode(), b'HTTPS_PROXY='):
                self.assertNotIn(forbidden, values)
        self.assertGreaterEqual(found, 1)

    def test_unit_start_runtime_permissions_provider_mcp_and_sigterm_cleanup(self):
        self.control('start', self.name)
        self.wait(lambda: bool(self.record()))
        record = self.record()
        self.assertTrue(self.runtime.is_dir())
        if self.version < 247:
            self.assertEqual(self.runtime.stat().st_mode & 0o777, 0o700)
        names = {self.store.credential_name(), self.store.credential_name('proxy')}
        self.assertEqual({p.name for p in self.runtime.iterdir()}, names)
        for path in self.runtime.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600 if self.version < 247 else 0o400)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(record['key'], hashlib.sha256(self.key.encode()).hexdigest())
        self.assertEqual(record['proxy'], hashlib.sha256(self.proxy.encode()).hexdigest())
        self.assertFalse(record['ambient_proxy'])
        self.assertFalse(record['credentials_directory'])
        self.assertTrue(record['source_readonly'])
        if self.version < 247: self.assertTrue(record['tmp_readonly'])
        self.assertEqual(record['readonly_tools'], 13)
        self.assertTrue(record['readonly_annotations'])
        self.assertTrue(record['observer_info_ok'])
        self.assert_worker_environment()
        self.control('stop', self.name)
        self.assertFalse(self.runtime.exists())
        self.assertEqual((self.root / 'project/public.txt').read_bytes(), self.original)

    def test_client_failure_restarts_and_reloads_new_staged_credentials(self):
        from observer.linux_credentials import stage
        self.control('start', self.name)
        self.wait(lambda: bool(self.record()))
        old_pid = self.properties()['MainPID']
        self.key += '_ROTATED'
        stage(self.store, 'runtime', self.key)
        (self.store.home / 'cache/exit-client').touch()
        expected = hashlib.sha256(self.key.encode()).hexdigest()
        self.wait(lambda: (self.record() or {}).get('key') == expected, seconds=20)
        self.assertNotEqual(self.properties()['MainPID'], old_pid)
        self.assertGreaterEqual(int((self.store.home / 'cache/start-count').read_text()), 2)
        self.assert_worker_environment()
        self.control('stop', self.name)
        self.assertFalse(self.runtime.exists())

    def test_failed_start_unsafe_sources_release_runtime_directory(self):
        from observer.linux_credentials import stage
        path = self.store.home / 'credentials/proxy'
        kinds = ('missing', 'mode', 'symlink', 'content') if self.version < 247 else ('missing',)
        for kind in kinds:
            with self.subTest(kind=kind):
                if path.exists() or path.is_symlink(): path.unlink()
                if kind == 'mode':
                    stage(self.store, 'proxy', self.proxy)
                    path.chmod(0o644)
                elif kind == 'symlink':
                    path.symlink_to(self.store.home / 'credentials/runtime')
                elif kind == 'content':
                    path.write_text('invalid synthetic proxy')
                    path.chmod(0o600)
                self.control('reset-failed', self.name, check=False)
                result = self.control('start', self.name, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.wait(lambda: not self.runtime.exists(), seconds=4)
                self.assertFalse((self.store.home / 'cache/client.json').exists())
                self.control('stop', self.name)
                self.assertFalse(self.runtime.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
