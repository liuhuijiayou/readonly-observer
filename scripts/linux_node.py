"""Linux deployment transactions. Stdlib bootstrap; secrets stay in Observer CLI.

The shell launchers only choose Python. This helper never accepts or reads key
or proxy values. Package builds execute trusted, explicitly reviewed Observer
source, never the observed project. Host dependencies are not auto-upgraded.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.request

SOURCE = Path(__file__).absolute().parents[1]
OFFICIAL = 'https://github.com/liuhuijiayou/readonly-observer.git'
DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
REGISTRY = Path('/var/lib/readonly-observer-deployments')
MIN_FREE = 1024 * 1024 * 1024


class Failure(Exception):
    pass


def path(value):
    value = str(value)
    if (not re.fullmatch(r'/[A-Za-z0-9_./-]+', value)
            or any(p in {'', '.', '..'} for p in value.split('/')[1:]) or len(value) > 512):
        raise Failure('absolute_path_required; unsupported_special_characters')
    return Path(value)


def data_path(value):
    value=str(value)
    parts=value.split('/')[1:]
    if (not value.startswith('/') or not parts or len(value.encode())>2048 or '\\' in value
            or any(ord(c)<32 or ord(c)==127 for c in value)
            or any(p in {'','.','..'} or len(p.encode())>255 for p in parts)):
        raise Failure('invalid_absolute_data_path')
    return Path(value)


def directory(value, create=False, private=False):
    value = data_path(value)
    fd = os.open('/', DIR)
    try:
        for part in value.parts[1:]:
            if create:
                try: os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError: pass
            child = os.open(part, DIR, dir_fd=fd)
            os.close(fd); fd = child
        st = os.fstat(fd)
        if private and (st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700):
            raise Failure('private_root_owned_directory_required')
        return fd
    except BaseException:
        os.close(fd)
        raise


def root_parent_control(value):
    current=Path('/')
    for part in path(value).parts[1:]:
        current=current/part
        if not os.path.lexists(current): break
        st=os.lstat(current)
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid!=0
                or (st.st_mode&0o022 and not st.st_mode&stat.S_ISVTX)):
            raise Failure('deployment_ancestor_not_root_controlled')


def metadata(filename):
    st = os.lstat(filename)
    return [st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def read_file(filename, mode=None, limit=1024*1024):
    filename = Path(filename)
    parent = directory(filename.parent)
    try:
        fd = os.open(filename.name, FILE, dir_fd=parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                raise Failure('unsafe_regular_file')
            if mode is not None and (before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != mode):
                raise Failure('unsafe_private_metadata')
            raw = bytearray()
            while len(raw) <= limit:
                block = os.read(fd, min(65536, limit+1-len(raw)))
                if not block: break
                raw.extend(block)
            after = os.fstat(fd)
            sig = lambda st: (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
            if len(raw) > limit or sig(before) != sig(after): raise Failure('file_changed')
            return bytes(raw)
        finally: os.close(fd)
    finally: os.close(parent)


def digest(filename):
    return hashlib.sha256(read_file(filename)).hexdigest()


def atomic(filename, raw, mode=0o600, expected=None, new=False):
    """Durable no-replace publication or identity-checked owned replacement."""
    filename = Path(filename)
    parent = directory(filename.parent)
    temporary = '.pending-' + secrets.token_hex(12)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        try:
            os.fchmod(fd, mode)
            data = memoryview(raw)
            while data:
                count = os.write(fd, data)
                if count <= 0: raise Failure('metadata_write_failed')
                data = data[count:]
            os.fsync(fd)
        finally: os.close(fd)
        if new:
            os.link(temporary, filename.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent)
        else:
            if expected is not None and digest(filename) != expected:
                raise Failure('owned_file_changed; refusing_overwrite')
            if os.path.lexists(filename):
                st = os.stat(filename.name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.getuid():
                    raise Failure('unsafe_metadata_destination')
            os.replace(temporary, filename.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try: os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError: pass
        os.close(parent)


def load(filename):
    value = json.loads(read_file(filename, mode=0o600, limit=65536))
    if not isinstance(value, dict): raise Failure('invalid_deployment_metadata')
    return value


def save(filename, value, new=False):
    atomic(filename, (json.dumps(value,sort_keys=True,indent=2)+'\n').encode(), new=new)


def clean_env():
    return {'PATH':'/usr/bin:/bin', 'LC_ALL':'C', 'PYTHONDONTWRITEBYTECODE':'1',
            'PYTHONNOUSERSITE':'1', 'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null',
            'GIT_CONFIG_SYSTEM':'/dev/null', 'GIT_TERMINAL_PROMPT':'0', 'GIT_ASKPASS':'/bin/false',
            'PIP_CONFIG_FILE':'/dev/null'}


class Runner:
    def run(self, args, label, cwd=None, timeout=600):
        child = subprocess.Popen([str(a) for a in args], cwd=cwd, env=clean_env(), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True)
        try:
            output, _ = child.communicate(timeout=timeout)
        except BaseException:
            try: os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError: pass
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try: os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(timeout=3)
            raise
        if child.returncode:
            # Never echo pip, Git, client, config or OS exception output.
            raise Failure(label + '_failed; exit=' + str(child.returncode))
        if len(output) > 4*1024*1024: raise Failure(label + '_output_limit')
        return output


class Terminal:
    def __init__(self):
        self.input = self.output = None
    def _open(self):
        if self.input is None:
            try:
                self.input = open('/dev/tty', 'r', encoding='utf-8')
                self.output = open('/dev/tty', 'w', encoding='utf-8', buffering=1)
            except OSError: raise Failure('human_tty_required; metadata_flags_do_not_bypass_approval') from None
    def available(self):
        try: self._open(); return True
        except Failure: return False
    def ask(self, prompt, default=None):
        self._open()
        self.output.write(prompt + (f' [{default}]' if default is not None else '') + ': ')
        self.output.flush()
        value = self.input.readline()
        if not value: raise KeyboardInterrupt()
        return value.rstrip('\n') or (default if default is not None else '')
    def confirm(self, text, word='approve'):
        if self.ask(text + f' — type {word}') != word:
            raise Failure('operator_declined; no_scope_expansion')
    def foreground(self, args):
        self._open()
        result = subprocess.run([str(a) for a in args], env=clean_env(), stdin=self.input,
                                stdout=self.output, stderr=self.output, close_fds=True)
        if result.returncode: raise Failure('observer_local_confirmation_or_credential_input_failed')
    def show(self, text):
        print(text, flush=True)
    def close(self):
        if self.input: self.input.close()
        if self.output: self.output.close()


class Host:
    def __init__(self, runner=None, unit_dir=Path('/etc/systemd/system'), registry=REGISTRY, git='/usr/bin/git'):
        self.runner = runner or Runner()
        self.unit_dir, self.registry, self.git = Path(unit_dir), Path(registry), str(git)
    def properties(self, unit):
        raw = self.runner.run(['/bin/systemctl','show',unit,'--property=LoadState','--property=ActiveState',
                               '--property=FragmentPath','--property=DropInPaths'], 'systemd_inspect', timeout=10)
        return dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
    def version(self):
        raw = self.runner.run(['/bin/systemctl','show','--property=Version'], 'systemd_version', timeout=10)
        match = re.fullmatch(rb'Version=(\d+)[^\r\n]*\n?', raw)
        if not match or int(match[1]) < 219: raise Failure('active_systemd_219_or_newer_required')
        return int(match[1])
    def identity(self, dry=False):
        if sys.platform != 'linux': raise Failure('linux_only; macos_unchanged')
        if not dry and os.geteuid() != 0: raise Failure('root_required; run_with_sudo')
        if sys.version_info < (3,14): raise Failure('python_3_14_or_newer_required')
    def prerequisites(self, root, wheelhouse=None, dry=False):
        self.identity(dry)
        self.runner.run([sys.executable,'-I','-c','import ensurepip,venv,ssl'], 'python_venv')
        raw = self.runner.run([self.git,'--version'], 'git_version', timeout=10)
        match = re.search(rb'git version (\d+)\.(\d+)',raw)
        if not match or tuple(map(int,match.groups())) < (2,28):
            raise Failure('git_2_28_required; no_automatic_system_upgrade')
        parent = Path(root)
        while not parent.exists(): parent = parent.parent
        if shutil.disk_usage(parent).free < MIN_FREE: raise Failure('at_least_1_GiB_free_required')
        version = self.version()
        if wheelhouse:
            fd = directory(wheelhouse); os.close(fd)
        elif not dry:
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open('https://pypi.org/simple/', timeout=10) as response:
                    if response.status != 200: raise Failure('dependency_network_unavailable')
            except (OSError, ValueError):
                raise Failure('dependency_network_unavailable; use_trusted_offline_wheelhouse') from None
        return version
    def control(self, action, unit):
        self.runner.run(['/bin/systemctl',action,unit], 'systemd_'+action, timeout=30)
    def reload(self): self.runner.run(['/bin/systemctl','daemon-reload'],'systemd_reload',timeout=30)
    def verify(self, candidate):
        self.runner.run(['/bin/systemd-analyze','verify',candidate], 'unit_verify', timeout=30)
    def render(self, python, home):
        return self.runner.run([python,'-I','-B','-m','observer.cli','--home',home,'systemd-unit'], 'unit_render')


class Builder:
    def __init__(self, runner): self.runner = runner
    def install(self, source, release, python, wheelhouse=None):
        target = release/'venv'
        if target.exists():
            # Only a transaction-owned incomplete candidate can reach here.
            if not (release/'.owned-candidate').is_file(): raise Failure('unknown_existing_venv')
            shutil.rmtree(target)
        self.runner.run([python,'-I','-m','venv',target], 'create_venv')
        command = [target/'bin/python','-I','-m','pip','--isolated','install','--no-input',
                   '--disable-pip-version-check','--no-cache-dir']
        command += ['--no-index','--find-links',wheelhouse] if wheelhouse else ['--index-url','https://pypi.org/simple']
        command += [source]
        self.runner.run(command, 'install_observer')
        return target/'bin/python'


class SourceTree:
    def __init__(self, runner, git='/usr/bin/git'): self.runner, self.git = runner, str(git)
    def git_run(self, root, *args):
        return self.runner.run([self.git,'-c','core.hooksPath=/dev/null','-C',root,*args], 'source_git', timeout=120)
    def resolve(self, source, ref, install=True):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]{0,127}',ref) or '..' in ref:
            raise Failure('invalid_git_ref')
        if not install and not re.fullmatch(r'[a-fA-F0-9]{40}',ref):
            tag = ref.removeprefix('refs/tags/')
            self.git_run(source,'show-ref','--verify','refs/tags/'+tag)
            ref = 'refs/tags/'+tag
        sha = self.git_run(source,'rev-parse','--verify',ref+'^{commit}').decode().strip()
        if not re.fullmatch(r'[a-f0-9]{40}',sha): raise Failure('invalid_resolved_commit')
        return sha
    def material(self, source, sha, reviewed=False):
        manifest = read_file(source/'PUBLIC_FILES.txt') if reviewed else self.git_run(source,'show',sha+':PUBLIC_FILES.txt')
        names = [x for x in manifest.decode().splitlines() if x and not x.startswith('#')]
        if not 1 <= len(names) <= 256 or names != sorted(set(names)): raise Failure('invalid_public_manifest')
        content, total = {}, 0
        for name in names:
            if (not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*',name)
                    or any(p in {'.','..','.git','.local','.venv','credentials','secrets'} for p in name.split('/'))):
                raise Failure('unsafe_source_manifest')
            if reviewed:
                raw = read_file(source/name)
                mode = stat.S_IMODE(os.lstat(source/name).st_mode)
            else:
                entry = self.git_run(source,'ls-tree',sha,'--',name).decode().split()
                if not entry or entry[0] not in {'100644','100755'}: raise Failure('unsafe_source_entry')
                raw = self.git_run(source,'show',sha+':'+name)
                mode = int(entry[0],8)
            total += len(raw)
            if len(raw)>1024*1024 or total>8*1024*1024: raise Failure('source_snapshot_limit')
            content[name] = (raw, 0o755 if mode&0o111 else 0o644)
        if not {'pyproject.toml','PUBLIC_FILES.txt','src/observer/cli.py','scripts/check_repository.py'} <= set(content):
            raise Failure('incomplete_observer_source')
        fingerprint = hashlib.sha256(b''.join(n.encode()+b'\0'+str(m).encode()+b'\0'+hashlib.sha256(b).digest()
                                            for n,(b,m) in sorted(content.items()))).hexdigest()
        return content, fingerprint
    def snapshot(self, content, destination):
        destination.mkdir(mode=0o700)
        for name,(raw,mode) in content.items():
            target=destination/name; target.parent.mkdir(parents=True,exist_ok=True)
            atomic(target,raw,mode=mode,new=True)
        self.runner.run([sys.executable,'-I',destination/'scripts/check_repository.py'], 'reviewed_source_check')


@contextmanager
def operation_lock(root):
    fd = os.open(root/'deployment.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        st=os.fstat(fd)
        if st.st_uid!=os.getuid() or st.st_nlink!=1 or not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode)!=0o600:
            raise Failure('unsafe_deployment_lock')
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Failure('deployment_busy') from None
        yield
    finally: os.close(fd)


class Deployment:
    def __init__(self, host=None, terminal=None, builder=None):
        self.host=host or Host(); self.runner=self.host.runner
        self.terminal=terminal or Terminal(); self.builder=builder or Builder(self.runner)
        self.source=SourceTree(self.runner,self.host.git)
    def progress(self, step): self.terminal.show('[Observer] '+step)
    def cli(self, python, home, *args):
        raw=self.runner.run([python,'-I','-B','-m','observer.cli','--home',home,*args], 'observer_'+str(args[0]), timeout=45)
        value=json.loads(raw)
        if not value.get('ok'): raise Failure('observer_validation_failed')
        return value
    def human_cli(self, python, home, *args):
        self.terminal.foreground([python,'-I','-B','-m','observer.cli','--home',home,*args])
    def probe(self, python, home):
        report=self.cli(python,home,'doctor','--level','local','--probe')
        result=report.get('layers',{}).get('local',{})
        if result.get('status')!='local_protocol_verified' or result.get('readonly_tools')!=13:
            raise Failure('local_mcp_13_readonly_tools_not_verified')
    def managed(self, python, home, unit):
        deadline=time.monotonic()+12
        while time.monotonic()<deadline:
            try:
                state=self.cli(python,home,'status')
                if state.get('manager')=='running':
                    self.probe(python,home); return
            except Failure: pass
            time.sleep(.15)
        raise Failure('started_service_local_acceptance_failed')
    def obtain(self, source, ref, root, install, reviewed=False):
        try: sha=self.source.resolve(source,ref,install)
        except Failure:
            if reviewed: raise
            cache=root/('.pending-source-'+secrets.token_hex(8))
            try:
                self.runner.run([self.host.git,'clone','--no-checkout','--no-hardlinks','--',OFFICIAL,cache], 'clone_official_source',timeout=180)
                sha=self.source.resolve(cache,ref,install)
                return sha,*self.source.material(cache,sha)
            finally:
                if cache.exists(): shutil.rmtree(cache)
        reviewed = reviewed or (install and ref=='HEAD' and Path(source)==SOURCE)
        return sha,*self.source.material(source,sha,reviewed)
    def candidate(self, root, state, source, ref, install, reviewed, python, wheelhouse):
        if state.get('candidate_ready'):
            release=path(state['candidate'])
            if release.parent!=root/'releases': raise Failure('candidate_outside_installation')
            fd=directory(release,private=True);os.close(fd)
            if read_file(release/'.owned-candidate',mode=0o600,limit=64)!=state['id'].encode():
                raise Failure('candidate_not_owned_by_transaction')
            return release,release/'venv/bin/python'
        self.progress('Resolve and review the exact Observer source')
        sha,content,source_hash=self.obtain(source,ref,root,install,reviewed)
        self.terminal.show('Commit: '+sha+'\nPublic snapshot SHA256: '+source_hash)
        self.terminal.confirm('Approve this trusted Observer code for root installation')
        release=root/'releases'/('r-'+sha[:12]+'-'+secrets.token_hex(6))
        release.parent.mkdir(mode=0o700,exist_ok=True); release.mkdir(mode=0o700)
        atomic(release/'.owned-candidate',state['id'].encode(),new=True)
        state.update(candidate=str(release),commit=sha,source_digest=source_hash)
        save(root/state['journal'],state)
        try:
            self.source.snapshot(content,release/'source')
            self.progress('Create isolated venv and install dependencies')
            executable=self.builder.install(release/'source',release,python,wheelhouse)
            state['candidate_ready']=True; save(root/state['journal'],state)
            return release,executable
        except BaseException:
            # Partial build artifacts are ours; grants/credentials/home are kept.
            shutil.rmtree(release)
            state.pop('candidate',None); state['candidate_ready']=False
            save(root/state['journal'],state)
            raise
    def ensure_unit_unused(self, unit):
        target=self.host.unit_dir/unit
        if os.path.lexists(target) or self.host.properties(unit).get('LoadState')!='not-found':
            raise Failure('unit_already_exists; refusing_takeover')
    def reserve_tunnel(self, plan, identity):
        folder=self.host.registry/'tunnels'
        fd=directory(folder,create=True,private=True);os.close(fd)
        claim=folder/(hashlib.sha256(plan['tunnel_id'].encode()).hexdigest()+'.json')
        owner=hashlib.sha256(plan['home'].encode()).hexdigest()[:24]
        if claim.exists():
            if load(claim)!={'owner':owner,'installation':identity}: raise Failure('tunnel_already_assigned_on_this_host')
        else: save(claim,{'owner':owner,'installation':identity},new=True)
    def credential(self, executable, home, kind):
        filename=home/'credentials'/kind
        if os.path.lexists(filename):
            info=metadata(filename)
            if not stat.S_ISREG(info[2]) or info[3]!=os.getuid() or info[4]!=1 or stat.S_IMODE(info[2])!=0o600:
                raise Failure('unsafe_existing_credential; no_overwrite')
            choice=self.terminal.ask(f'Existing {kind} credential: explicitly type keep or rotate')
            if choice=='keep':
                if kind=='runtime':
                    note=load(home/'state/runtime-key-claim.json')
                    if note.get('source_identity')!=info: raise Failure('runtime_key_unique_claim_not_current; choose_explicit_rotation')
                return
            if choice!='rotate': raise Failure('operator_declined_credential_change')
        if kind=='runtime':
            self.terminal.confirm('Confirm a separately issued Runtime Key for this node; never reuse another machine key','independent-key')
            self.human_cli(executable,home,'credentials','set','--approve','--unique-node-key',
                           '--key-registry',str(self.host.registry/'key-claims'))
        else:
            self.human_cli(executable,home,'credentials','set','--kind','proxy','--approve')
    def finish(self, plan, source):
        self.terminal.show('Local installation complete; remote ChatGPT readiness remains unverified.\n'
                           'Node Name: '+plan['name']+'\nTunnel Display Name: '+plan['tunnel_name']+
                           '\nTunnel ID: '+plan['tunnel_id']+'\nUnit: '+plan['unit']+
                           '\nCreate the ChatGPT MCP connection manually with this Tunnel. Verify observer_info.node, '
                           '13 read-only tools, and a harmless approved marker.\nSource commit: '+source)
    def install(self, args):
        if args.resume:
            root=path(args.install_dir or self.terminal.ask('Installation Directory to resume'))
            state=load(root/'install-state.json'); plan=state['plan']
            if state.get('kind')!='install': raise Failure('wrong_install_journal')
            for key in ('name','home','unit','project','alias','session','session_alias','client','tunnel_id','tunnel_name'):
                value=getattr(args,key,None)
                if value is not None and str(value)!=str(plan.get(key)):
                    raise Failure('resume_plan_override_refused')
        else:
            plan=collect_install(args,self.terminal)
            root=path(plan['install_dir'])
            state={'format':1,'kind':'install','id':secrets.token_hex(16),'journal':'install-state.json','plan':plan}
        home=path(plan['home']); target=self.host.unit_dir/plan['unit']
        self.progress('Check Linux, Python, Git, active systemd, paths and disk/network prerequisites')
        version=self.host.prerequisites(root,args.wheelhouse,args.dry_run)
        validate_plan(plan)
        for controlled in (root,home,self.host.unit_dir,self.host.registry): root_parent_control(controlled)
        if not args.resume:
            if os.path.lexists(root): raise Failure('installation_directory_already_exists; use_explicit_resume')
            if os.path.lexists(home): raise Failure('instance_home_already_exists; no_takeover')
            self.ensure_unit_unused(plan['unit'])
        else:
            fd=directory(root,private=True);os.close(fd)
            if home.exists():
                marker=load(home/'.installer-owner.json')
                if marker!={'id':state['id'],'install_dir':str(root)}: raise Failure('instance_not_owned_by_this_install')
            if os.path.lexists(target):
                if not state.get('unit_digest') or digest(target)!=state['unit_digest']:
                    raise Failure('existing_unit_not_owned_by_this_install')
            elif self.host.properties(plan['unit']).get('LoadState')!='not-found':
                raise Failure('other_unit_with_same_name_loaded')
        self.terminal.show(json.dumps({'plan':plan,'systemd':version,'source':str(args.source),'ref':args.ref or 'HEAD',
                                        'python':args.python or sys.executable,'wheelhouse':args.wheelhouse,
                                        'no_start':args.no_start,'credential_values':'not_collected_or_previewed'},indent=2))
        if args.dry_run:
            self.progress('Dry run complete: no instance, key, unit, venv or service was changed')
            return
        if state.get('complete'): raise Failure('installation_already_complete; use_upgrade')
        self.terminal.confirm('Approve the displayed new installation and public node identity')
        if not args.resume:
            fd=directory(root.parent,create=True);os.close(fd)
            root.mkdir(mode=0o700)
            save(root/state['journal'],state,new=True)
        with operation_lock(root):
            if args.resume and self.host.properties(plan['unit']).get('ActiveState') in {'active','activating'}:
                self.terminal.confirm('Stop this owned incomplete installation before resuming')
                self.host.control('stop',plan['unit'])
            self.reserve_tunnel(plan,state['id'])
            release,executable=self.candidate(root,state,data_path(args.source),args.ref or 'HEAD',True,
                                              args.local_reviewed,Path(args.python or sys.executable),args.wheelhouse)
            if not home.exists():
                fd=directory(home.parent,create=True);os.close(fd)
                home.mkdir(mode=0o700)
                save(home/'.installer-owner.json',{'id':state['id'],'install_dir':str(root)},new=True)
            if not (home/'config/settings.json').exists():
                self.progress('Initialize this empty instance')
                self.cli(executable,home,'init','--non-interactive')
            if not state.get('identity_set'):
                self.cli(executable,home,'node','set','--name',plan['name'],'--approve')
                state['identity_set']=True;save(root/state['journal'],state)
            for kind,filename,alias in [('project',plan['project'],plan['alias']),
                                         ('session',plan.get('session'),plan.get('session_alias'))]:
                if not filename: continue
                entries=self.cli(executable,home,kind,'list')['sources']
                matching=[e for e in entries if e['alias']==alias]
                if matching:
                    if len(matching)!=1 or matching[0]['path']!=filename:
                        raise Failure('existing_source_grant_conflicts; no_automatic_reapproval')
                else:
                    self.progress('Review and approve the exact '+kind+' scope in Observer')
                    self.human_cli(executable,home,kind,'add',filename,'--alias',alias)
            transport={'kind':'tunnel','client':plan['client'],'tunnel_id':plan['tunnel_id']}
            shown=self.cli(executable,home,'config','show')
            if shown['settings']['transport']!=transport:
                self.cli(executable,home,'transport','tunnel','--client',plan['client'],'--tunnel-id',plan['tunnel_id'])
            self.progress('Runtime API Key: Observer reads hidden TTY input directly')
            self.credential(executable,home,'runtime')
            if plan['proxy']:
                self.progress('Proxy URL: Observer reads hidden TTY input directly')
                self.credential(executable,home,'proxy')
            self.cli(executable,home,'proxy','enable' if plan['proxy'] else 'disable')
            self.progress('Validate exact authorizations and locally probe 13 read-only MCP tools')
            self.cli(executable,home,'config','validate','--check-sources');self.probe(executable,home)
            unit=self.host.render(executable,home)
            candidate=release/plan['unit'];atomic(candidate,unit)
            self.host.verify(candidate)
            self.terminal.show(unit.decode())
            self.terminal.confirm('Approve this verified systemd unit and its precise writable paths')
            state['unit_digest']=hashlib.sha256(unit).hexdigest();save(root/state['journal'],state)
            if not os.path.lexists(target):
                self.ensure_unit_unused(plan['unit'])
                atomic(target,unit,mode=0o644,new=True)
            elif digest(target)!=state['unit_digest']:
                raise Failure('unit_changed; no_overwrite')
            self.host.reload()
            node=self.cli(executable,home,'node','info')['node']
            deployed={'node':node,'format':1,'id':state['id'],'install_dir':str(root),'home':str(home),'unit':plan['unit'],
                      'release':str(release),'commit':state['commit'],'source_digest':state['source_digest'],
                      'unit_digest':state['unit_digest'],'plan':plan,'history':[]}
            save(home/'config/deployment.json',deployed)
            if not args.no_start and self.terminal.ask('Start service now and enable at boot? Type start, or press Enter to leave stopped','')=='start':
                try:
                    self.host.control('start',plan['unit'])
                    self.managed(executable,home,plan['unit'])
                    self.host.control('enable',plan['unit'])
                except BaseException:
                    self.host.control('stop',plan['unit']);raise
            state['complete']=True;save(root/state['journal'],state)
            self.finish(plan,state['commit'])
    def check_deployment(self, home):
        deployed=load(home/'config/deployment.json')
        if deployed.get('format')!=1 or deployed.get('home')!=str(home): raise Failure('unmanaged_instance; use_manual_upgrade')
        root=path(deployed['install_dir']);fd=directory(root,private=True);os.close(fd)
        target=self.host.unit_dir/deployed['unit']
        read_file(target,mode=0o644)
        if digest(target)!=deployed['unit_digest']: raise Failure('managed_unit_changed; review_manually')
        props=self.host.properties(deployed['unit'])
        if props.get('FragmentPath')!=str(target) or props.get('DropInPaths'):
            raise Failure('unexpected_unit_origin_or_dropins; no_takeover')
        release=path(deployed['release'])
        if release.parent!=root/'releases': raise Failure('release_outside_installation')
        node=self.cli(release/'venv/bin/python',home,'node','info')['node']
        if node.get('status')!='active' or node.get('id')!=deployed.get('node',{}).get('id'):
            raise Failure('node_identity_changed_or_retired; review_manually')
        return deployed,root,target,props
    def backup(self, home, target, root, tx):
        folder=root/'backups'/tx['id'];folder.parent.mkdir(mode=0o700,exist_ok=True);folder.mkdir(mode=0o700)
        for name in ('settings.json','approvals.json','node.json','linux.json','deployment.json'):
            filename=home/'config'/name
            if filename.exists(): atomic(folder/name,read_file(filename,mode=0o600),new=True)
        atomic(folder/'previous.service',read_file(target,mode=0o644),new=True)
        state={}
        for name in ('manager.lock','active.json','node-active.json','linux-active.json','last-error.json'):
            filename=home/'state'/name
            if os.path.lexists(filename): state[name]=metadata(filename)
        save(folder/'state-metadata.json',state,new=True)
        # Credentials are never opened, copied or included in the backup.
        tx['backup']=str(folder);save(root/tx['journal'],tx)
        instructions=('Recover an interrupted update without starting services:\n'
            'sudo bash '+str(SOURCE/'scripts/upgrade_linux_node.sh')+' --home '+str(home)+' --resume --no-start\n'
            'Previous interpreter: '+previous_interpreter(tx)+'\n'
            'Previous unit backup: '+str(folder/'previous.service')+'\n'
            'If automatic rollback already completed, retry upgrade with the desired ref.\n'
            'Do not reinitialize, restore old grant identities, or copy/delete credentials.\n')
        atomic(folder/'RESTORE.txt',instructions.encode(),new=True)
    def recover_upgrade(self, home, root, target, tx, no_start):
        previous=tx['previous']
        props=self.host.properties(previous['unit'])
        if props.get('FragmentPath')!=str(target) or props.get('DropInPaths'):
            raise Failure('rollback_refused; unexpected_unit_origin_or_dropins')
        current=digest(target)
        if current not in {previous['unit_digest'],tx.get('candidate_unit_digest')}:
            raise Failure('rollback_refused; unit_changed_outside_transaction')
        self.host.control('stop',previous['unit'])
        if current!=previous['unit_digest']:
            backup=path(tx['backup'])/'previous.service'
            atomic(target,read_file(backup,mode=0o600),mode=0o644,expected=current)
        save(home/'config/deployment.json',previous)
        self.host.reload()
        if tx['was_active'] and not no_start:
            self.host.control('start',previous['unit'])
            self.managed(path(previous['release'])/'venv/bin/python',home,previous['unit'])
        tx['rolled_back']=True;save(root/tx['journal'],tx)
    def upgrade(self, args):
        self.host.identity(args.dry_run)
        if args.resume and args.rollback: raise Failure('choose_resume_or_rollback')
        home=path(args.home or self.terminal.ask('Instance Home'))
        if args.resume:
            recorded=load(home/'config/deployment.json');root=path(recorded['install_dir'])
            tx=load(root/'upgrade-state.json')
            if tx.get('complete') or tx.get('rolled_back'): raise Failure('no_interrupted_upgrade_to_recover')
            if tx['previous']['home']!=str(home): raise Failure('upgrade_journal_home_mismatch')
            target=self.host.unit_dir/tx['previous']['unit']
            if args.dry_run:
                self.terminal.show('Dry run: restore the recorded previous unit/release; credentials remain untouched')
                return
            self.terminal.confirm('Recover the recorded interrupted upgrade and its previous running state')
            with operation_lock(root): self.recover_upgrade(home,root,target,tx,args.no_start)
            self.progress('Previous version restored. Re-run upgrade with the explicit desired commit/tag')
            return
        previous,root,target,props=self.check_deployment(home)
        version=self.host.prerequisites(root,args.wheelhouse,args.dry_run)
        if not args.ref and not args.rollback: raise Failure('explicit_commit_or_tag_required')
        self.terminal.show(json.dumps({'home':str(home),'unit':previous['unit'],'current_commit':previous['commit'],
                                       'requested_ref':args.ref,'rollback':args.rollback,'systemd':version,
                                       'credentials':'preserved_and_never_read'},indent=2))
        if args.dry_run: return
        self.terminal.confirm('Approve stop, metadata backup and code update; failure restores the old unit/version and prior running state')
        with operation_lock(root):
            # Check again after acquiring the deployment lease.
            previous,root,target,props=self.check_deployment(home)
            tx={'format':1,'kind':'upgrade','id':secrets.token_hex(16),'journal':'upgrade-state.json',
                'previous':previous,'was_active':props.get('ActiveState')=='active','ref':args.ref}
            save(root/tx['journal'],tx)
            self.progress('Stop the exact managed unit and back up config plus state metadata, excluding all credentials')
            try:
                self.host.control('stop',previous['unit'])
                self.backup(home,target,root,tx)
                if args.rollback:
                    if not previous.get('history'): raise Failure('no_previous_release_available')
                    chosen=previous['history'][-1]
                    release=path(chosen['release']);executable=release/'venv/bin/python'
                    if release.parent!=root/'releases': raise Failure('invalid_rollback_release')
                    tx.update(commit=chosen['commit'],source_digest=chosen['source_digest'])
                else:
                    release,executable=self.candidate(root,tx,data_path(args.source),args.ref,False,
                                                      args.local_reviewed,Path(args.python or sys.executable),args.wheelhouse)
                self.cli(executable,home,'config','validate','--check-sources');self.probe(executable,home)
                unit=self.host.render(executable,home)
                candidate=release/('upgrade-'+tx['id']+'.service');atomic(candidate,unit,new=True)
                self.host.verify(candidate)
                self.terminal.show(unit.decode())
                self.terminal.confirm('Approve replacing only this unchanged managed unit with the reviewed unit')
                if digest(target)!=previous['unit_digest']: raise Failure('unit_changed_before_update')
                tx['candidate_unit_digest']=hashlib.sha256(unit).hexdigest();save(root/tx['journal'],tx)
                atomic(target,unit,mode=0o644,expected=previous['unit_digest']);self.host.reload()
                updated={**previous,'release':str(release),'commit':tx['commit'],'source_digest':tx['source_digest'],
                         'unit_digest':tx['candidate_unit_digest'],'history':previous.get('history',[])+[
                             {k:previous[k] for k in ('release','commit','source_digest','unit_digest')}]}
                save(home/'config/deployment.json',updated)
                if not args.no_start:
                    self.terminal.confirm('Start the upgraded service and validate local MCP now','start')
                    self.host.control('start',previous['unit']);self.managed(executable,home,previous['unit'])
                tx['complete']=True;save(root/tx['journal'],tx)
                self.finish(previous['plan'],tx['commit'])
            except BaseException as error:
                self.progress('Upgrade failed: restore the previous unit/version; source grants and credentials are unchanged')
                keep_stopped=args.no_start or isinstance(error,KeyboardInterrupt) or str(error).startswith('operator_declined')
                self.recover_upgrade(home,root,target,tx,keep_stopped)
                raise


def previous_interpreter(tx):
    return str(path(tx['previous']['release'])/'venv/bin/python')


def collect_install(args, terminal):
    def value(key,prompt,default=None):
        given=getattr(args,key,None)
        if given is not None: return str(given)
        return terminal.ask(prompt,default)
    name=value('name','Node Name')
    slug=re.sub(r'[^a-z0-9_-]','-',name.lower()).strip('-')[:32] or 'node'
    install=value('install_dir','Installation Directory','/opt/readonly-observer-nodes/'+slug)
    home=value('home','Instance Home','/var/lib/readonly-observer/'+slug)
    project=value('project','Project absolute Path')
    alias=value('alias','Project Alias','app')
    if args.session is not None: session=args.session
    elif args.dry_run and not terminal.available(): session=''
    else: session=terminal.ask('Optional Exact Codex JSONL absolute path (Enter to skip)','')
    session_alias=value('session_alias','Exact Session Alias','task') if session else None
    tunnel_name=value('tunnel_name','Tunnel Display Name',name)
    # Never derive or reuse another node's Tunnel ID.
    tunnel_id=value('tunnel_id','Tunnel ID (explicitly enter this node own ID)')
    detected=shutil.which('tunnel-client')
    if not detected:
        candidates=sorted(Path('/opt/tunnel-client').glob('*/bin/tunnel-client'))
        detected=str(candidates[-1]) if candidates else None
    client=value('client','Tunnel Client Absolute Path (confirm detected path or enter another)',detected)
    if args.proxy is not None: proxy=args.proxy=='on'
    else:
        answer=terminal.ask('Enable Proxy? Enter yes or no','no')
        if answer not in {'yes','no'}: raise Failure('explicit_yes_or_no_required')
        proxy=answer=='yes'
    unit=value('unit','systemd Unit Name','observer-'+slug+'.service')
    return {'name':name,'install_dir':install,'home':home,'project':project,'alias':alias,
            'session':session or None,'session_alias':session_alias,'tunnel_name':tunnel_name,
            'tunnel_id':tunnel_id,'client':client,'proxy':proxy,'unit':unit}


def validate_plan(plan):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}',plan['name']): raise Failure('invalid_public_node_name')
    if not isinstance(plan['tunnel_name'],str) or not 1<=len(plan['tunnel_name'])<=64 or any(ord(c)<32 for c in plan['tunnel_name']):
        raise Failure('invalid_tunnel_display_name')
    if not re.fullmatch(r'tunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}',plan['tunnel_id']): raise Failure('invalid_explicit_tunnel_id')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.service',plan['unit']): raise Failure('invalid_unit_name')
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',plan['alias']): raise Failure('invalid_project_alias')
    root,home=path(plan['install_dir']),path(plan['home'])
    project=data_path(plan['project'])
    for location in (root,home):
        if len(location.parts)<3 or location in {Path('/root'),Path('/home'),Path('/opt'),Path('/var'),Path('/tmp')}:
            raise Failure('unsafe_deployment_root')
    if len(str(home/'state/control.sock').encode())>100: raise Failure('instance_home_too_long_for_socket')
    for left,right in ((root,home),(home,root),(project,home),(project,root),(home,project),(root,project)):
        if right==left or left in right.parents: raise Failure('installation_home_or_observed_project_overlap')
    fd=directory(project);os.close(fd)
    if plan.get('session'):
        session=data_path(plan['session'])
        if any(location==session or location in session.parents for location in (root,home)):
            raise Failure('session_inside_private_deployment')
        if session.suffix!='.jsonl' or not re.fullmatch(r'[a-z][a-z0-9_-]{0,31}',plan.get('session_alias') or ''):
            raise Failure('exact_jsonl_path_and_alias_required')
        if plan['session_alias']==plan['alias']: raise Failure('source_aliases_must_differ')
        parent=directory(session.parent);os.close(parent)
        st=os.lstat(session)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1: raise Failure('unsafe_exact_session_file')
    client=data_path(plan['client']);fd=directory(client.parent);os.close(fd)
    st=os.lstat(client)
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or st.st_mode&0o022 or not st.st_mode&0o111:
        raise Failure('unsafe_operator_installed_tunnel_client; no_download_attempted')


class SafeParser(argparse.ArgumentParser):
    def error(self,message): raise Failure('invalid_arguments; use_--help; never_supply_secrets_as_arguments')


def parser():
    root=SafeParser(description=__doc__)
    commands=root.add_subparsers(dest='operation',required=True)
    for operation in ('install','upgrade'):
        p=commands.add_parser(operation)
        p.add_argument('--python',help='Python 3.14+ interpreter; no automatic system upgrade')
        p.add_argument('--home',help='Independent instance home')
        p.add_argument('--ref',help='Exact commit or tag; install defaults to local HEAD')
        p.add_argument('--source',default=str(SOURCE),help='Reviewed local Observer Git checkout; missing refs clone the official public repository')
        p.add_argument('--local-reviewed',action='store_true',help='Explicitly review a public-file working-tree snapshot instead of committed bytes')
        p.add_argument('--wheelhouse',help='Trusted complete offline wheels, including build/runtime dependencies')
        p.add_argument('--dry-run',action='store_true',help='Preview non-secret metadata; never read credentials or mutate targets')
        p.add_argument('--no-start',action='store_true',help='Leave the service stopped, including after recovery')
        if operation=='install':
            p.add_argument('--resume',action='store_true',help='Resume only this installer owned journal/home')
            for name in ('name','install-dir','project','alias','session','session-alias','tunnel-name','tunnel-id','client','unit'):
                p.add_argument('--'+name)
            p.add_argument('--proxy',choices=('on','off'),help='Enable flag only; URL is always hidden TTY input')
        else:
            p.add_argument('--resume',action='store_true',help='Recover an interrupted upgrade to its recorded previous release')
            p.add_argument('--rollback',action='store_true',help='Review and restore the previous retained release')
    return root


def main(argv=None):
    os.umask(0o077)
    terminal=Terminal()
    args=None
    try:
        args=parser().parse_args(argv)
        deployment=Deployment(terminal=terminal)
        if args.operation=='install': deployment.install(args)
        else: deployment.upgrade(args)
        return 0
    except KeyboardInterrupt:
        print('Cancelled safely. Completed grants/credentials and owned journals are retained; no existing instance was deleted.',file=sys.stderr)
        return 130
    except (Failure,OSError,ValueError,KeyError):
        # Refusal text is static except caller-selected non-secret labels.
        error=sys.exception()
        print('Stopped: '+str(error) if isinstance(error,Failure) else 'Stopped: unsafe_or_unavailable_local_operation; raw_errors_suppressed',file=sys.stderr)
        if args and args.operation=='install':
            print('Recovery: rerun install_linux_node.sh --resume --install-dir <the reviewed installation directory>. Do not delete the instance or re-register grants.',file=sys.stderr)
        elif args:
            print('Recovery: inspect the private upgrade-state.json/backups and retained release. Restore only the recorded unit/version; credentials and source grants remain in place.',file=sys.stderr)
        return 2
    finally: terminal.close()


if __name__=='__main__':
    raise SystemExit(main())
