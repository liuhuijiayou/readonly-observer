"""Synthetic deployment transactions, real hidden CLI over a pseudo terminal."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import subprocess
import sys
import sysconfig
import tempfile
import termios
import time
import unittest
from unittest.mock import patch

from support import PROJECT, jsonl, metadata
import linux_node as wizard
from observer.gitreader import GIT


class ScriptedTerminal:
    """Test-only actor. Production Terminal has no automatic approval mode."""
    def __init__(self, key=None, proxy=None):
        self.key=key or 'SYNTHETIC_WIZARD_'+os.urandom(8).hex()
        self.proxy=proxy or 'http://synthetic:synthetic@proxy.invalid:8080'
        self.output=[];self.commands=[];self.hidden_checks=[]
        self.decline=None;self.cancel=None;self.start=False;self.keep='keep';self.answers={}
    def available(self): return True
    def ask(self,prompt,default=None):
        if self.cancel and self.cancel in prompt: raise KeyboardInterrupt()
        if self.decline and self.decline in prompt: return 'reject'
        for fragment,value in self.answers.items():
            if fragment in prompt: return value
        if 'Existing ' in prompt: return self.keep
        if 'Start service now' in prompt: return 'start' if self.start else ''
        if 'type independent-key' in prompt: return 'independent-key'
        if 'type start' in prompt: return 'start'
        if 'type approve' in prompt: return 'approve'
        return default or ''
    def confirm(self,text,word='approve'):
        if self.ask(text+' — type '+word)!=word: raise wizard.Failure('operator_declined; no_scope_expansion')
    def show(self,text): self.output.append(text)
    def close(self): pass
    def foreground(self,args):
        self.commands.append([str(a) for a in args])
        if self.cancel and any(self.cancel in str(a) for a in args): raise KeyboardInterrupt()
        master,slave=pty.openpty()
        child=subprocess.Popen([str(a) for a in args],stdin=slave,stdout=slave,stderr=slave,env=wizard.clean_env(),close_fds=True)
        output=bytearray();approved=0;sent=False
        deadline=time.monotonic()+15
        try:
            while time.monotonic()<deadline:
                if select.select([master],[],[],.1)[0]:
                    try: block=os.read(master,65536)
                    except OSError: break
                    output.extend(block)
                if output.count(b'Type approve')>approved:
                    approved+=1
                    word=b'reject\n' if self.decline=='project-grant' and 'project' in args else b'approve\n'
                    os.write(master,word)
                if not sent and b'(hidden, local only): ' in output:
                    sent=True
                    echo=bool(termios.tcgetattr(slave)[3]&termios.ECHO)
                    self.hidden_checks.append(not echo)
                    if echo: raise AssertionError('synthetic secret would be echoed')
                    value=self.proxy if '--kind' in args else self.key
                    os.write(master,(value+'\n').encode())
                if child.poll() is not None:
                    # Drain remaining terminal bytes without waiting for EOF on
                    # the parent's still-open slave descriptor.
                    while select.select([master],[],[],0)[0]:
                        try: output.extend(os.read(master,65536))
                        except OSError: break
                    break
            if child.poll() is None: raise AssertionError('synthetic TTY timeout')
            text=output.decode(errors='replace')
            if self.key in text or self.proxy in text: raise AssertionError('synthetic secret echoed')
            self.output.append(text)
            if child.returncode: raise wizard.Failure('observer_local_confirmation_or_credential_input_failed')
        finally:
            if child.poll() is None:
                child.terminate();child.wait(timeout=5)
            os.close(master);os.close(slave)


class FakeHost(wizard.Host):
    def __init__(self,base,version):
        super().__init__(unit_dir=base/'units',registry=base/'registry',git=GIT)
        self.unit_dir.mkdir(mode=0o700)
        self.systemd=version;self.actions=[];self.active=set();self.enabled=set();self.fail_start=False
    def prerequisites(self,root,wheelhouse=None,dry=False):
        if sys.version_info<(3,14):raise wizard.Failure('python_3_14_required')
        return self.systemd
    def properties(self,unit):
        target=self.unit_dir/unit
        return {'LoadState':'loaded' if target.exists() else 'not-found',
                'ActiveState':'active' if unit in self.active else 'inactive',
                'FragmentPath':str(target) if target.exists() else '', 'DropInPaths':''}
    def control(self,action,unit):
        self.actions.append((action,unit))
        if action=='start':
            if self.fail_start:self.fail_start=False;raise wizard.Failure('synthetic_start_failure')
            self.active.add(unit)
        elif action=='stop':self.active.discard(unit)
        elif action=='enable':self.enabled.add(unit)
    def reload(self):self.actions.append(('reload',''))
    def render(self,python,home):
        code='from observer.linux import LinuxStore;from observer.linux_systemd import render;import sys;print(render(LinuxStore(sys.argv[1]),version=int(sys.argv[2])),end="")'
        return self.runner.run([python,'-I','-c',code,home,str(self.systemd)],'synthetic_unit_render')
    def verify(self,candidate):
        text=candidate.read_text()
        if self.systemd==219:
            if 'LoadCredential=' in text or 'ReadWritePaths=' in text or 'WorkingDirectory="' in text:raise AssertionError('unsupported 219 unit')
            if 'RuntimeDirectoryMode=0700' not in text:raise AssertionError('missing protected runtime')
        else:
            if 'LoadCredential=' not in text:raise AssertionError('native backend lost')


class FixtureBuilder(wizard.Builder):
    def __init__(self,wheel,manager_python,site):
        super().__init__(wizard.Runner());self.wheel=wheel;self.manager_python=manager_python;self.site=site;self.fail=False
    def install(self,source,release,python,wheelhouse=None):
        target=release/'venv'
        self.runner.run([sys.executable,'-m','venv','--without-pip',target],'test_venv')
        if self.fail:self.fail=False;raise wizard.Failure('synthetic_build_failure')
        self.runner.run([self.manager_python,'-I','-m','pip','--python',target/'bin/python','install','--no-index','--no-deps',self.wheel],'test_wheel_install')
        pure=target/'lib/python3.14/site-packages'
        (pure/'test-only-dependencies.pth').write_text(str(self.site)+'\n')
        return target/'bin/python'


class TestDeployment(wizard.Deployment):
    __test__=False
    def managed(self,python,home,unit):
        if unit not in self.host.active:raise wizard.Failure('synthetic_unit_not_active')
        self.probe(python,home)


@unittest.skipUnless(sys.platform.startswith('linux') and os.geteuid()==0,'root Linux wizard tests; Mac flow unchanged')
class WizardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent=PROJECT/'.local/verification/linux-wizard';parent.mkdir(parents=True,exist_ok=True)
        cls.shared=tempfile.TemporaryDirectory(prefix='shared-',dir=parent)
        cls.common=Path(cls.shared.name);cls.source=cls.common/'source'
        sys.path.insert(0,str(PROJECT/'scripts'))
        from check_repository import export_repository
        export_repository(PROJECT,cls.source)
        git_env=wizard.clean_env();git_env.update(GIT_AUTHOR_NAME='Synthetic',GIT_AUTHOR_EMAIL='fixture@example.invalid',
                                                GIT_COMMITTER_NAME='Synthetic',GIT_COMMITTER_EMAIL='fixture@example.invalid')
        def git(*args):
            result=subprocess.run([GIT,'-C',str(cls.source),*args],env=git_env,capture_output=True)
            if result.returncode:raise AssertionError('synthetic source Git setup failed')
        git('init','--initial-branch=main');git('add','.');git('commit','-qm','Synthetic v1');git('tag','v1')
        with (cls.source/'README.md').open('a') as f:f.write('\nSynthetic second revision.\n')
        git('add','README.md');git('commit','-qm','Synthetic v2');git('tag','v2')
        cls.manager=PROJECT/'.local/build-venv/bin/python'
        if cls.manager.exists():
            command=[str(cls.manager),'-I','-m','build','--wheel','--no-isolation','--outdir',str(cls.common/'wheels')]
        else:
            cls.manager=Path(sys.executable)
            command=[sys.executable,'-m','pip','wheel','--no-deps','--wheel-dir',str(cls.common/'wheels'),str(PROJECT)]
        result=subprocess.run(command,cwd=PROJECT,env=wizard.clean_env(),capture_output=True)
        if result.returncode:raise AssertionError('synthetic test wheel build failed')
        cls.wheel=next((cls.common/'wheels').glob('local_readonly_observer-*.whl'))
        cls.site=Path(sysconfig.get_paths()['purelib'])
    @classmethod
    def tearDownClass(cls):cls.shared.cleanup()
    def setUp(self):
        self.holder=tempfile.TemporaryDirectory(prefix='wz-',dir=PROJECT/'.local')
        self.addCleanup(self.holder.cleanup);self.base=Path(self.holder.name)
        self.project=self.base/'project';self.project.mkdir();(self.project/'public.txt').write_text('synthetic public marker\n')
        self.client=self.base/'fake-client';self.client.write_text('#!/bin/sh\nexit 3\n');self.client.chmod(0o700)
        self.host=FakeHost(self.base,219);self.terminal=ScriptedTerminal()
        self.builder=FixtureBuilder(self.wheel,self.manager,self.site)
        self.deployment=TestDeployment(self.host,self.terminal,self.builder)
    def args(self,node='one',**overrides):
        values=['install','--name',node,'--install-dir',str(self.base/('root-'+node)),'--home',str(self.base/('home-'+node)),
                '--project',str(self.project),'--alias','app','--tunnel-name',node+' tunnel','--tunnel-id',
                'tunnel_'+hashlib.sha256(node.encode()).hexdigest()[:32],'--client',str(self.client),'--unit','observer-'+node+'.service',
                '--proxy','on','--source',str(self.source),'--ref','v1','--no-start']
        args=wizard.parser().parse_args(values)
        for k,v in overrides.items():setattr(args,k,v)
        return args
    def upgrade_args(self,args,**overrides):
        value=wizard.parser().parse_args(['upgrade','--home',args.home,'--source',str(self.source),'--ref','v2','--no-start'])
        for k,v in overrides.items():setattr(value,k,v)
        return value
    def test_fresh_219_install_hidden_runtime_proxy_local_13_and_no_start(self):
        args=self.args();self.deployment.install(args)
        home=Path(args.home)
        self.assertEqual(self.terminal.hidden_checks,[True,True])
        self.assertTrue((home/'config/deployment.json').exists())
        self.assertEqual(wizard.load(home/'config/deployment.json')['plan']['tunnel_name'],'one tunnel')
        self.assertFalse(self.host.active)
        self.assertTrue((self.host.unit_dir/args.unit).exists())
        for filename in (Path(args.install_dir)/'install-state.json',home/'config/deployment.json'):
            self.assertNotIn(self.terminal.key,filename.read_text());self.assertNotIn(self.terminal.proxy,filename.read_text())
        self.assertIn('--unique-node-key',next(c for c in self.terminal.commands if 'credentials' in c and '--kind' not in c))
    def test_fresh_247_install_preserves_native_backend(self):
        self.host.systemd=247;args=self.args();self.deployment.install(args)
        unit=(self.host.unit_dir/args.unit).read_text()
        self.assertIn('LoadCredential=',unit);self.assertNotIn('_stage-credentials',unit)
    def test_two_instances_independent_home_tunnel_key_unit_and_identity(self):
        one=self.args();self.deployment.install(one)
        second=ScriptedTerminal();other=TestDeployment(self.host,second,self.builder);two=self.args('two');other.install(two)
        self.assertNotEqual(wizard.load(Path(one.home)/'config/node.json')['id'],wizard.load(Path(two.home)/'config/node.json')['id'])
        self.assertNotEqual(one.tunnel_id,two.tunnel_id)
        self.assertEqual(len(list(self.host.unit_dir.glob('*.service'))),2)
    def test_existing_home_and_existing_unit_are_not_overwritten(self):
        args=self.args();Path(args.home).mkdir(mode=0o700)
        with self.assertRaises(wizard.Failure):self.deployment.install(args)
        self.assertFalse(Path(args.install_dir).exists())
        Path(args.home).rmdir();existing=self.host.unit_dir/args.unit;existing.write_text('existing unit')
        with self.assertRaises(wizard.Failure):self.deployment.install(args)
        self.assertEqual(existing.read_text(),'existing unit');self.assertFalse(Path(args.install_dir).exists())
    def test_dry_run_does_not_create_or_read_credentials(self):
        args=self.args(dry_run=True);self.deployment.install(args)
        self.assertFalse(Path(args.home).exists());self.assertFalse(Path(args.install_dir).exists())
        self.assertFalse(self.terminal.commands);self.assertFalse(self.host.actions)
    def test_declined_plan_has_no_mutations(self):
        args=self.args();self.terminal.decline='Approve the displayed'
        with self.assertRaises(wizard.Failure):self.deployment.install(args)
        self.assertFalse(Path(args.home).exists());self.assertFalse(Path(args.install_dir).exists())
    def test_declined_project_scope_stops_before_secret_and_unit(self):
        args=self.args();self.terminal.decline='project-grant'
        with self.assertRaises(wizard.Failure):self.deployment.install(args)
        self.assertFalse((Path(args.home)/'credentials/runtime').exists())
        self.assertFalse((self.host.unit_dir/args.unit).exists())
        self.assertFalse(wizard.load(Path(args.home)/'config/approvals.json')['entries'])
    def test_partial_build_failure_and_explicit_resume(self):
        args=self.args();self.builder.fail=True
        with self.assertRaises(wizard.Failure):self.deployment.install(args)
        state=wizard.load(Path(args.install_dir)/'install-state.json')
        self.assertFalse(state['candidate_ready']);self.assertFalse(list((Path(args.install_dir)/'releases').iterdir()))
        args.resume=True;self.deployment.install(args)
        self.assertTrue(wizard.load(Path(args.install_dir)/'install-state.json')['complete'])
    def test_ctrl_c_preserves_owned_instance_and_resume_does_not_reregister(self):
        args=self.args();self.terminal.cancel='credentials'
        with self.assertRaises(KeyboardInterrupt):self.deployment.install(args)
        grants=wizard.read_file(Path(args.home)/'config/approvals.json',mode=0o600)
        before=sum('project' in c and 'add' in c for c in self.terminal.commands)
        self.assertFalse(list(Path(args.install_dir).rglob('.pending-*')))
        self.terminal.cancel=None;args.resume=True;self.deployment.install(args)
        self.assertEqual(grants,wizard.read_file(Path(args.home)/'config/approvals.json',mode=0o600))
        self.assertEqual(before,sum('project' in c and 'add' in c for c in self.terminal.commands))
    def test_existing_key_keep_does_not_read_or_replace_and_rotation_is_explicit(self):
        args=self.args();self.terminal.cancel='Approve this verified systemd'
        with self.assertRaises(KeyboardInterrupt):self.deployment.install(args)
        source=Path(args.home)/'credentials/runtime';before=wizard.metadata(source)
        self.terminal.cancel=None;args.resume=True;self.deployment.install(args)
        self.assertEqual(before,wizard.metadata(source));self.assertEqual(len(self.terminal.hidden_checks),2)
    def test_duplicate_host_key_is_refused_by_hidden_observer_cli(self):
        one=self.args();self.deployment.install(one)
        duplicate=ScriptedTerminal(key=self.terminal.key)
        two=self.args('two');other=TestDeployment(self.host,duplicate,self.builder)
        with self.assertRaises(wizard.Failure):other.install(two)
        self.assertFalse((Path(two.home)/'credentials/runtime').exists())
    def test_duplicate_tunnel_is_refused_before_source_or_key(self):
        one=self.args();self.deployment.install(one)
        two=self.args('two');two.tunnel_id=one.tunnel_id
        with self.assertRaises(wizard.Failure):self.deployment.install(two)
        self.assertFalse(Path(two.home).exists())
    def test_upgrade_and_explicit_rollback_keep_grants_and_credentials(self):
        args=self.args();self.deployment.install(args);home=Path(args.home)
        before={n:wizard.metadata(home/'credentials'/n) for n in ('runtime','proxy')}
        grants=wizard.read_file(home/'config/approvals.json',mode=0o600)
        original=wizard.load(home/'config/deployment.json')
        self.deployment.upgrade(self.upgrade_args(args))
        updated=wizard.load(home/'config/deployment.json');self.assertNotEqual(updated['release'],original['release'])
        self.assertTrue(Path(original['release']).exists())
        self.deployment.upgrade(self.upgrade_args(args,ref=None,rollback=True))
        self.assertEqual(wizard.load(home/'config/deployment.json')['release'],original['release'])
        self.assertEqual(grants,wizard.read_file(home/'config/approvals.json',mode=0o600))
        self.assertEqual(before,{n:wizard.metadata(home/'credentials'/n) for n in ('runtime','proxy')})
        backup=Path(args.install_dir)/'backups'
        self.assertFalse(any(p.name in {'runtime','proxy'} for p in backup.rglob('*')))
    def test_upgrade_build_failure_restores_previous_running_state(self):
        args=self.args();self.deployment.install(args);home=Path(args.home)
        original=wizard.load(home/'config/deployment.json');body=(self.host.unit_dir/args.unit).read_bytes()
        self.host.active.add(args.unit);self.builder.fail=True
        with self.assertRaises(wizard.Failure):self.deployment.upgrade(self.upgrade_args(args,no_start=False))
        self.assertEqual(original,wizard.load(home/'config/deployment.json'))
        self.assertEqual(body,(self.host.unit_dir/args.unit).read_bytes());self.assertIn(args.unit,self.host.active)
    def test_upgrade_start_failure_rolls_back_automatically(self):
        args=self.args();self.deployment.install(args);home=Path(args.home)
        original=wizard.load(home/'config/deployment.json');self.host.active.add(args.unit);self.host.fail_start=True
        with self.assertRaises(wizard.Failure):self.deployment.upgrade(self.upgrade_args(args,no_start=False))
        self.assertEqual(wizard.load(home/'config/deployment.json'),original);self.assertIn(args.unit,self.host.active)
    def test_modified_managed_unit_refuses_upgrade_before_stop(self):
        args=self.args();self.deployment.install(args);unit=self.host.unit_dir/args.unit
        unit.write_text('external edit');self.host.actions.clear()
        with self.assertRaises(wizard.Failure):self.deployment.upgrade(self.upgrade_args(args))
        self.assertFalse(self.host.actions);self.assertEqual(unit.read_text(),'external edit')
    def test_optional_session_is_exact_and_separately_approved(self):
        session=self.base/'selected.jsonl';jsonl(session,[metadata('chosen',self.project)])
        args=self.args(session=str(session),session_alias='task');self.deployment.install(args)
        entries=wizard.load(Path(args.home)/'config/approvals.json')['entries']
        self.assertEqual([e['path'] for e in entries if e['kind']=='session'],[str(session)])
    def test_full_metadata_wizard_collects_all_non_secret_fields(self):
        args=wizard.parser().parse_args(['install'])
        self.terminal.answers={'Node Name':'node','Installation Directory':str(self.base/'root'),
            'Instance Home':str(self.base/'home'),'Project absolute':str(self.project),'Project Alias':'app',
            'Optional Exact':str(self.base/'selected.jsonl'),'Exact Session Alias':'task','Tunnel Display Name':'node tunnel',
            'Tunnel ID':'tunnel_'+'c'*32,'Tunnel Client Absolute':str(self.client),'Enable Proxy':'yes',
            'systemd Unit Name':'observer-node.service'}
        plan=wizard.collect_install(args,self.terminal)
        self.assertEqual(plan['name'],'node');self.assertTrue(plan['proxy']);self.assertEqual(plan['session_alias'],'task')
        self.assertNotIn('key',plan);self.assertNotIn('proxy_url',plan)
    def test_unsafe_paths_aliases_missing_explicit_tunnel_and_headless_secret_flags(self):
        args=self.args();plan=wizard.collect_install(args,self.terminal)
        for key,value in [('home',args.project),('project',args.home+'/nested-project'),
                          ('alias','../bad'),('unit','bad@.service'),('tunnel_id','')]:
            with self.subTest(key=key),self.assertRaises(wizard.Failure):wizard.validate_plan({**plan,key:value})
        with self.assertRaises(wizard.Failure):wizard.parser().parse_args(['install','--runtime-key','NEVER_ACCEPT_A_SECRET_ARGUMENT'])
    def test_explicit_rotation_only_after_existing_credential_choice(self):
        args=self.args();self.terminal.cancel='Approve this verified systemd'
        with self.assertRaises(KeyboardInterrupt):self.deployment.install(args)
        source=Path(args.home)/'credentials/runtime';before=wizard.metadata(source)
        self.terminal.cancel=None;self.terminal.keep='rotate';self.terminal.key+='_ROTATED';args.resume=True
        self.deployment.install(args)
        self.assertNotEqual(before,wizard.metadata(source));self.assertEqual(self.terminal.hidden_checks,[True]*4)

    def test_upgrade_refusal_leaves_previous_service_stopped(self):
        args=self.args();self.deployment.install(args);self.host.active.add(args.unit)
        previous=wizard.load(Path(args.home)/'config/deployment.json')
        self.terminal.decline='Approve replacing only'
        with self.assertRaises(wizard.Failure):self.deployment.upgrade(self.upgrade_args(args,no_start=False))
        self.assertNotIn(args.unit,self.host.active)
        self.assertEqual(previous,wizard.load(Path(args.home)/'config/deployment.json'))

    def test_interrupted_upgrade_recovery_uses_recorded_unit_and_no_key_read(self):
        args=self.args();self.deployment.install(args);home=Path(args.home)
        previous,root,target,props=self.deployment.check_deployment(home)
        tx={'id':os.urandom(8).hex(),'journal':'upgrade-state.json','previous':previous,'was_active':False}
        self.deployment.backup(home,target,root,tx)
        tx['candidate_unit_digest']=hashlib.sha256(b'partial replacement').hexdigest()
        wizard.atomic(target,b'partial replacement',mode=0o644,expected=previous['unit_digest'])
        wizard.save(root/'upgrade-state.json',tx)
        self.deployment.upgrade(self.upgrade_args(args,ref=None,resume=True))
        self.assertEqual(wizard.digest(target),previous['unit_digest'])
        self.assertTrue(wizard.load(root/'upgrade-state.json')['rolled_back'])

    def test_preflight_rejects_old_git_before_any_deployment(self):
        class Responses(wizard.Runner):
            def run(self,argv,label,**kwargs):
                if label=='git_version':return b'git version 1.8.3.1\n'
                return b''
        host=wizard.Host(runner=Responses(),unit_dir=self.host.unit_dir,registry=self.host.registry)
        with self.assertRaisesRegex(wizard.Failure,'git_2_28'):
            host.prerequisites(self.base/'new',dry=True)
        self.assertFalse((self.base/'new').exists())

    def test_real_tty_metadata_wizard_and_hidden_cli_complete_without_editing_config(self):
        args=wizard.parser().parse_args(['install','--source',str(self.source),'--ref','v1'])
        root=self.base/'interactive';home=self.base/'interactive-home'
        key='SYNTHETIC_FULL_TTY_KEY';proxy='http://tty:tty@proxy.invalid:8080'
        responses=[(b'Node Name',b'interactive'),(b'Installation Directory',str(root).encode()),
            (b'Instance Home',str(home).encode()),(b'Project absolute Path',str(self.project).encode()),
            (b'Project Alias',b'app'),(b'Optional Exact Codex',b''),(b'Tunnel Display Name',b'interactive tunnel'),
            (b'Tunnel ID',('tunnel_'+'9'*32).encode()),(b'Tunnel Client Absolute',str(self.client).encode()),
            (b'Enable Proxy',b'yes'),(b'systemd Unit Name',b'observer-interactive.service'),
            (b'Approve the displayed',b'approve'),(b'Approve this trusted',b'approve'),
            (b'Type approve',b'approve'),(b'type independent-key',b'independent-key'),
            (b'(hidden, local only): ',key.encode()),(b'(hidden, local only): ',proxy.encode()),
            (b'Approve this verified',b'approve'),(b'Start service now',b'')]
        pid,fd=pty.fork()
        if pid==0:
            try:
                actual=TestDeployment(self.host,wizard.Terminal(),self.builder)
                actual.install(args)
                os._exit(0)
            except BaseException:os._exit(2)
        output=bytearray();offset=0;index=0;status=None;deadline=time.monotonic()+45
        try:
            while time.monotonic()<deadline:
                if select.select([fd],[],[],.1)[0]:
                    try:output.extend(os.read(fd,65536))
                    except OSError:break
                if index<len(responses):
                    prompt,value=responses[index];where=output.find(prompt,offset)
                    if where>=0:
                        if b'hidden' in prompt:self.assertFalse(termios.tcgetattr(fd)[3]&termios.ECHO)
                        os.write(fd,value+b'\n');offset=where+len(prompt);index+=1
                ended,status=os.waitpid(pid,os.WNOHANG)
                if ended:break
                status=None
            if status is None:
                ended,status=os.waitpid(pid,os.WNOHANG)
                if not ended:raise AssertionError('interactive wizard timeout at prompt '+str(index))
            self.assertEqual(os.waitstatus_to_exitcode(status),0)
            self.assertEqual(index,len(responses))
            self.assertNotIn(key.encode(),output);self.assertNotIn(proxy.encode(),output)
            self.assertTrue((home/'config/deployment.json').exists())
            self.assertFalse((home/'config/settings.json').stat().st_mode&0o077)
        finally:
            if status is None:
                os.kill(pid,signal.SIGTERM);os.waitpid(pid,0)
            os.close(fd)

    def test_unsafe_registry_and_instance_symlinks_fail_closed(self):
        args=self.args();Path(args.home).symlink_to(self.project,target_is_directory=True)
        with self.assertRaises(wizard.Failure):self.deployment.install(args)
        self.assertFalse(Path(args.install_dir).exists())

    def test_recovery_requires_root_before_reading_instance_metadata(self):
        args=self.upgrade_args(self.args(),resume=True,ref=None)
        with patch.object(wizard.os,'geteuid',return_value=1000), patch.object(wizard,'load') as read:
            with self.assertRaisesRegex(wizard.Failure,'root_required'):self.deployment.upgrade(args)
            read.assert_not_called()

    def test_retired_node_cannot_be_upgraded_or_started(self):
        args=self.args();self.deployment.install(args);home=Path(args.home)
        deployed=wizard.load(home/'config/deployment.json')
        self.deployment.cli(Path(deployed['release'])/'venv/bin/python',home,'node','retire','--approve')
        self.host.actions.clear()
        with self.assertRaisesRegex(wizard.Failure,'node_identity_changed_or_retired'):
            self.deployment.upgrade(self.upgrade_args(args))
        self.assertFalse(self.host.actions)

    def test_resume_refuses_candidate_owned_by_another_transaction(self):
        args=self.args();self.terminal.cancel='credentials'
        with self.assertRaises(KeyboardInterrupt):self.deployment.install(args)
        state=wizard.load(Path(args.install_dir)/'install-state.json')
        wizard.atomic(Path(state['candidate'])/'.owned-candidate',b'another-transaction')
        self.terminal.cancel=None;self.host.actions.clear();args.resume=True
        with self.assertRaisesRegex(wizard.Failure,'candidate_not_owned_by_transaction'):
            self.deployment.install(args)
        self.assertFalse(self.host.actions)
