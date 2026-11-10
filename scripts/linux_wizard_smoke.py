"""Actual systemd wizard install/upgrade/rollback with synthetic TTY credentials.

Requires root and an installed test package/dependencies. Only uniquely named
runtime units and workspace-private fixture paths are used. No real Tunnel,
production instance, key, proxy or session is accessed. --git is test-only.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).absolute().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests'),str(ROOT/'src')]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--git',default='/usr/bin/git',help='Modern root-trusted Git for synthetic source fixtures only')
    args=parser.parse_args()
    if not sys.platform.startswith('linux') or os.geteuid()!=0:
        print(json.dumps({'status':'skipped','reason':'Linux root required'}));return 0
    import observer.gitreader as reader
    reader.GIT=reader.FIXED_ARGS[0]=args.git
    import test_linux_wizard as fixtures
    import linux_node as wizard
    from systemd_smoke import FAKE

    class RuntimeHost(wizard.Host):
        def control(self,action,unit):
            if action in {'enable','disable'}:
                self.runner.run(['/bin/systemctl','--runtime',action,unit],'synthetic_runtime_'+action,timeout=30)
            else: super().control(action,unit)

    class RealWizard(unittest.TestCase):
        @classmethod
        def setUpClass(cls):fixtures.WizardTests.setUpClass()
        @classmethod
        def tearDownClass(cls):fixtures.WizardTests.tearDownClass()
        def setUp(self):
            self.fixture=fixtures.WizardTests('test_fresh_219_install_hidden_runtime_proxy_local_13_and_no_start')
            self.fixture.setUp()
            self.addCleanup(self.fixture.doCleanups)
            f=self.fixture
            f.client.write_text('#!'+sys.executable+'\n'+FAKE);f.client.chmod(0o700)
            self.host=RuntimeHost(unit_dir=Path('/run/systemd/system'),registry=f.base/'host-registry',git=args.git)
            self.deployment=wizard.Deployment(self.host,f.terminal,f.builder)
            f.terminal.start=True
            self.args=f.args('actual-'+os.urandom(4).hex(),no_start=False,wheelhouse=str(fixtures.WizardTests.common/'wheels'))
            self.addCleanup(self.cleanup_unit)
        def cleanup_unit(self):
            unit=self.args.unit;target=self.host.unit_dir/unit
            for command in (['stop',unit],['--runtime','disable',unit],['reset-failed',unit]):
                subprocess.run(['/bin/systemctl',*command],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
            state=Path(self.args.install_dir)/'install-state.json'
            if target.exists():
                expected=wizard.load(Path(self.args.home)/'config/deployment.json')['unit_digest'] if (Path(self.args.home)/'config/deployment.json').exists() else wizard.load(state).get('unit_digest')
                self.assertEqual(wizard.digest(target),expected)
                target.unlink()
            self.host.reload()
            from observer.linux import LinuxStore
            from observer.linux_legacy import runtime_path
            if self.host.version()<247:self.assertFalse(runtime_path(LinuxStore(self.args.home)).exists())
        def test_real_unit_fresh_install_upgrade_rollback_without_credential_copy(self):
            self.deployment.install(self.args)
            home=Path(self.args.home)
            before={n:wizard.metadata(home/'credentials'/n) for n in ('runtime','proxy')}
            grants=wizard.read_file(home/'config/approvals.json',mode=0o600)
            initial=wizard.load(home/'config/deployment.json')
            self.assertEqual(self.host.properties(self.args.unit)['ActiveState'],'active')
            record=json.loads((home/'cache/client.json').read_text())
            self.assertEqual(record['readonly_tools'],13);self.assertTrue(record['readonly_annotations'])
            self.assertFalse(record['credentials_directory']);self.assertFalse(record['ambient_proxy'])
            self.assertTrue(record['source_readonly'])
            upgrade=self.fixture.upgrade_args(self.args,no_start=False,wheelhouse=self.args.wheelhouse)
            self.deployment.upgrade(upgrade)
            updated=wizard.load(home/'config/deployment.json')
            self.assertNotEqual(updated['release'],initial['release'])
            rollback=self.fixture.upgrade_args(self.args,ref=None,rollback=True,no_start=False,wheelhouse=self.args.wheelhouse)
            self.deployment.upgrade(rollback)
            self.assertEqual(wizard.load(home/'config/deployment.json')['release'],initial['release'])
            self.assertEqual(before,{n:wizard.metadata(home/'credentials'/n) for n in ('runtime','proxy')})
            self.assertEqual(grants,wizard.read_file(home/'config/approvals.json',mode=0o600))
            self.assertEqual(self.fixture.terminal.hidden_checks,[True,True])
            self.host.control('stop',self.args.unit)
            self.assertEqual(self.host.properties(self.args.unit)['ActiveState'],'inactive')

    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RealWizard))
    print(json.dumps({'actual_systemd':wizard.Host().version(),'tests':result.testsRun,
                     'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
                     'credentials':'synthetic_only','client':'fake_no_network','git_dependency':args.git}))
    return 0 if result.wasSuccessful() else 1


if __name__=='__main__':raise SystemExit(main())
