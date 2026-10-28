#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise the actual harness source gate with real, private Git repositories."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE/'xdev_ext_mech_zc_kvm.sh'
PROJECT = HERE.parents[4]
ANCHORS = ('net/xdp/xsk_xdev_ext_mech_zc_core.h',
           'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh',
           'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_wire.py',
           'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_validate.py')


class SourceGate(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='xdev-source-gate-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)

    def git(self, root, *args):
        return subprocess.check_output(['git','-C',str(root),*args], stderr=subprocess.STDOUT, text=True).strip()

    def checkout(self, overlay=False):
        root = self.folder/('project' if overlay else 'linux')
        root.mkdir()
        self.git(root,'init','-q')
        source = root/'kernel' if overlay else root
        source.mkdir(exist_ok=True)
        tracked = ['.gitignore']
        ignored = ['Makefile','Kconfig','scripts/Makefile.build','include/linux/types.h']
        prefix = 'kernel/' if overlay else ''
        (root/'.gitignore').write_text('build/\n'+''.join('/'+prefix+p+'\n' for p in ignored))
        for relative in ANCHORS:
            path=source/relative;path.parent.mkdir(parents=True,exist_ok=True)
            original=HERE/Path(relative).name
            path.write_bytes(original.read_bytes() if original.is_file() else b'fixture source anchor\n')
            tracked.append(prefix+relative)
        path=source/'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py'
        path.write_bytes((HERE/path.name).read_bytes());tracked.append(prefix+str(path.relative_to(source)))
        for relative in ignored:
            path=source/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('upstream fixture\n')
        if overlay:
            spec={'url':'https://example.invalid/linux.git','ref':'refs/tags/fixture',
                  'commit':'1'*40,'path':'kernel'}
            (root/'sources.lock.json').write_text(json.dumps({'schema':1,'components':{'linux':spec}}))
            path=root/'scripts/prepare_sources.py';path.parent.mkdir();path.write_bytes((PROJECT/'scripts/prepare_sources.py').read_bytes())
            marker=root/'build/source-state/linux.json';marker.parent.mkdir(parents=True)
            marker.write_text(json.dumps({'schema':1,'component':'linux',**spec}))
            tracked+=['sources.lock.json','scripts/prepare_sources.py']
        self.git(root,'add','--',*tracked)
        self.git(root,'-c','user.name=Selftest','-c','user.email=selftest@invalid','commit','-qm','source fixture')
        return root,source

    def gate(self, source):
        script=HARNESS.read_text()
        block=script[script.index('SRC=${SOURCE_OVERRIDE:'):script.index('# Use the same campaign geometry')]
        body='set -euo pipefail\nSOURCE_OVERRIDE=$1\nSCRATCH=$2\n'+block
        body+='printf "GATE_ROOT=%s\\nGATE_SHA=%s\\nGATE_LAYOUT=%s\\n" "${SOURCE_GIT_ROOT:-unset}" "${SOURCE_COMMIT:-unset}" "${SOURCE_LAYOUT:-unset}"\n'
        return subprocess.run(['bash','-c',body,'source-gate',str(source),str(self.folder)],text=True,capture_output=True,timeout=20)

    def test_standalone_kernel_checkout(self):
        _,source=self.checkout()
        self.assertEqual(self.gate(source).returncode,0)

    def test_prepared_overlay_records_actual_project_identity(self):
        root,source=self.checkout(True)
        run=self.gate(source)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
        self.assertIn('GATE_ROOT='+str(root),run.stdout)
        self.assertIn('GATE_SHA='+self.git(root,'rev-parse','HEAD'),run.stdout)
        self.assertIn('GATE_LAYOUT=overlay',run.stdout)

    def test_standalone_git_worktree(self):
        root,_=self.checkout()
        source=self.folder/'worktree'
        self.git(root,'worktree','add','--detach',str(source))
        self.assertEqual(self.gate(source).returncode,0)

    def test_rejects_non_git_wrong_root_and_symlink(self):
        non_git=self.folder/'plain';non_git.mkdir()
        self.assertNotEqual(self.gate(non_git).returncode,0)
        root,source=self.checkout(True)
        self.assertNotEqual(self.gate(root).returncode,0)
        wrong=root/'other';wrong.mkdir()
        self.assertNotEqual(self.gate(wrong).returncode,0)
        link=self.folder/'link';link.symlink_to(source,target_is_directory=True)
        self.assertNotEqual(self.gate(link).returncode,0)

    def test_overlay_rejects_missing_or_mismatched_preparation(self):
        root,source=self.checkout(True)
        marker=root/'build/source-state/linux.json'
        original=marker.read_text();marker.unlink()
        self.assertNotEqual(self.gate(source).returncode,0)
        marker.write_text(original.replace('1'*40,'2'*40))
        self.assertNotEqual(self.gate(source).returncode,0)

    def test_dirty_and_untracked_files_outside_kernel_are_rejected(self):
        root,source=self.checkout(True)
        path=root/'unexpected';path.write_text('not part of source identity\n')
        self.assertNotEqual(self.gate(source).returncode,0)
        path.unlink();path=root/'sources.lock.json';original=path.read_text();path.write_text(original+'\n')
        self.assertNotEqual(self.gate(source).returncode,0)
        self.git(root,'add','--','sources.lock.json')
        self.assertNotEqual(self.gate(source).returncode,0)

    def test_overlay_preparation_must_describe_this_kernel_directory(self):
        root,source=self.checkout(True)
        path=root/'sources.lock.json';lock=json.loads(path.read_text())
        lock['components']['linux']['path']='other';path.write_text(json.dumps(lock))
        marker=root/'build/source-state/linux.json';receipt=json.loads(marker.read_text())
        receipt['path']='other';marker.write_text(json.dumps(receipt))
        for relative in ('Makefile','Kconfig','scripts/Makefile.build','include/linux/types.h'):
            path=root/'other'/relative;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('another prepared directory\n')
        path=root/'.gitignore';path.write_text(path.read_text()+'other/\n')
        self.git(root,'add','--','.gitignore','sources.lock.json')
        self.git(root,'-c','user.name=Selftest','-c','user.email=selftest@invalid','commit','-qm','other preparation path')
        self.assertNotEqual(self.gate(source).returncode,0)

    def test_missing_tracked_anchor_is_rejected(self):
        root,source=self.checkout()
        self.git(root,'rm','--',ANCHORS[0])
        self.git(root,'-c','user.name=Selftest','-c','user.email=selftest@invalid','commit','-qm','missing source anchor')
        self.assertNotEqual(self.gate(source).returncode,0)

    def run_only(self, stamp):
        _,source=self.checkout(True)
        scratch=Path('/tmp/xdev-ext-e2e.'+secrets.token_hex(8));scratch.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree,scratch)
        record=scratch/'build/xdev-ext-source.commit'
        if stamp is not None:
            record.parent.mkdir();record.write_text(stamp+'\n')
        env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1'
        run=subprocess.run(['bash',str(HARNESS),'--scratch',str(scratch),'--source',str(source),'--run-only'],text=True,capture_output=True,timeout=20,env=env)
        return run,record

    def test_lifecycle_refuses_missing_collector_before_guest_setup(self):
        _, source = self.checkout(True)
        scratch = Path('/tmp/xdev-ext-e2e.' + secrets.token_hex(8))
        scratch.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, scratch)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        run = subprocess.run(['bash', str(HARNESS), '--source', str(source),
                              '--scratch', str(scratch), '--lifecycle'],
                             text=True, capture_output=True, timeout=20, env=env)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('native validation requires the product overlay', run.stderr)
        self.assertFalse((scratch / 'build').exists())

    def test_run_only_never_creates_missing_source_stamp(self):
        run,record=self.run_only(None)
        self.assertNotEqual(run.returncode,0)
        self.assertIn('run-only build identity missing',run.stdout+run.stderr)
        self.assertFalse(record.exists())

    def test_run_only_never_relabels_old_kernel_commit_as_project_sha(self):
        old='0'*40
        run,record=self.run_only(old)
        self.assertNotEqual(run.returncode,0)
        self.assertIn('run-only source SHA mismatch',run.stdout+run.stderr)
        self.assertEqual(record.read_text(),old+'\n')


if __name__=='__main__':
    unittest.main(verbosity=2)
