# SPDX-License-Identifier: GPL-2.0-only
"""Run actual kernel selftest readers against nested/standalone Git history."""
import argparse
import ast
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
CASES = {
    'peer': ('xdev_ext_mech/peer_graph/independent_admission.py', 'io_uring/xdev_ext_mech_step.h'),
    'socket': ('xdev_ext_mech/socket_guest/independent_class7_admission.py', 'io_uring/xdev_ext_mech_core.h'),
    'fork': ('xdev_ext_preload/independent_mech_fork_teardown.py', 'tools/io_uring_unified_preload.c'),
    'nowait': ('xdev_ext_mech/xdev_ext_mech_nvme_nowait_test.py', 'drivers/nvme/host/xdev_ext_mech_nvme.c'),
    'provider': ('xdev_ext_mech/provider/faults/run.py', 'io_uring/xdev_ext_mech_dma.c'),
}


def git(root, *args):
    return subprocess.check_output(['git','-C',str(root),*args], text=True, stderr=subprocess.PIPE).strip()


def actual_reader(kind, kernel, revision=None):
    filename,relative = CASES[kind]
    script = PROJECT/'kernel/tools/testing/selftests'/filename
    tree = ast.parse(script.read_text())
    scope = {'subprocess':subprocess, 'KERNEL':kernel, 'ROOT':kernel,
             'TEST_REVISION':revision, 'REF':revision, 'filename':relative,
             'name':relative, 'a':argparse.Namespace(revision=revision),
             'args':argparse.Namespace(revision=revision)}
    if kind=='provider':
        function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='source')
        exec(compile(ast.Module(body=[function],type_ignores=[]),str(script),'exec'),scope)
        return scope['source'](relative).encode()
    if kind=='peer':
        call=next(n for n in ast.walk(tree) if isinstance(n,ast.Call)
                  and isinstance(n.func,ast.Attribute) and n.func.attr=='check_output')
        return eval(compile(ast.Expression(call),str(script),'eval'),scope)
    if kind in ('socket','fork'):
        variable='data' if kind=='socket' else 'preload'
        assignment=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign)
                        and any(isinstance(t,ast.Name) and t.id==variable for t in n.targets))
        value=eval(compile(ast.Expression(assignment.value),str(script),'eval'),scope)
        return value if isinstance(value,bytes) else value.encode()
    # nowait now selects one dependency owner before reading it. Execute that
    # actual selection and its complete source branch, not the old is_file elif.
    setup=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='setUpClass')
    selections=[n for n in setup.body if isinstance(n,ast.Assign)
                and any(isinstance(t,ast.Name) and t.id=='selected' for t in n.targets)
                and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name)
                and n.value.func.id=='selected_source']
    branches=[n for n in setup.body if isinstance(n,ast.If)
              and any(isinstance(assignment,ast.Assign)
                      and any(isinstance(t,ast.Name) and t.id=='source' for t in assignment.targets)
                      and isinstance(assignment.value,ast.Call)
                      and isinstance(assignment.value.func,ast.Attribute)
                      and isinstance(assignment.value.func.value,ast.Name)
                      and assignment.value.func.value.id=='selected'
                      and assignment.value.func.attr=='read'
                      and len(assignment.value.args)==1
                      and isinstance(assignment.value.args[0],ast.Name)
                      and assignment.value.args[0].id=='RELATIVE_SOURCE'
                      for assignment in ast.walk(n))]
    if len(selections)!=1 or len(branches)!=1:
        raise RuntimeError('expected one actual nowait selection and source branch')
    layout_file=next(p/'tools/layout.py' for p in script.resolve().parents
                     if (p/'tools/layout.py').is_file())
    canonical=runpy.run_path(str(layout_file))['canonical_root'](script)
    utility=runpy.run_path(str(canonical/'tests/storage/nvme/_legacy_storfam_fixture.py'))

    def selected_read(owner):
        # A private tree needs its own mapping when TMPDIR has a canonical
        # checkout ancestor; source selection must stop at this exact owner.
        (owner/'source-layout.json').write_text(json.dumps(dict(schema=1,files=[
            dict(source=relative,component='linux',native_path=relative)])))
        scope.update(Path=Path,os=os,ROOT=owner,source_path=owner/relative,
                     RELATIVE_SOURCE=relative,selected_source=utility['selected_source'])
        # Select this owner while retaining parent toolchain and layout hints.
        with mock.patch.dict(os.environ,{'XDEV_EXT_NVME_TEST_ROOT':str(owner)}):
            os.environ.pop('XDEV_EXT_NVME_TEST_SOURCE',None)
            exec(compile(ast.Module(body=[selections[0],branches[0]],type_ignores=[]),
                         str(script),'exec'),scope)
            scope['selected'].verify()
        return scope['source'].encode()

    if revision is None:
        return selected_read(kernel)
    # The actual owner API intentionally has no revision/fallback parameter.
    # Supply a separate tree of the requested snapshot; never current bytes.
    prefix=git(kernel,'rev-parse','--show-prefix')
    snapshot=subprocess.check_output(['git','-C',str(kernel),'show',revision+':'+prefix+relative],
                                     stderr=subprocess.PIPE)
    with tempfile.TemporaryDirectory(prefix='xdev-nowait-revision-owner-') as temporary:
        owner=Path(temporary)
        target=owner/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(snapshot)
        return selected_read(owner)


class KernelRevisionLayoutTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='xdev-kernel-revision-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        git(self.root,'init','-q')
        git(self.root,'config','user.name','Selftest')
        git(self.root,'config','user.email','selftest@invalid')

    def checkout(self,nested):
        kernel=self.root/'kernel' if nested else self.root
        tracked=[]
        for kind,(_,relative) in CASES.items():
            target=kernel/relative;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_text('authoritative kernel '+kind+'\n')
            tracked.append(str(target.relative_to(self.root)))
            if nested:
                decoy=self.root/relative;decoy.parent.mkdir(parents=True,exist_ok=True)
                decoy.write_text('wrong root '+kind+'\n');tracked.append(relative)
        git(self.root,'add','--',*tracked);git(self.root,'commit','-qm','exact source snapshot')
        return kernel,git(self.root,'rev-parse','HEAD')

    def test_nested_revision_and_sparse_head_read_kernel_not_root_decoy(self):
        kernel,revision=self.checkout(True)
        for kind in CASES:
            with self.subTest(reader=kind):
                self.assertEqual(actual_reader(kind,kernel,revision),('authoritative kernel '+kind+'\n').encode())

    def test_standalone_revision_and_sparse_head_remain_compatible(self):
        kernel,revision=self.checkout(False)
        for kind in CASES:
            with self.subTest(reader=kind):
                self.assertEqual(actual_reader(kind,kernel,revision),('authoritative kernel '+kind+'\n').encode())

    def test_current_local_branches_keep_worktree_edits(self):
        kernel,_=self.checkout(True)
        for kind,(_,relative) in CASES.items():
            if kind=='peer':
                continue  # No source-reading branch without --revision.
            with self.subTest(reader=kind):
                target=kernel/relative;target.write_text('current local '+kind+'\n')
                self.assertEqual(actual_reader(kind,kernel),('current local '+kind+'\n').encode())

    def test_explicit_revision_ignores_later_local_edits(self):
        kernel,revision=self.checkout(True)
        for kind,(_,relative) in CASES.items():
            (kernel/relative).write_text('later local edits\n')
            with self.subTest(reader=kind):
                self.assertEqual(actual_reader(kind,kernel,revision),('authoritative kernel '+kind+'\n').encode())

    def test_missing_historical_file_rejects_even_with_current_and_root_files(self):
        kernel,_=self.checkout(True)
        git(self.root,'rm','--',*('kernel/'+relative for _,relative in CASES.values()))
        git(self.root,'commit','-qm','snapshot without requested source files')
        revision=git(self.root,'rev-parse','HEAD')
        for kind,(_,relative) in CASES.items():
            (kernel/relative).parent.mkdir(parents=True,exist_ok=True)
            (kernel/relative).write_text('current source cannot substitute history\n')
            with self.subTest(reader=kind),self.assertRaises(subprocess.CalledProcessError):
                actual_reader(kind,kernel,revision)

    def test_nowait_missing_selected_file_rejects_head_and_other_current_sources(self):
        kernel,_=self.checkout(True)
        relative=CASES['nowait'][1]
        target=kernel/relative
        decoy=self.root/relative
        other=self.root/'another-native'/relative
        other.parent.mkdir(parents=True,exist_ok=True)
        other.write_text('another current nowait source\n')
        target.unlink()
        self.assertTrue(kernel.is_dir())
        self.assertFalse(target.exists())
        self.assertEqual(git(self.root,'show','HEAD:kernel/'+relative),
                         'authoritative kernel nowait')
        self.assertEqual(decoy.read_text(),'wrong root nowait\n')
        self.assertEqual(other.read_text(),'another current nowait source\n')
        # No revision means the actual selected_source/read path must reject;
        # caller snapshot preparation cannot supply this test's exception.
        with self.assertRaises(ValueError) as raised:
            actual_reader('nowait',kernel,revision=None)
        self.assertEqual(str(raised.exception),'Missing regular source: '+str(target))
        self.assertFalse(target.exists())
        self.assertEqual(decoy.read_text(),'wrong root nowait\n')
        self.assertEqual(other.read_text(),'another current nowait source\n')

    def test_invalid_revision_does_not_fall_back_to_head_or_worktree(self):
        kernel,_=self.checkout(True)
        for kind in CASES:
            if kind=='nowait':
                continue  # Sparse reader intentionally selects HEAD only.
            with self.subTest(reader=kind),self.assertRaises(subprocess.CalledProcessError):
                actual_reader(kind,kernel,'refs/heads/absent-revision')


if __name__=='__main__':
    unittest.main(verbosity=2)
