# SPDX-License-Identifier: GPL-2.0-only
"""Run actual kernel selftest readers against nested/standalone Git history."""
import argparse
import ast
from pathlib import Path
import subprocess
import tempfile
import unittest

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
    # Execute the actual if/else that chooses local versus HEAD in setUpClass.
    block=next(n for n in ast.walk(tree) if isinstance(n,ast.If)
               and isinstance(n.test,ast.Call) and isinstance(n.test.func,ast.Attribute)
               and n.test.func.attr=='is_file')
    scope.update(source_path=kernel/relative if revision is None else kernel/'explicitly-unavailable-source.c',
                 RELATIVE_SOURCE=relative)
    exec(compile(ast.Module(body=[block],type_ignores=[]),str(script),'exec'),scope)
    return scope['source'].encode()


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

    def test_invalid_revision_does_not_fall_back_to_head_or_worktree(self):
        kernel,_=self.checkout(True)
        for kind in CASES:
            if kind=='nowait':
                continue  # Sparse reader intentionally selects HEAD only.
            with self.subTest(reader=kind),self.assertRaises(subprocess.CalledProcessError):
                actual_reader(kind,kernel,'refs/heads/absent-revision')


if __name__=='__main__':
    unittest.main(verbosity=2)
