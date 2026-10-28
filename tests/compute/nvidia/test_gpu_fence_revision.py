# SPDX-License-Identifier: GPL-2.0-only
"""Actual fence-test source reader against standalone and nested Git trees."""
import argparse
import ast
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'gpu/tests/nv_xdev_ext_ce_fence_algorithm_test.py'


def git(root, *args):
    return subprocess.check_output(['git','-C',str(root),*args],text=True,stderr=subprocess.PIPE).strip()


def production_reader(repo, revision=None):
    # Execute the actual nested read() unchanged, without running the C
    # arithmetic campaign or mocking Git/path decisions.
    tree = ast.parse(SCRIPT.read_text())
    main = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='main')
    read = next(node for node in main.body if isinstance(node,ast.FunctionDef) and node.name=='read')
    scope={'args':argparse.Namespace(repo=repo,revision=revision),'subprocess':subprocess}
    exec(compile(ast.Module(body=[read],type_ignores=[]),str(SCRIPT),'exec'),scope)
    return scope['read']


class FenceRevisionTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='xdev-gpu-revision-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        git(self.root,'init','-q')
        git(self.root,'config','user.name','Selftest')
        git(self.root,'config','user.email','selftest@invalid')
        self.relative='src/fence_fixture.c'

    def checkout(self, nested):
        component=self.root/'gpu' if nested else self.root
        target=component/self.relative
        target.parent.mkdir(parents=True)
        target.write_text('committed GPU source\n')
        if nested:
            decoy=self.root/self.relative;decoy.parent.mkdir(parents=True)
            decoy.write_text('different repository-root source\n')
        git(self.root,'add','--',*(['gpu/'+self.relative,self.relative] if nested else [self.relative]))
        git(self.root,'commit','-qm','authoritative source')
        return component,target,git(self.root,'rev-parse','HEAD')

    def test_nested_explicit_revision_reads_gpu_path_not_root_decoy(self):
        component,target,revision=self.checkout(True)
        target.write_text('later worktree source\n')
        self.assertEqual(production_reader(component,revision)(self.relative),'committed GPU source\n')

    def test_nested_sparse_fallback_reads_head_gpu_path(self):
        component,target,_=self.checkout(True);target.unlink()
        self.assertEqual(production_reader(component)(self.relative),'committed GPU source\n')

    def test_standalone_explicit_revision(self):
        component,target,revision=self.checkout(False)
        target.write_text('later standalone source\n')
        self.assertEqual(production_reader(component,revision)(self.relative),'committed GPU source\n')

    def test_standalone_sparse_fallback(self):
        component,target,_=self.checkout(False);target.unlink()
        self.assertEqual(production_reader(component)(self.relative),'committed GPU source\n')

    def test_default_prefers_actual_local_source(self):
        component,target,_=self.checkout(True)
        target.write_text('current local edits\n')
        self.assertEqual(production_reader(component)(self.relative),'current local edits\n')
        gpu=SCRIPT.parent.parent
        actual='src/nvidia/src/kernel/gpu/mem_mgr/ce_utils.c'
        self.assertEqual(production_reader(gpu)(actual),(gpu/actual).read_text())

    def test_missing_historical_file_never_reads_current_or_root_decoy(self):
        component,_,revision=self.checkout(True)
        relative='src/current_only.c'
        target=component/relative;target.write_text('only current GPU tree\n')
        decoy=self.root/relative;decoy.write_text('only later root tree\n')
        git(self.root,'add','--','gpu/'+relative,relative)
        git(self.root,'commit','-qm','later files must not replace old revision')
        with self.assertRaises(subprocess.CalledProcessError):
            production_reader(component,revision)(relative)
        target.unlink()
        self.assertEqual(production_reader(component)(relative),'only current GPU tree\n')


if __name__=='__main__':
    unittest.main(verbosity=2)
