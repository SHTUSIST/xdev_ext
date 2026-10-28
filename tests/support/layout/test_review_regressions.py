#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Disposable concrete reproductions of independent adapter findings A1-A7."""
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tools/build'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_adapter import Adapter
import layout
import run as runner
import prepare_sources
import prepare_host_component


class ReviewRegressions(Adapter):
    def test_a1_metadata_links_never_write_through(self):
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                view = layout.materialize_view(self.repo)
                canonical = self.repo / 'third_party/sources.lock.json'
                before = canonical.read_bytes()
                target = view.root / 'sources.lock.json'
                target.unlink()
                (os.symlink if kind == 'symlink' else os.link)(canonical, target)
                try:
                    layout.materialize_view(self.repo)
                except layout.LayoutError:
                    pass  # Rejection or safe replacement both protect the source.
                observed = canonical.read_bytes()
                target.unlink()
                canonical.write_bytes(before)
                layout.materialize_view(self.repo)
                self.assertEqual(observed, before)

    def test_a1_marker_hardlink_does_not_modify_its_other_name(self):
        view = layout.materialize_view(self.repo)
        marker = view.root / 'view.json'
        other = self.repo / 'saved-marker.json'
        other.write_bytes(marker.read_bytes())
        before = other.read_bytes()
        marker.unlink()
        os.link(other, marker)
        self.write('src/core/body.c', 'new dirty source\n')
        try:
            layout.materialize_view(self.repo)
        except layout.LayoutError:
            pass
        self.assertEqual(other.read_bytes(), before)

    def test_a2_equal_hardlink_is_replaced_or_rejected(self):
        view = layout.materialize_view(self.repo)
        canonical = self.repo / 'src/core/body.c'
        target = view.kernel / 'io_uring/body.c'
        target.unlink()
        os.link(canonical, target)
        try:
            layout.materialize_view(self.repo)
        except layout.LayoutError:
            return
        target.write_text('mutation after refresh\n')
        self.assertEqual(canonical.read_text(), 'canonical body\n')

    def test_a3_nvidia_inputs_come_from_immutable_git_pin(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        upstream = Path(tmp.name)
        for argv in (('init', '-q'), ('config', 'user.name', 'Fixture'),
                     ('config', 'user.email', 'fixture@example.invalid')):
            subprocess.run(['git', '-C', str(upstream), *argv], check=True)
        for name in prepare_sources.REQUIRED['nvidia'] + ('upstream.h',):
            p = upstream / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('official ' + name + '\n')
        subprocess.run(['git', '-C', str(upstream), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(upstream), 'commit', '-qm', 'official'], check=True)
        commit = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD']).decode().strip()
        ref = subprocess.check_output(['git', '-C', str(upstream), 'symbolic-ref', 'HEAD']).decode().strip()
        lock = json.loads((self.repo / 'third_party/sources.lock.json').read_text())
        lock['components']['nvidia'] = dict(url=upstream.as_uri(), ref=ref, commit=commit)
        self.write('third_party/sources.lock.json', json.dumps(lock))
        prepare_sources.prepare(self.repo, 'nvidia', self.repo / 'build/upstream')
        assembled = self.repo / 'build/assembled/nvidia'
        (assembled / 'upstream.h').write_text('poisoned assembled input\n')
        (assembled / 'injected.h').write_text('not in pinned Git tree\n')
        prepare_host_component.prepare(self.repo)
        view = self.repo / 'build/source-view'
        self.assertEqual((view / 'gpu/upstream.h').read_text(), 'official upstream.h\n')
        self.assertFalse((view / 'gpu/injected.h').exists())
        (view / 'gpu/upstream.h').write_text('later poison\n')
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo)
        (view / 'gpu/upstream.h').write_text('official upstream.h\n')
        (view / 'gpu/upstream.h').chmod(0o755)
        with self.assertRaises(layout.LayoutError):
            layout.materialize_view(self.repo)

    def test_a4_runner_honors_bash_shebang_and_exit_status(self):
        self.write('tests/core/bash.sh', '#!/usr/bin/env bash\nset -euo pipefail\n[[ -n "$BASH_VERSION" ]]\nexit 23\n')
        (self.repo / 'tests/core/bash.sh').chmod(0o755)
        self.files.append(dict(source='tests/core/bash.sh', logical_path='tests/bash.sh'))
        self.manifest()
        self.assertEqual(runner.main(['--root', str(self.repo), 'tests/core/bash.sh']), 23)

    def product_sha(self, archive):
        script = ROOT / 'tests/benchmarks/hft/hardware_build.py'
        tree = ast.parse(script.read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'product_sha')
        scope = dict(_LAYOUT=layout, HERE=archive / 'tests/eval/hft', ROOT=archive,
                     subprocess=subprocess, Path=Path, re=re)
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(script), 'exec'), scope)
        return scope['product_sha']()

    def test_a5_archive_provenance_is_unknown_outside_or_inside_unrelated_git(self):
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory() as tmp:
                parent = Path(tmp)
                if nested:
                    subprocess.run(['git', '-C', str(parent), 'init', '-q'], check=True)
                    subprocess.run(['git', '-C', str(parent), '-c', 'user.name=Fixture', '-c',
                                    'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'unrelated'], check=True)
                archive = parent / 'archive'
                (archive / 'tests/eval/hft').mkdir(parents=True)
                (archive / 'source-layout.json').write_text(json.dumps(dict(schema=1, files=[])))
                self.assertIsNone(self.product_sha(archive))

    def test_hft_genuine_checkout_provenance_is_retained(self):
        self.assertEqual(self.product_sha(self.repo), self.git('rev-parse', 'HEAD').decode().strip())

    def test_registered_dma_revision_branch_selects_native_git_root(self):
        from types import SimpleNamespace
        script = ROOT / 'tests/compute/nvidia/nv_xdev_ext_registered_dma_test.py'
        tree = ast.parse(script.read_text())
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
                      and isinstance(n.test, ast.Name) and n.test.id == 'revision')
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                native = root / 'gpu' if nested else root
                relative = 'kernel-open/nvidia/nv-p2p.c'
                target = native / relative
                target.parent.mkdir(parents=True)
                target.write_text('requested registered DMA snapshot\n')
                if nested:
                    decoy = root / relative
                    decoy.parent.mkdir(parents=True)
                    decoy.write_text('root decoy\n')
                for args in (('init', '-q'), ('config', 'user.name', 'Fixture'),
                             ('config', 'user.email', 'fixture@example.invalid'), ('add', '.'),
                             ('commit', '-qm', 'native source')):
                    subprocess.run(['git', '-C', str(root), *args], check=True)
                revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
                target.write_text('dirty current bytes\n')
                scope = dict(revision=revision, source='must be replaced', Path=Path,
                             ex=SimpleNamespace(GPU=native, REPO=root), subprocess=subprocess,
                             __file__=str(script))
                exec(compile(ast.Module(body=[branch], type_ignores=[]), str(script), 'exec'), scope)
                self.assertEqual(scope['source'], 'requested registered DMA snapshot\n')
                scope['revision'] = 'refs/heads/missing'
                with self.assertRaises(layout.LayoutError):
                    exec(compile(ast.Module(body=[branch], type_ignores=[]), str(script), 'exec'), scope)

    def test_actual_kernel_reader_helper_branches_use_canonical_revision(self):
        import argparse
        cases = {
            'peer': ('tests/integration/peer_graph/independent_admission.py', 'io_uring/xdev_ext_mech_step.h'),
            'socket': ('tests/network/socket/runtime/independent_class7_admission.py', 'io_uring/xdev_ext_mech_core.h'),
            'fork': ('tests/core/frontend/independent_mech_fork_teardown.py', 'tools/io_uring_unified_preload.c'),
            'nowait': ('tests/storage/nvme/xdev_ext_mech_nvme_nowait_test.py', 'drivers/nvme/host/xdev_ext_mech_nvme.c'),
            'provider': ('tests/core/provider/faults/run.py', 'io_uring/xdev_ext_mech_dma.c'),
        }
        self.files = []
        for kind, (_, native) in cases.items():
            source = 'src/core/' + kind + '.c'
            self.files.append(dict(source=source, component='linux', native_path=native))
            self.write(source, 'committed ' + kind + '\n')
        self.manifest()
        revision = self.commit()
        for kind, (scriptname, native) in cases.items():
            with self.subTest(reader=kind):
                self.write('src/core/' + kind + '.c', 'dirty ' + kind + '\n')
                tree = ast.parse((ROOT / scriptname).read_text())
                fixture_script = self.repo / 'tests/reader.py'
                scope = dict(_LAYOUT=layout, Path=Path, __file__=str(fixture_script),
                             HERE=fixture_script.parent, KERNEL=self.repo, ROOT=self.repo,
                             TEST_REVISION=revision, REF=revision, filename=native, name=native, RELATIVE_SOURCE=native,
                             args=argparse.Namespace(revision=revision),
                             a=argparse.Namespace(revision=revision), os=os, subprocess=subprocess)
                if kind == 'provider':
                    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'source')
                    exec(compile(ast.Module(body=[function], type_ignores=[]), scriptname, 'exec'), scope)
                    actual = scope['source'](native)
                elif kind == 'peer':
                    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call)
                                and isinstance(n.func, ast.Attribute) and n.func.attr == 'write_bytes')
                    actual = eval(compile(ast.Expression(call.args[0]), scriptname, 'eval'), scope).decode()
                else:
                    variable = {'socket': 'data', 'fork': 'preload', 'nowait': 'source'}[kind]
                    assignments = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                                   and any(isinstance(t, ast.Name) and t.id == variable for t in n.targets)]
                    assignment = next(n for n in assignments if any(isinstance(v, ast.Attribute) and v.attr == 'read_native'
                                                                   for v in ast.walk(n.value)))
                    actual = eval(compile(ast.Expression(assignment.value), scriptname, 'eval'), scope)
                    if isinstance(actual, bytes):
                        actual = actual.decode()
                expected = ('dirty ' if kind == 'nowait' else 'committed ') + kind + '\n'
                self.assertEqual(actual, expected)

    def test_actual_gpu_reader_helper_branch_uses_canonical_revision(self):
        import argparse
        native = 'src/nvidia/fence.c'
        self.files.append(dict(source='src/compute/fence.c', component='nvidia', native_path=native))
        self.write('src/compute/fence.c', 'committed GPU fence\n')
        self.manifest()
        revision = self.commit()
        self.write('src/compute/fence.c', 'dirty GPU fence\n')
        script = ROOT / 'tests/compute/nvidia/nv_xdev_ext_ce_fence_algorithm_test.py'
        tree = ast.parse(script.read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        reader = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'read')
        scope = dict(_LAYOUT=layout, args=argparse.Namespace(repo=self.repo, revision=revision))
        exec(compile(ast.Module(body=[reader], type_ignores=[]), str(script), 'exec'), scope)
        self.assertEqual(scope['read'](native), 'committed GPU fence\n')

    def test_a6_reject_unstable_authored_directories(self):
        for name in ('tests/20261028/probe.py', 'tests/session-2026-10-28/probe.py',
                     'tests/Review Session/probe.py'):
            with self.subTest(name=name), self.assertRaises(layout.LayoutError):
                layout.Layout(self.repo, dict(schema=1, files=[dict(source=name, logical_path='tests/probe.py')]))

    def test_a7_dma_explicit_source_root_controls_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            external = Path(tmp)
            subprocess.run(['git', '-C', str(external), 'init', '-q'], check=True)
            subprocess.run(['git', '-C', str(external), '-c', 'user.name=Fixture', '-c',
                            'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'external'], check=True)
            commit = subprocess.check_output(['git', '-C', str(external), 'rev-parse', 'HEAD']).decode().strip()
            script = ROOT / 'tests/core/provider/faults/run.py'
            tree = ast.parse(script.read_text())
            assignment = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                              and any(isinstance(t, ast.Name) and t.id == 'ref' for t in n.targets))
            old = os.environ.get('KERNEL_SRC')
            os.environ['KERNEL_SRC'] = str(external)
            try:
                scope = dict(_LAYOUT=layout, HERE=self.repo, ROOT=external, REF=commit,
                             subprocess=subprocess, os=os)
                actual = eval(compile(ast.Expression(assignment.value), str(script), 'eval'), scope)
                self.assertEqual(actual, commit)
            finally:
                if old is None:
                    del os.environ['KERNEL_SRC']
                else:
                    os.environ['KERNEL_SRC'] = old


if __name__ == '__main__':
    unittest.main()
