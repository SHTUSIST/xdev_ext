#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent CONTRACT A tests: real source admission, no runtime/guest."""
import ast
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixture import (ARTIFACTS, E2, FENCE, HARNESS, HEADER, LOGICAL_HEADER,
                     PRODUCT, RUNNER, Fixture, command, extract_shell_function,
                     import_file, write, write_json)


class SourceCase(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.cleanup)

    def good(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def bad(self, result):
        self.assertNotEqual(result.returncode, 0, 'invalid source was admitted: ' + result.stdout)

    def same_identity(self, directory):
        identity = self.f.identity(directory)
        self.assertEqual(identity['canonical_root'], str(self.f.repo))
        self.assertEqual(identity['revision'], self.f.sha)
        self.assertRegex(identity['revision'], r'^[0-9a-f]{40}$')
        self.assertEqual(identity['lifecycle_header_sha256'], self.f.header_hash())

    def rejects_identity(self, directory):
        # Missing interface is an assertion failure, never a passing refusal.
        runner = import_file(directory / 'run.py')
        self.assertTrue(callable(getattr(runner, 'source_identity', None)), 'missing required source_identity interface')
        with self.assertRaises((ValueError, RuntimeError, OSError, KeyError, SystemExit, subprocess.CalledProcessError)):
            runner.source_identity(directory)


class BaselineControls(SourceCase):
    """These must pass before any missing A interface is interpreted as RED."""
    def test_real_preparation_default_and_external_assembly(self):
        for selected in (self.f.repo, self.f.native):
            with self.subTest(selected=selected):
                result, values = self.f.gate(selected)
                self.good(result)
                self.assertEqual(values['SOURCE_GIT_ROOT'], str(self.f.repo))
                self.assertEqual(values['SOURCE_COMMIT'], self.f.sha)
                self.assertEqual(values['SRC'], str(self.f.native))
        foreign, foreign_sha = self.f.foreign_parent()
        native = foreign / 'native'
        self.f.prepare(native)
        result, values = self.f.gate(native)
        self.good(result)
        self.assertNotEqual(values['SOURCE_COMMIT'], foreign_sha)
        self.assertEqual(values['SOURCE_COMMIT'], self.f.sha)
        self.assertEqual(values['SRC'], str(native))

    def test_dirty_and_untracked_canonical_refused_without_view_creation(self):
        for path in (self.f.repo / HEADER, self.f.repo / 'untracked.txt'):
            with self.subTest(path=path):
                old = path.read_bytes() if path.exists() else None
                write(path, 'private mutation\n')
                result, _ = self.f.gate(e2=True)
                self.bad(result)
                self.assertIn('dirty or untracked', result.stderr)
                self.assertFalse(self.f.view.exists())
                path.unlink() if old is None else path.write_bytes(old)

    def test_wrong_assembly_owner_output_or_overlay_refused(self):
        receipt_path = self.f.native / '.xdev-ext-source.json'
        original = receipt_path.read_bytes()
        for key, value in (('canonical_root', str(self.f.root)), ('output', str(self.f.root / 'wrong-output'))):
            receipt = json.loads(original)
            receipt[key] = value
            write_json(receipt_path, receipt)
            result, _ = self.f.gate(self.f.native)
            self.bad(result)
            self.assertFalse(self.f.view.exists())
            receipt_path.write_bytes(original)
        write(self.f.native / 'io_uring/xdev_ext_mech_lifecycle.h', 'wrong actual native bytes\n')
        result, _ = self.f.gate(fence=True)
        self.bad(result)
        self.assertIn('overlay differs', result.stderr)
        self.assertFalse(self.f.view.exists())

    def test_symlink_source_and_plain_logical_native_refused(self):
        alias = self.f.root / 'source-alias'
        alias.symlink_to(self.f.repo, target_is_directory=True)
        self.bad(self.f.gate(alias)[0])
        view = self.f.materialize()
        self.bad(self.f.gate(view)[0])

    def test_real_logical_view_support_relative_make_dependencies(self):
        view = self.f.materialize()
        result = command(['make', '-n', '-C', view / E2, 'sink', 'ctl'])
        self.good(result)
        self.assertIn('mv_ctl.c', result.stdout)
        self.assertIn('xdev_ext_session.c', result.stdout)
        result = command(['make', '-n', '-C', view / E2 / 'tests', 'check'])
        self.good(result)
        self.assertIn('reverse', result.stdout)
        self.assertIn('gray', result.stdout)
        self.assertFalse((self.f.repo / 'kernel').exists())
        self.assertFalse((self.f.repo / 'tests/eval').exists())

    def test_protected_runner_oracle_segments_unchanged(self):
        source = (PRODUCT / RUNNER).read_text()
        tree = ast.parse(source)
        expected = {'admit_environment': 'cf4da82692b8d51e9d597f13895b608ba80436a04963ec107d3219e185223c39', 'validate_result': '02a86efb339cba46b183be5d91839b591bb599b13f21cc6f7ebb0680b1ca75da'}
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in expected:
                segment = ast.get_source_segment(source, node).encode()
                self.assertEqual(hashlib.sha256(segment).hexdigest(), expected.pop(node.name))
        self.assertEqual(expected, {})
        self.assertEqual(hashlib.sha256((PRODUCT / 'tests/benchmarks/dmabuf_lifecycle/lifecycle_core.h').read_bytes()).hexdigest(), '96f9436600a43976fd51cdaca2c1f4012ad05f23d4a7193777fd00f6fab872f5')


class GateContract(SourceCase):
    def assert_support(self, selected, e2=False, fence=False):
        result, values = self.f.gate(selected, e2=e2, fence=fence)
        self.good(result)
        self.assertEqual(values['SOURCE_SUPPORT_VIEW'], str(self.f.view), 'selected support needs checked logical view')
        self.assertEqual(values['SOURCE_GIT_ROOT'], str(self.f.repo))
        self.assertEqual(values['SOURCE_COMMIT'], self.f.sha)
        self.assertEqual(values['SRC'], str(self.f.native if selected == self.f.repo else selected))
        self.assertEqual(values['E2_SOURCE'], str(self.f.view / E2) if e2 else '')
        self.assertEqual(values['FENCE_OUT'], str(self.f.view / FENCE) if fence else '')
        self.assertEqual(values['LIFECYCLE_HEADER_SOURCE'], str(self.f.repo / HEADER) if fence else '')
        self.assertEqual(values['LIFECYCLE_HEADER_COPY'], str(self.f.view / LOGICAL_HEADER) if fence else '')
        receipt = json.loads((self.f.view / 'view.json').read_text())
        self.assertEqual(receipt['canonical_root'], str(self.f.repo))
        self.assertEqual(receipt['revision'], self.f.sha)
        self.assertEqual(receipt['source_origins'], self.f.by_logical)
        for logical, source in self.f.by_logical.items():
            copy, original = self.f.view / logical, self.f.repo / source
            self.assertTrue(copy.is_file())
            self.assertFalse(copy.is_symlink())
            self.assertEqual(copy.stat().st_nlink, 1)
            self.assertNotEqual((copy.stat().st_dev, copy.stat().st_ino), (original.stat().st_dev, original.stat().st_ino))
            self.assertEqual(copy.read_bytes(), original.read_bytes())
        self.assertFalse((self.f.repo / 'kernel').exists())
        self.assertFalse((self.f.repo / 'tests/eval').exists())

    def test_e2_default_canonical_support_paths_and_independent_copies(self):
        self.assert_support(self.f.repo, e2=True)

    def test_fence_registered_native_support_paths_and_header(self):
        self.assert_support(self.f.native, fence=True)

    def test_external_native_under_foreign_git_keeps_canonical_support(self):
        foreign, _ = self.f.foreign_parent()
        native = foreign / 'native'
        self.f.prepare(native)
        self.assert_support(native, e2=True)

    def test_unselected_support_variables_empty(self):
        result, values = self.f.gate()
        self.good(result)
        for key in ('SOURCE_SUPPORT_VIEW', 'E2_SOURCE', 'FENCE_OUT', 'LIFECYCLE_HEADER_SOURCE', 'LIFECYCLE_HEADER_COPY'):
            self.assertEqual(values[key], '')
        self.assertFalse(self.f.view.exists())

    def test_missing_mapped_support_cannot_admit(self):
        manifest = dict(self.f.manifest, files=[e for e in self.f.entries if e['source'] != 'tests/benchmarks/mechanism_variants/Makefile'])
        write_json(self.f.repo / 'source-layout.json', manifest)
        self.f.sha = self.f.commit(self.f.repo)
        self.bad(self.f.gate(e2=True)[0])
        self.assertFalse(self.f.view.exists())

    def test_run_only_good_view_is_accepted_without_refresh(self):
        self.f.materialize()
        receipt = self.f.view / 'view.json'
        before = {p: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in (receipt, self.f.view / E2 / 'Makefile', self.f.view / LOGICAL_HEADER)}
        result, values = self.f.gate(e2=True, run_only=True)
        self.good(result)
        self.assertEqual(values['SOURCE_SUPPORT_VIEW'], str(self.f.view))
        self.assertEqual(values['E2_SOURCE'], str(self.f.view / E2))
        for path, expected in before.items():
            self.assertEqual((path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()), expected)

    def test_untracked_ignored_mapped_input_refused_even_when_status_clean(self):
        from fixture import checked
        source = self.f.repo / 'tests/benchmarks/mechanism_variants/Makefile'
        checked(['git', '-C', self.f.repo, 'rm', '--cached', str(source)])
        write(self.f.repo / '.gitignore', '/build/\n/tests/benchmarks/mechanism_variants/Makefile\n')
        checked(['git', '-C', self.f.repo, 'add', '.gitignore'])
        checked(['git', '-C', self.f.repo, 'commit', '-qm', 'private ignored missing membership'])
        self.assertEqual(checked(['git', '-C', self.f.repo, 'status', '--porcelain']), '')
        self.bad(self.f.gate(e2=True)[0])
        self.assertFalse(self.f.view.exists())

    def test_run_only_missing_view_never_materializes(self):
        result, _ = self.f.gate(e2=True, run_only=True)
        self.bad(result)
        self.assertFalse(self.f.view.exists())

    def test_run_only_missing_copy_never_restores(self):
        self.f.materialize()
        copy = self.f.view / E2 / 'Makefile'
        copy.unlink()
        self.bad(self.f.gate(e2=True, run_only=True)[0])
        self.assertFalse(copy.exists())

    def test_run_only_wrong_copy_never_repairs(self):
        self.f.materialize()
        copy = self.f.view / E2 / 'mv_ctl.c'
        wrong = b'/* wrong independently copied frontend */\n'
        copy.write_bytes(wrong)
        self.bad(self.f.gate(e2=True, run_only=True)[0])
        self.assertEqual(copy.read_bytes(), wrong)

    def test_run_only_wrong_header_never_repairs(self):
        self.f.materialize()
        copy = self.f.view / LOGICAL_HEADER
        wrong = b'/* wrong actually included lifecycle header */\n'
        copy.write_bytes(wrong)
        self.bad(self.f.gate(fence=True, run_only=True)[0])
        self.assertEqual(copy.read_bytes(), wrong)

    def test_run_only_receipt_authority_revision_origins_refused(self):
        self.f.materialize()
        receipt_path = self.f.view / 'view.json'
        original = receipt_path.read_bytes()
        for key, wrong in (('canonical_root', str(self.f.root)), ('revision', 'a' * 40), ('source_origins', {})):
            with self.subTest(key=key):
                value = json.loads(original)
                value[key] = wrong
                write_json(receipt_path, value)
                before = receipt_path.read_bytes()
                self.bad(self.f.gate(e2=True, run_only=True)[0])
                self.assertEqual(receipt_path.read_bytes(), before)
                receipt_path.write_bytes(original)

    def test_run_only_linked_support_copy_refused(self):
        self.f.materialize()
        copy = self.f.view / E2 / 'mv_ctl.c'
        original = self.f.repo / 'tests/benchmarks/mechanism_variants/mv_ctl.c'
        for kind in ('symlink', 'hardlink'):
            with self.subTest(kind=kind):
                copy.unlink()
                copy.symlink_to(original) if kind == 'symlink' else os.link(original, copy)
                self.bad(self.f.gate(e2=True, run_only=True)[0])
        copy.unlink()


class IdentityContract(SourceCase):
    def test_canonical_identity(self):
        self.same_identity(self.f.repo / Path(RUNNER).parent)

    def test_default_logical_identity(self):
        self.f.materialize()
        self.same_identity(self.f.view / FENCE)

    def test_external_logical_view_does_not_borrow_parent_git(self):
        foreign, foreign_sha = self.f.foreign_parent()
        view = self.f.materialize(foreign / 'checked-view')
        self.assertNotEqual(self.f.sha, foreign_sha)
        self.same_identity(view / FENCE)

    def test_source_only_queries_exact_stdout_and_ignore_environment_sha(self):
        self.f.materialize()
        for directory in (self.f.repo / Path(RUNNER).parent, self.f.view / FENCE):
            for field, expected in (('revision', self.f.sha), ('lifecycle_header_sha256', self.f.header_hash())):
                result = self.f.query(directory, field, {'XB_BUILD_SHA': 'a' * 40, 'XB_LIFE_HASH': 'b' * 64, 'SOURCE_COMMIT': 'c' * 40, 'SOURCE_GIT_ROOT': str(self.f.root)})
                self.good(result)
                self.assertEqual(result.stdout, expected + '\n')
                self.assertEqual(result.stderr, '')

    def test_identity_dirty_or_untracked_canonical_refused(self):
        directory = self.f.repo / Path(RUNNER).parent
        for path in (self.f.repo / HEADER, self.f.repo / 'foreign-untracked'):
            with self.subTest(path=path):
                old = path.read_bytes() if path.exists() else None
                write(path, 'dirty source\n')
                self.rejects_identity(directory)
                path.unlink() if old is None else path.write_bytes(old)

    def test_missing_header_mapping_refused(self):
        self.f.manifest['files'] = [e for e in self.f.entries if e['source'] != HEADER]
        write_json(self.f.repo / 'source-layout.json', self.f.manifest)
        self.f.sha = self.f.commit(self.f.repo)
        self.rejects_identity(self.f.repo / Path(RUNNER).parent)

    def test_missing_canonical_header_cannot_fall_back_to_head(self):
        (self.f.repo / HEADER).unlink()
        self.rejects_identity(self.f.repo / Path(RUNNER).parent)

    def test_untracked_mapped_header_cannot_borrow_committed_bytes(self):
        # Remove only index membership, retain bytes, and commit the deletion.
        from fixture import checked
        checked(['git', '-C', self.f.repo, 'rm', '--cached', HEADER])
        write(self.f.repo / '.gitignore', '/build/\n/' + HEADER + '\n')
        checked(['git', '-C', self.f.repo, 'add', '.gitignore'])
        checked(['git', '-C', self.f.repo, 'commit', '-qm', 'private missing membership'])
        self.assertEqual(checked(['git', '-C', self.f.repo, 'status', '--porcelain']), '')
        self.rejects_identity(self.f.repo / Path(RUNNER).parent)

    def test_logical_actual_header_wrong_missing_or_linked_refused(self):
        self.f.materialize()
        copy = self.f.view / LOGICAL_HEADER
        original = self.f.repo / HEADER
        for kind in ('wrong', 'missing', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                if copy.exists() or copy.is_symlink():
                    copy.unlink()
                if kind == 'wrong':
                    write(copy, 'wrong actually included header\n')
                elif kind == 'symlink':
                    copy.symlink_to(original)
                elif kind == 'hardlink':
                    os.link(original, copy)
                self.rejects_identity(self.f.view / FENCE)
        copy.unlink()

    def test_view_receipt_wrong_root_revision_or_origins_refused(self):
        self.f.materialize()
        path = self.f.view / 'view.json'
        original = path.read_bytes()
        for key, value in (('canonical_root', str(self.f.root)), ('revision', 'f' * 40), ('source_origins', {})):
            with self.subTest(key=key):
                receipt = json.loads(original)
                receipt[key] = value
                write_json(path, receipt)
                self.rejects_identity(self.f.view / FENCE)
                path.write_bytes(original)

    def test_foreign_copy_without_own_git_cannot_borrow_enclosing_git(self):
        foreign, _ = self.f.foreign_parent()
        impostor = foreign / 'impostor'
        import shutil
        shutil.copytree(self.f.repo, impostor, ignore=shutil.ignore_patterns('.git', 'build'))
        self.rejects_identity(impostor / Path(RUNNER).parent)

    def test_query_wrong_actual_header_fails_without_repair(self):
        self.f.materialize()
        copy = self.f.view / LOGICAL_HEADER
        copy.write_bytes(b'wrong header\n')
        result = self.f.query(self.f.view / FENCE, 'lifecycle_header_sha256')
        self.bad(result)
        self.assertEqual(copy.read_bytes(), b'wrong header\n')


class BuildAndManifestContract(SourceCase):
    def kbuild(self, directory, extra=()):
        # Include actual Kbuild in a harmless query-only GNU make driver.
        driver = self.f.root / 'identity-query.mk'
        write(driver, 'src := ' + str(directory) + '\nobj := ' + str(directory) + '\ninclude ' + str(directory / 'Kbuild') + '\n.PHONY: show\nshow:\n\t@printf \'%s\\n\' $(ccflags-y)\n')
        return command(['make', '--no-print-directory', '-f', driver, 'show', *extra])

    def test_kbuild_identity_from_actual_external_view_and_override_refusal(self):
        foreign, foreign_sha = self.f.foreign_parent()
        view = self.f.materialize(foreign / 'view')
        result = self.kbuild(view / FENCE, ('XB_BUILD_SHA=' + 'a' * 40, 'XB_LIFE_HASH=' + 'b' * 64))
        self.good(result)
        self.assertIn(self.f.sha, result.stdout)
        self.assertIn(self.f.header_hash(), result.stdout)
        self.assertNotIn(foreign_sha, result.stdout)
        self.assertNotIn('a' * 40, result.stdout)
        self.assertNotIn('b' * 64, result.stdout)

    def test_kbuild_query_error_or_empty_identity_refused(self):
        self.f.materialize()
        runner = self.f.view / FENCE / 'run.py'
        # This adversarial fixture tests the downstream Kbuild boundary.
        for body in ('raise SystemExit(7)\n', 'raise SystemExit(0)\n'):
            with self.subTest(body=body):
                runner.write_text(body)
                self.bad(self.kbuild(self.f.view / FENCE))

    def test_kbuild_wrong_actual_header_refused(self):
        self.f.materialize()
        write(self.f.view / LOGICAL_HEADER, 'wrong include bytes\n')
        self.bad(self.kbuild(self.f.view / FENCE))

    def test_kbuild_object_depends_on_actual_runner_and_header(self):
        self.f.materialize()
        directory = self.f.view / FENCE
        driver = self.f.root / 'dependency-query.mk'
        write(driver, 'src := ' + str(directory) + '\nobj := ' + str(directory) + '\ninclude ' + str(directory / 'Kbuild') + '\n.PHONY: show\nshow:\n\t@true\n')
        result = command(['make', '-np', '--no-print-directory', '-f', driver, 'show'])
        self.good(result)
        dependencies = set()
        for line in result.stdout.splitlines():
            if ': ' not in line or line.startswith('#'):
                continue
            target, names = line.split(': ', 1)
            if any(t.endswith('/lifecycle_bench.o') or t == 'lifecycle_bench.o' for t in target.split()):
                dependencies.update((directory / name).resolve() for name in names.split() if name != '|')
        self.assertIn((directory / 'run.py').resolve(), dependencies, 'runner query must be an actual build dependency')
        self.assertIn((self.f.view / LOGICAL_HEADER).resolve(), dependencies, 'actual included header must be a build dependency')

    def record_manifest(self, build):
        variables = {'SOURCE_GIT_ROOT': self.f.repo, 'SOURCE_COMMIT': self.f.sha, 'SOURCE_SUPPORT_VIEW': self.f.view, 'SRC': self.f.native, 'E2_SOURCE': self.f.view / E2, 'BUILD': build}
        shell = 'set -euo pipefail\n' + '\n'.join(k + '=' + shlex.quote(str(v)) for k, v in variables.items()) + '\n'
        shell += extract_shell_function(PRODUCT / 'tests/benchmarks/mechanism_variants/kvm_mode.sh', 'e2_record_sources') + '\ne2_record_sources\n'
        return command(['bash', '-c', shell])

    def test_e2_manifest_refuses_wrong_actual_support_copy(self):
        self.f.materialize()
        build = self.f.root / 'build'
        build.mkdir()
        copy = self.f.view / E2 / 'mv_ctl.c'
        write(copy, '/* wrong actual frontend copy */\n')
        self.bad(self.record_manifest(build))
        self.assertEqual(copy.read_bytes(), b'/* wrong actual frontend copy */\n')

    def test_e2_manifest_refuses_missing_native_overlay(self):
        self.f.materialize()
        build = self.f.root / 'build'
        build.mkdir()
        (self.f.native / 'io_uring/xdev_ext_mech.c').unlink()
        self.bad(self.record_manifest(build))

    def test_e2_manifest_contains_canonical_actual_support_and_native_inputs(self):
        self.f.materialize()
        build = self.f.root / 'build'
        build.mkdir()
        result = self.record_manifest(build)
        self.good(result)
        manifest = build / 'xdev-ext-e2-sources.sha256'
        self.assertTrue(manifest.is_file())
        rows = {}
        for line in manifest.read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            name = name.lstrip('*')
            path = Path(name)
            self.assertTrue(path.is_absolute(), 'source path must have an unambiguous authority root: ' + name)
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())
            rows[path] = digest
        self.assertTrue(rows)
        required_logicals = {
            'kernel/io_uring/xdev_ext_mech.c', LOGICAL_HEADER, 'kernel/io_uring/extra_admission_input.h',
            'kernel/include/trace/events/xdev_ext.h', 'kernel/drivers/nvme/host/xdev_ext_mech_nvme.c',
            'kernel/net/xdp/xsk.c', 'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py',
            'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'}
        for logical, source in self.f.by_logical.items():
            if logical.startswith(E2 + '/') or logical in required_logicals:
                self.assertIn(self.f.repo / source, rows, 'canonical source omitted: ' + logical)
                if logical.startswith(E2 + '/'):
                    self.assertIn(self.f.view / logical, rows, 'actual support copy omitted: ' + logical)
                else:
                    self.assertIn(self.f.native / logical.removeprefix('kernel/'), rows, 'native consumed overlay omitted: ' + logical)


if __name__ == '__main__':
    unittest.main(verbosity=2)
