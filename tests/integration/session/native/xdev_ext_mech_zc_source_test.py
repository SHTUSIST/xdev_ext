#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise the actual harness source gate with real, private Git repositories."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'

def project_root():
    # Host views and full assemblies contain ordinary copies, not a Git root.
    # Follow their declared source owner before consulting canonical layout.
    for parent in HERE.parents:
        assembly = parent / '.xdev-ext-source.json'
        if assembly.is_file():
            candidate = Path(json.loads(assembly.read_text())['canonical_root'])
        elif (parent / 'source-layout.json').is_file() or (parent / 'view.json').is_file():
            candidate = parent
        else:
            continue
        sys.path.insert(0, str(candidate / 'tools'))
        from layout import canonical_root, provenance
        return Path(provenance(canonical_root(candidate))['canonical_root'])
    raise RuntimeError('source tests require a canonical checkout or declared native view')


PROJECT = project_root()
ANCHORS = ('net/xdp/xsk_xdev_ext_mech_zc_core.h',
           'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh',
           'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_wire.py',
           'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_validate.py')
REQUIRED = ('Makefile', 'Kconfig', 'scripts/Makefile.build', 'include/linux/types.h')
ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')


class SourceGate(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='xdev-source-gate-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)

    def git(self, root, *args):
        return subprocess.check_output(['git', '-C', str(root), *args],
                                       stderr=subprocess.STDOUT, text=True).strip()

    def write(self, root, name, data):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)

    def commit(self, root):
        self.git(root, 'add', '.')
        self.git(root, '-c', 'user.name=Selftest', '-c', 'user.email=selftest@invalid',
                 'commit', '-qm', 'source fixture')

    def checkout(self, canonical=False, prepare=True, guest=False):
        root = self.folder / ('project' if canonical else 'linux')
        root.mkdir()
        self.git(root, 'init', '-q')
        self.write(root, '.gitignore', '/build/\n')
        if not canonical:
            for relative in ANCHORS:
                original = HERE / Path(relative).name
                self.write(root, relative, original.read_bytes() if original.is_file()
                           else b'fixture source anchor\n')
            for relative in REQUIRED:
                self.write(root, relative, 'upstream fixture\n')
            self.commit(root)
            return root, root
        manifest = json.loads((PROJECT / 'source-layout.json').read_text())
        wanted = {
            *ANCHORS,
            'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_debug.py',
            'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_source_test.py',
            'tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/fanout_trace.py',
            'tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/fanout_trace_test.py',
            'tests/eval/native_trace/collector.py',
            'tests/eval/native_trace/cpu_sampling.py',
            'tests/eval/native_trace/timer_scope.py',
            'tests/eval/session_guest/Makefile',
        }
        files = [f for f in manifest['files']
                 if f.get('native_path', f.get('logical_path')) in wanted]
        if guest:
            # Keep the genuine guest/nested makefiles and every declared build
            # prerequisite. Unrelated device-driver sources are not exercised.
            files = [f for f in manifest['files'] if f['source'].startswith((
                'tests/integration/session/', 'tests/benchmarks/chains/',
                'tests/support/benchmarks/', 'src/cli/',
            )) or f['source'] in (
                'tests/benchmarks/nvme_gpu/session_nvme_ce.c',
                'tests/benchmarks/gpu_nic/session_gpu_nic.c',
            )]
        files += [dict(source=name, logical_path=name)
                  for name in ('tools/layout.py', 'tools/build/prepare_sources.py')]
        for entry in files:
            name = entry['source']
            self.write(root, name, (PROJECT / name).read_bytes())
        upstream = self.folder / 'upstream'
        upstream.mkdir()
        self.git(upstream, 'init', '-q')
        for relative in REQUIRED:
            self.write(upstream, relative, 'upstream fixture\n')
        self.commit(upstream)
        self.git(upstream, 'tag', 'fixture')
        spec = dict(url=upstream.as_uri(), ref='refs/tags/fixture',
                    commit=self.git(upstream, 'rev-parse', 'HEAD'))
        self.write(root, 'third_party/sources.lock.json',
                   json.dumps(dict(schema=2, components=dict(linux=spec))))
        self.write(root, 'source-layout.json', json.dumps(dict(schema=1, files=files)))
        self.commit(root)
        source = root / 'build/assembled/linux'
        if prepare:
            result = subprocess.run(['python3', str(root / 'tools/build/prepare_sources.py'),
                                     '--component', 'linux', '--cache', str(self.folder / 'cache')],
                                    env=ENV, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return root, source

    def gate(self, source, lifecycle=0, eval_session=0):
        script = HARNESS.read_text()
        block = script[script.index('SRC=${SOURCE_OVERRIDE:'):
                       script.index('# Use the same campaign geometry')]
        # The lifecycle support check must be included in this preflight block.
        body = ('set -euo pipefail\nSOURCE_OVERRIDE=$1\nSCRATCH=$2\n'
                'LIFECYCLE=$3\nEVAL_SESSION=$4\n' + block)
        body += ('printf "GATE_ROOT=%s\\nGATE_SHA=%s\\nGATE_LAYOUT=%s\\n'
                 'GATE_SOURCE=%s\\nGATE_COLLECTOR=%s\\nGATE_SESSION=%s\\n" '
                 '"${SOURCE_GIT_ROOT:-unset}" "${SOURCE_COMMIT:-unset}" '
                 '"${SOURCE_LAYOUT:-unset}" "$SRC" "${NATIVE_COLLECTOR:-unset}" '
                 '"${EVAL_SESSION_SOURCE:-unset}"\n')
        return subprocess.run(['bash', '-c', body, 'source-gate', str(source),
                               str(self.folder), str(lifecycle), str(eval_session)],
                              env=ENV, text=True, capture_output=True, timeout=20)

    def assert_gate(self, source, **modes):
        run = self.gate(source, **modes)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return run

    def test_standalone_kernel_checkout_and_worktree(self):
        root, source = self.checkout()
        self.assert_gate(source)
        worktree = self.folder / 'worktree'
        self.git(root, 'worktree', 'add', '--detach', str(worktree))
        self.assert_gate(worktree)

    def test_canonical_and_assembled_use_same_identity_and_support(self):
        root, source = self.checkout(True)
        for selected in (root, source):
            with self.subTest(source=selected):
                run = self.assert_gate(selected, lifecycle=1)
                self.assertIn('GATE_ROOT=' + str(root), run.stdout)
                self.assertIn('GATE_SHA=' + self.git(root, 'rev-parse', 'HEAD'), run.stdout)
                self.assertIn('GATE_SOURCE=' + str(source), run.stdout)
                self.assertIn('GATE_COLLECTOR=' + str(root / 'tests/support/evidence/native_trace/collector.py'), run.stdout)
                run = self.assert_gate(selected, eval_session=1)
                self.assertIn('GATE_SESSION=' + str(root / 'tests/integration/session'), run.stdout)
        for name, origin in json.loads((source / '.xdev-ext-source.json').read_text())['source_origins'].items():
            self.assertEqual((source / name).read_bytes(), (root / origin).read_bytes())
            self.assertFalse((source / name).is_symlink())
            self.assertNotEqual((source / name).stat().st_ino, (root / origin).stat().st_ino)

    def test_canonical_and_native_fanout_use_original_oracle(self):
        root, source = self.checkout(True)
        for script in (root / 'tests/integration/lifecycle/fanout_trace_test.py',
                       source / 'tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/fanout_trace_test.py'):
            with self.subTest(script=script):
                result = subprocess.run(['python3', '-I', str(script)], env=ENV,
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('Ran 25 tests', result.stderr)

    def test_canonical_guest_build_resolves_all_native_make_inputs(self):
        root, _ = self.checkout(True, prepare=False, guest=True)
        output = self.folder / 'guest-output'
        result = subprocess.run(['make', '-n', '-C', str(root / 'tests/integration/session'),
                                 'guest', 'GUEST_OUT=' + str(output), 'CC=gcc', 'CLANG=clang'],
                                env=ENV, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(str(output / 'chains/chain_bench'), result.stdout)
        self.assertIn(str(output / 'chains/chain_plan.bpf.o'), result.stdout)
        self.assertFalse(output.exists())

    def test_external_assembly_uses_receipt_not_enclosing_git(self):
        root, _ = self.checkout(True)
        native = self.folder / 'native'
        prepared = subprocess.run(['python3', str(root / 'tools/build/prepare_sources.py'),
                                   '--component', 'linux', '--output', str(native),
                                   '--cache', str(self.folder / 'cache'), '--offline'],
                                  env=ENV, capture_output=True, text=True, timeout=20)
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        self.assert_gate(native, lifecycle=1)
        script = native / 'tools/testing/selftests/xdev_ext_mech/lifecycle_runtime/fanout_trace_test.py'
        result = subprocess.run(['python3', '-I', str(script)], env=ENV,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_plain_native_view_does_not_borrow_parent_git_identity(self):
        root, _ = self.checkout(True)
        view = subprocess.run(['python3', str(root / 'tools/layout.py'), 'view', '--root', str(root)],
                              env=ENV, capture_output=True, text=True, timeout=20)
        self.assertEqual(view.returncode, 0, view.stdout + view.stderr)
        selected = Path(view.stdout.strip()) / 'kernel'
        run = self.gate(selected, lifecycle=1)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('registered full assembly', run.stdout + run.stderr)

    def record_external_source(self, foreign_parent=False):
        root, _ = self.checkout(True)
        parent = self.folder
        if foreign_parent:
            parent = self.folder / 'foreign'
            parent.mkdir()
            self.git(parent, 'init', '-q')
            self.write(parent, 'foreign-only', 'foreign committed input\n')
            self.commit(parent)
            self.write(parent, 'foreign-only', 'foreign dirty input\n')
            self.write(parent, 'foreign-untracked', 'foreign untracked input\n')
        native = parent / 'native'
        prepared = subprocess.run(['python3', str(root / 'tools/build/prepare_sources.py'),
                                   '--component', 'linux', '--output', str(native),
                                   '--cache', str(self.folder / 'cache'), '--offline'],
                                  env=ENV, capture_output=True, text=True, timeout=20)
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        evidence = self.folder / 'evidence'
        evidence.mkdir()
        script = HARNESS.read_text()
        gate = script[script.index('SRC=${SOURCE_OVERRIDE:'):
                      script.index('# Use the same campaign geometry')]
        marker = 'printf \'%s\\n\' "$SOURCE_COMMIT" >>"$EV/provenance.txt"\n'
        start = script.index(marker) + len(marker)
        record = script[start:script.index('if (( CE_SIM )); then', start)]
        body = ('set -euo pipefail\nSOURCE_OVERRIDE=$1\nSCRATCH=$2\n'
                'LIFECYCLE=1\nEVAL_SESSION=0\nEV=$3\n' + gate + '\n' + record)
        run = subprocess.run(['bash', '-c', body, 'source-record', str(native),
                              str(self.folder), str(evidence)], env=ENV,
                             capture_output=True, text=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual((evidence / 'source.patch').read_bytes(), b'')
        self.assertEqual((evidence / 'source-status.txt').read_bytes(), b'')
        hashes = (evidence / 'source-files.sha256').read_text().splitlines()
        # Exactly these four genuine native files, with no foreign Git inputs.
        # Accept absolute or native-relative names, but resolve every hash here.
        actual = {}
        for row in hashes:
            digest, name = row.split('  ', 1)
            path = Path(name)
            path = path if path.is_absolute() else native / path
            actual[path] = digest
        self.assertEqual(set(actual), {native / name for name in ANCHORS})
        for path, digest in actual.items():
            self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_external_recording_does_not_require_enclosing_git(self):
        self.record_external_source()

    def test_external_recording_does_not_read_foreign_parent_git(self):
        self.record_external_source(foreign_parent=True)

    def test_source_suite_entry_resolves_canonical_view_and_full_assembly(self):
        root, source = self.checkout(True)
        view = subprocess.run(['python3', str(root / 'tools/layout.py'), 'view', '--root', str(root)],
                              env=ENV, capture_output=True, text=True, timeout=20)
        self.assertEqual(view.returncode, 0, view.stdout + view.stderr)
        native_name = 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_source_test.py'
        canonical = root / 'tests/integration/session/native/xdev_ext_mech_zc_source_test.py'
        for entry in (canonical, Path(view.stdout.strip()) / 'kernel' / native_name,
                      source / native_name):
            with self.subTest(entry=entry):
                self.assertEqual(entry.read_bytes(), canonical.read_bytes())
                run = subprocess.run(['python3', '-I', str(entry),
                                      'SourceGate.test_canonical_and_assembled_use_same_identity_and_support'],
                                     env=ENV, capture_output=True, text=True, timeout=20)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_canonical_without_assembly_fails_with_prepare_hint(self):
        root, source = self.checkout(True, prepare=False)
        run = self.gate(root, lifecycle=1)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('prepare_sources.py', run.stdout + run.stderr)
        self.assertFalse(source.exists())

    def test_rejects_non_git_wrong_subdirectory_and_symlink(self):
        plain = self.folder / 'plain'
        plain.mkdir()
        self.assertNotEqual(self.gate(plain).returncode, 0)
        root, source = self.checkout(True)
        wrong = root / 'other'
        wrong.mkdir()
        self.assertNotEqual(self.gate(wrong).returncode, 0)
        link = self.folder / 'link'
        link.symlink_to(source, target_is_directory=True)
        self.assertNotEqual(self.gate(link).returncode, 0)

    def test_missing_and_tampered_receipt_fail_closed(self):
        root, source = self.checkout(True)
        marker = source / '.xdev-ext-source.json'
        original = marker.read_text()
        marker.unlink()
        self.assertNotEqual(self.gate(source).returncode, 0)
        for field, value in (('commit', '0' * 40), ('canonical_root', str(self.folder)),
                             ('output', str(root / 'other')), ('source_origins', {})):
            with self.subTest(field=field):
                receipt = json.loads(original)
                receipt[field] = value
                marker.write_text(json.dumps(receipt))
                self.assertNotEqual(self.gate(source).returncode, 0)

    def test_receipt_cannot_claim_unrelated_git_root(self):
        root, source = self.checkout(True)
        foreign = self.folder / 'foreign'
        foreign.mkdir()
        self.git(foreign, 'init', '-q')
        self.write(foreign, 'source-layout.json', (root / 'source-layout.json').read_bytes())
        self.commit(foreign)
        marker = source / '.xdev-ext-source.json'
        receipt = json.loads(marker.read_text())
        receipt['canonical_root'] = str(foreign)
        marker.write_text(json.dumps(receipt))
        self.assertNotEqual(self.gate(source).returncode, 0)

    def test_dirty_staged_and_untracked_inputs_fail_closed(self):
        root, source = self.checkout(True)
        path = root / 'third_party/sources.lock.json'
        original = path.read_text()
        path.write_text(original + '\n')
        self.assertNotEqual(self.gate(source).returncode, 0)
        self.git(root, 'add', str(path.relative_to(root)))
        self.assertNotEqual(self.gate(source).returncode, 0)
        self.git(root, 'reset', '--hard', 'HEAD')
        self.write(root, 'unexpected', 'untracked input\n')
        self.assertNotEqual(self.gate(source).returncode, 0)

    def test_untracked_ignored_support_is_not_accepted(self):
        root, source = self.checkout(True)
        name = 'tests/support/evidence/native_trace/collector.py'
        original = (root / name).read_bytes()
        self.git(root, 'rm', name)
        with (root / '.gitignore').open('a') as stream:
            stream.write('/' + name + '\n')
        self.commit(root)
        self.write(root, name, original)
        self.assertNotEqual(self.gate(source, lifecycle=1).returncode, 0)

    def test_assembled_modified_bytes_are_rejected(self):
        _, source = self.checkout(True)
        with (source / ANCHORS[0]).open('a') as stream:
            stream.write('modified assembly\n')
        self.assertNotEqual(self.gate(source).returncode, 0)

    def test_missing_tracked_anchor_is_rejected(self):
        root, source = self.checkout()
        self.git(root, 'rm', ANCHORS[0])
        self.commit(root)
        self.assertNotEqual(self.gate(source).returncode, 0)

    def run_only(self, stamp, lifecycle=False):
        root, source = self.checkout(True)
        if lifecycle:
            name = 'tests/support/evidence/native_trace/collector.py'
            self.git(root, 'rm', name)
            self.commit(root)
        scratch = Path('/tmp/xdev-ext-e2e.' + secrets.token_hex(8))
        scratch.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, scratch)
        record = scratch / 'build/xdev-ext-source.commit'
        if stamp is not None:
            record.parent.mkdir()
            record.write_text(stamp + '\n')
        command = ['bash', str(HARNESS), '--scratch', str(scratch), '--source', str(source)]
        command += ['--lifecycle'] if lifecycle else ['--run-only']
        run = subprocess.run(command, text=True, capture_output=True, timeout=20, env=ENV)
        return run, record

    def test_lifecycle_refuses_missing_collector_before_guest_setup(self):
        run, record = self.run_only(None, lifecycle=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertFalse(record.parent.exists())

    def test_run_only_never_creates_missing_source_stamp(self):
        run, record = self.run_only(None)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('run-only build identity missing', run.stdout + run.stderr)
        self.assertFalse(record.exists())

    def test_run_only_never_relabels_old_commit_as_project_sha(self):
        run, record = self.run_only('0' * 40)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('run-only source SHA mismatch', run.stdout + run.stderr)
        self.assertEqual(record.read_text(), '0' * 40 + '\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
