#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent B archive contract tests. Real files/children; no guest execution.

XDEV_ARCHIVE_PRODUCT or XDEV_EXT_CANONICAL_ROOT selects canonical production
inputs; otherwise existing view/assembly receipts locate the canonical owner.
Artifacts default to PRODUCT/build/archive-setup-tests; XDEV_ARCHIVE_ARTIFACTS
overrides that location. Missing implementation is SETUP2 rather than behavioral
evidence. Expected inputs precede the producer.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve()


def canonical_product(origin):
    """Find the existing canonical owner without borrowing enclosing Git."""
    origin = Path(origin).expanduser().resolve()
    start = origin.parent if origin.is_file() else origin
    for parent in (start, *start.parents):
        # A logical view contains copied layout metadata too: its receipt must
        # take precedence, so support helpers always come from canonical code.
        for filename, kind, schema in (('view.json', 'host-source-view', 1),
                                       ('.xdev-ext-source.json', 'full-assembly', 2)):
            marker = parent / filename
            if marker.exists() or marker.is_symlink():
                if not marker.is_file() or marker.is_symlink():
                    raise RuntimeError('SETUP2: invalid source ownership receipt: ' + str(marker))
                receipt = json.loads(marker.read_text())
                if receipt.get('kind') != kind or receipt.get('schema') != schema:
                    raise RuntimeError('SETUP2: unrecognized source ownership receipt: ' + str(marker))
                owner = Path(receipt['canonical_root'])
                if not owner.is_absolute():
                    raise RuntimeError('SETUP2: source receipt lacks an absolute canonical owner')
                owner = owner.resolve()
                if not (owner / 'source-layout.json').is_file() or (owner / 'view.json').exists():
                    raise RuntimeError('SETUP2: source receipt does not identify canonical layout metadata')
                return owner
        if (parent / 'source-layout.json').is_file():
            return parent
    raise RuntimeError('SETUP2: no canonical source-layout owner for ' + str(origin))


PRODUCT = canonical_product(os.environ.get('XDEV_ARCHIVE_PRODUCT') or
                            os.environ.get('XDEV_EXT_CANONICAL_ROOT') or HERE)
SUPPORT = PRODUCT / 'tests/integration/session/source_setup'
ARTIFACTS = Path(os.environ.get('XDEV_ARCHIVE_ARTIFACTS', PRODUCT / 'build/archive-setup-tests'))
os.environ['XDEV_SETUP_PRODUCT'] = str(PRODUCT)
os.environ['XDEV_SETUP_ARTIFACTS'] = str(ARTIFACTS)
sys.path.insert(0, str(SUPPORT))
from fixture import Fixture, write, write_json, import_file

HELPER = PRODUCT / 'tests/integration/session/native/xdev_ext_mech_zc_archive.py'
CHILD = SUPPORT / 'archive_recording_child.py'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}


class ArchiveContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority = Fixture()
        cls.authority.materialize()
        cls.archive = import_file(HELPER)

    @classmethod
    def tearDownClass(cls):
        cls.authority.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='archive-case-', dir=ARTIFACTS)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scratch = self.root / (self.root.name + '-live')
        self.scratch.mkdir(mode=0o700)
        self.case = self.scratch / 'acceptance/cases/first'
        self.source = self.authority.repo
        self.native = self.authority.native
        self.view = self.authority.view
        self.specification = self.root / 'recording.json'
        # This literal set covers every documented manifest cwd. Sources are
        # actual prepared native/mapped canonical/ordinary view files.
        self.rows = {
            'build/xdev-ext-artifacts.sha256': [
                ('build/arch/x86/boot/bzImage', str(self.scratch)),
                ('build/Module.symvers', str(self.scratch)),
                ('tools/actual-tool', str(self.scratch)),
                ('build/xdev-ext-eval-session-source.sha256', str(self.scratch)),
                ('build/xdev-ext-e2-sources.sha256', str(self.scratch)),
            ],
            'evidence/artifacts.sha256': [('source.raw', str(self.scratch)), ('compat.raw', str(self.scratch)), ('peer.raw', str(self.scratch))],
            'evidence/source-files.sha256': [('io_uring/xdev_ext_mech.c', str(self.native)), (str(self.source / 'src/core/io_uring/xdev_ext_mech_lifecycle.h'), ''), (str(self.view / 'kernel/io_uring/xdev_ext_mech_lifecycle.h'), '')],
            'build/xdev-ext-eval-session-source.sha256': [(str(self.native / 'net/xdp/xsk.c'), '')],
            'build/xdev-ext-e2-sources.sha256': [
                (str(self.source / 'source-layout.json'), ''),
                (str(self.source / 'third_party/sources.lock.json'), ''),
                (str(self.source / 'tests/benchmarks/dmabuf_lifecycle/run.py'), ''),
                (str(self.native / '.xdev-ext-source.json'), ''),
                (str(self.view / 'view.json'), ''),
                (str(self.view / 'tests/eval/dmabuf_lifecycle/run.py'), ''),
            ],
        }
        # Nested manifests are written before manifests that list them.
        ordered = {name: self.rows[name] for name in ('build/xdev-ext-eval-session-source.sha256', 'build/xdev-ext-e2-sources.sha256', 'build/xdev-ext-artifacts.sha256', 'evidence/artifacts.sha256', 'evidence/source-files.sha256')}
        write_json(self.specification, {'revision': self.authority.sha, 'manifests': ordered})

    def command(self, label='first', exit_code=0):
        return [sys.executable, '-B', str(CHILD), '--scratch', str(self.scratch), '--source', str(self.native), '--specification', str(self.specification), '--label', label, '--exit-code', str(exit_code)]

    def produce(self, label='first'):
        result = subprocess.run(self.command(label), text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_case(self, label='first', exit_code=0, case=None):
        return self.archive.run_command(self.command(label, exit_code), self.scratch, case or self.case, self.source, self.native)

    def cli(self, label='first', exit_code=0, case=None, command=None):
        argv = [sys.executable, '-B', str(HELPER), 'run', '--scratch', str(self.scratch), '--case-dir', str(case or self.case), '--source-root', str(self.source), '--native-root', str(self.native), '--', *(command or self.command(label, exit_code))]
        return subprocess.run(argv, text=True, capture_output=True, timeout=45)

    def freeze_produced(self):
        self.case.mkdir(mode=0o700, parents=True)
        self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
        self.archive.archive_case(self.scratch, self.case, self.source, self.native)

    def assert_archived_targets(self):
        mapping = json.loads((self.case / 'archived-artifacts.json').read_text())
        wanted = {}
        for rows in self.rows.values():
            for name, context in rows:
                original = Path(name) if Path(name).is_absolute() else Path(context) / name
                wanted[str(original)] = original.read_bytes()
        for original, expected in wanted.items():
            self.assertIn(original, mapping, 'listed manifest target was not frozen: ' + original)
            row = mapping[original]
            frozen = self.case / row['file']
            self.assertTrue(frozen.resolve().is_relative_to(self.case.resolve()))
            self.assertEqual(frozen.read_bytes(), expected, original)
            self.assertEqual(row['sha256'], hashlib.sha256(expected).hexdigest())
            self.assertEqual(row['expected_sha256'], row['sha256'])
            self.assertNotEqual(frozen.stat().st_ino, Path(original).stat().st_ino, original)
        return mapping

    def test_two_real_children_cannot_change_first_archive(self):
        """Break caught: copy evidence only, omit manifest sources, or link live."""
        receipt = self.run_case()
        self.assertEqual(receipt['command_exit'], 0)
        self.assert_archived_targets()
        frozen_before = snapshot(self.case)
        self.assertTrue(frozen_before)
        for name in ('source-before.raw', 'source.raw', 'destination-before.raw', 'destination.raw', 'expected.raw', 'compat.raw', 'peer.raw', 'initramfs.cpio.gz'):
            frozen = self.case / 'images' / name
            live = self.scratch / name
            self.assertEqual(frozen.read_bytes(), live.read_bytes())
            self.assertNotEqual(frozen.stat().st_ino, live.stat().st_ino)
        for name in ('.config', 'Module.symvers', 'xdev-ext-source.commit', 'xdev-ext-debug-profile.json', 'include/config/kernel.release'):
            self.assertEqual((self.case / 'build' / name).read_bytes(), (self.scratch / 'build' / name).read_bytes())
        for manifest in self.rows:
            original = (self.scratch / manifest).read_bytes()
            self.assertIn(original, frozen_before.values(), 'original manifest bytes missing: ' + manifest)
        self.run_case('second', case=self.scratch / 'acceptance/cases/second')
        # Overwrite every regular mutable live file including same-size rewrites.
        for base in ('build', 'tools', 'evidence'):
            for path in (self.scratch / base).rglob('*'):
                if path.is_file():
                    path.write_bytes(b'X' * max(1, path.stat().st_size))
        for path in self.scratch.glob('*.raw'):
            path.write_bytes(b'Y' * path.stat().st_size)
        self.assertEqual(snapshot(self.case), frozen_before)
        self.assertFalse(any(path.is_symlink() for path in self.case.rglob('*')))

    def test_receipt_records_actual_exact_argv_roots_log_exit_and_hashes(self):
        self.run_case()
        receipt = json.loads((self.case / 'receipt.json').read_text())
        self.assertEqual(receipt['command'], self.command())
        self.assertEqual(receipt['source_root'], str(self.source))
        self.assertEqual(receipt['native_root'], str(self.native))
        self.assertEqual(receipt['command_exit'], 0)
        self.assertEqual((self.case / 'command.exit').read_text(), '0\n')
        self.assertIn('RECORDING_CHILD label=first', (self.case / 'command.log').read_text())
        hashes = json.loads((self.case / 'archive-files.json').read_text())
        self.assertTrue(hashes)
        for name, expected in hashes.items():
            self.assertEqual(digest(self.case / name), expected)
        self.assertFalse(any(path.name in {'ALLOW', 'gate', 'PASS'} for path in self.case.rglob('*')))

    def test_child_exit_seven_freezes_exact_failure_then_cli_propagates_seven(self):
        result = self.cli(exit_code=7)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertEqual((self.case / 'command.exit').read_text(), '7\n')
        self.assertEqual(json.loads((self.case / 'receipt.json').read_text())['command_exit'], 7)
        self.assert_archived_targets()
        self.assertIn(b'archive-recording-only:first:', (self.case / 'images/source.raw').read_bytes())

    def test_python_api_returns_actual_failure_receipt(self):
        self.assertEqual(self.run_case(exit_code=7)['command_exit'], 7)
        self.assertEqual((self.case / 'command.exit').read_text(), '7\n')

    def test_duplicate_case_rejected_before_child_and_first_case_unchanged(self):
        self.run_case()
        before = snapshot(self.case)
        index = (self.scratch / 'recording-invocations.jsonl').read_bytes()
        result = self.cli('second')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(snapshot(self.case), before)
        self.assertEqual((self.scratch / 'recording-invocations.jsonl').read_bytes(), index)

    def test_case_directory_escape_rejected_before_child(self):
        result = self.cli(case=self.root / 'outside')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.scratch / 'recording-invocations.jsonl').exists())

    def test_symlink_case_parent_rejected_before_child(self):
        (self.root / 'external').mkdir()
        (self.scratch / 'acceptance').symlink_to(self.root / 'external', target_is_directory=True)
        result = self.cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.scratch / 'recording-invocations.jsonl').exists())

    def test_wrong_command_scratch_and_source_rejected_before_child(self):
        for flag in ('--scratch', '--source'):
            with self.subTest(flag=flag):
                command = self.command()
                command[command.index(flag) + 1] = str(self.root / 'foreign')
                result = self.cli(command=command)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.scratch / 'recording-invocations.jsonl').exists())

    def test_unrelated_prepared_native_authority_rejected_before_child(self):
        # A real unrelated assembly marker cannot be accepted by basename.
        foreign = self.root / 'foreign-native'
        foreign.mkdir()
        marker = json.loads((self.native / '.xdev-ext-source.json').read_text())
        marker['canonical_root'] = str(self.root / 'foreign-canonical')
        write_json(foreign / '.xdev-ext-source.json', marker)
        command = self.command()
        command[command.index('--source') + 1] = str(foreign)
        result = subprocess.run([sys.executable, '-B', str(HELPER), 'run', '--scratch', str(self.scratch), '--case-dir', str(self.case), '--source-root', str(self.source), '--native-root', str(foreign), '--', *command], capture_output=True, text=True, timeout=45)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.scratch / 'recording-invocations.jsonl').exists())

    def test_dirty_canonical_refuses_before_recording_child(self):
        untracked = self.source / 'untracked-archive-authority'
        write(untracked, 'cannot borrow a clean revision for dirty sources\n')
        try:
            result = self.cli()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.scratch / 'recording-launches.jsonl').exists())
        finally:
            untracked.unlink()

    def test_wrong_view_owner_cannot_authorize_manifest_targets(self):
        marker = self.view / 'view.json'
        before = marker.read_bytes()
        try:
            decision = json.loads(before)
            decision['canonical_root'] = str(self.root / 'foreign-canonical')
            write_json(marker, decision)
            self.produce()
            self.case.mkdir(mode=0o700, parents=True)
            self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
            with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
                self.archive.archive_case(self.scratch, self.case, self.source, self.native)
        finally:
            marker.write_bytes(before)

    def test_wrong_native_locked_upstream_refuses_before_recording_child(self):
        marker = self.native / '.xdev-ext-source.json'
        before = marker.read_bytes()
        try:
            decision = json.loads(before)
            # Existing full-assembly schema2 binds the locked upstream commit.
            decision['commit'] = '0' * 40
            write_json(marker, decision)
            result = self.cli()
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.scratch / 'recording-launches.jsonl').exists())
        finally:
            marker.write_bytes(before)

    def test_bad_manifest_inputs_are_hard_failures(self):
        for mutation in ('missing', 'hash', 'conflict', 'escape', 'foreign', 'symlink', 'parent-symlink'):
            with self.subTest(mutation=mutation):
                self.produce()
                manifest = self.scratch / 'evidence/artifacts.sha256'
                source = self.scratch / 'source.raw'
                if mutation == 'missing':
                    text = '0' * 64 + '  missing.raw\n'
                elif mutation == 'hash':
                    text = '0' * 64 + '  source.raw\n'
                elif mutation == 'conflict':
                    text = digest(source) + '  source.raw\n' + '0' * 64 + '  source.raw\n'
                elif mutation in ('escape', 'foreign'):
                    target = self.root / 'source.raw'
                    write(target, b'foreign same-name file\n')
                    name = '../source.raw' if mutation == 'escape' else str(target)
                    text = digest(target) + '  ' + name + '\n'
                else:
                    target = self.root / 'outside/source.raw'
                    write(target, b'symlink target\n')
                    if mutation == 'symlink':
                        (self.scratch / 'alias.raw').symlink_to(target)
                        name = 'alias.raw'
                    else:
                        (self.scratch / 'aliased-parent').symlink_to(target.parent, target_is_directory=True)
                        name = 'aliased-parent/source.raw'
                    text = digest(target) + '  ' + name + '\n'
                write(manifest, text)
                self.case = self.scratch / ('acceptance/cases/' + mutation)
                self.case.mkdir(mode=0o700, parents=True)
                self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
                with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
                    self.archive.archive_case(self.scratch, self.case, self.source, self.native)
                for alias in ('alias.raw', 'aliased-parent'):
                    (self.scratch / alias).unlink(missing_ok=True)

    def test_exact_checked_fence_module_is_frozen_as_build_artifact(self):
        """Break caught: refusing the actual mapped fence directory's output."""
        self.produce()
        module = self.view / 'tests/eval/dmabuf_lifecycle/lifecycle_bench.ko'
        self.assertFalse(module.exists())
        self.addCleanup(module.unlink, missing_ok=True)
        payload = b'opaque archive fixture for exact fence module output; never loaded\n'
        write(module, payload)
        for name in ('build/xdev-ext-artifacts.sha256', 'evidence/artifacts.sha256'):
            manifest = self.scratch / name
            manifest.write_text(manifest.read_text() + digest(module) + '  ' + str(module) + '\n')
        self.freeze_produced()
        mapping = json.loads((self.case / 'archived-artifacts.json').read_text())
        self.assertIn(str(module), mapping)
        row = mapping[str(module)]
        frozen = self.case / row['file']
        self.assertEqual(frozen.read_bytes(), payload)
        self.assertEqual(row['sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(row['expected_sha256'], row['sha256'])
        self.assertNotEqual(frozen.stat().st_ino, module.stat().st_ino)
        before = snapshot(self.case)
        module.write_bytes(b'next build overwrote the live module\n')
        self.assertEqual(snapshot(self.case), before)

    def test_generated_fence_module_is_not_source_manifest_identity(self):
        self.produce()
        module = self.view / 'tests/eval/dmabuf_lifecycle/lifecycle_bench.ko'
        self.assertFalse(module.exists())
        self.addCleanup(module.unlink, missing_ok=True)
        write(module, b'opaque generated artifact is not mapped source identity\n')
        for name in ('build/xdev-ext-artifacts.sha256', 'evidence/source-files.sha256'):
            manifest = self.scratch / name
            manifest.write_text(manifest.read_text() + digest(module) + '  ' + str(module) + '\n')
        self.case.mkdir(mode=0o700, parents=True)
        self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
        with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
            self.archive.archive_case(self.scratch, self.case, self.source, self.native)

    def test_unapproved_generated_outputs_are_not_arbitrary_view_authority(self):
        for index, name in enumerate(('foreign-view', 'unlisted-output', 'canonical-output')):
            with self.subTest(output=name):
                self.produce()
                paths = {
                    'foreign-view': self.root / 'foreign-view/tests/eval/dmabuf_lifecycle/lifecycle_bench.ko',
                    'unlisted-output': self.view / 'tests/eval/dmabuf_lifecycle/unlisted_bench.ko',
                    'canonical-output': self.source / 'tests/benchmarks/dmabuf_lifecycle/lifecycle_bench.ko',
                }
                module = paths[name]
                self.assertFalse(module.exists())
                write(module, b'opaque unapproved generated output\n')
                try:
                    manifest = self.scratch / 'build/xdev-ext-artifacts.sha256'
                    manifest.write_text(manifest.read_text() + digest(module) + '  ' + str(module) + '\n')
                    self.case = self.scratch / ('acceptance/cases/generated-negative-' + str(index))
                    self.case.mkdir(mode=0o700, parents=True)
                    self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
                    with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
                        self.archive.archive_case(self.scratch, self.case, self.source, self.native)
                finally:
                    module.unlink()

    def test_native_relative_sources_do_not_fall_back_to_scratch(self):
        self.produce()
        wrong = self.scratch / 'io_uring/xdev_ext_mech.c'
        write(wrong, b'wrong same-name scratch file\n')
        write(self.scratch / 'evidence/source-files.sha256', digest(wrong) + '  io_uring/xdev_ext_mech.c\n')
        self.case.mkdir(mode=0o700, parents=True)
        self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
        with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
            self.archive.archive_case(self.scratch, self.case, self.source, self.native)

    def test_same_byte_owned_manifest_symlink_is_rejected(self):
        self.produce()
        target = self.scratch / 'source.raw'
        alias = self.scratch / 'same-byte-alias.raw'
        alias.symlink_to(target)
        write(self.scratch / 'evidence/artifacts.sha256', digest(target) + '  same-byte-alias.raw\n')
        self.case.mkdir(mode=0o700, parents=True)
        self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
        with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
            self.archive.archive_case(self.scratch, self.case, self.source, self.native)

    def test_symlink_in_evidence_cannot_be_silently_dereferenced(self):
        self.produce()
        write(self.root / 'outside.log', 'foreign evidence\n')
        (self.scratch / 'evidence/foreign.log').symlink_to(self.root / 'outside.log')
        self.case.mkdir(mode=0o700, parents=True)
        self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
        with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
            self.archive.archive_case(self.scratch, self.case, self.source, self.native)

    def test_unreceipted_cache_alias_rejected(self):
        self.produce()
        shutil.move(self.scratch / 'tools', self.root / 'unapproved-tools')
        (self.scratch / 'tools').symlink_to(self.root / 'unapproved-tools', target_is_directory=True)
        self.case.mkdir(mode=0o700, parents=True)
        self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
        with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
            self.archive.archive_case(self.scratch, self.case, self.source, self.native)


    def test_archive_failure_is_nonzero_even_when_child_returns_zero(self):
        # Child writes a real malformed manifest after normal recording.
        command = self.command()
        wrapper = self.root / 'corrupt-child.py'
        write(wrapper, 'import subprocess,sys\nfrom pathlib import Path\nr=subprocess.run(sys.argv[1:]).returncode\nPath(' + repr(str(self.scratch / 'evidence/artifacts.sha256')) + ').write_text("malformed manifest\\n")\nsys.exit(r)\n')
        result = self.cli(command=[sys.executable, '-B', str(wrapper), *command])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.case / 'command.exit').read_text(), '0\n')
        self.assertNotIn('=PASS', result.stdout)
        self.assertNotIn('ALLOW', result.stdout)

    def test_duplicate_identical_manifest_target_may_share_frozen_store(self):
        self.produce()
        manifest = self.scratch / 'evidence/artifacts.sha256'
        manifest.write_text(manifest.read_text() + digest(self.scratch / 'source.raw') + '  source.raw\n')
        self.freeze_produced()
        mapping = self.assert_archived_targets()
        self.assertEqual(mapping[str(self.scratch / 'source.raw')]['sha256'], digest(self.scratch / 'source.raw'))

    def test_cache_receipt_foreign_roots_or_bad_mode_are_not_authority(self):
        self.produce()
        for name in ('build', 'tools'):
            shutil.move(self.scratch / name, self.root / ('unapproved-' + name))
            (self.scratch / name).symlink_to(self.root / ('unapproved-' + name), target_is_directory=True)
        receipt = self.scratch / 'cache-location.json'
        decision = dict(schema=1, decision='ALLOW_BUILD_TOOLS_CACHE_LOCATION', approved_by='root', root_approved=True,
                        verifiedcmp=True, source_scratch=str(self.scratch), cache_base=str(self.root),
                        cache_root=str(self.root), roots={name: str(self.root / ('unapproved-' + name)) for name in ('build', 'tools')}, method='independent rejection fixture')
        write_json(receipt, decision)
        receipt.chmod(0o600)
        self.case.mkdir(mode=0o700, parents=True)
        self.assertEqual(self.case.stat().st_mode & 0o777, 0o700)
        with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
            self.archive.archive_case(self.scratch, self.case, self.source, self.native)
        receipt.chmod(0o644)
        with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
            self.archive.archive_case(self.scratch, self.case, self.source, self.native)


    def test_exact_cache_receipt_archives_copies_from_two_owned_roots(self):
        self.produce()
        default = self.archive.SERVER_CACHE_BASE
        self.assertEqual(default, Path('/root/xdev_ext/build-cache'))
        base = self.root / 'isolated-cache-location-boundary'
        run = base / 'runs' / self.scratch.name
        for path in (base, base / 'runs', run):
            path.mkdir(mode=0o700)
        roots = {name: run / name for name in ('build', 'tools')}
        for name, destination in roots.items():
            shutil.move(self.scratch / name, destination)
            destination.chmod(0o700)
            (self.scratch / name).symlink_to(destination, target_is_directory=True)
        tools_owner_uid = roots['tools'].stat().st_uid

        def chown_tools(uid):
            # Only this private fixture directory crosses the privilege boundary.
            try:
                os.chown(roots['tools'], uid, -1)
            except PermissionError:
                if os.geteuid() == 0:
                    raise
                subprocess.run(['sudo', '-n', 'chown', '--', str(uid), str(roots['tools'])],
                               check=True, timeout=30)
            self.assertEqual(roots['tools'].stat().st_uid, uid)

        decision = dict(schema=1, decision='ALLOW_BUILD_TOOLS_CACHE_LOCATION', approved_by='root', root_approved=True,
                        verifiedcmp=True, source_scratch=str(self.scratch), cache_base=str(base),
                        cache_root=str(run), roots={name: str(path) for name, path in roots.items()},
                        method='test-only existing cache receipt location boundary; no production approval')
        receipt = self.scratch / 'cache-location.json'
        write_json(receipt, decision)
        receipt.chmod(0o600)
        # Root explicitly authorized replacing this filesystem-location constant
        # only. Existing receipt checks/copy/hash/ownership code remain real.
        with patch.object(self.archive, 'SERVER_CACHE_BASE', base):
            self.freeze_produced()
            mapping = json.loads((self.case / 'archived-artifacts.json').read_text())
            for original in (roots['build'] / 'arch/x86/boot/bzImage', roots['tools'] / 'actual-tool'):
                record = mapping[str(original)]
                frozen = self.case / record['file']
                self.assertEqual(frozen.read_bytes(), original.read_bytes())
                self.assertNotEqual(frozen.stat().st_ino, original.stat().st_ino)
            before = snapshot(self.case)
            (roots['build'] / 'arch/x86/boot/bzImage').write_bytes(b'changed live cached image\n')
            self.assertEqual(snapshot(self.case), before)
            # Rebuild the original live inputs so rejection depends on receipt.
            self.produce()
            for index, mutation in enumerate(('wrong-root', 'bad-receipt-mode', 'bad-directory-mode', 'foreign-directory-owner', 'wrong-alias', 'leaf-symlink')):
                with self.subTest(mutation=mutation):
                    changed = json.loads(json.dumps(decision))
                    if mutation == 'wrong-root':
                        changed['roots']['tools'] = str(base / 'foreign-tools')
                    write_json(receipt, changed)
                    receipt.chmod(0o644 if mutation == 'bad-receipt-mode' else 0o600)
                    if mutation == 'bad-directory-mode':
                        roots['tools'].chmod(0o755)
                    if mutation == 'wrong-alias':
                        (self.scratch / 'tools').unlink()
                        (self.scratch / 'tools').symlink_to(roots['build'], target_is_directory=True)
                    leaf = roots['build'] / 'arch/x86/boot/bzImage'
                    saved = leaf.read_bytes()
                    if mutation == 'leaf-symlink':
                        leaf.unlink()
                        write(roots['tools'] / 'same-byte-image', saved)
                        leaf.symlink_to(roots['tools'] / 'same-byte-image')
                    failed_case = self.scratch / ('acceptance/cases/cache-negative-' + str(index))
                    failed_case.mkdir(mode=0o700, parents=True)
                    self.assertEqual(failed_case.stat().st_mode & 0o777, 0o700)
                    try:
                        if mutation == 'foreign-directory-owner':
                            chown_tools(65534)
                        with self.assertRaises((ValueError, OSError, RuntimeError, subprocess.SubprocessError)):
                            self.archive.archive_case(self.scratch, failed_case, self.source, self.native)
                    finally:
                        if mutation == 'foreign-directory-owner':
                            chown_tools(tools_owner_uid)
                        receipt.chmod(0o600)
                        roots['tools'].chmod(0o700)
                        if mutation == 'wrong-alias':
                            (self.scratch / 'tools').unlink()
                            (self.scratch / 'tools').symlink_to(roots['tools'], target_is_directory=True)
                        if mutation == 'leaf-symlink':
                            leaf.unlink()
                            leaf.write_bytes(saved)
        self.assertEqual(self.archive.SERVER_CACHE_BASE, default)


class WrapperContract(unittest.TestCase):
    """Actual public wrappers + real child/file/archive boundaries, no guest."""
    setUp = ArchiveContract.setUp

    @classmethod
    def setUpClass(cls):
        cls.authority = Fixture()
        cls.archive = import_file(HELPER) if HELPER.is_file() else None
        # Bind the recording *external command boundary* into an actual clean
        # temporary canonical commit and prepared native receipt. This is not
        # a source-provenance stub: prepare/layout checks remain unmodified.
        source = cls.authority.repo
        harness = source / 'tests/integration/session/native/xdev_ext_mech_zc_kvm.sh'
        write(harness, '#!/usr/bin/env bash\nexec ' + shlex.quote(sys.executable) + ' -B ' + shlex.quote(str(SUPPORT / 'archive_recording_harness.py')) + ' "$@"\n')
        manifest = cls.authority.manifest
        helper_source = 'tests/integration/session/native/xdev_ext_mech_zc_archive.py'
        if HELPER.is_file():
            shutil.copyfile(HELPER, source / helper_source)
        if HELPER.is_file() and helper_source not in {row['source'] for row in manifest['files']}:
            manifest['files'].append(dict(source=helper_source, component='linux', native_path='tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_archive.py'))
        write_json(source / 'source-layout.json', manifest)
        cls.authority.sha = Fixture.commit(source)
        cls.authority.native = source / 'build/recording-assembled/linux'
        cls.authority.prepare(cls.authority.native)
        cls.authority.materialize()

    @classmethod
    def tearDownClass(cls):
        cls.authority.cleanup()

    def configure(self, **changes):
        spec = json.loads(self.specification.read_text())
        spec.update(changes)
        write_json(self.specification, spec)

    def wrapper(self, name):
        path = PRODUCT / ('tests/integration/session/native/xdev_ext_mech_zc_matrix.sh' if name == 'network' else 'tests/core/policy/matrix_policy_cases.sh')
        self.configure(check_prior_archive=True)
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'XDEV_RECORDING_SPEC': str(self.specification)}
        return subprocess.run(['bash', str(path), str(self.scratch), str(self.native)], env=env, text=True, capture_output=True, timeout=60)

    def recorded(self):
        path = self.scratch / 'recording-invocations.jsonl'
        return [json.loads(row) for row in path.read_text().splitlines()] if path.exists() else []

    def network_argv(self):
        base = ['--scratch', str(self.scratch), '--source', str(self.native)]
        stream = ['--groups', '257', '--depth', '8', '--ce-slots', '8', '--ce-sim', '--ce-delay-us', '10000', '--rx-ce']
        # Literal table from public campaign specification, independent of the
        # wrapper implementation after the B2 freeze.
        suffixes = [
            stream + ['--reliable', '--fault', 'none'],
            *[stream + ['--reliable', '--run-only', '--fault', name] for name in (
                'reliable-drop-data', 'reliable-drop-ack', 'reliable-duplicate-ack',
                'reliable-replay-group', 'reliable-reorder-group', 'reliable-budget-unknown')],
            stream + ['--reliable', '--run-only', '--fault', 'none', '--remote-window', '1'],
            stream + ['--run-only', '--fault', 'none'],
            stream + ['--run-only', '--fault', 'drop-middle'],
            stream + ['--run-only', '--fault', 'duplicate-middle'],
            ['--provider-case', 'short', '--run-only'],
            ['--provider-case', 'ambiguous', '--run-only'],
        ]
        return [base + suffix for suffix in suffixes]

    def policy_argv(self):
        base = ['--scratch', str(self.scratch), '--source', str(self.native), '--run-only',
                '--groups', '257', '--depth', '8', '--ce-slots', '8', '--ce-sim', '--ce-delay-us', '10000', '--rx-ce', '--reliable']
        return [base + ['--rel-policy', policy, '--fault', fault] for policy, fault in (
            ('window1', 'none'), ('window8', 'none'), ('every-n', 'none'), ('delayed', 'none'),
            ('exponential', 'reliable-drop-data'), ('oldest', 'reliable-drop-data'), ('round-robin', 'reliable-drop-data'))]

    def assert_frozen_cases_and_legacy(self, expected_names, legacy):
        cases = self.scratch / 'acceptance/cases'
        self.assertEqual({p.name for p in cases.iterdir() if p.is_dir() and p.name != 'blobs'}, set(expected_names))
        for number, name in enumerate(expected_names):
            case = cases / name
            self.assertEqual((case / 'images/source.raw').read_bytes(), ('archive-recording-only:invocation-' + str(number) + ':source.raw\n').encode())
            self.assertEqual((self.scratch / legacy / name / 'guest.log').read_bytes(), ('archive-recording-only:invocation-' + str(number) + ':evidence/guest.log\n').encode())
            self.assertTrue((case / 'archived-artifacts.json').is_file())
            self.assertFalse(any(path.is_symlink() for path in case.rglob('*')))

    def test_network_all_thirteen_exact_argv_and_freeze_before_next_child(self):
        result = self.wrapper('network')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recorded(), self.network_argv())
        names = ['normal', 'reliable-drop-data', 'reliable-drop-ack', 'reliable-duplicate-ack', 'reliable-replay-group',
                 'reliable-reorder-group', 'reliable-budget-unknown', 'credit-window-one', 'legacy-normal', 'legacy-drop-middle',
                 'legacy-duplicate-middle', 'provider-short', 'provider-ambiguous']
        self.assert_frozen_cases_and_legacy(names, 'campaigns')

    def test_policy_all_seven_exact_argv_and_reliable_drop_data(self):
        result = self.wrapper('policy')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.recorded(), self.policy_argv())
        self.assert_frozen_cases_and_legacy(['window1', 'window8', 'every-n', 'delayed', 'exponential', 'oldest', 'round-robin'], 'policy-campaigns')

    def check_exit_seven(self, name):
        self.configure(child_exit=7)
        result = self.wrapper(name)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)
        self.assertEqual(len(self.recorded()), 1)
        self.assertEqual(len((self.scratch / 'recording-launches.jsonl').read_text().splitlines()), 1, 'a later child was launched after failure')
        case_name = 'normal' if name == 'network' else 'window1'
        case = self.scratch / 'acceptance/cases' / case_name
        self.assertEqual((case / 'command.exit').read_text(), '7\n')
        self.assertEqual((case / 'images/source.raw').read_bytes(), b'archive-recording-only:invocation-0:source.raw\n')
        self.assertNotIn('=PASS', result.stdout)

    def test_network_exit_seven_stops_and_preserves_originals(self):
        self.check_exit_seven('network')

    def test_policy_exit_seven_stops_and_preserves_originals(self):
        self.check_exit_seven('policy')

    def check_archive_failure(self, name):
        self.configure(malformed_manifest=True)
        result = self.wrapper(name)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.recorded()), 1)
        self.assertEqual(len((self.scratch / 'recording-launches.jsonl').read_text().splitlines()), 1, 'a later child was launched after failure')
        self.assertNotIn('=PASS', result.stdout)

    def test_network_archive_failure_stops_before_case_two(self):
        self.check_archive_failure('network')

    def test_policy_archive_failure_stops_before_case_two(self):
        self.check_archive_failure('policy')

    def test_network_child_seven_survives_actual_archive_failure(self):
        self.configure(child_exit=7, malformed_manifest=True)
        result = self.wrapper('network')
        case = self.scratch / 'acceptance/cases/normal'
        self.assertEqual((case / 'command.exit').read_text(), '7\n')
        self.assertEqual(json.loads((case / 'receipt.json').read_text())['command_exit'], 7)
        self.assertIn('RECORDING_CHILD label=invocation-0', (case / 'command.log').read_text())
        self.assertEqual((case / 'evidence/artifacts.sha256').read_text(), 'deliberately malformed ordinary archive input\n')
        self.assertEqual((case / 'images/source.raw').read_bytes(), b'archive-recording-only:invocation-0:source.raw\n')
        self.assertEqual(len(self.recorded()), 1)
        self.assertEqual(len((self.scratch / 'recording-launches.jsonl').read_text().splitlines()), 1, 'a later child was launched after dual failure')
        self.assertNotIn('=PASS', result.stdout)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)

    def test_policy_child_seven_survives_actual_archive_failure(self):
        self.configure(child_exit=7, malformed_manifest=True)
        result = self.wrapper('policy')
        case = self.scratch / 'acceptance/cases/window1'
        self.assertEqual((case / 'command.exit').read_text(), '7\n')
        self.assertEqual(json.loads((case / 'receipt.json').read_text())['command_exit'], 7)
        self.assertIn('RECORDING_CHILD label=invocation-0', (case / 'command.log').read_text())
        self.assertEqual((case / 'evidence/artifacts.sha256').read_text(), 'deliberately malformed ordinary archive input\n')
        self.assertEqual((case / 'images/source.raw').read_bytes(), b'archive-recording-only:invocation-0:source.raw\n')
        self.assertEqual(len(self.recorded()), 1)
        self.assertEqual(len((self.scratch / 'recording-launches.jsonl').read_text().splitlines()), 1, 'a later child was launched after dual failure')
        self.assertNotIn('=PASS', result.stdout)
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)

    def test_network_sigterm_survives_actual_archive_failure_as_143(self):
        self.configure(child_signal=15, malformed_manifest=True)
        result = self.wrapper('network')
        case = self.scratch / 'acceptance/cases/normal'
        self.assertEqual((case / 'command.exit').read_text(), '-15\n')
        self.assertEqual(json.loads((case / 'receipt.json').read_text())['command_exit'], -15)
        self.assertIn('RECORDING_CHILD label=invocation-0', (case / 'command.log').read_text())
        self.assertEqual((case / 'evidence/artifacts.sha256').read_text(), 'deliberately malformed ordinary archive input\n')
        self.assertEqual((case / 'images/source.raw').read_bytes(), b'archive-recording-only:invocation-0:source.raw\n')
        self.assertEqual(len(self.recorded()), 1)
        self.assertEqual(len((self.scratch / 'recording-launches.jsonl').read_text().splitlines()), 1, 'a later child was launched after signal/archive failure')
        self.assertNotIn('=PASS', result.stdout)
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)

    def test_policy_sigterm_survives_actual_archive_failure_as_143(self):
        self.configure(child_signal=15, malformed_manifest=True)
        result = self.wrapper('policy')
        case = self.scratch / 'acceptance/cases/window1'
        self.assertEqual((case / 'command.exit').read_text(), '-15\n')
        self.assertEqual(json.loads((case / 'receipt.json').read_text())['command_exit'], -15)
        self.assertIn('RECORDING_CHILD label=invocation-0', (case / 'command.log').read_text())
        self.assertEqual((case / 'evidence/artifacts.sha256').read_text(), 'deliberately malformed ordinary archive input\n')
        self.assertEqual((case / 'images/source.raw').read_bytes(), b'archive-recording-only:invocation-0:source.raw\n')
        self.assertEqual(len(self.recorded()), 1)
        self.assertEqual(len((self.scratch / 'recording-launches.jsonl').read_text().splitlines()), 1, 'a later child was launched after signal/archive failure')
        self.assertNotIn('=PASS', result.stdout)
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)

    def fault_wrapper(self, child_exit):
        # tempfile's alphabet includes '_'; the real fault harness admits only
        # alphanumeric suffixes. Retry collisions at creation, never execution.
        for _ in range(16):
            scratch = Path('/tmp') / ('xdev-ext-e2e.' + secrets.token_hex(16))
            try:
                scratch.mkdir(mode=0o700)
            except FileExistsError:
                continue
            self.addCleanup(shutil.rmtree, scratch)
            break
        else:
            self.fail('could not create a unique legal fault scratch directory')
        self.assertRegex(str(scratch), r'\A/tmp/xdev-ext-e2e\.[A-Za-z0-9]+\Z')
        self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)
        old = str(self.scratch)
        self.scratch = scratch
        self.case = self.scratch / 'acceptance/cases/ring-exit-rx'
        spec = json.loads(self.specification.read_text().replace(old, str(self.scratch)))
        spec['child_exit'] = child_exit
        write_json(self.specification, spec)
        path = PRODUCT / 'tests/integration/session/native/xdev_ext_mech_zc_fault_matrix.py'
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'XDEV_RECORDING_SPEC': str(self.specification)}
        return subprocess.run([sys.executable, '-B', str(path), str(self.scratch), str(self.native)], env=env, capture_output=True, text=True, timeout=60)

    def test_fault_child_seven_freezes_and_stops_without_oracle_bypass(self):
        result = self.fault_wrapper(7)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.recorded()), 1)
        self.assertEqual(len((self.scratch / 'recording-launches.jsonl').read_text().splitlines()), 1)
        self.assertEqual((self.case / 'command.exit').read_text(), '7\n')
        self.assertEqual((self.case / 'images/source.raw').read_bytes(), b'archive-recording-only:invocation-0:source.raw\n')
        legacy = self.scratch / 'fault-campaigns/ring-exit-rx'
        self.assertTrue((legacy / 'other-qemu-before.txt').is_file())
        self.assertTrue((legacy / 'other-qemu-after.txt').is_file())
        self.assertNotIn('=PASS', result.stdout)

    def test_fault_child_zero_is_still_rejected_by_real_oracle(self):
        # These recording-only files must NEVER be admitted as successful guest
        # evidence. The real fault oracle executes unchanged and must reject.
        result = self.fault_wrapper(0)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.recorded()), 1)
        self.assertEqual(len((self.scratch / 'recording-launches.jsonl').read_text().splitlines()), 1)
        self.assertEqual((self.case / 'command.exit').read_text(), '0\n')
        self.assertTrue((self.case / 'build/Module.symvers').is_file())
        self.assertTrue((self.case / 'archived-artifacts.json').is_file())
        self.assertNotIn('XDEV_EXT_ZC_FAULT_MATRIX=PASS', result.stdout)

    def test_fault_eighteen_dry_run_exact_order_and_argv(self):
        # Selector names were separately frozen by root, without oracle logic.
        names = ['ring-exit-rx', 'exit-rx', 'exit-source', 'detach-afxdp-mid-run', 'detach-nvme-under-load',
                 'netdev-remove-tx', 'netdev-remove-rx', 'window-reject', 'fq-dup', 'afxdp-copy', 'afxdp-drv-copy',
                 'ce-presubmit', 'ce-ambiguous-multi', 'nvme-readonly-dest', 'nvme-reset-mid-run',
                 'concurrent-ce-disjoint', 'concurrent-ce-overlap', 'cross-session-isolation']
        scratch = '/tmp/xdev-ext-e2e.ArchivePlanOnly'
        path = PRODUCT / 'tests/integration/session/native/xdev_ext_mech_zc_fault_matrix.py'
        result = subprocess.run([sys.executable, '-B', str(path), '--dry-run', scratch, str(self.native)], text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        plans = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        self.assertEqual([row['campaign'] for row in plans], names)
        base = ['bash', str(self.native / 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'), '--scratch', scratch, '--source', str(self.native), '--ce-sim', '--groups', '64', '--depth', '8', '--ce-slots', '8', '--fault-campaign']
        self.assertEqual([row['harness_command'] for row in plans], [base + [name] + (['--run-only'] if i else []) for i, name in enumerate(names)])
        self.assertFalse((self.scratch / 'recording-invocations.jsonl').exists())


class ReplayTransportContract(unittest.TestCase):
    """Root-approved narrow path boundary only; never full E2 acceptance."""
    @classmethod
    def setUpClass(cls):
        directory = PRODUCT / 'tests/benchmarks/mechanism_variants'
        sys.path.insert(0, str(directory))
        cls.validator = import_file(directory / 'validate_e2.py')
        if not callable(getattr(cls.validator, 'validate_transport_command', None)):
            raise RuntimeError('SETUP2: approved B3 validate_transport_command boundary is absent')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='replay-transport-', dir=ARTIFACTS)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.original = self.root / 'original-live'
        self.live_evidence = self.original / 'evidence'
        self.live_evidence.mkdir(parents=True)
        self.evidence = self.root / 'frozen/evidence'
        self.argv = ['/usr/local/bin/qemu-system-x86_64', '-machine', 'q35,accel=kvm',
                     '-device', 'virtio-serial-pci',
                     '-chardev', 'file,id=e2_artifacts,path=' + str(self.live_evidence / 'e2-artifacts.raw.log'),
                     '-device', 'virtserialport,chardev=e2_artifacts,name=xdev-e2-artifacts']
        write(self.live_evidence / 'qemu.command', shlex.join(self.argv) + '\n')
        write(self.live_evidence / 'e2-artifacts.raw.log', b'ordinary parser transport bytes; no guest result\n')
        shutil.copytree(self.live_evidence, self.evidence)

    def transport(self, argv=None, original=None):
        if argv is not None:
            write(self.evidence / 'qemu.command', shlex.join(argv) + '\n')
        return self.validator.validate_transport_command(self.evidence, original or self.original)

    def test_actual_original_path_accepts_frozen_bytes_after_live_removed(self):
        before = snapshot(self.evidence)
        shutil.rmtree(self.original)
        self.assertIsNone(self.transport())
        self.assertEqual(snapshot(self.evidence), before)
        self.assertFalse(self.original.exists())

    def test_live_default_original_path_remains_accepted(self):
        self.assertIsNone(self.validator.validate_transport_command(self.live_evidence, self.original))

    def test_live_evidence_directory_alias_uses_resolved_original_transport(self):
        """The live harness resolves EV before recording its QEMU path."""
        actual_evidence = self.original / 'actual-evidence'
        self.live_evidence.rename(actual_evidence)
        self.live_evidence.symlink_to(actual_evidence, target_is_directory=True)
        self.assertTrue(self.live_evidence.is_symlink())
        argv = list(self.argv)
        argv[argv.index('-chardev') + 1] = ('file,id=e2_artifacts,path=' +
            str(self.live_evidence.resolve() / 'e2-artifacts.raw.log'))
        write(actual_evidence / 'qemu.command', shlex.join(argv) + '\n')
        shutil.copyfile(actual_evidence / 'qemu.command', self.evidence / 'qemu.command')
        shutil.copyfile(actual_evidence / 'e2-artifacts.raw.log', self.evidence / 'e2-artifacts.raw.log')
        frozen_before = snapshot(self.evidence)
        self.assertIsNone(self.transport())
        self.assertEqual(snapshot(self.evidence), frozen_before)

    def test_wrong_original_scratch_rejected(self):
        with self.assertRaises((ValueError, OSError, AssertionError)):
            self.transport(original=self.root / 'wrong-original')

    def test_frozen_path_cannot_replace_original_qemu_transport(self):
        argv = list(self.argv)
        argv[argv.index('-chardev') + 1] = 'file,id=e2_artifacts,path=' + str(self.evidence / 'e2-artifacts.raw.log')
        with self.assertRaises((ValueError, OSError, AssertionError)):
            self.transport(argv)

    def test_duplicate_transport_argument_rejected(self):
        with self.assertRaises((ValueError, OSError, AssertionError)):
            self.transport(self.argv + ['-chardev', self.argv[self.argv.index('-chardev') + 1]])

    def test_duplicate_transport_devices_rejected(self):
        for value in ('virtio-serial-pci', 'virtserialport,chardev=e2_artifacts,name=xdev-e2-artifacts'):
            with self.subTest(device=value):
                with self.assertRaises((ValueError, OSError, AssertionError)):
                    self.transport(self.argv + ['-device', value])

    def test_missing_required_actual_option_cannot_be_a_substring(self):
        for value in ('virtio-serial-pci', 'file,id=e2_artifacts,path=' + str(self.live_evidence / 'e2-artifacts.raw.log'),
                      'virtserialport,chardev=e2_artifacts,name=xdev-e2-artifacts'):
            with self.subTest(option=value):
                argv = list(self.argv)
                index = argv.index(value)
                del argv[index - 1:index + 1]
                argv += ['-name', 'irrelevant text containing ' + value]
                with self.assertRaises((ValueError, OSError, AssertionError)):
                    self.transport(argv)


class ArchiveReplayContract(unittest.TestCase):
    """Archive originals and replay target maps only; no full guest verdict."""
    setUpClass = classmethod(ArchiveContract.setUpClass.__func__)
    tearDownClass = classmethod(ArchiveContract.tearDownClass.__func__)
    setUp = ArchiveContract.setUp
    command = ArchiveContract.command
    run_case = ArchiveContract.run_case
    assert_archived_targets = ArchiveContract.assert_archived_targets

    def test_e2_command_original_manifests_and_frozen_targets_remain_distinct(self):
        specification = json.loads(self.specification.read_text())
        specification['e2_metadata'] = True
        specification['recorded_qemu_argv'] = ['/usr/local/bin/qemu-system-x86_64', '-device', 'virtio-serial-pci',
            '-chardev', 'file,id=e2_artifacts,path=' + str(self.scratch / 'evidence/e2-artifacts.raw.log'),
            '-device', 'virtserialport,chardev=e2_artifacts,name=xdev-e2-artifacts']
        write_json(self.specification, specification)
        self.run_case()
        self.assert_archived_targets()
        original_command = (self.scratch / 'evidence/qemu.command').read_bytes()
        self.assertEqual((self.case / 'evidence/qemu.command').read_bytes(), original_command)
        before = snapshot(self.case)
        for manifest in self.rows:
            self.assertIn((self.scratch / manifest).read_bytes(), before.values(), 'original manifest lost: ' + manifest)
        self.assertEqual((self.case / 'build/xdev-ext-e2-mode.txt').read_bytes(), (self.scratch / 'build/xdev-ext-e2-mode.txt').read_bytes())
        rewrite = self.case / 'build/xdev-ext-artifacts.sha256'
        original = self.case / 'build/xdev-ext-artifacts.original.sha256'
        self.assertEqual(original.read_bytes(), (self.scratch / 'build/xdev-ext-artifacts.sha256').read_bytes())
        target_map = json.loads((self.case / 'frozen-e2-manifest.json').read_text())
        self.assertEqual(target_map['original_sha256'], digest(original))
        self.assertEqual(target_map['frozen_sha256'], digest(rewrite))
        for old_path, new_path in target_map['targets'].items():
            self.assertTrue(Path(old_path).is_absolute())
            self.assertTrue(Path(new_path).is_relative_to(self.case))
            self.assertNotEqual(old_path, new_path)
        for line in rewrite.read_text().splitlines():
            expected, path = line.split('  ', 1)
            self.assertTrue(Path(path).is_relative_to(self.case))
            self.assertEqual(digest(Path(path)), expected)
        self.assertEqual((self.case / 'evidence/qemu.command').read_bytes(), original_command)
        # Remove every live byte while retaining the exact archive pathname.
        for directory in ('build', 'tools', 'evidence'):
            shutil.rmtree(self.scratch / directory)
        for path in self.scratch.glob('*.raw'):
            path.unlink()
        (self.scratch / 'initramfs.cpio.gz').unlink()
        self.assertEqual(snapshot(self.case), before)
        # Frozen build references remain checkable with live bytes absent.
        for line in rewrite.read_text().splitlines():
            expected, path = line.split('  ', 1)
            self.assertEqual(digest(Path(path)), expected)
        self.assertIn(str(self.scratch / 'evidence/e2-artifacts.raw.log').encode(), original_command)


class RecordingControls(unittest.TestCase):
    def test_actual_prepared_fixture_and_recording_child_metadata(self):
        authority = Fixture()
        self.addCleanup(authority.cleanup)
        authority.materialize()
        scratch = authority.root / 'recording-scratch'
        scratch.mkdir(mode=0o700)
        specification = authority.root / 'recording-input.json'
        rows = {'evidence/source-files.sha256': [('io_uring/xdev_ext_mech.c', str(authority.native)),
                (str(authority.view / 'view.json'), ''), (str(authority.repo / 'source-layout.json'), '')]}
        write_json(specification, dict(revision=authority.sha, manifests=rows))
        argv = [sys.executable, '-B', str(CHILD), '--scratch', str(scratch), '--source', str(authority.native), '--specification', str(specification), '--exit-code', '7']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual((scratch / 'source.raw').read_bytes(), b'archive-recording-only:first:source.raw\n')
        manifest = (scratch / 'evidence/source-files.sha256').read_text().splitlines()
        self.assertEqual(manifest[0], digest(authority.native / 'io_uring/xdev_ext_mech.c') + '  io_uring/xdev_ext_mech.c')
        self.assertEqual((scratch / 'build/xdev-ext-source.commit').read_text().strip(), authority.sha)
        self.assertTrue((authority.native / '.xdev-ext-source.json').is_file())
        self.assertFalse((authority.view / 'kernel/io_uring/xdev_ext_mech.c').is_symlink())

    def test_real_file_overwrite_changes_live_but_independent_copy_stays(self):
        """Control establishes the mutable-live gap, not producer correctness."""
        with tempfile.TemporaryDirectory(prefix='mutable-control-', dir=ARTIFACTS) as directory:
            root = Path(directory)
            live = root / 'live.raw'
            frozen = root / 'copy.raw'
            write(live, b'first original bytes\n')
            shutil.copyfile(live, frozen)
            result = subprocess.run([sys.executable, '-c', 'from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b"second overwritten bytes\\n")', str(live)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(frozen.read_bytes(), b'first original bytes\n')
            self.assertNotEqual(live.read_bytes(), frozen.read_bytes())
            self.assertNotEqual(live.stat().st_ino, frozen.stat().st_ino)


if __name__ == '__main__':
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    controls_only = any(arg.startswith('RecordingControls') for arg in sys.argv[1:])
    wrapper_only = any(arg.startswith('WrapperContract') for arg in sys.argv[1:])
    replay_only = any(arg.startswith('ReplayTransportContract') for arg in sys.argv[1:])
    if replay_only:
        try:
            ReplayTransportContract.setUpClass()
        except RuntimeError as error:
            print(str(error), file=sys.stderr)
            sys.exit(2)
    if not HELPER.is_file() and not controls_only and not wrapper_only and not replay_only:
        print('SETUP2: public B1 archive helper is absent; no archive behavior executed: ' + str(HELPER), file=sys.stderr)
        sys.exit(2)
    unittest.main()
