# SPDX-License-Identifier: GPL-2.0
"""Exercise reusable E2 caches with real GCC actual-core software exports.

Only make/BPF builds are replaced at their external command boundary. Their
outputs are labeled host fixtures and never certify a kernel/BPF/guest build.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
PRODUCT = HERE.parents[2]
MODE = HERE / 'kvm_mode.sh'
PATH_RECEIPT = 'xdev-ext-e2-old-ticket.path'


class OldTicketCache(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='e2-old-ticket-cache-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root/'tools'
        self.e2 = self.tools/'e2'
        self.build = self.root/'build'
        self.evidence = self.root/'evidence'
        self.guest = self.root/'guest-root'
        self.wrappers = self.root/'commands'
        for path in (self.e2, self.build, self.evidence, self.wrappers,
                     self.guest/'usr/bin', self.guest/'bin'):
            path.mkdir(parents=True, exist_ok=True)
        symbols = ('TRACING', 'FTRACE', 'BPF_EVENTS', 'XDEV_EXT_MECH',
                   'XDEV_EXT_MECH_ZEROCOPY', 'VIRTIO_CONSOLE')
        (self.build/'.config').write_text(''.join(f'CONFIG_{s}=y\n' for s in symbols))
        (self.build/'vmlinux').write_bytes(b'host build-boundary fixture, not BTF\n')
        for name in ('nxp_mech.bpf.o', 'nvme_s0.bpf.o'):
            (self.tools/name).write_bytes(b'host build-boundary fixture, never loaded\n')
        self.cc = shutil.which('gcc')
        self.assertIsNotNone(self.cc, 'real GCC is required for actual-core evidence')
        compiler = self.wrappers/'gcc-14'
        compiler.write_text('#!/bin/sh\n'
            'if [ "${E2_TEST_FAIL_CC:-0}" = 1 ]; then\n'
            '  echo "intentional compiler-boundary failure" >&2; exit 47\nfi\n'
            f'exec "{self.cc}" "$@"\n')
        compiler.chmod(0o700)
        self.stub = self.root/'make-boundary.py'
        self.stub.write_text('''import json,os,pathlib,sys
args=sys.argv[1:]
assert args[0]=='make' and '-C' in args, args
with open(os.environ['E2_TEST_MAKE_CALLS'],'a') as f: f.write(json.dumps(args)+'\\n')
if os.environ.get('E2_TEST_FAIL_MAKE')=='1':
    print('intentional make-boundary failure',file=sys.stderr); sys.exit(37)
values=dict(a.split('=',1) for a in args if '=' in a)
directory=args[args.index('-C')+1]
if directory.endswith('/tools/lib/bpf'):
    root=pathlib.Path(values['OUTPUT']); names=['libbpf.a']
elif directory.endswith('/tools/bpf/bpftool'):
    root=pathlib.Path(values['OUTPUT']); names=['bpftool']
elif directory==os.environ['E2_SOURCE']:
    root=pathlib.Path(values['BUILD']); names=['mv_ctl','mv_sink']
elif directory==os.environ['E2_SOURCE']+'/tests':
    root=pathlib.Path(values['BUILD_DIR']); names=['nvme_reverse.bpf.o','nvme_gray.bpf.o']
else: raise AssertionError(directory)
root.mkdir(parents=True,exist_ok=True)
for name in names: (root/name).write_bytes(b'host make/BPF boundary fixture, never executed\\n')
''')
        git_env = dict(os.environ)
        receipt = PRODUCT/'view.json'
        if receipt.is_file():
            view = json.loads(receipt.read_text())
            self.assertEqual(view['kind'], 'host-source-view')
            canonical = view['canonical_root']
            # The view contains native copies but has no native Git index.
            # Select the actual harness's source paths, then index their current
            # bytes in private objects. Canonical Git metadata stays read-only.
            command = MODE.read_text().split('git ls-files -z --', 1)[1].split('| while', 1)[0]
            source_paths = shlex.split(command.replace('\\\n', ''))
            tracked = subprocess.check_output(
                ['git', '-C', canonical, 'ls-files', '--stage', '-z'])
            entries = {}
            for row in filter(None, tracked.split(b'\0')):
                metadata, path = row.split(b'\t', 1)
                mode, _blob, stage = metadata.split()
                self.assertEqual(stage, b'0', 'source fixture requires resolved inputs')
                entries[os.fsdecode(path)] = mode
            selected = sorted(logical for logical in view['source_origins']
                              if any(logical == path or logical.startswith(path+'/')
                                     for path in source_paths))
            self.assertTrue(selected, 'actual source-record selection is empty')
            git_env.update(GIT_DIR=subprocess.check_output(
                ['git', '-C', canonical, 'rev-parse', '--absolute-git-dir'],
                text=True).strip(), GIT_WORK_TREE=str(PRODUCT),
                GIT_INDEX_FILE=str(self.root/'native-source.index'),
                GIT_OBJECT_DIRECTORY=str(self.root/'native-objects'),
                GIT_ALTERNATE_OBJECT_DIRECTORIES=subprocess.check_output(
                    ['git', '-C', canonical, 'rev-parse', '--path-format=absolute',
                     '--git-path', 'objects'], text=True).strip())
            Path(git_env['GIT_OBJECT_DIRECTORY']).mkdir()
            blobs = subprocess.check_output(
                ['git', 'hash-object', '-w', '--no-filters', '--stdin-paths'],
                input=''.join(str(PRODUCT/name)+'\n' for name in selected).encode(),
                env=git_env).splitlines()
            self.assertEqual(len(blobs), len(selected))
            native = b''.join(entries[view['source_origins'][logical]]+b' '+blob+
                              b'\t'+os.fsencode(logical)+b'\0'
                              for logical, blob in zip(selected, blobs))
            subprocess.run(['git', 'update-index', '-z', '--index-info'],
                           input=native, env=git_env, check=True)
        self.env = dict(git_env, SRC=str(PRODUCT/'kernel'), TOOLS=str(self.tools),
            BUILD=str(self.build), EV=str(self.evidence), ROOT=str(self.guest),
            E2_SOURCE=str(HERE), SOURCE_GIT_ROOT=str(PRODUCT), E2_MODE=str(MODE),
            SOURCE_COMMIT=subprocess.check_output(['git', '-C', str(PRODUCT),
                                                  'rev-parse', 'HEAD'], text=True, env=git_env).strip(),
            BUILD_STUB=str(self.stub), E2_TEST_MAKE_CALLS=str(self.root/'make-calls.jsonl'),
            PYTHONDONTWRITEBYTECODE='1', PATH=str(self.wrappers)+':'+os.environ['PATH'])

    def shell(self, action, **changes):
        code = ('source "$E2_MODE"\n'
                'lowprio() { python3 "$BUILD_STUB" "$@"; }\n' + action + '\n')
        return subprocess.run(['bash', '-euo', 'pipefail', '-c', code], cwd=self.root,
            env=dict(self.env, **changes), text=True, capture_output=True, timeout=90)

    def assert_success(self, run):
        log = self.evidence/'e2-old-ticket-host.log'
        detail = run.stdout + run.stderr + ('\n'+log.read_text() if log.exists() else '')
        self.assertEqual(run.returncode, 0, detail)

    def snapshot(self, directory):
        return {p.relative_to(directory).as_posix():p.read_bytes()
                for p in directory.rglob('*') if p.is_file()}

    def selected_path(self):
        receipt = self.build/PATH_RECEIPT
        self.assertTrue(receipt.is_file(), 'successful export did not record its path')
        lines = receipt.read_text().splitlines()
        self.assertEqual(len(lines), 1, 'path receipt must select one immutable export')
        path = Path(lines[0])
        self.assertTrue(path.is_absolute())
        self.assertEqual(path, path.resolve(), 'path receipt must be canonical')
        self.assertTrue(path.is_relative_to(self.e2.resolve()))
        self.assertTrue(path.is_dir())
        return path

    def assert_actual_export(self, directory):
        self.assertEqual((directory/'old-ticket-fixture').read_bytes()[:4], b'\x7fELF')
        negative = json.loads((directory/'old_ticket.json').read_text())
        self.assertEqual(negative['evidence_kind'], 'actual-core-host-fixture')
        self.assertNotEqual(negative['old_ticket'], negative['current_ticket'])
        raw = (directory/'old-ticket.log').read_text()
        rows = [json.loads(line.split(' ', 1)[1]) for line in raw.splitlines()
                if line.startswith('E2_OLD_TICKET_SNAPSHOT ')]
        self.assertEqual([row['phase'] for row in rows], ['before', 'after'])
        self.assertEqual(rows[0]['state'], rows[1]['state'])

    def hash_line(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()+'  '+str(path)+'\n'

    def qualify_fixture(self):
        """Actual first build + independently supplied receipt for gate tests.

        The old implementation has no receipt writer. Supplying a valid host
        fixture receipt lets negative tests reach its real run-only verifier.
        """
        self.assert_success(self.shell('e2_build'))
        path = (self.selected_path() if (self.build/PATH_RECEIPT).exists()
                else self.e2/'software-old-ticket')
        self.assert_actual_export(path)
        (self.build/PATH_RECEIPT).write_text(str(path.resolve())+'\n')
        (self.build/'xdev-ext-artifacts.sha256').write_text('')
        self.assert_success(self.shell('e2_record_artifacts'))
        # Independent valid SHA entries are test inputs, not replacement
        # verification logic; all production verifier behavior stays real.
        receipt = self.build/'xdev-ext-artifacts.sha256'
        text = receipt.read_text()
        for file in [self.build/PATH_RECEIPT, *sorted(path.iterdir())]:
            line = self.hash_line(file)
            if line not in text: text += line
        receipt.write_text(text)
        self.assert_success(self.shell('e2_verify_identity'))
        return path

    def test_helper_allocates_two_private_parents_and_retains_real_exports(self):
        self.assert_success(self.shell('e2_paths\ne2_export_old_ticket'))
        first = self.selected_path(); self.assert_actual_export(first)
        old = self.snapshot(first)
        self.assertEqual(first.name, 'capture')
        self.assertEqual(first.parent.parent, self.e2)
        self.assertEqual(first.parent.stat().st_mode & 0o777, 0o700)
        self.assert_success(self.shell('e2_paths\ne2_export_old_ticket'))
        second = self.selected_path(); self.assert_actual_export(second)
        self.assertNotEqual(first, second)
        self.assertNotEqual(first.parent, second.parent)
        self.assertEqual(self.snapshot(first), old, 'previous immutable evidence was overwritten/deleted')

    def test_actual_repeated_build_uses_same_cache_without_existing_dir_failure(self):
        self.assert_success(self.shell('e2_build'))
        receipt = self.build/PATH_RECEIPT
        # Reach the historical second-build failure even before the new path
        # interface exists; this fallback reads old evidence, never creates it.
        first = self.selected_path() if receipt.exists() else self.e2/'software-old-ticket'
        self.assert_actual_export(first); old = self.snapshot(first)
        self.assert_success(self.shell('e2_build'))
        second = self.selected_path()
        self.assertNotEqual(first, second)
        self.assertEqual(self.snapshot(first), old)
        self.assert_actual_export(second)
        calls = [json.loads(line) for line in (self.root/'make-calls.jsonl').read_text().splitlines()]
        self.assertEqual(len(calls), 8, 'both real e2_build invocations must traverse all four build boundaries')

    def test_failed_export_keeps_old_path_receipt_and_original_bytes(self):
        self.assert_success(self.shell('e2_paths\ne2_export_old_ticket'))
        path = self.selected_path(); old = self.snapshot(path)
        receipt = (self.build/PATH_RECEIPT).read_bytes()
        failed = self.shell('e2_paths\ne2_export_old_ticket', E2_TEST_FAIL_CC='1')
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual((self.build/PATH_RECEIPT).read_bytes(), receipt)
        self.assertEqual(self.snapshot(path), old)
        self.assertIn('actual fixture build failed', (self.evidence/'e2-old-ticket-host.log').read_text())

    def test_record_and_stage_use_selected_capture_not_retained_legacy_directory(self):
        self.assert_success(self.shell('e2_build'))
        previous = (self.selected_path() if (self.build/PATH_RECEIPT).exists()
                    else self.e2/'software-old-ticket')
        old = self.snapshot(previous)
        parent = Path(tempfile.mkdtemp(prefix='independent-export-', dir=self.e2))
        selected = parent/'capture'
        run = subprocess.run(['python3', '-B', str(HERE/'export_old_ticket.py'),
            str(PRODUCT/'kernel'), str(selected), '--cc', 'gcc-14'], env=self.env,
            text=True, capture_output=True, timeout=60)
        self.assert_success(run); self.assert_actual_export(selected)
        (self.build/PATH_RECEIPT).write_text(str(selected.resolve())+'\n')
        artifacts = self.build/'xdev-ext-artifacts.sha256'; artifacts.write_text('')
        self.assert_success(self.shell('e2_record_artifacts'))
        indexed = artifacts.read_text()
        with self.subTest(boundary='record'):
            for file in [self.build/PATH_RECEIPT, *sorted(selected.iterdir())]:
                self.assertIn(self.hash_line(file), indexed, 'selected capture/receipt absent from actual artifact identity')
        self.assert_success(self.shell('e2_stage'))
        self.assertTrue(self.snapshot(self.evidence/'e2-software') == self.snapshot(selected),
                        'stage copied retained legacy evidence instead of selected capture')
        self.assertEqual(self.snapshot(previous), old)

    def test_run_only_rejects_path_and_export_identity_corruption(self):
        selected = self.qualify_fixture()
        receipt = self.build/PATH_RECEIPT
        artifacts = self.build/'xdev-ext-artifacts.sha256'
        original_receipt, original_index = receipt.read_bytes(), artifacts.read_bytes()
        raw = selected/'old-ticket.log'; original_raw = raw.read_bytes()
        for case in ('missing-path', 'empty-path', 'outside', 'escape-symlink',
                     'receipt-hash', 'receipt-unindexed', 'proof-hash', 'proof-missing',
                     'proof-unindexed', 'source-hash', 'frontend-hash'):
            with self.subTest(case=case):
                receipt.write_bytes(original_receipt); artifacts.write_bytes(original_index)
                raw.write_bytes(original_raw)
                if case == 'missing-path': receipt.unlink()
                elif case == 'empty-path': receipt.write_bytes(b'')
                elif case in ('outside', 'escape-symlink'):
                    outside = self.root/'outside-export'
                    if not outside.exists(): shutil.copytree(selected, outside)
                    chosen = outside
                    if case == 'escape-symlink':
                        alias = self.e2/'outside-alias'; alias.symlink_to(outside, target_is_directory=True)
                        chosen = alias
                    receipt.write_text(str(chosen)+'\n')
                    # Correct hashes do not authorize escaping E2's namespace.
                    text = original_index.decode().replace(self.hash_line_from_bytes(receipt, original_receipt), '')
                    text += self.hash_line(receipt)
                    text += ''.join(self.hash_line(p) for p in outside.iterdir())
                    artifacts.write_text(text)
                elif case == 'receipt-hash': receipt.write_bytes(original_receipt+b'\n')
                elif case == 'receipt-unindexed':
                    artifacts.write_text(original_index.decode().replace(self.hash_line(receipt), ''))
                elif case == 'proof-hash': raw.write_bytes(original_raw+b'tampered actual observation\n')
                elif case == 'proof-missing': raw.unlink()
                elif case == 'proof-unindexed':
                    artifacts.write_text(original_index.decode().replace(self.hash_line(raw), ''))
                elif case == 'source-hash':
                    source_receipt = self.build/'xdev-ext-e2-sources.sha256'
                    source_old = source_receipt.read_bytes()
                    source_receipt.write_bytes((b'0' if source_old[:1] != b'0' else b'1')+source_old[1:])
                elif case == 'frontend-hash':
                    frontend = self.e2/'mv_ctl'; frontend_old = frontend.read_bytes()
                    frontend.write_bytes(frontend_old+b'tampered frontend\n')
                failed = self.shell('e2_verify_identity')
                self.assertNotEqual(failed.returncode, 0, 'run-only accepted '+case)
            if case == 'source-hash': source_receipt.write_bytes(source_old)
            if case == 'frontend-hash': frontend.write_bytes(frontend_old)

    def hash_line_from_bytes(self, path, data):
        return hashlib.sha256(data).hexdigest()+'  '+str(path)+'\n'

    def test_failed_make_does_not_publish_new_export_or_build_receipts(self):
        selected = self.qualify_fixture(); old = self.snapshot(selected)
        receipts = {name:(self.build/name).read_bytes() for name in
                    (PATH_RECEIPT, 'xdev-ext-e2-mode.txt', 'xdev-ext-e2-sources.sha256',
                     'xdev-ext-artifacts.sha256')}
        failed = self.shell('e2_build', E2_TEST_FAIL_MAKE='1')
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(receipts, {name:(self.build/name).read_bytes() for name in receipts})
        self.assertEqual(self.snapshot(selected), old)

    def test_failed_source_record_cannot_qualify_partial_new_build(self):
        selected = self.qualify_fixture(); old = self.snapshot(selected)
        actual_git = shutil.which('git')
        wrapper = self.wrappers/'git'
        marker = self.root/'source-record-failure-reached'
        wrapper.write_text('#!/bin/sh\ncase " $* " in\n'
            '  *" ls-files "*) echo reached > "$E2_TEST_GIT_FAILURE_MARKER"; '
            'echo "intentional source-record boundary failure" >&2; exit 41;;\nesac\n'
            f'exec "{actual_git}" "$@"\n')
        wrapper.chmod(0o700)
        failed = self.shell('e2_build', E2_TEST_GIT_FAILURE_MARKER=str(marker))
        self.assertNotEqual(failed.returncode, 0)
        self.assertTrue(marker.exists(), 'build failed before the intended source-record boundary')
        self.assertEqual(self.snapshot(selected), old)
        reuse = self.shell('e2_verify_identity')
        self.assertNotEqual(reuse.returncode, 0, 'partial new build retained a valid whole-build qualification')


if __name__ == '__main__': unittest.main(verbosity=2)
