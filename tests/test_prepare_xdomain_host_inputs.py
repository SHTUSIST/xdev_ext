# SPDX-License-Identifier: GPL-2.0-only
"""Offline checks of one pinned input; controlled bytes never qualify an SDK/header."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from urllib.error import URLError

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/prepare_xdomain_host_inputs.py'
COMMIT = '89be9a83ccf1f88522317ce02f854f30d6115c41'
RELATIVE = Path('kernel/drivers/thunderbolt/nhi_regs.h')


class PinnedHostInput(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'missing single-file NHI input preparation')
        spec = importlib.util.spec_from_file_location('prepare_xdomain_host_inputs', SCRIPT)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        temp = tempfile.TemporaryDirectory(prefix='xdomain-host-input-test-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.lock = {'schema': 1, 'components': {'linux': {
            'url': 'https://github.com/torvalds/linux.git',
            'commit': COMMIT, 'path': 'kernel'}}}
        self.write_lock()
        self.target = self.root / RELATIVE
        # Deliberately not a header: unit-test bytes exercise transfer/integrity
        # only, while a separate actual upstream download qualifies the real pin.
        self.payload = b'controlled dependency transfer bytes\n'
        patch = mock.patch.object(self.m, 'NHI_SHA256', hashlib.sha256(self.payload).hexdigest())
        patch.start()
        self.addCleanup(patch.stop)

    def write_lock(self):
        (self.root / 'sources.lock.json').write_text(json.dumps(self.lock))

    def response(self, data=None):
        return io.BytesIO(self.payload if data is None else data)

    def test_download_fills_only_the_missing_pinned_file_and_preserves_other_sources(self):
        authored = self.root / 'kernel/io_uring/author.c'
        authored.parent.mkdir(parents=True)
        authored.write_bytes(b'author source must survive\n')
        before = {p.relative_to(self.root): p.read_bytes()
                  for p in self.root.rglob('*') if p.is_file()}
        with mock.patch.object(self.m, 'urlopen', return_value=self.response()) as fetch:
            result = self.m.prepare(self.root)
        url = fetch.call_args.args[0]
        self.assertTrue(url.startswith('https://raw.githubusercontent.com/torvalds/linux/' + COMMIT + '/'))
        self.assertEqual(url.split('?', 1)[0].rsplit('/', 3)[-3:],
                         ['drivers', 'thunderbolt', 'nhi_regs.h'])
        self.assertEqual(fetch.call_args.kwargs['timeout'], 20)
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(self.target.read_bytes(), self.payload)
        self.assertEqual(result['status'], 'prepared')
        self.assertEqual(result['commit'], COMMIT)
        after = {p.relative_to(self.root): p.read_bytes()
                 for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(after, before | {RELATIVE: self.payload})

    def test_identical_existing_dependency_is_reused_without_network_or_rewrite(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(self.payload)
        before = self.target.stat().st_mtime_ns
        with mock.patch.object(self.m, 'urlopen') as fetch:
            result = self.m.prepare(self.root)
        self.assertEqual(result['status'], 'verified-existing')
        self.assertEqual(self.target.stat().st_mtime_ns, before)
        fetch.assert_not_called()

    def test_differing_existing_source_is_never_replaced_or_removed(self):
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b'local author modification\n')
        with mock.patch.object(self.m, 'urlopen') as fetch:
            with self.assertRaisesRegex(self.m.PreparationError, 'existing|SHA256'):
                self.m.prepare(self.root)
        self.assertEqual(self.target.read_bytes(), b'local author modification\n')
        fetch.assert_not_called()

    def test_downloaded_hash_mismatch_writes_nothing(self):
        with mock.patch.object(self.m, 'urlopen', return_value=self.response(b'wrong upstream bytes')):
            with self.assertRaisesRegex(self.m.PreparationError, 'SHA256'):
                self.m.prepare(self.root)
        self.assertFalse(self.target.exists())
        self.assertFalse((self.root / 'kernel').exists())

    def test_download_read_is_bounded_and_oversize_is_refused(self):
        response = self.response(b'x' * 65537)
        with mock.patch.object(response, 'read', wraps=response.read) as read:
            with mock.patch.object(self.m, 'urlopen', return_value=response):
                with self.assertRaisesRegex(self.m.PreparationError, 'size|limit'):
                    self.m.prepare(self.root)
            read.assert_called_once_with(65537)
        self.assertFalse(self.target.exists())

    def test_network_failure_leaves_no_partial_dependency(self):
        with mock.patch.object(self.m, 'urlopen', side_effect=URLError('controlled timeout')):
            with self.assertRaisesRegex(self.m.PreparationError, 'download|timeout'):
                self.m.prepare(self.root)
        self.assertFalse(self.target.exists())

    def test_changed_commit_remote_or_component_path_is_refused_before_network(self):
        original = dict(self.lock['components']['linux'])
        for key, value in [('commit', '0' * 40), ('url', 'https://example.invalid/linux.git'),
                           ('path', '../outside')]:
            with self.subTest(field=key):
                self.lock['components']['linux'] = dict(original, **{key: value})
                self.write_lock()
                with mock.patch.object(self.m, 'urlopen') as fetch:
                    with self.assertRaises(self.m.PreparationError):
                        self.m.prepare(self.root)
                fetch.assert_not_called()
        self.assertFalse(self.target.exists())

    def test_missing_or_unsupported_lock_fails_closed(self):
        for data in ({'schema': 2, 'components': self.lock['components']}, {'schema': 1}):
            with self.subTest(lock=data):
                (self.root / 'sources.lock.json').write_text(json.dumps(data))
                with mock.patch.object(self.m, 'urlopen') as fetch:
                    with self.assertRaises(self.m.PreparationError):
                        self.m.prepare(self.root)
                fetch.assert_not_called()

    def test_symlink_parent_or_target_is_not_followed_or_replaced(self):
        outside = self.root / 'outside'
        outside.mkdir()
        outside_file = outside / 'nhi_regs.h'
        outside_file.write_bytes(b'outside data\n')
        (self.root / 'kernel').symlink_to(outside, target_is_directory=True)
        with mock.patch.object(self.m, 'urlopen') as fetch:
            with self.assertRaisesRegex(self.m.PreparationError, 'symlink|Symlink'):
                self.m.prepare(self.root)
        fetch.assert_not_called()
        (self.root / 'kernel').unlink()
        self.target.parent.mkdir(parents=True)
        self.target.symlink_to(outside_file)
        with mock.patch.object(self.m, 'urlopen') as fetch:
            with self.assertRaisesRegex(self.m.PreparationError, 'symlink|Symlink'):
                self.m.prepare(self.root)
        fetch.assert_not_called()
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(outside_file.read_bytes(), b'outside data\n')

    def test_invalid_destination_directory_is_not_removed(self):
        self.target.mkdir(parents=True)
        with mock.patch.object(self.m, 'urlopen') as fetch:
            with self.assertRaises(self.m.PreparationError):
                self.m.prepare(self.root)
        self.assertTrue(self.target.is_dir())
        fetch.assert_not_called()

    def test_cli_help_requires_no_source_or_network(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--help'],
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('--root', run.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
