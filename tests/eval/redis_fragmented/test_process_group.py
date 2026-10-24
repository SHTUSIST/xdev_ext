#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent reviewer regressions; no production implementation changes."""
import ctypes
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

REVIEW = Path(__file__).resolve().parent
RUNNER = Path(__file__).resolve().with_name('run_redis_fragmented_eval.py')


class IndependentEdges(unittest.TestCase):
    def test_signals_reap_owned_server_and_publish_no_result(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(sig=sig), tempfile.TemporaryDirectory(
                    prefix='.rr-') as td:
                root = Path(td)
                marker = root / 'pid'
                fake = root / 'server'
                fake.write_text('#!/usr/bin/env python3\nimport os,time\n'
                    'from pathlib import Path\nPath(' + repr(str(marker)) +
                    ').write_text(str(os.getpid()))\ntime.sleep(30)\n')
                fake.chmod(0o700)
                scratch = root / 'scratch'
                scratch.mkdir()
                process = subprocess.Popen([
                    sys.executable, str(RUNNER), '--mode', 'correctness',
                    '--redis-server', str(fake), '--scratch-root', str(scratch),
                    '--output', str(root / 'result.json'), '--timeout', '10'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(marker.exists())
                    child = int(marker.read_text())
                    process.send_signal(sig)
                    stdout, stderr = process.communicate(timeout=10)
                    self.assertNotEqual(process.returncode, 0, stderr)
                    self.assertNotIn('PASS', stdout)
                    self.assertFalse((root / 'result.json').exists())
                    self.assertEqual(list(scratch.iterdir()), [])
                    with self.assertRaises(ProcessLookupError):
                        os.kill(child, 0)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5)

    def test_existing_result_is_preserved_without_launching_server(self):
        with tempfile.TemporaryDirectory(prefix='.rr-') as td:
            root = Path(td)
            marker = root / 'launched'
            fake = root / 'server'
            fake.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\n'
                'Path(' + repr(str(marker)) + ').write_text("bad")\n')
            fake.chmod(0o700)
            output = root / 'result.json'
            original = b'previous result\x00\xff'
            output.write_bytes(original)
            result = subprocess.run([
                sys.executable, str(RUNNER), '--mode', 'correctness',
                '--redis-server', str(fake), '--output', str(output)],
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), original)
            self.assertFalse(marker.exists())

    def test_relative_scratch_root_runs_real_redis(self):
        with tempfile.TemporaryDirectory(prefix='.rr-') as td:
            root = Path(td)
            (root / 'scratch').mkdir()
            result = subprocess.run([
                sys.executable, str(RUNNER), '--mode', 'correctness',
                '--redis-server', shutil.which('redis-server'),
                '--scratch-root', 'scratch', '--output', str(root / 'result.json'),
                '--timeout', '1'], cwd=root, capture_output=True, text=True,
                timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((root / 'result.json').is_file())

    def test_term_resistant_owned_descendant_is_cleaned(self):
        # Reap our orphaned test grandchild ourselves after observing the runner.
        self.assertEqual(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0), 0)
        descendant = None
        try:
            with tempfile.TemporaryDirectory(prefix='.rr-') as td:
                root = Path(td)
                marker = root / 'descendant.pid'
                fake = root / 'server'
                fake.write_text(
                    '#!/usr/bin/env python3\n'
                    'import os,signal,time\n'
                    'from pathlib import Path\n'
                    'pid=os.fork()\n'
                    'if pid==0:\n'
                    ' signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
                    ' Path(' + repr(str(marker)) + ').write_text(str(os.getpid()))\n'
                    ' time.sleep(30)\n'
                    'else:\n'
                    ' time.sleep(30)\n')
                fake.chmod(0o700)
                scratch = root / 'scratch'
                scratch.mkdir()
                result = subprocess.run([
                    sys.executable, str(RUNNER), '--mode', 'correctness',
                    '--redis-server', str(fake), '--scratch-root', str(scratch),
                    '--output', str(root / 'result.json'), '--timeout', '0.3'],
                    capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'result.json').exists())
                self.assertEqual(list(scratch.iterdir()), [])
                self.assertTrue(marker.exists(), result.stderr)
                descendant = int(marker.read_text())
                try:
                    state = Path(f'/proc/{descendant}/stat').read_text().rsplit(')', 1)[1].split()[0]
                except FileNotFoundError:
                    state = None
                self.assertIn(state, (None, 'Z'),
                    'owned descendant survived runner cleanup in state ' + str(state))
        finally:
            if descendant is not None:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(descendant, 0)
                except ChildProcessError:
                    pass


if __name__ == '__main__':
    unittest.main(verbosity=2)
