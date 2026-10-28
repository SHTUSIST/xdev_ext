# SPDX-License-Identifier: GPL-2.0
"""Raw completion observations cannot override actual driver process failure."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[4]
RUNNER = ROOT / 'tests/benchmarks/tp/run.py'


class DriverProcessTest(unittest.TestCase):
    def records(self):
        return [dict(record='validation', sequence=23, rank=0, direction='rx',
                     payload_bytes=4, valid=True),
                dict(record='interval', start=100, end=190, rank=0, clock=1,
                     kind='rtt', completed=True, custody_released=True),
                dict(record='metadata', execution_kind='echo', rank=0, clock=1,
                     completed=1, communicator=7, epoch=9, group_bytes=4,
                     native_mode=2, handoff_mode='gpu')]

    def fixture(self, directory, outcome):
        raw_text = ''.join(json.dumps(record) + '\n' for record in self.records())
        driver = directory / 'software-driver'
        driver.write_text('#!' + sys.executable + '\n'
                          'import signal, sys\n'
                          'sys.stdout.write(' + repr(raw_text) + ')\n'
                          'sys.stdout.flush()\n' + outcome + '\n')
        driver.chmod(0o700)
        raw, summary = directory / 'raw.jsonl', directory / 'summary.json'
        command = [sys.executable, str(RUNNER), '--driver', str(driver),
                   '--raw', str(raw), '--summary', str(summary)]
        environment = dict(os.environ)
        # These tests execute only the tiny software fixture, never a CUDA SDK,
        # link stub or actual benchmark. Do not inherit unrelated loader paths.
        environment.pop('LD_LIBRARY_PATH', None)
        return command, environment, raw, summary, raw_text

    def assert_raw_complete(self, raw, expected):
        self.assertEqual(raw.read_text(), expected)
        # Prove it really is otherwise acceptable full raw input; malformed
        # fixtures must not make the late-process gate look effective.
        spec = importlib.util.spec_from_file_location('late_driver_runner', RUNNER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.analyze_file(raw)
        self.assertEqual(result['host_intervals'][0]['duration_ns'], 90)

    def test_complete_raw_then_late_driver_error_preserves_raw_without_summary(self):
        with tempfile.TemporaryDirectory() as name:
            command, environment, raw, summary, expected = self.fixture(
                Path(name), 'sys.exit(17)')
            result = subprocess.run(command, env=environment, text=True,
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 17)
            self.assert_raw_complete(raw, expected)
            self.assertFalse(summary.exists(), 'nonzero driver cannot publish summary')
            self.assertEqual(result.stdout, '', 'failure cannot publish qualification receipt')

    def test_timeout_after_complete_raw_cannot_publish_summary(self):
        with tempfile.TemporaryDirectory() as name:
            command, environment, raw, summary, expected = self.fixture(
                Path(name), 'signal.pause()')
            # This software-only process group allows deterministic host cleanup
            # after an external timeout. Killing a process is never a proof of
            # device quiescence, native custody release or successful teardown.
            process = subprocess.Popen(command, env=environment, text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if raw.exists() and raw.stat().st_size == len(expected.encode()):
                        break
                    self.assertIsNone(process.poll(), 'driver must remain live after full raw')
                    time.sleep(0.01)
                self.assert_raw_complete(raw, expected)
                self.assertIsNone(process.poll())
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.communicate(timeout=0.1)
                self.assertFalse(summary.exists(), 'live/timed out driver cannot publish summary')
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            self.assert_raw_complete(raw, expected)
            self.assertFalse(summary.exists(), 'timeout cleanup is not successful driver exit')
            self.assertEqual(stdout, '', 'timeout cannot publish qualification receipt')


if __name__ == '__main__':
    unittest.main()
