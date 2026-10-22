#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Mutate actual call-shape outputs; a success marker alone is insufficient."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert (HERE / 'run.py').exists(), 'missing application call-shape runner'
        spec = importlib.util.spec_from_file_location('apps_run', HERE / 'run.py')
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)
        cls.temp = tempfile.TemporaryDirectory(prefix='apps-contract-', dir=HERE / 'build')
        cls.work = Path(cls.temp.name)
        cls.runner.run_suite(cls.work)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_whole_file_corruption_and_truncation(self):
        expected = (self.work / 'db-libc.db').read_bytes()
        actual = bytearray(expected)
        actual[len(actual) // 2] ^= 1
        with self.assertRaises(ValueError):
            self.runner.equal_bytes(expected, bytes(actual), 'corrupt file')
        with self.assertRaises(ValueError):
            self.runner.equal_bytes(expected, expected[:-1], 'short file')

    def test_missing_and_wrong_counter(self):
        report = (self.work / 'udp-model.err').read_text()
        self.runner.validate_counts(report, {'custom_send_count': 3, 'custom_send_bytes': 25})
        with self.assertRaises(ValueError):
            self.runner.validate_counts('', {'custom_send_count': 3})
        with self.assertRaises(ValueError):
            self.runner.validate_counts(report.replace('custom_send_count=3', 'custom_send_count=2'),
                                        {'custom_send_count': 3})
        with self.assertRaises(ValueError):
            self.runner.validate_counts(report + report, {'custom_send_count': 3})

    def test_fallback_cannot_be_called_acceleration(self):
        report = (self.work / 'fallback-model.err').read_text()
        self.runner.validate_model(report, {'read_sqes': 0, 'write_sqes': 0, 'send_sqes': 0})
        with self.assertRaises(ValueError):
            self.runner.validate_counts(report, {'custom_send_count': 1})
        with self.assertRaises(ValueError):
            self.runner.validate_model(report.replace('send_sqes=0', 'send_sqes=1'),
                                       {'send_sqes': 0})

    def test_db_trace_and_counters(self):
        baseline = (self.work / 'db-libc.out').read_text()
        taken = (self.work / 'db-model.out').read_text()
        report = (self.work / 'db-model.err').read_text()
        self.runner.validate_db(baseline, taken, report)
        with self.assertRaises(ValueError):
            self.runner.validate_db(baseline, taken.replace('trace=', 'trace=0'), report)
        with self.assertRaises(ValueError):
            self.runner.validate_db(baseline, taken, report.replace('read_count=', 'missing_read_count='))

    def test_nonzero_exit_rejected(self):
        with self.assertRaises(ValueError):
            self.runner.check_exit(1, 'XDEV_EXT_APP_FALLBACK=PASS')


if __name__ == '__main__':
    unittest.main(verbosity=2)
