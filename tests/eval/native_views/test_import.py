"""Supplemental import negatives; fixture never becomes physical evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from fixtures.builders import run_fixture, record_events
import analyze


class ImportEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.native-import-', dir=ROOT)
        self.directory = Path(self.temp.name)
        self.run = run_fixture()
        self.receipt = dict(status='ok', returncode=0, artifacts={})

    def tearDown(self):
        self.temp.cleanup()

    def artifact(self, kind, data):
        path = self.directory / kind
        path.write_text(data)
        self.receipt['artifacts'][kind] = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    def call(self):
        self.assertTrue(callable(getattr(analyze, 'import_collection', None)), 'missing real raw artifact importer')
        return analyze.import_collection(self.run, self.receipt)

    def test_missing_files_not_certified(self):
        result = self.call()
        self.assertFalse(result['performance_eligible'])
        self.assertEqual(result['status'], 'unavailable')
        self.assertIn('events', ' '.join(result['errors']))
        self.assertIn('oracle', ' '.join(result['errors']))

    def test_bad_hash_not_accepted(self):
        self.artifact('events', '')
        self.receipt['artifacts']['events']['sha256'] = '0' * 64
        result = self.call()
        self.assertIn('sha256', ' '.join(result['errors']))

    def test_foreign_run_metadata_rejected(self):
        self.artifact('trace_metadata', json.dumps(dict(run_id='foreign')))
        self.assertIn('run_id', ' '.join(self.call()['errors']))

    def test_workload_failure_preserved(self):
        self.receipt.update(status='failed', returncode=7)
        self.assertIn('failed', ' '.join(self.call()['errors']))

    def test_cpu_sampling_includes_every_cpu_and_rejects_missing_cpu(self):
        self.artifact('system_cpu_before', 'cpu 10 0 4 100 0 0 1 0 0 0\ncpu0 5 0 2 50 0 0 0 0 0 0\ncpu1 5 0 2 50 0 0 1 0 0 0\n')
        self.artifact('system_cpu_after', 'cpu 12 0 6 100 0 0 2 0 0 0\ncpu0 6 0 3 50 0 0 0 0 0 0\n')
        self.assertIn('cpu', ' '.join(self.call()['errors']).lower())

    def test_cpu_raw_ticks_produce_integer_nanoseconds(self):
        self.artifact('trace_metadata', json.dumps(dict(cpu_tick_hz=100)))
        self.artifact('system_cpu_before', 'cpu 10 0 4 100 0 0 1 0 0 0\ncpu0 10 0 4 100 0 0 1 0 0 0\n')
        self.artifact('system_cpu_after', 'cpu 12 0 6 100 0 0 2 0 0 0\ncpu0 12 0 6 100 0 0 2 0 0 0\n')
        result = self.call()
        self.assertEqual(result['manifest']['total_cpu_ns'], 50_000_000)
        self.assertIs(type(result['manifest']['total_cpu_ns']), int)
        self.assertFalse(result['performance_eligible'])

    def test_cpu_paired_bounds_use_cross_endpoints_and_unknown_stays_unknown(self):
        left, right = run_fixture(), run_fixture('K-BPF')
        for run, lower, upper in ((left, 10, 40), (right, 20, 60)):
            run['total_cpu_ns'] = None
            run['total_cpu_ns_bounds'] = dict(lower=lower, upper=upper)
            run['metrics']['cpu_ns_per_record'] = None
            run['metrics']['cpu_ns_per_record_bounds'] = dict(lower=lower, upper=upper)
        result = analyze.compare_runs(left, right)
        self.assertTrue(result['eligible'], result['errors'])
        self.assertIsNone(result['delta']['cpu_ns_per_record'])
        self.assertEqual(result['delta']['cpu_ns_per_record_bounds'], dict(lower=-20, upper=50))
        paired = analyze.compare_pairs([(left, right)])
        self.assertEqual(paired['mean_delta']['cpu_ns_per_record_bounds'], dict(lower=-20, upper=50))
        right['metrics']['cpu_ns_per_record_bounds'] = None
        self.assertIsNone(analyze.compare_runs(left, right)['delta']['cpu_ns_per_record_bounds'])

    def test_failed_oracle_is_not_pass(self):
        self.artifact('oracle', json.dumps(dict(schema='xdev-chain-campaign-v1', correctness_only=False,
            rows=[dict(result=dict(status='fail'))])))
        self.assertIn('oracle', ' '.join(self.call()['errors']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
