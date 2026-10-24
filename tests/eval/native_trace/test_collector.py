#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Collector admission contracts; actual subprocesses must remain unstarted.

Temporary directories represent missing tracing interfaces, not virtual DMA
devices. No test output is admissible as a physical performance result.
"""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


class CollectorAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-trace-admission-')
        self.directory = Path(self.temp.name)
        self.marker = self.directory / 'workload-started'
        self.command = [sys.executable, '-c',
                        'from pathlib import Path; import sys; Path(sys.argv[1]).touch()',
                        str(self.marker)]

    def tearDown(self):
        self.temp.cleanup()

    def collector(self):
        entry = HERE / 'collector.py'
        self.assertTrue(entry.is_file(), 'real native trace collector is not implemented')
        spec = importlib.util.spec_from_file_location('native_trace_collector', entry)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def manifest(self, arm='K-BPF'):
        return {
            'schema_version': 1, 'run_id': 'collector-admission-only', 'arm': arm,
            'environment': 'host-contract', 'evidence_kind': 'fixture',
            'physical': False, 'correctness_pass': False,
            'clock': 'CLOCK_MONOTONIC', 'clock_domain': 'local-host',
            'trace': {'clock': 'CLOCK_MONOTONIC', 'clock_domain': 'local-host',
                      'required_events': ['record_admit', 'native_submit',
                                          'native_complete', 'record_terminal'],
                      'record_mapping': 'batch_key_div_burst', 'burst': 1},
        }

    def collect(self, manifest):
        return self.collector().collect(manifest, self.command, self.directory / 'out',
                                        tracefs_root=self.directory / 'missing-tracefs')

    def assert_refused(self, result, reason):
        self.assertEqual(result['status'], 'unavailable')
        self.assertIs(result['performance_eligible'], False)
        self.assertFalse(self.marker.exists(), 'workload ran despite unavailable native probes')
        self.assertIn(reason, ' '.join(result['reasons']).lower())
        self.assertIsInstance(result['artifacts'], dict)
        # A rejection may retain metadata, but cannot fabricate a capture.
        self.assertNotIn('raw_trace', result['artifacts'])

    def test_missing_tracefs_never_starts_workload_or_creates_raw_evidence(self):
        self.assert_refused(self.collect(self.manifest()), 'trace')

    def test_user_cqe_observation_does_not_satisfy_native_completion_probe(self):
        manifest = self.manifest('U-poll')
        # These assertions must not bypass probe/cookie/clock verification.
        manifest.update(physical=True, correctness_pass=True)
        manifest['trace']['available_events'] = ['record_admit', 'user_observe',
                                                  'native_submit', 'record_terminal']
        manifest['trace']['user_observe_is_native_complete'] = True
        self.assert_refused(self.collect(manifest), 'native')

    def test_raw_clock_is_refused_before_workload_not_subtracted_from_kernel_mono(self):
        manifest = self.manifest()
        manifest['clock'] = 'CLOCK_MONOTONIC_RAW'
        manifest['trace']['clock'] = 'CLOCK_MONOTONIC_RAW'
        self.assert_refused(self.collect(manifest), 'clock')


if __name__ == '__main__':
    unittest.main()
