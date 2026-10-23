#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""A phase marker cannot replace a serialized, validated campaign manifest."""
import argparse
import contextlib
import copy
import io
import json
import unittest
from unittest import mock
import test_campaign_timing as frozen
from test_campaign_timing import SIZE, CHUNK, ITERATIONS, HISTORY_BYTES, OPERATIONS, runner


class ManifestEvidenceTests(frozen.ActualCampaignBodyTests):
    def test_manifest_contains_observed_data_identity_and_full_verification(self):
        for workload in ('llm-load', 'checkpoint'):
            with self.subTest(workload=workload):
                result, _ = self.execute(workload)
                self.assert_success(result)
                rows = [json.loads(line) for line in result.stderr.splitlines() if line.startswith('{')]
                self.assertEqual(len(rows), 1, 'one real manifest must be serialized after the campaign')
                manifest = rows[0]
                self.assertEqual(manifest['kind'], 'gds-campaign-manifest')
                self.assertEqual(manifest['geometry'], dict(bytes=SIZE, chunk=CHUNK, iterations=ITERATIONS,
                    operations=OPERATIONS, history_bytes=HISTORY_BYTES, guard_bytes=4096))
                self.assertEqual(manifest['input'], dict(id='deterministic-pattern-v1',
                    formula='(index*37+index/251+iteration*53)%256', index_window=[0,SIZE],
                    iteration_window=[0,ITERATIONS]))
                self.assertEqual(manifest['verification'], dict(phase='post-campaign',
                    payload_bytes=SIZE*ITERATIONS, device_history_bytes=HISTORY_BYTES,
                    file_bytes=SIZE*ITERATIONS if workload=='checkpoint' else 0,
                    device_equal=True, file_equal=True, complete=True))
                self.assertEqual(manifest['workload'], workload)
                # Independently generate the complete memory layout. The digest
                # identifies observed bytes, but never replaces byte comparison.
                expected=bytearray([0xa5])*HISTORY_BYTES
                slot=CHUNK+8192
                for iteration in range(ITERATIONS):
                    for offset in range(0,SIZE,CHUNK):
                        base=(iteration*((SIZE+CHUNK-1)//CHUNK)+offset//CHUNK)*slot+4096
                        for j in range(min(CHUNK,SIZE-offset)):
                            index=offset+j
                            expected[base+j]=(index*37+index//251+iteration*53)%256
                value=14695981039346656037
                for byte in expected:
                    value=((value^byte)*1099511628211)&((1<<64)-1)
                self.assertEqual(manifest['observed_history_fnv1a64'], f'{value:016x}')
                check=getattr(runner(), 'checked_manifest', None)
                self.assertTrue(callable(check), 'runner must validate the actual manifest')
                record=json.loads(result.stdout)
                self.assertEqual(check(result.stderr, record), manifest)
                for field, value in [('observed_history_fnv1a64','0'*16), ('workload','other')]:
                    invalid=copy.deepcopy(manifest);invalid[field]=value
                    with self.assertRaises(ValueError):check(json.dumps(invalid)+'\n',record)
                for field in ('input','geometry','verification'):
                    invalid=copy.deepcopy(manifest);del invalid[field]
                    with self.assertRaises(ValueError):check(json.dumps(invalid)+'\n',record)
                for bad in ('', result.stderr+result.stderr):
                    with self.assertRaises(ValueError):check(bad, record)

    def test_runner_requires_manifest_before_relaying_actual_result(self):
        result, _ = self.execute()
        self.assert_success(result)
        module = runner()
        args = argparse.Namespace(cuda_root=self.root, directory=self.root, build_only=False,
            workload='llm-load', bytes=SIZE, chunk=CHUNK, iterations=ITERATIONS)
        for diagnostic, expected in ((result.stderr, 0), ('', 1)):
            with self.subTest(has_manifest=bool(diagnostic)):
                controlled = copy.copy(result);controlled.stderr=diagnostic
                out, err = io.StringIO(), io.StringIO()
                with mock.patch.object(module, 'arguments', return_value=args), \
                     mock.patch.object(module, 'build', return_value=(self.binary, None)), \
                     mock.patch.object(module.Path, 'exists', return_value=True), \
                     mock.patch.object(module.subprocess, 'run', return_value=controlled), \
                     contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(module.main(), expected)
                if expected:
                    self.assertEqual(out.getvalue(), '', 'missing manifest was promoted to success')
                else:
                    self.assertEqual(json.loads(out.getvalue()), json.loads(result.stdout))
                    self.assertIn('gds-campaign-manifest', err.getvalue())

    def test_failed_byte_validation_never_emits_manifest_or_success(self):
        result, _ = self.execute(fault='payload-first')
        self.assert_failure_without_success(result)
        self.assertNotIn('gds-campaign-manifest', result.stderr)


if __name__ == '__main__':
    unittest.main()
