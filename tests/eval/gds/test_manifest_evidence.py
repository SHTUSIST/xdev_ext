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

    def assert_stderr_admission(self, result, workload, diagnostic, expected):
        """Exercise actual main with actual-body output, changing only stderr."""
        module = runner()
        args = argparse.Namespace(cuda_root=self.root, directory=self.root, build_only=False,
            workload=workload, bytes=SIZE, chunk=CHUNK, iterations=ITERATIONS)
        controlled = copy.copy(result)
        controlled.stderr = diagnostic
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(module, 'arguments', return_value=args), \
             mock.patch.object(module, 'build', return_value=(self.binary, None)), \
             mock.patch.object(module.Path, 'exists', return_value=True), \
             mock.patch.object(module.subprocess, 'run', return_value=controlled), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(module.main(), expected)
        self.assertTrue(err.getvalue().startswith(diagnostic), 'stderr evidence was altered')
        if expected:
            self.assertEqual(out.getvalue(), '', 'invalid stderr was promoted to success')
            self.assertIn('GDS execution failed:', err.getvalue())
        else:
            self.assertEqual(err.getvalue(), diagnostic)
            self.assertEqual(len(out.getvalue().splitlines()), 1)
            self.assertEqual(json.loads(out.getvalue()), json.loads(result.stdout))

    def test_runner_accepts_json_whitespace_and_sdk_text_diagnostics(self):
        for workload in ('llm-load', 'checkpoint'):
            result, _ = self.execute(workload)
            self.assert_success(result)
            for prefix in ('', ' ', '\t', '\r', ' \t\r ', '\n \t\r\n \t'):
                with self.subTest(workload=workload, prefix=repr(prefix)):
                    diagnostic = ('cuFile: diagnostic text\n[WARN] optional SDK message\n'
                                  'NaN is diagnostic text here\n\n' + prefix +
                                  result.stderr.rstrip('\n') + ' \t\r\n'
                                  '  [INFO] cleanup complete\nSDK trailing text')
                    self.assert_stderr_admission(result, workload, diagnostic, 0)

    def test_runner_refuses_whitespace_hidden_extra_manifest_records(self):
        for workload in ('llm-load', 'checkpoint'):
            result, _ = self.execute(workload)
            self.assert_success(result)
            manifest = json.loads(result.stderr)
            wrong = copy.deepcopy(manifest)
            wrong['verification']['complete'] = False
            cases = dict(duplicate=result.stderr, contradictory=json.dumps(wrong) + '\n',
                truncated='{"kind":"gds-campaign-manifest"\n', empty_object='{}\n',
                duplicate_key=result.stderr.rstrip()[:-1] + ',"kind":"gds-campaign-manifest"}\n',
                nan=result.stderr.replace('"schema_version":1', '"schema_version":NaN'),
                trailing_garbage=result.stderr.rstrip() + ' truncated\n')
            self.assertNotEqual(cases['nan'], result.stderr, 'NaN mutation missed its field')
            for name, extra in cases.items():
                for prefix in ('', ' ', '\t', '\r', ' \t\r ', '\n \t\r\n \t'):
                    for before in (False, True):
                        with self.subTest(workload=workload, case=name, prefix=repr(prefix), before=before):
                            diagnostic = prefix + extra + result.stderr if before else result.stderr + prefix + extra
                            self.assert_stderr_admission(result, workload, diagnostic, 1)

    def test_runner_refuses_missing_truncated_and_nonobject_evidence(self):
        for workload in ('llm-load', 'checkpoint'):
            result, _ = self.execute(workload)
            self.assert_success(result)
            for diagnostic in ('', '\n \t\r\n', '[WARN] SDK diagnostics only\n',
                               ' \t' + result.stderr.rstrip('\n'),
                               ' \t{"kind":"gds-campaign-manifest"\n',
                               json.dumps(json.loads(result.stderr), indent=2) + '\n'):
                with self.subTest(workload=workload, missing_or_truncated=repr(diagnostic[:60])):
                    self.assert_stderr_admission(result, workload, diagnostic, 1)
            for scalar in ('[]', '[1,2]', '[' + result.stderr.rstrip() + ']',
                           '"gds-campaign-manifest"', 'true', 'false', 'null', '0', '1.25',
                           'NaN', 'Infinity', '-Infinity', '1e400', '[NaN]'):
                for diagnostic in (' \t' + scalar + '\n', result.stderr + ' \t' + scalar + '\n',
                                   ' \t' + scalar + '\n' + result.stderr):
                    with self.subTest(workload=workload, nonobject=scalar[:60], placement=diagnostic[:3]):
                        self.assert_stderr_admission(result, workload, diagnostic, 1)


if __name__ == '__main__':
    unittest.main()
