#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""main() I/O boundary regressions. No module is loaded, no runtime evidence.

Loader/sysfs documents here are controlled I/O inputs, not a benchmark backend.
The assertions exercise request attribution and final result publication only.
"""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('provenance_target', HERE / 'run.py')
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)
spec = importlib.util.spec_from_file_location('provenance_fixture', HERE / 'test_run.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
SYSTEM_MODULE = '/sys/module/lifecycle_bench'
SYSTEM_RESULT = '/sys/kernel/debug/xdev_lifecycle_bench/result'


class MainProvenance(unittest.TestCase):
    def invoke(self, *, request_mode='check', request_n=8, report_mode=None,
               report_n=8, existing=None, module_name='lifecycle_bench',
               wrong_nonce=False, unload_status='ok', load_status='ok',
               resources_survive=False, reuse_output=False, invalid_document=False,
               wrong_sysfs_nonce=False, unload_exception=False):
        original_read, original_exists = Path.read_text, Path.exists
        real_check_output = subprocess.check_output
        calls, output = [], io.StringIO()
        state = dict(loaded=False, nonce='', eligible_at_unload=None)
        sha = real_check_output(['git', '-C', str(HERE), 'rev-parse', 'HEAD'], text=True).strip()
        with tempfile.TemporaryDirectory(prefix='.provenance-', dir=HERE) as tmp:
            tmp = Path(tmp)
            module = tmp / 'lifecycle_bench.ko'
            module.write_bytes(b'I/O boundary input only, not a Linux module')
            out = tmp / 'out'
            prior = dict(status='ok', performance_eligible=True, evidence='prior-run')
            if reuse_output:
                out.mkdir()
                (out / 'result.json').write_text(json.dumps(prior))
            def exists(path):
                name = str(path)
                if name in (SYSTEM_MODULE, SYSTEM_RESULT, str(Path(SYSTEM_RESULT).parent)):
                    return state['loaded'] or existing == name
                return original_exists(path)
            def read(path, *args, **kwargs):
                name = str(path)
                if name == SYSTEM_RESULT:
                    if invalid_document:
                        return '[]'
                    value = fixture.report_fixture(report_mode or request_mode)
                    value.update(exact_sha=sha, lifecycle_header_sha256=run.hashlib.sha256(
                        (HERE.parents[2] / 'kernel/io_uring/xdev_ext_mech_lifecycle.h').read_bytes()).hexdigest(),
                        kernel_runtime=True, evidence_kind='kernel-runtime', iterations=report_n,
                        run_nonce='stale-nonce' if wrong_nonce else state['nonce'])
                    return json.dumps(value)
                if name.startswith(SYSTEM_MODULE + '/parameters/'):
                    field = path.name
                    return dict(run_nonce='other-instance' if wrong_sysfs_nonce else state['nonce'], mode=request_mode,
                                iterations=str(request_n))[field] + '\n'
                return original_read(path, *args, **kwargs)
            def check_output(argv, **kwargs):
                if argv[0] == 'modinfo':
                    return module_name + '\n'
                if argv[0] == 'git' and 'status' in argv:
                    return ''  # isolate source cleanliness from this regression
                return real_check_output(argv, **kwargs)
            def command(argv, output_dir):
                calls.append(list(argv))
                if argv[0] == 'insmod':
                    state['nonce'] = next((a.split('=', 1)[1] for a in argv if a.startswith('run_nonce=')), '')
                    status = load_status
                    state['loaded'] = status == 'ok'
                elif argv[0] == 'rmmod':
                    if unload_exception:
                        raise ValueError('loader receipt could not be decoded')
                    result_path = out / 'result.json'
                    state['eligible_at_unload'] = (json.loads(original_read(result_path)).get('performance_eligible')
                                                   if original_exists(result_path) else False)
                    status = unload_status
                    if status == 'ok' and not resources_survive:
                        state['loaded'] = False
                else:
                    raise AssertionError('unexpected execution boundary ' + repr(argv))
                return dict(argv=list(argv), status=status, returncode=0 if status == 'ok' else 1,
                            performance_eligible=False)
            with patch.object(run, 'execute_command', command), \
                 patch.object(run, 'detected_environment', lambda: dict(kind='physical', physical=True, hypervisor=False)), \
                 patch.object(Path, 'read_text', read), patch.object(Path, 'exists', exists), \
                 patch.object(subprocess, 'check_output', check_output), contextlib.redirect_stdout(output):
                try:
                    rc = run.main(['--execute', '--mode', request_mode, '--iterations', str(request_n),
                                   '--module', str(module), '--output', str(out)])
                except ValueError:
                    rc = None  # asserted below: main must finalize teardown errors
            result = json.loads((out / 'result.json').read_text()) if (out / 'result.json').exists() else None
            raw = json.loads((out / 'raw-report.json').read_text()) if (out / 'raw-report.json').exists() else None
            return dict(rc=rc, calls=calls, result=result, raw=raw, state=state, stdout=output.getvalue(), prior=prior)

    def test_requested_mode_must_match_report(self):
        value = self.invoke(request_mode='check', report_mode='time')
        self.assertNotEqual(value['rc'], 0)
        self.assertFalse(value['result']['performance_eligible'])
        self.assertIn('mode', ' '.join(value['result']['validation_errors']))

    def test_requested_iterations_must_match_report(self):
        value = self.invoke(request_n=3)
        self.assertNotEqual(value['rc'], 0)
        self.assertIn('iterations', ' '.join(value['result']['validation_errors']))

    def test_existing_module_or_debugfs_is_rejected_without_loading(self):
        for resource in (SYSTEM_MODULE, SYSTEM_RESULT, str(Path(SYSTEM_RESULT).parent)):
            with self.subTest(resource=resource):
                value = self.invoke(existing=resource)
                self.assertNotEqual(value['rc'], 0)
                self.assertEqual(value['calls'], [])

    def test_unrelated_module_name_is_rejected_before_insmod(self):
        value = self.invoke(module_name='unrelated_module')
        self.assertNotEqual(value['rc'], 0)
        self.assertEqual(value['calls'], [])

    def test_new_module_nonce_must_match_debugfs_producer(self):
        value = self.invoke(wrong_nonce=True)
        self.assertNotEqual(value['rc'], 0)
        self.assertIn('nonce', ' '.join(value['result']['validation_errors']))
        self.assertTrue(value['state']['nonce'])
        self.assertIsNotNone(value['raw'])

    def test_unload_failure_invalidates_final_result_and_keeps_raw(self):
        value = self.invoke(request_mode='time', unload_status='failed')
        self.assertNotEqual(value['rc'], 0)
        self.assertFalse(value['result']['performance_eligible'])
        self.assertEqual(value['result']['status'], 'failed')
        self.assertIn('unload', ' '.join(value['result']['validation_errors']))
        self.assertEqual(value['raw']['status'], 'ok')

    def test_unload_success_with_surviving_resources_still_fails(self):
        value = self.invoke(resources_survive=True)
        self.assertNotEqual(value['rc'], 0)
        self.assertIn('teardown', ' '.join(value['result']['validation_errors']))

    def test_success_is_only_sealed_after_unload(self):
        value = self.invoke(request_mode='time')
        self.assertEqual(value['rc'], 0)
        self.assertFalse(value['state']['eligible_at_unload'])
        self.assertTrue(value['result']['performance_eligible'])
        self.assertTrue(value['result']['sealed'])

    def test_reused_output_is_refused_and_prior_evidence_untouched(self):
        value = self.invoke(reuse_output=True, load_status='failed')
        self.assertNotEqual(value['rc'], 0)
        self.assertEqual(value['calls'], [])
        self.assertEqual(value['result'], value['prior'])
        self.assertIn('output', value['stdout'])

    def test_unverified_sysfs_producer_is_retained_without_rmmod(self):
        value = self.invoke(wrong_sysfs_nonce=True)
        self.assertNotEqual(value['rc'], 0)
        self.assertFalse(any(argv[0] == 'rmmod' for argv in value['calls']))
        self.assertIn('unknown', ' '.join(value['result']['validation_errors']))
        self.assertFalse(value['result']['performance_eligible'])

    def test_malformed_report_never_seals_success_and_is_preserved(self):
        value = self.invoke(invalid_document=True)
        self.assertNotEqual(value['rc'], 0)
        self.assertEqual(value['raw'], [])
        self.assertEqual(value['result']['status'], 'failed')
        self.assertFalse(value['result']['sealed'])

    def test_unload_exception_still_writes_final_failure(self):
        value = self.invoke(request_mode='time', unload_exception=True)
        self.assertIsNotNone(value['rc'], 'unload exception escaped without finalizing receipt')
        self.assertNotEqual(value['rc'], 0)
        self.assertEqual(value['result']['status'], 'failed')
        self.assertIn('unload', ' '.join(value['result']['validation_errors']))
        self.assertFalse(value['result']['performance_eligible'])

    def test_fresh_failed_load_has_final_failure_receipt(self):
        value = self.invoke(load_status='failed')
        self.assertNotEqual(value['rc'], 0)
        self.assertIsNotNone(value['result'], 'failed load must emit a final failure receipt')
        self.assertEqual(value['result']['status'], 'failed')
        self.assertFalse(value['result']['performance_eligible'])


if __name__ == '__main__':
    unittest.main()
