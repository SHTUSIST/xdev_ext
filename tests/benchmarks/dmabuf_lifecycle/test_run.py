#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent module runner/report contracts. No insmod, VM, or device I/O."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ENTRY = HERE / 'run.py'


def target():
    assert ENTRY.is_file(), 'missing actual dma_fence lifecycle run.py'
    spec = importlib.util.spec_from_file_location('dma_lifecycle_runner_target', ENTRY)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def report_fixture(mode='check'):
    """Schema/parser fixture, not module output and never eligible performance."""
    arms = {}
    for arm in ('life', 'dma_fence'):
        arms[arm] = dict(attempted=8, successful=8, produced=8, consumed=8,
                         recycled=8, valid_len_checks=8, errors=0,
                         allocations_setup=1, allocations_steady=0,
                         cleanup_complete=True)
    arms['dma_fence'].update(fence_objects=16, fence_releases=16)
    value = dict(schema_version=1, experiment_kind='kernel_sync_primitive',
                 mode=mode, status='ok', iterations=8, exact_sha='a' * 40,
                 lifecycle_header_sha256='b' * 64, module_sha256='c' * 64,
                 kernel_release='fixture-kernel', environment=dict(kind='fixture',
                 hypervisor=False, physical=False), execution_context='serial-process',
                 kernel_runtime=False, evidence_kind='fixture', oracle_in_timing=False,
                 oracle_checked_operations=16, arms=arms,
                 checks={name: 'pass' for name in ('two_phase', 'signal_before_add',
                         'identity', 'duplicates', 'held_reference', 'independent_frames',
                         'allocation_failure', 'callback_failure', 'teardown')},
                 concurrent_check=dict(executed=False, contexts=0))
    if mode == 'time':
        value['timing'] = {arm: dict(prepare_ns=100, completion_ns=200,
                                    full_cycle_ns=320, allocation_ns=1000,
                                    callback_registration='prepare',
                                    denominator=8) for arm in arms}
    return value


class ResultContract(unittest.TestCase):
    def test_fixture_can_parse_but_cannot_claim_kernel_performance(self):
        api = target()
        report = report_fixture()
        self.assertEqual(api.validate_result(report), [])
        self.assertTrue(api.validate_result(report, performance=True))

    def test_t1_two_arms_require_equal_success_and_complete_oracle(self):
        api = target()
        for field in ('successful', 'produced', 'consumed', 'recycled', 'valid_len_checks'):
            with self.subTest(field=field):
                report = report_fixture()
                report['arms']['dma_fence'][field] = 7
                self.assertIn(field, ' '.join(api.validate_result(report)))
        report = report_fixture()
        report['oracle_checked_operations'] = 15
        self.assertIn('oracle', ' '.join(api.validate_result(report)))

    def test_t1_not_dma_buf_end_to_end_and_cannot_hide_failed_check(self):
        report = report_fixture()
        report['experiment_kind'] = 'dma_buf_end_to_end'
        self.assertIn('experiment_kind', ' '.join(target().validate_result(report)))
        report = report_fixture()
        report['checks']['two_phase'] = 'failed'
        self.assertIn('two_phase', ' '.join(target().validate_result(report)))

    def test_t5_host_or_serial_check_cannot_claim_two_kernel_contexts(self):
        report = report_fixture()
        report['concurrent_check'] = dict(executed=True, contexts=2)
        self.assertIn('kernel_runtime', ' '.join(target().validate_result(report)))
        report = report_fixture()
        report['concurrent_check'] = dict(executed=True, contexts=1)
        self.assertIn('contexts', ' '.join(target().validate_result(report)))

    def test_t6_injected_error_cannot_emit_successful_timing(self):
        api = target()
        for arm in ('life', 'dma_fence'):
            report = report_fixture('time')
            report['arms'][arm]['errors'] = 1
            report['arms'][arm]['successful'] = 7
            errors = ' '.join(api.validate_result(report))
            self.assertIn('errors', errors)
            self.assertIn('successful', errors)
        report = report_fixture('time')
        report['timing']['dma_fence']['denominator'] = 9
        self.assertIn('denominator', ' '.join(api.validate_result(report)))

    def test_t7_check_mode_rejects_ns_and_ratio_results(self):
        api = target()
        for key, value in (('timing', report_fixture('time')['timing']),
                           ('ratio', 3.0), ('ns_per_operation', 4.0)):
            report = report_fixture()
            report[key] = value
            self.assertIn('check', ' '.join(api.validate_result(report)).lower())

    def test_t7_time_environment_rejects_vm_even_with_override_physical_flag(self):
        api = target()
        for environment in (dict(kind='vm', physical=True, hypervisor=True),
                            dict(kind='fixture', physical=True, hypervisor=False),
                            dict(kind='unknown', physical=False, hypervisor=False)):
            self.assertTrue(api.admit_environment('time', environment))
        self.assertEqual(api.admit_environment('check', dict(kind='vm', physical=False,
                                                            hypervisor=True)), [])

    def test_t8_all_references_and_callbacks_must_be_drained(self):
        api = target()
        report = report_fixture()
        report['arms']['dma_fence']['fence_releases'] = 15
        self.assertIn('fence_releases', ' '.join(api.validate_result(report)))
        report = report_fixture()
        report['arms']['life']['cleanup_complete'] = False
        self.assertIn('cleanup_complete', ' '.join(api.validate_result(report)))

    def test_time_includes_prepare_completion_full_cycle_and_separate_allocation(self):
        api = target()
        for key in ('prepare_ns', 'completion_ns', 'full_cycle_ns', 'allocation_ns'):
            report = report_fixture('time')
            del report['timing']['life'][key]
            self.assertIn(key, ' '.join(api.validate_result(report)))
        report = report_fixture('time')
        report['arms']['dma_fence']['allocations_steady'] = 8
        self.assertIn('allocations_steady', ' '.join(api.validate_result(report)))

    def test_full_oracle_stays_outside_timed_region(self):
        report = report_fixture('time')
        report['oracle_in_timing'] = True
        self.assertIn('oracle_in_timing', ' '.join(target().validate_result(report)))

    def test_exact_source_header_module_and_running_kernel_are_required(self):
        api = target()
        for key in ('exact_sha', 'lifecycle_header_sha256', 'module_sha256', 'kernel_release'):
            report = report_fixture()
            del report[key]
            self.assertIn(key, ' '.join(api.validate_result(report)))


class RunnerContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.runner-contract-', dir=HERE)
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *extra):
        self.assertTrue(ENTRY.is_file(), 'missing safe actual kernel benchmark runner')
        return subprocess.run([sys.executable, str(ENTRY), '--mode', 'check',
                               '--module', str(self.directory / 'unbuilt.ko'),
                               '--output', str(self.directory / 'out'), *extra],
                              capture_output=True, text=True, timeout=15)

    def test_t7_invalid_iterations_rejected_before_any_execution(self):
        for value in ('0', '-1', '65537', '999999999999999999999999', '1.5'):
            with self.subTest(value=value):
                result = self.invoke('--iterations', value, '--dry-run')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.directory / 'out').exists())

    def test_t7_unknown_mode_rejected(self):
        result = self.invoke('--mode', 'benchmark', '--iterations', '8', '--dry-run')
        self.assertNotEqual(result.returncode, 0)

    def test_dry_run_is_nonexecuting_and_reports_mode(self):
        result = self.invoke('--iterations', '8', '--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['status'], 'dry-run')
        self.assertEqual(receipt['mode'], 'check')
        self.assertFalse(receipt['kernel_runtime'])
        self.assertFalse(receipt['performance_eligible'])
        self.assertFalse((self.directory / 'out').exists())

    def test_no_implicit_insmod_without_explicit_execute(self):
        # Fail closed at process/network boundary if an unapproved default path
        # ever tries to start tools. No command is patched to pretend success.
        self.assertTrue(ENTRY.is_file(), 'missing safe module runner')
        script = '''import importlib.util, pathlib, socket, subprocess, sys
p=pathlib.Path(sys.argv[1]); spec=importlib.util.spec_from_file_location('runner',p)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
def forbidden(*a,**k):raise AssertionError('module runner crossed execution boundary')
subprocess.Popen=forbidden;socket.socket=forbidden
raise SystemExit(m.main(['--mode','check','--iterations','8','--module',sys.argv[2],
                       '--output',sys.argv[3]]))
'''
        result = subprocess.run([sys.executable, '-c', script, str(ENTRY),
                                 str(self.directory / 'unbuilt.ko'), str(self.directory / 'out')],
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('crossed execution boundary', result.stderr)
        self.assertFalse((self.directory / 'out').exists())

    def test_missing_module_command_is_not_run(self):
        receipt = target().execute_command([str(self.directory / 'absent-loader')],
                                           self.directory / 'missing')
        self.assertEqual(receipt['status'], 'not-run')
        self.assertIsNone(receipt['returncode'])
        self.assertFalse(receipt['performance_eligible'])

    def test_real_module_command_error_is_preserved(self):
        receipt = target().execute_command(
            [sys.executable, '-c', 'import sys; print("load failure",file=sys.stderr);sys.exit(9)'],
            self.directory / 'failure')
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(receipt['returncode'], 9)
        self.assertIn('load failure', Path(receipt['stderr_path']).read_text())
        self.assertFalse(receipt['performance_eligible'])


if __name__ == '__main__':
    unittest.main()
