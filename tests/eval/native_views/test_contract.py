#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent R7-R10/R13-R14 contracts; no provider or kernel is started.

Run directly or with unittest discovery. Synthetic metadata remains tagged fixture.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fixtures.builders import HERE, clone, run_fixture, target


class RunAdmission(unittest.TestCase):
    def test_fixture_parses_without_becoming_performance(self):
        api = target('contract')
        run = run_fixture()
        self.assertEqual(api.validate_run(run), [])
        errors = api.validate_run(run, performance=True)
        self.assertTrue(errors)
        self.assertIn('physical', ' '.join(errors).lower())

    def test_required_identity_fields_are_not_optional(self):
        api = target('contract')
        for name in ('schema_version', 'run_id', 'pair_id', 'exact_sha',
                     'bpf_object_hash', 'config_hash', 'device_manifest', 'endpoint'):
            with self.subTest(field=name):
                run = run_fixture()
                del run[name]
                self.assertIn(name, ' '.join(api.validate_run(run)))

    def test_r7_mismatched_workload_reports_each_field(self):
        api = target('analyze')
        changes = dict(record_bytes=16384, frame_bytes=2048, depth=32, batch=8,
                       mtu=9000, protocol='other', crc='none', endpoint='nic_local_tx',
                       load='open', setup_in_timing=True, pool_bytes=32 << 20,
                       exact_sha='d' * 40)
        for field, value in changes.items():
            with self.subTest(field=field):
                left, right = run_fixture(), run_fixture('K-BPF')
                right[field] = value
                result = api.compare_runs(left, right)
                self.assertFalse(result['eligible'])
                self.assertIn(field, ' '.join(result['errors']))
                self.assertIsNone(result['delta'])

    def test_r7_arm_and_wait_strategy_may_differ(self):
        result = target('analyze').compare_runs(run_fixture(), run_fixture('U-event'))
        self.assertTrue(result['eligible'], result['errors'])
        self.assertFalse(result['performance_eligible'])

    def test_r8_shared_page_baseline_rejects_copy_bounce_and_reregistration(self):
        api = target('contract')
        changes = dict(payload_copy_bytes=4096, afxdp_zero_copy=False,
                       nvme_no_bounce=False, registration_reused=False,
                       registration_calls=2, shared_pages=False)
        for field, value in changes.items():
            with self.subTest(field=field):
                run = run_fixture()
                run[field] = value
                self.assertIn(field, ' '.join(api.validate_run(run)))

    def test_r9_nonphysical_incorrect_unrun_and_fixture_never_admit_performance(self):
        api = target('contract')
        for updates, field in (({'physical': False}, 'physical'),
                               ({'environment': 'vm', 'physical': True}, 'environment'),
                               ({'correctness_pass': False}, 'correctness_pass'),
                               ({'status': 'not-run'}, 'status'),
                               ({'status': 'failed'}, 'status'),
                               ({'evidence_kind': 'fixture', 'physical': True}, 'evidence_kind'),
                               ({'oracle_in_timing': True}, 'oracle_in_timing'),
                               ({'cpu_accounting': 'getrusage_only'}, 'cpu_accounting')):
            with self.subTest(updates=updates):
                run = run_fixture()
                run.update(updates)
                self.assertIn(field, ' '.join(api.validate_run(run, performance=True)))
        run = run_fixture()
        run['physical'] = 'true'
        self.assertIn('physical', ' '.join(api.validate_run(run)))

    def test_r10_bytes_and_bits_si_and_iec_are_explicit(self):
        parse = target('contract').parse_quantity
        for text, kind, expected in (('1Gb/s', 'bytes_per_second', 125000000),
                                     ('1GB/s', 'bytes_per_second', 1000000000),
                                     ('1GiB/s', 'bytes_per_second', 1073741824),
                                     ('4096B', 'bytes', 4096), ('4KiB', 'bytes', 4096),
                                     ('4KB', 'bytes', 4000)):
            with self.subTest(text=text):
                self.assertEqual(parse(text, kind=kind), expected)
        for text in ('4096', '1G', '1gb/s', '-1GB/s', 'nanGB/s', 'infGB/s'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse(text, kind='bytes_per_second')


class SafeRunner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.native-contract-', dir=HERE)
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, manifest, mode):
        entry = HERE / 'run.py'
        self.assertTrue(entry.is_file(), 'missing executable native_views runner')
        path = self.directory / 'manifest.json'
        path.write_text(json.dumps(manifest))
        return subprocess.run([sys.executable, str(entry), '--manifest', str(path),
                               '--output', str(self.directory / 'out'), mode],
                              text=True, capture_output=True, timeout=15)

    def test_r13_dry_run_does_not_execute_commands(self):
        marker = self.directory / 'provider_was_started'
        run = run_fixture()
        run['commands'] = [[sys.executable, '-c',
                            'from pathlib import Path; Path(__import__("sys").argv[1]).touch()',
                            str(marker)]]
        result = self.invoke(run, '--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertIn('dry-run', result.stdout)
        self.assertIn(sys.executable, result.stdout)
        self.assertFalse(json.loads(result.stdout)['performance_eligible'])

    def test_r13_validate_only_does_not_execute_commands(self):
        run = run_fixture()
        run['commands'] = [['/nonexistent/provider-should-not-be-run']]
        result = self.invoke(run, '--validate-only')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'validated')
        self.assertFalse(report['performance_eligible'])

    def test_r13_execute_rejects_fixture_before_provider_start(self):
        marker = self.directory / 'provider_was_started'
        run = run_fixture()
        run['commands'] = [[sys.executable, '-c', 'open(__import__("sys").argv[1],"w").close()',
                            str(marker)]]
        result = self.invoke(run, '--execute')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'not-run')
        self.assertFalse(report['performance_eligible'])

    def test_r14_missing_executable_is_not_run_and_preserves_reason(self):
        receipt = target('run').execute_command(
            [str(self.directory / 'absent')], self.directory / 'missing')
        self.assertEqual(receipt['status'], 'not-run')
        self.assertIsNone(receipt['returncode'])
        self.assertTrue(receipt['error'])
        self.assertFalse(receipt['performance_eligible'])

    def test_r14_real_nonzero_process_failure_is_not_pass_or_not_run(self):
        receipt = target('run').execute_command(
            [sys.executable, '-c', 'import sys; print("actual failure", file=sys.stderr); sys.exit(7)'],
            self.directory / 'failure')
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(receipt['returncode'], 7)
        self.assertIn('actual failure', Path(receipt['stderr_path']).read_text())
        self.assertFalse(receipt['performance_eligible'])

    def test_r14_successful_subprocess_alone_does_not_prove_performance(self):
        receipt = target('run').execute_command(
            [sys.executable, '-c', 'print("ordinary subprocess")'], self.directory / 'success')
        self.assertEqual(receipt['status'], 'ok')
        self.assertEqual(receipt['returncode'], 0)
        self.assertFalse(receipt['performance_eligible'])

    def test_actual_recipes_use_existing_shared_page_and_session_workloads(self):
        api = target('run')
        for chain in ('nvme-nic', 'nic-nvme'):
            with self.subTest(chain=chain):
                manifest = run_fixture()
                manifest['recipe'] = dict(chain=chain, rig=str(self.directory / 'rig.json'),
                                          records=32, pairs=3,
                                          arms=['U-poll', 'U-event', 'K-BPF', 'K-C'])
                plan = api.build_commands(manifest)
                commands = {row['arm']: row['argv'] for row in plan['commands']}
                self.assertEqual(set(commands), {'U-poll', 'U-event', 'K-BPF'})
                missing = {row['arm']: row['reason'] for row in plan['unavailable']}
                self.assertIn('K-C', missing)
                self.assertTrue(missing['K-C'])
                for arm, argv in commands.items():
                    self.assertIsInstance(argv, list)  # no shell command expansion
                    entry = next((Path(v) for v in argv if v.endswith('/chains/run.py')), None)
                    self.assertIsNotNone(entry, 'must invoke the actual existing chain workload')
                    self.assertTrue(entry.is_file())
                    expected = {'--chain': chain, '--rig': manifest['recipe']['rig'],
                                '--sizes': '4096', '--depth': '8', '--pairs': '3',
                                '--records': '32', '--afxdp-mode': 'zc'}
                    if arm.startswith('U-'):
                        expected.update({'--arms': 'userspace-shared',
                                         '--wait': 'poll' if arm == 'U-poll' else 'eventfd'})
                    else:
                        expected.update({'--arms': 'session', '--plan': 'bpf'})
                    for option, value in expected.items():
                        self.assertIn(option, argv)
                        self.assertEqual(argv[argv.index(option) + 1], value)
                    self.assertNotIn('--prepare-source', argv)

    def test_unsupported_batch_cannot_silently_run_batch_one(self):
        manifest = run_fixture()
        manifest['batch'] = 8
        manifest['recipe'] = dict(chain='nvme-nic', rig='unused.json', records=32,
                                  pairs=1, arms=['U-poll', 'K-BPF'])
        plan = target('run').build_commands(manifest)
        for row in plan['commands']:
            argv = row['argv']
            self.assertIn('--batch', argv)
            self.assertEqual(argv[argv.index('--batch') + 1], '8')
        for row in plan['unavailable']:
            self.assertIn('batch', row['reason'].lower())
        self.assertEqual(len(plan['commands']) + len(plan['unavailable']), 2)


if __name__ == '__main__':
    unittest.main()
