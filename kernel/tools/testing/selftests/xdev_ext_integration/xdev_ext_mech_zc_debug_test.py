#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute debug-profile/config identity and console diagnostics, without KVM."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HELPER = HERE / 'xdev_ext_mech_zc_debug.py'
REQUIRED = ('DEBUG_KERNEL', 'PROVE_LOCKING', 'LOCKDEP', 'DEBUG_ATOMIC_SLEEP',
            'KASAN', 'KASAN_GENERIC', 'DETECT_HUNG_TASK')


class DebugProfile(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location('focused_debug', HELPER)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        return helper

    def config(self):
        return ''.join(f'CONFIG_{key}=y\n' for key in REQUIRED)

    def test_each_required_debug_symbol_is_verified_after_kconfig(self):
        helper = self.load()
        helper.check_config(self.config(), True)
        for key in REQUIRED:
            for replacement in ('', f'# CONFIG_{key} is not set\n', f'CONFIG_{key}=m\n'):
                with self.subTest(key=key, replacement=replacement), self.assertRaises(ValueError):
                    helper.check_config(self.config().replace(f'CONFIG_{key}=y\n', replacement), True)

    def test_deliberate_kasan_kunit_reports_are_not_enabled(self):
        with self.assertRaises(ValueError):
            self.load().check_config(self.config() + 'CONFIG_KASAN_KUNIT_TEST=y\n', True)

    def test_default_profile_does_not_silently_reuse_debug_kernel(self):
        helper = self.load()
        helper.check_config('CONFIG_DEBUG_KERNEL=y\n', False)
        with self.assertRaises(ValueError):
            helper.check_config(self.config(), False)

    def test_reuse_requires_matching_profile_and_exact_config_hash(self):
        helper = self.load()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, identity = root/'kernel.config', root/'profile.json'
            config.write_text(self.config())
            with self.assertRaises((ValueError, FileNotFoundError)):
                helper.check_identity(config, identity, True)
            helper.record_identity(config, identity, True)
            helper.check_identity(config, identity, True)
            with self.assertRaises(ValueError):
                helper.check_identity(config, identity, False)
            config.write_text(self.config() + '# a changed config\n')
            with self.assertRaises(ValueError):
                helper.check_identity(config, identity, True)

    def test_cli_config_gate_rejects_missing_or_wrong_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config, identity = root/'kernel.config', root/'profile.json'
            config.write_text(self.config())
            def run(action, enabled):
                return subprocess.run([sys.executable, str(HELPER), action, str(config),
                                       str(identity), str(enabled)], capture_output=True, text=True)
            self.assertNotEqual(run('reuse', 1).returncode, 0)
            self.assertEqual(run('record', 1).returncode, 0)
            self.assertEqual(run('reuse', 1).returncode, 0)
            self.assertNotEqual(run('reuse', 0).returncode, 0)
            config.write_text(config.read_text().replace('CONFIG_PROVE_LOCKING=y\n', ''))
            self.assertNotEqual(run('reuse', 1).returncode, 0)

    def test_console_classifies_every_required_report(self):
        helper = self.load()
        reports = ['possible circular locking dependency detected',
                   'possible recursive locking detected', 'inconsistent lock state',
                   'BUG: sleeping function called from invalid context',
                   'BUG: scheduling while atomic', 'BUG: KASAN: use-after-free',
                   'INFO: task worker: blocked for more than 120 seconds.']
        self.assertEqual(helper.debug_reports('\n'.join(reports)),
                         dict(lockdep=3, atomic_sleep=2, kasan=1, hung=1, diagnostic=0, rcu_stall=0))
        self.assertEqual(helper.debug_reports('Linux boot\nPASS\n'),
                         dict(lockdep=0, atomic_sleep=0, kasan=0, hung=0, diagnostic=0, rcu_stall=0))

    def test_irq_balance_detector_off_and_generic_reports_fail_cli(self):
        reports = (
            ('WARNING: possible irq lock inversion dependency detected', 'lockdep'),
            ('WARNING: bad unlock balance detected!', 'lockdep'),
            ('WARNING: held lock freed!', 'lockdep'),
            ('turning off the locking correctness validator.', 'lockdep'),
            ('INFO: lockdep is turned off.', 'lockdep'),
            ('BUG: kernel NULL pointer dereference', 'diagnostic'),
            ('WARNING: unrelated kernel invariant failed', 'diagnostic'),
            ('Oops: 0000 [#1] PREEMPT SMP', 'diagnostic'),
            ('Kernel panic - not syncing: fatal exception', 'diagnostic'),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            console, report = root/'guest.log', root/'debug.json'
            for line, category in reports:
                with self.subTest(line=line):
                    console.write_text(line + '\n')
                    run = subprocess.run([sys.executable, str(HELPER), 'console',
                        str(console), str(report), '1'], capture_output=True, text=True)
                    self.assertNotEqual(run.returncode, 0, run.stdout)
                    self.assertIn('XDEV_EXT_MECH_LOCKDEP=FAIL enabled=1', run.stdout)
                    self.assertEqual(json.loads(report.read_text())[category], 1)

    def test_console_cli_always_records_actual_failure_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            console, report = root/'guest.log', root/'debug.json'
            console.write_text('INFO: task worker blocked for more than 30 seconds.\n')
            run = subprocess.run([sys.executable, str(HELPER), 'console', str(console),
                                  str(report), '1'], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('XDEV_EXT_MECH_LOCKDEP=FAIL enabled=1', run.stdout)
            self.assertEqual(json.loads(report.read_text())['hung'], 1)


class RcuStalls(unittest.TestCase):
    REPORTS = (
        'rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:',
        'rcu: rcu_preempt kthread starved for 26027 jiffies!',
        'rcu: INFO: rcu_preempt self-detected stall on CPU',
        'rcu: INFO: rcu_sched detected expedited stalls on CPUs/tasks: { 3-... }',
        'rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks: { 0-... }',
    )

    def helper(self):
        spec=importlib.util.spec_from_file_location('e2_rcu_debug', HELPER)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_normal_rcu_boot_is_not_a_stall(self):
        text=('rcu: Preemptible hierarchical RCU implementation.\n'
              'rcu: RCU calculated value of scheduler-enlistment delay is 100 jiffies.\n'
              'rcu: Hierarchical SRCU implementation.\n')
        counts=self.helper().check_console(text)
        self.assertFalse(any(counts.values()), counts)

    def test_each_rcu_report_is_rejected_by_shared_check_console(self):
        helper=self.helper()
        for report in self.REPORTS:
            with self.subTest(report=report):
                with self.assertRaisesRegex(ValueError, 'diagnostic'):
                    helper.check_console('Linux boot\n'+report+'\ncompletion\n')
                self.assertGreater(helper.debug_reports(report).get('rcu_stall', 0), 0)

    def test_each_rcu_report_fails_cli_and_records_truthful_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); console=root/'console'; report=root/'counts.json'
            for line in self.REPORTS:
                with self.subTest(line=line):
                    console.write_text('Linux boot\n'+line+'\n')
                    run=subprocess.run([sys.executable,str(HELPER),'console',str(console),str(report),'1'],
                                       text=True,capture_output=True)
                    self.assertNotEqual(run.returncode, 0, run.stdout)
                    self.assertIn('XDEV_EXT_MECH_LOCKDEP=FAIL enabled=1', run.stdout)
                    self.assertGreater(json.loads(report.read_text()).get('rcu_stall', 0), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
