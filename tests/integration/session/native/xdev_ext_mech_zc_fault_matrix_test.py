#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host checks for the real guest campaign orchestration, not device execution."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import re
import shlex
import shutil
import tempfile
import unittest

import xdev_ext_mech_zc_fault_validate as oracle

HERE = Path(__file__).resolve().parent
DRIVER = HERE / 'xdev_ext_mech_zc_fault_matrix.sh'
GUEST = HERE / 'xdev_ext_mech_zc_fault_guest.sh'
KVM = HERE / 'xdev_ext_mech_zc_kvm.sh'


def source_layout():
    """Use the real layout API from canonical or ordinary logical-view paths."""
    for parent in HERE.parents:
        tooling = parent / 'tools/layout.py'
        if tooling.is_file():
            spec = importlib.util.spec_from_file_location('_legacy_matrix_layout', tooling)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            repo = module.canonical_root(HERE)
            return repo, module.load_layout(repo)
    raise RuntimeError('matrix test requires a canonical or logical source layout')


class MatrixContract(unittest.TestCase):
    def run_driver(self, *args):
        return subprocess.run(['bash', str(DRIVER), *args], capture_output=True,
                              text=True, timeout=10)

    def test_all_dry_run_expectations_match_frozen_oracle(self):
        run = self.run_driver('--dry-run', '--campaign', 'all',
                              '/tmp/xdev-ext-e2e.Contract', '/private/source/kernel')
        self.assertEqual(run.returncode, 0, run.stderr)
        plans = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
        self.assertEqual({p['campaign'] for p in plans}, set(oracle.CAMPAIGNS))
        self.assertEqual(len(plans), len(oracle.CAMPAIGNS))
        for plan in plans:
            self.assertEqual(plan['expectation'], oracle.expectation_line(plan['campaign']))
            self.assertEqual(plan['performance_claim'], 'none')
            self.assertIn('--fault-campaign', plan['harness_command'])
            self.assertIn(plan['campaign'], plan['harness_command'])
            self.assertIn('-kernel', plan['qemu_command'])
            self.assertIn('-nic', plan['qemu_command'])
            self.assertNotIn('tap', ' '.join(plan['qemu_command']))
            self.assertEqual(plan['readonly_destination'],
                             bool(oracle.CAMPAIGNS[plan['campaign']]['readonly_destination']))

    def test_single_campaign_and_geometry(self):
        run = self.run_driver('--dry-run', '--campaign', 'exit-source', '--groups', '8',
                              '--depth', '2', '/tmp/xdev-ext-e2e.Contract', '/private/kernel')
        self.assertEqual(run.returncode, 0, run.stderr)
        plans = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{')]
        self.assertEqual(len(plans), 1)
        self.assertEqual((plans[0]['groups'], plans[0]['depth']), (8, 2))

    def test_bad_campaign_and_geometry_refused_without_boot(self):
        for options in (['--campaign', 'missing'], ['--depth', '9'],
                        ['--groups', '1'], ['--groups', '4', '--depth', '8']):
            run = self.run_driver('--dry-run', *options, '/tmp/xdev-ext-e2e.Contract', '/private/kernel')
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertNotIn('=PASS', run.stdout)

    def test_shell_syntax(self):
        for path in (DRIVER, GUEST, KVM):
            run = subprocess.run(['bash', '-n', str(path)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_guest_records_observations_and_every_campaign(self):
        self.assertTrue(GUEST.is_file(), 'guest actions missing')
        text = GUEST.read_text()
        for campaign in oracle.CAMPAIGNS:
            self.assertIn(campaign, text)
        for marker in ('EXPECT', 'ENV', 'PINS', 'CE_CONFIG', 'LOG_BEGIN', 'LOG_END',
                       'INFLIGHT_SEEN', 'KILL', 'NETDEV_REMOVED', 'RESET', 'PIN_GONE',
                       'CONCURRENT', 'VICTIM_ALIVE', 'SESSION', 'CE_SIM_STATS',
                       'CE_REFS', 'CE_UNLOAD', 'TRACE', 'CAMPAIGN_DONE', 'GUEST_EXIT'):
            self.assertIn('XDEV_EXT_ZC_FAULT_' + marker, text)
        self.assertIn('/proc/vmstat', text)
        self.assertIn('/proc/meminfo', text)
        self.assertIn('/sys/module/xdev_ext_ce_sim', text)
        self.assertNotIn('fault_fixtures', text)
        self.assertIn('--fault-campaign)', KVM.read_text())

    def test_guest_command_options_are_real_ctl_options(self):
        _, layout = source_layout()
        source = layout.source('linux', 'tools/xdev_ext_mech/xdev_ext_mech_ctl.c').read_text()
        options = set(re.findall(r'\{\s*"([a-z][a-z0-9-]*)",\s*(?:no|required)_argument', source))
        guest = GUEST.read_text()
        # Execute the real argument constructors with spawn intercepted. This
        # checks orchestration only and never simulates a device completion.
        functions = guest[guest.index('chain() {'):guest.index('remove_netdev() {')]
        setup = ('ctl=ctl; depth=8; groups=64; source_slba=2048; rx_slba=2048; '
                 'window_nlb=1024; source_ng=/dev/ng0n1; destination_ng=/dev/ng1n1; '
                 'cli_timeout_ms=60000; rx_timeout_ms=15000; '
                 'spawn() { printf "%s\\n" "$@"; }; ready() { return 0; };\n')
        for name in oracle.CAMPAIGNS:
            program = setup + functions + '\nnetwork RX TX ' + name + '\nchain SRC b 64 2048 4096 0\n'
            run = subprocess.run(['sh', '-c', program], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            used = {line[2:] for line in run.stdout.splitlines() if line.startswith('--')}
            self.assertLessEqual(used, options, 'unknown ctl option: ' + str(used - options))

    def test_real_exit_status_and_session_observation_are_preserved(self):
        text = GUEST.read_text()
        functions = text[text.index('spawn() {'):text.index('chain() {')]
        with tempfile.TemporaryDirectory() as directory:
            program = ('set -eu; work=' + directory + '; roles="";\n' + functions +
                       '\nspawn SRC sh -c "exit 7"\njoin_role SRC\nsettle SRC\n')
            run = subprocess.run(['sh', '-c', program], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn('LOG_BEGIN role=SRC exit=7', run.stdout)
            self.assertIn('SESSION role=SRC session=0 state=NOT_CREATED', run.stdout)
            self.assertNotIn('state=FREED', run.stdout)


class PinObservation(unittest.TestCase):
    """Execute only the actual pins() collector against ordinary temporary files.

    cat/read are observation and error-injection boundaries, not kernel counter
    models. These tests establish the shell protocol, never GUP accounting.
    """
    def run_pins(self, phases=('before', 'after'), *, fail_phase='',
                 refresh_present=True, conditional=False):
        source = GUEST.read_text()
        functions = re.findall(r'(?ms)^pins\(\) \{\n.*?^\}', source)
        self.assertEqual(len(functions), 1, 'require the actual unique guest pins()')
        function = functions[0]
        real_cat = shutil.which('cat')
        self.assertIsNotNone(real_cat, 'cat is required; no skipped protocol check')
        with tempfile.TemporaryDirectory(prefix='xdev-ext-pin-protocol-') as directory:
            root = Path(directory)
            paths = {name: root / name for name in ('stat_refresh', 'vmstat', 'meminfo')}
            if refresh_present:
                # Deliberately nonempty: the collector must discard refresh
                # output, not mix it into the unchanged PINS record protocol.
                paths['stat_refresh'].write_text('refresh boundary content\n')
            paths['vmstat'].write_text('nr_foll_pin_acquired 211\n'
                                       'nr_foll_pin_released 199\n')
            paths['meminfo'].write_text('Mlocked: 17 kB\n')
            for native, name in (('/proc/sys/vm/stat_refresh', 'stat_refresh'),
                                 ('/proc/vmstat', 'vmstat'),
                                 ('/proc/meminfo', 'meminfo')):
                # Replace fixed path tokens (quoted or unquoted), never the
                # collector's commands, branches, field parsing or output.
                pattern = r'([\'\"]?)' + re.escape(native) + r'\1'
                function = re.sub(pattern, lambda _: shlex.quote(str(paths[name])), function)
            self.assertNotIn('/proc/', function, 'collector must never access real host procfs')
            audit = root / 'audit'
            audit.write_text('')
            assignments = {'fixture_refresh': str(paths['stat_refresh']),
                           'fixture_audit': str(audit), 'fixture_real_cat': real_cat,
                           'fixture_fail_phase': fail_phase}
            setup = '\n'.join(name + '=' + shlex.quote(value)
                              for name, value in assignments.items())
            boundary = r'''
cat() {
    if [ "$#" -ne 1 ] || [ "$1" != "$fixture_refresh" ]; then
        echo 'unexpected collector cat boundary' >&2
        return 74
    fi
    printf 'refresh-attempt %s\n' "$fixture_phase" >>"$fixture_audit"
    if [ "$fixture_phase" = "$fixture_fail_phase" ]; then
        echo 'injected refresh read error' >&2
        return 73
    fi
    if "$fixture_real_cat" "$@"; then
        printf 'refresh-complete %s\n' "$fixture_phase" >>"$fixture_audit"
    else
        return "$?"
    fi
}
read() {
    printf 'sample-read %s\n' "$fixture_phase" >>"$fixture_audit"
    command read "$@"
}
'''
            call = ('if pins "$fixture_phase"; then :; else exit "$?"; fi'
                    if conditional else 'pins "$fixture_phase"')
            program = setup + '\n' + boundary + '\n' + function + '\n' + \
                'for fixture_phase in "$@"; do\n' + \
                'printf "phase %s\\n" "$fixture_phase" >>"$fixture_audit"\n' + \
                call + '\ndone\n'
            run = subprocess.run(['sh', '-euc', program, 'pin-protocol', *phases],
                                 capture_output=True, text=True, timeout=10)
            return run, audit.read_text().splitlines()

    def test_every_phase_refreshes_before_sampling_with_unchanged_records(self):
        run, audit = self.run_pins()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.splitlines(), [
            'XDEV_EXT_ZC_FAULT_PINS phase=before acquired=211 released=199 mlocked_kb=17',
            'XDEV_EXT_ZC_FAULT_PINS phase=after acquired=211 released=199 mlocked_kb=17'])
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                begin = audit.index('phase ' + phase)
                self.assertEqual(audit[begin + 1:begin + 4], [
                    'refresh-attempt ' + phase, 'refresh-complete ' + phase,
                    'sample-read ' + phase],
                    'each phase must successfully read stat_refresh before sampling')
                self.assertEqual(audit.count('refresh-attempt ' + phase), 1)
                self.assertEqual(audit.count('refresh-complete ' + phase), 1)

    def test_refresh_errors_stop_each_phase_without_a_pins_record(self):
        for phase in ('before', 'after'):
            for conditional in (False, True):
                with self.subTest(phase=phase, conditional=conditional):
                    run, audit = self.run_pins((phase,), fail_phase=phase,
                                               conditional=conditional)
                    self.assertNotEqual(run.returncode, 0, 'refresh error must propagate')
                    self.assertNotIn('XDEV_EXT_ZC_FAULT_PINS ', run.stdout)
                    self.assertEqual(audit, ['phase ' + phase, 'refresh-attempt ' + phase],
                                     'failed refresh must not read a sample')

    def test_missing_refresh_is_a_hard_failure(self):
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                run, audit = self.run_pins((phase,), refresh_present=False)
                self.assertNotEqual(run.returncode, 0, 'missing refresh must not use stale counters')
                self.assertNotIn('XDEV_EXT_ZC_FAULT_PINS ', run.stdout)
                self.assertEqual(audit, ['phase ' + phase, 'refresh-attempt ' + phase])

    def test_after_refresh_error_preserves_only_the_before_record(self):
        run, audit = self.run_pins(fail_phase='after')
        self.assertNotEqual(run.returncode, 0, 'after refresh must be checked independently')
        self.assertEqual(run.stdout.splitlines(), [
            'XDEV_EXT_ZC_FAULT_PINS phase=before acquired=211 released=199 mlocked_kb=17'])
        self.assertEqual(audit.count('refresh-complete before'), 1)
        self.assertIn('refresh-attempt after', audit)
        self.assertNotIn('refresh-complete after', audit)
        self.assertNotIn('sample-read after', audit)


class PinValidatorContract(unittest.TestCase):
    """Keep the actual validator's strict pin rules; no frozen console inputs."""
    def pins(self, acquired, released, *, mlocked=0, retained=None):
        console = oracle.Console(
            'XDEV_EXT_ZC_FAULT_PINS phase=before acquired=100 released=80 mlocked_kb=0\n'
            f'XDEV_EXT_ZC_FAULT_PINS phase=after acquired={acquired} released={released} '
            f'mlocked_kb={mlocked}\n')
        return oracle._pins(console, {} if retained is None else retained)

    def test_freed_sessions_require_exact_balance_and_reject_both_signs(self):
        self.assertEqual(self.pins(110, 90), 0)
        for acquired, released, message in (
                (110, 91, '1 more FOLL_PIN pins released than acquired'),
                (111, 90, '1 FOLL_PIN pins leaked after every session was freed')):
            with self.subTest(acquired=acquired, released=released):
                with self.assertRaisesRegex(oracle.FaultCheckError, message):
                    self.pins(acquired, released)

    def test_retained_pool_bounds_and_sequestered_pins_remain_strict(self):
        retained = {'SRC': {'pool_pages': 2, 'sequestered': 1}}
        self.assertEqual(self.pins(112, 90, retained=retained), 2)
        with self.assertRaisesRegex(oracle.FaultCheckError, 'parked sessions hold 3 pins, pool bound 2'):
            self.pins(113, 90, retained=retained)
        with self.assertRaisesRegex(oracle.FaultCheckError, 'sequestered frames were unpinned early'):
            self.pins(110, 90, retained=retained)

    def test_mlocked_must_not_change(self):
        with self.assertRaisesRegex(oracle.FaultCheckError, 'Mlocked changed'):
            self.pins(110, 90, mlocked=1)


if __name__ == '__main__':
    unittest.main()
