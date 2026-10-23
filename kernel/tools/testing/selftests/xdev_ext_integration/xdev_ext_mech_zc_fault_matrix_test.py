#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host checks for the real guest campaign orchestration, not device execution."""
import json
from pathlib import Path
import subprocess
import re
import tempfile
import unittest

import xdev_ext_mech_zc_fault_validate as oracle

HERE = Path(__file__).resolve().parent
DRIVER = HERE / 'xdev_ext_mech_zc_fault_matrix.sh'
GUEST = HERE / 'xdev_ext_mech_zc_fault_guest.sh'
KVM = HERE / 'xdev_ext_mech_zc_kvm.sh'


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
        source = (HERE.parents[2] / 'xdev_ext_mech/xdev_ext_mech_ctl.c').read_text()
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


if __name__ == '__main__':
    unittest.main()
