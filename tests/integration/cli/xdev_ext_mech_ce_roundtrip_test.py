#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""CE chains d and a: the round-trip data check must fail when the copy
engine moves nothing.

Compiles xdev_ext_mech_ce_roundtrip_test.c (a CPU model of the round trip
with copy-skipping mutants) against the control tool's core header under
UBSan, and checks that the tool wires the device-window oracle into chain
d and a.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CTL = ROOT / 'tools/xdev_ext_mech/xdev_ext_mech_ctl.c'


class CeRoundTrip(unittest.TestCase):
    def test_window_oracle_rejects_copy_skipping_mutants(self):
        with tempfile.TemporaryDirectory(prefix='xdev-ce-roundtrip-') as tmp:
            binary = Path(tmp) / 'roundtrip'
            command = [os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                       '-Werror', '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                       '-I' + str(ROOT), str(HERE / 'xdev_ext_mech_ce_roundtrip_test.c'),
                       '-o', str(binary)]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_ce_chain_fills_and_checks_the_device_window(self):
        source = CTL.read_text()
        start = source.index('static int cmd_ce_chain(')
        body = source[start:source.index('\nstatic int cmd_stats(', start)]
        # Poison before the session starts, oracle after it, for a and d.
        self.assertRegex(body, r'ctl_ce_window_fill\(')
        self.assertLess(body.index('ctl_ce_window_fill('), body.index('ctl_run_source('))
        run_source = source[source.index('static int ctl_run_source('):]
        run_source = run_source[:run_source.index('\nout:')]
        self.assertIn('xdev_ext_mech_ctl_ce_window_check(', source)
        self.assertRegex(run_source, r'src->ce_window')
        self.assertIn('xdev_ext_mech_ctl_report_ce_window(', body)


if __name__ == '__main__':
    unittest.main()
