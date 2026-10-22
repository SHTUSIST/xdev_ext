#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Small wiring guards supplement the console/image/wire behavior tests."""

import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
HARNESS = HERE / "xdev_ext_mech_zc_kvm.sh"
SIM = ROOT / "tools/testing/selftests/xdev_ext_mech/simulate/xdev_ext_ce_sim.c"


class HarnessWiringTest(unittest.TestCase):
    def setUp(self):
        self.script = HARNESS.read_text()

    def test_actual_shell_image_preparation_supports_long_disjoint_campaigns(self):
        spec = importlib.util.spec_from_file_location("layout_validator",
                    HERE / "xdev_ext_mech_zc_validate.py")
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        start = self.script.index('read -r SOURCE_SLBA RX_SLBA CE_SLBA IMAGE_BYTES')
        layout_shell = self.script[start:self.script.index('BUILD=$SCRATCH/build', start)]
        start = self.script.index('python3 - "$SCRATCH" "$GROUP_COUNT" "$CE_SIM" "$FAULT"')
        images_shell = self.script[start:self.script.index('\nPY\n', start) + 4]
        for groups in (257, 1024):
            with self.subTest(groups=groups), tempfile.TemporaryDirectory() as directory:
                scratch = Path(directory)
                (scratch / 'evidence').mkdir()
                env = dict(os.environ, SRC=str(ROOT), SCRATCH=str(scratch),
                           GROUP_COUNT=str(groups), CE_SIM='1', FAULT='none')
                run = subprocess.run(['bash', '-euc', layout_shell + images_shell],
                    env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                source, before, expected = ((scratch / name).read_bytes() for name in
                    ('source-before.raw', 'destination-before.raw', 'expected.raw'))
                self.assertEqual(len(source), len(before))
                self.assertEqual(len(before), len(expected))
                self.assertIsNone(validator.validate_images(source, source, before, expected,
                    groups=groups, receiver_batches_done=groups, ce_sim=True, depth=8, ce_slots=8))
                # Independent geometry and both complete payloads: no alias
                # can hide behind the shared expected-image construction.
                length = groups * 8192
                ce_offset = max(4 * 1024 * 1024, 2 * 1024 * 1024 + length + 8192)
                payload = source[1024 * 1024:1024 * 1024 + length]
                self.assertEqual(expected[2 * 1024 * 1024:2 * 1024 * 1024 + length], payload)
                self.assertEqual(expected[ce_offset:ce_offset + length], payload)
                self.assertEqual(expected[2 * 1024 * 1024 + length:ce_offset],
                                 before[2 * 1024 * 1024 + length:ce_offset])
                self.assertGreaterEqual(len(expected), ce_offset + length + 8192)

    def test_native_guest_commands_use_exported_campaign_offsets(self):
        for name, variable in (('source_slba', 'SOURCE_SLBA'), ('rx_slba', 'RX_SLBA'),
                               ('ce_slba', 'CE_SLBA')):
            self.assertIn('"$' + variable + '"', self.script)
            self.assertIn('"$' + name + '"', self.script)
        self.assertIn('--dst-slba "$ce_slba"', self.script)
        self.assertIn('--slba "$rx_slba"', self.script)
        self.assertNotRegex(self.script, r'--(?:dst-)?slba (?:2048|4096|8192)\b')

    def test_new_run_removes_only_derived_success_records(self):
        cleanup = re.search(r"(?ms)^clear_derived_results\(\) \{\n.*?^\}", self.script)
        self.assertIsNotNone(cleanup, 'a failed run must not retain an earlier PASS')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / 'evidence'
            evidence.mkdir()
            derived = ('result.txt', 'data-result.txt', 'validation.json',
                       'data.sha256', 'source-after.sha256',
                       'debug-locking.json', 'debug-locking-result.txt')
            for name in derived:
                (evidence / name).write_text('OLD PASS')
            preserved = evidence / 'guest.log'
            preserved.write_text('prior raw failure')
            history = root / 'campaigns' / 'prior'
            history.mkdir(parents=True)
            (history / 'result.txt').write_text('historical PASS')
            run = subprocess.run(['bash', '-euc', cleanup.group() + '\nclear_derived_results'],
                env=dict(os.environ, EV=str(evidence)), capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertTrue(all(not (evidence / name).exists() for name in derived))
            self.assertEqual(preserved.read_text(), 'prior raw failure')
            self.assertEqual((history / 'result.txt').read_text(), 'historical PASS')
        self.assertLess(self.script.index('\nclear_derived_results\n'),
                        self.script.index('if (( RUN_ONLY )); then'))

    def test_raw_lockdep_and_hung_reports_reject_otherwise_valid_console(self):
        modules = []
        for name in ('validate', 'validate_test'):
            spec = importlib.util.spec_from_file_location('debug_' + name,
                        HERE / ('xdev_ext_mech_zc_' + name + '.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules.append(module)
        validator, fixture = modules
        base = fixture.console_fixture(ce_sim=False, delay_us=0)
        for report in ('possible circular locking dependency detected',
                       'INFO: task kworker/0:1 blocked for more than 120 seconds.'):
            with self.subTest(report=report), self.assertRaises(ValueError):
                validator.validate_console(base + report + '\n', groups=8,
                    ce_sim=False, ce_delay_us=0)

    def test_debug_budgets_are_opt_in_and_propagated_to_guest_commands(self):
        start = self.script.index('TIMEOUT_FACTOR=')
        end = self.script.index('\n# Campaign length', start)
        snippet = self.script[start:end]
        for enabled, expected in ((0, '1 60000 15000 150'), (1, '4 240000 60000 600')):
            run = subprocess.run(['bash', '-euc', snippet +
                '\nprintf "%s %s %s %s" "$TIMEOUT_FACTOR" "$CLI_TIMEOUT_MS" "$RX_TIMEOUT_MS" "$QEMU_TIMEOUT_SECONDS"'],
                env=dict(os.environ, DEBUG_LOCKING=str(enabled)), capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout, expected)
        self.assertIn('--debug-locking)', self.script)
        self.assertIn('--timeout-ms "$cli_timeout_ms"', self.script)
        self.assertIn('timeout_ms=$cli_timeout_ms', self.script)
        self.assertNotIn('--timeout-ms 60000', self.script)
        self.assertIn('"$QEMU_TIMEOUT_SECONDS" "$QEMU"', self.script)
        record = self.script.index('python3 "$DEBUG_HELPER" record')
        seal = self.script.index('>"$BUILD/xdev-ext-artifacts.sha256"')
        self.assertLess(record, seal)
        self.assertIn('python3 "$DEBUG_HELPER" reuse "$BUILD/.config"', self.script)
        self.assertIn('sha256sum "$BUILD/xdev-ext-debug-profile.json"', self.script)

    def test_delay_flag_is_propagated_to_simulator_instead_of_fixed_zero(self):
        self.assertIn("--ce-delay-us)", self.script)
        insmod = re.search(r"(?m)^\s*insmod\s+[^\n]*xdev_ext_ce_sim\.ko[^\n]*", self.script)
        self.assertIsNotNone(insmod)
        self.assertRegex(insmod.group(), r"delay_us=[\"']?\$[{a-zA-Z_]")

    def test_fault_is_an_explicit_flag_defaulting_to_none(self):
        self.assertIn("--fault)", self.script)
        self.assertRegex(self.script, r"(?m)^[A-Z_]*FAULT[A-Z_]*=[\"']?none[\"']?\s*$")
        for mode in ("drop-middle", "duplicate-middle"):
            self.assertIn(mode, self.script)

    def test_receive_ce_is_an_explicit_harness_option(self):
        self.assertIn("--rx-ce)", self.script)

    def test_shared_host_validator_is_used_for_actual_evidence(self):
        self.assertIn("xdev_ext_mech_zc_validate", self.script)
        self.assertIn("guest.log", self.script)
        self.assertIn("source.raw", self.script)
        self.assertIn("destination.raw", self.script)

    def test_wire_injection_is_wired_into_harness(self):
        self.assertIn("xdev_ext_mech_zc_wire", self.script)
        self.assertIn("XDEV_EXT_ZC_FAULT_COUNTS", self.script)

    def test_simulator_counters_have_read_only_exports(self):
        text = SIM.read_text()
        # Permit uint/ullong or callback-based module parameters; exact C
        # counter storage/locking belongs to the simulator implementation.
        for name in ("accepted", "completed", "pending", "peak_pending",
                     "submit_before_first_complete"):
            with self.subTest(counter=name):
                exports = re.findall(r"module_param(?:_named|_cb)?\s*\([^;]+;", text, re.S)
                matching = [entry for entry in exports
                            if re.search(rf"\(\s*{name}\s*,", entry)]
                # The simulator uses one typed, read-only export macro for
                # all five counters. Check its definition and invocation.
                if re.search(rf"\bSIM_STAT\({name}\)\s*;", text):
                    macro = re.search(r"(?m)^#define SIM_STAT\(name\) (.+)$", text)
                    self.assertIsNotNone(macro)
                    matching.append(macro.group(1) + ";")
                self.assertTrue(matching, f"missing read-only simulator counter {name}")
                for entry in matching:
                    self.assertRegex(entry, r",\s*0?444\s*\)\s*;")

    def test_wire_helper_cannot_inject_native_completion_results(self):
        wire = HERE / "xdev_ext_mech_zc_wire.py"
        self.assertTrue(wire.is_file(), "wire-level injector missing")
        text = wire.read_text()
        for forbidden in ("xdev_ext_ce_complete", "xdev_ext_mech_batch_completion_publish",
                          "xdev_ext_mech_batch_completion_claim"):
            self.assertNotIn(forbidden, text)

    def test_guest_keeps_private_image_and_private_network_boundary(self):
        self.assertIn('file=$SCRATCH/source.raw', self.script)
        self.assertIn('file=$SCRATCH/destination.raw', self.script)
        self.assertIn("-nic none", self.script)
        self.assertNotRegex(self.script, r"-netdev\s+(?:tap|bridge|user)[,\s]")


if __name__ == "__main__":
    unittest.main()
