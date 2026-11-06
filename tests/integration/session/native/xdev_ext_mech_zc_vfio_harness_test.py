#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Harness wiring of VFIO passthrough, the real-GPU mode and the NIC model."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / 'xdev_ext_mech_zc_kvm.sh'


def function(script, name):
    match = re.search(r'(?ms)^' + re.escape(name) + r'\(\) \{\n.*?^\}\n', script)
    assert match, name
    return match.group()


class VfioArguments(unittest.TestCase):
    def setUp(self):
        self.script = HARNESS.read_text()
        self.tmp = tempfile.TemporaryDirectory(prefix='vfio-args-')
        base = Path(self.tmp.name)
        self.helper = base / 'helper.py'
        self.evidence = base / 'evidence'
        self.evidence.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_args(self, devices, ready):
        # The stub answers like vfio_passthrough.py check for the listed BDFs.
        self.helper.write_text(
            'import sys\n'
            f'ready = {sorted(ready)!r}\n'
            'bdf = sys.argv[2]\n'
            'if sys.argv[1] == "check" and bdf in ready:\n'
            '    print("VFIO_READY " + bdf); sys.exit(0)\n'
            'print("REFUSED " + bdf, file=sys.stderr); sys.exit(1)\n')
        program = ('set -euo pipefail\nGPU=0\nGPU_BDF=\n' +
                   f'VFIO_HELPER={self.helper}\nEV={self.evidence}\n' +
                   'VFIO_DEVICES=(' + ' '.join(devices) + ')\n' +
                   'GPU_DEVICE_ID=unknown\n' +
                   function(self.script, 'vfio_qemu_args') +
                   'vfio_qemu_args\nprintf "%s\\n" "${VFIO_ARGS[@]}"\n')
        return subprocess.run(['bash', '-c', program], capture_output=True, text=True)

    def test_every_ready_device_is_assigned_behind_its_own_root_port(self):
        run = self.run_args(['0000:01:00.0', '0000:4a:00.0'], {'0000:01:00.0', '0000:4a:00.0'})
        self.assertEqual(run.returncode, 0, run.stderr)
        args = run.stdout.splitlines()
        self.assertIn('vfio-pci,host=0000:01:00.0,bus=vfio_rp1', args)
        self.assertIn('vfio-pci,host=0000:4a:00.0,bus=vfio_rp2', args)
        self.assertTrue(any(a.startswith('pcie-root-port,id=vfio_rp1,') for a in args))
        self.assertTrue(any(a.startswith('pcie-root-port,id=vfio_rp2,') for a in args))
        self.assertIn('q35-pcihost.pci-hole64-size=256G', args)

    def test_a_device_that_fails_the_guard_stops_the_harness(self):
        run = self.run_args(['0000:01:00.0', '0000:4a:00.0'], {'0000:01:00.0'})
        self.assertNotEqual(run.returncode, 0)
        self.assertIn('0000:4a:00.0 not ready', run.stderr)
        self.assertNotIn('vfio-pci,host=0000:4a:00.0', run.stdout)

    def test_no_devices_add_no_arguments(self):
        run = self.run_args([], set())
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), '')

    def test_guard_runs_before_qemu_and_arguments_reach_qemu(self):
        call = self.script.index('\nvfio_qemu_args\n')
        qemu = self.script.index('"$QEMU_TIMEOUT_SECONDS" "$QEMU"')
        self.assertLess(call, qemu)
        self.assertIn('args+=("${VFIO_ARGS[@]}")', self.script)


class ModeRefusals(unittest.TestCase):
    def refuse(self, *options):
        run = subprocess.run(['bash', str(HARNESS), *options], capture_output=True, text=True,
                             env=dict(os.environ, PATH='/usr/bin:/bin'))
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        return run.stderr

    def test_unknown_nic_model_is_refused(self):
        self.assertIn('invalid --nic', self.refuse('--nic', 'e1000'))

    def test_igb_is_refused_where_it_is_not_wired(self):
        self.assertIn('--nic igb applies', self.refuse('--nic', 'igb', '--xdomain'))

    def test_gpu_requires_official_user_space(self):
        self.assertIn('--nvidia-userspace', self.refuse('--gpu', '0000:01:00.0'))

    def test_gpu_excludes_the_cpu_standin_and_other_modes(self):
        for extra in (('--ce-sim',), ('--reliable',), ('--lifecycle',), ('--fault', 'drop-middle')):
            with self.subTest(extra=extra):
                self.assertIn('gpu requires its exclusive correctness mode',
                              self.refuse('--gpu', '0000:01:00.0', '--nvidia-userspace', '/', *extra))

    def test_tb_nhi_is_exclusive_of_gpu_and_xdomain(self):
        for extra in (('--gpu', '0000:01:00.0', '--nvidia-userspace', '/'), ('--lifecycle',)):
            with self.subTest(extra=extra):
                self.assertIn('exclusive correctness mode',
                              self.refuse('--tb-nhi', '0000:4a:00.0', *extra))

    def test_vfio_is_refused_in_modes_with_their_own_qemu_setup(self):
        self.assertIn('vfio devices are not wired', self.refuse('--vfio', '0000:4a:00.0', '--xdomain'))


class BusyboxAppletCheck(unittest.TestCase):
    """grep -q stops reading early; with pipefail the writer's SIGPIPE turns a
    present applet into a spurious FAIL (seen with Ubuntu 26.04 busybox)."""

    def test_applet_presence_check_consumes_the_whole_list(self):
        script = HARNESS.read_text()
        checks = re.findall(r'(?m)^.*busybox --list \| grep[^\n]*$', script)
        self.assertTrue(checks)
        for line in checks:
            self.assertNotRegex(line, r'grep -[A-Za-z]*q', line)

    def test_check_survives_a_writer_that_outlives_the_match(self):
        line = next(l for l in HARNESS.read_text().splitlines() if 'busybox --list | grep' in l)
        condition = line.split('||')[0].strip()
        fake = ('busybox() { echo arp; for i in $(seq 1 20000); do echo applet$i; done; }\n')
        program = 'set -euo pipefail\n' + fake + condition.replace('/bin/busybox', 'busybox') + ' && echo FOUND\n'
        for _ in range(5):
            run = subprocess.run(['bash', '-c', program], capture_output=True, text=True)
            self.assertEqual(run.stdout.strip(), 'FOUND', run.stderr)


class GuestGpuWiring(unittest.TestCase):
    def setUp(self):
        self.script = HARNESS.read_text()

    def test_modules_are_unloaded_on_every_guest_exit_path(self):
        finish = re.search(r'(?ms)^finish\(\) \{\n.*?^\}', self.script).group()
        self.assertIn('xdev_ext_gpu_guest.sh unload', finish)
        self.assertLess(finish.index('xdev_ext_gpu_guest.sh unload'), finish.index('poweroff -f'))

    def test_gpu_cases_get_the_ce_window_and_the_host_expects_it(self):
        self.assertIn('"$source_slba" "$ce_slba" "$groups" "$depth" "$ce_len" "$cli_timeout_ms"', self.script)
        block = self.script.index("<<'PYGPUEXPECT'")
        self.assertIn('if (( ${GPU:-0} )); then', self.script[block - 120:block])
        self.assertIn("expected[ce_offset:ce_offset+size] = source[source_offset:source_offset+size]",
                      self.script[block:block + 900])
        self.assertLess(self.script.index("(p/'expected.raw').write_bytes(expected)"), block)
        self.assertIn("ce_sim=options['ce_sim'] or sys.argv[11] == '1'", self.script)

    def test_tb_nhi_mode_builds_usb4_in_and_runs_rebind_cycles(self):
        self.assertIn('if (( ${TB_NHI:-0} )); then cfg -e USB4; fi', self.script)
        self.assertIn('sh /opt/xdev_ext/tb/xdev_ext_tb_nhi_guest.sh "$tb_nhi_cycles"', self.script)
        self.assertIn('grep -Fxq "XDEV_EXT_TB_NHI=PASS cycles=$TB_NHI_CYCLES" "$EV/guest.log"', self.script)

    def test_igb_mode_boots_one_cpu_and_uses_the_qemu_igb_model(self):
        self.assertIn("KERNEL_APPEND+=' maxcpus=1'", self.script)
        # QEMU's igb is an SR-IOV PF: on pcie.0 its VF placeholders take the next
        # slots ("slot 19 function 0 not available for igbvf" on giga), so each
        # port sits behind its own pcie-root-port, as a real NIC would.
        start = self.script.index('nic_args=(-device pcie-root-port')
        block = self.script[start:self.script.index('\n\tKERNEL_APPEND', start)]
        for port, wire, mac in (('nic_rp0', 'wire0', '01'), ('nic_rp1', 'wire1', '02')):
            self.assertIn(f'pcie-root-port,id={port},', block)
            self.assertIn(f'igb,netdev={wire},mac=02:00:00:00:00:{mac},bus={port}', block)
        self.assertIn('cfg -e NET_VENDOR_INTEL -e IGB', self.script)


if __name__ == '__main__':
    unittest.main()
