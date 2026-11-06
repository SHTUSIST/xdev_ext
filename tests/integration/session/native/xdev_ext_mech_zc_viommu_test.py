#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host checks for the optional emulated Intel VT-d switch of the KVM harness.

The QEMU argument checks evaluate the harness's own argument construction in
bash; the console checks feed synthetic guest kernel lines to the validator.
Nothing here boots a guest, maps a device or measures time.
"""
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
KVM = HERE / 'xdev_ext_mech_zc_kvm.sh'
VALIDATOR = HERE / 'xdev_ext_mech_zc_viommu.py'
MATRIX = HERE / 'xdev_ext_mech_zc_fault_matrix.py'

# The 8f5561e harness command for the plain (no compat/peer/lifecycle) case,
# copied from its qemu.command evidence with the scratch path replaced by /S.
BASE = ['-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '4', '-m', '4096',
        '-nographic', '-no-reboot', '-kernel', '/S/build/arch/x86/boot/bzImage',
        '-initrd', '/S/initramfs.cpio.gz',
        '-append', 'console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr ipv6.disable=1',
        '-nic', 'none', '-netdev', 'hubport,id=wire0,hubid=0',
        '-netdev', 'hubport,id=wire1,hubid=0',
        '-device', 'virtio-net-pci,netdev=wire0,mac=02:00:00:00:00:01,iommu_platform=on,disable-legacy=on,rx_queue_size=1024',
        '-device', 'virtio-net-pci,netdev=wire1,mac=02:00:00:00:00:02,iommu_platform=on,disable-legacy=on,rx_queue_size=1024',
        '-drive', 'file=/S/source.raw,if=none,id=src,format=raw,cache=none,aio=threads',
        '-device', 'nvme,drive=src,serial=UBRZCSRC01',
        '-drive', 'file=/S/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads',
        '-device', 'nvme,drive=dst,serial=UBRZCDST01']
VIOMMU_DEVICE = 'intel-iommu,intremap=on,caching-mode=on'
VIOMMU_APPEND = ' intel_iommu=on iommu.strict=1'


def harness_args(viommu):
    """Run the harness's args=( ... ) block and its vIOMMU block in bash."""
    script = KVM.read_text()
    block = re.search(r'(?ms)^args=\(-machine .*?\)\n', script)
    if block is None:
        raise AssertionError('harness QEMU args block not found')
    marked = re.search(r'(?ms)^# --- vIOMMU QEMU arguments.*?^# --- end vIOMMU QEMU arguments\n', script)
    program = '\n'.join([
        'set -euo pipefail',
        'BUILD=/S/build; SCRATCH=/S; VIOMMU=%d' % viommu,
        'destination_drive="file=$SCRATCH/destination.raw,if=none,id=dst,format=raw,cache=none,aio=threads"',
        'wire_args=(-netdev hubport,id=wire0,hubid=0 -netdev hubport,id=wire1,hubid=0)',
        block.group(0),
        marked.group(0) if marked else '',
        'printf "%s\\0" "${args[@]}"', ''])
    run = subprocess.run(['bash', '-c', program], capture_output=True, timeout=10)
    if run.returncode:
        raise AssertionError(run.stderr.decode())
    return run.stdout.decode().split('\0')[:-1], marked is not None


def load_validator():
    spec = importlib.util.spec_from_file_location('xdev_ext_mech_zc_viommu', VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HarnessArguments(unittest.TestCase):
    def test_default_off_is_byte_identical_to_the_previous_command(self):
        args, _ = harness_args(0)
        self.assertEqual(args, BASE)

    def test_on_adds_split_irqchip_vtd_first_and_strict_guest_cmdline(self):
        args, marked = harness_args(1)
        self.assertTrue(marked, 'harness lacks the vIOMMU QEMU argument block')
        expected = list(BASE)
        expected[1] = 'q35,accel=kvm,kernel-irqchip=split'
        expected[2:2] = ['-device', VIOMMU_DEVICE]
        index = expected.index('-append') + 1
        expected[index] += VIOMMU_APPEND
        self.assertEqual(args, expected)
        # The emulated IOMMU must precede every PCI device it translates.
        devices = [args[i + 1] for i, value in enumerate(args) if value == '-device']
        self.assertEqual(devices[0], VIOMMU_DEVICE)

    def run_harness(self, *options):
        return subprocess.run(['bash', str(KVM), *options], capture_output=True,
                              text=True, timeout=20)

    def test_option_is_parsed(self):
        # An invalid scratch stops the harness after option parsing, before
        # any write; an unknown option exits 2 with a message instead.
        run = self.run_harness('--viommu', '--scratch', '/nonexistent/claude-viommu-probe')
        self.assertNotIn('unknown option', run.stderr)
        self.assertNotEqual(run.returncode, 2, run.stderr)

    def test_xdomain_rejects_viommu(self):
        run = self.run_harness('--xdomain', '--viommu', '--scratch', '/nonexistent/claude-viommu-probe')
        self.assertEqual(run.returncode, 2)
        self.assertNotIn('unknown option', run.stderr)
        self.assertIn('viommu does not apply to xdomain', run.stderr)

    def test_harness_records_requires_and_validates_viommu(self):
        script = KVM.read_text()
        wanted = ("printf 'viommu=%s\\n' \"$VIOMMU\" >>\"$EV/provenance.txt\"",
                  'grep -Fxq CONFIG_INTEL_IOMMU=y "$BUILD/.config"',
                  'xdev_ext_mech_zc_viommu.py" "$EV/guest.log" "$EV/viommu.json"')
        for fragment in wanted:
            self.assertTrue(fragment in script, 'harness lacks: ' + fragment)


class FaultMatrixPassThrough(unittest.TestCase):
    def test_matrix_forwards_viommu_and_records_matching_qemu_command(self):
        run = subprocess.run([sys.executable, str(MATRIX), '--dry-run', '--viommu',
                              '--campaign', 'exit-source', '/tmp/xdev-ext-e2e.Contract', '/private/kernel'],
                             capture_output=True, text=True, timeout=20, cwd=HERE)
        self.assertEqual(run.returncode, 0, run.stderr)
        plan = [line for line in run.stdout.splitlines() if line.startswith('{')]
        self.assertEqual(len(plan), 1)
        import json
        item = json.loads(plan[0])
        self.assertIn('--viommu', item['harness_command'])
        self.assertEqual(item['qemu_command'][1:3], ['-machine', 'q35,accel=kvm,kernel-irqchip=split'])
        self.assertEqual(item['qemu_command'][3:5], ['-device', VIOMMU_DEVICE])
        append = item['qemu_command'][item['qemu_command'].index('-append') + 1]
        self.assertTrue(append.endswith(VIOMMU_APPEND))

    def test_matrix_default_command_unchanged(self):
        run = subprocess.run([sys.executable, str(MATRIX), '--dry-run',
                              '--campaign', 'exit-source', '/tmp/xdev-ext-e2e.Contract', '/private/kernel'],
                             capture_output=True, text=True, timeout=20, cwd=HERE)
        self.assertEqual(run.returncode, 0, run.stderr)
        import json
        item = json.loads([line for line in run.stdout.splitlines() if line.startswith('{')][0])
        self.assertNotIn('--viommu', item['harness_command'])
        self.assertEqual(item['qemu_command'][1:3], ['-machine', 'q35,accel=kvm'])
        self.assertNotIn('intel-iommu', ' '.join(item['qemu_command']))


GOOD = '''\
[    0.000000] Command line: console=ttyS0 rdinit=/init panic=-1 loglevel=6 nokaslr ipv6.disable=1 intel_iommu=on iommu.strict=1
[    0.010000] DMAR: IOMMU enabled
[    0.020000] DMAR: Host address width 39
[    2.913574] pci 0000:00:00.0: [8086:29c0] type 00 class 0x060000 conventional PCI endpoint
[    2.965587] pci 0000:00:03.0: [1af4:1041] type 00 class 0x020000 conventional PCI endpoint
[    3.021560] pci 0000:00:04.0: [1b36:0010] type 00 class 0x010802 PCIe Root Complex Integrated Endpoint
[    3.045528] pci 0000:00:05.0: [1b36:0010] type 00 class 0x010802 PCIe Root Complex Integrated Endpoint
[    3.354681] iommu: Default domain type: Translated
[    3.354687] iommu: DMA domain TLB invalidation policy: strict mode
[    3.400000] DMAR: Intel(R) Virtualization Technology for Directed I/O
[    3.400100] pci 0000:00:00.0: Adding to iommu group 0
[    3.400200] pci 0000:00:03.0: Adding to iommu group 2
[    3.400300] pci 0000:00:04.0: Adding to iommu group 3
[    3.400400] pci 0000:00:05.0: Adding to iommu group 4
'''


class ConsoleValidator(unittest.TestCase):
    def setUp(self):
        self.v = load_validator()

    def test_enabled_strict_translated_and_grouped_passes(self):
        result = self.v.validate_viommu_console(GOOD)
        self.assertEqual(result['nvme'], ['0000:00:04.0', '0000:00:05.0'])
        self.assertEqual(result['virtio'], ['0000:00:03.0'])
        self.assertEqual(result['groups']['0000:00:04.0'], 3)
        self.assertEqual(result['faults'], 0)
        self.assertEqual(result['policy'], 'strict')

    def assertRejects(self, text, fragment):
        with self.assertRaises(ValueError) as caught:
            self.v.validate_viommu_console(text)
        self.assertIn(fragment, str(caught.exception))

    def test_missing_enable_line(self):
        self.assertRejects(GOOD.replace('DMAR: IOMMU enabled', 'DMAR: IOMMU disabled'), 'IOMMU enabled')

    def test_missing_vtd_init(self):
        self.assertRejects(GOOD.replace('Intel(R) Virtualization Technology for Directed I/O', 'x'),
                           'Directed I/O')

    def test_lazy_policy(self):
        self.assertRejects(GOOD.replace('strict mode', 'lazy mode'), 'strict')

    def test_passthrough_domain(self):
        self.assertRejects(GOOD.replace('Default domain type: Translated', 'Default domain type: Passthrough'),
                           'Translated')

    def test_nvme_without_group(self):
        self.assertRejects(GOOD.replace('pci 0000:00:05.0: Adding to iommu group 4\n', ''), '0000:00:05.0')

    def test_virtio_without_group(self):
        self.assertRejects(GOOD.replace('pci 0000:00:03.0: Adding to iommu group 2\n', ''), '0000:00:03.0')

    def test_no_nvme(self):
        text = '\n'.join(line for line in GOOD.splitlines() if '0x010802' not in line)
        self.assertRejects(text, 'NVMe')

    def test_dma_fault(self):
        fault = ('[   10.000000] DMAR: DRHD: handling fault status reg 2\n'
                 '[   10.000001] DMAR: [DMA Write NO_PASID] Request device [00:05.0] fault addr 0xffffe000 '
                 '[fault reason 0x05] PTE Write access is not set\n')
        self.assertRejects(GOOD + fault, 'fault')

    def test_allowed_faults_are_counted_not_rejected(self):
        fault = ('[   10.000001] DMAR: [DMA Write NO_PASID] Request device [00:05.0] fault addr 0xffffe000 '
                 '[fault reason 0x05] PTE Write access is not set\n')
        result = self.v.validate_viommu_console(GOOD + fault, allow_faults=True)
        self.assertEqual(result['faults'], 1)
        self.assertEqual(result['fault_devices'], ['0000:00:05.0'])

    def test_main_writes_json_and_pass_line(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'guest.log'
            out = Path(directory) / 'viommu.json'
            log.write_text(GOOD)
            run = subprocess.run([sys.executable, '-I', str(VALIDATOR), str(log), str(out)],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(run.stdout.strip(),
                             'XDEV_EXT_ZC_VIOMMU=PASS dmar=enabled domain=translated policy=strict nvme=2 virtio=1 faults=0')
            self.assertEqual(json.loads(out.read_text())['nvme'], ['0000:00:04.0', '0000:00:05.0'])
            log.write_text(GOOD.replace('strict mode', 'lazy mode'))
            run = subprocess.run([sys.executable, '-I', str(VALIDATOR), str(log), str(out)],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 1)
            self.assertTrue(run.stdout.startswith('XDEV_EXT_ZC_VIOMMU=FAIL'))


if __name__ == '__main__':
    unittest.main()
