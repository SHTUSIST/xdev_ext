# SPDX-License-Identifier: GPL-2.0
"""Bare-metal bring-up contracts; no real kernel build, install or reboot.

The fragment must carry every symbol a deployment needs at once, the checker
must reject a final .config that lost one, a dry run must touch nothing, the
build/stage phase must write only inside its staging directory, and install
steps must never run without an explicit --apply.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / 'tools/build/baremetal.py'
FRAGMENT = ROOT / 'tools/build/baremetal.config'
SWITCH = ROOT / 'tools/boot/kernel_switch.py'
ZC_HELPER = ROOT / 'tests/integration/session/native/xdev_ext_mech_zc_debug.py'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bm = load(TOOL, 'baremetal_contract_subject')
switch = load(SWITCH, 'baremetal_kernel_switch')

RELEASE = '6.16.0-rc7-xdev-ext-bm'
NV_RELEASE = '590.48.01'
UUID = 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'
Y, YM, N = frozenset('y'), frozenset('ym'), frozenset('n')
# Written from the TODO.61 requirement, independently of the tool's table.
EXPECTED = {
    'NET_VENDOR_INTEL': Y, 'ICE': YM, 'XDP_SOCKETS': Y,
    'USB4': YM, 'XDEV_EXT_MECH_XDOMAIN': YM,
    'XDEV_EXT_MECH': Y, 'XDEV_EXT_MECH_CE': Y, 'XDEV_EXT_MECH_DMA': Y,
    'XDEV_EXT_MECH_ZEROCOPY': Y, 'XDEV_EXT_MECH_KVM_BOUNCE': N,
    'IO_URING_XDEV_EXT_BPF_POLICY': Y, 'XDP_SOCKETS_XDEV_EXT_POLICY': Y,
    'MEMORY_HOTPLUG': Y, 'MEMORY_HOTREMOVE': Y, 'MIGRATION': Y,
    'SPARSEMEM_VMEMMAP': Y, 'ZONE_DEVICE': Y, 'PCI_P2PDMA': Y,
    'IOMMU_SUPPORT': Y, 'INTEL_IOMMU': Y, 'AMD_IOMMU': Y,
    'BLK_DEV_NVME': Y, 'BPF': Y, 'BPF_SYSCALL': Y, 'BPF_JIT': Y,
    'DEBUG_INFO_BTF': Y, 'MODULES': Y, 'MODULE_UNLOAD': Y,
}


def fragment_values():
    values = {}
    for line in FRAGMENT.read_text().splitlines():
        if line.startswith('CONFIG_'):
            key, value = line[len('CONFIG_'):].split('=', 1)
            values[key] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            values[line[len('# CONFIG_'):-len(' is not set')]] = 'n'
    return values


class Fragment(unittest.TestCase):
    def test_required_table_matches_the_deployment_symbol_list(self):
        for symbol, allowed in EXPECTED.items():
            with self.subTest(symbol=symbol):
                self.assertEqual(frozenset(bm.REQUIRED.get(symbol, ())), allowed)

    def test_required_table_keeps_the_harness_p2pdma_set(self):
        helper = load(ZC_HELPER, 'baremetal_zc_debug')
        for symbol in helper.P2PDMA:
            self.assertEqual(frozenset(bm.REQUIRED[symbol]), Y, symbol)

    def test_fragment_sets_every_required_symbol_to_an_accepted_value(self):
        values = fragment_values()
        for symbol, allowed in bm.REQUIRED.items():
            with self.subTest(symbol=symbol):
                self.assertIn(values.get(symbol, 'n'), allowed)

    def test_fragment_is_plain_kconfig(self):
        for line in FRAGMENT.read_text().splitlines():
            if not line or (line.startswith('#') and not line.startswith('# CONFIG_')):
                continue
            with self.subTest(line=line):
                self.assertRegex(line, r'^(CONFIG_[A-Z0-9_]+=(y|m|"[^"$`]*"|[0-9]+)|# CONFIG_[A-Z0-9_]+ is not set)$')


class Checker(unittest.TestCase):
    def test_accepts_the_fragment_itself(self):
        bm.check_config(FRAGMENT.read_text())

    def test_rejects_each_missing_or_downgraded_symbol(self):
        text = FRAGMENT.read_text()
        values = fragment_values()
        for symbol, allowed in bm.REQUIRED.items():
            if allowed == N:
                continue
            line = f'CONFIG_{symbol}={values[symbol]}\n'
            self.assertIn(line, text)
            bad = ['', f'# CONFIG_{symbol} is not set\n']
            if allowed == Y:
                bad.append(f'CONFIG_{symbol}=m\n')
            for replacement in bad:
                with self.subTest(symbol=symbol, replacement=replacement):
                    with self.assertRaisesRegex(ValueError, symbol):
                        bm.check_config(text.replace(line, replacement))

    def test_rejects_the_kvm_bounce_fallback(self):
        text = FRAGMENT.read_text().replace('# CONFIG_XDEV_EXT_MECH_KVM_BOUNCE is not set\n', '')
        with self.assertRaisesRegex(ValueError, 'XDEV_EXT_MECH_KVM_BOUNCE'):
            bm.check_config(text + 'CONFIG_XDEV_EXT_MECH_KVM_BOUNCE=y\n')

    def test_cli_exit_status(self):
        with tempfile.TemporaryDirectory(prefix='bm-check-') as tmp:
            config = Path(tmp) / '.config'
            config.write_text(FRAGMENT.read_text())
            command = [sys.executable, '-I', str(TOOL), 'check-config', str(config)]
            ok = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            config.write_text(FRAGMENT.read_text().replace('CONFIG_AMD_IOMMU=y\n', ''))
            bad = subprocess.run(command, text=True, capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn('AMD_IOMMU', bad.stderr)


FAKE_MAKE = r'''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['FAKE_LOG'], 'a') as log:
    log.write('make ' + ' '.join(args) + '\n')
opts = dict(a.split('=', 1) for a in args if '=' in a and not a.startswith('-'))
chdir = pathlib.Path(args[args.index('-C') + 1])
release = os.environ['FAKE_RELEASE']
if chdir.name == 'nvidia-build':
    if 'modules' in args:
        out = chdir / 'kernel-open'
        out.mkdir(parents=True, exist_ok=True)
        for name in ('nvidia', 'nvidia-uvm', 'nvidia-modeset', 'nvidia-drm', 'nvidia-peermem'):
            (out / (name + '.ko')).write_text(release)
    sys.exit(0)
build = pathlib.Path(opts['O'])
if 'olddefconfig' in args:
    drop = os.environ.get('FAKE_DROP')
    if drop:
        config = build / '.config'
        config.write_text(''.join(l for l in config.read_text().splitlines(True)
                                  if not l.startswith('CONFIG_' + drop + '=')))
elif 'bzImage' in args:
    (build / 'arch/x86/boot').mkdir(parents=True, exist_ok=True)
    (build / 'arch/x86/boot/bzImage').write_text('image')
    (build / 'include/config').mkdir(parents=True, exist_ok=True)
    (build / 'include/config/kernel.release').write_text(release + '\n')
    (build / 'System.map').write_text('map')
    (build / 'vmlinux').write_text('elf')
elif 'modules_install' in args:
    target = pathlib.Path(opts['INSTALL_MOD_PATH']) / 'lib/modules' / release / 'kernel'
    target.mkdir(parents=True, exist_ok=True)
    (target / 'ice.ko').write_text('ice')
'''
FAKE_RECORD = r'''#!/usr/bin/env python3
import os, sys
with open(os.environ['FAKE_LOG'], 'a') as log:
    log.write(os.path.basename(sys.argv[0]) + ' ' + ' '.join(sys.argv[1:]) + '\n')
if os.path.basename(sys.argv[0]) == 'modinfo':
    print(os.environ['FAKE_RELEASE'] + ' SMP preempt mod_unload modversions')
'''


def snapshot(root, exclude):
    found = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if Path(dirpath, d) not in exclude]
        for name in dirnames + filenames:
            path = Path(dirpath, name)
            if path in exclude:
                continue
            info = path.lstat()
            found[str(path)] = (info.st_size, info.st_mtime_ns, info.st_mode)
    return found


class BringUp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='bm-bringup-')
        self.tmp = Path(self._tmp.name)
        self.linux = self.tmp / 'linux'
        (self.linux / 'scripts').mkdir(parents=True)
        (self.linux / 'Makefile').write_text('# fake\n')
        (self.linux / 'Kconfig').write_text('# fake\n')
        self.nvidia = self.tmp / 'nvidia'
        (self.nvidia / 'kernel-open').mkdir(parents=True)
        (self.nvidia / 'version.mk').write_text(f'NVIDIA_VERSION = {NV_RELEASE}\n')
        self.package = self.tmp / 'NVIDIA-Linux-x86_64'
        self.write_package(NV_RELEASE)
        self.base = self.tmp / 'config-distro'
        self.base.write_text('CONFIG_ICE=m\nCONFIG_BLK_DEV_NVME=m\n'
                             'CONFIG_SYSTEM_TRUSTED_KEYS="debian/canonical-certs.pem"\nCONFIG_EXT4_FS=y\n')
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        (self.bin / 'make').write_text(FAKE_MAKE)
        for name in ('depmod', 'modinfo', 'update-initramfs', 'ldconfig'):
            (self.bin / name).write_text(FAKE_RECORD)
        for path in self.bin.iterdir():
            path.chmod(0o755)
        self.logs = self.tmp / 'fake-logs'
        self.logs.mkdir()
        self.log = self.logs / 'calls'
        self.staging = self.tmp / 'staging'

    def tearDown(self):
        self._tmp.cleanup()

    def write_package(self, release):
        (self.package / 'firmware').mkdir(parents=True, exist_ok=True)
        for name in ('gsp_ga10x.bin', 'gsp_tu10x.bin'):
            (self.package / 'firmware' / name).write_text(name + release)
        for lib in ('libcuda', 'libnvidia-ml', 'libnvidia-ptxjitcompiler'):
            (self.package / f'{lib}.so.{release}').write_text(lib)
        (self.package / 'nvidia-smi').write_text('smi')
        (self.package / 'nvidia-modprobe').write_text('modprobe')
        (self.package / 'nvidia-modprobe').chmod(0o4755)

    def run_tool(self, *extra, env_extra=None):
        env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}', FAKE_LOG=str(self.log),
                   FAKE_RELEASE=RELEASE, **(env_extra or {}))
        command = [sys.executable, '-I', str(TOOL), 'bringup', '--staging', str(self.staging),
                   '--base-config', str(self.base), '--linux-src', str(self.linux),
                   '--nvidia-src', str(self.nvidia), '--nvidia-package', str(self.package),
                   '--jobs', '3', '--cc', 'gcc', *extra]
        return subprocess.run(command, text=True, capture_output=True, env=env, timeout=120)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_dry_run_prints_every_step_and_touches_nothing(self):
        before = snapshot(self.tmp, {self.logs})
        result = self.run_tool('--dry-run')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(snapshot(self.tmp, {self.logs}), before)
        self.assertFalse(self.staging.exists())
        self.assertEqual(self.calls(), [])
        out = result.stdout
        for needle in ('olddefconfig', 'check-config', 'bzImage', 'modules_install',
                       'XDEV_EXT_ENABLE_GPU_CE_DMA=1', f'lib/firmware/nvidia/{NV_RELEASE}',
                       f'libcuda.so.{NV_RELEASE}', 'update-initramfs', 'custom.cfg',
                       'kernel_switch.py plan', 'usr/bin/nvidia-modprobe',
                       'etc/udev/rules.d/60-xdev-ext-nvidia.rules'):
            self.assertIn(needle, out)
        self.assertFalse([l for l in out.splitlines() if l.startswith('RUN ')])

    def test_build_writes_only_inside_staging_and_skips_install(self):
        before = snapshot(self.tmp, {self.logs, self.staging})
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(snapshot(self.tmp, {self.logs, self.staging}), before)
        root = self.staging / 'root'
        for path in (f'boot/vmlinuz-{RELEASE}', f'boot/config-{RELEASE}',
                     f'lib/modules/{RELEASE}/kernel/ice.ko',
                     f'lib/modules/{RELEASE}/extra/nvidia/nvidia.ko',
                     f'lib/modules/{RELEASE}/extra/nvidia/nvidia-uvm.ko',
                     f'lib/firmware/nvidia/{NV_RELEASE}/gsp_ga10x.bin',
                     f'usr/lib/x86_64-linux-gnu/libcuda.so.{NV_RELEASE}', 'usr/bin/nvidia-smi'):
            self.assertTrue((root / path).is_file(), path)
        bm.check_config((root / f'boot/config-{RELEASE}').read_text())
        manifest = json.loads((self.staging / 'bringup.json').read_text())
        self.assertEqual((manifest['kernel_release'], manifest['nvidia_release']), (RELEASE, NV_RELEASE))
        calls = self.calls()
        self.assertTrue(any('XDEV_EXT_ENABLE_GPU_CE_DMA=1' in c and 'nvidia-build' in c for c in calls))
        self.assertTrue(any(c.startswith('depmod') and str(root) in c for c in calls))
        self.assertFalse(any(c.startswith(('update-initramfs', 'ldconfig')) for c in calls))
        self.assertIn('SKIP', result.stdout)
        self.assertIn('--apply', result.stdout)

    def test_build_stages_nvidia_modprobe_and_a_device_node_udev_rule(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        root = self.staging / 'root'
        helper = root / 'usr/bin/nvidia-modprobe'
        self.assertEqual(helper.read_text(), 'modprobe')
        # Executable, but never staged setuid: the udev rule runs it as root.
        self.assertEqual(helper.stat().st_mode & 0o7777, 0o755)
        rule = (root / 'etc/udev/rules.d/60-xdev-ext-nvidia.rules').read_text()
        lines = [l for l in rule.splitlines() if l and not l.startswith('#')]
        self.assertEqual(len(lines), 1, rule)
        self.assertIn('ACTION=="add"', lines[0])
        self.assertIn('DEVPATH=="/bus/pci/drivers/nvidia"', lines[0])
        self.assertIn('RUN+="/usr/bin/nvidia-modprobe -c0 -u"', lines[0])

    def test_refuses_a_package_without_nvidia_modprobe(self):
        (self.package / 'nvidia-modprobe').unlink()
        result = self.run_tool('--dry-run')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('nvidia-modprobe', result.stderr)

    def test_build_stops_when_kconfig_drops_a_required_symbol(self):
        result = self.run_tool(env_extra={'FAKE_DROP': 'ICE'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ICE', result.stderr)
        self.assertFalse(any('bzImage' in c for c in self.calls()))

    def test_refuses_a_user_space_package_of_another_release(self):
        self.package = self.tmp / 'other-package'
        self.write_package('590.44.01')
        result = self.run_tool('--dry-run')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(NV_RELEASE, result.stderr)

    def test_install_refuses_without_apply(self):
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        before = snapshot(self.tmp, {self.logs})
        command = [sys.executable, '-I', str(TOOL), 'install', '--staging', str(self.staging)]
        refused = subprocess.run(command, text=True, capture_output=True,
                                 env=dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}',
                                          FAKE_LOG=str(self.log), FAKE_RELEASE=RELEASE))
        self.assertEqual(refused.returncode, 2)
        self.assertIn('--apply', refused.stderr)
        self.assertEqual(snapshot(self.tmp, {self.logs}), before)
        self.assertFalse(any(c.startswith('update-initramfs') for c in self.calls()))


class Install(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='bm-install-')
        self.tmp = Path(self._tmp.name)
        self.staging = self.tmp / 'staging'
        root = self.staging / 'root'
        for path in (f'boot/vmlinuz-{RELEASE}', f'boot/System.map-{RELEASE}', f'boot/config-{RELEASE}',
                     f'lib/modules/{RELEASE}/extra/nvidia/nvidia.ko',
                     f'lib/firmware/nvidia/{NV_RELEASE}/gsp_ga10x.bin',
                     f'usr/lib/x86_64-linux-gnu/libcuda.so.{NV_RELEASE}', 'usr/bin/nvidia-smi',
                     'etc/modprobe.d/xdev-ext-nvidia.conf'):
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(path)
        (root / 'usr/lib/x86_64-linux-gnu/libcuda.so.1').symlink_to(f'libcuda.so.{NV_RELEASE}')
        (self.staging / 'bringup.json').write_text(json.dumps(
            {'kernel_release': RELEASE, 'nvidia_release': NV_RELEASE}))
        self.target = self.tmp / 'target'
        (self.target / 'boot/grub').mkdir(parents=True)
        (self.target / 'boot/grub/custom.cfg').write_text('# operator text\n')
        self.calls = []
        self.facts = {'root_uuid': UUID, 'boot_uuid': UUID, 'boot_prefix': '/boot',
                      'cmdline': 'ro quiet'}

    def tearDown(self):
        self._tmp.cleanup()

    def runner(self, argv):
        self.calls.append(list(argv))

    def install(self, **overrides):
        options = dict(apply=True, target_root=self.target, runner=self.runner, euid=0,
                       facts=self.facts, good_entry=None, out=io.StringIO())
        options.update(overrides)
        return bm.install(self.staging, **options)

    def test_without_apply_nothing_is_written_or_run(self):
        with self.assertRaisesRegex(bm.BringupError, '--apply'):
            self.install(apply=False)
        self.assertEqual(self.calls, [])
        self.assertFalse((self.target / f'boot/vmlinuz-{RELEASE}').exists())

    def test_apply_requires_root(self):
        with self.assertRaisesRegex(bm.BringupError, 'root'):
            self.install(euid=1000)
        self.assertEqual(self.calls, [])

    def test_apply_installs_staged_tree_and_a_switchable_grub_entry(self):
        self.install()
        for path in (f'boot/vmlinuz-{RELEASE}', f'lib/modules/{RELEASE}/extra/nvidia/nvidia.ko',
                     f'lib/firmware/nvidia/{NV_RELEASE}/gsp_ga10x.bin',
                     f'usr/lib/x86_64-linux-gnu/libcuda.so.{NV_RELEASE}'):
            self.assertTrue((self.target / path).is_file(), path)
        self.assertIn(['depmod', RELEASE], self.calls)
        self.assertIn(['update-initramfs', '-c', '-k', RELEASE], self.calls)
        custom = (self.target / 'boot/grub/custom.cfg').read_text()
        self.assertTrue(custom.startswith('# operator text\n'))
        lines = custom.splitlines()
        start = next(i for i, l in enumerate(lines) if l.startswith('menuentry '))
        self.assertIn(f'--id {bm.entry_id(RELEASE)}', lines[start])
        entry = switch._parse_entry({}, lines[start + 1:])
        self.assertEqual(entry['unsafe'], [])
        self.assertEqual(entry['linux'], f'/boot/vmlinuz-{RELEASE}')
        self.assertEqual(entry['initrd'], f'/boot/initrd.img-{RELEASE}')
        self.assertEqual(entry['root_uuid'], UUID.lower())
        self.assertIn(f'root=UUID={UUID}', entry['args'])

    def test_apply_refuses_an_existing_entry_or_differing_file(self):
        self.install()
        self.calls.clear()
        with self.assertRaisesRegex(bm.BringupError, 'exists'):
            self.install()
        self.assertEqual(self.calls, [])


    def test_apply_refuses_to_overwrite_a_differing_host_file(self):
        library = self.target / f'usr/lib/x86_64-linux-gnu/libcuda.so.{NV_RELEASE}'
        library.parent.mkdir(parents=True)
        library.write_text('another build')
        with self.assertRaisesRegex(bm.BringupError, 'different content'):
            self.install()
        self.assertEqual(library.read_text(), 'another build')
        self.assertFalse((self.target / f'boot/vmlinuz-{RELEASE}').exists())
        self.assertEqual(self.calls, [])

def config_space(msix_table_size):
    data = bytearray(256)
    struct.pack_into('<HH', data, 0, 0x8086, 0x5781)
    struct.pack_into('<H', data, 0x06, 0x0010)        # capability list present
    data[0x34] = 0x80
    data[0x80:0x82] = bytes((0x05, 0xa0))              # MSI -> next
    data[0xa0:0xa2] = bytes((0x11, 0x00))              # MSI-X, last
    struct.pack_into('<H', data, 0xa2, msix_table_size - 1)
    return bytes(data)


class DayOne(unittest.TestCase):
    def test_sgl_support_decoding(self):
        self.assertEqual(bm.decode_sgls(0), 'unsupported')
        self.assertEqual(bm.decode_sgls(0x1), 'supported')
        self.assertEqual(bm.decode_sgls(0xf0002), 'supported-dword-aligned')
        self.assertEqual(bm.decode_sgls(0x3), 'reserved')

    def test_msix_table_size_from_config_space(self):
        self.assertEqual(bm.msix_table_size(config_space(16)), 16)
        self.assertIsNone(bm.msix_table_size(config_space(16)[:0x40]))

    @staticmethod
    def pci_device(devices, name, vendor, device, klass, config=None, driver=None):
        path = devices / name
        path.mkdir(parents=True)
        for key, value in (('vendor', vendor), ('device', device), ('class', klass)):
            (path / key).write_text(value + '\n')
        if config is not None:
            (path / 'config').write_bytes(config)
        if driver:
            target = devices.parent / 'drivers' / driver
            target.mkdir(parents=True, exist_ok=True)
            (path / 'driver').symlink_to(target)
        return path

    def test_msix_table_size_explains_a_non_root_64_byte_read(self):
        with tempfile.TemporaryDirectory(prefix='bm-day1-') as tmp:
            devices = Path(tmp) / 'sys/bus/pci/devices'
            # sysfs returns only the 64-byte header to a non-root reader.
            self.pci_device(devices, '0000:00:0d.2', '0x8086', '0x7ec2', '0x0c0340',
                            config=config_space(16)[:0x40], driver='thunderbolt')
            facts = bm.day_one_facts(Path(tmp), lambda argv: '{}')
        record = facts['thunderbolt_nhi'][0]
        self.assertIsNone(record['msix_table_size'])
        self.assertEqual(record['msix_table_size_unreadable'], 'unreadable: rerun as root')

    def test_full_config_read_has_no_unreadable_field(self):
        with tempfile.TemporaryDirectory(prefix='bm-day1-') as tmp:
            devices = Path(tmp) / 'sys/bus/pci/devices'
            self.pci_device(devices, '0000:00:0d.2', '0x8086', '0x7ec2', '0x0c0340',
                            config=config_space(16))
            facts = bm.day_one_facts(Path(tmp), lambda argv: '{}')
        record = facts['thunderbolt_nhi'][0]
        self.assertEqual(record['msix_table_size'], 16)
        self.assertNotIn('msix_table_size_unreadable', record)

    def test_detects_an_unbound_thunderbolt3_nhi_of_class_system_other(self):
        with tempfile.TemporaryDirectory(prefix='bm-day1-') as tmp:
            devices = Path(tmp) / 'sys/bus/pci/devices'
            # Titan Ridge 4C NHI reports class 0x088000, not the USB4 class.
            self.pci_device(devices, '0000:05:00.0', '0x8086', '0x15eb', '0x088000',
                            config=config_space(16))
            # Another Intel 0x088000 function that is not an NHI.
            self.pci_device(devices, '0000:00:08.0', '0x8086', '0x1911', '0x088000',
                            config=config_space(4))
            facts = bm.day_one_facts(Path(tmp), lambda argv: '{}')
        self.assertEqual([r['pci'] for r in facts['thunderbolt_nhi']], ['0000:05:00.0'])
        self.assertIsNone(facts['thunderbolt_nhi'][0]['driver'])
        self.assertEqual(facts['thunderbolt_nhi'][0]['msix_table_size'], 16)

    def test_facts_from_sysfs_tree(self):
        with tempfile.TemporaryDirectory(prefix='bm-day1-') as tmp:
            root = Path(tmp)
            devices = root / 'sys/bus/pci/devices'
            gpu = devices / '0000:01:00.0'
            gpu.mkdir(parents=True)
            for name, value in (('vendor', '0x10de'), ('device', '0x2b85'), ('class', '0x030000'),
                                ('current_link_speed', '32.0 GT/s PCIe'), ('current_link_width', '16'),
                                ('max_link_speed', '32.0 GT/s PCIe'), ('max_link_width', '16')):
                (gpu / name).write_text(value + '\n')
            nhi = devices / '0000:00:0d.2'
            nhi.mkdir()
            (nhi / 'vendor').write_text('0x8086\n')
            (nhi / 'device').write_text('0x7ec2\n')
            (nhi / 'class').write_text('0x0c0340\n')
            (nhi / 'config').write_bytes(config_space(16))
            (root / 'sys/class/iommu/dmar0').mkdir(parents=True)
            group = root / 'sys/kernel/iommu_groups/7'
            (group / 'devices').mkdir(parents=True)
            (group / 'type').write_text('DMA-FQ\n')
            (group / 'devices/0000:01:00.0').mkdir()
            (root / 'sys/class/nvme/nvme0').mkdir(parents=True)
            (root / 'proc').mkdir()
            (root / 'proc/cmdline').write_text('BOOT_IMAGE=/vmlinuz ro intel_iommu=on\n')

            def runner(argv):
                self.assertEqual(argv[:2], ['nvme', 'id-ctrl'])
                self.assertEqual(argv[2], '/dev/nvme0')
                return json.dumps({'sgls': 0xf0002, 'mn': 'TEST'})

            facts = bm.day_one_facts(root, runner)
        self.assertEqual(facts['nvme'][0]['controller'], 'nvme0')
        self.assertEqual(facts['nvme'][0]['sgls'], 'supported-dword-aligned')
        self.assertEqual(facts['thunderbolt_nhi'][0]['msix_table_size'], 16)
        self.assertEqual(facts['iommu']['units'], ['dmar0'])
        self.assertEqual(facts['iommu']['vendor'], 'intel')
        self.assertEqual(facts['iommu']['cmdline'], ['intel_iommu=on'])
        self.assertEqual(facts['iommu']['groups']['0000:01:00.0'], 'DMA-FQ')
        self.assertEqual(facts['nvidia_gpu'][0]['current_link_speed'], '32.0 GT/s PCIe')
        self.assertEqual(facts['nvidia_gpu'][0]['current_link_width'], '16')


if __name__ == '__main__':
    unittest.main()
