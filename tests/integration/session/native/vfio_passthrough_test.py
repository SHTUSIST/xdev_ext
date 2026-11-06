#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Guard and bind/restore behavior of the VFIO passthrough helper.

Every case builds a private fake sysfs/proc tree. Nothing touches the real
host: the helper only reads and writes paths under the given roots.
"""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
HELPER = HERE / 'vfio_passthrough.py'


def load():
    spec = importlib.util.spec_from_file_location('vfio_passthrough', HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHost:
    """A minimal sysfs/proc/dev layout shaped like the kernel's."""

    def __init__(self, base):
        self.base = Path(base)
        self.sys = self.base / 'sys'
        self.proc = self.base / 'proc'
        self.dev = self.base / 'dev'
        for path in (self.sys / 'bus/pci/devices', self.sys / 'bus/pci/drivers',
                     self.sys / 'kernel/iommu_groups', self.proc / 'self', self.dev):
            path.mkdir(parents=True, exist_ok=True)
        (self.sys / 'bus/pci/drivers_probe').write_text('')
        (self.proc / 'self/mountinfo').write_text('')
        (self.proc / 'swaps').write_text('Filename Type Size Used Priority\n')
        self.addresses = {}

    def driver(self, name):
        path = self.sys / 'bus/pci/drivers' / name
        path.mkdir(exist_ok=True)
        for leaf in ('bind', 'unbind', 'new_id'):
            (path / leaf).touch()
        return path

    def device(self, bdf, cls='0x030000', driver=None, group=1, reset='flr bus'):
        path = self.sys / 'devices/pci0000:00' / bdf
        path.mkdir(parents=True)
        (path / 'class').write_text(cls + '\n')
        (path / 'driver_override').write_text('(null)\n')
        if reset is not None:
            (path / 'reset_method').write_text(reset + '\n')
        (self.sys / 'bus/pci/devices' / bdf).symlink_to(path)
        groupdir = self.sys / 'kernel/iommu_groups' / str(group) / 'devices'
        groupdir.mkdir(parents=True, exist_ok=True)
        (groupdir / bdf).symlink_to(path)
        (path / 'iommu_group').symlink_to(groupdir.parent)
        if driver:
            self.bind(bdf, driver)
        return path

    def bind(self, bdf, driver):
        path = self.sys / 'bus/pci/devices' / bdf
        link = path / 'driver'
        if link.is_symlink():
            link.unlink()
        if driver:
            link.symlink_to(self.driver(driver))

    def netdev(self, bdf, name, up=False, operstate='down', addresses=()):
        net = self.sys / 'bus/pci/devices' / bdf / 'net' / name
        net.mkdir(parents=True)
        (net / 'operstate').write_text(operstate + '\n')
        (net / 'flags').write_text('0x1003\n' if up else '0x1002\n')
        self.addresses[name] = list(addresses)

    def nvme(self, bdf, ctrl, ns, devnum, parts=()):
        base = self.sys / 'bus/pci/devices' / bdf / 'nvme' / ctrl
        disk = base / ns
        disk.mkdir(parents=True)
        (disk / 'dev').write_text(devnum + '\n')
        (disk / 'holders').mkdir()
        for name, number in parts:
            part = disk / name
            part.mkdir()
            (part / 'dev').write_text(number + '\n')
            (part / 'holders').mkdir()
        return disk

    def mount(self, devnum, target):
        with (self.proc / 'self/mountinfo').open('a') as out:
            out.write(f'36 25 {devnum} / {target} rw,relatime shared:1 - ext4 /dev/x rw\n')

    def opened(self, pid, comm, target):
        fd = self.proc / str(pid) / 'fd'
        fd.mkdir(parents=True, exist_ok=True)
        (self.proc / str(pid) / 'comm').write_text(comm + '\n')
        (fd / str(len(list(fd.iterdir())) + 3)).symlink_to(target)

    def host(self, module):
        return module.Host(sys_root=self.sys, proc_root=self.proc, dev_root=self.dev,
                           addresses=lambda name: self.addresses.get(name, []))

    def read(self, bdf, leaf):
        return (self.sys / 'bus/pci/devices' / bdf / leaf).read_text()

    def current_driver(self, bdf):
        link = self.sys / 'bus/pci/devices' / bdf / 'driver'
        return os.path.basename(os.readlink(link)) if link.is_symlink() else None


class Base(unittest.TestCase):
    def setUp(self):
        self.mod = load()
        self.tmp = tempfile.TemporaryDirectory(prefix='vfio-guard-')
        self.fake = FakeHost(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()


class GroupViability(Base):
    """A device may be passed only when VFIO would accept its whole group."""

    def test_vfio_bound_device_with_driverless_sibling_is_ready(self):
        self.fake.device('0000:01:00.0', driver='vfio-pci', group=28)
        self.fake.device('0000:01:00.1', cls='0x040300', driver=None, group=28, reset=None)
        self.mod.check_ready(self.fake.host(self.mod), '01:00.0')

    def test_device_still_on_host_driver_is_refused(self):
        self.fake.device('0000:01:00.0', driver='nvidia', group=28)
        with self.assertRaisesRegex(self.mod.GuardError, 'bound to nvidia, not vfio-pci'):
            self.mod.check_ready(self.fake.host(self.mod), '0000:01:00.0')

    def test_group_member_on_host_driver_is_refused(self):
        self.fake.device('0000:4a:00.0', cls='0x0c0340', driver='vfio-pci', group=45)
        self.fake.device('0000:54:00.0', cls='0x0c0330', driver='xhci_hcd', group=45)
        with self.assertRaisesRegex(self.mod.GuardError, '0000:54:00.0 .*xhci_hcd'):
            self.mod.check_ready(self.fake.host(self.mod), '0000:4a:00.0')

    def test_bridges_on_pcieport_do_not_block_the_group(self):
        self.fake.device('0000:4a:00.0', cls='0x0c0340', driver='vfio-pci', group=45)
        self.fake.device('0000:49:00.0', cls='0x060400', driver='pcieport', group=45)
        self.fake.device('0000:54:00.0', cls='0x0c0330', driver='vfio-pci', group=45)
        self.mod.check_ready(self.fake.host(self.mod), '0000:4a:00.0')

    def test_non_bridge_on_pcieport_name_is_still_refused(self):
        self.fake.device('0000:4a:00.0', cls='0x0c0340', driver='vfio-pci', group=45)
        self.fake.device('0000:4a:00.1', cls='0x020000', driver='pcieport', group=45)
        with self.assertRaises(self.mod.GuardError):
            self.mod.check_ready(self.fake.host(self.mod), '0000:4a:00.0')

    def test_bridge_itself_is_never_passed(self):
        self.fake.device('0000:49:00.0', cls='0x060400', driver='vfio-pci', group=45)
        with self.assertRaisesRegex(self.mod.GuardError, 'bridge'):
            self.mod.check_ready(self.fake.host(self.mod), '0000:49:00.0')

    def test_missing_device_is_refused(self):
        with self.assertRaisesRegex(self.mod.GuardError, 'no PCI device'):
            self.mod.check_ready(self.fake.host(self.mod), '0000:02:00.0')

    def test_malformed_bdf_is_refused(self):
        for text in ('01:00', '0000:01:00.8', 'xx:00.0', '0000:01:00.0/../x', ''):
            with self.subTest(text=text), self.assertRaises(self.mod.GuardError):
                self.mod.normalize_bdf(text)


class ActiveUsers(Base):
    """Binding away a device that the host is using must be refused."""

    def test_idle_device_has_no_users(self):
        self.fake.device('0000:47:00.0', cls='0x020000', driver='atlantic', group=44)
        self.fake.netdev('0000:47:00.0', 'enp71s0', up=False)
        self.assertEqual(self.mod.active_users(self.fake.host(self.mod), '0000:47:00.0'), [])

    def test_up_interface_is_a_user(self):
        self.fake.device('0000:44:00.0', cls='0x020000', driver='atlantic', group=41)
        self.fake.netdev('0000:44:00.0', 'eno1', up=True, operstate='up')
        users = self.mod.active_users(self.fake.host(self.mod), '0000:44:00.0')
        self.assertTrue(any('eno1' in user and 'up' in user for user in users), users)

    def test_interface_with_address_is_a_user_even_when_down(self):
        self.fake.device('0000:44:00.0', cls='0x020000', driver='atlantic', group=41)
        self.fake.netdev('0000:44:00.0', 'eno1', addresses=['128.114.59.190/24'])
        users = self.mod.active_users(self.fake.host(self.mod), '0000:44:00.0')
        self.assertTrue(any('128.114.59.190/24' in user for user in users), users)

    def test_mounted_namespace_partition_is_a_user(self):
        self.fake.device('0000:60:00.0', cls='0x010802', driver='nvme', group=50)
        self.fake.nvme('0000:60:00.0', 'nvme1', 'nvme1n1', '259:0', parts=[('nvme1n1p2', '259:2')])
        self.fake.mount('259:2', '/mnt/data')
        users = self.mod.active_users(self.fake.host(self.mod), '0000:60:00.0')
        self.assertTrue(any('/mnt/data' in user for user in users), users)

    def test_swap_and_holders_are_users(self):
        self.fake.device('0000:60:00.0', cls='0x010802', driver='nvme', group=50)
        disk = self.fake.nvme('0000:60:00.0', 'nvme1', 'nvme1n1', '259:0')
        (disk / 'holders' / 'dm-0').mkdir()
        (self.fake.proc / 'swaps').write_text(
            'Filename Type Size Used Priority\n/dev/nvme1n1 partition 8 0 -2\n')
        users = self.mod.active_users(self.fake.host(self.mod), '0000:60:00.0')
        self.assertTrue(any('dm-0' in user for user in users), users)
        self.assertTrue(any('swap' in user for user in users), users)

    def test_open_nvidia_node_is_a_user_of_an_nvidia_bound_gpu(self):
        self.fake.device('0000:01:00.0', driver='nvidia', group=28)
        self.fake.opened(3968848, 'Xorg', '/dev/nvidia0')
        users = self.mod.active_users(self.fake.host(self.mod), '0000:01:00.0')
        self.assertTrue(any('3968848' in user and 'Xorg' in user for user in users), users)

    def test_open_drm_and_sound_nodes_of_the_device_are_users(self):
        gpu = self.fake.device('0000:01:00.0', driver='nvidia', group=28)
        (gpu / 'drm/card2').mkdir(parents=True)
        (gpu / 'drm/renderD129').mkdir(parents=True)
        audio = self.fake.device('0000:01:00.1', cls='0x040300', driver='snd_hda_intel',
                                 group=28, reset=None)
        (audio / 'sound/card1').mkdir(parents=True)
        self.fake.opened(10, 'Xorg', '/dev/dri/renderD129')
        self.fake.opened(11, 'pipewire', '/dev/snd/pcmC1D3p')
        self.fake.opened(12, 'other', '/dev/dri/renderD128')
        host = self.fake.host(self.mod)
        self.assertTrue(any('renderD129' in u for u in self.mod.active_users(host, '0000:01:00.0')))
        audio_users = self.mod.active_users(host, '0000:01:00.1')
        self.assertTrue(any('pcmC1D3p' in u for u in audio_users), audio_users)
        self.assertFalse(any('renderD128' in u for u in self.mod.active_users(host, '0000:01:00.0')))


class BindRestore(Base):
    """Binding records enough state to put every setting back."""

    def gpu(self):
        self.fake.device('0000:01:00.0', driver='nvidia', group=28)
        self.fake.driver('vfio-pci')
        return self.fake.host(self.mod)

    def test_bind_moves_device_to_vfio_and_records_original_settings(self):
        host = self.gpu()
        state = Path(self.tmp.name) / 'state.json'
        self.mod.bind(host, '0000:01:00.0', 'vfio-pci', state, reset_method='')
        saved = json.loads(state.read_text())
        self.assertEqual(saved['original_driver'], 'nvidia')
        self.assertEqual(saved['original_reset_method'], 'flr bus')
        self.assertEqual(self.fake.read('0000:01:00.0', 'driver_override'), 'vfio-pci')
        # sysfs ignores a zero-length write; the kernel disables every reset
        # method only for an empty line, so the helper must write a newline.
        self.assertEqual(self.fake.read('0000:01:00.0', 'reset_method'), '\n')
        nvidia = self.fake.sys / 'bus/pci/drivers/nvidia/unbind'
        vfio = self.fake.sys / 'bus/pci/drivers/vfio-pci/bind'
        self.assertEqual(nvidia.read_text(), '0000:01:00.0')
        self.assertEqual(vfio.read_text(), '0000:01:00.0')

    def test_bind_refuses_a_device_with_users_and_writes_nothing(self):
        host = self.gpu()
        self.fake.opened(77, 'Xorg', '/dev/nvidiactl')
        state = Path(self.tmp.name) / 'state.json'
        with self.assertRaisesRegex(self.mod.GuardError, 'Xorg'):
            self.mod.bind(host, '0000:01:00.0', 'vfio-pci', state)
        self.assertFalse(state.exists())
        self.assertEqual(self.fake.read('0000:01:00.0', 'driver_override'), '(null)\n')
        self.assertEqual((self.fake.sys / 'bus/pci/drivers/nvidia/unbind').read_text(), '')

    def test_dry_run_writes_nothing_and_returns_the_plan(self):
        host = self.gpu()
        state = Path(self.tmp.name) / 'state.json'
        actions = self.mod.bind(host, '0000:01:00.0', 'vfio-pci', state, reset_method='',
                                dry_run=True)
        self.assertFalse(state.exists())
        self.assertEqual(self.fake.read('0000:01:00.0', 'driver_override'), '(null)\n')
        written = [os.path.basename(path) for path, _ in actions]
        self.assertEqual(written, ['reset_method', 'driver_override', 'unbind', 'bind'])

    def test_driverless_mode_leaves_no_driver_able_to_claim_the_function(self):
        self.fake.device('0000:01:00.1', cls='0x040300', driver='snd_hda_intel', group=28,
                         reset=None)
        host = self.fake.host(self.mod)
        state = Path(self.tmp.name) / 'audio.json'
        self.mod.bind(host, '0000:01:00.1', None, state)
        override = self.fake.read('0000:01:00.1', 'driver_override')
        self.assertNotIn(override.strip(), ('', '(null)', 'snd_hda_intel'))
        self.assertEqual((self.fake.sys / 'bus/pci/drivers/snd_hda_intel/unbind').read_text(),
                         '0000:01:00.1')

    def test_bind_without_loaded_vfio_driver_is_refused(self):
        self.fake.device('0000:01:00.0', driver='nvidia', group=28)
        host = self.fake.host(self.mod)
        with self.assertRaisesRegex(self.mod.GuardError, 'vfio-pci .*not loaded'):
            self.mod.bind(host, '0000:01:00.0', 'vfio-pci', Path(self.tmp.name) / 's.json')

    def test_restore_returns_driver_override_and_reset_method(self):
        host = self.gpu()
        state = Path(self.tmp.name) / 'state.json'
        self.mod.bind(host, '0000:01:00.0', 'vfio-pci', state, reset_method='')
        # The fake kernel does not move links on bind; emulate the result.
        self.fake.bind('0000:01:00.0', 'vfio-pci')
        result = self.mod.restore(host, state)
        self.assertEqual((self.fake.sys / 'bus/pci/drivers/vfio-pci/unbind').read_text(),
                         '0000:01:00.0')
        self.assertEqual(self.fake.read('0000:01:00.0', 'driver_override'), '\n')
        self.assertEqual(self.fake.read('0000:01:00.0', 'reset_method'), 'flr bus')
        self.assertEqual((self.fake.sys / 'bus/pci/drivers/nvidia/bind').read_text(),
                         '0000:01:00.0')
        self.assertEqual(result, 'bind-requested')

    def test_restore_with_unloaded_original_driver_reports_partial(self):
        host = self.gpu()
        state = Path(self.tmp.name) / 'state.json'
        self.mod.bind(host, '0000:01:00.0', 'vfio-pci', state, reset_method='')
        self.fake.bind('0000:01:00.0', 'vfio-pci')
        # modprobe -r nvidia removed the driver directory while unbound.
        for leaf in ('bind', 'unbind', 'new_id'):
            (self.fake.sys / 'bus/pci/drivers/nvidia' / leaf).unlink()
        (self.fake.sys / 'bus/pci/drivers/nvidia').rmdir()
        result = self.mod.restore(host, state)
        self.assertEqual(result, 'original-driver-not-loaded')
        self.assertEqual((self.fake.sys / 'bus/pci/drivers_probe').read_text(), '0000:01:00.0')
        self.assertEqual(self.fake.read('0000:01:00.0', 'driver_override'), '\n')


class CommandLine(Base):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, '-B', str(HELPER),
                               '--sys-root', str(self.fake.sys), '--proc-root', str(self.fake.proc),
                               '--dev-root', str(self.fake.dev), '--no-ip', *args],
                              capture_output=True, text=True)

    def test_check_exit_codes(self):
        self.fake.device('0000:01:00.0', driver='vfio-pci', group=28)
        self.fake.device('0000:01:00.1', cls='0x040300', driver='snd_hda_intel', group=28,
                         reset=None)
        run = self.run_cli('check', '0000:01:00.0')
        self.assertEqual(run.returncode, 1, run.stdout + run.stderr)
        self.assertIn('snd_hda_intel', run.stderr)
        self.fake.bind('0000:01:00.1', None)
        run = self.run_cli('check', '0000:01:00.0')
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('VFIO_READY 0000:01:00.0', run.stdout)

    def test_bind_dry_run_prints_plan(self):
        self.fake.device('0000:01:00.0', driver='nvidia', group=28)
        self.fake.driver('vfio-pci')
        state = Path(self.tmp.name) / 'cli.json'
        run = self.run_cli('bind', '0000:01:00.0', '--target', 'vfio-pci', '--reset-method', '',
                           '--state', str(state), '--dry-run')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn('DRY-RUN write', run.stdout)
        self.assertFalse(state.exists())


if __name__ == '__main__':
    unittest.main()
