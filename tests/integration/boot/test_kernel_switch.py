# SPDX-License-Identifier: GPL-2.0
"""Independent software behavior tests; no real kernel load or host reboot."""
import copy
import io
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
TOOL = ROOT / 'tools/boot/kernel_switch.py'
if TOOL.is_file():
    SPEC = importlib.util.spec_from_file_location('kernel_switch_contract_subject', TOOL)
    switch = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = switch
    SPEC.loader.exec_module(switch)
else:
    switch = None
FIXTURES = Path(__file__).with_name('fixtures')
GRUB = (FIXTURES / 'grub_saved.cfg').read_text()
ENV = (FIXTURES / 'grub_saved.env').read_text()
EFI_MANAGER = (FIXTURES / 'efi_boot_manager.txt').read_text()
EFI_FORWARDER = (FIXTURES / 'efi_grub_forwarder.cfg').read_text()
TRIAL = 'advanced-test-root>trial-test-root'
GOOD = 'advanced-test-root>good-test-root'


def image(release='6.16.0-trial'):
    """Synthetic x86 bzImage prefix with real setup-header release pointer."""
    data = bytearray(4096)
    struct.pack_into('<H', data, 0x1fe, 0xaa55)
    data[0x202:0x206] = b'HdrS'
    struct.pack_into('<H', data, 0x206, 0x020b)
    struct.pack_into('<H', data, 0x20e, 0x100)
    struct.pack_into('<I', data, 0x238, 2048)
    version = (release + ' (test-builder) #1').encode() + b'\0'
    data[0x300:0x300 + len(version)] = version
    return bytes(data)


class Subject(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(switch, 'kernel-switch implementation is not available')
        # A production wiring bug must fail the test, never reach the host.
        for boundary in ('subprocess.run', 'subprocess.Popen', 'os.system'):
            guard = mock.patch(boundary, side_effect=AssertionError('uncontrolled host process boundary'))
            guard.start()
            self.addCleanup(guard.stop)

    def refuse(self, callback, state=None):
        with self.assertRaises(switch.SwitchError) as context:
            callback()
        if state is not None:
            self.assertEqual(context.exception.state, state)
        return context.exception


class Parser(Subject):
    def test_saved_default_requires_standard_environment_load(self):
        for config in (GRUB.replace('  load_env\n', ''),
                       GRUB.replace('  load_env\n', '  load_env -f /other/grubenv\n'),
                       GRUB.replace('if [ -s $prefix/grubenv ]; then', 'if false; then')):
            with self.subTest(config=config[:100]):
                self.refuse(lambda: switch.parse_grub(config, ENV))
        # Newer generated Ubuntu headers select the same env file in this
        # nested save_env branch; empty env_block keeps the ordinary path.
        standard = GRUB.replace('  save_env next_entry\n',
            '  if [ "${env_block}" ]; then\n'
            '    save_env -f "${env_block}" next_entry\n'
            '  else\n'
            '    save_env next_entry\n'
            '  fi\n')
        try:
            parsed = switch.parse_grub(standard, ENV)
        except switch.SwitchError as error:
            self.fail('valid generated nested env_block save was refused: ' + str(error))
        self.assertEqual(parsed['default'], GOOD)

    def test_saved_entry_override_or_custom_fallback_control_is_not_ignored(self):
        branch = 'if [ "${next_entry}" ] ; then'
        for command in ('set saved_entry="simple-test-root"',
                        'saved_entry="simple-test-root"',
                        'eval "set default=simple-test-root"',
                        'if true; then set default=simple-test-root; fi'):
            config = GRUB.replace(branch, command + '\n' + branch)
            with self.subTest(command=command):
                self.refuse(lambda: switch.parse_grub(config, ENV))
        config = GRUB.replace('set default="${saved_entry}"', "set default='${saved_entry}'")
        self.refuse(lambda: switch.parse_grub(config, ENV))
        config = GRUB.replace('  set default="${saved_entry}"',
                              '  set default="${saved_entry}"\n  default="simple-test-root"')
        self.refuse(lambda: switch.parse_grub(config, ENV))
        custom = ('function choose_other {\n'
                  '  regexp --set=1:saved_entry "(.*)" simple-test-root\n'
                  '}\nif choose_other; then\n  echo changed\nfi\n')
        self.refuse(lambda: switch.parse_grub(GRUB.replace(branch, custom + branch), ENV))
        for custom in ('function load_video {\n'
                       '  regexp --set=1:saved_entry "(.*)" simple-test-root\n'
                       '}\nload_video\n',
                       'if regexp --set=1:saved_entry "(.*)" simple-test-root; then\n'
                       '  echo changed\nfi\n'):
            with self.subTest(custom=custom):
                self.refuse(lambda: switch.parse_grub(GRUB.replace(branch, custom + branch), ENV))

    def test_kernel_cmdline_too_long_cannot_hide_required_panic(self):
        # 2 + 2036 + 1 + 8 = 2047 UTF-8 bytes, including the final panic=17.
        safe = switch.normalise_cmdline(['x=' + 'a' * 2036], 17)
        self.assertEqual(len(safe.encode('utf-8')), 2047)
        for args in (['x=' + 'a' * 2037], ['x=' + 'é' * 1200]):
            with self.subTest(arg_length=len(args[0])):
                self.refuse(lambda: switch.normalise_cmdline(args, 17))
        host = FixtureHost()
        prefix = bytearray(host.binary['/boot/vmlinuz-6.16.0-trial'])
        struct.pack_into('<I', prefix, 0x238, 80)
        host.binary['/boot/vmlinuz-6.16.0-trial'] = bytes(prefix)
        self.refuse(lambda: switch.validate_plan(switch.collect_snapshot(host, TRIAL, GOOD), TRIAL, GOOD, 17))

    def test_generated_nested_saved_default(self):
        parsed = switch.parse_grub(GRUB, ENV)
        self.assertEqual(parsed['default'], GOOD)
        self.assertEqual(set(parsed['entries']), {'simple-test-root', TRIAL, GOOD})
        self.assertEqual(parsed['entries'][TRIAL]['linux'], '/boot/vmlinuz-6.16.0-trial')
        self.assertEqual(parsed['entries'][TRIAL]['root_uuid'].lower(), 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
        self.assertEqual(parsed['pending'], {})

    def test_pending_boot_state_is_preserved_for_refusal(self):
        for key in ('next_entry', 'prev_entry', 'prev_saved_entry'):
            env = ENV.replace('next_entry=\n', '') + f'{key}=trial-pending\n'
            with self.subTest(key=key):
                self.assertEqual(switch.parse_grub(GRUB, env)['pending'][key], 'trial-pending')

    def test_direct_default_and_explicit_ids(self):
        config = f'set default="{GOOD}"\n' + GRUB[GRUB.index("menuentry 'Trial default alias'"):]
        for source in (config.replace("$menuentry_id_option 'advanced-test-root'", "--id advanced-test-root"),
                       config.replace("$menuentry_id_option 'advanced-test-root'", "--id=advanced-test-root")):
            with self.subTest(source=source[:80]):
                self.assertEqual(switch.parse_grub(source, ENV)['default'], GOOD)

    def test_dynamic_default_and_duplicate_ids_are_not_guessed(self):
        self.refuse(lambda: switch.parse_grub(GRUB.replace('${saved_entry}', '${unknown_default}'), ENV))
        self.refuse(lambda: switch.parse_grub(GRUB.replace("'good-test-root'", "'trial-test-root'"), ENV))

    def test_image_embedded_release_and_bad_header(self):
        self.assertEqual(switch.read_bzimage_release(image()), '6.16.0-trial')
        for offset in (0x1fe, 0x202, 0x20e):
            data = bytearray(image())
            data[offset] ^= 0xff
            with self.subTest(offset=offset):
                self.refuse(lambda: switch.read_bzimage_release(bytes(data)))

    def test_initrd_modules_listing_and_panic_arguments(self):
        listing = 'usr/lib/modules/6.16.0-trial/kernel/a.ko\nlib/modules/6.16.0-trial/kernel/b.ko.zst\n'
        self.assertEqual(switch.parse_initrd_releases(listing), ['6.16.0-trial'])
        args = ['root=UUID=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 'ro', 'console=ttyS0', 'iommu=pt', 'panic=0', 'panic=99']
        line = switch.normalise_cmdline(args, 17)
        self.assertEqual(line.split(), ['root=UUID=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 'ro', 'console=ttyS0', 'iommu=pt', 'panic=17'])
        for bad in (0, -1):
            with self.subTest(panic=bad):
                self.refuse(lambda: switch.normalise_cmdline(args, bad))


    def test_safe_space_value_uses_kernel_double_quoting_and_substitutions_refuse(self):
        args = ['root=UUID=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 'note=two words', 'console=ttyS0', 'panic=0']
        line = switch.normalise_cmdline(args, 17)
        self.assertEqual(shlex.split(line), ['root=UUID=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 'note=two words', 'console=ttyS0', 'panic=17'])
        self.assertIn('"', line)
        self.assertNotIn("'", line)  # Linux next_arg recognizes double quotes.
        for value in ('root=$(not-a-command)', 'note=`not-a-command`', 'note=first\nsecond'):
            with self.subTest(value=value):
                self.refuse(lambda: switch.normalise_cmdline([value], 17))



    def test_efi_boot_current_order_and_shim_path_are_parsed(self):
        self.assertTrue(callable(getattr(switch, 'parse_efi_boot_manager', None)), 'EFI manager parser missing')
        parsed = switch.parse_efi_boot_manager(EFI_MANAGER)
        self.assertEqual(parsed['boot_current'], '0008')
        self.assertEqual(parsed['boot_order'], ['0008', '0001'])
        self.assertEqual(parsed['partition_uuid'], '11111111-2222-3333-4444-555555555555')
        self.assertEqual(parsed['loader_path'], '/EFI/ubuntu/shimx64.efi')

    def test_efi_pending_foreign_direct_or_ambiguous_chain_refuses(self):
        self.assertTrue(callable(getattr(switch, 'parse_efi_boot_manager', None)), 'EFI manager parser missing')
        for text in (EFI_MANAGER + 'BootNext: 0001\n',
                     EFI_MANAGER.replace('BootOrder: 0008,0001', 'BootOrder: 0001,0008'),
                     EFI_MANAGER.replace('shimx64.efi', 'systemd-bootx64.efi'),
                     EFI_MANAGER.replace('shimx64.efi', 'vmlinuz.efi'),
                     EFI_MANAGER + 'BootCurrent: 0008\n',
                     EFI_MANAGER + EFI_MANAGER.splitlines()[-1] + '\n'):
            with self.subTest(text=text[:90]):
                self.refuse(lambda: switch.parse_efi_boot_manager(text))

    def test_efi_forwarder_requires_only_the_three_prescribed_commands(self):
        self.assertTrue(callable(getattr(switch, 'parse_efi_forwarder', None)), 'EFI forwarder parser missing')
        parsed = switch.parse_efi_forwarder(EFI_FORWARDER)
        self.assertEqual(parsed['root_uuid'], 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
        self.assertEqual(parsed['prefix'], '/boot/grub')
        for text in (EFI_FORWARDER + 'configfile /other/grub.cfg\n',
                     EFI_FORWARDER.replace('/boot/grub', '/boot/${dynamic}'),
                     EFI_FORWARDER.replace('configfile $prefix/grub.cfg', 'source $prefix/grub.cfg')):
            with self.subTest(text=text):
                self.refuse(lambda: switch.parse_efi_forwarder(text))



class FixtureHost:
    """Only OS facts/actions are replaced; production parsing stays real."""
    def __init__(self):
        self.euid = 0
        self.machine = 'x86_64'
        self.text = {
            '/boot/grub/grub.cfg': GRUB, '/boot/grub/grubenv': ENV,
            '/etc/default/grub': 'GRUB_DEFAULT="0"\n',
            '/proc/sys/kernel/osrelease': '6.15.0-good\n',
            '/proc/sys/kernel/random/boot_id': 'sanitized-current-boot\n',
            '/proc/1/comm': 'systemd\n',
            '/proc/cmdline': 'root=UUID=WRONG-CURRENT rootwait panic=0\n',
            '/sys/kernel/kexec_loaded': '0\n', '/sys/kernel/kexec_crash_loaded': '0\n',
            '/proc/sys/kernel/kexec_load_disabled': '0\n',
        }
        self.binary = {'/boot/vmlinuz-6.16.0-trial': image(),
                       '/boot/vmlinuz-6.15.0-good': image('6.15.0-good'),
                       '/boot/initrd.img-6.16.0-trial': b'target initrd bytes',
                       '/boot/initrd.img-6.15.0-good': b'good initrd bytes'}
        self.directories = {'/lib/modules/6.16.0-trial', '/lib/modules/6.15.0-good'}
        self.listings = {f'/boot/initrd.img-{release}': f'usr/lib/modules/{release}/kernel/test.ko\n'
                         for release in ('6.16.0-trial', '6.15.0-good')}
        self.mounts = [{'target': '/', 'source': '/dev/test-root', 'uuid': 'AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 'fstype': 'ext4'}]
        self.bootctl_status = 'Current Boot Loader:\n      Product: GRUB 2.12\n\nAvailable Boot Loaders on ESP:\n'
        self.efi_manager = EFI_MANAGER
        self.esp_partuuid = '11111111-2222-3333-4444-555555555555'
        self.text['/boot/efi/EFI/ubuntu/grub.cfg'] = EFI_FORWARDER
        self.binary.update({'/boot/efi/EFI/ubuntu/shimx64.efi': b'sanitized EFI shim bytes',
                            '/boot/efi/EFI/ubuntu/grubx64.efi': b'sanitized EFI GRUB bytes'})
        self.directories.add('/sys/firmware/efi')
        self.mounts.append({'target': '/boot/efi', 'source': '/dev/test-esp', 'uuid': 'CAFE-1234', 'fstype': 'vfat'})
        self.calls = []
        self.stat_overrides = {}
        self.tools = {name: '/usr/sbin/' + name for name in
                      ('kexec', 'systemctl', 'grub-editenv', 'lsinitramfs', 'findmnt', 'bootctl', 'efibootmgr', 'lsblk')}

    def read_text(self, path):
        path = str(path)
        if path not in self.text:
            raise FileNotFoundError(path)
        return self.text[path]

    def read_bytes(self, path, limit):
        path = str(path)
        if path not in self.binary:
            raise FileNotFoundError(path)
        return self.binary[path][:limit]

    def stat(self, path):
        path = str(path)
        if path not in self.binary and path not in self.text:
            raise FileNotFoundError(path)
        size = len(self.binary[path]) if path in self.binary else len(self.text[path])
        return dict(dev=1, ino=100 + sorted([*self.binary, *self.text]).index(path),
                    size=size, mtime_ns=self.stat_overrides.get(path, 1000), regular=True)

    def is_dir(self, path):
        return str(path) in self.directories

    def which(self, name):
        return self.tools.get(name)

    def run(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        name = Path(argv[0]).name
        if name == 'bootctl' and argv[1:] == ['--no-pager', 'status']:
            output = self.bootctl_status
        elif name == 'grub-editenv' and argv[-1] == 'list':
            output = self.text['/boot/grub/grubenv']
        elif name == 'findmnt':
            mounts = [m for m in self.mounts if m['target'] == '/boot/efi'] if '/boot/efi' in argv else self.mounts
            output = json.dumps({'filesystems': mounts})
        elif name == 'efibootmgr' and argv[1:] == ['--verbose']:
            output = self.efi_manager
        elif name == 'lsblk':
            output = self.esp_partuuid + '\n'
        elif name == 'lsinitramfs':
            output = self.listings[argv[-1]]
        elif name == 'uname':
            output = 'x86_64\n' if '-m' in argv else '6.15.0-good\n'
        else:
            raise AssertionError('unexpected OS command (never executed): ' + repr(argv))
        return subprocess.CompletedProcess(argv, 0, output, '')


class PlanFixture(Subject):
    def setUp(self):
        super().setUp()
        self.host = FixtureHost()

    def snapshot(self):
        return switch.collect_snapshot(self.host, TRIAL, GOOD)

    def plan(self):
        return switch.validate_plan(self.snapshot(), TRIAL, GOOD, 17)


class Planning(PlanFixture):
    def test_selected_conditional_good_entry_or_parent_submenu_is_refused(self):
        start = GRUB.index("  menuentry 'Known good Linux'")
        end = GRUB.index('\n  }', start) + len('\n  }')
        good_block = GRUB[start:end]
        submenu_start = GRUB.index("submenu 'Advanced options for Test Linux'")
        submenu_end = GRUB.rindex('\n}') + len('\n}')
        submenu_block = GRUB[submenu_start:submenu_end]
        for guard in ('if [ x = y ]; then', 'if [ "${unknown_menu_flag}" = yes ]; then'):
            for kind in ('entry', 'parent-submenu', 'entry-else'):
                if kind == 'entry':
                    replacement = guard + '\n' + good_block + '\nfi'
                    config = GRUB[:start] + replacement + GRUB[end:]
                elif kind == 'parent-submenu':
                    replacement = guard + '\n' + submenu_block + '\nfi'
                    config = GRUB[:submenu_start] + replacement + GRUB[submenu_end:]
                else:
                    replacement = guard + '\n  echo other-branch\nelse\n' + good_block + '\nfi'
                    config = GRUB[:start] + replacement + GRUB[end:]
                self.host = FixtureHost()
                self.host.text['/boot/grub/grub.cfg'] = config
                with self.subTest(guard=guard, kind=kind):
                    self.refuse(self.plan)

    def test_unselected_standard_efi_conditional_menu_remains_inspectable(self):
        self.host.text['/boot/grub/grub.cfg'] = GRUB + (
            '\nif [ "$grub_platform" = efi ]; then\n'
            "  menuentry 'Firmware settings' --id firmware-settings {\n"
            '    fwsetup\n  }\nfi\n')
        snapshot = switch.collect_snapshot(self.host)
        self.assertEqual(snapshot['grub']['default'], GOOD)
        self.assertIn('firmware-settings', snapshot['grub']['entries'])
        self.assertTrue(snapshot['grub']['entries']['firmware-settings']['unsafe'])
        self.assertEqual(self.plan()['state'], 'planned')

    def test_active_grub_loader_evidence_is_required_and_recorded(self):
        snapshot = self.snapshot()
        self.assertIn('loader', snapshot)
        self.assertEqual(snapshot['loader']['type'], 'grub2')
        self.assertTrue(snapshot['loader']['evidence'])
        self.assertIs(snapshot['loader'].get('qualified'), True)
        self.assertIsInstance(snapshot['loader'].get('chain'), dict)
        self.assertTrue(any(Path(command[0]).name == 'bootctl' for command in self.host.calls))

    def test_systemd_boot_or_unknown_loader_refuses_despite_grub_files(self):
        for status in ('Current Boot Loader:\n      Product: systemd-boot 255\n',
                       'Current Boot Loader:\n      Product: n/a\n',
                       'Current Boot Loader:\n      Product: n/a\n\nAvailable Boot Loaders on ESP:\n      Product: GRUB 2.12\n'):
            self.host = FixtureHost()
            self.host.bootctl_status = status
            if 'systemd-boot' not in status:
                self.host.directories.remove('/sys/firmware/efi')
            with self.subTest(status=status):
                self.refuse(self.plan)

    def test_missing_wrong_or_empty_loader_evidence_refuses_plan(self):
        for loader in (None, {'type': 'systemd-boot', 'evidence': 'active', 'qualified': True},
                       {'type': 'grub2', 'evidence': '', 'qualified': True},
                       {'type': 'grub2', 'evidence': 'only installed files'},
                       {'type': 'grub2', 'evidence': 'only installed files', 'qualified': False}):
            snapshot = self.snapshot()
            if loader is None:
                snapshot.pop('loader', None)
            else:
                snapshot['loader'] = loader
            with self.subTest(loader=loader):
                self.refuse(lambda: switch.validate_plan(snapshot, TRIAL, GOOD, 17))

    def test_unknown_bootctl_with_complete_ubuntu_efi_chain_is_qualified(self):
        self.host.bootctl_status = 'Current Boot Loader:\n      Product: n/a\n'
        try:
            snapshot = self.snapshot()
        except switch.SwitchError as error:
            self.fail('complete qualified Ubuntu EFI chain was refused: ' + str(error))
        self.assertIn('loader', snapshot)
        self.assertIs(snapshot['loader'].get('qualified'), True)
        self.assertEqual(switch.validate_plan(snapshot, TRIAL, GOOD, 17)['state'], 'planned')
        self.assertTrue(any(Path(argv[0]).name == 'efibootmgr' for argv in self.host.calls))

    def test_efi_chain_bad_partition_forwarder_binary_or_pending_next_refuses(self):
        for fault in ('partition', 'forwarder-uuid', 'forwarder-prefix', 'missing-grub', 'no-efi', 'boot-next', 'wrong-esp'):
            self.host = FixtureHost()
            if fault == 'partition':
                self.host.esp_partuuid = '99999999-2222-3333-4444-555555555555'
            elif fault == 'forwarder-uuid':
                self.host.text['/boot/efi/EFI/ubuntu/grub.cfg'] = EFI_FORWARDER.replace('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', '99999999-bbbb-cccc-dddd-eeeeeeeeeeee')
            elif fault == 'forwarder-prefix':
                self.host.text['/boot/efi/EFI/ubuntu/grub.cfg'] = EFI_FORWARDER.replace('/boot/grub', '/foreign/grub')
            elif fault == 'missing-grub':
                del self.host.binary['/boot/efi/EFI/ubuntu/grubx64.efi']
            elif fault == 'no-efi':
                self.host.directories.remove('/sys/firmware/efi')
            elif fault == 'boot-next':
                self.host.efi_manager += 'BootNext: 0001\n'
            else:
                self.host.mounts[-1]['fstype'] = 'ext4'
            with self.subTest(fault=fault):
                self.refuse(self.plan)

    def test_collect_and_plan_use_real_grub_and_embedded_metadata(self):
        snapshot = self.snapshot()
        self.assertEqual(snapshot['grub']['default'], GOOD)
        self.assertEqual(snapshot['artifacts'][TRIAL]['release'], '6.16.0-trial')
        plan = switch.validate_plan(snapshot, TRIAL, GOOD, 17)
        self.assertEqual(plan['state'], 'planned')
        self.assertEqual(plan['kernel'], '/boot/vmlinuz-6.16.0-trial')
        self.assertEqual(plan['initrd'], '/boot/initrd.img-6.16.0-trial')
        self.assertEqual(plan['cmdline'].split(), ['root=UUID=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', 'ro', 'console=ttyS0',
                                                 'intel_iommu=on', 'iommu=pt', 'panic=17'])
        self.assertEqual(plan['commands'], [
            ['/usr/sbin/kexec', '--load', '/boot/vmlinuz-6.16.0-trial',
             '--initrd=/boot/initrd.img-6.16.0-trial', '--append=' + plan['cmdline']],
            ['/usr/sbin/systemctl', 'kexec']])
        self.assertNotIn('WRONG-CURRENT', plan['cmdline'])

    def test_mismatch_embedded_release_initrd_modules_and_missing_assets(self):
        for fault in ('embedded', 'mixed-initrd', 'empty-initrd', 'disk-modules', 'missing-initrd', 'missing-good'):
            self.host = FixtureHost()
            if fault == 'embedded':
                self.host.binary['/boot/vmlinuz-6.16.0-trial'] = image('6.99.0-other')
            elif fault == 'mixed-initrd':
                self.host.listings['/boot/initrd.img-6.16.0-trial'] += 'lib/modules/other/kernel/x.ko\n'
            elif fault == 'empty-initrd':
                self.host.listings['/boot/initrd.img-6.16.0-trial'] = 'init\nbin/sh\n'
            elif fault == 'disk-modules':
                self.host.directories.remove('/lib/modules/6.16.0-trial')
            elif fault == 'missing-initrd':
                del self.host.binary['/boot/initrd.img-6.16.0-trial']
            else:
                del self.host.binary['/boot/vmlinuz-6.15.0-good']
            with self.subTest(fault=fault):
                self.refuse(self.plan)

    def test_pending_default_preload_and_unsupported_host_refuse(self):
        changes = [('pending', None), ('default', None), ('normal_loaded', True),
                   ('pid1', 'other-init'), ('machine', 'aarch64'), ('tool', None)]
        for field, value in changes:
            snapshot = self.snapshot()
            if field == 'pending':
                snapshot['grub']['pending'] = {'next_entry': TRIAL}
            elif field == 'default':
                snapshot['grub']['default'] = TRIAL
            elif field == 'tool':
                snapshot['tools']['kexec'] = None
            else:
                snapshot[field] = value
            with self.subTest(field=field):
                self.refuse(lambda: switch.validate_plan(snapshot, TRIAL, GOOD, 17))
        self.refuse(lambda: switch.validate_plan(self.snapshot(), GOOD, GOOD, 17))

    def test_unknown_loaded_state_and_unknown_or_ambiguous_root_mapping(self):
        for fault in ('unknown-loaded', 'missing-mount', 'ambiguous-mount'):
            self.host = FixtureHost()
            if fault == 'unknown-loaded':
                self.host.text['/sys/kernel/kexec_loaded'] = 'unknown\n'
            elif fault == 'missing-mount':
                self.host.mounts = []
            else:
                self.host.mounts.append(dict(self.host.mounts[0], target='/boot'))
            with self.subTest(fault=fault):
                self.refuse(self.plan)

    def test_selected_entry_savedefault_and_variable_image_are_unsafe(self):
        for command in ('savedefault', 'linux ${unresolved_image} root=UUID=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE'):
            self.host = FixtureHost()
            if command == 'savedefault':
                self.host.text['/boot/grub/grub.cfg'] = GRUB.replace("  menuentry 'Trial Linux'", "  menuentry 'Trial Linux'", 1).replace(
                    '    linux /boot/vmlinuz-6.16.0-trial', '    savedefault\n    linux /boot/vmlinuz-6.16.0-trial')
            else:
                self.host.text['/boot/grub/grub.cfg'] = GRUB.replace('linux /boot/vmlinuz-6.16.0-trial root=UUID=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE', command)
            with self.subTest(command=command):
                self.refuse(self.plan)

    def test_nonroot_readonly_plan_and_existing_crash_image(self):
        self.host.euid = 1000
        self.host.text['/sys/kernel/kexec_crash_loaded'] = '1\n'
        plan = self.plan()
        self.assertEqual(plan['state'], 'planned')
        self.assertEqual(self.host.text['/sys/kernel/kexec_crash_loaded'], '1\n')


class Execution(PlanFixture):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.receipt_path = Path(self.tmp.name) / 'switch.json'
        self.events = []
        self.commands = []

    def persist(self, event):
        switch.write_receipt(self.receipt_path, event)
        self.events.append(copy.deepcopy(event))
        self.assertEqual(json.loads(self.receipt_path.read_text()), event)

    def os_run(self, argv):
        # These callbacks are the external process boundary, never real exec.
        self.commands.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, '', '')

    def execute(self, *, runner=None, recheck=None, read_loaded=None, receipt=None):
        return switch.execute_switch(self.plan(), execute=True,
            runner=runner or self.os_run, recheck=recheck or self.plan,
            read_loaded=read_loaded or (lambda: True), receipt=receipt or self.persist)

    def test_no_execute_invokes_no_callbacks_or_receipt(self):
        def forbidden(*args):
            self.fail('readonly executor invoked an OS callback')
        result = switch.execute_switch(self.plan(), runner=forbidden, recheck=forbidden,
                                      read_loaded=forbidden, receipt=forbidden)
        self.assertEqual(result['state'], 'planned')
        self.assertFalse(self.receipt_path.exists())

    def test_real_executor_orders_receipts_load_state_and_handoff(self):
        timeline = []
        def runner(argv):
            timeline.append('load' if '--load' in argv else 'handoff')
            return self.os_run(argv)
        def loaded():
            timeline.append('read-loaded')
            return True
        def receipt(event):
            timeline.append(event['state'])
            self.persist(event)
        result = self.execute(runner=runner, read_loaded=loaded, receipt=receipt)
        self.assertEqual(timeline, ['prepared', 'load', 'read-loaded', 'loaded', 'handoff', 'handoff-requested'])
        self.assertEqual(self.commands, self.plan()['commands'])
        self.assertEqual(result['state'], 'handoff-requested')
        self.assertEqual(self.events[-1]['state'], 'handoff-requested')
        self.assertNotIn(result['state'], ('booted', 'recovered'))

    def test_failed_load_never_handoffs_and_reports_actual_residual_state(self):
        for loaded, state, code in ((False, 'load-failed', 4), (True, 'load-state-unknown', 6)):
            self.commands.clear()
            self.events.clear()
            def runner(argv):
                self.commands.append(list(argv))
                return subprocess.CompletedProcess(argv, 23, '', 'load failure')
            with self.subTest(loaded=loaded):
                error = self.refuse(lambda: self.execute(runner=runner, read_loaded=lambda: loaded), state)
                self.assertEqual(error.exit_code, code)
                self.assertEqual(len(self.commands), 1)
                self.assertEqual(self.events[-1]['state'], state)

    def test_load_success_without_confirmed_loaded_state_never_handoffs(self):
        for status in (False, None):
            self.commands.clear()
            def loaded():
                if status is None:
                    raise OSError('unreadable normal image flag')
                return status
            with self.subTest(status=status):
                error = self.refuse(lambda: self.execute(read_loaded=loaded))
                self.assertEqual(error.exit_code, 6)
                self.assertEqual(len(self.commands), 1)
                self.assertEqual(self.events[-1]['state'], 'load-state-unknown')

    def test_failed_load_with_unreadable_flag_reports_unknown_without_handoff(self):
        def runner(argv):
            self.commands.append(list(argv))
            return subprocess.CompletedProcess(argv, 1, '', 'load failed')
        def unknown():
            raise OSError('sysfs flag unreadable after load attempt')
        error = self.refuse(lambda: self.execute(runner=runner, read_loaded=unknown), 'load-state-unknown')
        self.assertEqual(error.exit_code, 6)
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(self.events[-1]['state'], 'load-state-unknown')

    def test_failed_handoff_keeps_loaded_image_and_stops(self):
        def runner(argv):
            self.commands.append(list(argv))
            return subprocess.CompletedProcess(argv, 0 if '--load' in argv else 7, '', '')
        error = self.refuse(lambda: self.execute(runner=runner), 'handoff-failed')
        self.assertEqual(error.exit_code, 5)
        self.assertEqual(len(self.commands), 2)
        self.assertEqual(self.events[-1]['state'], 'handoff-failed')

    def test_changed_recheck_identity_and_preflight_refusal_prevent_load(self):
        def changed():
            self.host.stat_overrides['/boot/vmlinuz-6.16.0-trial'] = 9999
            return self.plan()
        self.refuse(lambda: self.execute(recheck=changed))
        self.assertEqual(self.commands, [])
        self.host = FixtureHost()
        def pending():
            self.host.text['/boot/grub/grubenv'] = ENV + 'prev_entry=trial-pending\n'
            return self.plan()
        self.refuse(lambda: self.execute(recheck=pending))
        self.assertEqual(self.commands, [])

    def test_receipt_failure_prevents_next_mutation(self):
        for fail_state, allowed_commands in (('prepared', 0), ('loaded', 1)):
            self.commands.clear()
            def receipt(event):
                if event['state'] == fail_state:
                    raise OSError('private receipt storage failed')
                self.persist(event)
            with self.subTest(state=fail_state):
                self.refuse(lambda: self.execute(receipt=receipt))
                self.assertEqual(len(self.commands), allowed_commands)

    def test_timeout_and_interruption_never_retry_or_request_handoff(self):
        for failure in (subprocess.TimeoutExpired(['kexec'], 1), KeyboardInterrupt()):
            self.commands.clear()
            def runner(argv):
                self.commands.append(list(argv))
                raise failure
            with self.subTest(failure=type(failure).__name__):
                error = self.refuse(lambda: self.execute(runner=runner))
                self.assertEqual(error.exit_code, 6)
                self.assertEqual(len(self.commands), 1)
                self.assertIn(self.events[-1]['state'], ('interrupted', 'load-state-unknown'))


class Receipt(Subject):
    def test_private_atomic_replacement_and_failure_preserves_previous_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            switch.write_receipt(path, {'state': 'prepared'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with mock.patch('os.replace', side_effect=OSError('replace failed')):
                with self.assertRaises((switch.SwitchError, OSError)):
                    switch.write_receipt(path, {'state': 'loaded'})
            self.assertEqual(json.loads(path.read_text()), {'state': 'prepared'})
            switch.write_receipt(path, {'state': 'loaded'})
            self.assertEqual(json.loads(path.read_text()), {'state': 'loaded'})

    def test_symlink_and_world_writable_receipt_boundaries_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / 'outside'
            outside.write_text('retain original bytes')
            link = root / 'link.json'
            link.symlink_to(outside)
            with self.assertRaises((switch.SwitchError, OSError)):
                switch.write_receipt(link, {'state': 'prepared'})
            self.assertEqual(outside.read_text(), 'retain original bytes')
            shared = root / 'shared'
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            with self.assertRaises((switch.SwitchError, OSError)):
                switch.write_receipt(shared / 'receipt.json', {'state': 'prepared'})


@contextlib.contextmanager
def no_filesystem_mutations():
    """Guard readonly CLI behavior at actual OS file-operation boundaries."""
    real_builtin_open, real_io_open, real_os_open = open, io.open, os.open
    def guard_open(original):
        def guarded(path, mode='r', *args, **kwargs):
            if any(flag in mode for flag in 'wax+'):
                raise AssertionError('readonly CLI attempted a file write')
            return original(path, mode, *args, **kwargs)
        return guarded
    def guarded_os_open(path, flags, *args, **kwargs):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError('readonly CLI attempted a file write')
        return real_os_open(path, flags, *args, **kwargs)
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch('builtins.open', side_effect=guard_open(real_builtin_open)))
        stack.enter_context(mock.patch('io.open', side_effect=guard_open(real_io_open)))
        stack.enter_context(mock.patch('os.open', side_effect=guarded_os_open))
        for name in ('mkdir', 'makedirs', 'unlink', 'remove', 'rmdir', 'rename', 'replace', 'chmod', 'symlink'):
            stack.enter_context(mock.patch('os.' + name, side_effect=AssertionError('readonly filesystem mutation')))
        yield


class CliReadOnly(PlanFixture):
    def test_default_inspect_plan_and_unexecuted_switch_never_mutate(self):
        for arguments in ([], ['inspect'], ['plan', '--target-entry', TRIAL, '--good-entry', GOOD, '--panic-seconds', '17'],
                          ['switch', '--target-entry', TRIAL, '--good-entry', GOOD, '--panic-seconds', '17']):
            self.host = FixtureHost()
            before_text, before_binary = copy.deepcopy(self.host.text), copy.deepcopy(self.host.binary)
            with self.subTest(arguments=arguments), mock.patch.object(switch, 'Host', return_value=self.host):
                output, errors = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), no_filesystem_mutations():
                    code = switch.main(arguments)
                self.assertEqual(code, 0, errors.getvalue())
                self.assertIsInstance(json.loads(output.getvalue()), dict)
                self.assertEqual(self.host.text, before_text)
                self.assertEqual(self.host.binary, before_binary)
                self.assertFalse(any('--load' in command or command[-1:] == ['kexec'] for command in self.host.calls))

    def test_cli_nonroot_explicit_execution_refuses_without_load(self):
        self.host.euid = 1000
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(switch, 'Host', return_value=self.host):
            arguments = ['switch', '--target-entry', TRIAL, '--good-entry', GOOD, '--panic-seconds', '17',
                         '--execute', '--receipt', str(Path(directory) / 'receipt.json')]
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                code = switch.main(arguments)
            self.assertEqual(code, 3, errors.getvalue())
            self.assertFalse(any('--load' in command or command[-1:] == ['kexec'] for command in self.host.calls))


if __name__ == '__main__':
    unittest.main()
