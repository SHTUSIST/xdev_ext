# SPDX-License-Identifier: GPL-2.0
"""Host harness contracts only; these tests never boot a guest."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import os
import shutil
import hashlib
import unittest

spec = importlib.util.spec_from_file_location('contracts', Path(__file__).with_name('contracts.py'))
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)


class Roots(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.view = self.root / 'build/source-view'
        self.assembly = self.root / 'build/assembled/linux'
        self.build = self.root / 'output'
        self.sha = '1' * 40
        self.mapping = {'source': 'src/core/a.c', 'component': 'linux', 'native_path': 'io_uring/a.c'}
        self.manifest = {'schema': 1, 'files': [self.mapping]}
        self.write('source-layout.json', self.manifest)
        self.write('third_party/sources.lock.json', {'schema': 2, 'components': {'linux': {'commit': '2' * 40, 'url': 'https://example.invalid/linux', 'ref': 'refs/tags/test'}}})
        self.write('build/source-view/view.json', {'schema': 1, 'kind': 'host-source-view', 'canonical_root': str(self.root), 'revision': self.sha, 'dirty': False, 'manifest': self.manifest, 'source_origins': {'kernel/io_uring/a.c': 'src/core/a.c'}})
        self.write('build/assembled/linux/.xdev-ext-source.json', {'schema': 2, 'kind': 'full-assembly', 'component': 'linux', 'canonical_root': str(self.root), 'output': str(self.assembly), 'commit': '2' * 40, 'url': 'https://example.invalid/linux', 'ref': 'refs/tags/test', 'source_origins': {'io_uring/a.c': 'src/core/a.c'}})
        for p in ['src/core/a.c', 'build/source-view/kernel/io_uring/a.c', 'build/assembled/linux/io_uring/a.c', 'build/assembled/linux/Makefile', 'build/assembled/linux/scripts/Makefile.build', 'build/assembled/linux/include/linux/kernel.h']:
            self.write(p, 'int a;')
        self.build.mkdir()
        (self.build / 'source').symlink_to(self.assembly, target_is_directory=True)

    def write(self, path, value):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value) if isinstance(value, dict) else value)

    def test_distinct_matching_roots(self):
        receipt = contracts.check_roots(self.root, self.sha, self.build)
        self.assertEqual(receipt['native'], str(self.view / 'kernel'))
        self.assertEqual(receipt['assembled'], str(self.assembly))

    def test_stale_or_foreign_view_is_rejected(self):
        for key, bad in [('revision', '3' * 40), ('canonical_root', '/other'), ('dirty', True)]:
            p = self.view / 'view.json'
            original = p.read_text()
            receipt = json.loads(original)
            receipt[key] = bad
            p.write_text(json.dumps(receipt))
            with self.subTest(key=key), self.assertRaises(ValueError):
                contracts.check_roots(self.root, self.sha, self.build)
            p.write_text(original)

    def test_modified_view_and_assembly_are_rejected(self):
        for path in ['build/source-view/kernel/io_uring/a.c', 'build/assembled/linux/io_uring/a.c']:
            self.write(path, 'changed')
            with self.subTest(path=path), self.assertRaises(ValueError):
                contracts.check_roots(self.root, self.sha, self.build)
            self.write(path, 'int a;')

    def test_red_baseline_validates_new_guest_view_without_rebinding_old_kernel(self):
        (self.build / 'source').unlink()
        (self.build / 'source').symlink_to(self.root / 'old-baseline', target_is_directory=True)
        output = self.root / 'red-inputs.json'
        result = subprocess.run(['python3', str(Path(__file__).with_name('contracts.py')),
                                 'red-roots', str(self.root), self.sha, str(self.build), str(output)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text())['build_identity'], 'old-baseline-not-enforced')

    def test_wrong_kbuild_source_is_rejected(self):
        (self.build / 'source').unlink()
        (self.build / 'source').symlink_to(self.view / 'kernel', target_is_directory=True)
        with self.assertRaises(ValueError):
            contracts.check_roots(self.root, self.sha, self.build)



    def test_xdomain_requires_every_staged_module_in_prebuild_receipt(self):
        # Only Git/depmod/modprobe/make are command-boundary doubles. The
        # runner's receipts, checksum verification and stop decision are real.
        project = Path(__file__).resolve().parents[4]
        runner = project / 'tests/network/xdomain/stack/guest/xdomain_kvm.sh'
        bindir = self.root / 'bin'
        bindir.mkdir()
        (bindir / 'git').write_text('#!/bin/sh\ncase "$3:$4" in\nrev-parse:--show-toplevel) echo "$UNIT_SOURCE";;\nrev-parse:HEAD) echo "$UNIT_SHA";;\ndiff:*|ls-files:*) exit 0;;\n*) exit 17;;\nesac\n')
        (bindir / 'depmod').write_text('#!/bin/sh\nexit 0\n')
        (bindir / 'modprobe').write_text('#!/bin/sh\ncat "$UNIT_DEPENDENCIES"\n')
        (bindir / 'make').write_text('#!/bin/sh\ntouch "$UNIT_SENTINEL"\nexit 43\n')
        for command in bindir.iterdir():
            command.chmod(0o755)
        helper = 'tests/integration/build/kvm_layout/contracts.py'
        self.write(helper, (project / helper).read_text())
        self.write('src/network/drivers/thunderbolt/test.c',
                   'static struct kunit_case tb_test_cases[] = {\n' +
                   ''.join(f'KUNIT_CASE(tb_test_case_{i}),\n' for i in range(45)) + '};\n')
        symbols = 'MODULES MODULE_UNLOAD MEMORY_HOTPLUG MEMORY_HOTREMOVE MIGRATION SPARSEMEM_VMEMMAP ZONE_DEVICE PCI_P2PDMA DEBUG_INFO_BTF DEBUG_INFO_BTF_MODULES DEBUG_KERNEL PROVE_LOCKING DEBUG_ATOMIC_SLEEP KASAN KASAN_GENERIC DETECT_HUNG_TASK KUNIT USB4_KUNIT_TEST'
        self.write('output/.config', ''.join('CONFIG_' + key + '=y\n' for key in symbols.split()) +
                   'CONFIG_USB4=m\nCONFIG_XDEV_EXT_MECH_XDOMAIN=m\n')
        self.write('output/xdev-ext-source.commit', self.sha + '\n')
        self.write('output/include/config/kernel.release', 'unit-only\n')
        module_root = 'tools/xdomain-modules/lib/modules/unit-only/'
        modules = [module_root + 'kernel/io_uring/xdomain/xdev_ext_xdomain.ko',
                   module_root + 'kernel/drivers/thunderbolt/thunderbolt.ko',
                   module_root + 'kernel/lib/crc32c.ko.zst']
        artifacts = ['output/.config', 'output/arch/x86/boot/bzImage', 'output/vmlinux',
                     'output/Module.symvers', 'tools/xdev_ext_mech_ctl', 'tools/nvme_s0.bpf.o',
                     'tools/peer-guest/xdev_ext_peer_sw.ko'] + modules
        for artifact in artifacts[1:]:
            self.write(artifact, 'unit boundary input')
        self.write(module_root + 'modules.dep', 'unit depmod boundary\n')
        dependencies = self.root / 'dependencies.txt'
        dependencies.write_text(''.join('insmod ' + str(self.root / path) + '\n' for path in modules))
        sentinel = self.root / 'make-reached'
        env = dict(os.environ, PATH=str(bindir) + ':' + os.environ['PATH'],
                   UNIT_SOURCE=str(self.root), UNIT_SHA=self.sha,
                   UNIT_DEPENDENCIES=str(dependencies), UNIT_SENTINEL=str(sentinel),
                   QEMU='/nonexistent/no-qemu')
        for index, omitted in enumerate(modules + [None]):
            with self.subTest(omitted=omitted):
                sentinel.unlink(missing_ok=True)
                records = [path for path in artifacts if path != omitted]
                self.write('output/xdev-ext-xdomain-build.sha256', ''.join(
                    hashlib.sha256((self.root / path).read_bytes()).hexdigest() + '  ' +
                    str(self.root / path) + '\n' for path in records))
                scratch = self.root / f'xdomain-{index}'
                scratch.mkdir(mode=0o700)
                result = subprocess.run(['bash', str(runner), '--source', str(self.root),
                                         '--scratch', str(scratch), '--build', str(self.build),
                                         '--tools', str(self.root / 'tools')], env=env,
                                        capture_output=True, text=True)
                if omitted is None:
                    self.assertTrue(sentinel.is_file(), result.stdout + result.stderr)
                    self.assertEqual(result.returncode, 43)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(sentinel.exists(), 'unbound staged module reached make: ' + omitted)


    def test_ordered_packaging_preserves_relative_peer_header_and_baseline(self):
        # make and Git are external command-boundary doubles only. The runner,
        # receipts, source copies, ELF dependency inspection, image creation
        # and initramfs packaging remain real. QEMU cannot execute here.
        project = Path(__file__).resolve().parents[4]
        runner = project / 'tests/compute/user_stage/user_kvm.sh'
        bindir = self.root / 'bin'
        bindir.mkdir()
        (bindir / 'git').write_text('#!/bin/sh\ncase "$3:$4" in\nrev-parse:--show-toplevel) echo "$UNIT_SOURCE";;\nrev-parse:HEAD|rev-parse:--verify) echo "$UNIT_SHA";;\ndiff:*|ls-files:*) exit 0;;\n*) exit 17;;\nesac\n')
        (bindir / 'make').write_text('#!/usr/bin/env python3\nimport os, pathlib, shutil, sys\na=sys.argv[1:]\nassert a[-2:] == ["ordered_frames_guest", "ordered_frames_nvme.bpf.o"], a\nw=pathlib.Path(a[a.index("-C")+1])\nassert (w/"../../../xdev_ext_peer/guest/sw_provider_uapi.h").resolve().is_file()\nassert "KERNEL_SRC="+os.environ["UNIT_NATIVE"] in a\nassert (w/"ordered_frames_nvme.bpf.c").read_text() == "/* canonical test-only policy */"\nassert any(arg.startswith("VMLINUX_BTF=") for arg in a)\nshutil.copyfile("/bin/true", w/"ordered_frames_guest")\n(w/"ordered_frames_guest").chmod(0o755)\n(w/"ordered_frames_nvme.bpf.o").write_bytes(b"unit-only BPF object boundary")\n')
        for command in bindir.iterdir():
            command.chmod(0o755)
        self.write('tests/compute/user_stage/guest/ordered_frames_nvme.bpf.c', '/* canonical test-only policy */')
        guest = 'tools/testing/selftests/xdev_ext_mech/user_stage/guest'
        peer = 'tools/testing/selftests/xdev_ext_peer/guest/sw_provider_uapi.h'
        for relative, text in [(guest + '/Makefile', 'ordered_frames_guest:'),
                               (guest + '/ordered_frames_guest.c', '#include "../../../xdev_ext_peer/guest/sw_provider_uapi.h"'),
                               (peer, '/* relative header */')]:
            self.write('build/source-view/kernel/' + relative, text)
        contracts_path = 'tests/integration/build/kvm_layout/contracts.py'
        self.write(contracts_path, (project / contracts_path).read_text())
        debug_path = 'tests/integration/session/native/xdev_ext_mech_zc_debug.py'
        self.write(debug_path, (project / debug_path).read_text())
        symbols = 'MODULES MODULE_UNLOAD XDEV_EXT_MECH XDEV_EXT_MECH_ZEROCOPY BLK_DEV_NVME BLK_DEV_INITRD RD_GZIP DEVTMPFS DEVTMPFS_MOUNT TMPFS PROC_FS SYSFS BLOCK PCI PCI_MSI ACPI SERIAL_8250 SERIAL_8250_CONSOLE IO_URING BPF BPF_SYSCALL BPF_JIT DEBUG_INFO_BTF DEBUG_KERNEL PROVE_LOCKING LOCKDEP DEBUG_ATOMIC_SLEEP KASAN KASAN_GENERIC DETECT_HUNG_TASK'
        self.write('output/.config', ''.join('CONFIG_' + key + '=y\n' for key in symbols.split()))
        self.write('output/xdev-ext-source.commit', self.sha + '\n')
        self.write('output/include/config/kernel.release', 'unit-only\n')
        artifacts = ['output/.config', 'output/arch/x86/boot/bzImage', 'output/vmlinux', 'output/Module.symvers', 'tools/nvme_s0.bpf.o', 'tools/user_plan.bpf.o', 'tools/peer-guest/xdev_ext_peer_sw.ko']
        for artifact in artifacts[1:]:
            self.write(artifact, 'unit boundary input')
        self.write('output/xdev-ext-xdomain-build.sha256', ''.join(hashlib.sha256((self.root / p).read_bytes()).hexdigest() + '  ' + str(self.root / p) + '\n' for p in artifacts))
        scratch = self.root / 'scratch'
        scratch.mkdir(mode=0o700)
        env = dict(os.environ, PATH=str(bindir) + ':' + os.environ['PATH'],
                   UNIT_SOURCE=str(self.root), UNIT_SHA=self.sha,
                   UNIT_NATIVE=str(self.view / 'kernel'), QEMU='/nonexistent/no-qemu')
        result = subprocess.run(['bash', str(runner), '--ordered-frames', '--source', str(self.root),
                                 '--scratch', str(scratch), '--build', str(self.build),
                                 '--tools', str(self.root / 'tools')], env=env, capture_output=True, text=True)
        self.assertTrue((scratch / 'out/initramfs.cpio.gz').is_file(), result.stdout + result.stderr)
        self.assertNotEqual(result.returncode, 0)  # Deliberately cannot boot.
        before, after = scratch / 'out/destination-before.raw', scratch / 'out/destination.raw'
        self.assertEqual(before.stat().st_size, 16 * 1024 * 1024)
        self.assertNotEqual(before.stat().st_ino, after.stat().st_ino)
        self.assertEqual(before.read_bytes(), after.read_bytes())
        self.assertTrue((scratch / 'initroot/opt/user/ordered_frames_guest').is_file())
        self.assertTrue((scratch / 'initroot/opt/user/ordered_frames_nvme.bpf.o').is_file())
        self.assertFalse((scratch / 'initroot/opt/user/nvme_s0.bpf.o').exists())
        self.assertFalse((scratch / 'initroot/opt/user/user_stage_e2e').exists())
        self.assertGreater(len((scratch / 'evidence/guest-libraries.txt').read_text().splitlines()), 0)
        self.assertFalse((scratch / 'evidence/result.json').exists())
        # A checksum file that omits the USER BPF must fail before packaging;
        # checking only listed files would silently accept an unbound input.
        manifest = self.build / 'xdev-ext-xdomain-build.sha256'
        manifest.write_text(''.join(row for row in manifest.read_text().splitlines(True) if 'user_plan.bpf.o' not in row))
        second = self.root / 'scratch-unbound'
        second.mkdir(mode=0o700)
        unbound = subprocess.run(['bash', str(runner), '--ordered-frames', '--source', str(self.root),
                                 '--scratch', str(second), '--build', str(self.build),
                                 '--tools', str(self.root / 'tools')], env=env, capture_output=True, text=True)
        self.assertNotEqual(unbound.returncode, 0)
        self.assertFalse((second / 'out/initramfs.cpio.gz').exists(), 'unbound USER BPF reached packaging')


class Kunit(unittest.TestCase):
    names = [f'tb_test_example_{i}' for i in range(45)]

    def log(self, rows=None):
        rows = rows if rows is not None else self.names
        body = '\n'.join(f'[ 4.000]    ok {i + 1} {n}' for i, n in enumerate(rows))
        return 'live module console\nXDOMAIN_DMESG_BEGIN\n' + body + '\nXDOMAIN_DMESG_END\nXDEV_EXT_XDOMAIN_GUEST_EXIT=0\n'

    def test_full_final_dmesg(self):
        self.assertEqual(contracts.check_kunit(self.names, self.log())['cases'], 45)

    def test_missing_duplicate_unknown_and_skip_fail(self):
        for rows in [self.names[:-1], self.names + [self.names[0]], self.names[:-1] + ['tb_test_unknown']]:
            with self.subTest(rows=len(rows)), self.assertRaises(ValueError):
                contracts.check_kunit(self.names, self.log(rows))
        with self.assertRaises(ValueError):
            contracts.check_kunit(self.names, self.log() + '# SKIP\n')

    def test_repeated_dmesg_and_truncated_terminal_fail(self):
        for log in [self.log() + self.log(), self.log().replace('XDOMAIN_DMESG_END', ''),
                    'XDOMAIN_DMESG_END\n' + self.log().replace('XDOMAIN_DMESG_END\n', '')]:
            with self.assertRaises(ValueError):
                contracts.check_kunit(self.names, log)


class Ordered(unittest.TestCase):
    marker = 'XDEV_EXT_ORDERED_FRAMES_GUEST=PASS messages=6 selected=7,3,9,1 raw_user=1 poll_without_kick=1 whole_disk=1 stop_late=1 timing=none'

    def log(self):
        return '\n'.join(['XDEV_EXT_ORDERED_PROVIDER_LOAD=0', self.marker,
                         'XDEV_EXT_ORDERED_C_EXIT=0', 'XDEV_EXT_ORDERED_PROVIDER_UNLOAD=0',
                         'XDEV_EXT_ORDERED_DMESG_BEGIN', '[ 1.0] healthy console',
                         'XDEV_EXT_ORDERED_DMESG_END', 'XDEV_EXT_ORDERED_GUEST_EXIT=0', ''])

    def test_ordered_complete_log(self):
        self.assertTrue(callable(getattr(contracts, 'check_ordered', None)), 'ordered terminal gate is missing')
        self.assertEqual(contracts.check_ordered(self.log())['status'], 'PASS')

    def test_missing_duplicate_failed_and_diagnostic_logs(self):
        self.assertTrue(callable(getattr(contracts, 'check_ordered', None)), 'ordered terminal gate is missing')
        for row in self.log().splitlines():
            if row.startswith('XDEV_EXT_'):
                for log in [self.log().replace(row + '\n', ''), self.log() + row + '\n']:
                    with self.subTest(row=row), self.assertRaises(ValueError):
                        contracts.check_ordered(log)
        for bad in ['not ok 1 - failed', 'FAIL', '# SKIP', 'XDEV_EXT_ORDERED_C_EXIT=3',
                    '[ 2.0] quarantined session', '[ 2.0] drain bound passed',
                    'BUG: KASAN', 'WARNING: lockdep', 'Kernel panic']:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                contracts.check_ordered(self.log() + bad + '\n')

    def test_ordered_and_red_are_exclusive_before_setup(self):
        root = Path(__file__).resolve().parents[4]
        result = subprocess.run(['bash', str(root / 'tests/compute/user_stage/user_kvm.sh'),
                                 '--ordered-frames', '--red'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('incompatible', result.stderr)


class WholeImageGate(unittest.TestCase):
    def test_existing_oracle_accepts_only_six_selected_spans(self):
        project = Path(__file__).resolve().parents[4]
        oracle = project / 'tests/compute/user_stage/ordered_frames_validate.py'
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / 'before.raw', Path(directory) / 'after.raw'
            baseline = bytes([0xA5]) * (16 * 1024 * 1024)
            before.write_bytes(baseline)
            expected = bytearray(baseline)
            # Independent fixture from the requested six alternating messages.
            selected = [(7, 3), (9, 1), (7, 3), (9, 1), (7, 3), (9, 1)]
            update = bytes((67 + frame * 37 + byte * 11 + (byte // 256) * 19) % 256
                           for pair in selected for frame in pair for byte in range(512, 3584))
            self.assertEqual(len(update), 36864)
            expected[1048576:1048576 + 36864] = update
            after.write_bytes(expected)
            command = ['python3', '-I', str(oracle), str(before), str(after), '2048']
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['whole_image_bytes'], 16 * 1024 * 1024)
            for bad_offset in (0, 1048576, 1048576 + 36864):
                bad = bytearray(expected)
                bad[bad_offset] ^= 1
                after.write_bytes(bad)
                result = subprocess.run(command, capture_output=True, text=True)
                with self.subTest(offset=bad_offset):
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(json.loads(result.stdout)['verdict'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
