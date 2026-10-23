#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""iommu_receipt.py against fixture sysfs/proc trees; nothing on the host is read."""
import contextlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('iommu_receipt', HERE / 'iommu_receipt.py')
ir = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ir)


def tree(base, groups, cmdline='BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet',
         units=('dmar0', 'dmar1'), release='6.16.0-xdev', config=None, drivers=None):
    """groups: {id: (type, [bdf, ...])}; devices outside groups are created too."""
    root = Path(base)
    (root / 'proc/sys/kernel').mkdir(parents=True)
    (root / 'proc/cmdline').write_text(cmdline + '\n')
    (root / 'proc/sys/kernel/osrelease').write_text(release + '\n')
    pci = root / 'sys/bus/pci/devices'
    pci.mkdir(parents=True)
    for gid, (gtype, devices) in groups.items():
        g = root / 'sys/kernel/iommu_groups' / str(gid)
        (g / 'devices').mkdir(parents=True)
        if gtype is not None:
            (g / 'type').write_text(gtype + '\n')
        for bdf in devices:
            d = pci / bdf
            d.mkdir(exist_ok=True)
            os.symlink(os.path.relpath(d, g / 'devices'), g / 'devices' / bdf)
            os.symlink(os.path.relpath(g, d), d / 'iommu_group')
    for bdf, driver in (drivers or {}).items():
        d = pci / bdf
        d.mkdir(exist_ok=True)
        drv = root / 'sys/bus/pci/drivers' / driver
        drv.mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(drv, d), d / 'driver')
    for unit in units:
        (root / 'sys/class/iommu' / unit).mkdir(parents=True)
    if config is not None:
        (root / 'boot').mkdir()
        (root / 'boot' / ('config-' + release)).write_text(config)
    return root


class Receipt(unittest.TestCase):
    def test_modes_of_group_types(self):
        self.assertEqual(ir.mode_of('DMA'), 'strict')
        self.assertEqual(ir.mode_of('DMA-FQ'), 'lazy')
        self.assertEqual(ir.mode_of('identity'), 'passthrough')
        self.assertEqual(ir.mode_of('blocked'), 'blocked')
        self.assertEqual(ir.mode_of('unmanaged'), 'unmanaged')
        with self.assertRaises(ir.ReceiptError):
            ir.mode_of('fancy')

    def test_cmdline_params(self):
        params = ir.cmdline_params('BOOT_IMAGE=/v intel_iommu=on,sm_on iommu.strict=0 '
                                   'iommu=pt amd_iommu=off quiet iommu.passthrough=1')
        self.assertEqual(params, {'intel_iommu': 'on,sm_on', 'iommu.strict': '0',
                                  'iommu': 'pt', 'amd_iommu': 'off',
                                  'iommu.passthrough': '1'})

    def test_targeted_devices_lazy(self):
        with tempfile.TemporaryDirectory() as t:
            root = tree(t, {3: ('DMA-FQ', ['0000:17:00.0']), 4: ('DMA-FQ', ['0000:65:00.0']),
                            9: ('identity', ['0000:00:1f.0'])},
                        cmdline='root=/dev/sda iommu.strict=0',
                        drivers={'0000:17:00.0': 'nvme'},
                        config='CONFIG_IOMMU_DEFAULT_DMA_LAZY=y\n'
                               '# CONFIG_IOMMU_DEFAULT_DMA_STRICT is not set\n')
            r = ir.collect(root, devices=['0000:17:00.0', '0000:65:00.0'])
        self.assertEqual(r['schema'], ir.SCHEMA)
        self.assertEqual(r['kernel_release'], '6.16.0-xdev')
        self.assertEqual(r['summary_mode'], 'lazy')
        self.assertEqual(r['config_default'], 'lazy')
        self.assertEqual(r['cmdline'], {'iommu.strict': '0'})
        self.assertEqual(r['iommu_units'], ['dmar0', 'dmar1'])
        self.assertEqual(r['devices']['0000:17:00.0'],
                         dict(group=3, type='DMA-FQ', mode='lazy', driver='nvme'))
        self.assertEqual(r['devices']['0000:65:00.0']['driver'], None)
        self.assertEqual(r['groups']['9'], dict(type='identity', mode='passthrough',
                                                devices=['0000:00:1f.0']))

    def test_mixed_and_missing_group(self):
        with tempfile.TemporaryDirectory() as t:
            root = tree(t, {1: ('DMA', ['0000:17:00.0']), 2: ('identity', ['0000:65:00.0'])})
            self.assertEqual(ir.collect(root, devices=['0000:17:00.0', '0000:65:00.0'])
                             ['summary_mode'], 'mixed')
            r = ir.collect(root, devices=['0000:99:00.0'])
        self.assertEqual(r['devices']['0000:99:00.0']['mode'], 'absent')
        self.assertEqual(r['summary_mode'], 'absent')

    def test_device_without_group_means_off(self):
        with tempfile.TemporaryDirectory() as t:
            root = tree(t, {}, units=(), drivers={'0000:17:00.0': 'nvme'})
            r = ir.collect(root, devices=['0000:17:00.0'])
        self.assertEqual(r['devices']['0000:17:00.0']['mode'], 'off')
        self.assertEqual(r['summary_mode'], 'off')
        self.assertEqual(r['groups'], {})

    def test_all_groups_when_no_device_named(self):
        with tempfile.TemporaryDirectory() as t:
            root = tree(t, {1: ('DMA', ['0000:17:00.0']), 2: ('DMA', ['0000:65:00.0']),
                            3: ('blocked', ['0000:80:00.0'])})
            r = ir.collect(root)
        # Blocked groups carry no DMA and do not decide the mode.
        self.assertEqual(r['summary_mode'], 'strict')

    def test_unreadable_type_is_an_error(self):
        with tempfile.TemporaryDirectory() as t:
            root = tree(t, {1: (None, ['0000:17:00.0'])})
            with self.assertRaises(ir.ReceiptError):
                ir.collect(root)

    def test_gzip_config(self):
        with tempfile.TemporaryDirectory() as t:
            root = tree(t, {1: ('DMA', ['0000:17:00.0'])})
            (root / 'proc/config.gz').write_bytes(
                gzip.compress(b'CONFIG_IOMMU_DEFAULT_PASSTHROUGH=y\n'))
            self.assertEqual(ir.collect(root)['config_default'], 'passthrough')


class Cli(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ir.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_expect_mode(self):
        with tempfile.TemporaryDirectory() as t:
            root = tree(t, {1: ('DMA', ['0000:17:00.0'])})
            out = Path(t) / 'receipt.json'
            code, _, _ = self.run_main(['--host-root', str(root), '--device', '0000:17:00.0',
                                        '--expect', 'strict', '--out', str(out)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.read_text())['summary_mode'], 'strict')
            code, _, err = self.run_main(['--host-root', str(root), '--device',
                                          '0000:17:00.0', '--expect', 'lazy'])
        self.assertEqual(code, 1)
        self.assertIn('expected lazy', err)

    def test_bad_bdf_is_usage_error(self):
        with self.assertRaises(SystemExit) as raised, \
                contextlib.redirect_stderr(io.StringIO()):
            ir.main(['--device', '17:00.0'])
        self.assertEqual(raised.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
