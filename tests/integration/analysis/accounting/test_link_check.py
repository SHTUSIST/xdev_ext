#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""link_check.py against fake sysfs trees; nothing is read from real devices."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
TOOL = HERE / 'link_check.py'
spec = importlib.util.spec_from_file_location('link_check', TOOL)
lc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lc)

GPU, NVME = '0000:01:00.0', '0000:02:00.0'

# argv: FILE VALUE DELAY_S [FILE2 VALUE2] -> write VALUE, sleep, write VALUE2.
LOAD = """
import sys, time
from pathlib import Path
Path(sys.argv[1]).write_text(sys.argv[2] + '\\n')
time.sleep(float(sys.argv[3]))
if len(sys.argv) > 5:
    Path(sys.argv[4]).write_text(sys.argv[5] + '\\n')
    time.sleep(float(sys.argv[3]))
sys.exit(int(sys.argv[6]) if len(sys.argv) > 6 else 0)
"""


class Parse(unittest.TestCase):
    def test_pcie_speed_strings(self):
        self.assertEqual(lc.pcie_gts('32.0 GT/s PCIe'), 32.0)
        self.assertEqual(lc.pcie_gts('2.5 GT/s PCIe\n'), 2.5)
        self.assertEqual(lc.pcie_gts('8.0 GT/s'), 8.0)
        self.assertIsNone(lc.pcie_gts('Unknown'))

    def test_xdomain_speed_strings(self):
        self.assertEqual(lc.xdomain_gbps('20.0 Gb/s\n'), 20.0)
        self.assertIsNone(lc.xdomain_gbps('fast'))


class Check(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='link-check-')
        self.root = Path(self.tmp.name) / 'sys'
        self.pci(GPU, '32.0 GT/s PCIe', 16, '32.0 GT/s PCIe', 16)
        self.pci(NVME, '16.0 GT/s PCIe', 4, '16.0 GT/s PCIe', 4)
        self.xd('0-1', '20.0 Gb/s', 2)
        net = self.root / 'class/net/thunderbolt0'
        net.mkdir(parents=True)
        (net / 'mtu').write_text('65522\n')
        (net / 'operstate').write_text('up\n')
        self.load = Path(self.tmp.name) / 'load.py'
        self.load.write_text(LOAD)

    def tearDown(self):
        self.tmp.cleanup()

    def pci(self, bdf, cur, curw, mx, mxw):
        d = self.root / 'bus/pci/devices' / bdf
        d.mkdir(parents=True, exist_ok=True)
        for name, value in (('current_link_speed', cur), ('current_link_width', curw),
                            ('max_link_speed', mx), ('max_link_width', mxw)):
            (d / name).write_text(f'{value}\n')
        return d

    def xd(self, name, speed, lanes, tx_lanes=None):
        d = self.root / 'bus/thunderbolt/devices' / name
        d.mkdir(parents=True, exist_ok=True)
        (d / 'unique_id').write_text('00000000-0000-0000-0000-000000000001\n')
        for n, v in (('rx_speed', speed), ('tx_speed', speed), ('rx_lanes', lanes),
                     ('tx_lanes', lanes if tx_lanes is None else tx_lanes)):
            (d / n).write_text(f'{v}\n')
        return d

    def run_tool(self, *extra, cmd=()):
        out = Path(self.tmp.name) / 'link.json'
        if out.exists():
            out.unlink()
        argv = [sys.executable, str(TOOL), '--sysfs-root', str(self.root),
                '--pci', f'{GPU}=gpu', '--pci', f'{NVME}=nvme', '--interval-ms', '10',
                '--out', str(out), *extra]
        if cmd:
            argv += ['--', *cmd]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return r, json.loads(out.read_text()) if out.exists() else None

    def test_links_at_their_maximum_pass(self):
        r, rec = self.run_tool('--xdomain', 'auto', '--netdev', 'thunderbolt0')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(rec['schema'], lc.SCHEMA)
        self.assertEqual(rec['verdict'], 'ok')
        gpu = rec['pci']['gpu']
        self.assertEqual((gpu['bdf'], gpu['max_gts'], gpu['max_width']), (GPU, 32.0, 16))
        self.assertEqual(gpu['verdict'], 'ok')
        self.assertEqual(rec['xdomain']['device'], '0-1')
        self.assertEqual(rec['xdomain']['line_rate_gbps'], 40.0)
        self.assertEqual(rec['netdev']['mtu'], 65522)
        self.assertEqual(rec['mode'], 'snapshot')

    def test_speed_below_maximum_rejects(self):
        self.pci(GPU, '16.0 GT/s PCIe', 16, '32.0 GT/s PCIe', 16)
        r, rec = self.run_tool()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(rec['verdict'], 'below_max')
        self.assertEqual(rec['pci']['gpu']['verdict'], 'below_max')
        self.assertEqual(rec['pci']['nvme']['verdict'], 'ok')

    def test_width_below_maximum_rejects(self):
        self.pci(NVME, '16.0 GT/s PCIe', 2, '16.0 GT/s PCIe', 4)
        r, rec = self.run_tool()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(rec['pci']['nvme']['verdict'], 'below_max')

    def test_unreadable_speed_rejects(self):
        self.pci(GPU, 'Unknown', 16, '32.0 GT/s PCIe', 16)
        r, rec = self.run_tool()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(rec['pci']['gpu']['verdict'], 'unreadable')

    def test_idle_downshift_before_load_is_not_counted_after_warmup(self):
        # The GPU idles at 2.5 GT/s and trains to 32 GT/s when the load starts.
        self.pci(GPU, '2.5 GT/s PCIe', 16, '32.0 GT/s PCIe', 16)
        speed = self.root / 'bus/pci/devices' / GPU / 'current_link_speed'
        r, rec = self.run_tool('--warmup-ms', '100',
                               cmd=[sys.executable, str(self.load), str(speed),
                                    '32.0 GT/s PCIe', '0.5'])
        self.assertEqual(r.returncode, 0, r.stderr)
        gpu = rec['pci']['gpu']
        self.assertEqual(rec['mode'], 'under-load')
        self.assertGreater(gpu['samples'], 5)
        self.assertEqual(gpu['min_gts'], 32.0)
        self.assertEqual(gpu['fraction_at_max'], 1.0)
        self.assertEqual(rec['harness']['exit'], 0)

    def test_a_downshift_during_the_load_rejects(self):
        speed = self.root / 'bus/pci/devices' / GPU / 'current_link_speed'
        r, rec = self.run_tool('--warmup-ms', '50',
                               cmd=[sys.executable, str(self.load), str(speed),
                                    '32.0 GT/s PCIe', '0.3', str(speed), '8.0 GT/s PCIe'])
        self.assertEqual(r.returncode, 1, r.stderr)
        gpu = rec['pci']['gpu']
        self.assertEqual(gpu['verdict'], 'below_max')
        self.assertEqual(gpu['min_gts'], 8.0)
        self.assertLess(gpu['fraction_at_max'], 1.0)

    def test_harness_failure_rejects(self):
        speed = self.root / 'bus/pci/devices' / GPU / 'current_link_speed'
        r, rec = self.run_tool(cmd=[sys.executable, str(self.load), str(speed),
                                    '32.0 GT/s PCIe', '0.05', str(speed), '32.0 GT/s PCIe', '5'])
        self.assertEqual(r.returncode, 1)
        self.assertEqual(rec['verdict'], 'harness_failed')
        self.assertEqual(rec['harness']['exit'], 5)

    def test_single_lane_xdomain_rejects(self):
        self.xd('0-1', '20.0 Gb/s', 1)
        r, rec = self.run_tool('--xdomain', '0-1')
        self.assertEqual(r.returncode, 1)
        self.assertEqual(rec['xdomain']['verdict'], 'lanes_below_min')
        self.assertEqual(rec['xdomain']['line_rate_gbps'], 20.0)

    def test_xdomain_speed_floor(self):
        r, rec = self.run_tool('--xdomain', '0-1', '--min-xdomain-gbps', '40')
        self.assertEqual(r.returncode, 1)
        self.assertEqual(rec['xdomain']['verdict'], 'speed_below_min')

    def test_missing_devices_are_refused(self):
        r, rec = self.run_tool('--pci', '0000:09:00.0=ghost')
        self.assertEqual(r.returncode, 4)
        empty = Path(self.tmp.name) / 'empty'
        (empty / 'bus/thunderbolt/devices').mkdir(parents=True)
        self.root = empty
        r, rec = self.run_tool('--xdomain', 'auto')
        self.assertEqual(r.returncode, 4)

    def test_dry_run_reads_nothing(self):
        r = subprocess.run([sys.executable, str(TOOL), '--sysfs-root', '/nonexistent',
                            '--pci', f'{GPU}=gpu', '--dry-run'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIs(json.loads(r.stdout)['dry_run'], True)


if __name__ == '__main__':
    unittest.main()
