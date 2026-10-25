#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Unit tests of the host oracle of the libxdev_ext guest test.

A synthetic passing log and images are built from the oracle's own plan;
each mutation must turn the verdict into a failure that names the cause.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_validate as v  # noqa: E402


def passing_log():
    out = ['XDEV_EXT_LIB_GUEST_BEGIN']
    for p in v.PLANS:
        g, f = p['groups'], v.frames_per_group(p)
        zc = int(p['mode'] == 'zc')
        if p['expect'] == 'pass':
            out.append(f"XDEV_EXT_LIB_RX_READY ifname=eth1 seg={v.SEG} count={f}")
            out.append(f"XDEV_EXT_LIB_RESULT api={p['api']} ret=0 session=5 zero_copy={zc} "
                       "wait_err=0 nic_err=0 stop_err=0 retained=0")
            out.append(f"XDEV_EXT_LIB_STATS api={p['api']} state=1 last_err=0 batches_done={g} "
                       f"batches_abort=0 rejects=0 sequestered=0 timeouts=0 inflight=0 protocol_err=0 "
                       f"submitted0={g} completed0={g} submitted1={g} completed1={g}")
            ops, nbytes = g * f, g * p['group_bytes']
            out.append(f"XDEV_EXT_LIB_NIC api={p['api']} nic_copy_ops={0 if zc else ops} "
                       f"nic_copy_bytes={0 if zc else nbytes} nic_zc_ops={ops if zc else 0} "
                       f"nic_zc_bytes={nbytes if zc else 0}")
            out.append(f"XDEV_EXT_LIB_EXIT api={p['api']} ret=0 (Success)")
            out.append(f"XDEV_EXT_LIB_RX result=complete groups={g} segments={g * f} unique={g * f} "
                       f"duplicates=0 bad=0 foreign=0 expected={g * f}")
            out.append(f"XDEV_EXT_LIB_SCENARIO name={p['name']} tx_exit=0 rx_exit=0")
        else:
            out.append(f"XDEV_EXT_LIB_RESULT api={p['api']} ret=-34 session=6 zero_copy={zc} "
                       "wait_err=-34 nic_err=0 stop_err=-34 retained=0")
            out.append(f"XDEV_EXT_LIB_STATS api={p['api']} state=1 last_err=-34 batches_done=0 "
                       "batches_abort=1 rejects=1 sequestered=0 timeouts=0 inflight=0 protocol_err=0 "
                       "submitted0=3 completed0=3 submitted1=3 completed1=3")
            out.append(f"XDEV_EXT_LIB_NIC api={p['api']} nic_copy_ops=0 nic_copy_bytes=0 "
                       "nic_zc_ops=18 nic_zc_bytes=24576")
            out.append(f"XDEV_EXT_LIB_EXIT api={p['api']} ret=-34 (Numerical result out of range)")
            out.append(f"XDEV_EXT_LIB_SCENARIO name={p['name']} tx_exit=1 rx_exit=none")
    out += ['XDEV_EXT_LIB_GUEST_EXIT=0', 'XDEV_EXT_LIB_DMESG_BEGIN', '[    0.0] ok',
            'XDEV_EXT_LIB_DMESG_END']
    return '\n'.join(out) + '\n'


def images():
    src = v.source_pattern()
    return src, v.expected_destination(src)


class OracleTest(unittest.TestCase):
    def verdict(self, log, src=None, dst=None):
        s, d = images()
        return v.check(log, src if src is not None else s, dst if dst is not None else d)

    def assertFails(self, needle, log=None, src=None, dst=None):
        with self.assertRaises(ValueError) as e:
            self.verdict(passing_log() if log is None else log, src, dst)
        self.assertIn(needle, str(e.exception))

    def test_pass(self):
        r = self.verdict(passing_log())
        self.assertEqual(r['scenarios'], [p['name'] for p in v.PLANS])
        self.assertEqual(r['checked_bytes'],
                         sum(p['groups'] * p['group_bytes'] for p in v.PLANS if p['expect'] == 'pass'))

    def test_plan_shape(self):
        names = [p['name'] for p in v.PLANS]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('zc', [p['mode'] for p in v.PLANS if p['expect'] == 'pass'])
        self.assertIn('copy', [p['mode'] for p in v.PLANS if p['expect'] == 'pass'])
        self.assertEqual({p['api'] for p in v.PLANS if p['expect'] == 'pass'}, {'oneshot', 'steps'})
        self.assertTrue(any(p['expect'] == 'fail' for p in v.PLANS))
        # Destination regions do not overlap and fit the image.
        spans = sorted((p['dst_offset'], p['dst_offset'] + p['groups'] * p['group_bytes'])
                       for p in v.PLANS if p['expect'] == 'pass')
        self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))
        self.assertLessEqual(spans[-1][1], v.DISK_BYTES)

    def test_shell_plan(self):
        text = v.shell_plan()
        for p in v.PLANS:
            self.assertIn(f"{p['name']}:{p['api']}:{p['mode']}:", text)

    def test_destination_byte(self):
        s, d = images()
        p = v.PLANS[0]
        for off in (p['dst_offset'], p['dst_offset'] + p['groups'] * p['group_bytes'] - 1):
            bad = bytearray(d)
            bad[off] ^= 1
            self.assertFails(f'destination image differs at byte {off}', dst=bytes(bad))

    def test_guard_overwritten(self):
        s, d = images()
        bad = bytearray(d)
        bad[-1] = 0
        self.assertFails(f'destination image differs at byte {len(d) - 1}', dst=bytes(bad))

    def test_source_changed(self):
        s, d = images()
        bad = bytearray(s)
        bad[100] ^= 0xff
        self.assertFails('source image changed at byte 100', src=bytes(bad))

    def test_result_line(self):
        self.assertFails('result line', passing_log().replace(
            'api=oneshot ret=0 session=5 zero_copy=1', 'api=oneshot ret=0 session=5 zero_copy=0', 1))
        self.assertFails('result line', passing_log().replace('stop_err=0 retained=0', 'stop_err=0 retained=1', 1))

    def test_stats_line(self):
        self.assertFails('stats line', passing_log().replace('inflight=0', 'inflight=1', 1))
        self.assertFails('stats line', passing_log().replace('sequestered=0', 'sequestered=2', 1))

    def test_nic_line(self):
        p = v.PLANS[0]
        ops = p['groups'] * v.frames_per_group(p)
        self.assertFails('nic line', passing_log().replace(f'nic_copy_ops=0 nic_copy_bytes=0 nic_zc_ops={ops}',
                                                        f'nic_copy_ops=1 nic_copy_bytes=0 nic_zc_ops={ops}', 1))

    def test_rx_line(self):
        self.assertFails('receiver line', passing_log().replace('result=complete', 'result=timeout', 1))
        self.assertFails('receiver line', passing_log().replace('duplicates=0 bad=0', 'duplicates=0 bad=1', 1))

    def test_negative_scenario(self):
        neg = [p for p in v.PLANS if p['expect'] == 'fail'][0]
        self.assertFails('negative', passing_log().replace(
            f"XDEV_EXT_LIB_RESULT api={neg['api']} ret=-34", f"XDEV_EXT_LIB_RESULT api={neg['api']} ret=0"))
        self.assertFails('negative', passing_log().replace('stop_err=-34 retained=0', 'stop_err=-34 retained=1'))
        # STOP may return 0 or the session's own final error, nothing else.
        self.verdict(passing_log().replace('stop_err=-34 retained=0', 'stop_err=0 retained=0'))
        self.assertFails('negative', passing_log().replace('stop_err=-34 retained=0', 'stop_err=-5 retained=0'))
        self.assertFails('negative', passing_log().replace('last_err=-34 batches_done=0', 'last_err=0 batches_done=0'))

    def test_missing_or_duplicate_scenario(self):
        log = passing_log()
        name = v.PLANS[1]['name']
        self.assertFails('scenario', log.replace(f'XDEV_EXT_LIB_SCENARIO name={name} ', 'X '))
        line = f'XDEV_EXT_LIB_SCENARIO name={name} tx_exit=0 rx_exit=0'
        self.assertFails('scenario', log.replace(line, line + '\n' + line))
        self.assertFails('scenario', log.replace(line, line.replace('rx_exit=0', 'rx_exit=1')))

    def test_every_scenario_reported(self):
        log = passing_log().replace('inflight=0', 'inflight=1', 1)
        report = v.scenario_report(log)
        self.assertEqual(list(report), [p['name'] for p in v.PLANS])
        self.assertIn('stats line', report[v.PLANS[0]['name']])
        self.assertTrue(all(r == 'PASS' for r in list(report.values())[1:]))

    def test_guest_exit_and_debug(self):
        self.assertFails('guest exit', passing_log().replace('XDEV_EXT_LIB_GUEST_EXIT=0', 'XDEV_EXT_LIB_GUEST_EXIT=1'))
        self.assertFails('kernel debug', passing_log().replace(
            '[    0.0] ok', '[    1.0] BUG: KASAN: slab-use-after-free in xdev_ext_mech_stop+0x1/0x2'))


if __name__ == '__main__':
    unittest.main()
