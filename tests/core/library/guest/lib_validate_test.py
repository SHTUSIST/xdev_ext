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


def iou_stats(p, idx, phase, session, **over):
    g = p['groups']
    f = dict(state=1, last_err=0, batches_done=g, batches_abort=0, rejects=0, sequestered=0,
             timeouts=0, inflight=0, protocol_err=0, submitted=f'{g}/{g}/0/0',
             completed=f'{g}/{g}/0/0')
    f.update(over)
    return (f"XDEV_EXT_LIB_IOU_STATS name={p['name']} idx={idx} phase={phase} tag={phase} "
            f"session={session} " + ' '.join(f'{k}={val}' for k, val in f.items()))


def iou_lines(p):
    n, g = p['name'], p['groups']
    out = []
    if p['kind'] in ('single', 'threads', 'procs'):
        if p['kind'] == 'procs':
            out += [f"XDEV_EXT_LIB_IOU_READY name={n} idx=0 session=40 ret=0",
                    f"XDEV_EXT_LIB_IOU_READY name={n} idx=1 session=41 ret=0",
                    f"XDEV_EXT_LIB_IOU_GO name={n} session0=40 session1=41"]
        for idx in range(len(p['src'])):
            if p['kind'] == 'procs':
                out.append(f"XDEV_EXT_LIB_IOU_START name={n} idx={idx} session={40 + idx}")
            out.append(iou_stats(p, idx, 'wait', 40 + idx))
            out.append(f"XDEV_EXT_LIB_IOU_RESULT name={n} idx={idx} session={40 + idx} ret=0 "
                       "wait_err=0 stop_err=0 close_err=0 retained=0")
            if p['kind'] == 'procs':
                out.append(f"XDEV_EXT_LIB_IOU_CHILD name={n} idx={idx} exit=0")
    elif p['kind'] == 'retain':
        out.append(iou_stats(p, 0, 'before-stop', 50, batches_done=0, inflight=2,
                             submitted=f'{g}/{g}/0/0', completed=f'{g}/0/0/0'))
        out.append(f"XDEV_EXT_LIB_RETAIN name={n} phase=stop stop=-16 retained=1")
        out.append(f"XDEV_EXT_LIB_RETAIN name={n} phase=stats-after-stop stats=0")
        out.append(iou_stats(p, 0, 'after-stop', 50, state=3, batches_done=0, inflight=2,
                             submitted=f'{g}/{g}/0/0', completed=f'{g}/0/0/0'))
        out.append(f"XDEV_EXT_LIB_RETAIN name={n} phase=close-held close=-16")
        out.append(f"XDEV_EXT_LIB_RETAIN name={n} phase=released close=0 tries=25")
        out.append(f"XDEV_EXT_LIB_IOU_RESULT name={n} idx=0 session=50 ret=0 wait_err=0 "
                   "stop_err=-16 close_err=0 retained=1")
    else:
        out.append(iou_stats(p, 0, 'wait', 60, state=2, last_err=-5, batches_done=0, sequestered=12,
                             submitted=f'2/2/0/0', completed='2/2/0/0'))
        out.append(iou_stats(p, 0, 'error', 60, state=2, last_err=-5, batches_done=0, sequestered=12,
                             submitted=f'2/2/0/0', completed='2/2/0/0'))
        out.append(f"XDEV_EXT_LIB_ZOMBIE name={n} phase=stop stop=-16 retained=1 stats=0")
        out.append(iou_stats(p, 0, 'after-stop', 60, state=5, last_err=-5, batches_done=0,
                             sequestered=12, submitted='2/2/0/0', completed='2/2/0/0'))
        out.append(f"XDEV_EXT_LIB_ZOMBIE name={n} phase=close close1=-16 close2=-16 stats=0")
        out.append(iou_stats(p, 0, 'after-close', 60, state=5, last_err=-5, batches_done=0,
                             sequestered=12, submitted='2/2/0/0', completed='2/2/0/0'))
        out.append(f"XDEV_EXT_LIB_IOU_RESULT name={n} idx=0 session=60 ret=0 wait_err=-5 "
                   "stop_err=-16 close_err=-16 retained=1")
    out.append(f"XDEV_EXT_LIB_IOU_EXIT name={n} ret=0 (Success)")
    out.append(f"XDEV_EXT_LIB_SCENARIO name={n} tx_exit=0 rx_exit=none")
    return out


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
    for p in v.IOU_PLANS:
        out += iou_lines(p)
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
        self.assertEqual(r['scenarios'], [p['name'] for p in v.PLANS + v.IOU_PLANS])
        self.assertEqual(r['checked_bytes'],
                         sum(p['groups'] * p['group_bytes'] for p in v.PLANS if p['expect'] == 'pass') +
                         sum(p['groups'] * p['group_bytes'] * len(p['dst']) for p in v.IOU_PLANS))

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
        self.assertEqual(list(report), [p['name'] for p in v.PLANS + v.IOU_PLANS])
        self.assertIn('stats line', report[v.PLANS[0]['name']])
        self.assertTrue(all(r == 'PASS' for r in list(report.values())[1:]))

    def test_guest_exit_and_debug(self):
        self.assertFails('guest exit', passing_log().replace('XDEV_EXT_LIB_GUEST_EXIT=0', 'XDEV_EXT_LIB_GUEST_EXIT=1'))
        self.assertFails('kernel debug', passing_log().replace(
            '[    0.0] ok', '[    1.0] BUG: KASAN: slab-use-after-free in xdev_ext_mech_stop+0x1/0x2'))


class IouOracleTest(unittest.TestCase):
    """IOU_UMEM, concurrent-handle and retained/ZOMBIE scenarios."""

    def verdict(self, log, dst=None):
        s, d = images()
        return v.check(log, s, d if dst is None else dst)

    def assertFails(self, needle, log=None, dst=None):
        with self.assertRaises(ValueError) as e:
            self.verdict(passing_log() if log is None else log, dst)
        self.assertIn(needle, str(e.exception))

    def plan(self, kind):
        return next(p for p in v.IOU_PLANS if p['kind'] == kind)

    def test_iou_plan_shape(self):
        self.assertEqual([p['kind'] for p in v.IOU_PLANS],
                         ['single', 'threads', 'procs', 'retain', 'zombie'])
        spans = sorted((d * v.LBA, d * v.LBA + p['groups'] * p['group_bytes'])
                       for p in v.IOU_PLANS for d in p['dst'])
        spans += [(p['dst_offset'], p['dst_offset'] + p['groups'] * p['group_bytes'])
                  for p in v.PLANS if p['expect'] == 'pass']
        spans.sort()
        self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))
        self.assertLessEqual(spans[-1][1], v.DISK_BYTES)
        for p in v.IOU_PLANS:
            self.assertEqual(len(p['src']), len(p['dst']))
            self.assertEqual(len(p['src']), 2 if p['kind'] in ('threads', 'procs') else 1)
        # The late CE completion must outlast the kernel's 5 s drain bound.
        self.assertGreater(self.plan('retain')['ce_delay_us'], 5_000_000)
        self.assertEqual(self.plan('zombie')['ce_fail'], 'ambiguous')

    def test_iou_shell_plan(self):
        lines = v.shell_plan_iou().splitlines()
        self.assertEqual(len(lines), len(v.IOU_PLANS))
        p = self.plan('threads')
        self.assertIn(f"{p['name']}:threads:{p['groups']}:{p['depth']}:{p['group_bytes']}:"
                      f"{p['src'][0]}:{p['dst'][0]}:{p['src'][1]}:{p['dst'][1]}:", v.shell_plan_iou())
        p = self.plan('single')
        self.assertIn(f"{p['name']}:single:{p['groups']}:{p['depth']}:{p['group_bytes']}:"
                      f"{p['src'][0]}:{p['dst'][0]}:-:-:", v.shell_plan_iou())

    def test_exact_window_byte(self):
        s, d = images()
        for kind in ('single', 'threads', 'procs'):
            p = self.plan(kind)
            off = p['dst'][-1] * v.LBA + p['groups'] * p['group_bytes'] - 1
            bad = bytearray(d)
            bad[off] ^= 1
            self.assertFails(f'destination image differs at byte {off}', dst=bytes(bad))

    def test_retain_window_either_per_group(self):
        s, d = images()
        p = self.plan('retain')
        base, gb = p['dst'][0] * v.LBA, p['group_bytes']
        # Each group is the source group or untouched guard: both pass.
        for g in range(p['groups']):
            ok = bytearray(d)
            ok[base + g * gb:base + (g + 1) * gb] = s[p['src'][0] * v.LBA + g * gb:
                                                    p['src'][0] * v.LBA + (g + 1) * gb]
            self.verdict(passing_log(), dst=bytes(ok))
        torn = bytearray(d)
        torn[base:base + 512] = s[p['src'][0] * v.LBA:p['src'][0] * v.LBA + 512]
        self.assertFails(f"{p['name']} group 0", dst=bytes(torn))

    def test_zombie_window_untouched(self):
        s, d = images()
        p = self.plan('zombie')
        bad = bytearray(d)
        off = p['dst'][0] * v.LBA
        bad[off:off + p['group_bytes']] = s[p['src'][0] * v.LBA:p['src'][0] * v.LBA + p['group_bytes']]
        self.assertFails(f'destination image differs at byte {off}', dst=bytes(bad))

    def test_exact_result_and_stats(self):
        n = self.plan('single')['name']
        self.assertFails(f'{n} idx 0 result', passing_log().replace(
            f'name={n} idx=0 session=40 ret=0 wait_err=0 stop_err=0 close_err=0 retained=0',
            f'name={n} idx=0 session=40 ret=0 wait_err=0 stop_err=0 close_err=0 retained=1'))
        g = self.plan('single')['groups']
        self.assertFails(f'{n} idx 0 stats', passing_log().replace(
            f'name={n} idx=0 phase=wait tag=wait session=40 state=1 last_err=0 batches_done={g}',
            f'name={n} idx=0 phase=wait tag=wait session=40 state=1 last_err=0 batches_done={g - 1}'))
        self.assertFails(f'{n} idx 0 stats', passing_log().replace(
            f'completed={g}/{g}/0/0', f'completed={g}/{g - 1}/0/0', 1))

    def test_pair_needs_both_and_distinct_sessions(self):
        n = self.plan('threads')['name']
        log = passing_log()
        line = next(l for l in log.splitlines() if l.startswith(f'XDEV_EXT_LIB_IOU_RESULT name={n} idx=1 '))
        self.assertFails(f'{n} idx 1 result', log.replace(line + '\n', ''))
        same = log.replace(f'name={n} idx=1 session=41', f'name={n} idx=1 session=40')
        same = same.replace(f'name={n} idx=1 phase=wait tag=wait session=41',
                            f'name={n} idx=1 phase=wait tag=wait session=40')
        self.assertFails(f'{n} sessions', same)

    def test_procs_children(self):
        n = self.plan('procs')['name']
        self.assertFails(f'{n} child', passing_log().replace(
            f'XDEV_EXT_LIB_IOU_CHILD name={n} idx=1 exit=0', f'XDEV_EXT_LIB_IOU_CHILD name={n} idx=1 exit=1'))

    def test_procs_require_ready_go_and_start(self):
        n = self.plan('procs')['name']
        for tag in ('READY', 'GO', 'START'):
            with self.subTest(tag=tag):
                lines = passing_log().splitlines()
                line = next(l for l in lines if l.startswith(f'XDEV_EXT_LIB_IOU_{tag} name={n} '))
                self.assertFails(f'{n} barrier', '\n'.join(l for l in lines if l != line) + '\n')

    def test_procs_ready_identity_and_success(self):
        n = self.plan('procs')['name']
        for old, new in (('session=41 ret=0', 'session=40 ret=0'),
                         ('session=41 ret=0', 'session=42 ret=0'),
                         ('session=41 ret=0', 'session=41 ret=-5')):
            with self.subTest(new=new):
                self.assertFails(f'{n} barrier', passing_log().replace(
                    f'XDEV_EXT_LIB_IOU_READY name={n} idx=1 {old}',
                    f'XDEV_EXT_LIB_IOU_READY name={n} idx=1 {new}'))

    def test_procs_barrier_order(self):
        n = self.plan('procs')['name']
        original = passing_log().splitlines()
        go = next(l for l in original if l.startswith(f'XDEV_EXT_LIB_IOU_GO name={n} '))
        ready = next(l for l in original if l.startswith(f'XDEV_EXT_LIB_IOU_READY name={n} idx=1 '))
        start = next(l for l in original if l.startswith(f'XDEV_EXT_LIB_IOU_START name={n} idx=0 '))
        result = next(l for l in original if l.startswith(f'XDEV_EXT_LIB_IOU_RESULT name={n} idx=0 '))
        for line, before in ((go, ready), (start, go), (result, go)):
            with self.subTest(line=line):
                bad = original.copy()
                bad.remove(line)
                bad.insert(bad.index(before), line)
                self.assertFails(f'{n} barrier', '\n'.join(bad) + '\n')

    def test_procs_barrier_duplicate_and_mismatched_release(self):
        n = self.plan('procs')['name']
        log = passing_log()
        for tag in ('READY', 'GO', 'START'):
            with self.subTest(tag=tag):
                line = next(l for l in log.splitlines() if l.startswith(f'XDEV_EXT_LIB_IOU_{tag} name={n} '))
                self.assertFails(f'{n} barrier', log.replace(line, line + '\n' + line))
        self.assertFails(f'{n} barrier', log.replace(f'name={n} session0=40 session1=41',
                                                    f'name={n} session0=40 session1=42'))
        self.assertFails(f'{n} barrier', log.replace(f'XDEV_EXT_LIB_IOU_START name={n} idx=1 session=41',
                                                    f'XDEV_EXT_LIB_IOU_START name={n} idx=1 session=42'))

    def test_retain_sequence(self):
        n = self.plan('retain')['name']
        log = passing_log()
        self.assertFails(f'{n} stop', log.replace(f'name={n} phase=stop stop=-16 retained=1',
                                                  f'name={n} phase=stop stop=0 retained=0'))
        self.assertFails(f'{n} close-held', log.replace(f'name={n} phase=close-held close=-16',
                                                        f'name={n} phase=close-held close=0'))
        self.assertFails(f'{n} released', log.replace(f'name={n} phase=released close=0',
                                                      f'name={n} phase=released close=-16'))
        self.assertFails(f'{n} before-stop', log.replace(
            f'name={n} idx=0 phase=before-stop tag=before-stop session=50 state=1 last_err=0 batches_done=0 '
            'batches_abort=0 rejects=0 sequestered=0 timeouts=0 inflight=2',
            f'name={n} idx=0 phase=before-stop tag=before-stop session=50 state=1 last_err=0 batches_done=0 '
            'batches_abort=0 rejects=0 sequestered=0 timeouts=0 inflight=0'))
        self.assertFails(f'{n} after-stop', log.replace(
            f'name={n} idx=0 phase=after-stop tag=after-stop session=50 state=3',
            f'name={n} idx=0 phase=after-stop tag=after-stop session=50 state=1'))
        self.assertFails(f'{n} after-stop', log.replace(
            f'name={n} idx=0 phase=after-stop tag=after-stop session=50 state=3 last_err=0 batches_done=0 '
            'batches_abort=0 rejects=0 sequestered=0',
            f'name={n} idx=0 phase=after-stop tag=after-stop session=50 state=3 last_err=0 batches_done=0 '
            'batches_abort=0 rejects=0 sequestered=1'))

    def test_zombie_sequence(self):
        n = self.plan('zombie')['name']
        log = passing_log()
        self.assertFails(f'{n} stop', log.replace(f'name={n} phase=stop stop=-16 retained=1 stats=0',
                                                  f'name={n} phase=stop stop=-5 retained=0 stats=-2'))
        self.assertFails(f'{n} close', log.replace(f'name={n} phase=close close1=-16 close2=-16',
                                                   f'name={n} phase=close close1=-16 close2=0'))
        self.assertFails(f'{n} after-stop', log.replace(
            f'name={n} idx=0 phase=after-stop tag=after-stop session=60 state=5',
            f'name={n} idx=0 phase=after-stop tag=after-stop session=60 state=4'))
        self.assertFails(f'{n} after-close', log.replace(
            f'name={n} idx=0 phase=after-close tag=after-close session=60 state=5 last_err=-5 batches_done=0 '
            'batches_abort=0 rejects=0 sequestered=12',
            f'name={n} idx=0 phase=after-close tag=after-close session=60 state=5 last_err=-5 batches_done=0 '
            'batches_abort=0 rejects=0 sequestered=0'))
        self.assertFails(f'{n} wait', log.replace(
            f'name={n} idx=0 session=60 ret=0 wait_err=-5', f'name={n} idx=0 session=60 ret=0 wait_err=0'))
        # An ambiguous batch never reaches the NVMe write stage.
        self.assertFails(f'{n} error', log.replace(
            f'name={n} idx=0 phase=error tag=error session=60 state=2 last_err=-5 batches_done=0 '
            'batches_abort=0 rejects=0 sequestered=12 timeouts=0 inflight=0 protocol_err=0 submitted=2/2/0/0',
            f'name={n} idx=0 phase=error tag=error session=60 state=2 last_err=-5 batches_done=0 '
            'batches_abort=0 rejects=0 sequestered=12 timeouts=0 inflight=0 protocol_err=0 submitted=2/2/0/1'))

    def test_iou_exit_and_marker(self):
        n = self.plan('zombie')['name']
        self.assertFails(f'{n} exit', passing_log().replace(f'XDEV_EXT_LIB_IOU_EXIT name={n} ret=0',
                                                            f'XDEV_EXT_LIB_IOU_EXIT name={n} ret=-71'))
        self.assertFails(f'{n} scenario exits', passing_log().replace(
            f'XDEV_EXT_LIB_SCENARIO name={n} tx_exit=0', f'XDEV_EXT_LIB_SCENARIO name={n} tx_exit=1'))


if __name__ == '__main__':
    unittest.main()
