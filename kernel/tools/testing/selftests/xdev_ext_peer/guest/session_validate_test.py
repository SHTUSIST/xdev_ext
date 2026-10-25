#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Oracle sensitivity of the host-side POOL_PEER session validator."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import session_validate as v  # noqa: E402

SIZE = v.DISK_BYTES

STOP_SNAPSHOT = ('# stop-inflight before STOP: done=0 abort=0 inflight=4 sequestered=0 '
                 'submitted=4/0 completed=0/0 last_err=0 state=1')
KILL_SNAPSHOT = ('# kill-inflight before SIGKILL: done=1 abort=0 inflight=4 sequestered=0 '
                 'submitted=5/2 completed=5/1 last_err=0 state=1')


def good_log():
    lines = ['TAP version 13']
    lines += [v.plan_line(p) for p in v.PLANS]
    lines += [STOP_SNAPSHOT, '# stop-inflight STOP returned -125',
              KILL_SNAPSHOT, 'ok 1 - kill-inflight: owner died of SIGKILL']
    lines += [f'ok {i} - check' for i in range(2, 41)]
    lines += ['1..40', v.PASS_PREFIX + ' cases=reject-map,cli,depth4,stop-inflight,kill-inflight,fd-release',
              v.UNLOAD_MARKER, 'XDEV_EXT_SESSION_GUEST_EXIT=0',
              '[    1.0] kasan: KernelAddressSanitizer initialized']
    return '\n'.join(lines) + '\n'


class Images(unittest.TestCase):
    def setUp(self):
        self.source = v.source_pattern(SIZE)
        self.dest = bytearray(v.expected_destination(self.source))

    def test_exact_images_pass(self):
        v.check_images(self.source, bytes(self.dest))

    def test_source_is_not_uniform(self):
        self.assertGreater(len(set(self.source[:4096])), 200)

    def test_every_copied_region_is_checked_first_and_last_byte(self):
        for p in v.PLANS:
            if p['copies'] != v.ALL:
                continue
            start = p['dst_slba'] * v.LBA
            for offset in (start, start + v.plan_bytes(p) - 1):
                with self.subTest(case=p['name'], offset=offset):
                    dest = bytearray(self.dest)
                    dest[offset] ^= 0x01
                    with self.assertRaisesRegex(ValueError, 'destination'):
                        v.check_images(self.source, bytes(dest))

    def test_guard_bytes_around_and_in_rejected_region(self):
        rejected = next(p for p in v.PLANS if not p['copies'])
        for offset in (0, rejected['dst_slba'] * v.LBA, SIZE - 1,
                       v.PLANS[1]['dst_slba'] * v.LBA - 1):
            with self.subTest(offset=offset):
                dest = bytearray(self.dest)
                dest[offset] ^= 0xff
                with self.assertRaisesRegex(ValueError, 'destination'):
                    v.check_images(self.source, bytes(dest))

    def test_rejected_case_must_not_copy(self):
        rejected = next(p for p in v.PLANS if not p['copies'])
        dest = bytearray(self.dest)
        s, d, n = rejected['src_slba'] * v.LBA, rejected['dst_slba'] * v.LBA, v.plan_bytes(rejected)
        dest[d:d + n] = self.source[s:s + n]
        with self.assertRaisesRegex(ValueError, 'destination'):
            v.check_images(self.source, bytes(dest))

    def test_copy_from_wrong_source_offset_fails(self):
        p = v.PLANS[2]
        dest = bytearray(self.dest)
        s, d, n = p['src_slba'] * v.LBA + v.LBA, p['dst_slba'] * v.LBA, v.plan_bytes(p)
        dest[d:d + n] = self.source[s:s + n]
        with self.assertRaisesRegex(ValueError, 'destination'):
            v.check_images(self.source, bytes(dest))

    def test_source_change_fails(self):
        source = bytearray(self.source)
        source[123456] ^= 0x10
        with self.assertRaisesRegex(ValueError, 'source'):
            v.check_images(bytes(source), bytes(self.dest))

    def test_size_mismatch_fails(self):
        with self.assertRaises(ValueError):
            v.check_images(self.source, bytes(self.dest[:-v.LBA]))


class TeardownInFlight(unittest.TestCase):
    """stop-inflight / kill-inflight: each group is the source group or guard."""

    def setUp(self):
        self.source = v.source_pattern(SIZE)
        self.dest = bytearray(v.expected_destination(self.source))
        self.parts = [p for p in v.PLANS if p['copies'] == v.PART]

    def test_plan_has_both_teardown_cases(self):
        self.assertEqual([p['name'] for p in self.parts], ['stop-inflight', 'kill-inflight'])
        spans = sorted((p['dst_slba'], p['dst_slba'] + p['groups'] * p['group'] // v.LBA)
                       for p in v.PLANS if p['copies'] != v.NONE)
        self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))
        self.assertLessEqual(spans[-1][1] * v.LBA, SIZE)
        for p in v.PLANS:
            self.assertLessEqual((p['src_slba'] + p['groups'] * p['group'] // v.LBA) * v.LBA, SIZE)

    def group(self, p, g, shift=0):
        s = p['src_slba'] * v.LBA + g * p['group'] + shift
        return p['dst_slba'] * v.LBA + g * p['group'], self.source[s:s + p['group']]

    def test_untouched_and_copied_groups_pass(self):
        for p in self.parts:
            dest = bytearray(self.dest)
            for g in (0, 1, p['groups'] - 1):
                off, data = self.group(p, g)
                dest[off:off + p['group']] = data
            v.check_images(self.source, bytes(dest))
        v.check_images(self.source, bytes(self.dest))

    def test_torn_group_fails(self):
        for p in self.parts:
            with self.subTest(case=p['name']):
                dest = bytearray(self.dest)
                off, data = self.group(p, 3)
                dest[off:off + v.LBA] = data[:v.LBA]
                with self.assertRaisesRegex(ValueError, 'destination'):
                    v.check_images(self.source, bytes(dest))

    def test_group_from_wrong_source_fails(self):
        for p in self.parts:
            with self.subTest(case=p['name']):
                dest = bytearray(self.dest)
                off, data = self.group(p, 2, shift=p['group'])
                dest[off:off + p['group']] = data
                with self.assertRaisesRegex(ValueError, 'destination'):
                    v.check_images(self.source, bytes(dest))

    def test_plan_line_copies_value(self):
        for p in self.parts:
            self.assertTrue(v.plan_line(p).endswith(' copies=2'))
        self.assertTrue(v.plan_line(v.PLANS[0]).endswith(' copies=0'))
        self.assertTrue(v.plan_line(v.PLANS[1]).endswith(' copies=1'))


class Log(unittest.TestCase):
    def test_good_log_passes(self):
        self.assertEqual(v.check_log(good_log())['ok'], 40)

    def mutated(self, old, new, pattern):
        text = good_log()
        self.assertIn(old, text)
        with self.assertRaisesRegex(ValueError, pattern):
            v.check_log(text.replace(old, new, 1))

    def test_not_ok_fails(self):
        self.mutated('ok 7 - check', 'not ok 7 - check', 'not ok')

    def test_plan_count_mismatch_fails(self):
        self.mutated('1..40', '1..41', 'TAP')

    def test_missing_pass_fails(self):
        self.mutated(v.PASS_PREFIX, 'XDEV_EXT_PEER_SESSION=FAIL', 'PASS')

    def test_missing_unload_fails(self):
        self.mutated(v.UNLOAD_MARKER, '# unload skipped', 'unload')

    def test_guest_exit_nonzero_fails(self):
        self.mutated('XDEV_EXT_SESSION_GUEST_EXIT=0', 'XDEV_EXT_SESSION_GUEST_EXIT=1', 'exit')

    def test_plan_line_drift_fails(self):
        line = v.plan_line(v.PLANS[2])
        self.mutated(line, line.replace('depth=4', 'depth=1'), 'PLAN')

    def test_skip_directive_fails(self):
        self.mutated('ok 3 - check', 'ok 3 - check # SKIP', 'skip')

    def test_kernel_diagnostics_fail(self):
        for report in ('BUG: KASAN: use-after-free in x', 'WARNING: CPU: 1 PID: 2 at io_uring/x.c:1',
                       'possible circular locking dependency detected',
                       'INFO: task kworker blocked for more than 120 seconds.'):
            with self.subTest(report=report):
                with self.assertRaisesRegex(ValueError, 'diagnostic'):
                    v.check_log(good_log() + report + '\n')


class NativeObservation(unittest.TestCase):
    """A teardown PASS needs a real native-incomplete STATS observation."""

    def test_missing_observation_fails(self):
        for snapshot in (STOP_SNAPSHOT, KILL_SNAPSHOT):
            with self.subTest(snapshot=snapshot):
                with self.assertRaisesRegex(ValueError, 'native.*observation'):
                    v.check_log(good_log().replace(snapshot + '\n', ''))

    def test_zero_submission_fails_even_with_active_unfinished_start(self):
        for snapshot in (STOP_SNAPSHOT, KILL_SNAPSHOT):
            zero = snapshot.split(':', 1)[0] + (': done=0 abort=0 inflight=0 sequestered=0 '
                                               'submitted=0/0 completed=0/0 last_err=0 state=1')
            with self.subTest(snapshot=snapshot):
                with self.assertRaisesRegex(ValueError, 'native.*observation'):
                    v.check_log(good_log().replace(snapshot, zero))

    def test_inconsistent_or_no_longer_native_inflight_observation_fails(self):
        for old, new in (('inflight=4', 'inflight=0'),
                         ('submitted=4/0', 'submitted=0/0'),
                         ('completed=0/0', 'completed=4/0'),
                         ('completed=0/0', 'completed=5/0'),
                         ('submitted=4/0', 'submitted=1025/0'),
                         ('done=0', 'done=1024'),
                         ('abort=0', 'abort=1024'),
                         ('sequestered=0', 'sequestered=1'),
                         ('last_err=0', 'last_err=-5'),
                         ('state=1', 'state=2')):
            with self.subTest(old=old, new=new):
                changed = STOP_SNAPSHOT.replace(old, new)
                with self.assertRaisesRegex(ValueError, 'native.*observation'):
                    v.check_log(good_log().replace(STOP_SNAPSHOT, changed))

    def test_duplicate_or_malformed_observation_fails(self):
        for changed in (STOP_SNAPSHOT + '\n' + STOP_SNAPSHOT,
                        STOP_SNAPSHOT.replace('submitted=4/0', 'submitted=-1/0'),
                        STOP_SNAPSHOT.replace(' completed=0/0', '')):
            with self.subTest(changed=changed):
                with self.assertRaisesRegex(ValueError, 'native.*observation'):
                    v.check_log(good_log().replace(STOP_SNAPSHOT, changed))

    def test_producer_only_and_consumer_native_inflight_observations_pass(self):
        result = v.check_log(good_log())
        self.assertEqual(result['native_inflight_observations']['stop-inflight']['submitted'], [4, 0])
        self.assertEqual(result['native_inflight_observations']['kill-inflight']['completed'], [5, 1])

    def test_observation_after_teardown_fails(self):
        text = good_log().replace(STOP_SNAPSHOT + '\n', '')
        text = text.replace('# stop-inflight STOP returned -125',
                            '# stop-inflight STOP returned -125\n' + STOP_SNAPSHOT)
        with self.assertRaisesRegex(ValueError, 'native.*observation'):
            v.check_log(text)


if __name__ == '__main__':
    unittest.main()
