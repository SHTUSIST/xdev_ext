#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Oracle sensitivity of the host-side POOL_PEER session validator."""
from pathlib import Path
import re
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
    lines += epoch_receipts()
    lines += ['1..40', v.PASS_PREFIX + ' cases=' + ','.join(p['name'] for p in v.PLANS),
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

    def test_repeated_epochs_reject_stale_payload_and_check_surrounding_guards(self):
        # Reusing an allocation must not replay the previous epoch's bytes.
        for p in EPOCH_CASES:
            d = p['dst_slba'] * v.LBA
            source = p['src_slba'] * v.LBA
            n = p['group']
            with self.subTest(case=p['name'], mutation='stale-payload'):
                dest = bytearray(self.dest)
                dest[d:d + n] = self.source[source + n:source + 2 * n]
                with self.assertRaisesRegex(ValueError, 'destination'):
                    v.check_images(self.source, bytes(dest))
            for offset in (d - 1, d + n):
                with self.subTest(case=p['name'], mutation='guard', offset=offset):
                    dest = bytearray(self.dest)
                    dest[offset] ^= 1
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


EPOCH_CASES = (
    dict(name='epoch-4k-0', frame=4096, seg=4096, group=4096, depth=1, groups=1,
         src_slba=512, dst_slba=512, copies=v.ALL),
    dict(name='epoch-4k-1', frame=4096, seg=4096, group=4096, depth=1, groups=1,
         src_slba=528, dst_slba=528, copies=v.ALL),
    dict(name='epoch-64k-0', frame=65536, seg=65536, group=65536, depth=1, groups=1,
         src_slba=768, dst_slba=768, copies=v.ALL),
    dict(name='epoch-64k-1', frame=65536, seg=65536, group=65536, depth=1, groups=1,
         src_slba=1024, dst_slba=1024, copies=v.ALL),
)


def epoch_receipts():
    # Compose wire fixtures independently of the validator's parser/formatter.
    lines = []
    for index, p in enumerate(EPOCH_CASES):
        lines.append(('# epoch {name}: helper=shared raw_uapi=1 ready=EXTERNAL_READY '
                      'gpu_applicable=0 groups=1 first_seq={seq} create=0 claim_busy=-16 '
                      'start=0 stop=0 stop_proved=1 stats_valid=1 transport_valid=1 '
                      'done=1 abort=0 rejects=0 timeouts=0 protocol_err=0 last_err=0 '
                      'inflight=0 sequestered=0 native_controls=0 pending_acks=0 '
                      'uncertain_controls=0 native_safe=1 held=0 epoch_closed=1').format(
                          name=p['name'], seq=index))
        lines.append(('# epoch {name} provider: pins=2 unpins=1 maps=2 unmaps=0 '
                      'live_pins=1 live_maps=2').format(name=p['name']))
    lines.append('# epoch-provider last-close: pins=2 unpins=2 maps=2 unmaps=2 live_pins=0 live_maps=0')
    return lines


class SharedEpochContract(unittest.TestCase):
    def test_required_case_inventory(self):
        self.assertEqual(tuple(v.PLANS[-4:]), EPOCH_CASES,
                         'missing repeated shared-helper 4KiB/64KiB epoch cases')

    def test_guest_calls_shared_helper_for_required_cases(self):
        source = Path(__file__).with_name('peer_session_e2e.c').read_text()
        for p in EPOCH_CASES:
            self.assertTrue('"' + p['name'] + '"' in source,
                            'guest missing repeated shared-helper case ' + p['name'])
        for api in ('tb_guard_new', 'tb_guard_external_ready', 'tb_epoch_init',
                    'tb_epoch_open', 'tb_epoch_start', 'tb_epoch_wait',
                    'tb_epoch_stop', 'tb_epoch_close', 'tb_guard_snapshot'):
            self.assertIsNotNone(re.search(r'\b' + api + r'\s*\(', source),
                                 'guest missing shared-helper API ' + api)

    def test_missing_receipts_rejected(self):
        with self.assertRaisesRegex(ValueError, 'epoch'):
            v.check_log(good_log().replace('\n'.join(epoch_receipts()) + '\n', ''))

    def test_bad_epoch_snapshot_rejected(self):
        for old, new in (('raw_uapi=1', 'raw_uapi=0'), ('ready=EXTERNAL_READY', 'ready=GPU_READY'),
                         ('gpu_applicable=0', 'gpu_applicable=1'), ('claim_busy=-16', 'claim_busy=0'),
                         ('stop=0', 'stop=-16'), ('stop_proved=1', 'stop_proved=0'),
                         ('stats_valid=1', 'stats_valid=0'), ('transport_valid=1', 'transport_valid=0'),
                         ('done=1', 'done=0'), ('abort=0', 'abort=1'), ('rejects=0', 'rejects=1'),
                         ('timeouts=0', 'timeouts=1'), ('protocol_err=0', 'protocol_err=1'),
                         ('last_err=0', 'last_err=-5'), ('inflight=0', 'inflight=1'),
                         ('sequestered=0', 'sequestered=1'), ('native_controls=0', 'native_controls=1'),
                         ('pending_acks=0', 'pending_acks=1'), ('uncertain_controls=0', 'uncertain_controls=1'),
                         ('native_safe=1', 'native_safe=0'), ('held=0', 'held=1'),
                         ('epoch_closed=1', 'epoch_closed=0'), ('groups=1', 'groups=2'),
                         ('first_seq=0', 'first_seq=1'), ('create=0', 'create=-16'), ('start=0', 'start=-11')):
            with self.subTest(field=old):
                text = good_log()
                receipt = epoch_receipts()[0]
                with self.assertRaisesRegex(ValueError, 'epoch'):
                    v.check_log(text.replace(receipt, receipt.replace(old, new), 1))

    def test_cached_mapping_cannot_remap_or_unpin_between_epochs(self):
        text = good_log()
        receipt = epoch_receipts()[3]
        for old, new in (('maps=2', 'maps=3'), ('pins=2', 'pins=3'),
                         ('unpins=1', 'unpins=2'), ('live_maps=2', 'live_maps=0')):
            with self.subTest(field=old):
                with self.assertRaisesRegex(ValueError, 'epoch'):
                    v.check_log(text.replace(receipt, receipt.replace(old, new)))

    def test_balanced_mapping_or_pin_churn_between_epochs_rejected(self):
        # A remap/unmap pair balances accounting but still violates cache reuse.
        receipt = epoch_receipts()[3]
        for changed in (receipt.replace('maps=2 unmaps=0', 'maps=3 unmaps=1'),
                        receipt.replace('pins=2 unpins=1', 'pins=3 unpins=2')):
            with self.subTest(receipt=changed):
                with self.assertRaisesRegex(ValueError, 'epoch.*cache'):
                    v.check_log(good_log().replace(receipt, changed))

    def test_last_fd_close_must_balance_pin_and_map(self):
        text = good_log()
        receipt = epoch_receipts()[-1]
        for old, new in (('unpins=2', 'unpins=1'), ('unmaps=2', 'unmaps=1'),
                         ('live_pins=0', 'live_pins=1'), ('live_maps=0', 'live_maps=1')):
            with self.subTest(field=old):
                with self.assertRaisesRegex(ValueError, 'epoch'):
                    v.check_log(text.replace(receipt, receipt.replace(old, new)))

    def test_duplicate_missing_or_unknown_cases_rejected(self):
        text = good_log()
        prefix = v.PASS_PREFIX + ' cases='
        line = next(x for x in text.splitlines() if x.startswith(prefix))
        names = [p['name'] for p in v.PLANS]
        for changed in (names[:-1], names + names[-1:], names + ['unknown']):
            with self.subTest(cases=changed):
                with self.assertRaisesRegex(ValueError, 'case'):
                    v.check_log(text.replace(line, prefix + ','.join(changed)))

    def test_duplicate_or_reordered_receipt_rejected(self):
        text = good_log()
        for changed in (text + epoch_receipts()[0] + '\n',
                        text.replace(epoch_receipts()[0], epoch_receipts()[2], 1)):
            with self.assertRaisesRegex(ValueError, 'epoch'):
                v.check_log(changed)

if __name__ == '__main__':
    unittest.main()
