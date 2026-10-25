#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Synthetic decoder rejection controls, never device-execution evidence."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fanout_trace import ABI, validate_trace


def fixture(groups=2):
    events = []
    timestamp = 0
    def add(phase, group, ordinal, stage_value=0, **changes):
        nonlocal timestamp
        timestamp += 10
        length = min(1432, 8192 - ordinal * 1432)
        e = dict(abi=ABI, phase=phase, origin='K', session_id=17, batch_id=group,
                 batch_key=group, frame_id=ordinal, generation=group-1,
                 stage=stage_value, ticket=group*100+11+stage_value,
                 class_id=3 if stage_value < 2 else 2,
                 accepted=1, status=0, cookie=0,
                 address=ordinal*4096+360, bytes=length, aux=0, sequence=0,
                 ts_ns=timestamp, origin_tgid=0, process_start_ticks=0,
                 native_user_data=0, frame_ordinal=ordinal,
                 frame_offset=ordinal*1432, frame_length=length)
        e.update(changes)
        events.append(e)
    for group in range(1, groups+1):
        for ordinal in range(6):
            add('record_admit', group, ordinal, ticket=0)
        # One real NVMe command is expanded over all six frames by the ABI.
        for phase in ('native_submit', 'native_complete'):
            for ordinal in range(6):
                add(phase, group, ordinal, cookie=group*1000+100,
                    address=2048+(group-1)*16, bytes=8192, aux=2 | (15 << 8))
        for ordinal in range(6):
            add('downstream_complete', group, ordinal)
        for ordinal in range(6):
            add('native_submit', group, ordinal, 1, cookie=group*1000+101,
                address=4096+(group-1)*16, bytes=8192, aux=1 | (15 << 8))
        for ordinal in range(6):
            add('descriptor_bind', group, ordinal, 2, cookie=900,
                address=ordinal*4096+278, bytes=min(1432,8192-ordinal*1432)+82)
        for phase in ('native_submit', 'native_complete'):
            for ordinal in range(6):
                add(phase, group, ordinal, 2, cookie=900, session_id=0,
                    batch_key=0, batch_id=0, frame_id=0, generation=0,
                    stage=0, ticket=0, sequence=(group-1)*6+ordinal+1,
                    address=ordinal*4096+278, bytes=min(1432,8192-ordinal*1432)+82,
                    frame_ordinal=0, frame_offset=0, frame_length=0)
        for ordinal in range(6):
            add('downstream_complete', group, ordinal, 2)
        for ordinal in range(6):
            add('native_complete', group, ordinal, 1, cookie=group*1000+101,
                address=4096+(group-1)*16, bytes=8192, aux=1 | (15 << 8))
        for ordinal in range(6):
            add('downstream_complete', group, ordinal, 1)
        for phase in ('frame_recycle', 'record_terminal'):
            for ordinal in range(6):
                # The root batch keeps its producer ticket at the barrier;
                # it does not inherit the stage-2 child batch's ticket.
                add(phase, group, ordinal, 2, ticket=group*100+11)
    return events


def encode(events, loss=0):
    stats = ('XDEV_EXT_FANOUT_TRACE_CLOCK=mono\n'
             'XDEV_EXT_FANOUT_TRACE_CPU_BEGIN cpu0\n'
             f'overrun: {loss}\ndropped events: 0\ncommit overrun: 0\n'
             'XDEV_EXT_FANOUT_TRACE_CPU_END cpu0\n')
    lines = ['worker-1 [000] .... 1.000000: native_event: ' +
             ' '.join(f'{key}={value}' for key,value in e.items()) for e in events]
    return stats + 'XDEV_EXT_FANOUT_TRACE_BEGIN\n' + '\n'.join(lines) + '\nXDEV_EXT_FANOUT_TRACE_END\n'


class FanoutTraceTest(unittest.TestCase):
    def check_bad(self, events):
        with self.assertRaises(ValueError):
            validate_trace(encode(events), 17, 2)

    def test_two_groups_reuse_same_frames_only_after_both_completions(self):
        result = validate_trace(encode(fixture()), 17, 2)
        self.assertEqual(result['shared_frame_publications'], 12)
        self.assertEqual(result['nvme_read_commands'], 2)
        self.assertEqual(result['afxdp_native_completed'], 12)
        self.assertTrue(result['reuse_observed'])
        self.assertFalse(result['physical_dma_proven'])

    def test_nvme_consumer_finishes_before_tx_consumer(self):
        rows = fixture()
        for group in (1, 2):
            edge = min(e['ts_ns'] for e in rows
                       if e['batch_key']==group and e['phase']=='descriptor_bind')
            for e in rows:
                if e['batch_key']==group and e['stage']==1:
                    if e['phase']=='native_complete':
                        e['ts_ns']=edge+1
                    elif e['phase']=='downstream_complete':
                        e['ts_ns']=edge+2
        self.assertEqual(validate_trace(encode(rows), 17, 2)['status'], 'PASS')

    def test_malformed_cpu_block_not_silently_ignored(self):
        text = encode(fixture()) + 'XDEV_EXT_FANOUT_TRACE_CPU_BEGIN cpu1\n'
        with self.assertRaises(ValueError):
            validate_trace(text, 17, 2)

    def test_missing_native_tx_completion(self):
        rows = fixture()
        rows.pop(next(i for i,e in enumerate(rows)
                      if e['session_id']==0 and e['phase']=='native_complete'))
        self.check_bad(rows)

    def test_early_recycle_before_nvme_consumer(self):
        rows = fixture()
        recycle = next(e for e in rows if e['phase']=='frame_recycle')
        read = next(e for e in rows if e['phase']=='native_complete' and e['stage']==0)
        recycle['ts_ns'] = read['ts_ns'] + 1
        self.check_bad(rows)

    def test_changed_frame_identity_in_consumer(self):
        rows = fixture()
        next(e for e in rows if e['phase']=='descriptor_bind')['frame_id'] = 19
        self.check_bad(rows)

    def test_duplicate_completion(self):
        rows = fixture()
        rows.append(copy.copy(next(e for e in rows if e['phase']=='native_complete')))
        self.check_bad(rows)

    def test_clock_provenance_is_required(self):
        text=encode(fixture()).replace('XDEV_EXT_FANOUT_TRACE_CLOCK=mono',
                                       'XDEV_EXT_FANOUT_TRACE_CLOCK=local')
        with self.assertRaises(ValueError):
            validate_trace(text, 17, 2)

    def test_trace_loss(self):
        with self.assertRaisesRegex(ValueError, 'trace loss'):
            validate_trace(encode(fixture(), loss=1), 17, 2)

    def test_missing_cpu_statistics(self):
        text=encode(fixture()).replace('commit overrun: 0\n', '')
        with self.assertRaises(ValueError):
            validate_trace(text, 17, 2)

    def test_changed_nvme_completion_cookie(self):
        rows=fixture()
        next(e for e in rows if e['phase']=='native_complete' and e['class_id']==3)['cookie'] += 1
        self.check_bad(rows)

    def test_old_generation_after_slot_reuse(self):
        rows=fixture()
        for e in rows:
            if e['batch_key']==2:
                e['generation']=0
        self.check_bad(rows)

    def test_tx_descriptor_points_to_different_payload(self):
        rows=fixture()
        for e in rows:
            if e['class_id']==2 and e['phase'] in ('descriptor_bind','native_submit','native_complete'):
                e['address']+=16
        self.check_bad(rows)

    def test_peer_receiver_cannot_satisfy_missing_sender_completion(self):
        rows=fixture()
        next(e for e in rows if e['phase']=='native_complete' and e['stage']==1)['session_id']=18
        self.check_bad(rows)

    def test_unknown_native_journal(self):
        rows=fixture()
        extra=copy.copy(rows[0]);extra['phase']='trace_invalid';extra['session_id']=0
        rows.append(extra)
        self.check_bad(rows)

    def test_order_uses_native_nanoseconds_not_rounded_display(self):
        rows=fixture()
        # Text lines from different CPUs can have the same rounded timestamp.
        # Native ns preserves their real total ordering.
        rows.reverse()
        result=validate_trace(encode(rows), 17, 2)
        self.assertEqual(result['status'], 'PASS')

    def test_no_submission_or_terminal_marker_can_replace_completions(self):
        rows=[e for e in fixture() if e['phase']!='native_complete']
        self.check_bad(rows)

    def test_wrong_fixed_chain_write_lba(self):
        rows = fixture()
        for e in rows:
            if e['session_id'] == 17 and e['stage'] == 1 and e['phase'] in ('native_submit', 'native_complete'):
                e['address'] = 0
        self.check_bad(rows)

    def test_write_nlb_cannot_disagree_with_command_bytes(self):
        rows = fixture()
        for e in rows:
            if e['session_id'] == 17 and e['stage'] == 1 and e['phase'] in ('native_submit', 'native_complete'):
                # NLB is zero-based: this requests 512 bytes, not 8192.
                e['aux'] = 1
        self.check_bad(rows)

    def test_one_native_command_cannot_expand_to_different_lbas(self):
        rows = fixture()
        for e in rows:
            if (e['batch_key'] == 1 and e['frame_ordinal'] == 0 and
                    e['stage'] == 1 and e['phase'] in ('native_submit', 'native_complete')):
                e['address'] += 16
        self.check_bad(rows)

    def test_downstream_completion_must_match_native_stage_ticket(self):
        rows = fixture()
        for e in rows:
            if e['phase'] == 'downstream_complete':
                e['ticket'] += 9999
        self.check_bad(rows)

    def test_live_umem_rebind_cannot_hide_behind_changed_frame_identity(self):
        rows = fixture()
        # Put the second group's TX submits between the first group's TX
        # submits and completions. Both driver sequence streams remain FIFO.
        times = {
            (0, 'record_admit'): 42100,
            (0, 'native_submit'): 42200,
            (0, 'native_complete'): 42300,
            (0, 'downstream_complete'): 42400,
            (1, 'native_submit'): 42500,
            (2, 'descriptor_bind'): 42600,
            (2, 'downstream_complete'): 80100,
            (1, 'native_complete'): 80200,
            (1, 'downstream_complete'): 80300,
            (2, 'frame_recycle'): 80400,
            (2, 'record_terminal'): 80500,
        }
        for e in rows:
            if e['session_id'] == 17 and e['batch_key'] == 2:
                # Actual addresses still alias group 1. Invented frame IDs
                # must not evade its outstanding native ownership/generation.
                e['frame_id'] += 6
                e['generation'] = 0
                e['ts_ns'] = times[(e['stage'], e['phase'])] + e['frame_ordinal']
            elif e['session_id'] == 0 and e['sequence'] > 6:
                start = 42700 if e['phase'] == 'native_submit' else 80000
                e['ts_ns'] = start + e['sequence'] - 7
            else:
                e['ts_ns'] *= 100
        self.check_bad(rows)


if __name__ == '__main__':
    unittest.main()
