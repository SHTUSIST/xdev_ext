#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Synthetic raw mapping cases; these are never physical DMA evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('backing_real_collector', HERE / 'collector.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def fixture(directory, arm='K-BPF'):
    k = arm.startswith('K')
    owner = dict(origin_tgid=7, process_start_ticks=8)
    plan = dict(run_id='nonphysical-backing', exact_sha='a' * 40, arm=arm,
        physical=False, evidence_kind='fixture', clock='CLOCK_MONOTONIC', clock_domain='fixture',
        endpoint='local_tx_complete', record_bytes=16,
        recipe=dict(chain='nvme-nic', records=1, warmup_records=0),
        stages=[dict(id='read', after=[]), dict(id='tx', after=['read'])],
        records=[dict(session_id=7, record_id=0, generation=0, frame_ids=[0, 1])],
        trace=dict(record_mapping='batch_key_div_burst', generation_mapping='batch_key_relative',
                   burst=1, batch_key_origin=1, stage_map={'0': 'read', '1': 'tx'},
                   sessions=[dict(logical_id=7, role='sender', measured=True)],
                   layout=[dict(frame_id=0, offset_bytes=0, length_bytes=8),
                           dict(frame_id=1, offset_bytes=8, length_bytes=8)]))
    rows = []
    def emit(phase, t, **changes):
        item = dict(phase=phase, origin='K' if k else 'U', session_id=99 if k else 0,
            batch_id=1, batch_key=1, frame_id=0, generation=1, stage=0, ticket=19,
            class_id=3, accepted=1, status=0, cookie=42 if k else 90, address=64,
            bytes=16, aux=2, sequence=0 if k else 42, native_user_data=0 if k else 90,
            frame_ordinal=0, frame_offset=0, frame_length=8, **owner)
        item.update(changes, ts_ns=t)
        rows.append(item)
    emit('pool_bind', 1, origin='U', class_id=2, cookie=222, bytes=64, aux=128)
    emit('region_span', 2, origin='U', class_id=2, cookie=222, address=65536, bytes=128, aux=0)
    for i in range(2):
        emit('dma_span', 3+i, origin='U', class_id=2, cookie=222, address=65536+i*64,
             bytes=64, aux=i*64, sequence=i, native_user_data=131072+i*64)
    emit('dma_seal', 5, origin='U', class_id=2, cookie=222, address=0, bytes=128, aux=2, sequence=0, native_user_data=0)
    if k:
        emit('session_bind', 6)
        for f in range(2):
            emit('record_admit', 8, frame_id=f, frame_ordinal=f, frame_offset=f*8,
                 address=20+f*64, bytes=8)
            emit('native_submit', 10, frame_id=f, frame_ordinal=f, frame_offset=f*8)
    else:
        for i in range(2):
            emit('native_span', 9, address=65556+i*64, bytes=8, aux=i*8)
        emit('native_submit', 10)
    for i in range(2):
        emit('dma_span', 11+i, cookie=42, address=65556+i*64, bytes=8,
             aux=i*8, sequence=i, native_user_data=262144+i*64)
    emit('dma_seal', 13, cookie=42, address=0, bytes=16, aux=2, sequence=0, native_user_data=0)
    emit('dma_unmap', 14, cookie=42, address=0, bytes=16, aux=0, sequence=0, native_user_data=0)
    if k:
        for f in range(2):
            emit('native_complete', 20, frame_id=f, frame_ordinal=f, frame_offset=f*8)
    else:
        emit('native_complete', 20)
    journal = []
    if k:
        journal.append(dict(kind='session_bind', role='sender', pid=7, process_start_ticks=8,
            user_hz=os.sysconf('SC_CLK_TCK'), native_session_id=99, session_id=99,
            logical_session_id=7, first_batch_key=1, groups=1, warmup=0, burst=1))
    else:
        journal.append(dict(kind='metadata', abi='xdev-native-v1', clock='CLOCK_MONOTONIC',
            lost=False, fixed_io=False, rx=False, pid=7, process_start_ticks=8,
            user_hz=os.sysconf('SC_CLK_TCK'), session_id=7, role='sender'))
        for f in range(2):
            journal.append(dict(kind='nvme', ts_ns=9, cookie=90, session_id=7, record_id=0,
                generation=0, frame_id=f, frame_ordinal=f, frame_offset=f*8, frame_length=8,
                stage=0, lba=64, bytes=8, command_bytes=16, address=20+f*64))
    for f in range(2):
        if k:
            emit('descriptor_bind', 21+f*3, class_id=2, stage=1, cookie=222,
                 address=16+f*64, bytes=12, frame_id=f, frame_ordinal=f, frame_offset=f*8, sequence=0)
        else:
            journal.append(dict(kind='tx', ts_ns=21+f*3, cookie=91+f, session_id=7, record_id=0,
                generation=0, frame_id=f, frame_ordinal=f, frame_offset=f*8, frame_length=8,
                stage=1, bytes=8, descriptor_bytes=12, address=16+f*64))
        for phase, t in [('native_submit', 22+f*3), ('native_complete', 23+f*3)]:
            emit(phase, t, class_id=2, stage=1, cookie=222, address=16+f*64,
                 bytes=12, sequence=f+1, frame_id=0, frame_ordinal=0)
    for f in range(2):
        emit('dma_tx', 22+f*3, origin='U', class_id=2, cookie=222,
             address=16+f*64, bytes=12, native_user_data=131088+f*64, aux=0, sequence=0)
    if k:
        for f in range(2):
            emit('record_terminal', 30, frame_id=f, frame_ordinal=f, frame_offset=f*8,
                 address=20+f*64, bytes=8)
    path = Path(directory) / 'journal.jsonl'
    path.write_text(''.join(json.dumps(row)+'\n' for row in journal))
    meta = dict(clock='CLOCK_MONOTONIC', clock_domain='fixture', trace_dropped=0,
                journal_artifact=collector.artifact(path))
    return plan, rows, meta


def text(rows):
    return ''.join('worker-7 [000] .... 0.000001: native_event: ' +
                   ' '.join('%s=%s' % item for item in row.items())+'\n' for row in rows)


class NativeBacking(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.plan, self.rows, self.meta = fixture(self.temp.name)

    def derive(self):
        function = getattr(collector, 'derive_native_backing', None)
        self.assertTrue(callable(function), 'automatic raw native backing exporter missing')
        return function(self.plan, text(self.rows), self.meta)

    def test_actual_maps_and_payload_anchors_export_two_exact_frames(self):
        proof = self.derive()
        self.assertEqual(proof['source'], 'native_provider')
        self.assertEqual(proof['payload_copy_scope'], 'verified_nvme_read_to_native_afxdp_tx_boundary')
        self.assertEqual(proof['payload_copy_bytes'], 0)
        self.assertEqual(proof['nvme_bounces'], 0)
        self.assertEqual(proof['afxdp_mode'], 'zc')
        self.assertEqual([(f['record_offset_bytes'], f['payload_offset_bytes'], f['payload_bytes'],
                           f['valid_bytes'], f['physical_ranges']) for f in proof['frames']],
                         [(0, 20, 8, 64, [[65556, 8]]), (8, 20, 8, 64, [[65620, 8]])])

    def test_user_poll_and_event_use_request_pointer_and_immutable_payload_anchors(self):
        for arm in ('U-poll', 'U-event'):
            with self.subTest(arm=arm):
                self.plan, self.rows, self.meta = fixture(self.temp.name, arm)
                proof = self.derive()
                self.assertEqual([f['physical_ranges'] for f in proof['frames']],
                                 [[[65556, 8]], [[65620, 8]]])

    def test_different_sg_segmentation_preserves_ordered_payload_bytes(self):
        span = next(row for row in self.rows if row['phase'] == 'dma_span' and row['class_id'] == 3)
        split = dict(span, address=span['address']+4, aux=4, bytes=4, sequence=1)
        span['bytes'] = 4
        for row in self.rows:
            if row['phase'] == 'dma_span' and row['class_id'] == 3 and row['aux'] == 8:
                row['sequence'] = 2
            if row['phase'] == 'dma_seal' and row['class_id'] == 3:
                row['aux'] = 3
        self.rows.insert(self.rows.index(span)+1, split)
        self.assertEqual(self.derive()['frames'][0]['physical_ranges'], [[65556, 8]])

    def test_missing_failed_unknown_duplicate_and_incomplete_seals_refuse(self):
        original = copy.deepcopy(self.rows)
        for class_id in (2, 3):
            for failure in ('missing', 'failed', 'false', 'duplicate', 'count', 'size'):
                with self.subTest(class_id=class_id, failure=failure):
                    self.rows = copy.deepcopy(original)
                    seal = next(row for row in self.rows if row['phase'] == 'dma_seal' and row['class_id'] == class_id)
                    if failure == 'missing': self.rows.remove(seal)
                    elif failure == 'failed': seal['status'] = -95
                    elif failure == 'false': seal['accepted'] = 0
                    elif failure == 'duplicate': self.rows.append(dict(seal))
                    elif failure == 'count': seal['aux'] += 1
                    else: seal['bytes'] += 1
                    with self.assertRaises(ValueError): self.derive()

    def test_payload_mismatch_copy_fallback_and_incomplete_operations_refuse(self):
        original = copy.deepcopy(self.rows)
        for failure in ('physical', 'order', 'owner', 'pool_owner', 'pool_reuse', 'span_duplicate',
                        'span_hole', 'span_unknown', 'overflow', 'empty', 'missing_submit',
                        'missing_complete', 'failed_complete', 'header', 'anchor', 'no_native_tx',
                        'nic_unmap', 'remap', 'nvme_unmap_before_seal', 'missing_admit'):
            with self.subTest(failure=failure):
                self.rows = copy.deepcopy(original)
                nvme = [r for r in self.rows if r['phase'] == 'dma_span' and r['class_id'] == 3]
                seal = next(r for r in self.rows if r['phase'] == 'dma_seal' and r['class_id'] == 2)
                bind = next(r for r in self.rows if r['phase'] == 'pool_bind')
                if failure == 'physical': nvme[0]['address'] += 1
                elif failure == 'order': nvme[0]['address'], nvme[1]['address'] = nvme[1]['address'], nvme[0]['address']
                elif failure == 'owner':
                    for r in self.rows:
                        if r['phase'] == 'descriptor_bind': r['origin_tgid'] = 44
                elif failure == 'pool_owner': bind['origin_tgid'] = 44
                elif failure == 'pool_reuse': self.rows.append(dict(bind, ts_ns=7))
                elif failure == 'span_duplicate': self.rows.append(dict(nvme[0]))
                elif failure == 'span_hole': nvme[1]['aux'] += 1
                elif failure == 'span_unknown': nvme[0]['accepted'] = 0
                elif failure == 'overflow': nvme[0]['address'] = (1 << 64)-4
                elif failure == 'empty': nvme[0]['bytes'] = 0
                elif failure == 'missing_submit': self.rows = [r for r in self.rows if not (r['phase'] == 'native_submit' and r['class_id'] == 3)]
                elif failure == 'missing_complete': self.rows = [r for r in self.rows if not (r['phase'] == 'native_complete' and r['class_id'] == 2)]
                elif failure == 'failed_complete':
                    for r in self.rows:
                        if r['phase'] == 'native_complete': r['status'] = -5
                elif failure == 'header':
                    for r in self.rows:
                        if r['phase'] == 'record_admit': r['address'] -= 4
                elif failure == 'anchor':
                    for r in self.rows:
                        if r['phase'] == 'record_admit': r['address'] += 1
                elif failure == 'no_native_tx': self.rows = [r for r in self.rows if r['class_id'] != 2]
                elif failure == 'nic_unmap': self.rows.append(dict(seal, phase='dma_unmap', ts_ns=23, bytes=0, aux=0))
                elif failure == 'remap': self.rows.append(dict(seal, ts_ns=24))
                elif failure == 'nvme_unmap_before_seal':
                    for r in self.rows:
                        if r['phase'] == 'dma_unmap': r['ts_ns'] = 12
                elif failure == 'missing_admit': self.rows = [r for r in self.rows if r['phase'] != 'record_admit']
                with self.assertRaises(ValueError): self.derive()

    def test_loss_and_unknown_loss_refuse_instead_of_zero_proof(self):
        for loss in (None, 1, False):
            self.meta['trace_dropped'] = loss
            with self.assertRaises(ValueError): self.derive()

    def test_valid_nic_unmap_after_all_native_completions_remains_legal(self):
        seal = next(r for r in self.rows if r['phase'] == 'dma_seal' and r['class_id'] == 2)
        self.rows.append(dict(seal, phase='dma_unmap', ts_ns=35, bytes=0, aux=0))
        self.assertEqual(len(self.derive()['frames']), 2)

    def test_actual_driver_dma_descriptor_is_required_and_matches_sealed_translation(self):
        original = copy.deepcopy(self.rows)
        for failure in ('missing', 'wrong_dma', 'wrong_address', 'wrong_size', 'duplicate',
                        'before_consume', 'after_complete', 'uncertified'):
            with self.subTest(failure=failure):
                self.rows = copy.deepcopy(original)
                tx = next(r for r in self.rows if r['phase'] == 'dma_tx')
                if failure == 'missing': self.rows.remove(tx)
                elif failure == 'wrong_dma': tx['native_user_data'] += 1
                elif failure == 'wrong_address': tx['address'] += 1
                elif failure == 'wrong_size': tx['bytes'] -= 1
                elif failure == 'duplicate': self.rows.append(dict(tx))
                elif failure == 'before_consume': tx['ts_ns'] -= 1
                elif failure == 'after_complete': tx['ts_ns'] += 2
                else: tx['accepted'] = 0
                with self.assertRaises(ValueError): self.derive()

    def test_export_replaces_child_supplied_json_with_own_raw_derivation(self):
        output = Path(self.temp.name) / 'capture'
        output.mkdir()
        proof = output / 'native-backing.json'
        proof.write_text('{"source":"child-supplied"}')
        exporter = getattr(collector, 'export_native_backing', None)
        self.assertTrue(callable(exporter), 'collector-owned backing file generation missing')
        artifact = exporter(self.plan, text(self.rows), self.meta, output)
        self.assertEqual(json.loads(proof.read_text())['frames'][0]['physical_ranges'], [[65556, 8]])
        self.assertEqual(artifact, collector.artifact(proof))
        # Missing real evidence removes the child file rather than adopting it.
        proof.write_text('{"source":"native_provider","payload_copy_bytes":0}')
        self.rows = [r for r in self.rows if r['phase'] != 'dma_seal']
        with self.assertRaises(ValueError): exporter(self.plan, text(self.rows), self.meta, output)
        self.assertFalse(proof.exists())

    def test_child_symlink_is_replaced_without_writing_its_target(self):
        output = Path(self.temp.name) / 'capture'
        output.mkdir()
        target = Path(self.temp.name) / 'child-target'
        target.write_text('preserve unrelated bytes')
        (output / 'native-backing.json').symlink_to(target)
        exporter = getattr(collector, 'export_native_backing', None)
        self.assertTrue(callable(exporter), 'collector-owned backing file generation missing')
        exporter(self.plan, text(self.rows), self.meta, output)
        self.assertFalse((output / 'native-backing.json').is_symlink())
        self.assertEqual(target.read_text(), 'preserve unrelated bytes')

    def two_request_lifetimes(self, arm):
        self.plan, self.rows, self.meta = fixture(self.temp.name, arm)
        path = Path(self.meta['journal_artifact']['path'])
        journal = [json.loads(line) for line in path.read_text().splitlines()]
        second = copy.deepcopy(self.rows)
        second = [r for r in second if r['phase'] not in
                  ('pool_bind', 'region_span', 'session_bind') and not
                  (r['class_id'] == 2 and r['phase'] in ('dma_span', 'dma_seal', 'dma_unmap'))]
        for row in second:
            row['ts_ns'] += 100
            row['batch_key'] = 2
            row['ticket'] += 100
            if row['class_id'] == 2 and row['phase'] in ('native_submit', 'native_complete'):
                row['sequence'] += 2
            if arm.startswith('U') and row['class_id'] == 3 and row['phase'] in ('native_submit', 'native_complete', 'native_span'):
                row['cookie'] += 100
                row['native_user_data'] += 100
        self.rows += second
        self.plan['records'].append(dict(session_id=7, record_id=1, generation=1, frame_ids=[0, 1]))
        self.plan['recipe']['records'] = 2
        if arm.startswith('K'):
            journal[0]['groups'] = 2
        else:
            for row in copy.deepcopy(journal[1:]):
                row['ts_ns'] += 100
                row['cookie'] += 100
                row['record_id'] = row['generation'] = 1
                journal.append(row)
        path.write_text(''.join(json.dumps(row)+'\n' for row in journal))
        self.meta['journal_artifact'] = collector.artifact(path)

    def test_sequential_request_pointer_reuse_has_two_distinct_successful_lifetimes(self):
        for arm in ('K-BPF', 'U-poll', 'U-event'):
            with self.subTest(arm=arm):
                self.two_request_lifetimes(arm)
                proof = self.derive()
                self.assertEqual([(row['record_id'], row['frame_id']) for row in proof['frames']],
                                 [(0, 0), (0, 1), (1, 0), (1, 1)])

    def test_request_pointer_overlapping_lifetimes_refuse(self):
        for arm in ('K-BPF', 'U-poll'):
            with self.subTest(arm=arm):
                self.two_request_lifetimes(arm)
                for row in self.rows:
                    if row['phase'] == 'native_submit' and row['class_id'] == 3 and row['ts_ns'] == 110:
                        row['ts_ns'] = 19
                with self.assertRaises(ValueError): self.derive()

    def test_payload_anchors_are_bound_to_actual_native_slot(self):
        for phase in ('record_admit', 'descriptor_bind'):
            with self.subTest(phase=phase):
                self.plan, self.rows, self.meta = fixture(self.temp.name)
                for row in self.rows:
                    if row['phase'] == phase: row['frame_id'] += 7
                with self.assertRaises(ValueError): self.derive()

    def test_one_kernel_vector_command_has_distinct_per_frame_probe_timestamps(self):
        for row in self.rows:
            if row['class_id'] == 3 and row['phase'] in ('native_submit', 'native_complete'):
                row['ts_ns'] += row['frame_ordinal']
        self.assertEqual(len(self.derive()['frames']), 2)

    def page_rounded_pool(self):
        self.plan['records'][0]['frame_ids'] = [0]
        self.plan['trace']['layout'] = [dict(frame_id=0, offset_bytes=0, length_bytes=16)]
        kept = []
        for row in self.rows:
            phase = row['phase']
            if (phase in ('record_admit', 'record_terminal', 'descriptor_bind') or
                    (row['class_id'] == 3 and phase in ('native_submit', 'native_complete'))) and row['frame_ordinal'] == 1:
                continue
            if row['class_id'] == 2:
                if phase in ('native_submit', 'native_complete') and row['sequence'] == 2: continue
                if phase == 'dma_tx' and row['address'] == 80: continue
                if phase == 'dma_span' and row['aux'] == 64: continue
                if phase == 'pool_bind': row.update(bytes=2048, aux=2048)
                elif phase == 'region_span': row.update(bytes=4096)
                elif phase == 'dma_span': row.update(bytes=4096)
                elif phase == 'dma_seal': row.update(bytes=4096, aux=1)
                elif phase in ('native_submit', 'native_complete', 'descriptor_bind', 'dma_tx'):
                    row['bytes'] = 20
            if row['class_id'] == 3 and phase == 'dma_span' and row['aux'] == 8:
                row['address'] = 65564
            if phase in ('record_admit', 'record_terminal'): row['bytes'] = 16
            row['frame_length'] = 16
            kept.append(row)
        self.rows = kept

    def test_partial_final_umem_page_qualifies_only_registered_bytes(self):
        self.page_rounded_pool()
        proof = self.derive()
        self.assertEqual(proof['frames'][0]['valid_bytes'], 2048)
        self.assertEqual(proof['frames'][0]['physical_ranges'], [[65556, 16]])

    def test_unregistered_tail_of_mapped_page_cannot_be_payload(self):
        self.page_rounded_pool()
        for row in self.rows:
            if row['phase'] in ('record_admit', 'record_terminal', 'descriptor_bind', 'dma_tx') or (
                    row['class_id'] == 2 and row['phase'] in ('native_submit', 'native_complete')):
                row['address'] += 2048
            if row['phase'] == 'dma_tx': row['native_user_data'] += 2048
            if row['class_id'] == 3 and row['phase'] == 'dma_span': row['address'] += 2048
        with self.assertRaises(ValueError): self.derive()

    def test_u_actual_request_source_spans_must_agree_with_final_dma_map(self):
        for failure in ('missing', 'physical', 'request', 'owner', 'after_submit', 'hole'):
            with self.subTest(failure=failure):
                self.plan, self.rows, self.meta = fixture(self.temp.name, 'U-poll')
                span = next(r for r in self.rows if r['phase'] == 'native_span')
                if failure == 'missing': self.rows.remove(span)
                elif failure == 'physical': span['address'] += 1
                elif failure == 'request': span['sequence'] += 1
                elif failure == 'owner': span['origin_tgid'] += 1
                elif failure == 'after_submit': span['ts_ns'] = 11
                else: span['aux'] += 1
                with self.assertRaises(ValueError): self.derive()

    def test_u_protocol_session_is_resolved_to_distinct_logical_session(self):
        for arm in ('U-poll', 'U-event'):
            with self.subTest(arm=arm):
                self.plan, self.rows, self.meta = fixture(self.temp.name, arm)
                self.plan['trace']['sessions'][0]['protocol_session_id'] = 270019
                path = Path(self.meta['journal_artifact']['path'])
                entries = [json.loads(line) for line in path.read_text().splitlines()]
                for row in entries: row['session_id'] = 270019
                path.write_text(''.join(json.dumps(row)+'\n' for row in entries))
                self.meta['journal_artifact'] = collector.artifact(path)
                self.assertEqual([f['session_id'] for f in self.derive()['frames']], [7, 7])

    def test_paired_receiver_source_cookie_collision_does_not_replace_sender_source(self):
        self.plan, self.rows, self.meta = fixture(self.temp.name, 'U-poll')
        self.plan['trace']['sessions'].append(dict(logical_id=8, protocol_session_id=7,
                                                  role='receiver', measured=False))
        pool = next(r for r in self.rows if r['phase'] == 'pool_bind')
        self.rows.append(dict(pool, cookie=333, ts_ns=2, origin_tgid=8, process_start_ticks=9))
        source = next(r for r in self.rows if r['phase'] == 'native_span')
        self.rows.append(dict(source, address=99999, origin_tgid=8,
                              process_start_ticks=9, sequence=444))
        path = Path(self.meta['journal_artifact']['path'])
        header = dict(kind='metadata', abi='xdev-native-v1', clock='CLOCK_MONOTONIC',
            lost=False, fixed_io=False, rx=True, pid=8, process_start_ticks=9,
            user_hz=os.sysconf('SC_CLK_TCK'), session_id=7, role='receiver')
        with path.open('a') as stream: stream.write(json.dumps(header)+'\n')
        self.meta['journal_artifact'] = collector.artifact(path)
        self.assertEqual(len(self.derive()['frames']), 2)

    def test_one_hardware_dma_descriptor_cannot_satisfy_two_native_operations(self):
        # Overlapping FIFO intervals over one address must not double-consume
        # one actual hardware descriptor observation, even when source aliases.
        for row in self.rows:
            if row['class_id'] == 3 and row['phase'] == 'dma_span' and row['aux'] == 8:
                row['address'] = 65556
            if row['phase'] in ('record_admit', 'record_terminal') and row['frame_ordinal'] == 1:
                row['address'] = 20
            if row['class_id'] == 2 and row['phase'] in ('descriptor_bind', 'native_submit', 'native_complete', 'dma_tx'):
                row['address'] = 16
                if row['phase'] == 'native_complete': row['ts_ns'] = 26
                if row['phase'] == 'dma_tx': row['native_user_data'] = 131088
        self.rows = [r for r in self.rows if not (r['phase'] == 'dma_tx' and r['ts_ns'] == 22)]
        with self.assertRaises(ValueError): self.derive()


if __name__ == '__main__':
    unittest.main()
