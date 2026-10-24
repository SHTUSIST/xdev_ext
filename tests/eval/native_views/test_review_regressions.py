#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Review regressions and legal controls; synthetic, never physical evidence."""
import copy
import unittest

from fixtures.builders import event, record_events, run_fixture, target


def backing(manifest, views=None):
    if views is None:
        views = [dict(kind='nvme', backing_id='pages', offset_bytes=0, length_bytes=4096),
                 dict(kind='afxdp', backing_id='pages', offset_bytes=0, length_bytes=4096)]
    return dict(schema_version=1, source='native_provider', run_id=manifest['run_id'],
                exact_sha=manifest['exact_sha'], afxdp_mode='zc', nvme_bounces=0,
                payload_copy_bytes=0,
                frames=[dict(session_id=7, record_id=0, generation=1, frame_id=0,
                             backing_id='pages', valid_bytes=4096, native_views=views)])


class AcceptedWork(unittest.TestCase):
    def test_undeclared_accepted_stage_invalidates_terminal_record(self):
        manifest = run_fixture()
        events = record_events(manifest)
        events += [event(manifest, 'native_submit', 600, 'ghost', frame=0),
                   event(manifest, 'native_complete', 900, 'ghost', frame=0)]
        report = target('analyze').summarize_events(manifest, events)
        self.assertTrue(report['errors'])
        self.assertIsNone(report['records'][0]['latency_ns'])

    def test_accepted_work_requires_native_frame_and_endpoint_record_scope(self):
        for name, frame, stage in (('native_submit', -1, 'read'),
                                   ('record_terminal', 0, 'record'),
                                   ('native_unrecognized', 0, 'read')):
            with self.subTest(name=name):
                manifest = run_fixture()
                events = record_events(manifest) + [event(manifest, name, 200, stage, frame=frame)]
                self.assertTrue(target('analyze').summarize_events(manifest, events)['errors'])

    def test_observations_and_diagnostics_do_not_create_native_work(self):
        manifest = run_fixture()
        events = record_events(manifest)
        events += [event(manifest, 'user_observe', 250, 'read', frame=0),
                   event(manifest, 'view_build_begin', 260, 'send', frame=0),
                   event(manifest, 'view_build_end', 270, 'send', frame=0)]
        for name in ('ERROR', 'cancel', 'stale'):
            events.append(event(manifest, name, 600, 'diagnostic-only', frame=0, status=-1))
        events.append(event(manifest, 'native_complete', 900, 'ghost', frame=0,
                            accepted=False, status='stale'))
        report = target('analyze').summarize_events(manifest, events)
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['records'][0]['latency_ns'], 400)
        self.assertIn('diagnostics', report)
        self.assertEqual(len(report['diagnostics']), 4)

    def test_stage_local_frame_generation_may_advance_between_stages(self):
        manifest = run_fixture()
        events = record_events(manifest)
        for row in events:
            if row['event'].startswith('native_'):
                row.update(frame_generation=11 if row['stage'] == 'read' else 22,
                           ticket=101 if row['stage'] == 'read' else 202,
                           cookie=333 if row['stage'] == 'read' else 444)
        report = target('analyze').summarize_events(manifest, events)
        self.assertEqual(report['errors'], [])
        events[2]['frame_generation'] = 12
        report = target('analyze').summarize_events(manifest, events)
        self.assertTrue(report['errors'])
        self.assertIsNone(report['records'][0]['latency_ns'])

    def test_submit_completion_cookie_mismatch_cannot_publish_success(self):
        for field in ('ticket', 'cookie'):
            with self.subTest(field=field):
                manifest = run_fixture()
                events = record_events(manifest)
                events[1][field], events[2][field] = 1, 2
                self.assertTrue(target('analyze').summarize_events(manifest, events)['errors'])


class PayloadCoverage(unittest.TestCase):
    def check(self, manifest, proof):
        return target('contract')._check_backing(manifest, proof)

    def test_full_payload_segmented_iov_ranges_remain_legal(self):
        manifest = run_fixture()
        views = [dict(kind=kind, backing_id='pages', offset_bytes=offset, length_bytes=length,
                      dma_address=address)
                 for kind, offset, length, address in
                 (('nvme', 2048, 2048, 0x1000), ('nvme', 0, 2048, 0x2000),
                  ('afxdp', 0, 1000, 0x9000), ('afxdp', 1000, 3096, 0xa000))]
        self.assertEqual(self.check(manifest, backing(manifest, views)), [])

    def test_partial_disjoint_or_shifted_payload_views_are_rejected(self):
        manifest = run_fixture()
        for spans in (((0, 1), (4095, 1)), ((0, 4095), (1, 4095)),
                      ((0, 4096), (0, 4095))):
            with self.subTest(spans=spans):
                views = [dict(kind=kind, backing_id='pages', offset_bytes=span[0], length_bytes=span[1])
                         for kind, span in zip(('nvme', 'afxdp'), spans)]
                self.assertTrue(self.check(manifest, backing(manifest, views)))

    def test_multiple_frames_require_and_cover_explicit_record_payload_ranges(self):
        manifest = run_fixture()
        manifest['records'][0]['frame_ids'] = [0, 1]
        proof = backing(manifest)
        proof['frames'] = []
        for frame in (0, 1):
            proof['frames'].append(dict(session_id=7, record_id=0, generation=1, frame_id=frame,
                backing_id='page-%d' % frame, valid_bytes=2304,
                record_offset_bytes=frame * 2048, payload_offset_bytes=256, payload_bytes=2048,
                native_views=[dict(kind=kind, backing_id='page-%d' % frame,
                                   offset_bytes=256, length_bytes=2048) for kind in ('nvme', 'afxdp')]))
        self.assertEqual(self.check(manifest, proof), [])
        proof['frames'][1]['record_offset_bytes'] = 0
        self.assertTrue(self.check(manifest, proof))


class RecipePairing(unittest.TestCase):
    def pair(self):
        left, right = run_fixture(), run_fixture('K-BPF')
        recipe = dict(chain='nvme-nic', rig='/synthetic/rig.json', seed=1,
                      records=1, warmup_records=4, pairs=1, arms=['U-poll', 'K-BPF'])
        left['recipe'], right['recipe'] = copy.deepcopy(recipe), copy.deepcopy(recipe)
        return left, right

    def test_all_visible_recipe_work_changes_are_rejected(self):
        for field, value in dict(chain='nic-nvme', rig='/synthetic/other.json', seed=2,
                                 records=32, warmup_records=0, pairs=5,
                                 processing={'crc': 'different'}).items():
            with self.subTest(field=field):
                left, right = self.pair()
                right['recipe'][field] = value
                report = target('analyze').compare_runs(left, right)
                self.assertFalse(report['eligible'])
                self.assertIn('recipe.' + field, ' '.join(report['errors']))

    def test_default_warmup_and_intentional_arm_wait_difference_remain_legal(self):
        left, right = self.pair()
        del right['recipe']['warmup_records']
        left['recipe']['arms'] = ['U-poll']
        right['recipe']['arms'] = ['K-BPF']
        left['recipe']['wait_strategy'], right['recipe']['wait_strategy'] = 'poll', 'bpf'
        self.assertTrue(target('analyze').compare_runs(left, right)['eligible'])


if __name__ == '__main__':
    unittest.main()
