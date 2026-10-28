#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent timestamp/identity oracles, R1-R6/R11-R12; fixture only."""
import json
import unittest

from fixtures.builders import HERE, clone, event, record_events, run_fixture, target


class EventAssociation(unittest.TestCase):
    def summarize(self, manifest, events):
        result = target('analyze').summarize_events(manifest, events)
        self.assertFalse(result['performance_eligible'], 'fixture must stay nonperformance')
        return result

    def test_r1_e2e_is_not_intercompletion(self):
        manifest = run_fixture()
        manifest['records'].append(dict(session_id=7, record_id=1, generation=1, frame_ids=[1]))
        manifest['completed_records'] = 2
        events = record_events(manifest)
        events += record_events(manifest, record=1, start=110, complete=210,
                                submit=310, terminal=510, frame=1)
        report = self.summarize(manifest, events)
        self.assertEqual([r['latency_ns'] for r in report['records']], [400, 400])
        self.assertEqual(report['inter_completion_ns'], [10])
        self.assertEqual(report['errors'], [])

    def test_r2_native_gap_includes_user_observation_delay(self):
        gaps = []
        for arm, submit in (('U-poll', 220), ('K-BPF', 140)):
            manifest = run_fixture(arm)
            events = record_events(manifest, start=10, complete=100, submit=submit, terminal=300)
            if arm == 'U-poll':
                events.append(event(manifest, 'user_observe', 180, 'read', frame=0))
            report = self.summarize(manifest, events)
            gaps.append(report['gaps'][0]['duration_ns'])
        self.assertEqual(gaps, [120, 40])

    def test_r2_cqe_observation_boundary_cannot_match_native_boundary(self):
        left, right = run_fixture(), run_fixture('K-BPF')
        left['complete_boundary'] = 'user_cqe_observe'
        result = target('analyze').compare_runs(left, right)
        self.assertFalse(result['eligible'])
        self.assertIn('complete_boundary', ' '.join(result['errors']))

    def test_r3_generation_and_session_are_part_of_identity(self):
        manifest = run_fixture()
        manifest['records'] += [dict(session_id=7, record_id=0, generation=2, frame_ids=[0]),
                                dict(session_id=8, record_id=0, generation=1, frame_ids=[0])]
        manifest['completed_records'] = 3
        events = record_events(manifest)
        events += record_events(manifest, generation=2, start=600, complete=700,
                                submit=800, terminal=1000)
        events += record_events(manifest, session=8, start=600, complete=650,
                                submit=680, terminal=900)
        events.append(event(manifest, 'native_complete', 850, 'read', frame=0,
                            generation=1, accepted=False, status='stale'))
        report = self.summarize(manifest, list(reversed(events)))
        observed = {(r['session_id'], r['record_id'], r['generation']): r['latency_ns']
                    for r in report['records']}
        self.assertEqual(observed, {(7, 0, 1): 400, (7, 0, 2): 400, (8, 0, 1): 300})
        self.assertEqual(sorted(g['duration_ns'] for g in report['gaps']), [30, 100, 100])

    def test_r3_foreign_run_does_not_complete_local_record(self):
        manifest = run_fixture()
        events = record_events(manifest)
        events[2]['run_id'] = 'another-run'
        report = self.summarize(manifest, events)
        self.assertIsNone(report['gaps'][0]['duration_ns'])
        self.assertTrue(report['errors'])

    def test_r3_old_generation_completion_cannot_fill_new_missing_probe(self):
        manifest = run_fixture()
        manifest['records'][0]['generation'] = 2
        events = record_events(manifest, generation=2)
        events[2]['generation'] = 1
        report = self.summarize(manifest, events)
        self.assertIsNone(report['gaps'][0]['duration_ns'])
        self.assertTrue(report['errors'])

    def test_r4_reordered_duplicate_rejected_completion_does_not_double_count(self):
        manifest = run_fixture()
        events = record_events(manifest)
        duplicate = clone(events[2])
        duplicate.update(accepted=False, status='duplicate', ts_ns=201)
        events.append(duplicate)
        report = self.summarize(manifest, events[3:] + events[:3])
        self.assertEqual(len(report['records']), 1)
        self.assertEqual(len(report['gaps']), 1)
        self.assertEqual(report['gaps'][0]['duration_ns'], 100)
        self.assertEqual(report['errors'], [])

    def test_r4_rejected_submit_is_not_an_accepted_native_request(self):
        manifest = run_fixture()
        events = record_events(manifest)
        events[3]['accepted'] = False
        report = self.summarize(manifest, events)
        self.assertIsNone(report['gaps'][0]['duration_ns'])

    def test_r4_failed_completion_cannot_publish_successful_record(self):
        manifest = run_fixture()
        events = record_events(manifest)
        events[4]['status'] = -5
        report = self.summarize(manifest, events)
        self.assertIsNone(report['records'][0]['latency_ns'])
        self.assertTrue(report['errors'])

    def test_r5_missing_probe_is_unknown_not_zero(self):
        manifest = run_fixture()
        events = [e for e in record_events(manifest)
                  if not (e['event'] == 'native_complete' and e['stage'] == 'read')]
        report = self.summarize(manifest, events)
        self.assertIsNone(report['gaps'][0]['duration_ns'])
        self.assertIn('native_complete', ' '.join(report['gaps'][0]['reasons']))

    def test_r5_dropped_trace_invalidates_completion_gap(self):
        manifest = run_fixture()
        manifest['trace_dropped'] = 1
        report = self.summarize(manifest, record_events(manifest))
        self.assertTrue(report['errors'])
        self.assertIn('dropped', ' '.join(report['errors']).lower())
        self.assertIsNone(report['gaps'][0]['duration_ns'])

    def test_r6_clock_and_host_must_match_for_each_subtraction(self):
        for field, value in (('clock', 'CLOCK_MONOTONIC_RAW'), ('clock_domain', 'other-host')):
            with self.subTest(field=field):
                manifest = run_fixture()
                events = record_events(manifest)
                events[2][field] = value
                report = self.summarize(manifest, events)
                self.assertIsNone(report['gaps'][0]['duration_ns'])
                self.assertIn('clock', ' '.join(report['gaps'][0]['reasons']).lower())

    def test_r6_terminal_on_remote_clock_has_no_e2e_latency(self):
        manifest = run_fixture()
        events = record_events(manifest)
        events[5]['clock_domain'] = 'remote-host'
        report = self.summarize(manifest, events)
        self.assertIsNone(report['records'][0]['latency_ns'])
        self.assertTrue(report['errors'])

    def test_r11_fanout_recycle_waits_for_both_consumers(self):
        fixture = json.loads((HERE / 'fixtures' / 'fanout.json').read_text())
        manifest = fixture['manifest']
        events = [json.loads(line) for line in
                  (HERE / 'fixtures' / fixture['events_file']).read_text().splitlines()]
        report = self.summarize(manifest, events)
        self.assertEqual(report['errors'], [])
        # The fast frame legitimately retires while another frame is pending.
        self.assertEqual(len(report['records']), 2)
        bad = clone(events)
        for e in bad:
            if e['event'] == 'recycle' and e['frame_id'] == 0:
                e['ts_ns'] = 350  # consumer B does not complete until 499
        report = self.summarize(manifest, bad)
        self.assertIn('recycle', ' '.join(report['errors']).lower())

    def test_r11_record_requires_every_declared_frame(self):
        manifest = run_fixture()
        manifest['frame_bytes'] = 2048
        manifest['records'][0]['frame_ids'] = [0, 1]
        events = record_events(manifest, frame=0)
        report = self.summarize(manifest, events)
        self.assertIsNone(report['records'][0]['latency_ns'])
        self.assertTrue(report['errors'])
        # Add the other frame without duplicating record-level endpoints.
        events += [e for e in record_events(manifest, frame=1, complete=250, submit=350)
                   if e['frame_id'] != -1]
        report = self.summarize(manifest, events)
        self.assertEqual(report['records'][0]['latency_ns'], 400)
        self.assertEqual(len(report['gaps']), 2)
        self.assertEqual(report['errors'], [])

    def test_stage_dependencies_are_declared_not_guessed_from_time(self):
        manifest = run_fixture()
        manifest['stages'] = []
        report = self.summarize(manifest, record_events(manifest))
        self.assertTrue(report['errors'])
        self.assertEqual(report['gaps'], [])


class PairAggregation(unittest.TestCase):
    def test_r12_preserves_slower_kernel_negative_throughput_delta(self):
        left, right = run_fixture(), run_fixture('K-BPF')
        right['metrics'] = dict(latency_ns=500, throughput_bytes_per_second=800)
        report = target('analyze').compare_runs(left, right)
        self.assertTrue(report['eligible'])
        self.assertEqual(report['delta']['latency_ns'], 100)
        self.assertEqual(report['delta']['throughput_bytes_per_second'], -200)
        self.assertFalse(report['performance_eligible'])

    def test_r12_run_is_statistical_unit_missing_arm_excluded(self):
        a, b = run_fixture(pair='p1'), run_fixture('K-BPF', pair='p1')
        c, d = run_fixture(pair='p2'), run_fixture('K-BPF', pair='p2')
        b['metrics']['latency_ns'] = 300  # -100; 2 records
        d['metrics']['latency_ns'] = 700  # +300; 200 records
        a['completed_records'] = b['completed_records'] = 2
        c['completed_records'] = d['completed_records'] = 200
        report = target('analyze').compare_pairs([(a, b), (c, d), (run_fixture(pair='p3'), None)])
        self.assertEqual(len(report['pairs']), 2)
        self.assertEqual(len(report['excluded']), 1)
        self.assertEqual(report['mean_delta']['latency_ns'], 100)
        self.assertFalse(report['performance_eligible'])

    def test_r12_unknown_metrics_never_become_zero(self):
        left, right = run_fixture(), run_fixture('K-BPF')
        right['metrics']['latency_ns'] = None
        report = target('analyze').compare_runs(left, right)
        self.assertIsNone(report['delta']['latency_ns'])

    def test_r12_pair_id_mismatch_rejected(self):
        report = target('analyze').compare_runs(run_fixture(pair='a'), run_fixture('K-BPF', pair='b'))
        self.assertFalse(report['eligible'])
        self.assertIn('pair_id', ' '.join(report['errors']))


if __name__ == '__main__':
    unittest.main()
