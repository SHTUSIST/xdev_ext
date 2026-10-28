#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Strict benchmark-policy-v1 trial evidence must carry per-arm completion accounting.

Pure controller validation of one producer observation, shaped as the measured
hft_replay JSON. No device, network, timing or performance is exercised.
"""
import copy
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import hardware_measure as hw  # noqa: E402

PROFILE = dict(schema=1, record_bytes=64, payload_bytes=512, burst_packets=2, depth=2,
               bursts=2, actors=1, seed=1, session_base=77)
COUNT = PROFILE['burst_packets'] * PROFILE['bursts']
SESSION_STATS = dict(batches_done=COUNT, read_submitted=COUNT, read_completed=COUNT,
                     send_submitted=COUNT, send_completed=COUNT, state='ACTIVE',
                     batches_abort=0, rejects=0, sequestered=0, timeouts=0,
                     protocol_err=0, last_err=0, inflight=0)


def observation(backend):
    p = PROFILE
    samples = []
    for b in range(p['bursts']):
        t = 100 + 10 * b
        samples.append(dict(burst=b, warmup=b == 0, first_generation=b * p['burst_packets'] + 1,
                            packet_count=p['burst_packets'], read_submissions=p['burst_packets'],
                            send_submissions=p['burst_packets'], started_ns=t, local_release_ns=t + 1,
                            peer_receipt_ns=t + 2, completed_ns=t + 3))
    history = [dict(generation=g, frame_pos=(g - 1) % p['depth'], slot_addr=4096 * (1 + (g - 1) % p['depth']),
                    payload_bytes=p['payload_bytes'], committed=True, terminal_phase='post-send',
                    before_reuse=True, notification_complete=True, raw_prefix='a5' * 430,
                    raw_tail='5a' * (4096 - 512 - p['payload_bytes'])) for g in range(1, COUNT + 1)]
    completion = dict(read_cqes=0, send_result_cqes=0, send_notif_cqes=0, zc_copied_packets=0)
    if backend == 'uring-fixed-zc':
        completion = dict(read_cqes=COUNT, send_result_cqes=COUNT, send_notif_cqes=COUNT, zc_copied_packets=0)
    raw = dict(measurement_policy='benchmark-policy-v1', wire_version=1, read_submissions=COUNT,
               send_submissions=COUNT, registration_calls=0 if backend == 'posix' else 1,
               local_release_complete=True, stop_ret=0, copied_packets=0,
               frame_slots=[4096 * (1 + i) for i in range(p['depth'])], guard_history=history,
               completion=completion,
               native=dict(xdp_zero_copy=backend == 'session', strict_create=backend == 'session',
                           nvme_map_id=7 if backend == 'session' else 0,
                           afxdp_map_id=8 if backend == 'session' else 0),
               measurements=dict(clock='CLOCK_MONOTONIC_RAW', setup_started_ns=1, setup_completed_ns=2,
                                 teardown_started_ns=1000, teardown_completed_ns=1001, samples=samples))
    if backend == 'session':
        raw['session_stats'] = dict(SESSION_STATS)
    return raw


def check(raw, backend):
    trial = dict(trial_id='t-' + backend, backend=backend, profile=dict(PROFILE))
    return hw._strict_trial_observations(copy.deepcopy(raw), trial, dict(PROFILE))


class StrictTrialAccountingTests(unittest.TestCase):
    def test_complete_observation_of_each_arm_is_accepted(self):
        for backend in ('posix', 'uring-fixed-zc', 'session'):
            with self.subTest(backend=backend):
                self.assertEqual(len(check(observation(backend), backend)), COUNT)

    def test_missing_completion_accounting_is_refused(self):
        for backend in ('posix', 'uring-fixed-zc', 'session'):
            raw = observation(backend)
            del raw['completion']
            with self.subTest(backend=backend), self.assertRaises(ValueError):
                check(raw, backend)

    def test_registered_arm_needs_one_read_and_send_result_per_generation(self):
        for key, value in (('read_cqes', COUNT - 1), ('send_result_cqes', COUNT - 1),
                           ('send_notif_cqes', COUNT + 1), ('zc_copied_packets', COUNT + 1),
                           ('read_cqes', True)):
            raw = observation('uring-fixed-zc')
            raw['completion'][key] = value
            if key == 'zc_copied_packets':
                raw['completion']['send_notif_cqes'] = COUNT
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                check(raw, 'uring-fixed-zc')

    def test_copied_usage_is_reported_not_hidden(self):
        raw = observation('uring-fixed-zc')
        raw['completion']['zc_copied_packets'] = 1
        raw['copied_packets'] = 0
        with self.assertRaises(ValueError):
            check(raw, 'uring-fixed-zc')
        raw['copied_packets'] = 1
        self.assertEqual(len(check(raw, 'uring-fixed-zc')), COUNT)

    def test_posix_arm_reports_no_ring_completions(self):
        raw = observation('posix')
        raw['completion']['send_notif_cqes'] = 1
        with self.assertRaises(ValueError):
            check(raw, 'posix')

    def test_native_arm_needs_exact_terminal_stage_statistics(self):
        mutations = [('session_stats', None)] + [(k, None) for k in SESSION_STATS]
        mutations += [('batches_abort', 1), ('rejects', 1), ('inflight', 1), ('read_completed', COUNT - 1),
                      ('send_completed', COUNT - 1), ('batches_done', COUNT - 1), ('state', 'STOPPED'),
                      ('last_err', -5), ('batches_done', float(COUNT))]
        for key, value in mutations:
            raw = observation('session')
            if key == 'session_stats':
                del raw['session_stats']
            elif value is None:
                del raw['session_stats'][key]
            else:
                raw['session_stats'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                check(raw, 'session')

    def test_native_arm_needs_zero_copy_create_and_map_ids(self):
        for key, value in (('xdp_zero_copy', False), ('strict_create', False), ('nvme_map_id', 0), ('afxdp_map_id', 0)):
            raw = observation('session')
            raw['native'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                check(raw, 'session')

    def test_baseline_arms_must_not_carry_native_statistics(self):
        for backend in ('posix', 'uring-fixed-zc'):
            raw = observation(backend)
            raw['session_stats'] = dict(SESSION_STATS)
            with self.subTest(backend=backend), self.assertRaises(ValueError):
                check(raw, backend)


if __name__ == '__main__':
    unittest.main()
