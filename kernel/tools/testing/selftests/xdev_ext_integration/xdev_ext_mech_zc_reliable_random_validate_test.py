#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests of the reliable-random campaign validator (E17), fixture consoles only."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('random_validate', HERE / 'xdev_ext_mech_zc_reliable_random_validate.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)

PARAMS = dict(loss=0.02, reorder=0.01, seed=5, slow_receiver_us=0)


def wire(**over):
    stats = dict(mode='reliable-random', errors=[], loss=0.02, reorder=0.01, seed=5,
                 slow_receiver_us=0, matched=91, dropped=5, dropped_data=4, dropped_control=1,
                 reordered=2, delayed=0, forwarded_data=74, forwarded_control=12, duplicated=0)
    stats.update(over)
    return stats


def console(*, retransmits=3, rx_dup=12, tx_held=1, tx_unacked=0, outcome='success',
            rx_vector='0,10,0,0', done=10, tx_last='0'):
    w = wire()
    lines = [
        'XDEV_EXT_ZC_RX_STATS session=17 state=ACTIVE batches_done=%d held=%d recycled=86 '
        'sequestered=0 protocol_err=0 submitted=%s completed=%d,%s' %
        (done, done * 6, rx_vector, done, rx_vector.split(',', 1)[1]),
        'XDEV_EXT_ZC_RX_TRANSPORT_COUNTERS session=17 retransmits=0 dup_suppressed=%d held_acks=0 '
        'held_unacked=0' % rx_dup,
        'XDEV_EXT_ZC_TX_STATS session=18 state=ACTIVE batches_done=%d batches_abort=%d last_err=%s '
        'submitted=10,10,0,0 completed=10,10,0,0' % (done, 0 if outcome == 'success' else 1, tx_last),
        'XDEV_EXT_ZC_TX_TRANSPORT_COUNTERS session=18 retransmits=%d dup_suppressed=0 held_acks=%d '
        'held_unacked=%d' % (retransmits, tx_held, tx_unacked),
        'XDEV_EXT_ZC_TX_RESULT outcome=%s exit=%d elapsed_ms=10 timeout_ms=100' %
        (outcome, 0 if outcome == 'success' else 1),
        'XDEV_EXT_ZC_RX_RESULT outcome=%s exit=%d elapsed_ms=10 timeout_ms=100' %
        ('success' if outcome == 'success' else 'incomplete-remote-unknown', 0 if outcome == 'success' else 1),
        'XDEV_EXT_ZC_WIRE_RANDOM mode=reliable-random loss=0.02 reorder=0.01 seed=5 slow_receiver_us=0 '
        'matched=%d dropped_data=%d dropped_control=%d reordered=%d delayed=%d forwarded_data=%d '
        'forwarded_control=%d' % tuple(w[k] for k in ('matched', 'dropped_data', 'dropped_control',
                                                      'reordered', 'delayed', 'forwarded_data',
                                                      'forwarded_control')),
    ]
    return '\n'.join(lines) + '\n'


class RandomCampaignValidator(unittest.TestCase):
    def check(self, text, stats=None, **over):
        params = dict(PARAMS, **over)
        return validator.validate_reliable_random(text, stats or wire(), groups=10, **params)

    def test_consistent_recovery_passes(self):
        result = self.check(console())
        self.assertEqual(result['retransmits'], 3)
        self.assertTrue(result['success'])

    def test_retransmit_counter_must_match_cable(self):
        for count in (2, 4):
            with self.subTest(retransmits=count), self.assertRaises(ValueError):
                self.check(console(retransmits=count))

    def test_suppression_bounded_by_delivered_duplicates(self):
        with self.assertRaises(ValueError):
            self.check(console(rx_dup=15))

    def test_success_cannot_retain_unacked_frames(self):
        with self.assertRaises(ValueError):
            self.check(console(tx_unacked=6))

    def test_receiver_exactly_once(self):
        with self.assertRaises(ValueError):
            self.check(console(rx_vector='0,11,0,0'))

    def test_held_needs_a_carried_control(self):
        with self.assertRaises(ValueError):
            self.check(console(tx_held=13))

    def test_unknown_counters_are_not_evidence(self):
        text = console().replace('held_acks=1 held_unacked=0', 'held_acks=18446744073709551615 held_unacked=0')
        with self.assertRaises(ValueError):
            self.check(text)

    def test_cable_parameters_and_accounting(self):
        for stats in (wire(seed=6), wire(errors=['x']), wire(duplicated=1), wire(dropped=6),
                      wire(matched=95), wire(delayed=3)):
            with self.subTest(stats=stats), self.assertRaises(ValueError):
                self.check(console(), stats)
        with self.assertRaises(ValueError):
            self.check(console(), wire(), loss=0.0)

    def test_slow_receiver_delays_every_forwarded_data_frame(self):
        stats = wire(slow_receiver_us=500, delayed=74)
        text = console().replace('slow_receiver_us=0', 'slow_receiver_us=500').replace('delayed=0', 'delayed=74')
        self.check(text, stats, slow_receiver_us=500)
        bad = copy.deepcopy(stats)
        bad['delayed'] = 73
        with self.assertRaises(ValueError):
            self.check(text.replace('delayed=74', 'delayed=73'), bad, slow_receiver_us=500)

    def test_exhausted_budget_is_unknown_only_with_loss(self):
        text = console(outcome='unknown', tx_last='-EREMOTEIO', tx_unacked=6)
        result = self.check(text)
        self.assertFalse(result['success'])
        with self.assertRaises(ValueError):
            self.check(console(outcome='unknown', tx_last='0'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
