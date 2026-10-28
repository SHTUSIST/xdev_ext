#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production custody/notification functions and the IOU pool queue."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def function(text, name, optional=False):
    match = re.search(r'^\w[^;{}]*\b' + name + r'\([^;{}]*\)\n\{\n.*?^\}',
                      text, re.M | re.S)
    if not match:
        if optional:
            return ''
        raise RuntimeError('missing production function: ' + name)
    return match[0]


class RecycleTail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys
        sys.path.insert(0,str(HERE / 'core_lifecycle'))
        from ordered_frames_test import build
        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-recycle-tail-')
        cls.addClassCleanup(cls.temp.cleanup)
        # Share only extraction/OS adaptation, retaining this fixture's
        # original scenarios and every behavior assertion.
        def original_scenarios(fixture, core):
            return fixture.replace(' return ordered_scenario(argv[1]);\n', '')
        cls.binary = build(cls.temp.name,original_scenarios)

    def probe(self, mode):
        run = subprocess.run([str(self.binary), mode], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_start_installs_custody_and_wake_gate_before_a_following_stop(self):
        self.probe('start_accepted')

    def test_failed_user_handoff_rolls_back_without_installing_start(self):
        self.probe('start_bad_frames')

    def test_start_rejects_stop_during_user_copy_in_recycle_mode(self):
        self.probe('copy_stop_recycle')

    def test_start_rejects_stop_during_user_copy_in_legacy_user_mode(self):
        self.probe('copy_stop_legacy')

    def test_prior_legacy_completion_during_copy_defers_its_notification(self):
        self.probe('completion_copy')

    def test_1gib_legacy_pool_handoff_runs_without_irq_off_loop(self):
        self.probe('large_start')

    def test_stop_during_copy_waits_for_handoff_exit(self):
        self.probe('copy_gate')

    def test_stop_during_copy_failure_wakes_after_handoff_exit(self):
        self.probe('copy_fail_stop')

    def test_stop_during_custody_transfer_returns_loans_after_handoff(self):
        self.probe('loan_stop')

    def test_stop_during_queue_publication_returns_all_loans(self):
        self.probe('queue_stop')

    def test_recycle_stop_during_transfer_does_not_drain_partial_handoff(self):
        self.probe('loan_stop_recycle')

    def test_recycle_stop_during_queue_does_not_return_a_partial_loan_set(self):
        self.probe('queue_stop_recycle')

    def test_stop_during_failed_loan_rolls_back_then_wakes(self):
        self.probe('loan_fail_stop')

    def test_three_groups_over_two_slots_return_every_lent_frame(self):
        self.probe('tail')

    def test_257_groups_over_eight_slots_return_the_entire_tail(self):
        self.probe('long')

    def test_stop_before_kick_returns_queued_frames_before_notification(self):
        self.probe('stop')

    def test_stop_rearms_the_return_gate_after_normal_tail_reclaim(self):
        self.probe('stop_late')

    def test_abort_stops_pending_source_and_returns_safe_loans(self):
        self.probe('abort')

    def test_stop_retains_inflight_and_ambiguous_frames(self):
        self.probe('unsafe')


if __name__ == '__main__':
    unittest.main(verbosity=2)
