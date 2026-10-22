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
        core = Path(os.environ.get('XDEV_EXT_RECYCLE_SOURCE', ROOT / 'io_uring/xdev_ext_mech.c')).read_text()
        umem = (ROOT / 'io_uring/xdev_ext_umem.c').read_text()
        parts = {
            'POOL': '\n'.join(function(umem, n) for n in
                              ('io_xdev_ext_umem_mech_alloc', 'io_xdev_ext_umem_mech_recycle')),
            'NOTIFY': function(core, 'xdev_ext_mech_notify_locked'),
            'COUNT': function(core, 'xdev_ext_mech_count'),
            'MOVE': function(core, 'xdev_ext_mech_frames_move'),
            'RELEASE': function(core, 'xdev_ext_mech_frames_release'),
            'STOP': function(core, 'xdev_ext_mech_session_stop'),
            'SETTLED': function(core, 'xdev_ext_mech_settled'),
            'SETTLE': function(core, 'xdev_ext_mech_settle_locked'),
            'RETURN_IDLE': function(core, 'xdev_ext_mech_return_idle', optional=True),
            'END': function(core, 'xdev_ext_mech_end'),
            'STOP_WORK': function(core, 'xdev_ext_mech_stop_work'),
            'TAKE': function(core, 'xdev_ext_mech_take_user_frames'),
            'START': function(core, 'xdev_ext_mech_start'),
        }
        fixture = (HERE / 'xdev_ext_mech_recycle_tail_fixture.c').read_text()
        for marker, body in parts.items():
            fixture = fixture.replace('/* PRODUCTION_' + marker + ' */', body)
        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-recycle-tail-')
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        source = path / 'tail.c'
        source.write_text(fixture)
        cls.binary = path / 'probe'
        build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11',
                                '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                                '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                '-I' + str(ROOT), str(source), '-o', str(cls.binary)],
                               text=True, capture_output=True)
        if build.returncode:
            raise RuntimeError(build.stdout + build.stderr)

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
