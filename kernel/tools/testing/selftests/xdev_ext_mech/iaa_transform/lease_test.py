#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run independent schedules through unchanged production transform functions."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from acquire_red_test import function

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
FUNCTIONS = (
    'xdev_ext_mech_frames_move', 'xdev_ext_mech_frames_release',
    'xdev_ext_mech_transform_alias_free',
    'xdev_ext_mech_transform_reserve', 'xdev_ext_mech_transform_unreserve',
    'xdev_ext_mech_transform_alias', 'xdev_ext_mech_batch_transform_begin',
    'xdev_ext_mech_batch_completion_claim', 'xdev_ext_mech_sync_for_cpu',
    'xdev_ext_mech_trim_produced', 'xdev_ext_mech_batch_handoff',
    'xdev_ext_mech_batch_completion_publish',
    'xdev_ext_mech_batch_transform_complete', 'xdev_ext_mech_batch_transform_produced',
    'xdev_ext_mech_transform_landed', 'xdev_ext_mech_transform_undo', 'xdev_ext_mech_submit',
)


class TransformLease(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        production = Path(os.environ.get('XDEV_EXT_IAA_LEASE_SOURCE', ROOT / 'io_uring/xdev_ext_mech.c')).read_text()
        fixture = (HERE / 'lease_fixture.c').read_text()
        for name in FUNCTIONS:
            fixture = fixture.replace('/* ' + name + ' */', function(production, name))
        cls.temp = tempfile.TemporaryDirectory(prefix='xdev_ext-iaa-lease-')
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        (path / 'probe.c').write_text(fixture)
        cls.binary = path / 'probe'
        result = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra',
                                 '-Werror', '-Wno-unused-function', '-fsanitize=undefined',
                                 '-fno-sanitize-recover=undefined', '-I' + str(ROOT),
                                 str(path / 'probe.c'), '-o', str(cls.binary)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    def probe(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_preaccept_backpressure_rolls_back_destination_and_permits_retry(self):
        self.probe('preaccept')

    def test_sync_completion_wins_over_a_refused_submit_return(self):
        self.probe('sync_refuse')

    def test_short_output_publishes_actual_length_and_replaces_source_set(self):
        self.probe('short')

    def test_output_ends_in_second_frame_and_unused_frames_stay_private(self):
        self.probe('partial_tail')

    def test_zero_output_is_a_definitive_failure_without_publication(self):
        self.probe('zero')

    def test_output_over_capacity_is_a_definitive_failure_without_publication(self):
        self.probe('overcap')

    def test_duplicate_completion_cannot_overwrite_winning_produced(self):
        self.probe('duplicate')

    def test_stale_ticket_cannot_change_current_output_metadata(self):
        self.probe('stale')

    def test_second_source_return_failure_keeps_safe_return_and_retains_remaining_lease(self):
        self.probe('second_source_return_failure')

    def test_source_return_failure_quarantines_both_sets(self):
        self.probe('release_failure')

    def test_destination_generation_mismatch_quarantines_both_sets(self):
        self.probe('destination_generation')

    def test_unknown_retains_both_sets_without_publication_or_release(self):
        self.probe('unknown')

    def test_pending_request_prevents_unreserve_and_reuse(self):
        self.probe('pending')

    def test_physically_aliased_destination_is_rejected(self):
        self.probe('alias')

    def test_duplicate_destination_is_rejected(self):
        self.probe('duplicate_dst')

    def test_wrong_stage_destination_is_rejected(self):
        self.probe('wrong_stage')

    def test_second_destination_failure_rolls_back_first(self):
        self.probe('busy_dst')

    def test_resolve_failure_rolls_back_acquired_destination(self):
        self.probe('resolve_fail')

    def test_reservation_failure_rolls_back_only_its_own_frames(self):
        self.probe('reserve_fail')

    def test_physically_aliased_destinations_in_different_depth_slots_are_rejected(self):
        self.probe('cross_batch_alias')

    def test_source_ready_without_read_lease_cannot_be_submitted(self):
        self.probe('source_ready')

    def test_native_error_invalidates_destination_without_advancing_batch(self):
        self.probe('native_error')

    def test_stage_reservations_are_exclusive(self):
        self.probe('reserve_exclusive')

    def test_depth_eight_leases_are_independent_before_first_completion(self):
        self.probe('depth')

    def test_invalid_source_span_cannot_bypass_begin_validation(self):
        self.probe('short_source')


if __name__ == '__main__':
    unittest.main(verbosity=2)
