#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real epoch STOP_REPORT consumer; controlled external I/O, no device execution."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


class StopReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='tb-stop-report-test-')
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / 'epoch-stop-report'
        # RED can use the actual new public header in its isolated kernel tree.
        # The integrated test defaults to its own tree's public UAPI.
        uapi = Path(os.environ.get('TB_STOP_REPORT_UAPI', str(ROOT / 'kernel/include/uapi')))
        argv = ['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                '-fsanitize=undefined', '-fno-sanitize-recover=all', '-pthread',
                '-iquote' + str(uapi), '-I' + str(HERE),
                str(HERE / 'epoch_stop_report_test.c'),
                str(HERE / 'epoch_control.c'), str(HERE / 'check_contract.c'),
                '-o', str(cls.binary)]
        built = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        if built.returncode:
            raise AssertionError('actual public-header/epoch compile: ' + built.stdout + built.stderr)

    def check_case(self, name):
        run = subprocess.run([str(self.binary), name], capture_output=True,
                             text=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('PASS ' + name, run.stdout)

    def test_real_completed_report_preserves_observations(self): self.check_case('completed')
    def test_no_start_bringup_gets_real_zero_completion_report(self): self.check_case('bringup')
    def test_repeated_stop_replays_cached_typed_evidence_without_new_io(self): self.check_case('idempotent')
    def test_eagain_resets_entire_public_request_before_retry(self): self.check_case('eagain-reset')
    def test_eintr_poll_keeps_report_retry_and_absolute_deadline(self): self.check_case('poll-eintr')
    def test_unsupported_report_has_no_legacy_fallback(self): self.check_case('unsupported')
    def test_old_kernel_einval_has_no_legacy_fallback(self): self.check_case('invalid-opcode')
    def test_quarantine_error_preserved_and_held(self): self.check_case('quarantine')
    def test_copy_fault_never_credits_returned_bytes_as_safe(self): self.check_case('copy-fault')
    def test_unbind_release_error_preserved_and_held(self): self.check_case('release-error')
    def test_first_error_and_stop_error_remain_distinct(self): self.check_case('prior-error')
    def test_held_during_report_return_cannot_restore_safe_authority(self): self.check_case('cancel-late-success')
    def test_eagain_deadline_never_resets_or_credits_partial_output(self): self.check_case('absolute-deadline')
    def test_wrong_outer_size_is_held(self): self.check_case('malformed-1')
    def test_wrong_outer_version_is_held(self): self.check_case('malformed-2')
    def test_wrong_outer_session_is_held(self): self.check_case('malformed-3')
    def test_wrong_stats_session_is_held(self): self.check_case('malformed-4')
    def test_wrong_transport_size_is_held(self): self.check_case('malformed-5')
    def test_wrong_transport_version_is_held(self): self.check_case('malformed-6')
    def test_wrong_transport_session_is_held(self): self.check_case('malformed-7')
    def test_nonzero_transport_reserved_is_held(self): self.check_case('malformed-8')
    def test_nonzero_transport_v2_reserved_is_held(self): self.check_case('malformed-9')


if __name__ == '__main__': unittest.main(verbosity=2)
