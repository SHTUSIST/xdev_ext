#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Real validator regressions for omitted/fabricated IAA software evidence."""
import unittest
from xdev_ext_mech_zc_validate import validate_console
from xdev_ext_mech_zc_validate_test import console_fixture, iaa_console_fixture


class IAAEvidence(unittest.TestCase):
    def check(self, text):
        return validate_console(text, groups=8, ce_sim=True, ce_delay_us=100000)

    def console(self):
        text = console_fixture()
        return '\n'.join(line for line in text.splitlines()
                         if not line.startswith(('PASS IAA ', 'XDEV_EXT_IAA_SOFTWARE='))) + '\n'

    def test_missing_entire_iaa_campaign_cannot_pass(self):
        with self.assertRaises(ValueError):
            self.check(self.console())

    def test_summary_without_actual_cases_cannot_pass(self):
        with self.assertRaises(ValueError):
            self.check(self.console() + iaa_console_fixture().splitlines()[-1] + '\n')

    def test_complete_software_campaign_is_accepted(self):
        self.assertEqual(self.check(self.console() + iaa_console_fixture())['receiver_batches_done'], 8)

    def test_each_case_is_mandatory_and_unique(self):
        for case in ('normal', 'delay', 'stale', 'duplicate', 'stop'):
            marker = 'PASS IAA case=' + case + ' '
            line = next(line for line in iaa_console_fixture().splitlines() if line.startswith(marker))
            for mutate in (lambda text: text.replace(line + '\n', ''), lambda text: text + line + '\n'):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    self.check(self.console() + mutate(iaa_console_fixture()))

    def test_every_payload_guard_length_scope_and_count_is_enforced(self):
        for old, new in (('all_pool_guards=1', 'all_pool_guards=0'),
                         ('full_source=1', 'full_source=0'),
                         ('all_window_guards=1', 'all_window_guards=0'),
                         ('actual_lengths=257', 'actual_lengths=256'),
                         ('mutation_rejects=4', 'mutation_rejects=0'),
                         ('restored_bytes=1052672', 'restored_bytes=4096'),
                         ('stage_counts=257,257,257,257', 'stage_counts=257,257,256,257'),
                         ('native_completed=514', 'native_completed=513'),
                         ('pending=0', 'pending=1'),
                         ('owners_released=1', 'owners_released=0'),
                         ('compressed_min=25', 'compressed_min=4096'),
                         ('compressed_max=4101', 'compressed_max=4096'),
                         ('software=deflate-generic', 'software=memcpy'),
                         ('dma_cpu_simulation=1', 'dma_cpu_simulation=0'),
                         ('stopped_stage=DMA', 'stopped_stage=IAA'),
                         ('native_completed=8', 'native_completed=7')):
            with self.subTest(field=old), self.assertRaises(ValueError):
                self.check(self.console() + iaa_console_fixture().replace(old, new, 1))

    def test_missing_any_required_field_is_rejected(self):
        line = iaa_console_fixture().splitlines()[0]
        for field in line.split()[3:]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(self.console() + iaa_console_fixture().replace(line, ' '.join(token for token in line.split() if token != field), 1))


if __name__ == '__main__':
    unittest.main(verbosity=2)
