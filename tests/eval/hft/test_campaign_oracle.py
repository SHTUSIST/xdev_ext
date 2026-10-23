#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Strict campaign byte-oracle contract. No device/provider/performance work."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import hardware_measure as hardware
import oracle as legacy_oracle
from strict_fixture import campaign, changed, clone, expected_header, expected_payload

HERE = Path(__file__).resolve().parent


class CampaignOracleTests(unittest.TestCase):
    def verifier(self):
        path = HERE / 'campaign_oracle.py'
        self.assertTrue(path.is_file(), 'FEATURE_ABSENT RED: independent campaign_oracle.py does not exist')
        spec = importlib.util.spec_from_file_location('hft_strict_campaign_under_test', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        verify = getattr(module, 'verify_campaign', None)
        self.assertTrue(callable(verify), 'FEATURE_ABSENT RED: verify_campaign API does not exist')
        return verify

    def rejects(self, verify, values):
        with self.assertRaises(ValueError):
            verify(*values)

    def test_fixture_is_independent_complete_three_arm_campaign(self):
        manifest, captures, guards, source = campaign()
        self.assertEqual(len(captures), 12)
        self.assertEqual(len(guards), 12)
        self.assertEqual(len(source), 2048)
        self.assertEqual(captures[0]['datagram'][:40].hex(),
            '48465431012802001020304050607080000000010000000100000200000000000000020000000000')
        for trial in manifest['trials']:
            p = trial['profile']
            for row in [r for r in captures if r['trial_id'] == trial['trial_id']]:
                generation = int.from_bytes(row['datagram'][16:20], 'big')
                self.assertEqual(row['datagram'], expected_header(p['session_base'], generation, 512)
                                 + source[(generation - 1) * 512:generation * 512])
        self.assertEqual(guards[0]['slot_addr'], guards[2]['slot_addr'])
        self.assertEqual(source[:512], expected_payload(manifest['trials'][0]['profile'], 0))

    def test_complete_unordered_campaign_and_both_payload_profiles(self):
        verify = self.verifier()
        for size in (512, 1024):
            manifest, captures, guards, source = campaign(size)
            self.assertEqual(verify(manifest, captures[::-1], guards[::-1], source),
                dict(status='ok', validated_trials=3, validated_packets=12,
                     validated_bytes=12 * size, validated_guards=12))

    def test_every_application_header_byte_is_compared(self):
        verify = self.verifier()
        original = campaign()
        verify(*original)
        for index in range(40):
            values = clone(original)
            values[1][0]['datagram'] = changed(values[1][0]['datagram'], index)
            with self.subTest(header_byte=index):
                self.rejects(verify, values)

    def test_every_payload_byte_and_last_trial_tail_are_compared(self):
        verify = self.verifier()
        original = campaign()
        verify(*original)
        for index in range(40, 552):
            values = clone(original)
            values[1][0]['datagram'] = changed(values[1][0]['datagram'], index)
            with self.subTest(payload_byte=index - 40):
                self.rejects(verify, values)
        values = clone(original)
        values[1][-1]['datagram'] = changed(values[1][-1]['datagram'], -1)
        self.rejects(verify, values)

    def test_missing_duplicate_extra_foreign_stale_and_truncation(self):
        verify = self.verifier()
        original = campaign()
        verify(*original)
        mutations = []
        v = clone(original); v[1].pop(); mutations.append(v)
        v = clone(original); v[1][1] = clone(v[1][0]); mutations.append(v)
        v = clone(original); v[1].append(clone(v[1][0])); mutations.append(v)
        v = clone(original); v[1][0]['trial_id'] = 'foreign'; mutations.append(v)
        v = clone(original); v[1][0]['datagram'] = changed(v[1][0]['datagram'], 15); mutations.append(v)
        v = clone(original); v[1][0]['datagram'] = v[1][0]['datagram'][:16] + bytes(4) + v[1][0]['datagram'][20:]; mutations.append(v)
        v = clone(original); v[1][0]['truncated'] = True; mutations.append(v)
        v = clone(original); v[1][0]['datagram'] = v[1][0]['datagram'][:-1]; mutations.append(v)
        v = clone(original); v[1][0]['datagram'] += b'\0'; mutations.append(v)
        for index, values in enumerate(mutations):
            with self.subTest(mutant=index):
                self.rejects(verify, values)

    def test_warmup_and_earlier_trial_cannot_be_discarded(self):
        verify = self.verifier()
        original = campaign()
        verify(*original)
        for index in (0, 3, 4, 7, 8, 11):
            values = clone(original)
            values[1][index]['datagram'] = changed(values[1][index]['datagram'], -1)
            with self.subTest(capture=index):
                self.rejects(verify, values)

    def test_earlier_guard_corruption_survives_later_clean_address_reuse(self):
        verify = self.verifier()
        original = campaign()
        verify(*original)
        for field in ('raw_prefix', 'raw_tail'):
            for index in (0, -1):
                values = clone(original)
                values[2][0][field] = changed(values[2][0][field], index)
                self.assertEqual(values[2][0]['slot_addr'], values[2][2]['slot_addr'])
                self.assertEqual(values[2][2][field], original[2][2][field])
                with self.subTest(guard=field, byte=index):
                    self.rejects(verify, values)

    def test_each_guard_byte_in_full_tail_is_compared(self):
        verify = self.verifier()
        original = campaign()
        verify(*original)
        # Include the end of a 4096-byte frame, not only the former 32-byte tail.
        for field in ('raw_prefix', 'raw_tail'):
            for index in range(len(original[2][0][field])):
                values = clone(original)
                values[2][0][field] = changed(values[2][0][field], index)
                with self.subTest(guard=field, byte=index):
                    self.rejects(verify, values)

    def test_history_missing_overwrite_identity_late_notif_and_stop_failure(self):
        verify = self.verifier()
        original = campaign()
        verify(*original)
        mutants = []
        v = clone(original); v[2].pop(0); mutants.append(v)
        v = clone(original); v[2][0] = clone(v[2][2]); mutants.append(v)
        v = clone(original); v[2].append(clone(v[2][0])); mutants.append(v)
        for field, wrong in [('slot_addr', 0x9000), ('frame_pos', 1), ('terminal_phase', 'pending'),
                ('committed', False), ('before_reuse', False), ('notification_complete', False),
                ('raw_prefix', b'\xa5' * 429), ('raw_tail', b'\x5a' * 32)]:
            v = clone(original); v[2][0][field] = wrong; mutants.append(v)
        v = clone(original); v[0]['trials'][-1]['stop_ret'] = -1; mutants.append(v)
        for index, values in enumerate(mutants):
            with self.subTest(mutant=index):
                self.rejects(verify, values)

    def test_complete_source_reference_is_used_without_crc_sha_or_legacy_validator(self):
        verify = self.verifier()
        values = campaign()
        with patch.object(legacy_oracle, 'crc32c', side_effect=AssertionError('legacy CRC forbidden')), \
             patch.object(legacy_oracle, 'Validator', side_effect=AssertionError('legacy validator forbidden')), \
             patch('hashlib.sha256', side_effect=AssertionError('per-transfer SHA forbidden')):
            verify(*values)
        for index in (0, 511, 512, len(values[3]) - 1):
            mutant = list(clone(values)); mutant[3] = changed(mutant[3], index)
            self.rejects(verify, mutant)

    def test_campaign_identity_source_window_and_trial_set_must_be_complete(self):
        verify = self.verifier()
        original = campaign()
        verify(*original)
        mutants = []
        v = list(clone(original)); v[3] = v[3][:-1]; mutants.append(v)
        v = list(clone(original)); v[3] += b'\0'; mutants.append(v)
        v = clone(original); v[0]['trials'].pop(); mutants.append(v)
        v = clone(original); v[0]['trials'][1]['trial_id'] = v[0]['trials'][0]['trial_id']; mutants.append(v)
        v = clone(original); v[0]['trials'][1]['profile']['session_base'] = v[0]['trials'][0]['profile']['session_base']; mutants.append(v)
        v = clone(original); v[0]['trials'][0]['frame_slots'] = [0x1000, 0x1000]; mutants.append(v)
        v = clone(original); v[0]['measurement_policy'] = 'NXP2'; mutants.append(v)
        for index, values in enumerate(mutants):
            with self.subTest(mutant=index):
                self.rejects(verify, values)

    def test_no_oracle_or_success_publication_before_entire_campaign_drained(self):
        finalize = getattr(hardware, 'finalize_campaign', None)
        self.assertTrue(callable(finalize), 'FEATURE_ABSENT RED: campaign finalization gate absent')
        verify = self.verifier()
        events = []
        def observe(event, metadata):
            events.append(event)
        values = campaign()
        oracle_calls = []
        def trace(frame, event, argument):
            if event == 'call' and frame.f_code.co_name == 'verify_campaign' and \
                    Path(frame.f_code.co_filename).resolve() == (HERE / 'campaign_oracle.py').resolve():
                oracle_calls.append('verify_campaign')
        for field in ('workload_complete', 'local_release_complete'):
            bad = list(clone(values)); bad[0][field] = False
            previous = sys.getprofile()
            try:
                sys.setprofile(trace)
                with self.subTest(field=field), self.assertRaises(ValueError):
                    finalize(*bad, observer=observe)
            finally:
                sys.setprofile(previous)
            self.assertEqual(events, [], 'oracle must not start while any sample is active')
            self.assertEqual(oracle_calls, [])
        previous = sys.getprofile()
        try:
            sys.setprofile(trace)
            result = finalize(*values, observer=observe)
        finally:
            sys.setprofile(previous)
        self.assertEqual(oracle_calls, ['verify_campaign'], 'actual oracle must run exactly once')
        self.assertEqual(result, verify(*values))
        self.assertEqual(events, ['oracle_begin', 'oracle_done', 'success_publish'])
        events.clear()
        bad = list(clone(values)); bad[1][-1]['datagram'] = changed(bad[1][-1]['datagram'], -1)
        with self.assertRaises(ValueError):
            finalize(*bad, observer=observe)
        self.assertNotIn('success_publish', events)


if __name__ == '__main__':
    unittest.main()
