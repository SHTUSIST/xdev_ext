#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The host oracle accepts exactly the expected image."""
import runpy
import unittest
from pathlib import Path

V = runpy.run_path(str(Path(__file__).with_name('window_validate.py')))
WIN = V['WIN_BYTES']
GROUP = 4096
SEED = 0x1234abcd


def images():
    source = V['expected_source'](SEED)
    dest = bytearray([V['GUARD']]) * V['SPAN']
    for w in (0, 1, 5, 6, 7):
        dest[w * WIN:(w + 1) * WIN] = source[w * WIN:(w + 1) * WIN]
    return source, dest


class WindowOracle(unittest.TestCase):
    def state(self, source, dest):
        return V['validate'](bytes(source), bytes(dest))['state']

    def test_expected_image_passes(self):
        self.assertEqual(self.state(*images()), 'PASS')

    def test_tenant_bytes_in_victim_window_fail(self):
        source, dest = images()
        dest[1 * WIN:2 * WIN] = source[0:WIN]
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_one_victim_byte_fails(self):
        source, dest = images()
        dest[WIN + 4097] ^= 1
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_reversed_victim_groups_fail(self):
        source, dest = images()
        groups = [bytes(dest[WIN + g * GROUP:WIN + (g + 1) * GROUP]) for g in range(8)]
        dest[WIN:2 * WIN] = b''.join(reversed(groups))
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_spare_window_write_fails(self):
        source, dest = images()
        dest[2 * WIN + 100] = 0
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_missing_tenant_window_fails(self):
        source, dest = images()
        dest[0:WIN] = bytes([V['GUARD']]) * WIN
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_raw_window_from_wrong_source_fails(self):
        source, dest = images()
        dest[5 * WIN:6 * WIN] = source[6 * WIN:7 * WIN]
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_read_only_and_write_only_windows_must_stay_guard(self):
        for w in (3, 4):
            source, dest = images()
            dest[w * WIN:(w + 1) * WIN] = source[w * WIN:(w + 1) * WIN]
            self.assertEqual(self.state(source, dest), 'FAIL')

    def test_missing_victim2_window_fails(self):
        source, dest = images()
        dest[6 * WIN:7 * WIN] = bytes([V['GUARD']]) * WIN
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_tenant2_window_from_victim2_source_fails(self):
        source, dest = images()
        dest[7 * WIN:8 * WIN] = source[6 * WIN:7 * WIN]
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_write_past_tenant2_window_fails(self):
        source, dest = images()
        dest[8 * WIN] = 0
        self.assertEqual(self.state(source, dest), 'FAIL')

    def test_source_off_formula_fails(self):
        source, dest = images()
        source[8 * 513] ^= 0x80
        self.assertEqual(self.state(source, dest), 'FAIL')



def multi_images(kill_exact=(0, 1, 2)):
    """Rounds kill/escape/unknown/timeout x tenants 0..3 at window 4r + i."""
    source = V['expected_source'](SEED)
    dest = bytearray([V['GUARD']]) * V['SPAN']
    for r in range(4):
        for i in range(1, 4):
            w = 4 * r + i
            dest[w * WIN:(w + 1) * WIN] = source[w * WIN:(w + 1) * WIN]
    for g in kill_exact:
        dest[g * GROUP:(g + 1) * GROUP] = source[g * GROUP:(g + 1) * GROUP]
    aux = bytes([V['AUX_FILL']]) * V['SPAN']
    return source, dest, aux


class MultiTenantOracle(unittest.TestCase):
    def state(self, source, dest, aux, kill_min=2):
        return V['validate_multi'](bytes(source), bytes(dest), bytes(aux), kill_min)['state']

    def test_expected_image_passes(self):
        self.assertEqual(self.state(*multi_images()), 'PASS')

    def test_killed_tenant_any_subset_of_exact_groups_passes(self):
        self.assertEqual(self.state(*multi_images(kill_exact=(1, 3, 6, 7))), 'PASS')

    def test_killed_tenant_fewer_groups_than_completed_fails(self):
        self.assertEqual(self.state(*multi_images(kill_exact=(0,))), 'FAIL')

    def test_killed_tenant_group_from_wrong_slot_fails(self):
        source, dest, aux = multi_images()
        dest[3 * GROUP:4 * GROUP] = source[4 * GROUP:5 * GROUP]
        self.assertEqual(self.state(source, dest, aux), 'FAIL')

    def test_killed_tenant_torn_group_fails(self):
        source, dest, aux = multi_images()
        dest[3 * GROUP:3 * GROUP + 512] = source[3 * GROUP:3 * GROUP + 512]
        self.assertEqual(self.state(source, dest, aux), 'FAIL')

    def test_innocent_missing_group_fails(self):
        source, dest, aux = multi_images()
        w = 4 * 2 + 3
        dest[w * WIN + GROUP:w * WIN + 2 * GROUP] = bytes([V['GUARD']]) * GROUP
        self.assertEqual(self.state(source, dest, aux), 'FAIL')

    def test_escape_bytes_in_innocent_window_fail(self):
        source, dest, aux = multi_images()
        w = 4 * 1 + 1
        dest[w * WIN:w * WIN + GROUP] = source[(w - 1) * WIN:(w - 1) * WIN + GROUP]
        self.assertEqual(self.state(source, dest, aux), 'FAIL')

    def test_faulty_window_of_later_rounds_must_stay_guard(self):
        for r in (1, 2, 3):
            source, dest, aux = multi_images()
            w = 4 * r
            dest[w * WIN:w * WIN + GROUP] = source[w * WIN:w * WIN + GROUP]
            self.assertEqual(self.state(source, dest, aux), 'FAIL')

    def test_private_namespace_bytes_in_shared_namespace_fail(self):
        source, dest, aux = multi_images()
        w = 4 * 3 + 2
        dest[w * WIN:w * WIN + GROUP] = aux[w * WIN:w * WIN + GROUP]
        self.assertEqual(self.state(source, dest, aux), 'FAIL')

    def test_private_namespace_changed_fails(self):
        source, dest, aux = multi_images()
        aux = bytearray(aux)
        aux[12 * WIN] = 0
        self.assertEqual(self.state(source, dest, aux), 'FAIL')

    def test_write_past_round_windows_fails(self):
        source, dest, aux = multi_images()
        dest[16 * WIN + 7] = 0
        self.assertEqual(self.state(source, dest, aux), 'FAIL')

    def test_source_off_formula_fails(self):
        source, dest, aux = multi_images()
        source[8 * 513] ^= 0x80
        self.assertEqual(self.state(source, dest, aux), 'FAIL')


if __name__ == '__main__':
    unittest.main()
