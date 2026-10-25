#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Synthetic verdict rejection controls, never guest-execution evidence."""
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fanout_validate import check_counts, check_images, validate, HERE
from fanout_trace_test import encode, fixture


def counts(groups=3, depth=2):
    return dict(pass_=True, session=17, groups=groups, frames_per_group=6,
                window_groups=min(groups, depth), window_frames=6 * min(groups, depth),
                submitted=[groups] * 3 + [0], completed=[groups] * 3 + [0],
                recycled=groups * 6, published=0, inflight=0, sequestered=0,
                batches_done=groups, batches_abort=0, rejects=0, protocol_err=0,
                timeouts=0, last_err=0, state=1)


def log(record=None):
    record = copy.deepcopy(record or counts())
    record['pass'] = record.pop('pass_')
    return ('XDEV_EXT_MECH_FANOUT_COUNTS=' + json.dumps(record) + '\n'
            'XDEV_EXT_MECH_READY mode=source session=17 frames=6 seg_len=1432 xsk=zc\n'
            'XDEV_EXT_MECH_NIC_ACCOUNTING session=17 path=zc nic_copy_ops=0 '
            'nic_copy_bytes=0 nic_zc_ops=18 nic_zc_bytes=24576\n'
            'XDEV_EXT_MECH_FANOUT=PASS\nXDEV_EXT_MECH_LIFECYCLE_GUEST=PASS\n'
            'XDEV_EXT_ZC_GUEST_EXIT=0\n')


class VerdictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.tmp.name)
        (cls.directory / 'evidence').mkdir()
        kernel = HERE.parents[4]
        harness = kernel / 'tools/testing/selftests/xdev_ext_integration/xdev_ext_mech_zc_kvm.sh'
        image = re.search(r'python3 - "\$SCRATCH" "\$GROUP_COUNT"[^\n]* <<\'PY\'\n(.*?)\nPY\n',
                          harness.read_text(), re.S).group(1)
        subprocess.run([sys.executable, '-', str(cls.directory), '3', '0', 'none',
                        str(kernel), '', '1'], input=image, text=True, check=True)
        cls.expected = (cls.directory / 'expected.raw').read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        (self.directory / 'destination.raw').write_bytes(self.expected)
        (self.directory / 'source.raw').write_bytes((self.directory / 'source-before.raw').read_bytes())

    def test_accepts_exact_counts(self):
        self.assertEqual(check_counts(log(), 3, 2)['completed'], [3, 3, 3, 0])

    def test_rejects_incomplete_or_error_counts(self):
        for key in ('recycled', 'published', 'inflight', 'sequestered', 'batches_done',
                    'batches_abort', 'rejects', 'protocol_err', 'timeouts', 'last_err',
                    'window_frames', 'frames_per_group'):
            item = counts()
            item[key] += 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_counts(log(item), 3, 2)
        for stage in range(3):
            item = counts()
            item['completed'][stage] -= 1
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                check_counts(log(item), 3, 2)

    def test_rejects_missing_duplicate_or_fallback_evidence(self):
        for text in ('', log() + log().splitlines()[0] + '\n',
                     log().replace('xsk=zc', 'xsk=copy'),
                     log().replace('nic_copy_ops=0', 'nic_copy_ops=1'),
                     log().replace('nic_zc_bytes=24576', 'nic_zc_bytes=24575')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                check_counts(text, 3, 2)

    def test_checks_both_sinks_and_guards(self):
        result = check_images(self.directory, 3)
        self.assertEqual(len(result['sinks']), 2)
        self.assertEqual(result['sinks'][0]['sha256'], result['sinks'][1]['sha256'])
        for offset in (0, 4096 * 512, 4096 * 512 + 3 * 8192, len(self.expected) - 1):
            bad = bytearray(self.expected)
            bad[offset] ^= 1
            (self.directory / 'destination.raw').write_bytes(bad)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                check_images(self.directory, 3)

    def test_rejects_source_corruption(self):
        source = bytearray((self.directory / 'source.raw').read_bytes())
        source[2048 * 512] ^= 1
        (self.directory / 'source.raw').write_bytes(source)
        with self.assertRaisesRegex(ValueError, 'source image changed'):
            check_images(self.directory, 3)

    def test_guest_markers_and_exit_are_required(self):
        with patch('fanout_validate.validate_trace', return_value={'scope': 'synthetic-test'}):
            self.assertEqual(validate(self.directory, log(), 3, 2, 0)['status'], 'PASS')
            for text, exit_code in ((log(), 124), (log().replace('GUEST_EXIT=0', 'GUEST_EXIT=1'), 0),
                                    (log() + 'WARNING: bad lifetime\n', 0),
                                    (log().replace('FANOUT=PASS', 'FANOUT=FAIL'), 0)):
                self.assertEqual(validate(self.directory, text, 3, 2, exit_code)['status'], 'FAIL')

    def test_counters_and_images_cannot_replace_native_trace(self):
        self.assertEqual(validate(self.directory, log(), 3, 2, 0)['status'], 'FAIL')

    def test_integrated_synthetic_trace_counts_and_images(self):
        result = validate(self.directory, log() + encode(fixture(groups=3)), 3, 2, 0)
        self.assertEqual(result['status'], 'PASS', result['errors'])
        self.assertEqual(result['trace']['afxdp_native_completed'], 18)
        self.assertFalse(result['physical_dma_verified'])


if __name__ == '__main__':
    unittest.main()
