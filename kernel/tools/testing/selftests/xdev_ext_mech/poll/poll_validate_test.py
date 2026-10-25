#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The stage-polling KVM verdict rejects missing evidence and wrong data."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import poll_validate as v  # noqa: E402

GOOD_LOG = '\n'.join(
    ['XDEV_EXT_POLL_IO_POLL controller=nvme%d io_poll=1' % i for i in range(3)] +
    ['ok 1 - something'] + list(v.MARKERS) +
    ['XDEV_EXT_POLL_DMESG_RESET=PASS no_completion_polled_timeout=1 no_deferred_drain=1 '
     'upstream_group_cpus_warnings=1 other_warnings=0'] +
    ['PASS poll case=%s groups=1' % c for c in v.DMA_CASES]) + '\n'


class Validate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='xdev-ext-poll-validate-')
        self.dir = Path(self.temp.name)
        v.make_images(self.dir)
        source = (self.dir / 'source.raw').read_bytes()
        destination = v.expected_destination(source)
        start, nlb = v.STOP_WINDOW
        destination[start * v.LBA:(start + nlb) * v.LBA] = b'\x01' * (nlb * v.LBA)
        self.destination = destination
        (self.dir / 'destination.raw').write_bytes(destination)

    def tearDown(self):
        self.temp.cleanup()

    def verdict(self, log):
        (self.dir / 'guest.log').write_text(log)
        run = subprocess.run([sys.executable, str(HERE / 'poll_validate.py'), 'validate', '--dir', str(self.dir),
                              '--log', str(self.dir / 'guest.log'), '--result', str(self.dir / 'r.json')],
                             capture_output=True, text=True)
        return run.returncode, run.stdout

    def test_complete_evidence_passes(self):
        self.assertEqual(self.verdict(GOOD_LOG), (0, 'XDEV_EXT_POLL_VALIDATE=PASS\n'))

    def test_every_marker_is_required(self):
        for marker in v.MARKERS:
            with self.subTest(marker=marker):
                code, out = self.verdict(GOOD_LOG.replace(marker + '\n', ''))
                self.assertEqual(code, 1, out)

    def test_reset_log_check_is_required(self):
        code, out = self.verdict('\n'.join(l for l in GOOD_LOG.splitlines()
                                           if not l.startswith('XDEV_EXT_POLL_DMESG_RESET')) + '\n')
        self.assertEqual(code, 1, out)

    def test_failed_guest_check_fails(self):
        self.assertEqual(self.verdict(GOOD_LOG + 'not ok 9 - polled copy\n')[0], 1)
        self.assertEqual(self.verdict(GOOD_LOG.replace('io_poll=1', 'io_poll=0', 1))[0], 1)

    def test_wrong_copy_byte_fails(self):
        dst, _, size = v.COPIES[0]
        broken = bytearray(self.destination)
        broken[dst * v.LBA + size - 1] ^= 0xff
        (self.dir / 'destination.raw').write_bytes(broken)
        self.assertEqual(self.verdict(GOOD_LOG)[0], 1)

    def test_guard_overwrite_fails(self):
        broken = bytearray(self.destination)
        broken[-1] = 0
        (self.dir / 'destination.raw').write_bytes(broken)
        self.assertEqual(self.verdict(GOOD_LOG)[0], 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
