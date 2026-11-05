#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Mutate a correct peer batch run one fact at a time; the oracle must reject each.

Boots nothing. The correct run is synthesized from the oracle's own plan.
"""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate as v  # noqa: E402

BOUNDARY = 5 * v.MIB


def correct_log(issued=4, extra=()):
    lines = ['TAP version 13', 'OBSERVE case=queue max_hw_sectors_kb=1024',
             'OBSERVE case=pool dma_runs=9 boundary=%d' % BOUNDARY]
    obs = {'A1': 'setups=1 lens=2047 slba=4096', 'A2': 'setups=3 max_outstanding=3 completion_inversions=1',
           'B': 'setups=40 max_outstanding=17 completion_inversions=9',
           'C2': 'setups=32 max_outstanding=12 completion_inversions=4',
           'E1': 'ret=16769 completed=2 status=16769 setups=%d d2_setups=1 completes=%d' % (issued, issued)}
    refusal = dict(v.REFUSALS)
    n = 0
    for case, write, descs in v.plans(BOUNDARY):
        lines.append(v.plan_line(case, write, descs))
        if case in refusal:
            lines.append('OBSERVE case=%s ret=%d completed=0 status=%d setups=0,0,0' %
                         (case, -refusal[case], -refusal[case]))
        if case in obs:
            lines.append('OBSERVE case=%s %s' % (case, obs[case]))
        n += 1
        lines.append('ok %d - %s' % (n, case))
    lines += ['OBSERVE case=E3 vmpin_before_close=7454720 vmpin_after_close=7454720',
              'OBSERVE case=E3 attached=0000:00:04.0', '1..%d' % n, v.FINAL, *extra,
              'XDEV_EXT_PEER_BATCH_GUEST_EXIT=0', 'XDEV_EXT_PEER_BATCH_DMESG_BEGIN',
              '[    0.000000] Linux version 6.16.0-rc7', 'XDEV_EXT_PEER_BATCH_DMESG_END']
    return '\n'.join(lines) + '\n'


class Oracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix='peer-batch-oracle-'))
        v.make_images(cls.dir)
        cls.source = (cls.dir / 'source.raw').read_bytes()
        cls.error = (cls.dir / 'error.raw').read_bytes()
        cls.log = correct_log()
        seen = v.observations([line.strip() for line in cls.log.splitlines()])
        _, dest = v.expected_regions(seen, cls.source, cls.error)
        cls.dest = bytes(dest)
        (cls.dir / 'destination.raw').write_bytes(cls.dest)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def run_with(self, dest=None, log=None):
        (self.dir / 'destination.raw').write_bytes(self.dest if dest is None else dest)
        try:
            return v.validate(self.dir, self.log if log is None else log)
        finally:
            (self.dir / 'destination.raw').write_bytes(self.dest)

    def rejects(self, dest=None, log=None):
        with self.assertRaises(ValueError):
            self.run_with(dest, log)

    def test_correct_run_passes(self):
        summary = self.run_with()
        self.assertEqual(summary['e1']['issued'], 4)
        self.assertEqual(summary['boundary'], BOUNDARY)

    def flip(self, offset):
        data = bytearray(self.dest)
        data[offset] ^= 0x01
        return bytes(data)

    def test_every_region_byte_flip_rejected(self):
        for name, offset in (('C1 write', 4096), ('C2 write', 2 * v.MIB + 100), ('guard after writes', 15 * v.MIB),
                             ('A dump start', v.DUMP_A), ('A dump discontiguous request', v.DUMP_A + BOUNDARY),
                             ('A dump tail', v.DUMP_A + 4 * v.MIB + 1024), ('guard between dumps', 23 * v.MIB),
                             ('B dump', v.DUMP_B + 3 * v.MIB + 7), ('B dump end', v.DUMP_B + v.P_BYTES - 1),
                             ('Q completed prefix', v.DUMP_Q + 10), ('Q later issued', v.DUMP_Q + 3 * 128 * v.KIB),
                             ('Q not issued', v.DUMP_Q + 5 * 128 * v.KIB), ('Q between requests', v.DUMP_Q + 70000),
                             ('last guard byte', v.DST_BYTES - 1)):
            with self.subTest(name=name):
                self.rejects(dest=self.flip(offset))

    def test_failed_command_bytes_are_unspecified(self):
        self.run_with(dest=self.flip(v.DUMP_Q + 2 * 128 * v.KIB + 5))

    def test_issued_count_must_match_the_landed_requests(self):
        self.rejects(log=correct_log(issued=5))
        self.rejects(log=correct_log(issued=2))
        self.rejects(log=correct_log(issued=7))

    def test_source_and_error_images_must_be_unchanged(self):
        for name in ('source.raw', 'error.raw'):
            path = self.dir / name
            original = path.read_bytes()
            data = bytearray(original)
            data[777] ^= 1
            path.write_bytes(bytes(data))
            try:
                self.rejects()
            finally:
                path.write_bytes(original)

    def test_log_mutations_rejected(self):
        replace = [
            ('ok 3 - ', 'not ok 3 - '), ('ok 3 - A3', 'ok 3 - A3 # SKIP'), ('1..', '1..9'),
            (v.FINAL, v.FINAL + ' extra'), ('XDEV_EXT_PEER_BATCH_GUEST_EXIT=0', 'XDEV_EXT_PEER_BATCH_GUEST_EXIT=1'),
            ('max_hw_sectors_kb=1024', 'max_hw_sectors_kb=512'), ('dma_runs=9', 'dma_runs=1'),
            ('boundary=%d' % BOUNDARY, 'boundary=%d' % (BOUNDARY + 512)),
            ('boundary=%d' % BOUNDARY, 'boundary=%d' % (4 * v.MIB)),
            ('setups=1 lens=2047', 'setups=2 lens=2047'), ('lens=2047', 'lens=1023'),
            ('setups=3 max_outstanding=3', 'setups=3 max_outstanding=1'),
            ('setups=40 max_outstanding=17', 'setups=41 max_outstanding=17'),
            ('setups=40 max_outstanding=17', 'setups=40 max_outstanding=1'),
            ('setups=32 max', 'setups=31 max'),
            ('case=D2-overlap-last ret=-22 completed=0 status=-22 setups=0,0,0',
             'case=D2-overlap-last ret=-22 completed=0 status=-22 setups=1,0,0'),
            ('case=D4-target-past-pool ret=-34 completed=0', 'case=D4-target-past-pool ret=-34 completed=4'),
            ('case=D6-offset-wrap ret=-75', 'case=D6-offset-wrap ret=-34'),
            ('ret=16769 completed=2', 'ret=16769 completed=3'), ('ret=16769 completed=2', 'ret=-5 completed=2'),
            ('d2_setups=1', 'd2_setups=2'), ('vmpin_after_close=7454720', 'vmpin_after_close=6406144'),
            ('attached=0000:00:04.0', 'attached='),
            ('[    0.000000] Linux version 6.16.0-rc7', 'BUG: KASAN: use-after-free in nvme_pci_peer_batch'),
            ('[    0.000000] Linux version 6.16.0-rc7', 'WARNING: CPU: 1 PID: 1 at drivers/nvme/host/pci.c'),
        ]
        for old, new in replace:
            with self.subTest(old=old, new=new):
                self.assertIn(old, self.log)
                self.rejects(log=self.log.replace(old, new, 1))
        plan = next(line for line in self.log.splitlines() if line.startswith('PLAN case=B '))
        self.rejects(log=self.log.replace(plan, plan.replace(':', ';', 3), 1))
        self.rejects(log=self.log.replace(plan + '\n', '', 1))
        self.rejects(log=self.log + 'OBSERVE case=A1 setups=1\n')


if __name__ == '__main__':
    unittest.main()
