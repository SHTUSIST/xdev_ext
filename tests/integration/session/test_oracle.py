#!/usr/bin/env python3
"""Host tests of eval_session_oracle: regular files stand in for the guest's
NVMe block devices and for the CE stand-in's window (it is read with pread at
the window offset, as /dev/xdev_ext_ce_sim is).  No device, root or VM.

Expected bytes and hashes come from the guest validator
(kernel/tools/testing/selftests/xdev_ext_integration/
xdev_ext_eval_session_validate.py), a separate Python implementation.
Run: python3 tests/eval/session_guest/test_oracle.py -v
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import random
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
import zlib

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
VALIDATOR = REPO / 'kernel/tools/testing/selftests/xdev_ext_integration/xdev_ext_eval_session_validate.py'
CC = shlex.split(os.environ.get('CC', 'cc'))


def _load():
    spec = importlib.util.spec_from_file_location('eval_session_validate', VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ev = _load()
BUILD = tempfile.TemporaryDirectory(prefix='.oracle-build-', dir=HERE)
ORACLE = Path(BUILD.name) / 'eval_session_oracle'


def setUpModule():
    built = subprocess.run(['make', '-s', '-C', str(HERE), 'oracle', 'BUILD=' + BUILD.name,
                            'CC=' + ' '.join(CC)], capture_output=True, text=True)
    if built.returncode:
        raise AssertionError(built.stdout + built.stderr)


def tearDownModule():
    BUILD.cleanup()


def oracle(*args, code=0):
    p = subprocess.run([str(ORACLE), *map(str, args)], capture_output=True, text=True, timeout=60)
    if p.returncode != code:
        raise AssertionError('exit %d (want %d): %s%s' % (p.returncode, code, p.stdout, p.stderr))
    return p


def receipt(p, data):
    """The oracle's one result line names exactly @data."""
    m = re.fullmatch(r'bytes=(\d+) sha256=([0-9a-f]{64})\n', p.stdout)
    if not m:
        raise AssertionError('result line: %r' % p.stdout)
    return int(m.group(1)) == len(data) and m.group(2) == hashlib.sha256(data).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='.oracle-', dir=HERE)
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def image(self, name, size, fill=b'\0'):
        path = self.dir / name
        path.write_bytes(fill * size)
        return path


class Sha256(Base):
    def test_known_answers(self):
        rng = random.Random(7)
        for size in (0, 1, 55, 56, 63, 64, 65, 4096, 1 << 20):
            data = rng.randbytes(size)
            path = self.dir / ('d%d' % size)
            path.write_bytes(data)
            with self.subTest(size=size):
                self.assertTrue(receipt(oracle('sha256', path), data))


class Snapshot(Base):
    def test_snapshot_restore_round_trip(self):
        dev = self.image('dev.raw', 1 << 21)
        original = random.Random(1).randbytes(1 << 21)
        dev.write_bytes(original)
        snap = self.dir / 'span.snap'
        oracle('snapshot', '--dev', dev, '--offset', 1 << 20, '--length', 1 << 19, '--out', snap)
        self.assertEqual(snap.read_bytes(), original[1 << 20:(1 << 20) + (1 << 19)])
        oracle('fill', '--dev', dev, '--offset', 1 << 20, '--length', 1 << 19, '--byte', 0x5a)
        self.assertEqual(dev.read_bytes()[1 << 20:(1 << 20) + 8], b'\x5a' * 8)
        p = oracle('restore', '--dev', dev, '--offset', 1 << 20, '--snapshot', snap)
        self.assertTrue(receipt(p, snap.read_bytes()))
        self.assertEqual(dev.read_bytes(), original)

    def test_unaligned_or_existing_output_refused(self):
        dev = self.image('dev.raw', 1 << 20)
        oracle('snapshot', '--dev', dev, '--offset', 100, '--length', 4096,
               '--out', self.dir / 'x', code=2)
        existing = self.dir / 'exists'
        existing.write_bytes(b'keep')
        oracle('snapshot', '--dev', dev, '--offset', 0, '--length', 4096, '--out', existing, code=2)
        self.assertEqual(existing.read_bytes(), b'keep')


class Guards(Base):
    def test_compare_permits_only_the_declared_span(self):
        dev = self.image('guards.raw', 32768, b'\xa5')
        snap = self.dir / 'guards.snap'
        oracle('snapshot', '--dev', dev, '--offset', 4096, '--length', 16384, '--out', snap)
        args = ('compare', '--dev', dev, '--offset', 4096, '--snapshot', snap,
                '--skip-offset', 4096, '--skip-length', 8192)
        data = bytearray(dev.read_bytes())
        data[8192:16384] = b'x' * 8192
        dev.write_bytes(data)
        oracle(*args)
        for where in (4096, 8191, 16384, 20479):
            with self.subTest(where=where):
                bad = data.copy()
                bad[where] ^= 1
                dev.write_bytes(bad)
                oracle(*args, code=1)
        dev.write_bytes(data)
        oracle('compare', '--dev', dev, '--offset', 4096, '--snapshot', snap,
               '--skip-offset', 16384, '--skip-length', 4096, code=2)


class Chains(Base):
    def test_source_window_and_reference(self):
        dev = self.image('src.raw', 1 << 20)
        oracle('chain-source', '--dev', dev, '--offset', 65536, '--group', 4096, '--groups', 5,
               '--seed', 31)
        want = b''.join(ev.chain_group(31, g, 4096, False) for g in range(5))
        self.assertEqual(dev.read_bytes()[65536:65536 + len(want)], want)
        ref = self.dir / 'ref.bin'
        oracle('chain-ref', '--out', ref, '--group', 4096, '--groups', 5, '--seed', 31)
        self.assertEqual(ref.read_bytes(), want)
        oracle('chain-ref', '--out', ref, '--group', 4096, '--groups', 5, '--seed', 31, code=2)

    def test_compressed_source_inflates_to_the_text_groups(self):
        dev = self.image('src.raw', 1 << 20)
        oracle('chain-source', '--dev', dev, '--offset', 0, '--group', 65536, '--groups', 5,
               '--seed', 43, '--compress')
        raw = dev.read_bytes()
        for g in range(5):
            record = raw[g * 65536:(g + 1) * 65536]
            d = zlib.decompressobj(-11)
            self.assertEqual(d.decompress(record), ev.chain_group(43, g, 65536, True))
            self.assertTrue(d.eof)
            self.assertEqual(d.unused_data.strip(b'\0'), b'')

    def test_destination_window(self):
        dev = self.image('dst.raw', 1 << 20)
        want = b''.join(ev.chain_group(35, g, 32768, False) for g in range(10))
        data = bytearray(dev.read_bytes())
        data[4096:4096 + len(want)] = want
        dev.write_bytes(data)
        p = oracle('chain-file', '--dev', dev, '--offset', 4096, '--group', 32768, '--groups', 10,
                   '--seed', 35)
        self.assertTrue(receipt(p, want))
        data[4096 + 9 * 32768 + 17] ^= 1
        dev.write_bytes(data)
        oracle('chain-file', '--dev', dev, '--offset', 4096, '--group', 32768, '--groups', 10,
               '--seed', 35, code=1)

    def ce_window(self, slots):
        path = self.dir / 'ce.bin'
        data = bytearray(b'\xa6' * (8 << 20))
        for i, content in enumerate(slots):
            if content is not None:
                data[(1 << 20) + i * 4096:(1 << 20) + (i + 1) * 4096] = content
        path.write_bytes(data)
        return path

    def test_ce_window_newest_group_and_no_duplicates(self):
        text = [ev.chain_group(41, g, 4096, True) for g in range(5)]
        args = ('chain-ce', '--ce', None, '--va', 1 << 20, '--group', 4096, '--slots', 4,
                '--groups', 5, '--seed', 41)
        for slots, code in (([text[4], None, text[1], None], 0),   # LIFO reuse: newest kept
                            ([text[4], text[3], text[2], text[1]], 0),
                            ([text[3], None, None, None], 1),       # newest group missing
                            ([text[4], text[4], None, None], 1),    # one group in two slots
                            ([text[4], text[2][:-1] + b'x', None, None], 1)):
            with self.subTest(slots=[s[:1] if s else None for s in slots], code=code):
                call = list(args)
                call[2] = self.ce_window(slots)
                p = oracle(*call, code=code)
                if not code:
                    self.assertTrue(receipt(p, text[4]))


class SlotRing(Base):
    def window(self, blocks, size, seed, va=0, total=4 << 20):
        path = self.dir / 'ce.bin'
        data = bytearray(total)
        payload = ev.xg_payload(seed, size * 64)
        for s, b in enumerate(blocks):
            data[va + s * size:va + (s + 1) * size] = payload[b * size:(b + 1) * size] if b >= 0 else \
                ev.xg_payload(~seed & 0xffffffff, (s + 1) * size)[s * size:]
        path.write_bytes(data)
        return path

    def test_load_slots_are_a_permutation_of_the_window(self):
        canonical = ev.xg_payload(11, 4 * 8192)
        for blocks, code in (([2, 0, 3, 1], 0), ([0, 1, 2, 3], 0), ([0, 1, 1, 3], 1),
                             ([0, 1, 2, -1], 1), ([0, 1, 2, 4], 1)):
            with self.subTest(blocks=blocks):
                ce = self.window(blocks, 8192, 11, va=2 << 20)
                p = oracle('xg-slots', '--ce', ce, '--va', 2 << 20, '--size', 8192, '--slots', 4,
                           '--seed', 11, code=code)
                if not code:
                    self.assertTrue(receipt(p, canonical))

    def test_torn_slot_fails(self):
        ce = self.window([0, 1, 2, 3], 8192, 11)
        data = bytearray(ce.read_bytes())
        data[3 * 8192 + 4000] ^= 0xff
        ce.write_bytes(data)
        oracle('xg-slots', '--ce', ce, '--va', 0, '--size', 8192, '--slots', 4, '--seed', 11, code=1)

    def test_save_file_groups_are_slot_images(self):
        size, seed = 65536, 14
        payload = ev.xg_payload(seed, 4 * size)
        for order, code in (([3, 1, 0, 2], 0), ([0, 0, 1, 2], 1)):
            with self.subTest(order=order):
                dev = self.image('dst.raw', 2 << 20)
                data = bytearray(dev.read_bytes())
                for k, b in enumerate(order):
                    data[(1 << 20) + k * size:(1 << 20) + (k + 1) * size] = payload[b * size:(b + 1) * size]
                dev.write_bytes(data)
                p = oracle('xg-file', '--dev', dev, '--offset', 1 << 20, '--size', size, '--groups', 4,
                           '--slots', 4, '--seed', seed, code=code)
                if not code:
                    self.assertTrue(receipt(p, payload))


class AgreesWithValidator(unittest.TestCase):
    def test_every_case_kind_is_covered(self):
        kinds = {c[0] if c[0] != 'chains' else c[1] for c in ev.CASES}
        self.assertEqual(kinds, {'nvme_gpu', 'gpu_nic', 'pair', 'iaa'})


if __name__ == '__main__':
    unittest.main()
