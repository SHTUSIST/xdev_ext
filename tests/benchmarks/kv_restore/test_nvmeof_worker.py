#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""NVMe-oF/TCP baseline worker: reads, offsets, chunking, checks and refusals.

On host 2 the worker reads the KV object's LBA range from the NVMe-oF block
device and copies it to GPU memory with cuMemcpyHtoD. Here a regular file
stands in for the block device and --test-host-destination replaces the GPU
copy with a host copy: this checks the read loop and the protocol only, never
NVMe/TCP, a GPU or any timing.
"""
import ctypes.util
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kl, kp = load('kv_layout'), load('kv_protocol')
CC = shutil.which(os.environ.get('CC', 'cc'))
KIB, MIB = 1 << 10, 1 << 20


def fnv1a(data):
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & ((1 << 64) - 1)
    return h


@unittest.skipUnless(CC, 'no C compiler')
class Worker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='kv-nvmeof-')
        cls.bin = Path(cls.tmp.name) / 'nvmeof_worker'
        subprocess.run([CC, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(HERE / 'nvmeof_worker.c'), '-o', str(cls.bin), '-ldl'], check=True)
        cls.device = Path(cls.tmp.name) / 'device.img'
        cls.slba, cls.seed, cls.bytes = 2048 + 8, 0x77, MIB + 4096
        image = bytearray(4 * MIB)
        start = cls.slba * 512
        image[start:start + cls.bytes] = kl.pattern_bytes(cls.seed, 0, cls.bytes)
        cls.device.write_bytes(image)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def worker(self, *extra):
        return kp.Worker([self.bin, '--device', self.device, '--lba-bytes', 512,
                          '--frame-bytes', 128 * KIB, '--pool-bytes', 2 * MIB,
                          '--test-host-destination', *extra], ready_timeout=30,
                         log=Path(self.tmp.name) / 'worker.log')

    def test_reads_the_object_range_into_the_destination(self):
        for chunk in (64 * KIB, MIB, 3 * MIB):
            with self.subTest(chunk=chunk):
                w = self.worker('--chunk-bytes', chunk)
                self.assertEqual(w.ready['role'], 'nvmeof')
                self.assertTrue(w.ready['test_host_destination'])
                r = w.go(run='n1', ordinal=1, object_slba=self.slba, bytes=self.bytes,
                         dst_frame0=2, seed=self.seed, verify=True, timeout=30)
                self.assertTrue(r['ok'], r)
                self.assertTrue(r['verified'])
                self.assertEqual(r['bytes'], self.bytes)
                self.assertEqual(int(r['digest'], 16),
                                 fnv1a(kl.pattern_bytes(self.seed, 0, self.bytes)))
                self.assertEqual(r['chunks'], -(-self.bytes // chunk))
                self.assertEqual(w.quit(timeout=30)['error'], 0)

    def test_wrong_data_is_not_verified(self):
        w = self.worker()
        r = w.go(run='n2', ordinal=1, object_slba=self.slba + 8, bytes=64 * KIB, dst_frame0=0,
                 seed=self.seed, verify=True, timeout=30)
        self.assertFalse(r['ok'])
        self.assertIs(r['verified'], False)
        self.assertEqual(r['first_bad'], 0)
        w.quit(timeout=30)

    def test_refusals(self):
        w = self.worker()
        r = w.go(run='big', ordinal=1, object_slba=0, bytes=2 * MIB, dst_frame0=1, timeout=30)
        self.assertEqual(r['error'], -28, 'destination beyond the pool')
        r = w.go(run='end', ordinal=2, object_slba=4 * MIB // 512 - 8, bytes=MIB, dst_frame0=0,
                 timeout=30)
        self.assertFalse(r['ok'])
        self.assertEqual(r['error'], -5, 'short read past the device end')
        w.quit(timeout=30)

    def test_direct_io_needs_4k_multiples(self):
        try:
            d = self.worker('--io', 'direct', '--chunk-bytes', 64 * KIB)
        except kp.WorkerError as error:
            if 'Invalid argument' in str(error):
                self.skipTest('this filesystem refuses O_DIRECT (tmpfs)')
            raise
        r = d.go(run='odd', ordinal=1, object_slba=self.slba, bytes=1000, dst_frame0=0, timeout=30)
        self.assertEqual(r['error'], -22, 'O_DIRECT needs 4 KiB multiples')
        r = d.go(run='even', ordinal=2, object_slba=self.slba, bytes=64 * KIB, dst_frame0=0,
                 seed=self.seed, verify=True, timeout=30)
        self.assertTrue(r['ok'] and r['verified'], r)
        d.quit(timeout=30)

    @unittest.skipIf(ctypes.util.find_library('cuda'), 'a CUDA driver is installed here')
    def test_without_cuda_setup_fails_cleanly(self):
        with self.assertRaises(kp.WorkerError):
            kp.Worker([self.bin, '--device', self.device, '--lba-bytes', 512, '--frame-bytes',
                       128 * KIB, '--pool-bytes', 2 * MIB, '--gpu-bdf', '0000:01:00.0'],
                      ready_timeout=30)


if __name__ == '__main__':
    unittest.main()
