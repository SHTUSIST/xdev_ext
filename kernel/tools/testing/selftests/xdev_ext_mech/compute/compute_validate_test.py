#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host tests of compute_validate.py, the verdict of the BPF compute KVM run.

The oracle matches the published CRC-32C check value and the production
CRC32C_SEAL layout (io_uring/xdev_ext_mech_cpu_core.h with the independent C
oracle of xform_oracle.h), and the validator rejects a changed byte, a
touched guard region, a missing case or marker and a wrong RED log.
"""
from pathlib import Path
import shlex
import shutil
import subprocess
import os
import tempfile
import unittest

import compute_validate as cv

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[4]
LAYOUT = 'frame_size=4096 hdr_room=360 seg_len=1432 group_bytes=8192 capacity=3736\n'

SEAL_FIXTURE = r'''
#include <stdio.h>
#include "xform_oracle.h"
#include "io_uring/xdev_ext_mech_cpu_core.h"
static __u32 crc(__u32 c, const void *p, size_t n) { return oracle_crc32c_update(c, p, n); }
int main(void)
{
	struct xdev_ext_mech_cpu_prims prims = { .crc32c = crc };
	__u8 f[1432];
	__u32 i, out = 0;

	for (i = 0; i < sizeof(f); i++)
		f[i] = (__u8)(i * 7 + 3);
	if (xdev_ext_mech_cpu_apply(&prims, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, f, sizeof(f),
				    sizeof(f), &out) || out != sizeof(f))
		return 1;
	for (i = 0; i < sizeof(f); i++)
		printf("%02x", f[i]);
	printf("\n");
	return 0;
}
'''


def good_log():
    lines = ['XDEV_EXT_COMPUTE_CASE=PASS name=' + c for c in cv.CASES]
    # The verifier suites print their log directory after the marker.
    markers = [m + (' logs=/tmp/x' if 'VERIFIER' in m else '') for m in cv.MARKERS]
    return '\n'.join(lines + markers) + '\n'


class Oracle(unittest.TestCase):
    def test_check_value(self):
        self.assertEqual(cv.crc32c(b'123456789'), 0xE3069283)
        self.assertEqual(cv.crc32c(b''), 0)

    def test_frames_restart_per_group(self):
        self.assertEqual([len(f) for f in cv.frames(bytes(8192), 1432)], [1432] * 5 + [1032])

    def test_seal_matches_production_layout(self):
        compiler = shlex.split(os.environ.get('CC', 'cc'))
        self.assertTrue(shutil.which(compiler[0]), 'C compiler unavailable')
        with tempfile.TemporaryDirectory(prefix='xdev-ext-compute-seal-') as tmp:
            src = Path(tmp) / 'seal.c'
            src.write_text(SEAL_FIXTURE)
            exe = Path(tmp) / 'seal'
            build = subprocess.run(compiler + ['-std=gnu11', '-O2', '-Wall', '-Werror',
                                               '-I' + str(KERNEL), '-I' + str(HERE.parent),
                                               str(src), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stderr)
        frame = bytes((i * 7 + 3) & 0xFF for i in range(1432))
        self.assertEqual(cv.seal(frame).hex(), run.stdout.strip())

    def test_xor_seal(self):
        frame = bytes(range(256)) * 4
        out = cv.xor_seal(frame)
        body = bytes(b ^ 0x5A for b in frame[:-4])
        self.assertEqual(out[:-4], body)
        self.assertEqual(int.from_bytes(out[-4:], 'little'), cv.crc32c(body))
        self.assertEqual(len(out), len(frame))


class Validator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='xdev-ext-compute-validate-')
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        cv.make_images(self.dir)
        source = (self.dir / 'source.raw').read_bytes()
        (self.dir / 'destination.raw').write_bytes(bytes(cv.expected_destination(source, 1432)))
        (self.dir / 'layout.txt').write_text(LAYOUT)
        self.log = self.dir / 'guest.log'
        self.log.write_text(good_log())

    def run_validate(self, red=False):
        return cv.validate(self.dir, self.log, self.dir / 'layout.txt', self.dir / 'r.json', red)

    def poke(self, slba, offset=0):
        data = bytearray((self.dir / 'destination.raw').read_bytes())
        data[slba * cv.LBA + offset] ^= 1
        (self.dir / 'destination.raw').write_bytes(bytes(data))

    def test_expected_images_pass(self):
        self.assertEqual(self.run_validate(), 0)

    def test_regions_differ_by_kind(self):
        source = (self.dir / 'source.raw').read_bytes()
        expected = cv.expected_destination(source, 1432)
        span = cv.NLB * cv.LBA
        self.assertNotEqual(expected[1024 * cv.LBA:][:span], expected[2048 * cv.LBA:][:span])
        self.assertEqual(expected[2048 * cv.LBA:][:span], expected[3072 * cv.LBA:][:span])
        self.assertEqual(set(expected[4096 * cv.LBA:][:span]), {cv.GUARD})

    def test_changed_payload_byte_fails(self):
        self.poke(2048, 4000)
        self.assertEqual(self.run_validate(), 1)

    def test_changed_seal_fails(self):
        self.poke(1024, 1428)
        self.assertEqual(self.run_validate(), 1)

    def test_touched_failed_region_fails(self):
        for slba in (4096, 5120, 6144, 7168):
            with self.subTest(slba=slba):
                self.setUp()
                self.poke(slba)
                self.assertEqual(self.run_validate(), 1)

    def test_missing_case_or_marker_fails(self):
        for drop in ('name=bad-set-len', 'XDEV_EXT_MECH_VERIFIER_COMPUTES=PASS',
                     'XDEV_EXT_COMPUTE_GUEST_EXIT=0'):
            with self.subTest(drop=drop):
                self.log.write_text(''.join(l for l in good_log().splitlines(True) if drop not in l))
                self.assertEqual(self.run_validate(), 1)

    def test_marker_needs_its_exact_words(self):
        self.log.write_text(good_log().replace('VERIFIER_COMPUTES=PASS cases=7',
                                               'VERIFIER_COMPUTES=PASS cases=6'))
        self.assertEqual(self.run_validate(), 1)

    def test_failed_case_or_kernel_report_fails(self):
        self.log.write_text(good_log() + 'XDEV_EXT_COMPUTE_CASE=FAIL name=x\n')
        self.assertEqual(self.run_validate(), 1)
        self.log.write_text(good_log() + '[ 1.0] WARNING: CPU: 0 PID: 1 at x\n')
        self.assertEqual(self.run_validate(), 1)

    def test_red(self):
        red = ('XDEV_EXT_COMPUTE_CASE=FAIL name=attach-compute reason=attach-failed\n'
               'libbpf: struct_ops init_kern compute_test_ops: member compute not found in kernel BTF\n')
        self.log.write_text(red)
        self.assertEqual(self.run_validate(red=True), 0)
        kfunc = ('XDEV_EXT_COMPUTE_CASE=FAIL name=attach-compute reason=attach-failed\n'
                 "libbpf: extern (func ksym) 'bpf_xdev_ext_frame_len': not found in kernel or module BTFs\n")
        self.log.write_text(kfunc)
        self.assertEqual(self.run_validate(red=True), 0)
        self.log.write_text('XDEV_EXT_COMPUTE_CASE=FAIL name=attach-compute reason=attach-failed\n'
                            'xdev_ext_mech_ctl: load x: Permission denied\n')
        self.assertEqual(self.run_validate(red=True), 1)
        self.log.write_text(good_log())
        self.assertEqual(self.run_validate(red=True), 1)
        self.log.write_text('XDEV_EXT_COMPUTE_CASE=FAIL name=compute-xor-seal rc=1\n')
        self.assertEqual(self.run_validate(red=True), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
