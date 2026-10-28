#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""START keys first_seq .. first_seq + nr_batches - 1 must not wrap.

The worker gives batch k the key first_seq + k and an ordered stage (AF_XDP
TX of NXP generations) holds a key back only behind smaller keys
(xdev_ext_mech_order_holds_ex).  A wrapped key 0 would overtake U64_MAX.
Compiles io_uring/xdev_ext_mech_step.h unchanged.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

PROBE = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
static int failures;
#define EXPECT(c,msg) do { if (!(c)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } } while (0)
static struct xdev_ext_mech_start start(__u64 nr, __u64 first) {
	struct xdev_ext_mech_start st;
	memset(&st, 0, sizeof(st));
	st.nr_batches = nr;
	st.first_seq = first;
	return st;
}
int main(void) {
	const __u32 umem = XDEV_EXT_MECH_POOL_IOU_UMEM;
	struct xdev_ext_mech_bstate earlier = { .state = XDEV_EXT_MECH_B_READY, .stage = 0 };
	struct xdev_ext_mech_start st;

	/* Why a wrap matters: the later key 0 is not held behind U64_MAX. */
	EXPECT(!xdev_ext_mech_order_holds_ex(0, 0, UINT64_MAX, &earlier, false),
	       "order rule changed; wrapped keys would now be held");
	EXPECT(xdev_ext_mech_order_holds_ex(UINT64_MAX - 1, 0, UINT64_MAX - 2, &earlier, false),
	       "a smaller earlier key must hold a later one");

	st = start(2, UINT64_MAX);
	EXPECT(xdev_ext_mech_start_check(&st, umem, false, 1, 64) == -EINVAL,
	       "START with keys U64_MAX, 0 was admitted");
	st = start(1, UINT64_MAX);
	EXPECT(xdev_ext_mech_start_check(&st, umem, false, 1, 64) == -EINVAL,
	       "START whose sequence counter would wrap after its key was admitted");
	st = start(UINT64_MAX, 1);
	EXPECT(xdev_ext_mech_start_check(&st, umem, false, 1, 64) == -EINVAL,
	       "START of U64_MAX batches from key 1 was admitted");
	st = start(2, UINT64_MAX - 2);
	EXPECT(xdev_ext_mech_start_check(&st, umem, false, 1, 64) == 0,
	       "the highest non-wrapping key range was refused");
	st = start(4, 0);
	EXPECT(xdev_ext_mech_start_check(&st, umem, false, 1, 64) == 0,
	       "an ordinary START from key 0 was refused");
	if (!failures)
		puts("PASS start keys never wrap");
	return failures != 0;
}
'''


class StartKeys(unittest.TestCase):
    def test_start_rejects_key_ranges_that_wrap(self):
        with tempfile.TemporaryDirectory(prefix='xdev_ext-start-keys-') as tmp:
            source = Path(tmp) / 'keys.c'
            source.write_text(PROBE)
            binary = Path(tmp) / 'keys'
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                    '-I' + str(ROOT), str(source), '-o', str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
