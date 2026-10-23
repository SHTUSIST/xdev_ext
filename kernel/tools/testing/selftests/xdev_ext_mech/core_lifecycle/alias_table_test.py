#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The CREATE alias table of io_uring/xdev_ext_mech_core.h against brute force.

Random page-segment tables are sorted by xdev_ext_mech_alias_sort(); overlap
detection and xdev_ext_mech_alias_hits() must agree with an all-pairs
comparison for every probe interval.  The header is compiled unchanged.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

PROBE = r'''
#include <stdio.h>
#include <stdlib.h>
#include "io_uring/xdev_ext_mech_core.h"
static unsigned long long seed = 0x9e3779b97f4a7c15ULL;
static unsigned rnd(unsigned n) { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return (unsigned)(seed % n); }
static char pages[16];
static int overlap(const struct xdev_ext_mech_alias_seg *a, const void *p, __u32 off, __u32 len) {
	return a->page == p && a->off < (unsigned long long)off + len && off < (unsigned long long)a->off + a->len;
}
int main(void) {
	struct xdev_ext_mech_alias_seg t[64], u[64];
	unsigned round, failures = 0;
	for (round = 0; round < 20000; round++) {
		size_t n = rnd(64), i, j;
		int brute = 0;
		for (i = 0; i < n; i++) {
			t[i].page = &pages[rnd(round & 1 ? 4 : 16)];
			t[i].off = rnd(4096);
			t[i].len = 1 + rnd(round & 2 ? 64 : 1024);
			u[i] = t[i];
		}
		for (i = 0; i < n; i++)
			for (j = i + 1; j < n; j++)
				brute |= overlap(&u[i], u[j].page, u[j].off, u[j].len);
		xdev_ext_mech_alias_sort(t, n);
		for (i = 1; i < n; i++)
			if (xdev_ext_mech_alias_before(&t[i], &t[i - 1]))
				failures++;
		if (xdev_ext_mech_alias_overlapping(t, n) != !!brute)
			failures++;
		if (brute)
			continue;
		for (i = 0; i < 64; i++) {
			const void *p = &pages[rnd(16)];
			__u32 off = rnd(4200), len = 1 + rnd(512);
			int expect = 0;
			for (j = 0; j < n; j++)
				expect |= overlap(&u[j], p, off, len);
			if (xdev_ext_mech_alias_hits(t, n, p, off, len) != !!expect)
				failures++;
		}
	}
	if (failures) {
		fprintf(stderr, "FAIL %u alias table disagreements\n", failures);
		return 1;
	}
	puts("PASS alias table agrees with brute force");
	return 0;
}
'''


class AliasTable(unittest.TestCase):
    def test_sorted_table_matches_all_pairs_comparison(self):
        with tempfile.TemporaryDirectory(prefix='xdev_ext-alias-table-') as tmp:
            source = Path(tmp) / 'table.c'
            source.write_text(PROBE)
            binary = Path(tmp) / 'table'
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O2', '-Wall', '-Wextra',
                                    '-Werror', '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                    '-I' + str(ROOT), str(source), '-o', str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
