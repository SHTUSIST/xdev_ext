#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Valid-length rule of a producer completion (socket RX datagram length).

Executes xdev_ext_mech_produced_trim() from io_uring/xdev_ext_mech_produced.h
(track S API.md 2.3): a batch whose frames offer span capacities len[] is
trimmed to the produced byte count in frame order; frames left empty are not
published. Also pins the core's use of the rule and of the exported producer
completion entry points (API.md 2.2) in io_uring/xdev_ext_mech.c.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]

FIXTURE = r'''
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_core.h"
#include "io_uring/xdev_ext_mech_produced.h"
static int failures;
#define EXPECT(c) do { if (!(c)) { printf("not ok - line %d: %s\n", __LINE__, #c); failures++; } } while (0)
static int same(const __u32 *a, const __u32 *b, unsigned n) { return !memcmp(a, b, n * sizeof(*a)); }
int main(void)
{
 __u32 len[XDEV_EXT_MECH_MAX_FRAMES + 1], keep[XDEV_EXT_MECH_MAX_FRAMES + 1];
 unsigned i;

 /* 1500-byte group as 1000 + 500. */
 len[0] = 1000; len[1] = 500;
 EXPECT(xdev_ext_mech_produced_trim(len, 2, 1500) == 2 && len[0] == 1000 && len[1] == 500);
 len[0] = 1000; len[1] = 500;
 EXPECT(xdev_ext_mech_produced_trim(len, 2, 1001) == 2 && len[0] == 1000 && len[1] == 1);
 len[0] = 1000; len[1] = 500;
 EXPECT(xdev_ext_mech_produced_trim(len, 2, 1000) == 1 && len[0] == 1000 && len[1] == 0);
 len[0] = 1000; len[1] = 500;
 EXPECT(xdev_ext_mech_produced_trim(len, 2, 700) == 1 && len[0] == 700 && len[1] == 0);
 len[0] = 1000; len[1] = 500;
 EXPECT(xdev_ext_mech_produced_trim(len, 2, 1) == 1 && len[0] == 1 && len[1] == 0);
 /* Errors leave len[] unchanged. */
 len[0] = 1000; len[1] = 500; memcpy(keep, len, sizeof(len));
 EXPECT(xdev_ext_mech_produced_trim(len, 2, 0) == -EOVERFLOW && same(len, keep, 2));
 EXPECT(xdev_ext_mech_produced_trim(len, 2, 1501) == -EOVERFLOW && same(len, keep, 2));
 EXPECT(xdev_ext_mech_produced_trim(len, 0, 1) == -EINVAL);
 len[1] = 0; memcpy(keep, len, sizeof(len));
 EXPECT(xdev_ext_mech_produced_trim(len, 2, 10) == -EINVAL && same(len, keep, 2));
 for (i = 0; i <= XDEV_EXT_MECH_MAX_FRAMES; i++) len[i] = 4096;
 EXPECT(xdev_ext_mech_produced_trim(len, XDEV_EXT_MECH_MAX_FRAMES + 1, 1) == -EINVAL);
 /* Full 32 frames, sum beyond 32 bits is not wrapped. */
 for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++) len[i] = 0xffffffffU;
 EXPECT(xdev_ext_mech_produced_trim(len, XDEV_EXT_MECH_MAX_FRAMES, 0xffffffffU) == 1 && len[0] == 0xffffffffU && len[1] == 0);
 for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++) len[i] = 2048;
 EXPECT(xdev_ext_mech_produced_trim(len, XDEV_EXT_MECH_MAX_FRAMES, 2048 * 31 + 5) == 32 && len[30] == 2048 && len[31] == 5);
 for (i = 0; i < 4; i++) len[i] = 2048;
 EXPECT(xdev_ext_mech_produced_trim(len, 4, 4097) == 3 && len[2] == 1 && len[3] == 0);
 if (failures) printf("FAIL produced_trim failures=%d\n", failures); else printf("PASS produced_trim\n");
 return failures != 0;
}
'''


class ProducedTrim(unittest.TestCase):
    def test_pure_rule(self):
        header = ROOT / 'io_uring/xdev_ext_mech_produced.h'
        self.assertTrue(header.exists(), 'io_uring/xdev_ext_mech_produced.h (API.md 2.3) is missing')
        with tempfile.TemporaryDirectory(prefix='produced-trim-') as tmp:
            source = Path(tmp) / 'trim.c'
            exe = Path(tmp) / 'trim'
            source.write_text(FIXTURE)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                    '-I' + str(ROOT), str(source), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            print(run.stdout, end='')
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_core_exports_producer_completion(self):
        header = (ROOT / 'include/linux/xdev_ext_mech.h').read_text()
        self.assertTrue(re.search(r'void\s+xdev_ext_mech_batch_complete_produced\s*\(\s*struct xdev_ext_mech_batch \*\s*\w*\s*,\s*u64 \w*\s*,\s*int \w*\s*,\s*u32 \w*\s*\)\s*;', header),
                        'include/linux/xdev_ext_mech.h lacks xdev_ext_mech_batch_complete_produced (API.md 2.2)')
        self.assertTrue(re.search(r'u32\s+xdev_ext_mech_batch_produced\s*\(\s*const struct xdev_ext_mech_batch \*\s*\w*\s*\)\s*;', header),
                        'include/linux/xdev_ext_mech.h lacks xdev_ext_mech_batch_produced (API.md 2.2)')
        core = (ROOT / 'io_uring/xdev_ext_mech.c').read_text()
        for needle in ('EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_complete_produced);',
                       'EXPORT_SYMBOL_GPL(xdev_ext_mech_batch_produced);',
                       '#include "xdev_ext_mech_produced.h"'):
            self.assertTrue(needle in core, 'io_uring/xdev_ext_mech.c lacks ' + needle)
        self.assertTrue(re.search(r'xdev_ext_mech_produced_trim\(', core),
                        'the worker must trim producer batches with the pure rule')
        body = re.search(r'void xdev_ext_mech_batch_complete_produced\([^)]*\)\s*\{(.*?)\n\}', core, re.S)
        self.assertIsNotNone(body, 'xdev_ext_mech_batch_complete_produced definition not found')
        self.assertTrue('xdev_ext_mech_batch_completion_claim(' in body.group(1),
                        'the producer completion must claim its ticket before writing the length')
        self.assertTrue('-EOVERFLOW' in body.group(1), 'produced 0 or beyond the batch is -EOVERFLOW')


if __name__ == '__main__':
    unittest.main(verbosity=2)
