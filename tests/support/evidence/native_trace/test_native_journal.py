# SPDX-License-Identifier: GPL-2.0
"""Bounded real-provider metadata journal behavior; no devices or timing."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[3]
class NativeJournal(unittest.TestCase):
    def test_fifo_sequences_overflow_underflow_and_tail(self):
        header = ROOT / 'kernel/include/linux/xdev_ext_trace_journal.h'
        self.assertTrue(header.exists(), 'bounded native descriptor journal missing')
        src = r'''
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
typedef uint64_t u64;
typedef uint32_t u32;
#define XDEV_EXT_TRACE_JOURNAL_HOST
#include "HEADER"
int main(void) {
 struct xdev_ext_trace_entry entries[2], e;
 struct xdev_ext_trace_journal j = { .entries=entries, .capacity=2 };
 if (xdev_ext_trace_pop(&j,&e) != -ENODATA) return 1;
 if (xdev_ext_trace_push(&j,4096,64,&e) || e.sequence != 1) return 2;
 if (xdev_ext_trace_push(&j,8192,128,&e) || e.sequence != 2) return 3;
 if (xdev_ext_trace_push(&j,12288,256,&e) != -ENOSPC) return 4;
 if (xdev_ext_trace_pop(&j,&e) || e.address != 4096 || e.bytes != 64 || e.sequence != 1) return 5;
 if (xdev_ext_trace_push(&j,12288,256,&e) || e.sequence != 3) return 6;
 if (xdev_ext_trace_tail(&j,1,-EMSGSIZE)) return 7;
 if (xdev_ext_trace_pop(&j,&e) || e.address != 8192 || e.sequence != 2 || e.status) return 8;
 if (xdev_ext_trace_pop(&j,&e) || e.address != 12288 || e.sequence != 3 || e.status != -EMSGSIZE) return 9;
 if (xdev_ext_trace_tail(&j,1,-EIO) != -ENODATA) return 10;
 return xdev_ext_trace_pop(&j,&e) != -ENODATA;
}
'''.replace('HEADER', str(header))
        with tempfile.TemporaryDirectory() as temp:
            c = Path(temp)/'test.c'; c.write_text(src)
            binary = Path(temp)/'test'
            built = subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror',str(c),'-o',str(binary)],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run = subprocess.run([str(binary)])
            self.assertEqual(run.returncode,0)
if __name__ == '__main__': unittest.main()
