#!/usr/bin/env python3
"""Compile the production USER handoff: publish actual length, never capacity."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]
PRELUDE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include "io_uring/xdev_ext_mech_core.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"
#include "io_uring/xdev_ext_mech_step.h"
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM 2
#define XDEV_EXT_MECH_F_USER 0
#define XDEV_EXT_MECH_F_K_FREE 1
typedef uint32_t u32;
typedef __u64 u64;
struct xdev_ext_mech_frame {u32 index;};
struct pool_ops;
struct pool {struct pool_ops *ops;};
struct pool_ops {void (*recycle)(struct pool *,struct xdev_ext_mech_frame *);};
struct cls {unsigned flags;};
struct stage {unsigned direction; struct cls *cls;};
struct xdev_ext_mech_session {
 struct pool pool; struct stage st[1]; struct xdev_ext_mech_layout layout;
 struct xdev_ext_mech_life life[2]; u32 frames, start_user_len,nr_stages;
 struct xdev_ext_mech_stage_uapi plan[1];
};
static unsigned states[2], recycled;
static void cond_resched(void) {}
static int xdev_ext_mech_pool_frame_move(struct pool *p,u32 idx,u32 from,u32 to) {
 (void)p;if(idx>=2)return -ERANGE;if(states[idx]!=from)return -EBUSY;states[idx]=to;return 0;
}
static void recycle(struct pool *p,struct xdev_ext_mech_frame *f) {(void)p;(void)f;recycled++;}
'''
MAIN = r'''
int main(int argc,char **argv) {
 struct pool_ops ops={.recycle=recycle};struct cls cls={0};
 struct xdev_ext_mech_session s={.pool={&ops},.frames=1,
 .layout={.frame_size=4096,.seg_len=4096,.group_bytes=4096}};
 const u32 idx=0;int err;
 (void)argc;s.st[0].direction=XDEV_EXT_MECH_DIR_TO_DEVICE;s.st[0].cls=&cls;
 s.start_user_len=!strcmp(argv[1],"actual")?17:0;
 err=xdev_ext_mech_take_user_frames(&s,&idx,1);
 if(err || recycled!=1 || states[0]!=XDEV_EXT_MECH_F_K_FREE)return 3;
 if(s.life[0].valid_len!=(s.start_user_len?:4096)) {
  fprintf(stderr,"actual payload %u became capacity %u\n",s.start_user_len,s.life[0].valid_len);return 1;
 }
 return 0;
}
'''

class UserSpans(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / 'io_uring/xdev_ext_mech.c').read_text()
        fn = re.search(r'^static int xdev_ext_mech_take_user_frames\([^;{}]*\)\n\{\n.*?^\}', source, re.M | re.S)
        assert fn
        cls.tmp = tempfile.TemporaryDirectory(prefix='xdev-user-span-')
        cls.addClassCleanup(cls.tmp.cleanup)
        p = Path(cls.tmp.name)
        (p / 'test.c').write_text(PRELUDE + fn[0] + MAIN)
        cls.exe = p / 'test'
        subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-I' + str(ROOT), str(p / 'test.c'), '-o', str(cls.exe)], check=True)

    def test_legacy_publishes_layout_length(self):
        self.assertEqual(subprocess.run([str(self.exe), 'legacy']).returncode, 0)

    def test_explicit_user_span_publishes_actual_length(self):
        self.assertEqual(subprocess.run([str(self.exe), 'actual']).returncode, 0)

if __name__ == '__main__':
    unittest.main(verbosity=2)
