#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""CREATE admission of a SOCKET FROM_DEVICE (NIC-boundary copy receive) stage.

Executes the production xdev_ext_mech_create_check() from
io_uring/xdev_ext_mech_step.h. Contract (track S API.md 2.4): a SOCKET
receive stage is a START-driven producer and is legal only as stage 0 of a
chain of at least two stages, on the ring's UMEM or an XSK pool; the
existing TO_DEVICE sink, flag and PEER-pool rules are unchanged.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]

FIXTURE = r'''
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_step.h"
#define SOCK XDEV_EXT_MECH_CLASS_SOCKET
#define TO XDEV_EXT_MECH_DIR_TO_DEVICE
#define FROM XDEV_EXT_MECH_DIR_FROM_DEVICE
static int failures;
static struct xdev_ext_mech_create base(void)
{
 struct xdev_ext_mech_create c;
 memset(&c, 0, sizeof(c));
 c.abi_version = XDEV_EXT_MECH_ABI_VERSION; c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
 c.pool_fd = -1; c.depth = 8; c.eventfd = -1;
 c.layout = (struct xdev_ext_mech_layout){ .frame_size = 4096, .hdr_room = 256, .seg_len = 2048, .group_bytes = 8192 };
 return c;
}
static void stage(struct xdev_ext_mech_create *c, unsigned i, unsigned cls, unsigned dir, int fd)
{
 c->st[i] = (struct xdev_ext_mech_stage_uapi){ .class_id = cls, .direction = dir, .fd = fd };
 if (cls == XDEV_EXT_MECH_CLASS_NVME) { c->st[i].arg0 = 0; c->st[i].arg1 = 4096; }
 if (cls == XDEV_EXT_MECH_CLASS_CE) { c->st[i].arg0 = 0; c->st[i].arg1 = 1 << 20; }
}
static void expect(const char *name, struct xdev_ext_mech_create *c, int want, unsigned want_frames)
{
 __u32 frames = 0;
 int got = xdev_ext_mech_create_check(c, &frames);
 if (got != want || (!want && frames != want_frames)) {
  printf("not ok - %s: ret=%d frames=%u expected ret=%d frames=%u\n", name, got, frames, want, want_frames);
  failures++;
 } else {
  printf("ok - %s\n", name);
 }
}
int main(void)
{
 struct xdev_ext_mech_create c;

 c = base(); c.nr_stages = 2; stage(&c, 0, SOCK, FROM, 3); stage(&c, 1, XDEV_EXT_MECH_CLASS_NVME, TO, 4);
 expect("socket RX -> NVMe WRITE on IOU_UMEM", &c, 0, 4);
 c = base(); c.nr_stages = 2; stage(&c, 0, SOCK, FROM, 3); stage(&c, 1, XDEV_EXT_MECH_CLASS_CE, TO, 4);
 expect("socket RX -> CE H2D on IOU_UMEM", &c, 0, 4);
 c = base(); c.nr_stages = 3; stage(&c, 0, SOCK, FROM, 3); stage(&c, 1, XDEV_EXT_MECH_CLASS_CE, TO, 4);
 stage(&c, 2, XDEV_EXT_MECH_CLASS_CE, FROM, 5);
 expect("socket RX -> CE H2D -> CE D2H", &c, 0, 4);
 c = base(); c.pool_kind = XDEV_EXT_MECH_POOL_XSK; c.pool_fd = 7; c.nr_stages = 2;
 stage(&c, 0, SOCK, FROM, 3); stage(&c, 1, XDEV_EXT_MECH_CLASS_NVME, TO, 4);
 expect("socket RX -> NVMe on an XSK pool", &c, 0, 4);
 c = base(); c.nr_stages = 1; stage(&c, 0, SOCK, FROM, 3);
 expect("socket RX alone has no consumer", &c, -EINVAL, 0);
 c = base(); c.nr_stages = 2; stage(&c, 0, XDEV_EXT_MECH_CLASS_NVME, FROM, 4); stage(&c, 1, SOCK, FROM, 3);
 expect("socket RX after stage 0", &c, -EINVAL, 0);
 c = base(); c.nr_stages = 3; stage(&c, 0, SOCK, FROM, 3); stage(&c, 1, XDEV_EXT_MECH_CLASS_NVME, TO, 4);
 stage(&c, 2, SOCK, FROM, 5);
 expect("second socket RX later in the chain", &c, -EINVAL, 0);
 c = base(); c.nr_stages = 2; stage(&c, 0, SOCK, FROM, 3); stage(&c, 1, XDEV_EXT_MECH_CLASS_NVME, TO, 4);
 c.st[0].flags = 1;
 expect("socket RX flags must be zero", &c, -EINVAL, 0);
 c = base(); c.nr_stages = 2; stage(&c, 0, SOCK, FROM, -1); stage(&c, 1, XDEV_EXT_MECH_CLASS_NVME, TO, 4);
 expect("socket RX needs an fd", &c, -EBADF, 0);
 c = base(); c.pool_kind = XDEV_EXT_MECH_POOL_PEER; c.pool_fd = 7; c.nr_stages = 2;
 c.layout = (struct xdev_ext_mech_layout){ .frame_size = 65536, .seg_len = 65536, .group_bytes = 65536 };
 stage(&c, 0, SOCK, FROM, 3); stage(&c, 1, XDEV_EXT_MECH_CLASS_NVME, TO, 4);
 expect("socket RX into device-memory PEER pool refused", &c, -EOPNOTSUPP, 0);
 c = base(); c.nr_stages = 1; stage(&c, 0, SOCK, TO, 3);
 expect("socket TX sink alone unchanged", &c, 0, 4);
 c = base(); c.nr_stages = 2; stage(&c, 0, XDEV_EXT_MECH_CLASS_NVME, FROM, 4); stage(&c, 1, SOCK, TO, 3);
 expect("NVMe READ -> socket TX unchanged", &c, 0, 4);
 if (failures)
  printf("FAIL rx_create_check failures=%d\n", failures);
 else
  printf("PASS rx_create_check\n");
 return failures != 0;
}
'''


class SocketReceiveCreateCheck(unittest.TestCase):
    def test_create_check(self):
        with tempfile.TemporaryDirectory(prefix='socket-rx-create-') as tmp:
            source = Path(tmp) / 'create.c'
            exe = Path(tmp) / 'create'
            source.write_text(FIXTURE)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                    '-I' + str(ROOT), str(source), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            print(run.stdout, end='')
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
