#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The one published socket struct_ops program serves send and receive.

Only one program per class is published at a time, and a socket TX session
and a socket RX session run together in the forced-fallback guest section,
so tools/xdev_ext_mech/socket_sink.bpf.c must accept both completion kinds
(track S API.md 3.10). Executes the real build and complete functions on the
host with the C-owned kfunc views stubbed.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]


def function(source, name):
    start = source.index('__s32 BPF_PROG(' + name + ',')
    brace = source.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/if_xdp.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "tools/xdev_ext_mech/xdev_ext_mech_prog.h"
#define BPF_PROG(name,args...) name(unsigned long long *ctx,args)
static struct xdev_ext_socket_mech_info info;
static struct xdev_ext_socket_send_desc desc[32];
static struct xdev_ext_socket_mech_cqe cqe;
static __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c, size_t n)
{ (void)c; assert(n == sizeof(info)); return (void *)&info; }
static __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c, __u32 slot, size_t n)
{ (void)c; assert(n == sizeof(desc[0])); return slot < 32 ? (void *)&desc[slot] : NULL; }
static __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c, __u32 slot, size_t n)
{ (void)c; assert(!slot && n == sizeof(cqe)); return (void *)&cqe; }
'''

MAIN = r'''
static int failures;
#define EXPECT(c) do { if (!(c)) { printf("not ok - line %d: %s\n", __LINE__, #c); failures++; } } while (0)
static __s32 done(unsigned dir, __u32 length, __s32 status, __u32 sent, __u32 received, __u32 flags)
{
 struct xdev_ext_mech_ctx m;
 memset(&m, 0, sizeof(m)); m.base.direction = dir; m.base.length = length;
 cqe = (struct xdev_ext_socket_mech_cqe){ .status = status, .bytes_sent = sent,
   .bytes_received = received, .flags = flags };
 return socket_sink_complete(NULL, &m);
}
int main(void)
{
 struct xdev_ext_mech_ctx m;
 unsigned dir;
 for (dir = XDEV_EXT_MECH_DIR_TO_DEVICE; dir <= XDEV_EXT_MECH_DIR_FROM_DEVICE; dir++) {
  memset(&m, 0, sizeof(m)); memset(desc, 0, sizeof(desc));
  info.nr_frames = 2; info.max_datagram = XDEV_EXT_SOCKET_MAX_DATAGRAM;
  info.f[0].data_off = 16; info.f[0].data_len = 1000; info.f[1].data_off = 16; info.f[1].data_len = 500;
  m.base.direction = dir; m.base.length = 1500;
  EXPECT(socket_sink_build(NULL, &m) == XDEV_EXT_MP_BUILD_SUBMIT);
  EXPECT(desc[0].frame_pos == 0 && desc[0].frame_off == 16 && desc[0].len == 1000 && !desc[0].flags);
  EXPECT(desc[1].frame_pos == 1 && desc[1].frame_off == 16 && desc[1].len == 500 && !desc[1].flags);
 }
 /* Send completions keep their rule. */
 EXPECT(done(XDEV_EXT_MECH_DIR_TO_DEVICE, 1500, 0, 1500, 0, 0) == XDEV_EXT_MP_NEXT);
 EXPECT(done(XDEV_EXT_MECH_DIR_TO_DEVICE, 1500, 0, 1499, 0, 0) == XDEV_EXT_MP_ABORT);
 EXPECT(done(XDEV_EXT_MECH_DIR_TO_DEVICE, 1500, -EPIPE, 0, 0, 0) == XDEV_EXT_MP_ABORT);
 /* Receive completions: a published datagram within the batch advances. */
 EXPECT(done(XDEV_EXT_MECH_DIR_FROM_DEVICE, 1500, 0, 0, 1500, 0) == XDEV_EXT_MP_NEXT);
 EXPECT(done(XDEV_EXT_MECH_DIR_FROM_DEVICE, 1500, 0, 0, 700, 0) == XDEV_EXT_MP_NEXT);
 EXPECT(done(XDEV_EXT_MECH_DIR_FROM_DEVICE, 1500, 0, 0, 0, 0) == XDEV_EXT_MP_ABORT);
 EXPECT(done(XDEV_EXT_MECH_DIR_FROM_DEVICE, 1500, 0, 0, 1501, 0) == XDEV_EXT_MP_ABORT);
 EXPECT(done(XDEV_EXT_MECH_DIR_FROM_DEVICE, 1500, -EMSGSIZE, 0, 0, XDEV_EXT_SOCKET_CQE_F_TRUNC) == XDEV_EXT_MP_ABORT);
 EXPECT(done(XDEV_EXT_MECH_DIR_FROM_DEVICE, 1500, -ESHUTDOWN, 0, 0, 0) == XDEV_EXT_MP_ABORT);
 if (failures) printf("FAIL socket bpf both directions failures=%d\n", failures);
 else printf("PASS socket bpf both directions\n");
 return failures != 0;
}
'''


class SocketProgramBothDirections(unittest.TestCase):
    def test_build_and_complete(self):
        source = (ROOT / 'tools/xdev_ext_mech/socket_sink.bpf.c').read_text()
        code = PRELUDE + function(source, 'socket_sink_build') + '\n' + \
            function(source, 'socket_sink_complete') + '\n' + MAIN
        with tempfile.TemporaryDirectory(prefix='socket-bpf-') as tmp:
            cfile = Path(tmp) / 'prog.c'
            exe = Path(tmp) / 'prog'
            cfile.write_text(code)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-I' + str(ROOT), str(cfile), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            print(run.stdout, end='')
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
