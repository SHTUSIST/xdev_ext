#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""AF_XDP COPY-mode TX counts every frame it puts on the wire.

Requirement (track S API 1.3/2.1, nic_accounting_test.py): a TX stage whose
socket is not zero-copy adds one NIC copy operation and the frame's data
length to nic_copy_ops/nic_copy_bytes for each frame the device accepted.
The guest oracle in xdev_ext_mech_zc_kvm.sh (Track S, case 2) expects
nic_copy_ops == groups * frames on the sender.

The production send step xsk_xdev_ext_mech_tx_xmit() is extracted unchanged
and driven through the real xsk_xdev_ext_mech_tx_run().  The only host
boundary is xsk_kernel_xmit(), stubbed to its documented contract
("Return: @len on success ... or a negative errno"), which this test also
checks against the production body in net/xdp/xsk.c.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]


def function(text, name):
    match = re.search(r'^\w[^;{}]*\b' + name + r'\([^;{}]*\)\n\{\n.*?^\}', text, re.M | re.S)
    if not match:
        raise RuntimeError('missing production function: ' + name)
    return match[0]


FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "include/linux/xdev_ext_mech.h"
#include "net/xdp/xsk_xdev_ext_mech_tx_core.h"
typedef __u8 u8; typedef __u32 u32; typedef __u64 u64; typedef __s32 s32;
#define READ_ONCE(x) (x)
#define N XDEV_EXT_MECH_MAX_FRAMES
struct xdev_ext_mech_session { u64 cnt[XDEV_EXT_MECH_CNT_NR]; };
struct xdev_ext_mech_stage { struct xdev_ext_mech_session *s; };
struct xdp_sock { bool zc; struct xdev_ext_mech_stage *xdev_ext_mech_tx; };
struct socket { int unused; };
struct xsk_xdev_ext_mech_stage {
 struct xdp_sock *xs; struct socket *sock; bool dead;
 struct xdp_desc tx_desc[N]; u8 *tx_pkt[N]; struct xdev_ext_mech_frame_info tx_fi[N];
};
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s, enum xdev_ext_mech_counter c, u64 n)
{ s->cnt[c] += n; }
static int fail_at = -1, fail_err; static unsigned calls;
/* Host boundary, per the documented contract: @len on success, else -errno. */
static int xsk_kernel_xmit(struct socket *sock, u64 addr, u32 len, u32 options)
{
 (void)sock; (void)addr; (void)options;
 if ((int)calls++ == fail_at) return fail_err;
 return (int)len;
}
/* PRODUCTION_XMIT */
static int failures;
#define EXPECT(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __func__, __LINE__, #c); failures++; } } while (0)
static u8 pkt[N][2048];
static struct xdev_ext_mech_session sess; static struct xdev_ext_mech_stage stage = { .s = &sess };
static struct xdp_sock xs; static struct socket sock;
static struct xsk_xdev_ext_mech_stage xst;
static u64 sent_id[N]; static u64 *sent[N]; static s32 err[N];
static const u32 data_len[3] = { 1432, 1432, 100 };
static void setup(bool zc)
{
 memset(&sess, 0, sizeof(sess)); memset(&xst, 0, sizeof(xst)); memset(sent_id, 0, sizeof(sent_id));
 xs.zc = zc; xs.xdev_ext_mech_tx = &stage; xst.xs = &xs; xst.sock = &sock;
 calls = 0; fail_at = -1;
 for (int i = 0; i < 3; i++) {
  xst.tx_fi[i].umem_addr = 4096ULL * i; xst.tx_fi[i].data_len = data_len[i];
  xst.tx_desc[i].addr = 4096ULL * i + 256; xst.tx_desc[i].len = 42 + data_len[i];
  xst.tx_pkt[i] = pkt[i]; sent[i] = &sent_id[i]; err[i] = 1;
 }
}
static void copy_counts_each_sent_frame(void)
{
 setup(false);
 EXPECT(xsk_xdev_ext_mech_tx_run(7, 3, sent, err, xsk_xdev_ext_mech_tx_xmit, &xst) == 0);
 EXPECT(calls == 3);
 EXPECT(err[0] == 0 && err[1] == 0 && err[2] == 0);
 EXPECT(sent_id[0] == 7 && sent_id[1] == 7 && sent_id[2] == 7);
 EXPECT(sess.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 3);
 EXPECT(sess.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES] == 1432 + 1432 + 100);
 EXPECT(sess.cnt[XDEV_EXT_MECH_CNT_NIC_ZC_OPS] == 0 && sess.cnt[XDEV_EXT_MECH_CNT_NIC_ZC_BYTES] == 0);
 /* A retry of the same batch sends and counts nothing more. */
 EXPECT(xsk_xdev_ext_mech_tx_run(7, 3, sent, err, xsk_xdev_ext_mech_tx_xmit, &xst) == 0);
 EXPECT(calls == 3 && sess.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 3);
}
static void step_reports_zero_for_a_sent_frame(void)
{
 setup(false);
 EXPECT(xsk_xdev_ext_mech_tx_xmit(&xst, 0) == 0);
 EXPECT(sess.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 1);
}
static void failed_frame_is_not_counted(void)
{
 setup(false);
 fail_at = 1; fail_err = -EAGAIN;
 EXPECT(xsk_xdev_ext_mech_tx_run(9, 3, sent, err, xsk_xdev_ext_mech_tx_xmit, &xst) == -EAGAIN);
 EXPECT(err[0] == 0 && err[1] == -EAGAIN && err[2] == -ECANCELED);
 EXPECT(sess.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 1);
 EXPECT(sess.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES] == 1432);
}
static void dead_stage_sends_nothing(void)
{
 setup(false);
 xst.dead = true;
 EXPECT(xsk_xdev_ext_mech_tx_xmit(&xst, 0) == -ENXIO);
 EXPECT(calls == 0 && sess.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_OPS] == 0);
}
int main(void)
{
 copy_counts_each_sent_frame();
 step_reports_zero_for_a_sent_frame();
 failed_frame_is_not_counted();
 dead_stage_sends_nothing();
 puts(failures ? "FAIL xsk copy tx accounting" : "PASS xsk copy tx accounting");
 return !!failures;
}
'''


class XskTxCopyAccounting(unittest.TestCase):
    def test_kernel_xmit_returns_len_on_success(self):
        body = function((ROOT / 'net/xdp/xsk.c').read_text(), 'xsk_kernel_xmit')
        self.assertRegex(body, r'return err < 0 \? err : \(int\)len;\n\}$',
                         'stub contract: xsk_kernel_xmit() returns @len on success')

    def test_copy_tx_counts_sent_frames(self):
        mech = (ROOT / 'net/xdp/xsk_xdev_ext_mech.c').read_text()
        source = FIXTURE.replace('/* PRODUCTION_XMIT */', function(mech, 'xsk_xdev_ext_mech_tx_xmit'))
        with tempfile.TemporaryDirectory(prefix='xsk-tx-copy-') as tmp:
            path = Path(tmp) / 'probe.c'
            exe = Path(tmp) / 'probe'
            path.write_text(source)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-Wno-unused-function', '-fsanitize=undefined',
                                    '-fno-sanitize-recover=undefined', '-I' + str(ROOT), str(path), '-o', str(exe)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
