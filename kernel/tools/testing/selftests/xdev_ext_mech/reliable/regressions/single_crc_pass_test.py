#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""One payload CRC32C pass per direction on the reliable NXP v3 path (AF-3).

Before this change every DATA byte crossed the CPU twice per direction: TX
built the CRC in BPF and C recomputed it to check BPF; RX verified it in C
(xsk_rel_decode) and BPF recomputed it before HOLD. C stays the one
authority in both directions: it writes the TX CRC after its identity check
and verifies the RX CRC before the program runs.

This compiles the production tools/xdev_ext_mech/nxp_reliable.bpf.c as host C
(the cref host stand-ins for vmlinux.h and libbpf; kfuncs are counting mocks)
and the production xsk_rel_packet_check(). It runs BPF BUILD, then the C TX
boundary, checks the stored CRC independently, and feeds the wire bytes to the
BPF RX COMPLETE. Neither callback may call a CRC kfunc. RELIABLE_BPF and
RELIABLE_INC select other sources (RED runs).
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get('KERNEL_DIR', str(next(
    p for p in Path(__file__).resolve().parents if (p / 'io_uring/xdev_ext_mech.c').is_file()))))
INC = Path(os.environ.get('RELIABLE_INC', str(ROOT / 'net/xdp/xsk_xdev_ext_mech_reliable.inc')))
BPF = Path(os.environ.get('RELIABLE_BPF', str(ROOT / 'tools/xdev_ext_mech/nxp_reliable.bpf.c')))
CREF_HOST = ROOT / 'tools/testing/selftests/xdev_ext_mech/cref/host'


def body(path, signature):
    text = Path(path).read_text()
    match = re.search(r'^' + re.escape(signature) + r'[^;{}]*\)\s*\{.*?^\}', text, re.M | re.S)
    if match is None:
        raise RuntimeError('missing production ' + signature)
    return match[0]


FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmlinux.h"
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
static unsigned crc_calls, hold_calls;
static struct { __u64 key; __u32 pos, off, len; } hold;
static struct { struct xdev_ext_mech_ctx ctx; const void *info; size_t info_size; __u8 *frames[32];
 __u32 frame_size; struct xdp_desc *desc; __u32 desc_cap; const void *cqe; size_t cqe_size; } M;
static __u32 sw_crc32c(__u32 crc, const void *buf, size_t len)
{
 const __u8 *p = buf; int k;
 while (len--) { crc ^= *p++; for (k = 0; k < 8; k++) crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1))); }
 return crc;
}
__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *c, const size_t n)
{ (void)c; return n == M.info_size ? (__u8 *)M.info : NULL; }
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *c, __u32 slot, const size_t n)
{ (void)c; return n == sizeof(struct xdp_desc) && slot < M.desc_cap ? (__u8 *)&M.desc[slot] : NULL; }
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *c, __u32 slot, const size_t n)
{ (void)c; return !slot && n == M.cqe_size ? (__u8 *)M.cqe : NULL; }
__u8 *bpf_xdev_ext_frame(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, const size_t n)
{ (void)c; return pos < 32 && M.frames[pos] && off + n <= M.frame_size ? M.frames[pos] + off : NULL; }
__u32 bpf_xdev_ext_frame_crc32c(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, __u32 len, __u32 seed)
{ (void)c; crc_calls++; return sw_crc32c(seed, M.frames[pos] + off, len); }
__u32 bpf_xdev_ext_crc32c(const void *buf, __u32 n, __u32 seed) { crc_calls++; return sw_crc32c(seed, buf, n); }
__u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *c, const size_t n) { (void)c; (void)n; return NULL; }
__u8 *bpf_xdev_ext_afxdp_hdr(const struct xdev_ext_mech_ctx *c, __u32 pos, __u32 off, const size_t n)
{ (void)c; return pos < 32 && M.frames[pos] && off + n <= M.frame_size ? M.frames[pos] + off : NULL; }
int bpf_xdev_ext_afxdp_hold(const struct xdev_ext_mech_ctx *c, __u64 key, __u32 pos, __u32 off, __u32 len)
{ (void)c; hold_calls++; hold.key = key; hold.pos = pos; hold.off = off; hold.len = len; return 0; }
/* PROGRAM */
/* C TX boundary, with the envelope checker (tested elsewhere) admitted. */
struct xdev_ext_mech_session { struct xdev_ext_mech_layout layout; struct xdev_ext_mech_peer peer; };
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; u32 mtu; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv; struct xdev_ext_mech_session *s; };
struct xsk_xdev_ext_mech_tx_bounds { u32 hdr_room, mtu; struct xdev_ext_mech_peer peer; };
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s) { return &s->layout; }
static const struct xdev_ext_mech_peer *xdev_ext_mech_session_peer(struct xdev_ext_mech_session *s) { return &s->peer; }
static int xsk_xdev_ext_mech_tx_check(const struct xdp_desc *d, const struct xdev_ext_mech_frame_info *fi,
 const u8 *chunk, const struct xsk_xdev_ext_mech_tx_bounds *bd) { (void)d; (void)fi; (void)chunk; (void)bd; return 0; }
static u32 crc32c(u32 crc, const void *data, unsigned int len) { return sw_crc32c(crc, data, len); }
/* PACKET_CHECK */
static unsigned checks, failures;
#define EXPECT(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __func__, __LINE__, #c); } } while (0)
int main(void)
{
 static __u8 chunk[2][4096];
 struct xdp_desc desc[32] = { 0 };
 struct xdev_ext_afxdp_reliable_info tx = { 0 }, rx = { 0 };
 struct xdev_ext_rel_cfg cfg = { .session = 44, .first_group = 1, .timeout_ns = 100, .window = 2,
  .max_attempts = 3, .group_bytes = 1024, .seg_len = 512 };
 struct xsk_mech_reliable rel = { 0 };
 struct xsk_xdev_ext_mech_stage xst = { .rel = &rel, .mtu = 1500 };
 struct xdev_ext_mech_session session = { .layout = { .frame_size = 4096, .hdr_room = 384, .seg_len = 512, .group_bytes = 1024 } };
 struct xdev_ext_mech_stage st = { .priv = &xst, .s = &session };
 unsigned i, j;
 __s32 ret;

 EXPECT(!xdev_ext_rel_tx_init(&rel.tx, &cfg));
 tx.base.l = session.layout; tx.base.nr_frames = 2;
 tx.wire_session = 44; tx.wire_group = 1; tx.wire_attempt = 1; tx.wire_type = XDEV_EXT_REL_DATA;
 for (i = 0; i < 2; i++) {
  tx.base.f[i] = (struct xdev_ext_mech_frame_info){ .umem_addr = 0, .data_off = 384, .data_len = 512 };
  for (j = 0; j < 512; j++) chunk[i][384 + j] = (__u8)(i * 31 + j * 7);
  memset(chunk[i] + 98 + 278, 0xa5, 4);  /* stale bytes in the CRC field */
  M.frames[i] = chunk[i];
 }
 M.info = &tx; M.info_size = sizeof(tx); M.frame_size = 4096; M.desc = desc; M.desc_cap = 32;
 M.ctx.member = XDEV_EXT_MECH_MEMBER_BUILD; M.ctx.callsite = XDEV_EXT_MECH_SITE_WORKER;
 crc_calls = 0;
 ret = rel_afxdp_build(NULL, &M.ctx);
 EXPECT(ret == XDEV_EXT_MP_BUILD_SUBMIT);
 EXPECT(crc_calls == 0);
 for (i = 0; i < 2; i++) {
  __u8 *pkt = chunk[i] + 278, hdr[64];
  __u32 crc;
  EXPECT(desc[i].addr == 278 && desc[i].len == 618);
  EXPECT(!xsk_rel_packet_check(&st, &desc[i], &tx.base.f[i], chunk[i], 1, 1, 0, XDEV_EXT_REL_DATA, i));
  memcpy(hdr, pkt + 42, 64); memset(hdr + 56, 0, 4);
  crc = sw_crc32c(sw_crc32c(~0U, hdr, 64), pkt + 106, 512) ^ ~0U;
  EXPECT(xdev_ext_rel_be(pkt + 98, 4) == crc);
 }
 /* RX: C already verified these wire bytes; BPF only decodes identity. */
 rx.base.l = session.layout; rx.base.nr_frames = 1; rx.wire_session = 44;
 rx.base.f[0] = (struct xdev_ext_mech_frame_info){ .umem_addr = 0, .data_off = 278, .data_len = 618 };
 M.info = &rx; M.info_size = sizeof(rx); M.frames[0] = chunk[1]; M.frames[1] = NULL;
 M.ctx.member = XDEV_EXT_MECH_MEMBER_COMPLETE; M.ctx.callsite = XDEV_EXT_MECH_SITE_RX_NATIVE;
 crc_calls = 0; hold_calls = 0;
 ret = rel_afxdp_complete(NULL, &M.ctx);
 EXPECT(ret == XDEV_EXT_MP_HOLD);
 EXPECT(crc_calls == 0);
 EXPECT(hold_calls == 1 && hold.key == 1 && hold.pos == 1 && hold.off == 384 && hold.len == 512);
 /* Identity is still decoded strictly: a foreign session is not held. */
 rx.wire_session = 45; hold_calls = 0;
 EXPECT(rel_afxdp_complete(NULL, &M.ctx) == XDEV_EXT_MP_RECYCLE && !hold_calls);
 printf("single CRC pass: %u checks, %u failures\n", checks, failures);
 return failures != 0;
}
'''


class SingleCrcPass(unittest.TestCase):
    def test_bpf_never_streams_payload_and_c_owns_crc(self):
        program = BPF.read_text().replace('#include "../../include/linux/xdev_ext_mech_reliable_core.h"',
                                          '#include "include/linux/xdev_ext_mech_reliable_core.h"')
        source = FIXTURE.replace('/* PROGRAM */', program)
        source = source.replace('/* PACKET_CHECK */', body(INC, 'static int xsk_rel_packet_check('))
        with tempfile.TemporaryDirectory(prefix='xdev_ext-rel-crc-') as tmp:
            path = Path(tmp)
            (path / 'probe.c').write_text(source)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-unused-function', '-Wno-unused-parameter',
                                    '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                    '-I', str(CREF_HOST), '-I', str(ROOT),
                                    '-I', str(ROOT / 'tools/xdev_ext_mech'),
                                    str(path / 'probe.c'), '-o', str(path / 'probe')],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(path / 'probe')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
