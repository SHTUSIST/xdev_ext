#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Provider wiring of the HELD reply for a slow receiver chain (AF-1).

Executes the production xsk_rel_rx() and xsk_rel_build() with the production
protocol helpers. A retransmitted DATA segment of a group whose device chain
still runs must be recycled (never resubmitted), queue exactly one HELD
control for that slot, count a suppressed duplicate, and never displace an ACK
that the slot still owes. The control BUILD then encodes HELD; after the chain
completes it encodes ACK. A HELD arriving at the sender restores its budget
and is recycled like an ACK. Wire decode and the BPF call are shims; the RX
inspector, reply bookkeeping and type selection are production code.
RELIABLE_INC selects another .inc (RED runs).
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


def body(path, signature):
    text = Path(path).read_text()
    match = re.search(r'^' + re.escape(signature) + r'[^;{}]*\)\s*\{.*?^\}', text, re.M | re.S)
    if match is None:
        raise RuntimeError('missing production ' + signature)
    return match[0]


FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef int32_t s32;
#include "include/linux/xdev_ext_mech_reliable_core.h"
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 1
#define XDEV_EXT_MECH_MEMBER_BUILD 1
#define XDEV_EXT_MECH_SITE_WORKER 0
#define XDEV_EXT_MECH_BUILD_SUBMIT 1
#define spin_lock_irqsave(l,f) ((void)(l),(void)((f)=0))
#define spin_unlock_irqrestore(l,f) ((void)(l),(void)(f))
struct xdp_desc { u64 addr; u32 len, options; };
struct xdev_ext_mech_frame_info { u64 umem_addr; u32 data_off, data_len; };
struct xdev_ext_mech_frame { u32 index; u64 umem_addr; u32 data_off, data_len; u8 *kaddr; };
struct xdev_ext_afxdp_reliable_info {
 struct { u32 nr_frames; struct xdev_ext_mech_frame_info f[32]; } base;
 u64 wire_session, wire_group, wire_credit; u32 wire_attempt, wire_type; };
struct xsk_rel_control { struct xdev_ext_mech_frame frame; bool busy; };
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xdev_ext_rel_rx rx;
 u64 ack_pending[32]; u64 nr_groups; struct xdev_ext_afxdp_reliable_info info;
 struct xdev_ext_mech_frame frames[32]; struct xdp_desc scratch[32]; };
struct xsk_xdev_ext_mech_provider { int tx_lock; };
struct xdev_ext_mech_pool { struct xsk_xdev_ext_mech_provider *priv; u32 capabilities, frame_size; };
struct xdev_ext_mech_layout { u32 hdr_room; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; struct xdev_ext_mech_layout layout; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv; struct xdev_ext_mech_session *s; u32 direction; };
struct xdev_ext_mech_batch { int unused; };
struct xdev_ext_binding_ctx_v2 { u64 group; };
struct xdev_ext_mech_call_args { int member, callsite; struct xdev_ext_binding_ctx_v2 *base;
 struct xdev_ext_mech_batch *b; struct xdev_ext_mech_frame *frames; u32 nr_frames, frame_size, hdr_room;
 void *info; u32 info_size; u8 *scratch; u32 desc_size, desc_cap; };
static unsigned kicks, checked_type;
static struct xdev_ext_rel_msg wire;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s) { return &s->layout; }
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) { (void)st; kicks++; }
static int xsk_rel_decode(struct xdev_ext_mech_stage *st, const struct xdev_ext_mech_frame *f, struct xdev_ext_rel_msg *m)
{ (void)st; (void)f; *m = wire; return 0; }
static struct xdev_ext_binding_ctx_v2 xdev_ext_binding_make_afxdp_native_tx_ctx(u64 g, u32 bytes, u32 caps)
{ (void)bytes; (void)caps; return (struct xdev_ext_binding_ctx_v2){ .group = g }; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { (void)b; return 0; }
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { (void)b; return 0; }
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b, u32 i, struct xdev_ext_mech_frame *f)
{ (void)b; (void)i; (void)f; return 0; }
static void xsk_xdev_ext_mech_fill_info(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b, void *in)
{ (void)st; (void)b; memset(in, 0, sizeof(struct xdev_ext_afxdp_reliable_info)); }
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_call_args *a, s32 *ret, void *x)
{ (void)st; (void)x; ((struct xdp_desc *)a->scratch)[0] = (struct xdp_desc){ .addr = 64, .len = 106 };
  *ret = XDEV_EXT_MECH_BUILD_SUBMIT; return 0; }
static int xsk_rel_packet_check(struct xdev_ext_mech_stage *st, const struct xdp_desc *d,
 const struct xdev_ext_mech_frame_info *fi, u8 *chunk, u64 g, u32 attempt, u64 credit, u8 type, u32 index)
{ (void)st; (void)d; (void)fi; (void)chunk; (void)g; (void)attempt; (void)credit; (void)index;
  checked_type = type; return 0; }
static void xsk_xdev_ext_mech_tx_finish(u8 *pkt) { (void)pkt; }
/* PRODUCTION_RX */
/* PRODUCTION_BUILD */
static unsigned checks, failures;
#define EXPECT(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __func__, __LINE__, #c); } } while (0)
static const struct xdev_ext_rel_cfg cfg = { .session = 9, .first_group = 1, .timeout_ns = 100,
 .window = 4, .max_attempts = 3, .group_bytes = 8192, .seg_len = 1408 };
static struct xdev_ext_rel_msg data(u64 g, u16 i, u32 attempt)
{ return (struct xdev_ext_rel_msg){ .session = 9, .group = g, .attempt = attempt, .type = XDEV_EXT_REL_DATA,
   .total_len = 8192, .index = i, .count = 6, .relative_offset = i * 1408u, .payload_len = i == 5 ? 1152 : 1408 }; }
struct world { struct xsk_mech_reliable r; struct xsk_xdev_ext_mech_provider p; struct xdev_ext_mech_session s;
 struct xsk_xdev_ext_mech_stage x; struct xdev_ext_mech_stage st; struct xsk_rel_control c; u8 frame[512]; };
static void init(struct world *w, u32 direction)
{
 memset(w, 0, sizeof(*w));
 xdev_ext_rel_tx_init(&w->r.tx, &cfg); xdev_ext_rel_rx_init(&w->r.rx, &cfg);
 w->s.pool.priv = &w->p; w->s.layout.hdr_room = 256; w->x.rel = &w->r;
 w->st = (struct xdev_ext_mech_stage){ .priv = &w->x, .s = &w->s, .direction = direction };
 w->c.frame = (struct xdev_ext_mech_frame){ .umem_addr = 0, .data_off = 256, .kaddr = w->frame };
 kicks = 0;
}
static void hold_group(struct world *w, u64 g)
{
 u16 i;
 for (i = 0; i < 6; i++) { struct xdev_ext_rel_msg m = data(g, i, 1); xdev_ext_rel_rx_commit(&w->r.rx, &m); }
}
static int rx(struct world *w, struct xdev_ext_rel_msg m)
{
 struct xdev_ext_mech_frame f = { 0 };
 struct xdev_ext_rel_msg out;
 wire = m;
 return xsk_rel_rx(&w->st, &f, &out);
}
static void retransmit_while_chain_runs_queues_one_held(void)
{
 struct world w;
 init(&w, XDEV_EXT_MECH_DIR_FROM_DEVICE); hold_group(&w, 1);
 EXPECT(rx(&w, data(1, 2, 2)) == XDEV_EXT_REL_REPLAY_HELD);
 EXPECT(w.r.ack_pending[1] == 1 && kicks == 1);
 EXPECT(w.r.rx.entry[1].latest_attempt == 2 && w.r.rx.entry[1].state == XDEV_EXT_REL_RX_SUBMITTED);
 EXPECT(rx(&w, data(1, 3, 2)) == XDEV_EXT_REL_REPLAY_HELD);
 EXPECT(kicks == 1);
 EXPECT(w.r.rx.dup_suppressed == 2);
 EXPECT(!xsk_rel_build(&w.st, NULL, &w.c, 1, 2, w.r.rx.credit));
 EXPECT(w.r.info.wire_type == XDEV_EXT_REL_HELD && checked_type == XDEV_EXT_REL_HELD);
 /* The chain completes: the same slot now owes, and builds, an ACK. */
 EXPECT(xdev_ext_rel_rx_finish(&w.r.rx, 1, 0) == XDEV_EXT_REL_REPLAY_ACK);
 xdev_ext_rel_rx_reply(&w.r.rx, 1, XDEV_EXT_REL_REPLAY_ACK);
 EXPECT(!xsk_rel_build(&w.st, NULL, &w.c, 1, 2, w.r.rx.credit));
 EXPECT(w.r.info.wire_type == XDEV_EXT_REL_ACK && checked_type == XDEV_EXT_REL_ACK);
 EXPECT(rx(&w, data(1, 0, 3)) == XDEV_EXT_REL_REPLAY_ACK && w.r.rx.dup_suppressed == 3);
}
static void held_never_displaces_an_owed_ack(void)
{
 struct world w;
 init(&w, XDEV_EXT_MECH_DIR_FROM_DEVICE);
 hold_group(&w, 1);
 EXPECT(xdev_ext_rel_rx_finish(&w.r.rx, 1, 0) == XDEV_EXT_REL_REPLAY_ACK);
 w.r.ack_pending[1] = 1;
 hold_group(&w, 5);  /* slot 1 again, chain still running */
 EXPECT(rx(&w, data(5, 0, 2)) == XDEV_EXT_REL_REPLAY_HELD);
 EXPECT(w.r.ack_pending[1] == 1 && kicks == 0);
 EXPECT(!xsk_rel_build(&w.st, NULL, &w.c, 1, 1, w.r.rx.credit));
 EXPECT(w.r.info.wire_type == XDEV_EXT_REL_ACK);
}
static void sender_accepts_held_without_completion(void)
{
 struct world w;
 struct xdev_ext_rel_msg held = { .session = 9, .group = 1, .attempt = 2, .type = XDEV_EXT_REL_HELD, .credit = 5 };
 init(&w, 0);
 EXPECT(xdev_ext_rel_tx_open(&w.r.tx, 1, 8192, 6) == XDEV_EXT_REL_SEND);
 EXPECT(xdev_ext_rel_tx_native_begin(&w.r.tx, 1, 0) == XDEV_EXT_REL_SEND);
 EXPECT(xdev_ext_rel_tx_native_done(&w.r.tx, 1, 1, 0, false, 0) == XDEV_EXT_REL_NONE);
 EXPECT(xdev_ext_rel_tx_poll(&w.r.tx, 1, 100) == XDEV_EXT_REL_SEND);
 EXPECT(xdev_ext_rel_tx_native_begin(&w.r.tx, 1, 100) == XDEV_EXT_REL_SEND);
 EXPECT(rx(&w, held) == XDEV_EXT_REL_RECYCLE);
 EXPECT(w.r.tx.entry[1].held_attempt == 2 && !w.r.tx.entry[1].acked && w.r.tx.held_acks == 1);
 EXPECT(kicks == 0 && w.r.rx.dup_suppressed == 0);
}
int main(void)
{
 retransmit_while_chain_runs_queues_one_held();
 held_never_displaces_an_owed_ack();
 sender_accepts_held_without_completion();
 printf("held reply provider: %u checks, %u failures\n", checks, failures);
 return failures != 0;
}
'''


class HeldReplyProvider(unittest.TestCase):
    def test_provider_queues_builds_and_accepts_held(self):
        source = FIXTURE.replace('/* PRODUCTION_RX */', body(INC, 'static int xsk_rel_rx('))
        source = source.replace('/* PRODUCTION_BUILD */', body(INC, 'static int xsk_rel_build('))
        with tempfile.TemporaryDirectory(prefix='xdev_ext-rel-held-') as tmp:
            path = Path(tmp)
            (path / 'probe.c').write_text(source)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-DXDEV_EXT_REL_C_GLUE', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-unused-function', '-fsanitize=undefined',
                                    '-fno-sanitize-recover=undefined', '-I', str(ROOT),
                                    str(path / 'probe.c'), '-o', str(path / 'probe')],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(path / 'probe')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
