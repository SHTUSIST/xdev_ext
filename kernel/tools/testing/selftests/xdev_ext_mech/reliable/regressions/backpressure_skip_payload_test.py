#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Credit backpressure must not stream the payload on every retry tick (AF-5).

Without sender credit, xsk_rel_submit() refuses the initial DATA with -EAGAIN
and the core rebuilds the batch on its next retry tick. The C payload pass of
xsk_rel_validate_initial() for that refused attempt was wasted work repeated
every tick. Executes the production validate/submit pair: under backpressure
the C pass is skipped and submit refuses that staged batch even if credit
arrives in between, so no unchecked byte is ever enqueued. RELIABLE_INC selects
another .inc (RED runs).
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
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
#include "include/linux/xdev_ext_mech_reliable_core.h"
#define WARN_ON_ONCE(x) ((x) ? (abort(), 1) : 0)
#define spin_lock_irqsave(l,f) ((void)(l),(void)((f)=0))
#define spin_unlock_irqrestore(l,f) ((void)(l),(void)(f))
struct xdp_desc { u64 addr; u32 len, options; };
struct xdev_ext_mech_frame_info { u64 umem_addr; u32 data_off, data_len; };
struct xsk_xdev_ext_mech_tx_batch { void *batch; u64 ticket; bool control; u32 attempt; };
struct xdev_ext_mech_batch { struct xsk_xdev_ext_mech_tx_batch priv; u64 key; };
struct xsk_rel_data { struct xdev_ext_mech_batch *batch; u64 ticket; u32 count; struct xdp_desc desc[32]; };
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xsk_rel_data data[32]; bool initial_unchecked; };
struct xsk_xdev_ext_mech_provider { int tx_lock; };
struct xdev_ext_mech_pool { struct xsk_xdev_ext_mech_provider *priv; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; u32 tx_n; struct xdp_desc tx_desc[32];
 struct xdev_ext_mech_frame_info tx_fi[32]; u8 *tx_kaddr[32]; u8 *tx_pkt[32]; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv; struct xdev_ext_mech_session *s; };
static unsigned payload_passes, enqueues;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { return &b->priv; }
static u64 xdev_ext_mech_batch_key(struct xdev_ext_mech_batch *b) { return b->key; }
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b) { (void)b; return 7; }
static u32 xdev_ext_mech_batch_bytes(struct xdev_ext_mech_batch *b) { (void)b; return 1024; }
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { (void)b; return 2; }
static int xsk_rel_packet_check(struct xdev_ext_mech_stage *st, const struct xdp_desc *d,
 const struct xdev_ext_mech_frame_info *fi, u8 *chunk, u64 g, u32 a, u64 credit, u8 type, u32 index)
{ (void)st; (void)d; (void)fi; (void)chunk; (void)g; (void)a; (void)credit; (void)type; (void)index;
  payload_passes++; return 0; }
static void xsk_xdev_ext_mech_tx_finish(u8 *pkt) { (void)pkt; }
static u64 ktime_get_ns(void) { return 1; }
static int xsk_rel_enqueue(struct xdev_ext_mech_stage *st, struct xsk_xdev_ext_mech_tx_batch *tb,
 const struct xdp_desc *d, u32 count) { (void)st; (void)tb; (void)d; (void)count; enqueues++; return 0; }
static void xsk_rel_wakeup(struct xdev_ext_mech_stage *st) { (void)st; }
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) { (void)st; }
/* PRODUCTION_VALIDATE */
/* PRODUCTION_SUBMIT */
static unsigned checks, failures;
#define EXPECT(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __func__, __LINE__, #c); } } while (0)
int main(void)
{
 static u8 frame[2][4096];
 struct xsk_mech_reliable r = { 0 };
 struct xsk_xdev_ext_mech_provider p = { 0 };
 struct xdev_ext_mech_session s = { .pool = { .priv = &p } };
 struct xsk_xdev_ext_mech_stage x = { .rel = &r, .tx_n = 2, .tx_kaddr = { frame[0], frame[1] },
  .tx_pkt = { frame[0], frame[1] } };
 struct xdev_ext_mech_stage st = { .priv = &x, .s = &s };
 struct xdev_ext_mech_batch b3 = { .key = 3 };
 struct xdev_ext_rel_cfg cfg = { .session = 7, .first_group = 1, .timeout_ns = 100, .window = 2,
  .max_attempts = 3, .group_bytes = 1024, .seg_len = 512 };
 struct xdev_ext_rel_msg ack = { .session = 7, .group = 1, .attempt = 1, .type = XDEV_EXT_REL_ACK, .credit = 4 };
 unsigned tick;

 EXPECT(!xdev_ext_rel_tx_init(&r.tx, &cfg));
 EXPECT(xdev_ext_rel_tx_open(&r.tx, 1, 1024, 2) == XDEV_EXT_REL_SEND);
 EXPECT(xdev_ext_rel_tx_open(&r.tx, 2, 1024, 2) == XDEV_EXT_REL_SEND);
 EXPECT(xdev_ext_rel_tx_native_begin(&r.tx, 1, 0) == XDEV_EXT_REL_SEND);
 EXPECT(xdev_ext_rel_tx_native_done(&r.tx, 1, 1, 0, false, 0) == XDEV_EXT_REL_NONE);
 /* Group 3 waits for credit across several core retry ticks. */
 for (tick = 0; tick < 4; tick++) {
  EXPECT(!xsk_rel_validate_initial(&st, &b3));
  EXPECT(xsk_rel_submit(&st, &b3) == -EAGAIN);
 }
 EXPECT(payload_passes == 0 && enqueues == 0);
 /* Credit arrives after validate but before submit: still refused. */
 EXPECT(!xsk_rel_validate_initial(&st, &b3));
 EXPECT(xdev_ext_rel_tx_ack(&r.tx, &ack) == XDEV_EXT_REL_COMPLETE);
 EXPECT(!xdev_ext_rel_tx_retire(&r.tx, 1));
 EXPECT(xsk_rel_submit(&st, &b3) == -EAGAIN);
 EXPECT(payload_passes == 0 && enqueues == 0);
 /* Next tick: one C pass per frame, then the checked bytes are enqueued. */
 EXPECT(!xsk_rel_validate_initial(&st, &b3));
 EXPECT(payload_passes == 2);
 EXPECT(!xsk_rel_submit(&st, &b3));
 EXPECT(enqueues == 1 && r.data[1].batch == &b3);
 printf("backpressure payload passes: %u checks, %u failures\n", checks, failures);
 return failures != 0;
}
'''


class BackpressureSkipsPayload(unittest.TestCase):
    def test_refused_attempt_has_no_payload_pass(self):
        source = FIXTURE.replace('/* PRODUCTION_VALIDATE */', body(INC, 'static int xsk_rel_validate_initial('))
        source = source.replace('/* PRODUCTION_SUBMIT */', body(INC, 'static int xsk_rel_submit('))
        with tempfile.TemporaryDirectory(prefix='xdev_ext-rel-backpressure-') as tmp:
            path = Path(tmp)
            (path / 'probe.c').write_text(source)
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                                    '-Werror', '-Wno-unused-function', '-fsanitize=undefined',
                                    '-fno-sanitize-recover=undefined', '-I', str(ROOT),
                                    str(path / 'probe.c'), '-o', str(path / 'probe')],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(path / 'probe')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
