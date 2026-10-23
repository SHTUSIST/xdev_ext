#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""A failed receiver device chain must end the receiver session (AF-2).

The reliable receiver turns a failed NVMe/CE/IAA stage into a FAILED group.
That group is never ACKed and pins receiver credit, so a session that stayed
ACTIVE would admit at most window-1 later groups and then recycle all traffic
while reporting ACTIVE. Executes the production xsk_rel_batch_end() and the
production xdev_ext_mech_stage_dead(); only locks, accessors and the session
stop primitive are shims. RELIABLE_INC selects another .inc (RED runs).
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
typedef uint64_t u64; typedef uint32_t u32;
#include "include/linux/xdev_ext_mech_reliable_core.h"
#define XDEV_EXT_MECH_DIR_FROM_DEVICE 1
#define spin_lock_irqsave(l,f) ((void)(l),(void)((f)=0))
#define spin_unlock_irqrestore(l,f) ((void)(l),(void)(f))
enum { ACTIVE = 1, STOPPING = 3 };
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops { void (*mark_dead)(struct xdev_ext_mech_stage *st); };
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xdev_ext_rel_rx rx; u64 ack_pending[32]; };
struct xsk_xdev_ext_mech_provider { int tx_lock; };
struct xdev_ext_mech_pool { struct xsk_xdev_ext_mech_provider *priv; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; int state, stop_err; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; };
struct xdev_ext_mech_stage { void *priv; struct xdev_ext_mech_session *s; u32 direction;
 const struct xdev_ext_mech_class_ops *cls; int dead; };
struct xdev_ext_mech_batch { u64 key; struct xdev_ext_mech_stage *at; };
static int kicks;
static u64 xdev_ext_mech_batch_key(const struct xdev_ext_mech_batch *b) { return b->key; }
static struct xdev_ext_mech_stage *xdev_ext_mech_batch_stage(const struct xdev_ext_mech_batch *b) { return b->at; }
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s) { return s->state == ACTIVE; }
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) { (void)st; kicks++; }
/* Core primitive: closes admission and records the first reason. */
static void xdev_ext_mech_session_stop(struct xdev_ext_mech_session *s, int err)
{ s->state = STOPPING; if (err && !s->stop_err) s->stop_err = err; }
static void mark_dead(struct xdev_ext_mech_stage *st) { st->dead++; }
#define EXPORT_SYMBOL_GPL(x)
/* PRODUCTION_STAGE_DEAD */
/* PRODUCTION_BATCH_END */
static unsigned checks, failures;
#define EXPECT(c) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s:%d %s\n", __func__, __LINE__, #c); } } while (0)
static const struct xdev_ext_rel_cfg cfg = { .session = 9, .first_group = 1, .timeout_ns = 100,
 .window = 4, .max_attempts = 3, .group_bytes = 8192, .seg_len = 1408 };
static const struct xdev_ext_mech_class_ops afxdp_ops = { .mark_dead = mark_dead }, nvme_ops = { .mark_dead = mark_dead };
struct world { struct xsk_mech_reliable r; struct xsk_xdev_ext_mech_provider p; struct xdev_ext_mech_session s;
 struct xsk_xdev_ext_mech_stage x; struct xdev_ext_mech_stage rx, nvme; };
static void submitted(struct world *w, u64 g)
{
 unsigned i;
 for (i = 0; i < 6; i++) {
  struct xdev_ext_rel_msg m = { .session = 9, .group = g, .attempt = 1, .type = XDEV_EXT_REL_DATA,
   .total_len = 8192, .index = i, .count = 6, .relative_offset = i * 1408,
   .payload_len = i == 5 ? 1152 : 1408 };
  xdev_ext_rel_rx_commit(&w->r.rx, &m);
 }
}
static void init(struct world *w)
{
 memset(w, 0, sizeof(*w));
 xdev_ext_rel_rx_init(&w->r.rx, &cfg);
 w->s = (struct xdev_ext_mech_session){ .pool = { .priv = &w->p }, .state = ACTIVE };
 w->x.rel = &w->r;
 w->rx = (struct xdev_ext_mech_stage){ .priv = &w->x, .s = &w->s, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .cls = &afxdp_ops };
 w->nvme = (struct xdev_ext_mech_stage){ .s = &w->s, .cls = &nvme_ops };
 kicks = 0;
}
static void failed_device_stage_ends_session(void)
{
 struct world w; struct xdev_ext_mech_batch b = { .key = 1 };
 init(&w); b.at = &w.nvme; submitted(&w, 1);
 xsk_rel_batch_end(&w.rx, &b, -EIO);
 EXPECT(w.r.rx.entry[1].state == XDEV_EXT_REL_RX_FAILED);
 EXPECT(!w.r.ack_pending[1]);
 EXPECT(w.s.state == STOPPING && w.s.stop_err == -EIO);
 EXPECT(w.nvme.dead == 1 && w.rx.dead == 0);
}
static void stop_cancellation_is_not_a_device_failure(void)
{
 struct world w; struct xdev_ext_mech_batch b = { .key = 1 };
 init(&w); b.at = &w.nvme; submitted(&w, 1);
 w.s.state = STOPPING;
 xsk_rel_batch_end(&w.rx, &b, -ECANCELED);
 EXPECT(w.r.rx.entry[1].state == XDEV_EXT_REL_RX_FAILED);
 EXPECT(w.s.stop_err == 0 && w.nvme.dead == 0 && w.rx.dead == 0);
}
static void completed_chain_acks_and_stays_active(void)
{
 struct world w; struct xdev_ext_mech_batch b = { .key = 1 };
 init(&w); b.at = &w.nvme; submitted(&w, 1);
 xsk_rel_batch_end(&w.rx, &b, 0);
 EXPECT(w.r.ack_pending[1] == 1 && kicks == 1);
 EXPECT(w.s.state == ACTIVE && w.nvme.dead == 0);
}
static void incomplete_group_end_does_not_stop(void)
{
 struct world w; struct xdev_ext_mech_batch b = { .key = 2 };
 init(&w); b.at = &w.nvme;
 /* No SUBMITTED group 2: finish is STALE, owned by the group timer path. */
 xsk_rel_batch_end(&w.rx, &b, -ETIMEDOUT);
 EXPECT(w.s.state == ACTIVE && w.nvme.dead == 0);
}
int main(void)
{
 failed_device_stage_ends_session();
 stop_cancellation_is_not_a_device_failure();
 completed_chain_acks_and_stays_active();
 incomplete_group_end_does_not_stop();
 printf("downstream failure terminal: %u checks, %u failures\n", checks, failures);
 return failures != 0;
}
'''


class DownstreamFailureTerminal(unittest.TestCase):
    def test_failed_chain_stops_receiver_session(self):
        source = FIXTURE.replace('/* PRODUCTION_STAGE_DEAD */',
                                 body(ROOT / 'io_uring/xdev_ext_mech.c', 'void xdev_ext_mech_stage_dead('))
        source = source.replace('/* PRODUCTION_BATCH_END */',
                                body(INC, 'static void xsk_rel_batch_end('))
        with tempfile.TemporaryDirectory(prefix='xdev_ext-rel-terminal-') as tmp:
            path = Path(tmp)
            (path / 'probe.c').write_text(source)
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-Wno-unused-function', '-fsanitize=undefined',
                            '-fno-sanitize-recover=undefined', '-I', str(ROOT),
                            str(path / 'probe.c'), '-o', str(path / 'probe')], check=True)
            run = subprocess.run([str(path / 'probe')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
