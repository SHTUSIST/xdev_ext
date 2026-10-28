#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Version 2 transport counters of the AF_XDP reliable provider (E17).

Executes the production xsk_rel_transport_counters() over state produced by
the production protocol helpers: two DATA retransmissions, one accepted HELD,
duplicate DATA counted by the receiver, and frames retained by groups that
have no ACK yet. Counters add into the caller's struct, so several stages of
one session sum. Also pins the append-only v2 UAPI layout. RELIABLE_INC
selects another .inc (RED runs).
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

FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"
typedef uint32_t u32; typedef uint64_t u64;
#define U32_MAX UINT32_MAX
#include "include/linux/xdev_ext_mech_reliable_core.h"
#define spin_lock_irqsave(l,f) ((void)(l),(void)((f)=0))
#define spin_unlock_irqrestore(l,f) ((void)(l),(void)(f))
struct xdev_ext_mech_batch { int unused; };
struct xsk_rel_data { struct xdev_ext_mech_batch *batch; u64 ticket; u32 count; };
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xdev_ext_rel_rx rx; struct xsk_rel_data data[32]; };
struct xsk_xdev_ext_mech_provider { int tx_lock; };
struct xdev_ext_mech_pool { struct xsk_xdev_ext_mech_provider *priv; };
struct xdev_ext_mech_session { struct xdev_ext_mech_pool pool; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv; struct xdev_ext_mech_session *s; };
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
/* PRODUCTION */
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)
int main(void)
{
 static struct xsk_mech_reliable r;
 struct xsk_xdev_ext_mech_provider p = { 0 };
 struct xdev_ext_mech_session s = { .pool = { .priv = &p } };
 struct xsk_xdev_ext_mech_stage x = { .rel = &r };
 struct xdev_ext_mech_stage st = { .priv = &x, .s = &s };
 struct xdev_ext_mech_transport_stats_v2 out = { 0 };
 struct xdev_ext_mech_batch b1, b2;
 struct xdev_ext_rel_cfg cfg = { .session = 9, .first_group = 1, .timeout_ns = 100, .window = 4,
  .max_attempts = 3, .group_bytes = 8192, .seg_len = 1408 };
 struct xdev_ext_rel_msg held = { .session = 9, .group = 1, .attempt = 3, .type = XDEV_EXT_REL_HELD, .credit = 5 };
 struct xdev_ext_rel_msg ack = { .session = 9, .group = 2, .attempt = 1, .type = XDEV_EXT_REL_ACK, .credit = 5 };
 unsigned a;

 CHECK(sizeof(struct xdev_ext_mech_transport_stats) == 32);
 CHECK(sizeof(out) == 64 && offsetof(struct xdev_ext_mech_transport_stats_v2, retransmits) == 32);
 CHECK(offsetof(struct xdev_ext_mech_transport_stats_v2, held_unacked) == 56);
 CHECK(XDEV_EXT_MECH_TRANSPORT_STATS_VERSION == 1 && XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_2 == 2);
 CHECK(!xdev_ext_rel_tx_init(&r.tx, &cfg) && !xdev_ext_rel_rx_init(&r.rx, &cfg));
 CHECK(xdev_ext_rel_tx_open(&r.tx, 1, 8192, 6) == XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_open(&r.tx, 2, 8192, 6) == XDEV_EXT_REL_SEND);
 for (a = 1; a <= 3; a++) {
  CHECK(xdev_ext_rel_tx_native_begin(&r.tx, 1, a * 100) == XDEV_EXT_REL_SEND);
  CHECK(xdev_ext_rel_tx_native_done(&r.tx, 1, a, 0, false, a * 100) == XDEV_EXT_REL_NONE);
 }
 CHECK(xdev_ext_rel_tx_native_begin(&r.tx, 2, 0) == XDEV_EXT_REL_SEND);
 CHECK(xdev_ext_rel_tx_native_done(&r.tx, 2, 1, 0, false, 0) == XDEV_EXT_REL_NONE);
 CHECK(xdev_ext_rel_tx_ack(&r.tx, &held) == XDEV_EXT_REL_NONE);
 CHECK(xdev_ext_rel_tx_ack(&r.tx, &ack) == XDEV_EXT_REL_COMPLETE);
 /* Group 1 retains 6 frames without an ACK; acked group 2 is not counted. */
 r.data[1] = (struct xsk_rel_data){ .batch = &b1, .count = 6 };
 r.data[2] = (struct xsk_rel_data){ .batch = &b2, .count = 6 };
 r.rx.dup_suppressed = 5;
 xsk_rel_transport_counters(&st, &out);
 CHECK(out.retransmits == 2 && out.held_acks == 1 && out.dup_suppressed == 5 && out.held_unacked == 6);
 CHECK(!out.v1.size && !out.v1.pending_acks && !out.rsvd2);
 /* A second stage of the same session adds to the caller's totals. */
 xsk_rel_transport_counters(&st, &out);
 CHECK(out.retransmits == 4 && out.held_acks == 2 && out.dup_suppressed == 10 && out.held_unacked == 12);
 out.held_unacked = UINT32_MAX - 1;
 xsk_rel_transport_counters(&st, &out);
 CHECK(out.held_unacked == UINT32_MAX);
 x.rel = NULL;
 memset(&out, 0, sizeof(out));
 xsk_rel_transport_counters(&st, &out);
 CHECK(!out.retransmits && !out.held_acks && !out.dup_suppressed && !out.held_unacked);
 puts("PASS transport counters");
 return 0;
}
'''


class TransportCounters(unittest.TestCase):
    def test_provider_counters(self):
        source = INC.read_text()
        match = re.search(r'^static void xsk_rel_transport_counters\([^;{}]*\)\s*\{.*?^\}', source, re.M | re.S)
        self.assertIsNotNone(match, 'production reliable transport counters absent')
        with tempfile.TemporaryDirectory(prefix='transport-counters-') as tmp:
            path = Path(tmp)
            (path / 'probe.c').write_text(FIXTURE.replace('/* PRODUCTION */', match[0]))
            build = subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-Wno-unused-function', '-fsanitize=undefined',
                                    '-fno-sanitize-recover=undefined', '-I', str(ROOT),
                                    str(path / 'probe.c'), '-o', str(path / 'probe')],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(path / 'probe')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
