#!/usr/bin/env python3
"""Run the production native-done body after DMA-map teardown.

The deterministic schedule is: journal retirement has moved a completed batch
to its local done list; pool_dead returns; xp_dma_unmap clears the map; the
local done-list callback resumes. Only external kernel APIs/types are shims.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get("KERNEL_DIR", str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
FIXTURE = r'''
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;
#include "include/linux/xdev_ext_mech_reliable_core.h"
#define XDEV_EXT_MECH_F_INFLIGHT 1
#define XDEV_EXT_MECH_F_HELD 2
#define DMA_BIDIRECTIONAL 0
#define container_of(p, type, field) ((type *)((char *)(p)-offsetof(type, field)))
#define spin_lock_irqsave(p,f) do { (void)(p); (f)=0; } while (0)
#define spin_unlock_irqrestore(p,f) do { (void)(p); (void)(f); } while (0)
struct xdp_desc { u64 addr; u32 len; };
struct xdev_ext_mech_batch { u64 group; };
struct xdev_ext_mech_frame { u32 index; u64 umem_addr; u32 data_off; };
struct xsk_mech_zc_batch { bool uncertain; int status; };
struct xdev_ext_mech_stage;
struct xsk_xdev_ext_mech_tx_batch {
 struct xdev_ext_mech_stage *reliable_stage;
 bool control, cancelled_before_native;
 int native_error;
 struct xsk_mech_zc_batch completion;
 struct xdev_ext_mech_batch *batch;
 u32 attempt;
};
struct xsk_rel_data { u32 count; struct xdp_desc desc[32]; };
struct xsk_rel_control {
 struct xsk_xdev_ext_mech_tx_batch tb;
 struct xdev_ext_mech_frame frame;
 bool busy, uncertain;
};
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xsk_rel_data data[32]; };
struct fake_xp { void *dev, *dma_pages; };
struct xsk_xdev_ext_mech_provider { struct fake_xp *xp; bool stopped; int tx_lock; };
struct xdev_ext_mech_pool { struct xsk_xdev_ext_mech_provider *priv; };
struct fake_session { struct xdev_ext_mech_pool pool; int native_controls; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; bool dead; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv; struct fake_session *s; };
static int invalid_map_reads, syncs, frame_moves, kicks;
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct fake_session *s) { return &s->pool; }
static u64 xdev_ext_mech_batch_key(struct xdev_ext_mech_batch *b) { return b->group; }
static u64 ktime_get_ns(void) { return 42; }
static u64 xp_raw_get_dma(struct fake_xp *xp, u64 address)
{
 if (!xp->dev || !xp->dma_pages) invalid_map_reads++;
 return address;
}
static void dma_sync_single_for_cpu(void *dev, u64 address, u32 len, int direction)
{ (void)dev; (void)address; (void)len; (void)direction; syncs++; }
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p, u32 index, int from, int to)
{ (void)p; (void)index; (void)from; (void)to; frame_moves++; return 0; }
static void xdev_ext_mech_stage_native_put(struct xdev_ext_mech_stage *st) { st->s->native_controls--; }
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) { (void)st; kicks++; }
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err) { (void)st;(void)err; }
/* PRODUCTION_NATIVE_DONE */
int main(int argc, char **argv)
{
 bool control=argc>1 && !strcmp(argv[1],"control");
 bool map_dead=argc>2 && !strcmp(argv[2],"dead");
 bool uncertain=argc>3 && !strcmp(argv[3],"uncertain");
 struct fake_xp xp={.dev=(void *)1,.dma_pages=(void *)1};
 struct xsk_xdev_ext_mech_provider p={.xp=&xp};
 struct fake_session s={.pool={.priv=&p},.native_controls=control};
 struct xsk_mech_reliable r={0};
 struct xsk_xdev_ext_mech_stage xst={.rel=&r};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&s};
 struct xdev_ext_mech_batch b={.group=1};
 struct xsk_rel_control c={.busy=true,.frame={.index=20,.data_off=384}};
 struct xsk_xdev_ext_mech_tx_batch data={0}, *tb=control ? &c.tb : &data;
 struct xdev_ext_rel_cfg cfg={.session=17,.first_group=1,.timeout_ns=10,
   .window=1,.max_attempts=3,.group_bytes=16,.seg_len=16};
 xdev_ext_rel_tx_init(&r.tx,&cfg);
 xdev_ext_rel_tx_open(&r.tx,1,16,1);
 xdev_ext_rel_tx_native_begin(&r.tx,1,0);
 r.data[0].count=1; r.data[0].desc[0].addr=384; r.data[0].desc[0].len=122;
 tb->reliable_stage=&st; tb->control=control; tb->batch=&b; tb->attempt=1;
 tb->completion.uncertain=uncertain;
 /* xp_dma_unmap has run after this tb left the protected journal. */
 if (map_dead) { p.stopped=true; xp.dev=NULL; xp.dma_pages=NULL; }
 xsk_rel_native_done(tb);
 printf("invalid_map_reads=%d syncs=%d frame_moves=%d native_controls=%d uncertain=%d busy=%d terminal=%d kicks=%d\n",
   invalid_map_reads,syncs,frame_moves,s.native_controls,c.uncertain,c.busy,r.tx.entry[0].terminal,kicks);
 return 0;
}
'''


class NativeDoneMapTeardown(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "net/xdp/xsk_xdev_ext_mech_reliable.inc").read_text()
        fn = re.search(r"^static void xsk_rel_native_done\([^)]*\)\s*\{.*?^\}",
                       source, re.M | re.S)
        if fn is None:
            raise RuntimeError("production native_done missing")
        cls.temp = tempfile.TemporaryDirectory(prefix="rel-native-done-")
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        (path / "probe.c").write_text(FIXTURE.replace("/* PRODUCTION_NATIVE_DONE */", fn[0]))
        cls.probe = path / "probe"
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", "-I", str(ROOT), str(path / "probe.c"),
                        "-o", str(cls.probe)], check=True)

    def run_case(self, kind, state, uncertain=False):
        p = subprocess.run([str(self.probe), kind, state,
                            "uncertain" if uncertain else "definite"],
                           check=True, text=True, capture_output=True)
        return {k: int(v) for k, v in (f.split("=") for f in p.stdout.split())}

    def test_data_live_map_normal_completion(self):
        r = self.run_case("data", "live")
        self.assertEqual(r["invalid_map_reads"], 0, r)
        self.assertEqual(r["syncs"], 1, r)

    def test_control_live_map_normal_completion(self):
        r = self.run_case("control", "live")
        self.assertEqual(r["invalid_map_reads"], 0, r)
        self.assertEqual((r["syncs"], r["native_controls"], r["busy"]), (1, 0, 0), r)

    def test_data_local_done_list_cannot_read_torn_down_map(self):
        r = self.run_case("data", "dead")
        self.assertEqual(r["invalid_map_reads"], 0, r)

    def test_control_local_done_list_cannot_read_torn_down_map(self):
        r = self.run_case("control", "dead")
        self.assertEqual(r["invalid_map_reads"], 0, r)

    def test_uncertain_control_keeps_native_ownership_after_map_teardown(self):
        r = self.run_case("control", "dead", True)
        self.assertEqual((r["invalid_map_reads"], r["syncs"]), (0, 0), r)
        self.assertEqual((r["native_controls"], r["uncertain"], r["busy"]), (1, 1, 1), r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
