#!/usr/bin/env python3
"""Production progress/queue/core helper extraction with STOP during ACK BUILD.

No substitute protocol implementation: the helper, progress, enqueue, native_get,
and core stop/drain/fate/put bodies are the active production code. The BPF BUILD
API shim pauses the worker at the deterministic competing STOP schedule.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(os.environ.get("KERNEL_DIR", str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
FIXTURE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint64_t u64; typedef uint32_t u32;
typedef uint64_t __u64; typedef uint32_t __u32;
typedef uint16_t __u16; typedef uint8_t __u8;
#include "include/linux/xdev_ext_mech_reliable_core.h"
#define XDEV_EXT_MECH_U32_MAX UINT32_MAX
enum { XDEV_EXT_MECH_SESSION_NONE, XDEV_EXT_MECH_SESSION_ACTIVE, XDEV_EXT_MECH_SESSION_ERROR,
 XDEV_EXT_MECH_SESSION_STOPPING, XDEV_EXT_MECH_SESSION_STOPPED, XDEV_EXT_MECH_SESSION_ZOMBIE };
struct xdev_ext_mech_sess { u32 state,refs,inflight,sequestered; };
enum { XDEV_EXT_MECH_REFS_KEEP, XDEV_EXT_MECH_REFS_RELEASE, XDEV_EXT_MECH_REFS_QUARANTINE };
/* CORE_HELPERS */
struct xdp_desc { u64 addr; u32 len; };
struct xdev_ext_mech_frame { u32 index; };
struct xdev_ext_mech_stage;
struct xsk_mech_zc_batch { u32 pending; };
struct xsk_xdev_ext_mech_tx_batch { int done; struct xsk_mech_zc_batch completion;
 struct xdev_ext_mech_stage *reliable_stage; u32 n,attempt; bool control,cancelled_before_native;int native_error; };
struct xdev_ext_mech_batch { struct xsk_xdev_ext_mech_tx_batch priv; };
struct xsk_rel_data { struct xdev_ext_mech_batch *batch; u64 ticket; u32 count;
 struct xdp_desc desc[32]; };
struct xsk_rel_control { struct xsk_xdev_ext_mech_tx_batch tb; struct xdev_ext_mech_frame frame;
 bool busy; };
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xdev_ext_rel_rx rx;
 struct xsk_rel_data data[32]; struct xsk_rel_control control[32];
 u64 ack_pending[32]; struct xdp_desc scratch[32]; };
struct xsk_mech_zc_slot { struct xdp_desc desc; void *batch; u32 slot; int state,owner; };
struct fake_ring { u32 capacity,prod; };
struct xsk_xdev_ext_mech_provider { int tx_lock; bool stopped; struct fake_ring ring;
 struct xsk_mech_zc_slot slots[32]; void *xp; };
struct xdev_ext_mech_pool { struct xsk_xdev_ext_mech_provider *priv; };
struct xdev_ext_mech_session { struct xdev_ext_mech_sess ss; int native_controls,drain_wq,lock;
 bool start_preparing,start_return_pending;
 bool worker_gone; struct xdev_ext_mech_pool pool; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; bool dead; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv; struct xdev_ext_mech_session *s; };
#define XDEV_EXT_MECH_F_HELD 1
#define XDEV_EXT_MECH_F_INFLIGHT 2
#define XSK_MECH_ZC_PENDING 1
#define XSK_MECH_ZC_CONTROL 1
#define XSK_MECH_ZC_DATA 0
#define spin_lock_irqsave(p,f) do { (void)(p); (f)=0; } while (0)
#define spin_unlock_irqrestore(p,f) do { (void)(p); (void)(f); } while (0)
#define atomic_read(p) (*(p))
#define atomic_inc(p) (++*(p))
#define INIT_LIST_HEAD(p) (*(p)=0)
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
static void wake_up(int *p) { (void)p; }
/* SETTLE */
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s);
static void xdev_ext_mech_stage_native_put(struct xdev_ext_mech_stage *st) { st->s->native_controls--; }
/* NATIVE_GET */
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s)
{ return s->ss.state==XDEV_EXT_MECH_SESSION_ACTIVE; }
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{ return &s->pool; }
static int xsk_mech_zc_reserve(struct fake_ring *r,u32 n,u32 *at)
{ *at=r->prod; r->prod+=n; return 0; }
static u64 xp_raw_get_dma(void *xp,u64 addr) { (void)xp; return addr; }
static void xp_dma_sync_for_device(void *xp,u64 addr,u32 len) { (void)xp;(void)addr;(void)len; }
/* ENQUEUE */
static int stopped_during_build, release_decided, last_ref;
static void xsk_mech_zc_cancel_pending(struct xsk_xdev_ext_mech_provider *p,int err)
{ (void)err; p->stopped=true; }
static void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch *b,u64 t,int e)
{ (void)b;(void)t;(void)e; }
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b,u64 t,int e)
{ (void)b;(void)t;(void)e; }
#define xdev_ext_mech_batch_complete_cancelled xdev_ext_mech_batch_complete
static u64 ktime_get_ns(void) { return 1; }
static struct xsk_xdev_ext_mech_tx_batch *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b)
{ return &b->priv; }
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err)
{ (void)err; st->priv->dead=true; }
static int xsk_rel_build(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,
 struct xsk_rel_control *c,u64 group,u32 attempt,u64 credit)
{
 (void)b;(void)c;(void)group;(void)attempt;(void)credit;
 if (stopped_during_build) {
  /* Another CPU executes the real destroy decision while BUILD is paused.
   * The worker's stop_work cannot run until this progress call returns. */
  xdev_ext_mech_sess_stop(&st->s->ss);
  xdev_ext_mech_settle_locked(st->s);
  release_decided=xdev_ext_mech_sess_ref_fate(&st->s->ss)==XDEV_EXT_MECH_REFS_RELEASE;
  last_ref=xdev_ext_mech_sess_put(&st->s->ss);
  if(last_ref) st->s->worker_gone=true;
 }
 return 0;
}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p,u32 i,int f,int t)
{ (void)p;(void)i;(void)f;(void)t;return 0; }
static void xsk_rel_wakeup(struct xdev_ext_mech_stage *st) { (void)st; }
static unsigned long nsecs_to_jiffies(u64 n) { return n; }
/* PROGRESS */
int main(int argc,char **argv)
{
 struct xsk_xdev_ext_mech_provider p={.ring={.capacity=32}};
 struct xdev_ext_mech_session s={.ss={.state=XDEV_EXT_MECH_SESSION_ACTIVE,.refs=1},.pool={.priv=&p}};
 struct xsk_mech_reliable r={0};
 struct xsk_xdev_ext_mech_stage xst={.rel=&r};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&s};
 struct xdev_ext_rel_cfg cfg={.session=17,.first_group=1,.timeout_ns=10,
  .window=1,.max_attempts=3,.group_bytes=16,.seg_len=16};
 (void)argv;
 stopped_during_build=argc>1;
 xdev_ext_rel_tx_init(&r.tx,&cfg); xdev_ext_rel_rx_init(&r.rx,&cfg);
 r.rx.entry[0].group=1; r.rx.entry[0].latest_attempt=1; r.rx.entry[0].state=XDEV_EXT_REL_RX_DONE;
 r.ack_pending[0]=1;
 r.control[0].tb.control=true;
 xsk_rel_progress(&st);
 printf("release_decided=%d last_ref=%d controls=%d queued=%u busy=%d state=%u\n",
  release_decided,last_ref,s.native_controls,p.ring.prod,r.control[0].busy,s.ss.state);
 return 0;
}
'''


def function(source, declaration):
    match = re.search(r"^" + re.escape(declaration) + r"\([^)]*\)\s*\{.*?^\}",
                      source, re.M | re.S)
    if not match:
        raise RuntimeError("production function absent: " + declaration)
    return match[0]


class ControlStopAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rel = (ROOT / "net/xdp/xsk_xdev_ext_mech_reliable.inc").read_text()
        core = (ROOT / "io_uring/xdev_ext_mech.c").read_text()
        helper = (ROOT / "io_uring/xdev_ext_mech_core.h").read_text()
        source = FIXTURE.replace("/* CORE_HELPERS */", "\n".join(
            function(helper, "static inline " + decl) for decl in (
                "int xdev_ext_mech_sess_stop", "int xdev_ext_mech_sess_drain",
                "int xdev_ext_mech_sess_ref_fate", "bool xdev_ext_mech_sess_put")))
        for marker, text in (
            ("SETTLE", function(core, "static void xdev_ext_mech_settle_locked")),
            ("NATIVE_GET", function(core, "int xdev_ext_mech_stage_native_get")),
            ("ENQUEUE", function(rel, "static int xsk_rel_enqueue")),
            ("PROGRESS", function(rel, "static unsigned long xsk_rel_progress"))):
            source = source.replace("/* " + marker + " */", text)
        cls.temp = tempfile.TemporaryDirectory(prefix="rel-control-stop-")
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        (path / "probe.c").write_text(source)
        cls.probe = path / "probe"
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=undefined", "-I", str(ROOT), str(path / "probe.c"),
                        "-o", str(cls.probe)], check=True)

    def run_case(self, race):
        p = subprocess.run([str(self.probe)] + (["stop-during-build"] if race else []),
                           check=True, text=True, capture_output=True)
        return {k: int(v) for k, v in (f.split("=") for f in p.stdout.split())}

    def test_normal_ack_takes_one_native_control(self):
        r = self.run_case(False)
        self.assertEqual((r["controls"], r["queued"], r["busy"]), (1, 1, 1), r)

    def test_stop_during_build_cannot_queue_after_release_decision(self):
        r = self.run_case(True)
        self.assertEqual((r["release_decided"], r["last_ref"]), (1, 1), r)
        self.assertEqual((r["controls"], r["queued"], r["busy"]), (0, 0, 0), r)


if __name__ == "__main__":
    unittest.main(verbosity=2)
