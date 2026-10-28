#!/usr/bin/env python3
"""Real mixed reliable-RX/legacy-TX STOP through FIFO and core publication."""
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ.get('KERNEL_DIR',str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
HERE=Path(__file__).resolve().parent
MAIN=r'''
static unsigned build_calls;
static int xdev_ext_mech_stage_native_get(struct xdev_ext_mech_stage *st) {(void)st;build_calls++;return -ESHUTDOWN;}
static bool xdev_ext_mech_session_admits(struct fake_session *s) {return xdev_ext_mech_sess_admits(&s->ss);}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) {return b->priv;}
static int xsk_rel_build(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,struct xsk_rel_control *c,u64 group,u32 attempt,u64 credit)
{(void)st;(void)b;(void)c;(void)group;(void)attempt;(void)credit;build_calls++;return -EINVAL;}
static int xsk_rel_enqueue(struct xdev_ext_mech_stage *st,struct xsk_xdev_ext_mech_tx_batch *tb,const struct xdp_desc *d,u32 n)
{(void)st;(void)tb;(void)d;(void)n;build_calls++;return -EINVAL;}
static void xsk_rel_wakeup(struct xdev_ext_mech_stage *st) {(void)st;build_calls++;}
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define nsecs_to_jiffies(n) ((unsigned long)(n))
/* PRODUCTION_PROGRESS */
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(int argc,char **argv) {
 const char *mode=argc>1?argv[1]:"pending";
 bool prefix=!strncmp(mode,"prefix",6),native=!strcmp(mode,"native"),unknown=!strcmp(mode,"unknown");
 struct xdev_ext_mech_create mixed={.abi_version=1,.nr_stages=2,.pool_kind=XDEV_EXT_MECH_POOL_XSK,.pool_fd=5,.depth=1,.eventfd=-1,
 .layout={.frame_size=4096,.seg_len=16,.group_bytes=16},.st={{.class_id=XDEV_EXT_MECH_CLASS_AFXDP,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE,.fd=5,.flags=XDEV_EXT_AFXDP_F_RELIABLE},
 {.class_id=XDEV_EXT_MECH_CLASS_AFXDP,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE,.fd=5}}};u32 frames;
 CHECK(!xdev_ext_mech_create_check(&mixed,&frames));
 struct fake_xp xp={.dev=(void *)1,.dma_pages=(void *)1};struct xdp_sock xs={0};struct xsk_mech_zc_slot slots[4]={0};
 struct xsk_xdev_ext_mech_provider p={.xp=&xp,.xs=&xs,.slots=slots,.ring={.capacity=4}};
 struct fake_session s={.pool={.priv=&p},.ss={.state=XDEV_EXT_MECH_SESSION_STOPPING}};
 struct xsk_mech_reliable r={0};struct xdev_ext_rel_cfg cfg={.session=17,.first_group=1,.timeout_ns=10,.window=1,.max_attempts=3,.group_bytes=16,.seg_len=16};
 CHECK(!xdev_ext_rel_tx_init(&r.tx,&cfg)&&!xdev_ext_rel_rx_init(&r.rx,&cfg));
 struct xsk_xdev_ext_mech_stage rx={.rel=&r},tx={.rel=NULL};
 struct xdev_ext_mech_stage rx_st={.s=&s,.priv=&rx},tx_st={.s=&s,.priv=&tx};xs.xdev_ext_mech_rx=&rx_st;xs.xdev_ext_mech_tx=&tx_st;
 struct xdev_ext_mech_batch b={.s=&s};xdev_ext_mech_completion_init(&b.completion);CHECK(!xdev_ext_mech_completion_begin(&b.completion,&b.ticket));
 struct xsk_xdev_ext_mech_tx_batch tb={.batch=&b,.ticket=b.ticket,.completion={.pending=prefix?2:1}};
 tb.done.next=tb.done.prev=&tb.done;b.priv=&tb;p.ring.prod=prefix?2:1;
 for(u32 i=0;i<p.ring.prod;i++)slots[i]=(struct xsk_mech_zc_slot){.batch=&tb,.slot=i,.state=XSK_MECH_ZC_PENDING};
 struct xsk_buff_pool pool={.xdev_ext_mech_tx=&p};
 if(prefix||native||unknown)CHECK(xsk_mech_zc_peek(&p.ring,slots)==0);
 if(!native&&!unknown)CHECK(!xsk_rel_progress(&rx_st)); /* real mixed-stage STOP caller */
 if(prefix||native||unknown) {
  tb.completion.uncertain=unknown;
  CHECK(!xsk_xdev_ext_mech_tx_complete(&pool,1,!strcmp(mode,"prefix-ok")?0:!strcmp(mode,"prefix-error")?-EIO:-ECANCELED,false,false));
 }
 int status=0;CHECK(!xdev_ext_mech_completion_consume(&b.completion,b.ticket,&status));
 bool real_error=native||unknown||!strcmp(mode,"prefix-error");
 int expected=!strcmp(mode,"prefix-error")?-EIO:-ECANCELED;
 CHECK(s.last_err==(real_error?expected:0));CHECK(status==expected);
 CHECK(b.sequester==unknown);CHECK(b.queued==1);CHECK(!wrong_locked_dead&&!build_calls&&!p.tx_lock);
 return 0;
}
'''
class LegacyCancel(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  spec=importlib.util.spec_from_file_location('legacy_native_base',HERE/'native_ack_test.py')
  base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
  base.NativeAck.setUpClass();cls.addClassCleanup(base.NativeAck.tmp.cleanup)
  source=(Path(base.NativeAck.tmp.name)/'probe.c').read_text().split('int main(',1)[0]
  source=source.replace('#include "net/xdp/xsk_xdev_ext_mech_zc_core.h"','#include "net/xdp/xsk_xdev_ext_mech_zc_core.h"\n#include "io_uring/xdev_ext_mech_step.h"\n#include "io_uring/xdev_ext_mech_lifecycle.h"')
  source=source.replace('struct xdev_ext_mech_batch { u64 group; };','struct xdev_ext_mech_batch {u64 group;__u64 ticket;struct xdev_ext_mech_completion completion;struct fake_session *s;void *priv;bool locally_cancelled,sequester;u32 queued;};')
  source=source.replace('int native_controls,last_err;','int native_controls,last_err,lock;struct xdev_ext_mech_sess ss;')
  source=source.replace('struct xsk_rel_data { u32 count;','struct xsk_rel_data {struct xdev_ext_mech_batch *batch;u64 ticket;u32 count;')
  source=source.replace('struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xsk_rel_data data[32]; };','struct xsk_mech_reliable {struct xdev_ext_rel_tx tx;struct xdev_ext_rel_rx rx;struct xsk_rel_data data[32];struct xsk_rel_control control[32];struct xdp_desc scratch[32];u64 ack_pending[32];};')
  # Completion publication now calls the real lifecycle handoff. This legacy
  # FIFO fixture has no lifecycle frames or transform, but still executes the
  # actual handoff/sync/trim bodies, with typed empty pool callbacks.
  source='#define xdev_ext_mech_session fake_session\n'+source
  source=source.replace('#include "io_uring/xdev_ext_mech_lifecycle.h"',
   '#include "io_uring/xdev_ext_mech_lifecycle.h"\n#include "io_uring/xdev_ext_mech_produced.h"\n#define BIT(n) (1U<<(n))\n#define min(a,b) ((a)<(b)?(a):(b))')
  frame='struct xdev_ext_mech_frame { u32 index; u64 umem_addr; u32 data_off,data_len; };'
  assert frame in source
  source=source.replace(frame,'')
  batch='struct xdev_ext_mech_batch {u64 group;'
  source=source.replace(batch,frame+'\n'+batch)
  source=source.replace('u32 queued;};',
   'u32 queued,life_active,nr_frames,produced,produced_used,bytes;bool producing,produced_set;'
   'u64 life_token[XDEV_EXT_MECH_MAX_FRAMES];struct xdev_ext_mech_bstate bs;'
   'struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];'
   'struct {struct xdev_ext_mech_frame dst[XDEV_EXT_MECH_MAX_FRAMES];u64 token[XDEV_EXT_MECH_MAX_FRAMES];u32 nr,produced;bool active;} transform;};')
  source=source.replace('struct xdev_ext_mech_pool {',
   'struct xdev_ext_mech_pool;\nstruct xdev_ext_mech_pool_ops {'
   'void (*sync_for_cpu)(struct xdev_ext_mech_pool *,const struct xdev_ext_mech_frame *);'
   'void (*sync_for_cpu_batch)(struct xdev_ext_mech_pool *,const struct xdev_ext_mech_frame *,u32);};\n'
   'static const struct xdev_ext_mech_pool_ops legacy_pool_ops;\nstruct xdev_ext_mech_pool {const struct xdev_ext_mech_pool_ops *ops;')
  source=source.replace('struct xdev_ext_mech_sess ss;',
   'struct xdev_ext_mech_sess ss;u32 nr_stages;struct xdev_ext_mech_stage_uapi plan[XDEV_EXT_MECH_MAX_STAGES];struct xdev_ext_mech_life *life;')
  core=(ROOT/'io_uring/xdev_ext_mech.c').read_text()
  functions='\n'.join(base.function(core,n) for n in ('xdev_ext_mech_sync_for_cpu','xdev_ext_mech_trim_produced','xdev_ext_mech_batch_handoff','xdev_ext_mech_batch_completion_claim','xdev_ext_mech_batch_completion_publish','xdev_ext_mech_batch_complete','xdev_ext_mech_batch_complete_cancelled','xdev_ext_mech_batch_sequester'))
  for name in ('xdev_ext_mech_batch_complete','xdev_ext_mech_batch_complete_cancelled','xdev_ext_mech_batch_sequester'):
   source=re.sub(r'static void '+name+r'\([^)]*\)\s*\{[^}]*\}', '', source)
  index=source.index('static void xsk_rel_native_done(')
  source=source[:index]+'static void xdev_ext_mech_batch_queue(struct xdev_ext_mech_batch *b) {b->queued++;}\n'+functions+'\n'+source[index:]
  rel=(ROOT/'net/xdp/xsk_xdev_ext_mech_reliable.inc').read_text()
  progress=re.search(r'^static unsigned long xsk_rel_progress\([^;{}]*\)\s*\{.*?^\}',rel,re.M|re.S)[0]
  source+=MAIN.replace('.pool={.priv=&p}', '.pool={.priv=&p,.ops=&legacy_pool_ops}').replace('/* PRODUCTION_PROGRESS */',progress)
  cls.tmp=tempfile.TemporaryDirectory(prefix='legacy-mixed-cancel-');cls.addClassCleanup(cls.tmp.cleanup)
  p=Path(cls.tmp.name);(p/'probe.c').write_text(source);cls.binary=p/'probe'
  subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fsanitize=undefined','-fno-sanitize-recover=undefined','-I',str(ROOT),str(p/'probe.c'),'-o',str(cls.binary)],check=True)
 def test_real_mixed_stage_stop_and_native_prefix(self):
  for mode in ('pending','prefix-ok','prefix-error','native','unknown'):
   with self.subTest(mode=mode):
    r=subprocess.run([str(self.binary),mode],capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
