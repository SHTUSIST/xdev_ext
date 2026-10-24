#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the real worker selection/dispatch code with recording call boundaries."""
import unittest
import glue_common as G

FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include "include/linux/xdev_ext_mech_reliable_core.h"
typedef __u64 u64; typedef __u32 u32; typedef __s32 s32; typedef __u8 u8;
#define XDEV_EXT_MECH_MEMBER_BUILD 1
#define XDEV_EXT_MECH_SITE_WORKER_SELECT 6
#define XDEV_EXT_MECH_F_HELD 1
#define XDEV_EXT_MECH_F_INFLIGHT 2
#define max_t(t,a,b) ((t)(a)>(t)(b)?(t)(a):(t)(b))
#define spin_lock_irqsave(lock,flags) do{(void)(lock);(flags)=0;}while(0)
#define spin_unlock_irqrestore(lock,flags) do{(void)(lock);(void)(flags);}while(0)
struct xdp_desc {u64 addr;u32 len,options;};
struct xdev_ext_mech_batch {int unused;};
struct xsk_xdev_ext_mech_tx_batch {int unused;};
struct xdev_ext_mech_frame {u8 *kaddr;u64 umem_addr;u32 index;};
struct xsk_rel_control {struct xsk_xdev_ext_mech_tx_batch tb;struct xdev_ext_mech_frame frame;bool busy;};
struct xsk_rel_data {struct xdev_ext_mech_batch *batch;u64 ticket;};
struct xsk_mech_reliable {
 struct xdev_ext_rel_tx tx;struct xdev_ext_rel_rx rx;struct xdev_ext_rel_tx_view select_view;
 struct xsk_rel_data data[32];struct xsk_rel_control control[32];
 u64 ack_pending[32],owed_since[32];u8 owed_dup[32];struct xdp_desc scratch[32];
};
struct xsk_xdev_ext_mech_stage {struct xsk_mech_reliable *rel;bool dead;};
struct xsk_xdev_ext_mech_provider {int tx_lock;};
struct xdev_ext_mech_pool {void *priv;};
struct xdev_ext_mech_stage {struct xsk_xdev_ext_mech_stage *priv;struct xdev_ext_mech_pool *s;};
struct xdev_ext_binding_ctx_v2 {u64 unused;};
struct xdev_ext_mech_call_args {u32 member,callsite,info_size;void *base,*info;};
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_pool *s){return s;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_pool *s){return true;}
static void xsk_mech_zc_cancel_pending(void *p,int err){}
static void xdev_ext_mech_batch_sequester(void *b,u64 ticket,int err){}
static void xdev_ext_mech_batch_complete_cancelled(void *b,u64 ticket,int err){}
static void xdev_ext_mech_batch_complete(void *b,u64 ticket,int err){}
static u64 ktime_get_ns(void){return 100;}
static unsigned long nsecs_to_jiffies(u64 n){return n;}
static unsigned calls,resends,builds;static int chosen,call_error,dead_error,envelope_error,build_result=-EPROTO;
static u64 sent_group;static u32 sent_slot;
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err){dead_error=err;}
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_call_args *a,s32 *ret,void *q) {
 const struct xdev_ext_rel_tx_view *v=a->info;
 calls++;*ret=chosen;
 if(a->member!=1||a->callsite!=6||a->info!=&st->priv->rel->select_view||
    a->info_size!=sizeof(*v)||!a->base||v->count!=2||v->window!=4||
    v->candidate[0].group!=1||v->candidate[0].slot!=1||v->candidate[0].attempt!=2||
    v->candidate[1].group!=2||v->candidate[1].slot!=2)envelope_error++;
 return call_error;
}
static int xsk_rel_resend(struct xdev_ext_mech_stage *st,u32 slot,u64 group,u64 now,bool *wake) {
 resends++;sent_slot=slot;sent_group=group;return 0;
}
static int xsk_rel_build(struct xdev_ext_mech_stage *st,void *b,void *c,u64 group,u32 attempt,u64 credit){builds++;return build_result;}
static int xdev_ext_mech_stage_native_get(struct xdev_ext_mech_stage *st){return -ESHUTDOWN;}
static void xdev_ext_mech_stage_native_put(struct xdev_ext_mech_stage *st){}
static int xsk_rel_enqueue(struct xdev_ext_mech_stage *st,void *tb,void *desc,u32 count){return -EPROTO;}
static void xdev_ext_mech_pool_frame_move(void *p,u32 i,u32 from,u32 to){}
static void xsk_rel_owed_covered(struct xsk_mech_reliable *r,u64 group){}
static void xsk_rel_wakeup(struct xdev_ext_mech_stage *st){}
/* BODY */
int main(void) {
 struct xdev_ext_rel_cfg cfg={.session=9,.first_group=1,.timeout_ns=10,.window=4,
  .max_attempts=8,.group_bytes=512,.seg_len=512};
 struct xsk_mech_reliable r;struct xsk_xdev_ext_mech_stage xst={.rel=&r};
 struct xsk_xdev_ext_mech_provider provider={0};struct xdev_ext_mech_pool pool={.priv=&provider};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&pool};struct xdev_ext_mech_batch b[2];
 unsigned checks=0,fail=0,i,test;
#define CHECK(c) do{checks++;if(!(c)){fail++;fprintf(stderr,"FAIL %d %s\n",__LINE__,#c);}}while(0)
 for(test=0;test<7;test++) {
  memset(&r,0,sizeof(r));xdev_ext_rel_tx_init(&r.tx,&cfg);xdev_ext_rel_rx_init(&r.rx,&cfg);
  calls=resends=builds=0;dead_error=envelope_error=call_error=0;chosen=3;
  for(i=0;i<2;i++){r.data[i+1].batch=&b[i];xdev_ext_rel_tx_open(&r.tx,i+1,512,1);
   xdev_ext_rel_tx_native_begin(&r.tx,i+1,0);xdev_ext_rel_tx_native_done(&r.tx,i+1,1,0,false,0);}
  if(test==1)chosen=5; /* outside configured window */
  if(test==2)chosen=1; /* valid slot, absent from frozen candidates */
  if(test==3)chosen=-EINVAL;
  if(test==4)call_error=-EIO;
  if(test==5)chosen=0;
  if(test==6){r.tx.entry[1].native_pending=1;r.tx.entry[2].deadline_ns=101;}
  xsk_rel_progress(&st);
  CHECK(builds==0);CHECK(!envelope_error);CHECK(calls==(test==6?0:1));
  if(!test){CHECK(resends==1&&sent_group==2&&sent_slot==2);CHECK(!dead_error);}
  else if(test<5){CHECK(!resends);CHECK(dead_error==(test==4?-EIO:-EPROTO));}
  else {CHECK(!resends&&!dead_error);if(test==5)CHECK(r.tx.entry[1].declined==1&&r.tx.entry[2].declined==1);}
 }
 /* A deferred reply remains owed and the real worker rearms for its remaining delay. */
 for(test=0;test<2;test++) {
  unsigned long delay;
  memset(&r,0,sizeof(r));cfg.timeout_ns=100;cfg.ack_delay_ns=10;
  xdev_ext_rel_tx_init(&r.tx,&cfg);xdev_ext_rel_rx_init(&r.rx,&cfg);
  calls=builds=0;dead_error=0;build_result=1;
  r.ack_pending[1]=1;r.owed_since[1]=test?80:99;
  delay=xsk_rel_progress(&st);
  CHECK(delay==(test?1:9));CHECK(!calls&&builds==1&&!dead_error);
  CHECK(r.ack_pending[1]==1&&r.owed_since[1]==(test?80:99));
 }
 printf("progress selection: %u checks, %u failures\n",checks,fail);return fail!=0;
}
'''

class ProgressBoundary(unittest.TestCase):
    def test_actual_worker_rejects_selection_outside_snapshot(self):
        body = G.require(G.default_text(G.INC), 'xsk_rel_progress', 'provider')
        G.build_and_run(self, FIXTURE.replace('/* BODY */', body), name='progress-selection')

if __name__ == '__main__':
    unittest.main(verbosity=2)
