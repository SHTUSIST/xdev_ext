#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the real sealed SELECT admission boundary; no protocol model."""
import unittest
import glue_common as G

FIXTURE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define XDEV_EXT_MECH_MAX_FRAMES 32
#define XDEV_EXT_MECH_MEMBER_PREPARE 0
#define XDEV_EXT_MECH_MEMBER_BUILD 1
#define XDEV_EXT_MECH_MEMBER_COMPLETE 2
#define XDEV_EXT_MECH_SITE_WORKER 0
#define XDEV_EXT_MECH_SITE_CREATE 4
#define XDEV_EXT_MECH_SITE_WORKER_SELECT 6
struct xdev_ext_mech_call_args {
 unsigned member,callsite,nr_frames,info_size,desc_size,desc_cap,cqe_size,cqe_cap;
 void *base,*frames,*info,*scratch,*b,*cqe;
};
/* BODY */
int main(void) {
 int obj,fail=0; unsigned i;
 struct xdev_ext_mech_call_args a={.member=1,.callsite=6,.base=&obj,.info=&obj,.info_size=528};
 if (!xdev_ext_mech_args_ok(&a)) fail++;
 for(i=0;i<9;i++) {
  struct xdev_ext_mech_call_args b=a;
  switch(i) {
   case 0:b.b=&obj;break; case 1:b.frames=&obj;break; case 2:b.nr_frames=1;break;
   case 3:b.scratch=&obj;break; case 4:b.desc_size=16;break; case 5:b.desc_cap=1;break;
   case 6:b.cqe=&obj;break;case 7:b.cqe_size=8;break;case 8:b.cqe_cap=1;break;
  }
  if(xdev_ext_mech_args_ok(&b)) fail++;
 }
 a.member=2; if(xdev_ext_mech_args_ok(&a)) fail++;
 a.member=0; if(xdev_ext_mech_args_ok(&a)) fail++;
 a.member=1;a.callsite=0;if(xdev_ext_mech_args_ok(&a)) fail++;
 printf("SELECT envelope: 13 checks, %d failures\n",fail);return fail!=0;
}
'''
class SelectBoundary(unittest.TestCase):
 def test_select_has_no_batch_or_payload_capability(self):
  text=(G.ROOT/'io_uring/xdev_ext_mech_ops.c').read_text()
  body=G.require(text,'xdev_ext_mech_args_ok','ops')
  G.build_and_run(self,FIXTURE.replace('/* BODY */',body),name='select-envelope')

RESEND_FIXTURE = r'''
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include "include/linux/xdev_ext_mech_reliable_core.h"
typedef __u64 u64; typedef __u32 u32;
struct xdp_desc { u64 addr; u32 len,options; };
struct xdev_ext_mech_batch { u64 key; void *priv; };
struct xsk_xdev_ext_mech_tx_batch { struct xdev_ext_mech_batch *batch; u32 attempt; };
struct xsk_rel_data { struct xdev_ext_mech_batch *batch; u64 ticket; u32 count; struct xdp_desc desc[32]; };
struct xsk_mech_reliable { struct xdev_ext_rel_tx tx; struct xsk_rel_data data[32]; struct xdp_desc scratch[32]; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; };
struct xsk_xdev_ext_mech_provider { int tx_lock; };
struct xdev_ext_mech_pool { void *priv; };
struct xdev_ext_mech_stage { struct xsk_xdev_ext_mech_stage *priv; struct xdev_ext_mech_pool *s; };
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_pool *p) {return p;}
static u64 xdev_ext_mech_batch_key(struct xdev_ext_mech_batch *b) {return b->key;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) {return b->priv;}
static u64 ktime_get_ns(void) {return 100;}
#define spin_lock_irqsave(lock,flags) do {(void)(lock);(flags)=0;}while(0)
#define spin_unlock_irqrestore(lock,flags) do {(void)(lock);(void)(flags);}while(0)
#define WARN_ON_ONCE(c) ((void)(c))
static unsigned builds,enqueues; static int mode; static u64 built,enqueued;
static int xsk_rel_build(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_batch *b,
 void *control,u64 group,u32 attempt,u64 credit) {
 struct xsk_mech_reliable *r=st->priv->rel;
 (void)control;(void)credit;builds++;built=b->key;
 if(b->key!=group || attempt!=2)return -EPROTO;
 r->scratch[0]=(struct xdp_desc){.addr=group*4096,.len=100+group};
 if(mode==1)r->tx.entry[group%4].acked=1;
 if(mode==2)r->tx.entry[group%4].native_pending=1;
 return mode==3 ? 1:0;
}
static int xsk_rel_enqueue(struct xdev_ext_mech_stage *st,struct xsk_xdev_ext_mech_tx_batch *tb,
 const struct xdp_desc *desc,u32 count) {
 (void)st;enqueues++;enqueued=tb->batch->key;
 return count==1 && desc[0].addr==tb->batch->key*4096 && desc[0].len==100+tb->batch->key ? 0:-EPROTO;
}
/* BODY */
int main(void) {
 struct xdev_ext_rel_cfg cfg={.session=9,.first_group=1,.timeout_ns=10,.window=4,
  .max_attempts=8,.group_bytes=512,.seg_len=512};
 struct xsk_mech_reliable r={0};struct xsk_xdev_ext_mech_stage xst={.rel=&r};
 struct xsk_xdev_ext_mech_provider provider={0};struct xdev_ext_mech_pool pool={.priv=&provider};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&pool};
 struct xdev_ext_mech_batch b[2]={{.key=1},{.key=2}};
 struct xsk_xdev_ext_mech_tx_batch tb[2]={{.batch=&b[0]},{.batch=&b[1]}};
 unsigned checks=0,fail=0,i,test;
#define CHECK(c) do{checks++;if(!(c)){fail++;fprintf(stderr,"FAIL %d %s\n",__LINE__,#c);}}while(0)
 for(test=0;test<8;test++) {
  bool wake=false;int rc;
  xdev_ext_rel_tx_init(&r.tx,&cfg);builds=enqueues=0;mode=test<4 ? test:0;
  for(i=0;i<2;i++) {b[i].priv=&tb[i];r.data[i+1].batch=&b[i];r.data[i+1].count=1;
   xdev_ext_rel_tx_open(&r.tx,i+1,512,1);xdev_ext_rel_tx_native_begin(&r.tx,i+1,0);
   xdev_ext_rel_tx_native_done(&r.tx,i+1,1,0,false,0);}
  if(test==4)r.tx.entry[2].native_pending=1;
  if(test==5)r.tx.entry[2].deadline_ns=101;
  if(test==6)r.tx.entry[2].attempt=8;
  rc=xsk_rel_resend(&st,test==7?32:2,2,100,&wake);
  if(!test){CHECK(!rc);CHECK(builds==1 && built==2);CHECK(enqueues==1 && enqueued==2 && wake);CHECK(r.tx.entry[1].attempt==1 && r.tx.entry[2].attempt==2);}
  else {CHECK(enqueues==0 && !wake);CHECK(test==3 ? rc==0 && r.tx.entry[2].declined==1 : rc<0);}
  if(test>=4)CHECK(builds==0);
 }
 printf("selected batch: %u checks, %u failures\n",checks,fail);return fail!=0;
}
'''
class ResendBinding(unittest.TestCase):
 def test_selected_batch_and_stale_snapshot(self):
  body=G.require(G.default_text(G.INC),'xsk_rel_resend','provider')
  G.build_and_run(self,RESEND_FIXTURE.replace('/* BODY */',body),name='selected-batch')

if __name__=='__main__':unittest.main(verbosity=2)
