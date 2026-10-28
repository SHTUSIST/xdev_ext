#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
import unittest
import glue_common as G
FIXTURE=r'''
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include "io_uring/xdev_ext_policy.h"
typedef __u64 u64;typedef __u32 u32;typedef __u8 u8;
#define __bpf_kfunc
#define data_race(x) (x)
#define spin_lock_irqsave(p,f) do{(void)(p);f=0;}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(p);(void)(f);}while(0)
struct xsk_rel_rx_intent {u64 group;u32 index,attempt;u8 calls,valid;};
struct xsk_mech_reliable {struct xdev_ext_rel_tx tx;struct xdev_ext_rel_rx rx;
 struct xdev_ext_rel_policy policy;struct xdev_ext_rel_tx_view select_view;
 struct xsk_rel_rx_intent rx_intent;u64 ack_pending[32],owed_since[32],nr_groups;u8 owed_dup[32];bool build_must;};
struct xsk_xdev_ext_mech_stage {struct xsk_mech_reliable *rel;};
struct xsk_xdev_ext_mech_provider {int tx_lock;};
struct xdev_ext_mech_pool {void *priv;};
struct xdev_ext_mech_stage {void *priv;struct xdev_ext_mech_pool *s;u32 direction;};
struct xdev_ext_mech_call {struct xdev_ext_mech_ctx ctx;u32 member,callsite,nr_frames;struct xdev_ext_mech_stage *st;
 void *b,*frames,*scratch,*cqe,*info;int protocol_error;};
static struct xdev_ext_mech_call call;
static struct xdev_ext_mech_call *xdev_ext_mech_call_of(const struct xdev_ext_mech_ctx *ctx) {return ctx==&call.ctx ? &call:NULL;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_pool *s) {return s;}
static u64 ktime_get_ns(void) {return 100;}
static unsigned kicks;
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) {(void)st;kicks++;}
/* BODY */
int main(void) {
 struct xsk_mech_reliable r={};struct xsk_xdev_ext_mech_stage xst={.rel=&r};
 struct xsk_xdev_ext_mech_provider provider={};struct xdev_ext_mech_pool pool={.priv=&provider};
 struct xdev_ext_mech_stage st={.priv=&xst,.s=&pool,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE};
 struct xdev_ext_rel_cfg cfg={.session=9,.first_group=1,.timeout_ns=10,.window=4,.max_attempts=8,.group_bytes=512,.seg_len=512};
 unsigned checks=0,fail=0,i;
#define CHECK(c) do{checks++;if(!(c)){fail++;fprintf(stderr,"FAIL %d %s\n",__LINE__,#c);}}while(0)
 xdev_ext_rel_rx_init(&r.rx,&cfg);xdev_ext_rel_tx_init(&r.tx,&cfg);xdev_ext_rel_policy_defaults(&r.policy);
 call=(struct xdev_ext_mech_call){.ctx.class_id=XDEV_EXT_MECH_CLASS_AFXDP,.member=XDEV_EXT_MECH_MEMBER_BUILD,
  .callsite=XDEV_EXT_MECH_SITE_WORKER_SELECT,.st=&st,.info=&r.select_view};
 CHECK(bpf_xdev_ext_rel_tx_view(&call.ctx,sizeof(r.select_view))==(__u8 *)&r.select_view);
 CHECK(!bpf_xdev_ext_rel_tx_view(NULL,sizeof(r.select_view)));
 CHECK(!bpf_xdev_ext_rel_tx_view(&call.ctx,sizeof(r.select_view)-1));
 for(i=0;i<9;i++) {
  struct xdev_ext_mech_call saved=call;
  switch(i){case 0:call.callsite=XDEV_EXT_MECH_SITE_WORKER;break;case 1:call.member=XDEV_EXT_MECH_MEMBER_COMPLETE;break;
   case 2:call.ctx.class_id=XDEV_EXT_MECH_CLASS_NVME;break;case 3:call.b=&st;break;case 4:call.frames=&st;break;
   case 5:call.nr_frames=1;break;case 6:call.scratch=&st;break;case 7:call.cqe=&st;break;case 8:call.info=&st;break;}
  CHECK(!bpf_xdev_ext_rel_tx_view(&call.ctx,sizeof(r.select_view)));call=saved;
 }
 call.member=XDEV_EXT_MECH_MEMBER_COMPLETE;call.callsite=XDEV_EXT_MECH_SITE_RX_NATIVE;
 CHECK(!bpf_xdev_ext_rel_rx_data(&call.ctx,1,0,1,XDEV_EXT_REL_HOLD));CHECK(r.rx_intent.valid);
 /* Calls cannot wrap a byte counter and regain transition authority. */
 for(i=0;i<300;i++) CHECK(bpf_xdev_ext_rel_rx_data(&call.ctx,1,0,1,XDEV_EXT_REL_HOLD)==-EALREADY);
 CHECK(call.protocol_error==1);
 r.rx_intent=(struct xsk_rel_rx_intent){};call.protocol_error=0;
 CHECK(bpf_xdev_ext_rel_rx_data(&call.ctx,1,65536,1,XDEV_EXT_REL_HOLD)==-EINVAL);
 CHECK(!r.rx_intent.valid && !r.rx.entry[1].present);
 r.rx_intent=(struct xsk_rel_rx_intent){};r.nr_groups=1;
 CHECK(bpf_xdev_ext_rel_rx_data(&call.ctx,2,0,1,XDEV_EXT_REL_HOLD)==-ERANGE);
 call.callsite=XDEV_EXT_MECH_SITE_WORKER;
 CHECK(bpf_xdev_ext_rel_rx_data(&call.ctx,1,0,1,XDEV_EXT_REL_HOLD)==-EOPNOTSUPP);
 printf("provider kfunc: %u checks, %u failures\n",checks,fail);return fail!=0;
}
'''
class ProviderKfunc(unittest.TestCase):
 def test_real_kfunc_seals_and_once_guard(self):
  text=G.XSK.read_text()
  names=['xsk_rel_call_state','xsk_rel_call_rx','bpf_xdev_ext_rel_rx_data','bpf_xdev_ext_rel_tx_view']
  bodies=G.require(G.default_text(G.INC),'xsk_rel_owe','inc')+'\n'+'\n'.join(G.require(text,n,'provider') for n in names)
  G.build_and_run(self,FIXTURE.replace('/* BODY */',bodies),name='provider-kfunc')
if __name__=='__main__':unittest.main(verbosity=2)
