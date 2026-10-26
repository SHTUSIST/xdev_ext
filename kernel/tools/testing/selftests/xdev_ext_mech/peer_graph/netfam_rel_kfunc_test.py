#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Executes the family kfunc bodies and filter with the call identity,
struct_ops table and AF_XDP provider stubbed; proves argument, family and
callsite gating, not verifier acceptance (that is the guest test of Task X7).

The reliable core, UAPI records, family table, rel-view declarations and
struct_ops member offsets are real. Identity is deliberately STUBBED: this
does not prove that a forged ctx is rejected by the real call envelope.
--syntax-only checks the fixture against declarations, without substituting
implementations for the missing production feature or claiming a GREEN run.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

KERNEL = Path(__file__).resolve().parents[5]
RUNTIME = KERNEL / "io_uring/family/xdev_ext_netfam_rel.c"


def declaration(text, name):
    match = re.search(r"\bstruct\s+" + re.escape(name) + r"\s*\{[^}]*\};", text, re.S)
    if not match:
        raise AssertionError(f"missing declaration: {name}")
    return match.group()


def function(text, name):
    # Remove comments first so braces in comments cannot truncate the slice.
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    match = re.search(r"^(?:static\s+)?[\w\s*]+?\b" + re.escape(name)
                      + r"\s*\([^;{}]*\)\s*\{", text, re.M)
    if not match:
        raise AssertionError(f"missing production function: {name}")
    end, depth = match.end(), 1
    while end < len(text) and depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    if depth:
        raise AssertionError(f"unclosed production function: {name}")
    return text[match.start():end]


SHIM = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "include/linux/xdev_ext_family_core.h"
#include "include/linux/xdev_ext_mech_reliable_core.h"
#include "include/uapi/linux/xdev_ext_policy.h"
typedef __u8 u8; typedef __u16 u16; typedef __u32 u32; typedef __u64 u64;
#define __bpf_kfunc
#define __bpf_kfunc_start_defs()
#define __bpf_kfunc_end_defs()
typedef struct { unsigned int held, acquisitions, releases; } spinlock_t;
static spinlock_t provider_lock, unrelated_lock;
static void (*on_lock)(void);
static void lock_provider(spinlock_t *lock)
{
 assert(lock == &provider_lock && !lock->held);
 lock->held = 1; lock->acquisitions++;
 if (on_lock) on_lock();
}
static void unlock_provider(spinlock_t *lock)
{
 assert(lock == &provider_lock && lock->held);
 lock->held = 0; lock->releases++;
}
#define spin_lock_irqsave(lock, flags) do { (flags) = 0; lock_provider(lock); } while (0)
#define spin_unlock_irqrestore(lock, flags) do { (void)(flags); unlock_provider(lock); } while (0)
struct xdev_ext_mech_stage;
struct xdev_ext_family_hooks_hdr { u32 family; };
'''

PROVIDER = r'''
/* Only the AF_XDP provider dependency is replaced, not the function under test. */
struct xsk_mech_reliable {
 struct xdev_ext_rel_policy policy;
 struct xdev_ext_rel_tx tx;
 struct xdev_ext_rel_rx rx;
 u64 ack_pending[XDEV_EXT_REL_MAX_WINDOW];
};
struct xsk_xdev_ext_mech_provider { spinlock_t tx_lock; };
struct fake_pool { void *priv; };
struct xdev_ext_mech_session { struct fake_pool pool; };
struct xsk_xdev_ext_mech_stage { struct xsk_mech_reliable *rel; };
struct xdev_ext_mech_class_ops { union { const struct xdev_ext_net_hooks *net; } fam; };
struct xdev_ext_mech_stage {
 struct xdev_ext_mech_session *s;
 const struct xdev_ext_mech_class_ops *cls;
 void *priv;
};
struct xdev_ext_mech_call { struct xdev_ext_mech_ctx ctx; struct xdev_ext_mech_stage *st; u32 callsite; u8 member; };
static struct xdev_ext_mech_call call;
static int no_call;
/* STUBBED identity. The real active-call authentication is separately tested. */
static struct xdev_ext_mech_call *xdev_ext_mech_call_of(const struct xdev_ext_mech_ctx *ctx)
{ assert(ctx == &call.ctx); return no_call ? NULL : &call; }
static struct fake_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{ return &s->pool; }
struct bpf_prog { int unused; };
struct bpf_struct_ops { u32 class_id; };
struct btf_id_set { int tag; };
struct btf_id_set8 { int tag; };
static struct bpf_struct_ops ops[XDEV_EXT_MECH_CLASS_MAX];
static u32 omitted_ops = ~0U;
static const struct bpf_struct_ops *xdev_ext_mech_st_ops_of(u32 class_id)
{
 assert(class_id < XDEV_EXT_MECH_CLASS_MAX);
 return class_id == omitted_ops ? NULL : &ops[class_id];
}
'''

FILTER = r'''
static const struct bpf_struct_ops *recorded_ops[XDEV_EXT_MECH_CLASS_MAX];
static struct xdev_ext_ops_kfunc_member recorded_members[2];
static u32 nr_ops, nr_members;
static const struct btf_id_set8 *recorded_ids;
static const struct bpf_prog *recorded_prog;
static u32 recorded_id;
static int filter_result = -EACCES;
static int xdev_ext_ops_kfunc_filter(const struct xdev_ext_ops_kfunc_rule *rule,
                                    const struct bpf_prog *prog, u32 kfunc_id)
{
 assert(rule->nr_st_ops <= XDEV_EXT_MECH_CLASS_MAX && rule->nr_members <= 2);
 nr_ops = rule->nr_st_ops; nr_members = rule->nr_members;
 for (u32 i=0;i<nr_ops;i++) recorded_ops[i] = rule->st_ops[i];
 for (u32 i=0;i<nr_members;i++) recorded_members[i] = rule->members[i];
 recorded_ids = rule->ids; recorded_prog = prog; recorded_id = kfunc_id;
 return filter_result;
}
'''

DECLARATIONS = r'''
int bpf_xdev_ext_net_rel_rx_view(const struct xdev_ext_mech_ctx *, u64, void *, u32);
int bpf_xdev_ext_net_rel_tx_state(const struct xdev_ext_mech_ctx *, u64, void *, u32);
int bpf_xdev_ext_net_rel_policy(const struct xdev_ext_mech_ctx *, void *, u32);
int xdev_ext_mech_family_kfunc_filter(u32, const struct bpf_prog *, u32,
                                    const struct btf_id_set8 *, const struct btf_id_set *,
                                    const struct btf_id_set *);
bool xsk_xdev_ext_net_rel(struct xdev_ext_mech_stage *, struct xdev_ext_net_rel_view *);
'''

MAIN = r'''
static struct xsk_mech_reliable rel;
static struct xsk_xdev_ext_mech_stage xst;
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_mech_class_ops cls;
static struct xdev_ext_net_hooks hooks;
static struct xdev_ext_net_rel_view supplied;
static int rel_present = 1, rel_calls;
static bool supply(struct xdev_ext_mech_stage *st, struct xdev_ext_net_rel_view *out)
{ assert(st == &stage); rel_calls++; *out = supplied; return rel_present; }
static void init(void)
{
 const struct xdev_ext_rel_cfg cfg = { .session=23, .first_group=3, .timeout_ns=10000,
  .window=4, .max_attempts=8, .group_bytes=128, .seg_len=64, .initial_credit=4 };
 memset(&rel, 0, sizeof(rel));
 assert(!xdev_ext_rel_tx_init(&rel.tx, &cfg));
 assert(!xdev_ext_rel_rx_init(&rel.rx, &cfg));
 assert(xdev_ext_rel_tx_open(&rel.tx, 3, 128, 2) == XDEV_EXT_REL_SEND);
 assert(xdev_ext_rel_tx_open(&rel.tx, 4, 128, 2) == XDEV_EXT_REL_SEND);
 assert(xdev_ext_rel_tx_open(&rel.tx, 5, 128, 2) == XDEV_EXT_REL_SEND);
 assert(xdev_ext_rel_tx_native_begin(&rel.tx, 5, 10) == XDEV_EXT_REL_SEND);
 assert(xdev_ext_rel_rx_claim(&rel.rx, 3, 0, 2) == XDEV_EXT_REL_HOLD);
 assert(xdev_ext_rel_rx_claim(&rel.rx, 3, 1, 2) == XDEV_EXT_REL_SUBMIT);
 rel.ack_pending[3] = 3;
 rel.policy = (struct xdev_ext_rel_policy){ .version=1, .size=120, .window=4,
  .initial_credit=4, .rto_ns=10000, .max_attempts=8, .ack_every=1 };
 xst = (struct xsk_xdev_ext_mech_stage){ .rel=&rel };
 hooks = (struct xdev_ext_net_hooks){ .hdr={XDEV_EXT_FAMILY_NETWORK}, .rel=supply };
 cls = (struct xdev_ext_mech_class_ops){ .fam.net=&hooks };
 stage = (struct xdev_ext_mech_stage){ .s=&session, .cls=&cls, .priv=&xst };
 call = (struct xdev_ext_mech_call){ .ctx={.class_id=XDEV_EXT_MECH_CLASS_AFXDP},
  .st=&stage, .callsite=XDEV_EXT_MECH_SITE_WORKER, .member=XDEV_EXT_MECH_MEMBER_BUILD };
 provider_lock = (spinlock_t){}; unrelated_lock = (spinlock_t){};
 supplied = (struct xdev_ext_net_rel_view){ .tx=&rel.tx, .rx=&rel.rx,
  .ack_pending=rel.ack_pending, .policy=&rel.policy, .lock=&provider_lock };
 no_call=0; rel_present=1; rel_calls=0; on_lock=NULL;
}
/* Every invocation checks the entire reliable state, not only observed fields. */
static void query(int which, u64 group, void *out, u32 size, int want, u32 locks)
{
 struct xsk_mech_reliable before = rel;
 unsigned int acquisitions=provider_lock.acquisitions, releases=provider_lock.releases;
 int ret = which==0 ? bpf_xdev_ext_net_rel_tx_state(&call.ctx,group,out,size) :
           which==1 ? bpf_xdev_ext_net_rel_rx_view(&call.ctx,group,out,size) :
                      bpf_xdev_ext_net_rel_policy(&call.ctx,out,size);
 assert(ret == want && !memcmp(&before, &rel, sizeof(rel)));
 assert(!provider_lock.held && provider_lock.acquisitions-acquisitions==locks &&
        provider_lock.releases-releases==locks && !unrelated_lock.acquisitions);
}
static void errors(int want)
{
 u8 bytes[136], before[136]; memset(bytes,0xa7,sizeof(bytes)); memcpy(before,bytes,sizeof(bytes));
 query(0,5,bytes+8,56,want,0); assert(!memcmp(bytes,before,sizeof(bytes)));
 query(1,3,bytes+8,64,want,0); assert(!memcmp(bytes,before,sizeof(bytes)));
 query(2,0,bytes+8,120,want,0); assert(!memcmp(bytes,before,sizeof(bytes)));
}
static bool has(u32 c)
{ for (u32 i=0;i<nr_ops;i++) if (recorded_ops[i]==&ops[c]) return true; return false; }
static void mutate_at_lock(void)
{
 assert(provider_lock.held);
 rel.tx.base_group=4; rel.tx.next_group=7; rel.tx.credit=9;
 rel.tx.entry[1].attempt=6; rel.tx.entry[1].acked=1; rel.tx.entry[1].native_pending=0;
 rel.tx.entry[1].terminal=XDEV_EXT_REL_COMPLETE;
 rel.rx.base_group=4; rel.rx.credit=8; rel.rx.entry[3].latest_attempt=6;
 rel.ack_pending[3]=19;
}
int main(void)
{
 struct { u64 pre; struct xdev_ext_net_rel_tx_state out; u64 post; } tx;
 struct { u64 pre; struct xdev_ext_rel_rx_view out; u64 post; } rx;
 struct { u64 pre; struct xdev_ext_rel_policy out; u64 post; } policy;
 const struct xdev_ext_net_rel_tx_state tx_want = { .group=5,.base_group=3,.next_group=6,
  .credit=7,.attempt=1,.live=1,.native_pending=1 };
 const struct xdev_ext_rel_rx_view rx_want = { .group=3,.slot_group=3,.base_group=3,
  .credit=7,.present=3,.latest_attempt=2,.total_len=128,.count=2,
  .state=XDEV_EXT_REL_RX_SUBMITTED,.owed=3 };
 _Static_assert(sizeof(struct xdev_ext_net_rel_tx_state)==56, "TX UAPI size");
 _Static_assert(offsetof(struct xdev_ext_net_rel_tx_state,rsvd)==52, "TX UAPI reserved offset");
 _Static_assert(sizeof(struct xdev_ext_rel_rx_view)==64, "RX UAPI size");
 init();
 for (u32 c=0;c<XDEV_EXT_MECH_CLASS_MAX;c++) {
  call.ctx.class_id=c;call.callsite=XDEV_EXT_MECH_SITE_WORKER;
  if (c!=XDEV_EXT_MECH_CLASS_AFXDP && c!=XDEV_EXT_MECH_CLASS_SOCKET && c!=XDEV_EXT_MECH_CLASS_NET) {
   errors(-EOPNOTSUPP); continue;
  }
  for (u8 member=XDEV_EXT_MECH_MEMBER_BUILD;member<=XDEV_EXT_MECH_MEMBER_COMPLETE;member++) {
   call.member=member;
   for (u32 site=0;site<=7;site++) {
   call.callsite=site;
   if (site!=XDEV_EXT_MECH_SITE_WORKER && site!=XDEV_EXT_MECH_SITE_WORKER_SELECT) {
    errors(-EOPNOTSUPP); continue;
   }
   memset(&tx,0xa7,sizeof(tx)); tx.pre=0x1122334455667788ULL; tx.post=tx.pre;
   query(0,5,&tx.out,sizeof(tx.out),0,1);
   assert(!memcmp(&tx.out,&tx_want,sizeof(tx.out)) && tx.pre==tx.post && tx.pre==0x1122334455667788ULL);
   memset(&rx,0xa7,sizeof(rx)); rx.pre=tx.pre;rx.post=tx.pre;
   query(1,3,&rx.out,sizeof(rx.out),0,1);
   assert(!memcmp(&rx.out,&rx_want,sizeof(rx.out)) && rx.pre==tx.pre && rx.post==tx.pre);
   memset(&policy,0xa7,sizeof(policy)); policy.pre=tx.pre;policy.post=tx.pre;
   query(2,0,&policy.out,sizeof(policy.out),0,0);
   assert(!memcmp(&policy.out,&rel.policy,sizeof(policy.out)) && policy.pre==tx.pre && policy.post==tx.pre);
   }
  }
 }
 puts("ok 1 - only network classes at WORKER or WORKER_SELECT receive exact initialized read-only records");

 init();
 /* Explicit added coverage: only BUILD/COMPLETE members may use these views. */
 const u8 bad_members[]={0,XDEV_EXT_MECH_MEMBER_PREPARE,XDEV_EXT_MECH_MEMBER_COMPUTE,0xff};
 for (u32 i=0;i<sizeof(bad_members)/sizeof(bad_members[0]);i++) {
  call.member=bad_members[i];errors(-EOPNOTSUPP);
 }
 call.member=XDEV_EXT_MECH_MEMBER_BUILD;
 no_call=1; errors(-EINVAL); no_call=0;
 call.st=NULL; errors(-EINVAL); call.st=&stage;
 const u32 unknown[]={~0U, XDEV_EXT_MECH_CLASS_MAX, XDEV_EXT_MECH_CLASS_MAX+1};
 for (u32 i=0;i<sizeof(unknown)/sizeof(unknown[0]);i++) { call.ctx.class_id=unknown[i];errors(-EOPNOTSUPP); }
 call.ctx.class_id=XDEV_EXT_MECH_CLASS_AFXDP;
 call.callsite=~0U; errors(-EOPNOTSUPP); call.callsite=XDEV_EXT_MECH_SITE_WORKER;
 cls.fam.net=NULL; errors(-EOPNOTSUPP); cls.fam.net=&hooks;
 hooks.rel=NULL; errors(-EOPNOTSUPP); hooks.rel=supply;
 rel_present=0; errors(-EOPNOTSUPP); rel_present=1;
 supplied.lock=NULL; errors(-EOPNOTSUPP); supplied.lock=&provider_lock;
 puts("ok 2 - missing identity, stage, network hooks, reliable state or provider lock refuses without output writes");

 init();
 for (int which=0;which<3;which++) {
  u32 exact=which==0?56:which==1?64:120;
  const u32 sizes[]={0,7,exact-1,exact+1,~0U};
  for (u32 i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++) {
   u8 bytes[136], before[136];memset(bytes,0xac,sizeof(bytes));memcpy(before,bytes,sizeof(bytes));
   query(which,which==0?5:3,bytes+8,sizes[i],-EINVAL,0);
   assert(!memcmp(bytes,before,sizeof(bytes)));
  }
 }
 supplied.tx=NULL;query(0,5,&tx.out,56,-EOPNOTSUPP,0);supplied.tx=&rel.tx;
 supplied.rx=NULL;query(1,3,&rx.out,64,-EOPNOTSUPP,0);supplied.rx=&rel.rx;
 supplied.policy=NULL;query(2,0,&policy.out,120,-EOPNOTSUPP,0);supplied.policy=&rel.policy;
 const u64 bad_groups[]={0,~0ULL,~0ULL-3};
 for (u32 i=0;i<sizeof(bad_groups)/sizeof(bad_groups[0]);i++) {
  query(0,bad_groups[i],&tx.out,56,-ERANGE,0);query(1,bad_groups[i],&rx.out,64,-ERANGE,0);
 }
 query(1,2,&rx.out,64,-ERANGE,0);
 /* Unsigned representation of negative group is the upper overflow boundary. */
 query(0,(u64)-1,&tx.out,56,-ERANGE,0);
 query(1,(u64)-2,&rx.out,64,-ERANGE,0);
 puts("ok 3 - exact sizes, optional directions/policy and unsigned group boundaries are enforced before copy");

 init(); memset(&tx.out,0xa7,sizeof(tx.out));
 query(0,9,&tx.out,56,0,1); /* group 9 aliases live group 5's slot: no identity leak */
 const struct xdev_ext_net_rel_tx_state absent = { .group=9,.base_group=3,.next_group=6,.credit=7 };
 assert(!memcmp(&tx.out,&absent,sizeof(absent)));
 rel.tx.entry[1].live=0; memset(&tx.out,0xa7,sizeof(tx.out));query(0,5,&tx.out,56,0,1);
 const struct xdev_ext_net_rel_tx_state retired = { .group=5,.base_group=3,.next_group=6,.credit=7 };
 assert(!memcmp(&tx.out,&retired,sizeof(retired)));
 supplied.ack_pending=NULL; query(1,3,&rx.out,64,0,1);assert(!rx.out.owed);
 supplied.ack_pending=rel.ack_pending;
 query(0,~0ULL-4,&tx.out,56,0,1);query(1,~0ULL-4,&rx.out,64,0,1);
 puts("ok 4 - unknown and retired TX identities expose no old attempt; optional ACK debt and last legal group work");

 init();on_lock=mutate_at_lock;
 assert(!bpf_xdev_ext_net_rel_tx_state(&call.ctx,5,&tx.out,56));
 assert(tx.out.base_group==4 && tx.out.next_group==7 && tx.out.credit==9 &&
        tx.out.attempt==6 && tx.out.acked && !tx.out.native_pending && tx.out.terminal==XDEV_EXT_REL_COMPLETE);
 assert(!bpf_xdev_ext_net_rel_rx_view(&call.ctx,3,&rx.out,64));
 assert(rx.out.base_group==4 && rx.out.credit==8 && rx.out.latest_attempt==6 && rx.out.owed==19);
 assert(provider_lock.acquisitions==2 && provider_lock.releases==2 && !provider_lock.held);
 puts("ok 5 - snapshots observe provider state only after taking the provider serialization lock");

 init();struct xsk_xdev_ext_mech_provider provider={};session.pool.priv=&provider;
 struct xdev_ext_net_rel_view view;
 memset(&view,0xa7,sizeof(view));assert(xsk_xdev_ext_net_rel(&stage,&view));
 assert(view.tx==&rel.tx && view.rx==&rel.rx && view.ack_pending==rel.ack_pending &&
        view.policy==&rel.policy && view.lock==&provider.tx_lock);
 struct xdev_ext_net_rel_view view_before=view;
 struct xsk_mech_reliable rel_before=rel;
 xst.rel=NULL;assert(!xsk_xdev_ext_net_rel(&stage,&view));assert(!memcmp(&view,&view_before,sizeof(view)));
 stage.priv=NULL;assert(!xsk_xdev_ext_net_rel(&stage,&view));assert(!memcmp(&view,&view_before,sizeof(view)));
 assert(!memcmp(&rel,&rel_before,sizeof(rel)));
 puts("ok 6 - actual AF_XDP rel-view uses the existing provider tx_lock and does not mutate state");

 struct btf_id_set8 ids={1};struct btf_id_set build={2},complete={3};struct bpf_prog prog={};
 for(u32 c=0;c<XDEV_EXT_MECH_CLASS_MAX;c++) ops[c].class_id=c;
 for (u32 mask=0;mask<4;mask++) {
  int result=xdev_ext_mech_family_kfunc_filter(XDEV_EXT_FAMILY_NETWORK,&prog,123,&ids,
                                             mask&1?&build:NULL,mask&2?&complete:NULL);
  assert(result==-EACCES && recorded_ids==&ids && recorded_prog==&prog && recorded_id==123);
  assert(nr_ops==3 && has(XDEV_EXT_MECH_CLASS_AFXDP) && has(XDEV_EXT_MECH_CLASS_SOCKET) && has(XDEV_EXT_MECH_CLASS_NET));
  assert(!has(XDEV_EXT_MECH_CLASS_NVME) && !has(XDEV_EXT_MECH_CLASS_CE) && !has(XDEV_EXT_MECH_CLASS_IAA));
  assert(nr_members==(u32)!!(mask&1)+(u32)!!(mask&2));
  u32 m=0;
  if(mask&1) { assert(recorded_members[m].off==offsetof(struct xdev_ext_nvme_mech_ops,build) && recorded_members[m].allowed==&build);m++; }
  if(mask&2) assert(recorded_members[m].off==offsetof(struct xdev_ext_nvme_mech_ops,complete) && recorded_members[m].allowed==&complete);
 }
 omitted_ops=XDEV_EXT_MECH_CLASS_SOCKET;filter_result=0;
 assert(!xdev_ext_mech_family_kfunc_filter(XDEV_EXT_FAMILY_NETWORK,NULL,17,&ids,&build,&complete));
 assert(nr_ops==2 && has(XDEV_EXT_MECH_CLASS_AFXDP) && has(XDEV_EXT_MECH_CLASS_NET) && !has(XDEV_EXT_MECH_CLASS_SOCKET));
 omitted_ops=~0U;
 assert(!xdev_ext_mech_family_kfunc_filter(~0U,NULL,17,&ids,NULL,NULL));assert(!nr_ops && !nr_members);
 puts("ok 7 - family filter enumerates all three network types, preserves member offsets and propagates filter verdicts");
 return 0;
}
'''


def fixture(syntax_only=False):
    mech = (KERNEL / "include/linux/xdev_ext_mech.h").read_text()
    net = (KERNEL / "include/linux/xdev_ext_netfam.h").read_text()
    ops = (KERNEL / "io_uring/xdev_ext_ops_core.h").read_text()
    macro = re.search(r"^#define XDEV_EXT_MECH_OPS_TYPE\(name\).*?^}", mech, re.M | re.S)
    if not macro:
        raise AssertionError("missing real struct_ops layout macro")
    layouts = (macro.group() + "\nXDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);\n")
    declarations = "\n".join(declaration(net, name) for name in
                               ("xdev_ext_net_rel_view", "xdev_ext_net_hooks"))
    rule = "\n".join(declaration(ops, name) for name in
                       ("xdev_ext_ops_kfunc_member", "xdev_ext_ops_kfunc_rule"))
    tx_decl = ""
    if syntax_only and "struct xdev_ext_net_rel_tx_state {" not in (
            KERNEL / "include/uapi/linux/xdev_ext_mech.h").read_text():
        tx_decl = r'''
/* Frozen F6 UAPI declaration only; no implementation substitution. */
struct xdev_ext_net_rel_tx_state {
 __aligned_u64 group, base_group, next_group, credit;
 __u32 attempt, live, acked, native_pending;
 __u32 terminal, rsvd;
};
'''
    if syntax_only:
        bodies = DECLARATIONS
    else:
        runtime = RUNTIME.read_text()
        begin = "/* netfam rel kfuncs begin */"
        end = "/* netfam rel kfuncs end */"
        if runtime.count(begin) != 1 or runtime.count(end) != 1:
            raise AssertionError("missing unique netfam rel kfunc slice markers")
        bodies = runtime.split(begin, 1)[1].split(end, 1)[0]
        bodies += function((KERNEL / "io_uring/xdev_ext_mech_ops.c").read_text(),
                           "xdev_ext_mech_family_kfunc_filter")
        bodies += function((KERNEL / "net/xdp/xsk_xdev_ext_mech.c").read_text(),
                           "xsk_xdev_ext_net_rel")
    return SHIM + tx_decl + layouts + declarations + PROVIDER + rule + FILTER + bodies + MAIN


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syntax-only", action="store_true")
    args = parser.parse_args()
    if not args.syntax_only and not RUNTIME.exists():
        print("not ok 1 - io_uring/family/xdev_ext_netfam_rel.c missing", flush=True)
        return 1
    with tempfile.TemporaryDirectory(prefix="netfam-rel-kfunc-") as tmp:
        source = Path(tmp) / "test.c"
        source.write_text(fixture(args.syntax_only))
        cmd = shlex.split(os.environ.get("CC", "gcc")) + [
            "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
            "-I" + str(KERNEL), str(source)]
        if args.syntax_only:
            subprocess.run(cmd + ["-fsyntax-only"], check=True)
            print("ok - fixture syntax only; production bodies absent, no behavior verdict")
        else:
            executable = Path(tmp) / "test"
            subprocess.run(cmd + ["-fsanitize=undefined", "-fno-sanitize-recover=undefined",
                                  "-o", str(executable)], check=True)
            subprocess.run([str(executable)], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
