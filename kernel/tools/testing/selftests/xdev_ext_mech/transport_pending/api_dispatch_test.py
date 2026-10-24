#!/usr/bin/env python3
"""Exercise production dispatcher, transport handler/fill and live uid lookup."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
ROOT=Path(os.environ.get('KERNEL_DIR',str(next(p for p in Path(__file__).resolve().parents if (p/'io_uring/xdev_ext_mech.c').is_file()))))
def definition(source,name):
 m=re.search(r'^(?:static )?(?:void|int|struct xdev_ext_mech_session \*)\s*'+re.escape(name)+r'\([^)]*\)\s*\{.*?^\}',source,re.M|re.S)
 if m is None: raise RuntimeError('missing production '+name)
 return m[0]
FIXTURE=r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "io_uring/xdev_ext_policy.h"
#include "include/linux/xdev_ext_mech.h"
#define atomic64_read(p) (*(p))
typedef __u64 u64; typedef __u32 u32;
#ifndef XDEV_EXT_MECH_TRANSPORT_STATS_VERSION
#define XDEV_EXT_MECH_TRANSPORT_STATS_VERSION 1
struct xdev_ext_mech_transport_stats { __u32 size,version;__aligned_u64 session_id;__u32 native_controls,pending_acks,uncertain_controls,rsvd; };
#endif
#define __user
#define u64_to_user_ptr(v) ((void *)(uintptr_t)(v))
#define U32_MAX UINT32_MAX
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define atomic_read(p) (*(p))
#define READ_ONCE(v) (v)
#define lockdep_assert_held(p) ((void)(p))
#define mutex_lock(p) (++*(p))
#define mutex_unlock(p) (--*(p))
struct list_head { struct list_head *next,*prev; };
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m);&p->m!=(h);p=container_of(p->m.next,__typeof__(*p),m))
static void init_list(struct list_head *h) { h->next=h->prev=h; }
static void add_list(struct list_head *n,struct list_head *h) { n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n; }
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops { void (*transport_stats)(struct xdev_ext_mech_stage *,u32 *,u32 *);
 void (*transport_counters)(struct xdev_ext_mech_stage *,struct xdev_ext_mech_transport_stats_v2 *);
 void (*transport_policy)(struct xdev_ext_mech_stage *,struct xdev_ext_rel_policy *); };
struct xdev_ext_mech_stage { const struct xdev_ext_mech_class_ops *cls; u32 pending,uncertain,held; u64 retransmits; };
struct xdev_ext_mech_session { struct list_head ring_node,live_node;u64 id;int uid,native_controls;u32 nr_stages;u64 cnt[XDEV_EXT_MECH_CNT_NR];struct xdev_ext_mech_stage st[4]; };
struct io_ring_ctx { struct list_head xdev_ext_mech_sessions; };
static struct list_head xdev_ext_mech_live;
static int xdev_ext_mech_live_lock, caller_uid=10;
#define current_euid() (caller_uid)
#define uid_eq(a,b) ((a)==(b))
static int fail_from,fail_to,copy_calls;
static int copy_from_user(void *dst,const void *src,size_t n) { copy_calls++;if(!src||copy_calls==fail_from)return 1;memcpy(dst,src,n);return 0; }
static int copy_to_user(void *dst,const void *src,size_t n) { if(!dst||fail_to)return 1;memcpy(dst,src,n);return 0; }
static int xdev_ext_mech_create(struct io_ring_ctx *ctx,void *p) { (void)ctx;(void)p;return -ENOSYS; }
static int xdev_ext_mech_start(struct io_ring_ctx *ctx,void *p) { (void)ctx;(void)p;return -ENOSYS; }
static int xdev_ext_mech_stop_op(struct io_ring_ctx *ctx,u64 id) { (void)ctx;(void)id;return -ENOSYS; }
static int xdev_ext_mech_stats(struct io_ring_ctx *ctx,void *p) { (void)ctx;(void)p;return -ENOSYS; }
static int xdev_ext_mech_notify_arm_op(struct io_ring_ctx *ctx,void *p) { (void)ctx;(void)p;return -ENOSYS; }
static void provider_stats(struct xdev_ext_mech_stage *st,u32 *pending,u32 *uncertain) { *pending=st->pending;*uncertain=st->uncertain; }
static void provider_counters(struct xdev_ext_mech_stage *st,struct xdev_ext_mech_transport_stats_v2 *out)
{ out->retransmits+=st->retransmits;out->dup_suppressed+=2;out->held_acks+=1;out->held_unacked+=st->held; }
static void *memchr_inv(const void *p,int byte,size_t len) {
 const unsigned char *b=p;size_t i;for(i=0;i<len;i++)if(b[i]!=(unsigned char)byte)return (void *)(b+i);return NULL;
}
static void provider_policy(struct xdev_ext_mech_stage *st,struct xdev_ext_rel_policy *p)
{ (void)st;xdev_ext_rel_policy_defaults(p);p->window=7;p->initial_credit=7; }
/* PRODUCTION */
#define CHECK(c) do { if(!(c)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#c);return 1;} } while(0)
int main(int argc,char **argv)
{
 const char *mode=argc>1?argv[1]:"valid";
 struct io_ring_ctx ctx;init_list(&ctx.xdev_ext_mech_sessions);init_list(&xdev_ext_mech_live);
 const struct xdev_ext_mech_class_ops ops={.transport_stats=provider_stats,.transport_counters=provider_counters,.transport_policy=provider_policy},empty_ops={0};
 struct xdev_ext_mech_session s={.id=7,.uid=10,.native_controls=3,.nr_stages=3,
 .st={{.cls=&ops,.pending=2,.uncertain=1,.retransmits=4,.held=6},{.cls=&ops,.pending=5,.uncertain=2,.retransmits=1},{.cls=&empty_ops}}};
 init_list(&s.ring_node);init_list(&s.live_node);add_list(&s.live_node,&xdev_ext_mech_live);
 if(!strcmp(mode,"owner"))add_list(&s.ring_node,&ctx.xdev_ext_mech_sessions);
 unsigned int nr=1;int expected=0;
 struct xdev_ext_mech_transport_stats_v4 wire4={.v3.v2.v1={.size=216,.version=4,.session_id=7}};
 struct xdev_ext_mech_transport_stats_v3 wire3={.v2.v1={.size=96,.version=3,.session_id=7}};
 struct xdev_ext_mech_transport_stats_v2 wire2={.v1={.size=64,.version=2,.session_id=7}};
 struct xdev_ext_mech_transport_stats wire={.size=32,.version=1,.session_id=7};
 struct io_uring_xdev_ext_mech req={.op=6,.arg=(uintptr_t)&wire};
 bool v3=!strncmp(mode,"v3",2);
 s.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_OPS]=11;s.cnt[XDEV_EXT_MECH_CNT_NIC_COPY_BYTES]=2200;
 s.cnt[XDEV_EXT_MECH_CNT_NIC_ZC_OPS]=33;s.cnt[XDEV_EXT_MECH_CNT_NIC_ZC_BYTES]=4400;
 if(v3)req.arg=(uintptr_t)&wire3;
 if(!strcmp(mode,"v3-size")){wire3.v2.v1.size=64;expected=-EINVAL;}
 if(!strcmp(mode,"v3-copy-ops")){wire3.nic_copy_ops=1;expected=-EINVAL;}
 if(!strcmp(mode,"v3-copy-bytes")){wire3.nic_copy_bytes=1;expected=-EINVAL;}
 if(!strcmp(mode,"v3-zc-ops")){wire3.nic_zc_ops=1;expected=-EINVAL;}
 if(!strcmp(mode,"v3-zc-bytes")){wire3.nic_zc_bytes=1;expected=-EINVAL;}
 if(!strcmp(mode,"v3-v2-reserved")){wire3.v2.rsvd2=1;expected=-EINVAL;}
 if(!strcmp(mode,"v3-copy-fault")){fail_from=3;expected=-EFAULT;}
 bool v2=!strncmp(mode,"v2",2);
 if(v2)req.arg=(uintptr_t)&wire2;
 bool v4=!strncmp(mode,"v4",2);
 if(v3)req.arg=(uintptr_t)&wire3;
 if(v4)req.arg=(uintptr_t)&wire4;
 if(!strcmp(mode,"v3-size")){wire3.v2.v1.size=216;expected=-EINVAL;}
 if(!strcmp(mode,"v3-input")){wire3.nic_copy_ops=1;expected=-EINVAL;}
 if(!strcmp(mode,"v4-size")){wire4.v3.v2.v1.size=184;expected=-EINVAL;}
 if(!strcmp(mode,"v4-input")){wire4.rel_policy.window=1;expected=-EINVAL;}
 if(!strcmp(mode,"v4-copy")){fail_from=3;expected=-EFAULT;}
 if(!strcmp(mode,"v2-size")){wire2.v1.size=32;expected=-EINVAL;}
 if(!strcmp(mode,"v2-input")){wire2.retransmits=1;expected=-EINVAL;}
 if(!strcmp(mode,"v2-reserved")){wire2.rsvd2=1;expected=-EINVAL;}
 if(!strcmp(mode,"v2-copy")){fail_from=3;expected=-EFAULT;}
 if(!strcmp(mode,"uid")){caller_uid=11;expected=-ENOENT;}
 if(!strcmp(mode,"gone")){wire.session_id=8;expected=-ENOENT;}
 if(!strcmp(mode,"size")){wire.size=40;expected=-EINVAL;}
 if(!strcmp(mode,"version")){wire.version=2;expected=-EINVAL;}
 if(!strcmp(mode,"controls")){wire.native_controls=1;expected=-EINVAL;}
 if(!strcmp(mode,"pending")){wire.pending_acks=1;expected=-EINVAL;}
 if(!strcmp(mode,"uncertain")){wire.uncertain_controls=1;expected=-EINVAL;}
 if(!strcmp(mode,"reserved")){wire.rsvd=1;expected=-EINVAL;}
 if(!strcmp(mode,"request-reserved")){req.rsvd=1;expected=-EINVAL;}
 if(!strcmp(mode,"nr")){nr=2;expected=-EINVAL;}
 if(!strcmp(mode,"copy-request")){fail_from=1;expected=-EFAULT;}
 if(!strcmp(mode,"copy-input")){fail_from=2;expected=-EFAULT;}
 if(!strcmp(mode,"copy-output")){fail_to=1;expected=-EFAULT;}
 if(!strcmp(mode,"null")){req.arg=0;expected=-EFAULT;}
 if(!strcmp(mode,"saturate")){s.st[0].pending=U32_MAX;s.st[0].uncertain=U32_MAX;}
 int r=io_xdev_ext_mech_register(&ctx,&req,nr);CHECK(r==expected);CHECK(xdev_ext_mech_live_lock==0);
 if(!r&&v2){CHECK(wire2.v1.size==64&&wire2.v1.version==2&&wire2.v1.session_id==7&&!wire2.v1.rsvd&&!wire2.rsvd2);
  CHECK(wire2.v1.native_controls==3&&wire2.v1.pending_acks==7&&wire2.v1.uncertain_controls==3);
  CHECK(wire2.retransmits==5&&wire2.dup_suppressed==4&&wire2.held_acks==2&&wire2.held_unacked==6);return 0;}
 if(!r&&v3){CHECK(wire3.v2.v1.size==96&&wire3.v2.v1.version==3&&wire3.v2.v1.session_id==7);
  CHECK(wire3.v2.v1.native_controls==3&&wire3.v2.v1.pending_acks==7&&wire3.v2.v1.uncertain_controls==3);
  CHECK(wire3.v2.retransmits==5&&wire3.v2.dup_suppressed==4&&wire3.v2.held_acks==2&&wire3.v2.held_unacked==6);
  CHECK(wire3.nic_copy_ops==11&&wire3.nic_copy_bytes==2200&&wire3.nic_zc_ops==33&&wire3.nic_zc_bytes==4400);return 0;}
 if(!r&&v4){CHECK(wire4.v3.v2.v1.size==216&&wire4.v3.v2.v1.version==4);CHECK(wire4.v3.v2.retransmits==5);
  CHECK(offsetof(struct xdev_ext_mech_transport_stats_v4,rel_policy)==96);
  CHECK(wire4.v3.nic_copy_ops==11&&wire4.v3.nic_copy_bytes==2200&&wire4.v3.nic_zc_ops==33&&wire4.v3.nic_zc_bytes==4400);
  CHECK(wire4.rel_policy.version==1&&wire4.rel_policy.size==120&&wire4.rel_policy.window==7&&wire4.rel_policy.initial_credit==7);return 0;}
 /* A version 1 caller never sees the appended counters. */
 if(!r){CHECK(wire.size==32&&wire.version==1&&wire.session_id==7&&!wire.rsvd);CHECK(wire.native_controls==3);CHECK(wire.pending_acks==(!strcmp(mode,"saturate")?U32_MAX:7));CHECK(wire.uncertain_controls==(!strcmp(mode,"saturate")?U32_MAX:3));}
 return 0;
}
'''
class Dispatch(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  source=(ROOT/'io_uring/xdev_ext_mech.c').read_text()
  functions=['xdev_ext_mech_find','xdev_ext_mech_find_live']
  if 'static int xdev_ext_mech_transport_stats(' in source:
   functions+=['xdev_ext_mech_transport_stats_fill','xdev_ext_mech_transport_stats']
  functions+=['io_xdev_ext_mech_register']
  code='\n'.join(definition(source,n) for n in functions)
  cls.tmp=tempfile.TemporaryDirectory(prefix='transport-api-');cls.addClassCleanup(cls.tmp.cleanup)
  p=Path(cls.tmp.name);(p/'probe.c').write_text(FIXTURE.replace('/* PRODUCTION */',code));cls.binary=p/'probe'
  subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-I',str(ROOT),str(p/'probe.c'),'-o',str(cls.binary)],check=True)
 def test_production_api_contract(self):
  for mode in ('valid','owner','uid','gone','size','version','controls','pending','uncertain','reserved','request-reserved','nr','copy-request','copy-input','copy-output','null','saturate','v2','v2-size','v2-input','v2-reserved','v2-copy','v3','v3-size','v3-input','v3-copy-ops','v3-copy-bytes','v3-zc-ops','v3-zc-bytes','v3-v2-reserved','v3-copy-fault','v4','v4-size','v4-input','v4-copy'):
   with self.subTest(mode=mode):
    p=subprocess.run([str(self.binary),mode],capture_output=True,text=True)
    self.assertEqual(p.returncode,0,p.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
