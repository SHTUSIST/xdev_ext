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
#include "include/uapi/linux/xdev_ext_mech.h"
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
struct xdev_ext_mech_class_ops { void (*transport_stats)(struct xdev_ext_mech_stage *,u32 *,u32 *); };
struct xdev_ext_mech_stage { const struct xdev_ext_mech_class_ops *cls; u32 pending,uncertain; };
struct xdev_ext_mech_session { struct list_head ring_node,live_node;u64 id;int uid,native_controls;u32 nr_stages;struct xdev_ext_mech_stage st[4]; };
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
/* PRODUCTION */
#define CHECK(c) do { if(!(c)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#c);return 1;} } while(0)
int main(int argc,char **argv)
{
 const char *mode=argc>1?argv[1]:"valid";
 struct io_ring_ctx ctx;init_list(&ctx.xdev_ext_mech_sessions);init_list(&xdev_ext_mech_live);
 const struct xdev_ext_mech_class_ops ops={.transport_stats=provider_stats},empty_ops={0};
 struct xdev_ext_mech_session s={.id=7,.uid=10,.native_controls=3,.nr_stages=3,
 .st={{.cls=&ops,.pending=2,.uncertain=1},{.cls=&ops,.pending=5,.uncertain=2},{.cls=&empty_ops}}};
 init_list(&s.ring_node);init_list(&s.live_node);add_list(&s.live_node,&xdev_ext_mech_live);
 if(!strcmp(mode,"owner"))add_list(&s.ring_node,&ctx.xdev_ext_mech_sessions);
 struct xdev_ext_mech_transport_stats wire={.size=32,.version=1,.session_id=7};
 struct io_uring_xdev_ext_mech req={.op=6,.arg=(uintptr_t)&wire};
 unsigned int nr=1;int expected=0;
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
  for mode in ('valid','owner','uid','gone','size','version','controls','pending','uncertain','reserved','request-reserved','nr','copy-request','copy-input','copy-output','null','saturate'):
   with self.subTest(mode=mode):
    p=subprocess.run([str(self.binary),mode],capture_output=True,text=True)
    self.assertEqual(p.returncode,0,p.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
