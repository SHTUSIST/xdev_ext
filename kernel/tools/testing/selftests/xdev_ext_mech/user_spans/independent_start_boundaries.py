#!/usr/bin/env python3
"""Independent host execution of verbatim START production functions.

Only locks, userspace copies, pool/worker plumbing are fixtures. Pure admission,
layout, frame ownership and lifecycle are the real shared production headers.
Completion is modeled explicitly; this does not claim native/DMA/VM coverage.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]

def extract(text, name):
    import re
    match = re.search(r'^static (?:int|void) ' + name + r'\(', text, re.M)
    if not match:
        raise AssertionError(f'production function missing: {name}')
    end = text.index('{', match.start())
    depth = 1
    cursor = end + 1
    while depth:
        depth += (text[cursor] == '{') - (text[cursor] == '}')
        cursor += 1
    return text[match.start():cursor]

PREAMBLE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include "io_uring/xdev_ext_mech_step.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"
typedef __u32 u32;
typedef __u64 u64;
#define __user
#define GFP_KERNEL 0
#define BIT(n) (1U << (n))
#define GENMASK_ULL(h,l) (((~0ULL) << (l)) & ((~0ULL) >> (63-(h))))
#include "io_uring/xdev_ext_mech_start_queue.h"
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define IS_ERR(p) ((uintptr_t)(p) > (uintptr_t)-4096)
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define WARN_ON_ONCE(x) (x)
#define spin_lock_irqsave(l,f) do {(void)(l); (f)=0;} while (0)
#define spin_unlock_irqrestore(l,f) do {(void)(l); (void)(f);} while (0)
#define cond_resched() ((void)0)
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
#define kfree free
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM 1
struct xdev_ext_mech_frame {u32 index, data_off, data_len;};
struct xdev_ext_mech_pool;
struct pool_ops {
 int (*alloc)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *,u32);
 int (*resolve)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *);
 void (*recycle)(struct xdev_ext_mech_pool *,struct xdev_ext_mech_frame *);
};
struct xdev_ext_mech_pool {u32 kind, nr_frames,frame_size; const struct pool_ops *ops; __u8 custody[4]; u32 queue[4], count;};
struct fake_cls {u32 flags;};
struct xdev_ext_mech_batch {struct xdev_ext_mech_session *s;u64 key; bool ordered_loan,to_user; u32 nr_frames,present,bytes; struct xdev_ext_mech_frame f[4]; struct xdev_ext_mech_bstate bs;};
struct xdev_ext_mech_session {
 struct xdev_ext_mech_start_queue *start_queue;bool start_ordered;
 struct xdev_ext_mech_stage_uapi plan[1];u32 nr_stages;
 int lock; bool start_preparing,start_return_pending,start_recycle,start_to_user,worker_gone,admit;
 u32 frames,depth,start_user_len; u64 start_left,start_seq;
 struct {u32 inflight;} ss;
 struct xdev_ext_mech_pool pool;
 struct xdev_ext_mech_layout layout;
 struct {u32 direction; struct fake_cls *cls;} st[1];
 struct xdev_ext_mech_life life[4];
 void *worker; int stop_work,kick_work;
 struct xdev_ext_mech_batch batch;
};
struct io_ring_ctx {struct xdev_ext_mech_session *s;};
/* Legacy span scenarios must never enter ordered-queue branches. */
static void xdev_ext_mech_session_stop(struct xdev_ext_mech_session*s,int e){(void)s;(void)e;abort();}
static void xdev_ext_mech_trace_batch(struct xdev_ext_mech_batch*b,const char*tag,int e,int v){(void)b;(void)tag;(void)e;(void)v;}
static int inject_alloc_fail, inject_copy_fail, kicks, stops, runs, observed_len, observed_bytes;
static struct xdev_ext_mech_session *xdev_ext_mech_find(struct io_ring_ctx *c,u64 id){return id==7 ? c->s : NULL;}
static bool xdev_ext_mech_rx_first(struct xdev_ext_mech_session *s){(void)s;return false;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s){return s->admit;}
static int copy_from_user(void *d,const void *s,size_t n){if (!s || inject_copy_fail)return 1;memcpy(d,s,n);return 0;}
static void *kmemdup(const void *s,size_t n,int g){(void)g;if(inject_alloc_fail)return NULL;void *p=malloc(n);memcpy(p,s,n);return p;}
static void *memdup_array_user(const void *s,size_t n,size_t z){return kmemdup(s,n*z,0);}
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p,u32 i,u32 from,u32 to){return i>=p->nr_frames ? -ERANGE : xdev_ext_mech_frame_move(&p->custody[i],from,to);}
static int alloc_frame(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_frame *f,u32 n){
 if(n!=1 || !p->count)return -ENOSPC;
 f->index=p->queue[--p->count]; return xdev_ext_mech_pool_frame_move(p,f->index,XDEV_EXT_MECH_F_K_FREE,XDEV_EXT_MECH_F_HELD);
}
static int resolve_frame(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_frame *f){(void)p;(void)f;return 0;}
static void recycle_frame(struct xdev_ext_mech_pool *p,struct xdev_ext_mech_frame *f){p->queue[p->count++]=f->index;}
static const struct pool_ops ops={alloc_frame,resolve_frame,recycle_frame};
static void xdev_ext_mech_settle_locked(struct xdev_ext_mech_session *s){(void)s;}
static void xdev_ext_mech_notify_locked(struct xdev_ext_mech_session *s,bool idle){(void)s;(void)idle;}
static int kthread_queue_work(void *worker,int *work){(void)worker;(void)work;kicks++;return 1;}
static struct xdev_ext_mech_batch *xdev_ext_mech_batch_get_locked(struct xdev_ext_mech_session *s){
 if(s->ss.inflight || !s->admit)return NULL;
 s->ss.inflight++;memset(&s->batch,0,sizeof(s->batch));xdev_ext_mech_bstate_init(&s->batch.bs,1);return &s->batch;
}
static bool xdev_ext_mech_batch_put_locked(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,bool last){(void)b;(void)last;s->ss.inflight--;return false;}
static void xdev_ext_mech_set_err_locked(struct xdev_ext_mech_session *s,int r){(void)s;(void)r;}
static void xdev_ext_mech_return_idle(struct xdev_ext_mech_session *s,bool b){(void)s;(void)b;}
static void xdev_ext_mech_abort(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,int e){(void)s;(void)b;(void)e;stops++;}
static void xdev_ext_mech_batch_run(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b){(void)s;runs++;observed_len=b->f[0].data_len;observed_bytes=b->bytes;}
'''
TESTS = r'''
#define CHECK(x) do {if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static struct fake_cls cls;
static void init(struct xdev_ext_mech_session *s){
 memset(s,0,sizeof(*s));s->admit=true;s->frames=s->depth=s->nr_stages=1;s->pool.kind=XDEV_EXT_MECH_POOL_IOU_UMEM;
 s->pool.nr_frames=4;s->pool.frame_size=4096;s->pool.ops=&ops;s->layout=(struct xdev_ext_mech_layout){4096,32,1024,1024};
 s->st[0].direction=XDEV_EXT_MECH_DIR_TO_DEVICE;s->st[0].cls=&cls;
 inject_alloc_fail=inject_copy_fail=kicks=stops=runs=0;
}
static struct xdev_ext_mech_start request(struct xdev_ext_mech_user_span *span){return (struct xdev_ext_mech_start){.session_id=7,.nr_batches=1,.first_seq=91,.flags=XDEV_EXT_MECH_START_F_USER_FRAMES|XDEV_EXT_MECH_START_F_USER_SPANS,.nr_user_frames=1,.user_frames=(uintptr_t)span};}
static int check_arg(struct xdev_ext_mech_start *r,u32 pool,bool rx,u32 frames,u32 cap){return xdev_ext_mech_start_check(r,pool,rx,frames,cap);}
static int admission(void){
 CHECK(sizeof(struct xdev_ext_mech_start)==40);CHECK(sizeof(struct xdev_ext_mech_user_span)==8);CHECK(XDEV_EXT_MECH_START_F_USER_SPANS==(1U<<2));
 struct xdev_ext_mech_user_span span={0,17};struct xdev_ext_mech_start r=request(&span), b;
 CHECK(check_arg(&r,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==0);
 b=r;b.flags|=XDEV_EXT_MECH_START_F_ORDERED_FRAMES;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==-EOPNOTSUPP);
 for(unsigned bit=4;bit<32;bit++){b=r;b.flags|=1U<<bit;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==-EINVAL);}
 b=r;b.flags&=~XDEV_EXT_MECH_START_F_USER_FRAMES;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==-EINVAL);
 b=r;b.flags|=XDEV_EXT_MECH_START_F_RECYCLE;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==-EINVAL);
 b=r;b.nr_batches=0;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==-EINVAL);
 b=r;b.nr_batches=2;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==-EINVAL);
 b=r;b.nr_user_frames=2;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==-EINVAL);
 b=r;b.user_frames=0;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,4)==-EFAULT);
 CHECK(check_arg(&r,XDEV_EXT_MECH_POOL_XSK,false,1,4)==-EINVAL);
 CHECK(check_arg(&r,XDEV_EXT_MECH_POOL_IOU_UMEM,true,1,4)==-EINVAL);
 CHECK(check_arg(&r,XDEV_EXT_MECH_POOL_IOU_UMEM,false,0,4)==-EINVAL);
 CHECK(check_arg(&r,XDEV_EXT_MECH_POOL_IOU_UMEM,false,2,4)==-EINVAL);
 CHECK(check_arg(&r,XDEV_EXT_MECH_POOL_IOU_UMEM,false,1,0)==-ENOSPC);
 b=r;b.flags=0;b.user_frames=0;b.nr_user_frames=0;b.nr_batches=10;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,2,4)==0);
 b=r;b.flags=XDEV_EXT_MECH_START_F_USER_FRAMES;b.nr_batches=2;b.nr_user_frames=4;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,2,4)==0);
 b.flags|=XDEV_EXT_MECH_START_F_RECYCLE;b.nr_batches=5;CHECK(check_arg(&b,XDEV_EXT_MECH_POOL_IOU_UMEM,false,2,4)==0);
 return 0;
}
static int invalid_spans(void){
 struct xdev_ext_mech_session s;struct io_ring_ctx ctx={&s};struct xdev_ext_mech_user_span span;struct xdev_ext_mech_start r=request(&span);
 const u32 lens[]={0,1025,UINT32_MAX};
 for(unsigned i=0;i<3;i++){init(&s);span=(struct xdev_ext_mech_user_span){0,lens[i]};CHECK(xdev_ext_mech_start(&ctx,&r)==-EINVAL);CHECK(s.pool.count==0&&!s.start_preparing&&s.start_left==0&&kicks==0);CHECK(s.pool.custody[0]==XDEV_EXT_MECH_F_USER);}
 init(&s);span=(struct xdev_ext_mech_user_span){4,17};CHECK(xdev_ext_mech_start(&ctx,&r)==-EINVAL);CHECK(!s.start_preparing&&kicks==0);
 init(&s);span=(struct xdev_ext_mech_user_span){0,17};s.st[0].direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;CHECK(xdev_ext_mech_start(&ctx,&r)==-EINVAL);CHECK(!s.start_preparing&&kicks==0);
 init(&s);r.session_id=8;CHECK(xdev_ext_mech_start(&ctx,&r)==-ENOENT);
 return 0;
}
static int busy(void){
 struct xdev_ext_mech_session s;struct io_ring_ctx ctx={&s};struct xdev_ext_mech_user_span span={0,17};struct xdev_ext_mech_start r=request(&span);
 for(int c=0;c<5;c++){init(&s);if(c==0)s.start_preparing=true;if(c==1)s.start_return_pending=true;if(c==2)s.start_left=1;if(c==3)s.ss.inflight=1;if(c==4)s.admit=false;
 CHECK(xdev_ext_mech_start(&ctx,&r)==(c==4?-ESHUTDOWN:-EBUSY));CHECK(s.pool.count==0&&kicks==0&&s.pool.custody[0]==XDEV_EXT_MECH_F_USER);}
 init(&s);s.start_user_len=17;s.ss.inflight=1;r.flags=0;r.user_frames=0;r.nr_user_frames=0;CHECK(xdev_ext_mech_start(&ctx,&r)==-EBUSY);
 return 0;
}
static int failure_cleanup(void){
 struct xdev_ext_mech_session s;struct io_ring_ctx ctx={&s};struct xdev_ext_mech_user_span span={0,17};struct xdev_ext_mech_start r=request(&span);
 init(&s);inject_alloc_fail=1;CHECK(xdev_ext_mech_start(&ctx,&r)==-ENOMEM);CHECK(!s.start_preparing&&s.start_left==0&&s.pool.count==0);inject_alloc_fail=0;CHECK(xdev_ext_mech_start(&ctx,&r)==0);
 init(&s);s.pool.custody[0]=XDEV_EXT_MECH_F_HELD;CHECK(xdev_ext_mech_start(&ctx,&r)==-EBUSY);CHECK(!s.start_preparing&&s.start_left==0&&s.pool.count==0);s.pool.custody[0]=XDEV_EXT_MECH_F_USER;CHECK(xdev_ext_mech_start(&ctx,&r)==0);
 init(&s);s.life[0].ctrl=(1ULL<<3)|XDEV_EXT_MECH_L_READY;s.life[0].valid_len=11;CHECK(xdev_ext_mech_start(&ctx,&r)==-EBUSY);CHECK(!s.start_preparing&&s.pool.custody[0]==XDEV_EXT_MECH_F_USER&&s.pool.count==0);CHECK(s.life[0].valid_len==11&&xdev_ext_mech_life_phase(&s.life[0])==XDEV_EXT_MECH_L_READY);
 return 0;
}
static int lengths_and_repeat(void){
 struct xdev_ext_mech_session s;struct io_ring_ctx ctx={&s};struct xdev_ext_mech_user_span span={0,1};struct xdev_ext_mech_start r=request(&span);init(&s);
 const u32 lengths[]={1,17,1024,5};
 for(unsigned i=0;i<4;i++){
 span.len=lengths[i];CHECK(xdev_ext_mech_start(&ctx,&r)==0);CHECK(s.start_left==1&&!s.start_preparing);CHECK(s.life[0].valid_len==span.len&&xdev_ext_mech_life_phase(&s.life[0])==XDEV_EXT_MECH_L_READY);
 xdev_ext_mech_start_more(&s);CHECK(runs==(int)i+1);CHECK(observed_len==(int)span.len&&observed_bytes==(int)span.len);CHECK(s.batch.f[0].data_off==32&&s.start_left==0&&s.ss.inflight==1);CHECK(xdev_ext_mech_start(&ctx,&r)==-EBUSY);
 /* explicit completion fixture: terminal lifecycle and custody returned */
 CHECK(xdev_ext_mech_life_release(&s.life[0],xdev_ext_mech_life_gen(&s.life[0]))==0);
 CHECK(xdev_ext_mech_pool_frame_move(&s.pool,0,XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_USER)==0);s.ss.inflight=0;
 }
 u32 idx=0;r.flags=XDEV_EXT_MECH_START_F_USER_FRAMES;r.user_frames=(uintptr_t)&idx;CHECK(xdev_ext_mech_start(&ctx,&r)==0);CHECK(s.start_user_len==0);CHECK(s.life[0].valid_len==1024);xdev_ext_mech_start_more(&s);CHECK(observed_len==1024&&observed_bytes==1024);
 return 0;
}
int main(int argc,char **argv){if(argc!=2)return 2;if(!strcmp(argv[1],"admission"))return admission();if(!strcmp(argv[1],"invalid_spans"))return invalid_spans();if(!strcmp(argv[1],"busy"))return busy();if(!strcmp(argv[1],"failure_cleanup"))return failure_cleanup();if(!strcmp(argv[1],"lengths_and_repeat"))return lengths_and_repeat();return 2;}
'''

class IndependentStart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='independent-start-')
        text = (ROOT / 'io_uring/xdev_ext_mech.c').read_text()
        # Queue entrypoints are unreachable in this legacy USER_SPANS suite;
        # fail on entry, while compiling real legacy START/publication bodies.
        queue_names = ('xdev_ext_mech_start_queue_prepare',
                       'xdev_ext_mech_start_queue_rollback', 'xdev_ext_mech_start_queue_bind')
        queue_guards = '\n'.join(extract(text,n).split('{',1)[0] + '{ abort(); }' for n in queue_names)
        code = PREAMBLE + '\n' + queue_guards + '\n' + '\n'.join(extract(text, n) for n in (
            'xdev_ext_mech_take_user_frames', 'xdev_ext_mech_start', 'xdev_ext_mech_start_publication', 'xdev_ext_mech_start_more')) + '\n' + TESTS
        source = Path(cls.tmp.name) / 'fixture.c'
        cls.binary = Path(cls.tmp.name) / 'fixture'
        source.write_text(code)
        result = subprocess.run([os.getenv('CC','cc'), '-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-value','-Wno-unused-parameter','-I',str(ROOT),str(source),'-o',str(cls.binary)],capture_output=True,text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def test_production_boundaries(self):
        for case in ('admission','invalid_spans','busy','failure_cleanup','lengths_and_repeat'):
            with self.subTest(case=case):
                r = subprocess.run([str(self.binary),case],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stdout+r.stderr)

if __name__ == '__main__':
    unittest.main(verbosity=2)
