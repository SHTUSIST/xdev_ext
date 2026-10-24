#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual GPU pool, CPU access guards and START window admission.

Only OS allocation/file boundaries and native completions are adapters. No
payload backing or software device/provider is created. The START fixture
certifies core scheduling/custody only, not native DMA or full graph execution.
"""
from pathlib import Path
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[5]


def function(source, signature):
    start = source.index(signature)
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


def struct(source, name):
    start = source.index("struct " + name + " {")
    return source[start:source.index("\n};", start) + 3] + "\n"


SHIM = r'''
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "io_uring/xdev_ext_mech_core.h"
#include "io_uring/xdev_ext_mech_step.h" /* P1: shared PEER geometry rule */
typedef uint64_t u64;typedef uint32_t u32;typedef uint8_t u8;
#define GFP_KERNEL 0
#define U32_MAX UINT32_MAX
#define EXPORT_SYMBOL_GPL(x)
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096UL
#define PAGE_MASK (~(PAGE_SIZE-1))
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p)||IS_ERR(p))
#define PTR_ERR(p) ((intptr_t)(p))
struct page {int unused;};struct xdev_ext_mech_pool;
struct file {int refs;};
static struct file authority={1};
static u64 allocation_len=8*65536ULL,allocation_gen=19;
static int alloc_calls,fail_alloc,claim_calls,claim_error,put_calls;
static void *allocate(size_t n){alloc_calls++;if(alloc_calls==fail_alloc)return NULL;return calloc(1,n);}
#define kzalloc(n,g) allocate(n)
#define kvmalloc_array(n,z,g) allocate((n)*(z))
#define kfree free
#define kvfree free
static struct file *xdev_ext_peer_file_claim(struct file *f,u64 *len,u64 *gen)
{assert(f);claim_calls++;if(claim_error)return ERR_PTR(claim_error);*len=allocation_len;*gen=allocation_gen;authority.refs++;return &authority;}
static void fput(struct file *f){assert(f==&authority&&f->refs>1);f->refs--;put_calls++;}
'''
GLUE = r'''
static int xdev_ext_mech_pool_frame_move(struct xdev_ext_mech_pool *p,u32 i,u32 from,u32 to)
{if(!p->state||i>=p->nr_frames)return -ERANGE;return xdev_ext_mech_frame_move(&p->state[i],from,to);}
struct xdev_ext_mech_call {u32 member,callsite,nr_frames,frame_size;const struct xdev_ext_mech_frame *frames;};
'''
SCHEDULER = r'''
#define spin_lock_irqsave(l,f) ((void)(l),(f)=0)
#define spin_unlock_irqrestore(l,f) ((void)(l),(void)(f))
#define GENMASK_ULL(h,l) (((~0ULL)<<(l))&((~0ULL)>>(63-(h))))
#define WARN_ON_ONCE(x) assert(!(x))
struct xdev_ext_mech_batch {u64 key;bool to_user,busy;u32 nr_frames,present,bytes;struct xdev_ext_mech_bstate bs;struct xdev_ext_mech_frame f[1];};
struct xdev_ext_mech_session {int lock;bool start_preparing,start_to_user;u64 start_left,start_seq;u32 start_user_len,frames;struct {u32 inflight;}ss;struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;struct xdev_ext_mech_batch batches[2];};
static int submitted,admission_error;
static struct xdev_ext_mech_batch *xdev_ext_mech_batch_get_locked(struct xdev_ext_mech_session *s)
{for(unsigned i=0;i<2;i++)if(!s->batches[i].busy){struct xdev_ext_mech_batch *b=&s->batches[i];b->busy=true;s->ss.inflight++;xdev_ext_mech_bstate_init(&b->bs,2);return b;}return NULL;}
static bool xdev_ext_mech_batch_put_locked(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,bool done)
{(void)done;assert(b->busy&&s->ss.inflight);b->busy=false;s->ss.inflight--;return false;}
static void xdev_ext_mech_set_err_locked(struct xdev_ext_mech_session *s,int err){(void)s;admission_error=err;}
static void xdev_ext_mech_notify_locked(struct xdev_ext_mech_session *s,bool terminal){(void)s;(void)terminal;}
static void xdev_ext_mech_return_idle(struct xdev_ext_mech_session *s,bool unused){(void)s;(void)unused;}
static void xdev_ext_mech_abort(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,int err){(void)s;(void)b;assert(!err);}
static void xdev_ext_mech_batch_run(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b)
{assert(s->pool.kind==3&&b->bs.state==XDEV_EXT_MECH_B_READY&&b->nr_frames==1&&b->present==1&&b->bytes==4096);assert(!b->f[0].kaddr&&!b->f[0].pool_priv&&b->f[0].data_len==4096&&!b->f[0].data_off);assert(b->f[0].umem_addr==(u64)b->f[0].index*65536);submitted++;}
'''
MAIN = r'''
static void reset(void){alloc_calls=fail_alloc=claim_calls=claim_error=put_calls=0;allocation_len=8*65536ULL;allocation_gen=19;assert(authority.refs==1);}
struct racer {struct xdev_ext_mech_pool *p;struct xdev_ext_mech_frame f;int result;};
static void *allocate_frame(void *arg){struct racer *r=arg;r->result=xdev_ext_peer_pool_alloc(r->p,&r->f,1);return NULL;}
int main(void)
{
 struct xdev_ext_mech_layout l={.frame_size=65536,.seg_len=4096,.group_bytes=4096};
 struct xdev_ext_mech_pool p={};struct file original={1};struct xdev_ext_mech_frame frames[8]={};
 struct xdev_ext_mech_call call={.member=XDEV_EXT_MECH_MEMBER_BUILD,.callsite=XDEV_EXT_MECH_SITE_WORKER,.nr_frames=1,.frame_size=65536,.frames=frames};
 reset();l.hdr_room=16;assert(xdev_ext_peer_mech_pool_bind(&p,&original,&l)==-EOPNOTSUPP&&!claim_calls);l.hdr_room=0;
 fail_alloc=1;assert(xdev_ext_peer_mech_pool_bind(&p,&original,&l)==-ENOMEM&&!claim_calls);reset();
 claim_error=-EPERM;assert(xdev_ext_peer_mech_pool_bind(&p,&original,&l)==-EPERM&&claim_calls==1&&!put_calls);reset();
 fail_alloc=2;assert(xdev_ext_peer_mech_pool_bind(&p,&original,&l)==-ENOMEM&&claim_calls==1&&put_calls==1);reset();
 allocation_len=65535;assert(xdev_ext_peer_mech_pool_bind(&p,&original,&l)==-EINVAL&&put_calls==1);reset();
 allocation_len=((u64)UINT32_MAX+1)*65536;assert(xdev_ext_peer_mech_pool_bind(&p,&original,&l)==-EINVAL&&put_calls==1);reset();
 puts("ok 1 - actual pool binding rejects unsupported layout, propagates authority failure, unwinds state-allocation and geometry failure");
 assert(!xdev_ext_peer_mech_pool_bind(&p,&original,&l));
 assert(p.kind==3&&p.frame_size==65536&&p.size==8*65536ULL&&p.nr_frames==8&&p.state&&!p.pages&&!p.vaddr&&!p.nr_pages);
 assert(p.capabilities&XDEV_EXT_BINDING_CAP_ZERO_COPY);
 assert(xdev_ext_peer_mech_pool_file(&p)==&authority&&xdev_ext_peer_mech_pool_generation(&p)==19);
 /* Updated for P1: multi-frame batches; 75b51c2 refused nr != 1 here. */
 assert(!xdev_ext_peer_pool_alloc(&p,frames,2)&&frames[0].index==0&&frames[1].index==1);memset(p.state,XDEV_EXT_MECH_F_K_FREE,8);
 for(unsigned i=0;i<8;i++){
  u32 off=0,len=0;assert(!xdev_ext_peer_pool_alloc(&p,&frames[i],1)&&frames[i].index==i&&p.state[i]==XDEV_EXT_MECH_F_HELD);
  frames[i].kaddr=(void*)1;frames[i].pool_priv=(void*)1;
  assert(!xdev_ext_peer_pool_resolve(&p,&frames[i])&&!frames[i].kaddr&&!frames[i].pool_priv&&frames[i].umem_addr==(u64)i*65536);
  assert(!xdev_ext_mech_frame_page(&p,&frames[i],0,&off,&len));
 }
 assert(xdev_ext_peer_pool_alloc(&p,&(struct xdev_ext_mech_frame){},1)==-ENOSPC);
 assert(!xdev_ext_mech_frame_bytes(&call,0,0,16));call.member=XDEV_EXT_MECH_MEMBER_COMPLETE;assert(!xdev_ext_mech_frame_bytes(&call,0,0,16));
 frames[0].kaddr=frames;assert(xdev_ext_mech_frame_bytes(&call,0,0,16)==(u8*)frames);frames[0].kaddr=NULL;
 assert(xdev_ext_peer_pool_resolve(&p,&(struct xdev_ext_mech_frame){.index=8})==-ERANGE);
 puts("ok 2 - actual pool allocates only ownership words and allocation offsets; page helper and BPF frame byte access reject GPU payload");
 for(unsigned i=0;i<8;i++){p.state[i]=XDEV_EXT_MECH_F_SEQUESTERED;xdev_ext_peer_pool_recycle(&p,&frames[i]);assert(p.state[i]==XDEV_EXT_MECH_F_SEQUESTERED);}
 assert(xdev_ext_peer_pool_alloc(&p,&(struct xdev_ext_mech_frame){},1)==-ENOSPC);
 memset(p.state,XDEV_EXT_MECH_F_K_FREE,8);
 {pthread_t threads[8];struct racer r[8]={};unsigned mask=0;for(int i=0;i<8;i++){r[i].p=&p;assert(!pthread_create(&threads[i],NULL,allocate_frame,&r[i]));}for(int i=0;i<8;i++){assert(!pthread_join(threads[i],NULL)&&!r[i].result);assert(!(mask&(1U<<r[i].f.index)));mask|=1U<<r[i].f.index;}assert(mask==255);}
 p.ops->release(&p);assert(authority.refs==1&&put_calls==1);
 puts("ok 3 - actual pool never recycles sequestered GPU frames; concurrent allocations have distinct custody and normal release returns authority once");
 reset();memset(&p,0,sizeof(p));allocation_len=2*65536;assert(!xdev_ext_peer_mech_pool_bind(&p,&original,&l));
 {struct xdev_ext_mech_session s={.start_left=257,.frames=1,.pool=p,.layout=l};unsigned finished=0,waves=0;
  xdev_ext_mech_start_more(&s);assert(s.ss.inflight==2&&submitted==2&&s.start_left==255);
  while(s.ss.inflight){assert(++waves<=257);for(int i=0;i<2;i++)if(s.batches[i].busy){struct xdev_ext_mech_batch *b=&s.batches[i];assert(b->key==finished++);assert(!xdev_ext_mech_pool_frame_move(&s.pool,b->f[0].index,XDEV_EXT_MECH_F_HELD,XDEV_EXT_MECH_F_K_FREE));assert(!xdev_ext_mech_batch_put_locked(&s,b,true));}xdev_ext_mech_start_more(&s);}
  assert(finished==257&&submitted==257&&!s.start_left&&s.start_seq==257&&!admission_error);for(int i=0;i<2;i++)assert(s.pool.state[i]==XDEV_EXT_MECH_F_K_FREE);
  s.pool.ops->release(&s.pool);
 }
 puts("ok 4 - actual START scheduling admits 257 groups through a two-frame GPU window from one initial START budget, no continuation or CPU backing");
 return 0;
}
'''


def execute(pool, start, support, directory, name):
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text(SHIM + support + pool + SCHEDULER + start + MAIN)
    compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-pthread", "-I" + str(KERNEL), str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)


def main():
    contract = (KERNEL / "include/linux/xdev_ext_mech.h").read_text()
    ops = (KERNEL / "io_uring/xdev_ext_mech_ops.c").read_text()
    core = (KERNEL / "io_uring/xdev_ext_mech.c").read_text()
    pool = (KERNEL / "io_uring/xdev_ext_mech_peer_pool.c").read_text()
    pool = pool[pool.index("struct xdev_ext_peer_mech_pool {"):]
    support = "".join(struct(contract, name) for name in ("xdev_ext_mech_frame", "xdev_ext_mech_pool_ops", "xdev_ext_mech_pool")) + GLUE + function(contract, "static inline struct page *xdev_ext_mech_frame_page(") + function(ops, "static u8 *xdev_ext_mech_frame_bytes(")
    start = function(core, "static void xdev_ext_mech_start_more(")
    mutations = [
        ("GPU offset shifted", pool.replace("(u64)f->index * pool->frame_size", "(u64)(f->index + 1) * pool->frame_size"), start),
        ("fake CPU address exposed", pool.replace("f->kaddr = NULL", "f->kaddr = (void *)1"), start),
        ("allocation authority not released", pool.replace("fput(p->authority);", "(void)p->authority;"), start),
        ("START fills only one slot", pool, start.replace("for (;;) {", "for (int once = 0; once < 1; once++) {")),
    ]
    with tempfile.TemporaryDirectory(prefix="independent-peer-pool-") as tmp:
        directory = Path(tmp)
        result = execute(pool, start, support, directory, "actual")
        print(result.stdout, end="")
        assert result.returncode == 0, result.stderr
        for i, (name, changed_pool, changed_start) in enumerate(mutations):
            assert (changed_pool, changed_start) != (pool, start), name
            result = execute(changed_pool, changed_start, support, directory, "mutation" + str(i))
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
