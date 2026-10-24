#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual generic NET binding, descriptor admission and native results.

Native-send/OS boundaries are deterministic adapters. No software device,
payload provider, physical DMA or remote delivery is claimed by this test.
"""
# P4: this checks the one-at-a-time synchronous NET path, kept under XDEV_EXT_PEER_NET_SYNC_ONE.
from pathlib import Path
import subprocess
import tempfile

KERNEL = Path(__file__).resolve().parents[5]
SHIM = r'''
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_net_core.h"
#include "io_uring/xdev_ext_mech_step.h"
#include "include/uapi/linux/xdev_ext_peer.h"
typedef uint32_t u32;typedef uint64_t u64;typedef uint8_t u8;
#define GFP_KERNEL 0
#define U32_MAX UINT32_MAX
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define ERR_PTR(e) ((void*)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((intptr_t)(p))
#define kzalloc(n,g) calloc(1,n)
#define kfree free
struct file {bool control;};static struct file allocation={false};
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;void *pool_priv;};
struct xdev_ext_mech_pool {u32 kind,nr_frames,frame_size;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;struct xdev_ext_mech_peer peer;bool admits;};
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;struct file *file;void *priv;u32 direction;};
struct xdev_ext_mech_batch {void *priv;struct xdev_ext_mech_frame f;u32 frames,bytes;u64 ticket,id;};
struct xdev_ext_peer_net_endpoint {u32 mtu;int refs;};
static struct xdev_ext_peer_net_endpoint endpoint={1500,0};
static int bind_error,calls,completed,sequestered,completion_status,results[16],accepted_results[16];
static u64 observed_offsets[16];static u32 observed_bytes[16];static u8 observed_headers[16];
static bool xdev_ext_peer_control_file(struct file *f){return f&&f->control;}
static struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_stage(u32 ifindex,u32 queue,void(*dead)(void*),void *arg)
{assert(ifindex==4&&queue==2&&dead&&arg);if(bind_error)return ERR_PTR(bind_error);endpoint.refs++;return &endpoint;}
static void xdev_ext_peer_net_unbind(struct xdev_ext_peer_net_endpoint *e){assert(e==&endpoint&&e->refs>0);e->refs--;}
static u32 xdev_ext_peer_net_mtu(struct xdev_ext_peer_net_endpoint *e){assert(e==&endpoint);return e->mtu;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s){return &s->layout;}
static const struct xdev_ext_mech_peer *xdev_ext_mech_session_peer(struct xdev_ext_mech_session *s){return &s->peer;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s){return s->admits;}
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p){assert(p->kind==3);return 37;}
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p){assert(p->kind==3);return &allocation;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b){return b->frames;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 pos,struct xdev_ext_mech_frame *f){if(pos||!b->frames)return -ERANGE;*f=b->f;return 0;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b){return b->priv;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b,u64 ticket,int status){assert(ticket==b->ticket&&!completed&&!sequestered);completed++;completion_status=status;}
static void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch *b,u64 ticket,int status){assert(ticket==b->ticket&&!completed&&!sequestered);sequestered++;completion_status=status;}
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b){return b->id;}
static void xdev_ext_net_dead(struct xdev_ext_mech_stage *st);
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err){assert(err==-ENXIO);st->s->admits=false;xdev_ext_net_dead(st);}
static int xdev_ext_peer_net_send_stoppable(struct xdev_ext_peer_net_endpoint *e,struct file *f,u64 gen,const struct xdev_ext_peer_net_desc *d,bool *accepted,bool(*stopped)(void*),void *arg)
{int i=calls++;assert(stopped&&arg&&!stopped(arg));assert(i<16&&e==&endpoint&&f==&allocation&&gen==37&&!d->reserved);observed_offsets[i]=d->offset;observed_bytes[i]=d->bytes;observed_headers[i]=d->header[0];*accepted=accepted_results[i];return results[i];}
'''
MAIN = r'''
struct fixture {struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;struct file control;struct xdev_ext_net_batch bp;struct xdev_ext_mech_batch b;struct xdev_ext_net_send_desc d[16];};
static void initialize(struct fixture *f)
{memset(f,0,sizeof(*f));f->s=(struct xdev_ext_mech_session){.pool={3,4,65536},.layout={65536,0,3000,3000},.peer={.local_mac={1},.peer_mac={2}},.admits=true};f->control.control=true;f->st=(struct xdev_ext_mech_stage){.s=&f->s,.file=&f->control,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};f->b=(struct xdev_ext_mech_batch){.priv=&f->bp,.f={.umem_addr=65536,.index=1,.data_len=3000},.frames=1,.bytes=3000,.ticket=71};for(int i=0;i<3;i++)f->d[i]=(struct xdev_ext_net_send_desc){.frame_off=i*1000,.len=1000,.header_len=42,.header={0xA0+i}};calls=completed=sequestered=completion_status=bind_error=0;memset(results,0,sizeof(results));for(int i=0;i<16;i++)accepted_results[i]=true;endpoint.mtu=1500;assert(!endpoint.refs);}
static int bind(struct fixture *f){struct xdev_ext_mech_stage_uapi u={.arg0=4,.arg1=2};return xdev_ext_net_bind(&f->st,&u);}
static int validate(struct fixture *f){return xdev_ext_net_validate(&f->st,&f->b,(const u8*)f->d,3);}
int main(void)
{
 struct fixture f;struct xdev_ext_net_mech_info info;struct xdev_ext_net_mech_cqe cqe;
 initialize(&f);f.s.pool.kind=2;assert(bind(&f)==-EOPNOTSUPP);
 initialize(&f);f.st.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;assert(bind(&f)==-EOPNOTSUPP);
 initialize(&f);f.control.control=false;assert(bind(&f)==-EINVAL);
 initialize(&f);bind_error=-EPERM;assert(bind(&f)==-EPERM&&!endpoint.refs);
 initialize(&f);assert(!bind(&f));xdev_ext_net_fill_info(&f.st,&f.b,&info);assert(info.generation==37&&info.nr_frames==1&&info.mtu==1500&&info.f[0].umem_addr==65536&&info.f[0].data_len==3000&&info.peer.local_mac[0]==1);
 xdev_ext_net_unbind(&f.st);assert(!f.st.priv&&!endpoint.refs);
 puts("ok 1 - actual NET binds only a peer pool/control fd/TX endpoint, preserves namespace-bind errors and exposes offset-only info");
 for(int bad=0;bad<19;bad++){
  initialize(&f);assert(!bind(&f));u32 nr=3;
  switch(bad){case 0:nr=0;break;case 1:nr=17;break;case 2:f.b.f.kaddr=(void*)1;break;case 3:f.b.f.index=4;break;case 4:f.b.f.umem_addr++;break;case 5:f.b.f.data_off=65537;break;case 6:f.b.f.data_len=65537;break;case 7:f.d[1].frame_pos=1;break;case 8:f.d[0].flags=1;break;case 9:f.d[2].reserved=1;break;case 10:f.d[1].frame_off--;break;case 11:f.d[1].frame_off++;break;case 12:f.d[0].len=3001;break;case 13:f.d[0].len=0;break;case 14:f.d[2].len--;break;case 15:f.d[0].header_len=13;break;case 16:f.d[0].header_len=129;break;case 17:endpoint.mtu=100;break;case 18:f.b.frames=2;break;}
  assert(xdev_ext_net_validate(&f.st,&f.b,(const u8*)f.d,nr)<0&&!calls);xdev_ext_net_unbind(&f.st);
 }
 puts("ok 2 - actual NET admission rejects gaps/overlap/short coverage, foreign frame, CPU address, bad headers/MTU, flags and entry bounds");
 initialize(&f);assert(!bind(&f)&&!validate(&f));f.d[0].frame_off=999;f.d[0].header[0]=0;
 assert(!xdev_ext_net_submit(&f.st,&f.b)&&calls==3&&completed==1&&!sequestered&&!completion_status);
 for(int i=0;i<3;i++)assert(observed_offsets[i]==65536+(u64)i*1000&&observed_bytes[i]==1000&&observed_headers[i]==0xA0+i);
 xdev_ext_net_fill_cqe(&f.st,&f.b,&cqe);assert(!cqe.status&&cqe.bytes_sent==3000&&cqe.entries_done==3&&!cqe.outcome);
 xdev_ext_net_unbind(&f.st);
 puts("ok 3 - actual NET snapshots BPF plan/header bytes and submits exact admitted GPU offsets once, with accurate successful-prefix counts");
 initialize(&f);assert(!bind(&f)&&!validate(&f));results[0]=-EAGAIN;accepted_results[0]=false;
 assert(xdev_ext_net_submit(&f.st,&f.b)==-EAGAIN&&calls==1&&!completed&&!sequestered&&!f.bp.cqe.entries_done);xdev_ext_net_unbind(&f.st);
 initialize(&f);assert(!bind(&f)&&!validate(&f));results[1]=-EAGAIN;accepted_results[1]=false;
 assert(xdev_ext_net_submit(&f.st,&f.b)==-EAGAIN&&calls==2&&!completed&&!sequestered);
 assert(f.bp.cqe.bytes_sent==1000&&f.bp.cqe.entries_done==1&&f.bp.cqe.outcome==1);
 memset(&f.bp,0,sizeof(f.bp));assert(!validate(&f)&&!xdev_ext_net_submit(&f.st,&f.b)&&calls==4&&completed==1&&!completion_status);
 assert(observed_offsets[2]==66536&&observed_offsets[3]==67536&&f.bp.cqe.entries_done==3&&f.bp.cqe.bytes_sent==3000);xdev_ext_net_unbind(&f.st);
 initialize(&f);assert(!bind(&f)&&!validate(&f));results[1]=-ENETDOWN;accepted_results[1]=false;
 assert(!xdev_ext_net_submit(&f.st,&f.b)&&calls==2&&completed==1&&!sequestered&&completion_status==-ENETDOWN);
 assert(f.bp.cqe.bytes_sent==1000&&f.bp.cqe.entries_done==1&&f.bp.cqe.outcome==1);xdev_ext_net_unbind(&f.st);
 puts("ok 4 - actual NET retries first and later transient backpressure from the refused entry, ends permanent refusal, and never resends an accepted prefix");
 initialize(&f);assert(!bind(&f)&&!validate(&f));results[1]=-EIO;
 assert(!xdev_ext_net_submit(&f.st,&f.b)&&calls==2&&!completed&&sequestered==1&&completion_status==-EIO);
 assert(f.bp.cqe.bytes_sent==1000&&f.bp.cqe.entries_done==1&&f.bp.cqe.outcome==2);xdev_ext_net_unbind(&f.st);
 initialize(&f);assert(!bind(&f)&&!validate(&f));xdev_ext_net_dead(&f.st);assert(xdev_ext_net_submit(&f.st,&f.b)==-ESHUTDOWN&&!calls);xdev_ext_net_unbind(&f.st);
 initialize(&f);assert(!bind(&f)&&!validate(&f));f.s.admits=false;assert(xdev_ext_net_submit(&f.st,&f.b)==-ESHUTDOWN&&!calls);xdev_ext_net_unbind(&f.st);
 for(int status=-4095;status<128;status++){int err;assert(xdev_ext_mech_complete_step(8,XDEV_EXT_MECH_RETRY,status,false,false,0,&err)!=XDEV_EXT_MECH_STEP_RETRY);}
 puts("ok 5 - actual NET accepted error sequesters once, stopped endpoints cannot send, and native completion RETRY never replays accepted work");
 return 0;
}
'''


def execute(code, plan, directory, name):
    source = directory / (name + ".c")
    binary = directory / name
    # A renamed included definition permits mutations of the actual pure plan
    # without replacing any assertion or using a copied implementation oracle.
    preamble = SHIM.replace('#include "io_uring/xdev_ext_mech_net_core.h"', '#define xdev_ext_net_plan_check original_plan\n#include "io_uring/xdev_ext_mech_net_core.h"\n#undef xdev_ext_net_plan_check')
    source.write_text(preamble + plan + code + MAIN)
    compiled = subprocess.run(["cc", "-std=gnu11", "-DXDEV_EXT_PEER_NET_SYNC_ONE", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-I" + str(KERNEL), str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)


def main():
    source = (KERNEL / "io_uring/xdev_ext_mech_net.c").read_text()
    code = source[source.index("struct xdev_ext_net_stage {"):source.index("static const struct xdev_ext_mech_class_ops")]
    source = (KERNEL / "io_uring/xdev_ext_mech_net_core.h").read_text()
    plan = source[source.index("static inline int xdev_ext_net_plan_check("):source.index("\n#endif")]
    mutations = [
        ("payload coverage omitted", code, plan.replace("return cur + 1 == info->nr_frames && bytes == f->data_len ? 0 : -EMSGSIZE;", "return 0;")),
        ("plan gap/overlap accepted", code, plan.replace("(__u64)f->data_off + bytes != d[i].frame_off", "((__u64)f->data_off + bytes != d[i].frame_off && false)")),
        ("accepted prefix replayed as refusal", code.replace("for (i = bp->cqe.entries_done; i < bp->nr; i++) {", "for (i = 0; i < bp->nr; i++) {"), plan),
        ("unknown error treated quiesced", code.replace("if (accepted) xdev_ext_mech_batch_sequester", "if (accepted && false) xdev_ext_mech_batch_sequester"), plan),
        ("GPU byte offset shifted", code.replace("f.umem_addr + bp->desc[i].frame_off", "f.umem_addr + bp->desc[i].frame_off + 1"), plan),
    ]
    with tempfile.TemporaryDirectory(prefix="independent-peer-net-graph-") as tmp:
        directory = Path(tmp)
        result = execute(code, plan, directory, "actual")
        print(result.stdout, end="")
        assert result.returncode == 0, result.stderr
        for i, (name, changed_code, changed_plan) in enumerate(mutations):
            assert (changed_code, changed_plan) != (code, plan), name
            result = execute(changed_code, changed_plan, directory, "mutation" + str(i))
            assert result.returncode != 0 and "Assertion" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
