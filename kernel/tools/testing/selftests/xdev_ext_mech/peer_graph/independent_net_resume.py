#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the actual NET class against transient refusal after a sent prefix.

The mechanism core rebuilds a refused batch (its batch private area is zeroed
and the BPF plan validated again) before it calls submit again. This test
drives exactly that sequence through the real NET bind/validate/submit code
with deterministic native-send adapters. It also checks the device-removal
and STOP hooks the NET class registers. No device, DMA or wire is involved.
"""
from pathlib import Path
import subprocess
import sys
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
#define UNUSED __attribute__((unused))
struct file {bool control;};static struct file allocation={false};
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;void *pool_priv;};
struct xdev_ext_mech_pool {u32 kind,nr_frames,frame_size;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout layout;struct xdev_ext_mech_peer peer;bool admits;};
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;struct file *file;void *priv;u32 direction;};
struct xdev_ext_mech_batch {void *priv;struct xdev_ext_mech_frame f;u32 frames,bytes;u64 ticket,id;};
struct xdev_ext_peer_net_endpoint {u32 mtu;int refs;};
static struct xdev_ext_peer_net_endpoint endpoint={1500,0};
static int calls,completed,sequestered,completion_status,results[16],accepted_results[16],stage_dead_calls,stage_dead_err,stop_checks;
static u64 observed_offsets[16];static u8 observed_headers[16];static bool observed_accepted[16];
static void (*registered_dead)(void *);static void *registered_arg;
static struct xdev_ext_mech_stage *dead_stage;
static void xdev_ext_net_dead(struct xdev_ext_mech_stage *st);
static bool xdev_ext_peer_control_file(struct file *f){return f&&f->control;}
static UNUSED struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind(u32 ifindex,u32 queue)
{assert(ifindex==4&&queue==2);endpoint.refs++;return &endpoint;}
static UNUSED struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_stage(u32 ifindex,u32 queue,void(*dead)(void*),void *arg)
{assert(ifindex==4&&queue==2&&dead&&arg);registered_dead=dead;registered_arg=arg;endpoint.refs++;return &endpoint;}
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
static UNUSED u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b){return b->id;}
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch *b,u64 ticket,int status){assert(ticket==b->ticket&&!completed&&!sequestered);completed++;completion_status=status;}
static void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch *b,u64 ticket,int status){assert(ticket==b->ticket&&!completed&&!sequestered);sequestered++;completion_status=status;}
/* Same contract as the core: stop the session, then the class mark_dead. */
static UNUSED void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int err)
{stage_dead_calls++;stage_dead_err=err;dead_stage=st;st->s->admits=false;xdev_ext_net_dead(st);}
static int record_send(struct xdev_ext_peer_net_endpoint *e,struct file *f,u64 gen,const struct xdev_ext_peer_net_desc *d,bool *accepted)
{int i=calls++;assert(i<16&&e==&endpoint&&f==&allocation&&gen==37&&!d->reserved);observed_offsets[i]=d->offset;observed_headers[i]=d->header[0];*accepted=accepted_results[i];observed_accepted[i]=!results[i]||accepted_results[i];return results[i];}
static UNUSED int xdev_ext_peer_net_send(struct xdev_ext_peer_net_endpoint *e,struct file *f,u64 gen,const struct xdev_ext_peer_net_desc *d,bool *accepted)
{return record_send(e,f,gen,d,accepted);}
static UNUSED int xdev_ext_peer_net_send_stoppable(struct xdev_ext_peer_net_endpoint *e,struct file *f,u64 gen,const struct xdev_ext_peer_net_desc *d,bool *accepted,bool(*stopped)(void*),void *arg)
{assert(stopped&&arg);stop_checks++;assert(stopped(arg)==!((struct xdev_ext_mech_stage*)arg)->s->admits);return record_send(e,f,gen,d,accepted);}
'''
MAIN = r'''
struct fixture {struct xdev_ext_mech_session s;struct xdev_ext_mech_stage st;struct file control;struct xdev_ext_net_batch bp;struct xdev_ext_mech_batch b;struct xdev_ext_net_send_desc d[16];};
static void initialize(struct fixture *f)
{memset(f,0,sizeof(*f));f->s=(struct xdev_ext_mech_session){.pool={3,4,65536},.layout={65536,0,3000,3000},.peer={.local_mac={1},.peer_mac={2}},.admits=true};f->control.control=true;f->st=(struct xdev_ext_mech_stage){.s=&f->s,.file=&f->control,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};f->b=(struct xdev_ext_mech_batch){.priv=&f->bp,.f={.umem_addr=65536,.index=1,.data_len=3000},.frames=1,.bytes=3000,.ticket=71,.id=9};for(int i=0;i<3;i++)f->d[i]=(struct xdev_ext_net_send_desc){.frame_off=i*1000,.len=1000,.header_len=42,.header={0xA0+i}};calls=completed=sequestered=completion_status=stage_dead_calls=stage_dead_err=stop_checks=0;registered_dead=NULL;registered_arg=NULL;dead_stage=NULL;memset(results,0,sizeof(results));memset(observed_accepted,0,sizeof(observed_accepted));for(int i=0;i<16;i++)accepted_results[i]=true;endpoint.mtu=1500;assert(!endpoint.refs);}
static int bind(struct fixture *f){struct xdev_ext_mech_stage_uapi u={.arg0=4,.arg1=2};return xdev_ext_net_bind(&f->st,&u);}
/* The core's xdev_ext_mech_build(): zero the batch private area, validate. */
static int rebuild(struct fixture *f){memset(&f->bp,0,sizeof(f->bp));return xdev_ext_net_validate(&f->st,&f->b,(const u8*)f->d,3);}
static int sent_once(u64 offset){int n=0;for(int i=0;i<calls;i++)n+=observed_offsets[i]==offset&&observed_accepted[i];return n;}
static int case_resume(void)
{
 struct fixture f;struct xdev_ext_net_mech_cqe cqe;
 initialize(&f);assert(!bind(&f)&&!rebuild(&f));results[1]=-EAGAIN;accepted_results[1]=false;
 int ret=xdev_ext_net_submit(&f.st,&f.b);
 if(ret!=-EAGAIN||completed||sequestered){fprintf(stderr,"RED transient refusal at descriptor 1 ended the group: submit=%d completed=%d status=%d; ordered NET aborts the session\n",ret,completed,completion_status);return 1;}
 assert(calls==2);
 /* Retry after the core rebuilt the batch: resume at the refused entry. */
 f.b.ticket=72;assert(!rebuild(&f));assert(!xdev_ext_net_submit(&f.st,&f.b));
 assert(calls==4&&completed==1&&!sequestered&&!completion_status);
 assert(observed_offsets[2]==66536&&observed_offsets[3]==67536&&observed_headers[2]==0xA1&&observed_headers[3]==0xA2);
 assert(sent_once(65536)==1&&sent_once(66536)==1&&sent_once(67536)==1);
 xdev_ext_net_fill_cqe(&f.st,&f.b,&cqe);assert(!cqe.status&&!cqe.outcome&&cqe.entries_done==3&&cqe.bytes_sent==3000);
 /* A second refusal at the last entry resumes again from there. */
 xdev_ext_net_unbind(&f.st);initialize(&f);assert(!bind(&f)&&!rebuild(&f));results[1]=-EAGAIN;accepted_results[1]=false;results[3]=-EAGAIN;accepted_results[3]=false;
 assert(xdev_ext_net_submit(&f.st,&f.b)==-EAGAIN&&calls==2);
 assert(!rebuild(&f)&&xdev_ext_net_submit(&f.st,&f.b)==-EAGAIN&&calls==4&&!completed);
 assert(!rebuild(&f)&&!xdev_ext_net_submit(&f.st,&f.b)&&calls==5&&completed==1&&!completion_status);
 assert(observed_offsets[4]==67536&&sent_once(65536)==1&&sent_once(66536)==1&&sent_once(67536)==1);
 xdev_ext_net_fill_cqe(&f.st,&f.b,&cqe);assert(cqe.entries_done==3&&cqe.bytes_sent==3000);
 xdev_ext_net_unbind(&f.st);
 puts("ok 1 - actual NET resumes a transiently refused group at the refused descriptor; every descriptor is transmitted exactly once");
 return 0;
}
static int case_plan_change(void)
{
 struct fixture f;struct xdev_ext_net_mech_cqe cqe;
 initialize(&f);assert(!bind(&f)&&!rebuild(&f));results[1]=-EAGAIN;accepted_results[1]=false;
 if(xdev_ext_net_submit(&f.st,&f.b)!=-EAGAIN){fprintf(stderr,"RED no resumable refusal exists to protect\n");return 1;}
 f.d[2].header[0]=0x55;
 assert(rebuild(&f)==-EPROTO&&calls==2);
 xdev_ext_net_fill_cqe(&f.st,&f.b,&cqe);assert(cqe.entries_done==1&&cqe.bytes_sent==1000&&cqe.outcome==1&&cqe.status==-EPROTO);
 /* A later batch is a new group and starts at its first descriptor. */
 f.d[2].header[0]=0xA2;f.b.id=10;assert(!rebuild(&f)&&!xdev_ext_net_submit(&f.st,&f.b)&&calls==5&&observed_offsets[2]==65536);
 xdev_ext_net_unbind(&f.st);
 initialize(&f);assert(!bind(&f)&&!rebuild(&f));results[1]=-EAGAIN;accepted_results[1]=false;
 assert(xdev_ext_net_submit(&f.st,&f.b)==-EAGAIN);
 f.b.id=11;assert(!rebuild(&f)&&!xdev_ext_net_submit(&f.st,&f.b)&&calls==5&&observed_offsets[2]==65536&&completed==1);
 xdev_ext_net_unbind(&f.st);
 puts("ok 2 - actual NET refuses a changed plan on resume and never applies a stale resume point to another batch");
 return 0;
}
static int case_terminal(void)
{
 struct fixture f;
 initialize(&f);assert(!bind(&f)&&!rebuild(&f));results[1]=-ENETDOWN;accepted_results[1]=false;
 assert(!xdev_ext_net_submit(&f.st,&f.b)&&calls==2&&completed==1&&completion_status==-ENETDOWN);
 assert(f.bp.cqe.entries_done==1&&f.bp.cqe.bytes_sent==1000&&f.bp.cqe.outcome==1);xdev_ext_net_unbind(&f.st);
 initialize(&f);assert(!bind(&f)&&!rebuild(&f));results[0]=-EAGAIN;accepted_results[0]=false;
 assert(xdev_ext_net_submit(&f.st,&f.b)==-EAGAIN&&calls==1&&!completed);
 assert(!rebuild(&f)&&!xdev_ext_net_submit(&f.st,&f.b)&&calls==4&&observed_offsets[1]==65536&&completed==1);xdev_ext_net_unbind(&f.st);
 initialize(&f);assert(!bind(&f)&&!rebuild(&f));results[1]=-EIO;
 assert(!xdev_ext_net_submit(&f.st,&f.b)&&sequestered==1&&f.bp.cqe.outcome==2);xdev_ext_net_unbind(&f.st);
 puts("ok 3 - actual NET keeps permanent refusal and accepted native errors terminal for the group");
 return 0;
}
static int case_hooks(void)
{
 struct fixture f;
 initialize(&f);assert(!bind(&f)&&!rebuild(&f));
 if(!registered_dead){fprintf(stderr,"RED NET bind registers no device-removal callback; an unregistering netdev never marks the stage dead\n");xdev_ext_net_unbind(&f.st);return 1;}
 assert(!xdev_ext_net_submit(&f.st,&f.b));
 if(stop_checks!=3){fprintf(stderr,"RED NET sends cannot observe STOP while waiting for native completion (stop-aware sends=%d)\n",stop_checks);xdev_ext_net_unbind(&f.st);return 1;}
 xdev_ext_net_unbind(&f.st);
 initialize(&f);assert(!bind(&f)&&!rebuild(&f));
 registered_dead(registered_arg);
 assert(stage_dead_calls==1&&stage_dead_err==-ENXIO&&dead_stage==&f.st&&!f.s.admits);
 assert(xdev_ext_net_submit(&f.st,&f.b)==-ESHUTDOWN&&!calls);
 xdev_ext_net_unbind(&f.st);assert(!endpoint.refs);
 puts("ok 4 - actual NET registers a device-removal callback that stops the stage and sends that observe STOP");
 return 0;
}
int main(int argc,char **argv)
{
 assert(argc==2);
 if(!strcmp(argv[1],"resume"))return case_resume();
 if(!strcmp(argv[1],"plan_change"))return case_plan_change();
 if(!strcmp(argv[1],"terminal"))return case_terminal();
 if(!strcmp(argv[1],"hooks"))return case_hooks();
 return 2;
}
'''
CASES = ("resume", "plan_change", "terminal", "hooks")


def build(code, directory, name):
    source = directory / (name + ".c")
    binary = directory / name
    source.write_text(SHIM + code + MAIN)
    compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-Wno-address", "-fsanitize=undefined", "-I" + str(KERNEL), str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return binary


def run(binary, case):
    return subprocess.run([str(binary), case], capture_output=True, text=True, timeout=15)


def main():
    source = (KERNEL / "io_uring/xdev_ext_mech_net.c").read_text()
    code = source[source.index("struct xdev_ext_net_stage {"):source.index("static const struct xdev_ext_mech_class_ops")]
    mutations = [
        ("resume restarts at the first descriptor", "resume", code.replace("for (i = bp->cqe.entries_done; i < bp->nr; i++) {", "for (i = 0; i < bp->nr; i++) {")),
        ("transient refusal after a prefix ends the group", "resume", code.replace("if (!accepted && (!i || ret == -EAGAIN)) {", "if (!accepted && !i) {")),
        ("changed plan resumed", "plan_change", code.replace("memcmp(ns->resume.desc, bp->desc, nr * sizeof(bp->desc[0])))", "(memcmp(ns->resume.desc, bp->desc, nr * sizeof(bp->desc[0])) && false))")),
        ("stale resume point applied to another batch", "plan_change", code.replace("ns->resume.batch != xdev_ext_mech_batch_id(b)", "ns->resume.batch != xdev_ext_mech_batch_id(b) && false")),
        ("removal callback does not stop the stage", "hooks", code.replace("xdev_ext_mech_stage_dead(arg, -ENXIO);", "(void)arg;")),
    ]
    failed = []
    with tempfile.TemporaryDirectory(prefix="independent-net-resume-") as tmp:
        directory = Path(tmp)
        actual = build(code, directory, "actual")
        for case in CASES:
            result = run(actual, case)
            print(result.stdout, end="")
            if result.returncode:
                failed.append(case)
                print(result.stderr, end="", file=sys.stderr)
        if failed:
            raise SystemExit("not ok - actual NET failed: " + ", ".join(failed))
        for i, (name, case, changed) in enumerate(mutations):
            assert changed != code, name
            result = run(build(changed, directory, "mutation" + str(i)), case)
            assert result.returncode != 0, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by behavior assertions")


if __name__ == "__main__":
    main()
