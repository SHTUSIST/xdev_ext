#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute the default NET stage, real native contexts and tracker with metadata
adapters; no NIC, GPU, DMA, performance or physical completion is represented."""
import os
from pathlib import Path
import subprocess
import tempfile
KERNEL = Path(__file__).resolve().parents[5]
SHIM = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "io_uring/xdev_ext_mech_net_core.h"
#include "io_uring/xdev_ext_peer_net_track.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
enum dma_data_direction {DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE};
#define XDEV_EXT_PEER_HOST_TEST
#include "include/linux/xdev_ext_peer.h"
#define GFP_KERNEL 0
#define U32_MAX UINT32_MAX
#define NSEC_PER_MSEC 1000000ULL
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define WARN_ON_ONCE(x) (!!(x))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define min(a,b) ((a)<(b)?(a):(b))
#define kzalloc(n,g) calloc(1,n)
#define kvcalloc(n,s,g) calloc(n,s)
#define kvfree free
#define kfree free
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define msecs_to_jiffies(x) (x)
struct file {int unused;}; struct pci_dev {int unused;};
struct xdev_ext_mech_pool {u32 kind, frame_size, nr_frames;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool pool;struct xdev_ext_mech_layout l;struct xdev_ext_mech_peer peer;u32 depth;bool admits;};
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;struct file *file;void *priv;u32 direction;};
struct xdev_ext_mech_frame {void *kaddr;u64 umem_addr;u32 index,data_off,data_len;};
struct xdev_ext_mech_batch {void *priv;struct xdev_ext_mech_frame f[16];u32 nr;u64 ticket;int claims,publishes,status;bool sequester;};
struct xdev_ext_peer_net_endpoint {bool rx;};
static struct xdev_ext_peer_net_endpoint endpoint;
static struct pci_dev peer;
static struct file allocation;
static u64 now_ms;
static int live, retired, quarantined, posts, refusal, inline_complete;
static struct xdev_ext_peer_tx *tx_posted[16];
static struct xdev_ext_peer_rx *rx_posted[16];
static u64 ktime_get_boottime_ns(void){return now_ms*NSEC_PER_MSEC;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s){return &s->l;}
static const struct xdev_ext_mech_peer *xdev_ext_mech_session_peer(struct xdev_ext_mech_session *s){return &s->peer;}
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s){return s->depth;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s){return s->admits;}
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *s,int err){(void)err;s->s->admits=false;}
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p){assert(p->kind==3);return &allocation;}
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p){assert(p->kind==3);return 7;}
bool xdev_ext_peer_control_file(struct file *f){return f==&allocation;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b){return b->priv;}
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b){return b->nr;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 i,struct xdev_ext_mech_frame *f){if(i>=b->nr)return -EINVAL;*f=b->f[i];return 0;}
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 ticket){assert(ticket==b->ticket);if(b->claims)return -ESTALE;b->claims++;return 0;}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int status,bool sequester){assert(ticket==b->ticket&&b->claims==1&&!b->publishes);b->publishes++;b->status=status;b->sequester=sequester;}
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_dir(u32 i,u32 q,bool rx,void(*dead)(void*),void *arg){assert(i==4&&q==2&&dead&&arg);endpoint.rx=rx;return &endpoint;}
struct pci_dev *xdev_ext_peer_net_peer(struct xdev_ext_peer_net_endpoint *e){assert(e==&endpoint);return &peer;}
u32 xdev_ext_peer_net_mtu(struct xdev_ext_peer_net_endpoint *e){assert(e==&endpoint);return 1500;}
void xdev_ext_peer_net_unbind(struct xdev_ext_peer_net_endpoint *e){assert(e==&endpoint);}
int xdev_ext_peer_file_acquire(struct file *f,struct pci_dev *p,u64 gen,u64 off,u32 len,enum dma_data_direction dir,struct xdev_ext_peer_fd_lease *l){assert(f==&allocation&&p==&peer&&gen==7&&!l->file&&!l->lease.mapping);assert(dir==(endpoint.rx?DMA_FROM_DEVICE:DMA_TO_DEVICE));l->file=f;l->lease.mapping=(void *)1;l->lease.dma_address=0x10000000+off;l->lease.len=len;live++;return 0;}
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *l,bool quiesced){if(!l->file)return;live--;retired++;quarantined+=!quiesced;memset(l,0,sizeof(*l));}
int xdev_ext_peer_net_post_tx(struct xdev_ext_peer_net_endpoint *e,struct xdev_ext_peer_tx *tx){assert(e==&endpoint&&!e->rx);if(refusal)return refusal;tx_posted[posts++]=tx;if(inline_complete)for(;tx;tx=tx->next)tx->complete(tx,0,true);return 0;}
int xdev_ext_peer_net_post_rx(struct xdev_ext_peer_net_endpoint *e,struct xdev_ext_peer_rx *rx){assert(e==&endpoint&&e->rx);if(refusal)return refusal;rx_posted[posts++]=rx;return 0;}
int xdev_ext_peer_net_rx_flush(struct xdev_ext_peer_net_endpoint *e){assert(e==&endpoint&&e->rx);for(int i=0;i<posts;i++){struct xdev_ext_peer_rx *rx=rx_posted[i];if(!rx)continue;rx_posted[i]=NULL;for(;rx;rx=rx->next)rx->complete(rx,-ECANCELED,0,0,true);}return 0;}
'''
MAIN = r'''
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_net_batch bp[4];
static struct xdev_ext_mech_batch batches[4];
static void init(bool rx)
{
 live=retired=quarantined=posts=refusal=inline_complete=0;now_ms=10;
 memset(tx_posted,0,sizeof(tx_posted));memset(rx_posted,0,sizeof(rx_posted));memset(bp,0,sizeof(bp));memset(batches,0,sizeof(batches));
 session=(struct xdev_ext_mech_session){.pool={3,4096,16},.l={4096,0,3000,3000},.depth=4,.admits=true};
 stage=(struct xdev_ext_mech_stage){.s=&session,.file=&allocation,.direction=rx?XDEV_EXT_MECH_DIR_FROM_DEVICE:XDEV_EXT_MECH_DIR_TO_DEVICE};
 struct xdev_ext_mech_stage_uapi u={.arg0=4,.arg1=2|(rx?(42ULL<<32):0)};
 assert(!xdev_ext_net_bind(&stage,&u));
 for(int i=0;i<4;i++){
  batches[i]=(struct xdev_ext_mech_batch){.priv=&bp[i],.nr=1,.ticket=(u64)i+1};
  batches[i].f[0]=(struct xdev_ext_mech_frame){.umem_addr=(u64)i*4096,.index=(u32)i,.data_len=3000};
  struct xdev_ext_net_send_desc d[3]={0};int nr=3;
  if(rx)nr=xdev_ext_net_default_build(&stage,&batches[i],(u8*)d);
  else for(int j=0;j<3;j++)d[j]=(struct xdev_ext_net_send_desc){.frame_off=(u32)j*1000,.len=1000,.header_len=42};
  assert(nr>0&&!xdev_ext_net_validate(&stage,&batches[i],(u8*)d,(u32)nr));
 }
}
static void consume(int i){struct xdev_ext_net_rx_mech_cqe cqe;xdev_ext_net_fill_cqe(&stage,&batches[i],&cqe);assert(cqe.base.status==batches[i].status);}
static void complete_tx(int p,int status,bool q){for(struct xdev_ext_peer_tx *tx=tx_posted[p];tx;tx=tx->next)tx->complete(tx,status,q);}
int main(void)
{
 init(false);
 for(int i=0;i<3;i++)assert(!xdev_ext_net_submit(&stage,&batches[i]));
 assert(posts==3&&live==9&&!batches[0].publishes&&!batches[1].publishes);
 struct xdev_ext_peer_tx *tx=tx_posted[1];tx->next->next->complete(tx->next->next,0,true);tx->complete(tx,0,true);
 assert(!batches[1].publishes);tx->next->complete(tx->next,0,true);
 assert(batches[1].publishes==1&&!batches[1].status&&bp[1].cqe.base.bytes_sent==3000&&bp[1].cqe.base.entries_done==3);
 consume(1);assert(live==6);
 complete_tx(0,0,true);complete_tx(2,0,true);consume(0);consume(2);assert(!live&&!quarantined);
 xdev_ext_net_unbind(&stage);
 puts("ok 1 - actual async NET keeps three batches/nine native descriptors in flight; out-of-order callbacks publish each once; worker releases leases");
 init(false);refusal=-EAGAIN;assert(xdev_ext_net_submit(&stage,&batches[0])==-EAGAIN&&!live&&!posts&&!batches[0].publishes);refusal=0;inline_complete=1;
 assert(!xdev_ext_net_submit(&stage,&batches[0])&&batches[0].publishes==1);consume(0);assert(!live);xdev_ext_net_unbind(&stage);
 puts("ok 2 - whole-chain backpressure releases every preaccept lease; inline completion is supported");
 init(false);for(int i=0;i<3;i++)assert(!xdev_ext_net_submit(&stage,&batches[i]));session.admits=false;xdev_ext_net_progress(&stage);now_ms+=1000;xdev_ext_net_progress(&stage);
 for(int i=0;i<3;i++){assert(batches[i].publishes==1&&batches[i].status==-ECANCELED&&batches[i].sequester);consume(i);complete_tx(i,0,true);assert(batches[i].publishes==1);}
 assert(!live&&quarantined==9); /* Native callback contexts remain pinned. */
 puts("ok 3 - STOP abandons nine outstanding elements after one-second grace, quarantines every lease; late callbacks publish nothing");
 init(true);assert(!xdev_ext_net_submit(&stage,&batches[0]));struct xdev_ext_peer_rx *rx=rx_posted[0];memset(rx->header,0x5a,42);rx_posted[0]=NULL;
 rx->complete(rx,0,42,1000,true);
 assert(batches[0].publishes==1&&batches[0].status==-EMSGSIZE&&!batches[0].sequester);
 assert(bp[0].cqe.base.bytes_sent==1000&&bp[0].cqe.rx[0].payload_len==1000&&bp[0].cqe.rx[0].header_len==42&&bp[0].cqe.rx[0].header[0]==0x5a);
 consume(0);assert(!live&&!quarantined);xdev_ext_net_unbind(&stage);
 puts("ok 4 - short RX fails before lifecycle publication while preserving actual payload/header lengths and bytes in CQE");
 init(true);assert(!xdev_ext_net_submit(&stage,&batches[0]));session.admits=false;xdev_ext_net_progress(&stage);assert(batches[0].publishes==1&&batches[0].status==-ECANCELED&&!batches[0].sequester);consume(0);assert(!live);xdev_ext_net_unbind(&stage);
 puts("ok 5 - RX STOP flush completes posted elements before release; cancellation is quiesced");
 init(true);assert(!xdev_ext_net_submit(&stage,&batches[0]));now_ms+=30000;xdev_ext_net_progress(&stage);assert(batches[0].publishes==1&&!batches[0].sequester);consume(0);assert(!live&&!quarantined);xdev_ext_net_unbind(&stage);
 puts("ok 6 - RX deadline flushes native buffers before considering uncertain abandonment");
 return 0;
}
'''

def main():
    source = (KERNEL / "io_uring/xdev_ext_mech_net.c").read_text()
    code = source[source.index("/* Completion-driven NET:"):]
    code = code[:code.index("static const struct xdev_ext_mech_class_ops")]
    code = "\n".join(line for line in code.splitlines() if not line.startswith("#include"))
    # The real scheduler gates a later batch until the earlier native FIFO accepted it.
    assert ".flags = XDEV_EXT_MECH_CLASS_F_ORDERED | XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE" in source
    with tempfile.TemporaryDirectory(prefix="net-async-stage-") as tmp:
        p=Path(tmp);(p/"test.c").write_text(SHIM+code+MAIN)
        cmd=[os.environ.get("CC","cc"),"-std=gnu11","-Wall","-Wextra","-Werror","-Wno-unused-function","-fsanitize=undefined","-fno-sanitize-recover=undefined","-I"+str(KERNEL),str(p/"test.c"),"-o",str(p/"test")]
        subprocess.run(cmd,check=True)
        subprocess.run([str(p/"test")],check=True)
if __name__=="__main__":main()
