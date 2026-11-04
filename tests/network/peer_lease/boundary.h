/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>
#include <linux/types.h>
typedef __u64 u64;typedef __u32 u32;typedef __u16 u16;typedef __u8 u8;typedef __s32 s32;typedef u64 dma_addr_t;
#define U32_MAX UINT32_MAX
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
struct list_head {struct list_head *next,*prev;};
#define INIT_LIST_HEAD(h) do {(h)->next=(h);(h)->prev=(h);}while(0)
static void list_add_tail(struct list_head *n,struct list_head *h){n->next=h;n->prev=h->prev;h->prev->next=n;h->prev=n;}
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,__typeof__(*p),m); &p->m!=(h); p=container_of(p->m.next,__typeof__(*p),m))
struct mutex{int held;};static void mutex_lock(struct mutex *m){assert(!m->held);m->held++;}static void mutex_unlock(struct mutex *m){assert(m->held==1);m->held--;}
typedef struct mutex spinlock_t;
#define spin_lock_init(m) ((m)->held=0)
#define spin_lock_irqsave(m,f) do {(f)=0;mutex_lock(m);}while(0)
#define spin_unlock_irqrestore(m,f) do {(void)(f);mutex_unlock(m);}while(0)
typedef u64 atomic64_t;static u64 atomic64_inc_return(atomic64_t *p){return ++*p;}
struct file_operations{int id;};struct file{const struct file_operations *f_op;void *private_data;int refs;};struct pci_dev{int id;};
static void get_file(struct file *f){f->refs++;}static void fput(struct file *f){assert(f->refs>0);f->refs--;}
enum dma_data_direction{DMA_BIDIRECTIONAL=0,DMA_TO_DEVICE=1,DMA_FROM_DEVICE=2,DMA_NONE=3};
#define XDEV_EXT_PEER_HOST_TEST 1
#include "xdev_ext_peer.h"
#include "xdev_ext_mech_core.h"
#include "xdev_ext_netfam_core.h"
#include "xdev_ext_peer_net_track.h"
#include "xdev_ext_peer_net_core.h"
struct xdev_ext_rel_policy;
#define EXPORT_SYMBOL_GPL(x)
#define THIS_MODULE NULL
#define GFP_KERNEL 0
static int alloc_calls,alloc_fail;
static void *allocation(size_t n){alloc_calls++;return alloc_fail==alloc_calls?NULL:calloc(1,n);}
static void *kvcalloc(size_t n,size_t size,int flags){return allocation(n*size);}static void *kzalloc(size_t n,int flags){return allocation(n);}static void kvfree(void *p){free(p);}static void kfree(void *p){free(p);}
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define NSEC_PER_MSEC 1000000ULL
static u64 now_ms=100;
static u64 ktime_get_boottime_ns(void){return now_ms*NSEC_PER_MSEC;}static unsigned long msecs_to_jiffies(unsigned long n){return n;}
struct xdev_ext_mech_pool{struct file *authority;u64 generation;u32 nr_frames,frame_size;};
struct xdev_ext_mech_session{u32 depth;bool admits;struct xdev_ext_mech_pool pool;};
struct xdev_ext_mech_stage{void *priv;struct xdev_ext_mech_session *s;u32 direction;bool create_reporting;u32 create_phase;};
#include "actual_frame.h"
struct xdev_ext_mech_batch{struct xdev_ext_mech_session *s;struct xdev_ext_mech_frame frame[32];int frame_error;u32 bad_frame;u64 ticket;void *priv;unsigned claims,publishes;u64 claimed_ticket,published_ticket;int status;bool sequester;};
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s){return s->depth;}
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s){return s->admits;}
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return &s->pool;}
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p){return p->authority;}
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p){return p->generation;}
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 i,struct xdev_ext_mech_frame *f){if(b->frame_error && i==b->bad_frame)return b->frame_error;*f=b->frame[i];return 0;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b){return b->priv;}
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 ticket){b->claims++;b->claimed_ticket=ticket;return ticket==b->ticket?0:-ESTALE;}
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int status,bool sequester){b->publishes++;b->published_ticket=ticket;b->status=status;b->sequester=sequester;}
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *s,int error){(void)s;(void)error;}
#define EQ(a,b) do{long long va=(long long)(a),vb=(long long)(b);if(va!=vb){fprintf(stderr,"ASSERT %s:%d %s=%lld expected %s=%lld\n",__FILE__,__LINE__,#a,va,#b,vb);abort();}}while(0)
