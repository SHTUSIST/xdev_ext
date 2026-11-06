/* OS-only instrumentation and transparent fixture field declarations. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef int32_t s32;
typedef u8 __u8; typedef u16 __u16; typedef u32 __u32; typedef u64 __u64; typedef s32 __s32;
typedef u64 dma_addr_t;
#define U32_MAX UINT32_MAX
#define check_add_overflow(a,b,p) __builtin_add_overflow(a,b,p)
#define PAGE_SHIFT 12
#define PAGE_SIZE 4096ULL
#define PAGE_MASK (~(PAGE_SIZE-1))
#define XSK_NEXT_PG_CONTIG_MASK 1ULL
#define XSK_UNALIGNED_BUF_ADDR_MASK ((1ULL<<48)-1)
#define XSK_UNALIGNED_BUF_OFFSET_SHIFT 48
#define XDEV_EXT_MECH_MAX_FRAMES 16
#define XSK_BOUND 3
#define XDP_WAKEUP_TX 2
#define DMA_BIDIRECTIONAL 0
#define MAX_PER_SOCKET_BUDGET 16
#define EXPORT_SYMBOL(x)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define min(a,b) ((a)<(b)?(a):(b))
#define container_of(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
struct list_head {struct list_head *next,*prev;};
#define LIST_HEAD(name) struct list_head name={&name,&name}
#define INIT_LIST_HEAD(p) do {(p)->next=(p);(p)->prev=(p);}while(0)
static inline void list_add_tail(struct list_head *n,struct list_head *h){ n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n; }
static inline void list_del_init(struct list_head *n){n->prev->next=n->next;n->next->prev=n->prev;INIT_LIST_HEAD(n);}
#define list_for_each_entry_safe(p,n,h,m) for(p=container_of((h)->next,typeof(*p),m),n=container_of(p->m.next,typeof(*p),m); &p->m!=(h);p=n,n=container_of(n->m.next,typeof(*n),m))
#define list_for_each_entry(p,h,m) for(p=container_of((h)->next,typeof(*p),m); &p->m!=(h);p=container_of(p->m.next,typeof(*p),m))
#define list_for_each_entry_rcu(p,h,m) for(p=container_of((h)->next,typeof(*p),m); &p->m!=(h);p=container_of(p->m.next,typeof(*p),m))
#define list_is_singular(h) ((h)->next!=(h) && (h)->next==(h)->prev)
#define list_first_or_null_rcu(h,t,m) ((h)->next==(h)?NULL:container_of((h)->next,t,m))
typedef int spinlock_t;
static int lock_depth,mutex_depth,lock_epoch,failures;
static const char *case_name;
#define CHECK(n,c) do {if(!(c)){fprintf(stderr,"ASSERT %s: %s line %d\n",case_name,n,__LINE__);failures++;return;}}while(0)
#define REQUIRE(n,c) do {if(!(c)){fprintf(stderr,"BOUNDARY_ASSERT %s: %s\n",case_name,n);exit(42);}}while(0)
static char events[32768]; static size_t event_n;
static void ev(const char *s){size_t n=strlen(s); REQUIRE("event_capacity",event_n+n+1<sizeof(events));memcpy(events+event_n,s,n+1);event_n+=n;}
#define spin_lock_irqsave(p,f) do{(f)=0; REQUIRE("provider_lock_not_recursive",!*(p)); *(p)=1;lock_depth++;lock_epoch++;ev("L ");}while(0)
#define spin_unlock_irqrestore(p,f) do{(void)(f);REQUIRE("provider_lock_balanced",*(p));*(p)=0;lock_depth--;ev("U ");}while(0)
#define lockdep_assert_held(p) REQUIRE("mapping_lock",*(p))
#define mutex_lock(p) do{REQUIRE("mutex_before_provider",!lock_depth);(*(p))++;mutex_depth++;ev("M ");}while(0)
#define mutex_unlock(p) do{(*(p))--;mutex_depth--;ev("m ");}while(0)
#define rcu_read_lock() do{}while(0)
#define rcu_read_unlock() do{}while(0)
#define rcu_dereference(p) (p)
struct device {int id;}; struct file{}; struct xdp_buff_xsk{int unused;};
struct xdp_desc {u64 addr;u32 len,options;};
struct xdev_ext_mech_frame_info {u64 umem_addr;u32 index,data_off,data_len;};
struct xdev_ext_mech_peer {u8 peer_mac[6],local_mac[6];u32 local_ip,peer_ip;u16 local_port,peer_port;};
/* xdev_ext_mech_span_in is extracted verbatim into production_journal.h. */

struct xdev_ext_mech_pool;
#include "production_types.h"
struct xdev_ext_mech_pool_ops {int unused;};
struct xdev_ext_mech_pool {const struct xdev_ext_mech_pool_ops *ops;void *priv;void **pages;u32 frame_size,nr_frames;};
struct xdev_ext_mech_session {struct xdev_ext_mech_pool *pool;};
struct xdev_ext_mech_stage {struct xdev_ext_mech_session *s;void *priv;};
struct xdev_ext_mech_batch {struct xdev_ext_mech_session *s;struct xdev_ext_mech_frame f[16];u32 nr_frames;u64 id,ticket;void *priv;};
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s){return s?s->pool:NULL;}
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b){return b->priv;}
static u64 xdev_ext_mech_batch_id(struct xdev_ext_mech_batch *b){return b->id;}
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b){return b->ticket;}
struct xdev_ext_net_elem {struct xdev_ext_net_lease lease;void *slot;u32 len,buf_len;};
struct xdev_ext_net_slot {struct xdev_ext_mech_batch *batch;struct xdev_ext_net_elem *elem;u32 nr;bool busy;};
struct xdev_ext_net_member {u32 lease_kind;};
struct xdev_ext_netfam_stage {struct xdev_ext_mech_stage *st;struct xdev_ext_net_member *m;u32 max_elems;};
static void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *l,bool q){REQUIRE("no_peer_release",false);(void)l;(void)q;}
struct xsk_queue {int queue_empty_descs;};
struct sock {void (*sk_write_space)(struct sock *);};
struct net_device;
struct net_device_ops {int (*ndo_xsk_wakeup)(struct net_device *,u32,u32);};
struct net_device {const struct net_device_ops *netdev_ops;};
/* Link state is an OS boundary; these fixtures keep the link up. */
#ifndef XDEV_EXT_TEST_LINK_STATE
static bool netif_running(const struct net_device *d){(void)d;return true;}
static bool netif_carrier_ok(const struct net_device *d){(void)d;return true;}
#endif
struct xdp_umem {struct list_head xsk_dma_list;u32 npgs,chunks;u64 size;void **pgs;};
struct xsk_buff_pool {struct net_device *netdev;void *xdev_ext_mech_tx;struct device *dev;dma_addr_t *dma_pages;u32 dma_pages_cnt,chunk_size,heads_cnt;bool unaligned;struct xdp_umem *umem;struct xdp_buff_xsk *heads;u8 *addrs;u32 tx_descs_capacity;struct xdp_desc *tx_descs;struct list_head xsk_tx_list;spinlock_t cq_lock;struct xsk_queue *cq;};
struct xdp_sock {struct xsk_buff_pool *pool;struct xdp_umem *umem;struct net_device *dev;u32 queue_id;int mutex,state;bool zc;struct xdev_ext_mech_stage *xdev_ext_mech_rx,*xdev_ext_mech_tx;struct list_head tx_list;u32 tx_budget_spent;struct xsk_queue *tx;struct sock sk;};
struct xsk_xdev_ext_mech_stage {void *rel;struct xdp_sock *xs;bool dead;u64 *tx_sent;u32 tx_nr_sent;struct xdev_ext_mech_batch *tx_staged;u64 tx_staged_id;u32 tx_n;struct xdp_desc tx_desc[16];u8 *tx_pkt[16];u64 *tx_tag[16];struct xdev_ext_mech_frame_info tx_fi[16];u8 *tx_kaddr[16];};
struct xdev_ext_afxdp_tx_cqe {s32 err;};
#include "production_journal.h"
static const struct xdev_ext_mech_pool_ops xsk_xdev_ext_mech_pool_ops;
static int callbacks,complete_status,dead_status,count_ops,count_bytes,seq_callbacks,cancel_callbacks;
static int sync_dev_n,sync_cpu_n,raw_n,trace_n,wakeup_n,peek_on_wakeup,wakeup_result;
static int check_epoch[3];
static void boundary_check(const struct xdev_ext_mech_frame *f,int r){if(!r && f->index<3)check_epoch[f->index]=lock_epoch;}
static u64 sync_addr[32];static size_t sync_len[32];static int sync_epoch[32];
static struct xsk_xdev_ext_mech_provider *observed_provider;
static struct xsk_xdev_ext_mech_stage *observed_stage;
static void callback_common(struct xdev_ext_mech_batch *b,u64 t,int s,const char *event){REQUIRE("callback_outside_lock",!lock_depth);REQUIRE("callback_ticket",t==b->ticket);callbacks++;complete_status=s;ev(event);}
static void xdev_ext_mech_batch_complete(struct xdev_ext_mech_batch*b,u64 t,int s){callback_common(b,t,s,"C ");}
static void xdev_ext_mech_batch_complete_cancelled(struct xdev_ext_mech_batch*b,u64 t,int s){cancel_callbacks++;callback_common(b,t,s,"K ");}
static void xdev_ext_mech_batch_sequester(struct xdev_ext_mech_batch*b,u64 t,int s){seq_callbacks++;callback_common(b,t,s,"Q ");}
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int s){(void)st;REQUIRE("stage_dead_outside_lock",!lock_depth);dead_status=s;ev("D ");}
static int xdev_ext_mech_nic_ops_counter(bool zc){REQUIRE("zc_counter",zc);return 0;}
static int xdev_ext_mech_nic_bytes_counter(bool zc){REQUIRE("zc_counter",zc);return 1;}
static void xdev_ext_mech_count(struct xdev_ext_mech_session*s,int c,u64 n){(void)s;REQUIRE("count_under_lock",lock_depth==1);if(c)count_bytes+=n;else count_ops+=n;ev(c?"B ":"O ");}
static void xdev_ext_mech_trace_descriptor_bind(struct xdev_ext_mech_batch*b,u32 i,u64 p,u64 a,u32 len){REQUIRE("bind_lock",lock_depth==1);REQUIRE("bind_original_frame",a==b->f[i].umem_addr+22 && len==58);REQUIRE("bind_pool",p==(u64)(uintptr_t)observed_provider->xp);REQUIRE("tag_after_descriptor_bind",*observed_stage->tx_tag[i]!=b->id);
REQUIRE("slot_before_descriptor_bind",observed_provider->slots[trace_n].state==XSK_MECH_ZC_PENDING && observed_provider->slots[trace_n].slot==i && observed_provider->slots[trace_n].desc.addr==a);
trace_n++;ev("T ");}
static void boundary_raw(struct xsk_buff_pool*p,u64 a){(void)p;(void)a;REQUIRE("raw_under_provider_lock",lock_depth==1);
#if HAVE_POOL
if(observed_provider && !observed_provider->stopped && (a>>12)<3) REQUIRE("check_sync_one_critical_section",check_epoch[a>>12]==lock_epoch);
#endif
if(observed_provider && !observed_provider->stopped && a<12288){u8 *pkt=p->addrs+a;REQUIRE("checksum_before_sync",pkt[24]==0x7c && pkt[25]==0x56 && pkt[40]==0 && pkt[41]==0);}
raw_n++;ev("R ");}
static void dma_sync_single_for_device(struct device*d,dma_addr_t a,size_t n,int dir){REQUIRE("sync_under_provider_lock",lock_depth==1);REQUIRE("live_requester_device",d && d->id==17);REQUIRE("bidirectional",dir==0);sync_addr[sync_dev_n]=a;sync_len[sync_dev_n]=n;sync_epoch[sync_dev_n]=lock_epoch;sync_dev_n++;ev("S ");}
static void dma_sync_single_for_cpu(struct device*d,dma_addr_t a,size_t n,int dir){(void)a;(void)n;REQUIRE("cpu_sync_lock",lock_depth==1);REQUIRE("cpu_sync_device",d && d->id==17 && dir==0);sync_cpu_n++;ev("s ");}
static void xsk_rel_native_done(struct xsk_xdev_ext_mech_tx_batch*t){(void)t;REQUIRE("reliable_not_in_slice",false);}
static int xsk_rel_submit(struct xdev_ext_mech_stage*s,struct xdev_ext_mech_batch*b){(void)s;(void)b;return -EOPNOTSUPP;}
static int xsk_xdev_ext_mech_tx_xmit(void*a,u32 i){(void)a;(void)i;return -EOPNOTSUPP;}
static void xsk_native_trace_complete(struct xsk_buff_pool*p,u32 n){(void)p;(void)n;ev("H ");}
static void xsk_native_trace_tail(struct xsk_buff_pool*p,u32 n,int r,bool cancel){(void)p;(void)n;(void)r;ev(cancel?"X ":"Y ");}
static void xsk_native_trace_submit(struct xsk_buff_pool*p,const struct xdp_desc*d,u32 n){(void)p;(void)d;(void)n;ev("N ");}
/* Upstream/policy fallbacks are OS boundaries, unused by admitted provider cases. */
static int xsk_xdev_ext_zc_tx_completed(struct xsk_buff_pool*p,u32 n){(void)p;(void)n;return -EOPNOTSUPP;}
static int xsk_xdev_ext_zc_tx_cancel_tail(struct xsk_buff_pool*p,u32 n,int r){(void)p;(void)n;(void)r;return -EOPNOTSUPP;}
static int xsk_xdev_ext_zc_tx_set_tail_result(struct xsk_buff_pool*p,u32 n,int r){(void)p;(void)n;(void)r;return -EOPNOTSUPP;}
static int xsk_xdev_ext_zc_tx_peek_desc(struct xsk_buff_pool*p,struct xdp_desc*d){(void)p;(void)d;return -EOPNOTSUPP;}
static int xsk_xdev_ext_zc_tx_peek_release_desc_batch(struct xsk_buff_pool*p,u32 n){(void)p;(void)n;return -EOPNOTSUPP;}
static void xsk_cq_submit_locked(struct xsk_buff_pool*p,u32 n){(void)p;(void)n;ev("FALLBACK ");}
static void __xskq_cons_release(struct xsk_queue*q){(void)q;}
static bool xsk_tx_writeable(struct xdp_sock*x){(void)x;return false;}
static bool xskq_cons_peek_desc(struct xsk_queue*q,struct xdp_desc*d,struct xsk_buff_pool*p){(void)q;(void)d;(void)p;return false;}
static bool xskq_has_descs(struct xsk_queue*q){(void)q;return false;}
static void xskq_cons_release(struct xsk_queue*q){(void)q;}
static bool xsk_cq_reserve_addr_locked(struct xsk_buff_pool*p,u64 a){(void)p;(void)a;return true;}
static u32 xskq_cons_nb_entries(struct xsk_queue*q,u32 n){(void)q;(void)n;return 0;}
static bool xsk_xdev_ext_mech_tx_active(struct xsk_buff_pool*p){return p->xdev_ext_mech_tx!=NULL;}
static u32 xskq_prod_nb_free(struct xsk_queue*q,u32 n){(void)q;(void)n;return 0;}
static u32 xskq_cons_read_desc_batch(struct xsk_queue*q,struct xsk_buff_pool*p,u32 n){(void)q;(void)p;(void)n;return 0;}
static void xskq_prod_write_addr_batch(struct xsk_queue*q,struct xdp_desc*d,u32 n){(void)q;(void)d;(void)n;}

struct xsk_dma_map {struct list_head list;struct net_device *netdev;int users;};
static bool refcount_dec_and_test(int *n){return --*n==0;}
static void __xp_dma_unmap(struct xsk_dma_map *m,unsigned long a){(void)m;(void)a;REQUIRE("shared_mapping_retained",false);}
static void xp_native_dma_unmap(struct xsk_buff_pool *pool){(void)pool;REQUIRE("unmap_admission_closed",observed_provider->stopped && !lock_depth);ev("I ");}
static void kvfree(void *p){REQUIRE("free_admission_closed",observed_provider->stopped && !lock_depth);free(p);ev("V ");}
#define WARN(c,s) REQUIRE("unexpected_unmap_warning",!(c))
