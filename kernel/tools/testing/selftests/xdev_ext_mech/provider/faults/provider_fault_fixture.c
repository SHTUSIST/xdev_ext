/* SPDX-License-Identifier: GPL-2.0 */
/* Native provider and OS boundary shims; all adapter/core decisions extracted. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_core.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"
#include "io_uring/xdev_ext_mech_notify.h"
#include "io_uring/xdev_ext_mech_step.h"
#include "io_uring/xdev_ext_mech_dma_core.h"
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_mech_native_cookie.h"

typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
typedef int kuid_t;
typedef int spinlock_t;
typedef int wait_queue_head_t;
typedef unsigned long atomic64_t;
typedef int atomic_t;
struct module { int refs; bool going; };
struct file_operations { int tag; };
struct file { const struct file_operations *f_op; };
struct page { int unused; };
struct eventfd_ctx { int unused; };
struct kthread_worker { int unused; };
struct kthread_work { int unused; };
struct kthread_delayed_work { struct kthread_work work; };
struct work_struct { int unused; };
struct timer_list { int unused; };
struct list_head { struct list_head *next, *prev; };
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }
#define DEFINE_MUTEX(n) pthread_mutex_t n = PTHREAD_MUTEX_INITIALIZER
#define mutex_lock(p) assert(!pthread_mutex_lock(p))
#define mutex_unlock(p) assert(!pthread_mutex_unlock(p))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_entry(p,t,m) container_of(p,t,m)
#define list_for_each_entry(p,h,m) \
 for ((p)=list_entry((h)->next,typeof(*(p)),m); &(p)->m!=(h); \
      (p)=list_entry((p)->m.next,typeof(*(p)),m))
static void INIT_LIST_HEAD(struct list_head *h) { h->next=h->prev=h; }
static void list_add_tail(struct list_head *n,struct list_head *h) {
 n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;
}
static void list_del(struct list_head *n) { n->prev->next=n->next;n->next->prev=n->prev; }
static void list_del_init(struct list_head *n) { list_del(n);INIT_LIST_HEAD(n); }
struct llist_node { struct llist_node *next; };
struct llist_head { struct llist_node *first; };
static bool llist_add(struct llist_node *n,struct llist_head *h) {
 bool empty=!h->first; n->next=h->first;h->first=n;return empty;
}
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define atomic64_read(p) (*(p))
#define atomic64_inc(p) (++*(p))
#define atomic64_dec(p) (--*(p))
#define atomic64_add(n,p) (*(p)+=(n))
#define atomic_inc(p) (++*(p))
#define atomic_read(p) (*(p))
#define cmpxchg(p,o,n) __sync_val_compare_and_swap(p,o,n)
#define spin_lock_irqsave(l,f) do {(void)(l);(f)=0;}while(0)
#define spin_unlock_irqrestore(l,f) do {(void)(l);(void)(f);}while(0)
#define spin_lock(l) ((void)(l))
#define spin_unlock(l) ((void)(l))
#define lockdep_assert_held(l) ((void)(l))
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define synchronize_rcu() ((void)0)
#define PAGE_SHIFT 12
#define GFP_KERNEL 0
#define BIT(n) (1U<<(n))
#define U32_MAX UINT32_MAX
#define XDEV_EXT_MECH_DRAIN_TIMEOUT 5
#define XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE (1U<<1)
#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))
#define kmalloc(n,g) malloc(n)
#define kzalloc(n,g) calloc(1,n)
#define kfree(p) free(p)
#define kvfree(p) free(p)
#define EXPORT_SYMBOL_GPL(n)
#define pr_warn(...) do { if (0) fprintf(stderr,__VA_ARGS__); } while(0)
#define THIS_MODULE NULL
static unsigned warnings,queued_work,destroyed_workers,pool_releases,file_puts;
static unsigned event_puts,event_signals;
#define WARN_ON_ONCE(c) ({bool bad=!!(c);if(bad)warnings++;bad;})
#define WARN_ONCE(c,...) WARN_ON_ONCE(c)
static bool try_module_get(struct module *m) {
 if (!m)return true;
 if(m->going)return false;
 m->refs++;return true;
}
static void module_put(struct module *m) {if(m){assert(m->refs>0);m->refs--;}}
static void wake_up(int *w) {(void)w;}
static void eventfd_signal(struct eventfd_ctx *e) {(void)e;event_signals++;}
static void eventfd_ctx_put(struct eventfd_ctx *e) {(void)e;event_puts++;}
static void fput(struct file *f) {(void)f;file_puts++;}
static void kthread_queue_work(struct kthread_worker *w,struct kthread_work *work) {
 (void)w;(void)work;queued_work++;
}
static void kthread_cancel_delayed_work_sync(struct kthread_delayed_work *w) {(void)w;}
static void kthread_destroy_worker(struct kthread_worker *w) {(void)w;destroyed_workers++;}
static void timer_shutdown_sync(struct timer_list *t) {(void)t;}
static void (*wait_hook)(void);
#define wait_event_timeout(w,c,t) do {(void)(w);(void)(t);if(!(c)&&wait_hook)wait_hook();(void)(c);}while(0)

struct xdev_ext_mech_session;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_class_ops;
struct xdev_ext_mech_pool;
struct xdev_ext_dma_cookie;
struct xdev_ext_ce_cookie;
struct xdev_ext_dma_provider_ops;
/* PRODUCTION_STRUCTURES */

static LIST_HEAD(xdev_ext_mech_quarantined);
static DEFINE_MUTEX(xdev_ext_mech_quarantine_lock);
static struct xdev_ext_mech_quarantine xdev_ext_mech_parked;
static int xdev_ext_mech_all_lock;
static DEFINE_MUTEX(xdev_ext_mech_live_lock);
/* OS/BPF reference boundary; these fixtures use no published program pin. */
static void xdev_ext_ops_unpin(const void *p) {(void)p;assert(!"unexpected BPF pin");}
/* PRODUCTION_OPS */
/* CORE_BEFORE functions call each other in this order except queue and notify. */
/* PRODUCTION_CORE_BEFORE */
/* PRODUCTION_ADAPTER */
/* PRODUCTION_CE_ADAPTER */
/* PRODUCTION_CORE_AFTER */

/* Native provider fixture: observable resource handles and externally selected
 * faults. It does not implement admission, completion classification or STOP. */
static struct module owner;
static const struct file_operations fops={1},other_fops={2};
static struct file device={&fops};
static unsigned region_binds,host_binds,region_unbinds,host_unbinds,native_calls;
static unsigned accepts;
static int region_error,host_error,submit_error,callback_status;
static bool inline_completion,submitted=true;
static u64 callback_bytes=128;
static u32 native_directions=XDEV_EXT_DMA_DIR_KNOWN_MASK;
static u32 native_alignment=1;
static struct xdev_ext_dma_cookie *pending_cookie;
static u64 pending_ticket;
static struct xdev_ext_dma_xfer saved_x[XDEV_EXT_DMA_MAX_ENTRIES];
static u32 saved_n;
static int native_bind_region(struct file *f,u64 off,u64 len,struct xdev_ext_dma_region *r) {
 (void)f;(void)off;region_binds++;
 if(region_error)return region_error;
 r->priv=malloc(8);assert(r->priv);r->len=len;r->segment_size=4096;
 r->max_entry_len=4096;r->alignment=native_alignment;r->directions=native_directions;
 return 0;
}
static void native_unbind_region(struct xdev_ext_dma_region *r) {
 region_unbinds++;free(r->priv);r->priv=NULL;
}
static int native_bind_host(struct xdev_ext_dma_region *r,struct page **pages,u32 nr,void **h) {
 (void)r;(void)pages;(void)nr;host_binds++;
 if(host_error)return host_error;
 *h=malloc(8);assert(*h);return 0;
}
static void native_unbind_host(void *h) {host_unbinds++;free(h);}
static int native_submit(struct xdev_ext_dma_region *r,void *h,u32 dir,
 const struct xdev_ext_dma_xfer *x,u32 n,struct xdev_ext_dma_cookie *ck,u64 ticket) {
 (void)r;(void)h;(void)dir;native_calls++;
 if(submit_error&&!inline_completion)return submit_error;
 accepts++;pending_cookie=ck;pending_ticket=ticket;saved_n=n;
 memcpy(saved_x,x,n*sizeof(*x));
 if(inline_completion)xdev_ext_dma_complete(ck,ticket,callback_status,submitted,callback_bytes);
 return submit_error;
}
static const struct xdev_ext_dma_provider_ops provider={
 .owner=&owner,.fops=&fops,.bind_region=native_bind_region,
 .unbind_region=native_unbind_region,.bind_host=native_bind_host,
 .unbind_host=native_unbind_host,.submit=native_submit,
};
static void pool_release(struct xdev_ext_mech_pool *p) {(void)p;pool_releases++;}
static const struct xdev_ext_mech_pool_ops pool_ops={.release=pool_release};
static struct page page;
static struct page *pages[]={&page,&page};
static struct kthread_worker worker;
static struct xdev_ext_mech_session *session_new(void) {
 struct xdev_ext_mech_session *s=calloc(1,sizeof(*s));assert(s);
 xdev_ext_mech_sess_init(&s->ss);s->nr_stages=1;s->depth=1;s->frames=1;s->worker=&worker;
 INIT_LIST_HEAD(&s->all_node);INIT_LIST_HEAD(&s->live_node);INIT_LIST_HEAD(&s->quarantine_node);
 s->layout=(struct xdev_ext_mech_layout){.frame_size=4096,.hdr_room=64,.seg_len=128,.group_bytes=128};
 s->pool=(struct xdev_ext_mech_pool){.ops=&pool_ops,.pages=pages,.nr_pages=2,
  .nr_frames=2,.frame_size=4096,.state=calloc(2,1),.size=8192};
 assert(s->pool.state);s->pool.state[1]=XDEV_EXT_MECH_F_HELD;
 /* state is a boundary-owned allocation; production pool_release releases it
  * in the kernel. The host test keeps it separate for post-STOP observations. */
 s->st[0]=(struct xdev_ext_mech_stage){.s=s,.cls=&xdev_ext_dma_class,.file=&device,
  .class_id=XDEV_EXT_MECH_CLASS_DMA,.direction=XDEV_EXT_MECH_DIR_FROM_DEVICE};
 return s;
}
static int bind_session(struct xdev_ext_mech_session *s) {
 struct xdev_ext_mech_stage_uapi u={.arg1=4096};
 int err=xdev_ext_dma_bind(&s->st[0],&u);if(!err)s->nr_bound=1;return err;
}
static struct xdev_ext_mech_batch *batch_new(struct xdev_ext_mech_session *s) {
 struct xdev_ext_mech_batch *b=calloc(1,sizeof(*b));assert(b);s->batches=b;
 s->privs=calloc(1,sizeof(struct xdev_ext_dma_batch));s->cookies=calloc(1,sizeof(struct xdev_ext_dma_cookie));
 assert(s->privs&&s->cookies);b->s=s;b->priv=s->privs;b->cookie=s->cookies;
 b->nr_frames=1;b->present=1;b->bytes=128;
 b->f[0]=(struct xdev_ext_mech_frame){.index=1,.umem_addr=4096,.data_off=64,.data_len=128};
 xdev_ext_mech_bstate_init(&b->bs,1);assert(!xdev_ext_mech_batch_step(&b->bs,XDEV_EXT_MECH_EV_READY,0));
 xdev_ext_mech_completion_init(&b->completion);assert(!xdev_ext_mech_sess_batch_begin(&s->ss));
 return b;
}
static int validate(struct xdev_ext_mech_batch *b) {
 struct xdev_ext_dma_copy_desc d={.frame_pos=0,.frame_off=64,.device_off=0,.len=128};
 return xdev_ext_dma_validate(&b->s->st[0],b,(const u8 *)&d,1);
}
static int submit(struct xdev_ext_mech_batch *b) {
 int err=validate(b);if(err)return err;return xdev_ext_mech_submit(b->s,&b->s->st[0],b);
}
static unsigned checks;
#define CHECK(c,msg) do {checks++;if(!(c)){fprintf(stderr,"FAIL %s:%d %s\n",__func__,__LINE__,msg);return 1;}}while(0)
#define EQ(a,b,msg) CHECK((a)==(b),msg)
static struct xdev_ext_mech_session *bound_session(void) {
 assert(!xdev_ext_dma_provider_register(&provider));
 struct xdev_ext_mech_session *s=session_new();assert(!bind_session(s));return s;
}
/* A test observer consumes and retires an adapter callback using actual core
 * primitives. This is NOT a replacement for or proof of the full worker.
 * Worker/drain thread scheduling and BPF execution require KVM acceptance. */
static void observe_retire(struct xdev_ext_mech_batch *b) {
 struct xdev_ext_mech_session *s=b->s;int result;
 assert(!xdev_ext_mech_completion_consume(&b->completion,b->ticket,&result));b->status=result;
 assert(!xdev_ext_mech_frames_move(s,b,XDEV_EXT_MECH_F_INFLIGHT,
  b->sequester?XDEV_EXT_MECH_F_SEQUESTERED:XDEV_EXT_MECH_F_HELD));
 assert(!xdev_ext_mech_leave_locked(s,b->sequester));
 b->queued=0;s->inbox.first=NULL;
}
static struct xdev_ext_mech_batch *wait_batch;
static void complete_in_wait(void) {
 assert(!region_unbinds&&!host_unbinds&&owner.refs==1);
 xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,128);
 observe_retire(wait_batch);
 assert(!region_unbinds&&!host_unbinds&&owner.refs==1);
}

static int test_registry(void) {
 struct xdev_ext_mech_session *s=session_new();
 EQ(bind_session(s),-ENODEV,"unregistered fops must be rejected");
 EQ(owner.refs,0,"unregistered lookup must not pin");EQ(region_binds,0,"no unregistered bind call");
 EQ(xdev_ext_dma_provider_register(NULL),-EINVAL,"NULL registry entry");
 struct xdev_ext_dma_provider_ops missing=provider;missing.submit=NULL;
 EQ(xdev_ext_dma_provider_register(&missing),-EINVAL,"incomplete registry entry");
 EQ(xdev_ext_dma_provider_register(&provider),0,"register provider");
 struct xdev_ext_dma_provider_ops same=provider;
 EQ(xdev_ext_dma_provider_register(&same),-EBUSY,"duplicate fops must be rejected");
 EQ(xdev_ext_dma_provider_register(&provider),-EBUSY,"identical duplicate fops");
 owner.going=true;EQ(bind_session(s),-ENODEV,"going module cannot bind");
 EQ(owner.refs,0,"going module cannot acquire reference");owner.going=false;
 same.fops=&other_fops;EQ(xdev_ext_dma_provider_register(&same),0,"independent fops");
 xdev_ext_dma_provider_unregister(&same);xdev_ext_dma_provider_unregister(&provider);
 EQ(bind_session(s),-ENODEV,"unregister prevents later bind");
 EQ(warnings,0,"no registry warnings");return 0;
}
static int test_registry_capacity(void) {
 struct file_operations fs[64];struct xdev_ext_dma_provider_ops ps[64];
 for(unsigned i=0;i<64;i++) {
  fs[i].tag=(int)i;ps[i]=provider;ps[i].fops=&fs[i];
  EQ(xdev_ext_dma_provider_register(&ps[i]),0,"registry has no small fixed provider limit");
 }
 for(unsigned i=0;i<64;i++)xdev_ext_dma_provider_unregister(&ps[i]);
 EQ(xdev_ext_dma_providers.next,&xdev_ext_dma_providers,"all dynamic registrations removed");return 0;
}
static int test_bind_rollback(void) {
 assert(!xdev_ext_dma_provider_register(&provider));struct xdev_ext_mech_session *s=session_new();
 region_error=-EACCES;EQ(bind_session(s),-EACCES,"region failure preserved");
 EQ(owner.refs,0,"region failure drops module pin");EQ(region_unbinds,0,"failed bind has no bound region");
 region_error=0;host_error=-ENOMEM;
 EQ(bind_session(s),-ENOMEM,"host bind failure preserved");
 EQ(region_unbinds,1,"host failure unbinds native region");EQ(host_unbinds,0,"failed host not unbound");
 EQ(owner.refs,0,"host failure drops pin");host_error=0;native_alignment=0;
 EQ(bind_session(s),-EINVAL,"invalid native geometry");EQ(owner.refs,0,"geometry failure drops pin");
 EQ(region_unbinds,2,"geometry failure unbinds region");native_alignment=1;
 native_directions=XDEV_EXT_DMA_DIR_TO_DEVICE;
 EQ(bind_session(s),-EOPNOTSUPP,"unsupported native direction");EQ(owner.refs,0,"direction failure drops pin");
 EQ(region_unbinds,3,"direction failure unbinds region");return 0;
}
static int test_directions_and_bounds(void) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 struct xdev_ext_dma_copy_desc d={.frame_pos=0,.frame_off=64,.device_off=4095,.len=128};
 EQ(xdev_ext_dma_validate(&s->st[0],b,(const u8 *)&d,1),-ERANGE,"device window overrun");
 EQ(native_calls,0,"bad plan cannot reach native submit");
 d.device_off=0;d.frame_off=63;
 EQ(xdev_ext_dma_validate(&s->st[0],b,(const u8 *)&d,1),-EINVAL,"bad host coverage");
 d.frame_off=64;s->st[0].direction=0;
 EQ(xdev_ext_dma_validate(&s->st[0],b,(const u8 *)&d,1),-EOPNOTSUPP,"invalid direction before native");
 EQ(native_calls,0,"direction cannot reach native");s->st[0].direction=XDEV_EXT_MECH_DIR_FROM_DEVICE;
 EQ(submit(b),0,"valid translated plan");EQ(saved_n,1,"native entries");
 EQ(saved_x[0].host_byte_off,4160,"translated nonzero frame host offset");
 EQ(saved_x[0].device_off,0,"device offset retained");EQ(saved_x[0].len,128,"native len");return 0;
}
static int test_preaccept(void) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 submit_error=-EAGAIN;EQ(submit(b),-EAGAIN,"preaccept EAGAIN preserved");
 EQ(native_calls,1,"one attempted native call");EQ(accepts,0,"refusal never accepted");
 EQ(s->submitted[0],0,"core rolls back submitted count");EQ(b->bs.state,XDEV_EXT_MECH_B_READY,"core READY rollback");
 EQ(s->pool.state[1],XDEV_EXT_MECH_F_HELD,"core returns custody after refusal");
 EQ(((struct xdev_ext_dma_cookie *)b->cookie)->state,XDEV_EXT_DMA_CK_IDLE,"cookie arm rolled back");
 EQ(s->inbox.first,NULL,"no refusal callback enqueued");u64 old=b->ticket;
 submit_error=0;EQ(submit(b),0,"capacity becomes available");
 CHECK(b->ticket>old,"preaccept retry uses new native ticket");EQ(accepts,1,"exactly one accepted native operation");
 xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,128);
 EQ(s->submitted[0],1,"one accepted submission counted");observe_retire(b);
 EQ(b->status,0,"eventual exact success");EQ(warnings,0,"refusal produces no warning");return 0;
}
static int test_inline(void) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 inline_completion=true;EQ(submit(b),0,"inline accepted submit");
 EQ(b->bs.state,XDEV_EXT_MECH_B_IN_FLIGHT,"core armed flight before native callback");
 EQ(s->submitted[0],1,"inline success counted once");CHECK(s->inbox.first!=NULL,"inline callback enqueued");
 observe_retire(b);EQ(b->status,0,"inline success result");EQ(accepts,1,"inline not resent");
 EQ(warnings,0,"inline callback legal");return 0;
}
static int test_duplicate(bool stale,bool change_stage) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 EQ(submit(b),0,"first accepted submit");u64 old=pending_ticket;
 xdev_ext_dma_complete(pending_cookie,old,0,true,128);
 if(stale) {
  observe_retire(b);assert(!xdev_ext_mech_sess_batch_begin(&s->ss));
  s->pool.state[1]=XDEV_EXT_MECH_F_HELD;b->bs.state=XDEV_EXT_MECH_B_READY;
  if(change_stage) {
   s->nr_stages=2;s->st[1]=s->st[0];s->st[1].index=1;s->st[1].priv=NULL;
   struct xdev_ext_mech_stage_uapi u={.arg1=4096};
   EQ(xdev_ext_dma_bind(&s->st[1],&u),0,"second independent stage bind");s->nr_bound=2;
   EQ(owner.refs,2,"independent stage module pin");
   b->bs.nr_stages=2;b->bs.stage=1;
   struct xdev_ext_dma_copy_desc d={.frame_pos=0,.frame_off=64,.device_off=0,.len=128};
   EQ(xdev_ext_dma_validate(&s->st[1],b,(const u8 *)&d,1),0,"new stage valid plan");
   EQ(xdev_ext_mech_submit(s,&s->st[1],b),0,"same cookie reused in different bound stage");
  } else EQ(submit(b),0,"reuse same cookie for new ticket");
  CHECK(b->ticket>old,"ticket monotonically advances");
 }
 struct xdev_ext_dma_cookie before;memcpy(&before,b->cookie,sizeof(before));
 struct xdev_ext_mech_completion completion;memcpy(&completion,&b->completion,sizeof(completion));
 unsigned q=queued_work;
 xdev_ext_dma_complete(pending_cookie,old,-ETIMEDOUT,true,1);
 EQ(memcmp(&before,b->cookie,sizeof(before)),0,"stale callback must not overwrite cookie metadata");
 EQ(memcmp(&completion,&b->completion,sizeof(completion)),0,"stale callback must not alter completion");
 EQ(queued_work,q,"stale callback must not queue worker");
 EQ(((struct xdev_ext_dma_stage *)s->st[0].priv)->ambiguous,0,"stale callback must not quarantine new stage");
 if(change_stage)EQ(((struct xdev_ext_dma_stage *)s->st[1].priv)->ambiguous,0,"stale callback must not corrupt different stage");
 EQ(warnings,0,"stale or duplicate rejected before cookie finish");
 if(stale)xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,128);
 observe_retire(b);EQ(b->status,0,"valid exact callback survives stale callback");return 0;
}
static int test_unregister_bound(void) {
 struct xdev_ext_mech_session *s=bound_session();
 xdev_ext_dma_provider_unregister(&provider);
 EQ(owner.refs,1,"unregister cannot drop existing session owner pin");
 struct xdev_ext_mech_session *other=session_new();
 EQ(bind_session(other),-ENODEV,"unregistered provider rejects new session");
 EQ(owner.refs,1,"failed later bind preserves existing pin");
 struct xdev_ext_mech_batch *b=batch_new(s);EQ(submit(b),0,"bound native ops survive unregister");
 xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,128);observe_retire(b);
 u8 *states=s->pool.state;EQ(xdev_ext_mech_session_destroy(s),false,"existing bound session drains safely");
 EQ(owner.refs,0,"STOP releases final existing reference");
 EQ(host_unbinds,1,"existing host mapping unbound once");EQ(region_unbinds,1,"existing region unbound once");
 free(states);return 0;
}
static int test_outcome(const char *mode) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 EQ(submit(b),0,"native accepted");int status=0;bool hw=true;u64 bytes=128;
 if(!strcmp(mode,"short"))bytes=127;
 if(!strcmp(mode,"excess"))bytes=129;
 if(!strcmp(mode,"ambiguous"))status=-ETIMEDOUT;
 if(!strcmp(mode,"unsubmitted_zero"))hw=false;
 if(!strcmp(mode,"accepted_pre_submit_error")){hw=false;status=-EAGAIN;bytes=0;}
 xdev_ext_dma_complete(pending_cookie,pending_ticket,status,hw,bytes);
 struct xdev_ext_dma_mech_cqe c;xdev_ext_dma_fill_cqe(&s->st[0],b,&c);
 EQ(b->sequester,hw,"submitted fault quarantine flag");
 EQ(c.outcome,hw?XDEV_EXT_DMA_AMBIGUOUS:XDEV_EXT_DMA_PRE_SUBMIT_FAILED,"native outcome classification");
 EQ(c.entries_done,0,"failure cannot report all entries done");CHECK(c.bytes_done<=128,"CQE bytes clamped");
 if(!hw&&!status)EQ((int)c.provider_status,-EIO,"unsubmitted success normalized to EIO");
 observe_retire(b);int err=0;
 for(int verdict=XDEV_EXT_MECH_NEXT;verdict<=XDEV_EXT_MECH_ABORT;verdict++) {
  int step=xdev_ext_mech_complete_step(XDEV_EXT_MECH_CLASS_DMA,verdict,b->status,b->sequester,false,0,&err);
  if(hw)EQ(step,XDEV_EXT_MECH_STEP_SEQUESTER,"BPF verdict cannot bypass ambiguity");
  else CHECK(step!=XDEV_EXT_MECH_STEP_NEXT&&step!=XDEV_EXT_MECH_STEP_DONE,"failed operation cannot advance");
 }
 EQ(accepts,1,"completion callback does not submit another operation");
 EQ(warnings,0,"legitimate fault not protocol warning");return 0;
}
static int test_dead(void) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 EQ(validate(b),0,"stage plan initially valid");xdev_ext_dma_mark_dead(&s->st[0]);
 EQ(xdev_ext_mech_submit(s,&s->st[0],b),-ENODEV,"dead stage refuses staged plan");
 EQ(native_calls,0,"dead stage cannot call provider");EQ(s->submitted[0],0,"no accepted count");
 EQ(s->pool.state[1],XDEV_EXT_MECH_F_HELD,"dead stage rollback custody");return 0;
}
static int test_callback_then_error(void) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 inline_completion=true;submit_error=-EIO;EQ(submit(b),0,"callback ownership wins refused return");
 EQ(s->submitted[0],1,"callback claim cannot be cancelled");observe_retire(b);
 EQ(b->status,0,"callback result retained");EQ(warnings,1,"contract violation warns exactly once");
 EQ(accepts,1,"violation does not authorize resend");return 0;
}
static int test_stop(const char *mode) {
 struct xdev_ext_mech_session *s=bound_session();u8 *states=s->pool.state;
 struct xdev_ext_dma_stage *cs=s->st[0].priv;
 CHECK(cs->host&&cs->region.priv&&owner.refs==1,"initial mappings and owner pin");
 struct xdev_ext_mech_batch *b=NULL;
 if(strcmp(mode,"stop_idle")) {b=batch_new(s);EQ(submit(b),0,"pending accepted command");}
 if(!strcmp(mode,"stop_delayed")){wait_batch=b;wait_hook=complete_in_wait;}
 if(!strcmp(mode,"stop_ambiguous")) {
  xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,127);observe_retire(b);
  EQ(states[1],XDEV_EXT_MECH_F_SEQUESTERED,"ambiguous frame remains sequestered");
 }
 bool quarantine=xdev_ext_mech_session_destroy(s);
 bool expected=!strcmp(mode,"stop_pending")||!strcmp(mode,"stop_ambiguous");
 EQ(quarantine,expected,"production STOP chooses expected reference fate");
 if(expected) {
  EQ(owner.refs,1,"STOP quarantine retains provider module pin");
  EQ(region_unbinds,0,"STOP quarantine retains native region");
  EQ(host_unbinds,0,"STOP quarantine retains host mapping");
  EQ(pool_releases,0,"STOP quarantine retains pinned pool");
  EQ(file_puts,0,"STOP quarantine retains provider fd");
  CHECK(s->st[0].priv==cs&&cs->host&&cs->region.priv,"quarantine handles still reachable");
  if(!strcmp(mode,"stop_pending"))EQ(s->ss.state,XDEV_EXT_MECH_SESSION_STOPPING,"accepted command defers the release decision");
  else EQ(s->ss.state,XDEV_EXT_MECH_SESSION_ZOMBIE,"unknown DMA keeps ZOMBIE");
  if(!strcmp(mode,"stop_pending"))EQ(states[1],XDEV_EXT_MECH_F_INFLIGHT,"timeout cannot recycle device frame");
 }else {
  EQ(owner.refs,0,"safe STOP drops provider module pin");
  EQ(region_unbinds,1,"safe STOP unbinds native region once");
  EQ(host_unbinds,1,"safe STOP unbinds host once");EQ(pool_releases,1,"safe STOP releases pool");
  EQ(file_puts,1,"safe STOP releases device file");
 }
 if(!expected)free(states);
 return 0;
}
static int test_ambiguous_unbind(void) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 EQ(submit(b),0,"accepted ambiguous test");xdev_ext_dma_complete(pending_cookie,pending_ticket,-EIO,true,0);
 void *priv=s->st[0].priv;xdev_ext_dma_unbind(&s->st[0]);
 EQ(owner.refs,1,"ambiguous unbind must retain provider pin");
 EQ(region_unbinds,0,"ambiguous unbind must retain region");EQ(host_unbinds,0,"ambiguous unbind retains host");
 EQ(s->st[0].priv,priv,"ambiguous unbind keeps stage handle");return 0;
}
/* Both submissions and callbacks are production code. The CE validator's
 * admitted one-span plan is an explicit boundary, as with native providers. */
static struct xdev_ext_ce_cookie *ce_pending_cookie;
static u64 ce_pending_ticket;
static int ce_native_submit(struct xdev_ext_ce_region *r,void *host,u32 dir,
 const struct xdev_ext_ce_xfer *x,u32 n,struct xdev_ext_ce_cookie *cookie,u64 ticket) {
 (void)r;(void)host;(void)dir;(void)x;assert(n==1);
 ce_pending_cookie=cookie;ce_pending_ticket=ticket;return 0;
}
static const struct xdev_ext_ce_backend_ops ce_native_ops={.submit=ce_native_submit};
static const struct xdev_ext_mech_class_ops ce_test_class={.class_id=XDEV_EXT_MECH_CLASS_CE,.submit=xdev_ext_ce_submit};
static int ce_submit_admitted(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b) {
 struct xdev_ext_ce_stage *cs=s->st[1].priv;
 cs->staged=b;cs->plan.n=1;cs->plan.total=128;cs->plan.host_off[0]=4160;
 cs->d[0]=(struct xdev_ext_ce_copy_desc){.len=128};
 return xdev_ext_mech_submit(s,&s->st[1],b);
}
static int test_crossclass(bool ce_first) {
 struct xdev_ext_mech_session *s=bound_session();struct xdev_ext_mech_batch *b=batch_new(s);
 struct xdev_ext_ce_stage cs={.region={.ops=&ce_native_ops}};
 s->st[1]=(struct xdev_ext_mech_stage){.s=s,.cls=&ce_test_class,.priv=&cs,
  .class_id=XDEV_EXT_MECH_CLASS_CE,.index=1,.direction=XDEV_EXT_MECH_DIR_TO_DEVICE};
 s->nr_stages=b->bs.nr_stages=2;
 if(ce_first) { b->bs.stage=1;EQ(ce_submit_admitted(s,b),0,"initial CE production submit");
  xdev_ext_ce_complete(ce_pending_cookie,ce_pending_ticket,0,true,128);
 } else { EQ(submit(b),0,"initial DMA production submit");
  xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,128);
 }
 u64 old=b->ticket;observe_retire(b);
 assert(!xdev_ext_mech_sess_batch_begin(&s->ss));s->pool.state[1]=XDEV_EXT_MECH_F_HELD;
 b->bs.state=XDEV_EXT_MECH_B_READY;b->bs.stage=ce_first?0:1;
 if(ce_first)EQ(submit(b),0,"switch CE cookie to real DMA submit");
 else EQ(ce_submit_admitted(s,b),0,"switch DMA cookie to real CE submit");
 CHECK(b->ticket>old,"crossclass ticket advances");
 unsigned char before[sizeof(struct xdev_ext_dma_cookie)];memcpy(before,b->cookie,sizeof(before));
 struct xdev_ext_mech_completion completion=b->completion;
 unsigned q=queued_work;
 for(unsigned replay=0;replay<2;replay++) {
  if(ce_first)xdev_ext_ce_complete(b->cookie,old,-ETIMEDOUT,true,1);
  else xdev_ext_dma_complete(b->cookie,old,-ETIMEDOUT,true,1);
  EQ(memcmp(before,b->cookie,sizeof(before)),0,"crossclass stale callback changed current cookie");
  EQ(memcmp(&completion,&b->completion,sizeof(completion)),0,"crossclass stale callback changed completion");
  EQ(queued_work,q,"crossclass stale callback queued work");
  EQ(cs.ambiguous,0,"crossclass stale callback touched CE stage");
  EQ(((struct xdev_ext_dma_stage *)s->st[0].priv)->ambiguous,0,"crossclass stale callback touched DMA stage");
 }
 if(ce_first)xdev_ext_dma_complete(pending_cookie,pending_ticket,0,true,128);
 else xdev_ext_ce_complete(ce_pending_cookie,ce_pending_ticket,0,true,128);
 observe_retire(b);EQ(b->status,0,"exact current-class callback survives old-class replay");
 EQ(warnings,0,"stale crossclass rejected before state/CS access");return 0;
}
int main(int argc,char **argv) {
 if(argc!=2)return 2;
 const char *m=argv[1];int bad;
 if(!strcmp(m,"registry"))bad=test_registry();
 else if(!strcmp(m,"registry_capacity"))bad=test_registry_capacity();
 else if(!strcmp(m,"bind_rollback"))bad=test_bind_rollback();
 else if(!strcmp(m,"directions_and_bounds"))bad=test_directions_and_bounds();
 else if(!strcmp(m,"preaccept_eagain"))bad=test_preaccept();
 else if(!strcmp(m,"inline"))bad=test_inline();
 else if(!strcmp(m,"duplicate"))bad=test_duplicate(false,false);
 else if(!strcmp(m,"stale_reuse"))bad=test_duplicate(true,false);
 else if(!strcmp(m,"stale_stage_reuse"))bad=test_duplicate(true,true);
 else if(!strcmp(m,"dma_to_ce_stale"))bad=test_crossclass(false);
 else if(!strcmp(m,"ce_to_dma_stale"))bad=test_crossclass(true);
 else if(!strcmp(m,"unregister_bound"))bad=test_unregister_bound();
 else if(!strcmp(m,"dead_before_submit"))bad=test_dead();
 else if(!strcmp(m,"callback_then_error"))bad=test_callback_then_error();
 else if(!strncmp(m,"stop_",5))bad=test_stop(m);
 else if(!strcmp(m,"ambiguous_unbind"))bad=test_ambiguous_unbind();
 else bad=test_outcome(m);
 if(!bad)printf("PASS %s %u checks\n",m,checks);
 return bad;
}
