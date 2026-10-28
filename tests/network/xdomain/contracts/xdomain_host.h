/* SPDX-License-Identifier: GPL-2.0 */
/* Host metadata only. No protocol decisions or fabricated native quiescence. */
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_xdp.h>
#include "@UAPI@"
#include "@PROG@"
#include "@KERNEL@/io_uring/xdev_ext_mech_core.h"
#include "@KERNEL@/include/linux/xdev_ext_peer_net_track.h"
#include "@KERNEL@/include/linux/xdev_ext_netfam_core.h"
#include "@KERNEL@/include/linux/xdev_ext_requester_core.h"
#include "@KERNEL@/io_uring/xdomain/xdev_ext_xdomain_core.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int32_t s32; typedef int64_t s64; typedef u64 dma_addr_t;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE };
#define XDEV_EXT_PEER_HOST_TEST
#include "@KERNEL@/include/linux/xdev_ext_peer.h"
#define GFP_KERNEL 0
#define NSEC_PER_MSEC 1000000ULL
#define NSEC_PER_SEC 1000000000ULL
#define U64_MAX UINT64_MAX
#define U32_MAX UINT32_MAX
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define IS_ERR(p) ((uintptr_t)(p)>=(uintptr_t)-4095)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define WARN_ON_ONCE(x) (!!(x))
#define DIV_ROUND_UP(n,d) (((n)+(d)-1)/(d))
#define min(a,b) ((a)<(b)?(a):(b))
#define max(a,b) ((a)>(b)?(a):(b))
#define min_t(t,a,b) min((t)(a),(t)(b))
#define BIT(n) (1U << (n))
#define BIT_ULL(n) (1ULL << (n))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define kzalloc(n,g) calloc(1,n)
#define kcalloc(n,s,g) calloc(n,s)
#define kvcalloc(n,s,g) calloc(n,s)
#define kvfree free
#define kfree free
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define msecs_to_jiffies(x) (x)
#define nsecs_to_jiffies(x) (((x)+NSEC_PER_MSEC-1)/NSEC_PER_MSEC)
#define EXPORT_SYMBOL_GPL(name)
#define THIS_MODULE NULL
#define static_assert _Static_assert
#define SEC(s)
#define BPF_PROG(name, ...) name(void *ctx __attribute__((unused)), __VA_ARGS__)
#define __init
#define __exit
#define module_init(x)
#define module_exit(x)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define lockdep_assert_held(p) assert(*(p))
typedef unsigned spinlock_t;
static unsigned held_spinlocks, held_mutexes, callback_depth, worker_depth, protocol_calls;
static void host_lock(spinlock_t *p) { assert(!*p); *p=1; held_spinlocks++; }
static void host_unlock(spinlock_t *p) { assert(*p && held_spinlocks); *p=0; held_spinlocks--; }
#define spin_lock_init(p) (*(p)=0)
#define spin_lock_irqsave(p,f) do { (f)=0; host_lock(p); } while (0)
#define spin_unlock_irqrestore(p,f) do { (void)(f); host_unlock(p); } while (0)
#define spin_lock(p) host_lock(p)
#define spin_unlock(p) host_unlock(p)
#define spin_lock_irq(p) host_lock(p)
#define spin_unlock_irq(p) host_unlock(p)
struct mutex { unsigned held; };
static void mutex_lock(struct mutex *m) { assert(!m->held); m->held=1; held_mutexes++; }
static void mutex_unlock(struct mutex *m) { assert(m->held && held_mutexes); m->held=0; held_mutexes--; }
struct kref { int refs; }; struct list_head { void *next,*prev; };
struct work_struct { unsigned queued; }; struct delayed_work { struct work_struct work; };
struct tb_ring;
struct ring_frame {
 dma_addr_t buffer_phy;
 void (*callback)(struct tb_ring *,struct ring_frame *,bool);
 struct list_head list;
 u32 size:12,flags:12,eof:4,sof:4;
};
static struct ring_frame *tb_ring_poll(struct tb_ring *ring)
{ (void)ring;assert(!"unexpected native poll in IRQ class fixture");abort(); }
static bool tb_ring_poll_pending(struct tb_ring *ring)
{ (void)ring;assert(!"unexpected native poll query in IRQ class fixture");abort(); }
static bool mod_delayed_work(void *queue,struct delayed_work *work,unsigned long delay)
{ (void)queue;(void)work;(void)delay;assert(!"unexpected native poll work in IRQ class fixture");abort(); }
#define system_long_wq NULL
struct tb_ring; struct tb_service; struct tb_xdomain;
typedef struct { u8 bytes[16]; } uuid_t;
typedef int atomic_t; typedef long atomic64_t;
#define atomic_read(p) (*(p))
#define atomic_inc(p) host_atomic_inc(p)
#define atomic_dec(p) host_atomic_dec(p)
#define atomic64_inc(p) (++*(p))
#define BITS_TO_LONGS(x) (((x)+sizeof(unsigned long)*8-1)/(sizeof(unsigned long)*8))
struct device { unsigned tag; };
struct pci_dev { struct device dev; unsigned devfn; struct { unsigned number; } *bus; };
struct file { unsigned tag; };
struct module;
struct xdev_ext_mech_pool { u32 kind,frame_size,nr_frames; u64 generation; };
struct xdev_ext_mech_session;
struct xdev_ext_mech_stage;
struct xdev_ext_mech_batch;
struct xdev_ext_mech_class_ops;
struct xdev_ext_rel_policy;
struct xdev_ext_mech_hold_intent;
#define XDEV_EXT_MECH_CLASS_F_ORDERED (1U<<0)
#define XDEV_EXT_MECH_CLASS_F_FIFO_ENQUEUE (1U<<1)
#define XDEV_EXT_MECH_CLASS_F_TRANSFORM (1U<<2)
/* Exact current production structs from header, not a parallel class ABI. */
@DECLARATIONS@
#define kthread_work work_struct
struct kthread_delayed_work { struct work_struct work; };
#define smp_load_acquire(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
struct xdev_ext_mech_session {
 struct xdev_ext_mech_pool pool;
 struct xdev_ext_mech_layout l;
 struct xdev_ext_mech_sess ss;
 struct xdev_ext_mech_stage st[XDEV_EXT_MECH_MAX_STAGES];
 unsigned nr_stages,depth,queued,gets,puts;
 bool progress_ready,create_pending_publish;
 u64 id;
 spinlock_t lock;
 atomic_t native_controls;
 bool worker_gone,start_preparing,start_return_pending,start_recycle;
 unsigned start_left;
 atomic64_t done,aborted;
 int drain_wq,last_err,stop_err;
 u64 stop_started_ns;
 struct xdev_ext_mech_start_queue *start_queue;
 bool start_ordered;
 void *worker;
 struct work_struct reap_work,kick_work,stop_work;
 struct kthread_delayed_work progress_work;
};
struct xdev_ext_mech_batch {
 void *priv,*cookie;
 struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
 struct { unsigned state,stage; } bs;
 u32 nr;
 u64 ticket;
 bool ordered_loan;
 unsigned claims,publishes,filled,ended,disposition_order;
 int status;
 bool sequester,disposed;
};
static void count_native_get(atomic_t *value);
static void count_native_put(atomic_t *value);
static void host_atomic_inc(atomic_t *value) { count_native_get(value);++*value; }
static void host_atomic_dec(atomic_t *value) { assert(*value>0);count_native_put(value);--*value; }
static u64 host_ns=1000000;
static unsigned observation_order, frame_release_fail;
static const struct xdev_ext_mech_class_ops *registered;
static u64 ktime_get_boottime_ns(void) { return host_ns; }
static struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s) { return &s->pool; }
static const struct xdev_ext_mech_layout *xdev_ext_mech_session_layout(struct xdev_ext_mech_session *s) { return &s->l; }
static u32 xdev_ext_mech_session_depth(struct xdev_ext_mech_session *s) { return s->depth; }
static u64 xdev_ext_mech_session_id(const struct xdev_ext_mech_session *s) { return s->id; }
static u32 xdev_ext_mech_session_state(struct xdev_ext_mech_session *s) { return s->ss.state; }
static bool xdev_ext_mech_session_admits(struct xdev_ext_mech_session *s) { return s->ss.state==XDEV_EXT_MECH_SESSION_ACTIVE; }
static void *xdev_ext_mech_batch_priv(struct xdev_ext_mech_batch *b) { return b->priv; }
static void *xdev_ext_mech_batch_cookie(struct xdev_ext_mech_batch *b) { return b->cookie; }
static u32 xdev_ext_mech_batch_nr_frames(struct xdev_ext_mech_batch *b) { return b->nr; }
static u64 xdev_ext_mech_batch_ticket(struct xdev_ext_mech_batch *b) { return b->ticket; }
static int xdev_ext_mech_batch_frame(struct xdev_ext_mech_batch *b,u32 i,struct xdev_ext_mech_frame *out) { if(i>=b->nr)return -EINVAL; *out=b->f[i]; return 0; }
static int xdev_ext_mech_batch_completion_claim(struct xdev_ext_mech_batch *b,u64 ticket) { if(ticket!=b->ticket||b->claims)return -ESTALE; b->claims++; return 0; }
static void xdev_ext_mech_batch_completion_publish(struct xdev_ext_mech_batch *b,u64 ticket,int status,bool q) { assert(ticket==b->ticket&&b->claims==1&&!b->publishes); b->publishes++;b->status=status;b->sequester=q; }
static void xdev_ext_mech_stage_kick(struct xdev_ext_mech_stage *st) { st->s->queued=1; /* records only; never calls progress */ }
static void xdev_ext_mech_stage_dead(struct xdev_ext_mech_stage *st,int error) { st->s->last_err=error; if(st->cls&&st->cls->mark_dead)st->cls->mark_dead(st); st->s->queued=1; }
static struct file authority;
static struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *p) { assert(p->kind==XDEV_EXT_MECH_POOL_PEER);return &authority; }
static u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *p) { return p->generation; }
bool xdev_ext_peer_control_file(struct file *f) { return f==&authority; }
static int xdev_ext_mech_class_register(const struct xdev_ext_mech_class_ops *ops) { assert(ops->class_id==XDEV_EXT_MECH_CLASS_XDOMAIN&&!registered);registered=ops;return 0; }
static void xdev_ext_mech_class_unregister(const struct xdev_ext_mech_class_ops *ops) { assert(registered==ops);registered=NULL; }
static bool xdev_ext_mech_stage_has_member(const struct xdev_ext_mech_stage *st,u32 member);
static int xdev_ext_mech_call(struct xdev_ext_mech_stage *st,const struct xdev_ext_mech_call_args *a,s32 *ret,struct xdev_ext_mech_hold_intent *hold);
static void xdev_ext_mech_trace_native_submit(struct xdev_ext_mech_batch *b,u64 cookie,u64 lba,u32 bytes,u32 opcode);
static void xdev_ext_mech_trace_native_complete(struct xdev_ext_mech_batch *b,u64 ticket,int status);
static void xdev_ext_mech_count(struct xdev_ext_mech_session *s,u32 counter,u64 add) { (void)s;(void)counter;(void)add; }
static int bitmap_empty(const unsigned long *p,unsigned bits) { for(unsigned i=0;i<BITS_TO_LONGS(bits);i++)if(p[i])return 0;return 1; }
static void capture_debug(struct device *dev,const char *format,...);
#define dev_dbg(dev,...) capture_debug(dev,__VA_ARGS__)
static const char *pci_name(const struct pci_dev *pdev) { (void)pdev;return "0000:06:00.0"; }
/* Unrelated external core effects. The ordering/drain functions below are REAL. */
#define wake_up(p) ((void)(p))
static void xdev_ext_mech_session_stop(struct xdev_ext_mech_session *s,int err);
static void xdev_ext_mech_retry_kick(struct xdev_ext_mech_session *s) { (void)s; }
static void xdev_ext_mech_order_kick(struct xdev_ext_mech_session *s) { (void)s; }
static int xdev_ext_mech_frames_release(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b) { (void)s;b->disposed=true;b->disposition_order=++observation_order;return frame_release_fail?-EIO:0; }
static void xdev_ext_mech_trace_batch(struct xdev_ext_mech_batch *b,const char *label,u64 ticket,int err) { (void)b;(void)label;(void)ticket;(void)err; }
static void xdev_ext_mech_return_idle(struct xdev_ext_mech_session *s,bool strict) { (void)s;(void)strict; }
static void xdev_ext_mech_set_err_locked(struct xdev_ext_mech_session *s,int err) { if(err&&!s->last_err)s->last_err=err; }
static bool xdev_ext_mech_batch_put_locked(struct xdev_ext_mech_session *s,struct xdev_ext_mech_batch *b,bool q) { assert(s->ss.inflight);s->ss.inflight--;s->ss.sequestered+=q;b->ended++;return false; }
static void xdev_ext_mech_notify_locked(struct xdev_ext_mech_session *s,bool terminal) { (void)s;(void)terminal; }
static int queue_work(void *queue,struct work_struct *work) { (void)queue;work->queued=1;return 1; }
static int kthread_queue_work(void *queue,struct work_struct *work) { return queue_work(queue,work); }
static int kthread_queue_delayed_work(void *queue,struct kthread_delayed_work *w,unsigned long delay) { (void)delay;return queue_work(queue,&w->work); }
#define system_unbound_wq NULL
/* Existing XDOMAIN cases do not enter ordered START queue release. Refuse
 * that external boundary rather than inventing a successful lifecycle. */
static int xdev_ext_mech_start_queue_release(struct xdev_ext_mech_session *s,
 struct xdev_ext_mech_batch *b, bool reusable) {
 (void)s;(void)b;(void)reusable;
 assert(!"ordered START queue outside XDOMAIN class fixture scope");return -EOPNOTSUPP;
}
@CORE@
/* Full actual family runtime; no substituted CHANNEL policy. */
@FAMILY@
/* BPF runtime metadata adapters, implemented after actual source definitions. */
static void *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx,__u32 size);
static void *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx,__u32 slot,__u32 size);
static void *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx,__u32 slot,__u32 size);
static int bpf_xdev_ext_xdomain_info(const struct xdev_ext_mech_ctx *ctx,void *out,__u32 size);
static int bpf_xdev_ext_xdomain_verdict(const struct xdev_ext_mech_ctx *ctx,const void *in,__u32 size);
struct xdev_ext_xdomain_mech_ops {
 __u32 abi_version,flags;
 __s32 (*prepare)(const struct xdev_ext_mech_ctx *);
 __s32 (*build)(const struct xdev_ext_mech_ctx *);
 __s32 (*complete)(const struct xdev_ext_mech_ctx *);
 __s32 (*compute)(const struct xdev_ext_mech_ctx *);
};
@BPF@
/* Complete actual class, not a test model. */
@POLL@
@CLASS@
@BOUNDARIES@
@CASES@
