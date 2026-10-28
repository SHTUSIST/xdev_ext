/* SPDX-License-Identifier: GPL-2.0 */
/* Environmental host shim. Never implement X4 custody/acceptance here. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/types.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#include <stdarg.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef __u64 u64;
typedef uintptr_t dma_addr_t;
#define BIT(n) (1UL << (n))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BITS_TO_LONGS(n) (((n) + 8 * sizeof(long) - 1) / (8 * sizeof(long)))
#define GFP_KERNEL 0
#define THIS_MODULE NULL
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define static_assert _Static_assert
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define WARN_ON_ONCE(x) ({ bool _warn=!!(x); assert(!_warn); _warn; })

struct mutex { int held; };
static void mutex_init(struct mutex *m) { m->held=0; }
static void mutex_lock(struct mutex *m) { assert(!m->held); m->held=1; }
static void mutex_unlock(struct mutex *m) { assert(m->held); m->held=0; }
typedef struct { int held; pthread_mutex_t native; } spinlock_t;
static _Thread_local int active_spins, inside_callback;
static void fixture_unlock(spinlock_t *);
static void spin_lock_init(spinlock_t *s) { s->held=0; assert(!pthread_mutex_init(&s->native,NULL)); }
static void spin_lock_irq(spinlock_t *s) { assert(!pthread_mutex_lock(&s->native)); assert(!s->held); s->held=1; active_spins++; }
static void spin_unlock_irq(spinlock_t *s) { assert(s->held); s->held=0; active_spins--; assert(!pthread_mutex_unlock(&s->native)); fixture_unlock(s); }
#define spin_lock_irqsave(s,f) do { (f)=0; spin_lock_irq(s); } while (0)
#define spin_unlock_irqrestore(s,f) do { (void)(f); spin_unlock_irq(s); } while (0)
#define lockdep_assert_held(m) assert((m)->held)
static void __set_bit(unsigned n,unsigned long *p) { p[n/(8*sizeof(long))] |= BIT(n%(8*sizeof(long))); }
static void __clear_bit(unsigned n,unsigned long *p) { p[n/(8*sizeof(long))] &= ~BIT(n%(8*sizeof(long))); }
static bool test_bit(unsigned n,const unsigned long *p) { return !!(p[n/(8*sizeof(long))]&BIT(n%(8*sizeof(long)))); }
static unsigned find_first_bit(const unsigned long *p,unsigned n)
{ unsigned i; for(i=0;i<n;i++) if(test_bit(i,p)) return i; return n; }
static void bitmap_fill(unsigned long *p,unsigned n)
{ memset(p,0,BITS_TO_LONGS(n)*sizeof(long)); for(unsigned i=0;i<n;i++) __set_bit(i,p); }

struct list_head { struct list_head *next,*prev; };
struct kref { int n; };
typedef struct { int n; } atomic_t;
typedef struct { u8 b[16]; } uuid_t;
struct work_struct { void (*fn)(struct work_struct *); };
struct delayed_work { struct work_struct work; };
#define to_delayed_work(w) container_of(w,struct delayed_work,work)
static void *system_long_wq;
/* These original suites use IRQ completion. Native polling/work scheduling
 * belongs to the separate actual-NHI composition and must never be hidden. */
static bool mod_delayed_work(void *queue,struct delayed_work *work,unsigned long delay)
{ (void)queue;(void)work;(void)delay;assert(!"unexpected native poll work in IRQ ring fixture");abort(); }
static bool cancel_delayed_work_sync(struct delayed_work *work)
{ (void)work;assert(!"unexpected native poll cancellation in IRQ ring fixture");abort(); }
struct device { int id; const char *name; };
static const char *dev_name(const struct device *d) { assert(d && d->name);return d->name; }
struct pci_dev { struct device dev; int refs; };
struct tb_nhi { struct pci_dev *pdev; bool going_away; unsigned int hop_count; };
struct tb { struct tb_nhi *nhi; };
struct tb_xdomain { struct tb *tb;struct device dev; };
struct tb_service { int unused; };
struct file; struct module; struct xdev_ext_net_slot;
struct xdev_ext_peer_mapping;
struct xdev_ext_mech_session;
struct xdev_ext_mech_stage { u32 direction; int id; struct xdev_ext_mech_session *s; };
static bool xdev_ext_mech_session_admits(const struct xdev_ext_mech_session *session)
{ (void)session;assert(!"v2 session admission outside original v1 ring fixture");abort(); }

/* Exact public frame field layout from locked upstream thunderbolt.h. */
struct tb_ring;
struct ring_frame;
typedef void (*ring_cb)(struct tb_ring *,struct ring_frame *,bool);
struct ring_frame {
    dma_addr_t buffer_phy;
    ring_cb callback;
    struct list_head list;
    u32 size:12,flags:12,eof:4,sof:4;
};
struct tb_ring_snapshot {u32 in_flight,software_pending;bool running,notify_pending;};
static void tb_ring_snapshot(struct tb_ring *,struct tb_ring_snapshot *);
struct tb_ring {
    struct tb_nhi *nhi;
    int size,hop;
    bool is_tx,running;
    unsigned flags;
    /* Recorder-only upstream queue state; production never accesses these. */
    struct ring_frame *queued[512];
    unsigned queued_nr,enqueue_calls,notify_calls;
    bool freed;
};
#define RING_FLAG_FRAME BIT(1)
#define RING_FLAG_E2E BIT(2)
#define RING_FLAG_NO_INTERRUPT BIT(3)
#define RING_DESC_CRC_ERROR 1U
#define RING_DESC_BUFFER_OVERRUN 4U
static struct tb_ring *tb_ring_alloc_tx(struct tb_nhi *,int,int,unsigned);
static struct tb_ring *tb_ring_alloc_rx(struct tb_nhi *,int,int,unsigned,int,u16,u16,void (*)(void *),void *);
static void tb_ring_start(struct tb_ring *);
static void tb_ring_stop(struct tb_ring *);
static void tb_ring_free(struct tb_ring *);
static void tb_ring_free_quarantined(struct tb_ring *);
static int tb_ring_tx(struct tb_ring *,struct ring_frame *);
static int tb_ring_rx(struct tb_ring *,struct ring_frame *);
static int tb_ring_tx_more(struct tb_ring *,struct ring_frame *);
static int tb_ring_rx_more(struct tb_ring *,struct ring_frame *);
static void tb_ring_notify(struct tb_ring *);
static struct ring_frame *tb_ring_poll(struct tb_ring *ring)
{ (void)ring;assert(!"unexpected native poll in IRQ ring fixture");abort(); }
static bool tb_ring_poll_pending(struct tb_ring *ring)
{ (void)ring;assert(!"unexpected native poll query in IRQ ring fixture");abort(); }
static struct device *tb_ring_dma_device(struct tb_ring *);
static int tb_xdomain_alloc_in_hopid(struct tb_xdomain *,int);
static int tb_xdomain_alloc_out_hopid(struct tb_xdomain *,int);
static void tb_xdomain_release_in_hopid(struct tb_xdomain *,int);
static void tb_xdomain_release_out_hopid(struct tb_xdomain *,int);
static int tb_xdomain_enable_paths(struct tb_xdomain *,int,int,int,int);
static int tb_xdomain_disable_paths(struct tb_xdomain *,int,int,int,int);
static void *dma_alloc_coherent(struct device *,size_t,dma_addr_t *,int);
static void dma_free_coherent(struct device *,size_t,void *,dma_addr_t);
static void *kzalloc(size_t,int);
static void kfree(void *);
static u32 crc32c(u32,const void *,size_t);

#define DEFINE_SPINLOCK(n) spinlock_t n={.native=PTHREAD_MUTEX_INITIALIZER}
#define LIST_HEAD_INIT(n) {&(n),&(n)}
#define LIST_HEAD(n) struct list_head n=LIST_HEAD_INIT(n)
static void INIT_LIST_HEAD(struct list_head *h) {h->next=h->prev=h;}
static bool list_empty(const struct list_head *h) {return h->next==h;}
static void list_add_tail(struct list_head *n,struct list_head *h) {n->prev=h->prev;n->next=h;h->prev->next=n;h->prev=n;}
static void list_del_init(struct list_head *n) {n->prev->next=n->next;n->next->prev=n->prev;INIT_LIST_HEAD(n);}
#define list_first_entry(h,t,m) container_of((h)->next,t,m)
#define list_for_each_entry(p,h,m) for(p=list_first_entry(h,typeof(*p),m);&(p)->m!=(h);p=list_first_entry(&(p)->m,typeof(*p),m))
#define spin_lock spin_lock_irq
#define spin_unlock spin_unlock_irq
#define DECLARE_BITMAP(n,b) unsigned long n[BITS_TO_LONGS(b)]
#define bitmap_zero(p,n) memset(p,0,BITS_TO_LONGS(n)*sizeof(long))

/* C1 external scalar counter and printk boundary, never a marker generator. */
typedef struct { _Atomic long long counter; } atomic64_t;
#define ATOMIC64_INIT(v) { .counter=(v) }
static long long atomic64_inc_return(atomic64_t *p) {return atomic_fetch_add(&p->counter,1)+1;}
static void dev_info(const struct device *,const char *,...);

/* Kernel facilities required by the built-in retention core. */
#define EXPORT_SYMBOL_GPL(n)
static void list_del(struct list_head *n) { n->prev->next=n->next; n->next->prev=n->prev; }

static unsigned bitmap_weight(const unsigned long *map,unsigned n){unsigned count=0;for(unsigned i=0;i<n;i++)count+=!!(map[i/(8*sizeof(long))]&(1UL<<(i%(8*sizeof(long)))));return count;}

#include "include/linux/xdev_ext_mech_reliable_core.h"
#include "io_uring/xdomain/xdev_ext_xdomain_probe_core.h"

#include "io_uring/xdomain/xdev_ext_xdomain_early.h"
