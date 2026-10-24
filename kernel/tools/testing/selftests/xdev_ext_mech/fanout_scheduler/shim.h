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
#include "io_uring/xdev_ext_mech_produced.h"
#include "io_uring/xdev_ext_mech_dma_core.h"
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_mech_native_cookie.h"

typedef __s32 s32;
typedef __u8 u8;
typedef __u32 u32;
typedef __u64 u64;
typedef int kuid_t;
typedef int spinlock_t;
typedef int wait_queue_head_t;
typedef unsigned long atomic64_t;
typedef int atomic_t;
struct xdev_ext_rel_policy;
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

/* These scheduler fixtures run with the optional tracepoint disabled. */
static inline bool trace_native_event_enabled(void) { return false; }
static inline void xdev_ext_mech_trace_batch(struct xdev_ext_mech_batch *b,
 const char *phase, u64 ticket, int status)
{ (void)b; (void)phase; (void)ticket; (void)status; }
static inline void xdev_ext_mech_trace_frame(struct xdev_ext_mech_batch *b,
 const char *phase, u32 pos, u64 ticket, int status)
{ (void)b; (void)phase; (void)pos; (void)ticket; (void)status; }
