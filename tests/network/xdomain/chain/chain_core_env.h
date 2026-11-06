/* SPDX-License-Identifier: GPL-2.0 */
/*
 * OS boundary of the core translation unit.  Every scheduler, lifecycle,
 * completion, custody and release decision compiled with this header is a
 * production definition extracted by run.py; this file only supplies kernel
 * primitives.  Single-threaded deterministic host: locks record nesting,
 * kthread work runs from chain_core_run_one() in FIFO order of due time.
 */
#ifndef CHAIN_CORE_ENV_H
#define CHAIN_CORE_ENV_H
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __KERNEL__ 1
#define CONFIG_XDEV_EXT_MECH 1
typedef signed char __s8;
typedef unsigned char __u8;
typedef short __s16;
typedef unsigned short __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long __s64;
typedef unsigned long long __u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;
typedef __u32 __wsum;
#define __aligned_u64 __u64 __attribute__((aligned(8)))
typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef u64 dma_addr_t;
typedef unsigned int gfp_t;
typedef int kuid_t;
typedef struct { int counter; } atomic_t;
typedef struct { long long counter; } atomic64_t;
typedef struct { unsigned depth; } spinlock_t;
typedef struct { int unused; } wait_queue_head_t;
struct module { int refs; bool going; };
struct file;
struct page;
struct pci_dev;
struct eventfd_ctx;
struct io_ring_ctx;
struct list_head { struct list_head *next, *prev; };
struct llist_node { struct llist_node *next; };
struct llist_head { struct llist_node *first; };
struct kthread_worker { unsigned id; };
struct kthread_work {
	void (*func)(struct kthread_work *);
	struct kthread_worker *worker;
	bool pending;
	unsigned long long due;
	unsigned long long order;
};
struct kthread_delayed_work { struct kthread_work work; };
struct work_struct { void (*func)(struct work_struct *); bool pending; };
struct timer_list { void (*func)(struct timer_list *); };
struct xdev_ext_rel_policy;
enum dma_data_direction { DMA_BIDIRECTIONAL, DMA_TO_DEVICE, DMA_FROM_DEVICE, DMA_NONE };
#define XDEV_EXT_PEER_HOST_TEST 1

#define __user
#define __rcu
#define __must_check
#ifndef __always_inline
#define __always_inline inline
#endif
#define __aligned(n) __attribute__((aligned(n)))
#define __packed __attribute__((packed))
#define likely(x) (x)
#define unlikely(x) (x)
#define EXPORT_SYMBOL_GPL(n)
#define THIS_MODULE NULL
#define GFP_KERNEL 0U
#define HZ 1000
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define BIT(n) (1U << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK_ULL(h, l) ((~0ULL << (l)) & (~0ULL >> (63 - (h))))
#define U32_MAX UINT32_MAX
#define U64_MAX UINT64_MAX
#define S64_MAX INT64_MAX
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ALIGN(x, a) (((x) + (a) - 1) & ~((__typeof__(x))(a) - 1))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_entry(p, t, m) container_of(p, t, m)
#define list_first_entry(h, t, m) list_entry((h)->next, t, m)
#define list_first_entry_or_null(h, t, m) (list_empty(h) ? NULL : list_first_entry(h, t, m))
#define list_for_each_entry(p, h, m) \
	for ((p) = list_entry((h)->next, __typeof__(*(p)), m); &(p)->m != (h); \
	     (p) = list_entry((p)->m.next, __typeof__(*(p)), m))
#define list_for_each_entry_safe(p, n, h, m) \
	for ((p) = list_entry((h)->next, __typeof__(*(p)), m), \
	     (n) = list_entry((p)->m.next, __typeof__(*(p)), m); &(p)->m != (h); \
	     (p) = (n), (n) = list_entry((n)->m.next, __typeof__(*(n)), m))
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }
static inline void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
static inline bool list_empty(const struct list_head *h) { return h->next == h; }
static inline void list_add_tail(struct list_head *n, struct list_head *h)
{ n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n; }
static inline void list_add(struct list_head *n, struct list_head *h)
{ n->next = h->next; n->prev = h; h->next->prev = n; h->next = n; }
static inline void list_del(struct list_head *n) { n->prev->next = n->next; n->next->prev = n->prev; }
static inline void list_del_init(struct list_head *n) { list_del(n); INIT_LIST_HEAD(n); }
static inline void list_splice_init(struct list_head *a, struct list_head *b)
{
	if (list_empty(a)) return;
	a->next->prev = b; a->prev->next = b->next; b->next->prev = a->prev;
	b->next = a->next; INIT_LIST_HEAD(a);
}
#define llist_entry(p, t, m) container_of(p, t, m)
#define llist_for_each_safe(p, n, h) for ((p) = (h); (p) && ((n) = (p)->next, 1); (p) = (n))
static inline void init_llist_head(struct llist_head *h) { h->first = NULL; }
static inline bool llist_add(struct llist_node *n, struct llist_head *h)
{ bool empty = !h->first; n->next = h->first; h->first = n; return empty; }
static inline struct llist_node *llist_del_all(struct llist_head *h)
{ struct llist_node *n = h->first; h->first = NULL; return n; }
static inline struct llist_node *llist_reverse_order(struct llist_node *h)
{
	struct llist_node *r = NULL;
	while (h) { struct llist_node *n = h->next; h->next = r; r = h; h = n; }
	return r;
}
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_store_release(p, v) __atomic_store_n(p, v, __ATOMIC_RELEASE)
#define smp_load_acquire(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)
#define smp_mb() __sync_synchronize()
#define smp_wmb() __atomic_thread_fence(__ATOMIC_RELEASE)
#define smp_rmb() __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define cmpxchg(p, o, n) __sync_val_compare_and_swap(p, o, n)
#define try_cmpxchg(p, o, n) __atomic_compare_exchange_n(p, o, n, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define hweight32(x) __builtin_popcount(x)
#define check_add_overflow(a, b, d) __builtin_add_overflow((a), (b), (d))
#define check_mul_overflow(a, b, d) __builtin_mul_overflow((a), (b), (d))
#define atomic_read(a) ((a)->counter)
#define atomic_set(a, v) ((a)->counter = (v))
#define atomic_inc(a) ((void)++(a)->counter)
#define atomic_dec(a) ((void)--(a)->counter)
#define atomic64_read(a) ((a)->counter)
#define atomic64_set(a, v) ((a)->counter = (v))
#define atomic64_inc(a) ((void)++(a)->counter)
#define atomic64_dec(a) ((void)--(a)->counter)
#define atomic64_add(n, a) ((void)((a)->counter += (n)))
#define atomic64_inc_return(a) (++(a)->counter)
#define ATOMIC64_INIT(v) { (v) }
extern unsigned chain_core_spins;
static inline void spin_lock_init(spinlock_t *l) { l->depth = 0; }
static inline void chain_spin_lock(spinlock_t *l) { assert(!l->depth); l->depth++; chain_core_spins++; }
static inline void chain_spin_unlock(spinlock_t *l) { assert(l->depth == 1); l->depth--; chain_core_spins--; }
#define spin_lock(l) chain_spin_lock(l)
#define spin_unlock(l) chain_spin_unlock(l)
#define spin_lock_irqsave(l, f) do { (f) = 0; chain_spin_lock(l); } while (0)
#define spin_unlock_irqrestore(l, f) do { (void)(f); chain_spin_unlock(l); } while (0)
#define lockdep_assert_held(l) assert((l)->depth)
#define DEFINE_SPINLOCK(n) spinlock_t n = { 0 }
#define DEFINE_MUTEX(n) int n
#define mutex_lock(m) ((void)(m))
#define mutex_unlock(m) ((void)(m))
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define synchronize_rcu() ((void)0)
extern unsigned chain_core_warnings;
#define WARN_ON_ONCE(c) ({ bool bad_ = !!(c); if (bad_) { chain_core_warnings++; \
	fprintf(stderr, "CHAIN_CORE_WARN %s:%d\n", __FILE__, __LINE__); } bad_; })
#define WARN_ON(c) WARN_ON_ONCE(c)
#define WARN_ONCE(c, ...) WARN_ON_ONCE(c)
#define pr_warn(...) ((void)0)
#define pr_warn_once(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)
#define ERR_PTR(e) ((void *)(intptr_t)(e))
#define PTR_ERR(p) ((long)(intptr_t)(p))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define IS_ERR_OR_NULL(p) (!(p) || IS_ERR(p))
#define ERR_CAST(p) ((void *)(p))
void *chain_kzalloc(size_t n);
void chain_kfree(const void *p);
#define kzalloc(n, g) chain_kzalloc(n)
#define kmalloc(n, g) chain_kzalloc(n)
#define kcalloc(n, s, g) chain_kzalloc((size_t)(n) * (s))
#define kvcalloc(n, s, g) chain_kzalloc((size_t)(n) * (s))
#define kvmalloc_array(n, s, g) chain_kzalloc((size_t)(n) * (s))
#define kfree(p) chain_kfree(p)
#define kvfree(p) chain_kfree(p)
static inline bool try_module_get(struct module *m) { if (m && m->going) return false; if (m) m->refs++; return true; }
static inline void module_put(struct module *m) { if (m) { assert(m->refs); m->refs--; } }
static inline kuid_t current_euid(void) { return 0; }
static inline void wake_up(wait_queue_head_t *w) { (void)w; }
static inline void init_waitqueue_head(wait_queue_head_t *w) { (void)w; }
#define timer_setup(t, f, flags) do { (t)->func = (f); } while (0)
static inline void timer_shutdown_sync(struct timer_list *t) { (void)t; }
#define INIT_WORK(w, f) do { (w)->func = (f); (w)->pending = false; } while (0)
static inline bool queue_work(void *wq, struct work_struct *w) { (void)wq; w->pending = true; return true; }
#define system_unbound_wq NULL
static inline void eventfd_signal(struct eventfd_ctx *e) { (void)e; }
static inline void eventfd_ctx_put(struct eventfd_ctx *e) { (void)e; }
static inline struct eventfd_ctx *eventfd_ctx_fdget(int fd) { (void)fd; return ERR_PTR(-EBADF); }
struct file *fget(int fd);
void fput(struct file *f);
/* kthread work: owned by this TU; chain_core_run_one() executes it. */
#define kthread_init_work(w, f) do { *(w) = (struct kthread_work){ .func = (f) }; } while (0)
#define kthread_init_delayed_work(d, f) kthread_init_work(&(d)->work, f)
struct kthread_worker *kthread_run_worker(unsigned flags, const char *fmt, ...);
bool kthread_queue_work(struct kthread_worker *w, struct kthread_work *work);
bool kthread_queue_delayed_work(struct kthread_worker *w, struct kthread_delayed_work *d,
				unsigned long delay);
bool kthread_mod_delayed_work(struct kthread_worker *w, struct kthread_delayed_work *d,
			      unsigned long delay);
void kthread_cancel_delayed_work_sync(struct kthread_delayed_work *d);
void kthread_destroy_worker(struct kthread_worker *w);
extern unsigned long jiffies;
static inline unsigned long msecs_to_jiffies(unsigned long n) { return n; }
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
u64 ktime_get_boottime_ns(void);
/* The optional tracepoints are disabled in this composition. */
static inline bool trace_native_event_enabled(void) { return false; }
static inline bool trace_xdomain_event_enabled(void) { return false; }
#define trace_xdomain_event(...) ((void)0)
static inline void xdev_ext_native_event_emit(const char *phase, const char *origin,
		u64 session_id, u64 batch_id, u64 batch_key, u32 frame_id,
		u64 generation, u32 stage, u64 ticket, u32 class_id, int accepted,
		int status, u64 cookie, u64 address, u32 bytes, u64 aux, u64 sequence,
		u32 frame_ordinal, u32 frame_offset, u32 frame_length)
{
	(void)phase; (void)origin; (void)session_id; (void)batch_id; (void)batch_key;
	(void)frame_id; (void)generation; (void)stage; (void)ticket; (void)class_id;
	(void)accepted; (void)status; (void)cookie; (void)address; (void)bytes; (void)aux;
	(void)sequence; (void)frame_ordinal; (void)frame_offset; (void)frame_length;
}
#endif
