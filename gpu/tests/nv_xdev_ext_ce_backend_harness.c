/* SPDX-License-Identifier: MIT */
/*
 * Host fixture that compiles the actual nv-xdev_ext-ce-backend.c and drives it
 * through its registered xdev_ext_ce_backend_ops.  Kernel services (locks,
 * work, timers, allocation, the DMA-mapping API) and the RM/nv-p2p boundary
 * are ordinary user-space stubs with counters; no GPU, IOMMU, page pin or
 * copy engine exists here and no transfer is simulated.  The stubs record
 * calls so the cases can check correctness, teardown and error-path
 * behaviour: exactly-once completion, completion by event, window/cookie
 * rejection, DMA-address selection, unmap ordering and sleep-in-atomic.
 *
 * Variants (compiler -D): NV_XDEV_EXT_CE_POLL_COMPLETION, NV_XDEV_EXT_CE_PHYS_ADDR.
 * Contract switches set by the runner from the production headers:
 * HARNESS_EVENT_API (nv_p2p_ce_event_fn declared), HARNESS_UNBIND_STATUS
 * (nv_p2p_vidmem_unbind returns NV_STATUS). See the corresponding Python runner.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <unistd.h>
#include <stddef.h>
#include "nv_xdev_ext_host_env.h"

#ifndef HARNESS_EVENT_API
#define HARNESS_EVENT_API 0
#endif
#ifndef HARNESS_UNBIND_STATUS
#define HARNESS_UNBIND_STATUS 0
#endif
#ifndef HARNESS_OWNER_API
#define HARNESS_OWNER_API 0
#endif

#if defined(NV_XDEV_EXT_CE_POLL_COMPLETION)
#define VARIANT_EVENT 0
#else
#define VARIANT_EVENT 1
#endif
#if defined(NV_XDEV_EXT_CE_PHYS_ADDR)
#define VARIANT_IOVA 0
#else
#define VARIANT_IOVA 1
#endif

/* ---------------------------------------------------------------- types */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
typedef u64 dma_addr_t;
typedef u64 phys_addr_t;
typedef s64 ktime_t;
typedef unsigned int gfp_t;

#define __user
#define __iomem
#define __must_check
#undef __always_inline
#define __always_inline inline
#define noinline
#define likely(x) (x)
#define unlikely(x) (x)
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define static_assert(expr, ...) _Static_assert(expr, #expr)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(ptr, type, member) \
	((type *)((char *)(ptr) - offsetof(type, member)))
#define min(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ < b_ ? a_ : b_; })
#define max(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ > b_ ? a_ : b_; })
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define max_t(t, a, b) ((t)(a) > (t)(b) ? (t)(a) : (t)(b))
#define clamp_t(t, v, lo, hi) min_t(t, max_t(t, v, lo), hi)
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define WRITE_ONCE(x, v) (*(volatile __typeof__(x) *)&(x) = (v))
#define smp_load_acquire(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)
#define smp_store_release(p, v) __atomic_store_n(p, v, __ATOMIC_RELEASE)
#define smp_mb() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define smp_wmb() __atomic_thread_fence(__ATOMIC_RELEASE)
#define smp_rmb() __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define smp_mb__before_atomic() smp_mb()
#define smp_mb__after_atomic() smp_mb()
#define cmpxchg(p, o, n) __sync_val_compare_and_swap(p, o, n)
#define xchg(p, v) __atomic_exchange_n(p, v, __ATOMIC_SEQ_CST)
#define GFP_KERNEL 0u
#define GFP_ATOMIC 1u
#define GFP_NOWAIT 2u
#define __GFP_NOWARN 0u
#define __GFP_ZERO 4u
#define HZ 1000UL
#define NSEC_PER_USEC 1000ULL
#define NSEC_PER_MSEC 1000000ULL
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define module_param_named(name, var, type, perm) extern int harness_module_param_##name
#define module_param(var, type, perm) extern int harness_module_param_##var
#define MODULE_PARM_DESC(name, desc) extern int harness_module_param_desc_##name
#define pr_err(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
#define pr_debug(...) ((void)0)
#define pr_warn_once(...) ((void)0)
#define pr_err_ratelimited(...) ((void)0)
#define printk(...) ((void)0)

/* ------------------------------------------------- harness global state */
#define MAX_TICKETS 4096
#define MAX_PAGES 64
static __thread int tls_atomic_depth;   /* spinlocks held + event context */
struct harness_completion {
	unsigned int count;
	int status;
	int hw;
	u64 bytes;
	void *cookie;
	unsigned char synced_cpu[MAX_PAGES];
};
static struct harness {
	pthread_mutex_t big;        /* serializes stub state across threads */
	void *live[1024];
	unsigned int live_count, alloc_calls, fail_alloc_at;
	unsigned int sleep_in_atomic, recursive_lock, warns;
	unsigned int vidmem_bind, vidmem_unbind, vidmem_live;
	NV_STATUS vidmem_unbind_status;
	int translated;
	unsigned int rm_bind, rm_unbind, rm_submit, rm_progress;
	NV_STATUS rm_bind_status, rm_unbind_status, rm_progress_status;
	NV_STATUS submit_status;
	int submit_issued, submit_zero_token, fire_in_submit, fire_in_unbind;
	u64 rm_last, rm_completed;
	u64 bound_addrs[MAX_PAGES];
	u32 bound_count, bound_page_size;
	u64 bound_bytes;
	void (*event_fn)(void *, NvU64);
	void *event_arg;
	unsigned int events_fired;
	u32 last_n, last_dir;
	int submit_saw_dev_sync_gap;
	unsigned int dma_map, dma_unmap, sg_alloc, sg_free, dma_bad_dir;
	void *dma_dev;
	int dma_mode;               /* 0 merged, 1 split, 2 fail */
	u64 page_iova[MAX_PAGES];
	unsigned char synced_cpu[MAX_PAGES], synced_dev[MAX_PAGES];
	unsigned int hrtimer_starts, timer_arms;
	char order[512];
	struct harness_completion done[MAX_TICKETS];
	unsigned int total_completions, bad_ticket;
	u64 expected_ticket[MAX_TICKETS];
	u64 frame_owner[MAX_PAGES], frame_generation[MAX_PAGES];
	unsigned int owner_validations, owner_rejections;
} H = { .big = PTHREAD_MUTEX_INITIALIZER };

static void order(const char *what)
{
	pthread_mutex_lock(&H.big);
	if (strlen(H.order) + strlen(what) + 2 < sizeof(H.order)) {
		strcat(H.order, what);
		strcat(H.order, " ");
	}
	pthread_mutex_unlock(&H.big);
}

static void might_sleep_check(const char *what)
{
	if (tls_atomic_depth > 0) {
		__atomic_add_fetch(&H.sleep_in_atomic, 1, __ATOMIC_SEQ_CST);
		printf("VIOLATION: %s may sleep in atomic/event context\n", what);
	}
}
#define might_sleep() might_sleep_check("might_sleep")

#define WARN_ON(c) ({ int c_ = !!(c); if (c_) __atomic_add_fetch(&H.warns, 1, __ATOMIC_SEQ_CST); c_; })
#define WARN_ON_ONCE(c) WARN_ON(c)
#define WARN_ONCE(c, ...) WARN_ON(c)
#define WARN(c, ...) WARN_ON(c)
#define BUG_ON(c) do { if (c) { printf("BUG_ON(%s)\n", #c); abort(); } } while (0)

/* --------------------------------------------------------- allocation */
static void *track(void *p)
{
	if (p) {
		pthread_mutex_lock(&H.big);
		if (H.live_count < ARRAY_SIZE(H.live))
			H.live[H.live_count++] = p;
		pthread_mutex_unlock(&H.big);
	}
	return p;
}
static int harness_is_live(const void *p)
{
	unsigned int i;
	int found = 0;
	pthread_mutex_lock(&H.big);
	for (i = 0; i < H.live_count; i++)
		if (H.live[i] == p)
			found = 1;
	pthread_mutex_unlock(&H.big);
	return found;
}
static void untrack(void *p)
{
	unsigned int i;
	if (!p)
		return;
	pthread_mutex_lock(&H.big);
	for (i = 0; i < H.live_count; i++)
		if (H.live[i] == p) {
			H.live[i] = H.live[--H.live_count];
			break;
		}
	pthread_mutex_unlock(&H.big);
	free(p);
}
static void *harness_alloc(size_t n, gfp_t gfp)
{
	unsigned int call = __atomic_add_fetch(&H.alloc_calls, 1, __ATOMIC_SEQ_CST);
	if (gfp == GFP_KERNEL)
		might_sleep_check("GFP_KERNEL allocation");
	if (H.fail_alloc_at && call == H.fail_alloc_at)
		return NULL;
	return track(calloc(1, n ? n : 1));
}
#define kzalloc(n, g) harness_alloc(n, g)
#define kmalloc(n, g) harness_alloc(n, g)
#define kcalloc(n, s, g) harness_alloc((size_t)(n) * (s), g)
#define kmalloc_array(n, s, g) harness_alloc((size_t)(n) * (s), g)
#define kvzalloc(n, g) harness_alloc(n, g)
#define kvmalloc(n, g) harness_alloc(n, g)
#define kvcalloc(n, s, g) harness_alloc((size_t)(n) * (s), g)
#define kvmalloc_array(n, s, g) harness_alloc((size_t)(n) * (s), g)
#define vzalloc(n) harness_alloc(n, GFP_KERNEL)
#define kfree(p) untrack((void *)(p))
#define kvfree(p) untrack((void *)(p))
#define vfree(p) untrack((void *)(p))

/* ------------------------------------------------------------ locking */
struct mutex { pthread_mutex_t m; pthread_t owner; int held; };
static void mutex_init(struct mutex *l)
{
	pthread_mutex_init(&l->m, NULL);
	l->held = 0;
}
static void mutex_lock(struct mutex *l)
{
	might_sleep_check("mutex_lock");
	if (__atomic_load_n(&l->held, __ATOMIC_SEQ_CST) &&
	    pthread_equal(l->owner, pthread_self())) {
		printf("VIOLATION: recursive mutex_lock (self deadlock)\n");
		H.recursive_lock++;
		fflush(stdout);
		abort();
	}
	pthread_mutex_lock(&l->m);
	l->owner = pthread_self();
	__atomic_store_n(&l->held, 1, __ATOMIC_SEQ_CST);
}
static void mutex_unlock(struct mutex *l)
{
	__atomic_store_n(&l->held, 0, __ATOMIC_SEQ_CST);
	pthread_mutex_unlock(&l->m);
}
static void mutex_destroy(struct mutex *l) { pthread_mutex_destroy(&l->m); }
#define DEFINE_MUTEX(name) struct mutex name = { PTHREAD_MUTEX_INITIALIZER, 0, 0 }

typedef struct { pthread_mutex_t m; pthread_t owner; int held; } spinlock_t;
static void spin_lock_init(spinlock_t *l)
{
	pthread_mutex_init(&l->m, NULL);
	l->held = 0;
}
static void spin_lock(spinlock_t *l)
{
	if (__atomic_load_n(&l->held, __ATOMIC_SEQ_CST) &&
	    pthread_equal(l->owner, pthread_self())) {
		printf("VIOLATION: recursive spin_lock (self deadlock)\n");
		H.recursive_lock++;
		fflush(stdout);
		abort();
	}
	pthread_mutex_lock(&l->m);
	l->owner = pthread_self();
	__atomic_store_n(&l->held, 1, __ATOMIC_SEQ_CST);
	tls_atomic_depth++;
}
static void spin_unlock(spinlock_t *l)
{
	tls_atomic_depth--;
	__atomic_store_n(&l->held, 0, __ATOMIC_SEQ_CST);
	pthread_mutex_unlock(&l->m);
}
#define DEFINE_SPINLOCK(name) spinlock_t name = { PTHREAD_MUTEX_INITIALIZER, 0, 0 }
#define spin_lock_irqsave(l, f) do { (f) = 0; spin_lock(l); } while (0)
#define spin_unlock_irqrestore(l, f) do { (void)(f); spin_unlock(l); } while (0)
#define spin_lock_irq(l) spin_lock(l)
#define spin_unlock_irq(l) spin_unlock(l)
#define spin_lock_bh(l) spin_lock(l)
#define spin_unlock_bh(l) spin_unlock(l)
#define lockdep_assert_held(l) ((void)0)

struct rw_semaphore { int readers; };
static struct rw_semaphore nv_system_pm_lock;
static void down_read(struct rw_semaphore *s)
{
	might_sleep_check("down_read");
	__atomic_add_fetch(&s->readers, 1, __ATOMIC_SEQ_CST);
}
static void up_read(struct rw_semaphore *s) { __atomic_sub_fetch(&s->readers, 1, __ATOMIC_SEQ_CST); }
static int nv_down_read_interruptible(struct rw_semaphore *s) { down_read(s); return 0; }

typedef struct { int counter; } atomic_t;
typedef struct { s64 counter; } atomic64_t;
#define ATOMIC_INIT(v) { (v) }
#define ATOMIC64_INIT(v) { (v) }
#define atomic_read(a) __atomic_load_n(&(a)->counter, __ATOMIC_SEQ_CST)
#define atomic_set(a, v) __atomic_store_n(&(a)->counter, v, __ATOMIC_SEQ_CST)
#define atomic_inc(a) ((void)__atomic_add_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST))
#define atomic_dec(a) ((void)__atomic_sub_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST))
#define atomic_inc_return(a) __atomic_add_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST)
#define atomic_dec_return(a) __atomic_sub_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST)
#define atomic_dec_and_test(a) (__atomic_sub_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST) == 0)
#define atomic_add(v, a) ((void)__atomic_add_fetch(&(a)->counter, v, __ATOMIC_SEQ_CST))
#define atomic_sub(v, a) ((void)__atomic_sub_fetch(&(a)->counter, v, __ATOMIC_SEQ_CST))
#define atomic_cmpxchg(a, o, n) __sync_val_compare_and_swap(&(a)->counter, o, n)
#define atomic_xchg(a, v) __atomic_exchange_n(&(a)->counter, v, __ATOMIC_SEQ_CST)
#define atomic64_read(a) __atomic_load_n(&(a)->counter, __ATOMIC_SEQ_CST)
#define atomic64_set(a, v) __atomic_store_n(&(a)->counter, v, __ATOMIC_SEQ_CST)
#define atomic64_inc(a) ((void)__atomic_add_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST))
#define atomic64_add(v, a) ((void)__atomic_add_fetch(&(a)->counter, v, __ATOMIC_SEQ_CST))
#define atomic64_inc_return(a) __atomic_add_fetch(&(a)->counter, 1, __ATOMIC_SEQ_CST)
#define atomic64_cmpxchg(a, o, n) __sync_val_compare_and_swap(&(a)->counter, o, n)
#define atomic64_xchg(a, v) __atomic_exchange_n(&(a)->counter, v, __ATOMIC_SEQ_CST)

/* ---------------------------------------------- time, work and timers */
static volatile unsigned long jiffies = 1000;
#define time_after(a, b) ((long)((b) - (a)) < 0)
#define time_before(a, b) time_after(b, a)
#define time_after_eq(a, b) ((long)((a) - (b)) >= 0)
#define time_before_eq(a, b) time_after_eq(b, a)
#define msecs_to_jiffies(m) ((unsigned long)(m) * HZ / 1000)
#define usecs_to_jiffies(u) (((unsigned long)(u) + 999) / 1000)
#define ns_to_ktime(n) ((ktime_t)(n))
#define ms_to_ktime(m) ((ktime_t)(m) * 1000000)
#define us_to_ktime(u) ((ktime_t)(u) * 1000)

struct workqueue_struct { int unused; };
static struct workqueue_struct harness_wq;
#define system_unbound_wq (&harness_wq)
#define system_wq (&harness_wq)
#define system_highpri_wq (&harness_wq)
struct work_struct { void (*func)(struct work_struct *); int pending, running; };
#define INIT_WORK(w, f) do { (w)->func = (f); (w)->pending = 0; (w)->running = 0; } while (0)
struct delayed_work { struct work_struct work; unsigned long expires; int armed; };
#define INIT_DELAYED_WORK(d, f) do { INIT_WORK(&(d)->work, f); (d)->armed = 0; } while (0)
#define to_delayed_work(w) container_of(w, struct delayed_work, work)
struct timer_list { void (*function)(struct timer_list *); unsigned long expires; int armed; };
enum hrtimer_restart { HRTIMER_NORESTART, HRTIMER_RESTART };
enum hrtimer_mode { HRTIMER_MODE_REL = 1, HRTIMER_MODE_ABS = 0,
		    HRTIMER_MODE_REL_SOFT = 5, HRTIMER_MODE_ABS_SOFT = 4 };
#define CLOCK_MONOTONIC 1
struct hrtimer { enum hrtimer_restart (*function)(struct hrtimer *); int armed; };

#define MAX_DEFERRED 64
static struct work_struct *pending_work[MAX_DEFERRED];
static struct delayed_work *pending_dwork[MAX_DEFERRED];
static struct timer_list *pending_timer[MAX_DEFERRED];
static struct hrtimer *pending_hrtimer[MAX_DEFERRED];
static pthread_mutex_t deferred_lock = PTHREAD_MUTEX_INITIALIZER;

static void add_unique(void **list, void *item)
{
	unsigned int i;
	for (i = 0; i < MAX_DEFERRED; i++)
		if (list[i] == item)
			return;
	for (i = 0; i < MAX_DEFERRED; i++)
		if (!list[i]) {
			list[i] = item;
			return;
		}
	printf("harness: deferred list full\n");
	abort();
}
static void remove_item(void **list, void *item)
{
	unsigned int i;
	for (i = 0; i < MAX_DEFERRED; i++)
		if (list[i] == item)
			list[i] = NULL;
}
static bool queue_work(struct workqueue_struct *wq, struct work_struct *w)
{
	bool queued;
	(void)wq;
	pthread_mutex_lock(&deferred_lock);
	queued = !w->pending;
	w->pending = 1;
	add_unique((void **)pending_work, w);
	pthread_mutex_unlock(&deferred_lock);
	return queued;
}
#define schedule_work(w) queue_work(system_wq, w)
static bool queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *d,
			       unsigned long delay)
{
	(void)wq;
	pthread_mutex_lock(&deferred_lock);
	H.timer_arms++;
	if (!d->armed) {
		d->armed = 1;
		d->expires = jiffies + delay;
		add_unique((void **)pending_dwork, d);
		pthread_mutex_unlock(&deferred_lock);
		return true;
	}
	pthread_mutex_unlock(&deferred_lock);
	return false;
}
static bool mod_delayed_work(struct workqueue_struct *wq, struct delayed_work *d,
			     unsigned long delay)
{
	(void)wq;
	pthread_mutex_lock(&deferred_lock);
	H.timer_arms++;
	d->armed = 1;
	d->expires = jiffies + delay;
	add_unique((void **)pending_dwork, d);
	pthread_mutex_unlock(&deferred_lock);
	return true;
}
#define schedule_delayed_work(d, delay) queue_delayed_work(system_wq, d, delay)
static void wait_not_running(struct work_struct *w)
{
	while (__atomic_load_n(&w->running, __ATOMIC_SEQ_CST))
		sched_yield();
}
static bool cancel_work_sync(struct work_struct *w)
{
	bool was;
	might_sleep_check("cancel_work_sync");
	pthread_mutex_lock(&deferred_lock);
	was = w->pending;
	w->pending = 0;
	remove_item((void **)pending_work, w);
	pthread_mutex_unlock(&deferred_lock);
	wait_not_running(w);
	return was;
}
static bool cancel_delayed_work(struct delayed_work *d)
{
	bool was;
	pthread_mutex_lock(&deferred_lock);
	was = d->armed || d->work.pending;
	d->armed = 0;
	d->work.pending = 0;
	remove_item((void **)pending_dwork, d);
	remove_item((void **)pending_work, &d->work);
	pthread_mutex_unlock(&deferred_lock);
	return was;
}
static bool cancel_delayed_work_sync(struct delayed_work *d)
{
	bool was;
	might_sleep_check("cancel_delayed_work_sync");
	was = cancel_delayed_work(d);
	wait_not_running(&d->work);
	return was;
}
static void flush_work(struct work_struct *w) { wait_not_running(w); }
#define timer_setup(t, f, flags) do { (t)->function = (f); (t)->armed = 0; } while (0)
static int mod_timer(struct timer_list *t, unsigned long expires)
{
	int was;
	pthread_mutex_lock(&deferred_lock);
	H.timer_arms++;
	was = t->armed;
	t->armed = 1;
	t->expires = expires;
	add_unique((void **)pending_timer, t);
	pthread_mutex_unlock(&deferred_lock);
	return was;
}
#define add_timer(t) ((void)mod_timer(t, (t)->expires))
#define timer_delete harness_timer_delete
static int timer_delete(struct timer_list *t)
{
	int was;
	pthread_mutex_lock(&deferred_lock);
	was = t->armed;
	t->armed = 0;
	remove_item((void **)pending_timer, t);
	pthread_mutex_unlock(&deferred_lock);
	return was;
}
#define timer_delete_sync(t) timer_delete(t)
#define del_timer_sync(t) timer_delete(t)
#define del_timer(t) timer_delete(t)
#define timer_container_of(var, t, field) container_of(t, __typeof__(*var), field)
#define from_timer(var, t, field) container_of(t, __typeof__(*var), field)
#define hrtimer_setup(t, f, clock, mode) do { (t)->function = (f); (t)->armed = 0; } while (0)
static void hrtimer_start(struct hrtimer *t, ktime_t when, enum hrtimer_mode mode)
{
	(void)when; (void)mode;
	pthread_mutex_lock(&deferred_lock);
	H.hrtimer_starts++;
	t->armed = 1;
	add_unique((void **)pending_hrtimer, t);
	pthread_mutex_unlock(&deferred_lock);
}
static int hrtimer_cancel(struct hrtimer *t)
{
	int was;
	pthread_mutex_lock(&deferred_lock);
	was = t->armed;
	t->armed = 0;
	remove_item((void **)pending_hrtimer, t);
	pthread_mutex_unlock(&deferred_lock);
	return was;
}

/* Run what is due once; hrtimers fire regardless of time (microsecond scale),
 * jiffies timers and delayed work only once expired. */
static unsigned int run_deferred_once(void)
{
	unsigned int i, ran = 0;
	for (i = 0; i < MAX_DEFERRED; i++) {
		struct hrtimer *t = NULL;
		pthread_mutex_lock(&deferred_lock);
		if (pending_hrtimer[i] && pending_hrtimer[i]->armed) {
			t = pending_hrtimer[i];
			t->armed = 0;
			pending_hrtimer[i] = NULL;
		}
		pthread_mutex_unlock(&deferred_lock);
		if (t) {
			tls_atomic_depth++;
			t->function(t);
			tls_atomic_depth--;
			ran++;
		}
	}
	for (i = 0; i < MAX_DEFERRED; i++) {
		struct timer_list *t = NULL;
		pthread_mutex_lock(&deferred_lock);
		if (pending_timer[i] && pending_timer[i]->armed &&
		    time_after_eq(jiffies, pending_timer[i]->expires)) {
			t = pending_timer[i];
			t->armed = 0;
			pending_timer[i] = NULL;
		}
		pthread_mutex_unlock(&deferred_lock);
		if (t) {
			tls_atomic_depth++;
			t->function(t);
			tls_atomic_depth--;
			ran++;
		}
	}
	for (i = 0; i < MAX_DEFERRED; i++) {
		pthread_mutex_lock(&deferred_lock);
		if (pending_dwork[i] && pending_dwork[i]->armed &&
		    time_after_eq(jiffies, pending_dwork[i]->expires)) {
			pending_dwork[i]->armed = 0;
			pending_dwork[i]->work.pending = 1;
			add_unique((void **)pending_work, &pending_dwork[i]->work);
			pending_dwork[i] = NULL;
		}
		pthread_mutex_unlock(&deferred_lock);
	}
	for (i = 0; i < MAX_DEFERRED; i++) {
		struct work_struct *w = NULL;
		pthread_mutex_lock(&deferred_lock);
		if (pending_work[i] && pending_work[i]->pending) {
			w = pending_work[i];
			w->pending = 0;
			pending_work[i] = NULL;
			__atomic_add_fetch(&w->running, 1, __ATOMIC_SEQ_CST);
		}
		pthread_mutex_unlock(&deferred_lock);
		if (w) {
			w->func(w);
			__atomic_sub_fetch(&w->running, 1, __ATOMIC_SEQ_CST);
			ran++;
		}
	}
	return ran;
}
static void run_deferred(unsigned int rounds)
{
	while (rounds--)
		if (!run_deferred_once())
			break;
}

/* -------------------------------------------------- pages and devices */
struct page { unsigned int index; };
struct device { int id; };
struct inode { int minor; };
struct module { int refs; };
struct file_operations { int unused; };
struct file { struct inode *inode; void *private_data; };
static struct module harness_module;
#define THIS_MODULE (&harness_module)
#define __module_get(m) ((void)((m)->refs++))
#define module_put(m) ((void)((m)->refs--))
static struct page host_pages[MAX_PAGES];
static phys_addr_t page_to_phys(struct page *p)
{
	/* non-contiguous CPU physical addresses, distinct from any IOVA */
	return 0x40000000ULL + (u64)p->index * 3 * PAGE_SIZE;
}

/* ------------------------------------------------------- DMA mapping */
enum dma_data_direction { DMA_BIDIRECTIONAL = 0, DMA_TO_DEVICE = 1,
			  DMA_FROM_DEVICE = 2, DMA_NONE = 3 };
#define DMA_ATTR_SKIP_CPU_SYNC (1UL << 5)
#define DMA_MAPPING_ERROR (~(dma_addr_t)0)
struct scatterlist {
	struct page *page;
	unsigned int offset, length;
	dma_addr_t dma_address;
	unsigned int dma_length;
	int last;
};
struct sg_table { struct scatterlist *sgl; unsigned int nents, orig_nents; };
#define sg_dma_address(sg) ((sg)->dma_address)
#define sg_dma_len(sg) ((sg)->dma_length)
#define sg_page(sg) ((sg)->page)
static struct scatterlist *sg_next(struct scatterlist *sg) { return sg->last ? NULL : sg + 1; }
#define for_each_sg(sglist, sg, nr, i) \
	for ((i) = 0, (sg) = (sglist); (i) < (nr); (i)++, (sg) = sg_next(sg))
#define for_each_sgtable_sg(sgt, sg, i) for_each_sg((sgt)->sgl, sg, (sgt)->orig_nents, i)
#define for_each_sgtable_dma_sg(sgt, sg, i) for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)

static int sg_alloc_table_from_pages_segment(struct sg_table *sgt, struct page **pages,
	unsigned int n, unsigned int offset, unsigned long size,
	unsigned int max_segment, gfp_t gfp)
{
	unsigned int i;
	(void)max_segment;
	if (!n || offset || size != (unsigned long)n << PAGE_SHIFT)
		return -EINVAL;
	sgt->sgl = harness_alloc(sizeof(*sgt->sgl) * n, gfp);
	if (!sgt->sgl)
		return -ENOMEM;
	for (i = 0; i < n; i++) {
		sgt->sgl[i].page = pages[i];
		sgt->sgl[i].length = PAGE_SIZE;
		sgt->sgl[i].last = i + 1 == n;
	}
	sgt->nents = sgt->orig_nents = n;
	H.sg_alloc++;
	order("sg_alloc");
	return 0;
}
static int sg_alloc_table_from_pages(struct sg_table *sgt, struct page **pages,
	unsigned int n, unsigned int offset, unsigned long size, gfp_t gfp)
{
	return sg_alloc_table_from_pages_segment(sgt, pages, n, offset, size, ~0u, gfp);
}
static void sg_free_table(struct sg_table *sgt)
{
	if (!sgt->sgl)
		return;
	kfree(sgt->sgl);
	sgt->sgl = NULL;
	H.sg_free++;
	order("sg_free");
}
static int dma_map_sgtable(struct device *dev, struct sg_table *sgt,
			   enum dma_data_direction dir, unsigned long attrs)
{
	unsigned int i, n = sgt->orig_nents;
	(void)attrs;
	might_sleep_check("dma_map_sgtable");
	H.dma_map++;
	H.dma_dev = dev;
	if (dir != DMA_BIDIRECTIONAL)
		H.dma_bad_dir++;
	order("dma_map");
	if (H.dma_mode == 2)
		return -ENOMEM;
	/* IOVAs differ from the CPU physical addresses on purpose. */
	if (H.dma_mode == 1 && n >= 2) {
		sgt->sgl[0].dma_address = 0xA00000000ULL;
		sgt->sgl[0].dma_length = (n - 1) * PAGE_SIZE;
		sgt->sgl[1].dma_address = 0xB00000000ULL;
		sgt->sgl[1].dma_length = PAGE_SIZE;
		sgt->nents = 2;
		for (i = 0; i + 1 < n; i++)
			H.page_iova[i] = 0xA00000000ULL + (u64)i * PAGE_SIZE;
		H.page_iova[n - 1] = 0xB00000000ULL;
	} else {
		sgt->sgl[0].dma_address = 0xA00000000ULL;
		sgt->sgl[0].dma_length = n * PAGE_SIZE;
		sgt->nents = 1;
		for (i = 0; i < n; i++)
			H.page_iova[i] = 0xA00000000ULL + (u64)i * PAGE_SIZE;
	}
	return 0;
}
static void dma_unmap_sgtable(struct device *dev, struct sg_table *sgt,
			      enum dma_data_direction dir, unsigned long attrs)
{
	(void)dev; (void)sgt; (void)attrs;
	H.dma_unmap++;
	if (dir != DMA_BIDIRECTIONAL)
		H.dma_bad_dir++;
	order("dma_unmap");
}
static void mark_sync(unsigned char *map, dma_addr_t addr, size_t len)
{
	unsigned int i;
	for (i = 0; i < MAX_PAGES; i++)
		if (H.page_iova[i] && addr < H.page_iova[i] + PAGE_SIZE &&
		    H.page_iova[i] < addr + len)
			map[i] = 1;
}
static void dma_sync_single_for_cpu(struct device *d, dma_addr_t a, size_t l,
				    enum dma_data_direction dir)
{ (void)d; (void)dir; mark_sync(H.synced_cpu, a, l); }
static void dma_sync_single_for_device(struct device *d, dma_addr_t a, size_t l,
				       enum dma_data_direction dir)
{ (void)d; (void)dir; mark_sync(H.synced_dev, a, l); }
static void dma_sync_single_range_for_cpu(struct device *d, dma_addr_t a,
	unsigned long off, size_t l, enum dma_data_direction dir)
{ dma_sync_single_for_cpu(d, a + off, l, dir); }
static void dma_sync_single_range_for_device(struct device *d, dma_addr_t a,
	unsigned long off, size_t l, enum dma_data_direction dir)
{ dma_sync_single_for_device(d, a + off, l, dir); }
static void dma_sync_sgtable_for_cpu(struct device *d, struct sg_table *s,
				     enum dma_data_direction dir)
{ (void)d; (void)s; (void)dir; memset(H.synced_cpu, 1, sizeof(H.synced_cpu)); }
static void dma_sync_sgtable_for_device(struct device *d, struct sg_table *s,
					enum dma_data_direction dir)
{ (void)d; (void)s; (void)dir; memset(H.synced_dev, 1, sizeof(H.synced_dev)); }
#define dma_sync_sg_for_cpu(d, sgl, n, dir) dma_sync_sgtable_for_cpu(d, NULL, dir)
#define dma_sync_sg_for_device(d, sgl, n, dir) dma_sync_sgtable_for_device(d, NULL, dir)

/* ------------------------------------------------ NVIDIA kernel-open */
typedef struct { int unused; } nvidia_stack_t;
typedef struct { int unused; } nv_state_t;
typedef struct { struct device *dev; nv_state_t nv_state; } nv_linux_state_t;
typedef struct { int open_rc; nv_linux_state_t *nvptr; } nv_linux_file_private_t;
#define NV_GET_LINUX_FILE_PRIVATE(f) ((nv_linux_file_private_t *)(f)->private_data)
#define NV_FILE_INODE(f) ((f)->inode)
#define NV_STATE_PTR(nvl) (&(nvl)->nv_state)
#define NV_DBG_ERRORS 4
#define NV_DBG_WARNINGS 3
#define NV_DBG_INFO 1
#define nv_printf(...) ((void)0)
static int NVreg_EnableXdevExtCeDma = 1;
static int nv_is_control_device(struct inode *i) { return i->minor == 255; }
static int nv_wait_open_complete_interruptible(nv_linux_file_private_t *p) { (void)p; return 0; }
static nvidia_stack_t harness_stack;
static int nv_kmem_cache_alloc_stack(nvidia_stack_t **sp) { *sp = &harness_stack; return 0; }
static void nv_kmem_cache_free_stack(nvidia_stack_t *sp) { (void)sp; }
static const NvU8 harness_uuid[16] = { 0x47, 0x50, 0x55 };
static const NvU8 *rm_get_gpu_uuid_raw(nvidia_stack_t *sp, nv_state_t *nv)
{ (void)sp; (void)nv; return harness_uuid; }

typedef struct nv_p2p_umem_xfer { NvU64 umemOffset, gpuOffset, size; } nv_p2p_umem_xfer_t;
typedef struct nv_p2p_vidmem_binding { int live; } nv_p2p_vidmem_binding_t;
typedef struct nv_p2p_ce_host { int unused; } nv_p2p_ce_host_t;
static nv_p2p_ce_host_t harness_rm_host;

static NV_STATUS nv_p2p_vidmem_bind(const NvU8 *uuid, NvU64 va, NvU64 len,
	nv_p2p_vidmem_binding_t **out, NvU32 *seg, nv_p2p_vidmem_binding_t **residual)
{
	(void)uuid; (void)va; (void)len;
	*residual = NULL;
	might_sleep_check("nv_p2p_vidmem_bind");
	*out = calloc(1, sizeof(**out));
	(*out)->live = 1;
	if (seg)
		*seg = 0;
	H.vidmem_bind++;
	H.vidmem_live++;
	order("vidmem_bind");
	return NV_OK;
}
#if HARNESS_UNBIND_STATUS
static NV_STATUS nv_p2p_vidmem_unbind(nv_p2p_vidmem_binding_t *b)
#else
static void nv_p2p_vidmem_unbind(nv_p2p_vidmem_binding_t *b)
#endif
{
	might_sleep_check("nv_p2p_vidmem_unbind");
	H.vidmem_unbind++;
	order("vidmem_unbind");
#if HARNESS_UNBIND_STATUS
	if (H.vidmem_unbind_status != NV_OK)
		return H.vidmem_unbind_status;
#endif
	b->live = 0;
	free(b);
	H.vidmem_live--;
#if HARNESS_UNBIND_STATUS
	return NV_OK;
#endif
}
static NvBool nv_p2p_umem_iommu_untranslated(struct device *dev)
{
	(void)dev;
	return !H.translated;
}
static int nv_p2p_umem_errno(NV_STATUS s)
{
	switch (s) {
	case NV_OK: return 0;
	case NV_ERR_NO_MEMORY: return -ENOMEM;
	case NV_ERR_INVALID_ARGUMENT: return -EINVAL;
	case NV_ERR_NOT_SUPPORTED: return -EOPNOTSUPP;
	case NV_ERR_BUSY_RETRY: return -EAGAIN;
	}
	return -EIO;
}

#if HARNESS_EVENT_API
typedef void (*nv_p2p_ce_event_fn)(void *arg, NvU64 watermark);
static NV_STATUS nv_p2p_ce_host_bind(nv_p2p_vidmem_binding_t *b, NvU64 *addrs,
	NvU32 count, NvU32 page_size, NvU64 bytes, nv_p2p_ce_event_fn event,
	void *event_arg, nv_p2p_ce_host_t **out)
#else
static NV_STATUS nv_p2p_ce_host_bind(nv_p2p_vidmem_binding_t *b, NvU64 *addrs,
	NvU32 count, NvU32 page_size, NvU64 bytes, nv_p2p_ce_host_t **out)
#endif
{
	NvU32 i;
	(void)b;
	might_sleep_check("nv_p2p_ce_host_bind");
	H.rm_bind++;
	order("rm_bind");
	for (i = 0; i < count && i < MAX_PAGES; i++)
		H.bound_addrs[i] = addrs[i];
	H.bound_count = count;
	H.bound_page_size = page_size;
	H.bound_bytes = bytes;
	if (H.rm_bind_status != NV_OK)
		return H.rm_bind_status;
#if HARNESS_EVENT_API
	H.event_fn = event;
	H.event_arg = event_arg;
#endif
	*out = &harness_rm_host;
	return NV_OK;
}

/* Any context: models the CE non-stall/semaphore event reaching the backend. */
static int fire_event(NvU64 watermark)
{
	void (*fn)(void *, NvU64);
	void *arg;
	pthread_mutex_lock(&H.big);
	fn = H.event_fn;
	arg = H.event_arg;
	pthread_mutex_unlock(&H.big);
	if (!fn)
		return -1;
	tls_atomic_depth++;
	__atomic_add_fetch(&H.events_fired, 1, __ATOMIC_SEQ_CST);
	fn(arg, watermark);
	tls_atomic_depth--;
	return 0;
}

static NV_STATUS nv_p2p_ce_host_unbind(nv_p2p_ce_host_t *h)
{
	(void)h;
	might_sleep_check("nv_p2p_ce_host_unbind");
	H.rm_unbind++;
	order("rm_unbind");
	/* RM's CeUtils destructor processes remaining callbacks before freeing. */
	if (H.fire_in_unbind)
		fire_event(H.rm_completed);
	if (H.rm_unbind_status != NV_OK)
		return H.rm_unbind_status;
	pthread_mutex_lock(&H.big);
	H.event_fn = NULL;
	pthread_mutex_unlock(&H.big);
	return NV_OK;
}

static NV_STATUS nv_p2p_ce_async_submit(nv_p2p_ce_host_t *h,
	const struct nv_p2p_umem_xfer *x, NvU32 n, NvU32 dir, NvBool *issued,
	NvU64 *token)
{
	NvU32 i;
	u64 t;
	(void)h;
	might_sleep_check("nv_p2p_ce_async_submit");
	*issued = NV_FALSE;
	*token = 0;
	pthread_mutex_lock(&H.big);
	H.rm_submit++;
	H.last_n = n;
	H.last_dir = dir;
	/* RM direction 1: host pages are read by the CE. */
	if (dir == 1)
		for (i = 0; i < n; i++) {
			u64 p;
			for (p = x[i].umemOffset >> PAGE_SHIFT;
			     p <= (x[i].umemOffset + x[i].size - 1) >> PAGE_SHIFT &&
			     p < MAX_PAGES; p++)
				if (!H.synced_dev[p])
					H.submit_saw_dev_sync_gap = 1;
		}
	if (H.submit_status != NV_OK) {
		*issued = H.submit_issued ? NV_TRUE : NV_FALSE;
		pthread_mutex_unlock(&H.big);
		return H.submit_status;
	}
	*issued = NV_TRUE;
	H.rm_last += n;
	t = H.rm_last;
	if (H.fire_in_submit)
		H.rm_completed = t;
	pthread_mutex_unlock(&H.big);
	/* The CE may finish and raise its event before this call returns. */
	if (H.fire_in_submit)
		fire_event(t);
	*token = H.submit_zero_token ? 0 : t;
	return NV_OK;
}
static NV_STATUS nv_p2p_ce_progress(nv_p2p_ce_host_t *h, NvU64 *watermark)
{
	(void)h;
	might_sleep_check("nv_p2p_ce_progress");
	pthread_mutex_lock(&H.big);
	H.rm_progress++;
	*watermark = H.rm_completed;
	pthread_mutex_unlock(&H.big);
	return H.rm_progress_status;
}

/* ------------------------------------------------- xdev_ext core side */
struct xdev_ext_ce_cookie { int index; };
#include "nv_xdev_ext_ce_backend_types.h"   /* actual structs, generated */
/* Core boundary only: actual frame claim validation belongs to the core
 * suite. The backend under test must preserve each submitted snapshot and
 * revalidate it both before RM submission and before terminal publication. */
static bool xdev_ext_ce_owners_valid(struct xdev_ext_ce_cookie *ck, u64 ticket,
	const struct xdev_ext_ce_xfer *x, u32 n)
{
	u32 i;
	bool valid = true;
	pthread_mutex_lock(&H.big);
	H.owner_validations++;
	if (!ck || ticket >= MAX_TICKETS || H.expected_ticket[ticket] != ticket ||
	    ck->index != (int)ticket)
		valid = false;
#if HARNESS_OWNER_API
	for (i = 0; valid && i < n; i++) {
		u64 page = x[i].host_byte_off >> PAGE_SHIFT;
		if (page >= MAX_PAGES || x[i].owner != H.frame_owner[page] ||
		    x[i].generation != H.frame_generation[page])
			valid = false;
	}
#else
	(void)i; (void)x; (void)n;
	valid = false;
#endif
	if (!valid) H.owner_rejections++;
	pthread_mutex_unlock(&H.big);
	return valid;
}
static const struct xdev_ext_ce_backend_ops *registered_ops;
static int xdev_ext_ce_backend_register(const struct xdev_ext_ce_backend_ops *ops)
{ registered_ops = ops; return 0; }
static void xdev_ext_ce_backend_unregister(const struct xdev_ext_ce_backend_ops *ops)
{ (void)ops; registered_ops = NULL; }
static void xdev_ext_ce_complete(struct xdev_ext_ce_cookie *ck, u64 ticket, int status,
				 bool hw_submitted, u64 bytes_done)
{
	struct harness_completion *c;
	pthread_mutex_lock(&H.big);
	if (!ck || ticket >= MAX_TICKETS || H.expected_ticket[ticket] != ticket ||
	    ck->index != (int)ticket) {
		H.bad_ticket++;
		pthread_mutex_unlock(&H.big);
		return;
	}
	c = &H.done[ticket];
	c->count++;
	c->status = status;
	c->hw = hw_submitted;
	c->bytes = bytes_done;
	c->cookie = ck;
	memcpy(c->synced_cpu, H.synced_cpu, sizeof(c->synced_cpu));
	__atomic_add_fetch(&H.total_completions, 1, __ATOMIC_SEQ_CST);
	pthread_mutex_unlock(&H.big);
}

/* ------------------------------------------- the actual production body */
#include "nv-xdev_ext-ce-backend-actual.c"

/* ================================================================ cases */
static struct inode gpu_inode = { 0 };
static nv_linux_state_t gpu_nvl;
static struct device gpu_dev = { 7 };
static nv_linux_file_private_t gpu_fpriv;
static struct file gpu_file;
static struct file_operations harness_fops;
static const struct xdev_ext_ce_backend_ops *ops;
static struct page *page_ptrs[MAX_PAGES];
static struct xdev_ext_ce_cookie cookies[MAX_TICKETS];

struct fixture { struct xdev_ext_ce_region r; void *host; };

static void harness_init(void)
{
	unsigned int i;
	for (i = 0; i < MAX_PAGES; i++) {
		host_pages[i].index = i;
		page_ptrs[i] = &host_pages[i];
		H.frame_owner[i] = 1;
		H.frame_generation[i] = i + 17;
	}
	for (i = 0; i < MAX_TICKETS; i++)
		cookies[i].index = (int)i;
	gpu_nvl.dev = &gpu_dev;
	gpu_fpriv.nvptr = &gpu_nvl;
	gpu_file.inode = &gpu_inode;
	gpu_file.private_data = &gpu_fpriv;
	nv_xdev_ext_ce_backend_init(&harness_fops);
	ops = registered_ops;
	H.translated = VARIANT_IOVA;    /* IOVA variants must work behind a translating IOMMU */
}

static int bind(struct fixture *fx, u32 nr)
{
	int rc;
	memset(fx, 0, sizeof(*fx));
	fx->r.ops = ops;
	rc = ops->bind_region(&gpu_file, 0x7f0000000000ULL, 1ULL << 24, &fx->r);
	if (rc) {
		printf("note: bind_region rc=%d\n", rc);
		return rc;
	}
	rc = ops->bind_host(&fx->r, page_ptrs, nr, &fx->host);
	if (rc)
		printf("note: bind_host rc=%d with %s IOMMU domain%s\n", rc,
		       H.translated ? "a translating" : "an identity",
		       VARIANT_IOVA && H.translated ?
		       " (G2: IOVA build must map through the DMA API, not refuse)" : "");
	return rc;
}

static int submit1(struct fixture *fx, u64 ticket, u32 dir, u64 host_off, u32 len)
{
	struct xdev_ext_ce_xfer x = { .host_byte_off = host_off, .gpu_off = 0,
				      .len = len, .flags = 0 };
#if HARNESS_OWNER_API
	x.owner = H.frame_owner[host_off >> PAGE_SHIFT];
	x.generation = H.frame_generation[host_off >> PAGE_SHIFT];
#endif
	H.expected_ticket[ticket] = ticket;
	return ops->submit(&fx->r, fx->host, dir, &x, 1, &cookies[ticket], ticket);
}

/* Make every token up to wm complete, by event or by the poller. */
static void deliver(u64 wm)
{
	pthread_mutex_lock(&H.big);
	H.rm_completed = wm;
	pthread_mutex_unlock(&H.big);
#if VARIANT_EVENT
	fire_event(wm);
	run_deferred(4);
#else
	run_deferred(16);
#endif
}

static void common_checks(void)
{
	CHECK(H.sleep_in_atomic == 0, "a sleeping call ran in event/atomic context (%u)",
	      H.sleep_in_atomic);
	CHECK(H.bad_ticket == 0, "completion carried an unexpected cookie/ticket (%u)",
	      H.bad_ticket);
}

static unsigned int nv_live_before;

static void require_event_registered(void)
{
#if VARIANT_EVENT
	CHECK(H.event_fn != NULL,
	      "G1: bind_host registered no CE completion event with nv_p2p_ce_host_bind "
	      "(event API %s)", HARNESS_EVENT_API ? "declared" : "not declared in nv-p2p.h");
#endif
}

static void case_bind_unbind_clean(void)
{
	struct fixture fx;
	unsigned int before = H.live_count;
	int rc = bind(&fx, 4);
	REQUIRE(rc == 0, "bind returned %d (translated IOMMU=%d)", rc, H.translated);
	require_event_registered();
	CHECK(H.rm_bind == 1 && H.vidmem_bind == 1, "rm_bind=%u vidmem_bind=%u",
	      H.rm_bind, H.vidmem_bind);
#if VARIANT_EVENT
	CHECK(H.hrtimer_starts == 0, "G1: hrtimer armed at bind in event build");
#endif
	ops->unbind_host(fx.host);
	ops->unbind_region(&fx.r);
	CHECK(H.rm_unbind == 1 && H.vidmem_unbind == 1 && H.vidmem_live == 0,
	      "rm_unbind=%u vidmem_unbind=%u live=%u", H.rm_unbind, H.vidmem_unbind,
	      H.vidmem_live);
	CHECK(H.live_count == before, "allocations leaked: %u live after teardown, %u before",
	      H.live_count, before);
#if VARIANT_IOVA
	CHECK(H.dma_map == 1 && H.dma_unmap == 1 && H.sg_alloc == 1 && H.sg_free == 1,
	      "G2: DMA map/unmap/sg alloc/free = %u/%u/%u/%u, expected 1/1/1/1",
	      H.dma_map, H.dma_unmap, H.sg_alloc, H.sg_free);
#else
	CHECK(H.dma_map == 0 && H.sg_alloc == 0, "PHYS build used the DMA API");
#endif
	common_checks();
}

static void case_complete_once(void)
{
	struct fixture fx;
	unsigned int progress_before;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	require_event_registered();
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "submit");
	CHECK(H.done[1].count == 0, "completed before the copy engine finished");
	progress_before = H.rm_progress;
	(void)progress_before;
#if VARIANT_EVENT
	run_deferred(8);    /* nothing due: no poller may run */
	CHECK(H.rm_progress == progress_before,
	      "G1: RM progress polled %u times without an event",
	      H.rm_progress - progress_before);
	CHECK(H.hrtimer_starts == 0, "G1: hrtimer poll armed %u times in event build",
	      H.hrtimer_starts);
	CHECK(H.done[1].count == 0, "completed without an event");
#endif
	deliver(H.rm_last);
	CHECK(H.done[1].count == 1, "completion count %u, expected exactly 1", H.done[1].count);
	CHECK(H.done[1].status == 0 && H.done[1].hw == 1 && H.done[1].bytes == 4096,
	      "status=%d hw=%d bytes=%llu", H.done[1].status, H.done[1].hw,
	      (unsigned long long)H.done[1].bytes);
	deliver(H.rm_last);    /* duplicate event / repeated progress */
	CHECK(H.done[1].count == 1, "duplicate delivery completed again (%u)", H.done[1].count);
#if VARIANT_EVENT && HARNESS_EVENT_API
	if (H.event_fn)
		CHECK(((struct nv_xdev_ext_ce_host *)fx.host)->stats.late >= 1,
		      "G3: duplicate event not counted as late");
#endif
	ops->unbind_host(fx.host);
	ops->unbind_region(&fx.r);
	CHECK(H.rm_unbind == 1, "drained host not unbound");
	common_checks();
}

static void case_complete_partial(void)
{
	struct fixture fx;
	u64 t;
	REQUIRE(bind(&fx, 8) == 0, "bind");
	require_event_registered();
	for (t = 1; t <= 3; t++)
		REQUIRE(submit1(&fx, t, XDEV_EXT_MECH_DIR_FROM_DEVICE, (t - 1) * 4096, 4096) == 0,
			"submit %llu", (unsigned long long)t);
	deliver(H.rm_last - 1);
	CHECK(H.done[1].count == 1 && H.done[2].count == 1 && H.done[3].count == 0,
	      "partial watermark retired %u/%u/%u", H.done[1].count, H.done[2].count,
	      H.done[3].count);
	deliver(H.rm_last);
	CHECK(H.done[3].count == 1, "final watermark did not retire the last ticket");
	CHECK(H.total_completions == 3, "total %u", H.total_completions);
	ops->unbind_host(fx.host);
	ops->unbind_region(&fx.r);
	common_checks();
}

static void case_complete_in_submit(void)
{
#if VARIANT_EVENT
	struct fixture fx;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	require_event_registered();
	H.fire_in_submit = 1;
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "submit");
	H.fire_in_submit = 0;
	run_deferred(4);
	CHECK(H.done[1].count == 1,
	      "G1: event raised before submit returned its token was lost (count=%u); "
	      "the backend must remember the highest watermark", H.done[1].count);
	fire_event(H.rm_last);
	CHECK(H.done[1].count <= 1, "completed twice");
	if (H.done[1].count == 1) {
		ops->unbind_host(fx.host);
		ops->unbind_region(&fx.r);
	}
	common_checks();
#endif
}

static void case_event_regress(void)
{
#if VARIANT_EVENT
	struct fixture fx;
	struct nv_xdev_ext_ce_host *h;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	require_event_registered();
	REQUIRE(H.event_fn, "no event");
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "submit1");
	REQUIRE(submit1(&fx, 2, XDEV_EXT_MECH_DIR_TO_DEVICE, 4096, 4096) == 0, "submit2");
	deliver(2);
	h = fx.host;
#if HARNESS_EVENT_API
	{
		u64 late = h->stats.late;
		fire_event(1);   /* regressed watermark: retires nothing */
		CHECK(h->stats.late == late + 1, "G3: regressed event not counted late");
		fire_event(2);   /* duplicate */
		CHECK(h->stats.late == late + 2, "G3: duplicate event not counted late");
	}
#endif
	(void)h;
	CHECK(H.done[1].count == 1 && H.done[2].count == 1, "%u/%u", H.done[1].count,
	      H.done[2].count);
	ops->unbind_host(fx.host);
	ops->unbind_region(&fx.r);
	common_checks();
#endif
}

static void case_event_impossible(void)
{
#if VARIANT_EVENT
	struct fixture fx;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	require_event_registered();
	REQUIRE(H.event_fn, "no event");
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "submit");
	fire_event(H.rm_last + 5);   /* beyond anything submitted on this host */
	run_deferred(4);
	CHECK(H.done[1].count == 1 && H.done[1].status < 0 && H.done[1].hw == 1 &&
	      H.done[1].bytes == 0,
	      "G3: impossible watermark must quarantine pending work as AMBIGUOUS "
	      "(count=%u status=%d hw=%d)", H.done[1].count, H.done[1].status, H.done[1].hw);
#if HARNESS_EVENT_API
	CHECK(((struct nv_xdev_ext_ce_host *)fx.host)->stats.stale == 1,
	      "G3: impossible watermark not counted stale");
#endif
	CHECK(READ_ONCE(((struct nv_xdev_ext_ce_region *)fx.r.priv)->ambiguous),
	      "window not marked ambiguous");
	{
		unsigned int submits = H.rm_submit;
		CHECK(submit1(&fx, 2, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) < 0,
		      "submit accepted on a quarantined host");
		CHECK(H.rm_submit == submits, "quarantined host reached RM");
	}
	common_checks();
#endif
}

static void case_ambiguous_submit(void)
{
	struct fixture fx;
	unsigned int unbinds;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	H.submit_status = NV_ERR_INVALID_STATE;
	H.submit_issued = 1;
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0,
		"an issued failure is accepted and completed");
	CHECK(H.done[1].count == 1 && H.done[1].status < 0 && H.done[1].hw == 1,
	      "AMBIGUOUS completion count=%u status=%d hw=%d", H.done[1].count,
	      H.done[1].status, H.done[1].hw);
	H.submit_status = NV_OK;
	deliver(H.rm_last + 1);
	CHECK(H.done[1].count == 1, "AMBIGUOUS ticket completed again (%u)", H.done[1].count);
	unbinds = H.rm_unbind;
	ops->unbind_host(fx.host);
	CHECK(H.rm_unbind == unbinds, "host unbound after AMBIGUOUS");
	CHECK(H.dma_unmap == 0, "IOVA unmapped after AMBIGUOUS");
	ops->unbind_region(&fx.r);
	CHECK(H.vidmem_unbind == 0, "window unbound after AMBIGUOUS");
	common_checks();
}

static void case_pre_submit_failure(void)
{
	struct fixture fx;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	H.submit_status = NV_ERR_NO_MEMORY;
	H.submit_issued = 0;
	memset(H.synced_cpu, 0, sizeof(H.synced_cpu));
	CHECK(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) < 0,
	      "pre-submit failure must return an error");
	CHECK(H.done[1].count == 0, "pre-submit failure completed");
#if VARIANT_IOVA
	CHECK(H.synced_cpu[0], "pre-submit refusal did not return streaming ownership to CPU");
#endif
	H.submit_status = NV_OK;
	REQUIRE(submit1(&fx, 2, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "retry submit");
	deliver(H.rm_last);
	CHECK(H.done[2].count == 1 && H.done[1].count == 0, "%u/%u", H.done[1].count,
	      H.done[2].count);
	ops->unbind_host(fx.host);
	ops->unbind_region(&fx.r);
	CHECK(H.rm_unbind == 1, "drained after pre-submit failure must unbind");
	common_checks();
}

static void case_token_zero(void)
{
	struct fixture fx;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	H.submit_zero_token = 1;
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "submit");
	CHECK(H.done[1].count == 1 && H.done[1].status < 0 && H.done[1].hw == 1,
	      "success without token must be AMBIGUOUS once (count=%u)", H.done[1].count);
	H.submit_zero_token = 0;
	deliver(H.rm_last);
	CHECK(H.done[1].count == 1, "completed again");
	common_checks();
}

static void case_timeout(void)
{
	struct fixture fx;
	unsigned int progress_before;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "submit");
	progress_before = H.rm_progress;
	(void)progress_before;
	run_deferred(8);
#if VARIANT_EVENT
	CHECK(H.rm_progress == progress_before,
	      "G1: event build polled RM progress %u times before the deadline",
	      H.rm_progress - progress_before);
#endif
	CHECK(H.done[1].count == 0, "completed before deadline without hardware progress");
	jiffies += 31 * HZ;
	run_deferred(16);
	CHECK(H.done[1].count == 1 && H.done[1].status < 0 && H.done[1].hw == 1,
	      "deadline must complete the ticket once as AMBIGUOUS (count=%u status=%d)",
	      H.done[1].count, H.done[1].status);
	deliver(H.rm_last);
	CHECK(H.done[1].count == 1, "completed again after deadline");
	CHECK(READ_ONCE(((struct nv_xdev_ext_ce_region *)fx.r.priv)->ambiguous),
	      "deadline did not park the window");
	common_checks();
}

static void case_owner_mismatch(void)
{
	struct fixture a, b;
	struct xdev_ext_ce_xfer x = { .host_byte_off = 0, .gpu_off = 0, .len = 4096 };
	unsigned int submits;
	int rc;
	REQUIRE(bind(&a, 4) == 0, "bind a");
	REQUIRE(bind(&b, 4) == 0, "bind b");
	submits = H.rm_submit;
	H.expected_ticket[1] = 1;
	rc = ops->submit(&b.r, a.host, XDEV_EXT_MECH_DIR_TO_DEVICE, &x, 1, &cookies[1], 1);
	CHECK(rc == -EINVAL, "G3: host bound to another window accepted (rc=%d)", rc);
	CHECK(H.rm_submit == submits, "G3: owner mismatch reached RM submission");
	CHECK(H.done[1].count == 0, "owner mismatch completed");
	rc = ops->submit(&a.r, a.host, XDEV_EXT_MECH_DIR_TO_DEVICE, &x, 1, NULL, 2);
	CHECK(rc == -EINVAL, "G3: submit without an owner cookie accepted (rc=%d)", rc);
	CHECK(H.rm_submit == submits, "G3: cookie-less submit reached RM");
	common_checks();
}

static void case_owner_busy(void)
{
	struct fixture fx;
	struct xdev_ext_ce_xfer x = { .host_byte_off = 0, .gpu_off = 0, .len = 4096 };
	unsigned int submits;
	int rc;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "submit");
	submits = H.rm_submit;
	/* Same callback cookie, different ticket, while the first is in flight.
	 * This is callback-storage exclusion, not a frame-generation test. */
	H.expected_ticket[2] = 2;
	rc = ops->submit(&fx.r, fx.host, XDEV_EXT_MECH_DIR_TO_DEVICE, &x, 1, &cookies[1], 2);
	CHECK(rc == -EBUSY, "in-flight callback cookie reused by another ticket (rc=%d)", rc);
	CHECK(H.rm_submit == submits, "callback cookie conflict reached RM");
	deliver(H.rm_last);
	CHECK(H.done[1].count == 1, "first ticket completion %u", H.done[1].count);
	common_checks();
}

static void case_frame_tokens(const char *which)
{
#if HARNESS_OWNER_API
	struct fixture fx;
	struct xdev_ext_ce_xfer x[2] = {
		{ .host_byte_off = 0, .gpu_off = 0, .len = 4096, .owner = 1, .generation = 17 },
		{ .host_byte_off = 4096, .gpu_off = 4096, .len = 4096, .owner = 1, .generation = 18 }
	};
	unsigned int before;
	int rc;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	H.expected_ticket[1] = 1;
	if (!strcmp(which, "frame-owner-reject")) x[1].owner = 2;
	if (!strcmp(which, "frame-generation-reject")) x[1].generation = 16;
	rc = ops->submit(&fx.r, fx.host, XDEV_EXT_MECH_DIR_TO_DEVICE, x, 2, &cookies[1], 1);
	if (strstr(which, "reject")) {
		CHECK(rc < 0 && H.rm_submit == 0 && H.done[1].count == 0,
		      "G3: invalid second frame reached RM: rc=%d submits=%u", rc, H.rm_submit);
		CHECK(H.owner_validations > 0 && H.owner_rejections > 0,
		      "G3: per-frame core validation was not called");
		return;
	}
	REQUIRE(rc == 0, "valid two-frame submit rc=%d", rc);
	before = H.owner_validations;
	/* Submit inputs are caller-owned scratch; callback must use its own copy. */
	x[0].owner = 99; x[1].generation = 99;
	if (!strcmp(which, "frame-generation-late")) H.frame_generation[1]++;
	deliver(H.rm_last);
	CHECK(H.owner_validations > before, "G3: completion did not revalidate saved frame snapshots");
	if (!strcmp(which, "frame-generation-late")) {
		CHECK(H.owner_rejections > 0 && H.done[1].count == 0,
		      "G3: stale second-frame generation published completion");
	} else {
		CHECK(H.done[1].count == 1, "G3: scratch mutation corrupted saved snapshots");
		deliver(H.rm_last);
		CHECK(H.done[1].count == 1, "G3: duplicate ticket published twice");
		ops->unbind_host(fx.host);
		CHECK(H.event_fn == NULL, "G3: event producer still registered after successful unbind");
		CHECK(fire_event(H.rm_last) == -1 && H.done[1].count == 1,
		      "G3: event after unbind reached released callback storage");
		ops->unbind_region(&fx.r);
	}
	common_checks();
#else
	(void)which;
	CHECK(0, "ABSENCE (not semantic RED): xdev_ext_ce_xfer lacks per-frame owner/generation");
#endif
}
static void case_frame_owner_reject(void) { case_frame_tokens("frame-owner-reject"); }
static void case_frame_generation_reject(void) { case_frame_tokens("frame-generation-reject"); }
static void case_frame_generation_late(void) { case_frame_tokens("frame-generation-late"); }
static void case_frame_ticket_duplicate(void) { case_frame_tokens("frame-ticket-duplicate"); }

static void case_unbind_pending(void)
{
	struct fixture fx;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 4096) == 0, "submit");
	ops->unbind_host(fx.host);
	CHECK(H.rm_unbind == 0, "host with in-flight work unbound in RM");
	CHECK(H.dma_unmap == 0 && H.sg_free == 0,
	      "G2: host pages unmapped while a GPU reference is in flight");
	CHECK(harness_is_live(fx.host), "host state freed with in-flight work");
	CHECK(READ_ONCE(((struct nv_xdev_ext_ce_region *)fx.r.priv)->ambiguous),
	      "window not parked after refused unbind");
	common_checks();
}

static void case_unbind_order(void)
{
	struct fixture fx;
	const char *rm, *unmap, *free_;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_FROM_DEVICE, 0, 4096) == 0, "submit");
	deliver(H.rm_last);
	REQUIRE(H.done[1].count == 1, "completion before unbind");
	H.order[0] = 0;
	H.fire_in_unbind = 1;   /* RM destructor processes leftover callbacks */
	ops->unbind_host(fx.host);
	CHECK(H.done[1].count == 1, "teardown callback completed again");
	CHECK(H.rm_unbind == 1, "drained host not unbound");
	rm = strstr(H.order, "rm_unbind");
	unmap = strstr(H.order, "dma_unmap");
	free_ = strstr(H.order, "sg_free");
	(void)free_;
#if VARIANT_IOVA
	CHECK(rm && unmap && free_ && rm < unmap && unmap < free_,
	      "G2: order must be rm_unbind < dma_unmap < sg_free, got '%s'", H.order);
#else
	CHECK(rm && !unmap, "PHYS order '%s'", H.order);
#endif
	ops->unbind_region(&fx.r);
	common_checks();
}

static void case_unbind_rm_fail(void)
{
	struct fixture fx;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	H.rm_unbind_status = NV_ERR_BUSY_RETRY;
	ops->unbind_host(fx.host);
	CHECK(H.rm_unbind == 1, "rm unbind not attempted");
	CHECK(H.dma_unmap == 0 && H.sg_free == 0,
	      "G2: pages unmapped although RM still holds the host descriptor");
	CHECK(harness_is_live(fx.host), "host freed after failed RM unbind");
	CHECK(READ_ONCE(((struct nv_xdev_ext_ce_region *)fx.r.priv)->ambiguous),
	      "window not parked after failed RM unbind");
	common_checks();
}

static void case_iova_bind(void)
{
#if VARIANT_IOVA
	struct fixture fx;
	u32 i;
	int rc;
	H.translated = 1;
	H.dma_mode = 0;
	rc = bind(&fx, 4);
	REQUIRE(rc == 0, "G2: bind_host refused behind a translating IOMMU (rc=%d)", rc);
	CHECK(H.dma_map == 1, "G2: dma_map_sgtable calls %u, expected 1", H.dma_map);
	CHECK(H.dma_dev == &gpu_dev, "G2: mapped for the wrong struct device");
	CHECK(H.dma_bad_dir == 0, "G2: mapping direction must be DMA_BIDIRECTIONAL");
	CHECK(H.bound_count == 4 && H.bound_page_size == PAGE_SIZE &&
	      H.bound_bytes == 4 * PAGE_SIZE, "count=%u page=%u bytes=%llu",
	      H.bound_count, H.bound_page_size, (unsigned long long)H.bound_bytes);
	for (i = 0; i < 4 && i < H.bound_count; i++) {
		CHECK(H.bound_addrs[i] == 0xA00000000ULL + (u64)i * PAGE_SIZE,
		      "G2: page %u passed 0x%llx to the CE, expected IOVA 0x%llx (phys 0x%llx)",
		      i, (unsigned long long)H.bound_addrs[i],
		      (unsigned long long)(0xA00000000ULL + (u64)i * PAGE_SIZE),
		      (unsigned long long)page_to_phys(&host_pages[i]));
	}
	common_checks();
#endif
}

static void case_iova_segments(void)
{
#if VARIANT_IOVA
	struct fixture fx;
	H.dma_mode = 1;
	REQUIRE(bind(&fx, 4) == 0, "bind");
	CHECK(H.bound_count == 4, "count %u", H.bound_count);
	CHECK(H.bound_addrs[0] == 0xA00000000ULL && H.bound_addrs[1] == 0xA00001000ULL &&
	      H.bound_addrs[2] == 0xA00002000ULL && H.bound_addrs[3] == 0xB00000000ULL,
	      "G2: per-page IOVAs from two DMA segments wrong: %llx %llx %llx %llx",
	      (unsigned long long)H.bound_addrs[0], (unsigned long long)H.bound_addrs[1],
	      (unsigned long long)H.bound_addrs[2], (unsigned long long)H.bound_addrs[3]);
	common_checks();
#endif
}

static void case_iova_map_fail(void)
{
#if VARIANT_IOVA
	struct fixture fx;
	unsigned int live;
	int rc;
	memset(&fx, 0, sizeof(fx));
	fx.r.ops = ops;
	REQUIRE(ops->bind_region(&gpu_file, 0x7f0000000000ULL, 1ULL << 24, &fx.r) == 0,
		"bind_region");
	live = H.live_count;
	H.dma_mode = 2;
	rc = ops->bind_host(&fx.r, page_ptrs, 4, &fx.host);
	CHECK(rc < 0, "G2: bind_host succeeded although DMA mapping failed");
	CHECK(H.dma_map == 1, "G2: dma_map_sgtable not attempted (%u)", H.dma_map);
	CHECK(H.rm_bind == 0, "RM bound unmapped pages");
	CHECK(H.dma_unmap == 0, "unmapped a failed mapping");
	CHECK(H.sg_alloc == H.sg_free, "sg table leaked");
	CHECK(H.live_count == live, "allocations leaked (%u vs %u)", H.live_count, live);
	ops->unbind_region(&fx.r);
	common_checks();
#endif
}

static void case_iova_rm_bind_fail(void)
{
#if VARIANT_IOVA
	struct fixture fx;
	unsigned int live;
	int rc;
	memset(&fx, 0, sizeof(fx));
	fx.r.ops = ops;
	REQUIRE(ops->bind_region(&gpu_file, 0x7f0000000000ULL, 1ULL << 24, &fx.r) == 0,
		"bind_region");
	live = H.live_count;
	H.rm_bind_status = NV_ERR_NOT_SUPPORTED;
	rc = ops->bind_host(&fx.r, page_ptrs, 4, &fx.host);
	CHECK(rc < 0, "bind_host succeeded although RM refused");
	CHECK(H.dma_map == 1 && H.dma_unmap == 1,
	      "G2: failed RM bind must unmap exactly once (map=%u unmap=%u)", H.dma_map,
	      H.dma_unmap);
	CHECK(H.sg_alloc == 1 && H.sg_free == 1, "sg alloc/free %u/%u", H.sg_alloc, H.sg_free);
	CHECK(H.live_count == live, "allocations leaked");
	ops->unbind_region(&fx.r);
	common_checks();
#endif
}

static void case_phys_identity(void)
{
#if !VARIANT_IOVA
	struct fixture fx;
	int rc;
	u32 i;
	H.translated = 1;
	rc = bind(&fx, 4);
	CHECK(rc == -EOPNOTSUPP, "PHYS build must refuse a translating IOMMU (rc=%d)", rc);
	CHECK(H.rm_bind == 0, "RM bound CPU physical addresses behind an IOMMU");
	if (rc == 0)
		return;
	ops->unbind_region(&fx.r);
	H.translated = 0;
	REQUIRE(bind(&fx, 4) == 0, "identity bind");
	for (i = 0; i < 4; i++)
		CHECK(H.bound_addrs[i] == page_to_phys(&host_pages[i]),
		      "PHYS build passed 0x%llx for page %u", (unsigned long long)H.bound_addrs[i], i);
	CHECK(H.dma_map == 0, "PHYS build used the DMA API");
	common_checks();
#endif
}

static void case_sync(void)
{
#if VARIANT_IOVA
	struct fixture fx;
	REQUIRE(bind(&fx, 8) == 0, "bind");
	memset(H.synced_cpu, 0, sizeof(H.synced_cpu));
	memset(H.synced_dev, 0, sizeof(H.synced_dev));
	/* host pages 0 and 1 are read by the CE */
	REQUIRE(submit1(&fx, 1, XDEV_EXT_MECH_DIR_TO_DEVICE, 0, 2 * 4096) == 0, "to device");
	CHECK(!H.submit_saw_dev_sync_gap,
	      "G3: host pages not synchronized for the device before CE submission");
	/* host pages 2 and 3 are written: [2*4096 + 100, + 5000) */
	REQUIRE(submit1(&fx, 2, XDEV_EXT_MECH_DIR_FROM_DEVICE, 2 * 4096 + 100, 5000) == 0,
		"from device");
	deliver(H.rm_last);
	REQUIRE(H.done[2].count == 1 && H.done[2].status == 0, "from-device completion");
	CHECK(H.done[2].synced_cpu[2] && H.done[2].synced_cpu[3],
	      "G3: produced bytes not synchronized for the CPU before completion "
	      "(page2=%d page3=%d)", H.done[2].synced_cpu[2], H.done[2].synced_cpu[3]);
	common_checks();
#endif
}

static void case_host_released_region_failed(void)
{
    struct fixture fx;
    REQUIRE(bind(&fx, 4) == 0, "bind");
    CHECK(ops->unbind_host(fx.host) == 0, "host unbind");
    fx.host = NULL; /* core checked teardown transfers ownership on success */
    H.vidmem_unbind_status = NV_ERR_INVALID_LOCK_STATE;
    CHECK(ops->unbind_region(&fx.r) < 0 && fx.r.priv, "region failure dropped owner");
    CHECK(ops->unbind_host(fx.host) == 0, "NULL host retry");
    CHECK(ops->unbind_region(&fx.r) < 0, "quarantined region retry");
    CHECK(H.rm_unbind == 1 && H.vidmem_unbind == 1, "teardown repeated native release");
#if VARIANT_IOVA
    CHECK(H.dma_unmap == 1 && H.sg_free == 1, "host mapping released twice");
#endif
    common_checks();
}

static void case_region_unbind_fail(void)
{
	struct fixture fx;
	void *region;
	memset(&fx, 0, sizeof(fx));
	fx.r.ops = ops;
	REQUIRE(ops->bind_region(&gpu_file, 0x7f0000000000ULL, 1ULL << 24, &fx.r) == 0,
		"bind_region");
	region = fx.r.priv;
#if !HARNESS_UNBIND_STATUS
	CHECK(0, "G12: nv_p2p_vidmem_unbind returns void; a failed RM unbind cannot be "
	      "observed and the backend frees its only owner");
	(void)region;
#else
	H.vidmem_unbind_status = NV_ERR_INVALID_LOCK_STATE;
	ops->unbind_region(&fx.r);
	CHECK(H.vidmem_unbind == 1, "unbind not attempted");
	CHECK(H.vidmem_live == 1, "binding released despite failure");
	CHECK(harness_is_live(region), "G12: backend freed the window after a failed unbind");
	CHECK(READ_ONCE(((struct nv_xdev_ext_ce_region *)region)->ambiguous),
	      "G12: window not retained for good after a failed unbind");
	H.vidmem_unbind_status = NV_OK;
	memset(&fx, 0, sizeof(fx));
	fx.r.ops = ops;
	REQUIRE(ops->bind_region(&gpu_file, 0x7f0000000000ULL, 1ULL << 24, &fx.r) == 0,
		"bind_region 2");
	region = fx.r.priv;
	ops->unbind_region(&fx.r);
	CHECK(!harness_is_live(region), "successful unbind did not free the window");
#endif
	common_checks();
}

/* Bounded race: one submitter, one completer (event source or poller). */
#define RACE_N 1500
static int race_done_submitting;
static struct fixture race_fx;
static void *race_completer(void *arg)
{
	(void)arg;
	for (;;) {
		u64 last, completed;
		pthread_mutex_lock(&H.big);
		last = H.rm_last;
		/* hardware finishes in steps of up to 3 tokens */
		if (H.rm_completed < last)
			H.rm_completed = H.rm_completed + 3 < last ? H.rm_completed + 3 : last;
		completed = H.rm_completed;
		pthread_mutex_unlock(&H.big);
#if VARIANT_EVENT
		fire_event(completed);
#else
		(void)completed;
#endif
		run_deferred(2);
		if (__atomic_load_n(&race_done_submitting, __ATOMIC_SEQ_CST) &&
		    __atomic_load_n(&H.total_completions, __ATOMIC_SEQ_CST) >= RACE_N)
			break;
		sched_yield();
	}
	return NULL;
}
static void case_race(void)
{
	pthread_t t;
	u64 ticket;
	unsigned int dup = 0, missing = 0;
	REQUIRE(bind(&race_fx, 16) == 0, "bind");
	require_event_registered();
	REQUIRE(!VARIANT_EVENT || H.event_fn, "no event registered");
	pthread_create(&t, NULL, race_completer, NULL);
	for (ticket = 1; ticket <= RACE_N; ticket++) {
		u32 dir = (ticket & 1) ? XDEV_EXT_MECH_DIR_TO_DEVICE : XDEV_EXT_MECH_DIR_FROM_DEVICE;
		int rc;
		H.fire_in_submit = (ticket % 7) == 0;
		while ((rc = submit1(&race_fx, ticket, dir, (ticket % 16) * 4096, 4096)) == -EAGAIN)
			sched_yield();
		if (rc) {
			CHECK(0, "submit %llu failed %d", (unsigned long long)ticket, rc);
			break;
		}
	}
	H.fire_in_submit = 0;
	__atomic_store_n(&race_done_submitting, 1, __ATOMIC_SEQ_CST);
	{
		/* bounded wait: completer stops once everything is retired */
		unsigned int spins = 0;
		while (__atomic_load_n(&H.total_completions, __ATOMIC_SEQ_CST) < RACE_N &&
		       spins++ < 2000000)
			sched_yield();
		if (__atomic_load_n(&H.total_completions, __ATOMIC_SEQ_CST) < RACE_N) {
			CHECK(0, "race: only %u of %u completed", H.total_completions, RACE_N);
			fflush(stdout);
			_exit(1);
		}
	}
	pthread_join(t, NULL);
	for (ticket = 1; ticket <= RACE_N; ticket++) {
		if (H.done[ticket].count > 1)
			dup++;
		if (H.done[ticket].count == 0)
			missing++;
	}
	CHECK(dup == 0 && missing == 0, "race: %u duplicated, %u missing completions", dup,
	      missing);
	ops->unbind_host(race_fx.host);
	ops->unbind_region(&race_fx.r);
	CHECK(H.rm_unbind == 1, "drained host not unbound after race");
	common_checks();
}

struct named_case { const char *name; void (*fn)(void); };
static const struct named_case cases[] = {
	{ "bind-unbind-clean", case_bind_unbind_clean },
	{ "complete-once", case_complete_once },
	{ "complete-partial", case_complete_partial },
	{ "complete-in-submit", case_complete_in_submit },
	{ "event-regress", case_event_regress },
	{ "event-impossible", case_event_impossible },
	{ "ambiguous-submit", case_ambiguous_submit },
	{ "pre-submit-failure", case_pre_submit_failure },
	{ "token-zero", case_token_zero },
	{ "timeout", case_timeout },
	{ "owner-mismatch", case_owner_mismatch },
	{ "owner-busy", case_owner_busy },
	{ "frame-owner-reject", case_frame_owner_reject },
	{ "frame-generation-reject", case_frame_generation_reject },
	{ "frame-generation-late", case_frame_generation_late },
	{ "frame-ticket-duplicate", case_frame_ticket_duplicate },
	{ "unbind-pending", case_unbind_pending },
	{ "unbind-order", case_unbind_order },
	{ "unbind-rm-fail", case_unbind_rm_fail },
	{ "iova-bind", case_iova_bind },
	{ "iova-segments", case_iova_segments },
	{ "iova-map-fail", case_iova_map_fail },
	{ "iova-rm-bind-fail", case_iova_rm_bind_fail },
	{ "phys-identity", case_phys_identity },
	{ "sync", case_sync },
	{ "region-unbind-fail", case_region_unbind_fail },
    { "host-released-region-failed", case_host_released_region_failed },
	{ "race", case_race },
};

int main(int argc, char **argv)
{
	unsigned int i;
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc != 2) {
		for (i = 0; i < ARRAY_SIZE(cases); i++)
			printf("%s\n", cases[i].name);
		return 2;
	}
	harness_init();
	(void)nv_live_before;
	for (i = 0; i < ARRAY_SIZE(cases); i++)
		if (!strcmp(argv[1], cases[i].name)) {
			cases[i].fn();
			return env_report(argv[1]);
		}
	printf("unknown case %s\n", argv[1]);
	return 2;
}
