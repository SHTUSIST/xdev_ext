/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xdev_ext_frame_sm.h — Conduit per-frame 4-state lifecycle state machine.
 *
 *	FREE -> IO_PENDING -> READY -> TX_PENDING -> FREE
 *
 * Transition primitives (the paper's mix):
 *	claim    FREE->IO_PENDING	single CAS
 *	publish  IO_PENDING->READY	CAS with release semantics (valid_len
 *					written before; a stale/duplicate
 *					completion fails the CAS and is dropped)
 *	to_tx    READY->TX_PENDING	single CAS (+ consumers count)
 *	retire   TX_PENDING->FREE	atomic_dec_and_test on consumers
 *	abort    IO_PENDING->FREE	single CAS (I/O error path)
 *
 * Dual-mode: kernel (__KERNEL__: try_cmpxchg/smp_store_release/atomic_t) and
 * userspace (GCC __atomic builtins) compile the SAME logic, so the userspace
 * unit tests exercise what the kernel runs.
 *
 * Userspace backends (kernel always uses the CAS primitives):
 *	XDEV_EXT_SM_CAS	(default) lock-free atomics — the shipped design.
 *	XDEV_EXT_SM_PLAIN	plain loads/stores on the state word; the publish edge
 *			stays a release store. Single-thread reference; NOT
 *			safe for concurrent transitions by design.
 *	XDEV_EXT_SM_DMAFENCE	publish/retire additionally drive an EMULATED fence
 *			(pthread spinlock + callback list + refcounted object)
 *			mirroring dma_fence_signal's cost shape. Benchmark
 *			baseline ONLY — not a real dma_fence.
 *
 * Allocation disciplines:
 *	userspace pipeline: xdev_ext_frame_alloc() pops a lock-free Treiber stack
 *	  (tagged head vs ABA), then claims. xdev_ext_pool_init(.., use_stack=true).
 *	kernel: userspace names the frame (UMEM offset); xdev_ext_frame_claim(idx)
 *	  CASes that index. use_stack=false; retire/abort do not push.
 */
#ifndef XDEV_EXT_FRAME_SM_H
#define XDEV_EXT_FRAME_SM_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/bug.h>
typedef u32 xdev_ext_sm_u32;
typedef u64 xdev_ext_sm_u64;
#define XDEV_EXT_SM_WARN_ON(x)	WARN_ON_ONCE(x)
#else /* !__KERNEL__ */
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
typedef uint32_t xdev_ext_sm_u32;
typedef uint64_t xdev_ext_sm_u64;
#define XDEV_EXT_SM_WARN_ON(x)	((void)(x))
#endif

enum xdev_ext_frame_state {
	XDEV_EXT_FRAME_FREE		= 0,
	XDEV_EXT_FRAME_IO_PENDING	= 1,
	XDEV_EXT_FRAME_READY		= 2,
	XDEV_EXT_FRAME_TX_PENDING	= 3,
	/* Internal transient: one producer won publish and is storing metadata. */
	XDEV_EXT_FRAME_PUBLISHING	= 4,
};

#define XDEV_EXT_SM_NIL	((xdev_ext_sm_u32)~0u)

#if !defined(__KERNEL__) && defined(XDEV_EXT_SM_DMAFENCE)
#include <pthread.h>
#include <stdlib.h>
/*
 * EMULATED fence: reproduces dma_fence's per-hand-off cost shape
 * (irqsave-spinlock stand-in + callback-list walk + refcounted object
 * lifecycle).  Benchmark baseline only.
 */
struct xdev_ext_emu_fence_cb {
	void (*fn)(void *arg);
	void *arg;
	struct xdev_ext_emu_fence_cb *next;
};

struct xdev_ext_emu_fence {
	pthread_spinlock_t lock;
	int refcount;
	int signaled;
	struct xdev_ext_emu_fence_cb *cbs;
};

static inline struct xdev_ext_emu_fence *xdev_ext_emu_fence_create(void)
{
	struct xdev_ext_emu_fence *fe = calloc(1, sizeof(*fe));

	if (!fe)
		abort();
	pthread_spin_init(&fe->lock, PTHREAD_PROCESS_PRIVATE);
	fe->refcount = 1;
	return fe;
}

static inline void xdev_ext_emu_fence_put(struct xdev_ext_emu_fence *fe)
{
	if (__atomic_sub_fetch(&fe->refcount, 1, __ATOMIC_ACQ_REL) == 0) {
		pthread_spin_destroy(&fe->lock);
		free(fe);
	}
}

static inline void xdev_ext_emu_fence_signal(struct xdev_ext_emu_fence *fe)
{
	struct xdev_ext_emu_fence_cb *cb;

	pthread_spin_lock(&fe->lock);
	fe->signaled = 1;
	cb = fe->cbs;
	fe->cbs = NULL;
	while (cb) {
		struct xdev_ext_emu_fence_cb *next = cb->next;

		cb->fn(cb->arg);
		free(cb);
		cb = next;
	}
	pthread_spin_unlock(&fe->lock);
}

static inline int xdev_ext_emu_fence_add_callback(struct xdev_ext_emu_fence *fe,
					     void (*fn)(void *), void *arg)
{
	struct xdev_ext_emu_fence_cb *cb;

	pthread_spin_lock(&fe->lock);
	if (fe->signaled) {
		pthread_spin_unlock(&fe->lock);
		return -ENOENT;
	}
	cb = malloc(sizeof(*cb));
	if (!cb)
		abort();
	cb->fn = fn;
	cb->arg = arg;
	cb->next = fe->cbs;
	fe->cbs = cb;
	pthread_spin_unlock(&fe->lock);
	return 0;
}
#endif /* !__KERNEL__ && XDEV_EXT_SM_DMAFENCE */

struct xdev_ext_frame {
	xdev_ext_sm_u32	state;		/* enum xdev_ext_frame_state */
	xdev_ext_sm_u32	valid_len;	/* bytes valid once READY */
#ifdef __KERNEL__
	atomic_t	consumers;
#else
	int		consumers;
#endif
	xdev_ext_sm_u32	free_next;	/* Treiber link (use_stack pools) */
#if !defined(__KERNEL__) && defined(XDEV_EXT_SM_DMAFENCE)
	struct xdev_ext_emu_fence *fence;	/* one per hand-off (claim..retire) */
#endif
};

struct xdev_ext_pool {
	xdev_ext_sm_u32	nr_frames;
	bool		use_stack;
	struct xdev_ext_frame *frames;
	xdev_ext_sm_u64	free_head;	/* [63:32] ABA tag | [31:0] index */
	xdev_ext_sm_u32	free_count;	/* diagnostics only */
};

/* ---- primitive layer ---------------------------------------------------- */
#ifdef __KERNEL__

static inline xdev_ext_sm_u32 xdev_ext_sm_load_acq(xdev_ext_sm_u32 *p)
{
	/* pairs with xdev_ext_sm_store_rel()/the release publish edge: a consumer
	 * that observes READY also observes valid_len + the DMA'd bytes */
	return smp_load_acquire(p);
}

static inline void xdev_ext_sm_store_rel(xdev_ext_sm_u32 *p, xdev_ext_sm_u32 v)
{
	/* publish/retire edges: order the frame's payload/metadata writes
	 * before the state becomes visible (pairs with xdev_ext_sm_load_acq) */
	smp_store_release(p, v);
}

static inline xdev_ext_sm_u32 xdev_ext_sm_load_rlx(xdev_ext_sm_u32 *p)
{
	return READ_ONCE(*p);
}

static inline void xdev_ext_sm_store_rlx(xdev_ext_sm_u32 *p, xdev_ext_sm_u32 v)
{
	WRITE_ONCE(*p, v);
}

static inline xdev_ext_sm_u64 xdev_ext_sm_load64_acq(xdev_ext_sm_u64 *p)
{
	/* Treiber-stack head load: acquire pairs with the releasing CAS in
	 * push/pop so frames[idx].free_next reads see the matching link */
	return smp_load_acquire(p);
}

static inline bool xdev_ext_sm_cas32(xdev_ext_sm_u32 *p, xdev_ext_sm_u32 old, xdev_ext_sm_u32 new)
{
	return try_cmpxchg(p, &old, new);
}

static inline bool xdev_ext_sm_cas64(xdev_ext_sm_u64 *p, xdev_ext_sm_u64 *old, xdev_ext_sm_u64 new)
{
	return try_cmpxchg64(p, old, new);
}

static inline void xdev_ext_sm_consumers_set(struct xdev_ext_frame *f, int n)
{
	atomic_set(&f->consumers, n);
}

static inline bool xdev_ext_sm_consumers_dec_and_test(struct xdev_ext_frame *f)
{
	return atomic_dec_and_test(&f->consumers);
}

#else /* !__KERNEL__ */

static inline xdev_ext_sm_u32 xdev_ext_sm_load_acq(xdev_ext_sm_u32 *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void xdev_ext_sm_store_rel(xdev_ext_sm_u32 *p, xdev_ext_sm_u32 v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static inline xdev_ext_sm_u32 xdev_ext_sm_load_rlx(xdev_ext_sm_u32 *p)
{
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

static inline void xdev_ext_sm_store_rlx(xdev_ext_sm_u32 *p, xdev_ext_sm_u32 v)
{
	__atomic_store_n(p, v, __ATOMIC_RELAXED);
}

static inline xdev_ext_sm_u64 xdev_ext_sm_load64_acq(xdev_ext_sm_u64 *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline bool xdev_ext_sm_cas32(xdev_ext_sm_u32 *p, xdev_ext_sm_u32 old, xdev_ext_sm_u32 new)
{
	return __atomic_compare_exchange_n(p, &old, new, false,
					   __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline bool xdev_ext_sm_cas64(xdev_ext_sm_u64 *p, xdev_ext_sm_u64 *old, xdev_ext_sm_u64 new)
{
	return __atomic_compare_exchange_n(p, old, new, false,
					   __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static inline void xdev_ext_sm_consumers_set(struct xdev_ext_frame *f, int n)
{
	__atomic_store_n(&f->consumers, n, __ATOMIC_RELEASE);
}

static inline bool xdev_ext_sm_consumers_dec_and_test(struct xdev_ext_frame *f)
{
	return __atomic_sub_fetch(&f->consumers, 1, __ATOMIC_ACQ_REL) == 0;
}

#endif /* __KERNEL__ */

/* ---- backend selection for the state-word edges ------------------------- */
#if !defined(__KERNEL__) && defined(XDEV_EXT_SM_PLAIN)

/* Plain (non-atomic) transition — the uncontended-overhead reference. */
static inline bool xdev_ext_sm_claim_edge(xdev_ext_sm_u32 *state, xdev_ext_sm_u32 from,
				     xdev_ext_sm_u32 to)
{
	if (*state != from)
		return false;
	*state = to;
	return true;
}

/* Publish keeps release semantics even in PLAIN (HANDOFF §4.2). */
static inline bool xdev_ext_sm_publish_edge(xdev_ext_sm_u32 *state)
{
	if (*state != XDEV_EXT_FRAME_IO_PENDING)
		return false;
	xdev_ext_sm_store_rel(state, XDEV_EXT_FRAME_READY);
	return true;
}

static inline void xdev_ext_sm_consumers_init(struct xdev_ext_frame *f, int n)
{
	f->consumers = n;
}

static inline bool xdev_ext_sm_retire_dec(struct xdev_ext_frame *f)
{
	return --f->consumers == 0;
}

#else /* CAS (default; also the only kernel mode) */

#define xdev_ext_sm_claim_edge(state, from, to)	xdev_ext_sm_cas32(state, from, to)
#define xdev_ext_sm_publish_edge(state)					\
	xdev_ext_sm_cas32(state, XDEV_EXT_FRAME_IO_PENDING, XDEV_EXT_FRAME_READY)
#define xdev_ext_sm_consumers_init(f, n)		xdev_ext_sm_consumers_set(f, n)
#define xdev_ext_sm_retire_dec(f)			xdev_ext_sm_consumers_dec_and_test(f)

#endif

/* ---- Treiber free-stack (use_stack pools; all backends) ----------------- */
static inline void xdev_ext_sm_free_count_add(struct xdev_ext_pool *p, int v)
{
#ifdef __KERNEL__
	/* diagnostics only; kernel pools are use_stack=false today */
	WRITE_ONCE(p->free_count, READ_ONCE(p->free_count) + v);
#else
	__atomic_add_fetch(&p->free_count, v, __ATOMIC_RELAXED);
#endif
}

static inline xdev_ext_sm_u32 xdev_ext_pool_free_count(struct xdev_ext_pool *p)
{
	return xdev_ext_sm_load_rlx(&p->free_count);
}

static inline xdev_ext_sm_u32 xdev_ext_frame_state(struct xdev_ext_pool *p, xdev_ext_sm_u32 idx)
{
	return xdev_ext_sm_load_rlx(&p->frames[idx].state);
}

static inline xdev_ext_sm_u32 xdev_ext_stack_pop(struct xdev_ext_pool *p)
{
	xdev_ext_sm_u64 old = xdev_ext_sm_load64_acq(&p->free_head);

	for (;;) {
		xdev_ext_sm_u32 idx = (xdev_ext_sm_u32)old;
		xdev_ext_sm_u64 tag = old >> 32;
		xdev_ext_sm_u32 next;

		if (idx == XDEV_EXT_SM_NIL)
			return XDEV_EXT_SM_NIL;
		next = xdev_ext_sm_load_rlx(&p->frames[idx].free_next);
		if (xdev_ext_sm_cas64(&p->free_head, &old, ((tag + 1) << 32) | next)) {
			xdev_ext_sm_free_count_add(p, -1);
			return idx;
		}
		/* a failed CAS reloaded `old`; retry */
	}
}

static inline void xdev_ext_stack_push(struct xdev_ext_pool *p, xdev_ext_sm_u32 idx)
{
	xdev_ext_sm_u64 old = xdev_ext_sm_load64_acq(&p->free_head);

	for (;;) {
		xdev_ext_sm_u64 tag = old >> 32;

		xdev_ext_sm_store_rlx(&p->frames[idx].free_next, (xdev_ext_sm_u32)old);
		if (xdev_ext_sm_cas64(&p->free_head, &old, ((tag + 1) << 32) | idx)) {
			xdev_ext_sm_free_count_add(p, 1);
			return;
		}
	}
}

/* ---- API (SM_SPEC §2) ---------------------------------------------------- */

static inline int xdev_ext_pool_init(struct xdev_ext_pool *p, struct xdev_ext_frame *frames,
				xdev_ext_sm_u32 nr, bool use_stack)
{
	xdev_ext_sm_u32 i;

	if (!p || !frames || !nr || nr >= XDEV_EXT_SM_NIL)
		return -EINVAL;
	p->nr_frames = nr;
	p->use_stack = use_stack;
	p->frames = frames;
	for (i = 0; i < nr; i++) {
		frames[i].state = XDEV_EXT_FRAME_FREE;
		frames[i].valid_len = 0;
		xdev_ext_sm_consumers_init(&frames[i], 0);
		frames[i].free_next = (use_stack && i + 1 < nr) ? i + 1
								: XDEV_EXT_SM_NIL;
	}
	p->free_head = use_stack ? 0 : XDEV_EXT_SM_NIL;	/* tag 0 | first idx */
	p->free_count = use_stack ? nr : 0;
	return 0;
}

/*
 * CAS-claim a CALLER-CHOSEN frame: kernel discipline (userspace names the
 * frame via the op's UMEM offset). The cross-context claim race (userspace
 * vs kernel vs another submitter) is resolved by this CAS — HANDOFF §2.a.
 */
static inline int xdev_ext_frame_claim(struct xdev_ext_pool *p, xdev_ext_sm_u32 idx)
{
	struct xdev_ext_frame *f;

	if (idx >= p->nr_frames)
		return -ERANGE;
	f = &p->frames[idx];
	if (!xdev_ext_sm_claim_edge(&f->state, XDEV_EXT_FRAME_FREE, XDEV_EXT_FRAME_IO_PENDING))
		return -EBUSY;
#if !defined(__KERNEL__) && defined(XDEV_EXT_SM_DMAFENCE)
	f->fence = xdev_ext_emu_fence_create();
#endif
	return 0;
}

/* Pop the free stack, then claim: userspace-pipeline discipline. */
static inline int xdev_ext_frame_alloc(struct xdev_ext_pool *p, xdev_ext_sm_u32 *idx)
{
	xdev_ext_sm_u32 i;

	if (!p->use_stack)
		return -EOPNOTSUPP;
	i = xdev_ext_stack_pop(p);
	if (i == XDEV_EXT_SM_NIL)
		return -ENOSPC;
	/* The pop granted exclusive ownership; this edge is the SM transition
	 * plus a corruption check (a stacked frame must be FREE). */
	if (!xdev_ext_sm_claim_edge(&p->frames[i].state, XDEV_EXT_FRAME_FREE,
			       XDEV_EXT_FRAME_IO_PENDING)) {
		XDEV_EXT_SM_WARN_ON(1);
		return -EFAULT;
	}
#if !defined(__KERNEL__) && defined(XDEV_EXT_SM_DMAFENCE)
	p->frames[i].fence = xdev_ext_emu_fence_create();
#endif
	*idx = i;
	return 0;
}

/*
 * IO_PENDING -> READY. The producer first claims a short internal
 * PUBLISHING state, then writes valid_len, then release-stores READY. This
 * prevents stale/duplicate completions from corrupting valid_len on a frame
 * already published by the winning completion.
 */
static inline int xdev_ext_frame_publish(struct xdev_ext_pool *p, xdev_ext_sm_u32 idx,
				    xdev_ext_sm_u32 len)
{
	struct xdev_ext_frame *f;

	if (idx >= p->nr_frames)
		return -ERANGE;
	f = &p->frames[idx];
	if (!xdev_ext_sm_claim_edge(&f->state, XDEV_EXT_FRAME_IO_PENDING,
			       XDEV_EXT_FRAME_PUBLISHING))
		return -EINVAL;
	/* Relaxed store (kernel: WRITE_ONCE): a consumer that loses the to_tx
	 * race can read valid_len concurrently with a LATER publish of the
	 * recycled frame; it discards the value, but the access must still be
	 * a marked (atomic) access. Ordering vs the winning consumer comes
	 * from the release publish edge below + the acquire load in
	 * xdev_ext_frame_acquire_ready(). */
	xdev_ext_sm_store_rlx(&f->valid_len, len);
	xdev_ext_sm_store_rel(&f->state, XDEV_EXT_FRAME_READY);
#if !defined(__KERNEL__) && defined(XDEV_EXT_SM_DMAFENCE)
	xdev_ext_emu_fence_signal(f->fence);
#endif
	return 0;
}

/* Acquire-load: consumer's entry point. -EAGAIN if not READY. */
static inline int xdev_ext_frame_acquire_ready(struct xdev_ext_pool *p, xdev_ext_sm_u32 idx,
					  xdev_ext_sm_u32 *len)
{
	struct xdev_ext_frame *f;

	if (idx >= p->nr_frames)
		return -ERANGE;
	f = &p->frames[idx];
	if (xdev_ext_sm_load_acq(&f->state) != XDEV_EXT_FRAME_READY)
		return -EAGAIN;
	if (len)
		*len = xdev_ext_sm_load_rlx(&f->valid_len);	/* see publish */
	return 0;
}

/*
 * READY -> TX_PENDING. The CAS resolves racing consumers to ONE winner;
 * only the winner sets `consumers` (a release store), AFTER the edge.
 * Contract: xdev_ext_frame_consumer_done() may only be called by consumers the
 * winner handed the frame to after to_tx returned 0 — that hand-off (ring
 * submit/completion, or the winner's own program order) is what sequences
 * their view of `consumers`. Setting the count before the edge looks
 * safer but is wrong: a LOSING racer's cleanup would clobber the winner's
 * count and strand the frame in TX_PENDING forever (found by xdev_ext_sm_stress).
 */
static inline int xdev_ext_frame_to_tx(struct xdev_ext_pool *p, xdev_ext_sm_u32 idx,
				  int n_consumers)
{
	struct xdev_ext_frame *f;

	if (idx >= p->nr_frames)
		return -ERANGE;
	if (n_consumers < 1)
		return -EINVAL;
	f = &p->frames[idx];
	if (!xdev_ext_sm_claim_edge(&f->state, XDEV_EXT_FRAME_READY,
			       XDEV_EXT_FRAME_TX_PENDING))
		return -EINVAL;
	xdev_ext_sm_consumers_init(f, n_consumers);	/* winner-only */
	return 0;
}

/* One consumer done; the LAST decrement retires TX_PENDING -> FREE. */
static inline int xdev_ext_frame_consumer_done(struct xdev_ext_pool *p, xdev_ext_sm_u32 idx)
{
	struct xdev_ext_frame *f;

	if (idx >= p->nr_frames)
		return -ERANGE;
	f = &p->frames[idx];
	if (xdev_ext_sm_load_rlx(&f->state) != XDEV_EXT_FRAME_TX_PENDING)
		return -EINVAL;
	if (xdev_ext_sm_retire_dec(f)) {
#if !defined(__KERNEL__) && defined(XDEV_EXT_SM_DMAFENCE)
		xdev_ext_emu_fence_put(f->fence);
		f->fence = NULL;
#endif
		xdev_ext_sm_store_rel(&f->state, XDEV_EXT_FRAME_FREE);
		if (p->use_stack)
			xdev_ext_stack_push(p, idx);
	}
	return 0;
}

/* I/O-error path: IO_PENDING -> FREE (the read never published). */
static inline int xdev_ext_frame_abort(struct xdev_ext_pool *p, xdev_ext_sm_u32 idx)
{
	if (idx >= p->nr_frames)
		return -ERANGE;
	if (!xdev_ext_sm_claim_edge(&p->frames[idx].state, XDEV_EXT_FRAME_IO_PENDING,
			       XDEV_EXT_FRAME_FREE))
		return -EINVAL;
#if !defined(__KERNEL__) && defined(XDEV_EXT_SM_DMAFENCE)
	xdev_ext_emu_fence_put(p->frames[idx].fence);
	p->frames[idx].fence = NULL;
#endif
	if (p->use_stack)
		xdev_ext_stack_push(p, idx);
	return 0;
}

#endif /* XDEV_EXT_FRAME_SM_H */
