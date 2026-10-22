/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_ADMISSION_H
#define XDEV_EXT_PRELOAD_ADMISSION_H

/*
 * Process-lifetime admission gate for the front end, after ExitOS's
 * src/frontend_admission.c.  The constructor publishes everything a gated
 * path reads and then opens the gate; the destructor closes it and waits for
 * the callers already inside.  The gate itself is static, so a caller that
 * arrives after the close only reads a closed flag.
 *
 * A gated section must be bounded: lookup, eligibility and publishing an
 * SQE, or copying out of a receive ring.  Waiting for a CQE or for a datagram
 * happens outside it (xdev_ext_admission_scope_exit() before the wait,
 * xdev_ext_admission_scope_reenter() after), with the object kept alive by its own
 * reference count, so quiesce never waits for the application.  A gated
 * section must also not act on a cancellation request: C cleanup attributes
 * do not run when pthread_cancel unwinds, and a lost leave would make the
 * destructor wait forever.
 *
 * The state is static in this header; include it from one translation unit
 * per library.
 */
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>

/*
 * A single counter would put two locked read-modify-writes from every
 * intercepted call on one cache line.  A thread picks a shard on first entry
 * and keeps it.
 */
#define XDEV_EXT_ADMISSION_SHARDS 64U

struct xdev_ext_admission_shard {
	_Atomic unsigned int refs;
} __attribute__((aligned(64)));

static _Atomic unsigned int xdev_ext_admission_accepting;
static _Atomic unsigned int xdev_ext_admission_next_shard;
static struct xdev_ext_admission_shard xdev_ext_admission_shards[XDEV_EXT_ADMISSION_SHARDS];
/* initial-exec for the same reason as xdev_ext_in_hook in the export layer. */
static __thread unsigned int __attribute__((tls_model("initial-exec")))
	xdev_ext_admission_shard_plus_one;
/* This thread's admissions, so that its own quiesce does not wait on them. */
static __thread unsigned int __attribute__((tls_model("initial-exec")))
	xdev_ext_admission_depth;

static inline struct xdev_ext_admission_shard *xdev_ext_admission_thread_shard(void)
{
	unsigned int shard = xdev_ext_admission_shard_plus_one;

	if (!shard) {
		shard = atomic_fetch_add_explicit(&xdev_ext_admission_next_shard, 1,
						  memory_order_relaxed) %
			XDEV_EXT_ADMISSION_SHARDS + 1;
		xdev_ext_admission_shard_plus_one = shard;
	}
	return &xdev_ext_admission_shards[shard - 1];
}

static inline void xdev_ext_admission_enable(void)
{
	atomic_store_explicit(&xdev_ext_admission_accepting, 1,
			      memory_order_seq_cst);
}

/*
 * The first load keeps an inert process at one atomic load per call.  The
 * increment and the second load close the check/use race with quiesce: all
 * sequentially consistent, so if quiesce saw this shard at zero before the
 * increment, the second load sees the gate closed and backs out; if it saw
 * the increment, it waits for the leave.  The depth goes up first, so a
 * signal handler on this thread that quiesces in between does not wait for
 * its own interrupted entry.
 */
static inline bool xdev_ext_admission_enter(void)
{
	struct xdev_ext_admission_shard *shard;

	if (!atomic_load_explicit(&xdev_ext_admission_accepting,
				  memory_order_seq_cst))
		return false;
	shard = xdev_ext_admission_thread_shard();
	xdev_ext_admission_depth++;
	atomic_fetch_add_explicit(&shard->refs, 1, memory_order_seq_cst);
	if (atomic_load_explicit(&xdev_ext_admission_accepting,
				 memory_order_seq_cst))
		return true;
	atomic_fetch_sub_explicit(&shard->refs, 1, memory_order_seq_cst);
	xdev_ext_admission_depth--;
	return false;
}

/* Only after an xdev_ext_admission_enter() that returned true. */
static inline void xdev_ext_admission_leave(void)
{
	struct xdev_ext_admission_shard *shard = xdev_ext_admission_thread_shard();

	atomic_fetch_sub_explicit(&shard->refs, 1, memory_order_seq_cst);
	xdev_ext_admission_depth--;
}

/*
 * Close the gate, then wait until every caller admitted before the close has
 * left.  The calling thread's own admissions are excused: exit() from inside
 * a wrapper, or from a signal handler that interrupted one, reaches the
 * destructor here and must not wait for itself.  Other threads that share
 * its shard are still waited for.
 */
static inline void xdev_ext_admission_quiesce(void)
{
	unsigned int own = xdev_ext_admission_shard_plus_one;

	atomic_store_explicit(&xdev_ext_admission_accepting, 0,
			      memory_order_seq_cst);
	for (;;) {
		bool busy = false;

		for (unsigned int i = 0; i < XDEV_EXT_ADMISSION_SHARDS; i++) {
			unsigned int excused = own == i + 1 ?
				xdev_ext_admission_depth : 0;

			if (atomic_load_explicit(&xdev_ext_admission_shards[i].refs,
						 memory_order_seq_cst) >
			    excused) {
				busy = true;
				break;
			}
		}
		if (!busy)
			return;
		sched_yield();
	}
}

/* Callers inside the gate right now, for tests and white-box checks. */
static inline unsigned int xdev_ext_admission_inflight(void)
{
	unsigned int total = 0;

	for (unsigned int i = 0; i < XDEV_EXT_ADMISSION_SHARDS; i++)
		total += atomic_load_explicit(&xdev_ext_admission_shards[i].refs,
					      memory_order_seq_cst);
	return total;
}

/*
 * pthread_atfork child handler.  The child has only the forking thread; the
 * other threads' admissions were copied with the memory but will never
 * leave, and the child's exit would wait for them.
 */
static inline void xdev_ext_admission_after_fork_child(void)
{
	unsigned int own = xdev_ext_admission_shard_plus_one;

	for (unsigned int i = 0; i < XDEV_EXT_ADMISSION_SHARDS; i++)
		atomic_store_explicit(&xdev_ext_admission_shards[i].refs,
				      own == i + 1 ? xdev_ext_admission_depth : 0,
				      memory_order_seq_cst);
}

struct xdev_ext_admission_scope {
	bool entered;
};

static inline struct xdev_ext_admission_scope xdev_ext_admission_scope_enter(void)
{
	struct xdev_ext_admission_scope scope = {
		.entered = xdev_ext_admission_enter(),
	};

	return scope;
}

/* Leave early, before a blocking wait; the scope's cleanup then does nothing. */
static inline void xdev_ext_admission_scope_exit(struct xdev_ext_admission_scope *scope)
{
	if (scope->entered) {
		scope->entered = false;
		xdev_ext_admission_leave();
	}
}

/* Re-enter after the wait; false means the front end is shutting down. */
static inline bool
xdev_ext_admission_scope_reenter(struct xdev_ext_admission_scope *scope)
{
	if (!scope->entered)
		scope->entered = xdev_ext_admission_enter();
	return scope->entered;
}

/*
 * Every return path of the enclosing block leaves the gate.  name.entered
 * says whether the caller may touch state the constructor published.
 */
#define XDEV_EXT_ADMISSION_SCOPE(name)					\
	struct xdev_ext_admission_scope name					\
		__attribute__((cleanup(xdev_ext_admission_scope_exit))) =	\
			xdev_ext_admission_scope_enter()

#endif /* XDEV_EXT_PRELOAD_ADMISSION_H */
