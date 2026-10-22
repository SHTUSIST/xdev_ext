/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_REG_H
#define XDEV_EXT_PRELOAD_REG_H

/*
 * Per-descriptor registration table of the transparent front end.
 *
 * A two-level array indexed by fd number (64 chunks of 1024 slots, allocated
 * on first use) holds a pointer to a reference-counted struct xdev_ext_reg.
 * Descriptors made by dup/dup2/dup3/F_DUPFD point at the same object, so a
 * datagram already in a receive ring is visible through every alias; an
 * alias the table cannot hold (fd >= 65536) releases a receive registration
 * to the kernel stack instead (xdev_ext_reg_escaped()).  Each slot holds one
 * reference and each in-flight call holds one; the object is destroyed
 * exactly once, when the last of them is dropped.
 *
 * The lifecycle functions below are the bodies of the close, dup, dup2, dup3,
 * fcntl(F_DUPFD*) and close_range wrappers.  dup2, dup3, close and
 * close_range make the real call under the shard lock(s) of the numbers they
 * change, so it is ordered against every table change for those numbers;
 * errno is saved right after the real call and restored on return.  dup and
 * F_DUPFD return a number nobody can lock in advance, so they hold the
 * source's registration across the real call and check the new number's
 * identity under its shard lock before it inherits a slot.  Backend actions
 * (closing a link, deleting mirrors, the REPORT line) are injected hooks and
 * never run with a lock held.
 *
 * A real close made under a lock (close, fclose, freopen, the rollback in
 * dup2/dup3) runs with cancellation disabled: a deferred request acting
 * inside it would unwind with the lock held and hang every later call on
 * that shard.  close, fclose and freopen stay cancellation points for the
 * caller: a request pending at entry acts before anything is locked or
 * closed, as in libc, and one that arrives during the call acts once the
 * lock is released and the slot forgotten.
 *
 * Lock order: xdev_ext_privfd_mu, then xdev_ext_reg_shard_mu[] in ascending index.
 * close_range and atfork take every shard; dup2/dup3 take two, lower index
 * first, and hold xdev_ext_privfd_mu as well when the target is at or above
 * XDEV_EXT_PRIVFD_FLOOR_MIN, so those calls serialize with each other and with
 * adoption of private descriptors.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "xdev_ext_preload_privfd.h"

/* Defined by the sink/source modules; the table only stores the pointers. */
struct xdev_ext_sink_ops;
struct xdev_ext_source_ops;

enum xdev_ext_reg_kind {
	XDEV_EXT_REG_NS_PASSTHRU = 1,	/* whole NVMe namespace, passthrough */
	XDEV_EXT_REG_DGRAM_RX    = 2,	/* UDP receive served from AF_XDP */
	XDEV_EXT_REG_FILE_DIRECT = 3,	/* files and other block devices */
	XDEV_EXT_REG_DGRAM_TX    = 4,	/* connected UDP send */
};

enum xdev_ext_reg_state {
	XDEV_EXT_REG_ACTIVE = 1,
	XDEV_EXT_REG_RELEASING,	/* new packets to the stack; ring drains */
	XDEV_EXT_REG_RELEASED,	/* ring empty; everything goes to libc */
	XDEV_EXT_REG_SEQUESTERED,	/* impossible ring state; libc only */
};

enum xdev_ext_release_reason {
	XDEV_EXT_RELEASE_NONE,
	XDEV_EXT_RELEASE_SOCKOPT,
	XDEV_EXT_RELEASE_SHUTDOWN,
	XDEV_EXT_RELEASE_REFILTER,
	XDEV_EXT_RELEASE_MIRROR,
	XDEV_EXT_RELEASE_FORK,
	XDEV_EXT_RELEASE_SCM_RIGHTS,
	XDEV_EXT_RELEASE_ALIAS,	/* an alias the table cannot hold, fd >= 65536 */
};

struct xdev_ext_fd_identity {
	dev_t dev;
	ino_t ino;
	dev_t rdev;
	mode_t type;
};

struct xdev_ext_reg {
	_Atomic unsigned int refs;	/* one per slot and per in-flight call */
	enum xdev_ext_reg_kind kind;
	_Atomic int state;
	enum xdev_ext_release_reason release_reason;
	struct xdev_ext_fd_identity id;
	_Atomic int status_flags;	/* maintained by the F_SETFL wrapper */
	pid_t owner_pid;
	uint32_t slot;			/* NS_PASSTHRU fixed file slot 0..15 */
	uint32_t generation;		/* reinstall when a slot is reused */
	const struct xdev_ext_sink_ops *sink;
	const struct xdev_ext_source_ops *source;
	void *backend;
	pthread_mutex_t rx_mu;		/* DGRAM_RX only */
	struct xdev_ext_reg *reap_next;	/* close_range: destroy after unlock */
};

#define XDEV_EXT_REG_CHUNK_SHIFT 10U
#define XDEV_EXT_REG_CHUNKS      64U
#define XDEV_EXT_REG_CHUNK_SLOTS (1U << XDEV_EXT_REG_CHUNK_SHIFT)
#define XDEV_EXT_REG_FD_LIMIT    (XDEV_EXT_REG_CHUNKS * XDEV_EXT_REG_CHUNK_SLOTS)
#define XDEV_EXT_REG_SHARDS      64U

_Static_assert(XDEV_EXT_REG_FD_LIMIT == XDEV_EXT_PRIVFD_FD_LIMIT,
	       "the registration table and the private set cover one range");

static _Atomic(struct xdev_ext_reg **) xdev_ext_reg_chunks[XDEV_EXT_REG_CHUNKS];
static pthread_mutex_t xdev_ext_reg_shard_mu[XDEV_EXT_REG_SHARDS] = {
	[0 ... XDEV_EXT_REG_SHARDS - 1] = PTHREAD_MUTEX_INITIALIZER,
};
/* ADDed to an epoll set while unregistered: never activate receive on it. */
static uint64_t xdev_ext_epoll_seen[XDEV_EXT_REG_FD_LIMIT / 64];

/*
 * Backend actions of the registration state machine.  The front end routes
 * them to the registration's sink or source ops; every hook is optional.
 */
struct xdev_ext_reg_backend_ops {
	/* ACTIVE -> RELEASING: detach the link; new packets go to the stack. */
	void (*release)(struct xdev_ext_reg *r, enum xdev_ext_release_reason why);
	/* RELEASING -> RELEASED: delete and close every epoll mirror. */
	void (*retire)(struct xdev_ext_reg *r);
	/* -> SEQUESTERED: detach the link, delete mirrors, leave the ring. */
	void (*sequester)(struct xdev_ext_reg *r);
	/* Last reference gone: tear down and report exactly once. */
	void (*destroy)(struct xdev_ext_reg *r);
};

struct xdev_ext_reg_env {
	const struct xdev_ext_fd_real_ops *real;
	const struct xdev_ext_reg_backend_ops *backend;
};

static inline void xdev_ext_fd_identity_from_stat(const struct stat *st,
					     struct xdev_ext_fd_identity *id)
{
	id->dev = st->st_dev;
	id->ino = st->st_ino;
	id->rdev = st->st_rdev;
	id->type = st->st_mode & S_IFMT;
}

static inline bool xdev_ext_fd_identity_equal(const struct xdev_ext_fd_identity *a,
					 const struct xdev_ext_fd_identity *b)
{
	return a->dev == b->dev && a->ino == b->ino && a->rdev == b->rdev &&
	       a->type == b->type;
}

static inline bool xdev_ext_reg_fd_in_range(int fd)
{
	return fd >= 0 && (unsigned int)fd < XDEV_EXT_REG_FD_LIMIT;
}

static inline unsigned int xdev_ext_reg_shard(int fd)
{
	return (unsigned int)fd & (XDEV_EXT_REG_SHARDS - 1);
}

static inline void xdev_ext_reg_lock(int fd)
{
	(void)pthread_mutex_lock(&xdev_ext_reg_shard_mu[xdev_ext_reg_shard(fd)]);
}

static inline void xdev_ext_reg_unlock(int fd)
{
	(void)pthread_mutex_unlock(&xdev_ext_reg_shard_mu[xdev_ext_reg_shard(fd)]);
}

/* dup2(A, B) and dup2(B, A) on two threads both lock the lower index first. */
static inline void xdev_ext_reg_lock_pair(int a, int b)
{
	unsigned int lo = xdev_ext_reg_shard(a);
	unsigned int hi = xdev_ext_reg_shard(b);

	if (lo > hi) {
		unsigned int tmp = lo;

		lo = hi;
		hi = tmp;
	}
	(void)pthread_mutex_lock(&xdev_ext_reg_shard_mu[lo]);
	if (hi != lo)
		(void)pthread_mutex_lock(&xdev_ext_reg_shard_mu[hi]);
}

static inline void xdev_ext_reg_unlock_pair(int a, int b)
{
	unsigned int sa = xdev_ext_reg_shard(a);
	unsigned int sb = xdev_ext_reg_shard(b);

	if (sb != sa)
		(void)pthread_mutex_unlock(&xdev_ext_reg_shard_mu[sb]);
	(void)pthread_mutex_unlock(&xdev_ext_reg_shard_mu[sa]);
}

static inline void xdev_ext_reg_lock_shards(void)
{
	for (unsigned int i = 0; i < XDEV_EXT_REG_SHARDS; i++)
		(void)pthread_mutex_lock(&xdev_ext_reg_shard_mu[i]);
}

static inline void xdev_ext_reg_unlock_shards(void)
{
	for (unsigned int i = XDEV_EXT_REG_SHARDS; i > 0; i--)
		(void)pthread_mutex_unlock(&xdev_ext_reg_shard_mu[i - 1]);
}

/* atfork prepare takes the private set and every shard; parent and child
 * release them in reverse order. */
static inline void xdev_ext_reg_lock_all(void)
{
	xdev_ext_privfd_lock();
	xdev_ext_reg_lock_shards();
}

static inline void xdev_ext_reg_unlock_all(void)
{
	xdev_ext_reg_unlock_shards();
	xdev_ext_privfd_unlock();
}

static inline void xdev_ext_epoll_seen_set(int fd, bool seen)
{
	uint64_t mask;

	if (!xdev_ext_reg_fd_in_range(fd))
		return;
	mask = UINT64_C(1) << (fd % 64);
	if (seen)
		__atomic_fetch_or(&xdev_ext_epoll_seen[fd / 64], mask,
				  __ATOMIC_RELAXED);
	else
		__atomic_fetch_and(&xdev_ext_epoll_seen[fd / 64], ~mask,
				   __ATOMIC_RELAXED);
}

static inline bool xdev_ext_epoll_seen_get(int fd)
{
	if (!xdev_ext_reg_fd_in_range(fd))
		return false;
	return __atomic_load_n(&xdev_ext_epoll_seen[fd / 64], __ATOMIC_RELAXED) &
	       (UINT64_C(1) << (fd % 64));
}

static inline void xdev_ext_epoll_seen_mark(int fd)
{
	xdev_ext_epoll_seen_set(fd, true);
}

/* Numbers the table cannot hold report "seen", so they are never activated. */
static inline bool xdev_ext_epoll_seen_test(int fd)
{
	return !xdev_ext_reg_fd_in_range(fd) || xdev_ext_epoll_seen_get(fd);
}

static inline void xdev_ext_epoll_seen_clear_range(unsigned int first,
					      unsigned int last)
{
	while (first <= last) {
		unsigned int word = first / 64;
		unsigned int hi = last / 64 == word ? last % 64 : 63;
		uint64_t mask = ~UINT64_C(0) << (first % 64);

		if (hi < 63)
			mask &= (UINT64_C(1) << (hi + 1)) - 1;
		__atomic_fetch_and(&xdev_ext_epoll_seen[word], ~mask,
				   __ATOMIC_RELAXED);
		first = (word + 1) * 64;
	}
}

/* The slot of @fd, allocating its chunk when @create is set.  NULL when the
 * number is outside the table, or the chunk is absent and not created. */
static inline struct xdev_ext_reg **xdev_ext_reg_slot(int fd, bool create)
{
	struct xdev_ext_reg **chunk;
	unsigned int idx;

	if (!xdev_ext_reg_fd_in_range(fd))
		return NULL;
	idx = (unsigned int)fd >> XDEV_EXT_REG_CHUNK_SHIFT;
	chunk = atomic_load_explicit(&xdev_ext_reg_chunks[idx],
				     memory_order_acquire);
	if (!chunk && create) {
		struct xdev_ext_reg **fresh;

		/* A chunk spans every shard, so it is published by one CAS;
		 * chunks live as long as the process. */
		fresh = calloc(XDEV_EXT_REG_CHUNK_SLOTS, sizeof(*fresh));
		if (!fresh)
			return NULL;
		if (atomic_compare_exchange_strong_explicit(
			    &xdev_ext_reg_chunks[idx], &chunk, fresh,
			    memory_order_acq_rel, memory_order_acquire))
			chunk = fresh;
		else
			free(fresh);
	}
	if (!chunk)
		return NULL;
	return &chunk[(unsigned int)fd & (XDEV_EXT_REG_CHUNK_SLOTS - 1)];
}

static inline struct xdev_ext_reg *xdev_ext_reg_slot_load(struct xdev_ext_reg **slot)
{
	return __atomic_load_n(slot, __ATOMIC_ACQUIRE);
}

static inline void xdev_ext_reg_slot_store(struct xdev_ext_reg **slot, struct xdev_ext_reg *r)
{
	__atomic_store_n(slot, r, __ATOMIC_RELEASE);
}

/* The creator holds the first reference; xdev_ext_reg_install() adds the slot's. */
static inline struct xdev_ext_reg *xdev_ext_reg_new(enum xdev_ext_reg_kind kind,
					  const struct xdev_ext_fd_identity *id,
					  pid_t owner_pid)
{
	struct xdev_ext_reg *r = calloc(1, sizeof(*r));

	if (!r)
		return NULL;
	if (pthread_mutex_init(&r->rx_mu, NULL)) {
		free(r);
		return NULL;
	}
	atomic_init(&r->refs, 1);
	atomic_init(&r->state, XDEV_EXT_REG_ACTIVE);
	atomic_init(&r->status_flags, 0);
	r->kind = kind;
	r->release_reason = XDEV_EXT_RELEASE_NONE;
	r->id = *id;
	r->owner_pid = owner_pid;
	return r;
}

static inline void xdev_ext_reg_destroy(const struct xdev_ext_reg_env *env,
				   struct xdev_ext_reg *r)
{
	int saved = errno;

	if (env->backend && env->backend->destroy)
		env->backend->destroy(r);
	(void)pthread_mutex_destroy(&r->rx_mu);
	free(r);
	errno = saved;
}

/* Never call with a shard lock or xdev_ext_privfd_mu held: it may destroy. */
static inline void xdev_ext_reg_put(const struct xdev_ext_reg_env *env,
			       struct xdev_ext_reg *r)
{
	if (r && atomic_fetch_sub_explicit(&r->refs, 1,
					   memory_order_acq_rel) == 1)
		xdev_ext_reg_destroy(env, r);
}

static inline void xdev_ext_reg_reap(const struct xdev_ext_reg_env *env,
				struct xdev_ext_reg *reap)
{
	while (reap) {
		struct xdev_ext_reg *next = reap->reap_next;

		xdev_ext_reg_destroy(env, reap);
		reap = next;
	}
}

/* Two atomic loads and no lock: the cost of an unregistered descriptor. */
static inline bool xdev_ext_reg_maybe_registered(int fd)
{
	struct xdev_ext_reg **chunk;

	if (!xdev_ext_reg_fd_in_range(fd))
		return false;
	chunk = atomic_load_explicit(
		&xdev_ext_reg_chunks[(unsigned int)fd >> XDEV_EXT_REG_CHUNK_SHIFT],
		memory_order_acquire);
	return chunk && __atomic_load_n(
		&chunk[(unsigned int)fd & (XDEV_EXT_REG_CHUNK_SLOTS - 1)],
		__ATOMIC_RELAXED);
}

/* Look up @fd and take an in-flight reference; the lock is held only for
 * the lookup.  Drop the reference with xdev_ext_reg_put(). */
static inline struct xdev_ext_reg *xdev_ext_reg_get(int fd)
{
	struct xdev_ext_reg **slot;
	struct xdev_ext_reg *r = NULL;

	if (!xdev_ext_reg_maybe_registered(fd))
		return NULL;
	xdev_ext_reg_lock(fd);
	slot = xdev_ext_reg_slot(fd, false);
	if (slot) {
		r = xdev_ext_reg_slot_load(slot);
		if (r)
			atomic_fetch_add_explicit(&r->refs, 1,
						  memory_order_relaxed);
	}
	xdev_ext_reg_unlock(fd);
	return r;
}

static inline int xdev_ext_reg_check_identity(const struct xdev_ext_reg_env *env,
					 int fd,
					 const struct xdev_ext_fd_identity *want)
{
	struct xdev_ext_fd_identity now;
	struct stat st;

	if (env->real->fstat(fd, &st))
		return errno ? -errno : -EBADF;
	xdev_ext_fd_identity_from_stat(&st, &now);
	return xdev_ext_fd_identity_equal(&now, want) ? 0 : -ESTALE;
}

/*
 * Point @fd's slot at @r after confirming, under the shard lock, that @fd
 * still names the file @r was registered for: another thread may have closed
 * and reused the number while the registration was being built.  Returns 0,
 * -EBADF, -ERANGE (beyond the table), -ESTALE or -ENOMEM; errno is preserved.
 */
static inline int xdev_ext_reg_install(const struct xdev_ext_reg_env *env, int fd,
				  struct xdev_ext_reg *r)
{
	struct xdev_ext_reg *old = NULL;
	struct xdev_ext_reg **slot;
	int saved = errno;
	int ret;

	if (fd < 0 || xdev_ext_privfd_test(fd))
		return -EBADF;
	if (!xdev_ext_reg_fd_in_range(fd))
		return -ERANGE;
	xdev_ext_reg_lock(fd);
	ret = xdev_ext_reg_check_identity(env, fd, &r->id);
	if (!ret) {
		slot = xdev_ext_reg_slot(fd, true);
		if (slot) {
			atomic_fetch_add_explicit(&r->refs, 1,
						  memory_order_relaxed);
			old = xdev_ext_reg_slot_load(slot);
			xdev_ext_reg_slot_store(slot, r);
		} else {
			ret = -ENOMEM;
		}
	}
	xdev_ext_reg_unlock(fd);
	xdev_ext_reg_put(env, old);
	errno = saved;
	return ret;
}

/* F_SETFL only refreshes the cached flags; it never stops the fast path. */
static inline void xdev_ext_reg_refresh_status_flags(int fd, int flags)
{
	struct xdev_ext_reg **slot;
	struct xdev_ext_reg *r;

	if (!xdev_ext_reg_maybe_registered(fd))
		return;
	xdev_ext_reg_lock(fd);
	slot = xdev_ext_reg_slot(fd, false);
	r = slot ? xdev_ext_reg_slot_load(slot) : NULL;
	if (r)
		atomic_store_explicit(&r->status_flags, flags,
				      memory_order_relaxed);
	xdev_ext_reg_unlock(fd);
}

static inline bool xdev_ext_reg_release(const struct xdev_ext_reg_env *env,
				   struct xdev_ext_reg *r,
				   enum xdev_ext_release_reason why);

/*
 * dup2, dup3, dup or F_DUPFD put an alias of @r where the table cannot hold
 * it: at or above XDEV_EXT_REG_FD_LIMIT, or in a chunk that could not be
 * allocated.  Calls on that alias reach libc, so a receive registration
 * hands new datagrams back to the kernel stack, as after fork or
 * SCM_RIGHTS; the ring is still drained through the aliases in the table.
 * Other kinds keep serving: libc on the alias reaches the same file.  Call
 * with no lock held.
 */
static inline void xdev_ext_reg_escaped(const struct xdev_ext_reg_env *env,
				   struct xdev_ext_reg *r)
{
	if (r && r->kind == XDEV_EXT_REG_DGRAM_RX)
		(void)xdev_ext_reg_release(env, r, XDEV_EXT_RELEASE_ALIAS);
}

/* Caller holds the shard locks of both numbers.  Returns the registration
 * that @newfd's slot held, for the caller to put after unlocking.  When
 * @newfd cannot hold @oldfd's registration, *escaped gets it with an
 * in-flight reference, for xdev_ext_reg_escaped() and a put after unlocking. */
static inline struct xdev_ext_reg *xdev_ext_reg_copy_locked(int oldfd, int newfd,
						  struct xdev_ext_reg **escaped)
{
	struct xdev_ext_reg **src = xdev_ext_reg_slot(oldfd, false);
	struct xdev_ext_reg *r = src ? xdev_ext_reg_slot_load(src) : NULL;
	struct xdev_ext_reg **dst = xdev_ext_reg_slot(newfd, r != NULL);
	struct xdev_ext_reg *old;

	xdev_ext_epoll_seen_set(newfd, xdev_ext_epoll_seen_get(oldfd));
	if (!dst) {
		if (r) {
			atomic_fetch_add_explicit(&r->refs, 1,
						  memory_order_relaxed);
			*escaped = r;
		}
		return NULL;
	}
	if (r)
		atomic_fetch_add_explicit(&r->refs, 1, memory_order_relaxed);
	old = xdev_ext_reg_slot_load(dst);
	xdev_ext_reg_slot_store(dst, r);
	return old;
}

/*
 * After a successful dup or F_DUPFD.  The new number was handed out by an
 * unlocked real call, so it inherits a registration only if it still names
 * that registration's file.  @held and @seen are @oldfd's registration (an
 * in-flight reference, or NULL) and epoll mark taken before the real call:
 * a close(oldfd) on another thread may clear both before this runs, while
 * the new number is still an alias of the registered file.  @oldfd is
 * looked up again for a registration installed during the call.
 */
static inline void xdev_ext_reg_copy_checked(const struct xdev_ext_reg_env *env,
					struct xdev_ext_reg *held, bool seen,
					int oldfd, int newfd)
{
	struct xdev_ext_reg *now = xdev_ext_reg_get(oldfd);
	struct xdev_ext_reg *escaped = NULL;
	struct xdev_ext_reg *next = NULL;
	struct xdev_ext_reg *old = NULL;
	struct xdev_ext_reg **slot;

	seen = seen || xdev_ext_epoll_seen_get(oldfd);
	if (!held && !now && !xdev_ext_reg_maybe_registered(newfd)) {
		xdev_ext_epoll_seen_set(newfd, seen);
		return;
	}
	xdev_ext_reg_lock(newfd);
	if (held && !xdev_ext_reg_check_identity(env, newfd, &held->id))
		next = held;
	else if (now && now != held &&
		 !xdev_ext_reg_check_identity(env, newfd, &now->id))
		next = now;
	slot = xdev_ext_reg_slot(newfd, next != NULL);
	if (slot) {
		if (next)
			atomic_fetch_add_explicit(&next->refs, 1,
						  memory_order_relaxed);
		old = xdev_ext_reg_slot_load(slot);
		xdev_ext_reg_slot_store(slot, next);
	} else {
		/* @held and @now are referenced until after the release. */
		escaped = next;
	}
	xdev_ext_epoll_seen_set(newfd, seen);
	xdev_ext_reg_unlock(newfd);
	xdev_ext_reg_escaped(env, escaped);
	xdev_ext_reg_put(env, old);
	xdev_ext_reg_put(env, now);
}

/*
 * Run @call, a real close in some form (close itself, or fclose/freopen of
 * the stream on @fd, which close inside libc), under @fd's shard lock and
 * forget @fd's slot whatever it returns: the number is released even when
 * the close reports EINTR or EIO.  Returns the call's result with its errno.
 * Cancellation acts only before the lock is taken or after it is released.
 */
static inline int xdev_ext_reg_close_call(const struct xdev_ext_reg_env *env, int fd,
				     int (*call)(void *arg), void *arg)
{
	struct xdev_ext_reg *old = NULL;
	struct xdev_ext_reg **slot;
	int ret, saved, cancel_state;

	pthread_testcancel();
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	xdev_ext_reg_lock(fd);
	ret = call(arg);
	saved = errno;
	slot = xdev_ext_reg_slot(fd, false);
	if (slot) {
		old = xdev_ext_reg_slot_load(slot);
		xdev_ext_reg_slot_store(slot, NULL);
	}
	xdev_ext_epoll_seen_set(fd, false);
	xdev_ext_reg_unlock(fd);
	xdev_ext_reg_put(env, old);
	(void)pthread_setcancelstate(cancel_state, NULL);
	pthread_testcancel();
	errno = saved;
	return ret;
}

struct xdev_ext_reg_real_close {
	const struct xdev_ext_fd_real_ops *real;
	int fd;
};

static inline int xdev_ext_reg_real_close_call(void *arg)
{
	const struct xdev_ext_reg_real_close *c = arg;

	return c->real->close(c->fd);
}

static inline int xdev_ext_reg_close(const struct xdev_ext_reg_env *env, int fd)
{
	struct xdev_ext_reg_real_close c = { .real = env->real, .fd = fd };

	/* The application never sees a private descriptor as open.  The test
	 * is lock-free: a number only becomes private while it is unused, and
	 * closing an unused number is already a bug in the caller. */
	if (xdev_ext_privfd_test(fd)) {
		pthread_testcancel();
		errno = EBADF;
		return -1;
	}
	return xdev_ext_reg_close_call(env, fd, xdev_ext_reg_real_close_call, &c);
}

/*
 * Drop @fd's slot if it still holds @r, after a per-call identity check
 * found that @fd no longer names @r's file (it was closed or replaced
 * without going through libc).  Other aliases of @r keep their slots.  The
 * caller holds its own reference to @r.  Returns whether the slot was
 * dropped.
 */
static inline bool xdev_ext_reg_forget(const struct xdev_ext_reg_env *env, int fd,
				  struct xdev_ext_reg *r)
{
	struct xdev_ext_reg **slot;
	bool dropped = false;

	if (!xdev_ext_reg_maybe_registered(fd))
		return false;
	xdev_ext_reg_lock(fd);
	slot = xdev_ext_reg_slot(fd, false);
	if (slot && xdev_ext_reg_slot_load(slot) == r) {
		xdev_ext_reg_slot_store(slot, NULL);
		dropped = true;
	}
	xdev_ext_reg_unlock(fd);
	if (dropped)
		xdev_ext_reg_put(env, r);
	return dropped;
}

static inline int xdev_ext_reg_dup(const struct xdev_ext_reg_env *env, int oldfd)
{
	struct xdev_ext_reg *held;
	int ret, saved;
	bool seen;

	if (xdev_ext_privfd_test(oldfd)) {
		errno = EBADF;
		return -1;
	}
	held = xdev_ext_reg_get(oldfd);
	seen = xdev_ext_epoll_seen_get(oldfd);
	ret = env->real->dup(oldfd);
	saved = errno;
	if (ret >= 0)
		xdev_ext_reg_copy_checked(env, held, seen, oldfd, ret);
	xdev_ext_reg_put(env, held);
	errno = saved;
	return ret;
}

/* fcntl(oldfd, F_DUPFD or F_DUPFD_CLOEXEC, minfd). */
static inline int xdev_ext_reg_dupfd(const struct xdev_ext_reg_env *env, int oldfd,
				int cmd, int minfd)
{
	struct xdev_ext_reg *held;
	int ret, saved;
	bool seen;

	if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC) {
		errno = EINVAL;
		return -1;
	}
	if (xdev_ext_privfd_test(oldfd)) {
		errno = EBADF;
		return -1;
	}
	held = xdev_ext_reg_get(oldfd);
	seen = xdev_ext_epoll_seen_get(oldfd);
	ret = env->real->fcntl_dupfd(oldfd, cmd, minfd);
	saved = errno;
	if (ret >= 0)
		xdev_ext_reg_copy_checked(env, held, seen, oldfd, ret);
	xdev_ext_reg_put(env, held);
	errno = saved;
	return ret;
}

/* dup2/dup3 with oldfd != newfd and a non-private oldfd. */
static inline int xdev_ext_reg_dup_over(const struct xdev_ext_reg_env *env, int oldfd,
				   int newfd, bool use_dup3, int flags)
{
	bool privfd_locked = newfd >= XDEV_EXT_PRIVFD_FLOOR_MIN;
	struct xdev_ext_reg *escaped = NULL;
	struct xdev_ext_reg *old = NULL;
	bool moved = false;
	int ret, saved, cancel_state;

	/* dup2 and dup3 are not cancellation points, but the rollback close
	 * below is; it must not unwind with these locks held. */
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	/* Holding the private set across the real call also keeps a number
	 * from being adopted between the check and the call. */
	if (privfd_locked) {
		struct xdev_ext_privfd_entry *entry;

		xdev_ext_privfd_lock();
		entry = xdev_ext_privfd_find_locked(newfd);
		if (entry) {
			(void)xdev_ext_privfd_migrate_locked(env->real, entry);
			moved = true;
		}
	}
	xdev_ext_reg_lock_pair(oldfd, newfd);
	ret = use_dup3 ? env->real->dup3(oldfd, newfd, flags) :
			 env->real->dup2(oldfd, newfd);
	saved = errno;
	if (ret >= 0)
		old = xdev_ext_reg_copy_locked(oldfd, newfd, &escaped);
	else if (moved)
		/* The private file now lives elsewhere; keep the number
		 * unused, as the application saw it. */
		(void)env->real->close(newfd);
	xdev_ext_reg_unlock_pair(oldfd, newfd);
	if (privfd_locked)
		xdev_ext_privfd_unlock();
	xdev_ext_reg_put(env, old);
	xdev_ext_reg_escaped(env, escaped);
	xdev_ext_reg_put(env, escaped);
	(void)pthread_setcancelstate(cancel_state, NULL);
	errno = saved;
	return ret;
}

static inline int xdev_ext_reg_dup2(const struct xdev_ext_reg_env *env, int oldfd,
			       int newfd)
{
	if (xdev_ext_privfd_test(oldfd)) {
		errno = EBADF;
		return -1;
	}
	/* dup2(fd, fd) only validates fd and leaves the table alone. */
	if (oldfd == newfd)
		return env->real->dup2(oldfd, newfd);
	return xdev_ext_reg_dup_over(env, oldfd, newfd, false, 0);
}

static inline int xdev_ext_reg_dup3(const struct xdev_ext_reg_env *env, int oldfd,
			       int newfd, int flags)
{
	/* The kernel rejects these before it looks at either descriptor. */
	if ((flags & ~O_CLOEXEC) || oldfd == newfd)
		return env->real->dup3(oldfd, newfd, flags);
	if (xdev_ext_privfd_test(oldfd)) {
		errno = EBADF;
		return -1;
	}
	return xdev_ext_reg_dup_over(env, oldfd, newfd, true, flags);
}

/* Caller holds every shard lock.  Drops the slots in [first, last] and links
 * the registrations whose last reference went with them onto @reap. */
static inline struct xdev_ext_reg *
xdev_ext_reg_drop_range_locked(unsigned int first, unsigned int last,
			  struct xdev_ext_reg *reap)
{
	unsigned int fd = first;

	if (first >= XDEV_EXT_REG_FD_LIMIT)
		return reap;
	if (last >= XDEV_EXT_REG_FD_LIMIT)
		last = XDEV_EXT_REG_FD_LIMIT - 1;
	xdev_ext_epoll_seen_clear_range(first, last);
	while (fd <= last) {
		unsigned int idx = fd >> XDEV_EXT_REG_CHUNK_SHIFT;
		unsigned int end = (idx + 1) * XDEV_EXT_REG_CHUNK_SLOTS - 1;
		struct xdev_ext_reg **chunk;

		if (end > last)
			end = last;
		chunk = atomic_load_explicit(&xdev_ext_reg_chunks[idx],
					     memory_order_acquire);
		for (; chunk && fd <= end; fd++) {
			struct xdev_ext_reg **slot =
				&chunk[fd & (XDEV_EXT_REG_CHUNK_SLOTS - 1)];
			struct xdev_ext_reg *r = xdev_ext_reg_slot_load(slot);
			unsigned int left;

			if (!r)
				continue;
			xdev_ext_reg_slot_store(slot, NULL);
			left = atomic_fetch_sub_explicit(&r->refs, 1,
							 memory_order_acq_rel);
			if (left == 1) {
				r->reap_next = reap;
				reap = r;
			}
		}
		fd = end + 1;
	}
	return reap;
}

/*
 * close_range() that steps around private descriptors: one real call per
 * span between them, stopping at the first error.  Spans closed without
 * CLOSE_RANGE_CLOEXEC lose their slots.  Splitting also keeps
 * CLOSE_RANGE_UNSHARE correct: only the first call unshares, and its copy of
 * the table keeps every descriptor outside that span.
 */
static inline int xdev_ext_reg_close_range(const struct xdev_ext_reg_env *env,
				      unsigned int first, unsigned int last,
				      int flags)
{
	struct xdev_ext_fd_span spans[XDEV_EXT_PRIVFD_MAX_SPANS];
	struct xdev_ext_reg *reap = NULL;
	int saved = errno;
	unsigned int n, i;
	int ret = 0;

	/* EINVAL before the kernel looks at any descriptor. */
	if (first > last)
		return env->real->close_range(first, last, flags);
	xdev_ext_reg_lock_all();
	n = xdev_ext_privfd_spans_locked(first, last, spans);
	/* Only private descriptors in range: none is open to the application,
	 * but unknown flags still fail as they would natively. */
	if (!n && ((unsigned int)flags &
		   ~(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC))) {
		ret = -1;
		saved = EINVAL;
	}
	for (i = 0; i < n; i++) {
		ret = env->real->close_range(spans[i].first, spans[i].last,
					     flags);
		if (ret < 0) {
			saved = errno;
			break;
		}
		if (!((unsigned int)flags & CLOSE_RANGE_CLOEXEC))
			reap = xdev_ext_reg_drop_range_locked(spans[i].first,
							 spans[i].last, reap);
	}
	xdev_ext_reg_unlock_all();
	xdev_ext_reg_reap(env, reap);
	errno = saved;
	return ret;
}

static inline enum xdev_ext_reg_state xdev_ext_reg_state_of(const struct xdev_ext_reg *r)
{
	return (enum xdev_ext_reg_state)atomic_load_explicit(&r->state,
							memory_order_acquire);
}

/* Whether calls on this registration may take the fast path in @pid.  A
 * forked child never touches the parent's receive ring; write registrations
 * keep serving there. */
static inline bool xdev_ext_reg_serves(const struct xdev_ext_reg *r, pid_t pid)
{
	enum xdev_ext_reg_state state = xdev_ext_reg_state_of(r);

	if (r->kind == XDEV_EXT_REG_DGRAM_RX)
		return r->owner_pid == pid &&
		       (state == XDEV_EXT_REG_ACTIVE || state == XDEV_EXT_REG_RELEASING);
	return state == XDEV_EXT_REG_ACTIVE;
}

/* ACTIVE -> RELEASING.  Only the caller that wins the transition records
 * the reason and runs the hook. */
static inline bool xdev_ext_reg_release(const struct xdev_ext_reg_env *env,
				   struct xdev_ext_reg *r,
				   enum xdev_ext_release_reason why)
{
	int expected = XDEV_EXT_REG_ACTIVE;

	if (!atomic_compare_exchange_strong_explicit(
		    &r->state, &expected, XDEV_EXT_REG_RELEASING,
		    memory_order_acq_rel, memory_order_acquire))
		return false;
	__atomic_store_n(&r->release_reason, why, __ATOMIC_RELEASE);
	if (env->backend && env->backend->release)
		env->backend->release(r, why);
	return true;
}

/* RELEASING -> RELEASED, once the receive ring has been delivered empty. */
static inline bool xdev_ext_reg_retire(const struct xdev_ext_reg_env *env,
				  struct xdev_ext_reg *r)
{
	int expected = XDEV_EXT_REG_RELEASING;

	if (!atomic_compare_exchange_strong_explicit(
		    &r->state, &expected, XDEV_EXT_REG_RELEASED,
		    memory_order_acq_rel, memory_order_acquire))
		return false;
	if (env->backend && env->backend->retire)
		env->backend->retire(r);
	return true;
}

/* ACTIVE or RELEASING -> SEQUESTERED, on an impossible ring state. */
static inline bool xdev_ext_reg_sequester(const struct xdev_ext_reg_env *env,
				     struct xdev_ext_reg *r)
{
	int state = atomic_load_explicit(&r->state, memory_order_acquire);

	while (state == XDEV_EXT_REG_ACTIVE || state == XDEV_EXT_REG_RELEASING) {
		if (atomic_compare_exchange_weak_explicit(
			    &r->state, &state, XDEV_EXT_REG_SEQUESTERED,
			    memory_order_acq_rel, memory_order_acquire)) {
			if (env->backend && env->backend->sequester)
				env->backend->sequester(r);
			return true;
		}
	}
	return false;
}

#endif /* XDEV_EXT_PRELOAD_REG_H */
