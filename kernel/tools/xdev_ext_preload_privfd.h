/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_PRIVFD_H
#define XDEV_EXT_PRELOAD_PRIVFD_H

/*
 * Descriptors the front end owns (the NVMe namespace anchor, XSK, bpf_link
 * and epoll mirrors) live in the application's fd table but must stay
 * invisible to it: close() of one fails with EBADF, dup2()/dup3() onto one
 * first moves it to a fresh number, and close_range() steps around it.  All
 * of them are close-on-exec and sit at or above a floor of
 * max(64, min(soft RLIMIT_NOFILE - 64, 1000)).
 *
 * Every real call goes through struct xdev_ext_fd_real_ops so host tests run the
 * same code against libc.  Lock order: xdev_ext_privfd_mu, then the registration
 * shard locks (xdev_ext_preload_reg.h).  An owner's relocated() callback runs
 * under xdev_ext_privfd_mu and must do nothing but record the new number.
 *
 * close() is a cancellation point.  A request acting inside it would unwind
 * with xdev_ext_privfd_mu held and stop every later adoption, dup2() onto a high
 * number and fork(), so adoption and the front end's own close run with
 * cancellation disabled; neither is a cancellation point for the caller.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

/* Always consume the ABI from this source tree. */
#include "../include/uapi/linux/close_range.h"

#define XDEV_EXT_PRIVFD_FD_LIMIT		65536
#define XDEV_EXT_PRIVFD_MAX			64U
#define XDEV_EXT_PRIVFD_MAX_SPANS		(XDEV_EXT_PRIVFD_MAX + 1U)
#define XDEV_EXT_PRIVFD_RLIMIT_MARGIN	64ULL
/* A dup2() target below XDEV_EXT_PRIVFD_FLOOR_MIN is never private. */
#define XDEV_EXT_PRIVFD_FLOOR_MIN		64
#define XDEV_EXT_PRIVFD_FLOOR_MAX		1000

struct xdev_ext_fd_real_ops {
	int (*close)(int fd);
	int (*dup)(int fd);
	int (*dup2)(int oldfd, int newfd);
	int (*dup3)(int oldfd, int newfd, int flags);
	int (*close_range)(unsigned int first, unsigned int last, int flags);
	/* fcntl(fd, F_DUPFD or F_DUPFD_CLOEXEC, minfd) */
	int (*fcntl_dupfd)(int fd, int cmd, int minfd);
	int (*fstat)(int fd, struct stat *st);
};

enum xdev_ext_privfd_role {
	XDEV_EXT_PRIVFD_NG_ANCHOR = 1,
	XDEV_EXT_PRIVFD_XSK,
	XDEV_EXT_PRIVFD_LINK,
	XDEV_EXT_PRIVFD_MIRROR,
};

/* role == 0 marks a free entry. */
struct xdev_ext_privfd_entry {
	int fd;
	enum xdev_ext_privfd_role role;
	void *owner;
	void (*relocated)(void *owner, int oldfd, int newfd);
};

struct xdev_ext_fd_span {
	unsigned int first;
	unsigned int last;
};

/* Membership bits, read without the lock by the close/dup fast paths. */
static uint64_t xdev_ext_privfd_bits[XDEV_EXT_PRIVFD_FD_LIMIT / 64];
static struct xdev_ext_privfd_entry xdev_ext_privfd_table[XDEV_EXT_PRIVFD_MAX];
static pthread_mutex_t xdev_ext_privfd_mu = PTHREAD_MUTEX_INITIALIZER;
static int xdev_ext_privfd_floor = XDEV_EXT_PRIVFD_FLOOR_MIN;

static inline int xdev_ext_privfd_floor_for_nofile(unsigned long long soft)
{
	unsigned long long floor = 0;

	if (soft > XDEV_EXT_PRIVFD_RLIMIT_MARGIN)
		floor = soft - XDEV_EXT_PRIVFD_RLIMIT_MARGIN;
	if (floor > XDEV_EXT_PRIVFD_FLOOR_MAX)
		floor = XDEV_EXT_PRIVFD_FLOOR_MAX;
	if (floor < XDEV_EXT_PRIVFD_FLOOR_MIN)
		floor = XDEV_EXT_PRIVFD_FLOOR_MIN;
	return (int)floor;
}

/* Set once by the constructor from the soft RLIMIT_NOFILE. */
static inline void xdev_ext_privfd_set_floor(int floor)
{
	if (floor < XDEV_EXT_PRIVFD_FLOOR_MIN)
		floor = XDEV_EXT_PRIVFD_FLOOR_MIN;
	__atomic_store_n(&xdev_ext_privfd_floor, floor, __ATOMIC_RELAXED);
}

static inline void xdev_ext_privfd_lock(void)
{
	(void)pthread_mutex_lock(&xdev_ext_privfd_mu);
}

static inline void xdev_ext_privfd_unlock(void)
{
	(void)pthread_mutex_unlock(&xdev_ext_privfd_mu);
}

/* Lock-free membership test for the close/dup fast paths. */
static inline bool xdev_ext_privfd_test(int fd)
{
	if (fd < 0 || fd >= XDEV_EXT_PRIVFD_FD_LIMIT)
		return false;
	return __atomic_load_n(&xdev_ext_privfd_bits[fd / 64], __ATOMIC_ACQUIRE) &
	       (UINT64_C(1) << (fd % 64));
}

static inline void xdev_ext_privfd_mark_locked(int fd, bool member)
{
	uint64_t mask = UINT64_C(1) << (fd % 64);

	if (member)
		__atomic_fetch_or(&xdev_ext_privfd_bits[fd / 64], mask,
				  __ATOMIC_RELEASE);
	else
		__atomic_fetch_and(&xdev_ext_privfd_bits[fd / 64], ~mask,
				   __ATOMIC_RELEASE);
}

static inline struct xdev_ext_privfd_entry *xdev_ext_privfd_find_locked(int fd)
{
	unsigned int i;

	if (!xdev_ext_privfd_test(fd))
		return NULL;
	for (i = 0; i < XDEV_EXT_PRIVFD_MAX; i++)
		if (xdev_ext_privfd_table[i].role && xdev_ext_privfd_table[i].fd == fd)
			return &xdev_ext_privfd_table[i];
	return NULL;
}

/*
 * Move a descriptor the front end just created to a private number with
 * close-on-exec set.  The original number is closed in every case, so a
 * refused adoption needs no cleanup.  *fdp holds the original on entry and
 * the private number (or -1) on return; it is written under xdev_ext_privfd_mu,
 * as relocated() writes it, so the owner never records a stale number.
 * Returns 0 or a negative errno; errno is preserved.
 */
static inline int
xdev_ext_privfd_adopt(const struct xdev_ext_fd_real_ops *real, int *fdp,
		 enum xdev_ext_privfd_role role, void *owner,
		 void (*relocated)(void *owner, int oldfd, int newfd))
{
	struct xdev_ext_privfd_entry *entry = NULL;
	int saved = errno;
	int fd = *fdp;
	int priv = -1;
	int ret = 0;
	int cancel_state;
	unsigned int i;

	if (fd < 0)
		return -EBADF;
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	xdev_ext_privfd_lock();
	for (i = 0; i < XDEV_EXT_PRIVFD_MAX && !entry; i++)
		if (!xdev_ext_privfd_table[i].role)
			entry = &xdev_ext_privfd_table[i];
	if (!entry) {
		ret = -EMFILE;
		goto out;
	}
	priv = real->fcntl_dupfd(fd, F_DUPFD_CLOEXEC,
				 __atomic_load_n(&xdev_ext_privfd_floor,
						 __ATOMIC_RELAXED));
	if (priv < 0) {
		ret = errno ? -errno : -EBADF;
		goto out;
	}
	if (priv >= XDEV_EXT_PRIVFD_FD_LIMIT) {
		(void)real->close(priv);
		ret = -EMFILE;
		goto out;
	}
	*entry = (struct xdev_ext_privfd_entry){
		.fd = priv,
		.role = role,
		.owner = owner,
		.relocated = relocated,
	};
	xdev_ext_privfd_mark_locked(priv, true);
out:
	(void)real->close(fd);
	*fdp = ret ? -1 : priv;
	xdev_ext_privfd_unlock();
	(void)pthread_setcancelstate(cancel_state, NULL);
	errno = saved;
	return ret;
}

/*
 * Close a private descriptor on behalf of its owner.  *fdp is read under
 * xdev_ext_privfd_mu, so a concurrent relocation cannot hand the old number, by
 * then the application's, to the real close.  A number that is not in the
 * set is never closed.  Returns 0 or -EBADF; errno is preserved.
 */
static inline int xdev_ext_privfd_close(const struct xdev_ext_fd_real_ops *real,
				   int *fdp)
{
	struct xdev_ext_privfd_entry *entry;
	int saved = errno;
	int ret = 0;
	int cancel_state;

	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	xdev_ext_privfd_lock();
	entry = xdev_ext_privfd_find_locked(*fdp);
	if (!entry) {
		ret = -EBADF;
		goto out;
	}
	(void)real->close(entry->fd);
	xdev_ext_privfd_mark_locked(entry->fd, false);
	memset(entry, 0, sizeof(*entry));
	*fdp = -1;
out:
	xdev_ext_privfd_unlock();
	(void)pthread_setcancelstate(cancel_state, NULL);
	errno = saved;
	return ret;
}

/*
 * dup2()/dup3() is about to replace private descriptor entry->fd.  Copy the
 * private file to a fresh number at or above the floor and tell the owner.
 * The old number still refers to the private file until the caller's real
 * call replaces it; if that call fails the caller closes the old number, so
 * the application keeps seeing it unused.  When no copy can be made the
 * application's call still goes ahead: the entry is dropped and the owner is
 * told the object is gone (newfd -1) and must stop using it.  Returns the new
 * number or -1.
 */
static inline int
xdev_ext_privfd_migrate_locked(const struct xdev_ext_fd_real_ops *real,
			  struct xdev_ext_privfd_entry *entry)
{
	void (*relocated)(void *owner, int oldfd, int newfd) = entry->relocated;
	void *owner = entry->owner;
	int oldfd = entry->fd;
	int newfd;

	newfd = real->fcntl_dupfd(oldfd, F_DUPFD_CLOEXEC,
				  __atomic_load_n(&xdev_ext_privfd_floor,
						  __ATOMIC_RELAXED));
	if (newfd >= XDEV_EXT_PRIVFD_FD_LIMIT) {
		(void)real->close(newfd);
		newfd = -1;
	}
	if (newfd < 0)
		newfd = -1;
	xdev_ext_privfd_mark_locked(oldfd, false);
	if (newfd >= 0) {
		entry->fd = newfd;
		xdev_ext_privfd_mark_locked(newfd, true);
	} else {
		memset(entry, 0, sizeof(*entry));
	}
	if (relocated)
		relocated(owner, oldfd, newfd);
	return newfd;
}

/*
 * Split [first, last] (first <= last) into the spans that avoid @holes,
 * which must be sorted in ascending order.  At most nholes + 1 spans.
 */
static inline unsigned int
xdev_ext_fd_spans_split(unsigned int first, unsigned int last,
		   const unsigned int *holes, unsigned int nholes,
		   struct xdev_ext_fd_span *spans)
{
	unsigned int start = first;
	unsigned int n = 0;
	unsigned int i;

	for (i = 0; i < nholes; i++) {
		unsigned int hole = holes[i];

		if (hole < start || hole > last)
			continue;
		if (hole > start)
			spans[n++] = (struct xdev_ext_fd_span){ start, hole - 1 };
		if (hole == last)
			return n;
		start = hole + 1;
	}
	spans[n++] = (struct xdev_ext_fd_span){ start, last };
	return n;
}

/* close_range() spans that step around every private descriptor. */
static inline unsigned int
xdev_ext_privfd_spans_locked(unsigned int first, unsigned int last,
			struct xdev_ext_fd_span spans[XDEV_EXT_PRIVFD_MAX_SPANS])
{
	unsigned int holes[XDEV_EXT_PRIVFD_MAX];
	unsigned int n = 0;
	unsigned int i, j;

	for (i = 0; i < XDEV_EXT_PRIVFD_MAX; i++) {
		const struct xdev_ext_privfd_entry *entry = &xdev_ext_privfd_table[i];
		unsigned int fd;

		if (!entry->role)
			continue;
		fd = (unsigned int)entry->fd;
		if (fd < first || fd > last)
			continue;
		for (j = n; j > 0 && holes[j - 1] > fd; j--)
			holes[j] = holes[j - 1];
		holes[j] = fd;
		n++;
	}
	return xdev_ext_fd_spans_split(first, last, holes, n, spans);
}

#endif /* XDEV_EXT_PRELOAD_PRIVFD_H */
