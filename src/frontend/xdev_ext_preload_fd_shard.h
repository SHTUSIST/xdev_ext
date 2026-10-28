/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_FD_SHARD_H
#define XDEV_EXT_PRELOAD_FD_SHARD_H

#include <pthread.h>

#define XDEV_EXT_PRELOAD_FD_SHARDS 64U

struct xdev_ext_preload_fd_lockset {
	pthread_mutex_t shards[XDEV_EXT_PRELOAD_FD_SHARDS];
};

/* The preload library is built as GNU C11, so a range initializer keeps every
 * shard available before constructors or interposed libc calls can run. */
#define XDEV_EXT_PRELOAD_FD_LOCKSET_INITIALIZER { \
	.shards = { [0 ... XDEV_EXT_PRELOAD_FD_SHARDS - 1] = \
			PTHREAD_MUTEX_INITIALIZER }, \
}

static inline unsigned int xdev_ext_preload_fd_shard(int fd)
{
	return (unsigned int)fd & (XDEV_EXT_PRELOAD_FD_SHARDS - 1);
}

static inline void
xdev_ext_preload_fd_lock(struct xdev_ext_preload_fd_lockset *locks, int fd)
{
	(void)pthread_mutex_lock(&locks->shards[xdev_ext_preload_fd_shard(fd)]);
}

static inline void
xdev_ext_preload_fd_unlock(struct xdev_ext_preload_fd_lockset *locks, int fd)
{
	(void)pthread_mutex_unlock(&locks->shards[xdev_ext_preload_fd_shard(fd)]);
}

/* atfork takes every shard in ascending order.  No normal registry operation
 * holds more than one shard, and parent/child release in reverse order. */
static inline void
xdev_ext_preload_fd_lock_all(struct xdev_ext_preload_fd_lockset *locks)
{
	for (unsigned int i = 0; i < XDEV_EXT_PRELOAD_FD_SHARDS; i++)
		(void)pthread_mutex_lock(&locks->shards[i]);
}

static inline void
xdev_ext_preload_fd_unlock_all(struct xdev_ext_preload_fd_lockset *locks)
{
	for (unsigned int i = XDEV_EXT_PRELOAD_FD_SHARDS; i > 0; i--)
		(void)pthread_mutex_unlock(&locks->shards[i - 1]);
}

#endif /* XDEV_EXT_PRELOAD_FD_SHARD_H */
