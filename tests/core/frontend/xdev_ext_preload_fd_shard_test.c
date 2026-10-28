// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "xdev_ext_preload_fd_shard.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_TRUE(expr) do {                                           \
	checks++;                                                          \
	if (!(expr)) {                                                     \
		fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n",       \
			__FILE__, __LINE__, #expr);                           \
		failures++;                                               \
	}                                                                  \
} while (0)

#define EXPECT_EQ(actual, expected) do {                                \
	long long _actual = (long long)(actual);                          \
	long long _expected = (long long)(expected);                      \
	checks++;                                                          \
	if (_actual != _expected) {                                       \
		fprintf(stderr, "%s:%d: %s=%lld, expected %lld\n",       \
			__FILE__, __LINE__, #actual, _actual, _expected);      \
		failures++;                                               \
	}                                                                  \
} while (0)

struct waiter {
	struct xdev_ext_preload_fd_lockset *locks;
	int fd;
	atomic_bool started;
	atomic_bool acquired;
};

static void *lock_once(void *opaque)
{
	struct waiter *waiter = opaque;

	atomic_store_explicit(&waiter->started, true, memory_order_release);
	xdev_ext_preload_fd_lock(waiter->locks, waiter->fd);
	atomic_store_explicit(&waiter->acquired, true, memory_order_release);
	xdev_ext_preload_fd_unlock(waiter->locks, waiter->fd);
	return NULL;
}

static bool wait_until_true(atomic_bool *value)
{
	struct timespec pause = { .tv_nsec = 1000000 };

	for (unsigned int i = 0; i < 1000; i++) {
		if (atomic_load_explicit(value, memory_order_acquire))
			return true;
		nanosleep(&pause, NULL);
	}
	return false;
}

static void test_unrelated_fds_do_not_share_the_hot_lock(void)
{
	struct xdev_ext_preload_fd_lockset locks = XDEV_EXT_PRELOAD_FD_LOCKSET_INITIALIZER;
	struct waiter same = { .locks = &locks, .fd = 3 + XDEV_EXT_PRELOAD_FD_SHARDS };
	struct waiter other = { .locks = &locks, .fd = 4 };
	pthread_t same_thread;
	pthread_t other_thread;

	EXPECT_EQ(xdev_ext_preload_fd_shard(3), xdev_ext_preload_fd_shard(same.fd));
	EXPECT_TRUE(xdev_ext_preload_fd_shard(3) != xdev_ext_preload_fd_shard(other.fd));
	xdev_ext_preload_fd_lock(&locks, 3);
	EXPECT_EQ(pthread_create(&same_thread, NULL, lock_once, &same), 0);
	EXPECT_EQ(pthread_create(&other_thread, NULL, lock_once, &other), 0);
	EXPECT_TRUE(wait_until_true(&same.started));
	EXPECT_TRUE(wait_until_true(&other.started));
	EXPECT_TRUE(wait_until_true(&other.acquired));
	EXPECT_TRUE(!atomic_load_explicit(&same.acquired, memory_order_acquire));
	xdev_ext_preload_fd_unlock(&locks, 3);
	EXPECT_EQ(pthread_join(other_thread, NULL), 0);
	EXPECT_EQ(pthread_join(same_thread, NULL), 0);
	EXPECT_TRUE(atomic_load_explicit(&same.acquired, memory_order_acquire));
}

static void test_atfork_order_covers_every_shard(void)
{
	struct xdev_ext_preload_fd_lockset locks = XDEV_EXT_PRELOAD_FD_LOCKSET_INITIALIZER;

	xdev_ext_preload_fd_lock_all(&locks);
	for (unsigned int i = 0; i < XDEV_EXT_PRELOAD_FD_SHARDS; i++)
		EXPECT_EQ(pthread_mutex_trylock(&locks.shards[i]), EBUSY);
	xdev_ext_preload_fd_unlock_all(&locks);
	for (unsigned int i = 0; i < XDEV_EXT_PRELOAD_FD_SHARDS; i++) {
		EXPECT_EQ(pthread_mutex_trylock(&locks.shards[i]), 0);
		EXPECT_EQ(pthread_mutex_unlock(&locks.shards[i]), 0);
	}
}

int main(void)
{
	EXPECT_EQ(XDEV_EXT_PRELOAD_FD_SHARDS, 64);
	EXPECT_TRUE((XDEV_EXT_PRELOAD_FD_SHARDS &
		    (XDEV_EXT_PRELOAD_FD_SHARDS - 1)) == 0);
	test_unrelated_fds_do_not_share_the_hot_lock();
	test_atfork_order_covers_every_shard();
	printf("xdev_ext_preload_fd_shard: %u checks, %u failures\n", checks,
	       failures);
	return failures ? 1 : 0;
}
