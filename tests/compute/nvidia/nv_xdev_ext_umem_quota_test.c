/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel-open/nvidia/nv-xdev_ext-umem-quota.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(expected, actual)                                             \
	do {                                                                     \
		long long _expected = (long long)(expected);                       \
		long long _actual = (long long)(actual);                           \
		checks++;                                                        \
		if (_expected != _actual) {                                     \
			fprintf(stderr, "%s:%d: expected %lld, got %lld\n",      \
				__FILE__, __LINE__, _expected, _actual);             \
			failures++;                                               \
		}                                                                \
	} while (0)

struct quota_fixture {
	struct nv_xdev_ext_umem_quota quota;
	pthread_mutex_t lock;
};

struct quota_thread {
	struct quota_fixture *fixture;
	int result;
};

static void *reserve_one(void *private)
{
	struct quota_thread *thread = private;

	pthread_mutex_lock(&thread->fixture->lock);
	thread->result = nv_xdev_ext_umem_quota_reserve(&thread->fixture->quota,
						   4096, 1);
	pthread_mutex_unlock(&thread->fixture->lock);
	return NULL;
}

static void *release_one(void *private)
{
	struct quota_thread *thread = private;

	pthread_mutex_lock(&thread->fixture->lock);
	thread->result = nv_xdev_ext_umem_quota_release(&thread->fixture->quota,
						   4096, 1);
	pthread_mutex_unlock(&thread->fixture->lock);
	return NULL;
}

static void test_validation_overflow_and_exact_release(void)
{
	struct nv_xdev_ext_umem_quota quota = {
		.max_bytes = 8192,
		.max_buffers = 2,
	};
	struct nv_xdev_ext_umem_quota before;

	EXPECT_EQ(-EINVAL, nv_xdev_ext_umem_quota_reserve(NULL, 1, 1));
	EXPECT_EQ(-EINVAL, nv_xdev_ext_umem_quota_reserve(&quota, 0, 1));
	EXPECT_EQ(-EINVAL, nv_xdev_ext_umem_quota_reserve(&quota, 1, 0));
	EXPECT_EQ(0, nv_xdev_ext_umem_quota_reserve(&quota, 4096, 1));
	EXPECT_EQ(0, nv_xdev_ext_umem_quota_reserve(&quota, 4096, 3));
	EXPECT_EQ(-ENOSPC, nv_xdev_ext_umem_quota_reserve(&quota, 1, 1));
	EXPECT_EQ(8192, quota.bytes);
	EXPECT_EQ(4, quota.pages);
	EXPECT_EQ(2, quota.buffers);

	before = quota;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_umem_quota_release(&quota, 8193, 1));
	EXPECT_EQ(0, memcmp(&before, &quota, sizeof(quota)));
	EXPECT_EQ(-EINVAL, nv_xdev_ext_umem_quota_release(&quota, 1, 5));
	EXPECT_EQ(0, memcmp(&before, &quota, sizeof(quota)));
	EXPECT_EQ(0, nv_xdev_ext_umem_quota_release(&quota, 4096, 3));
	EXPECT_EQ(4096, quota.bytes);
	EXPECT_EQ(1, quota.pages);
	EXPECT_EQ(1, quota.buffers);
	EXPECT_EQ(0, nv_xdev_ext_umem_quota_release(&quota, 4096, 1));
	EXPECT_EQ(0, quota.bytes);
	EXPECT_EQ(0, quota.pages);
	EXPECT_EQ(0, quota.buffers);
	before = quota;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_umem_quota_release(&quota, 4096, 1));
	EXPECT_EQ(0, memcmp(&before, &quota, sizeof(quota)));

	quota.bytes = UINT64_MAX;
	quota.pages = UINT64_MAX;
	quota.buffers = UINT32_MAX;
	quota.max_bytes = 0;
	quota.max_buffers = 0;
	EXPECT_EQ(-EOVERFLOW, nv_xdev_ext_umem_quota_reserve(&quota, 1, 1));
}

static void test_locked_concurrent_reservation_never_oversubscribes(void)
{
	enum { THREADS = 64, LIMIT = 17 };
	struct quota_fixture fixture = {
		.quota = {
			.max_bytes = LIMIT * 4096,
			.max_buffers = LIMIT,
		},
		.lock = PTHREAD_MUTEX_INITIALIZER,
	};
	struct quota_thread threads[THREADS];
	pthread_t tids[THREADS];
	unsigned int accepted = 0;

	for (unsigned int i = 0; i < THREADS; i++) {
		threads[i].fixture = &fixture;
		threads[i].result = -999;
		EXPECT_EQ(0, pthread_create(&tids[i], NULL, reserve_one,
					    &threads[i]));
	}
	for (unsigned int i = 0; i < THREADS; i++) {
		EXPECT_EQ(0, pthread_join(tids[i], NULL));
		if (!threads[i].result)
			accepted++;
		else
			EXPECT_EQ(-ENOSPC, threads[i].result);
	}
	EXPECT_EQ(LIMIT, accepted);
	EXPECT_EQ(LIMIT * 4096, fixture.quota.bytes);
	EXPECT_EQ(LIMIT, fixture.quota.pages);
	EXPECT_EQ(LIMIT, fixture.quota.buffers);

	for (unsigned int i = 0; i < accepted; i++) {
		threads[i].fixture = &fixture;
		threads[i].result = -999;
		EXPECT_EQ(0, pthread_create(&tids[i], NULL, release_one,
					    &threads[i]));
	}
	for (unsigned int i = 0; i < accepted; i++) {
		EXPECT_EQ(0, pthread_join(tids[i], NULL));
		EXPECT_EQ(0, threads[i].result);
	}
	EXPECT_EQ(0, fixture.quota.bytes);
	EXPECT_EQ(0, fixture.quota.pages);
	EXPECT_EQ(0, fixture.quota.buffers);
	pthread_mutex_destroy(&fixture.lock);
}

/*
 * Pin charge fixture: the tracker stands in for the driver's global quota,
 * locked_vm/locked_limit for the pinning mm's locked_vm and RLIMIT_MEMLOCK.
 */
struct pin_owner {
	struct nv_xdev_ext_umem_quota quota;
	uint64_t locked_vm;
	uint64_t locked_limit;
	unsigned int lock_calls;
	unsigned int unlock_calls;
};

static nv_xdev_ext_quota_u32 owner_reserve(void *private, nv_xdev_ext_quota_u64 bytes,
				      nv_xdev_ext_quota_u32 pages)
{
	struct pin_owner *owner = private;

	return (nv_xdev_ext_quota_u32)-nv_xdev_ext_umem_quota_reserve(&owner->quota,
							    bytes, pages);
}

static nv_xdev_ext_quota_u32 owner_release(void *private, nv_xdev_ext_quota_u64 bytes,
				      nv_xdev_ext_quota_u32 pages)
{
	struct pin_owner *owner = private;

	return (nv_xdev_ext_quota_u32)-nv_xdev_ext_umem_quota_release(&owner->quota,
							    bytes, pages);
}

static nv_xdev_ext_quota_u32 owner_lock(void *private, nv_xdev_ext_quota_u32 pages)
{
	struct pin_owner *owner = private;

	owner->lock_calls++;
	if (owner->locked_vm + pages > owner->locked_limit)
		return ENOMEM;
	owner->locked_vm += pages;
	return 0;
}

static void owner_unlock(void *private, nv_xdev_ext_quota_u32 pages)
{
	struct pin_owner *owner = private;

	owner->unlock_calls++;
	owner->locked_vm -= pages;
}

static const struct nv_xdev_ext_pin_charge_ops owner_ops = {
	.reserve = owner_reserve,
	.release = owner_release,
	.lock = owner_lock,
	.unlock = owner_unlock,
};

static void expect_uncharged(const struct pin_owner *owner)
{
	EXPECT_EQ(0, owner->quota.bytes);
	EXPECT_EQ(0, owner->quota.pages);
	EXPECT_EQ(0, owner->quota.buffers);
	EXPECT_EQ(0, owner->locked_vm);
}

static void test_pin_charge_both_or_neither(void)
{
	struct pin_owner owner = {
		.quota = { .max_bytes = 4 * 4096, .max_buffers = 2 },
		.locked_limit = 3,
	};
	struct nv_xdev_ext_umem_quota before;

	/* A pin charges the tracker and locked_vm; unpin returns both. */
	EXPECT_EQ(0, nv_xdev_ext_pin_charge(&owner_ops, &owner, 8192, 2));
	EXPECT_EQ(8192, owner.quota.bytes);
	EXPECT_EQ(2, owner.quota.pages);
	EXPECT_EQ(1, owner.quota.buffers);
	EXPECT_EQ(2, owner.locked_vm);
	EXPECT_EQ(0, nv_xdev_ext_pin_uncharge(&owner_ops, &owner, 8192, 2));
	expect_uncharged(&owner);

	/* locked_vm over RLIMIT_MEMLOCK: the tracker reservation rolls back. */
	EXPECT_EQ(0, nv_xdev_ext_pin_charge(&owner_ops, &owner, 8192, 2));
	before = owner.quota;
	EXPECT_EQ(ENOMEM, nv_xdev_ext_pin_charge(&owner_ops, &owner, 8192, 2));
	EXPECT_EQ(0, memcmp(&before, &owner.quota, sizeof(before)));
	EXPECT_EQ(2, owner.locked_vm);

	/* Tracker full: locked_vm is never charged. */
	EXPECT_EQ(0, nv_xdev_ext_pin_charge(&owner_ops, &owner, 4096, 1));
	owner.lock_calls = 0;
	EXPECT_EQ(ENOSPC, nv_xdev_ext_pin_charge(&owner_ops, &owner, 4096, 1));
	EXPECT_EQ(0, owner.lock_calls);
	EXPECT_EQ(3, owner.locked_vm);
	EXPECT_EQ(2, owner.quota.buffers);

	EXPECT_EQ(0, nv_xdev_ext_pin_uncharge(&owner_ops, &owner, 4096, 1));
	EXPECT_EQ(0, nv_xdev_ext_pin_uncharge(&owner_ops, &owner, 8192, 2));
	expect_uncharged(&owner);

	/* A mismatched uncharge reports the tracker's refusal. */
	owner.unlock_calls = 0;
	EXPECT_EQ(EINVAL, nv_xdev_ext_pin_uncharge(&owner_ops, &owner, 4096, 0));
	EXPECT_EQ(1, owner.unlock_calls);
	expect_uncharged(&owner);
}

static void test_pin_charge_sequence_returns_to_zero(void)
{
	enum { PINS = 32 };
	struct pin_owner owner = {
		.quota = { .max_bytes = 40 * 4096, .max_buffers = 12 },
		.locked_limit = 25,
	};
	nv_xdev_ext_quota_u32 charged[PINS];
	unsigned int accepted = 0, enomem = 0, enospc = 0;

	/* Sizes 1..4 pages; later pins hit either limit and must not leak. */
	for (unsigned int i = 0; i < PINS; i++) {
		nv_xdev_ext_quota_u32 pages = 1 + i % 4;
		nv_xdev_ext_quota_u32 status = nv_xdev_ext_pin_charge(
			&owner_ops, &owner, (nv_xdev_ext_quota_u64)pages * 4096, pages);

		charged[i] = status ? 0 : pages;
		accepted += !status;
		enomem += status == ENOMEM;
		enospc += status == ENOSPC;
		EXPECT_EQ(owner.quota.pages, owner.locked_vm);
	}
	EXPECT_EQ(PINS, accepted + enomem + enospc);
	EXPECT_EQ(12, accepted);
	EXPECT_EQ(1, enomem > 0 && enospc > 0);
	for (unsigned int i = 0; i < PINS; i++) {
		if (charged[i])
			EXPECT_EQ(0, nv_xdev_ext_pin_uncharge(
				&owner_ops, &owner,
				(nv_xdev_ext_quota_u64)charged[i] * 4096, charged[i]));
	}
	expect_uncharged(&owner);
}

int main(void)
{
	test_validation_overflow_and_exact_release();
	test_locked_concurrent_reservation_never_oversubscribes();
	test_pin_charge_both_or_neither();
	test_pin_charge_sequence_returns_to_zero();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return 1;
	}
	printf("PASS: %u checks\n", checks);
	return 0;
}
