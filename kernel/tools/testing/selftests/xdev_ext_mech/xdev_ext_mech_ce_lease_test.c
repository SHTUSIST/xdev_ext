// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include "../../../../io_uring/xdev_ext_mech_ce_lease.h"

static void same_session_depth_and_stale_completion(void)
{
	struct xdev_ext_ce_lease_state state = {0};
	struct xdev_ext_ce_lease_slot slots[8] = {0};
	assert(!xdev_ext_ce_lease_acquire(&state, &slots[0], 10, false));
	assert(state.active_batches == 1);
	assert(!xdev_ext_ce_lease_acquire(&state, &slots[0], 10, false));
	assert(state.active_batches == 1); /* The second CE stage is not a new batch. */
	for (unsigned i = 1; i < 8; i++)
		assert(!xdev_ext_ce_lease_acquire(&state, &slots[i], 10+i, true));
	assert(state.active_batches == 8); /* Existing session keeps its depth. */
	assert(xdev_ext_ce_lease_acquire(&state, &slots[0], 99, false));
	assert(xdev_ext_ce_lease_finish(&state, &slots[0], 99, false) == -ESTALE);
	assert(state.active_batches == 8 && slots[0].active && slots[0].generation == 10);
	for (unsigned i = 0; i < 8; i++) {
		assert(!xdev_ext_ce_lease_finish(&state, &slots[i], 10+i, false));
		assert(!xdev_ext_ce_lease_finish(&state, &slots[i], 10+i, false));
		assert(state.active_batches == 7-i); /* Duplicate terminal cannot decrement twice. */
	}
	assert(!state.active_batches && !state.quarantined);
}

static void conflict_and_unknown_never_recycle(void)
{
	struct xdev_ext_ce_lease_state owner = {0}, waiter = {0};
	struct xdev_ext_ce_lease_slot first = {0}, second = {0}, next = {0};
	assert(!xdev_ext_ce_lease_acquire(&owner, &first, 1, false));
	assert(xdev_ext_ce_lease_acquire(&waiter, &second, 2, true));
	assert(!waiter.active_batches && !second.active);
	assert(!xdev_ext_ce_lease_finish(&owner, &first, 1, false));
	assert(!xdev_ext_ce_lease_acquire(&waiter, &second, 2, false));
	assert(xdev_ext_ce_lease_finish(&waiter, &second, 2, true) == -EBUSY);
	assert(waiter.quarantined && waiter.active_batches == 1 && second.active);
	assert(xdev_ext_ce_lease_acquire(&waiter, &second, 2, false) == -EBUSY);
	assert(xdev_ext_ce_lease_acquire(&waiter, &next, 3, false) == -EBUSY);
	assert(xdev_ext_ce_lease_finish(&waiter, &second, 2, false) == -EBUSY);
	assert(waiter.quarantined && waiter.active_batches == 1 && second.active);
}

static void all_bound_ranges_are_checked_before_acquiring(void)
{
	static const int provider_a, provider_b;
	assert(xdev_ext_ce_lease_overlap(&provider_a, 0, 65536, &provider_a, 0, 65536));
	assert(xdev_ext_ce_lease_overlap(&provider_a, 0, 65536, &provider_a, 32768, 65536));
	assert(!xdev_ext_ce_lease_overlap(&provider_a, 0, 4096, &provider_a, 4096, 4096));
	assert(!xdev_ext_ce_lease_overlap(&provider_a, 0, 65536, &provider_b, 0, 65536));
	assert(xdev_ext_ce_lease_overlap(&provider_a, UINT64_MAX-1, 8, &provider_a, 0, 8));
	assert(xdev_ext_ce_lease_overlap(&provider_a, 0, 0, &provider_a, 0, 8));
}

int main(void)
{
	same_session_depth_and_stale_completion();
	conflict_and_unknown_never_recycle();
	all_bound_ranges_are_checked_before_acquiring();
	puts("ok - CE ownership: same-session depth8, idempotent stages, stale generation, foreign conflict and permanent unknown quarantine");
	return 0;
}
