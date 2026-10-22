// SPDX-License-Identifier: GPL-2.0
/*
 * xdev_ext_sm_test — unit tests for the per-frame lifecycle SM (xdev_ext_frame_sm.h).
 * One test per transition + illegal-transition rejection (SM_SPEC §3 A5u).
 *
 * Build:  gcc -O2 -Wall -Wextra -std=c11 -o xdev_ext_sm_test xdev_ext_sm_test.c
 *         gcc -O2 -Wall -Wextra -std=c11 -DXDEV_EXT_SM_PLAIN -o xdev_ext_sm_test_plain xdev_ext_sm_test.c
 *         gcc -O2 -Wall -Wextra -std=gnu11 -DXDEV_EXT_SM_DMAFENCE -pthread -o xdev_ext_sm_test_fence xdev_ext_sm_test.c
 *         (DMAFENCE needs gnu11: strict c11 hides POSIX pthread_spinlock_t)
 * Run:    ./xdev_ext_sm_test   -> prints "RESULT: PASS", exit 0
 */
#include <stdio.h>
#include <string.h>
#include "xdev_ext_frame_sm.h"

#define NFRAMES 8

static struct xdev_ext_frame frames[NFRAMES];
static struct xdev_ext_pool pool;
static int failures;

#define CHECK(cond, name) do {                                        \
	if (cond) {                                                   \
		printf("ok   %s\n", name);                            \
	} else {                                                      \
		printf("FAIL %s (line %d)\n", name, __LINE__);        \
		failures++;                                           \
	}                                                             \
} while (0)

static void reset(bool use_stack)
{
	memset(frames, 0, sizeof(frames));
	CHECK(xdev_ext_pool_init(&pool, frames, NFRAMES, use_stack) == 0, "pool_init");
}

int main(void)
{
	xdev_ext_sm_u32 idx[NFRAMES], a, b, len, i, j;

	/* T1: alloc = FREE->IO_PENDING, unique idx, exhaustion -> -ENOSPC */
	reset(true);
	for (i = 0; i < NFRAMES; i++) {
		CHECK(xdev_ext_frame_alloc(&pool, &idx[i]) == 0, "T1 alloc");
		CHECK(xdev_ext_frame_state(&pool, idx[i]) == XDEV_EXT_FRAME_IO_PENDING,
		      "T1 state==IO_PENDING");
		for (j = 0; j < i; j++)
			CHECK(idx[i] != idx[j], "T1 idx unique");
	}
	CHECK(xdev_ext_frame_alloc(&pool, &a) == -ENOSPC, "T1 exhausted -> -ENOSPC");
	CHECK(xdev_ext_pool_free_count(&pool) == 0, "T1 free_count==0");

	/* T2: publish = IO_PENDING->READY (release); dup completion dropped */
	reset(true);
	CHECK(xdev_ext_frame_alloc(&pool, &a) == 0, "T2 alloc");
	CHECK(xdev_ext_frame_publish(&pool, a, 1234) == 0, "T2 publish");
	CHECK(xdev_ext_frame_state(&pool, a) == XDEV_EXT_FRAME_READY, "T2 state==READY");
	len = 0;
	CHECK(xdev_ext_frame_acquire_ready(&pool, a, &len) == 0 && len == 1234,
	      "T2 acquire sees valid_len");
	CHECK(xdev_ext_frame_publish(&pool, a, 99) == -EINVAL,
	      "T2 duplicate publish dropped");
	len = 0;
	CHECK(xdev_ext_frame_acquire_ready(&pool, a, &len) == 0 && len == 1234,
	      "T2 duplicate publish does not alter valid_len");

	/* T3: to_tx + consumer_done xN -> FREE exactly at the Nth (N=1, N=3) */
	CHECK(xdev_ext_frame_to_tx(&pool, a, 1) == 0, "T3 to_tx N=1");
	CHECK(xdev_ext_frame_state(&pool, a) == XDEV_EXT_FRAME_TX_PENDING, "T3 TX_PENDING");
	CHECK(xdev_ext_frame_consumer_done(&pool, a) == 0, "T3 done 1/1");
	CHECK(xdev_ext_frame_state(&pool, a) == XDEV_EXT_FRAME_FREE, "T3 FREE at N=1");

	CHECK(xdev_ext_frame_alloc(&pool, &a) == 0, "T3 realloc");
	CHECK(xdev_ext_frame_publish(&pool, a, 64) == 0, "T3 publish");
	CHECK(xdev_ext_frame_to_tx(&pool, a, 3) == 0, "T3 to_tx N=3");
	CHECK(xdev_ext_frame_consumer_done(&pool, a) == 0 &&
	      xdev_ext_frame_state(&pool, a) == XDEV_EXT_FRAME_TX_PENDING, "T3 done 1/3");
	CHECK(xdev_ext_frame_consumer_done(&pool, a) == 0 &&
	      xdev_ext_frame_state(&pool, a) == XDEV_EXT_FRAME_TX_PENDING, "T3 done 2/3");
	CHECK(xdev_ext_frame_consumer_done(&pool, a) == 0 &&
	      xdev_ext_frame_state(&pool, a) == XDEV_EXT_FRAME_FREE, "T3 FREE at 3/3");

	/* T4: illegal transitions rejected, state unchanged */
	reset(true);
	CHECK(xdev_ext_frame_alloc(&pool, &a) == 0, "T4 alloc");
	CHECK(xdev_ext_frame_to_tx(&pool, a, 1) == -EINVAL, "T4 to_tx on IO_PENDING");
	CHECK(xdev_ext_frame_consumer_done(&pool, a) == -EINVAL, "T4 done on IO_PENDING");
	CHECK(xdev_ext_frame_acquire_ready(&pool, a, NULL) == -EAGAIN,
	      "T4 acquire on not-READY");
	for (b = 0; b < NFRAMES; b++)
		if (xdev_ext_frame_state(&pool, b) == XDEV_EXT_FRAME_FREE)
			break;
	CHECK(b < NFRAMES, "T4 found a FREE frame");
	CHECK(xdev_ext_frame_publish(&pool, b, 1) == -EINVAL, "T4 publish on FREE");
	CHECK(xdev_ext_frame_consumer_done(&pool, b) == -EINVAL, "T4 done on FREE");
	CHECK(xdev_ext_frame_publish(&pool, a, 1) == 0, "T4 legal publish");
	CHECK(xdev_ext_frame_abort(&pool, a) == -EINVAL, "T4 abort on READY");
	CHECK(xdev_ext_frame_publish(&pool, NFRAMES, 1) == -ERANGE, "T4 idx range");

	/* T5: abort = IO_PENDING->FREE; full-cycle conservation */
	reset(true);
	CHECK(xdev_ext_frame_alloc(&pool, &a) == 0, "T5 alloc");
	CHECK(xdev_ext_frame_abort(&pool, a) == 0 &&
	      xdev_ext_frame_state(&pool, a) == XDEV_EXT_FRAME_FREE, "T5 abort -> FREE");
	CHECK(xdev_ext_pool_free_count(&pool) == NFRAMES, "T5 count restored");
	for (i = 0; i < NFRAMES; i++)
		CHECK(xdev_ext_frame_alloc(&pool, &idx[i]) == 0, "T5 alloc-all");
	for (i = 0; i < NFRAMES; i++) {
		CHECK(xdev_ext_frame_publish(&pool, idx[i], 1) == 0, "T5 pub");
		CHECK(xdev_ext_frame_to_tx(&pool, idx[i], 1) == 0, "T5 totx");
		CHECK(xdev_ext_frame_consumer_done(&pool, idx[i]) == 0, "T5 done");
	}
	CHECK(xdev_ext_pool_free_count(&pool) == NFRAMES, "T5 conservation");

	/* T6: claim-by-index (kernel discipline, use_stack=false) */
	reset(false);
	CHECK(xdev_ext_frame_claim(&pool, 3) == 0 &&
	      xdev_ext_frame_state(&pool, 3) == XDEV_EXT_FRAME_IO_PENDING, "T6 claim");
	CHECK(xdev_ext_frame_claim(&pool, 3) == -EBUSY, "T6 double-claim -> -EBUSY");
	CHECK(xdev_ext_frame_claim(&pool, NFRAMES) == -ERANGE, "T6 idx range");
	CHECK(xdev_ext_frame_alloc(&pool, &a) == -EOPNOTSUPP, "T6 alloc w/o stack");
	CHECK(xdev_ext_frame_publish(&pool, 3, 512) == 0, "T6 publish");
	CHECK(xdev_ext_frame_to_tx(&pool, 3, 1) == 0, "T6 to_tx");
	CHECK(xdev_ext_frame_consumer_done(&pool, 3) == 0 &&
	      xdev_ext_frame_state(&pool, 3) == XDEV_EXT_FRAME_FREE, "T6 retire");

	if (failures)
		printf("RESULT: FAIL (%d failures)\n", failures);
	else
		printf("RESULT: PASS\n");
	return failures ? 1 : 0;
}
