// SPDX-License-Identifier: GPL-2.0
/*
 * xdev_ext_sm_stress — concurrency stress for xdev_ext_frame_sm.h (SM_SPEC §3 A5s).
 * P producers claim+publish; C consumers acquire+to_tx+retire; tiny pool so
 * the free stack and the state words genuinely contend.
 *
 * Build:  gcc -O2 -g -fsanitize=thread -pthread -o xdev_ext_sm_stress xdev_ext_sm_stress.c
 *         gcc -O2 -g -fsanitize=thread -pthread -DXDEV_EXT_SM_PLAIN -o xdev_ext_sm_stress_plain xdev_ext_sm_stress.c
 * Run:    ./xdev_ext_sm_stress [nprod] [ncons]      (default 2 2)
 *         ./xdev_ext_sm_stress claim [nthreads] [iters]
 * Pass:   "RESULT: PASS" + exit 0 + no TSan report (CAS backend).
 *         PLAIN backend results are RECORDED, not asserted (HANDOFF §4.2).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "xdev_ext_frame_sm.h"

#define NFRAMES 8
/* TSan slows execution ~10-20x and the point is CONTENTION (tiny pool), not
 * volume; 20k iters/producer keeps wall time bounded under -fsanitize=thread. */
#define ITERS   20000L

static struct xdev_ext_frame frames[NFRAMES];
static struct xdev_ext_pool pool;
static long nprod = 2, ncons = 2;
static long total_alloc, total_retire;	/* updated with __atomic */
static int producers_done;

static pthread_barrier_t claim_start;
static pthread_barrier_t claim_done;
static pthread_barrier_t claim_recycled;
static struct xdev_ext_frame claim_frame[1];
static struct xdev_ext_pool claim_pool;
static int *claim_winners;
static long claim_threads = 4;
static long claim_iters = 10000;

static void *producer(void *arg)
{
	long n;

	(void)arg;
	for (n = 0; n < ITERS; n++) {
		xdev_ext_sm_u32 idx;

		while (xdev_ext_frame_alloc(&pool, &idx) == -ENOSPC)
			sched_yield();
		__atomic_add_fetch(&total_alloc, 1, __ATOMIC_RELAXED);
		/* sentinel rides in valid_len: consumer verifies after acquire */
		if (xdev_ext_frame_publish(&pool, idx, idx ^ 0xA5A5u) != 0) {
			fprintf(stderr, "BUG: publish failed\n");
			_exit(2);
		}
	}
	return NULL;
}

static void *consumer(void *arg)
{
	(void)arg;
	for (;;) {
		long retired = __atomic_load_n(&total_retire, __ATOMIC_RELAXED);
		int done = __atomic_load_n(&producers_done, __ATOMIC_ACQUIRE);
		xdev_ext_sm_u32 i;

		xdev_ext_sm_u32 progressed = 0;

		if (done && retired >= nprod * ITERS)
			return NULL;
		for (i = 0; i < NFRAMES; i++) {
			xdev_ext_sm_u32 len;

			if (xdev_ext_frame_acquire_ready(&pool, i, &len) != 0)
				continue;
			if (xdev_ext_frame_to_tx(&pool, i, 1) != 0)
				continue;	/* another consumer won it */
			if (len != (i ^ 0xA5A5u)) {
				fprintf(stderr, "SENTINEL MISMATCH frame %u\n", i);
				_exit(2);
			}
			if (xdev_ext_frame_consumer_done(&pool, i) != 0) {
				fprintf(stderr, "BUG: retire failed\n");
				_exit(2);
			}
			__atomic_add_fetch(&total_retire, 1, __ATOMIC_RELAXED);
			progressed++;
		}
		if (!progressed)
			sched_yield();	/* don't burn the core (TSan!) */
	}
}

static void *claim_worker(void *arg)
{
	long n;

	(void)arg;
	for (n = 0; n < claim_iters; n++) {
		bool won;

		pthread_barrier_wait(&claim_start);
		won = xdev_ext_frame_claim(&claim_pool, 0) == 0;
		if (won)
			__atomic_add_fetch(&claim_winners[n], 1,
					   __ATOMIC_RELAXED);
		pthread_barrier_wait(&claim_done);

		if (won) {
			if (xdev_ext_frame_publish(&claim_pool, 0, 64) != 0 ||
			    xdev_ext_frame_to_tx(&claim_pool, 0, 1) != 0 ||
			    xdev_ext_frame_consumer_done(&claim_pool, 0) != 0) {
				fprintf(stderr, "BUG: claim winner recycle failed\n");
				_exit(2);
			}
		}
		pthread_barrier_wait(&claim_recycled);
	}
	return NULL;
}

static int run_claim_mode(int argc, char **argv)
{
	pthread_t threads[16];
	long i;
	int failures = 0;

	if (argc > 2)
		claim_threads = atol(argv[2]);
	if (argc > 3)
		claim_iters = atol(argv[3]);
	if (claim_threads < 2 || claim_threads > 16 || claim_iters < 1) {
		fprintf(stderr, "usage: %s claim [nthreads 2..16] [iters]\n",
			argv[0]);
		return 1;
	}

	claim_winners = calloc((size_t)claim_iters, sizeof(*claim_winners));
	if (!claim_winners)
		return 1;
	memset(claim_frame, 0, sizeof(claim_frame));
	if (xdev_ext_pool_init(&claim_pool, claim_frame, 1, false) != 0)
		return 1;

	pthread_barrier_init(&claim_start, NULL, (unsigned)claim_threads);
	pthread_barrier_init(&claim_done, NULL, (unsigned)claim_threads);
	pthread_barrier_init(&claim_recycled, NULL, (unsigned)claim_threads);

	for (i = 0; i < claim_threads; i++)
		pthread_create(&threads[i], NULL, claim_worker, NULL);
	for (i = 0; i < claim_threads; i++)
		pthread_join(threads[i], NULL);

	for (i = 0; i < claim_iters; i++) {
		if (claim_winners[i] != 1) {
			printf("FAIL claim round %ld winners=%d\n", i,
			       claim_winners[i]);
			failures++;
			break;
		}
	}
	if (xdev_ext_frame_state(&claim_pool, 0) != XDEV_EXT_FRAME_FREE) {
		printf("FAIL claim frame not FREE at end\n");
		failures++;
	}
	if (xdev_ext_pool_free_count(&claim_pool) != 0) {
		printf("FAIL claim free_count %u != 0\n",
		       xdev_ext_pool_free_count(&claim_pool));
		failures++;
	}

	pthread_barrier_destroy(&claim_start);
	pthread_barrier_destroy(&claim_done);
	pthread_barrier_destroy(&claim_recycled);
	free(claim_winners);

	printf("%s claim_threads=%ld iters=%ld\n",
	       failures ? "RESULT: FAIL" : "RESULT: PASS",
	       claim_threads, claim_iters);
	return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
	pthread_t pt[16], ct[16];
	long i;
	int failures = 0;

	if (argc > 1 && strcmp(argv[1], "claim") == 0)
		return run_claim_mode(argc, argv);

	if (argc > 1)
		nprod = atol(argv[1]);
	if (argc > 2)
		ncons = atol(argv[2]);
	if (nprod < 1 || nprod > 16 || ncons < 1 || ncons > 16) {
		fprintf(stderr, "usage: %s [nprod 1..16] [ncons 1..16]\n",
			argv[0]);
		return 1;
	}

	memset(frames, 0, sizeof(frames));
	if (xdev_ext_pool_init(&pool, frames, NFRAMES, true) != 0)
		return 1;

	for (i = 0; i < ncons; i++)
		pthread_create(&ct[i], NULL, consumer, NULL);
	for (i = 0; i < nprod; i++)
		pthread_create(&pt[i], NULL, producer, NULL);
	for (i = 0; i < nprod; i++)
		pthread_join(pt[i], NULL);
	__atomic_store_n(&producers_done, 1, __ATOMIC_RELEASE);
	for (i = 0; i < ncons; i++)
		pthread_join(ct[i], NULL);

	/* invariants: conservation + everything back to FREE */
	if (total_alloc != nprod * ITERS) {
		printf("FAIL alloc count %ld != %ld\n", total_alloc,
		       nprod * ITERS);
		failures++;
	}
	if (total_retire != total_alloc) {
		printf("FAIL retire %ld != alloc %ld (leak/double-free)\n",
		       total_retire, total_alloc);
		failures++;
	}
	for (i = 0; i < NFRAMES; i++) {
		if (xdev_ext_frame_state(&pool, (xdev_ext_sm_u32)i) != XDEV_EXT_FRAME_FREE) {
			printf("FAIL frame %ld not FREE at end\n", i);
			failures++;
		}
	}
	if (xdev_ext_pool_free_count(&pool) != NFRAMES) {
		printf("FAIL free_count %u != %d\n",
		       xdev_ext_pool_free_count(&pool), NFRAMES);
		failures++;
	}

	printf("%s nprod=%ld ncons=%ld alloc=%ld retire=%ld\n",
	       failures ? "RESULT: FAIL" : "RESULT: PASS",
	       nprod, ncons, total_alloc, total_retire);
	return failures ? 1 : 0;
}
