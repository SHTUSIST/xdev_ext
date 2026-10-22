// SPDX-License-Identifier: GPL-2.0
/*
 * xdev_ext_sm_bench — per-hand-off cost of the lifecycle SM (SM_SPEC §3 A5b).
 * Measures the full claim->publish->acquire->to_tx->retire cycle with rdtscp,
 * at 1/2/4/8 threads over a shared pool (HANDOFF §4.4 Part B locally).
 *
 * Build the three backends:
 *   gcc -O2 -Wall -Wextra -pthread -o xdev_ext_sm_bench xdev_ext_sm_bench.c
 *   gcc -O2 -Wall -Wextra -pthread -DXDEV_EXT_SM_PLAIN -o xdev_ext_sm_bench_plain xdev_ext_sm_bench.c
 *   gcc -O2 -Wall -Wextra -pthread -DXDEV_EXT_SM_DMAFENCE -o xdev_ext_sm_bench_fence xdev_ext_sm_bench.c
 * Output: CSV  backend,threads,ops,cycles_per_handoff,ns_per_handoff
 *
 * HONESTY: numbers from this harness are host-local and (for the fence arm)
 * EMULATED — scaffolding, NOT the paper's dma_fence comparison. The real
 * number comes from xdev_ext_sm_fence_bench.ko on the XDEV_EXT kernel (gated).
 * NOTE: XDEV_EXT_SM_PLAIN is not safe for concurrent transitions (see
 * xdev_ext_frame_sm.h); its multi-thread rows measure a broken-by-design
 * reference and are reported for the 1-thread overhead comparison only.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>
#include "xdev_ext_frame_sm.h"

#define NFRAMES 64
#define ITERS   1000000L

#if defined(XDEV_EXT_SM_PLAIN)
#define BACKEND "plain"
#elif defined(XDEV_EXT_SM_DMAFENCE)
#define BACKEND "fence-emu"
#else
#define BACKEND "cas"
#endif

static struct xdev_ext_frame frames[NFRAMES];
static struct xdev_ext_pool pool;
static pthread_barrier_t barrier;

struct worker_result {
	uint64_t cycles;
	long ops;
};

static void *worker(void *arg)
{
	struct worker_result *r = arg;
	unsigned int aux;
	uint64_t t0, t1;
	long n;

	pthread_barrier_wait(&barrier);
	t0 = __rdtscp(&aux);
	for (n = 0; n < ITERS; n++) {
		xdev_ext_sm_u32 idx, len;

		if (xdev_ext_frame_alloc(&pool, &idx) != 0)
			continue;	/* pool momentarily empty under threads */
		xdev_ext_frame_publish(&pool, idx, 4096);
		xdev_ext_frame_acquire_ready(&pool, idx, &len);
		xdev_ext_frame_to_tx(&pool, idx, 1);
		xdev_ext_frame_consumer_done(&pool, idx);
		r->ops++;
	}
	t1 = __rdtscp(&aux);
	r->cycles = t1 - t0;
	return NULL;
}

static double tsc_ghz(void)
{
	struct timespec a, b;
	unsigned int aux;
	uint64_t c0, c1;

	clock_gettime(CLOCK_MONOTONIC, &a);
	c0 = __rdtscp(&aux);
	usleep(200000);
	c1 = __rdtscp(&aux);
	clock_gettime(CLOCK_MONOTONIC, &b);
	return (double)(c1 - c0) /
	       ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec));
}

int main(void)
{
	static const int tcounts[] = { 1, 2, 4, 8 };
	double ghz = tsc_ghz();
	size_t t;

	printf("backend,threads,ops,cycles_per_handoff,ns_per_handoff\n");
	for (t = 0; t < sizeof(tcounts) / sizeof(tcounts[0]); t++) {
		int nt = tcounts[t];
		pthread_t th[8];
		struct worker_result res[8];
		uint64_t cyc = 0;
		long ops = 0;
		int i;

		memset(frames, 0, sizeof(frames));
		memset(res, 0, sizeof(res));
		if (xdev_ext_pool_init(&pool, frames, NFRAMES, true) != 0)
			return 1;
		pthread_barrier_init(&barrier, NULL, nt);
		for (i = 0; i < nt; i++)
			pthread_create(&th[i], NULL, worker, &res[i]);
		for (i = 0; i < nt; i++) {
			pthread_join(th[i], NULL);
			cyc += res[i].cycles;
			ops += res[i].ops;
		}
		pthread_barrier_destroy(&barrier);
		if (!ops)
			return 1;
		printf("%s,%d,%ld,%.1f,%.1f\n", BACKEND, nt, ops,
		       (double)cyc / ops, (double)cyc / ops / ghz);
	}
	return 0;
}
