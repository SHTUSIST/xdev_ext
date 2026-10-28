/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_BENCH_H
#define CHAIN_BENCH_H

#include <stdint.h>
#include <sys/resource.h>
#include <time.h>

#include "../common/cpu_timer.h"
#include "chain_check.h"
#include "chain_spec.h"
#include "chain_timing.h"

/* Exit status of chain_bench, as the other eval harnesses use them. */
enum { CB_PASS = 0, CB_FAIL = 1, CB_INVALID = 2, CB_NOT_RUN = 4 };

struct chain_result {
	struct cpu_timer cpu_timer;
	int status;			/* CB_* */
	char failure[256];
	/* closed load: one CLOCK_MONOTONIC_RAW interval per measured window */
	uint64_t *samples;
	uint64_t nr_samples, windows_done, batches_done;
	/* sustained load: one completion time per record (chain_timing.h) */
	struct chain_sustained sus;
	uint64_t *rec_ns;
	const char *observer;		/* how completions were seen */
	uint64_t observer_syscalls;	/* STATS polls of that observer */
	/* session counters, last STATS */
	struct xdev_ext_mech_stats stats;
	bool have_stats;
	/* CPU payload copies seen by this run, by source */
	unsigned int nr_copy_sources;
	const char *copy_sources[CHAIN_MAX_COPY_SOURCES];
	int64_t nvme_bounces;		/* -1: no bounce counter in this kernel */
	int xsk_zero_copy;		/* -1: no AF_XDP stage */
	/* staged arm accounting */
	uint64_t cpu_copies, cpu_copy_bytes, cpu_read_bytes, socket_bytes;
	/* IAA plan counters (chain_plan.bpf.c), when loaded */
	int64_t iaa_completes, iaa_errors;
	const char *iaa_scope;		/* "this-process" or "system-wide-pin" */
	/* oracle */
	const char *oracle_verdict;	/* "pass", "fail", "not-checked" */
	uint64_t oracle_bytes;
	long long oracle_detail;
	/* cost outside timing */
	struct rusage ru_before, ru_after;
	uint64_t syscalls;		/* system calls the arm itself issued */
	const char *ce_backend;
	const char *wire_crc;		/* user-space arms: chain_crc32c_impl() */
};

static inline uint64_t cb_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline void cb_copy_source(struct chain_result *r, const char *what)
{
	unsigned int i;

	for (i = 0; i < r->nr_copy_sources; i++)
		if (!strcmp(r->copy_sources[i], what))
			return;
	if (r->nr_copy_sources < CHAIN_MAX_COPY_SOURCES)
		r->copy_sources[r->nr_copy_sources++] = what;
}

int cb_fail(struct chain_result *r, int status, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
int chain_run_session(const struct chain_spec *s, struct chain_result *r);
int chain_run_staged(const struct chain_spec *s, struct chain_result *r);
/* Post-campaign readback of a file/block window against the reference. */
int chain_oracle_file(const struct chain_spec *s, struct chain_result *r);
/* Read the whole reference file; caller frees. */
uint8_t *chain_read_reference(const struct chain_spec *s, size_t *len,
			      struct chain_result *r);

#endif /* CHAIN_BENCH_H */
