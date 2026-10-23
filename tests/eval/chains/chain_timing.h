/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CHAIN_TIMING_H
#define CHAIN_TIMING_H

/*
 * The sustained load of chain_bench and uo_bench: the whole campaign is
 * admitted at once and up to depth batches stay in flight, so throughput is
 * the campaign's bytes over its wall time, not one record at a time.  A
 * record (burst batches) counts as complete when (r + 1) x burst batches of
 * the campaign have finished: the session reports only counts (one eventfd
 * count per finished batch, or STATS), so every arm uses the same rule.
 * Each completion is one CLOCK_MONOTONIC_RAW read into an array allocated
 * and touched before the campaign; run.py turns the inter-completion gaps
 * into p50/p99/p999 and the last completion into throughput.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

struct chain_sustained {
	uint64_t records;	/* warmup + measured records */
	uint64_t warm;		/* the first @warm records are warmup */
	uint32_t burst;		/* batches per record */
	uint64_t *done_ns;	/* per record, absolute; caller's array */
	uint64_t next;		/* first record not yet complete */
	uint64_t t_begin;	/* campaign start: the START, or receiver ready */
};

static inline void chain_sustained_init(struct chain_sustained *t, uint64_t records,
					uint64_t warm, uint32_t burst, uint64_t *done_ns)
{
	*t = (struct chain_sustained){ .records = records, .warm = warm,
		.burst = burst, .done_ns = done_ns };
	/* Fault the array in now, not inside the campaign. */
	memset(done_ns, 0, records * sizeof(*done_ns));
}

/* @finished batches of the campaign are done at @now. */
static inline void chain_sustained_note(struct chain_sustained *t, uint64_t finished,
					uint64_t now)
{
	while (t->next < t->records && finished >= (t->next + 1) * t->burst)
		t->done_ns[t->next++] = now;
}

static inline bool chain_sustained_complete(const struct chain_sustained *t)
{
	return t->next == t->records;
}

/* Start of the measured part: the last warmup record's completion. */
static inline uint64_t chain_sustained_t0(const struct chain_sustained *t)
{
	return t->warm && t->next >= t->warm ? t->done_ns[t->warm - 1] : t->t_begin;
}

#endif /* CHAIN_TIMING_H */
