// SPDX-License-Identifier: GPL-2.0
/* Host-only tests of the public lifecycle and native-completion contracts. */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "io_uring/xdev_ext_mech_lifecycle.h"

#define CHECK(expr) do {                                                     \
	if (!(expr)) {                                                        \
		fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr);        \
		return false;                                                  \
	}                                                                     \
} while (0)

/* The frozen public representation allows deterministic exhaustion tests. */
#define PHASE_BITS 3
#define RACERS 12
#define RACE_ROUNDS 24
#define PUBLICATIONS 8192
#define COMPLETION_REUSES 100000

static bool unchanged(const struct xdev_ext_mech_life *life, __u64 ctrl, __u32 len)
{
	return life->ctrl == ctrl && life->valid_len == len;
}

static bool ready(struct xdev_ext_mech_life *life, __u32 len, __u64 *token)
{
	xdev_ext_mech_life_init(life);
	return !xdev_ext_mech_life_begin_produce(life, false, token) &&
	       !xdev_ext_mech_life_publish(life, *token, len);
}

static bool test_serialized_chain(void)
{
	struct xdev_ext_mech_life life;
	__u64 producer, consumer, overwrite;

	xdev_ext_mech_life_init(&life);
	CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_FREE);
	CHECK(xdev_ext_mech_life_token(&life) == 0);
	CHECK(life.valid_len == 0);
	CHECK(!xdev_ext_mech_life_begin_produce(&life, false, &producer));
	CHECK(producer != 0);
	CHECK(xdev_ext_mech_life_token(&life) == producer);
	CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_IO_PENDING);
	CHECK(!xdev_ext_mech_life_publish(&life, producer, 4093));
	CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_READY);
	CHECK(!xdev_ext_mech_life_begin_consume(&life, &consumer));
	CHECK(consumer > producer);
	CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_OUT_PENDING);
	/* Metadata is read only after the consumer owns OUT_PENDING. */
	CHECK(life.valid_len == 4093);
	CHECK(!xdev_ext_mech_life_complete_consume(&life, consumer));
	CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_READY);
	CHECK(!xdev_ext_mech_life_begin_produce(&life, true, &overwrite));
	CHECK(overwrite > consumer);
	CHECK(!xdev_ext_mech_life_publish(&life, overwrite, 0));
	CHECK(!xdev_ext_mech_life_begin_consume(&life, &consumer));
	CHECK(life.valid_len == 0);
	CHECK(!xdev_ext_mech_life_complete_consume(&life, consumer));
	CHECK(!xdev_ext_mech_life_release(&life, consumer));
	CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_FREE);
	/* Terminal release is idempotent only for the same generation. */
	CHECK(!xdev_ext_mech_life_release(&life, consumer));
	return true;
}

static bool test_illegal_edges_do_not_mutate(void)
{
	struct xdev_ext_mech_life life;
	__u64 token, other = 0, ctrl;
	__u32 len;

	xdev_ext_mech_life_init(&life);
	CHECK(xdev_ext_mech_life_publish(&life, 0, 23) < 0);
	CHECK(xdev_ext_mech_life_complete_consume(&life, 0) < 0);
	CHECK(xdev_ext_mech_life_release(&life, 0) < 0);
	CHECK(xdev_ext_mech_life_begin_consume(&life, &other) < 0);
	CHECK(xdev_ext_mech_life_begin_produce(&life, true, &other) < 0);
	CHECK(life.valid_len == 0);
	CHECK(xdev_ext_mech_life_token(&life) == 0);
	CHECK(!xdev_ext_mech_life_begin_produce(&life, false, &token));
	ctrl = life.ctrl;
	len = life.valid_len;
	CHECK(xdev_ext_mech_life_release(&life, token) < 0);
	CHECK(xdev_ext_mech_life_complete_consume(&life, token) < 0);
	CHECK(xdev_ext_mech_life_begin_consume(&life, &other) < 0);
	CHECK(xdev_ext_mech_life_begin_produce(&life, false, &other) < 0);
	CHECK(xdev_ext_mech_life_begin_produce(&life, true, &other) < 0);
	CHECK(unchanged(&life, ctrl, len));
	CHECK(!xdev_ext_mech_life_publish(&life, token, UINT32_MAX));
	ctrl = life.ctrl;
	CHECK(xdev_ext_mech_life_begin_produce(&life, false, &other) < 0);
	CHECK(xdev_ext_mech_life_complete_consume(&life, token) < 0);
	CHECK(unchanged(&life, ctrl, UINT32_MAX));
	CHECK(!xdev_ext_mech_life_begin_consume(&life, &token));
	ctrl = life.ctrl;
	CHECK(xdev_ext_mech_life_publish(&life, token, 17) < 0);
	CHECK(xdev_ext_mech_life_release(&life, token) < 0);
	CHECK(xdev_ext_mech_life_begin_consume(&life, &other) < 0);
	CHECK(xdev_ext_mech_life_begin_produce(&life, true, &other) < 0);
	CHECK(unchanged(&life, ctrl, UINT32_MAX));
	return true;
}

static bool test_duplicate_publish_preserves_metadata(void)
{
	struct xdev_ext_mech_life life;
	__u64 token, ctrl;

	CHECK(ready(&life, 123, &token));
	ctrl = life.ctrl;
	CHECK(xdev_ext_mech_life_publish(&life, token, 456) < 0);
	CHECK(unchanged(&life, ctrl, 123));
	CHECK(!xdev_ext_mech_life_begin_consume(&life, &token));
	CHECK(life.valid_len == 123);
	CHECK(!xdev_ext_mech_life_complete_consume(&life, token));
	ctrl = life.ctrl;
	CHECK(xdev_ext_mech_life_complete_consume(&life, token) < 0);
	CHECK(unchanged(&life, ctrl, 123));
	return true;
}

static bool test_stale_after_reuse(void)
{
	struct xdev_ext_mech_life life;
	__u64 old_producer, old_consumer, current, ctrl;
	__u32 len;
	unsigned int i;

	CHECK(ready(&life, 100, &old_producer));
	CHECK(!xdev_ext_mech_life_begin_consume(&life, &old_consumer));
	CHECK(!xdev_ext_mech_life_complete_consume(&life, old_consumer));
	CHECK(!xdev_ext_mech_life_release(&life, old_consumer));
	for (i = 0; i < 32; i++) {
		CHECK(!xdev_ext_mech_life_begin_produce(&life, false, &current));
		CHECK(current > old_consumer);
		ctrl = life.ctrl;
		len = life.valid_len;
		CHECK(xdev_ext_mech_life_publish(&life, old_producer, 9999) < 0);
		CHECK(xdev_ext_mech_life_rollback(&life, old_producer,
					 XDEV_EXT_MECH_L_FREE) < 0);
		CHECK(xdev_ext_mech_life_release(&life, old_consumer) < 0);
		CHECK(unchanged(&life, ctrl, len));
		CHECK(!xdev_ext_mech_life_publish(&life, current, i + 1));
		ctrl = life.ctrl;
		CHECK(xdev_ext_mech_life_release(&life, old_consumer) < 0);
		CHECK(unchanged(&life, ctrl, i + 1));
		CHECK(!xdev_ext_mech_life_begin_consume(&life, &current));
		CHECK(life.valid_len == i + 1);
		ctrl = life.ctrl;
		CHECK(xdev_ext_mech_life_complete_consume(&life, old_consumer) < 0);
		CHECK(xdev_ext_mech_life_rollback(&life, old_consumer,
					 XDEV_EXT_MECH_L_READY) < 0);
		CHECK(unchanged(&life, ctrl, i + 1));
		CHECK(!xdev_ext_mech_life_complete_consume(&life, current));
		CHECK(!xdev_ext_mech_life_release(&life, current));
	}
	return true;
}

static bool test_preaccept_rollback(void)
{
	struct xdev_ext_mech_life life;
	__u64 token, retry, ctrl;

	xdev_ext_mech_life_init(&life);
	CHECK(!xdev_ext_mech_life_begin_produce(&life, false, &token));
	ctrl = life.ctrl;
	CHECK(xdev_ext_mech_life_rollback(&life, token, XDEV_EXT_MECH_L_OUT_PENDING) < 0);
	CHECK(unchanged(&life, ctrl, 0));
	CHECK(!xdev_ext_mech_life_rollback(&life, token, XDEV_EXT_MECH_L_FREE));
	CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_FREE);
	CHECK(!xdev_ext_mech_life_begin_produce(&life, false, &retry));
	CHECK(retry > token);
	CHECK(xdev_ext_mech_life_publish(&life, token, 33) < 0);
	CHECK(!xdev_ext_mech_life_publish(&life, retry, 2048));
	CHECK(!xdev_ext_mech_life_begin_produce(&life, true, &token));
	CHECK(!xdev_ext_mech_life_rollback(&life, token, XDEV_EXT_MECH_L_READY));
	CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_READY);
	CHECK(life.valid_len == 2048);
	CHECK(!xdev_ext_mech_life_begin_consume(&life, &token));
	ctrl = life.ctrl;
	CHECK(xdev_ext_mech_life_rollback(&life, token, XDEV_EXT_MECH_L_FREE) < 0);
	CHECK(unchanged(&life, ctrl, 2048));
	CHECK(!xdev_ext_mech_life_rollback(&life, token, XDEV_EXT_MECH_L_READY));
	CHECK(!xdev_ext_mech_life_begin_consume(&life, &retry));
	CHECK(retry > token);
	CHECK(xdev_ext_mech_life_complete_consume(&life, token) < 0);
	CHECK(life.valid_len == 2048);
	return true;
}

static bool test_generation_exhaustion(void)
{
	struct xdev_ext_mech_life life;
	__u64 token, ctrl;

	xdev_ext_mech_life_init(&life);
	life.ctrl = ((XDEV_EXT_MECH_L_GEN_MAX - 1) << PHASE_BITS) | XDEV_EXT_MECH_L_FREE;
	life.valid_len = 91;
	CHECK(!xdev_ext_mech_life_begin_produce(&life, false, &token));
	CHECK(token == XDEV_EXT_MECH_L_GEN_MAX);
	CHECK(!xdev_ext_mech_life_rollback(&life, token, XDEV_EXT_MECH_L_FREE));
	ctrl = life.ctrl;
	CHECK(xdev_ext_mech_life_begin_produce(&life, false, &token) == -EOVERFLOW);
	CHECK(unchanged(&life, ctrl, 91));
	life.ctrl = (XDEV_EXT_MECH_L_GEN_MAX << PHASE_BITS) | XDEV_EXT_MECH_L_READY;
	ctrl = life.ctrl;
	CHECK(xdev_ext_mech_life_begin_produce(&life, true, &token) == -EOVERFLOW);
	CHECK(xdev_ext_mech_life_begin_consume(&life, &token) == -EOVERFLOW);
	CHECK(unchanged(&life, ctrl, 91));
	return true;
}

enum race_op {
	BEGIN_PRODUCE, BEGIN_CONSUME, PUBLISH, COMPLETE_CONSUME, ROLLBACK,
	COMPLETION_BEGIN, COMPLETION_CLAIM, COMPLETION_PUBLISH, COMPLETION_CONSUME,
	COMPLETION_CANCEL_CLAIM,
};

struct racer {
	pthread_barrier_t *barrier;
	struct xdev_ext_mech_life *life;
	struct xdev_ext_mech_completion *completion;
	enum race_op op;
	__u64 token;
	unsigned int index;
	int rc;
	int result;
};

static void *race(void *arg)
{
	struct racer *r = arg;

	pthread_barrier_wait(r->barrier);
	switch (r->op) {
	case BEGIN_PRODUCE:
		r->rc = xdev_ext_mech_life_begin_produce(r->life, false, &r->token);
		break;
	case BEGIN_CONSUME:
		r->rc = xdev_ext_mech_life_begin_consume(r->life, &r->token);
		break;
	case PUBLISH:
		r->rc = xdev_ext_mech_life_publish(r->life, r->token, 1000 + r->index);
		break;
	case COMPLETE_CONSUME:
		r->rc = xdev_ext_mech_life_complete_consume(r->life, r->token);
		break;
	case ROLLBACK:
		r->rc = xdev_ext_mech_life_rollback(r->life, r->token, XDEV_EXT_MECH_L_FREE);
		break;
	case COMPLETION_BEGIN:
		r->rc = xdev_ext_mech_completion_begin(r->completion, &r->token);
		break;
	case COMPLETION_CLAIM:
		r->rc = xdev_ext_mech_completion_claim(r->completion, r->token);
		break;
	case COMPLETION_PUBLISH:
		r->rc = xdev_ext_mech_completion_publish(r->completion, r->token,
						  1000 + r->index);
		break;
	case COMPLETION_CONSUME:
		r->rc = xdev_ext_mech_completion_consume(r->completion, r->token, &r->result);
		break;
	case COMPLETION_CANCEL_CLAIM:
		if (r->index & 1)
			r->rc = xdev_ext_mech_completion_claim(r->completion, r->token);
		else
			r->rc = xdev_ext_mech_completion_cancel(r->completion, r->token);
		break;
	}
	return NULL;
}

/* A single legal edge must have one winner among simultaneous contenders. */
static bool contend(struct racer racers[RACERS], enum race_op op,
		    struct xdev_ext_mech_life *life,
		    struct xdev_ext_mech_completion *completion, __u64 token,
		    unsigned int *winner)
{
	pthread_t threads[RACERS];
	pthread_barrier_t barrier;
	unsigned int i, wins = 0, started = 0;

	CHECK(!pthread_barrier_init(&barrier, NULL, RACERS));
	for (i = 0; i < RACERS; i++) {
		racers[i] = (struct racer) {
			.barrier = &barrier, .op = op, .life = life,
			.completion = completion, .token = token, .index = i,
			.result = -987654321,
		};
		/* Failure is fatal: a partially populated barrier cannot progress. */
		if (pthread_create(&threads[i], NULL, race, &racers[i])) {
			fprintf(stderr, "cannot create racer %u (started %u)\n", i, started);
			exit(EXIT_FAILURE);
		}
		started++;
	}
	for (i = 0; i < RACERS; i++) {
		CHECK(!pthread_join(threads[i], NULL));
		if (!racers[i].rc) {
			wins++;
			*winner = i;
		} else {
			CHECK(racers[i].rc < 0);
		}
	}
	CHECK(!pthread_barrier_destroy(&barrier));
	CHECK(wins == 1);
	return true;
}

static bool test_lifecycle_competition(void)
{
	struct xdev_ext_mech_life life;
	struct racer racers[RACERS];
	__u64 token;
	unsigned int round, winner = 0, published_winner;

	for (round = 0; round < RACE_ROUNDS; round++) {
		xdev_ext_mech_life_init(&life);
		CHECK(contend(racers, BEGIN_PRODUCE, &life, NULL, 0, &winner));
		token = racers[winner].token;
		CHECK(token != 0);
		CHECK(contend(racers, PUBLISH, &life, NULL, token, &published_winner));
		CHECK(contend(racers, BEGIN_CONSUME, &life, NULL, token, &winner));
		/* The winner of publish alone determines the metadata. */
		CHECK(life.valid_len == 1000 + published_winner);
		token = racers[winner].token;
		CHECK(contend(racers, COMPLETE_CONSUME, &life, NULL, token, &winner));
		CHECK(!xdev_ext_mech_life_release(&life, token));
		CHECK(!xdev_ext_mech_life_begin_produce(&life, false, &token));
		CHECK(contend(racers, ROLLBACK, &life, NULL, token, &winner));
		CHECK(xdev_ext_mech_life_phase(&life) == XDEV_EXT_MECH_L_FREE);
	}
	return true;
}

struct publication {
	struct xdev_ext_mech_life life;
	__u64 token;
	__u64 payload[4];
};

struct publication_run {
	struct publication *slots;
	bool ok;
};

static bool deadline_passed(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec - start->tv_sec >= 15;
}

static void *read_publications(void *arg)
{
	struct publication_run *run = arg;
	struct timespec start;
	unsigned int i, j, spins = 0;
	__u64 consumer;

	run->ok = false;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < PUBLICATIONS; i++) {
		struct publication *slot = &run->slots[i];

		while (xdev_ext_mech_life_begin_consume(&slot->life, &consumer)) {
			if (!(++spins % 1024)) {
				if (deadline_passed(&start))
					return NULL;
				sched_yield();
			}
		}
		if (slot->life.valid_len != i + 1)
			return NULL;
		for (j = 0; j < 4; j++)
			if (slot->payload[j] != ((__u64)i << 32 | (j + 1)))
				return NULL;
		if (xdev_ext_mech_life_complete_consume(&slot->life, consumer))
			return NULL;
	}
	run->ok = true;
	return NULL;
}

static bool test_consumer_acquires_metadata(void)
{
	struct publication_run run;
	pthread_t reader;
	unsigned int i, j;
	bool published = true;

	run.slots = calloc(PUBLICATIONS, sizeof(*run.slots));
	CHECK(run.slots != NULL);
	for (i = 0; i < PUBLICATIONS; i++) {
		xdev_ext_mech_life_init(&run.slots[i].life);
		CHECK(!xdev_ext_mech_life_begin_produce(&run.slots[i].life, false,
						  &run.slots[i].token));
	}
	CHECK(!pthread_create(&reader, NULL, read_publications, &run));
	for (i = 0; i < PUBLICATIONS; i++) {
		/* These ordinary stores must become visible via publish/acquire. */
		for (j = 0; j < 4; j++)
			run.slots[i].payload[j] = ((__u64)i << 32) | (j + 1);
		if (xdev_ext_mech_life_publish(&run.slots[i].life, run.slots[i].token, i + 1)) {
			published = false;
			break;
		}
	}
	CHECK(!pthread_join(reader, NULL));
	free(run.slots);
	CHECK(published);
	CHECK(run.ok);
	return true;
}

static bool test_completion_before_submit_returns(void)
{
	struct xdev_ext_mech_completion completion;
	__u64 token, next;
	int result = 77;

	xdev_ext_mech_completion_init(&completion);
	CHECK(!xdev_ext_mech_completion_begin(&completion, &token));
	CHECK(token != 0);
	CHECK(!xdev_ext_mech_completion_claim(&completion, token));
	/* Submit returned an error, but callback has already accepted ownership. */
	CHECK(xdev_ext_mech_completion_cancel(&completion, token) < 0);
	CHECK(xdev_ext_mech_completion_consume(&completion, token, &result) < 0);
	CHECK(result == 77);
	CHECK(!xdev_ext_mech_completion_publish(&completion, token, -EIO));
	CHECK(xdev_ext_mech_completion_cancel(&completion, token) < 0);
	CHECK(xdev_ext_mech_completion_begin(&completion, &next) < 0);
	CHECK(!xdev_ext_mech_completion_consume(&completion, token, &result));
	CHECK(result == -EIO);
	CHECK(xdev_ext_mech_completion_consume(&completion, token, &result) < 0);
	CHECK(!xdev_ext_mech_completion_begin(&completion, &next));
	CHECK(next > token);
	return true;
}

static bool test_completion_stale_duplicate_and_cancel(void)
{
	struct xdev_ext_mech_completion completion;
	__u64 old, current, ctrl;
	int result = 123;

	xdev_ext_mech_completion_init(&completion);
	CHECK(xdev_ext_mech_completion_claim(&completion, 0) < 0);
	CHECK(xdev_ext_mech_completion_cancel(&completion, 0) < 0);
	CHECK(xdev_ext_mech_completion_publish(&completion, 0, 2) < 0);
	CHECK(xdev_ext_mech_completion_consume(&completion, 0, &result) < 0);
	CHECK(result == 123);
	CHECK(!xdev_ext_mech_completion_begin(&completion, &old));
	CHECK(!xdev_ext_mech_completion_cancel(&completion, old));
	CHECK(xdev_ext_mech_completion_claim(&completion, old) < 0);
	CHECK(xdev_ext_mech_completion_publish(&completion, old, 4) < 0);
	CHECK(!xdev_ext_mech_completion_begin(&completion, &current));
	CHECK(current > old);
	ctrl = completion.ctrl;
	CHECK(xdev_ext_mech_completion_claim(&completion, old) < 0);
	CHECK(xdev_ext_mech_completion_publish(&completion, old, 5) < 0);
	CHECK(xdev_ext_mech_completion_cancel(&completion, old) < 0);
	CHECK(xdev_ext_mech_completion_consume(&completion, old, &result) < 0);
	CHECK(completion.ctrl == ctrl);
	CHECK(!xdev_ext_mech_completion_claim(&completion, current));
	CHECK(xdev_ext_mech_completion_claim(&completion, current) < 0);
	CHECK(!xdev_ext_mech_completion_publish(&completion, current, 4096));
	ctrl = completion.ctrl;
	CHECK(xdev_ext_mech_completion_publish(&completion, current, 8192) < 0);
	CHECK(completion.ctrl == ctrl);
	CHECK(completion.result == 4096);
	CHECK(!xdev_ext_mech_completion_consume(&completion, current, &result));
	CHECK(result == 4096);
	CHECK(!xdev_ext_mech_completion_begin(&completion, &old));
	CHECK(old > current);
	CHECK(!xdev_ext_mech_completion_claim(&completion, old));
	CHECK(!xdev_ext_mech_completion_publish(&completion, old, 333));
	CHECK(xdev_ext_mech_completion_consume(&completion, current, &result) < 0);
	CHECK(!xdev_ext_mech_completion_consume(&completion, old, &result));
	CHECK(result == 333);
	return true;
}

static bool test_completion_generation_exhaustion(void)
{
	struct xdev_ext_mech_completion completion;
	__u64 token, ctrl;

	xdev_ext_mech_completion_init(&completion);
	/* init establishes the private IDLE phase; preserve its low bits. */
	completion.ctrl |= (XDEV_EXT_MECH_L_GEN_MAX - 1) << PHASE_BITS;
	CHECK(!xdev_ext_mech_completion_begin(&completion, &token));
	CHECK(token == XDEV_EXT_MECH_L_GEN_MAX);
	CHECK(!xdev_ext_mech_completion_cancel(&completion, token));
	ctrl = completion.ctrl;
	CHECK(xdev_ext_mech_completion_begin(&completion, &token) == -EOVERFLOW);
	CHECK(completion.ctrl == ctrl);
	return true;
}

static bool test_completion_competition(void)
{
	struct xdev_ext_mech_completion completion;
	struct racer racers[RACERS];
	__u64 token;
	unsigned int round, winner = 0, published_winner;
	int result;

	for (round = 0; round < RACE_ROUNDS; round++) {
		xdev_ext_mech_completion_init(&completion);
		CHECK(contend(racers, COMPLETION_BEGIN, NULL, &completion, 0, &winner));
		token = racers[winner].token;
		CHECK(contend(racers, COMPLETION_CLAIM, NULL, &completion, token, &winner));
		CHECK(contend(racers, COMPLETION_PUBLISH, NULL, &completion, token,
			      &published_winner));
		CHECK(contend(racers, COMPLETION_CONSUME, NULL, &completion, token, &winner));
		CHECK(racers[winner].result == (int)(1000 + published_winner));
		CHECK(!xdev_ext_mech_completion_begin(&completion, &token));
		CHECK(contend(racers, COMPLETION_CANCEL_CLAIM, NULL, &completion, token,
			      &winner));
		if (winner & 1) {
			CHECK(!xdev_ext_mech_completion_publish(&completion, token, -ENOSPC));
			CHECK(!xdev_ext_mech_completion_consume(&completion, token, &result));
			CHECK(result == -ENOSPC);
		} else {
			CHECK(xdev_ext_mech_completion_claim(&completion, token) < 0);
			CHECK(xdev_ext_mech_completion_publish(&completion, token, 1) < 0);
		}
	}
	return true;
}

struct completion_reuse {
	struct xdev_ext_mech_completion completion;
	__u64 *tickets;
	bool ok;
};

static int completion_result(unsigned int i)
{
	return i & 1 ? -(int)(i + 1) : (int)(i + 1);
}

static void *read_completions(void *arg)
{
	struct completion_reuse *run = arg;
	struct timespec start;
	__u64 ticket;
	unsigned int i, spins = 0;
	int result;

	run->ok = true;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < COMPLETION_REUSES; i++) {
		/* Relaxed transfer gives the callback's ticket, not its result. */
		while (!(ticket = __atomic_load_n(&run->tickets[i], __ATOMIC_RELAXED))) {
			if (!(++spins % 1024) && deadline_passed(&start)) {
				run->ok = false;
				return NULL;
			}
		}
		while (xdev_ext_mech_completion_consume(&run->completion, ticket, &result)) {
			if (!(++spins % 1024) && deadline_passed(&start)) {
				run->ok = false;
				return NULL;
			}
		}
		/* Keep draining after a mismatch so the writer cannot be stranded. */
		if (result != completion_result(i))
			run->ok = false;
	}
	return NULL;
}

static bool test_completion_result_before_idle(void)
{
	struct completion_reuse run;
	struct timespec start;
	pthread_t reader;
	__u64 ticket;
	unsigned int i, spins = 0;
	bool submitted = true;

	run.tickets = calloc(COMPLETION_REUSES, sizeof(*run.tickets));
	CHECK(run.tickets != NULL);
	xdev_ext_mech_completion_init(&run.completion);
	CHECK(!pthread_create(&reader, NULL, read_completions, &run));
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < COMPLETION_REUSES; i++) {
		while (xdev_ext_mech_completion_begin(&run.completion, &ticket)) {
			if (!(++spins % 1024) && deadline_passed(&start)) {
				submitted = false;
				goto join;
			}
		}
		__atomic_store_n(&run.tickets[i], ticket, __ATOMIC_RELAXED);
		if (xdev_ext_mech_completion_claim(&run.completion, ticket) ||
		    xdev_ext_mech_completion_publish(&run.completion, ticket,
					completion_result(i))) {
			submitted = false;
			break;
		}
	}
join:
	CHECK(!pthread_join(reader, NULL));
	free(run.tickets);
	CHECK(submitted);
	CHECK(run.ok);
	return true;
}

int main(void)
{
	static const struct {
		const char *name;
		bool (*run)(void);
	} tests[] = {
		{ "serialized four-state stage chain", test_serialized_chain },
		{ "illegal edges leave ownership and metadata unchanged", test_illegal_edges_do_not_mutate },
		{ "duplicate publish preserves valid length", test_duplicate_publish_preserves_metadata },
		{ "stale operation after repeated frame reuse", test_stale_after_reuse },
		{ "preaccept refusal rolls back without publication", test_preaccept_rollback },
		{ "generation exhaustion refuses wraparound", test_generation_exhaustion },
		{ "simultaneous lifecycle contenders have one winner", test_lifecycle_competition },
		{ "consumer acquire observes payload and valid length", test_consumer_acquires_metadata },
		{ "callback claims before submit returns an error", test_completion_before_submit_returns },
		{ "completion reuse rejects stale and duplicate callbacks", test_completion_stale_duplicate_and_cancel },
		{ "completion generation exhaustion refuses wraparound", test_completion_generation_exhaustion },
		{ "simultaneous completion and cancellation contenders", test_completion_competition },
		{ "completion reads result before permitting immediate reuse", test_completion_result_before_idle },
	};
	unsigned int i, failed = 0;

	printf("TAP version 13\n1..%zu\n", sizeof(tests) / sizeof(tests[0]));
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		bool ok = tests[i].run();

		printf("%s %u - %s\n", ok ? "ok" : "not ok", i + 1, tests[i].name);
		failed += !ok;
	}
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
