// SPDX-License-Identifier: GPL-2.0
/* Exercise production portable helpers; this fixture is an event schedule,
 * not an allocator or replacement implementation of the batch state machine.
 */
/* L11: H2D final put recycles FREE before the D2H producer claims it. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"
#include "io_uring/xdev_ext_mech_step.h"
#include "io_uring/xdev_ext_mech_window.h"

#define DEPTH 2U
#define BYTES 8192U
#define GROUPS 256U
static unsigned int checks, failures;
static bool check(bool ok, const char *expr, unsigned int line)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "%s:%u: %s\n", __FILE__, line, expr);
	}
	return ok;
}
#define REQUIRE(c) do { if (!check(!!(c), #c, __LINE__)) return false; } while (0)

struct batch_fixture {
	struct xdev_ext_mech_bstate state;
	struct xdev_ext_mech_life frame;
	struct xdev_ext_mech_completion completion;
	__u32 slot;
	__u64 key, ticket, life_token, retired_ticket, retired_life, h2d_offset;
};

/* A callback delivered after a newer owner has submitted cannot alter it. */
static bool stale_callback(struct batch_fixture *b)
{
	__u64 ctrl = b->completion.ctrl;
	int result = 12345;

	if (!b->retired_ticket)
		return true;
	REQUIRE(xdev_ext_mech_completion_claim(&b->completion, b->retired_ticket) == -ESTALE);
	REQUIRE(xdev_ext_mech_completion_publish(&b->completion, b->retired_ticket, -EIO) == -ESTALE);
	REQUIRE(xdev_ext_mech_completion_consume(&b->completion, b->retired_ticket, &result) == -ESTALE);
	REQUIRE(result == 12345);
	REQUIRE(b->completion.ctrl == ctrl);
	return true;
}

static bool submit_stage(struct batch_fixture *b)
{
	__u64 offset = UINT64_MAX;
	__u64 ignored = 0;
	struct xdev_ext_mech_bstate before;

	REQUIRE(b->state.state == XDEV_EXT_MECH_B_READY);
	before = b->state;
	REQUIRE(xdev_ext_mech_batch_step(&b->state, XDEV_EXT_MECH_EV_RELEASE, 0) == -EINVAL);
	REQUIRE(b->state.state == before.state && b->state.stage == before.stage);
	REQUIRE(xdev_ext_mech_batch_step(&b->state, XDEV_EXT_MECH_EV_READY, 0) == -EINVAL);
	REQUIRE(xdev_ext_mech_batch_step(&b->state, XDEV_EXT_MECH_EV_SUBMIT, 0) == 0);
	REQUIRE(xdev_ext_mech_batch_step(&b->state, XDEV_EXT_MECH_EV_RELEASE, 0) == -EINVAL);
	if (b->state.stage == 0 || b->state.stage == 2)
		REQUIRE(xdev_ext_mech_life_claim(&b->frame, b->state.stage, &b->life_token) == 0);
	else
		REQUIRE(xdev_ext_mech_life_acquire(&b->frame, b->state.stage, 0, &b->life_token) == 0);
	REQUIRE(xdev_ext_mech_life_claim(&b->frame, 0, &ignored) == -EBUSY);
	REQUIRE(xdev_ext_mech_life_release(&b->frame, xdev_ext_mech_life_claim_gen(b->life_token)) == -EBUSY);
	if (b->retired_life) {
		__u64 ctrl = b->frame.ctrl;
		REQUIRE(xdev_ext_mech_life_release(&b->frame, b->retired_life) == -EBUSY);
		REQUIRE(b->frame.ctrl == ctrl);
	}
	REQUIRE(xdev_ext_mech_completion_begin(&b->completion, &b->ticket) == 0);
	REQUIRE(xdev_ext_mech_completion_begin(&b->completion, &ignored) == -EBUSY);
	REQUIRE(stale_callback(b));
	if (b->state.stage == 1 || b->state.stage == 2) {
		REQUIRE(xdev_ext_mech_window_offset(b->slot, DEPTH, BYTES,
			DEPTH * BYTES, &offset) == 0);
		REQUIRE(offset == (__u64)b->slot * BYTES);
		if (b->state.stage == 1)
			b->h2d_offset = offset;
		else
			REQUIRE(offset == b->h2d_offset);
	}
	return true;
}

static bool admit(struct batch_fixture *b, __u64 key)
{
	REQUIRE(b->state.state == XDEV_EXT_MECH_B_FREE);
	b->key = key;
	REQUIRE(xdev_ext_mech_batch_step(&b->state, XDEV_EXT_MECH_EV_READY, 0) == 0);
	return submit_stage(b);
}

static bool complete_stage(struct batch_fixture *b, bool *finished)
{
	__u32 stage = b->state.stage;
	int status = 0, err = -999, result = -999;

	*finished = false;
	REQUIRE(b->state.state == XDEV_EXT_MECH_B_IN_FLIGHT);
	REQUIRE(xdev_ext_mech_completion_claim(&b->completion, b->ticket) == 0);
	REQUIRE(xdev_ext_mech_completion_claim(&b->completion, b->ticket) == -ESTALE);
	if (stage == 1 || stage == 2) {
		__u32 outcome;
		status = xdev_ext_ce_completion_status(0, true, BYTES, BYTES);
		REQUIRE(status == 0);
		outcome = xdev_ext_ce_classify(status, true);
		REQUIRE(!xdev_ext_ce_disposition(outcome, status, &err));
		REQUIRE(err == 0);
	}
	if (stage == 0 || stage == 2)
		REQUIRE(xdev_ext_mech_life_publish(&b->frame, b->life_token, 1, BYTES) == 0);
	else
		REQUIRE(xdev_ext_mech_life_put(&b->frame, b->life_token) == XDEV_EXT_MECH_L_FREED);
	REQUIRE(xdev_ext_mech_completion_publish(&b->completion, b->ticket, status) == 0);
	REQUIRE(xdev_ext_mech_completion_consume(&b->completion, b->ticket, &result) == 0);
	REQUIRE(result == 0);
	REQUIRE(xdev_ext_mech_complete_step(stage == 1 || stage == 2 ?
		XDEV_EXT_MECH_CLASS_CE : XDEV_EXT_MECH_CLASS_NVME,
		XDEV_EXT_MECH_NEXT, result, false, false, 0, &err) == XDEV_EXT_MECH_STEP_NEXT);
	REQUIRE(xdev_ext_mech_batch_step(&b->state, XDEV_EXT_MECH_EV_NEXT, 0) == 0);
	b->retired_ticket = b->ticket;
	if (b->state.state != XDEV_EXT_MECH_B_DONE)
		return submit_stage(b);
	REQUIRE(stage == 3);
	REQUIRE(xdev_ext_mech_life_phase(&b->frame) == XDEV_EXT_MECH_L_FREE);
	b->retired_life = xdev_ext_mech_life_claim_gen(b->life_token);
	REQUIRE(xdev_ext_mech_batch_step(&b->state, XDEV_EXT_MECH_EV_RELEASE, 0) == 0);
	*finished = true;
	return true;
}

static bool reordered_campaign(void)
{
	struct batch_fixture batches[DEPTH] = { 0 };
	unsigned int admitted = DEPTH, done = 0, inversions = 0, non_modulo = 0;

	for (__u32 i = 0; i < DEPTH; i++) {
		batches[i].slot = i;
		xdev_ext_mech_bstate_init(&batches[i].state, 4);
		xdev_ext_mech_life_init(&batches[i].frame);
		xdev_ext_mech_completion_init(&batches[i].completion);
		REQUIRE(admit(&batches[i], i));
	}
	/* Most callbacks favour slot 1. Slot 0 remains live across many reuses. */
	for (unsigned int tick = 1; tick <= GROUPS * 16 && done < GROUPS; tick++) {
		unsigned int pick = tick % 19 ? 1 : 0;
		struct batch_fixture *b, *other;
		bool finished;

		if (batches[pick].state.state == XDEV_EXT_MECH_B_FREE)
			pick ^= 1;
		b = &batches[pick];
		other = &batches[pick ^ 1];
		if (other->state.state == XDEV_EXT_MECH_B_IN_FLIGHT && b->key > other->key)
			inversions++;
		REQUIRE(complete_stage(b, &finished));
		if (!finished)
			continue;
		done++;
		if (admitted < GROUPS) {
			if (admitted % DEPTH != b->slot)
				non_modulo++;
			REQUIRE(admit(b, admitted++));
		}
	}
	REQUIRE(done == GROUPS && admitted == GROUPS);
	REQUIRE(inversions > GROUPS && non_modulo > 0);
	for (__u32 i = 0; i < DEPTH; i++) {
		REQUIRE(batches[i].state.state == XDEV_EXT_MECH_B_FREE);
		REQUIRE(xdev_ext_mech_life_phase(&batches[i].frame) == XDEV_EXT_MECH_L_FREE);
	}
	printf("reordered campaign: %u groups, %u out-of-order callbacks, %u non-modulo admissions\n",
	       done, inversions, non_modulo);
	return true;
}

static bool ambiguous_keeps_slot(void)
{
	struct batch_fixture b = { .slot = 0 };
	__u8 frame_state = XDEV_EXT_MECH_F_INFLIGHT;
	int status, result = 0, err;
	__u32 outcome;
	bool sequestered;
	bool finished;

	xdev_ext_mech_bstate_init(&b.state, 4);
	xdev_ext_mech_life_init(&b.frame);
	xdev_ext_mech_completion_init(&b.completion);
	REQUIRE(admit(&b, 0));
	REQUIRE(complete_stage(&b, &finished));
	REQUIRE(!finished && b.state.stage == 1);
	/* Submitted success with a short transfer is ambiguous, never reusable. */
	status = xdev_ext_ce_completion_status(0, true, BYTES - 1, BYTES);
	REQUIRE(status == -EIO);
	outcome = xdev_ext_ce_classify(status, true);
	sequestered = xdev_ext_ce_disposition(outcome, status, &err);
	REQUIRE(sequestered && outcome == XDEV_EXT_CE_AMBIGUOUS);
	REQUIRE(xdev_ext_mech_completion_claim(&b.completion, b.ticket) == 0);
	REQUIRE(xdev_ext_mech_completion_publish(&b.completion, b.ticket, err) == 0);
	REQUIRE(xdev_ext_mech_completion_consume(&b.completion, b.ticket, &result) == 0);
	REQUIRE(xdev_ext_mech_complete_step(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_NEXT,
		result, sequestered, false, 0, &err) == XDEV_EXT_MECH_STEP_SEQUESTER);
	REQUIRE(xdev_ext_mech_batch_step(&b.state, XDEV_EXT_MECH_EV_SEQUESTER, 0) == 0);
	REQUIRE(xdev_ext_mech_frame_move(&frame_state, XDEV_EXT_MECH_F_INFLIGHT,
		XDEV_EXT_MECH_F_SEQUESTERED) == 0);
	for (unsigned int retry = 0; retry < 256; retry++) {
		REQUIRE(xdev_ext_mech_batch_step(&b.state, XDEV_EXT_MECH_EV_RELEASE, 0) == -EINVAL);
		REQUIRE(xdev_ext_mech_batch_step(&b.state, XDEV_EXT_MECH_EV_READY, 0) == -EINVAL);
		REQUIRE(xdev_ext_mech_life_release(&b.frame, xdev_ext_mech_life_claim_gen(b.life_token)) == -EBUSY);
		REQUIRE(xdev_ext_mech_completion_claim(&b.completion, b.ticket) == -ESTALE);
		REQUIRE(xdev_ext_mech_frame_move(&frame_state, XDEV_EXT_MECH_F_SEQUESTERED,
			XDEV_EXT_MECH_F_K_FREE) == -EINVAL);
	}
	REQUIRE(b.state.state == XDEV_EXT_MECH_B_SEQUESTERED);
	return true;
}

int main(void)
{
	bool ok = reordered_campaign() && ambiguous_keeps_slot();
	printf("window lifecycle: %u checks, %u failures\n", checks, failures);
	return !ok || !!failures;
}
