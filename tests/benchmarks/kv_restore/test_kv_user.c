// SPDX-License-Identifier: GPL-2.0
/*
 * Host test of kv_user.h, the user-space continuation of the E5 user modes
 * (kv_restore --dst user-copy / user-direct).  Requirement (E5 levels 2 and
 * 3): every group the USER stage hands over lands whole at
 * dst + (key - first_key) * group_bytes of the GPU allocation; user-copy
 * copies the group with the CPU into a pinned staging slot, returns the
 * frames at once and copies the slot to the GPU asynchronously, reusing a
 * slot only after its copy completed; user-direct copies straight from the
 * received frames (one copy per physically contiguous run) and returns the
 * frames only after the copy completed.  A key outside the restore, a group
 * of the wrong size or a failed library call ends the restore with an error,
 * after every copy in flight finished and every held batch was returned.
 *
 * The fake copy engine reads its source only when the copy's event
 * completes, and the fake USER stage poisons frames when they are returned,
 * so reusing a slot or returning a frame too early corrupts the result.
 * No device, no CUDA, no kernel.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/libxdev_ext.h"
#include "kv_user.h"

static unsigned checks, failures;
#define EXPECT(c, why) do { checks++; if (!(c)) { failures++; \
	fprintf(stderr, "%s:%d: FAIL %s\n", __FILE__, __LINE__, why); } } while (0)
#define EXPECT_EQ(a, b, why) do { long long _a = (long long)(a), _b = (long long)(b); \
	checks++; if (_a != _b) { failures++; \
	fprintf(stderr, "%s:%d: FAIL %s: got %lld want %lld\n", __FILE__, __LINE__, why, _a, _b); } \
	} while (0)

enum { FRAME = 4096, FPG = 4, GROUP = FRAME * FPG, MAXG = 8, RING = 4 * FPG, MAXSLOT = 8 };

struct pending { bool live; uint64_t dst; const uint8_t *src; size_t len; };

struct fake {
	uint8_t umem[RING * FRAME];
	uint8_t dev[MAXG * GROUP + GROUP];
	struct xdev_ext_user_batch script[MAXG];
	unsigned nr, next, again_left;
	int next_err_at, next_err;		/* return next_err at batch next_err_at */
	struct pending pend[MAXSLOT][64];
	unsigned npend[MAXSLOT];
	unsigned query_busy;			/* queries answering "not yet" before "done" */
	unsigned busy_left[MAXSLOT];
	unsigned h2d, completes, waits;
	int status[MAXG];			/* status per completed batch, by script index */
	bool returned[MAXG];
	int h2d_err_at;
};

static uint64_t key_of(unsigned i) { return 100 + i; }

static void fill_frame(uint8_t *p, uint64_t key, unsigned frame)
{
	for (unsigned i = 0; i < FRAME; i++)
		p[i] = (uint8_t)(key * 31 + frame * 7 + i);
}

/* Script batch i in ring frames frame0..frame0+FPG-1 (or the given order). */
static void script(struct fake *f, unsigned i, uint64_t key, const unsigned *frames)
{
	struct xdev_ext_user_batch *b = &f->script[i];

	memset(b, 0, sizeof(*b));
	b->slot = i % 4;
	b->ticket = 1000 + i;
	b->batch_id = i;
	b->key = key;
	b->nr_frames = FPG;
	for (unsigned k = 0; k < FPG; k++) {
		uint8_t *p = f->umem + frames[k] * FRAME;

		b->f[k] = (struct xdev_ext_user_frame){ .umem_addr = frames[k] * FRAME,
			.data_len = FRAME, .capacity = FRAME, .out_len = FRAME };
		b->data[k] = p;
	}
	if (i + 1 > f->nr)
		f->nr = i + 1;
}

static void place(struct fake *f, unsigned i)
{
	struct xdev_ext_user_batch *b = &f->script[i];

	for (unsigned k = 0; k < b->nr_frames; k++)
		fill_frame(b->data[k], b->key, k);
}

static int f_next(void *ctx, int timeout_ms, struct xdev_ext_user_batch *b)
{
	struct fake *f = ctx;

	(void)timeout_ms;
	if (f->next_err && (int)f->next == f->next_err_at)
		return f->next_err;
	if (f->again_left) {
		f->again_left--;
		return -EAGAIN;
	}
	if (f->next >= f->nr)
		return -EAGAIN;
	place(f, f->next);	/* the frames are written when the batch arrives */
	*b = f->script[f->next++];
	return 0;
}

static int f_complete(void *ctx, const struct xdev_ext_user_batch *b, int status)
{
	struct fake *f = ctx;
	unsigned i = (unsigned)b->batch_id;

	f->completes++;
	f->status[i] = status;
	f->returned[i] = true;
	for (unsigned k = 0; k < b->nr_frames; k++)
		memset(b->data[k], 0xEE, b->f[k].data_len);	/* recycled */
	return 0;
}

static int f_h2d(void *ctx, uint32_t slot, uint64_t dst, const void *src, size_t len)
{
	struct fake *f = ctx;

	if (f->h2d_err_at && (int)++f->h2d == f->h2d_err_at)
		return -EIO;
	if (!f->h2d_err_at)
		f->h2d++;
	f->pend[slot][f->npend[slot]++] = (struct pending){ true, dst, src, len };
	return 0;
}

static int f_record(void *ctx, uint32_t slot)
{
	struct fake *f = ctx;

	f->busy_left[slot] = f->query_busy;
	return 0;
}

static void land(struct fake *f, uint32_t slot)
{
	for (unsigned n = 0; n < f->npend[slot]; n++) {
		struct pending *p = &f->pend[slot][n];

		if (p->dst + p->len <= sizeof(f->dev))
			memcpy(f->dev + p->dst, p->src, p->len);
	}
	f->npend[slot] = 0;
}

static int f_query(void *ctx, uint32_t slot)
{
	struct fake *f = ctx;

	if (f->busy_left[slot]) {
		f->busy_left[slot]--;
		return -EAGAIN;
	}
	land(f, slot);
	return 0;
}

static int f_wait(void *ctx, uint32_t slot)
{
	struct fake *f = ctx;

	f->waits++;
	f->busy_left[slot] = 0;
	land(f, slot);
	return 0;
}

static const struct kv_user_ops ops = { .next = f_next, .complete = f_complete, .h2d = f_h2d,
	.record = f_record, .query = f_query, .wait = f_wait };

static struct kv_user_pipe pipe_for(struct fake *f, bool direct, uint32_t depth, uint64_t groups,
				    uint8_t *staging, struct xdev_ext_user_batch *held)
{
	struct kv_user_pipe p = { .ctx = f, .direct = direct, .depth = depth, .group_bytes = GROUP,
		.staging = staging, .held = held, .dst_base = GROUP, .first_key = key_of(0),
		.groups = groups, .timeout_ms = 1000 };

	return p;
}

/* Expected device image: group i (key first_key + i) at dst_base + i * GROUP. */
static bool device_ok(const struct fake *f, unsigned groups)
{
	uint8_t want[FRAME];

	for (unsigned i = 0; i < groups; i++)
		for (unsigned k = 0; k < FPG; k++) {
			fill_frame(want, key_of(0) + i, k);
			if (memcmp(f->dev + GROUP + i * GROUP + k * FRAME, want, FRAME))
				return false;
		}
	return true;
}

static void test_copy_reuses_slots_only_after_their_copy(void)
{
	static struct fake f;
	static uint8_t staging[2 * GROUP];
	struct kv_user_pipe p;
	/* Arrival order differs from key order: placement follows the key. */
	const unsigned order[5] = { 0, 2, 1, 4, 3 };

	memset(&f, 0, sizeof(f));
	for (unsigned i = 0; i < 5; i++) {
		unsigned frames[FPG];

		for (unsigned k = 0; k < FPG; k++)
			frames[k] = ((i % 4) * FPG + k);
		script(&f, i, key_of(order[i]), frames);
	}
	f.query_busy = 3;
	p = pipe_for(&f, false, 2, 5, staging, NULL);
	EXPECT_EQ(kv_user_run(&p, &ops), 0, "user-copy restore of 5 groups");
	EXPECT_EQ(f.completes, 5, "every batch returned");
	for (unsigned i = 0; i < 5; i++)
		EXPECT_EQ(f.status[i], 0, "status 0");
	EXPECT(device_ok(&f, 5), "every group at dst + (key - first_key) * group_bytes, intact");
	EXPECT_EQ(p.copied, 5ULL * GROUP, "CPU memcpy bytes counted");
	EXPECT_EQ(f.h2d, 5, "one GPU copy per group from the staging slot");
	EXPECT_EQ(p.retired, 5, "all retired");
}

static void test_direct_returns_frames_after_copy(void)
{
	static struct fake f;
	struct xdev_ext_user_batch held[3];
	struct kv_user_pipe p;
	/* Group 1's frames are split: 4,5 then 10,11 -> two runs. */
	const unsigned contiguous[FPG] = { 0, 1, 2, 3 }, split[FPG] = { 4, 5, 10, 11 },
		       reversed[FPG] = { 15, 14, 13, 12 };

	memset(&f, 0, sizeof(f));
	script(&f, 0, key_of(0), contiguous);
	script(&f, 1, key_of(1), split);
	script(&f, 2, key_of(2), reversed);
	f.query_busy = 2;
	p = pipe_for(&f, true, 3, 3, NULL, held);
	EXPECT_EQ(kv_user_run(&p, &ops), 0, "user-direct restore of 3 groups");
	EXPECT(device_ok(&f, 3), "groups intact although frames are recycled on return");
	EXPECT_EQ(p.copied, 0, "no CPU copy");
	EXPECT_EQ(f.h2d, 1 + 2 + 4, "one GPU copy per contiguous run");
	EXPECT_EQ(f.completes, 3, "every batch returned");
}

static void test_refusals(void)
{
	static struct fake f;
	static uint8_t staging[2 * GROUP];
	struct xdev_ext_user_batch held[2];
	struct kv_user_pipe p;
	const unsigned fr0[FPG] = { 0, 1, 2, 3 }, fr1[FPG] = { 4, 5, 6, 7 };

	memset(&f, 0, sizeof(f));
	script(&f, 0, key_of(0), fr0);
	script(&f, 1, key_of(0) + 9, fr1);	/* outside a 2-group restore */
	p = pipe_for(&f, false, 2, 2, staging, NULL);
	EXPECT_EQ(kv_user_run(&p, &ops), -EPROTO, "key outside the restore");
	EXPECT_EQ(f.completes, 2, "both batches returned");
	EXPECT_EQ(f.status[0], 0, "the good group completes");
	EXPECT(f.status[1] != 0, "the bad group fails");
	EXPECT_EQ(f.npend[0] + f.npend[1], 0, "no copy left in flight");

	memset(&f, 0, sizeof(f));
	script(&f, 0, key_of(0), fr0);
	f.script[0].nr_frames = FPG - 1;	/* short group */
	p = pipe_for(&f, true, 2, 1, NULL, held);
	EXPECT_EQ(kv_user_run(&p, &ops), -EPROTO, "group of the wrong size");
	EXPECT(f.status[0] != 0, "short group failed");

	memset(&f, 0, sizeof(f));
	script(&f, 0, key_of(0), fr0);
	script(&f, 1, key_of(1), fr1);
	f.query_busy = 5;
	f.next_err_at = 1;
	f.next_err = -ESHUTDOWN;
	p = pipe_for(&f, true, 2, 2, NULL, held);
	EXPECT_EQ(kv_user_run(&p, &ops), -ESHUTDOWN, "library error propagates");
	EXPECT_EQ(f.completes, 1, "the held batch is returned");
	EXPECT_EQ(f.npend[0] + f.npend[1], 0, "its copy finished first");

	memset(&f, 0, sizeof(f));
	script(&f, 0, key_of(0), fr0);
	script(&f, 1, key_of(1), fr1);
	f.h2d_err_at = 2;
	p = pipe_for(&f, false, 2, 2, staging, NULL);
	EXPECT_EQ(kv_user_run(&p, &ops), -EIO, "failed GPU copy");
	EXPECT_EQ(f.completes, 2, "both batches returned");

	memset(&f, 0, sizeof(f));
	p = pipe_for(&f, false, 0, 2, staging, NULL);
	EXPECT_EQ(kv_user_run(&p, &ops), -EINVAL, "depth 0");
	p = pipe_for(&f, false, 2, 2, NULL, NULL);
	EXPECT_EQ(kv_user_run(&p, &ops), -EINVAL, "user-copy without staging");
	p = pipe_for(&f, true, 2, 2, NULL, NULL);
	EXPECT_EQ(kv_user_run(&p, &ops), -EINVAL, "user-direct without held batches");
}

static void test_waits_when_nothing_arrives(void)
{
	static struct fake f;
	static uint8_t staging[2 * GROUP];
	struct kv_user_pipe p;
	const unsigned fr0[FPG] = { 0, 1, 2, 3 }, fr1[FPG] = { 4, 5, 6, 7 };

	memset(&f, 0, sizeof(f));
	script(&f, 0, key_of(0), fr0);
	script(&f, 1, key_of(1), fr1);
	f.query_busy = 1000;	/* only a blocking wait finishes a copy */
	p = pipe_for(&f, false, 2, 2, staging, NULL);
	EXPECT_EQ(kv_user_run(&p, &ops), 0, "copies finish through a blocking wait");
	EXPECT(f.waits >= 1, "blocked instead of spinning on query");
	EXPECT(device_ok(&f, 2), "data intact");
}

int main(void)
{
	test_copy_reuses_slots_only_after_their_copy();
	test_direct_returns_frames_after_copy();
	test_refusals();
	test_waits_when_nothing_arrives();
	printf("kv_user: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
