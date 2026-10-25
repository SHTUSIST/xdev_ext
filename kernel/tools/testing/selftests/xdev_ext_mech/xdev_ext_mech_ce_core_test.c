// SPDX-License-Identifier: GPL-2.0
/*
 * User-space checks of the copy-engine class rules in
 * io_uring/xdev_ext_mech_ce_core.h that the kernel runs unchanged: copy plan
 * validation and translation, the completion classifier and what C does with
 * each outcome, the cookie state word and the completion copy.
 * Build with -I <kernel tree>.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_ce_core.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                              \
	long long _expected = (long long)(expected);                          \
	checks++;                                                              \
	if (_actual != _expected) {                                            \
		fprintf(stderr, "%s:%d: got %lld, expected %lld\n",             \
			__FILE__, __LINE__, _actual, _expected);                    \
		failures++;                                                     \
	}                                                                       \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

_Static_assert(sizeof(struct xdev_ext_ce_copy_desc) == 24, "CE descriptor size");
_Static_assert(sizeof(struct xdev_ext_ce_mech_cqe) == 24, "CE completion size");
_Static_assert(XDEV_EXT_CE_MAX_ENTRIES == 32, "CE plan cap changed");
_Static_assert(XDEV_EXT_CE_CK_IDLE == 0,
	       "a zeroed batch area must hold an idle cookie");

#define KIB		1024U
#define SEG		(64U * KIB)
#define FRAME		4096U
#define NR_POOL		16U
#define HOST_BYTES	((uint64_t)NR_POOL * FRAME)

/* A 1 MiB window in 64 KiB segments over a 16-frame pool. */
static struct xdev_ext_ce_geom geom(uint32_t seg, uint32_t max_entry)
{
	struct xdev_ext_ce_geom g;

	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 1024 * KIB, 1024 * KIB, seg, max_entry,
				   HOST_BYTES, 0, FRAME, NR_POOL), 0);
	return g;
}

/* Three NXP-like frames: 1432 + 1432 + 1000 payload bytes after 360. */
static const struct xdev_ext_mech_frame_info frames[3] = {
	{ .umem_addr = 2 * FRAME, .data_off = 360, .data_len = 1432 },
	{ .umem_addr = 5 * FRAME, .data_off = 360, .data_len = 1432 },
	{ .umem_addr = 7 * FRAME, .data_off = 360, .data_len = 1000 },
};
static const uint32_t pool_index[3] = { 2, 5, 7 };

static struct xdev_ext_ce_copy_desc ent(uint32_t pos, uint32_t off, uint64_t gpu,
				   uint32_t len, uint32_t flags)
{
	struct xdev_ext_ce_copy_desc d = {
		.frame_pos = pos, .frame_off = off, .gpu_off = gpu,
		.len = len, .flags = flags,
	};

	return d;
}

/* The canonical plan: one entry per frame, packed in the window. */
static void good_plan(struct xdev_ext_ce_copy_desc *d)
{
	d[0] = ent(0, 360, 0, 1432, 0);
	d[1] = ent(1, 360, 1432, 1432, 0);
	d[2] = ent(2, 360, 2864, 1000, XDEV_EXT_CE_F_COMPLETION_POINT);
}

static int check(const struct xdev_ext_ce_geom *g, const struct xdev_ext_ce_copy_desc *d,
		 uint32_t n)
{
	struct xdev_ext_ce_plan plan;

	return xdev_ext_ce_plan_check(g, frames, pool_index, 3, d, n, &plan);
}

static void test_geometry(void)
{
	struct xdev_ext_ce_geom g;

	g = geom(SEG, 0);
	EXPECT_EQ(g.window_len, 1024 * KIB);
	EXPECT_EQ(g.seg_size, SEG);
	EXPECT_EQ(g.host_bytes, HOST_BYTES);

	/* max_entry_len 0 means the segment; no segment means any u32. */
	EXPECT_EQ(xdev_ext_ce_max_entry_len(SEG, 0), SEG);
	EXPECT_EQ(xdev_ext_ce_max_entry_len(0, 0), UINT32_MAX);
	EXPECT_EQ(xdev_ext_ce_max_entry_len(SEG, 512), 512);
	EXPECT_EQ(xdev_ext_ce_max_entry_len(0, 512), 512);
	EXPECT_EQ(geom(SEG, 0).max_entry_len, SEG);
	EXPECT_EQ(geom(0, 0).max_entry_len, UINT32_MAX);

	/* The backend binds exactly the requested, non-empty window. */
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 0, 0, SEG, 0, HOST_BYTES, 0, FRAME,
				   NR_POOL), -EINVAL);
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 8192, SEG, 0, HOST_BYTES, 0,
				   FRAME, NR_POOL), -EINVAL);
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 8192, 4096, SEG, 0, HOST_BYTES, 0,
				   FRAME, NR_POOL), -EINVAL);

	/* Every chunk of the pool lies inside the bind_host() pages. */
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 4096, 0, 0, HOST_BYTES, 0, 0,
				   NR_POOL), -EINVAL);
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 4096, 0, 0, HOST_BYTES, 0, FRAME,
				   0), -EINVAL);
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 4096, 0, 0, HOST_BYTES, 0, FRAME,
				   NR_POOL + 1), -EINVAL);
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 4096, 0, 0, HOST_BYTES, 1, FRAME,
				   NR_POOL), -EINVAL);
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 4096, 0, 0, HOST_BYTES + 512, 512,
				   FRAME, NR_POOL), 0);
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 4096, 0, 0, UINT64_MAX, UINT32_MAX,
				   UINT32_MAX, UINT32_MAX), 0);
}

static void test_host_offset(void)
{
	struct xdev_ext_ce_geom g;
	__u64 off = 0;

	/* Chunk 0 starts first_page_off into the first page. */
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 4096, 0, 0, HOST_BYTES + 512, 512,
				   FRAME, NR_POOL), 0);
	EXPECT_EQ(xdev_ext_ce_host_off(&g, 0, 0, 1, &off), 0);
	EXPECT_EQ(off, 512);
	EXPECT_EQ(xdev_ext_ce_host_off(&g, 3, 360, 1432, &off), 0);
	EXPECT_EQ(off, 512 + 3 * FRAME + 360);
	EXPECT_EQ(xdev_ext_ce_host_off(&g, NR_POOL - 1, 0, FRAME, &off), 0);
	EXPECT_EQ(off, 512 + (NR_POOL - 1) * FRAME);

	off = 77;
	EXPECT_EQ(xdev_ext_ce_host_off(&g, NR_POOL, 0, 1, &off), -ERANGE);
	EXPECT_EQ(xdev_ext_ce_host_off(&g, 0, FRAME - 1, 2, &off), -ERANGE);
	EXPECT_EQ(xdev_ext_ce_host_off(&g, 0, UINT32_MAX, 2, &off), -ERANGE);
	EXPECT_EQ(xdev_ext_ce_host_off(&g, 0, 0, FRAME + 1, &off), -ERANGE);
	EXPECT_EQ(off, 77);

	/* A pool that does not fill its last page still stays in bounds. */
	EXPECT_EQ(xdev_ext_ce_geom_init(&g, 4096, 4096, 0, 0, 3 * FRAME, 0, 1000,
				   3), 0);
	EXPECT_EQ(xdev_ext_ce_host_off(&g, 2, 0, 1000, &off), 0);
	EXPECT_EQ(off, 2000);
}

static void test_plan_accepted(void)
{
	struct xdev_ext_ce_geom g = geom(SEG, 0);
	struct xdev_ext_ce_copy_desc d[XDEV_EXT_CE_MAX_ENTRIES];
	struct xdev_ext_ce_plan plan;
	struct xdev_ext_mech_frame_info f[3];
	uint32_t index[3];
	uint32_t i;

	good_plan(d);
	memset(&plan, 0xa5, sizeof(plan));
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, frames, pool_index, 3, d, 3, &plan), 0);
	EXPECT_EQ(plan.n, 3);
	EXPECT_EQ(plan.total, 1432 + 1432 + 1000);
	EXPECT_EQ(plan.host_off[0], 2 * FRAME + 360);
	EXPECT_EQ(plan.host_off[1], 5 * FRAME + 360);
	EXPECT_EQ(plan.host_off[2], 7 * FRAME + 360);

	/* Both known flags; one frame split into two entries, reordered on the GPU. */
	d[0] = ent(0, 360, 8192, 1000,
		   XDEV_EXT_CE_F_COMPLETION_POINT | XDEV_EXT_CE_F_BARRIER);
	d[1] = ent(0, 1360, 0, 432, XDEV_EXT_CE_F_BARRIER);
	d[2] = ent(1, 360, 4096, 1432, 0);
	d[3] = ent(2, 360, 2048, 1000, 0);
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, frames, pool_index, 3, d, 4, &plan), 0);
	EXPECT_EQ(plan.n, 4);
	EXPECT_EQ(plan.host_off[1], 2 * FRAME + 1360);

	/* Entries that end exactly at a segment end and start the next one. */
	d[0] = ent(0, 360, SEG - 1432, 1432, 0);
	d[1] = ent(1, 360, SEG, 1432, 0);
	d[2] = ent(2, 360, 1024 * KIB - 1000, 1000, 0);
	EXPECT_EQ(check(&g, d, 3), 0);

	/* No segment: an entry may span what would be a segment boundary. */
	g = geom(0, 0);
	d[0] = ent(0, 360, SEG - 100, 1432, 0);
	d[1] = ent(1, 360, SEG + 1332, 1432, 0);
	d[2] = ent(2, 360, 2 * SEG, 1000, 0);
	EXPECT_EQ(check(&g, d, 3), 0);

	/* An empty frame span needs no entry. */
	memcpy(f, frames, sizeof(f));
	memcpy(index, pool_index, sizeof(index));
	f[1].data_len = 0;
	g = geom(SEG, 0);
	d[0] = ent(0, 360, 0, 1432, 0);
	d[1] = ent(2, 360, 4096, 1000, 0);
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, f, index, 3, d, 2, &plan), 0);
	EXPECT_EQ(plan.total, 2432);

	/*
	 * GPU side overlap within one batch is accepted (the caller's
	 * responsibility): with the next entry, with an earlier entry, and all
	 * entries on the same bytes.  Host offsets and the total are unchanged:
	 * the total is the sum of entry lengths, not the GPU bytes touched.
	 */
	g = geom(SEG, 0);
	good_plan(d);
	d[1].gpu_off = 1431;
	memset(&plan, 0xa5, sizeof(plan));
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, frames, pool_index, 3, d, 3, &plan), 0);
	EXPECT_EQ(plan.n, 3);
	EXPECT_EQ(plan.total, 1432 + 1432 + 1000);
	EXPECT_EQ(plan.host_off[0], 2 * FRAME + 360);
	EXPECT_EQ(plan.host_off[1], 5 * FRAME + 360);
	EXPECT_EQ(plan.host_off[2], 7 * FRAME + 360);
	good_plan(d);
	d[2].gpu_off = 1000;
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, frames, pool_index, 3, d, 3, &plan), 0);
	EXPECT_EQ(plan.total, 1432 + 1432 + 1000);
	good_plan(d);
	d[2].gpu_off = 0;
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, frames, pool_index, 3, d, 3, &plan), 0);
	EXPECT_EQ(plan.total, 1432 + 1432 + 1000);
	good_plan(d);
	d[0].gpu_off = d[1].gpu_off = d[2].gpu_off = 4096;
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, frames, pool_index, 3, d, 3, &plan), 0);
	EXPECT_EQ(plan.n, 3);
	EXPECT_EQ(plan.total, 1432 + 1432 + 1000);

	/* 32 entries of 32 bytes each cover one 1024-byte span. */
	f[0] = (struct xdev_ext_mech_frame_info){ .data_off = 0, .data_len = 1024 };
	for (i = 0; i < XDEV_EXT_CE_MAX_ENTRIES; i++)
		d[i] = ent(0, i * 32, (uint64_t)i * 64, 32, 0);
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, f, index, 1, d, XDEV_EXT_CE_MAX_ENTRIES,
				    &plan), 0);
	EXPECT_EQ(plan.n, XDEV_EXT_CE_MAX_ENTRIES);
}

static void test_plan_rejected(void)
{
	struct xdev_ext_ce_geom g = geom(SEG, 0);
	struct xdev_ext_ce_copy_desc d[XDEV_EXT_CE_MAX_ENTRIES + 1];
	struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES + 1];
	uint32_t index[XDEV_EXT_MECH_MAX_FRAMES + 1];
	struct xdev_ext_ce_plan plan;
	uint32_t i;

	memset(d, 0, sizeof(d));

	/* Entry count: at least one, at most 32. */
	good_plan(d);
	EXPECT_EQ(check(&g, d, 0), -EINVAL);
	EXPECT_EQ(check(&g, d, XDEV_EXT_CE_MAX_ENTRIES + 1), -E2BIG);

	/* len 0. */
	good_plan(d);
	d[1].len = 0;
	EXPECT_EQ(check(&g, d, 3), -EINVAL);

	/* Unknown flag bits. */
	for (i = 2; i < 32; i++) {
		good_plan(d);
		d[2].flags |= 1U << i;
		EXPECT_EQ(check(&g, d, 3), -EOPNOTSUPP);
	}

	/* Longer than the backend's largest entry. */
	g = geom(SEG, 1024);
	good_plan(d);
	EXPECT_EQ(check(&g, d, 3), -EMSGSIZE);
	g = geom(SEG, 0);

	/* Frame side: unknown frame, before the span, a gap, out of order. */
	good_plan(d);
	d[2].frame_pos = 3;
	EXPECT_EQ(check(&g, d, 3), -EINVAL);
	good_plan(d);
	d[0].frame_off = 359;
	EXPECT_EQ(check(&g, d, 3), -EINVAL);
	good_plan(d);
	d[0] = ent(0, 360, 0, 1000, 0);
	d[1] = ent(0, 1361, 1000, 431, 0);
	EXPECT_EQ(check(&g, d, 3), -EINVAL);
	good_plan(d);
	d[0] = ent(1, 360, 0, 1432, 0);
	d[1] = ent(0, 360, 1432, 1432, 0);
	EXPECT_EQ(check(&g, d, 3), -EINVAL);

	/* Frame side overlap: the second piece restarts inside the first. */
	d[0] = ent(0, 360, 0, 1000, 0);
	d[1] = ent(0, 1000, 1000, 792, 0);
	d[2] = ent(1, 360, 4096, 1432, 0);
	d[3] = ent(2, 360, 8192, 1000, 0);
	EXPECT_EQ(check(&g, d, 4), -EINVAL);

	/* Frame side: past the span, and an entry after full coverage. */
	good_plan(d);
	d[2].len = 1001;
	EXPECT_EQ(check(&g, d, 3), -ERANGE);
	good_plan(d);
	d[3] = ent(2, 1360, 8192, 1, 0);
	EXPECT_EQ(check(&g, d, 4), -ERANGE);

	/* Entries that do not cover the whole batch. */
	good_plan(d);
	EXPECT_EQ(check(&g, d, 2), -ENODATA);
	good_plan(d);
	d[2].len = 999;
	EXPECT_EQ(check(&g, d, 3), -ENODATA);

	/* GPU side outside the window, including a wrapping offset. */
	good_plan(d);
	d[2].gpu_off = 1024 * KIB - 999;
	EXPECT_EQ(check(&g, d, 3), -ERANGE);
	good_plan(d);
	d[0].gpu_off = UINT64_MAX - 100;
	EXPECT_EQ(check(&g, d, 3), -ERANGE);

	/* GPU side crossing a C-computed contiguous segment. */
	good_plan(d);
	d[1].gpu_off = SEG - 1;
	EXPECT_EQ(check(&g, d, 3), -EXDEV);
	g = geom(4096, 0);
	good_plan(d);
	d[0].gpu_off = 4096 - 1;
	EXPECT_EQ(check(&g, d, 3), -EXDEV);
	g = geom(SEG, 0);

	/*
	 * GPU side overlap is the caller's responsibility, so it never masks a
	 * fault found later: an overlapping entry whose host side is outside
	 * its chunk is -ERANGE (this plan was -EEXIST while the kernel checked
	 * overlap, because that check ran before host-side translation).
	 */
	memcpy(f, frames, sizeof(frames));
	memcpy(index, pool_index, sizeof(pool_index));
	f[2].data_off = FRAME - 500;
	good_plan(d);
	d[2].frame_off = FRAME - 500;
	d[2].gpu_off = 0;
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, f, index, 3, d, 3, &plan), -ERANGE);
	/* An overlapping entry is still confined to the window. */
	good_plan(d);
	d[2].gpu_off = 0;
	d[1].gpu_off = 1024 * KIB - 1000;
	EXPECT_EQ(check(&g, d, 3), -ERANGE);

	/* Host side: a frame span outside its chunk or a chunk outside the pool. */
	memcpy(f, frames, sizeof(frames));
	memcpy(index, pool_index, sizeof(pool_index));
	f[2].data_off = FRAME - 500;
	good_plan(d);
	d[2].frame_off = FRAME - 500;
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, f, index, 3, d, 3, &plan), -ERANGE);
	memcpy(f, frames, sizeof(frames));
	index[1] = NR_POOL;
	good_plan(d);
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, f, index, 3, d, 3, &plan), -ERANGE);

	/* More frames than a batch can have. */
	for (i = 0; i <= XDEV_EXT_MECH_MAX_FRAMES; i++) {
		f[i] = (struct xdev_ext_mech_frame_info){ .data_off = 0, .data_len = 1 };
		index[i] = 0;
		d[i] = ent(i, 0, i, 1, 0);
	}
	EXPECT_EQ(xdev_ext_ce_plan_check(&g, f, index, XDEV_EXT_MECH_MAX_FRAMES + 1, d,
				    XDEV_EXT_CE_MAX_ENTRIES, &plan), -EINVAL);
}

/* status, hw_submitted -> outcome: the classification belongs to C. */
static void test_classifier(void)
{
	static const int fails[] = { -EIO, -EBUSY, -ETIMEDOUT, 1, 0x1f, -4095 };
	unsigned int i;

	EXPECT_EQ(xdev_ext_ce_classify(0, false), XDEV_EXT_CE_OK);
	EXPECT_EQ(xdev_ext_ce_classify(0, true), XDEV_EXT_CE_OK);
	for (i = 0; i < sizeof(fails) / sizeof(fails[0]); i++) {
		EXPECT_EQ(xdev_ext_ce_classify(fails[i], false),
			  XDEV_EXT_CE_PRE_SUBMIT_FAILED);
		EXPECT_EQ(xdev_ext_ce_classify(fails[i], true), XDEV_EXT_CE_AMBIGUOUS);
	}
}

static int event_of(int32_t ret)
{
	switch (ret) {
	case XDEV_EXT_MECH_NEXT:
		return XDEV_EXT_MECH_EV_NEXT;
	case XDEV_EXT_MECH_DONE:
		return XDEV_EXT_MECH_EV_DONE;
	case XDEV_EXT_MECH_RETRY:
		return XDEV_EXT_MECH_EV_RETRY;
	default:
		return XDEV_EXT_MECH_EV_ABORT;
	}
}

/*
 * An AMBIGUOUS transfer sequesters the batch before the program runs, so no
 * program return can move it on; the other outcomes complete it with a
 * status the core's RETRY rule accepts only for PRE_SUBMIT_FAILED.
 */
static void test_disposition(void)
{
	static const int statuses[] = { 0, -EIO, -EBUSY, 0x1f, -5000 };
	unsigned int i, hw;
	int32_t ret;
	uint32_t r;

	for (i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
		for (hw = 0; hw < 2; hw++) {
			int status = statuses[i];
			uint32_t outcome = xdev_ext_ce_classify(status, hw);
			int err = 12345;
			bool seq = xdev_ext_ce_disposition(outcome, status, &err);

			EXPECT_EQ(seq, outcome == XDEV_EXT_CE_AMBIGUOUS);
			if (seq) {
				EXPECT_TRUE(err < 0 && err >= -4095);
				EXPECT_EQ(err, status == -EIO || status == -EBUSY ?
					  status : -EIO);
				continue;
			}
			EXPECT_EQ(err, (int)outcome);
			for (r = 0; r <= XDEV_EXT_MECH_RETRY_MAX_CE + 1; r++)
				EXPECT_EQ(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_CE, r,
							    err),
					  outcome == XDEV_EXT_CE_PRE_SUBMIT_FAILED &&
					  r < XDEV_EXT_MECH_RETRY_MAX_CE);
		}
	}

	/* AMBIGUOUS cannot become DONE (or anything else) afterwards. */
	for (ret = -5; ret <= 10; ret++) {
		struct xdev_ext_mech_bstate b;
		bool illegal;
		int32_t act;
		int err;

		xdev_ext_mech_bstate_init(&b, 3);
		EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_READY, 1), 0);
		EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_SUBMIT, 0), 0);
		EXPECT_TRUE(xdev_ext_ce_disposition(xdev_ext_ce_classify(-EIO, true),
					       -EIO, &err));
		EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_SEQUESTER, 0), 0);
		act = xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_CE,
					   XDEV_EXT_MECH_MEMBER_COMPLETE,
					   XDEV_EXT_MECH_SITE_WORKER, ret, &illegal);
		EXPECT_EQ(xdev_ext_mech_batch_step(&b, event_of(act), 0), -EINVAL);
		EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_DONE, 0), -EINVAL);
		EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_RELEASE, 0),
			  -EINVAL);
		EXPECT_EQ(b.state, XDEV_EXT_MECH_B_SEQUESTERED);
	}
}

/* One completion per accepted submit; a refused submit takes its arm back. */
static void test_cookie(void)
{
	uint8_t st = XDEV_EXT_CE_CK_IDLE;

	EXPECT_FALSE(xdev_ext_ce_cookie_finish(&st));	/* completion without submit */
	EXPECT_FALSE(xdev_ext_ce_cookie_disarm(&st));
	EXPECT_TRUE(xdev_ext_ce_cookie_arm(&st));
	EXPECT_EQ(st, XDEV_EXT_CE_CK_ARMED);
	EXPECT_FALSE(xdev_ext_ce_cookie_arm(&st));		/* still with the backend */
	EXPECT_TRUE(xdev_ext_ce_cookie_finish(&st));
	EXPECT_EQ(st, XDEV_EXT_CE_CK_DONE);
	EXPECT_FALSE(xdev_ext_ce_cookie_finish(&st));	/* second completion */
	EXPECT_FALSE(xdev_ext_ce_cookie_disarm(&st));	/* completed before refusing */
	EXPECT_EQ(st, XDEV_EXT_CE_CK_DONE);

	EXPECT_TRUE(xdev_ext_ce_cookie_arm(&st));		/* RETRY resubmits */
	EXPECT_TRUE(xdev_ext_ce_cookie_disarm(&st));
	EXPECT_EQ(st, XDEV_EXT_CE_CK_IDLE);
	EXPECT_FALSE(xdev_ext_ce_cookie_finish(&st));

	st = 7;						/* not a cookie state */
	EXPECT_FALSE(xdev_ext_ce_cookie_arm(&st));
	EXPECT_FALSE(xdev_ext_ce_cookie_finish(&st));
	EXPECT_EQ(st, 7);
}

static void test_cqe(void)
{
	struct xdev_ext_ce_mech_cqe c;

	memset(&c, 0xa5, sizeof(c));
	xdev_ext_ce_cqe_fill(&c, XDEV_EXT_CE_CK_DONE, XDEV_EXT_CE_OK, 0, 3864, 3864, 3);
	EXPECT_EQ(c.outcome, XDEV_EXT_CE_OK);
	EXPECT_EQ(c.backend_status, 0);
	EXPECT_EQ(c.bytes_done, 3864);
	EXPECT_EQ(c.entries_done, 3);
	EXPECT_EQ(c.rsvd, 0);

	/* A backend never claims more than the plan. */
	xdev_ext_ce_cqe_fill(&c, XDEV_EXT_CE_CK_DONE, XDEV_EXT_CE_OK, 0, 1ULL << 40, 3864, 3);
	EXPECT_EQ(c.bytes_done, 3864);

	xdev_ext_ce_cqe_fill(&c, XDEV_EXT_CE_CK_DONE, XDEV_EXT_CE_PRE_SUBMIT_FAILED, -EBUSY,
			1432, 3864, 3);
	EXPECT_EQ(c.outcome, XDEV_EXT_CE_PRE_SUBMIT_FAILED);
	EXPECT_EQ(c.backend_status, (uint32_t)-EBUSY);
	EXPECT_EQ(c.bytes_done, 1432);
	EXPECT_EQ(c.entries_done, 0);

	xdev_ext_ce_cqe_fill(&c, XDEV_EXT_CE_CK_DONE, XDEV_EXT_CE_AMBIGUOUS, -EIO, 3864, 3864,
			3);
	EXPECT_EQ(c.outcome, XDEV_EXT_CE_AMBIGUOUS);
	EXPECT_EQ(c.entries_done, 0);

	/* No completion arrived: never report the previous one. */
	xdev_ext_ce_cqe_fill(&c, XDEV_EXT_CE_CK_IDLE, XDEV_EXT_CE_OK, -ENODEV, 3864, 3864, 3);
	EXPECT_EQ(c.outcome, XDEV_EXT_CE_PRE_SUBMIT_FAILED);
	EXPECT_EQ(c.backend_status, (uint32_t)-ENODEV);
	EXPECT_EQ(c.bytes_done, 0);
	EXPECT_EQ(c.entries_done, 0);
	xdev_ext_ce_cqe_fill(&c, XDEV_EXT_CE_CK_ARMED, XDEV_EXT_CE_OK, 0, 3864, 3864, 3);
	EXPECT_EQ(c.outcome, XDEV_EXT_CE_PRE_SUBMIT_FAILED);
	EXPECT_EQ(c.entries_done, 0);
}

static void test_info(void)
{
	const struct xdev_ext_mech_layout l = {
		.frame_size = FRAME, .hdr_room = 360, .seg_len = 1432,
		.group_bytes = 3864,
	};
	struct xdev_ext_ce_geom g = geom(SEG, 0);
	struct xdev_ext_ce_mech_info info;
	unsigned int i;

	memset(&info, 0xa5, sizeof(info));
	EXPECT_EQ(xdev_ext_ce_info_fill(&info, &l, &g, frames, 3), 0);
	EXPECT_EQ(info.l.frame_size, FRAME);
	EXPECT_EQ(info.l.hdr_room, 360);
	EXPECT_EQ(info.l.seg_len, 1432);
	EXPECT_EQ(info.l.group_bytes, 3864);
	EXPECT_EQ(info.gpu_window_len, 1024 * KIB);
	EXPECT_EQ(info.gpu_seg_size, SEG);	/* from the region */
	EXPECT_EQ(info.max_entry_len, SEG);
	EXPECT_EQ(info.nr_frames, 3);
	EXPECT_EQ(info.rsvd, 0);
	for (i = 0; i < 3; i++) {
		EXPECT_EQ(info.f[i].umem_addr, frames[i].umem_addr);
		EXPECT_EQ(info.f[i].data_off, frames[i].data_off);
		EXPECT_EQ(info.f[i].data_len, frames[i].data_len);
	}
	for (; i < XDEV_EXT_MECH_MAX_FRAMES; i++)
		EXPECT_EQ(info.f[i].umem_addr | info.f[i].data_off |
			  info.f[i].data_len, 0);

	/* CREATE has no batch. */
	memset(&info, 0xa5, sizeof(info));
	EXPECT_EQ(xdev_ext_ce_info_fill(&info, &l, &g, NULL, 0), 0);
	EXPECT_EQ(info.nr_frames, 0);
	EXPECT_EQ(info.f[0].data_len, 0);

	EXPECT_EQ(xdev_ext_ce_info_fill(&info, &l, &g, frames,
				   XDEV_EXT_MECH_MAX_FRAMES + 1), -E2BIG);
}

int main(void)
{
	test_geometry();
	test_host_offset();
	test_plan_accepted();
	test_plan_rejected();
	test_classifier();
	test_disposition();
	test_cookie();
	test_cqe();
	test_info();

	if (failures) {
		fprintf(stderr, "FAIL: %u of %u checks\n", failures, checks);
		return 1;
	}
	printf("PASS: %u XDEV_EXT copy-engine class checks\n", checks);
	return 0;
}
