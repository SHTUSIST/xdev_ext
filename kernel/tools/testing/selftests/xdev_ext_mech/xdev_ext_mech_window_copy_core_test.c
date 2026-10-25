// SPDX-License-Identifier: GPL-2.0
/*
 * User-space checks of io_uring/xdev_ext_mech_window_copy_core.h, the rules
 * the copy-engine and DMA provider classes share, and of the three-outcome
 * classifier in io_uring/xdev_ext_mech_core.h that CE, DMA and NET use.
 * The kernel runs the same code.  Build with -I <kernel tree>.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_window_copy_core.h"

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

_Static_assert(sizeof(struct xdev_ext_window_copy_desc) == 24, "entry size");
_Static_assert(XDEV_EXT_WINDOW_COPY_CK_IDLE == 0,
	       "a zeroed batch area must hold an idle cookie");
_Static_assert(XDEV_EXT_WINDOW_COPY_DIRS == XDEV_EXT_DMA_DIR_KNOWN_MASK,
	       "window copy directions are the DMA direction bits");

#define FRAME		4096U
#define NR_POOL		16U
#define TO		XDEV_EXT_MECH_DIR_TO_DEVICE
#define FROM		XDEV_EXT_MECH_DIR_FROM_DEVICE

/* A 64 KiB window in 4 KiB segments over a 16-frame pool, 64-byte aligned. */
static struct xdev_ext_window_copy_geom geom(__u32 alignment, __u32 directions)
{
	return (struct xdev_ext_window_copy_geom){
		.window_len = 64 * 1024, .host_bytes = (__u64)NR_POOL * FRAME,
		.seg_size = 4096, .max_entry_len = 4096, .first_page_off = 0,
		.frame_size = FRAME, .nr_frames = NR_POOL,
		.alignment = alignment, .directions = directions,
	};
}

/* Two frames: 1024 bytes at 256 in chunk 2, 512 bytes at 256 in chunk 5. */
static const struct xdev_ext_mech_frame_info frames[2] = {
	{ .umem_addr = 2 * FRAME, .data_off = 256, .data_len = 1024 },
	{ .umem_addr = 5 * FRAME, .data_off = 256, .data_len = 512 },
};
static const __u32 pool_index[2] = { 2, 5 };

static struct xdev_ext_window_copy_desc ent(__u32 pos, __u32 off, __u64 dev,
					    __u32 len, __u32 flags)
{
	return (struct xdev_ext_window_copy_desc){
		.frame_pos = pos, .frame_off = off, .dev_off = dev,
		.len = len, .flags = flags,
	};
}

static void good(struct xdev_ext_window_copy_desc *d)
{
	d[0] = ent(0, 256, 0, 1024, 0);
	d[1] = ent(1, 256, 1024, 512, 1);
}

/* Run the check with a poisoned output; *total must move only on success. */
static int check(const struct xdev_ext_window_copy_geom *g, __u32 dir,
		 const struct xdev_ext_window_copy_desc *d, __u32 n, __u64 *off)
{
	__u64 total = 0x5a5a;
	int err;

	memset(off, 0xa5, XDEV_EXT_MECH_MAX_FRAMES * sizeof(*off));
	err = xdev_ext_window_copy_plan_check(g, frames, pool_index, 2, dir, d, n,
					      4, 1, off, &total);
	if (err)
		EXPECT_EQ(total, 0x5a5a);
	else
		EXPECT_EQ(total, (__u64)d[0].len + (n > 1 ? d[1].len : 0) +
			  (n > 2 ? d[2].len : 0));
	return err;
}

static void test_geometry(void)
{
	struct xdev_ext_window_copy_geom g = geom(1, XDEV_EXT_WINDOW_COPY_DIRS);
	__u64 off = 77;

	EXPECT_EQ(xdev_ext_window_copy_max_entry_len(4096, 0), 4096);
	EXPECT_EQ(xdev_ext_window_copy_max_entry_len(0, 0), UINT32_MAX);
	EXPECT_EQ(xdev_ext_window_copy_max_entry_len(4096, 512), 512);

	EXPECT_TRUE(xdev_ext_window_copy_geom_ok(4096, 4096, NR_POOL * FRAME, 0,
						 FRAME, NR_POOL));
	EXPECT_FALSE(xdev_ext_window_copy_geom_ok(0, 0, NR_POOL * FRAME, 0, FRAME,
						  NR_POOL));
	EXPECT_FALSE(xdev_ext_window_copy_geom_ok(4096, 8192, NR_POOL * FRAME, 0,
						  FRAME, NR_POOL));
	EXPECT_FALSE(xdev_ext_window_copy_geom_ok(4096, 4096, NR_POOL * FRAME, 0,
						  0, NR_POOL));
	EXPECT_FALSE(xdev_ext_window_copy_geom_ok(4096, 4096, NR_POOL * FRAME, 0,
						  FRAME, 0));
	EXPECT_FALSE(xdev_ext_window_copy_geom_ok(4096, 4096, NR_POOL * FRAME, 1,
						  FRAME, NR_POOL));
	EXPECT_TRUE(xdev_ext_window_copy_geom_ok(4096, 4096, NR_POOL * FRAME + 1, 1,
						 FRAME, NR_POOL));
	/* The pool size is computed in 64 bits: no u32 product wraps. */
	EXPECT_TRUE(xdev_ext_window_copy_geom_ok(4096, 4096, UINT64_MAX, 0,
						 UINT32_MAX, UINT32_MAX));
	EXPECT_FALSE(xdev_ext_window_copy_geom_ok(4096, 4096, UINT32_MAX, 0,
						  65536, 65536));

	EXPECT_EQ(xdev_ext_window_copy_host_off(&g, 5, 256, 512, &off), 0);
	EXPECT_EQ(off, 5 * FRAME + 256);
	off = 77;
	EXPECT_EQ(xdev_ext_window_copy_host_off(&g, NR_POOL, 0, 1, &off), -ERANGE);
	EXPECT_EQ(xdev_ext_window_copy_host_off(&g, 0, FRAME - 1, 2, &off), -ERANGE);
	EXPECT_EQ(xdev_ext_window_copy_host_off(&g, 0, UINT32_MAX, 2, &off), -ERANGE);
	EXPECT_EQ(off, 77);
	g.first_page_off = 512;
	EXPECT_EQ(xdev_ext_window_copy_host_off(&g, NR_POOL - 1, 0, FRAME, &off),
		  -ERANGE);
	EXPECT_EQ(xdev_ext_window_copy_host_off(&g, 0, 0, 1, &off), 0);
	EXPECT_EQ(off, 512);
}

static void test_plan_accepted(void)
{
	struct xdev_ext_window_copy_geom g = geom(64, XDEV_EXT_WINDOW_COPY_DIRS);
	struct xdev_ext_window_copy_desc d[4];
	__u64 off[XDEV_EXT_MECH_MAX_FRAMES];
	__u32 dir;

	for (dir = TO; dir <= FROM; dir++) {
		good(d);
		EXPECT_EQ(check(&g, dir, d, 2, off), 0);
		EXPECT_EQ(off[0], 2 * FRAME + 256);
		EXPECT_EQ(off[1], 5 * FRAME + 256);
		EXPECT_EQ(off[2], 0xa5a5a5a5a5a5a5a5ULL);

		/* Overlapping device ranges: accepted, total is the sum. */
		good(d);
		d[1].dev_off = 512;
		EXPECT_EQ(check(&g, dir, d, 2, off), 0);
		good(d);
		d[1].dev_off = 0;
		EXPECT_EQ(check(&g, dir, d, 2, off), 0);
		d[0] = ent(0, 256, 2048, 512, 0);
		d[1] = ent(0, 768, 2048, 512, 0);
		d[2] = ent(1, 256, 2048, 512, 0);
		EXPECT_EQ(check(&g, dir, d, 3, off), 0);
		EXPECT_EQ(off[1], 2 * FRAME + 768);
	}
	/* One direction only. */
	g = geom(1, 1U << FROM);
	good(d);
	EXPECT_EQ(check(&g, FROM, d, 2, off), 0);
	EXPECT_EQ(check(&g, TO, d, 2, off), -EOPNOTSUPP);
}

/*
 * Each rejection, with a second fault in a later check so the order shows:
 * only the first failing check decides the errno.
 */
static void test_plan_rejected_in_order(void)
{
	struct xdev_ext_window_copy_geom g = geom(64, XDEV_EXT_WINDOW_COPY_DIRS);
	struct xdev_ext_window_copy_desc d[8];
	__u64 off[XDEV_EXT_MECH_MAX_FRAMES];
	__u64 total = 9;

	memset(d, 0, sizeof(d));
	/* Count before entries; entries before direction. */
	good(d);
	EXPECT_EQ(check(&g, 7, d, 0, off), -EINVAL);
	EXPECT_EQ(check(&g, 7, d, 5, off), -E2BIG);
	EXPECT_EQ(check(&g, 7, d, 2, off), -EOPNOTSUPP);
	EXPECT_EQ(xdev_ext_window_copy_plan_check(&g, frames, pool_index,
						  XDEV_EXT_MECH_MAX_FRAMES + 1, 7, d, 5,
						  4, 1, off, &total), -EINVAL);
	EXPECT_EQ(total, 9);

	/* len 0 before an unknown flag. */
	good(d);
	d[1].len = 0;
	d[1].flags = 2;
	EXPECT_EQ(check(&g, TO, d, 2, off), -EINVAL);
	EXPECT_EQ(off[0], 2 * FRAME + 256);	/* entry 0 passed */
	EXPECT_EQ(off[1], 0xa5a5a5a5a5a5a5a5ULL);
	/* Unknown flag before too long. */
	good(d);
	d[0].flags = 2;
	d[0].len = 8192;
	EXPECT_EQ(check(&g, TO, d, 2, off), -EOPNOTSUPP);
	/* Too long before the frame-side order. */
	g.max_entry_len = 1000;
	good(d);
	d[0].frame_off = 0;
	EXPECT_EQ(check(&g, TO, d, 2, off), -EMSGSIZE);
	g.max_entry_len = 4096;
	/* Frame-side gap before the window. */
	good(d);
	d[1].frame_off = 320;
	d[1].dev_off = 1ULL << 40;
	EXPECT_EQ(check(&g, TO, d, 2, off), -EINVAL);
	/* Frame side past the span. */
	good(d);
	d[1].len = 576;
	EXPECT_EQ(check(&g, TO, d, 2, off), -ERANGE);
	/* Window before the segment. */
	good(d);
	d[1].dev_off = 64 * 1024 - 256;
	EXPECT_EQ(check(&g, TO, d, 2, off), -ERANGE);
	/* Segment before the host chunk. */
	good(d);
	d[1].dev_off = 4096 - 256;
	EXPECT_EQ(xdev_ext_window_copy_plan_check(&g, frames, (const __u32[]){ 2, 16 },
						  2, TO, d, 2, 4, 1, off, &total),
		  -EXDEV);
	/* Host chunk before the alignment. */
	good(d);
	d[1].dev_off = 1025;
	EXPECT_EQ(xdev_ext_window_copy_plan_check(&g, frames, (const __u32[]){ 2, 16 },
						  2, TO, d, 2, 4, 1, off, &total),
		  -ERANGE);
	/* Alignment, of the device offset and of the length. */
	good(d);
	d[1].dev_off = 1025;
	EXPECT_EQ(check(&g, TO, d, 2, off), -EINVAL);
	EXPECT_EQ(off[1], 0xa5a5a5a5a5a5a5a5ULL);
	g = geom(1, XDEV_EXT_WINDOW_COPY_DIRS);
	EXPECT_EQ(check(&g, TO, d, 2, off), 0);
	/* Coverage last. */
	good(d);
	EXPECT_EQ(check(&g, TO, d, 1, off), -ENODATA);
	EXPECT_EQ(total, 9);
}

static void test_classifier(void)
{
	EXPECT_EQ(xdev_ext_mech_classify(true, true), XDEV_EXT_MECH_OUTCOME_OK);
	EXPECT_EQ(xdev_ext_mech_classify(true, false), XDEV_EXT_MECH_OUTCOME_OK);
	EXPECT_EQ(xdev_ext_mech_classify(false, true), XDEV_EXT_MECH_OUTCOME_AMBIGUOUS);
	EXPECT_EQ(xdev_ext_mech_classify(false, false),
		  XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED);
	/* The NET completion field: 0 OK; 1 refused; 2 ambiguous. */
	EXPECT_EQ(XDEV_EXT_MECH_OUTCOME_OK, 0);
	EXPECT_EQ(XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED, 1);
	EXPECT_EQ(XDEV_EXT_MECH_OUTCOME_AMBIGUOUS, 2);
	EXPECT_EQ(XDEV_EXT_CE_AMBIGUOUS, XDEV_EXT_MECH_OUTCOME_AMBIGUOUS);
	EXPECT_EQ(XDEV_EXT_DMA_PRE_SUBMIT_FAILED,
		  XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED);
}

static void test_disposition(void)
{
	static const int statuses[] = { 0, -EIO, -ETIMEDOUT, -4095, -4096, 1, 5000 };
	unsigned int i, o;

	for (i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
		int s = statuses[i];

		for (o = 0; o < 4; o++) {
			int err = 777;
			bool seq = xdev_ext_window_copy_disposition(o, s, &err);

			EXPECT_EQ(seq, o == XDEV_EXT_MECH_OUTCOME_AMBIGUOUS);
			if (seq)
				EXPECT_EQ(err, s < 0 && s >= -4095 ? s : -EIO);
			else
				EXPECT_EQ(err, (int)o);
		}
	}
}

static void test_cookie_and_cqe(void)
{
	__u8 st = XDEV_EXT_WINDOW_COPY_CK_IDLE;
	__u32 outcome = 9, entries = 9;
	__u64 bytes = 9;

	EXPECT_FALSE(xdev_ext_window_copy_cookie_finish(&st));
	EXPECT_FALSE(xdev_ext_window_copy_cookie_disarm(&st));
	EXPECT_TRUE(xdev_ext_window_copy_cookie_arm(&st));
	EXPECT_FALSE(xdev_ext_window_copy_cookie_arm(&st));
	EXPECT_TRUE(xdev_ext_window_copy_cookie_disarm(&st));
	EXPECT_EQ(st, XDEV_EXT_WINDOW_COPY_CK_IDLE);
	EXPECT_TRUE(xdev_ext_window_copy_cookie_arm(&st));
	EXPECT_TRUE(xdev_ext_window_copy_cookie_finish(&st));
	EXPECT_FALSE(xdev_ext_window_copy_cookie_finish(&st));
	EXPECT_EQ(st, XDEV_EXT_WINDOW_COPY_CK_DONE);
	/* A RETRY re-arms a finished cookie; an unknown state never arms. */
	EXPECT_TRUE(xdev_ext_window_copy_cookie_arm(&st));
	st = 3;
	EXPECT_FALSE(xdev_ext_window_copy_cookie_arm(&st));

	xdev_ext_window_copy_cqe(XDEV_EXT_WINDOW_COPY_CK_DONE, XDEV_EXT_MECH_OUTCOME_OK,
				 1536, 1536, 2, &outcome, &bytes, &entries);
	EXPECT_EQ(outcome, XDEV_EXT_MECH_OUTCOME_OK);
	EXPECT_EQ(bytes, 1536);
	EXPECT_EQ(entries, 2);
	xdev_ext_window_copy_cqe(XDEV_EXT_WINDOW_COPY_CK_DONE,
				 XDEV_EXT_MECH_OUTCOME_AMBIGUOUS, UINT64_MAX, 1536, 2,
				 &outcome, &bytes, &entries);
	EXPECT_EQ(outcome, XDEV_EXT_MECH_OUTCOME_AMBIGUOUS);
	EXPECT_EQ(bytes, 1536);
	EXPECT_EQ(entries, 0);
	xdev_ext_window_copy_cqe(XDEV_EXT_WINDOW_COPY_CK_ARMED, XDEV_EXT_MECH_OUTCOME_OK,
				 1536, 1536, 2, &outcome, &bytes, &entries);
	EXPECT_EQ(outcome, XDEV_EXT_MECH_OUTCOME_PRE_SUBMIT_FAILED);
	EXPECT_EQ(bytes, 0);
	EXPECT_EQ(entries, 0);
}

static void test_frames(void)
{
	struct xdev_ext_mech_frame_info out[XDEV_EXT_MECH_MAX_FRAMES];
	unsigned int i;

	memset(out, 0xa5, sizeof(out));
	xdev_ext_window_copy_frames(out, frames, 2);
	EXPECT_EQ(memcmp(out, frames, sizeof(frames)), 0);
	for (i = 2; i < XDEV_EXT_MECH_MAX_FRAMES; i++)
		EXPECT_EQ(out[i].umem_addr | out[i].data_off | out[i].data_len, 0);
	memset(out, 0xa5, sizeof(out));
	xdev_ext_window_copy_frames(out, NULL, 0);
	for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++)
		EXPECT_EQ(out[i].umem_addr | out[i].data_off | out[i].data_len, 0);
}

int main(void)
{
	test_geometry();
	test_plan_accepted();
	test_plan_rejected_in_order();
	test_classifier();
	test_disposition();
	test_cookie_and_cqe();
	test_frames();
	if (failures) {
		printf("FAIL: %u of %u window copy core checks\n", failures, checks);
		return 1;
	}
	printf("PASS: %u window copy core checks\n", checks);
	return 0;
}
