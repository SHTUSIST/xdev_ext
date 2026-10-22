// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/uapi/linux/io_uring.h"
#include "io_uring/iaa/xdev_ext_iaa_core.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static unsigned int checks;
static unsigned int failures;

#define EXPECT_TRUE(expr) do {                                                   \
	checks++;                                                                  \
	if (!(expr)) {                                                             \
		fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n",               \
			__FILE__, __LINE__, #expr);                                   \
		failures++;                                                       \
	}                                                                          \
} while (0)

#define EXPECT_EQ(actual, expected) do {                                        \
	long long _actual = (long long)(actual);                                  \
	long long _expected = (long long)(expected);                              \
	checks++;                                                                  \
	if (_actual != _expected) {                                                \
		fprintf(stderr, "%s:%d: %s=%lld, expected %lld\n",               \
			__FILE__, __LINE__, #actual, _actual, _expected);              \
		failures++;                                                       \
	}                                                                          \
} while (0)

static struct xdev_ext_iaa_window_plan valid_plan(void)
{
	struct xdev_ext_iaa_sqe_fields fields = {
		.src_off = 128,
		.dst_off = 4096,
		.src_len = 1024,
		.dst_cap = 2048,
	};
	struct xdev_ext_iaa_window_plan plan = {};

	EXPECT_EQ(xdev_ext_iaa_decode_windows(&fields, 4 * 4096, 4096, &plan), 0);
	return plan;
}

static void test_exact_encoding_and_opcodes(void)
{
	struct io_uring_sqe sqe = {
		.addr = UINT64_C(0x100000002),
		.off = UINT64_C(0x100002000),
		.rw_flags = 31,
		.addr3 = 4096,
	};
	struct xdev_ext_iaa_sqe_fields fields =
		xdev_ext_iaa_sqe_fields_from_words(sqe.addr, sqe.off,
					      sqe.rw_flags, sqe.addr3);
	struct xdev_ext_iaa_window_plan plan = {};

	EXPECT_EQ(IO_UNIFIED_OP_IAA_COMPRESS, 4);
	EXPECT_EQ(IO_UNIFIED_OP_IAA_DECOMPRESS, 5);
	EXPECT_EQ(XDEV_EXT_IAA_OP_COMPRESS, IO_UNIFIED_OP_IAA_COMPRESS);
	EXPECT_EQ(XDEV_EXT_IAA_OP_DECOMPRESS, IO_UNIFIED_OP_IAA_DECOMPRESS);
	EXPECT_EQ(sizeof(sqe), 64);
	EXPECT_EQ(offsetof(struct io_uring_sqe, off), 8);
	EXPECT_EQ(offsetof(struct io_uring_sqe, addr), 16);
	EXPECT_EQ(offsetof(struct io_uring_sqe, rw_flags), 28);
	EXPECT_EQ(offsetof(struct io_uring_sqe, addr3), 48);
	EXPECT_EQ(sizeof(fields.src_off), 8);
	EXPECT_EQ(sizeof(fields.dst_off), 8);
	EXPECT_EQ(sizeof(fields.src_len), 4);
	EXPECT_EQ(sizeof(fields.dst_cap), 8);
	EXPECT_EQ(xdev_ext_iaa_decode_windows(&fields, UINT64_C(0x100004000),
					 4096, &plan), 0);
	EXPECT_EQ(plan.src_off, fields.src_off);
	EXPECT_EQ(plan.dst_off, fields.dst_off);
	EXPECT_EQ(plan.src_len, fields.src_len);
	EXPECT_EQ(plan.dst_cap, fields.dst_cap);
	EXPECT_EQ(plan.src_frame, 0x100000002ULL / 4096);
	EXPECT_EQ(plan.dst_frame, 0x100002000ULL / 4096);
	EXPECT_EQ(plan.src_frame_offset, 2);
	EXPECT_TRUE(xdev_ext_iaa_opcode_valid(XDEV_EXT_IAA_OP_COMPRESS));
	EXPECT_TRUE(xdev_ext_iaa_opcode_valid(XDEV_EXT_IAA_OP_DECOMPRESS));
	EXPECT_TRUE(!xdev_ext_iaa_opcode_valid(XDEV_EXT_IAA_OP_DECOMPRESS + 1));
	EXPECT_TRUE(!xdev_ext_iaa_is_decompress(XDEV_EXT_IAA_OP_COMPRESS));
	EXPECT_TRUE(xdev_ext_iaa_is_decompress(XDEV_EXT_IAA_OP_DECOMPRESS));
}

static void test_optional_stats_never_alias_destination_offset(void)
{
	const xdev_ext_sm_u64 dst_off = UINT64_C(4096);
	const xdev_ext_sm_u64 registered_stats = UINT64_C(0x12345000);
	struct xdev_ext_iaa_sqe_fields fields = {
		.src_off = 128,
		.dst_off = dst_off,
		.src_len = 1024,
		.dst_cap = 2048,
	};
	struct xdev_ext_iaa_window_plan plan = {};

	EXPECT_TRUE(!xdev_ext_iaa_has_registered_stats(false, dst_off));
	EXPECT_EQ(xdev_ext_iaa_decode_windows(&fields, 4 * 4096, 4096, &plan), 0);
	EXPECT_TRUE(xdev_ext_iaa_has_registered_stats(registered_stats != 0,
						 dst_off));
}

static void test_registered_umem_stats_never_fall_back_to_sqe(void)
{
	EXPECT_EQ(xdev_ext_unified_stats_source(true, false, false, true), -EFAULT);
	EXPECT_EQ(xdev_ext_unified_stats_source(true, false, true, true),
		  XDEV_EXT_UNIFIED_STATS_REGISTERED);
	EXPECT_EQ(xdev_ext_unified_stats_source(true, true, false, true),
		  XDEV_EXT_UNIFIED_STATS_NONE);
	EXPECT_EQ(xdev_ext_unified_stats_source(true, true, true, true),
		  XDEV_EXT_UNIFIED_STATS_REGISTERED);
	EXPECT_EQ(xdev_ext_unified_stats_source(false, false, false, true),
		  XDEV_EXT_UNIFIED_STATS_SQE);
	EXPECT_EQ(xdev_ext_unified_stats_source(false, false, false, false),
		  -EFAULT);
	EXPECT_EQ(xdev_ext_unified_stats_source(false, true, false, true),
		  -EOPNOTSUPP);
}

static void expect_decode_error(struct xdev_ext_iaa_sqe_fields fields,
				xdev_ext_sm_u64 umem_size, xdev_ext_sm_u32 frame_size)
{
	struct xdev_ext_iaa_window_plan plan;

	memset(&plan, 0xa5, sizeof(plan));
	EXPECT_TRUE(xdev_ext_iaa_decode_windows(&fields, umem_size, frame_size,
					   &plan) < 0);
}

static void test_window_validation(void)
{
	struct xdev_ext_iaa_sqe_fields fields = {
		.src_off = 128,
		.dst_off = 4096 + 128,
		.src_len = 512,
		.dst_cap = 1024,
	};

	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0, .dst_off = 4096, .src_len = 0, .dst_cap = 1,
	}, 8192, 4096);
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0, .dst_off = 4096, .src_len = 1, .dst_cap = 0,
	}, 8192, 4096);
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = UINT64_MAX - 3, .dst_off = 0,
		.src_len = 8, .dst_cap = 1,
	}, UINT64_MAX, 4096);
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0, .dst_off = UINT64_MAX - 3,
		.src_len = 1, .dst_cap = 8,
	}, UINT64_MAX, 4096);
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 8191, .dst_off = 0, .src_len = 2, .dst_cap = 1,
	}, 8192, 4096);
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0, .dst_off = 8191, .src_len = 1, .dst_cap = 2,
	}, 8192, 4096);
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 4000, .dst_off = 8192, .src_len = 128, .dst_cap = 1,
	}, 12288, 4096);
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0, .dst_off = 4096 + 4000,
		.src_len = 1, .dst_cap = 128,
	}, 12288, 4096);
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0, .dst_off = 4096 + 128,
		.src_len = 1, .dst_cap = 1024,
	}, 12288, 4096); /* destination publication is a frame prefix */
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0, .dst_off = 2048, .src_len = 1024, .dst_cap = 1024,
	}, 8192, 4096); /* distinct windows, same frame */
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 128, .dst_off = 256, .src_len = 512, .dst_cap = 512,
	}, 8192, 4096); /* overlap */
	expect_decode_error((struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0, .dst_off = 4096, .src_len = 1,
		.dst_cap = XDEV_EXT_IAA_DST_MAX + 1ULL,
	}, 1ULL << 20, 1U << 18);
	expect_decode_error(fields, 8192, 0);
	expect_decode_error(fields, 8192, 3000);
}

static void test_truthful_page_sg_layout(void)
{
	struct xdev_ext_iaa_sg_cursor cursor;
	struct xdev_ext_iaa_sg_segment segment;

	EXPECT_EQ(xdev_ext_iaa_sg_cursor_init(&cursor, 100, 4, 4000, 5000), 0);
	EXPECT_EQ(cursor.nents, 2);
	EXPECT_EQ(xdev_ext_iaa_sg_cursor_next(&cursor, &segment), 1);
	EXPECT_EQ(segment.page_index, 1);
	EXPECT_EQ(segment.page_offset, 4);
	EXPECT_EQ(segment.length, 4092);
	EXPECT_EQ(xdev_ext_iaa_sg_cursor_next(&cursor, &segment), 1);
	EXPECT_EQ(segment.page_index, 2);
	EXPECT_EQ(segment.page_offset, 0);
	EXPECT_EQ(segment.length, 908);
	EXPECT_EQ(xdev_ext_iaa_sg_cursor_next(&cursor, &segment), 0);

	EXPECT_TRUE(xdev_ext_iaa_sg_cursor_init(&cursor, 0, 1, 0, 0) < 0);
	EXPECT_TRUE(xdev_ext_iaa_sg_cursor_init(&cursor, 0, 1, 4096, 1) < 0);
	EXPECT_TRUE(xdev_ext_iaa_sg_cursor_init(&cursor, UINT32_MAX, 1,
					   UINT64_MAX, 1) < 0);
}

static void test_physical_page_alias_detection(void)
{
	struct xdev_ext_iaa_phys_extent extent;
	struct xdev_ext_iaa_phys_segment source = {
		.page_id = 7,
		.page_offset = 100,
		.length = 100,
	};
	struct xdev_ext_iaa_phys_segment destination = {
		.page_id = 8,
		.page_offset = 100,
		.length = 100,
	};

	EXPECT_TRUE(!xdev_ext_iaa_phys_segments_overlap(&source, &destination));

	/* Distinct logical frames can still alias the same pinned page. */
	destination.page_id = source.page_id;
	destination.page_offset = 199;
	EXPECT_TRUE(xdev_ext_iaa_phys_segments_overlap(&source, &destination));

	/* Adjacent sub-page frames do not overlap merely because the page does. */
	destination.page_offset = 200;
	EXPECT_TRUE(!xdev_ext_iaa_phys_segments_overlap(&source, &destination));
	destination.page_offset = 0;
	destination.length = 100;
	EXPECT_TRUE(!xdev_ext_iaa_phys_segments_overlap(&source, &destination));

	EXPECT_EQ(xdev_ext_iaa_phys_extent_init(&extent, 100, 100), 0);
	EXPECT_EQ(xdev_ext_iaa_phys_extent_merge(&extent, 300, 100), 0);
	EXPECT_EQ(extent.first, 100);
	EXPECT_EQ(extent.last, 400);
	/* Gaps in duplicate-PFN source aliases are conservatively rejected. */
	EXPECT_TRUE(xdev_ext_iaa_phys_extent_overlaps(&extent, 250, 10));
	EXPECT_TRUE(!xdev_ext_iaa_phys_extent_overlaps(&extent, 400, 10));
	EXPECT_EQ(xdev_ext_iaa_phys_extent_merge(&extent, 50, 25), 0);
	EXPECT_EQ(extent.first, 50);
	EXPECT_EQ(extent.last, 400);
}

#define FAKE_PHYS_SEGMENTS 16

struct fake_phys_env {
	xdev_ext_sm_u64 page_ids[8];
	struct xdev_ext_iaa_phys_segment source[FAKE_PHYS_SEGMENTS];
	unsigned int source_count;
};

static int fake_phys_record_source(void *opaque,
				   const struct xdev_ext_iaa_sg_segment *segment)
{
	struct fake_phys_env *env = opaque;
	struct xdev_ext_iaa_phys_segment *source;

	if (segment->page_index >= ARRAY_SIZE(env->page_ids) ||
	    env->source_count >= ARRAY_SIZE(env->source))
		return -ERANGE;
	source = &env->source[env->source_count++];
	*source = (struct xdev_ext_iaa_phys_segment) {
		.page_id = env->page_ids[segment->page_index],
		.page_offset = segment->page_offset,
		.length = segment->length,
	};
	return 0;
}

static int
fake_phys_check_destination(void *opaque,
			    const struct xdev_ext_iaa_sg_segment *segment)
{
	struct fake_phys_env *env = opaque;
	struct xdev_ext_iaa_phys_segment destination;
	unsigned int i;

	if (segment->page_index >= ARRAY_SIZE(env->page_ids))
		return -ERANGE;
	destination = (struct xdev_ext_iaa_phys_segment) {
		.page_id = env->page_ids[segment->page_index],
		.page_offset = segment->page_offset,
		.length = segment->length,
	};
	for (i = 0; i < env->source_count; i++)
		if (xdev_ext_iaa_phys_segments_overlap(&env->source[i], &destination))
			return -EINVAL;
	return 0;
}

static const struct xdev_ext_iaa_phys_walk_ops fake_phys_ops = {
	.source = fake_phys_record_source,
	.destination = fake_phys_check_destination,
};

static void test_physical_alias_production_walk(void)
{
	struct xdev_ext_iaa_sqe_fields fields = {
		.src_off = 0,
		.dst_off = 4096,
		.src_len = 4096,
		.dst_cap = 4096,
	};
	struct xdev_ext_iaa_window_plan windows = {};
	struct fake_phys_env env = {
		.page_ids = { 7, 7 },
	};

	EXPECT_EQ(xdev_ext_iaa_decode_windows(&fields, 8192, 4096, &windows), 0);
	EXPECT_EQ(xdev_ext_iaa_walk_physical_windows(0, 2, &windows,
						&fake_phys_ops, &env), -EINVAL);

	env = (struct fake_phys_env) {
		.page_ids = { 7, 8 },
	};
	EXPECT_EQ(xdev_ext_iaa_walk_physical_windows(0, 2, &windows,
						&fake_phys_ops, &env), 0);

	/* Same physical page is safe when frame-sized subranges are disjoint. */
	fields = (struct xdev_ext_iaa_sqe_fields) {
		.src_off = 0,
		.dst_off = 2048,
		.src_len = 100,
		.dst_cap = 100,
	};
	EXPECT_EQ(xdev_ext_iaa_decode_windows(&fields, 4096, 2048, &windows), 0);
	env = (struct fake_phys_env) {
		.page_ids = { 9 },
	};
	EXPECT_EQ(xdev_ext_iaa_walk_physical_windows(0, 1, &windows,
						&fake_phys_ops, &env), 0);
}

static void publish_source(struct xdev_ext_pool *pool, xdev_ext_sm_u32 idx,
			   xdev_ext_sm_u32 len)
{
	EXPECT_EQ(xdev_ext_frame_claim(pool, idx), 0);
	EXPECT_EQ(xdev_ext_frame_publish(pool, idx, len), 0);
}

static void init_pool(struct xdev_ext_pool *pool, struct xdev_ext_frame *frames,
		      size_t nr)
{
	memset(frames, 0, nr * sizeof(*frames));
	EXPECT_EQ(xdev_ext_pool_init(pool, frames, nr, false), 0);
}

static void test_legacy_window_contract(void)
{
	struct xdev_ext_lifecycle_window window = {};

	EXPECT_EQ(xdev_ext_lifecycle_decode_window(4224, 896, 16384, 4096, false,
					      &window), 0);
	EXPECT_EQ(window.frame, 1);
	EXPECT_EQ(window.frame_offset, 128);
	EXPECT_EQ(window.length, 896);

	/* A legacy operation may not bypass ownership by spanning frames. */
	EXPECT_EQ(xdev_ext_lifecycle_decode_window(4032, 128, 16384, 4096, false,
					      &window),
		  -EMSGSIZE);
	/* A producer publishes a prefix, so its destination starts at zero. */
	EXPECT_EQ(xdev_ext_lifecycle_decode_window(4224, 896, 16384, 4096, true,
					      &window), -EINVAL);
	EXPECT_EQ(xdev_ext_lifecycle_decode_window(4096, 896, 16384, 4096, true,
					      &window), 0);
}

static void test_legacy_ready_source_respects_offset(void)
{
	struct xdev_ext_lifecycle_window window = {};
	struct xdev_ext_frame frames[2];
	struct xdev_ext_pool pool;
	int mode;

	EXPECT_EQ(xdev_ext_lifecycle_decode_window(128, 896, 8192, 4096, false,
					      &window), 0);
	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, window.frame, 1024);
	mode = xdev_ext_lifecycle_consume_begin(&pool, &window);
	EXPECT_EQ(mode, XDEV_EXT_LIFECYCLE_SOURCE_READY);
	EXPECT_EQ(xdev_ext_lifecycle_consume_end(&pool, &window, mode), 0);
	EXPECT_EQ(xdev_ext_frame_state(&pool, window.frame), XDEV_EXT_FRAME_FREE);

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, window.frame, 1023);
	EXPECT_EQ(xdev_ext_lifecycle_consume_begin(&pool, &window), -EMSGSIZE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, window.frame), XDEV_EXT_FRAME_READY);
	EXPECT_EQ(frames[window.frame].valid_len, 1023);
}

static void test_legacy_and_iaa_ownership_conflicts(void)
{
	struct xdev_ext_iaa_window_plan iaa = valid_plan();
	struct xdev_ext_iaa_frame_claim claim;
	struct xdev_ext_lifecycle_window legacy = {};
	struct xdev_ext_frame frames[4];
	struct xdev_ext_pool pool;
	int mode;

	/* A legacy producer blocks IAA from reading the same frame. */
	EXPECT_EQ(xdev_ext_lifecycle_decode_window(0, 1024, 16384, 4096, true,
					      &legacy), 0);
	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_lifecycle_producer_begin(&pool, &legacy), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &iaa,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), -EBUSY);
	EXPECT_EQ(xdev_ext_frame_state(&pool, legacy.frame), XDEV_EXT_FRAME_IO_PENDING);
	EXPECT_EQ(xdev_ext_frame_state(&pool, iaa.dst_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_lifecycle_producer_abort(&pool, &legacy), 0);

	/* IAA ownership blocks both legacy producers and consumers. */
	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &iaa,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), 0);
	EXPECT_EQ(xdev_ext_lifecycle_producer_begin(&pool, &legacy), -EBUSY);
	legacy.frame = iaa.dst_frame;
	legacy.frame_offset = 0;
	legacy.length = 512;
	EXPECT_EQ(xdev_ext_lifecycle_consume_begin(&pool, &legacy), -EBUSY);
	EXPECT_EQ(xdev_ext_iaa_frames_rollback(&claim), 0);

	/* A legacy READY consumer also excludes IAA until it retires. */
	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, iaa.src_frame,
		       iaa.src_frame_offset + iaa.src_len);
	legacy.frame = iaa.src_frame;
	legacy.frame_offset = iaa.src_frame_offset;
	legacy.length = iaa.src_len;
	mode = xdev_ext_lifecycle_consume_begin(&pool, &legacy);
	EXPECT_EQ(mode, XDEV_EXT_LIFECYCLE_SOURCE_READY);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &iaa,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), -EBUSY);
	EXPECT_EQ(xdev_ext_frame_state(&pool, iaa.dst_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_lifecycle_consume_end(&pool, &legacy, mode), 0);
}

static void test_source_ready_success_and_failure(void)
{
	struct xdev_ext_frame frames[4];
	struct xdev_ext_pool pool;
	struct xdev_ext_iaa_frame_claim claim;
	struct xdev_ext_iaa_window_plan plan = valid_plan();

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, plan.src_frame,
		       plan.src_frame_offset + plan.src_len);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_SOURCE_FIRST), 0);
	EXPECT_EQ(claim.source_mode, XDEV_EXT_IAA_SOURCE_READY);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_TX_PENDING);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_IO_PENDING);
	EXPECT_EQ(xdev_ext_iaa_frames_finish(&claim, 0, 777), 777);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_READY);
	EXPECT_EQ(frames[plan.dst_frame].valid_len, 777);
	EXPECT_EQ(xdev_ext_iaa_frames_finish(&claim, 0, 777), -EALREADY);

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, plan.src_frame,
		       plan.src_frame_offset + plan.src_len);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_SOURCE_FIRST), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_finish(&claim, -EIO, 0), -EIO);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);
}

static void test_ready_source_respects_valid_prefix(void)
{
	struct xdev_ext_frame frames[4];
	struct xdev_ext_pool pool;
	struct xdev_ext_iaa_frame_claim claim;
	struct xdev_ext_iaa_window_plan plan = valid_plan();
	xdev_ext_sm_u32 valid_end = plan.src_frame_offset + plan.src_len;

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, plan.src_frame, valid_end);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_rollback(&claim), 0);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_READY);
	EXPECT_EQ(frames[plan.src_frame].valid_len, valid_end);

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, plan.src_frame, valid_end - 1);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), -EMSGSIZE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_READY);
	EXPECT_EQ(frames[plan.src_frame].valid_len, valid_end - 1);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);
}

static void test_source_free_success_and_provider_overrun(void)
{
	struct xdev_ext_frame frames[4];
	struct xdev_ext_pool pool;
	struct xdev_ext_iaa_frame_claim claim;
	struct xdev_ext_iaa_window_plan plan = valid_plan();

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), 0);
	EXPECT_EQ(claim.source_mode, XDEV_EXT_IAA_SOURCE_FREE);
	EXPECT_EQ(xdev_ext_iaa_frames_finish(&claim, 0, plan.dst_cap),
		  plan.dst_cap);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_READY);

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_SOURCE_FIRST), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_finish(&claim, 0, plan.dst_cap + 1),
		  -EOVERFLOW);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);
}

static void test_terminal_state_corruption_fails_closed(void)
{
	struct xdev_ext_frame frames[4];
	struct xdev_ext_pool pool;
	struct xdev_ext_iaa_frame_claim claim;
	struct xdev_ext_iaa_window_plan plan = valid_plan();

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), 0);
	frames[plan.dst_frame].state = XDEV_EXT_FRAME_FREE;
	EXPECT_EQ(xdev_ext_iaa_frames_finish(&claim, -EBADMSG, 0), -EIO);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_FREE);
}

static void test_both_claim_orders_roll_back_partial_ownership(void)
{
	struct xdev_ext_frame frames[4];
	struct xdev_ext_pool pool;
	struct xdev_ext_iaa_frame_claim claim;
	struct xdev_ext_iaa_window_plan plan = valid_plan();

	/* Source first: destination contention restores the published source. */
	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, plan.src_frame,
		       plan.src_frame_offset + plan.src_len);
	EXPECT_EQ(xdev_ext_frame_claim(&pool, plan.dst_frame), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_SOURCE_FIRST), -EBUSY);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_READY);
	EXPECT_EQ(frames[plan.src_frame].valid_len,
		  plan.src_frame_offset + plan.src_len);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_IO_PENDING);
	EXPECT_EQ(xdev_ext_frame_abort(&pool, plan.dst_frame), 0);

	/* Source first: destination contention releases a FREE source claim. */
	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_frame_claim(&pool, plan.dst_frame), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_SOURCE_FIRST), -EBUSY);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_frame_abort(&pool, plan.dst_frame), 0);

	/* Destination first: source contention releases the destination. */
	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_frame_claim(&pool, plan.src_frame), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), -EBUSY);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_frame_abort(&pool, plan.src_frame), 0);

	/* A short READY source is restored unchanged while destination rolls back. */
	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, plan.src_frame,
		       plan.src_frame_offset + plan.src_len - 1);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), -EMSGSIZE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_READY);
	EXPECT_EQ(frames[plan.src_frame].valid_len,
		  plan.src_frame_offset + plan.src_len - 1);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);
}

static void test_pre_submit_rollback_preserves_ready_source(void)
{
	struct xdev_ext_frame frames[4];
	struct xdev_ext_pool pool;
	struct xdev_ext_iaa_frame_claim claim;
	struct xdev_ext_iaa_window_plan plan = valid_plan();

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, plan.src_frame,
		       plan.src_frame_offset + plan.src_len + 17);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_SOURCE_FIRST), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_rollback(&claim), 0);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_READY);
	EXPECT_EQ(frames[plan.src_frame].valid_len,
		  plan.src_frame_offset + plan.src_len + 17);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_iaa_frames_rollback(&claim), -EALREADY);

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_rollback(&claim), 0);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	publish_source(&pool, plan.src_frame,
		       plan.src_frame_offset + plan.src_len);
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_DEST_FIRST), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_rollback(&claim), 0);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_READY);
	EXPECT_EQ(frames[plan.src_frame].valid_len,
		  plan.src_frame_offset + plan.src_len);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);

	init_pool(&pool, frames, ARRAY_SIZE(frames));
	EXPECT_EQ(xdev_ext_iaa_frames_claim(&claim, &pool, &plan,
				       XDEV_EXT_IAA_CLAIM_SOURCE_FIRST), 0);
	EXPECT_EQ(xdev_ext_iaa_frames_rollback(&claim), 0);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.src_frame), XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(xdev_ext_frame_state(&pool, plan.dst_frame), XDEV_EXT_FRAME_FREE);
}

static void test_sync_submit_results(void)
{
	struct xdev_ext_iaa_terminal terminal;

	xdev_ext_iaa_terminal_init(&terminal);
	EXPECT_EQ(xdev_ext_iaa_submit_return(&terminal, 0, 321),
		  XDEV_EXT_IAA_SUBMIT_FINISH_INLINE);
	EXPECT_EQ(xdev_ext_iaa_terminal_result(&terminal), 0);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&terminal), 321);

	xdev_ext_iaa_terminal_init(&terminal);
	EXPECT_EQ(xdev_ext_iaa_submit_return(&terminal, -EINVAL, 999),
		  XDEV_EXT_IAA_SUBMIT_FINISH_INLINE);
	EXPECT_EQ(xdev_ext_iaa_terminal_result(&terminal), -EINVAL);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&terminal), 0);
}

static void test_async_and_backlog_callbacks(void)
{
	struct xdev_ext_iaa_terminal terminal;

	xdev_ext_iaa_terminal_init(&terminal);
	EXPECT_EQ(xdev_ext_iaa_submit_return(&terminal, -EINPROGRESS, 0),
		  XDEV_EXT_IAA_SUBMIT_WAIT);
	EXPECT_EQ(xdev_ext_iaa_terminal_callback(&terminal, -EINPROGRESS, 0),
		  XDEV_EXT_IAA_CALLBACK_PROGRESS);
	EXPECT_EQ(xdev_ext_iaa_terminal_callback(&terminal, 0, 111),
		  XDEV_EXT_IAA_CALLBACK_QUEUE);
	EXPECT_EQ(xdev_ext_iaa_terminal_result(&terminal), 0);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&terminal), 111);
	EXPECT_EQ(xdev_ext_iaa_terminal_callback(&terminal, -EIO, 0),
		  XDEV_EXT_IAA_CALLBACK_DUPLICATE);

	xdev_ext_iaa_terminal_init(&terminal);
	EXPECT_EQ(xdev_ext_iaa_submit_return(&terminal, -EBUSY, 0),
		  XDEV_EXT_IAA_SUBMIT_WAIT);
	EXPECT_EQ(xdev_ext_iaa_terminal_callback(&terminal, -EINPROGRESS, 0),
		  XDEV_EXT_IAA_CALLBACK_PROGRESS);
	EXPECT_EQ(xdev_ext_iaa_terminal_callback(&terminal, -EIO, 700),
		  XDEV_EXT_IAA_CALLBACK_QUEUE);
	EXPECT_EQ(xdev_ext_iaa_terminal_result(&terminal), -EIO);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&terminal), 0);
}

static void test_callback_before_submit_return(void)
{
	struct xdev_ext_iaa_terminal terminal;

	xdev_ext_iaa_terminal_init(&terminal);
	EXPECT_EQ(xdev_ext_iaa_terminal_callback(&terminal, 0, 444),
		  XDEV_EXT_IAA_CALLBACK_DEFER);
	EXPECT_EQ(xdev_ext_iaa_submit_return(&terminal, -EINPROGRESS, 0),
		  XDEV_EXT_IAA_SUBMIT_QUEUE_EARLY);
	EXPECT_EQ(xdev_ext_iaa_terminal_result(&terminal), 0);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&terminal), 444);
	EXPECT_EQ(xdev_ext_iaa_terminal_callback(&terminal, 0, 444),
		  XDEV_EXT_IAA_CALLBACK_DUPLICATE);

	xdev_ext_iaa_terminal_init(&terminal);
	EXPECT_EQ(xdev_ext_iaa_terminal_callback(&terminal, -EBADMSG, 99),
		  XDEV_EXT_IAA_CALLBACK_DEFER);
	EXPECT_EQ(xdev_ext_iaa_submit_return(&terminal, -EBUSY, 0),
		  XDEV_EXT_IAA_SUBMIT_QUEUE_EARLY);
	EXPECT_EQ(xdev_ext_iaa_terminal_result(&terminal), -EBADMSG);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&terminal), 0);
}

struct fake_runtime_env {
	struct xdev_ext_iaa_runtime *runtime;
	xdev_ext_sm_u32 opcode;
	int submit_ret;
	int callback_err[3];
	xdev_ext_sm_u32 callback_out[3];
	unsigned int callbacks;
	bool callback_before_return;
	bool provider_present;
	bool submitter_dead;
	int complete_ret;
	unsigned int dispatch_calls;
	unsigned int provider_attempts;
	unsigned int compress_calls;
	unsigned int decompress_calls;
	unsigned int queue_calls;
	unsigned int queues_while_dead;
	unsigned int complete_calls;
	unsigned int token_put_calls;
	unsigned int umem_get_calls;
	unsigned int umem_put_calls;
	int registry_refs;
	int generation_refs;
	int token_refs;
	int umem_refs;
	int token_put_observed_umem_refs;
	int complete_observed_umem_refs;
};

static int fake_runtime_dispatch(void *opaque)
{
	struct fake_runtime_env *env = opaque;

	env->dispatch_calls++;
	if (env->registry_refs) {
		env->generation_refs++;
		env->token_refs++;
	}
	return 0;
}

static void fake_runtime_detach(struct fake_runtime_env *env)
{
	if (env->registry_refs)
		env->registry_refs--;
}

static int fake_runtime_prepare_provider(void *opaque)
{
	struct fake_runtime_env *env = opaque;

	env->provider_attempts++;
	return env->provider_present ? 0 : -ENOENT;
}

static void fake_runtime_token_put(void *opaque)
{
	struct fake_runtime_env *env = opaque;

	env->token_put_calls++;
	env->token_put_observed_umem_refs = env->umem_refs;
	if (env->token_refs) {
		env->token_refs--;
		env->generation_refs--;
	}
}

static void fake_runtime_umem_get(void *opaque)
{
	struct fake_runtime_env *env = opaque;

	env->umem_get_calls++;
	env->umem_refs++;
}

static void fake_runtime_umem_put(void *opaque)
{
	struct fake_runtime_env *env = opaque;

	env->umem_put_calls++;
	env->umem_refs--;
}

static int fake_runtime_complete(void *opaque, int result)
{
	struct fake_runtime_env *env = opaque;

	(void)result;
	env->complete_calls++;
	env->complete_observed_umem_refs = env->umem_refs;
	if (env->token_refs) {
		env->token_refs--;
		env->generation_refs--;
	}
	return env->complete_ret;
}

static void fake_runtime_queue_task_work(void *opaque)
{
	struct fake_runtime_env *env = opaque;

	env->queue_calls++;
	if (env->submitter_dead)
		env->queues_while_dead++;
}

static int fake_runtime_submit(void *opaque, bool decompress,
			       xdev_ext_sm_u32 *produced)
{
	struct fake_runtime_env *env = opaque;
	unsigned int i;

	if (decompress)
		env->decompress_calls++;
	else
		env->compress_calls++;
	EXPECT_EQ(decompress, env->opcode == XDEV_EXT_IAA_OP_DECOMPRESS);
	if (env->callback_before_return) {
		for (i = 0; i < env->callbacks; i++)
			xdev_ext_iaa_runtime_callback(env->runtime,
						 env->callback_err[i],
						 env->callback_out[i]);
	}
	if (!env->submit_ret)
		*produced = env->callback_out[0];
	if (!env->callback_before_return) {
		for (i = 0; i < env->callbacks; i++)
			xdev_ext_iaa_runtime_callback(env->runtime,
						 env->callback_err[i],
						 env->callback_out[i]);
	}
	return env->submit_ret;
}

static const struct xdev_ext_iaa_runtime_ops fake_runtime_ops = {
	.dispatch = fake_runtime_dispatch,
	.prepare_provider = fake_runtime_prepare_provider,
	.token_put = fake_runtime_token_put,
	.umem_get = fake_runtime_umem_get,
	.umem_put = fake_runtime_umem_put,
	.complete = fake_runtime_complete,
	.submit = fake_runtime_submit,
	.queue_task_work = fake_runtime_queue_task_work,
};

static void test_production_runtime_seam_lifetimes(void)
{
	struct xdev_ext_iaa_runtime runtime;
	struct fake_runtime_env env = {
		.opcode = XDEV_EXT_IAA_OP_COMPRESS,
		.submit_ret = -EINPROGRESS,
		.callback_out = { 77 },
		.registry_refs = 1,
	};

	EXPECT_EQ(xdev_ext_iaa_runtime_init(&runtime, &fake_runtime_ops, &env), 0);
	env.runtime = &runtime;
	EXPECT_EQ(xdev_ext_iaa_runtime_dispatch(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_prepare_provider(&runtime), -ENOENT);
	xdev_ext_iaa_runtime_release(&runtime);
	EXPECT_EQ(env.provider_attempts, 1);
	EXPECT_EQ(env.token_put_calls, 1);
	EXPECT_EQ(env.token_refs, 0);
	EXPECT_EQ(env.umem_refs, 0);

	/* Lazy per-request allocation sees a provider registered later. */
	env.provider_present = true;
	EXPECT_EQ(xdev_ext_iaa_runtime_init(&runtime, &fake_runtime_ops, &env), 0);
	env.runtime = &runtime;
	EXPECT_EQ(xdev_ext_iaa_runtime_dispatch(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_prepare_provider(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_acquire_umem(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_submit(&runtime, false),
		  XDEV_EXT_IAA_SUBMIT_WAIT);
	EXPECT_EQ(env.provider_attempts, 2);
	EXPECT_EQ(env.compress_calls, 1);
	EXPECT_EQ(env.token_refs, 1);
	fake_runtime_detach(&env);
	EXPECT_EQ(env.registry_refs, 0);
	EXPECT_EQ(env.generation_refs, 1);
	EXPECT_EQ(env.token_refs, 1);
	env.submitter_dead = true;
	EXPECT_EQ(xdev_ext_iaa_runtime_callback(&runtime, -EINPROGRESS, 0),
		  XDEV_EXT_IAA_CALLBACK_PROGRESS);
	EXPECT_EQ(xdev_ext_iaa_runtime_callback(&runtime, 0, 123),
		  XDEV_EXT_IAA_CALLBACK_QUEUE);
	EXPECT_EQ(xdev_ext_iaa_runtime_callback(&runtime, -EIO, 0),
		  XDEV_EXT_IAA_CALLBACK_DUPLICATE);
	EXPECT_EQ(env.queue_calls, 1);
	EXPECT_EQ(env.queues_while_dead, 1);
	EXPECT_EQ(xdev_ext_iaa_terminal_result(&runtime.terminal), 0);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&runtime.terminal), 123);
	EXPECT_EQ(env.token_refs, 1);
	EXPECT_EQ(env.umem_refs, 1);
	EXPECT_EQ(xdev_ext_iaa_runtime_complete(&runtime, 123), 0);
	EXPECT_EQ(env.complete_calls, 1);
	EXPECT_EQ(env.token_refs, 0);
	EXPECT_EQ(env.generation_refs, 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_complete(&runtime, 123), -EALREADY);
	EXPECT_EQ(env.complete_calls, 1);
	xdev_ext_iaa_runtime_release(&runtime);
	xdev_ext_iaa_runtime_release(&runtime);
	EXPECT_EQ(env.umem_put_calls, 1);
	EXPECT_EQ(env.umem_refs, 0);
	EXPECT_EQ(env.queue_calls, 1);
	EXPECT_EQ(env.token_put_calls, 1);

	/* A callback before -EBUSY returns still queues terminal work once. */
	env.opcode = XDEV_EXT_IAA_OP_COMPRESS;
	env.submit_ret = -EBUSY;
	env.callback_before_return = true;
	env.callbacks = 3;
	env.callback_err[0] = -EINPROGRESS;
	env.callback_err[1] = 0;
	env.callback_err[2] = -EIO;
	env.callback_out[0] = 0;
	env.callback_out[1] = 88;
	env.callback_out[2] = 0;
	env.submitter_dead = false;
	EXPECT_EQ(xdev_ext_iaa_runtime_init(&runtime, &fake_runtime_ops, &env), 0);
	env.runtime = &runtime;
	EXPECT_EQ(xdev_ext_iaa_runtime_dispatch(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_prepare_provider(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_acquire_umem(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_submit(&runtime, false),
		  XDEV_EXT_IAA_SUBMIT_QUEUE_EARLY);
	EXPECT_EQ(env.queue_calls, 2);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&runtime.terminal), 88);
	EXPECT_EQ(xdev_ext_iaa_runtime_complete(&runtime, 88), 0);
	xdev_ext_iaa_runtime_release(&runtime);
	EXPECT_EQ(env.token_refs, 0);
	EXPECT_EQ(env.umem_refs, 0);

	/* The same production submit seam selects decompression synchronously. */
	env.opcode = XDEV_EXT_IAA_OP_DECOMPRESS;
	env.submit_ret = 0;
	env.submitter_dead = false;
	env.callbacks = 0;
	env.callback_before_return = false;
	env.callback_out[0] = 77;
	EXPECT_EQ(xdev_ext_iaa_runtime_init(&runtime, &fake_runtime_ops, &env), 0);
	env.runtime = &runtime;
	EXPECT_EQ(xdev_ext_iaa_runtime_dispatch(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_prepare_provider(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_acquire_umem(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_submit(&runtime, true),
		  XDEV_EXT_IAA_SUBMIT_FINISH_INLINE);
	EXPECT_EQ(env.compress_calls, 2);
	EXPECT_EQ(env.decompress_calls, 1);
	EXPECT_EQ(xdev_ext_iaa_terminal_produced(&runtime.terminal), 77);
	EXPECT_EQ(xdev_ext_iaa_runtime_complete(&runtime, 77), 0);
	xdev_ext_iaa_runtime_release(&runtime);
	EXPECT_EQ(env.token_refs, 0);
	EXPECT_EQ(env.umem_refs, 0);
}

static void test_runtime_release_order_and_completion_error(void)
{
	struct xdev_ext_iaa_runtime runtime;
	struct fake_runtime_env env = {
		.opcode = XDEV_EXT_IAA_OP_COMPRESS,
		.submit_ret = 0,
		.callback_out = { 32 },
		.provider_present = true,
		.complete_ret = -EPERM,
		.registry_refs = 1,
	};
	unsigned int token_put_calls;

	EXPECT_EQ(xdev_ext_iaa_runtime_init(&runtime, &fake_runtime_ops, &env), 0);
	env.runtime = &runtime;
	EXPECT_EQ(xdev_ext_iaa_runtime_dispatch(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_prepare_provider(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_acquire_umem(&runtime), 0);
	xdev_ext_iaa_runtime_release(&runtime);
	EXPECT_EQ(env.token_put_observed_umem_refs, 1);
	EXPECT_EQ(env.token_refs, 0);
	EXPECT_EQ(env.generation_refs, 0);
	EXPECT_EQ(env.umem_refs, 0);

	EXPECT_EQ(xdev_ext_iaa_runtime_init(&runtime, &fake_runtime_ops, &env), 0);
	env.runtime = &runtime;
	EXPECT_EQ(xdev_ext_iaa_runtime_dispatch(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_prepare_provider(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_acquire_umem(&runtime), 0);
	EXPECT_EQ(xdev_ext_iaa_runtime_submit(&runtime, false),
		  XDEV_EXT_IAA_SUBMIT_FINISH_INLINE);
	EXPECT_EQ(xdev_ext_iaa_runtime_complete(&runtime, -EIO), -EPERM);
	EXPECT_EQ(env.complete_observed_umem_refs, 1);
	EXPECT_EQ(env.token_refs, 0);
	EXPECT_EQ(env.generation_refs, 0);
	token_put_calls = env.token_put_calls;
	xdev_ext_iaa_runtime_release(&runtime);
	EXPECT_EQ(env.token_put_calls, token_put_calls);
	EXPECT_EQ(env.umem_refs, 0);
}

int main(void)
{
	test_exact_encoding_and_opcodes();
	test_optional_stats_never_alias_destination_offset();
	test_registered_umem_stats_never_fall_back_to_sqe();
	test_window_validation();
	test_truthful_page_sg_layout();
	test_physical_page_alias_detection();
	test_physical_alias_production_walk();
	test_legacy_window_contract();
	test_legacy_ready_source_respects_offset();
	test_legacy_and_iaa_ownership_conflicts();
	test_source_ready_success_and_failure();
	test_ready_source_respects_valid_prefix();
	test_source_free_success_and_provider_overrun();
	test_terminal_state_corruption_fails_closed();
	test_both_claim_orders_roll_back_partial_ownership();
	test_pre_submit_rollback_preserves_ready_source();
	test_sync_submit_results();
	test_async_and_backlog_callbacks();
	test_callback_before_submit_return();
	test_production_runtime_seam_lifetimes();
	test_runtime_release_order_and_completion_error();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u checks\n", checks);
	return EXIT_SUCCESS;
}
