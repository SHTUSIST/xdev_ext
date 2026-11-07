// SPDX-License-Identifier: GPL-2.0
/*
 * Runs the PREPARE/BUILD/COMPLETE callbacks of kv_ce_place.bpf.c as host C,
 * then the production CE window admission (xdev_ext_ce_geom_init and the
 * common target-range validator xdev_ext_comp_copy_validate) on what BUILD
 * wrote.  Requirement: batch key k of a restore whose target names keys
 * [first_key, first_key + groups) lands as one contiguous group at device
 * offset dst_off + (k - first_key) * group_bytes of the window, split only
 * where a device segment or the largest entry ends; a key outside the
 * target, a target past the window or frames that do not cover the group
 * are refused before a descriptor reaches the CE.  Neither verifier nor
 * device evidence (the guest run loads the real object).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmlinux.h"
XDEV_EXT_MECH_CREF_HOST_OPS(xdev_ext_ce_mech_ops);
#include "kv_ce_place.bpf.c"
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_compfam_copy_core.h"

enum { FRAME = 4096, GROUP = 128 * 1024, FRAMES = GROUP / FRAME, DEPTH = 4,
       WINDOW = 16 << 20, SEG = 2 << 20 };

static struct xdev_ext_ce_mech_info info;
static struct xdev_ext_ce_mech_cqe cqe;
static struct xdev_ext_ce_copy_desc scratch[XDEV_EXT_CE_RANGE_MAX_ENTRIES + 1];
static unsigned checks;

__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, const size_t n)
{
	(void)ctx;
	return n == sizeof(info) ? (void *)&info : NULL;
}
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot, const size_t n)
{
	(void)ctx;
	return slot < XDEV_EXT_CE_RANGE_MAX_ENTRIES && n == sizeof(scratch[0]) ?
		(void *)&scratch[slot] : NULL;
}
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot, const size_t n)
{
	(void)ctx;
	return !slot && n == sizeof(cqe) ? (void *)&cqe : NULL;
}

#define CHECK(c, msg) do { checks++; if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
	__FILE__, __LINE__, msg); exit(1); } } while (0)

/* Batch @key in ring slot @slot: frames in ring order, as the core presents them. */
static void setup(struct xdev_ext_mech_ctx *ctx, __u64 key, __u32 slot, __u32 seg, __u32 max)
{
	memset(&info, 0, sizeof(info));
	memset(scratch, 0, sizeof(scratch));
	info.l = (struct xdev_ext_mech_layout){ .frame_size = FRAME, .hdr_room = 0,
		.seg_len = FRAME, .group_bytes = GROUP };
	info.gpu_window_len = WINDOW;
	info.gpu_seg_size = seg;
	info.max_entry_len = max;
	info.nr_frames = FRAMES;
	for (__u32 i = 0; i < FRAMES; i++)
		info.f[i] = (struct xdev_ext_mech_frame_info){
			.umem_addr = ((__u64)slot * FRAMES + i) * FRAME, .data_len = FRAME };
	info.window_slot = slot;
	info.window_depth = DEPTH;
	info.lease_generation = 77 + key;
	*ctx = (struct xdev_ext_mech_ctx){ .callsite = XDEV_EXT_MP_SITE_WORKER,
		.nr_frames = FRAMES, .desc_cap = XDEV_EXT_CE_RANGE_MAX_ENTRIES,
		.batch_id = 77 + key };
	ctx->base.direction = XDEV_EXT_MP_DIR_TO_DEVICE;
	ctx->base.length = GROUP;
	ctx->base.src_offset = key;
	ctx->base.request_id = 77 + key;
}

static unsigned used(void)
{
	static const struct xdev_ext_ce_copy_desc zero;
	unsigned n = 0;

	while (n < XDEV_EXT_CE_RANGE_MAX_ENTRIES && memcmp(&scratch[n], &zero, sizeof(zero)))
		n++;
	return n;
}

/* The production range validator on BUILD's descriptors, as the CE bind sets it up. */
static int admit(__u32 seg, __u32 max, struct xdev_ext_comp_copy_plan *plan)
{
	struct xdev_ext_ce_geom geom;
	struct xdev_ext_window_copy_geom wg;
	struct xdev_ext_comp_copy_window w;
	__u32 index[FRAMES];
	int ret;

	ret = xdev_ext_ce_geom_init(&geom, WINDOW, WINDOW, seg, max, (__u64)DEPTH * GROUP, 0,
				    FRAME, DEPTH * FRAMES);
	if (ret)
		return ret;
	wg = xdev_ext_ce_window_geom(&geom);
	ret = xdev_ext_comp_copy_prepare_mode(&w, XDEV_EXT_COMP_COPY_WINDOW, &wg,
			XDEV_EXT_MECH_DIR_TO_DEVICE, DEPTH, GROUP, true);
	if (ret)
		return ret;
	for (__u32 i = 0; i < FRAMES; i++)
		index[i] = (__u32)(info.f[i].umem_addr / FRAME);
	return xdev_ext_comp_copy_validate(&w, info.f, index, FRAMES, scratch, used(),
			XDEV_EXT_CE_RANGE_MAX_ENTRIES, XDEV_EXT_CE_F_KNOWN_MASK,
			info.window_slot, info.lease_generation, plan);
}

static void target(__u64 first, __u64 groups, __u64 dst)
{
	kv_ce_target = (struct kv_ce_target){ .first_key = first, .groups = groups, .dst_off = dst };
}

static void keys_land_contiguously(void)
{
	static const struct { __u64 first, groups, dst, key; __u32 slot; } c[] = {
		{ 1000, 40, 0, 1000, 0 },		/* first group at the target start */
		{ 1000, 40, 0, 1039, 3 },		/* last group, any ring slot */
		{ 1000, 40, 0, 1017, 1 },
		{ 5, 3, 8192, 7, 2 },			/* dst_frame0 = 2 frames of 4 KiB */
		{ 1ULL << 40, 10, 4 << 20, (1ULL << 40) + 9, 1 },
	};
	struct xdev_ext_mech_ctx ctx;
	struct xdev_ext_comp_copy_plan plan;

	for (unsigned i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
		__u64 want = c[i].dst + (c[i].key - c[i].first) * GROUP;

		target(c[i].first, c[i].groups, c[i].dst);
		setup(&ctx, c[i].key, c[i].slot, SEG, 0);
		CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "BUILD submits");
		CHECK(used() == FRAMES, "one entry per frame inside one segment");
		CHECK(scratch[0].gpu_off == want, "group lands at dst + index * group_bytes");
		for (unsigned e = 0; e < FRAMES; e++) {
			CHECK(scratch[e].frame_pos == e && scratch[e].frame_off == 0 &&
			      scratch[e].len == FRAME, "frame order kept");
			CHECK(scratch[e].gpu_off == want + (__u64)e * FRAME, "contiguous device bytes");
			CHECK(!!(scratch[e].flags & XDEV_EXT_CE_F_COMPLETION_POINT) == (e + 1 == FRAMES),
			      "completion point on the last entry only");
		}
		CHECK(!admit(SEG, 0, &plan), "production range admission accepts");
		CHECK(plan.target_range && plan.target_start == want && plan.target_len == GROUP &&
		      plan.total == GROUP, "admitted target equals the placement");
	}
}

static void segment_and_entry_limits_split(void)
{
	struct xdev_ext_mech_ctx ctx;
	struct xdev_ext_comp_copy_plan plan;
	__u64 dst = SEG - 6144;	/* group straddles the first 2 MiB segment boundary */
	__u64 at;
	unsigned n;

	target(10, 4, dst);
	setup(&ctx, 10, 0, SEG, 0);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "straddling group submits");
	n = used();
	CHECK(n == FRAMES + 1, "one extra entry at the segment boundary");
	at = dst;
	for (unsigned e = 0; e < n; e++) {
		CHECK(scratch[e].gpu_off == at, "pieces stay contiguous");
		CHECK(scratch[e].gpu_off / SEG == (scratch[e].gpu_off + scratch[e].len - 1) / SEG,
		      "no piece crosses a segment");
		at += scratch[e].len;
	}
	CHECK(at == dst + GROUP, "pieces cover the group");
	CHECK(scratch[1].frame_pos == 1 && scratch[1].len == 2048 &&
	      scratch[2].frame_pos == 1 && scratch[2].frame_off == 2048, "frame 1 split at the boundary");
	CHECK(!admit(SEG, 0, &plan), "production admission accepts the split");

	/* A 1 KiB largest entry needs 128 entries: more than a range batch takes. */
	target(10, 4, 0);
	setup(&ctx, 10, 0, SEG, 1024);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "over-capacity group aborts");
	/* 2 KiB entries in one segment: exactly 64.  With 2 MiB segments the
	 * offset-independent bound (one more possible segment cut) is 65 and the
	 * group is refused, although this offset would need only 64. */
	setup(&ctx, 11, 0, 0, 2048);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "64 entries submit");
	CHECK(used() == 64, "two entries per frame");
	CHECK(!admit(0, 2048, &plan), "production admission accepts 64 entries");
	setup(&ctx, 11, 0, SEG, 2048);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "bound of 65 refused");
}

static void refusals(void)
{
	struct xdev_ext_mech_ctx ctx;

	target(100, 10, 0);
	setup(&ctx, 99, 0, SEG, 0);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "key before the target");
	setup(&ctx, 110, 0, SEG, 0);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "key after the target");
	CHECK(used() == 0, "no descriptor for a refused key");
	target(100, 0, 0);
	setup(&ctx, 100, 0, SEG, 0);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "no target set");
	target(100, 200, 0);
	setup(&ctx, 100 + WINDOW / GROUP, 0, SEG, 0);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "group past the window");
	target(100, 10, WINDOW - GROUP + FRAME);
	setup(&ctx, 100, 0, SEG, 0);
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "target start past the window");
	target(1, 2, 0);
	setup(&ctx, 1, 0, SEG, 0);
	ctx.base.src_offset = 1ULL << 63;
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "far key refused");
	target(100, 10, 0);
	setup(&ctx, 100, 0, SEG, 0);
	ctx.base.direction = XDEV_EXT_MP_DIR_FROM_DEVICE;
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "device-to-host refused");
	setup(&ctx, 100, 0, SEG, 0);
	info.f[5].data_len = FRAME / 2;
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "frames short of the group");
	setup(&ctx, 100, 0, SEG, 0);
	info.lease_generation++;
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "stale lease generation");
	setup(&ctx, 100, 0, SEG, 0);
	ctx.base.length = GROUP / 2;
	CHECK(kv_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "batch length differs from group");
}

static void prepare_and_complete(void)
{
	struct xdev_ext_mech_ctx ctx;

	setup(&ctx, 1, 0, SEG, 0);
	CHECK(kv_ce_prepare(NULL, &ctx) == 0, "PREPARE admits 32 frames in 2 MiB segments");
	info.max_entry_len = 1024;
	CHECK(kv_ce_prepare(NULL, &ctx) != 0, "PREPARE refuses a geometry past 64 entries");
	cqe.outcome = XDEV_EXT_MP_CE_OK;
	CHECK(kv_ce_complete(NULL, &ctx) == XDEV_EXT_MP_NEXT, "OK continues");
	cqe.outcome = XDEV_EXT_MP_CE_PRE_SUBMIT_FAILED;
	CHECK(kv_ce_complete(NULL, &ctx) == XDEV_EXT_MP_RETRY, "pre-submit failure retries");
	cqe.outcome = 7;
	CHECK(kv_ce_complete(NULL, &ctx) == XDEV_EXT_MP_ABORT, "anything else aborts");
	CHECK(kv_ce_ops.flags & XDEV_EXT_MP_OPS_F_PRIVATE, "PRIVATE instance only");
	CHECK(kv_ce_ops.abi_version == XDEV_EXT_MP_CE_ABI_VERSION, "CE ABI version");
}

int main(void)
{
	keys_land_contiguously();
	segment_and_entry_limits_split();
	refusals();
	prepare_and_complete();
	printf("kv_ce_place host body: %u checks PASS\n", checks);
	return 0;
}
