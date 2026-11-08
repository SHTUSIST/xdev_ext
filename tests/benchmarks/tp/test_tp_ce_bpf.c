// SPDX-License-Identifier: GPL-2.0
/*
 * Runs the PREPARE/BUILD/COMPLETE callbacks of tp_ce_place.bpf.c as host C,
 * then the production CE window admission on what BUILD wrote.
 * Requirement (TP host-frame route, libxdev_ext_frame_endpoint.h): on the
 * receive side (CE TO_DEVICE with TARGET_RANGE) the group keyed k lands as
 * one contiguous group at device offset (k % (window_len / group_bytes)) *
 * group_bytes; on the send side (CE FROM_DEVICE, slot mode) the group of
 * batch slot s is read from offset s * group_bytes. Pieces split only where
 * a device segment or the largest entry ends; frames that do not cover the
 * group, a stale lease or a window smaller than a group are refused before
 * a descriptor reaches the CE. No verifier or device evidence.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmlinux.h"
XDEV_EXT_MECH_CREF_HOST_OPS(xdev_ext_ce_mech_ops);
#include "tp_ce_place.bpf.c"
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_compfam_copy_core.h"

enum { FRAME = 4096, SEG = 2 << 20 };

static struct xdev_ext_ce_mech_info info;
static struct xdev_ext_ce_mech_cqe cqe;
static struct xdev_ext_ce_copy_desc scratch[XDEV_EXT_CE_RANGE_MAX_ENTRIES + 1];
static unsigned checks;
static __u32 group, frames, depth;
static __u64 window;
extern int tp_frame_placement(__u32, __u32, __u64, __u64, __u64 *, __u32 *);

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

static void geometry(__u32 g, __u32 d, __u64 w)
{
	group = g; depth = d; window = w;
	frames = (g + FRAME - 1) / FRAME;
}

/* Batch @key in slot @slot: layout spans of the ring's frames at START. */
static void setup(struct xdev_ext_mech_ctx *ctx, __u32 dir, __u64 key, __u32 slot,
		  __u32 seg, __u32 max)
{
	__u32 left = group;

	memset(&info, 0, sizeof(info));
	memset(scratch, 0, sizeof(scratch));
	info.l = (struct xdev_ext_mech_layout){ .frame_size = FRAME, .hdr_room = 0,
		.seg_len = FRAME, .group_bytes = group };
	info.gpu_window_len = window;
	info.gpu_seg_size = seg;
	info.max_entry_len = max;
	info.nr_frames = frames;
	for (__u32 i = 0; i < frames; i++) {
		__u32 len = left < FRAME ? left : FRAME;

		info.f[i] = (struct xdev_ext_mech_frame_info){
			.umem_addr = ((__u64)slot * frames + i) * FRAME, .data_len = len };
		left -= len;
	}
	info.window_slot = slot;
	info.window_depth = depth;
	info.lease_generation = 50 + key;
	*ctx = (struct xdev_ext_mech_ctx){ .callsite = XDEV_EXT_MP_SITE_WORKER,
		.nr_frames = frames, .desc_cap = XDEV_EXT_CE_RANGE_MAX_ENTRIES,
		.batch_id = 50 + key };
	ctx->base.direction = dir;
	ctx->base.length = group;
	ctx->base.src_offset = key;
	ctx->base.request_id = 50 + key;
}

static unsigned used(void)
{
	static const struct xdev_ext_ce_copy_desc zero;
	unsigned n = 0;

	while (n < XDEV_EXT_CE_RANGE_MAX_ENTRIES && memcmp(&scratch[n], &zero, sizeof(zero)))
		n++;
	return n;
}

/* The production validator on BUILD's descriptors, as the CE bind sets it up. */
static int admit(__u32 dir, bool range, __u32 seg, __u32 max, struct xdev_ext_comp_copy_plan *plan)
{
	struct xdev_ext_ce_geom geom;
	struct xdev_ext_window_copy_geom wg;
	struct xdev_ext_comp_copy_window w;
	__u32 index[XDEV_EXT_MECH_MAX_FRAMES];
	int ret;

	ret = xdev_ext_ce_geom_init(&geom, window, window, seg, max, (__u64)depth * frames * FRAME,
				    0, FRAME, depth * frames);
	if (ret)
		return ret;
	wg = xdev_ext_ce_window_geom(&geom);
	ret = xdev_ext_comp_copy_prepare_mode(&w, XDEV_EXT_COMP_COPY_WINDOW, &wg, dir, depth,
					      group, range);
	if (ret)
		return ret;
	for (__u32 i = 0; i < frames; i++)
		index[i] = (__u32)(info.f[i].umem_addr / FRAME);
	return xdev_ext_comp_copy_validate(&w, info.f, index, frames, scratch, used(),
			range ? XDEV_EXT_CE_RANGE_MAX_ENTRIES : XDEV_EXT_CE_MAX_ENTRIES,
			XDEV_EXT_CE_F_KNOWN_MASK, info.window_slot, info.lease_generation, plan);
}

static void contiguous(__u64 at, unsigned n)
{
	for (unsigned e = 0; e < n; e++) {
		CHECK(scratch[e].gpu_off == at, "contiguous device bytes");
		CHECK(!!(scratch[e].flags & XDEV_EXT_CE_F_COMPLETION_POINT) == (e + 1 == n),
		      "completion point on the last entry only");
		at += scratch[e].len;
	}
}

static void receive_keys_land_in_ring(void)
{
	static const __u64 keys[] = { 1, 2, 3, 7, 1ULL << 40, (1ULL << 40) + 3 };
	struct xdev_ext_mech_ctx ctx;
	struct xdev_ext_comp_copy_plan plan;

	geometry(128 * 1024, 1, 3 * 128 * 1024);	/* three-group receive ring */
	for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		__u64 want = (keys[i] % 3) * group;

		setup(&ctx, XDEV_EXT_MP_DIR_TO_DEVICE, keys[i], 0, SEG, 0);
		CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "receive BUILD submits");
		CHECK(used() == frames, "one entry per frame inside one segment");
		CHECK(scratch[0].gpu_off == want, "key k lands at (k % slots) * group_bytes");
		contiguous(want, used());
		CHECK(!admit(XDEV_EXT_MECH_DIR_TO_DEVICE, true, SEG, 0, &plan),
		      "production range admission accepts");
		CHECK(plan.target_range && plan.target_start == want && plan.target_len == group,
		      "admitted target equals the placement");
	}
	/* A partial last frame (TP group = 64-byte header + payload, 64-aligned). */
	geometry(3 * FRAME + 64, 1, 2ULL * (3 * FRAME + 64));
	setup(&ctx, XDEV_EXT_MP_DIR_TO_DEVICE, 5, 0, SEG, 0);
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "partial last frame submits");
	CHECK(used() == 4 && scratch[3].len == 64, "last piece is the partial frame");
	contiguous(group, 4);
	CHECK(!admit(XDEV_EXT_MECH_DIR_TO_DEVICE, true, SEG, 0, &plan), "admitted");
}

static void send_slot_is_read(void)
{
	struct xdev_ext_mech_ctx ctx;
	struct xdev_ext_comp_copy_plan plan;

	geometry(32 * FRAME, 1, 32 * FRAME);
	setup(&ctx, XDEV_EXT_MP_DIR_FROM_DEVICE, 9, 0, SEG, 0);
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "send BUILD submits");
	CHECK(used() == 32, "32 frames, 32 entries");
	contiguous(0, 32);
	CHECK(!admit(XDEV_EXT_MECH_DIR_FROM_DEVICE, false, SEG, 0, &plan),
	      "production slot admission accepts");
	CHECK(!plan.target_range && plan.total == group, "slot plan covers the group");
	/* Slot s of a deeper window. */
	geometry(8 * FRAME, 4, 4 * 8 * FRAME);
	setup(&ctx, XDEV_EXT_MP_DIR_FROM_DEVICE, 12, 2, SEG, 0);
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "slot 2 submits");
	contiguous(2ULL * group, used());
	CHECK(!admit(XDEV_EXT_MECH_DIR_FROM_DEVICE, false, SEG, 0, &plan), "slot 2 admitted");
	/* The slot window holds at most 32 entries: 1 KiB entries over 8 frames are 32. */
	setup(&ctx, XDEV_EXT_MP_DIR_FROM_DEVICE, 12, 0, SEG, 1024);
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "32 small entries submit");
	CHECK(used() == 32, "four entries per frame");
	geometry(9 * FRAME, 1, 9 * FRAME);
	setup(&ctx, XDEV_EXT_MP_DIR_FROM_DEVICE, 12, 0, SEG, 1024);
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "36 entries exceed the slot limit");
}

static void refusals(void)
{
	struct xdev_ext_mech_ctx ctx;

	geometry(4 * FRAME, 1, 4 * FRAME);
	setup(&ctx, XDEV_EXT_MP_DIR_TO_DEVICE, 3, 0, SEG, 0);
	info.f[2].data_len = FRAME / 2;
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "frames short of the group");
	CHECK(used() == 0, "no descriptor for a refused batch");
	setup(&ctx, XDEV_EXT_MP_DIR_TO_DEVICE, 3, 0, SEG, 0);
	info.lease_generation++;
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "stale lease generation");
	setup(&ctx, XDEV_EXT_MP_DIR_TO_DEVICE, 3, 0, SEG, 0);
	ctx.base.length = 2 * FRAME;
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "batch length differs from group");
	setup(&ctx, XDEV_EXT_MP_DIR_TO_DEVICE, 3, 0, SEG, 0);
	info.gpu_window_len = 3 * FRAME;
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "window smaller than a group");
	setup(&ctx, XDEV_EXT_MP_DIR_FROM_DEVICE, 3, 1, SEG, 0);
	info.window_depth = 1;
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "slot past the depth");
	setup(&ctx, XDEV_EXT_MP_DIR_TO_DEVICE, 3, 0, SEG, 0);
	ctx.base.direction = 0;
	CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "unknown direction");
}

static void prepare_and_complete(void)
{
	struct xdev_ext_mech_ctx ctx;

	geometry(32 * FRAME, 1, 32 * FRAME);
	setup(&ctx, XDEV_EXT_MP_DIR_TO_DEVICE, 1, 0, SEG, 0);
	CHECK(tp_ce_prepare(NULL, &ctx) == 0, "PREPARE admits 32 frames in 2 MiB segments");
	info.max_entry_len = 1024;
	CHECK(tp_ce_prepare(NULL, &ctx) != 0, "PREPARE refuses a geometry past 64 entries");
	cqe.outcome = XDEV_EXT_MP_CE_OK;
	CHECK(tp_ce_complete(NULL, &ctx) == XDEV_EXT_MP_NEXT, "OK continues");
	cqe.outcome = XDEV_EXT_MP_CE_PRE_SUBMIT_FAILED;
	CHECK(tp_ce_complete(NULL, &ctx) == XDEV_EXT_MP_RETRY, "pre-submit failure retries");
	cqe.outcome = 7;
	CHECK(tp_ce_complete(NULL, &ctx) == XDEV_EXT_MP_ABORT, "anything else aborts");
	CHECK(tp_ce_ops.flags & XDEV_EXT_MP_OPS_F_PRIVATE, "PRIVATE instance only");
	CHECK(tp_ce_ops.abi_version == XDEV_EXT_MP_CE_ABI_VERSION, "CE ABI version");
}

/* Hand-derived offsets, including a non-power-of-two receive ring and a
 * non-divisible window tail. The endpoint and actual BPF BUILD must agree. */
static void endpoint_placement_matches_build(void)
{
	static const struct { bool send; __u32 group; __u64 window, sequence, offset; } cases[] = {
		{ false, 12352, 37056, 7, 12352 },
		{ false, 12352, 37120, 9, 0 },
		{ false, 4096, 12288, ~0ULL, 0 },
		{ true, 12352, 37056, 7, 0 },
	};
	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct xdev_ext_mech_ctx ctx;
		struct xdev_ext_comp_copy_plan plan;
		__u64 offset = ~0ULL;
		__u32 bytes = 0;
		__u32 ce_dir = cases[i].send ? XDEV_EXT_MP_DIR_FROM_DEVICE : XDEV_EXT_MP_DIR_TO_DEVICE;
		__u32 endpoint_dir = cases[i].send ? XDEV_EXT_MP_DIR_TO_DEVICE : XDEV_EXT_MP_DIR_FROM_DEVICE;

		CHECK(!tp_frame_placement(endpoint_dir, cases[i].group, cases[i].window,
			cases[i].sequence, &offset, &bytes), "actual endpoint placement succeeds");
		CHECK(offset == cases[i].offset && bytes == cases[i].group,
		      "endpoint placement equals independently expected offset");
		geometry(cases[i].group, 1, cases[i].window);
		setup(&ctx, ce_dir, cases[i].sequence, 0, FRAME, 1024);
		CHECK(tp_ce_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "joint BPF BUILD submits");
		CHECK(scratch[0].gpu_off == offset, "BPF target equals actual endpoint placement");
		contiguous(offset, used());
		CHECK(!admit(ce_dir, !cases[i].send, FRAME, 1024, &plan), "joint descriptor plan admitted");
	}
}

int main(void)
{
	receive_keys_land_in_ring();
	send_slot_is_read();
	refusals();
	prepare_and_complete();
	endpoint_placement_matches_build();
	printf("tp_ce_place host body: %u checks PASS\n", checks);
	return 0;
}
