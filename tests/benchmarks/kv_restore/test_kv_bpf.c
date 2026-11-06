// SPDX-License-Identifier: GPL-2.0
/*
 * Runs the BUILD/COMPLETE callbacks of kv_nvme_read.bpf.c as host C, then the
 * production SQE admission helper nvme_xdev_ext_mech_validate() on what BUILD
 * wrote.  Requirement: batch key k reads slot (k mod slots) of the stage window
 * as one READ of exactly one group, whatever the batch id; anything else is
 * refused before a command exists.  This is neither verifier nor device
 * evidence (the guest run loads the real object).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kv_nvme_read.bpf.c"
#include "include/linux/nvme_xdev_ext_passthru.h"

static struct xdev_ext_nvme_mech_info info;
static struct xdev_ext_nvme_mech_cqe cqe;
static unsigned char scratch[64];
static unsigned checks;

__u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx, const size_t n)
{
	(void)ctx;
	return n == sizeof(info) ? (void *)&info : NULL;
}
__u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx, __u32 slot, const size_t n)
{
	(void)ctx;
	return !slot && n == sizeof(scratch) ? scratch : NULL;
}
__u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *ctx, __u32 slot, const size_t n)
{
	(void)ctx;
	return !slot && n == sizeof(cqe) ? (void *)&cqe : NULL;
}

#define CHECK(c, msg) do { checks++; if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
	__FILE__, __LINE__, msg); exit(1); } } while (0)

enum { GROUP = 262144, LBA_SHIFT = 9, BLOCKS = GROUP >> LBA_SHIFT, SLOTS = 40 };
static const unsigned long long WSLBA = 2048;

static void setup(struct xdev_ext_mech_ctx *ctx, struct nvme_xdev_ext_mech_bounds *b)
{
	memset(&info, 0, sizeof(info));
	info.window_slba = WSLBA;
	info.window_nlb = SLOTS * BLOCKS + 7;	/* a partial slot at the end is never read */
	info.capacity_lbas = 1ULL << 32;
	info.lba_shift = LBA_SHIFT;
	info.max_nlb = BLOCKS;
	info.l.group_bytes = GROUP;
	*ctx = (struct xdev_ext_mech_ctx){ .callsite = XDEV_EXT_MP_SITE_WORKER };
	ctx->base.direction = XDEV_EXT_MP_DIR_FROM_DEVICE;
	ctx->base.length = GROUP;
	*b = (struct nvme_xdev_ext_mech_bounds){ .window_slba = WSLBA,
		.window_nlb = info.window_nlb, .capacity_lbas = info.capacity_lbas,
		.data_len = GROUP, .lba_shift = LBA_SHIFT };
}

static void keys_select_slots(void)
{
	/* Expected slot of each key computed here, never by a program helper. */
	static const unsigned long long keys[] = { 40, 41, 79, 3 * 40 + 39, 5 * 40 + 12,
		(1ULL << 41) + 17, 0xffffffffffffffffULL };
	/* (2^41 + 17) mod 40 = 9; (2^64 - 1) mod 40 = 15. */
	static const unsigned slots[] = { 0, 1, 39, 39, 12, 9, 15 };
	struct nvme_xdev_ext_mech_bounds b;
	struct nvme_xdev_ext_decoded d;
	struct xdev_ext_mech_ctx ctx;

	setup(&ctx, &b);
	for (unsigned i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		unsigned long long want = WSLBA + (unsigned long long)slots[i] * BLOCKS;

		ctx.base.src_offset = keys[i];
		ctx.base.request_id = 1000 + 3 * i;	/* unrelated batch id */
		memset(scratch, 0, sizeof(scratch));
		CHECK(kv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "BUILD submits");
		CHECK(!nvme_xdev_ext_mech_validate(scratch, &b, &d), "production admission accepts");
		if (d.slba != want) {
			fprintf(stderr, "FAIL key=%llu slba=%llu want=%llu\n", keys[i],
				(unsigned long long)d.slba, want);
			exit(1);
		}
		CHECK(d.nlb == BLOCKS && d.byte_length == GROUP && !d.write, "one READ of one group");
	}
	/* Same key, different batch ids: same LBA. */
	ctx.base.src_offset = 45;
	ctx.base.request_id = 1;
	CHECK(kv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "build key 45");
	CHECK(!nvme_xdev_ext_mech_validate(scratch, &b, &d) && d.slba == WSLBA + 5 * BLOCKS,
	      "key 45 reads slot 5");
	ctx.base.request_id = 2;
	CHECK(kv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "rebuild key 45");
	CHECK(!nvme_xdev_ext_mech_validate(scratch, &b, &d) && d.slba == WSLBA + 5 * BLOCKS,
	      "the batch id does not move the LBA");
}

static void refusals(void)
{
	struct nvme_xdev_ext_mech_bounds b;
	struct xdev_ext_mech_ctx ctx;

	setup(&ctx, &b);
	ctx.base.src_offset = 41;
	ctx.base.direction = XDEV_EXT_MP_DIR_TO_DEVICE;
	CHECK(kv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "a WRITE stage is refused");
	setup(&ctx, &b);
	ctx.base.length = GROUP / 2;
	CHECK(kv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "a partial group is refused");
	setup(&ctx, &b);
	ctx.base.length = GROUP - 1;
	info.l.group_bytes = GROUP - 1;
	CHECK(kv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "not whole LBAs is refused");
	setup(&ctx, &b);
	info.window_nlb = BLOCKS - 1;
	CHECK(kv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "window below one group");
	setup(&ctx, &b);
	info.max_nlb = BLOCKS - 1;
	CHECK(kv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "above the controller limit");
}

static void completion_and_ops(void)
{
	struct nvme_xdev_ext_mech_bounds b;
	struct xdev_ext_mech_ctx ctx;

	setup(&ctx, &b);
	cqe.status = 0;
	cqe.err = 0;
	CHECK(kv_nvme_complete(NULL, &ctx) == XDEV_EXT_MP_NEXT, "success continues the chain");
	cqe.err = -EIO;
	CHECK(kv_nvme_complete(NULL, &ctx) == XDEV_EXT_MP_ABORT, "an error aborts");
	cqe.err = 0;
	cqe.status = 0x2;
	CHECK(kv_nvme_complete(NULL, &ctx) == XDEV_EXT_MP_ABORT, "an NVMe status aborts");
	CHECK(kv_nvme_ops.flags == XDEV_EXT_MP_OPS_F_PRIVATE, "selected per stage, never the default");
	CHECK(kv_nvme_ops.abi_version == XDEV_EXT_MP_ABI_VERSION, "mechanism ABI");
}

int main(void)
{
	keys_select_slots();
	refusals();
	completion_and_ops();
	printf("kv_nvme_read host body: %u checks PASS (no verifier/device claim)\n", checks);
	return 0;
}
