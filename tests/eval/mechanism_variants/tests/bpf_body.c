// SPDX-License-Identifier: GPL-2.0
/* Execute the checked-in BPF callback as host C, then the production SQE
 * admission helper. This is neither verifier nor class/provider evidence. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef MV_BASELINE
#define nvme_s0_build mv_nvme_build
#define nvme_s0_complete mv_nvme_complete
#define nvme_s0_ops mv_nvme_ops
#include "nvme_s0.bpf.c"
#else
#include MV_BPF_SOURCE
#endif
#include "include/linux/nvme_xdev_ext_passthru.h"

static struct xdev_ext_nvme_mech_info info;
static struct xdev_ext_nvme_mech_cqe cqe;
static unsigned char scratch[64];

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

#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
	__FILE__, __LINE__, msg); return 1; } } while (0)

static int mapping(int gray)
{
	/* Independent, literal expected slots: no mapping helper from the BPF. */
	static const unsigned reverse[] = { 0, 4, 2, 6, 1, 5, 3, 7 };
	static const unsigned gray_slots[] = { 0, 1, 3, 2, 6, 7, 5, 4 };
	static const unsigned long long ids[] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0x100000003ULL, 0xffffffffffffffffULL,
	};
	const unsigned *slots = gray ? gray_slots : reverse;
	struct xdev_ext_mech_ctx ctx = { .callsite = XDEV_EXT_MP_SITE_WORKER };
	struct nvme_xdev_ext_decoded d;
	struct nvme_xdev_ext_mech_bounds b = {
		.window_slba = 2048, .window_nlb = 64, .capacity_lbas = 4096,
		.data_len = 4096, .lba_shift = 9,
	};
	unsigned i;

	memset(&info, 0, sizeof(info));
	info.window_slba = b.window_slba;
	info.window_nlb = b.window_nlb;
	info.capacity_lbas = b.capacity_lbas;
	info.lba_shift = b.lba_shift;
	info.l.group_bytes = b.data_len;
	ctx.base.direction = XDEV_EXT_MP_DIR_FROM_DEVICE;
	ctx.base.length = b.data_len;
	for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
		unsigned long long want = 2048 + 8 * slots[ids[i] & 7];
		int ret;

		ctx.base.request_id = ids[i];
		/* Deliberately unrelated key: request_id must choose the address. */
		ctx.base.src_offset = 100 + i;
		memset(scratch, 0, sizeof(scratch));
		CHECK(mv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_SUBMIT, "BUILD SUBMIT");
		ret = nvme_xdev_ext_mech_validate(scratch, &b, &d);
		CHECK(!ret, "production SQE admission rejects legal mapping");
		if (d.slba != want) {
			fprintf(stderr, "FAIL %s request_id=%llu actual_slba=%llu expected_slba=%llu\n",
				gray ? "gray" : "reverse", ids[i], (unsigned long long)d.slba, want);
			return 1;
		}
		CHECK(d.nlb == 8 && d.byte_length == 4096 && !d.write, "same READ/NLB/bytes");
		/* Mutate actual callback scratch, run the actual production guard. */
		scratch[8] = 1;
		CHECK(nvme_xdev_ext_mech_validate(scratch, &b, &d) == -EPERM, "reserved cdw2 rejected");
		scratch[8] = 0;
		xdev_ext_mp_put_le64(scratch + 40, 2112);
		CHECK(nvme_xdev_ext_mech_validate(scratch, &b, &d) == -ERANGE, "outside window rejected");
	}
	cqe.status = 0;
	cqe.err = 0;
	CHECK(mv_nvme_complete(NULL, &ctx) == XDEV_EXT_MP_NEXT, "success completion NEXT");
	cqe.err = -EIO;
	CHECK(mv_nvme_complete(NULL, &ctx) == XDEV_EXT_MP_ABORT, "failed completion ABORT");
	ctx.base.length = 4095;
	CHECK(mv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "unaligned geometry ABORT");
	ctx.base.length = 4096;
	info.window_nlb = 63;
	CHECK(mv_nvme_build(NULL, &ctx) == XDEV_EXT_MP_BUILD_ABORT, "not eight whole slots ABORT");
	puts("PASS host BPF callback + production SQE helper (no verifier/provider/performance claim)");
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2 || (strcmp(argv[1], "reverse") && strcmp(argv[1], "gray")))
		return 2;
	return mapping(!strcmp(argv[1], "gray"));
}
