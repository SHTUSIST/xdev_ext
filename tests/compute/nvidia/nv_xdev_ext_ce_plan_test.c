/* SPDX-License-Identifier: MIT */
/*
 * Pure parts of the copy-engine mechanism backend: a validated plan entry of
 * the kernel CE class becomes one RM transfer only when it lies inside the
 * bound GPU window and the bound host pages.
 */
#include <stdint.h>
#include <stdio.h>

#include "../kernel-open/nvidia/nv-xdev_ext-ce-plan.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(expected, actual) do {                                  \
	long long expected_ = (long long)(expected);                         \
	long long actual_ = (long long)(actual);                             \
	checks++;                                                             \
	if (expected_ != actual_) {                                          \
		fprintf(stderr, "%s:%d expected %lld got %lld\n",           \
			__FILE__, __LINE__, expected_, actual_);                 \
		failures++;                                                     \
	}                                                                    \
} while (0)

#define KB(x) ((uint64_t)(x) << 10)
#define MB(x) ((uint64_t)(x) << 20)

/*
 * Measurement-only switch of E5 level 4 (xdev_ext_ce_entries_per_submit):
 * 0 sends the whole plan in one RM call with adjacent entries merged; k > 0
 * sends k plan entries per call, in plan order, merged only within a call.
 * The batch completes with the last call's token; a failed call stops the
 * plan, and work issued by an earlier call keeps the batch "issued", so the
 * batch-level classification (ambiguous, never pre-submit) still holds.
 */
struct fake_rm {
	unsigned int calls, fail_at, fail_issued;
	nv_xdev_ext_gpu_u32 m[16];
	struct nv_xdev_ext_ce_span first[16];
};

static nv_xdev_ext_gpu_u32 fake_submit(void *ctx, const struct nv_xdev_ext_ce_span *s,
				       nv_xdev_ext_gpu_u32 m, int *issued,
				       nv_xdev_ext_gpu_u64 *token)
{
	struct fake_rm *rm = ctx;
	unsigned int call = rm->calls++;

	rm->m[call] = m;
	rm->first[call] = s[0];
	if (rm->fail_at && call + 1 == rm->fail_at) {
		*issued = rm->fail_issued;
		*token = 0;
		return 0x55;
	}
	*issued = 1;
	*token = 100 + call;
	return 0;
}

static void test_entries_per_submit(void)
{
	struct nv_xdev_ext_ce_span e[5], sp[5];
	struct fake_rm rm;
	nv_xdev_ext_gpu_u64 token;
	nv_xdev_ext_gpu_u32 calls;
	int issued;
	unsigned int i;

	for (i = 0; i < 5; i++)	/* five adjacent 4 KiB entries */
		e[i] = (struct nv_xdev_ext_ce_span){ KB(4) * i, KB(64) + KB(4) * i, KB(4) };

	rm = (struct fake_rm){ 0 };
	EXPECT_EQ(0, nv_xdev_ext_ce_submit_plan(e, 5, 0, sp, fake_submit, &rm, &issued,
						&token, &calls));
	EXPECT_EQ(1, calls);			/* batch: one call */
	EXPECT_EQ(1, rm.m[0]);			/* adjacent entries merged */
	EXPECT_EQ(100, token);
	EXPECT_EQ(1, issued);

	rm = (struct fake_rm){ 0 };
	EXPECT_EQ(0, nv_xdev_ext_ce_submit_plan(e, 5, 1, sp, fake_submit, &rm, &issued,
						&token, &calls));
	EXPECT_EQ(5, calls);			/* one call per plan entry */
	for (i = 0; i < 5; i++) {
		EXPECT_EQ(1, rm.m[i]);
		EXPECT_EQ(KB(4) * i, rm.first[i].host_off);
		EXPECT_EQ(KB(4), rm.first[i].len);
	}
	EXPECT_EQ(104, token);			/* the last call completes the batch */

	rm = (struct fake_rm){ 0 };
	EXPECT_EQ(0, nv_xdev_ext_ce_submit_plan(e, 5, 2, sp, fake_submit, &rm, &issued,
						&token, &calls));
	EXPECT_EQ(3, calls);
	EXPECT_EQ(KB(8), rm.first[0].len);	/* merged within a call */
	EXPECT_EQ(KB(4), rm.first[2].len);

	rm = (struct fake_rm){ .fail_at = 3 };
	EXPECT_EQ(0x55, nv_xdev_ext_ce_submit_plan(e, 5, 1, sp, fake_submit, &rm, &issued,
						   &token, &calls));
	EXPECT_EQ(3, calls);			/* nothing after the failed call */
	EXPECT_EQ(3, rm.calls);
	EXPECT_EQ(1, issued);			/* earlier calls issued DMA */
	EXPECT_EQ(101, token);

	rm = (struct fake_rm){ .fail_at = 1 };
	EXPECT_EQ(0x55, nv_xdev_ext_ce_submit_plan(e, 5, 1, sp, fake_submit, &rm, &issued,
						   &token, &calls));
	EXPECT_EQ(0, issued);			/* first call refused: pre-submit */
	EXPECT_EQ(0, token);

	rm = (struct fake_rm){ .fail_at = 1, .fail_issued = 1 };
	nv_xdev_ext_ce_submit_plan(e, 5, 0, sp, fake_submit, &rm, &issued, &token, &calls);
	EXPECT_EQ(1, issued);			/* RM's own issued flag is kept */
}

int main(void)
{
	nv_xdev_ext_gpu_u32 rm_dir = 7;

	/*
	 * Stage direction is relative to the GPU: TO_DEVICE copies host pages
	 * into the window (RM direction 1), FROM_DEVICE back (RM direction 0).
	 */
	EXPECT_EQ(0, nv_xdev_ext_ce_rm_direction(NV_XDEV_EXT_GPU_TO_DEVICE, &rm_dir));
	EXPECT_EQ(NV_XDEV_EXT_GPU_UMEM_TO_GPU, rm_dir);
	EXPECT_EQ(1, rm_dir);
	EXPECT_EQ(0, nv_xdev_ext_ce_rm_direction(NV_XDEV_EXT_GPU_FROM_DEVICE, &rm_dir));
	EXPECT_EQ(NV_XDEV_EXT_GPU_GPU_TO_UMEM, rm_dir);
	EXPECT_EQ(0, rm_dir);
	rm_dir = 7;
	EXPECT_EQ(-EINVAL, nv_xdev_ext_ce_rm_direction(0, &rm_dir));
	EXPECT_EQ(-EINVAL, nv_xdev_ext_ce_rm_direction(3, &rm_dir));
	EXPECT_EQ(7, rm_dir);

	/* One submit carries 1..NV_XDEV_EXT_CE_MAX_XFERS entries (RM's bound). */
	EXPECT_EQ(64, NV_XDEV_EXT_CE_MAX_XFERS);
	EXPECT_EQ(0, nv_xdev_ext_ce_count_ok(0));
	EXPECT_EQ(1, nv_xdev_ext_ce_count_ok(1));
	EXPECT_EQ(1, nv_xdev_ext_ce_count_ok(32));
	EXPECT_EQ(1, nv_xdev_ext_ce_count_ok(NV_XDEV_EXT_CE_MAX_XFERS));
	EXPECT_EQ(0, nv_xdev_ext_ce_count_ok(NV_XDEV_EXT_CE_MAX_XFERS + 1));

	/* Entries inside both the window and the host pages. */
	EXPECT_EQ(1, nv_xdev_ext_ce_entry_ok(0, 0, 4096, MB(1), MB(4)));
	EXPECT_EQ(1, nv_xdev_ext_ce_entry_ok(MB(4) - 64, MB(1) - 64, 64, MB(1), MB(4)));
	EXPECT_EQ(1, nv_xdev_ext_ce_entry_ok(KB(6), KB(130), 2048, MB(1), MB(4)));

	/* Empty, past the window, past the host pages, at the edges. */
	EXPECT_EQ(0, nv_xdev_ext_ce_entry_ok(0, 0, 0, MB(1), MB(4)));
	EXPECT_EQ(0, nv_xdev_ext_ce_entry_ok(0, MB(1) - 64, 65, MB(1), MB(4)));
	EXPECT_EQ(0, nv_xdev_ext_ce_entry_ok(0, MB(1), 1, MB(1), MB(4)));
	EXPECT_EQ(0, nv_xdev_ext_ce_entry_ok(MB(4) - 64, 0, 65, MB(1), MB(4)));
	EXPECT_EQ(0, nv_xdev_ext_ce_entry_ok(MB(4), 0, 1, MB(1), MB(4)));

	/* Offsets that would wrap a sum are refused, never summed. */
	EXPECT_EQ(0, nv_xdev_ext_ce_entry_ok(UINT64_MAX, 0, 1, MB(1), MB(4)));
	EXPECT_EQ(0, nv_xdev_ext_ce_entry_ok(0, UINT64_MAX, 1, MB(1), MB(4)));
	EXPECT_EQ(0, nv_xdev_ext_ce_entry_ok(0, 0, UINT32_MAX, MB(1), UINT64_MAX));
	EXPECT_EQ(1, nv_xdev_ext_ce_entry_ok(UINT64_MAX - 1, UINT64_MAX - 1, 1,
					UINT64_MAX, UINT64_MAX));

	/*
	 * Status handed to xdev_ext_ce_complete(): 0 for NV_OK whatever the mapped
	 * errno, else the mapped negative errno, else -EIO.
	 */
	EXPECT_EQ(0, nv_xdev_ext_gpu_normalize_status(0, -EIO));
	EXPECT_EQ(-EBUSY, nv_xdev_ext_gpu_normalize_status(0x55, -EBUSY));
	EXPECT_EQ(-EIO, nv_xdev_ext_gpu_normalize_status(0x55, 0));
	EXPECT_EQ(-EIO, nv_xdev_ext_gpu_normalize_status(0x55, 5));
	EXPECT_EQ(-EIO, nv_xdev_ext_gpu_normalize_status(0x55, -5000));

	/*
	 * RM transfers of a plan: an entry adjacent to the previous one in both
	 * the host pages and the window extends it; any gap starts a new one;
	 * one transfer never exceeds RM's 32-bit size.
	 */
	{
		struct nv_xdev_ext_ce_span sp[8];
		nv_xdev_ext_gpu_u32 m = 0;

		nv_xdev_ext_ce_span_add(sp, &m, KB(8), 0, 4096);
		nv_xdev_ext_ce_span_add(sp, &m, KB(12), KB(4), 4096);
		nv_xdev_ext_ce_span_add(sp, &m, KB(16), KB(8), 2048);
		EXPECT_EQ(1, m);
		EXPECT_EQ(KB(8), sp[0].host_off);
		EXPECT_EQ(0, sp[0].gpu_off);
		EXPECT_EQ(10240, sp[0].len);
		nv_xdev_ext_ce_span_add(sp, &m, KB(40), KB(10), 4096);	/* host gap */
		EXPECT_EQ(2, m);
		nv_xdev_ext_ce_span_add(sp, &m, KB(44), KB(20), 4096);	/* window gap */
		EXPECT_EQ(3, m);
		nv_xdev_ext_ce_span_add(sp, &m, KB(48), KB(24), 4096);
		EXPECT_EQ(3, m);
		EXPECT_EQ(8192, sp[2].len);
		/* Same host, earlier window: never merged backwards or overlapping. */
		nv_xdev_ext_ce_span_add(sp, &m, KB(52), KB(24), 4096);
		EXPECT_EQ(4, m);
		nv_xdev_ext_ce_span_add(sp, &m, KB(52), KB(28), 4096);	/* overlaps host */
		EXPECT_EQ(5, m);
		/* 32-bit size limit: the next adjacent entry starts a new transfer. */
		m = 0;
		nv_xdev_ext_ce_span_add(sp, &m, 0, 0, 0xffffe000U);
		nv_xdev_ext_ce_span_add(sp, &m, 0xffffe000ULL, 0xffffe000ULL, 0x1000);
		EXPECT_EQ(1, m);
		EXPECT_EQ(0xfffff000ULL, sp[0].len);
		nv_xdev_ext_ce_span_add(sp, &m, 0xfffff000ULL, 0xfffff000ULL, 0x1000);
		EXPECT_EQ(2, m);
		EXPECT_EQ(0xfffff000ULL, sp[0].len);
		EXPECT_EQ(0x1000, sp[1].len);
		EXPECT_EQ(0xfffff000ULL, sp[1].host_off);
	}

	test_entries_per_submit();
	printf("nv_xdev_ext_ce_plan_test: %u checks, %u failures\n", checks,
	       failures);
	return failures != 0;
}
