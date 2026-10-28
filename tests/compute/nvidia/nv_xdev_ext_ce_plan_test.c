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

	printf("nv_xdev_ext_ce_plan_test: %u checks, %u failures\n", checks,
	       failures);
	return failures != 0;
}
