/* SPDX-License-Identifier: MIT */
#include <stdio.h>

#include "../kernel-open/nvidia/nv-xdev_ext-dma-lifetime.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(expected, actual) do {                                  \
	unsigned long expected_ = (unsigned long)(expected);                 \
	unsigned long actual_ = (unsigned long)(actual);                     \
	checks++;                                                             \
	if (expected_ != actual_) {                                          \
		fprintf(stderr, "%s:%d expected %lu got %lu\n",             \
			__FILE__, __LINE__, expected_, actual_);                 \
		failures++;                                                     \
	}                                                                    \
} while (0)

int main(void)
{
	struct nv_xdev_ext_dma_lifetime lifetime = { 0 };
	struct nv_xdev_ext_dma_lifetime batch_lifetime = { 0 };

	EXPECT_EQ(1, nv_xdev_ext_dma_can_submit(&lifetime));
	EXPECT_EQ(1, nv_xdev_ext_dma_can_release(&lifetime));

	/* Failures before CE acceptance leave the backings reusable. */
	nv_xdev_ext_dma_finish(&lifetime, NV_XDEV_EXT_DMA_PRE_SUBMIT_FAILURE);
	EXPECT_EQ(1, nv_xdev_ext_dma_can_submit(&lifetime));
	EXPECT_EQ(1, nv_xdev_ext_dma_can_release(&lifetime));

	/* A proven completion also permits normal release and reuse. */
	nv_xdev_ext_dma_finish(&lifetime, NV_XDEV_EXT_DMA_COMPLETED);
	EXPECT_EQ(1, nv_xdev_ext_dma_can_submit(&lifetime));
	EXPECT_EQ(1, nv_xdev_ext_dma_can_release(&lifetime));

	/* Post-submit uncertainty is permanent and cannot be cleared by success. */
	EXPECT_EQ(1, nv_xdev_ext_dma_finish(
		&lifetime, NV_XDEV_EXT_DMA_POST_SUBMIT_AMBIGUOUS));
	EXPECT_EQ(0, nv_xdev_ext_dma_can_submit(&lifetime));
	EXPECT_EQ(0, nv_xdev_ext_dma_can_release(&lifetime));
	EXPECT_EQ(1, lifetime.quarantine_tracked);
	EXPECT_EQ(1, lifetime.module_ref_count);
	/* Normal path transfers the xarray base ref to the quarantine list. */
	EXPECT_EQ(0, nv_xdev_ext_dma_quarantine_needs_ref(&lifetime, 1));
	EXPECT_EQ(0, nv_xdev_ext_dma_finish(
		&lifetime, NV_XDEV_EXT_DMA_POST_SUBMIT_AMBIGUOUS));
	EXPECT_EQ(1, lifetime.quarantine_tracked);
	EXPECT_EQ(1, lifetime.module_ref_count);
	nv_xdev_ext_dma_finish(&lifetime, NV_XDEV_EXT_DMA_COMPLETED);
	EXPECT_EQ(0, nv_xdev_ext_dma_can_submit(&lifetime));
	EXPECT_EQ(0, nv_xdev_ext_dma_can_release(&lifetime));

	/* Batch ambiguity has the same one-way, one-ref transition. */
	EXPECT_EQ(1, nv_xdev_ext_dma_finish(
		&batch_lifetime, NV_XDEV_EXT_DMA_POST_SUBMIT_AMBIGUOUS));
	EXPECT_EQ(0, nv_xdev_ext_dma_can_submit(&batch_lifetime));
	EXPECT_EQ(0, nv_xdev_ext_dma_can_release(&batch_lifetime));
	EXPECT_EQ(1, batch_lifetime.quarantine_tracked);
	EXPECT_EQ(1, batch_lifetime.module_ref_count);
	/* Concurrent UNPIN removed xarray ownership, so list takes a new ref. */
	EXPECT_EQ(1, nv_xdev_ext_dma_quarantine_needs_ref(&batch_lifetime, 0));

	printf("nv_xdev_ext_dma_lifetime_test: %u checks, %u failures\n",
	       checks, failures);
	return failures ? 1 : 0;
}
