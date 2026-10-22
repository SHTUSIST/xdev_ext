/* SPDX-License-Identifier: MIT */
#include <stdio.h>

#define NV_STATUS_CODE(name, code, string) enum { name = code };
#include "../kernel-open/common/inc/nvstatuscodes.h"
#undef NV_STATUS_CODE

#include "../kernel-open/nvidia/nv-xdev_ext-ce-classify.h"

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
	/* Numbering is shared with the kernel CE mechanism's completion copy. */
	EXPECT_EQ(0, NV_XDEV_EXT_CE_OK);
	EXPECT_EQ(1, NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED);
	EXPECT_EQ(2, NV_XDEV_EXT_CE_AMBIGUOUS);

	/* An observed completion payload is success. */
	EXPECT_EQ(NV_XDEV_EXT_CE_OK, nv_xdev_ext_ce_classify(NV_OK, 1));
	/* A request that ended before its first copy never failed either. */
	EXPECT_EQ(NV_XDEV_EXT_CE_OK, nv_xdev_ext_ce_classify(NV_OK, 0));

	/*
	 * Admission refusals before memmgrMemCopy(): CeUtils absent, paused or
	 * not selected (REQUIRE_CE), a bad page span, an allocation failure.
	 * Nothing reached a channel, so the backing stays reusable.
	 */
	EXPECT_EQ(NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED,
		  nv_xdev_ext_ce_classify(NV_ERR_NOT_SUPPORTED, 0));
	EXPECT_EQ(NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED,
		  nv_xdev_ext_ce_classify(NV_ERR_BUSY_RETRY, 0));
	EXPECT_EQ(NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED,
		  nv_xdev_ext_ce_classify(NV_ERR_INVALID_ARGUMENT, 0));
	EXPECT_EQ(NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED,
		  nv_xdev_ext_ce_classify(NV_ERR_NO_MEMORY, 0));

	/*
	 * Any failure once memmgrMemCopy() was entered is ambiguous, even the
	 * codes a pre-submit refusal would also use: inside the copy they no
	 * longer prove that no GPFIFO entry or doorbell was written.
	 */
	EXPECT_EQ(NV_XDEV_EXT_CE_AMBIGUOUS, nv_xdev_ext_ce_classify(NV_ERR_TIMEOUT, 1));
	EXPECT_EQ(NV_XDEV_EXT_CE_AMBIGUOUS,
		  nv_xdev_ext_ce_classify(NV_ERR_NOT_SUPPORTED, 1));
	EXPECT_EQ(NV_XDEV_EXT_CE_AMBIGUOUS, nv_xdev_ext_ce_classify(NV_ERR_BUSY_RETRY, 1));
	EXPECT_EQ(NV_XDEV_EXT_CE_AMBIGUOUS, nv_xdev_ext_ce_classify(NV_ERR_GENERIC, 1));
	/* A warning code is still not an observed completion. */
	EXPECT_EQ(NV_XDEV_EXT_CE_AMBIGUOUS,
		  nv_xdev_ext_ce_classify(NV_WARN_OUT_OF_RANGE, 1));

	printf("nv_xdev_ext_ce_classify_test: %u checks, %u failures\n",
	       checks, failures);
	return failures ? 1 : 0;
}
