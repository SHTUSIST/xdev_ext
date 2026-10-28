/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>

#include "../kernel-open/nvidia/nv-p2p-gpu-identity.h"

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
	unsigned char opened[NV_P2P_GPU_IDENTITY_UUID_LEN];
	unsigned char allocation[NV_P2P_GPU_IDENTITY_UUID_LEN];
	unsigned int i;

	for (i = 0; i < NV_P2P_GPU_IDENTITY_UUID_LEN; i++)
		opened[i] = allocation[i] = (unsigned char)(i + 1);
	EXPECT_EQ(1, nv_p2p_gpu_identity_matches(opened, allocation));
	EXPECT_EQ(0, nv_p2p_gpu_identity_matches(NULL, allocation));
	EXPECT_EQ(0, nv_p2p_gpu_identity_matches(opened, NULL));
	for (i = 0; i < NV_P2P_GPU_IDENTITY_UUID_LEN; i++) {
		allocation[i] ^= 0x80U;
		EXPECT_EQ(0, nv_p2p_gpu_identity_matches(opened, allocation));
		allocation[i] ^= 0x80U;
	}

	printf("nv_xdev_ext_gpu_identity_test: %u checks, %u failures\n",
	       checks, failures);
	return failures ? 1 : 0;
}
