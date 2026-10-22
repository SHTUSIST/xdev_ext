// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "../../../nvme_gpu_nic_runtime.h"

int main(void)
{
	struct ngn_gpu_runtime runtime = NGN_GPU_RUNTIME_INIT;
	const struct ngn_gpu_transfer transfer = {
		.umem_offset = 0,
		.gpu_offset = 0,
		.length = 4096,
	};
	uint32_t completed = UINT32_MAX;
	bool ambiguous = true;
	int ret;

	ret = ngn_gpu_runtime_init(&runtime, "/dev/nvidia0", 3,
				   (void *)(uintptr_t)4096, 4096, 4096);
	if (ret != -EOPNOTSUPP) {
		fprintf(stderr, "host init returned %d\n", ret);
		return 1;
	}
	ret = ngn_gpu_runtime_submit(&runtime, NGN_GPU_UMEM_TO_GPU,
				     &transfer, 1, &completed, &ambiguous);
	if (ret != -EOPNOTSUPP || completed != 0 || ambiguous) {
		fprintf(stderr,
			"host submit returned %d completed=%u ambiguous=%d\n",
			ret, completed, ambiguous);
		return 1;
	}
	if (ngn_gpu_runtime_cleanup(&runtime)) {
		fprintf(stderr, "inactive cleanup failed\n");
		return 1;
	}
	puts("PASS: no-CUDA runtime fails closed");
	return 0;
}
