/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stdio.h>

#include "../kernel-open/nvidia/nv-xdev_ext-gpu.h"

int main(void)
{
	struct nv_xdev_ext_gpu_binding binding = {};
	struct nv_xdev_ext_gpu_request request = {
		.direction = NV_XDEV_EXT_GPU_UMEM_TO_GPU,
		.umem_page_size = 4096,
		.umem_page_count = 1,
		.gpu_page_size = 4096,
		.gpu_page_count = 1,
		.length = 4096,
		.umem_capacity = 4096,
	};
	struct nv_xdev_ext_gpu_result result = { .bytes_done = 4096 };
	struct nv_xdev_ext_gpu_plan plan = { .action = 99 };

	if (nv_xdev_ext_gpu_binding_dispatch(&binding, &request, &plan) != 0 ||
	    plan.action != NV_XDEV_EXT_GPU_ACTION_FALLBACK)
		return 1;
	plan.action = 99;
	if (nv_xdev_ext_gpu_binding_complete(&binding, &request, &result, &plan) != 0 ||
	    plan.action != NV_XDEV_EXT_GPU_ACTION_FALLBACK)
		return 1;
	nv_xdev_ext_gpu_binding_put(&binding);
	puts("PASS: CONFIG-off XDEV_EXT GPU binding stub");
	return 0;
}
