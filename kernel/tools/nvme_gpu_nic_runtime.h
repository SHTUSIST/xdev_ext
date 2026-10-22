/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NVME_GPU_NIC_RUNTIME_H
#define NVME_GPU_NIC_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "nvme_gpu_nic_chain_core.h"

struct ngn_gpu_runtime {
	int gpu_fd;
	int cuda_device;
	uintptr_t cuda_context;
	uint64_t gpu_base;
	uint64_t gpu_bytes;
	uint64_t p2p_handle;
	uint64_t batch_calls;
	uint64_t completed_items;
	bool cuda_primary_retained;
	bool active;
	bool sequestered;
};

#define NGN_GPU_RUNTIME_INIT { .gpu_fd = -1 }

int ngn_gpu_runtime_init(struct ngn_gpu_runtime *runtime,
			 const char *gpu_device, int xsk_fd, void *umem,
			 size_t umem_bytes, uint32_t frame_size);

int ngn_gpu_runtime_submit(void *opaque, enum ngn_gpu_direction direction,
			   const struct ngn_gpu_transfer *transfers,
			   uint32_t count, uint32_t *completed,
			   bool *ambiguous);

int ngn_gpu_runtime_cleanup(struct ngn_gpu_runtime *runtime);

#endif /* NVME_GPU_NIC_RUNTIME_H */
