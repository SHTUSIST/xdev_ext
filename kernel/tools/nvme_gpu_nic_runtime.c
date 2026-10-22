// SPDX-License-Identifier: GPL-2.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nvme_gpu_nic_runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "include/xdev_ext_gpu_identity.h"
#include "include/xdev_ext_nv_p2p_ioctl.h"

#ifdef XDEV_EXT_NVME_GPU_NIC_WITH_CUDA
#include <cuda.h>

static int ngn_cuda_result(CUresult result)
{
	return result == CUDA_SUCCESS ? 0 : -EIO;
}

static int ngn_cuda_match_bdf(const char *bdf, CUdevice *matched)
{
	CUdevice found = 0;
	unsigned int matches = 0;
	int count;
	int ret;

	ret = ngn_cuda_result(cuInit(0));
	if (ret)
		return ret;
	ret = ngn_cuda_result(cuDeviceGetCount(&count));
	if (ret)
		return ret;
	for (int ordinal = 0; ordinal < count; ordinal++) {
		CUdevice device;
		char candidate[32] = { 0 };

		if (ngn_cuda_result(cuDeviceGet(&device, ordinal)) ||
		    ngn_cuda_result(cuDeviceGetPCIBusId(candidate,
						 sizeof(candidate), device)))
			return -EIO;
		if (!strcasecmp(candidate, bdf)) {
			found = device;
			matches++;
		}
	}
	if (matches != 1)
		return matches ? -EEXIST : -ENODEV;
	*matched = found;
	return 0;
}

static int ngn_release_cuda(struct ngn_gpu_runtime *runtime)
{
	int first = 0;

	if (runtime->gpu_base) {
		int ret = ngn_cuda_result(cuCtxSetCurrent(
			(CUcontext)runtime->cuda_context));

		if (!ret)
			ret = ngn_cuda_result(cuMemFree(
				(CUdeviceptr)runtime->gpu_base));
		if (ret)
			first = ret;
		else
			runtime->gpu_base = 0;
	}
	if (runtime->cuda_primary_retained) {
		int ret = ngn_cuda_result(cuDevicePrimaryCtxRelease(
			(CUdevice)runtime->cuda_device));

		if (ret && !first)
			first = ret;
		if (!ret)
			runtime->cuda_primary_retained = false;
	}
	return first;
}

int ngn_gpu_runtime_init(struct ngn_gpu_runtime *runtime,
			 const char *gpu_device, int xsk_fd, void *umem,
			 size_t umem_bytes, uint32_t frame_size)
{
	struct xdev_ext_nv_p2p_pin_umem pin = { 0 };
	CUdevice device;
	CUcontext context;
	CUdeviceptr allocation;
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };
	int ret;

	if (!runtime || !gpu_device || xsk_fd < 0 || !umem || !umem_bytes ||
	    !frame_size || (frame_size & (frame_size - 1)) ||
	    (uintptr_t)umem % frame_size || umem_bytes % frame_size)
		return -EINVAL;
	*runtime = (struct ngn_gpu_runtime)NGN_GPU_RUNTIME_INIT;
	runtime->gpu_fd = open(gpu_device, O_RDWR | O_CLOEXEC);
	if (runtime->gpu_fd < 0)
		return -errno;
	ret = xdev_ext_gpu_identity_from_opened(runtime->gpu_fd, gpu_device,
					   XDEV_EXT_GPU_IDENTITY_ANY_MINOR, bdf);
	if (ret)
		goto fail;
	ret = ngn_cuda_match_bdf(bdf, &device);
	if (ret)
		goto fail;
	runtime->cuda_device = (int)device;
	ret = ngn_cuda_result(cuDevicePrimaryCtxRetain(&context, device));
	if (ret)
		goto fail;
	runtime->cuda_context = (uintptr_t)context;
	runtime->cuda_primary_retained = true;
	ret = ngn_cuda_result(cuCtxSetCurrent(context));
	if (ret)
		goto fail;
	ret = ngn_cuda_result(cuMemAlloc(&allocation, umem_bytes));
	if (ret)
		goto fail;
	runtime->gpu_base = (uint64_t)allocation;
	runtime->gpu_bytes = umem_bytes;
	if (runtime->gpu_base > UINT64_MAX - runtime->gpu_bytes) {
		ret = -EOVERFLOW;
		goto fail;
	}
	pin = (struct xdev_ext_nv_p2p_pin_umem) {
		.umem_addr = (uint64_t)(uintptr_t)umem,
		.size = umem_bytes,
		.frame_size = frame_size,
		.xsk_fd = xsk_fd,
		.flags = 0,
	};
	if (xdev_ext_nv_p2p_pin_umem(runtime->gpu_fd, &pin)) {
		ret = errno ? -errno : -EIO;
		goto fail;
	}
	runtime->p2p_handle = pin.handle;
	runtime->active = true;
	return 0;

fail:
	if (ngn_release_cuda(runtime))
		runtime->sequestered = true;
	if (runtime->gpu_fd >= 0 && !runtime->sequestered)
		close(runtime->gpu_fd);
	if (!runtime->sequestered)
		runtime->gpu_fd = -1;
	return ret;
}

int ngn_gpu_runtime_submit(void *opaque, enum ngn_gpu_direction direction,
			   const struct ngn_gpu_transfer *transfers,
			   uint32_t count, uint32_t *completed,
			   bool *ambiguous)
{
	struct ngn_gpu_runtime *runtime = opaque;
	struct xdev_ext_nv_p2p_dma_batch batch = { 0 };
	int saved_errno;
	int ret;

	if (!completed || !ambiguous)
		return -EINVAL;
	*completed = 0;
	*ambiguous = false;
	if (!runtime || !runtime->active || runtime->sequestered ||
	    !runtime->p2p_handle || !transfers || !count ||
	    count > NGN_GPU_MAX_BATCH ||
	    (direction != NGN_GPU_UMEM_TO_GPU &&
	     direction != NGN_GPU_GPU_TO_UMEM))
		return -EINVAL;
	batch.handle = runtime->p2p_handle;
	batch.count = count;
	for (uint32_t i = 0; i < count; i++) {
		uint64_t gpu_address;
		uint64_t gpu_end;

		if (!transfers[i].length ||
		    ngn_u64_add_overflow(transfers[i].gpu_offset,
					 transfers[i].length, &gpu_end) ||
		    gpu_end > runtime->gpu_bytes ||
		    runtime->gpu_base >
			UINT64_MAX - transfers[i].gpu_offset)
			return -ERANGE;
		gpu_address = runtime->gpu_base + transfers[i].gpu_offset;
		batch.entries[i] = (struct xdev_ext_nv_p2p_dma_batch_entry) {
			.gpu_offset = gpu_address,
			.umem_offset = transfers[i].umem_offset,
			.size = transfers[i].length,
			.direction =
				direction == NGN_GPU_UMEM_TO_GPU ?
				XDEV_EXT_NV_P2P_UMEM_TO_GPU :
				XDEV_EXT_NV_P2P_GPU_TO_UMEM,
		};
	}
	runtime->batch_calls++;
	ret = xdev_ext_nv_p2p_dma_batch(runtime->gpu_fd, &batch);
	saved_errno = errno;
	if (batch.completed <= count) {
		*completed = batch.completed;
		runtime->completed_items += batch.completed;
	} else {
		*completed = count;
	}
	if (!ret)
		return 0;
	/*
	 * Validation above makes a pre-ioctl failure impossible for a correctly
	 * initialized runtime.  The first failed CE item can have reached the
	 * engine, so preserve the handle, XSK fd, CUDA allocation, and UMEM.
	 */
	*ambiguous = true;
	runtime->sequestered = true;
	return saved_errno ? -saved_errno : -EIO;
}

int ngn_gpu_runtime_cleanup(struct ngn_gpu_runtime *runtime)
{
	struct xdev_ext_nv_p2p_unpin_umem unpin;
	int ret;

	if (!runtime)
		return -EINVAL;
	if (runtime->sequestered)
		return -EBUSY;
	if (!runtime->active) {
		ret = ngn_release_cuda(runtime);
		if (runtime->gpu_fd >= 0)
			close(runtime->gpu_fd);
		runtime->gpu_fd = -1;
		return ret;
	}
	ret = ngn_cuda_result(cuCtxSetCurrent(
		(CUcontext)runtime->cuda_context));
	if (!ret)
		ret = ngn_cuda_result(cuCtxSynchronize());
	if (ret) {
		runtime->sequestered = true;
		return ret;
	}
	unpin = (struct xdev_ext_nv_p2p_unpin_umem) {
		.handle = runtime->p2p_handle,
	};
	if (xdev_ext_nv_p2p_unpin_umem(runtime->gpu_fd, &unpin)) {
		runtime->sequestered = true;
		return errno ? -errno : -EIO;
	}
	runtime->p2p_handle = 0;
	runtime->active = false;
	ret = ngn_release_cuda(runtime);
	if (ret) {
		runtime->sequestered = true;
		return ret;
	}
	if (runtime->gpu_fd >= 0 && close(runtime->gpu_fd))
		return -errno;
	runtime->gpu_fd = -1;
	return 0;
}

#else /* !XDEV_EXT_NVME_GPU_NIC_WITH_CUDA */

int ngn_gpu_runtime_init(struct ngn_gpu_runtime *runtime,
			 const char *gpu_device, int xsk_fd, void *umem,
			 size_t umem_bytes, uint32_t frame_size)
{
	(void)runtime;
	(void)gpu_device;
	(void)xsk_fd;
	(void)umem;
	(void)umem_bytes;
	(void)frame_size;
	return -EOPNOTSUPP;
}

int ngn_gpu_runtime_submit(void *opaque, enum ngn_gpu_direction direction,
			   const struct ngn_gpu_transfer *transfers,
			   uint32_t count, uint32_t *completed,
			   bool *ambiguous)
{
	(void)opaque;
	(void)direction;
	(void)transfers;
	(void)count;
	if (!completed || !ambiguous)
		return -EINVAL;
	*completed = 0;
	*ambiguous = false;
	return -EOPNOTSUPP;
}

int ngn_gpu_runtime_cleanup(struct ngn_gpu_runtime *runtime)
{
	return runtime ? 0 : -EINVAL;
}

#endif /* XDEV_EXT_NVME_GPU_NIC_WITH_CUDA */
