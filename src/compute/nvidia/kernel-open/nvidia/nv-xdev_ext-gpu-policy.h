/*
 * SPDX-FileCopyrightText: Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 *
 * Pure admission and synchronous routing for the XDEV_EXT GPU CE hook.  This file
 * deliberately has no NVIDIA RM or XDEV_EXT ABI dependency so the state machine can
 * be compiled and exercised with a fake backend.
 */
#ifndef _NV_XDEV_EXT_GPU_POLICY_H_
#define _NV_XDEV_EXT_GPU_POLICY_H_

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
typedef u32 nv_xdev_ext_gpu_u32;
typedef s32 nv_xdev_ext_gpu_s32;
typedef u64 nv_xdev_ext_gpu_u64;
#else
#include <errno.h>
#include <stdint.h>
typedef uint32_t nv_xdev_ext_gpu_u32;
typedef int32_t nv_xdev_ext_gpu_s32;
typedef uint64_t nv_xdev_ext_gpu_u64;
#endif

enum nv_xdev_ext_gpu_transfer_direction {
	NV_XDEV_EXT_GPU_GPU_TO_UMEM = 0,
	NV_XDEV_EXT_GPU_UMEM_TO_GPU = 1,
};

enum nv_xdev_ext_gpu_device_direction {
	NV_XDEV_EXT_GPU_TO_DEVICE = 1,
	NV_XDEV_EXT_GPU_FROM_DEVICE = 2,
};

enum nv_xdev_ext_gpu_action {
	NV_XDEV_EXT_GPU_ACTION_FALLBACK = 0,
	NV_XDEV_EXT_GPU_ACTION_USE_PLAN = 1,
	NV_XDEV_EXT_GPU_ACTION_TERMINAL = 2,
};

#define NV_XDEV_EXT_GPU_LINUX_ERRNO_MAX 4095

struct nv_xdev_ext_gpu_request {
	nv_xdev_ext_gpu_u64 request_id;
	nv_xdev_ext_gpu_u64 chain_id;
	nv_xdev_ext_gpu_u64 endpoint_id;
	nv_xdev_ext_gpu_u64 umem_buffer_id;
	nv_xdev_ext_gpu_u64 gpu_buffer_id;
	nv_xdev_ext_gpu_u32 direction;
	nv_xdev_ext_gpu_u32 umem_page_size;
	nv_xdev_ext_gpu_u32 umem_page_count;
	nv_xdev_ext_gpu_u32 gpu_page_size;
	nv_xdev_ext_gpu_u32 gpu_page_count;
	nv_xdev_ext_gpu_u64 umem_offset;
	nv_xdev_ext_gpu_u64 gpu_offset;
	nv_xdev_ext_gpu_u64 length;
	nv_xdev_ext_gpu_u64 umem_capacity;
};

struct nv_xdev_ext_gpu_route {
	nv_xdev_ext_gpu_u32 device_direction;
	nv_xdev_ext_gpu_u64 src_buffer_id;
	nv_xdev_ext_gpu_u64 dst_buffer_id;
	nv_xdev_ext_gpu_u64 src_offset;
	nv_xdev_ext_gpu_u64 dst_offset;
};

struct nv_xdev_ext_gpu_plan {
	nv_xdev_ext_gpu_u32 action;
};

struct nv_xdev_ext_gpu_result {
	nv_xdev_ext_gpu_s32 result;
	nv_xdev_ext_gpu_u64 bytes_done;
};

struct nv_xdev_ext_gpu_outcome {
	nv_xdev_ext_gpu_s32 dispatch_error;
	nv_xdev_ext_gpu_s32 completion_error;
	nv_xdev_ext_gpu_u32 dispatch_action;
	nv_xdev_ext_gpu_u32 completion_action;
};

struct nv_xdev_ext_gpu_ops {
	int (*dispatch)(void *private,
			const struct nv_xdev_ext_gpu_request *request,
			struct nv_xdev_ext_gpu_plan *plan);
	nv_xdev_ext_gpu_u32 (*submit)(void *private,
				 const struct nv_xdev_ext_gpu_request *request);
	int (*complete)(void *private,
			const struct nv_xdev_ext_gpu_request *request,
			const struct nv_xdev_ext_gpu_result *result,
			struct nv_xdev_ext_gpu_plan *plan);
	void (*token_put)(void *private);
	nv_xdev_ext_gpu_s32 (*normalize_status)(void *private,
					    nv_xdev_ext_gpu_u32 status);
};

static inline int nv_xdev_ext_gpu_page_size_valid(nv_xdev_ext_gpu_u32 page_size)
{
	return page_size == 4096U || page_size == 65536U ||
	       page_size == 131072U;
}

/* Validate coverage without ever forming offset + length or count * size. */
static inline int
nv_xdev_ext_gpu_pages_cover(nv_xdev_ext_gpu_u64 offset, nv_xdev_ext_gpu_u64 length,
		       nv_xdev_ext_gpu_u32 page_size, nv_xdev_ext_gpu_u32 page_count)
{
	nv_xdev_ext_gpu_u64 first_page;
	nv_xdev_ext_gpu_u64 first_bytes;
	nv_xdev_ext_gpu_u64 extra_pages;
	nv_xdev_ext_gpu_u64 remaining;

	if (!length || !page_size || !page_count)
		return 0;
	first_page = offset / page_size;
	if (first_page >= page_count)
		return 0;
	first_bytes = page_size - offset % page_size;
	if (length <= first_bytes)
		return 1;
	remaining = length - first_bytes;
	extra_pages = 1 + (remaining - 1) / page_size;
	return extra_pages <= (nv_xdev_ext_gpu_u64)page_count - first_page - 1;
}

static inline int
nv_xdev_ext_gpu_validate_request(const struct nv_xdev_ext_gpu_request *request)
{
	if (!request)
		return -EINVAL;
	if (!request->request_id || !request->chain_id ||
	    !request->endpoint_id || !request->umem_buffer_id ||
	    !request->gpu_buffer_id)
		return -EINVAL;
	if (request->direction != NV_XDEV_EXT_GPU_GPU_TO_UMEM &&
	    request->direction != NV_XDEV_EXT_GPU_UMEM_TO_GPU)
		return -EINVAL;
	if (!request->length ||
	    request->length > (nv_xdev_ext_gpu_u64)(nv_xdev_ext_gpu_u32)~0U)
		return -EINVAL;
	if (request->umem_offset > request->umem_capacity ||
	    request->length > request->umem_capacity - request->umem_offset)
		return -EINVAL;
	if (!nv_xdev_ext_gpu_pages_cover(request->umem_offset, request->length,
				    request->umem_page_size,
				    request->umem_page_count))
		return -EINVAL;
	if (!nv_xdev_ext_gpu_page_size_valid(request->gpu_page_size) ||
	    request->gpu_offset >= request->gpu_page_size ||
	    !nv_xdev_ext_gpu_pages_cover(request->gpu_offset, request->length,
				    request->gpu_page_size,
				    request->gpu_page_count))
		return -EINVAL;
	return 0;
}

static inline int
nv_xdev_ext_gpu_make_route(const struct nv_xdev_ext_gpu_request *request,
		      struct nv_xdev_ext_gpu_route *route)
{
	int ret;

	if (!route)
		return -EINVAL;
	ret = nv_xdev_ext_gpu_validate_request(request);
	if (ret)
		return ret;
	if (request->direction == NV_XDEV_EXT_GPU_UMEM_TO_GPU) {
		route->device_direction = NV_XDEV_EXT_GPU_TO_DEVICE;
		route->src_buffer_id = request->umem_buffer_id;
		route->dst_buffer_id = request->gpu_buffer_id;
		route->src_offset = request->umem_offset;
		route->dst_offset = request->gpu_offset;
	} else {
		route->device_direction = NV_XDEV_EXT_GPU_FROM_DEVICE;
		route->src_buffer_id = request->gpu_buffer_id;
		route->dst_buffer_id = request->umem_buffer_id;
		route->src_offset = request->gpu_offset;
		route->dst_offset = request->umem_offset;
	}
	return 0;
}

static inline nv_xdev_ext_gpu_s32
nv_xdev_ext_gpu_normalize_status(nv_xdev_ext_gpu_u32 status,
			    nv_xdev_ext_gpu_s32 mapped_error)
{
	if (!status)
		return 0;
	return mapped_error < 0 &&
	       mapped_error >= -NV_XDEV_EXT_GPU_LINUX_ERRNO_MAX ?
	       mapped_error : -EIO;
}

static inline int nv_xdev_ext_gpu_action_valid(nv_xdev_ext_gpu_u32 action)
{
	return action <= NV_XDEV_EXT_GPU_ACTION_TERMINAL;
}

/*
 * Run one synchronous CE request.  Once submit is entered, complete is called
 * exactly once and the native status is returned unchanged.  Before submit,
 * every path following dispatch goes through token_put.
 */
static inline nv_xdev_ext_gpu_u32
nv_xdev_ext_gpu_run(const struct nv_xdev_ext_gpu_request *request,
	       const struct nv_xdev_ext_gpu_ops *ops, void *private,
	       nv_xdev_ext_gpu_u32 invalid_status, nv_xdev_ext_gpu_u32 denied_status,
	       struct nv_xdev_ext_gpu_outcome *outcome)
{
	struct nv_xdev_ext_gpu_result result = {};
	struct nv_xdev_ext_gpu_plan dispatch_plan = {};
	struct nv_xdev_ext_gpu_plan complete_plan = {};
	nv_xdev_ext_gpu_u32 native_status;
	int ret;

	if (outcome)
		*outcome = (struct nv_xdev_ext_gpu_outcome){};
	ret = nv_xdev_ext_gpu_validate_request(request);
	if (ret)
		goto invalid_without_token;
	if (!ops || !ops->dispatch || !ops->submit || !ops->complete ||
	    !ops->token_put || !ops->normalize_status) {
		ret = -EINVAL;
		goto invalid_without_token;
	}

	ret = ops->dispatch(private, request, &dispatch_plan);
	if (outcome) {
		outcome->dispatch_error = ret < 0 ? ret : ret ? -EPROTO : 0;
		outcome->dispatch_action = dispatch_plan.action;
	}
	if (ret || !nv_xdev_ext_gpu_action_valid(dispatch_plan.action)) {
		if (!ret && outcome)
			outcome->dispatch_error = -EPROTO;
		ops->token_put(private);
		return invalid_status;
	}
	if (dispatch_plan.action == NV_XDEV_EXT_GPU_ACTION_TERMINAL) {
		ops->token_put(private);
		return denied_status;
	}

	native_status = ops->submit(private, request);
	if (!native_status) {
		result.bytes_done = request->length;
	} else {
		result.result = nv_xdev_ext_gpu_normalize_status(
			native_status, ops->normalize_status(private, native_status));
	}
	ret = ops->complete(private, request, &result, &complete_plan);
	if (outcome) {
		outcome->completion_error =
			ret < 0 ? ret : ret ? -EPROTO : 0;
		outcome->completion_action = complete_plan.action;
		if (!ret && !nv_xdev_ext_gpu_action_valid(complete_plan.action))
			outcome->completion_error = -EPROTO;
	}
	return native_status;

invalid_without_token:
	if (outcome)
		outcome->dispatch_error = ret;
	return invalid_status;
}

#endif /* _NV_XDEV_EXT_GPU_POLICY_H_ */
