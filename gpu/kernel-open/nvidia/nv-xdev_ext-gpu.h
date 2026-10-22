/*
 * SPDX-FileCopyrightText: Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 */
#ifndef _NV_XDEV_EXT_GPU_H_
#define _NV_XDEV_EXT_GPU_H_

#include "nv-xdev_ext-gpu-policy.h"

#if defined(CONFIG_IO_URING_XDEV_EXT_BPF_POLICY) && \
	CONFIG_IO_URING_XDEV_EXT_BPF_POLICY

#include <linux/xdev_ext_binding.h>

struct nv_xdev_ext_gpu_binding {
	struct xdev_ext_binding_token token;
	struct xdev_ext_binding_ctx_v2 ctx;
};

static inline int
nv_xdev_ext_gpu_action_from_xdev_ext(nv_xdev_ext_gpu_u32 action,
			   struct nv_xdev_ext_gpu_plan *plan)
{
	if (!plan)
		return -EINVAL;
	switch (action) {
	case XDEV_EXT_BINDING_ACTION_FALLBACK:
		plan->action = NV_XDEV_EXT_GPU_ACTION_FALLBACK;
		return 0;
	case XDEV_EXT_BINDING_ACTION_USE_PLAN:
		plan->action = NV_XDEV_EXT_GPU_ACTION_USE_PLAN;
		return 0;
	case XDEV_EXT_BINDING_ACTION_TERMINAL:
		plan->action = NV_XDEV_EXT_GPU_ACTION_TERMINAL;
		return 0;
	default:
		return -EPROTO;
	}
}

static inline int
nv_xdev_ext_gpu_binding_dispatch(void *private,
			    const struct nv_xdev_ext_gpu_request *request,
			    struct nv_xdev_ext_gpu_plan *plan)
{
	struct nv_xdev_ext_gpu_binding *binding = private;
	struct xdev_ext_binding_plan xdev_ext_plan = {};
	struct nv_xdev_ext_gpu_route route;
	nv_xdev_ext_gpu_u32 direction;
	int ret;

	if (!binding || !plan)
		return -EINVAL;
	ret = nv_xdev_ext_gpu_make_route(request, &route);
	if (ret)
		return ret;
	direction = route.device_direction == NV_XDEV_EXT_GPU_TO_DEVICE ?
		XDEV_EXT_BINDING_DIRECTION_TO_DEVICE :
		XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE;
	binding->ctx = xdev_ext_binding_make_gpu_ctx(direction, route.src_offset,
						 route.dst_offset,
						 request->length);
	binding->ctx.request_id = request->request_id;
	binding->ctx.chain_id = request->chain_id;
	binding->ctx.endpoint_id = request->endpoint_id;
	binding->ctx.src_buffer_id = route.src_buffer_id;
	binding->ctx.dst_buffer_id = route.dst_buffer_id;
	binding->ctx.capabilities |= XDEV_EXT_BINDING_CAP_ZERO_COPY;
	ret = xdev_ext_binding_dispatch(&binding->ctx, &binding->token, &xdev_ext_plan);
	if (ret)
		return ret;
	ret = nv_xdev_ext_gpu_action_from_xdev_ext(xdev_ext_plan.action, plan);
	if (ret)
		xdev_ext_binding_token_put(&binding->token);
	return ret;
}

static inline int
nv_xdev_ext_gpu_binding_complete(void *private,
			    const struct nv_xdev_ext_gpu_request *request,
			    const struct nv_xdev_ext_gpu_result *result,
			    struct nv_xdev_ext_gpu_plan *plan)
{
	struct nv_xdev_ext_gpu_binding *binding = private;
	struct xdev_ext_binding_plan xdev_ext_plan = {};
	int ret;

	(void)request;
	if (!binding || !result || !plan)
		return -EINVAL;
	if (!binding->token.private) {
		plan->action = NV_XDEV_EXT_GPU_ACTION_FALLBACK;
		return 0;
	}
	binding->ctx.event = XDEV_EXT_BINDING_EVENT_COMPLETE;
	binding->ctx.result = result->result;
	binding->ctx.bytes_done = result->bytes_done;
	ret = xdev_ext_binding_complete(&binding->ctx, &binding->token, &xdev_ext_plan);
	if (ret)
		return ret;
	return nv_xdev_ext_gpu_action_from_xdev_ext(xdev_ext_plan.action, plan);
}

static inline void nv_xdev_ext_gpu_binding_put(void *private)
{
	struct nv_xdev_ext_gpu_binding *binding = private;

	if (binding && binding->token.private)
		xdev_ext_binding_token_put(&binding->token);
}

#else /* CONFIG_IO_URING_XDEV_EXT_BPF_POLICY */

struct nv_xdev_ext_gpu_binding {
	unsigned char disabled;
};

static inline int
nv_xdev_ext_gpu_binding_dispatch(void *private,
			    const struct nv_xdev_ext_gpu_request *request,
			    struct nv_xdev_ext_gpu_plan *plan)
{
	(void)private;
	(void)request;
	if (!plan)
		return -EINVAL;
	plan->action = NV_XDEV_EXT_GPU_ACTION_FALLBACK;
	return 0;
}

static inline int
nv_xdev_ext_gpu_binding_complete(void *private,
			    const struct nv_xdev_ext_gpu_request *request,
			    const struct nv_xdev_ext_gpu_result *result,
			    struct nv_xdev_ext_gpu_plan *plan)
{
	(void)private;
	(void)request;
	(void)result;
	if (!plan)
		return -EINVAL;
	plan->action = NV_XDEV_EXT_GPU_ACTION_FALLBACK;
	return 0;
}

static inline void nv_xdev_ext_gpu_binding_put(void *private)
{
	(void)private;
}

#endif /* CONFIG_IO_URING_XDEV_EXT_BPF_POLICY */

#endif /* _NV_XDEV_EXT_GPU_H_ */
