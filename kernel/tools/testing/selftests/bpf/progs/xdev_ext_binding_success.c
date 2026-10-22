// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

enum xdev_ext_binding_success_mode {
	XDEV_EXT_BINDING_SUCCESS_FALLBACK,
	XDEV_EXT_BINDING_SUCCESS_USE_PLAN,
	XDEV_EXT_BINDING_SUCCESS_TERMINAL,
	XDEV_EXT_BINDING_SUCCESS_RETURN_MISMATCH,
	XDEV_EXT_BINDING_SUCCESS_ZERO_CALLS,
	XDEV_EXT_BINDING_SUCCESS_DUPLICATE_CALLS,
	XDEV_EXT_BINDING_SUCCESS_INVALID_PLAN,
	XDEV_EXT_BINDING_SUCCESS_HOLD_DISPATCH,
	XDEV_EXT_BINDING_SUCCESS_FORGED_CTX = 9,
	XDEV_EXT_BINDING_SUCCESS_FOREIGN_THEN_VALID = 10,
	XDEV_EXT_BINDING_SUCCESS_VALID_THEN_FOREIGN,
};

__u32 dispatch_mode;
__u32 complete_mode;
__u64 dispatch_count[XDEV_EXT_BINDING_BACKEND_MAX];
__u64 complete_count[XDEV_EXT_BINDING_BACKEND_MAX];
__u64 nvme_read_dispatch_count;
__u64 nvme_write_dispatch_count;
__u64 nvme_read_complete_count;
__u64 nvme_write_complete_count;
__u64 observed_length;
__u64 observed_src_offset;
__u64 observed_logical_offset;
__u32 observed_recipe;
__s32 observed_result;
__u64 observed_bytes_done;
__u32 observed_dispatch_backend;
__u32 observed_dispatch_event;
__u32 observed_dispatch_stage;
__u32 observed_dispatch_direction;
__u32 observed_capabilities;
__u32 observed_complete_backend;
__u32 observed_complete_event;
__u32 observed_complete_stage;
__u32 observed_complete_direction;
__u32 observed_complete_recipe;
__u64 observed_complete_logical_offset;
__u32 dispatch_entered;
volatile __u32 dispatch_release;
__s32 fabricated_kfunc_ret;

static __always_inline __u32 recipe_for(const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	switch (binding_ctx->backend) {
	case XDEV_EXT_BINDING_BACKEND_SOCKET:
		return XDEV_EXT_BINDING_RECIPE_SOCKET_SEND;
	case XDEV_EXT_BINDING_BACKEND_AFXDP:
		if (binding_ctx->current_stage == XDEV_EXT_BINDING_STAGE_AFXDP_RX)
			return XDEV_EXT_BINDING_RECIPE_AFXDP_RX;
		return binding_ctx->allowed_recipe_mask &
		       xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX) ?
			XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX :
			XDEV_EXT_BINDING_RECIPE_AFXDP_COPY;
	case XDEV_EXT_BINDING_BACKEND_NVME:
		return binding_ctx->direction == XDEV_EXT_BINDING_DIRECTION_TO_DEVICE ?
			XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE :
			XDEV_EXT_BINDING_RECIPE_NVME_PT_READ;
	case XDEV_EXT_BINDING_BACKEND_IAA:
		return binding_ctx->current_stage == XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS ?
			XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS :
			XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS;
	case XDEV_EXT_BINDING_BACKEND_GPU:
		return XDEV_EXT_BINDING_RECIPE_GPU_COPY;
	default:
		return XDEV_EXT_BINDING_RECIPE_DEFAULT;
	}
}

static long wait_for_dispatch_release(__u32 index, void *opaque)
{
	(void)index;
	(void)opaque;
	return dispatch_release ? 1 : 0;
}

static __noinline int
dispatch_forged_ctx(const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	struct xdev_ext_binding_ctx_v2 forged = {};
	int ret;

	forged.abi_version = binding_ctx->abi_version;
	ret = bpf_xdev_ext_dispatch_action(&forged, XDEV_EXT_BINDING_ACTION_FALLBACK,
				      0, 0, 0);
	fabricated_kfunc_ret = ret;
	return ret;
}

static __noinline int
complete_forged_ctx(const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	struct xdev_ext_binding_ctx_v2 forged = {};
	int ret;

	forged.abi_version = binding_ctx->abi_version;
	ret = bpf_xdev_ext_complete_action(&forged, XDEV_EXT_BINDING_ACTION_FALLBACK,
				      0, 0, 0);
	fabricated_kfunc_ret = ret;
	return ret;
}

SEC("struct_ops/dispatch")
__s32 BPF_PROG(dispatch_success, const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	__u32 mode = dispatch_mode;
	int ret;

	observed_length = binding_ctx->length;
	observed_src_offset = binding_ctx->src_offset;
	observed_logical_offset = binding_ctx->logical_offset;
	observed_recipe = recipe_for(binding_ctx);
	observed_dispatch_backend = binding_ctx->backend;
	observed_dispatch_event = binding_ctx->event;
	observed_dispatch_stage = binding_ctx->current_stage;
	observed_dispatch_direction = binding_ctx->direction;
	observed_capabilities = binding_ctx->capabilities;
	if (binding_ctx->backend < XDEV_EXT_BINDING_BACKEND_MAX)
		__sync_fetch_and_add(&dispatch_count[binding_ctx->backend], 1);
	if (binding_ctx->backend == XDEV_EXT_BINDING_BACKEND_NVME) {
		if (binding_ctx->direction == XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE)
			__sync_fetch_and_add(&nvme_read_dispatch_count, 1);
		else if (binding_ctx->direction == XDEV_EXT_BINDING_DIRECTION_TO_DEVICE)
			__sync_fetch_and_add(&nvme_write_dispatch_count, 1);
	}

	if (mode == XDEV_EXT_BINDING_SUCCESS_ZERO_CALLS)
		return 0;
	if (mode == XDEV_EXT_BINDING_SUCCESS_FORGED_CTX)
		return dispatch_forged_ctx(binding_ctx);
	if (mode == XDEV_EXT_BINDING_SUCCESS_FOREIGN_THEN_VALID) {
		dispatch_forged_ctx(binding_ctx);
		return bpf_xdev_ext_dispatch_action(binding_ctx,
					       XDEV_EXT_BINDING_ACTION_FALLBACK,
					       0, 0, 0);
	}
	if (mode == XDEV_EXT_BINDING_SUCCESS_VALID_THEN_FOREIGN) {
		ret = bpf_xdev_ext_dispatch_action(binding_ctx,
					      XDEV_EXT_BINDING_ACTION_FALLBACK,
					      0, 0, 0);
		dispatch_forged_ctx(binding_ctx);
		return ret;
	}
	if (mode == XDEV_EXT_BINDING_SUCCESS_USE_PLAN)
		ret = bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_USE_PLAN,
					      recipe_for(binding_ctx),
					      XDEV_EXT_BINDING_STAGE_COMPLETE,
					      XDEV_EXT_BINDING_PROFILE_NATIVE);
	else if (mode == XDEV_EXT_BINDING_SUCCESS_TERMINAL)
		ret = bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_TERMINAL,
					      0, 0, 0);
	else if (mode == XDEV_EXT_BINDING_SUCCESS_INVALID_PLAN)
		ret = bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_USE_PLAN,
					      XDEV_EXT_BINDING_RECIPE_FILE_READ,
					      XDEV_EXT_BINDING_STAGE_COMPLETE,
					      XDEV_EXT_BINDING_PROFILE_NATIVE);
	else
		ret = bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
					      0, 0, 0);
	if (mode == XDEV_EXT_BINDING_SUCCESS_HOLD_DISPATCH) {
		dispatch_entered = 1;
		bpf_loop(1U << 23, wait_for_dispatch_release, NULL, 0);
	}
	if (mode == XDEV_EXT_BINDING_SUCCESS_DUPLICATE_CALLS)
		return bpf_xdev_ext_dispatch_action(binding_ctx,
					       XDEV_EXT_BINDING_ACTION_FALLBACK,
					       0, 0, 0);

	return mode == XDEV_EXT_BINDING_SUCCESS_RETURN_MISMATCH ? ret - 1 : ret;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(complete_success, const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	__u32 mode = complete_mode;
	int ret;

	observed_result = binding_ctx->result;
	observed_bytes_done = binding_ctx->bytes_done;
	observed_complete_backend = binding_ctx->backend;
	observed_complete_event = binding_ctx->event;
	observed_complete_stage = binding_ctx->current_stage;
	observed_complete_direction = binding_ctx->direction;
	observed_complete_recipe = recipe_for(binding_ctx);
	observed_complete_logical_offset = binding_ctx->logical_offset;
	if (binding_ctx->backend < XDEV_EXT_BINDING_BACKEND_MAX)
		__sync_fetch_and_add(&complete_count[binding_ctx->backend], 1);
	if (binding_ctx->backend == XDEV_EXT_BINDING_BACKEND_NVME) {
		if (binding_ctx->direction == XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE)
			__sync_fetch_and_add(&nvme_read_complete_count, 1);
		else if (binding_ctx->direction == XDEV_EXT_BINDING_DIRECTION_TO_DEVICE)
			__sync_fetch_and_add(&nvme_write_complete_count, 1);
	}

	if (mode == XDEV_EXT_BINDING_SUCCESS_ZERO_CALLS)
		return 0;
	if (mode == XDEV_EXT_BINDING_SUCCESS_FORGED_CTX)
		return complete_forged_ctx(binding_ctx);
	if (mode == XDEV_EXT_BINDING_SUCCESS_FOREIGN_THEN_VALID) {
		complete_forged_ctx(binding_ctx);
		return bpf_xdev_ext_complete_action(binding_ctx,
					       XDEV_EXT_BINDING_ACTION_FALLBACK,
					       0, 0, 0);
	}
	if (mode == XDEV_EXT_BINDING_SUCCESS_VALID_THEN_FOREIGN) {
		ret = bpf_xdev_ext_complete_action(binding_ctx,
					      XDEV_EXT_BINDING_ACTION_FALLBACK,
					      0, 0, 0);
		complete_forged_ctx(binding_ctx);
		return ret;
	}
	if (mode == XDEV_EXT_BINDING_SUCCESS_USE_PLAN)
		ret = bpf_xdev_ext_complete_action(binding_ctx, XDEV_EXT_BINDING_ACTION_USE_PLAN,
					      recipe_for(binding_ctx),
					      XDEV_EXT_BINDING_STAGE_COMPLETE,
					      XDEV_EXT_BINDING_PROFILE_NATIVE);
	else if (mode == XDEV_EXT_BINDING_SUCCESS_TERMINAL)
		ret = bpf_xdev_ext_complete_action(binding_ctx, XDEV_EXT_BINDING_ACTION_TERMINAL,
					      0, 0, 0);
	else if (mode == XDEV_EXT_BINDING_SUCCESS_INVALID_PLAN)
		ret = bpf_xdev_ext_complete_action(binding_ctx, XDEV_EXT_BINDING_ACTION_USE_PLAN,
					      XDEV_EXT_BINDING_RECIPE_FILE_READ,
					      XDEV_EXT_BINDING_STAGE_COMPLETE,
					      XDEV_EXT_BINDING_PROFILE_NATIVE);
	else
		ret = bpf_xdev_ext_complete_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
					      0, 0, 0);
	if (mode == XDEV_EXT_BINDING_SUCCESS_DUPLICATE_CALLS)
		return bpf_xdev_ext_complete_action(binding_ctx,
					       XDEV_EXT_BINDING_ACTION_FALLBACK,
					       0, 0, 0);

	return mode == XDEV_EXT_BINDING_SUCCESS_RETURN_MISMATCH ? ret - 1 : ret;
}

#define XDEV_EXT_POLICY_FLAGS(name, backend_id, policy_flags) \
	SEC(".struct_ops.link") \
	struct xdev_ext_binding_ops name = { \
		.abi_version = XDEV_EXT_BINDING_ABI_VERSION, \
		.backend = (backend_id), \
		.flags = (policy_flags), \
		.dispatch = (void *)dispatch_success, \
		.complete = (void *)complete_success, \
	}

#define XDEV_EXT_POLICY(name, backend_id) XDEV_EXT_POLICY_FLAGS(name, backend_id, 0)

XDEV_EXT_POLICY(socket_policy, XDEV_EXT_BINDING_BACKEND_SOCKET);
XDEV_EXT_POLICY(afxdp_policy, XDEV_EXT_BINDING_BACKEND_AFXDP);
XDEV_EXT_POLICY_FLAGS(afxdp_rx_policy, XDEV_EXT_BINDING_BACKEND_AFXDP,
		 XDEV_EXT_BINDING_OPS_F_AFXDP_RX);
XDEV_EXT_POLICY(nvme_policy, XDEV_EXT_BINDING_BACKEND_NVME);
XDEV_EXT_POLICY(iaa_policy, XDEV_EXT_BINDING_BACKEND_IAA);
XDEV_EXT_POLICY(gpu_policy, XDEV_EXT_BINDING_BACKEND_GPU);
XDEV_EXT_POLICY(duplicate_socket_policy, XDEV_EXT_BINDING_BACKEND_SOCKET);

char _license[] SEC("license") = "GPL";
