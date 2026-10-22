/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_BINDING_H
#define _LINUX_XDEV_EXT_BINDING_H

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/xdev_ext_binding.h>
#else
#include <errno.h>
#include "../uapi/linux/xdev_ext_binding.h"
#endif

/* One independently attachable policy instance is registered per backend. */
struct xdev_ext_binding_ops {
	__u32 abi_version;
	__u32 backend;
	__u32 flags;
	__u32 reserved;
	__s32 (*dispatch)(const struct xdev_ext_binding_ctx_v2 *ctx);
	__s32 (*complete)(const struct xdev_ext_binding_ctx_v2 *ctx);
};

/* C-private result recorded by one phase-matched XDEV_EXT kfunc call. */
struct xdev_ext_binding_plan {
	__u32 action;
	__u32 recipe;
	__u32 next_stage;
	__u32 profile;
};

/*
 * BPF never observes this value.  While non-NULL it pins the exact
 * struct_ops generation selected at dispatch until completion or unwind.
 */
struct xdev_ext_binding_token {
	const void *private;
};

struct xdev_ext_binding_normalized_result {
	__s32 result;
	__u64 bytes_done;
};

#define XDEV_EXT_BINDING_LINUX_ERRNO_MAX	4095

static inline int xdev_ext_binding_event_known(__u32 event)
{
	return event > XDEV_EXT_BINDING_EVENT_UNSPEC &&
	       event < XDEV_EXT_BINDING_EVENT_MAX;
}

static inline int xdev_ext_binding_backend_known(__u32 backend)
{
	return backend > XDEV_EXT_BINDING_BACKEND_UNSPEC &&
	       backend < XDEV_EXT_BINDING_BACKEND_MAX;
}

static inline int xdev_ext_binding_direction_known(__u32 direction)
{
	return direction > XDEV_EXT_BINDING_DIRECTION_UNSPEC &&
	       direction < XDEV_EXT_BINDING_DIRECTION_MAX;
}

static inline int xdev_ext_binding_recipe_known(__u32 recipe)
{
	return recipe > XDEV_EXT_BINDING_RECIPE_DEFAULT &&
	       recipe < XDEV_EXT_BINDING_RECIPE_MAX;
}

static inline int xdev_ext_binding_stage_known(__u32 stage)
{
	return stage > XDEV_EXT_BINDING_STAGE_NONE &&
	       stage < XDEV_EXT_BINDING_STAGE_MAX;
}

static inline int xdev_ext_binding_profile_known(__u32 profile)
{
	return profile > XDEV_EXT_BINDING_PROFILE_NONE &&
	       profile < XDEV_EXT_BINDING_PROFILE_MAX;
}

static inline int xdev_ext_binding_action_known(__u32 action)
{
	return action < XDEV_EXT_BINDING_ACTION_MAX;
}

static inline __u32 xdev_ext_binding_backend_recipe_mask(__u32 backend)
{
	switch (backend) {
	case XDEV_EXT_BINDING_BACKEND_SOCKET:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND);
	case XDEV_EXT_BINDING_BACKEND_AFXDP:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_COPY) |
		       xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX) |
		       xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_RX);
	case XDEV_EXT_BINDING_BACKEND_NVME:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_READ) |
		       xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE);
	case XDEV_EXT_BINDING_BACKEND_IAA:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS) |
		       xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS);
	case XDEV_EXT_BINDING_BACKEND_GPU:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_GPU_COPY);
	default:
		return 0;
	}
}

static inline int
xdev_ext_binding_backend_allows_recipe(__u32 backend, __u32 recipe)
{
	return xdev_ext_binding_recipe_known(recipe) &&
	       !!(xdev_ext_binding_backend_recipe_mask(backend) &
		  xdev_ext_binding_recipe_bit(recipe));
}

static inline __u32 xdev_ext_binding_stage_recipe_mask(__u32 stage)
{
	switch (stage) {
	case XDEV_EXT_BINDING_STAGE_FILE_READ:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_FILE_READ);
	case XDEV_EXT_BINDING_STAGE_CPU_CALC:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_CPU_CALC);
	case XDEV_EXT_BINDING_STAGE_GPU_COPY:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_GPU_COPY);
	case XDEV_EXT_BINDING_STAGE_SEND:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_SOCKET_SEND);
	case XDEV_EXT_BINDING_STAGE_FILE_WRITE:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_FILE_WRITE);
	case XDEV_EXT_BINDING_STAGE_COMPLETE:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_COMPLETE);
	case XDEV_EXT_BINDING_STAGE_NVME_READ:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_READ);
	case XDEV_EXT_BINDING_STAGE_NVME_WRITE:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE);
	case XDEV_EXT_BINDING_STAGE_AFXDP_TX:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_COPY) |
		       xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX);
	case XDEV_EXT_BINDING_STAGE_IAA_COMPRESS:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS);
	case XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS);
	case XDEV_EXT_BINDING_STAGE_AFXDP_RX:
		return xdev_ext_binding_recipe_bit(XDEV_EXT_BINDING_RECIPE_AFXDP_RX);
	default:
		return 0;
	}
}

static inline int
xdev_ext_binding_stage_allows_recipe(__u32 stage, __u32 recipe)
{
	return xdev_ext_binding_recipe_known(recipe) &&
	       !!(xdev_ext_binding_stage_recipe_mask(stage) &
		  xdev_ext_binding_recipe_bit(recipe));
}

/* A backend's stage and direction form one immutable classification. */
static inline int
xdev_ext_binding_backend_stage_direction_valid(const struct xdev_ext_binding_ctx_v2 *ctx)
{
	switch (ctx->backend) {
	case XDEV_EXT_BINDING_BACKEND_SOCKET:
		return ctx->current_stage == XDEV_EXT_BINDING_STAGE_SEND &&
		       ctx->direction == XDEV_EXT_BINDING_DIRECTION_TO_DEVICE;
	case XDEV_EXT_BINDING_BACKEND_AFXDP:
		return (ctx->current_stage == XDEV_EXT_BINDING_STAGE_AFXDP_TX &&
			ctx->direction == XDEV_EXT_BINDING_DIRECTION_TO_DEVICE) ||
		       (ctx->current_stage == XDEV_EXT_BINDING_STAGE_AFXDP_RX &&
			ctx->direction == XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE);
	case XDEV_EXT_BINDING_BACKEND_NVME:
		return (ctx->current_stage == XDEV_EXT_BINDING_STAGE_NVME_READ &&
			ctx->direction == XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE) ||
		       (ctx->current_stage == XDEV_EXT_BINDING_STAGE_NVME_WRITE &&
			ctx->direction == XDEV_EXT_BINDING_DIRECTION_TO_DEVICE);
	case XDEV_EXT_BINDING_BACKEND_IAA:
		return (ctx->current_stage == XDEV_EXT_BINDING_STAGE_IAA_COMPRESS ||
			ctx->current_stage == XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS) &&
		       ctx->direction == XDEV_EXT_BINDING_DIRECTION_INTERNAL;
	case XDEV_EXT_BINDING_BACKEND_GPU:
		return ctx->current_stage == XDEV_EXT_BINDING_STAGE_GPU_COPY &&
		       (ctx->direction == XDEV_EXT_BINDING_DIRECTION_TO_DEVICE ||
			ctx->direction == XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE);
	default:
		return 0;
	}
}

static inline int xdev_ext_binding_ops_flags_valid(__u32 backend, __u32 flags)
{
	if (!xdev_ext_binding_backend_known(backend) ||
	    (flags & ~XDEV_EXT_BINDING_KNOWN_OPS_FLAG_MASK))
		return 0;
	if (flags && backend != XDEV_EXT_BINDING_BACKEND_AFXDP)
		return 0;
	return 1;
}

static inline int
xdev_ext_binding_ops_accepts_ctx(__u32 backend, __u32 flags,
			    const struct xdev_ext_binding_ctx_v2 *ctx)
{
	if (!ctx || ctx->backend != backend ||
	    !xdev_ext_binding_ops_flags_valid(backend, flags))
		return 0;
	if (ctx->backend == XDEV_EXT_BINDING_BACKEND_AFXDP &&
	    ctx->current_stage == XDEV_EXT_BINDING_STAGE_AFXDP_RX)
		return !!(flags & XDEV_EXT_BINDING_OPS_F_AFXDP_RX);
	return 1;
}

/* Overflow-safe containment test for a [offset, offset + length) window. */
static inline int xdev_ext_binding_window_valid(__u64 offset, __u64 length,
					   __u64 capacity)
{
	return offset <= capacity && length <= capacity - offset;
}

/*
 * Normalize a native byte-returning API without modifying its native result
 * storage.  Callers copy the returned fields into the public completion view.
 */
static inline struct xdev_ext_binding_normalized_result
xdev_ext_binding_normalize_byte_result(__s64 native_result)
{
	struct xdev_ext_binding_normalized_result normalized = {};

	if (native_result >= 0)
		normalized.bytes_done = native_result;
	else if (native_result >= -XDEV_EXT_BINDING_LINUX_ERRNO_MAX)
		normalized.result = native_result;
	else
		normalized.result = -EIO;

	return normalized;
}

/*
 * Normalize an all-or-nothing status API.  A positive device status is not a
 * Linux errno; expose -EIO while the caller retains the native status itself.
 */
static inline struct xdev_ext_binding_normalized_result
xdev_ext_binding_normalize_status_result(__s64 native_status, __u64 success_bytes)
{
	struct xdev_ext_binding_normalized_result normalized = {};

	if (!native_status) {
		normalized.bytes_done = success_bytes;
	} else if (native_status < 0 &&
		   native_status >= -XDEV_EXT_BINDING_LINUX_ERRNO_MAX) {
		normalized.result = native_status;
	} else {
		normalized.result = -EIO;
	}

	return normalized;
}

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_base_ctx(__u32 backend, __u32 stage, __u32 direction,
			  __u32 recipe, __u64 length)
{
	struct xdev_ext_binding_ctx_v2 ctx = {
		.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
		.ctx_size = sizeof(struct xdev_ext_binding_ctx_v2),
		.event = XDEV_EXT_BINDING_EVENT_DISPATCH,
		.backend = backend,
		.current_stage = stage,
		.direction = direction,
		.frame_state = XDEV_EXT_BINDING_FRAME_UNTRACKED,
		.allowed_recipe_mask = xdev_ext_binding_recipe_bit(recipe),
		.allowed_next_mask =
			xdev_ext_binding_stage_bit(XDEV_EXT_BINDING_STAGE_COMPLETE),
		.allowed_profile_mask =
			xdev_ext_binding_profile_bit(XDEV_EXT_BINDING_PROFILE_NATIVE),
		.length = length,
	};

	return ctx;
}

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_socket_send_ctx(__u64 length)
{
	return xdev_ext_binding_make_base_ctx(XDEV_EXT_BINDING_BACKEND_SOCKET,
					 XDEV_EXT_BINDING_STAGE_SEND,
					 XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
					 XDEV_EXT_BINDING_RECIPE_SOCKET_SEND,
					 length);
}

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_afxdp_tx_ctx(__u64 length)
{
	return xdev_ext_binding_make_base_ctx(XDEV_EXT_BINDING_BACKEND_AFXDP,
					 XDEV_EXT_BINDING_STAGE_AFXDP_TX,
					 XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
					 XDEV_EXT_BINDING_RECIPE_AFXDP_COPY,
					 length);
}

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_afxdp_native_tx_ctx(__u64 src_offset, __u64 length,
				     __u32 capabilities)
{
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_base_ctx(XDEV_EXT_BINDING_BACKEND_AFXDP,
					  XDEV_EXT_BINDING_STAGE_AFXDP_TX,
					  XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
					  XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX,
					  length);

	ctx.src_offset = src_offset;
	ctx.capabilities = capabilities;
	return ctx;
}

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_afxdp_rx_ctx(__u64 dst_offset, __u64 length,
			      __u32 capabilities)
{
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_base_ctx(XDEV_EXT_BINDING_BACKEND_AFXDP,
					  XDEV_EXT_BINDING_STAGE_AFXDP_RX,
					  XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
					  XDEV_EXT_BINDING_RECIPE_AFXDP_RX,
					  length);

	ctx.dst_offset = dst_offset;
	ctx.capabilities = capabilities;
	return ctx;
}

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_nvme_ctx(int write, __u64 logical_offset, __u64 length)
{
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_base_ctx(XDEV_EXT_BINDING_BACKEND_NVME,
					  write ? XDEV_EXT_BINDING_STAGE_NVME_WRITE :
						  XDEV_EXT_BINDING_STAGE_NVME_READ,
					  write ? XDEV_EXT_BINDING_DIRECTION_TO_DEVICE :
						  XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
					  write ? XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE :
						  XDEV_EXT_BINDING_RECIPE_NVME_PT_READ,
					  length);

	ctx.logical_offset = logical_offset;
	return ctx;
}

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_iaa_ctx(int decompress, __u64 src_offset,
			 __u64 dst_offset, __u64 length)
{
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_base_ctx(XDEV_EXT_BINDING_BACKEND_IAA,
					  decompress ?
						  XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS :
						  XDEV_EXT_BINDING_STAGE_IAA_COMPRESS,
					  XDEV_EXT_BINDING_DIRECTION_INTERNAL,
					  decompress ?
						  XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS :
						  XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS,
					  length);

	ctx.src_offset = src_offset;
	ctx.dst_offset = dst_offset;
	return ctx;
}

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_gpu_ctx(__u32 direction, __u64 src_offset,
			 __u64 dst_offset, __u64 length)
{
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_base_ctx(XDEV_EXT_BINDING_BACKEND_GPU,
					  XDEV_EXT_BINDING_STAGE_GPU_COPY, direction,
					  XDEV_EXT_BINDING_RECIPE_GPU_COPY, length);

	ctx.src_offset = src_offset;
	ctx.dst_offset = dst_offset;
	return ctx;
}

static inline int
xdev_ext_binding_validate_ctx(const struct xdev_ext_binding_ctx_v2 *ctx)
{
	if (!ctx)
		return -EINVAL;
	if (ctx->abi_version != XDEV_EXT_BINDING_ABI_VERSION ||
	    ctx->ctx_size != sizeof(*ctx))
		return -EPROTO;
	if (!xdev_ext_binding_event_known(ctx->event) ||
	    !xdev_ext_binding_backend_known(ctx->backend) ||
	    !xdev_ext_binding_direction_known(ctx->direction) ||
	    !xdev_ext_binding_stage_known(ctx->current_stage))
		return -EINVAL;
	if (!xdev_ext_binding_backend_stage_direction_valid(ctx))
		return -EINVAL;
	if (ctx->frame_state != XDEV_EXT_BINDING_FRAME_UNTRACKED ||
	    ctx->reserved0 || ctx->reserved1 ||
	    (ctx->capabilities & ~XDEV_EXT_BINDING_KNOWN_CAPABILITY_MASK) ||
	    (ctx->allowed_recipe_mask & ~XDEV_EXT_BINDING_KNOWN_RECIPE_MASK) ||
	    (ctx->allowed_next_mask & ~XDEV_EXT_BINDING_KNOWN_STAGE_MASK) ||
	    (ctx->allowed_profile_mask & ~XDEV_EXT_BINDING_KNOWN_PROFILE_MASK))
		return -EINVAL;
	if (ctx->allowed_recipe_mask &
	    ~xdev_ext_binding_backend_recipe_mask(ctx->backend))
		return -EINVAL;
	if (ctx->allowed_recipe_mask &
	    ~xdev_ext_binding_stage_recipe_mask(ctx->current_stage))
		return -EINVAL;
	if (ctx->event == XDEV_EXT_BINDING_EVENT_DISPATCH &&
	    (ctx->result || ctx->bytes_done))
		return -EINVAL;
	if (ctx->event == XDEV_EXT_BINDING_EVENT_COMPLETE &&
	    (ctx->result > 0 ||
	     ctx->result < -XDEV_EXT_BINDING_LINUX_ERRNO_MAX ||
	     (ctx->result < 0 && ctx->bytes_done)))
		return -EINVAL;
	return 0;
}

static inline int
xdev_ext_binding_validate_plan(const struct xdev_ext_binding_ctx_v2 *ctx,
			  const struct xdev_ext_binding_plan *plan)
{
	int ret;

	if (!plan)
		return -EINVAL;
	ret = xdev_ext_binding_validate_ctx(ctx);
	if (ret)
		return ret;
	if (!xdev_ext_binding_action_known(plan->action))
		return -EINVAL;

	if (plan->action != XDEV_EXT_BINDING_ACTION_USE_PLAN)
		return plan->recipe || plan->next_stage || plan->profile ?
		       -EINVAL : 0;

	if (!xdev_ext_binding_recipe_known(plan->recipe) ||
	    !xdev_ext_binding_stage_known(plan->next_stage) ||
	    !xdev_ext_binding_profile_known(plan->profile))
		return -EINVAL;
	if (!(ctx->allowed_recipe_mask &
	      xdev_ext_binding_recipe_bit(plan->recipe)) ||
	    !(ctx->allowed_next_mask &
	      xdev_ext_binding_stage_bit(plan->next_stage)) ||
	    !(ctx->allowed_profile_mask &
	      xdev_ext_binding_profile_bit(plan->profile)))
		return -EPERM;
	if (!xdev_ext_binding_backend_allows_recipe(ctx->backend, plan->recipe))
		return -EPERM;
	if (!xdev_ext_binding_stage_allows_recipe(ctx->current_stage, plan->recipe))
		return -EPERM;
	if (ctx->current_stage == plan->next_stage)
		return -ELOOP;
	if (ctx->event == XDEV_EXT_BINDING_EVENT_COMPLETE && ctx->result < 0)
		return -EPERM;
	return 0;
}

#ifdef __KERNEL__
#ifdef CONFIG_IO_URING_XDEV_EXT_BPF_POLICY
#include <linux/jump_label.h>

DECLARE_STATIC_KEY_FALSE(xdev_ext_binding_policy_key);

static __always_inline bool xdev_ext_binding_policy_active(void)
{
	return static_branch_unlikely(&xdev_ext_binding_policy_key);
}

/*
 * Dispatch initializes a non-NULL plan before any validation.  The caller
 * must serialize operations on a token and pass a zero-initialized, empty
 * token for each request.  A live token returns -EBUSY without changing its
 * ownership.  The plan is initialized on every call; an empty token remains
 * empty unless a plugin generation is accepted.  No plugin yields FALLBACK
 * and an empty token.  A successful plugin FALLBACK or USE_PLAN leaves a live
 * token for the same generation; TERMINAL and every error return an empty
 * token.
 *
 * Complete initializes a non-NULL plan and atomically consumes a live token
 * before validating the remaining arguments, including plan and ctx.  An
 * empty token is a valid no-plugin no-op.  token_put() is the idempotent
 * pre-submit unwind operation and is also safe after complete has cleared the
 * token.
 */
int xdev_ext_binding_dispatch(const struct xdev_ext_binding_ctx_v2 *ctx,
			 struct xdev_ext_binding_token *token,
			 struct xdev_ext_binding_plan *plan);
int xdev_ext_binding_complete(const struct xdev_ext_binding_ctx_v2 *ctx,
			 struct xdev_ext_binding_token *token,
			 struct xdev_ext_binding_plan *plan);
void xdev_ext_binding_token_put(struct xdev_ext_binding_token *token);
#else
static __always_inline bool xdev_ext_binding_policy_active(void)
{
	return false;
}

static inline int
xdev_ext_binding_dispatch(const struct xdev_ext_binding_ctx_v2 *ctx,
		     struct xdev_ext_binding_token *token,
		     struct xdev_ext_binding_plan *plan)
{
	int ret;

	if (plan)
		*plan = (struct xdev_ext_binding_plan) {
			.action = XDEV_EXT_BINDING_ACTION_FALLBACK,
		};
	if (!token)
		return -EINVAL;
	if (token->private)
		return -EBUSY;
	if (!plan)
		return -EINVAL;
	ret = xdev_ext_binding_validate_ctx(ctx);
	if (ret)
		return ret;
	return ctx->event == XDEV_EXT_BINDING_EVENT_DISPATCH ? 0 : -EINVAL;
}

static inline int
xdev_ext_binding_complete(const struct xdev_ext_binding_ctx_v2 *ctx,
		     struct xdev_ext_binding_token *token,
		     struct xdev_ext_binding_plan *plan)
{
	int ret;

	if (plan)
		*plan = (struct xdev_ext_binding_plan) {
			.action = XDEV_EXT_BINDING_ACTION_FALLBACK,
		};
	if (!token)
		return -EINVAL;
	token->private = NULL;
	if (!plan)
		return -EINVAL;
	ret = xdev_ext_binding_validate_ctx(ctx);
	if (ret)
		return ret;
	return ctx->event == XDEV_EXT_BINDING_EVENT_COMPLETE ? 0 : -EINVAL;
}

static inline void xdev_ext_binding_token_put(struct xdev_ext_binding_token *token)
{
	if (token)
		token->private = NULL;
}
#endif /* CONFIG_IO_URING_XDEV_EXT_BPF_POLICY */
#endif /* __KERNEL__ */

#endif /* _LINUX_XDEV_EXT_BINDING_H */
