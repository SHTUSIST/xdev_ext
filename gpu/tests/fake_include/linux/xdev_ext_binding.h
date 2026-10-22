/* SPDX-License-Identifier: MIT */
#ifndef _FAKE_LINUX_XDEV_EXT_BINDING_H_
#define _FAKE_LINUX_XDEV_EXT_BINDING_H_

#include <stdint.h>

/* Standalone snapshot of the public XDEV_EXT v2 scalar ABI. */
#define XDEV_EXT_BINDING_ABI_VERSION 2U

enum xdev_ext_binding_event {
	XDEV_EXT_BINDING_EVENT_UNSPEC = 0,
	XDEV_EXT_BINDING_EVENT_DISPATCH = 1,
	XDEV_EXT_BINDING_EVENT_COMPLETE = 2,
	XDEV_EXT_BINDING_EVENT_MAX,
};

enum xdev_ext_binding_backend {
	XDEV_EXT_BINDING_BACKEND_UNSPEC = 0,
	XDEV_EXT_BINDING_BACKEND_SOCKET = 1,
	XDEV_EXT_BINDING_BACKEND_AFXDP = 2,
	XDEV_EXT_BINDING_BACKEND_NVME = 3,
	XDEV_EXT_BINDING_BACKEND_IAA = 4,
	XDEV_EXT_BINDING_BACKEND_GPU = 5,
	XDEV_EXT_BINDING_BACKEND_MAX,
};

enum xdev_ext_binding_direction {
	XDEV_EXT_BINDING_DIRECTION_UNSPEC = 0,
	XDEV_EXT_BINDING_DIRECTION_TO_DEVICE = 1,
	XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE = 2,
	XDEV_EXT_BINDING_DIRECTION_INTERNAL = 3,
	XDEV_EXT_BINDING_DIRECTION_MAX,
};

enum xdev_ext_binding_recipe {
	XDEV_EXT_BINDING_RECIPE_DEFAULT = 0,
	XDEV_EXT_BINDING_RECIPE_FILE_READ = 1,
	XDEV_EXT_BINDING_RECIPE_FILE_WRITE = 2,
	XDEV_EXT_BINDING_RECIPE_SOCKET_SEND = 3,
	XDEV_EXT_BINDING_RECIPE_AFXDP_COPY = 4,
	XDEV_EXT_BINDING_RECIPE_CPU_CALC = 5,
	XDEV_EXT_BINDING_RECIPE_GPU_COPY = 6,
	XDEV_EXT_BINDING_RECIPE_COMPLETE = 7,
	XDEV_EXT_BINDING_RECIPE_NVME_PT_READ = 8,
	XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE = 9,
	XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS = 10,
	XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS = 11,
	XDEV_EXT_BINDING_RECIPE_MAX,
};

enum xdev_ext_binding_stage {
	XDEV_EXT_BINDING_STAGE_NONE = 0,
	XDEV_EXT_BINDING_STAGE_FILE_READ = 1,
	XDEV_EXT_BINDING_STAGE_CPU_CALC = 2,
	XDEV_EXT_BINDING_STAGE_GPU_COPY = 3,
	XDEV_EXT_BINDING_STAGE_SEND = 4,
	XDEV_EXT_BINDING_STAGE_FILE_WRITE = 5,
	XDEV_EXT_BINDING_STAGE_COMPLETE = 6,
	XDEV_EXT_BINDING_STAGE_NVME_READ = 7,
	XDEV_EXT_BINDING_STAGE_NVME_WRITE = 8,
	XDEV_EXT_BINDING_STAGE_AFXDP_TX = 9,
	XDEV_EXT_BINDING_STAGE_IAA_COMPRESS = 10,
	XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS = 11,
	XDEV_EXT_BINDING_STAGE_MAX,
};

enum xdev_ext_binding_action {
	XDEV_EXT_BINDING_ACTION_FALLBACK = 0,
	XDEV_EXT_BINDING_ACTION_USE_PLAN = 1,
	XDEV_EXT_BINDING_ACTION_TERMINAL = 2,
	XDEV_EXT_BINDING_ACTION_MAX,
};

enum xdev_ext_binding_profile {
	XDEV_EXT_BINDING_PROFILE_NONE = 0,
	XDEV_EXT_BINDING_PROFILE_NATIVE = 1,
	XDEV_EXT_BINDING_PROFILE_MAX,
};

enum xdev_ext_binding_frame_state {
	XDEV_EXT_BINDING_FRAME_UNTRACKED = 0,
};

#define XDEV_EXT_BINDING_CAP_ASYNC (1U << 0)
#define XDEV_EXT_BINDING_CAP_POLL (1U << 1)
#define XDEV_EXT_BINDING_CAP_FIXED_FILE (1U << 2)
#define XDEV_EXT_BINDING_CAP_FIXED_BUFFER (1U << 3)
#define XDEV_EXT_BINDING_CAP_ZERO_COPY (1U << 4)

static inline uint32_t xdev_ext_binding_recipe_bit(uint32_t recipe)
{
	return recipe < 32U ? 1U << recipe : 0U;
}

static inline uint32_t xdev_ext_binding_stage_bit(uint32_t stage)
{
	return stage < 32U ? 1U << stage : 0U;
}

static inline uint32_t xdev_ext_binding_profile_bit(uint32_t profile)
{
	return profile < 32U ? 1U << profile : 0U;
}

#define XDEV_EXT_BINDING_KNOWN_RECIPE_MASK 0x00000ffeU
#define XDEV_EXT_BINDING_KNOWN_STAGE_MASK 0x00000ffeU
#define XDEV_EXT_BINDING_KNOWN_PROFILE_MASK 0x00000002U
#define XDEV_EXT_BINDING_KNOWN_CAPABILITY_MASK 0x0000001fU

typedef uint64_t xdev_ext_binding_aligned_u64 __attribute__((aligned(8)));

struct xdev_ext_binding_ctx_v2 {
	uint32_t abi_version;
	uint32_t ctx_size;
	uint32_t event;
	uint32_t backend;

	uint32_t current_stage;
	uint32_t direction;
	uint32_t frame_state;
	uint32_t capabilities;

	uint32_t allowed_recipe_mask;
	uint32_t allowed_next_mask;
	uint32_t allowed_profile_mask;
	uint32_t reserved0;

	xdev_ext_binding_aligned_u64 request_id;
	xdev_ext_binding_aligned_u64 chain_id;
	xdev_ext_binding_aligned_u64 endpoint_id;
	xdev_ext_binding_aligned_u64 src_buffer_id;
	xdev_ext_binding_aligned_u64 dst_buffer_id;
	xdev_ext_binding_aligned_u64 src_offset;
	xdev_ext_binding_aligned_u64 dst_offset;
	xdev_ext_binding_aligned_u64 logical_offset;
	xdev_ext_binding_aligned_u64 length;
	xdev_ext_binding_aligned_u64 bytes_done;

	int32_t result;
	uint32_t reserved1;
};

struct xdev_ext_binding_token {
	const void *private;
};

struct xdev_ext_binding_plan {
	uint32_t action;
	uint32_t recipe;
	uint32_t next_stage;
	uint32_t profile;
};

static inline struct xdev_ext_binding_ctx_v2
xdev_ext_binding_make_base_ctx(uint32_t backend, uint32_t stage,
			  uint32_t direction, uint32_t recipe,
			  uint64_t length)
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
xdev_ext_binding_make_gpu_ctx(uint32_t direction, uint64_t src_offset,
			 uint64_t dst_offset, uint64_t length)
{
	struct xdev_ext_binding_ctx_v2 ctx =
		xdev_ext_binding_make_base_ctx(XDEV_EXT_BINDING_BACKEND_GPU,
					  XDEV_EXT_BINDING_STAGE_GPU_COPY, direction,
					  XDEV_EXT_BINDING_RECIPE_GPU_COPY, length);

	ctx.src_offset = src_offset;
	ctx.dst_offset = dst_offset;
	return ctx;
}

int xdev_ext_binding_dispatch(const struct xdev_ext_binding_ctx_v2 *ctx,
			 struct xdev_ext_binding_token *token,
			 struct xdev_ext_binding_plan *plan);
int xdev_ext_binding_complete(const struct xdev_ext_binding_ctx_v2 *ctx,
			 struct xdev_ext_binding_token *token,
			 struct xdev_ext_binding_plan *plan);
void xdev_ext_binding_token_put(struct xdev_ext_binding_token *token);

#endif /* _FAKE_LINUX_XDEV_EXT_BINDING_H_ */
