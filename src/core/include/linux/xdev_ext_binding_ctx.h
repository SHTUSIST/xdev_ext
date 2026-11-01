/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_BINDING_CTX_H
#define _LINUX_XDEV_EXT_BINDING_CTX_H

/* Pure context constructors, also consumed by C++ class declarations. */
#ifdef __KERNEL__
#include <uapi/linux/xdev_ext_binding.h>
#else
#include "../uapi/linux/xdev_ext_binding.h"
#endif

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

#endif /* _LINUX_XDEV_EXT_BINDING_CTX_H */
