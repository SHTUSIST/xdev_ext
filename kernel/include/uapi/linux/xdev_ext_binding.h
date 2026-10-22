/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_XDEV_EXT_BINDING_H
#define _UAPI_LINUX_XDEV_EXT_BINDING_H

#include <linux/types.h>

/* v2 replaces the scalar-return v1 callback contract. */
#define XDEV_EXT_BINDING_ABI_VERSION		2U

enum xdev_ext_binding_event {
	XDEV_EXT_BINDING_EVENT_UNSPEC	= 0,
	XDEV_EXT_BINDING_EVENT_DISPATCH	= 1,
	XDEV_EXT_BINDING_EVENT_COMPLETE	= 2,
	XDEV_EXT_BINDING_EVENT_MAX,
};

enum xdev_ext_binding_backend {
	XDEV_EXT_BINDING_BACKEND_UNSPEC	= 0,
	XDEV_EXT_BINDING_BACKEND_SOCKET	= 1,
	XDEV_EXT_BINDING_BACKEND_AFXDP	= 2,
	XDEV_EXT_BINDING_BACKEND_NVME	= 3,
	XDEV_EXT_BINDING_BACKEND_IAA		= 4,
	XDEV_EXT_BINDING_BACKEND_GPU		= 5,
	XDEV_EXT_BINDING_BACKEND_MAX,
};

/* Direction is relative to the device; INTERNAL is device-local processing. */
enum xdev_ext_binding_direction {
	XDEV_EXT_BINDING_DIRECTION_UNSPEC		= 0,
	XDEV_EXT_BINDING_DIRECTION_TO_DEVICE		= 1,
	XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE	= 2,
	XDEV_EXT_BINDING_DIRECTION_INTERNAL		= 3,
	XDEV_EXT_BINDING_DIRECTION_MAX,
};

/*
 * A recipe names trusted C code that owns final validation, native descriptor
 * construction, submission, completion and rollback.  Values 0..7 retain the
 * v1 ABI numbers; passthrough recipes are appended rather than reinterpreting
 * FILE or CPU recipes.
 */
enum xdev_ext_binding_recipe {
	XDEV_EXT_BINDING_RECIPE_DEFAULT		= 0,
	XDEV_EXT_BINDING_RECIPE_FILE_READ		= 1,
	XDEV_EXT_BINDING_RECIPE_FILE_WRITE		= 2,
	XDEV_EXT_BINDING_RECIPE_SOCKET_SEND		= 3,
	XDEV_EXT_BINDING_RECIPE_AFXDP_COPY		= 4,
	XDEV_EXT_BINDING_RECIPE_CPU_CALC		= 5,
	XDEV_EXT_BINDING_RECIPE_GPU_COPY		= 6,
	XDEV_EXT_BINDING_RECIPE_COMPLETE		= 7,
	XDEV_EXT_BINDING_RECIPE_NVME_PT_READ		= 8,
	XDEV_EXT_BINDING_RECIPE_NVME_PT_WRITE	= 9,
	XDEV_EXT_BINDING_RECIPE_IAA_COMPRESS		= 10,
	XDEV_EXT_BINDING_RECIPE_IAA_DECOMPRESS	= 11,
	XDEV_EXT_BINDING_RECIPE_AFXDP_NATIVE_TX	= 12,
	XDEV_EXT_BINDING_RECIPE_AFXDP_RX		= 13,
	XDEV_EXT_BINDING_RECIPE_MAX,
};

/* Values 0..6 retain the v1 ABI numbers. */
enum xdev_ext_binding_stage {
	XDEV_EXT_BINDING_STAGE_NONE			= 0,
	XDEV_EXT_BINDING_STAGE_FILE_READ		= 1,
	XDEV_EXT_BINDING_STAGE_CPU_CALC		= 2,
	XDEV_EXT_BINDING_STAGE_GPU_COPY		= 3,
	XDEV_EXT_BINDING_STAGE_SEND			= 4,
	XDEV_EXT_BINDING_STAGE_FILE_WRITE		= 5,
	XDEV_EXT_BINDING_STAGE_COMPLETE		= 6,
	XDEV_EXT_BINDING_STAGE_NVME_READ		= 7,
	XDEV_EXT_BINDING_STAGE_NVME_WRITE		= 8,
	XDEV_EXT_BINDING_STAGE_AFXDP_TX		= 9,
	XDEV_EXT_BINDING_STAGE_IAA_COMPRESS		= 10,
	XDEV_EXT_BINDING_STAGE_IAA_DECOMPRESS	= 11,
	XDEV_EXT_BINDING_STAGE_AFXDP_RX		= 12,
	XDEV_EXT_BINDING_STAGE_MAX,
};

enum xdev_ext_binding_action {
	XDEV_EXT_BINDING_ACTION_FALLBACK	= 0,
	XDEV_EXT_BINDING_ACTION_USE_PLAN	= 1,
	XDEV_EXT_BINDING_ACTION_TERMINAL	= 2,
	XDEV_EXT_BINDING_ACTION_MAX,
};

enum xdev_ext_binding_profile {
	XDEV_EXT_BINDING_PROFILE_NONE	= 0,
	XDEV_EXT_BINDING_PROFILE_NATIVE	= 1,
	XDEV_EXT_BINDING_PROFILE_MAX,
};

/* v2 still exposes no private lifecycle state of a backend frame. */
enum xdev_ext_binding_frame_state {
	XDEV_EXT_BINDING_FRAME_UNTRACKED	= 0,
};

/* Capabilities describe facts established by trusted C, never BPF grants. */
#define XDEV_EXT_BINDING_CAP_ASYNC		(1U << 0)
#define XDEV_EXT_BINDING_CAP_POLL		(1U << 1)
#define XDEV_EXT_BINDING_CAP_FIXED_FILE	(1U << 2)
#define XDEV_EXT_BINDING_CAP_FIXED_BUFFER	(1U << 3)
#define XDEV_EXT_BINDING_CAP_ZERO_COPY	(1U << 4)
#define XDEV_EXT_BINDING_CAP_MULTIBUFFER	(1U << 5)
#define XDEV_EXT_BINDING_CAP_SHARED_UMEM	(1U << 6)

/* AF_XDP RX is an appended callback input domain and requires opt-in. */
#define XDEV_EXT_BINDING_OPS_F_AFXDP_RX	(1U << 0)
#define XDEV_EXT_BINDING_KNOWN_OPS_FLAG_MASK	0x00000001U

/* Dynamic IDs use these helpers so an out-of-range value cannot shift by 32. */
static inline __u32 xdev_ext_binding_recipe_bit(__u32 recipe)
{
	return recipe < 32U ? 1U << recipe : 0U;
}

static inline __u32 xdev_ext_binding_stage_bit(__u32 stage)
{
	return stage < 32U ? 1U << stage : 0U;
}

static inline __u32 xdev_ext_binding_profile_bit(__u32 profile)
{
	return profile < 32U ? 1U << profile : 0U;
}

#define XDEV_EXT_BINDING_KNOWN_RECIPE_MASK	0x00003ffeU
#define XDEV_EXT_BINDING_KNOWN_STAGE_MASK	0x00001ffeU
#define XDEV_EXT_BINDING_KNOWN_PROFILE_MASK	0x00000002U
#define XDEV_EXT_BINDING_KNOWN_CAPABILITY_MASK	0x0000007fU

/*
 * A callback receives only this immutable, pointer-free scalar snapshot.
 * IDs are opaque correlation values and must not encode kernel pointers.
 * Zero is valid when trusted C has not established a canonical ID.
 */
struct xdev_ext_binding_ctx_v2 {
	__u32 abi_version;
	__u32 ctx_size;
	__u32 event;
	__u32 backend;

	__u32 current_stage;
	__u32 direction;
	__u32 frame_state;
	__u32 capabilities;

	__u32 allowed_recipe_mask;
	__u32 allowed_next_mask;
	__u32 allowed_profile_mask;
	__u32 reserved0;

	__aligned_u64 request_id;
	__aligned_u64 chain_id;
	__aligned_u64 endpoint_id;
	__aligned_u64 src_buffer_id;
	__aligned_u64 dst_buffer_id;
	__aligned_u64 src_offset;
	__aligned_u64 dst_offset;
	__aligned_u64 logical_offset;
	__aligned_u64 length;
	__aligned_u64 bytes_done;

	__s32 result;
	__u32 reserved1;
};

#endif /* _UAPI_LINUX_XDEV_EXT_BINDING_H */
