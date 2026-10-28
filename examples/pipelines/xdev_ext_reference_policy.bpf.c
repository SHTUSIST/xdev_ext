// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_reference_policy_abi.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Keep this userspace-built object tied to the kernel's BTF-visible type. */
struct xdev_ext_binding_ops {
	__u32 abi_version;
	__u32 backend;
	__u32 flags;
	__u32 reserved;
	__s32 (*dispatch)(const struct xdev_ext_binding_ctx_v2 *ctx);
	__s32 (*complete)(const struct xdev_ext_binding_ctx_v2 *ctx);
} __attribute__((preserve_access_index));

extern int bpf_xdev_ext_dispatch_action(const struct xdev_ext_binding_ctx_v2 *ctx,
				   __u32 action, __u32 recipe,
				   __u32 next_stage, __u32 profile) __ksym;
extern int bpf_xdev_ext_complete_action(const struct xdev_ext_binding_ctx_v2 *ctx,
				   __u32 action, __u32 recipe,
				   __u32 next_stage, __u32 profile) __ksym;

struct xdev_ext_reference_policy_stats xdev_ext_reference_stats;

static __always_inline struct xdev_ext_reference_policy_backend_stats *
xdev_ext_reference_backend_stats(const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	if (binding_ctx->backend <= XDEV_EXT_BINDING_BACKEND_UNSPEC ||
	    binding_ctx->backend >= XDEV_EXT_BINDING_BACKEND_MAX)
		return (void *)0;
	return &xdev_ext_reference_stats.backend[binding_ctx->backend];
}

/*
 * Trusted C admits only stages the context's backend owns, so this row splits
 * the backend row by stage (AF_XDP TX vs RX) without inference.
 */
static __always_inline struct xdev_ext_reference_policy_backend_stats *
xdev_ext_reference_stage_stats(const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	if (binding_ctx->current_stage <= XDEV_EXT_BINDING_STAGE_NONE ||
	    binding_ctx->current_stage >= XDEV_EXT_BINDING_STAGE_MAX)
		return (void *)0;
	return &xdev_ext_reference_stats.stage[binding_ctx->current_stage];
}

static __always_inline void
xdev_ext_reference_dispatch_enter(struct xdev_ext_reference_policy_backend_stats *stats)
{
	if (stats)
		__sync_fetch_and_add(&stats->dispatch_callbacks, 1);
}

static __always_inline void
xdev_ext_reference_dispatch_exit(struct xdev_ext_reference_policy_backend_stats *stats,
			    int ret)
{
	if (!stats)
		return;
	if (!ret)
		__sync_fetch_and_add(&stats->dispatch_kfunc_ok, 1);
	else
		__sync_fetch_and_add(&stats->dispatch_kfunc_errors, 1);
}

static __always_inline void
xdev_ext_reference_complete_enter(struct xdev_ext_reference_policy_backend_stats *stats,
			     const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	if (!stats)
		return;
	__sync_fetch_and_add(&stats->complete_callbacks, 1);
	__sync_fetch_and_add(&stats->bytes_done, binding_ctx->bytes_done);
	stats->last_result = binding_ctx->result;
	if (!binding_ctx->result)
		__sync_fetch_and_add(&stats->result_ok, 1);
	else
		__sync_fetch_and_add(&stats->result_errors, 1);
}

static __always_inline void
xdev_ext_reference_complete_exit(struct xdev_ext_reference_policy_backend_stats *stats,
			    int ret)
{
	if (!stats)
		return;
	if (!ret)
		__sync_fetch_and_add(&stats->complete_kfunc_ok, 1);
	else
		__sync_fetch_and_add(&stats->complete_kfunc_errors, 1);
}

SEC("struct_ops/dispatch")
__s32 BPF_PROG(xdev_ext_reference_dispatch,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	struct xdev_ext_reference_policy_backend_stats *backend, *stage;
	int ret;

	(void)ctx;
	backend = xdev_ext_reference_backend_stats(binding_ctx);
	stage = xdev_ext_reference_stage_stats(binding_ctx);
	xdev_ext_reference_dispatch_enter(backend);
	xdev_ext_reference_dispatch_enter(stage);
	ret = bpf_xdev_ext_dispatch_action(binding_ctx,
				      XDEV_EXT_BINDING_ACTION_FALLBACK, 0, 0, 0);
	xdev_ext_reference_dispatch_exit(backend, ret);
	xdev_ext_reference_dispatch_exit(stage, ret);
	return ret;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(xdev_ext_reference_complete,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	struct xdev_ext_reference_policy_backend_stats *backend, *stage;
	int ret;

	(void)ctx;
	backend = xdev_ext_reference_backend_stats(binding_ctx);
	stage = xdev_ext_reference_stage_stats(binding_ctx);
	xdev_ext_reference_complete_enter(backend, binding_ctx);
	xdev_ext_reference_complete_enter(stage, binding_ctx);
	ret = bpf_xdev_ext_complete_action(binding_ctx,
				      XDEV_EXT_BINDING_ACTION_FALLBACK, 0, 0, 0);
	xdev_ext_reference_complete_exit(backend, ret);
	xdev_ext_reference_complete_exit(stage, ret);
	return ret;
}

struct xdev_ext_binding_ops socket_policy SEC(".struct_ops.link") = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_SOCKET,
	.dispatch = (void *)xdev_ext_reference_dispatch,
	.complete = (void *)xdev_ext_reference_complete,
};

struct xdev_ext_binding_ops afxdp_policy SEC(".struct_ops.link") = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_AFXDP,
	.flags = XDEV_EXT_BINDING_OPS_F_AFXDP_RX,
	.dispatch = (void *)xdev_ext_reference_dispatch,
	.complete = (void *)xdev_ext_reference_complete,
};

struct xdev_ext_binding_ops nvme_policy SEC(".struct_ops.link") = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_NVME,
	.dispatch = (void *)xdev_ext_reference_dispatch,
	.complete = (void *)xdev_ext_reference_complete,
};

struct xdev_ext_binding_ops iaa_policy SEC(".struct_ops.link") = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_IAA,
	.dispatch = (void *)xdev_ext_reference_dispatch,
	.complete = (void *)xdev_ext_reference_complete,
};

struct xdev_ext_binding_ops gpu_policy SEC(".struct_ops.link") = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_GPU,
	.dispatch = (void *)xdev_ext_reference_dispatch,
	.complete = (void *)xdev_ext_reference_complete,
};

char LICENSE[] SEC("license") = "GPL";
