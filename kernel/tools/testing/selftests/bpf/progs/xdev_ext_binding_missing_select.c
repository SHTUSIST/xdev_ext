// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include <bpf/bpf_tracing.h>

SEC("struct_ops/dispatch")
__s32 BPF_PROG(missing_complete_dispatch,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	return bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC("struct_ops/complete")
__s32 BPF_PROG(missing_dispatch_complete,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	return bpf_xdev_ext_complete_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC(".struct_ops.link")
struct xdev_ext_binding_ops missing_complete_policy = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_SOCKET,
	.dispatch = (void *)missing_complete_dispatch,
};

SEC(".struct_ops.link")
struct xdev_ext_binding_ops missing_dispatch_policy = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_AFXDP,
	.complete = (void *)missing_dispatch_complete,
};

char _license[] SEC("license") = "GPL";
