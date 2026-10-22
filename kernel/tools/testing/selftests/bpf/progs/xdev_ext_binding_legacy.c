// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("struct_ops/dispatch")
__s32 BPF_PROG(dispatch_legacy, const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	return bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC("struct_ops/complete")
__s32 BPF_PROG(complete_legacy, const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	return bpf_xdev_ext_complete_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC(".struct_ops")
struct xdev_ext_binding_ops legacy_policy = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_SOCKET,
	.dispatch = (void *)dispatch_legacy,
	.complete = (void *)complete_legacy,
};

char _license[] SEC("license") = "GPL";
