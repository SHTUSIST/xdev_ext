// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

SEC("struct_ops/dispatch")
__failure __msg("R1 must be referenced or trusted")
__s32 BPF_PROG(dispatch_fabricated_ctx,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	struct xdev_ext_binding_ctx_v2 copy = {};
	const struct xdev_ext_binding_ctx_v2 *untrusted;

	copy.abi_version = binding_ctx->abi_version;
	untrusted = bpf_core_cast(&copy, struct xdev_ext_binding_ctx_v2);
	return bpf_xdev_ext_dispatch_action(untrusted, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC(".struct_ops.link")
struct xdev_ext_binding_ops fabricated_ctx_policy = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_SOCKET,
	.dispatch = (void *)dispatch_fabricated_ctx,
};

char _license[] SEC("license") = "GPL";
