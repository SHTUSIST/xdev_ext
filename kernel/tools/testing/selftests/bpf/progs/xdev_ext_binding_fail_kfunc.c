// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

SEC("struct_ops/dispatch")
__failure __msg("calling kernel function bpf_xdev_ext_complete_action is not allowed")
__s32 BPF_PROG(dispatch_calls_complete,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	return bpf_xdev_ext_complete_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC(".struct_ops.link")
struct xdev_ext_binding_ops wrong_dispatch_phase_policy = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_SOCKET,
	.dispatch = (void *)dispatch_calls_complete,
};

char _license[] SEC("license") = "GPL";
