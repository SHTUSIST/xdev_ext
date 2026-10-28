// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include <bpf/bpf_tracing.h>

SEC("struct_ops/dispatch")
__s32 BPF_PROG(valid_dispatch, const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	return bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC("struct_ops/complete")
__s32 BPF_PROG(valid_complete, const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	return bpf_xdev_ext_complete_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

#define INVALID_POLICY(name, abi, backend_id, policy_flags, policy_reserved) \
	SEC(".struct_ops.link") \
	struct xdev_ext_binding_ops name = { \
		.abi_version = (abi), \
		.backend = (backend_id), \
		.flags = (policy_flags), \
		.reserved = (policy_reserved), \
		.dispatch = (void *)valid_dispatch, \
		.complete = (void *)valid_complete, \
	}

INVALID_POLICY(bad_abi_policy, XDEV_EXT_BINDING_ABI_VERSION - 1,
	       XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 0);
INVALID_POLICY(bad_backend_policy, XDEV_EXT_BINDING_ABI_VERSION,
	       XDEV_EXT_BINDING_BACKEND_MAX, 0, 0);
INVALID_POLICY(bad_flags_policy, XDEV_EXT_BINDING_ABI_VERSION,
	       XDEV_EXT_BINDING_BACKEND_SOCKET, 1, 0);
INVALID_POLICY(bad_unknown_flags_policy, XDEV_EXT_BINDING_ABI_VERSION,
	       XDEV_EXT_BINDING_BACKEND_AFXDP, 1U << 31, 0);
INVALID_POLICY(bad_reserved_policy, XDEV_EXT_BINDING_ABI_VERSION,
	       XDEV_EXT_BINDING_BACKEND_SOCKET, 0, 1);

char _license[] SEC("license") = "GPL";
