// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/*
 * The mechanism kfunc filters sit on the same struct_ops hook as the policy
 * filter; they must pass kfuncs they do not own.
 */
SEC("struct_ops/dispatch")
__success
__s32 BPF_PROG(dispatch_next_to_mech,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	return bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC(".struct_ops.link")
struct xdev_ext_binding_ops loads_next_to_mech_policy = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_SOCKET,
	.dispatch = (void *)dispatch_next_to_mech,
};

char _license[] SEC("license") = "GPL";
