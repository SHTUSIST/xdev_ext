// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* Mechanism kfuncs belong to the three mechanism struct_ops types only. */
SEC("struct_ops/dispatch")
__failure __msg("calling kernel function bpf_xdev_ext_info is not allowed")
__s32 BPF_PROG(dispatch_calls_mech,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	const __u8 *info = bpf_xdev_ext_info((const void *)binding_ctx,
					sizeof(struct xdev_ext_nvme_mech_info));

	return info ? XDEV_EXT_BINDING_ACTION_TERMINAL : XDEV_EXT_BINDING_ACTION_FALLBACK;
}

SEC(".struct_ops.link")
struct xdev_ext_binding_ops mech_kfunc_policy = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_NVME,
	.dispatch = (void *)dispatch_calls_mech,
};

char _license[] SEC("license") = "GPL";
