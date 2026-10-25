// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* compute changes payload only; the descriptor was validated before submit. */
SEC("struct_ops/compute")
__failure __msg("calling kernel function bpf_xdev_ext_desc is not allowed")
__s32 BPF_PROG(compute_rewrites_desc, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *d = bpf_xdev_ext_desc(mctx, 0, 16);

	if (d)
		d[0] = 1;
	return 0;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops compute_desc_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.compute = (void *)compute_rewrites_desc,
};

char _license[] SEC("license") = "GPL";
