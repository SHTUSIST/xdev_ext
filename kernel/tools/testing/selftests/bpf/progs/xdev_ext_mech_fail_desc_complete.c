// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* The descriptor scratch exists only during build. */
SEC("struct_ops/complete")
__failure __msg("calling kernel function bpf_xdev_ext_desc is not allowed")
__s32 BPF_PROG(complete_takes_desc, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *desc = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_NVME_MECH_DESC_SIZE);

	if (desc)
		desc[0] = XDEV_EXT_MECH_NVME_OP_WRITE;
	return XDEV_EXT_MECH_DONE;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops desc_complete_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.complete = (void *)complete_takes_desc,
};

char _license[] SEC("license") = "GPL";
