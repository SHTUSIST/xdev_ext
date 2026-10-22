// SPDX-License-Identifier: GPL-2.0
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

XDEV_EXT_MECH_TEST_OPS(xdev_ext_dma_mech_ops);

SEC("struct_ops/complete")
__failure __msg("calling kernel function bpf_xdev_ext_desc is not allowed")
__s32 BPF_PROG(dma_complete_takes_desc, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *desc = bpf_xdev_ext_desc(mctx, 0, sizeof(struct xdev_ext_dma_copy_desc));

	if (desc)
		desc[0] = 0;
	return XDEV_EXT_MECH_DONE;
}

SEC(".struct_ops.link")
struct xdev_ext_dma_mech_ops dma_desc_complete_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.complete = (void *)dma_complete_takes_desc,
};
char _license[] SEC("license") = "GPL";
