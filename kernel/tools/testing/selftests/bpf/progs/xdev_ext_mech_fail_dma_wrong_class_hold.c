// SPDX-License-Identifier: GPL-2.0
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

XDEV_EXT_MECH_TEST_OPS(xdev_ext_dma_mech_ops);

SEC("struct_ops/complete")
__failure __msg("calling kernel function bpf_xdev_ext_afxdp_hold is not allowed")
__s32 BPF_PROG(dma_complete_holds, const struct xdev_ext_mech_ctx *mctx)
{
	return bpf_xdev_ext_afxdp_hold(mctx, mctx->batch_id, 0, 0, 1) ?
		XDEV_EXT_MECH_ABORT : XDEV_EXT_MECH_DONE;
}

SEC(".struct_ops.link")
struct xdev_ext_dma_mech_ops dma_wrong_class_hold_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.complete = (void *)dma_complete_holds,
};
char _license[] SEC("license") = "GPL";
