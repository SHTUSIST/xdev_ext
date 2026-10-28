// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* Only compute records output lengths; complete runs after they are applied. */
SEC("struct_ops/complete")
__failure __msg("calling kernel function bpf_xdev_ext_frame_set_len is not allowed")
__s32 BPF_PROG(cpu_complete_sets_len, const struct xdev_ext_mech_ctx *mctx)
{
	return bpf_xdev_ext_frame_set_len(mctx, 0, 0) ? XDEV_EXT_MECH_ABORT : XDEV_EXT_MECH_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops compute_set_len_complete_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.complete = (void *)cpu_complete_sets_len,
};

char _license[] SEC("license") = "GPL";
