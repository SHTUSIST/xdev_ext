// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* A view grants exactly its constant size; C bounds it by the capacity. */
SEC("struct_ops/compute")
__failure __msg("invalid access to memory, mem_size=4 off=4 size=1")
__s32 BPF_PROG(compute_writes_past_view, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *p = bpf_xdev_ext_frame_rw(mctx, 0, 0, 4);

	if (!p)
		return -14;
	p[4] = 1;
	return 0;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops compute_view_past_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.compute = (void *)compute_writes_past_view,
};

char _license[] SEC("license") = "GPL";
