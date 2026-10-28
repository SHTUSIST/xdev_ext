// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* The writable view's size is fixed at load time. */
SEC("struct_ops/compute")
__failure __msg("R4 is not a const")
__s32 BPF_PROG(compute_sizes_view_at_run_time, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *p = bpf_xdev_ext_frame_rw(mctx, 0, 0, bpf_xdev_ext_frame_len(mctx, 0));

	return p ? 0 : -14;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops compute_view_size_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.compute = (void *)compute_sizes_view_at_run_time,
};

char _license[] SEC("license") = "GPL";
