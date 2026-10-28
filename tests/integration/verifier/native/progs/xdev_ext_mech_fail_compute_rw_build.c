// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* Payload writes belong to compute: a failed build is retried. */
SEC("struct_ops/build")
__failure __msg("calling kernel function bpf_xdev_ext_frame_rw is not allowed")
__s32 BPF_PROG(cpu_build_writes_frame, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *byte = bpf_xdev_ext_frame_rw(mctx, 0, 0, 1);

	if (byte)
		byte[0] = 0;
	return XDEV_EXT_MECH_BUILD_DEFAULT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops compute_rw_build_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)cpu_build_writes_frame,
};

char _license[] SEC("license") = "GPL";
