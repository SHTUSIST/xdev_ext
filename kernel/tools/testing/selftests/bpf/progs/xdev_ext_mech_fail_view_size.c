// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* A view's size is fixed at load time; C compares it with the class size. */
SEC("struct_ops/build")
__failure __msg("R2 is not a const")
__s32 BPF_PROG(build_sizes_view_at_run_time, const struct xdev_ext_mech_ctx *mctx)
{
	const __u8 *info = bpf_xdev_ext_info(mctx, mctx->nr_frames);

	return info ? XDEV_EXT_MECH_BUILD_SUBMIT : XDEV_EXT_MECH_BUILD_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops view_size_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)build_sizes_view_at_run_time,
};

char _license[] SEC("license") = "GPL";
