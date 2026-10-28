// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* Only prepare may sleep; build runs under the worker and at uring_cmd issue. */
SEC("struct_ops.s/build")
__failure __msg("attach to unsupported member build of struct xdev_ext_nvme_mech_ops")
__s32 BPF_PROG(build_sleepable, const struct xdev_ext_mech_ctx *mctx)
{
	return mctx->nr_frames ? XDEV_EXT_MECH_BUILD_DEFAULT : XDEV_EXT_MECH_BUILD_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops sleepable_build_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)build_sleepable,
};

char _license[] SEC("license") = "GPL";
