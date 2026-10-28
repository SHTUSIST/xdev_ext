// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* A kfunc takes only the callback's own trusted ctx, never a cast copy. */
SEC("struct_ops/build")
__failure __msg("R1 must be referenced or trusted")
__s32 BPF_PROG(build_forged_ctx, const struct xdev_ext_mech_ctx *mctx)
{
	struct xdev_ext_mech_ctx copy = {};
	const struct xdev_ext_mech_ctx *forged;

	copy.batch_id = mctx->batch_id;
	forged = bpf_core_cast(&copy, struct xdev_ext_mech_ctx);
	if (!bpf_xdev_ext_info(forged, sizeof(struct xdev_ext_nvme_mech_info)))
		return XDEV_EXT_MECH_BUILD_ABORT;
	return XDEV_EXT_MECH_BUILD_SUBMIT;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops forged_ctx_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)build_forged_ctx,
};

char _license[] SEC("license") = "GPL";
