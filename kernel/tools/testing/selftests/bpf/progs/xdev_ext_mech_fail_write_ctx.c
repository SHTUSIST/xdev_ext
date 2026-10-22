// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* The callback ctx is an immutable snapshot; C reads its own copy. */
SEC("struct_ops/build")
__failure __msg("XDEV_EXT callback context is read-only at off")
__s32 BPF_PROG(build_writes_ctx, const struct xdev_ext_mech_ctx *mctx)
{
	((struct xdev_ext_mech_ctx *)mctx)->batch_id = 0;
	return XDEV_EXT_MECH_BUILD_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops write_ctx_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)build_writes_ctx,
};

char _license[] SEC("license") = "GPL";
