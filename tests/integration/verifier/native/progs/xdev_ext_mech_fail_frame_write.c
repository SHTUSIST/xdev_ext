// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* Frame bytes are a read-only view; only AF_XDP header room is writable. */
SEC("struct_ops/build")
__failure __msg("cannot write into rdonly_mem")
__s32 BPF_PROG(build_writes_frame, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *byte = bpf_xdev_ext_frame(mctx, 0, 0, 1);

	if (!byte)
		return XDEV_EXT_MECH_BUILD_ABORT;
	byte[0] = 0;
	return XDEV_EXT_MECH_BUILD_SUBMIT;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops frame_write_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)build_writes_frame,
};

char _license[] SEC("license") = "GPL";
