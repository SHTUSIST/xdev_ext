// SPDX-License-Identifier: GPL-2.0
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

extern __u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *ctx,
			       const __u64 rdwr_buf_size) __ksym;

/* Even an AF_XDP build callback cannot use the RX complete state view. */
SEC("struct_ops/build")
__failure __msg("calling kernel function bpf_xdev_ext_afxdp_state is not allowed")
__s32 BPF_PROG(afxdp_build_takes_state, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *state = bpf_xdev_ext_afxdp_state(mctx, 1);

	if (state)
		state[0] = 1;
	return XDEV_EXT_MECH_BUILD_DEFAULT;
}

SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops state_build_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)afxdp_build_takes_state,
};

char _license[] SEC("license") = "GPL";
