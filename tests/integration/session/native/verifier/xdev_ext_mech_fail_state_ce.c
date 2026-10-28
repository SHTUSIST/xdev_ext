// SPDX-License-Identifier: GPL-2.0
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

extern __u8 *bpf_xdev_ext_afxdp_state(const struct xdev_ext_mech_ctx *ctx,
			       const __u64 rdwr_buf_size) __ksym;

/* The CE class cannot access a private AF_XDP pool's RX state. */
SEC("struct_ops/complete")
__failure __msg("calling kernel function bpf_xdev_ext_afxdp_state is not allowed")
__s32 BPF_PROG(ce_complete_takes_state, const struct xdev_ext_mech_ctx *mctx)
{
	__u8 *state = bpf_xdev_ext_afxdp_state(mctx, 1);

	if (state)
		state[0] = 1;
	return XDEV_EXT_MECH_DONE;
}

SEC(".struct_ops.link")
struct xdev_ext_ce_mech_ops state_ce_ops = {
	.abi_version = XDEV_EXT_CE_MECH_ABI_VERSION,
	.complete = (void *)ce_complete_takes_state,
};

char _license[] SEC("license") = "GPL";
