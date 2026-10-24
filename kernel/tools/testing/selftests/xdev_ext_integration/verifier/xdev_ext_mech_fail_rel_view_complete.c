// SPDX-License-Identifier: GPL-2.0
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
extern __u8 *bpf_xdev_ext_rel_tx_view(const struct xdev_ext_mech_ctx *ctx,
                                     const __u64 rdonly_buf_size) __ksym;
SEC("struct_ops/complete")
__failure __msg("calling kernel function bpf_xdev_ext_rel_tx_view is not allowed")
__s32 BPF_PROG(rel_view_complete,const struct xdev_ext_mech_ctx *mctx)
{
 __u8 *view=bpf_xdev_ext_rel_tx_view(mctx,528);
 if (view) return view[0];
 return 0;
}
SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops rel_view_complete_ops={
 .abi_version=XDEV_EXT_MECH_ABI_VERSION,.complete=(void *)rel_view_complete,
};
char _license[] SEC("license")="GPL";
