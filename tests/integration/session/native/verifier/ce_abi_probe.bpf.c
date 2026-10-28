// SPDX-License-Identifier: GPL-2.0
/* Identical positive/negative objects, differing only in the declared CE ABI. */
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#ifndef CE_TEST_ABI
#define CE_TEST_ABI XDEV_EXT_CE_MECH_ABI_VERSION
#endif

SEC("struct_ops/build")
__s32 BPF_PROG(ce_abi_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MECH_BUILD_ABORT;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(ce_abi_complete, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MECH_DONE;
}

SEC(".struct_ops.link")
struct xdev_ext_ce_mech_ops ce_abi_ops = {
	.abi_version = CE_TEST_ABI,
	.build = (void *)ce_abi_build,
	.complete = (void *)ce_abi_complete,
};
char _license[] SEC("license") = "GPL";
