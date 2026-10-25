// SPDX-License-Identifier: GPL-2.0
/* The USER stage's program: the class default descriptor (arg 0) for every
 * batch, and NEXT after the user thread finished; the core applies the
 * batch's status before NEXT.  A session never runs a class without its
 * program.  To pass a per-batch choice to the user thread, a program fills
 * struct xdev_ext_user_desc through bpf_xdev_ext_desc() and returns SUBMIT. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"

SEC("struct_ops/user_plan_build")
__s32 BPF_PROG(user_plan_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_BUILD_DEFAULT;
}

SEC("struct_ops/user_plan_complete")
__s32 BPF_PROG(user_plan_complete, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_user_mech_ops user_plan_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)user_plan_build,
	.complete = (void *)user_plan_complete,
};
char LICENSE[] SEC("license") = "GPL";
