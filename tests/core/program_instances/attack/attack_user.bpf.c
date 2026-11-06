// SPDX-License-Identifier: GPL-2.0
/*
 * GUEST TEST ONLY: a PRIVATE USER-stage program for the stall attack. It is
 * the class default per batch and NEXT after the user thread finishes, like
 * the shipped user_plan example, but flagged PRIVATE so the attacker session
 * selects it through CREATE_PROGRAMS. The stall itself is produced by the user
 * thread never completing a held batch; the kernel cancels it at its deadline.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"

SEC("struct_ops/attack_user_build")
__s32 BPF_PROG(attack_user_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_BUILD_DEFAULT;
}

SEC("struct_ops/attack_user_complete")
__s32 BPF_PROG(attack_user_complete, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_user_mech_ops attack_user_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.flags = XDEV_EXT_MP_OPS_F_PRIVATE,
	.build = (void *)attack_user_build,
	.complete = (void *)attack_user_complete,
};

char LICENSE[] SEC("license") = "GPL";
