// SPDX-License-Identifier: GPL-2.0
/* Select a fixed bounded transform; the CPU class validates the length delta
 * and parameters, performs the operation and owns completion/error handling. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "xdev_ext_mech_cpu_abi.h"

/* Zero uses the transform and parameter admitted at CREATE. */
__u32 cpu_xform;
__u64 cpu_param;

SEC("struct_ops/cpu_plan_build")
__s32 BPF_PROG(cpu_plan_build, const struct xdev_ext_mech_ctx *mctx)
{
	struct xdev_ext_mp_cpu_desc *desc;

	(void)ctx;
	if (!cpu_xform)
		return 0; /* BUILD_DEFAULT */
	desc = (void *)bpf_xdev_ext_desc(mctx, 0, sizeof(*desc));
	if (!desc)
		return XDEV_EXT_MP_BUILD_ABORT;
	desc->xform = cpu_xform;
	desc->flags = 0;
	desc->param = cpu_param;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/cpu_plan_complete")
__s32 BPF_PROG(cpu_plan_complete, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	/* Core applies the native CPU error before interpreting NEXT. */
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops cpu_plan_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)cpu_plan_build,
	.complete = (void *)cpu_plan_complete,
};
char LICENSE[] SEC("license") = "GPL";
