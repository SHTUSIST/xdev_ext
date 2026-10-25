// SPDX-License-Identifier: GPL-2.0
/*
 * Compute example: append XXH64 of every frame behind it, in plain BPF.
 * Byte for byte the output of XDEV_EXT_CPU_XFORM_XXH64_APPEND with stage
 * parameter = seed: the 64-bit hash, big endian. See README.md.
 *
 * Stage: class CPU, arg0 = XDEV_EXT_CPU_XFORM_BPF (10), arg1 = 8. The BPF
 * transform's arg1 is the length change, so the seed is a global here.
 * Globals (xdev_ext_mech_ctl attach --set): seed.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "compute_example.h"
#include "xxh64.h"

__u64 seed;

SEC("struct_ops/xxh_app_comp")
__s32 BPF_PROG(xxh_app_comp, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	return ex_xxh64_append(mctx, seed);
}

SEC("struct_ops/xxh_app_build")
__s32 BPF_PROG(xxh_app_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_BUILD_DEFAULT;
}

SEC("struct_ops/xxh_app_done")
__s32 BPF_PROG(xxh_app_done, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops xxh64_append_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)xxh_app_build,
	.complete = (void *)xxh_app_done,
	.compute = (void *)xxh_app_comp,
};

char LICENSE[] SEC("license") = "GPL";
