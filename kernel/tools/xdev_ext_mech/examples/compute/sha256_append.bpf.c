// SPDX-License-Identifier: GPL-2.0
/*
 * Compute example: append SHA-256 of every frame behind it, in plain BPF.
 * Byte for byte the output of XDEV_EXT_CPU_XFORM_SHA256_APPEND: the 32-byte
 * digest. See README.md.
 *
 * Stage: class CPU, arg0 = XDEV_EXT_CPU_XFORM_BPF (10), arg1 = 32.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "compute_example.h"
#include "sha256.h"

SEC("struct_ops/sha_app_comp")
__s32 BPF_PROG(sha_app_comp, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	return ex_sha256_append(mctx);
}

SEC("struct_ops/sha_app_build")
__s32 BPF_PROG(sha_app_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_BUILD_DEFAULT;
}

SEC("struct_ops/sha_app_done")
__s32 BPF_PROG(sha_app_done, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops sha256_append_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)sha_app_build,
	.complete = (void *)sha_app_done,
	.compute = (void *)sha_app_comp,
};

char LICENSE[] SEC("license") = "GPL";
