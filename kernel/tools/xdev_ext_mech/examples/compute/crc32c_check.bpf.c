// SPDX-License-Identifier: GPL-2.0
/*
 * Compute example: check the CRC32C at the end of every frame, in plain BPF
 * (no CRC kfunc). Same result as XDEV_EXT_CPU_XFORM_CRC32C_CHECK, or with
 * strip=1 as XDEV_EXT_CPU_XFORM_CRC32C_STRIP. See README.md.
 *
 * Build: -DEX_CRC32C_SLICE8=0 (bytewise, 1 KiB table) or 1 (slice-by-8,
 * 8 KiB of tables).
 * Stage: class CPU, arg0 = XDEV_EXT_CPU_XFORM_BPF (10), arg1 = 0, or
 * arg1 = -4 (two's complement) with strip=1.
 * Globals (xdev_ext_mech_ctl attach --set): strip.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "compute_example.h"
#include "crc32c.h"

/* 1: also remove the four CRC bytes (the stage declares -4). */
__u32 strip;

SEC("struct_ops/crc_check_comp")
__s32 BPF_PROG(crc_check_comp, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	return ex_crc32c_check(mctx, strip);
}

/* The class defaults: the kernel's own descriptor and completion. */
SEC("struct_ops/crc_check_build")
__s32 BPF_PROG(crc_check_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_BUILD_DEFAULT;
}

SEC("struct_ops/crc_check_done")
__s32 BPF_PROG(crc_check_done, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops crc32c_check_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)crc_check_build,
	.complete = (void *)crc_check_done,
	.compute = (void *)crc_check_comp,
};

char LICENSE[] SEC("license") = "GPL";
