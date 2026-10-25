// SPDX-License-Identifier: GPL-2.0
/*
 * Compute example: append the CRC32C of every frame behind it, in plain BPF
 * (no CRC kfunc). Byte for byte the output of XDEV_EXT_CPU_XFORM_CRC32C_APPEND:
 * ~crc32c(~0, frame), little endian. See README.md.
 *
 * Build: -DEX_CRC32C_SLICE8=0 (bytewise, 1 KiB table) or 1 (slice-by-8,
 * 8 KiB of tables).
 * Stage: class CPU, arg0 = XDEV_EXT_CPU_XFORM_BPF (10), arg1 = 4.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "compute_example.h"
#include "crc32c.h"

SEC("struct_ops/crc_app_comp")
__s32 BPF_PROG(crc_app_comp, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	return ex_crc32c_append(mctx);
}

SEC("struct_ops/crc_app_build")
__s32 BPF_PROG(crc_app_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_BUILD_DEFAULT;
}

SEC("struct_ops/crc_app_done")
__s32 BPF_PROG(crc_app_done, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops crc32c_append_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)crc_app_build,
	.complete = (void *)crc_app_done,
	.compute = (void *)crc_app_comp,
};

char LICENSE[] SEC("license") = "GPL";
