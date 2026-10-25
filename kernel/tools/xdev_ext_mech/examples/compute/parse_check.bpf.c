// SPDX-License-Identifier: GPL-2.0
/*
 * Compute example: the header check of XDEV_EXT_CPU_XFORM_PARSE_STRIP, in
 * plain BPF, without the strip. Each frame starts with a header of hdr bytes
 * whose first four bytes hold, little endian, the payload length behind it.
 * The check writes nothing; moving the payload stays the kernel's fixed
 * transform, which a later CPU stage of the same session may run
 * (XDEV_EXT_CPU_XFORM_PARSE_STRIP, arg1 = hdr). See README.md.
 *
 * Stage: class CPU, arg0 = XDEV_EXT_CPU_XFORM_BPF (10), arg1 = 0.
 * Globals (xdev_ext_mech_ctl attach --set): hdr, 4..256.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "compute_example.h"
#include "parse.h"

__u32 hdr = 16;

SEC("struct_ops/parse_comp")
__s32 BPF_PROG(parse_comp, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	return ex_parse_check(mctx, hdr);
}

SEC("struct_ops/parse_build")
__s32 BPF_PROG(parse_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_BUILD_DEFAULT;
}

SEC("struct_ops/parse_done")
__s32 BPF_PROG(parse_done, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops parse_check_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)parse_build,
	.complete = (void *)parse_done,
	.compute = (void *)parse_comp,
};

char LICENSE[] SEC("license") = "GPL";
