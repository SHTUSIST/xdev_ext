// SPDX-License-Identifier: GPL-2.0
/*
 * A CPU struct_ops object compiled against the layout before the compute
 * member existed: it must still load, attach and run fixed transforms.
 * libbpf matches struct_ops members by name, so the kernel's compute stays
 * NULL. Its own struct definition keeps it independent of the new headers.
 */
#include <linux/xdev_ext_mech.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct xdev_ext_cpu_mech_ops {
	__u32 abi_version;
	__u32 flags;
	__s32 (*prepare)(const struct xdev_ext_mech_ctx *ctx);
	__s32 (*build)(const struct xdev_ext_mech_ctx *ctx);
	__s32 (*complete)(const struct xdev_ext_mech_ctx *ctx);
} __attribute__((preserve_access_index));

SEC("struct_ops/old_layout_build")
__s32 BPF_PROG(old_layout_build, const struct xdev_ext_mech_ctx *mctx)
{
	return XDEV_EXT_MECH_BUILD_DEFAULT;
}

SEC("struct_ops/old_layout_complete")
__s32 BPF_PROG(old_layout_complete, const struct xdev_ext_mech_ctx *mctx)
{
	return XDEV_EXT_MECH_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops old_layout_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)old_layout_build,
	.complete = (void *)old_layout_complete,
};

char _license[] SEC("license") = "GPL";
