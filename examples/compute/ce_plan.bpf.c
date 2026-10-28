// SPDX-License-Identifier: GPL-2.0
/*
 * Copy-engine mechanism program (S3).  build writes one copy-plan entry per
 * batch frame: the frame's data span to consecutive device offsets of the
 * batch's group slot in the bound window, with the completion point on the
 * last entry.  complete continues on OK, retries a pre-submit failure and
 * aborts otherwise; C sequesters an ambiguous batch whatever it returns.
 * The same plan serves host-to-device and device-to-host stages, so a
 * round trip lands each byte back where it came from.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

SEC("struct_ops/ce_plan_build")
__s32 BPF_PROG(ce_plan_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_info *info;
	const struct xdev_ext_mech_frame_info *f;
	struct xdev_ext_ce_copy_desc *desc;
	__u64 gpu_off;
	__u32 pos, nr;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(struct xdev_ext_ce_mech_info));
	if (!info)
		return XDEV_EXT_MP_BUILD_ABORT;
	nr = info->nr_frames;
	if (!nr || nr > XDEV_EXT_MP_MAX_FRAMES || !info->lease_generation ||
	    !info->window_depth || info->window_slot >= info->window_depth ||
	    !info->l.group_bytes ||
	    info->window_depth > info->gpu_window_len / info->l.group_bytes ||
	    xdev_ext_mp_ce_base(info->window_slot, info->l.group_bytes,
			   info->gpu_window_len, &gpu_off))
		return XDEV_EXT_MP_BUILD_ABORT;
	for (pos = 0; pos < XDEV_EXT_MP_MAX_FRAMES; pos++) {
		if (pos >= nr)
			break;
		f = &info->f[pos];
		desc = (void *)bpf_xdev_ext_desc(mctx, pos,
					    sizeof(struct xdev_ext_ce_copy_desc));
		if (!desc)
			return XDEV_EXT_MP_BUILD_ABORT;
		if (xdev_ext_mp_ce_entry(desc, pos, nr, f->data_off, f->data_len,
				    gpu_off, info->gpu_window_len,
				    info->gpu_seg_size, info->max_entry_len))
			return XDEV_EXT_MP_BUILD_ABORT;
		gpu_off += f->data_len;
	}
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/ce_plan_complete")
__s32 BPF_PROG(ce_plan_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_ce_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0,
					sizeof(struct xdev_ext_ce_mech_cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_ce_next(cqe->outcome);
}

SEC(".struct_ops.link")
struct xdev_ext_ce_mech_ops ce_plan_ops = {
	.abi_version = XDEV_EXT_MP_CE_ABI_VERSION,
	.build = (void *)ce_plan_build,
	.complete = (void *)ce_plan_complete,
};

char LICENSE[] SEC("license") = "GPL";
