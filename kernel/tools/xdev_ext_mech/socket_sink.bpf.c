// SPDX-License-Identifier: GPL-2.0
/* Ordinary socket compatibility copy: one full batch per UDP datagram. */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

SEC("struct_ops/socket_sink_build")
__s32 BPF_PROG(socket_sink_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_socket_mech_info *info;
	struct xdev_ext_socket_send_desc *d;
	__u32 i;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || !info->nr_frames || info->nr_frames > 32 ||
	    !mctx->base.length || mctx->base.length > info->max_datagram)
		return XDEV_EXT_MP_BUILD_ABORT;
	for (i = 0; i < 32; i++) {
		if (i >= info->nr_frames)
			break;
		d = (void *)bpf_xdev_ext_desc(mctx, i, sizeof(*d));
		if (!d)
			return XDEV_EXT_MP_BUILD_ABORT;
		d->frame_pos = i;
		d->frame_off = info->f[i].data_off;
		d->len = info->f[i].data_len;
		d->flags = 0;
	}
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/socket_sink_complete")
__s32 BPF_PROG(socket_sink_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_socket_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	return cqe && !cqe->status && cqe->bytes_sent == mctx->base.length ?
		XDEV_EXT_MP_NEXT : XDEV_EXT_MP_ABORT;
}

SEC(".struct_ops.link")
struct xdev_ext_socket_mech_ops socket_sink_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)socket_sink_build,
	.complete = (void *)socket_sink_complete,
};
char LICENSE[] SEC("license") = "GPL";
