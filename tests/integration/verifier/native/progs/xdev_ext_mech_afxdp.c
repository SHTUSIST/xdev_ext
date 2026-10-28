// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

/*
 * AF_XDP positive program: every kfunc each member may call.  TX build puts
 * an NXP header in the header room right before each frame's data and
 * points one xdp_desc at header plus data; RX complete records the hold the
 * test asks for and returns its verdict (the hold count is C's: the frames
 * per batch the caller hands xdev_ext_mech_call_active()).
 */
#define XDEV_EXT_MECH_RX_L2L4	42	/* Ethernet, IPv4 and UDP headers */

__u64 tx_session;		/* NXP session id of TX headers */
__u32 prepare_calls;
__u32 prepare_mtu;
__u32 prepare_tag_crc;
struct xdev_ext_mech_obs build_obs;
struct xdev_ext_mech_obs complete_obs;
__u32 tx_cqes;
__u32 rx_verdict;		/* enum xdev_ext_mech_next for RX */
__u64 rx_hold_key;
__u32 rx_hold_pos;
__u32 rx_hold_twice;		/* call bpf_xdev_ext_afxdp_hold() a second time */
__s32 rx_hold_ret;
__s32 rx_hold_again_ret;
__u64 rx_desc_addr;
__u32 rx_desc_len;
__u32 rx_state_visible;

SEC("struct_ops.s/prepare")
__s32 BPF_PROG(afxdp_prepare, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_mech_info *info;
	__u8 tag[8] = { 'u', 'b', 'r', '-', 'm', 'e', 'c', 'h' };

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return -EINVAL;
	prepare_calls++;
	prepare_mtu = info->mtu;
	prepare_tag_crc = bpf_xdev_ext_crc32c(tag, sizeof(tag), ~0U);
	return 0;
}

SEC("struct_ops/build")
__s32 BPF_PROG(afxdp_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_mech_info *info;
	__u8 nxp[XDEV_EXT_MECH_NXP_HDR];
	__u32 i, n, rel = 0, hdr_off;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	n = mctx->nr_frames;
	if (!info || !n || n > XDEV_EXT_MECH_MAX_FRAMES ||
	    info->l.hdr_room < XDEV_EXT_MECH_NXP_HDR)
		return XDEV_EXT_MECH_BUILD_ABORT;
	hdr_off = info->l.hdr_room - XDEV_EXT_MECH_NXP_HDR;

	for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++) {
		const struct xdev_ext_mech_frame_info *f = &info->f[i];
		struct xdp_desc *desc;
		__u8 *hdr;
		__u32 crc;

		if (i >= n)
			break;
		__builtin_memset(nxp, 0, sizeof(nxp));
		xdev_ext_mech_put_be32(nxp, XDEV_EXT_MECH_NXP_MAGIC);
		nxp[4] = XDEV_EXT_MECH_NXP_VERSION;
		nxp[5] = XDEV_EXT_MECH_NXP_HDR;
		nxp[6] = XDEV_EXT_MECH_NXP_DIR_WRITE;
		xdev_ext_mech_put_be64(nxp + 8, tx_session);
		xdev_ext_mech_put_be32(nxp + 16, mctx->base.src_offset);
		xdev_ext_mech_put_be16(nxp + 20, i);
		xdev_ext_mech_put_be16(nxp + 22, n);
		xdev_ext_mech_put_be32(nxp + 24, mctx->base.length);
		xdev_ext_mech_put_be32(nxp + 28, rel);
		xdev_ext_mech_put_be32(nxp + 32, f->data_len);
		crc = bpf_xdev_ext_crc32c(nxp, sizeof(nxp), ~0U);
		crc = bpf_xdev_ext_frame_crc32c(mctx, i, f->data_off, f->data_len,
					   crc);
		xdev_ext_mech_put_be32(nxp + XDEV_EXT_MECH_NXP_CSUM, ~crc);

		hdr = bpf_xdev_ext_afxdp_hdr(mctx, i, hdr_off, sizeof(nxp));
		desc = (void *)bpf_xdev_ext_desc(mctx, i, sizeof(*desc));
		if (!hdr || !desc)
			return XDEV_EXT_MECH_BUILD_ABORT;
		__builtin_memcpy(hdr, nxp, sizeof(nxp));
		desc->addr = f->umem_addr + hdr_off;
		desc->len = sizeof(nxp) + f->data_len;
		desc->options = 0;
		rel += f->data_len;
	}
	xdev_ext_mech_observe(mctx, &info->f[0], &build_obs);
	return XDEV_EXT_MECH_BUILD_SUBMIT;
}

/*
 * One xsk_kernel_xmit() result per frame: RETRY on -EAGAIN only.  C stops
 * at the first failed send and reports -ECANCELED for the frames after it,
 * which were not attempted.
 */
static __always_inline __s32
xdev_ext_mech_tx_complete(const struct xdev_ext_mech_ctx *mctx)
{
	__s32 next = XDEV_EXT_MECH_DONE;
	__u32 i;

	for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++) {
		const struct xdev_ext_afxdp_tx_cqe *cqe;

		if (i >= mctx->nr_frames)
			break;
		cqe = (const void *)bpf_xdev_ext_cqe(mctx, i, sizeof(*cqe));
		if (!cqe)
			return XDEV_EXT_MECH_ABORT;
		tx_cqes++;
		if (cqe->err == -EAGAIN)
			next = XDEV_EXT_MECH_RETRY;
		else if (cqe->err == -ECANCELED && next == XDEV_EXT_MECH_RETRY)
			continue;
		else if (cqe->err)
			return XDEV_EXT_MECH_ABORT;
	}
	return next;
}

static __always_inline __s32
xdev_ext_mech_rx_complete(const struct xdev_ext_mech_ctx *mctx,
		     const struct xdev_ext_mech_frame_info *f0)
{
	__u32 skip = XDEV_EXT_MECH_RX_L2L4 + XDEV_EXT_MECH_NXP_HDR;
	const struct xdp_desc *rx;

	rx_state_visible = bpf_xdev_ext_afxdp_state(mctx, XDEV_EXT_AFXDP_MECH_STATE_SIZE) != NULL;
	rx = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*rx));
	if (!rx || f0->data_len <= skip)
		return XDEV_EXT_MECH_PUBLISH;
	rx_desc_addr = rx->addr;
	rx_desc_len = rx->len;
	rx_hold_ret = bpf_xdev_ext_afxdp_hold(mctx, rx_hold_key, rx_hold_pos,
					 f0->data_off + skip,
					 f0->data_len - skip);
	if (rx_hold_twice)
		rx_hold_again_ret = bpf_xdev_ext_afxdp_hold(mctx, rx_hold_key + 1,
						       rx_hold_pos,
						       f0->data_off + skip,
						       f0->data_len - skip);
	return rx_verdict;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(afxdp_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_mech_info *info;
	int tx = mctx->callsite == XDEV_EXT_MECH_SITE_WORKER;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info)
		return tx ? XDEV_EXT_MECH_ABORT : XDEV_EXT_MECH_PUBLISH;
	xdev_ext_mech_observe(mctx, &info->f[0], &complete_obs);
	return tx ? xdev_ext_mech_tx_complete(mctx) :
		    xdev_ext_mech_rx_complete(mctx, &info->f[0]);
}

SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops afxdp_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.prepare = (void *)afxdp_prepare,
	.build = (void *)afxdp_build,
	.complete = (void *)afxdp_complete,
};

char _license[] SEC("license") = "GPL";
