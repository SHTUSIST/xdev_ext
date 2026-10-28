// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe<->NIC eval policy (reviewer E3), for both session directions:
 *   forward  START -> NVMe READ of one group -> AF_XDP TX of its frames
 *   reverse  AF_XDP RX of a group's frames -> NVMe WRITE of the group
 *
 * Derived from kernel/tools/xdev_ext_mech/nxp_mech.bpf.c (product HEAD
 * 8e0238a); the wire format is the same NXP2 header.  The differences are the
 * measurement contract of tests/eval/nvme_nic:
 *   - no CRC32C on transmit or receive: the NXP2 checksum field stays zero,
 *     like every baseline arm, and payload bytes are never read by a program;
 *   - multi-frame groups of the eval geometry (nnb_wire.h);
 *   - a batch's NVMe slot wraps modulo the window's whole groups, so one
 *     window serves any number of trials;
 *   - generation = batch key (key_base 1) in both directions.
 * Provider validation, IPv4 checksum finishing, DMA synchronization and the
 * completion path are unchanged and remain inside the measured interval.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

/* Wire session this side stamps on TX and expects on RX; set before load. */
__u64 nnb_session;

static __always_inline __s32 nnb_rx_complete(const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_mech_info *info;
	struct xdev_ext_mp_rx_state *rx;
	struct xdev_ext_mp_rx_cfg cfg;
	struct xdev_ext_mp_segment seg;
	const __u8 *pkt;
	int cls;

	rx = (void *)bpf_xdev_ext_afxdp_state(mctx, sizeof(*rx));
	if (!rx)
		return XDEV_EXT_MP_ABORT;
	rx->candidate_valid = 0;
	xdev_ext_mp_rx_order_session(&rx->order, mctx->session_id);
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(struct xdev_ext_afxdp_mech_info));
	if (!info)
		return XDEV_EXT_MP_PUBLISH;
	if (info->f[0].data_len < XDEV_EXT_MP_PKT_HDR_LEN)
		return XDEV_EXT_MP_PUBLISH;
	pkt = bpf_xdev_ext_frame(mctx, 0, info->f[0].data_off, XDEV_EXT_MP_PKT_HDR_LEN);
	if (!pkt)
		return XDEV_EXT_MP_PUBLISH;

	cfg.session_id = nnb_session;
	cfg.mtu = info->mtu;
	cfg.frame_size = info->l.frame_size;
	cfg.hdr_room = info->l.hdr_room;
	cfg.seg_len = info->l.seg_len;
	cfg.group_bytes = info->l.group_bytes;
	cls = xdev_ext_mp_rx_parse(pkt, info->f[0].data_off, info->f[0].data_len,
				   &info->peer, &cfg, &seg);
	if (cls == XDEV_EXT_MP_RX_FOREIGN)
		return XDEV_EXT_MP_PUBLISH;
	/* The benchmark wire carries no checksum; a nonzero field is not ours. */
	if (cls != XDEV_EXT_MP_RX_SEGMENT ||
	    xdev_ext_mp_get_be32(pkt + XDEV_EXT_MP_NXP_OFF + XDEV_EXT_MP_NXP_CSUM_OFF))
		return XDEV_EXT_MP_RECYCLE;

	rx->candidate = rx->order;
	if (xdev_ext_mp_rx_order(&rx->candidate, &seg, bpf_ktime_get_ns()) != XDEV_EXT_MP_HOLD)
		return XDEV_EXT_MP_RECYCLE;
	if (bpf_xdev_ext_afxdp_hold(mctx, seg.generation, seg.index, seg.payload_off,
				    seg.payload_len))
		return XDEV_EXT_MP_RECYCLE;
	rx->candidate_key = seg.generation;
	rx->candidate_pos = seg.index;
	rx->candidate_valid = 1;
	return XDEV_EXT_MP_HOLD;
}

/* Commit the candidate order only after C admitted the HOLD (nxp_mech.bpf.c). */
static __always_inline __s32 nnb_rx_hold_result(const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_rx_hold_cqe *cqe;
	struct xdev_ext_mp_rx_state *rx;

	rx = (void *)bpf_xdev_ext_afxdp_state(mctx, sizeof(*rx));
	if (!rx)
		return XDEV_EXT_MP_ABORT;
	if (rx->order.session_id != mctx->session_id) {
		rx->candidate_valid = 0;
		xdev_ext_mp_rx_order_session(&rx->order, mctx->session_id);
		return XDEV_EXT_MP_ABORT;
	}
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(struct xdev_ext_afxdp_rx_hold_cqe));
	if (!cqe || !rx->candidate_valid || cqe->key != rx->candidate_key ||
	    cqe->pos != rx->candidate_pos) {
		rx->candidate_valid = 0;
		return XDEV_EXT_MP_ABORT;
	}
	rx->candidate_valid = 0;
	if (cqe->err)
		return XDEV_EXT_MP_RECYCLE;
	rx->order = rx->candidate;
	return XDEV_EXT_MP_HOLD;
}

static __always_inline __s32 nnb_tx_complete(const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_tx_cqe *cqe;
	int verdict = XDEV_EXT_MP_NEXT;
	__u32 pos;

	for (pos = 0; pos < XDEV_EXT_MP_MAX_FRAMES; pos++) {
		if (pos >= mctx->nr_frames)
			break;
		cqe = (const void *)bpf_xdev_ext_cqe(mctx, pos, sizeof(struct xdev_ext_afxdp_tx_cqe));
		if (!cqe) {
			if (!pos)
				return XDEV_EXT_MP_ABORT;
			break;
		}
		verdict = xdev_ext_mp_tx_fold(verdict, cqe->err);
	}
	return verdict;
}

SEC("struct_ops/nnb_afxdp_complete")
__s32 BPF_PROG(nnb_afxdp_complete, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	if (mctx->callsite == XDEV_EXT_MP_SITE_WORKER)
		return nnb_tx_complete(mctx);
	if (mctx->callsite == XDEV_EXT_MP_SITE_RX_HOLD_RESULT)
		return nnb_rx_hold_result(mctx);
	if (mctx->callsite != XDEV_EXT_MP_SITE_RX_GENERIC &&
	    mctx->callsite != XDEV_EXT_MP_SITE_RX_NATIVE)
		return XDEV_EXT_MP_PUBLISH;
	return nnb_rx_complete(mctx);
}

SEC("struct_ops/nnb_afxdp_build")
__s32 BPF_PROG(nnb_afxdp_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_mech_info *info;
	const struct xdev_ext_mech_frame_info *f;
	struct xdev_ext_mp_tx_seg seg;
	__u64 key = mctx->base.src_offset;
	struct xdp_desc *desc;
	__u32 pos, nr, rel = 0;
	__u8 *pkt;
	int i;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(struct xdev_ext_afxdp_mech_info));
	if (!info || !nnb_session)
		return XDEV_EXT_MP_BUILD_ABORT;
	nr = info->nr_frames;
	if (!nr || nr > XDEV_EXT_MP_MAX_FRAMES || !key || key > 0xffffffffULL)
		return XDEV_EXT_MP_BUILD_ABORT;
	seg.session_id = nnb_session;
	seg.generation = (__u32)key;
	seg.total_len = info->l.group_bytes;
	seg.count = (__u16)nr;
	bpf_for(i, 0, (int)nr) {
		pos = (__u32)i;
		if (pos >= XDEV_EXT_MP_MAX_FRAMES)
			return XDEV_EXT_MP_BUILD_ABORT;
		f = &info->f[pos];
		if (f->data_off < XDEV_EXT_MP_PKT_HDR_LEN)
			return XDEV_EXT_MP_BUILD_ABORT;
		pkt = bpf_xdev_ext_afxdp_hdr(mctx, pos, f->data_off - XDEV_EXT_MP_PKT_HDR_LEN,
					     XDEV_EXT_MP_PKT_HDR_LEN);
		desc = (void *)bpf_xdev_ext_desc(mctx, pos, sizeof(struct xdp_desc));
		if (!pkt || !desc)
			return XDEV_EXT_MP_BUILD_ABORT;
		seg.index = (__u16)pos;
		seg.relative_offset = rel;
		seg.payload_len = f->data_len;
		if (xdev_ext_mp_tx_encode(pkt, &info->peer, &seg))
			return XDEV_EXT_MP_BUILD_ABORT;
		xdev_ext_mp_tx_desc(desc, f->umem_addr, f->data_off, f->data_len);
		rel += f->data_len;
	}
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/nnb_nvme_build")
__s32 BPF_PROG(nnb_nvme_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 key = mctx->base.src_offset, blocks, slots, slba;
	__u8 *sqe;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(struct xdev_ext_nvme_mech_info));
	if (!info || !key || info->lba_shift < 9 || info->lba_shift > 31 ||
	    mctx->base.length != info->l.group_bytes)
		return XDEV_EXT_MP_BUILD_ABORT;
	blocks = info->l.group_bytes >> info->lba_shift;
	slots = blocks ? info->window_nlb / blocks : 0;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe || !slots ||
	    xdev_ext_mp_nvme_slba(info->window_slba, info->window_nlb, info->lba_shift,
				  info->l.group_bytes, (key - 1) % slots,
				  XDEV_EXT_MP_NVME_MODE_WINDOW, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba, info->l.group_bytes,
				info->lba_shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/nnb_nvme_complete")
__s32 BPF_PROG(nnb_nvme_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(struct xdev_ext_nvme_mech_cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops nnb_afxdp_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)nnb_afxdp_build,
	.complete = (void *)nnb_afxdp_complete,
};

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops nnb_nvme_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)nnb_nvme_build,
	.complete = (void *)nnb_nvme_complete,
};

char LICENSE[] SEC("license") = "GPL";
