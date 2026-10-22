// SPDX-License-Identifier: GPL-2.0
/*
 * NXP mechanism programs for the NIC <-> NVMe sessions (S1, S2, S3).
 *
 * nxp_afxdp_ops, AF_XDP class:
 *   complete at RX_GENERIC/RX_NATIVE - parse the 82 header bytes of a received frame,
 *     check the CRC and the group order, and hold the frame at its segment
 *     position in the batch of its generation.  Foreign traffic goes to user
 *     space; failing NXP traffic is recycled.
 *   complete at RX_HOLD_RESULT - commit the candidate order only after C
 *     admitted the HOLD. Rejected admission recycles without advancing order.
 *   build at WORKER - write Ethernet/IPv4/UDP/NXP headers in front of each
 *     frame's payload and one xdp_desc per frame.
 *   complete at WORKER - fold the per-frame transmit results.
 * nxp_nvme_ops, NVMe class:
 *   build at WORKER - one READ or WRITE of the batch at its window slot.
 *   complete at WORKER - continue on success, abort otherwise.
 *
 * Batch index k = key - key_base: an RX batch's key is its wire generation
 * and a START batch's key its sequence number, so with key_base 1 batch k
 * is generation k + 1 at group k of the NVMe window.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

/* NXP session id the peer stamps on RX and this side stamps on TX. */
__u64 nxp_session;
/* Key of batch 0. */
__u64 key_base = 1;
/* NVMe build: XDEV_EXT_MP_NVME_MODE_WINDOW, or XDEV_EXT_MP_NVME_MODE_OUTSIDE. */
__u32 nvme_mode;

static __always_inline __s32
nxp_rx_complete(const struct xdev_ext_mech_ctx *mctx)
{
	struct xdev_ext_mp_rx_state *rx;
	const struct xdev_ext_afxdp_mech_info *info;
	struct xdev_ext_mp_rx_cfg cfg;
	struct xdev_ext_mp_segment seg;
	__u8 hdr[XDEV_EXT_MP_NXP_LEN];
	const __u8 *pkt;
	__u32 data_off, data_len, crc;
	int cls;

	rx = (void *)bpf_xdev_ext_afxdp_state(mctx, sizeof(*rx));
	if (!rx)
		return XDEV_EXT_MP_ABORT;
	/* A new packet/session cannot reuse an earlier admission candidate. */
	rx->candidate_valid = 0;
	xdev_ext_mp_rx_order_session(&rx->order, mctx->session_id);
	info = (const void *)bpf_xdev_ext_info(mctx,
					  sizeof(struct xdev_ext_afxdp_mech_info));
	if (!info)
		return XDEV_EXT_MP_PUBLISH;
	data_off = info->f[0].data_off;
	data_len = info->f[0].data_len;
	if (data_len < XDEV_EXT_MP_PKT_HDR_LEN)
		return XDEV_EXT_MP_PUBLISH;
	pkt = bpf_xdev_ext_frame(mctx, 0, data_off, XDEV_EXT_MP_PKT_HDR_LEN);
	if (!pkt)
		return XDEV_EXT_MP_PUBLISH;

	cfg.session_id = nxp_session;
	cfg.mtu = info->mtu;
	cfg.frame_size = info->l.frame_size;
	cfg.hdr_room = info->l.hdr_room;
	cfg.seg_len = info->l.seg_len;
	cfg.group_bytes = info->l.group_bytes;
	cls = xdev_ext_mp_rx_parse(pkt, data_off, data_len, &info->peer, &cfg, &seg);
	if (cls == XDEV_EXT_MP_RX_FOREIGN)
		return XDEV_EXT_MP_PUBLISH;
	if (cls != XDEV_EXT_MP_RX_SEGMENT)
		return XDEV_EXT_MP_RECYCLE;

	xdev_ext_mp_nxp_crc_prep(hdr, pkt + XDEV_EXT_MP_NXP_OFF);
	crc = bpf_xdev_ext_crc32c(hdr, sizeof(hdr), XDEV_EXT_MP_CRC32C_SEED);
	crc = bpf_xdev_ext_frame_crc32c(mctx, 0, seg.payload_off, seg.payload_len,
				   crc);
	if (!xdev_ext_mp_nxp_crc_ok(pkt + XDEV_EXT_MP_NXP_OFF, crc))
		return XDEV_EXT_MP_RECYCLE;

	rx->candidate = rx->order;
	if (xdev_ext_mp_rx_order(&rx->candidate, &seg, bpf_ktime_get_ns()) !=
	    XDEV_EXT_MP_HOLD)
		return XDEV_EXT_MP_RECYCLE;
	if (bpf_xdev_ext_afxdp_hold(mctx, seg.generation, seg.index,
			       seg.payload_off, seg.payload_len))
		return XDEV_EXT_MP_RECYCLE;
	rx->candidate_key = seg.generation;
	rx->candidate_pos = seg.index;
	rx->candidate_valid = 1;
	return XDEV_EXT_MP_HOLD;
}

static __always_inline __s32
nxp_rx_hold_result(const struct xdev_ext_mech_ctx *mctx)
{
	struct xdev_ext_mp_rx_state *rx;
	const struct xdev_ext_afxdp_rx_hold_cqe *cqe;

	rx = (void *)bpf_xdev_ext_afxdp_state(mctx, sizeof(*rx));
	if (!rx)
		return XDEV_EXT_MP_ABORT;

	if (rx->order.session_id != mctx->session_id) {
		rx->candidate_valid = 0;
		xdev_ext_mp_rx_order_session(&rx->order, mctx->session_id);
		return XDEV_EXT_MP_ABORT;
	}
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0,
					 sizeof(struct xdev_ext_afxdp_rx_hold_cqe));
	if (!cqe || !rx->candidate_valid ||
	    cqe->key != rx->candidate_key || cqe->pos != rx->candidate_pos) {
		rx->candidate_valid = 0;
		return XDEV_EXT_MP_ABORT;
	}
	/* Consume once, including admission rejection. Never roll back committed order. */
	rx->candidate_valid = 0;
	if (cqe->err)
		return XDEV_EXT_MP_RECYCLE;
	rx->order = rx->candidate;
	return XDEV_EXT_MP_HOLD;
}

static __always_inline __s32
nxp_tx_complete(const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_tx_cqe *cqe;
	int verdict = XDEV_EXT_MP_NEXT;
	__u32 pos;

	/* One copy per frame; a shorter list ends the fold. */
	for (pos = 0; pos < XDEV_EXT_MP_MAX_FRAMES; pos++) {
		if (pos >= mctx->nr_frames)
			break;
		cqe = (const void *)bpf_xdev_ext_cqe(mctx, pos,
						sizeof(struct xdev_ext_afxdp_tx_cqe));
		if (!cqe) {
			if (!pos)
				return XDEV_EXT_MP_ABORT;
			break;
		}
		verdict = xdev_ext_mp_tx_fold(verdict, cqe->err);
	}
	return verdict;
}

SEC("struct_ops/nxp_afxdp_complete")
__s32 BPF_PROG(nxp_afxdp_complete, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	if (mctx->callsite == XDEV_EXT_MP_SITE_WORKER)
		return nxp_tx_complete(mctx);
	if (mctx->callsite == XDEV_EXT_MP_SITE_RX_HOLD_RESULT)
		return nxp_rx_hold_result(mctx);
	if (mctx->callsite != XDEV_EXT_MP_SITE_RX_GENERIC &&
	    mctx->callsite != XDEV_EXT_MP_SITE_RX_NATIVE)
		return XDEV_EXT_MP_PUBLISH;
	return nxp_rx_complete(mctx);
}

SEC("struct_ops/nxp_afxdp_build")
__s32 BPF_PROG(nxp_afxdp_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_afxdp_mech_info *info;
	const struct xdev_ext_mech_frame_info *f;
	struct xdev_ext_mp_tx_seg seg;
	__u8 hdr[XDEV_EXT_MP_NXP_LEN];
	__u64 key = mctx->base.src_offset;
	struct xdp_desc *desc;
	__u32 pos, nr, rel = 0, crc;
	__u8 *pkt;
	int i;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx,
					  sizeof(struct xdev_ext_afxdp_mech_info));
	if (!info)
		return XDEV_EXT_MP_BUILD_ABORT;
	nr = info->nr_frames;
	if (!nr || nr > XDEV_EXT_MP_MAX_FRAMES || key < key_base ||
	    key - key_base >= 0xffffffffULL)
		return XDEV_EXT_MP_BUILD_ABORT;

	seg.session_id = nxp_session;
	seg.generation = (__u32)(key - key_base) + 1;
	seg.total_len = info->l.group_bytes;
	seg.count = (__u16)nr;
	/*
	 * An open-coded iterator, so the verifier checks the body once with
	 * pos unknown; a counted loop made it walk one copy per possible frame
	 * and passed the 1M instruction limit.
	 */
	bpf_for(i, 0, (int)nr) {
		pos = (__u32)i;
		if (pos >= XDEV_EXT_MP_MAX_FRAMES)
			return XDEV_EXT_MP_BUILD_ABORT;
		f = &info->f[pos];
		if (f->data_off < XDEV_EXT_MP_PKT_HDR_LEN)
			return XDEV_EXT_MP_BUILD_ABORT;
		pkt = bpf_xdev_ext_afxdp_hdr(mctx, pos,
					f->data_off - XDEV_EXT_MP_PKT_HDR_LEN,
					XDEV_EXT_MP_PKT_HDR_LEN);
		if (!pkt)
			return XDEV_EXT_MP_BUILD_ABORT;
		seg.index = (__u16)pos;
		seg.relative_offset = rel;
		seg.payload_len = f->data_len;
		if (xdev_ext_mp_tx_encode(pkt, &info->peer, &seg))
			return XDEV_EXT_MP_BUILD_ABORT;

		xdev_ext_mp_nxp_crc_prep(hdr, pkt + XDEV_EXT_MP_NXP_OFF);
		crc = bpf_xdev_ext_crc32c(hdr, sizeof(hdr), XDEV_EXT_MP_CRC32C_SEED);
		crc = bpf_xdev_ext_frame_crc32c(mctx, pos, f->data_off, f->data_len,
					   crc);
		xdev_ext_mp_nxp_crc_store(pkt + XDEV_EXT_MP_NXP_OFF, crc);

		desc = (void *)bpf_xdev_ext_desc(mctx, pos, sizeof(struct xdp_desc));
		if (!desc)
			return XDEV_EXT_MP_BUILD_ABORT;
		xdev_ext_mp_tx_desc(desc, f->umem_addr, f->data_off, f->data_len);
		rel += f->data_len;
	}
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/nxp_nvme_build")
__s32 BPF_PROG(nxp_nvme_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 key = mctx->base.src_offset;
	__u64 bytes = mctx->base.length;
	__u64 slba;
	__u8 *sqe;

	(void)ctx;
	info = (const void *)bpf_xdev_ext_info(mctx,
					  sizeof(struct xdev_ext_nvme_mech_info));
	if (!info)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe || key < key_base || bytes > 0xffffffffULL)
		return XDEV_EXT_MP_BUILD_ABORT;
	if (xdev_ext_mp_nvme_slba(info->window_slba, info->window_nlb,
			     info->lba_shift, info->l.group_bytes,
			     key - key_base, nvme_mode, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba, (__u32)bytes,
			   info->lba_shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/nxp_nvme_complete")
__s32 BPF_PROG(nxp_nvme_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	(void)ctx;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0,
					sizeof(struct xdev_ext_nvme_mech_cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops nxp_afxdp_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)nxp_afxdp_build,
	.complete = (void *)nxp_afxdp_complete,
};

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops nxp_nvme_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.build = (void *)nxp_nvme_build,
	.complete = (void *)nxp_nvme_complete,
};

char LICENSE[] SEC("license") = "GPL";
