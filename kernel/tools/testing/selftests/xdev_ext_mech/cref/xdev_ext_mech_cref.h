/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CREF_H
#define XDEV_EXT_MECH_CREF_H

/*
 * C reference callbacks of the measurement arm C (plan section 6.1): the
 * programs of tools/xdev_ext_mech/nxp_mech.bpf.c line for line, on the same pure
 * helpers (tools/xdev_ext_mech/xdev_ext_mech_prog.h) and the same views, so arm C
 * differs from arm E only in the language of the callbacks.
 *
 * Configuration globals become struct xdev_ext_mech_cref_state; RX protocol state
 * belongs to the AF_XDP stage through the exported state accessor. The includer
 * supplies, before this header:
 *   - the UAPI types, xdev_ext_mech_prog.h and net/xdp/xsk_xdev_ext_mech_core.h;
 *   - the six shared kfuncs bpf_xdev_ext_info(), bpf_xdev_ext_desc(), bpf_xdev_ext_cqe(),
 *     bpf_xdev_ext_frame(), bpf_xdev_ext_frame_crc32c() and bpf_xdev_ext_crc32c(), which
 *     the kernel exports for C callers of the same checks;
 *   - the exported bpf_xdev_ext_afxdp_state() accessor for per-stage RX state;
 *   - XDEV_EXT_MECH_CREF_CALL_OF(ctx), the call envelope of a callback ctx
 *     (xdev_ext_mech_call_of() in the kernel), for the two AF_XDP kfuncs, which
 *     are built in and not exported: xdev_ext_mech_cref_afxdp_hdr() and
 *     xdev_ext_mech_cref_afxdp_hold() below repeat bpf_xdev_ext_afxdp_hdr() and
 *     bpf_xdev_ext_afxdp_hold() of net/xdp/xsk_xdev_ext_mech.c on that envelope;
 *   - xdev_ext_mech_cref_now_ns(), the clock bpf_ktime_get_ns() reads.
 * The kernel module (xdev_ext_mech_cref.c) installs these callbacks with
 * xdev_ext_mech_set_c_ops(); xdev_ext_mech_cref_test.c runs them and the BPF programs
 * compiled as host C on the same inputs and requires identical bytes and
 * return values.
 */

/* bpf_xdev_ext_afxdp_hdr(): a writable view inside frame @pos's header room. */
static inline __u8 *xdev_ext_mech_cref_afxdp_hdr(const struct xdev_ext_mech_ctx *ctx,
					    __u32 pos, __u32 off,
					    const size_t rdwr_buf_size)
{
	__typeof__(XDEV_EXT_MECH_CREF_CALL_OF(ctx)) c = XDEV_EXT_MECH_CREF_CALL_OF(ctx);

	if (!c || !c->frames ||
	    !xsk_xdev_ext_mech_hdr_ok(c->ctx.class_id, c->member, c->callsite, pos,
				 c->nr_frames, off, rdwr_buf_size,
				 c->hdr_room))
		return NULL;
	return (__u8 *)c->frames[pos].kaddr + off;
}

/* bpf_xdev_ext_afxdp_hold(): record the hold intent once, at an RX complete. */
static inline int xdev_ext_mech_cref_afxdp_hold(const struct xdev_ext_mech_ctx *ctx,
					   __u64 key, __u32 pos,
					   __u32 span_off, __u32 span_len)
{
	__typeof__(XDEV_EXT_MECH_CREF_CALL_OF(ctx)) c = XDEV_EXT_MECH_CREF_CALL_OF(ctx);
	int err;

	if (!c)
		return -EINVAL;
	err = xsk_xdev_ext_mech_hold_record(c->ctx.class_id, c->member,
				       c->callsite, &c->hold_calls);
	if (err) {
		c->protocol_error = 1;
		return err;
	}
	c->hold = (struct xdev_ext_mech_hold_intent) {
		.key = key,
		.pos = pos,
		.count = c->batch_frames,
		.span_off = span_off,
		.span_len = span_len,
	};
	return 0;
}

struct xdev_ext_mech_cref_state {
	/* NXP session id the peer stamps on RX and this side stamps on TX. */
	__u64 nxp_session;
	/* Key of batch 0. */
	__u64 key_base;
	/* NVMe build: XDEV_EXT_MP_NVME_MODE_WINDOW, or XDEV_EXT_MP_NVME_MODE_OUTSIDE. */
	__u32 nvme_mode;
};

/* nxp_rx_complete() */
static inline __s32
xdev_ext_mech_cref_rx_complete(struct xdev_ext_mech_cref_state *g,
                          const struct xdev_ext_mech_ctx *mctx)
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

	cfg.session_id = g->nxp_session;
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
	if (xdev_ext_mp_rx_order(&rx->candidate, &seg, xdev_ext_mech_cref_now_ns()) !=
	    XDEV_EXT_MP_HOLD)
		return XDEV_EXT_MP_RECYCLE;
	if (xdev_ext_mech_cref_afxdp_hold(mctx, seg.generation, seg.index,
			       seg.payload_off, seg.payload_len))
		return XDEV_EXT_MP_RECYCLE;
	rx->candidate_key = seg.generation;
	rx->candidate_pos = seg.index;
	rx->candidate_valid = 1;
	return XDEV_EXT_MP_HOLD;
}

static inline __s32
xdev_ext_mech_cref_rx_hold_result(const struct xdev_ext_mech_ctx *mctx)
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

/* nxp_tx_complete() */
static inline __s32
xdev_ext_mech_cref_tx_complete(const struct xdev_ext_mech_ctx *mctx)
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

/* nxp_afxdp_complete() */
static inline __s32
xdev_ext_mech_cref_afxdp_complete(struct xdev_ext_mech_cref_state *g,
			     const struct xdev_ext_mech_ctx *mctx)
{
	if (mctx->callsite == XDEV_EXT_MP_SITE_WORKER)
		return xdev_ext_mech_cref_tx_complete(mctx);
	if (mctx->callsite == XDEV_EXT_MP_SITE_RX_HOLD_RESULT)
		return xdev_ext_mech_cref_rx_hold_result(mctx);
	if (mctx->callsite != XDEV_EXT_MP_SITE_RX_GENERIC &&
	    mctx->callsite != XDEV_EXT_MP_SITE_RX_NATIVE)
		return XDEV_EXT_MP_PUBLISH;
	return xdev_ext_mech_cref_rx_complete(g, mctx);
}

/* nxp_afxdp_build() */
static inline __s32
xdev_ext_mech_cref_afxdp_build(struct xdev_ext_mech_cref_state *g,
			  const struct xdev_ext_mech_ctx *mctx)
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

	info = (const void *)bpf_xdev_ext_info(mctx,
					  sizeof(struct xdev_ext_afxdp_mech_info));
	if (!info)
		return XDEV_EXT_MP_BUILD_ABORT;
	nr = info->nr_frames;
	if (!nr || nr > XDEV_EXT_MP_MAX_FRAMES || key < g->key_base ||
	    key - g->key_base >= 0xffffffffULL)
		return XDEV_EXT_MP_BUILD_ABORT;

	seg.session_id = g->nxp_session;
	seg.generation = (__u32)(key - g->key_base) + 1;
	seg.total_len = info->l.group_bytes;
	seg.count = (__u16)nr;
	/* bpf_for(i, 0, (int)nr) */
	for (i = 0; i < (int)nr; i++) {
		pos = (__u32)i;
		if (pos >= XDEV_EXT_MP_MAX_FRAMES)
			return XDEV_EXT_MP_BUILD_ABORT;
		f = &info->f[pos];
		if (f->data_off < XDEV_EXT_MP_PKT_HDR_LEN)
			return XDEV_EXT_MP_BUILD_ABORT;
		pkt = xdev_ext_mech_cref_afxdp_hdr(mctx, pos,
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

/* nxp_nvme_build() */
static inline __s32
xdev_ext_mech_cref_nvme_build(struct xdev_ext_mech_cref_state *g,
			 const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_info *info;
	__u64 key = mctx->base.src_offset;
	__u64 bytes = mctx->base.length;
	__u64 slba;
	__u8 *sqe;

	info = (const void *)bpf_xdev_ext_info(mctx,
					  sizeof(struct xdev_ext_nvme_mech_info));
	if (!info)
		return XDEV_EXT_MP_BUILD_ABORT;
	sqe = bpf_xdev_ext_desc(mctx, 0, XDEV_EXT_MP_NVME_DESC_SIZE);
	if (!sqe || key < g->key_base || bytes > 0xffffffffULL)
		return XDEV_EXT_MP_BUILD_ABORT;
	if (xdev_ext_mp_nvme_slba(info->window_slba, info->window_nlb,
			     info->lba_shift, info->l.group_bytes,
			     key - g->key_base, g->nvme_mode, &slba) ||
	    xdev_ext_mp_nvme_rw(sqe, mctx->base.direction, slba, (__u32)bytes,
			   info->lba_shift))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

/* nxp_nvme_complete() */
static inline __s32
xdev_ext_mech_cref_nvme_complete(const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_nvme_mech_cqe *cqe;

	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0,
					sizeof(struct xdev_ext_nvme_mech_cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	return xdev_ext_mp_nvme_next(mctx->callsite, cqe->status, cqe->err);
}

#endif /* XDEV_EXT_MECH_CREF_H */
