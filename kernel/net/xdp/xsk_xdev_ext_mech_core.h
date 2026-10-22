/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NET_XDP_XSK_XDEV_EXT_MECH_CORE_H
#define _NET_XDP_XSK_XDEV_EXT_MECH_CORE_H

/*
 * Pure rules of the AF_XDP mechanism class: which socket may back a
 * session's frame pool, which fill-ring addresses the allocator accepts
 * while a session uses the UMEM, and the bounds of the two AF_XDP kfuncs.
 * No locking here; net/xdp and tools/testing/selftests/xsk_xdev_ext compile the
 * same code.
 */

#include "../../io_uring/xdev_ext_mech_core.h"

/* What CREATE reads from the AF_XDP socket behind an xsk pool. */
struct xsk_xdev_ext_mech_sock_facts {
	bool bound;
	bool zero_copy;
	bool unaligned;
	bool owned;		/* a session already uses the UMEM */
	__u32 pool_users;
	__u32 umem_users;
	__u32 fq_entries;	/* filled and not yet released by the kernel */
	__u32 tx_entries;
	__u32 cq_entries;
	bool fq_used;
	__u32 rx_entries;	/* reserved or published, not yet consumed */
	__u32 chunk_size;
	__u32 chunks;
};

/*
 * A session takes an aligned copy- or zero-copy UMEM that no other socket or session
 * shares, with empty fill and RX rings, chunked as the session layout says.
 */
static inline int xsk_xdev_ext_mech_pool_admit(const struct xsk_xdev_ext_mech_sock_facts *f,
					  const struct xdev_ext_mech_layout *l)
{
	int nr;

	if (!f->bound)
		return -ENXIO;
	if (f->unaligned)
		return -EOPNOTSUPP;
	if (f->owned || f->pool_users > 1 || f->umem_users > 1 ||
	    f->fq_entries || f->rx_entries || f->tx_entries ||
	    f->cq_entries || (f->zero_copy && f->fq_used))
		return -EBUSY;
	if (l->frame_size != f->chunk_size || !f->chunks)
		return -EINVAL;
	nr = xdev_ext_mech_layout_frames(l);
	return nr < 0 ? nr : 0;
}

/*
 * An AF_XDP stage on the pool's socket.  RX feeds the chain, so it is
 * stage 0; TX may sit anywhere.  Either needs the socket bound with the
 * ring it uses (RX ring, or the TX ring xsk_kernel_xmit() requires), and a
 * socket carries at most one stage per direction.
 */
static inline int xsk_xdev_ext_mech_stage_check(__u32 direction, __u32 index,
					   bool bound, bool has_ring,
					   bool taken)
{
	if (direction == XDEV_EXT_MECH_DIR_FROM_DEVICE ? index != 0 :
	    direction != XDEV_EXT_MECH_DIR_TO_DEVICE)
		return -EINVAL;
	if (!bound || !has_ring)
		return -ENXIO;
	return taken ? -EBUSY : 0;
}

/* XDP_SHARED_UMEM onto a socket whose UMEM a session uses. */
static inline int xsk_xdev_ext_mech_share_check(bool owned)
{
	return owned ? -EBUSY : 0;
}

/*
 * Fill-ring address of chunk @idx.  Without a session (@state NULL) every
 * address is the user's; with one, only a USER chunk is.  A frame the
 * session holds, has in flight, keeps in its free partition or sequestered
 * is counted as an invalid descriptor instead of being received into.
 */
static inline bool xsk_xdev_ext_mech_fq_ok(const __u8 *state, __u64 nr, __u64 idx)
{
	if (!state)
		return true;
	return idx < nr && xdev_ext_mech_frame_state(&state[idx]) == XDEV_EXT_MECH_F_USER;
}

/*
 * Source batches draw frames from the pool only when no RX path allocates
 * from it, so the session worker is the pool's only allocator.
 */
static inline int xsk_xdev_ext_mech_source_ok(bool has_rx_ring)
{
	return has_rx_ring ? -EOPNOTSUPP : 0;
}

/*
 * bpf_xdev_ext_afxdp_hdr(): [off, off + size) of batch frame @pos must lie in
 * the frame's header room [0, hdr_room), during an AF_XDP TX build.
 */
static inline bool xsk_xdev_ext_mech_hdr_ok(__u32 class_id, __u32 member,
				       __u32 callsite, __u32 pos,
				       __u32 nr_frames, __u32 off, __u64 size,
				       __u32 hdr_room)
{
	return class_id == XDEV_EXT_MECH_CLASS_AFXDP &&
	       member == XDEV_EXT_MECH_MEMBER_BUILD &&
	       callsite == XDEV_EXT_MECH_SITE_WORKER && pos < nr_frames && size &&
	       xdev_ext_mech_span_in(off, size, hdr_room);
}

/*
 * bpf_xdev_ext_afxdp_hold(): only an AF_XDP RX complete records an intent, and
 * only once per callback.  *@hold_calls counts every call (saturating).
 */
static inline int xsk_xdev_ext_mech_hold_record(__u32 class_id, __u32 member,
					   __u32 callsite, __u8 *hold_calls)
{
	if (class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
	    member != XDEV_EXT_MECH_MEMBER_COMPLETE ||
	    (callsite != XDEV_EXT_MECH_SITE_RX_GENERIC &&
	     callsite != XDEV_EXT_MECH_SITE_RX_NATIVE))
		return -EINVAL;
	if (*hold_calls) {
		if (*hold_calls < 255)
			(*hold_calls)++;
		return -EALREADY;
	}
	*hold_calls = 1;
	return 0;
}

/*
 * A single-buffer frame on a session socket runs the AF_XDP complete
 * program at RX_GENERIC, or RX_NATIVE on a zero-copy socket, under
 * pool->rx_lock. Native copy compatibility publishes without a callback,
 * and only while the session admits batches and the stage is alive.
 */
static inline bool xsk_xdev_ext_mech_rx_runs(__u32 callsite, bool live, bool zero_copy)
{
	return live && (callsite == XDEV_EXT_MECH_SITE_RX_GENERIC ||
		       (callsite == XDEV_EXT_MECH_SITE_RX_NATIVE && zero_copy));
}

/*
 * What C does with the received frame once the callback has returned:
 * XDEV_EXT_MECH_HOLD, XDEV_EXT_MECH_RECYCLE or XDEV_EXT_MECH_PUBLISH.  HOLD needs a HOLD
 * return and a recorded intent whose span lies inside the packet bytes
 * [data_off, data_off + data_len) of the chunk; any other intent is
 * dropped. A failed callback, an illegal
 * return or a HOLD without a valid intent publishes and counts a protocol
 * error.
 */
static inline __s32 xsk_xdev_ext_mech_rx_verdict(__u32 callsite, bool ran,
					    int call_err, __s32 ret,
					    const struct xdev_ext_mech_hold_intent *hold,
					    __u32 data_off, __u32 data_len,
					    bool *protocol_err,
					    bool *native_publish)
{
	bool intent_ok;

	*protocol_err = false;
	*native_publish = false;
	if (callsite == XDEV_EXT_MECH_SITE_RX_GENERIC ||
	    callsite == XDEV_EXT_MECH_SITE_RX_NATIVE) {
		if (!ran || call_err) {
			*protocol_err = !!call_err;
			*native_publish = callsite == XDEV_EXT_MECH_SITE_RX_NATIVE;
			return XDEV_EXT_MECH_PUBLISH;
		}
	}
	intent_ok = hold->count &&
		    !xdev_ext_mech_hold_check(hold->pos, hold->count, hold->span_off,
					 hold->span_len, data_off, data_len);
	return xdev_ext_mech_rx_resolve(callsite, ret, intent_ok, protocol_err,
				   native_publish);
}

/*
 * Ownership is decided before RX_HOLD_RESULT runs. An old program may
 * return PUBLISH as a no-op at this new site; it cannot publish a held
 * frame or expose a rejected payload. A malformed callback stops the
 * session, while successful admission still retains its batch ownership.
 */
#define XSK_XDEV_EXT_MECH_RX_HOLD_RESULT 1
static inline __s32 xsk_xdev_ext_mech_rx_hold_result(int admission_err,
					     int callback_err, __s32 ret,
					     bool *protocol_err)
{
	*protocol_err = callback_err ||
		!xdev_ext_mech_ret_legal(XDEV_EXT_MECH_CLASS_AFXDP,
				    XDEV_EXT_MECH_MEMBER_COMPLETE,
				    XDEV_EXT_MECH_SITE_RX_HOLD_RESULT, ret);
	return admission_err ? XDEV_EXT_MECH_RECYCLE : XDEV_EXT_MECH_HOLD;
}

/*
 * A frame leaves the RX path of a session UMEM: published (@to_user, the
 * word becomes USER) or back on free_list (the word becomes K_FREE, so the
 * user cannot hand it in again).  Returns 0 when the word already says so,
 * 1 with the edge in *@from / *@to, -EPROTO when another owner has it.
 */
static inline int xsk_xdev_ext_mech_settle_edge(__u8 cur, bool to_user,
					   __u32 *from, __u32 *to)
{
	__u32 want = to_user ? XDEV_EXT_MECH_F_USER : XDEV_EXT_MECH_F_K_FREE;

	if (cur == want)
		return 0;
	if (cur != XDEV_EXT_MECH_F_USER && cur != XDEV_EXT_MECH_F_K_FREE &&
	    cur != XDEV_EXT_MECH_F_NIC_RX)
		return -EPROTO;
	*from = cur;
	*to = want;
	return 1;
}

#endif /* _NET_XDP_XSK_XDEV_EXT_MECH_CORE_H */
