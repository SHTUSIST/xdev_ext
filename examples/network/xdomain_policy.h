/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Protocol-agnostic XDOMAIN completion rules, shared by the RTS/CTS program
 * (xdomain_rts_cts.bpf.c) and the early-grant program (xdomain_early.bpf.c).
 * They decide publication, link failure, ARMED cancellation, peer replies,
 * final ACK/FAIL and the bounded wake. They never bind a group: how a group is
 * announced, posted and advertised is each program's own protocol.
 *
 * The rules are the reference policy's (xdomain_peer.bpf.c) and keep its
 * order. C retains native custody, admission, checked actions and mandatory
 * safety termination; a verdict only names an intent C validates.
 */
#ifndef XDEV_EXT_XDOMAIN_POLICY_H
#define XDEV_EXT_XDOMAIN_POLICY_H

/* These errno values are Linux ABI constants, not BTF enum values. */
#define XD_POLICY_ENOLINK 67
#define XD_POLICY_EPROTO 71
#define XD_POLICY_EREMOTEIO 121
#define XD_POLICY_ETIMEDOUT 110
#define XD_POLICY_TICK_NS 20000000ULL

/* A verdict was chosen; the protocol's binding rules must decide; or no rule
 * applies and the caller ends with the bounded WAIT. */
#define XD_POLICY_DONE 0
#define XD_POLICY_BINDING 1
#define XD_POLICY_WAIT 2

struct xd_policy {
	__u32 facts;
	int tx, hard_due, policy_due;
};

/*
 * Validate a version-1 fact record (events TX_SUBMIT..DUPLICATE) and decide
 * terminal publication, link failure and ARMED cancellation. Returns DONE,
 * BINDING, or a negative error. A WITHDRAW of an announced group, which only
 * an RTS protocol creates, belongs to the caller between this and the next
 * step.
 */
static __always_inline int
xd_policy_begin(const struct xdev_ext_xdomain_proto_info *info,
		struct xdev_ext_xdomain_proto_verdict *verdict, struct xd_policy *p)
{
	__u32 facts;
	int tx, terminal;

	if (!info || !verdict || info->size != sizeof(*info) ||
	    info->version != XDEV_EXT_MP_XDOMAIN_PROTO_VERSION ||
	    info->event < XDEV_EXT_XDP_EV_TX_SUBMIT ||
	    info->event > XDEV_EXT_XDP_EV_DUPLICATE ||
	    (info->direction != XDEV_EXT_MP_DIR_TO_DEVICE &&
	     info->direction != XDEV_EXT_MP_DIR_FROM_DEVICE))
		return -EINVAL;
	*verdict = (struct xdev_ext_xdomain_proto_verdict){};
	verdict->size = sizeof(*verdict);
	verdict->version = XDEV_EXT_MP_XDOMAIN_PROTO_VERSION;
	verdict->event_id = info->event_id;
	verdict->epoch = info->epoch;
	facts = p->facts = info->facts;
	tx = p->tx = info->direction == XDEV_EXT_MP_DIR_TO_DEVICE;
	p->hard_due = info->hard_deadline_ns && info->now_ns >= info->hard_deadline_ns;
	p->policy_due = info->policy_deadline_ns && info->now_ns >= info->policy_deadline_ns;

	/* Terminal CQE truth is derived from facts, never supplied by an intent. */
	terminal = (facts & XDEV_EXT_MP_XDP_F_LOCAL_KNOWN) &&
		   !(facts & XDEV_EXT_MP_XDP_F_NATIVE_PENDING);
	if (tx)
		terminal = terminal &&
			((info->local_status != 0) ||
			 info->remote == XDEV_EXT_MP_NET_REMOTE_FAILED ||
			 info->remote == XDEV_EXT_MP_NET_REMOTE_LOST ||
			 (info->remote == XDEV_EXT_MP_NET_REMOTE_ACKED &&
			  (facts & XDEV_EXT_MP_XDP_F_LOCAL_QUIESCED)));
	/* A pre-CTS refusal proves that no local work was ever posted. */
	if (tx && !(facts & (XDEV_EXT_MP_XDP_F_NATIVE_POSTED |
			    XDEV_EXT_MP_XDP_F_NATIVE_PENDING)) &&
	    info->remote == XDEV_EXT_MP_NET_REMOTE_FAILED)
		terminal = 1;
	/* A local error does not discharge the peer's posted commitment. */
	if (tx && terminal && info->local_status &&
	    (facts & XDEV_EXT_MP_XDP_F_NATIVE_POSTED) &&
	    info->remote != XDEV_EXT_MP_NET_REMOTE_ACKED &&
	    info->remote != XDEV_EXT_MP_NET_REMOTE_FAILED &&
	    info->remote != XDEV_EXT_MP_NET_REMOTE_LOST &&
	    (info->event == XDEV_EXT_XDP_EV_LOCAL ||
	     info->event == XDEV_EXT_XDP_EV_READY)) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_POLICY_ENOLINK;
		return XD_POLICY_DONE;
	}
	if ((info->event == XDEV_EXT_XDP_EV_LOCAL ||
	     info->event == XDEV_EXT_XDP_EV_READY) && terminal &&
	    (tx || info->event != XDEV_EXT_XDP_EV_LOCAL || !info->local_status ||
	     !(facts & XDEV_EXT_MP_XDP_F_FINAL_OWED))) {
		verdict->action = XDEV_EXT_XDP_ACT_PUBLISH;
		verdict->status = info->local_status;
		if (tx && !verdict->status) {
			if (info->remote == XDEV_EXT_MP_NET_REMOTE_FAILED)
				verdict->status = -XD_POLICY_EREMOTEIO;
			else if (info->remote == XDEV_EXT_MP_NET_REMOTE_LOST)
				verdict->status = -XD_POLICY_ENOLINK;
		}
		return XD_POLICY_DONE;
	}
	if (info->event == XDEV_EXT_XDP_EV_LINK_DOWN ||
	    !(facts & XDEV_EXT_MP_XDP_F_LINK_UP) ||
	    (facts & XDEV_EXT_MP_XDP_F_STAGE_DEAD)) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_POLICY_ENOLINK;
		return XD_POLICY_DONE;
	}
	if (!tx && info->state == XDEV_EXT_MP_RDV_ARMED &&
	    info->event != XDEV_EXT_XDP_EV_RTS &&
	    info->event != XDEV_EXT_XDP_EV_CANCEL &&
	    ((facts & XDEV_EXT_MP_XDP_F_STOPPING) || p->hard_due)) {
		verdict->action = XDEV_EXT_XDP_ACT_CANCEL_ARMED;
		verdict->status = (facts & XDEV_EXT_MP_XDP_F_STOPPING) ?
			-ECANCELED : -XD_POLICY_ETIMEDOUT;
		return XD_POLICY_DONE;
	}
	return XD_POLICY_BINDING;
}

/*
 * After a missed hard deadline only link failure remains. Then decide the
 * events whose handling does not depend on how groups were bound. Returns
 * BINDING for TX_SUBMIT, RTS and CTS, which belong to the protocol, and WAIT
 * when no rule applies.
 */
static __always_inline int
xd_policy_event(const struct xdev_ext_xdomain_proto_info *info,
		struct xdev_ext_xdomain_proto_verdict *verdict, const struct xd_policy *p)
{
	__u32 facts = p->facts;
	int tx = p->tx;

	if (p->hard_due) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_POLICY_ETIMEDOUT;
		return XD_POLICY_DONE;
	}
	switch (info->event) {
	case XDEV_EXT_XDP_EV_TX_SUBMIT:
	case XDEV_EXT_XDP_EV_RTS:
	case XDEV_EXT_XDP_EV_CTS:
		return XD_POLICY_BINDING;
	case XDEV_EXT_XDP_EV_RX_SUBMIT:
		if (!tx && (facts & XDEV_EXT_MP_XDP_F_ADMITS) &&
		    !(facts & XDEV_EXT_MP_XDP_F_STOPPING)) {
			verdict->action = XDEV_EXT_XDP_ACT_RX_ARM;
			return XD_POLICY_DONE;
		}
		break;
	case XDEV_EXT_XDP_EV_HELD:
	case XDEV_EXT_XDP_EV_ACK:
	case XDEV_EXT_XDP_EV_FAIL:
		if (!tx)
			return -XD_POLICY_EPROTO;
		verdict->action = info->event == XDEV_EXT_XDP_EV_HELD ?
			XDEV_EXT_XDP_ACT_ACCEPT_HELD :
			(info->event == XDEV_EXT_XDP_EV_ACK ?
			 XDEV_EXT_XDP_ACT_ACCEPT_ACK : XDEV_EXT_XDP_ACT_ACCEPT_FAIL);
		verdict->credit = info->msg_credit;
		return XD_POLICY_DONE;
	case XDEV_EXT_XDP_EV_CANCEL:
		if (tx)
			return -XD_POLICY_EPROTO;
		if (!(facts & XDEV_EXT_MP_XDP_F_NATIVE_POSTED)) {
			verdict->action = XDEV_EXT_XDP_ACT_REJECT_RTS;
			verdict->status = info->local_status < 0 ?
				info->local_status : -ECANCELED;
			return XD_POLICY_DONE;
		}
		if (info->ctl_room) {
			verdict->action = XDEV_EXT_XDP_ACT_SEND_CTS;
			verdict->credit = info->credit;
			return XD_POLICY_DONE;
		}
		break;
	case XDEV_EXT_XDP_EV_CHAIN_END:
		if (tx)
			return -XD_POLICY_EPROTO;
		if (info->ctl_room) {
			verdict->action = info->chain_status ||
				(facts & XDEV_EXT_MP_XDP_F_CHAIN_SEQUESTERED) ?
				XDEV_EXT_XDP_ACT_SEND_FAIL : XDEV_EXT_XDP_ACT_SEND_ACK;
			verdict->credit = info->credit;
			if (verdict->action == XDEV_EXT_XDP_ACT_SEND_FAIL)
				verdict->status = info->chain_status < 0 ?
					info->chain_status : -XD_POLICY_ENOLINK;
			return XD_POLICY_DONE;
		}
		break;
	case XDEV_EXT_XDP_EV_POST_RESULT:
		if (info->local_status) {
			/* All-or-none RX rejection has no native commitment. Finish
			 * this group through FAIL; other sessions keep the link. */
			if (!tx && !(facts & XDEV_EXT_MP_XDP_F_NATIVE_POSTED) &&
			    (facts & XDEV_EXT_MP_XDP_F_FINAL_OWED)) {
				if (!info->ctl_room)
					break;
				verdict->action = XDEV_EXT_XDP_ACT_SEND_FAIL;
				verdict->status = info->local_status;
				verdict->credit = info->credit;
				return XD_POLICY_DONE;
			}
			verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
			verdict->status = info->local_status;
			return XD_POLICY_DONE;
		}
		/* A successful RX post creates the CTS obligation that advertises it. */
		if (!tx && info->ctl_room) {
			verdict->action = XDEV_EXT_XDP_ACT_SEND_CTS;
			verdict->credit = info->credit;
			return XD_POLICY_DONE;
		}
		break;
	case XDEV_EXT_XDP_EV_REPLY_DUE:
	case XDEV_EXT_XDP_EV_DUPLICATE:
		if (!tx && info->ctl_room) {
			if (facts & XDEV_EXT_MP_XDP_F_CTS_OWED) {
				verdict->action = XDEV_EXT_XDP_ACT_SEND_CTS;
				verdict->credit = info->credit;
				return XD_POLICY_DONE;
			}
			if (facts & XDEV_EXT_MP_XDP_F_FINAL_OWED) {
				verdict->action = info->chain_status || info->local_status ||
					(facts & XDEV_EXT_MP_XDP_F_CHAIN_SEQUESTERED) ?
					XDEV_EXT_XDP_ACT_SEND_FAIL : XDEV_EXT_XDP_ACT_SEND_ACK;
				verdict->credit = info->credit;
				if (verdict->action == XDEV_EXT_XDP_ACT_SEND_FAIL)
					verdict->status = info->local_status ? info->local_status :
						(info->chain_status ? info->chain_status : -XD_POLICY_ENOLINK);
				return XD_POLICY_DONE;
			}
		}
		if (info->event == XDEV_EXT_XDP_EV_DUPLICATE &&
		    !(facts & (XDEV_EXT_MP_XDP_F_CTS_OWED |
			       XDEV_EXT_MP_XDP_F_FINAL_OWED))) {
			verdict->action = XDEV_EXT_XDP_ACT_IGNORE;
			return XD_POLICY_DONE;
		}
		break;
	case XDEV_EXT_XDP_EV_LOCAL:
		/* A known RX error owes FAIL; only success waits for CHAIN_END. */
		if (!tx && (facts & XDEV_EXT_MP_XDP_F_LOCAL_KNOWN) &&
		    (facts & XDEV_EXT_MP_XDP_F_FINAL_OWED) &&
		    info->local_status < 0 && info->ctl_room) {
			verdict->action = XDEV_EXT_XDP_ACT_SEND_FAIL;
			verdict->status = info->local_status;
			verdict->credit = info->credit;
			return XD_POLICY_DONE;
		}
		break;
	case XDEV_EXT_XDP_EV_READY:
	case XDEV_EXT_XDP_EV_TIMER:
	case XDEV_EXT_XDP_EV_STOP:
		break;
	default:
		return -EINVAL;
	}
	return XD_POLICY_WAIT;
}

/* WAIT for the next bounded tick; never wrap into the past or past a deadline. */
static __always_inline int
xd_policy_wait(const struct xdev_ext_xdomain_proto_info *info,
	       struct xdev_ext_xdomain_proto_verdict *verdict)
{
	__u64 wake, max_time = ~(__u64)0;

	wake = info->now_ns > max_time - XD_POLICY_TICK_NS ?
		max_time : info->now_ns + XD_POLICY_TICK_NS;
	if (info->hard_deadline_ns > info->now_ns && info->hard_deadline_ns < wake)
		wake = info->hard_deadline_ns;
	if (info->policy_deadline_ns > info->now_ns && info->policy_deadline_ns < wake)
		wake = info->policy_deadline_ns;
	if (wake <= info->now_ns) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_POLICY_ETIMEDOUT;
		return XD_POLICY_DONE;
	}
	verdict->action = XDEV_EXT_XDP_ACT_WAIT;
	verdict->wake_ns = wake;
	return XD_POLICY_DONE;
}

/* Canonical descriptors, as the reference program builds them: one span per
 * batch frame; slot 0 of a TX batch names the group and carries the batch key
 * as eight big-endian tag bytes. */
static __always_inline int xd_policy_build(const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_xdomain_mech_info *info;
	struct xdev_ext_xdomain_desc *d;
	__u64 key = mctx->base.src_offset;
	__u32 i, j;

	info = (const void *)bpf_xdev_ext_info(mctx, sizeof(*info));
	if (!info || !info->nr_frames || info->nr_frames > XDEV_EXT_MP_MAX_FRAMES)
		return XDEV_EXT_MP_BUILD_ABORT;
	for (i = 0; i < XDEV_EXT_MP_MAX_FRAMES; i++) {
		if (i >= info->nr_frames)
			break;
		if (!info->f[i].data_len ||
		    info->f[i].data_off % XDEV_EXT_MP_XDOMAIN_MAX_FRAME)
			return XDEV_EXT_MP_BUILD_ABORT;
		d = (void *)bpf_xdev_ext_desc(mctx, i, sizeof(*d));
		if (!d)
			return XDEV_EXT_MP_BUILD_ABORT;
		*d = (struct xdev_ext_xdomain_desc){};
		d->frame_pos = i;
		d->frame_off = info->f[i].data_off;
		d->len = info->f[i].data_len;
		if (i || info->direction == XDEV_EXT_MP_DIR_FROM_DEVICE)
			continue;
		d->group = info->next_group;
		for (j = 0; j < 8; j++)
			d->tag[j] = key >> (56 - j * 8);
	}
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

/* A finished batch continues only when the whole group arrived and, for TX,
 * the receiver's chain acknowledged it. */
static __always_inline int xd_policy_cqe(const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_xdomain_mech_cqe *cqe;

	if (mctx->callsite != XDEV_EXT_MP_SITE_WORKER)
		return XDEV_EXT_MP_ABORT;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!cqe || cqe->status || cqe->outcome || cqe->bytes != mctx->base.length)
		return XDEV_EXT_MP_ABORT;
	if (mctx->base.direction == XDEV_EXT_MP_DIR_TO_DEVICE &&
	    cqe->remote != XDEV_EXT_MP_NET_REMOTE_ACKED)
		return XDEV_EXT_MP_ABORT;
	return XDEV_EXT_MP_NEXT;
}

#endif
