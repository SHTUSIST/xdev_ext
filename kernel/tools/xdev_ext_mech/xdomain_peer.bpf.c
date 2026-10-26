// SPDX-License-Identifier: GPL-2.0
/*
 * Reference XDOMAIN descriptor and bounded protocol policy. C retains native
 * custody, admission, checked actions and mandatory safety termination.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

#ifndef XDEV_EXT_XDOMAIN_OBSERVE_BUILD
#define XDEV_EXT_XDOMAIN_OBSERVE_BUILD(ctx, info) 0
#endif
#ifndef XDEV_EXT_XDOMAIN_OBSERVE_CQE
#define XDEV_EXT_XDOMAIN_OBSERVE_CQE(ctx, cqe) 0
#endif

/* These errno values are Linux ABI constants, not BTF enum values. */
#define XD_ENOLINK 67
#define XD_EPROTO 71
#define XD_EREMOTEIO 121
#define XD_ETIMEDOUT 110

static __always_inline int
xdomain_peer_choose(const struct xdev_ext_xdomain_proto_info *info,
		    struct xdev_ext_xdomain_proto_verdict *verdict)
{
	__u64 wake, max_time = ~(__u64)0;
	__u32 facts;
	int tx, hard_due, policy_due, terminal;

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
	facts = info->facts;
	tx = info->direction == XDEV_EXT_MP_DIR_TO_DEVICE;
	hard_due = info->hard_deadline_ns && info->now_ns >= info->hard_deadline_ns;
	policy_due = info->policy_deadline_ns && info->now_ns >= info->policy_deadline_ns;

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
		verdict->status = -XD_ENOLINK;
		return 0;
	}
	if ((info->event == XDEV_EXT_XDP_EV_LOCAL ||
	     info->event == XDEV_EXT_XDP_EV_READY) && terminal &&
	    (tx || info->event != XDEV_EXT_XDP_EV_LOCAL || !info->local_status ||
	     !(facts & XDEV_EXT_MP_XDP_F_FINAL_OWED))) {
		verdict->action = XDEV_EXT_XDP_ACT_PUBLISH;
		verdict->status = info->local_status;
		if (tx && !verdict->status) {
			if (info->remote == XDEV_EXT_MP_NET_REMOTE_FAILED)
				verdict->status = -XD_EREMOTEIO;
			else if (info->remote == XDEV_EXT_MP_NET_REMOTE_LOST)
				verdict->status = -XD_ENOLINK;
		}
		return 0;
	}
	if (info->event == XDEV_EXT_XDP_EV_LINK_DOWN ||
	    !(facts & XDEV_EXT_MP_XDP_F_LINK_UP) ||
	    (facts & XDEV_EXT_MP_XDP_F_STAGE_DEAD)) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_ENOLINK;
		return 0;
	}
	if (!tx && info->state == XDEV_EXT_MP_RDV_ARMED &&
	    info->event != XDEV_EXT_XDP_EV_RTS &&
	    info->event != XDEV_EXT_XDP_EV_CANCEL &&
	    ((facts & XDEV_EXT_MP_XDP_F_STOPPING) || hard_due)) {
		verdict->action = XDEV_EXT_XDP_ACT_CANCEL_ARMED;
		verdict->status = (facts & XDEV_EXT_MP_XDP_F_STOPPING) ?
			-ECANCELED : -XD_ETIMEDOUT;
		return 0;
	}
	if (tx && info->state == XDEV_EXT_MP_RDV_ANNOUNCED &&
	    !(facts & (XDEV_EXT_MP_XDP_F_NATIVE_POSTED |
		       XDEV_EXT_MP_XDP_F_WITHDRAWN)) &&
	    info->event != XDEV_EXT_XDP_EV_CTS &&
	    info->event != XDEV_EXT_XDP_EV_FAIL &&
	    (hard_due || policy_due || (facts & XDEV_EXT_MP_XDP_F_STOPPING))) {
		verdict->action = XDEV_EXT_XDP_ACT_WITHDRAW;
		return 0;
	}
	if (hard_due) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_ETIMEDOUT;
		return 0;
	}
	switch (info->event) {
	case XDEV_EXT_XDP_EV_TX_SUBMIT:
		if (tx && (facts & XDEV_EXT_MP_XDP_F_ADMITS) &&
		    !(facts & XDEV_EXT_MP_XDP_F_STOPPING) &&
		    info->next_group < info->credit && info->ctl_room) {
			verdict->action = XDEV_EXT_XDP_ACT_TX_ANNOUNCE;
			return 0;
		}
		break;
	case XDEV_EXT_XDP_EV_RX_SUBMIT:
		if (!tx && (facts & XDEV_EXT_MP_XDP_F_ADMITS) &&
		    !(facts & XDEV_EXT_MP_XDP_F_STOPPING)) {
			verdict->action = XDEV_EXT_XDP_ACT_RX_ARM;
			return 0;
		}
		break;
	case XDEV_EXT_XDP_EV_RTS:
		if (tx)
			return -XD_EPROTO;
		if (facts & (XDEV_EXT_MP_XDP_F_RTS_CANCELED |
			     XDEV_EXT_MP_XDP_F_STOPPING) || info->local_status) {
			verdict->action = XDEV_EXT_XDP_ACT_REJECT_RTS;
			verdict->status = info->local_status < 0 ?
				info->local_status : -ECANCELED;
			return 0;
		}
		if (info->state == XDEV_EXT_MP_RDV_ARMED && !info->posted_groups) {
			verdict->action = XDEV_EXT_XDP_ACT_RX_POST;
			return 0;
		}
		break;
	case XDEV_EXT_XDP_EV_CTS:
		if (!tx)
			return -XD_EPROTO;
		if (!(facts & XDEV_EXT_MP_XDP_F_NATIVE_POSTED)) {
			verdict->action = XDEV_EXT_XDP_ACT_TX_POST;
			return 0;
		}
		break;
	case XDEV_EXT_XDP_EV_HELD:
	case XDEV_EXT_XDP_EV_ACK:
	case XDEV_EXT_XDP_EV_FAIL:
		if (!tx)
			return -XD_EPROTO;
		verdict->action = info->event == XDEV_EXT_XDP_EV_HELD ?
			XDEV_EXT_XDP_ACT_ACCEPT_HELD :
			(info->event == XDEV_EXT_XDP_EV_ACK ?
			 XDEV_EXT_XDP_ACT_ACCEPT_ACK : XDEV_EXT_XDP_ACT_ACCEPT_FAIL);
		verdict->credit = info->msg_credit;
		return 0;
	case XDEV_EXT_XDP_EV_CANCEL:
		if (tx)
			return -XD_EPROTO;
		if (!(facts & XDEV_EXT_MP_XDP_F_NATIVE_POSTED)) {
			verdict->action = XDEV_EXT_XDP_ACT_REJECT_RTS;
			verdict->status = info->local_status < 0 ?
				info->local_status : -ECANCELED;
			return 0;
		}
		if (info->ctl_room) {
			verdict->action = XDEV_EXT_XDP_ACT_SEND_CTS;
			verdict->credit = info->credit;
			return 0;
		}
		break;
	case XDEV_EXT_XDP_EV_CHAIN_END:
		if (tx)
			return -XD_EPROTO;
		if (info->ctl_room) {
			verdict->action = info->chain_status ||
				(facts & XDEV_EXT_MP_XDP_F_CHAIN_SEQUESTERED) ?
				XDEV_EXT_XDP_ACT_SEND_FAIL : XDEV_EXT_XDP_ACT_SEND_ACK;
			verdict->credit = info->credit;
			if (verdict->action == XDEV_EXT_XDP_ACT_SEND_FAIL)
				verdict->status = info->chain_status < 0 ?
					info->chain_status : -XD_ENOLINK;
			return 0;
		}
		break;
	case XDEV_EXT_XDP_EV_POST_RESULT:
		if (info->local_status) {
			verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
			verdict->status = info->local_status;
			return 0;
		}
		/* Successful RX post creates a CTS obligation. */
		if (!tx && info->ctl_room) {
			verdict->action = XDEV_EXT_XDP_ACT_SEND_CTS;
			verdict->credit = info->credit;
			return 0;
		}
		break;
	case XDEV_EXT_XDP_EV_REPLY_DUE:
	case XDEV_EXT_XDP_EV_DUPLICATE:
		if (!tx && info->ctl_room) {
			if (facts & XDEV_EXT_MP_XDP_F_CTS_OWED) {
				verdict->action = XDEV_EXT_XDP_ACT_SEND_CTS;
				verdict->credit = info->credit;
				return 0;
			}
			if (facts & XDEV_EXT_MP_XDP_F_FINAL_OWED) {
				verdict->action = info->chain_status || info->local_status ||
					(facts & XDEV_EXT_MP_XDP_F_CHAIN_SEQUESTERED) ?
					XDEV_EXT_XDP_ACT_SEND_FAIL : XDEV_EXT_XDP_ACT_SEND_ACK;
				verdict->credit = info->credit;
				if (verdict->action == XDEV_EXT_XDP_ACT_SEND_FAIL)
					verdict->status = info->local_status ? info->local_status :
						(info->chain_status ? info->chain_status : -XD_ENOLINK);
				return 0;
			}
		}
		if (info->event == XDEV_EXT_XDP_EV_DUPLICATE &&
		    !(facts & (XDEV_EXT_MP_XDP_F_CTS_OWED |
			       XDEV_EXT_MP_XDP_F_FINAL_OWED))) {
			verdict->action = XDEV_EXT_XDP_ACT_IGNORE;
			return 0;
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
			return 0;
		}
		break;
	case XDEV_EXT_XDP_EV_READY:
	case XDEV_EXT_XDP_EV_TIMER:
	case XDEV_EXT_XDP_EV_STOP:
		break;
	default:
		return -EINVAL;
	}
	/* Never wrap a wake into the past or refresh an immutable deadline. */
	wake = info->now_ns > max_time - 20000000ULL ?
		max_time : info->now_ns + 20000000ULL;
	if (info->hard_deadline_ns > info->now_ns && info->hard_deadline_ns < wake)
		wake = info->hard_deadline_ns;
	if (info->policy_deadline_ns > info->now_ns && info->policy_deadline_ns < wake)
		wake = info->policy_deadline_ns;
	if (wake <= info->now_ns) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_ETIMEDOUT;
		return 0;
	}
	verdict->action = XDEV_EXT_XDP_ACT_WAIT;
	verdict->wake_ns = wake;
	return 0;
}

SEC("struct_ops.s/xdomain_peer_prepare")
__s32 BPF_PROG(xdomain_peer_prepare, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return 0;
}

SEC("struct_ops/xdomain_peer_build")
__s32 BPF_PROG(xdomain_peer_build, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_xdomain_mech_info *info;
	struct xdev_ext_xdomain_desc *d;
	__u64 key = mctx->base.src_offset;
	__u32 i, j;

	(void)ctx;
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
	if (XDEV_EXT_XDOMAIN_OBSERVE_BUILD(mctx, info))
		return XDEV_EXT_MP_BUILD_ABORT;
	return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/xdomain_peer_complete")
__s32 BPF_PROG(xdomain_peer_complete, const struct xdev_ext_mech_ctx *mctx)
{
	const struct xdev_ext_xdomain_mech_cqe *cqe;

	(void)ctx;
	if (mctx->callsite == XDEV_EXT_MP_SITE_WORKER_PROTOCOL) {
		struct xdev_ext_xdomain_proto_info info = {};
		struct xdev_ext_xdomain_proto_verdict verdict = {};

		/* Both __sz arguments require initialized writable memory. */
		if (bpf_xdev_ext_xdomain_info(mctx, &info, sizeof(info)) ||
		    xdomain_peer_choose(&info, &verdict) ||
		    bpf_xdev_ext_xdomain_verdict(mctx, &verdict, sizeof(verdict)))
			return XDEV_EXT_MP_ABORT;
		return 0;
	}
	if (mctx->callsite != XDEV_EXT_MP_SITE_WORKER)
		return XDEV_EXT_MP_ABORT;
	cqe = (const void *)bpf_xdev_ext_cqe(mctx, 0, sizeof(*cqe));
	if (!cqe)
		return XDEV_EXT_MP_ABORT;
	if (XDEV_EXT_XDOMAIN_OBSERVE_CQE(mctx, cqe))
		return XDEV_EXT_MP_ABORT;
	if (cqe->status || cqe->outcome || cqe->bytes != mctx->base.length)
		return XDEV_EXT_MP_ABORT;
	if (mctx->base.direction == XDEV_EXT_MP_DIR_TO_DEVICE &&
	    cqe->remote != XDEV_EXT_MP_NET_REMOTE_ACKED)
		return XDEV_EXT_MP_ABORT;
	return XDEV_EXT_MP_NEXT;
}

SEC(".struct_ops.link")
struct xdev_ext_xdomain_mech_ops xdomain_peer_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.prepare = (void *)xdomain_peer_prepare,
	.build = (void *)xdomain_peer_build,
	.complete = (void *)xdomain_peer_complete,
};
char LICENSE[] SEC("license") = "GPL";
