// SPDX-License-Identifier: GPL-2.0
/*
 * XDOMAIN protocol: post the next batch early and advertise it.
 *
 * The two endpoints first pair (HELLO, CHALLENGE, CONFIRM), binding their
 * fresh endpoint identities. The receiver then posts the buffers of its next
 * group as soon as one batch is armed, and advertises them by a CTS grant
 * before the sender asks. The sender posts a batch on that grant without an
 * RTS round trip. This program never binds a group from an RTS: an RTS from a
 * peer running another protocol is only refused.
 *
 * It needs a stage bound with XDEV_EXT_XDOMAIN_F_EARLY (the version-2
 * envelope) at both ends. It registers the same struct_ops map as the
 * reference program; a caller selects this protocol by loading this object.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "xdomain_policy.h"

/* Pairing, grant and early posting decisions. */
static __always_inline int
xd_early_bind(const struct xdev_ext_xdomain_proto_info_v2 *info,
	      struct xdev_ext_xdomain_proto_verdict *verdict)
{
	const struct xdev_ext_xdomain_proto_info *b = &info->base;
	__u64 wake;
	__u32 action = 0;

	*verdict = (struct xdev_ext_xdomain_proto_verdict){
		.size = sizeof(*verdict), .version = XDEV_EXT_MP_XDOMAIN_PROTO_V2_VERSION,
		.event_id = b->event_id, .epoch = b->epoch };
	if (!(b->facts & XDEV_EXT_MP_XDP_F_LINK_UP) ||
	    !(b->facts & XDEV_EXT_MP_XDP_F_ADMITS) ||
	    (b->facts & (XDEV_EXT_MP_XDP_F_STAGE_DEAD | XDEV_EXT_MP_XDP_F_STOPPING))) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_POLICY_ENOLINK;
		return 0;
	}
	if (b->hard_deadline_ns && b->now_ns >= b->hard_deadline_ns) {
		verdict->action = XDEV_EXT_XDP_ACT_FAIL_LINK;
		verdict->status = -XD_POLICY_ETIMEDOUT;
		return 0;
	}
	switch (b->event) {
	case XDEV_EXT_XDP_EV_PAIR_DUE:
		/* Start or repeat this endpoint's pairing step. */
		if (b->ctl_room && (info->early_facts & XDEV_EXT_MP_XDP_EARLY_F_PAIR_RETRY_DUE))
			action = b->direction == XDEV_EXT_MP_DIR_TO_DEVICE ?
				XDEV_EXT_XDP_ACT_SEND_HELLO : XDEV_EXT_XDP_ACT_SEND_CHALLENGE;
		break;
	case XDEV_EXT_XDP_EV_HELLO:
		if (b->ctl_room && (info->early_facts & XDEV_EXT_MP_XDP_EARLY_F_PAIR_RETRY_DUE))
			action = XDEV_EXT_XDP_ACT_SEND_CHALLENGE;
		break;
	case XDEV_EXT_XDP_EV_CHALLENGE:
		if (b->ctl_room && (info->early_facts & XDEV_EXT_MP_XDP_EARLY_F_PAIR_RETRY_DUE))
			action = XDEV_EXT_XDP_ACT_SEND_CONFIRM;
		break;
	case XDEV_EXT_XDP_EV_CONFIRM:
		action = XDEV_EXT_XDP_ACT_BIND_PAIR;
		break;
	case XDEV_EXT_XDP_EV_GRANT:
		action = XDEV_EXT_XDP_ACT_ACCEPT_GRANT;
		break;
	case XDEV_EXT_XDP_EV_EARLY_RX_READY:
		/* Post the next group before the sender asks; its CTS follows. */
		if (info->early_facts & XDEV_EXT_MP_XDP_EARLY_F_RX_POSTABLE)
			action = XDEV_EXT_XDP_ACT_RX_POST_EARLY;
		break;
	case XDEV_EXT_XDP_EV_TX_SUBMIT:
		/* Send a batch only on the grant advertised for its exact key. */
		if (info->early_facts & XDEV_EXT_MP_XDP_EARLY_F_TX_POSTABLE)
			action = XDEV_EXT_XDP_ACT_TX_POST_EARLY;
		break;
	default:
		return -XD_POLICY_EPROTO;
	}
	if (action) {
		verdict->action = action;
		return 0;
	}
	wake = b->now_ns > ~(__u64)0 - XD_POLICY_TICK_NS ? ~(__u64)0 : b->now_ns + XD_POLICY_TICK_NS;
	if (b->hard_deadline_ns && b->hard_deadline_ns < wake)
		wake = b->hard_deadline_ns;
	if (b->policy_deadline_ns && b->policy_deadline_ns < wake)
		wake = b->policy_deadline_ns;
	if (wake <= b->now_ns)
		return -XD_POLICY_ETIMEDOUT;
	verdict->action = XDEV_EXT_XDP_ACT_WAIT;
	verdict->wake_ns = wake;
	return 0;
}

static __always_inline int
xd_early_choose(struct xdev_ext_xdomain_proto_info_v2 *info,
		struct xdev_ext_xdomain_proto_verdict *verdict)
{
	struct xdev_ext_xdomain_proto_info *b = &info->base;
	struct xd_policy p = {};
	int ret;

	if (b->size != sizeof(*info) || b->version != XDEV_EXT_MP_XDOMAIN_PROTO_V2_VERSION)
		return -EINVAL;
	if (b->event == XDEV_EXT_XDP_EV_TX_SUBMIT || b->event >= XDEV_EXT_XDP_EV_PAIR_DUE)
		return xd_early_bind(info, verdict);
	/* Completion, replies and peer results use the shared version-1 rules. */
	b->size = sizeof(*b);
	b->version = XDEV_EXT_MP_XDOMAIN_PROTO_VERSION;
	ret = xd_policy_begin(b, verdict, &p);
	if (ret == XD_POLICY_BINDING)
		ret = xd_policy_event(b, verdict, &p);
	if (ret == XD_POLICY_BINDING) {
		ret = XD_POLICY_WAIT;
		switch (b->event) {
		case XDEV_EXT_XDP_EV_RTS:
			/* Never bind a group from an RTS. Refuse what can be
			 * refused now; the rest waits for cancellation or teardown. */
			if (p.tx) {
				ret = -XD_POLICY_EPROTO;
			} else if ((p.facts & (XDEV_EXT_MP_XDP_F_RTS_CANCELED |
					       XDEV_EXT_MP_XDP_F_STOPPING)) || b->local_status) {
				verdict->action = XDEV_EXT_XDP_ACT_REJECT_RTS;
				verdict->status = b->local_status < 0 ? b->local_status : -ECANCELED;
				ret = XD_POLICY_DONE;
			}
			break;
		default:
			/* A version-1 CTS answers an RTS this protocol never sends. */
			ret = -XD_POLICY_EPROTO;
		}
	}
	if (ret == XD_POLICY_WAIT)
		ret = xd_policy_wait(b, verdict);
	b->size = sizeof(*info);
	b->version = XDEV_EXT_MP_XDOMAIN_PROTO_V2_VERSION;
	verdict->version = XDEV_EXT_MP_XDOMAIN_PROTO_V2_VERSION;
	return ret;
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
	(void)ctx;
	return xd_policy_build(mctx);
}

SEC("struct_ops/xdomain_peer_complete")
__s32 BPF_PROG(xdomain_peer_complete, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	if (mctx->callsite == XDEV_EXT_MP_SITE_WORKER_PROTOCOL) {
		struct xdev_ext_xdomain_proto_info_v2 info = {};
		struct xdev_ext_xdomain_proto_verdict verdict = {};

		if (bpf_xdev_ext_xdomain_info_v2(mctx, &info, sizeof(info)) ||
		    xd_early_choose(&info, &verdict) ||
		    bpf_xdev_ext_xdomain_verdict_v2(mctx, &verdict, sizeof(verdict)))
			return XDEV_EXT_MP_ABORT;
		return 0;
	}
	return xd_policy_cqe(mctx);
}

SEC(".struct_ops.link")
struct xdev_ext_xdomain_mech_ops xdomain_peer_ops = {
	.abi_version = XDEV_EXT_MP_ABI_VERSION,
	.prepare = (void *)xdomain_peer_prepare,
	.build = (void *)xdomain_peer_build,
	.complete = (void *)xdomain_peer_complete,
};
char LICENSE[] SEC("license") = "GPL";
