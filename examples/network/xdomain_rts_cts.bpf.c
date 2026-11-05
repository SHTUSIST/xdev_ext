// SPDX-License-Identifier: GPL-2.0
/*
 * XDOMAIN protocol: post receive buffers only after RTS, then CTS.
 *
 * The sender announces each group by RTS. The receiver posts that group's
 * buffers when the RTS arrives and advertises them by CTS. The sender posts
 * the group only on that CTS. On a stage that offers pairing (the version-2
 * envelope of XDEV_EXT_XDOMAIN_F_EARLY) this program declines it, so the
 * stage keeps the version-1 control messages.
 *
 * It registers the same struct_ops map as the reference program; a caller
 * selects this protocol by loading this object instead of another one.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#include "xdomain_policy.h"

static __always_inline int
xd_rts_cts_choose(struct xdev_ext_xdomain_proto_info_v2 *info2,
		  struct xdev_ext_xdomain_proto_verdict *verdict)
{
	struct xdev_ext_xdomain_proto_info *info = &info2->base;
	struct xd_policy p = {};
	__u32 facts;
	int ret;

	if (info->size != sizeof(*info2) ||
	    info->version != XDEV_EXT_MP_XDOMAIN_PROTO_V2_VERSION)
		return -EINVAL;
	/* This protocol never pairs: decline the offer and any pairing input. */
	if (info->event == XDEV_EXT_XDP_EV_PAIR_DUE ||
	    info->event == XDEV_EXT_XDP_EV_HELLO) {
		*verdict = (struct xdev_ext_xdomain_proto_verdict){
			.size = sizeof(*verdict),
			.version = XDEV_EXT_MP_XDOMAIN_PROTO_V2_VERSION,
			.action = XDEV_EXT_XDP_ACT_IGNORE,
			.event_id = info->event_id, .epoch = info->epoch };
		return 0;
	}
	/* The shared rules read the version-1 prefix of the facts in place. */
	info->size = sizeof(*info);
	info->version = XDEV_EXT_MP_XDOMAIN_PROTO_VERSION;
	ret = xd_policy_begin(info, verdict, &p);
	facts = p.facts;
	if (ret == XD_POLICY_BINDING) {
		/* An announced group the receiver never cleared is withdrawn. */
		if (p.tx && info->state == XDEV_EXT_MP_RDV_ANNOUNCED &&
		    !(facts & (XDEV_EXT_MP_XDP_F_NATIVE_POSTED |
			       XDEV_EXT_MP_XDP_F_WITHDRAWN)) &&
		    info->event != XDEV_EXT_XDP_EV_CTS &&
		    info->event != XDEV_EXT_XDP_EV_FAIL &&
		    (p.hard_due || p.policy_due || (facts & XDEV_EXT_MP_XDP_F_STOPPING))) {
			verdict->action = XDEV_EXT_XDP_ACT_WITHDRAW;
			ret = XD_POLICY_DONE;
		} else {
			ret = xd_policy_event(info, verdict, &p);
		}
	}
	if (ret == XD_POLICY_BINDING) {
		ret = XD_POLICY_WAIT;
		switch (info->event) {
		case XDEV_EXT_XDP_EV_TX_SUBMIT:
			/* Announce the next group while it is inside the credit. */
			if (p.tx && (facts & XDEV_EXT_MP_XDP_F_ADMITS) &&
			    !(facts & XDEV_EXT_MP_XDP_F_STOPPING) &&
			    info->next_group < info->credit && info->ctl_room) {
				verdict->action = XDEV_EXT_XDP_ACT_TX_ANNOUNCE;
				ret = XD_POLICY_DONE;
			}
			break;
		case XDEV_EXT_XDP_EV_RTS:
			if (p.tx) {
				ret = -XD_POLICY_EPROTO;
			} else if ((facts & (XDEV_EXT_MP_XDP_F_RTS_CANCELED |
					     XDEV_EXT_MP_XDP_F_STOPPING)) || info->local_status) {
				verdict->action = XDEV_EXT_XDP_ACT_REJECT_RTS;
				verdict->status = info->local_status < 0 ?
					info->local_status : -ECANCELED;
				ret = XD_POLICY_DONE;
			} else if (info->state == XDEV_EXT_MP_RDV_ARMED && !info->posted_groups) {
				/* Post this group's receive buffers now that it was asked for. */
				verdict->action = XDEV_EXT_XDP_ACT_RX_POST;
				ret = XD_POLICY_DONE;
			}
			break;
		case XDEV_EXT_XDP_EV_CTS:
			if (!p.tx) {
				ret = -XD_POLICY_EPROTO;
			} else if (!(facts & XDEV_EXT_MP_XDP_F_NATIVE_POSTED)) {
				/* The receiver posted and advertised this group: send it. */
				verdict->action = XDEV_EXT_XDP_ACT_TX_POST;
				ret = XD_POLICY_DONE;
			}
			break;
		default:
			ret = -EINVAL;
		}
	}
	if (ret == XD_POLICY_WAIT)
		ret = xd_policy_wait(info, verdict);
	info->size = sizeof(*info2);
	info->version = XDEV_EXT_MP_XDOMAIN_PROTO_V2_VERSION;
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
		    xd_rts_cts_choose(&info, &verdict) ||
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
