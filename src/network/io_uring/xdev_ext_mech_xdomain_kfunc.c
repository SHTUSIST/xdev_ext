// SPDX-License-Identifier: GPL-2.0
/*
 * XDOMAIN protocol callbacks receive pointer-free facts and record one intent.
 * The dispatcher validates current facts and applies effects after BPF returns.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/xdev_ext_mech.h>

static bool xdev_ext_xdomain_call_ok(const struct xdev_ext_mech_call *c)
{
	const struct xdev_ext_xdomain_proto_info *info;

	if (c->ctx.class_id != XDEV_EXT_MECH_CLASS_XDOMAIN ||
	    c->member != XDEV_EXT_MECH_MEMBER_COMPLETE ||
	    c->callsite != XDEV_EXT_MECH_SITE_WORKER_PROTOCOL ||
	    !c->st || !c->s || c->st->s != c->s ||
	    c->st->class_id != XDEV_EXT_MECH_CLASS_XDOMAIN || !c->xdomain ||
	    c->ctx.session_id != xdev_ext_mech_session_id(c->s) ||
	    c->b || c->frames || c->nr_frames || c->scratch ||
	    c->desc_size || c->desc_cap || c->cqe || c->cqe_size || c->cqe_cap ||
	    c->out_len || c->len_delta || c->ctx.batch_id || c->ctx.nr_frames ||
	    c->ctx.desc_cap || c->ctx.base.length || c->ctx.base.bytes_done ||
	    !c->info || c->info_size != sizeof(*info))
		return false;
	info = c->info;
	return info->size == sizeof(*info) &&
	       info->version == XDEV_EXT_XDOMAIN_PROTO_VERSION;
}

static bool xdev_ext_xdomain_verdict_ok(const struct xdev_ext_xdomain_proto_verdict *v,
				       const struct xdev_ext_xdomain_proto_info *info)
{
	bool credit = false, status = false;

	if (v->size != sizeof(*v) || v->version != XDEV_EXT_XDOMAIN_PROTO_VERSION ||
	    v->action <= XDEV_EXT_XDP_ACT_INVALID ||
	    v->action > XDEV_EXT_XDP_ACT_CANCEL_ARMED || v->flags ||
	    v->reserved0 || v->reserved1 || v->event_id != info->event_id ||
	    v->epoch != info->epoch)
		return false;

	/* Only parameters belonging to the selected action may be nonzero. */
	switch (v->action) {
	case XDEV_EXT_XDP_ACT_WAIT:
		return !v->credit && !v->status;
	case XDEV_EXT_XDP_ACT_ACCEPT_HELD:
	case XDEV_EXT_XDP_ACT_ACCEPT_ACK:
	case XDEV_EXT_XDP_ACT_ACCEPT_FAIL:
	case XDEV_EXT_XDP_ACT_SEND_CTS:
	case XDEV_EXT_XDP_ACT_SEND_ACK:
		credit = true;
		break;
	case XDEV_EXT_XDP_ACT_SEND_FAIL:
		credit = true;
		fallthrough;
	case XDEV_EXT_XDP_ACT_REJECT_RTS:
	case XDEV_EXT_XDP_ACT_FAIL_LINK:
	case XDEV_EXT_XDP_ACT_CANCEL_ARMED:
		if (v->status >= 0 || v->status < -MAX_ERRNO)
			return false;
		status = true;
		break;
	case XDEV_EXT_XDP_ACT_PUBLISH:
		if (v->status > 0 || v->status < -MAX_ERRNO)
			return false;
		status = true;
		break;
	default:
		break;
	}
	return !v->wake_ns && (credit || !v->credit) && (status || !v->status);
}

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_xdev_ext_xdomain_info(const struct xdev_ext_mech_ctx *ctx,
				       void *info, __u32 info__sz)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);

	if (!c)
		return -EINVAL;
	if (!xdev_ext_xdomain_call_ok(c) || !info ||
	    info__sz != sizeof(struct xdev_ext_xdomain_proto_info)) {
		c->protocol_error = 1;
		return -EINVAL;
	}
	memcpy(info, c->info, sizeof(struct xdev_ext_xdomain_proto_info));
	return 0;
}

__bpf_kfunc int bpf_xdev_ext_xdomain_verdict(const struct xdev_ext_mech_ctx *ctx,
					  const void *verdict, __u32 verdict__sz)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);
	struct xdev_ext_xdomain_proto_verdict v;

	if (!c)
		return -EINVAL;
	if (!xdev_ext_xdomain_call_ok(c)) {
		c->protocol_error = 1;
		return -EINVAL;
	}
	if (c->xdomain->calls) {
		c->protocol_error = 1;
		return -EALREADY;
	}
	/* An invalid attempt cannot be replaced by a later valid one. */
	c->xdomain->calls = 1;
	if (!verdict || verdict__sz != sizeof(v)) {
		c->protocol_error = 1;
		return -EINVAL;
	}
	memcpy(&v, verdict, sizeof(v));
	if (!xdev_ext_xdomain_verdict_ok(&v, c->info)) {
		c->protocol_error = 1;
		return -EINVAL;
	}
	c->xdomain->verdict = v;
	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(xdev_ext_xdomain_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdev_ext_xdomain_info, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_xdomain_verdict, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(xdev_ext_xdomain_kfunc_ids)

BTF_SET_START(xdev_ext_xdomain_complete_kfuncs)
BTF_ID(func, bpf_xdev_ext_xdomain_info)
BTF_ID(func, bpf_xdev_ext_xdomain_verdict)
BTF_SET_END(xdev_ext_xdomain_complete_kfuncs)

static int xdev_ext_xdomain_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	return xdev_ext_mech_class_kfunc_filter(XDEV_EXT_MECH_CLASS_XDOMAIN, prog,
					      kfunc_id, &xdev_ext_xdomain_kfunc_ids,
					      NULL, &xdev_ext_xdomain_complete_kfuncs);
}

static const struct btf_kfunc_id_set xdev_ext_xdomain_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &xdev_ext_xdomain_kfunc_ids,
	.filter = xdev_ext_xdomain_kfunc_filter,
};

static int __init xdev_ext_xdomain_kfunc_init(void)
{
	BTF_TYPE_EMIT(struct xdev_ext_xdomain_proto_info);
	BTF_TYPE_EMIT(struct xdev_ext_xdomain_proto_verdict);
	BTF_TYPE_EMIT(enum xdev_ext_xdomain_proto_event);
	BTF_TYPE_EMIT(enum xdev_ext_xdomain_proto_action);
	BTF_TYPE_EMIT(enum xdev_ext_mech_callsite);
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
				       &xdev_ext_xdomain_kfunc_set);
}
late_initcall(xdev_ext_xdomain_kfunc_init);
