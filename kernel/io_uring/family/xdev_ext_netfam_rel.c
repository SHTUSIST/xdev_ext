// SPDX-License-Identifier: GPL-2.0
/*
 * Network family BPF kfuncs: read-only copies of a stage's reliable window,
 * available to network-family build and complete callbacks at the worker.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/xdev_ext_family_core.h>
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_netfam.h>

/* netfam rel kfuncs begin */
static int xdev_ext_net_call_rel(const struct xdev_ext_mech_ctx *ctx,
			       struct xdev_ext_net_rel_view *v)
{
	struct xdev_ext_mech_call *c = xdev_ext_mech_call_of(ctx);
	const struct xdev_ext_mech_class_ops *cls;

	if (!c || !c->st)
		return -EINVAL;
	if ((c->member != XDEV_EXT_MECH_MEMBER_BUILD &&
	     c->member != XDEV_EXT_MECH_MEMBER_COMPLETE) ||
	    (c->callsite != XDEV_EXT_MECH_SITE_WORKER &&
	     c->callsite != XDEV_EXT_MECH_SITE_WORKER_SELECT))
		return -EOPNOTSUPP;
	cls = c->st->cls;
	if (xdev_ext_mech_class_family(c->ctx.class_id) != XDEV_EXT_FAMILY_NETWORK ||
	    !cls->fam.net || !cls->fam.net->rel ||
	    !cls->fam.net->rel(c->st, v) || !v->lock)
		return -EOPNOTSUPP;
	return 0;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_xdev_ext_net_rel_rx_view(const struct xdev_ext_mech_ctx *ctx,
					     u64 group, void *view, u32 view__sz)
{
	struct xdev_ext_net_rel_view v = {};
	unsigned long flags;
	u64 owed;
	int ret = xdev_ext_net_call_rel(ctx, &v);

	if (ret)
		return ret;
	if (view__sz != sizeof(struct xdev_ext_rel_rx_view))
		return -EINVAL;
	if (!v.rx)
		return -EOPNOTSUPP;
	if (!group || group < v.rx->cfg.first_group ||
	    group > ~0ULL - v.rx->cfg.window)
		return -ERANGE;
	spin_lock_irqsave(v.lock, flags);
	owed = v.ack_pending ? v.ack_pending[group % v.rx->cfg.window] : 0;
	xdev_ext_rel_rx_view_fill(v.rx, owed, group, view);
	spin_unlock_irqrestore(v.lock, flags);
	return 0;
}

__bpf_kfunc int bpf_xdev_ext_net_rel_tx_state(const struct xdev_ext_mech_ctx *ctx,
					      u64 group, void *view, u32 view__sz)
{
	struct xdev_ext_net_rel_tx_state *s = view;
	const struct xdev_ext_rel_tx_entry *e;
	struct xdev_ext_net_rel_view v = {};
	unsigned long flags;
	int ret = xdev_ext_net_call_rel(ctx, &v);

	if (ret)
		return ret;
	if (view__sz != sizeof(*s))
		return -EINVAL;
	if (!v.tx)
		return -EOPNOTSUPP;
	if (!group || group > ~0ULL - v.tx->cfg.window)
		return -ERANGE;
	spin_lock_irqsave(v.lock, flags);
	e = &v.tx->entry[group % v.tx->cfg.window];
	*s = (struct xdev_ext_net_rel_tx_state) {
		.group = group,
		.base_group = v.tx->base_group,
		.next_group = v.tx->next_group,
		.credit = v.tx->credit,
	};
	if (e->live && e->group == group) {
		s->attempt = e->attempt;
		s->live = 1;
		s->acked = e->acked;
		s->native_pending = e->native_pending;
		s->terminal = e->terminal;
	}
	spin_unlock_irqrestore(v.lock, flags);
	return 0;
}

__bpf_kfunc int bpf_xdev_ext_net_rel_policy(const struct xdev_ext_mech_ctx *ctx,
					    void *policy, u32 policy__sz)
{
	struct xdev_ext_net_rel_view v = {};
	int ret = xdev_ext_net_call_rel(ctx, &v);

	if (ret)
		return ret;
	if (!v.policy)
		return -EOPNOTSUPP;
	if (policy__sz != sizeof(*v.policy))
		return -EINVAL;
	memcpy(policy, v.policy, sizeof(*v.policy)); /* immutable after CREATE */
	return 0;
}

__bpf_kfunc_end_defs();
/* netfam rel kfuncs end */

BTF_KFUNCS_START(xdev_ext_netfam_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdev_ext_net_rel_rx_view, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_net_rel_tx_state, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_net_rel_policy, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(xdev_ext_netfam_kfunc_ids)

BTF_SET_START(xdev_ext_netfam_kfuncs)
BTF_ID(func, bpf_xdev_ext_net_rel_rx_view)
BTF_ID(func, bpf_xdev_ext_net_rel_tx_state)
BTF_ID(func, bpf_xdev_ext_net_rel_policy)
BTF_SET_END(xdev_ext_netfam_kfuncs)

static int xdev_ext_netfam_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	return xdev_ext_mech_family_kfunc_filter(XDEV_EXT_FAMILY_NETWORK, prog,
					      kfunc_id, &xdev_ext_netfam_kfunc_ids,
					      &xdev_ext_netfam_kfuncs,
					      &xdev_ext_netfam_kfuncs);
}

static const struct btf_kfunc_id_set xdev_ext_netfam_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &xdev_ext_netfam_kfunc_ids,
	.filter = xdev_ext_netfam_kfunc_filter,
};

static int __init xdev_ext_netfam_rel_init(void)
{
	BTF_TYPE_EMIT(struct xdev_ext_net_rel_tx_state);
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
				       &xdev_ext_netfam_kfunc_set);
}
late_initcall(xdev_ext_netfam_rel_init);
