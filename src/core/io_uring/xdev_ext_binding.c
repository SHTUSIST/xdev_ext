// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/stddef.h>

#include <linux/xdev_ext_binding.h>

#include "xdev_ext_ops_core.h"

#define XDEV_EXT_BINDING_CALL_MAGIC	0x55425232U

struct xdev_ext_binding_call {
	struct xdev_ext_binding_ctx_v2 ctx;
	struct xdev_ext_binding_plan plan;
	int kfunc_ret;
	struct xdev_ext_ops_call_state cs;
};

/*
 * The public ctx type alone is not proof that a kfunc argument belongs to the
 * callback currently being invoked.  Keep the exact private envelope active
 * while preemption is disabled, and save/restore it for synchronous nesting.
 */
static DEFINE_PER_CPU(struct xdev_ext_binding_call *, xdev_ext_binding_active_call);

DEFINE_STATIC_KEY_FALSE(xdev_ext_binding_policy_key);
DEFINE_XDEV_EXT_OPS_REGISTRY(xdev_ext_binding_registry, XDEV_EXT_BINDING_BACKEND_MAX,
			&xdev_ext_binding_policy_key);

static struct bpf_struct_ops bpf_xdev_ext_binding_ops;

static void xdev_ext_binding_plan_fallback(struct xdev_ext_binding_plan *plan)
{
	*plan = (struct xdev_ext_binding_plan) {
		.action = XDEV_EXT_BINDING_ACTION_FALLBACK,
	};
}

static int xdev_ext_binding_record_action(const struct xdev_ext_binding_ctx_v2 *ctx,
				     __u32 expected_event, __u32 action,
				     __u32 recipe, __u32 next_stage,
				     __u32 profile)
{
	struct xdev_ext_binding_call *call;
	struct xdev_ext_binding_plan candidate = {
		.action = action,
		.recipe = recipe,
		.next_stage = next_stage,
		.profile = profile,
	};
	int ret;

	call = this_cpu_read(xdev_ext_binding_active_call);
	if (unlikely(!call))
		return -EPROTO;
	if (unlikely(ctx != &call->ctx)) {
		call->cs.protocol_error = 1;
		return -EPROTO;
	}
	if (unlikely(!xdev_ext_ops_call_sealed(&call->cs, XDEV_EXT_BINDING_CALL_MAGIC) ||
		     call->ctx.event != expected_event)) {
		call->cs.protocol_error = 1;
		return -EPROTO;
	}

	if (unlikely(!xdev_ext_ops_call_take(&call->cs, 1)))
		return -EPROTO;

	ret = xdev_ext_binding_validate_plan(ctx, &candidate);
	call->kfunc_ret = ret;
	if (!ret)
		call->plan = candidate;
	return ret;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int
bpf_xdev_ext_dispatch_action(const struct xdev_ext_binding_ctx_v2 *ctx, __u32 action,
			__u32 recipe, __u32 next_stage, __u32 profile)
{
	return xdev_ext_binding_record_action(ctx, XDEV_EXT_BINDING_EVENT_DISPATCH,
					 action, recipe, next_stage, profile);
}

__bpf_kfunc int
bpf_xdev_ext_complete_action(const struct xdev_ext_binding_ctx_v2 *ctx, __u32 action,
			__u32 recipe, __u32 next_stage, __u32 profile)
{
	return xdev_ext_binding_record_action(ctx, XDEV_EXT_BINDING_EVENT_COMPLETE,
					 action, recipe, next_stage, profile);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(xdev_ext_binding_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdev_ext_dispatch_action, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_xdev_ext_complete_action, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(xdev_ext_binding_kfunc_ids)

BTF_SET_START(xdev_ext_binding_dispatch_kfunc_set)
BTF_ID(func, bpf_xdev_ext_dispatch_action)
BTF_SET_END(xdev_ext_binding_dispatch_kfunc_set)

BTF_SET_START(xdev_ext_binding_complete_kfunc_set)
BTF_ID(func, bpf_xdev_ext_complete_action)
BTF_SET_END(xdev_ext_binding_complete_kfunc_set)

static const struct bpf_struct_ops *const xdev_ext_binding_kfunc_st_ops[] = {
	&bpf_xdev_ext_binding_ops,
};

static const struct xdev_ext_ops_kfunc_member xdev_ext_binding_kfunc_members[] = {
	{
		.off = offsetof(struct xdev_ext_binding_ops, dispatch),
		.allowed = &xdev_ext_binding_dispatch_kfunc_set,
	},
	{
		.off = offsetof(struct xdev_ext_binding_ops, complete),
		.allowed = &xdev_ext_binding_complete_kfunc_set,
	},
};

static const struct xdev_ext_ops_kfunc_rule xdev_ext_binding_kfunc_rule = {
	.ids = &xdev_ext_binding_kfunc_ids,
	.st_ops = xdev_ext_binding_kfunc_st_ops,
	.nr_st_ops = ARRAY_SIZE(xdev_ext_binding_kfunc_st_ops),
	.members = xdev_ext_binding_kfunc_members,
	.nr_members = ARRAY_SIZE(xdev_ext_binding_kfunc_members),
};

static int xdev_ext_binding_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	return xdev_ext_ops_kfunc_filter(&xdev_ext_binding_kfunc_rule, prog, kfunc_id);
}

static const struct btf_kfunc_id_set xdev_ext_binding_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &xdev_ext_binding_kfunc_ids,
	.filter = xdev_ext_binding_kfunc_filter,
};

static int
xdev_ext_binding_invoke(const struct xdev_ext_binding_ops *ops,
		   const struct xdev_ext_binding_ctx_v2 *ctx, bool dispatch,
		   struct xdev_ext_binding_plan *plan)
{
	struct xdev_ext_binding_call call = {
		.ctx = *ctx,
	};
	struct xdev_ext_binding_call *previous;
	int callback_ret;

	xdev_ext_ops_call_seal(&call.cs, XDEV_EXT_BINDING_CALL_MAGIC);
	xdev_ext_binding_plan_fallback(&call.plan);
	preempt_disable();
	previous = this_cpu_read(xdev_ext_binding_active_call);
	this_cpu_write(xdev_ext_binding_active_call, &call);
	callback_ret = dispatch ? ops->dispatch(&call.ctx) :
				  ops->complete(&call.ctx);
	this_cpu_write(xdev_ext_binding_active_call, previous);
	preempt_enable();

	if (!xdev_ext_ops_call_clean(&call.cs, 1) || callback_ret != call.kfunc_ret)
		return -EPROTO;
	if (call.kfunc_ret)
		return call.kfunc_ret;

	*plan = call.plan;
	return 0;
}

static const struct xdev_ext_binding_ops *
xdev_ext_binding_token_consume(struct xdev_ext_binding_token *token)
{
	if (!token)
		return NULL;
	return xchg(&token->private, NULL);
}

void xdev_ext_binding_token_put(struct xdev_ext_binding_token *token)
{
	const struct xdev_ext_binding_ops *ops = xdev_ext_binding_token_consume(token);

	if (ops)
		xdev_ext_ops_unpin(ops);
}
EXPORT_SYMBOL_GPL(xdev_ext_binding_token_put);

int xdev_ext_binding_dispatch(const struct xdev_ext_binding_ctx_v2 *ctx,
			 struct xdev_ext_binding_token *token,
			 struct xdev_ext_binding_plan *plan)
{
	const struct xdev_ext_binding_ops *ops;
	int ret;

	if (plan)
		xdev_ext_binding_plan_fallback(plan);
	if (!token)
		return -EINVAL;
	if (READ_ONCE(token->private))
		return -EBUSY;
	if (!plan)
		return -EINVAL;

	ret = xdev_ext_binding_validate_ctx(ctx);
	if (ret)
		return ret;
	if (ctx->event != XDEV_EXT_BINDING_EVENT_DISPATCH)
		return -EINVAL;
	if (!xdev_ext_binding_policy_active())
		return 0;

	ops = xdev_ext_ops_pin(&xdev_ext_binding_registry, ctx->backend);
	if (!ops)
		return 0;
	if (!xdev_ext_binding_ops_accepts_ctx(ops->backend, ops->flags, ctx)) {
		xdev_ext_ops_unpin(ops);
		return 0;
	}

	ret = xdev_ext_binding_invoke(ops, ctx, true, plan);
	if (ret || plan->action == XDEV_EXT_BINDING_ACTION_TERMINAL) {
		xdev_ext_ops_unpin(ops);
		return ret;
	}

	WRITE_ONCE(token->private, ops);
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_binding_dispatch);

int xdev_ext_binding_complete(const struct xdev_ext_binding_ctx_v2 *ctx,
			 struct xdev_ext_binding_token *token,
			 struct xdev_ext_binding_plan *plan)
{
	const struct xdev_ext_binding_ops *ops;
	int ret;

	if (plan)
		xdev_ext_binding_plan_fallback(plan);
	if (!token)
		return -EINVAL;
	ops = xdev_ext_binding_token_consume(token);
	if (!plan) {
		ret = -EINVAL;
		goto out_put;
	}

	ret = xdev_ext_binding_validate_ctx(ctx);
	if (ret)
		goto out_put;
	if (ctx->event != XDEV_EXT_BINDING_EVENT_COMPLETE) {
		ret = -EINVAL;
		goto out_put;
	}
	if (!ops)
		return 0;
	if (ctx->backend != ops->backend) {
		ret = -EXDEV;
		goto out_put;
	}
	if (!xdev_ext_binding_ops_accepts_ctx(ops->backend, ops->flags, ctx)) {
		ret = 0;
		goto out_put;
	}

	ret = xdev_ext_binding_invoke(ops, ctx, false, plan);

out_put:
	if (ops)
		xdev_ext_ops_unpin(ops);
	return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_binding_complete);

static bool xdev_ext_binding_abi_valid(u32 value)
{
	return value == XDEV_EXT_BINDING_ABI_VERSION;
}

static bool xdev_ext_binding_backend_valid(u32 value)
{
	return xdev_ext_binding_backend_known(value);
}

static bool xdev_ext_binding_flags_known(u32 value)
{
	return !(value & ~XDEV_EXT_BINDING_KNOWN_OPS_FLAG_MASK);
}

static const struct xdev_ext_ops_u32_field xdev_ext_binding_ops_fields[] = {
	{ offsetof(struct xdev_ext_binding_ops, abi_version), xdev_ext_binding_abi_valid },
	{ offsetof(struct xdev_ext_binding_ops, backend), xdev_ext_binding_backend_valid },
	{ offsetof(struct xdev_ext_binding_ops, flags), xdev_ext_binding_flags_known },
	{ offsetof(struct xdev_ext_binding_ops, reserved), xdev_ext_ops_u32_zero },
};

static const struct xdev_ext_ops_member xdev_ext_binding_ops_members[] = {
	{ .off = offsetof(struct xdev_ext_binding_ops, dispatch), .required = true },
	{ .off = offsetof(struct xdev_ext_binding_ops, complete), .required = true },
};

static const struct xdev_ext_ops_desc xdev_ext_binding_ops_desc = {
	.fields = xdev_ext_binding_ops_fields,
	.nr_fields = ARRAY_SIZE(xdev_ext_binding_ops_fields),
	.members = xdev_ext_binding_ops_members,
	.nr_members = ARRAY_SIZE(xdev_ext_binding_ops_members),
};

static int xdev_ext_binding_ops_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	return xdev_ext_ops_init_member(&xdev_ext_binding_ops_desc, t, member, kdata,
				   udata);
}

static int xdev_ext_binding_ops_check_member(const struct btf_type *t,
					const struct btf_member *member,
					const struct bpf_prog *prog)
{
	return xdev_ext_ops_check_member(&xdev_ext_binding_ops_desc, t, member, prog);
}

static int xdev_ext_binding_ops_validate(void *kdata)
{
	const struct xdev_ext_binding_ops *ops = kdata;

	if (xdev_ext_ops_validate(&xdev_ext_binding_ops_desc, kdata) ||
	    !xdev_ext_binding_ops_flags_valid(ops->backend, ops->flags))
		return -EINVAL;
	return 0;
}

static int xdev_ext_binding_ops_reg(void *kdata, struct bpf_link *link)
{
	const struct xdev_ext_binding_ops *ops = kdata;

	return xdev_ext_ops_publish(&xdev_ext_binding_registry, ops->backend, ops, link);
}

static void xdev_ext_binding_ops_unreg(void *kdata, struct bpf_link *link)
{
	const struct xdev_ext_binding_ops *ops = kdata;

	(void)link;
	xdev_ext_ops_retract(&xdev_ext_binding_registry, ops->backend, ops);
}

static int
xdev_ext_binding_ops_btf_struct_access(struct bpf_verifier_log *log,
				  const struct bpf_reg_state *reg,
				  int off, int size)
{
	return xdev_ext_ops_deny_btf_write(log, reg, off, size, "xdev_ext_binding_ctx_v2");
}

static const struct bpf_verifier_ops xdev_ext_binding_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = xdev_ext_ops_is_valid_access,
	.btf_struct_access = xdev_ext_binding_ops_btf_struct_access,
};

XDEV_EXT_OPS_CFI_STUB(xdev_ext_binding_ops__dispatch, struct xdev_ext_binding_ctx_v2)
XDEV_EXT_OPS_CFI_STUB(xdev_ext_binding_ops__complete, struct xdev_ext_binding_ctx_v2)

static struct xdev_ext_binding_ops xdev_ext_binding_cfi_stubs = {
	.dispatch = xdev_ext_binding_ops__dispatch,
	.complete = xdev_ext_binding_ops__complete,
};

static struct bpf_struct_ops bpf_xdev_ext_binding_ops = {
	.verifier_ops = &xdev_ext_binding_verifier_ops,
	.init = xdev_ext_ops_init,
	.check_member = xdev_ext_binding_ops_check_member,
	.init_member = xdev_ext_binding_ops_init_member,
	.reg = xdev_ext_binding_ops_reg,
	.unreg = xdev_ext_binding_ops_unreg,
	.validate = xdev_ext_binding_ops_validate,
	.cfi_stubs = &xdev_ext_binding_cfi_stubs,
	.name = "xdev_ext_binding_ops",
	.owner = THIS_MODULE,
};

static int __init xdev_ext_binding_struct_ops_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&xdev_ext_binding_kfunc_set);
	if (ret)
		return ret;
	return register_bpf_struct_ops(&bpf_xdev_ext_binding_ops, xdev_ext_binding_ops);
}
late_initcall(xdev_ext_binding_struct_ops_init);
