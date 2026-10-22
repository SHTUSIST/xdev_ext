// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/jump_label.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

#include "xdev_ext_ops_core.h"

int xdev_ext_ops_publish(struct xdev_ext_ops_registry *reg, u32 slot, const void *ops,
		    struct bpf_link *link)
{
	int ret = 0;

	if (!link)
		return -EOPNOTSUPP;
	if (slot >= reg->nr_slots)
		return -EINVAL;

	mutex_lock(&reg->lock);
	if (rcu_access_pointer(reg->slots[slot])) {
		ret = -EBUSY;
		goto out_unlock;
	}

	rcu_assign_pointer(reg->slots[slot], ops);
	if (reg->nr_active++ == 0 && reg->key)
		static_branch_enable(reg->key);

out_unlock:
	mutex_unlock(&reg->lock);
	return ret;
}

bool xdev_ext_ops_retract(struct xdev_ext_ops_registry *reg, u32 slot, const void *ops)
{
	bool detached = false;

	if (slot >= reg->nr_slots)
		return false;

	mutex_lock(&reg->lock);
	if (rcu_access_pointer(reg->slots[slot]) == ops) {
		rcu_assign_pointer(reg->slots[slot], NULL);
		if (--reg->nr_active == 0 && reg->key)
			static_branch_disable(reg->key);
		detached = true;
	}
	mutex_unlock(&reg->lock);

	if (detached)
		synchronize_rcu();
	return detached;
}

const void *xdev_ext_ops_pin(struct xdev_ext_ops_registry *reg, u32 slot)
{
	const void *ops;

	if (slot >= reg->nr_slots)
		return NULL;

	rcu_read_lock();
	ops = rcu_dereference(reg->slots[slot]);
	if (ops && !bpf_struct_ops_get(ops))
		ops = NULL;
	rcu_read_unlock();
	return ops;
}

void xdev_ext_ops_unpin(const void *ops)
{
	bpf_struct_ops_put(ops);
}

bool xdev_ext_ops_u32_zero(u32 value)
{
	return !value;
}

int xdev_ext_ops_init(struct btf *btf)
{
	(void)btf;
	return 0;
}

static u32 xdev_ext_ops_member_off(const struct btf_type *t,
			      const struct btf_member *member)
{
	return __btf_member_bit_offset(t, member) / 8;
}

static const struct xdev_ext_ops_u32_field *
xdev_ext_ops_find_field(const struct xdev_ext_ops_desc *desc, u32 moff)
{
	u32 i;

	for (i = 0; i < desc->nr_fields; i++)
		if (desc->fields[i].off == moff)
			return &desc->fields[i];
	return NULL;
}

/*
 * Returns 1 after copying a valid listed scalar, -EINVAL for an invalid one,
 * and 0 for every other member so bpf_struct_ops handles callbacks itself.
 */
int xdev_ext_ops_init_member(const struct xdev_ext_ops_desc *desc,
			const struct btf_type *t,
			const struct btf_member *member, void *kdata,
			const void *udata)
{
	u32 moff = xdev_ext_ops_member_off(t, member);
	const struct xdev_ext_ops_u32_field *field = xdev_ext_ops_find_field(desc, moff);
	u32 value;

	if (!field)
		return 0;
	value = *(const u32 *)(udata + moff);
	if (!field->valid(value))
		return -EINVAL;
	*(u32 *)(kdata + moff) = value;
	return 1;
}

/* Only listed callbacks attach; a sleepable program only where allowed. */
int xdev_ext_ops_check_member(const struct xdev_ext_ops_desc *desc,
			 const struct btf_type *t,
			 const struct btf_member *member,
			 const struct bpf_prog *prog)
{
	u32 moff = xdev_ext_ops_member_off(t, member);
	u32 i;

	for (i = 0; i < desc->nr_members; i++) {
		if (desc->members[i].off != moff)
			continue;
		return prog->sleepable && !desc->members[i].sleepable ?
		       -EINVAL : 0;
	}
	return -EINVAL;
}

int xdev_ext_ops_validate(const struct xdev_ext_ops_desc *desc, const void *kdata)
{
	u32 i;

	for (i = 0; i < desc->nr_fields; i++)
		if (!desc->fields[i].valid(*(const u32 *)(kdata +
							  desc->fields[i].off)))
			return -EINVAL;
	for (i = 0; i < desc->nr_members; i++)
		if (desc->members[i].required &&
		    !*(void *const *)(kdata + desc->members[i].off))
			return -EINVAL;
	return 0;
}

bool xdev_ext_ops_is_valid_access(int off, int size, enum bpf_access_type type,
			     const struct bpf_prog *prog,
			     struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

int xdev_ext_ops_deny_btf_write(struct bpf_verifier_log *log,
			   const struct bpf_reg_state *reg, int off, int size,
			   const char *ctx_type)
{
	s32 ctx_id;

	if (reg->btf) {
		ctx_id = btf_find_by_name_kind(reg->btf, ctx_type,
					       BTF_KIND_STRUCT);
		if (ctx_id > 0 && reg->btf_id == ctx_id) {
			bpf_log(log,
				"XDEV_EXT callback context is read-only at off %d size %d\n",
				off, size);
			return -EACCES;
		}
	}

	/*
	 * The verifier calls this hook only for writes through non-allocated
	 * kernel PTR_TO_BTF_ID values.  Returning success here would replace the
	 * verifier's default read-only gate and would also require returning the
	 * pointer-field metadata consumed by check_ptr_to_btf_access().
	 */
	bpf_log(log,
		"XDEV_EXT callback kernel BTF objects are read-only at off %d size %d\n",
		off, size);
	return -EACCES;
}

int xdev_ext_ops_kfunc_filter(const struct xdev_ext_ops_kfunc_rule *rule,
			 const struct bpf_prog *prog, u32 kfunc_id)
{
	u32 i, moff;

	if (!btf_id_set8_contains(rule->ids, kfunc_id))
		return 0;

	for (i = 0; i < rule->nr_st_ops; i++)
		if (prog->aux->st_ops == rule->st_ops[i])
			break;
	if (i == rule->nr_st_ops)
		return -EACCES;

	moff = prog->aux->attach_st_ops_member_off;
	for (i = 0; i < rule->nr_members; i++)
		if (rule->members[i].off == moff &&
		    btf_id_set_contains(rule->members[i].allowed, kfunc_id))
			return 0;
	return -EACCES;
}
