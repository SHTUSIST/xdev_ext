// SPDX-License-Identifier: GPL-2.0
/* Legacy window-copy execution shared by the typed CE and DMA adapters. */
#include <linux/slab.h>

#include "xdev_ext_compfam_copy_runtime.h"

int xdev_ext_comp_copy_registry_register(struct xdev_ext_comp_copy_registry *registry,
	const struct xdev_ext_comp_copy_member *member)
{
	struct xdev_ext_comp_copy_registration *p, *new = NULL;
	u32 i;
	int err = 0;

	/* Dynamic registration preserves allocation-before-duplicate ordering. */
	if (!registry->fixed) {
		new = kmalloc(sizeof(*new), GFP_KERNEL);
		if (!new)
			return -ENOMEM;
	}
	mutex_lock(&registry->lock);
	list_for_each_entry(p, &registry->members, node) {
		if (p->member.fops == member->fops) {
			err = -EBUSY;
			goto unlock;
		}
	}
	if (registry->fixed) {
		for (i = 0; i < registry->capacity; i++) {
			if (!registry->fixed[i].member.identity) {
				new = &registry->fixed[i];
				break;
			}
		}
		if (!new) {
			err = -ENOSPC;
			goto unlock;
		}
	}
	new->member = *member;
	list_add_tail(&new->node, &registry->members);
unlock:
	mutex_unlock(&registry->lock);
	if (err && !registry->fixed)
		kfree(new);
	return err;
}

bool xdev_ext_comp_copy_registry_unregister(struct xdev_ext_comp_copy_registry *registry,
	const void *identity)
{
	struct xdev_ext_comp_copy_registration *p, *found = NULL;
	bool removed;
	u32 i;

	mutex_lock(&registry->lock);
	/* The fixed registry historically matches NULL against an empty slot. */
	if (registry->fixed && !identity) {
		for (i = 0; i < registry->capacity; i++) {
			if (!registry->fixed[i].member.identity) {
				found = &registry->fixed[i];
				break;
			}
		}
		goto unlock;
	}
	list_for_each_entry(p, &registry->members, node) {
		if (p->member.identity == identity) {
			list_del(&p->node);
			found = p;
			if (registry->fixed)
				p->member = (struct xdev_ext_comp_copy_member){ 0 };
			break;
		}
	}
unlock:
	mutex_unlock(&registry->lock);
	removed = found != NULL;
	if (!registry->fixed)
		kfree(found);
	return removed;
}

bool xdev_ext_comp_copy_registry_get(struct xdev_ext_comp_copy_registry *registry,
	struct file *file, struct xdev_ext_comp_copy_member *out)
{
	struct xdev_ext_comp_copy_registration *p;
	bool found = false;

	*out = (struct xdev_ext_comp_copy_member){ 0 };
	mutex_lock(&registry->lock);
	list_for_each_entry(p, &registry->members, node) {
		if (p->member.fops == file->f_op && try_module_get(p->member.owner)) {
			*out = p->member;
			found = true;
			break;
		}
	}
	mutex_unlock(&registry->lock);
	return found;
}

/* Worker or CREATE: preserve frame order and the first failed read. */
int xdev_ext_comp_copy_collect(struct xdev_ext_comp_copy_stage *cs,
	struct xdev_ext_mech_batch *b)
{
	u32 i, nr = xdev_ext_mech_batch_nr_frames(b);
	struct xdev_ext_mech_frame f;
	int err;

	if (nr > XDEV_EXT_MECH_MAX_FRAMES)
		return -E2BIG;
	for (i = 0; i < nr; i++) {
		err = xdev_ext_mech_batch_frame(b, i, &f);
		if (err)
			return err;
		cs->fi[i] = (struct xdev_ext_mech_frame_info){
			.umem_addr = f.umem_addr,
			.data_off = f.data_off,
			.data_len = f.data_len,
		};
		cs->index[i] = f.index;
	}
	return nr;
}

int xdev_ext_comp_copy_stage_validate(struct xdev_ext_comp_copy_stage *cs,
	struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n,
	u32 max_entries, u32 known_flags)
{
	int nr, err;

	cs->staged = NULL;
	if (!b)
		return -EINVAL;
	if (n > max_entries)
		return -E2BIG;
	nr = xdev_ext_comp_copy_collect(cs, b);
	if (nr < 0)
		return nr;
	err = xdev_ext_comp_copy_validate(&cs->window, cs->fi, cs->index, nr,
		scratch, n, max_entries, known_flags, xdev_ext_mech_batch_slot(b),
		xdev_ext_mech_batch_id(b), &cs->plan);
	if (err)
		return err;
	cs->staged = b;
	return 0;
}

static int xdev_ext_comp_copy_claim(void *batch, __u32 frame_pos,
	__u64 *owner, __u64 *generation)
{
	return xdev_ext_mech_batch_frame_claim(batch, frame_pos, owner, generation);
}

int xdev_ext_comp_copy_stage_submit(struct xdev_ext_comp_copy_stage *cs,
	struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_comp_copy_cookie *ck = xdev_ext_mech_batch_cookie(b);
	struct xdev_ext_mech_batch *staged;
	int err;

	err = cs->ops->lease_get(cs, b);
	if (err)
		return err;
	if (!xdev_ext_window_copy_cookie_arm(&ck->state))
		return -EBUSY;
	if (!ck->b)
		ck->b = b;
	ck->cs = cs;
	staged = cs->staged;
	cs->staged = NULL;
	if (READ_ONCE(cs->dead))
		err = -ENODEV;
	else if (staged != b)
		err = -EPROTO;
	else
		err = xdev_ext_comp_copy_transfer(&cs->plan, xdev_ext_mech_batch_id(b),
			xdev_ext_mech_batch_slot(b), b, xdev_ext_comp_copy_claim, cs->transfer);
	if (!err)
		err = cs->ops->submit(cs, st, b, cs->transfer, cs->plan.n,
			cs->plan.total, ck, xdev_ext_mech_batch_ticket(b));
	if (err >= 0)
		return 0;
	if (!xdev_ext_window_copy_cookie_disarm(&ck->state)) {
		cs->ops->warn(true);
		return 0;
	}
	ck->status = err;
	return err;
}

void xdev_ext_comp_copy_complete(struct xdev_ext_comp_copy_cookie *ck, u64 ticket,
	int status, bool hw_submitted, u64 bytes_done,
	const struct xdev_ext_comp_copy_legacy_ops *ops)
{
	u32 outcome;
	bool sequester;
	int err;

	/* Only the stable batch pointer may be read before ticket admission. */
	if (xdev_ext_mech_batch_completion_claim(ck->b, ticket))
		return;
	if (!xdev_ext_window_copy_cookie_finish(&ck->state)) {
		ops->warn(false);
		atomic_inc(&ck->cs->ambiguous);
		xdev_ext_mech_batch_completion_publish(ck->b, ticket, -EPROTO, true);
		return;
	}
	outcome = ops->classify(ck->b, ticket, &status, &hw_submitted, bytes_done);
	ck->outcome = outcome;
	ck->status = status;
	ck->bytes_done = bytes_done;
	sequester = xdev_ext_window_copy_disposition(outcome, status, &err);
	if (sequester)
		atomic_inc(&ck->cs->ambiguous);
	xdev_ext_mech_batch_completion_publish(ck->b, ticket, err, sequester);
}

void xdev_ext_comp_copy_mark_dead(struct xdev_ext_comp_copy_stage *cs)
{
	WRITE_ONCE(cs->dead, true);
}

int xdev_ext_comp_copy_poll(struct xdev_ext_comp_copy_stage *cs)
{
	return cs->ops->poll(cs);
}

int xdev_ext_comp_copy_unbind(struct xdev_ext_comp_copy_stage *cs)
{
	int err;

	if (atomic_read(&cs->ambiguous))
		return -EBUSY;
	err = cs->ops->unbind_begin(cs);
	if (err)
		return err;
	if (cs->host) {
		err = cs->ops->unbind_host(cs);
		if (err)
			return err;
		cs->host = NULL;
	}
	err = cs->ops->unbind_region(cs);
	if (err)
		return err;
	return cs->ops->unbind_end(cs);
}
