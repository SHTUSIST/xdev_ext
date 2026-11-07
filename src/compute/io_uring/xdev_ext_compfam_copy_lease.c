// SPDX-License-Identifier: GPL-2.0
/* Session-wide copy exclusion; native ownership stays in the typed adapters. */
#include <linux/slab.h>

#include "xdev_ext_compfam_copy_lease.h"

int xdev_ext_comp_copy_lease_bind(
	struct xdev_ext_comp_copy_lease_domain *domain,
	struct xdev_ext_comp_copy_lease_region *region,
	struct xdev_ext_mech_session *session, u32 depth,
	const void *key, bool hold_at_bind)
{
	struct xdev_ext_comp_copy_lease_group *group, *found = NULL;
	struct xdev_ext_comp_copy_lease_region *other;

	mutex_lock(&domain->lock);
	list_for_each_entry(group, &domain->groups, node)
		if (group->session == session) {
			found = group;
			break;
		}
	if (!found) {
		found = kvzalloc(struct_size(found, slots, depth), GFP_KERNEL);
		if (!found) {
			mutex_unlock(&domain->lock);
			return -ENOMEM;
		}
		INIT_LIST_HEAD(&found->regions);
		found->session = session;
		found->depth = depth;
		list_add_tail(&found->node, &domain->groups);
	}
	/* Shifted aliases can overlap different slots. Keep serialization sticky
	 * even when the region that established it is later removed.
	 */
	list_for_each_entry(other, &found->regions, node)
		if (domain->policy->serial(other->key, key))
			found->state.serial_batches = true;
	region->domain = domain;
	region->group = found;
	region->key = key;
	region->cleanup_held = hold_at_bind;
	if (hold_at_bind)
		found->cleanup_holds++;
	list_add_tail(&region->node, &found->regions);
	mutex_unlock(&domain->lock);
	return 0;
}

static int xdev_ext_comp_copy_lease_get_mode(
	struct xdev_ext_comp_copy_lease_region *region,
	u32 slot, u64 batch_id, bool target_range, u64 start, u64 len)
{
	struct xdev_ext_comp_copy_lease_group *group = region->group, *other;
	struct xdev_ext_comp_copy_lease_domain *domain = region->domain;
	struct xdev_ext_comp_copy_lease_region *a, *held;
	bool conflict = false, cleanup_conflict = false;
	struct xdev_ext_ce_lease_slot *owner;
	u32 i;
	int ret;

	if (slot >= group->depth)
		return -ERANGE;
	mutex_lock(&domain->lock);
	list_for_each_entry(other, &domain->groups, node) {
		if (other == group)
			continue;
		if (!other->cleanup_holds &&
		    (group->state.active_batches || !other->state.active_batches))
			continue;
		list_for_each_entry(a, &group->regions, node)
			list_for_each_entry(held, &other->regions, node)
				if (domain->policy->overlap(a->key, held->key)) {
					conflict = true;
					cleanup_conflict = other->cleanup_holds != 0;
					goto checked;
				}
	}
checked:
	/* First overlap wins, including cleanup before same-batch idempotence. */
	if (cleanup_conflict)
		ret = -EAGAIN;
	else if (group->cleanup_holds)
		ret = -EBUSY;
	else if (!batch_id)
		ret = -EINVAL;
	else if (group->state.quarantined)
		ret = -EBUSY;
	else {
		owner = &group->slots[slot];
		if (owner->active && owner->generation != batch_id) {
			ret = -EBUSY;
			goto unlock;
		}
		if (owner->active &&
		    (owner->target_range != target_range ||
		     (target_range && (owner->range_start != start || owner->range_len != len)))) {
			ret = -EPROTO;
			goto unlock;
		}
		/* Range mode has exactly one CE window in this session. Check every
		 * other active owner and publish under this same domain lock. Mixed
		 * legacy/range metadata has no sharing proof, so fail closed.
		 */
		for (i = 0; i < group->depth; i++) {
			const struct xdev_ext_ce_lease_slot *reserved = &group->slots[i];

			if (i == slot || !reserved->active)
				continue;
			if ((target_range || reserved->target_range) &&
			    (!target_range || !reserved->target_range ||
			     xdev_ext_ce_lease_overlap(group, start, len, group,
						      reserved->range_start, reserved->range_len))) {
				ret = -EAGAIN;
				goto unlock;
			}
		}
		ret = xdev_ext_ce_lease_acquire(&group->state, &group->slots[slot],
					      batch_id, conflict);
		if (!ret) {
			owner->target_range = target_range;
			owner->range_start = target_range ? start : 0;
			owner->range_len = target_range ? len : 0;
		}
	}
unlock:
	mutex_unlock(&domain->lock);
	return ret;
}

int xdev_ext_comp_copy_lease_get(
	struct xdev_ext_comp_copy_lease_region *region,
	u32 slot, u64 batch_id)
{
	return xdev_ext_comp_copy_lease_get_mode(region, slot, batch_id, false, 0, 0);
}

int xdev_ext_comp_copy_lease_get_range(
	struct xdev_ext_comp_copy_lease_region *region,
	u32 slot, u64 batch_id, u64 start, u64 len)
{
	if (!len || start > ~0ULL - len)
		return -ERANGE;
	return xdev_ext_comp_copy_lease_get_mode(region, slot, batch_id, true, start, len);
}

int xdev_ext_comp_copy_lease_finish(
	struct xdev_ext_comp_copy_lease_region *region,
	u32 slot, u64 batch_id, bool sequestered)
{
	struct xdev_ext_comp_copy_lease_group *group = region->group;
	struct xdev_ext_comp_copy_lease_domain *domain = region->domain;
	int ret;

	if (slot >= group->depth)
		return -ERANGE;
	mutex_lock(&domain->lock);
	ret = xdev_ext_ce_lease_finish(&group->state, &group->slots[slot],
				     batch_id, sequestered);
	if (!ret && !group->slots[slot].active) {
		group->slots[slot].target_range = false;
		group->slots[slot].range_start = 0;
		group->slots[slot].range_len = 0;
	}
	mutex_unlock(&domain->lock);
	return ret;
}

void xdev_ext_comp_copy_lease_hold(
	struct xdev_ext_comp_copy_lease_region *region, bool hold)
{
	struct xdev_ext_comp_copy_lease_group *group = region->group;
	struct xdev_ext_comp_copy_lease_domain *domain;

	if (!group)
		return;
	domain = region->domain;
	mutex_lock(&domain->lock);
	if (region->cleanup_held != hold) {
		if (hold)
			group->cleanup_holds++;
		else
			group->cleanup_holds--;
		region->cleanup_held = hold;
	}
	mutex_unlock(&domain->lock);
}

bool xdev_ext_comp_copy_lease_busy(
	struct xdev_ext_comp_copy_lease_region *region)
{
	struct xdev_ext_comp_copy_lease_group *group = region->group;
	struct xdev_ext_comp_copy_lease_domain *domain = region->domain;
	bool busy;

	mutex_lock(&domain->lock);
	busy = group->state.active_batches || group->state.quarantined;
	mutex_unlock(&domain->lock);
	return busy;
}

int xdev_ext_comp_copy_lease_cleanup_begin(
	struct xdev_ext_comp_copy_lease_region *region)
{
	struct xdev_ext_comp_copy_lease_group *group = region->group;
	struct xdev_ext_comp_copy_lease_domain *domain;

	if (!group)
		return 0;
	domain = region->domain;
	mutex_lock(&domain->lock);
	if (group->state.active_batches || group->state.quarantined) {
		mutex_unlock(&domain->lock);
		return -EBUSY;
	}
	if (!region->cleanup_held) {
		region->cleanup_held = true;
		group->cleanup_holds++;
	}
	mutex_unlock(&domain->lock);
	return 0;
}

bool xdev_ext_comp_copy_lease_unbind(
	struct xdev_ext_comp_copy_lease_region *region, bool release_hold)
{
	struct xdev_ext_comp_copy_lease_group *group = region->group;
	struct xdev_ext_comp_copy_lease_domain *domain = region->domain;
	bool empty;

	mutex_lock(&domain->lock);
	if (group->state.active_batches || group->state.quarantined) {
		mutex_unlock(&domain->lock);
		return false;
	}
	if (release_hold && region->cleanup_held) {
		group->cleanup_holds--;
		region->cleanup_held = false;
	}
	list_del(&region->node);
	region->group = NULL;
	empty = list_empty(&group->regions);
	if (empty)
		list_del(&group->node);
	mutex_unlock(&domain->lock);
	if (empty)
		kvfree(group);
	return true;
}
