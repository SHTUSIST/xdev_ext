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

int xdev_ext_comp_copy_lease_get(
	struct xdev_ext_comp_copy_lease_region *region,
	u32 slot, u64 batch_id)
{
	struct xdev_ext_comp_copy_lease_group *group = region->group, *other;
	struct xdev_ext_comp_copy_lease_domain *domain = region->domain;
	struct xdev_ext_comp_copy_lease_region *a, *held;
	bool conflict = false, cleanup_conflict = false;
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
	else
		ret = xdev_ext_ce_lease_acquire(&group->state, &group->slots[slot],
					      batch_id, conflict);
	mutex_unlock(&domain->lock);
	return ret;
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
