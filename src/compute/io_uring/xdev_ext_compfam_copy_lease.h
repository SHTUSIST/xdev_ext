/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_COMPFAM_COPY_LEASE_H
#define IO_URING_XDEV_EXT_COMPFAM_COPY_LEASE_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "xdev_ext_mech_ce_lease.h"

struct xdev_ext_mech_session;
struct xdev_ext_comp_copy_lease_group;

/* Pure metadata predicates, called only under the owning domain mutex. */
struct xdev_ext_comp_copy_lease_policy {
	bool (*overlap)(const void *a, const void *b);
	bool (*serial)(const void *a, const void *b);
};

struct xdev_ext_comp_copy_lease_domain {
	struct mutex lock;
	struct list_head groups;
	const struct xdev_ext_comp_copy_lease_policy *policy;
};

/* Key storage and any native/scope references remain owned by the adapter. */
struct xdev_ext_comp_copy_lease_region {
	struct list_head node;
	struct xdev_ext_comp_copy_lease_domain *domain;
	struct xdev_ext_comp_copy_lease_group *group;
	const void *key;
	bool cleanup_held;
};

struct xdev_ext_comp_copy_lease_group {
	struct list_head node;
	struct list_head regions;
	struct xdev_ext_mech_session *session;
	struct xdev_ext_ce_lease_state state;
	u32 depth;
	u32 cleanup_holds;
	struct xdev_ext_ce_lease_slot slots[];
};

int xdev_ext_comp_copy_lease_bind(
	struct xdev_ext_comp_copy_lease_domain *domain,
	struct xdev_ext_comp_copy_lease_region *region,
	struct xdev_ext_mech_session *session, u32 depth,
	const void *key, bool hold_at_bind);
int xdev_ext_comp_copy_lease_get(
	struct xdev_ext_comp_copy_lease_region *region,
	u32 slot, u64 batch_id);
int xdev_ext_comp_copy_lease_finish(
	struct xdev_ext_comp_copy_lease_region *region,
	u32 slot, u64 batch_id, bool sequestered);
void xdev_ext_comp_copy_lease_hold(
	struct xdev_ext_comp_copy_lease_region *region, bool hold);
bool xdev_ext_comp_copy_lease_busy(
	struct xdev_ext_comp_copy_lease_region *region);
int xdev_ext_comp_copy_lease_cleanup_begin(
	struct xdev_ext_comp_copy_lease_region *region);
bool xdev_ext_comp_copy_lease_unbind(
	struct xdev_ext_comp_copy_lease_region *region, bool release_hold);

#endif /* IO_URING_XDEV_EXT_COMPFAM_COPY_LEASE_H */
