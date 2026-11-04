// SPDX-License-Identifier: GPL-2.0
/*
 * Copy-engine class of the XDEV_EXT mechanism layer.
 *
 * A CE stage binds one device window through the backend driver whose
 * file_operations the stage fd carries, and hands the session pool pages to
 * that backend once at CREATE.  The class program fills struct
 * xdev_ext_ce_copy_desc entries in the scratch area; C validates them against the
 * window, its contiguous segments and the batch frame spans, translates them
 * into struct xdev_ext_ce_xfer and submits them through the backend from the
 * session worker.  The backend reports once through xdev_ext_ce_complete(), from
 * any context.  C classifies the result: a failure after GPPut or a doorbell
 * was written is AMBIGUOUS, sequesters the batch whatever the program
 * returns, and parks the stage's window, host mapping and backend module
 * reference for good.
 */
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xdev_ext_compfam.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_ce_core.h"
#include "xdev_ext_compfam_copy_runtime.h"
#include "xdev_ext_mech_ce_lease.h"

#define XDEV_EXT_CE_MAX_BACKENDS	4

/* A session atomically owns ALL its bound CE windows while any batch can
 * use them. Reentrant batches keep per-slot depth parallelism for matching
 * bases or disjoint windows; shifted overlapping bases serialize batches.
 * Numeric windows are compared across every device of the same backend,
 * conservatively merging device-node aliases and independent GPU VAs.
 * Distinct VAs aliasing the same physical bytes require backend canonical
 * identity; this contract covers overlapping configured address windows.
 */
struct xdev_ext_ce_lease_group {
	struct list_head node;
	struct list_head regions;
	struct xdev_ext_mech_session *session;
	struct xdev_ext_ce_lease_state state;
	u32 depth;
	u32 cleanup_holds;		/* one contribution per cleanup_held stage */
	struct xdev_ext_ce_lease_slot slots[];
};

static DEFINE_MUTEX(xdev_ext_ce_lease_lock);
static LIST_HEAD(xdev_ext_ce_lease_groups);

/* One CE stage from bind to unbind; parked for good after AMBIGUOUS. */
struct xdev_ext_ce_stage {
	struct list_head lease_node;
	struct xdev_ext_ce_lease_group *lease_group;
	/* C-owned configured identity; native region output cannot weaken it. */
	const struct xdev_ext_ce_backend_ops *ops;
	u64 window_start;
	u64 window_len;
	bool cleanup_held;
	struct xdev_ext_ce_region region;
	struct xdev_ext_ce_geom geom;
	struct xdev_ext_comp_copy_stage copy;
};

_Static_assert(XDEV_EXT_CE_MAX_ENTRIES <=
	       sizeof(((struct xdev_ext_comp_copy_plan *)0)->entry) /
	       sizeof(struct xdev_ext_comp_copy_entry),
	       "CE entries exceed the common copy plan capacity");

struct xdev_ext_ce_batch {
	u64 total;
	u32 n;
	struct xdev_ext_ce_xfer x[XDEV_EXT_CE_MAX_ENTRIES];
};

static struct xdev_ext_comp_copy_registration
xdev_ext_ce_backends[XDEV_EXT_CE_MAX_BACKENDS];
static struct xdev_ext_comp_copy_registry xdev_ext_ce_registry = {
	.lock = __MUTEX_INITIALIZER(xdev_ext_ce_registry.lock),
	.members = LIST_HEAD_INIT(xdev_ext_ce_registry.members),
	.fixed = xdev_ext_ce_backends,
	.capacity = XDEV_EXT_CE_MAX_BACKENDS,
};

int xdev_ext_ce_backend_register(const struct xdev_ext_ce_backend_ops *ops)
{
	struct xdev_ext_comp_copy_member member;

	if (!ops || !ops->fops || !ops->bind_region || !ops->unbind_region ||
	    !ops->bind_host || !ops->unbind_host || !ops->submit)
		return -EINVAL;
	member = (struct xdev_ext_comp_copy_member){
		.identity = ops,
		.fops = ops->fops,
		.owner = ops->owner,
	};
	return xdev_ext_comp_copy_registry_register(&xdev_ext_ce_registry, &member);
}
EXPORT_SYMBOL_GPL(xdev_ext_ce_backend_register);

void xdev_ext_ce_backend_unregister(const struct xdev_ext_ce_backend_ops *ops)
{
	WARN_ON_ONCE(!xdev_ext_comp_copy_registry_unregister(&xdev_ext_ce_registry, ops));
}
EXPORT_SYMBOL_GPL(xdev_ext_ce_backend_unregister);

/* CREATE, process context: the backend of @file, its module pinned. */
static const struct xdev_ext_ce_backend_ops *xdev_ext_ce_backend_get(struct file *file)
{
	struct xdev_ext_comp_copy_member member;

	if (!xdev_ext_comp_copy_registry_get(&xdev_ext_ce_registry, file, &member))
		return NULL;
	return member.identity;
}

/* CREATE publishes configured exclusion before any native mapping can remain. */
static int xdev_ext_ce_lease_bind(struct xdev_ext_mech_stage *st,
		struct xdev_ext_ce_stage *cs, u64 start, u64 len)
{
	struct xdev_ext_ce_lease_group *group, *found = NULL;
	struct xdev_ext_ce_stage *other;
	u32 depth = xdev_ext_mech_session_depth(st->s);

	mutex_lock(&xdev_ext_ce_lease_lock);
	list_for_each_entry(group, &xdev_ext_ce_lease_groups, node)
		if (group->session == st->s) {
			found = group;
			break;
		}
	if (!found) {
		found = kvzalloc(struct_size(found, slots, depth), GFP_KERNEL);
		if (!found) {
			mutex_unlock(&xdev_ext_ce_lease_lock);
			return -ENOMEM;
		}
		INIT_LIST_HEAD(&found->regions);
		found->session = st->s;
		found->depth = depth;
		list_add_tail(&found->node, &xdev_ext_ce_lease_groups);
	}
	/* Relative slot offsets are shared across stages. With shifted bases,
	 * slot N of one stage may overlap slot M of another. Bind finishes
	 * before ACTIVE, so this conservative group policy is then immutable.
	 */
	list_for_each_entry(other, &found->regions, lease_node)
		if (other->window_start != start &&
		    xdev_ext_ce_lease_overlap(other->ops,
			other->window_start, other->window_len,
			cs->ops, start, len))
			found->state.serial_batches = true;
	cs->lease_group = found;
	cs->window_start = start;
	cs->window_len = len;
	cs->cleanup_held = true;
	found->cleanup_holds++;
	list_add_tail(&cs->lease_node, &found->regions);
	mutex_unlock(&xdev_ext_ce_lease_lock);
	return 0;
}

/* Only complete bind success permits normal overlap scheduling. */
static void xdev_ext_ce_lease_bind_ready(struct xdev_ext_ce_stage *cs)
{
	struct xdev_ext_ce_lease_group *group = cs->lease_group;

	mutex_lock(&xdev_ext_ce_lease_lock);
	if (cs->cleanup_held) {
		group->cleanup_holds--;
		cs->cleanup_held = false;
	}
	mutex_unlock(&xdev_ext_ce_lease_lock);
}

/* Worker: acquire all ranges in one transaction, before any native CE work.
 * EAGAIN uses the core's preaccept retry; no accepted command is replayed.
 */
static int xdev_ext_ce_lease_get(struct xdev_ext_ce_stage *cs,
		struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_ce_lease_group *group = cs->lease_group, *other;
	struct xdev_ext_ce_stage *a, *held;
	u32 slot = xdev_ext_mech_batch_slot(b);
	bool conflict = false, cleanup_conflict = false;
	int ret;

	if (slot >= group->depth)
		return -ERANGE;
	mutex_lock(&xdev_ext_ce_lease_lock);
	list_for_each_entry(other, &xdev_ext_ce_lease_groups, node) {
		if (other == group)
			continue;
		if (!other->cleanup_holds &&
		    (group->state.active_batches || !other->state.active_batches))
			continue;
		list_for_each_entry(a, &group->regions, lease_node)
			list_for_each_entry(held, &other->regions, lease_node)
				if (xdev_ext_ce_lease_overlap(a->ops,
					a->window_start, a->window_len,
					held->ops, held->window_start,
					held->window_len)) {
					conflict = true;
					cleanup_conflict = other->cleanup_holds != 0;
					goto checked;
				}
	}
checked:
	if (cleanup_conflict)
		ret = -EAGAIN;
	else if (group->cleanup_holds)
		ret = -EBUSY;
	else
		ret = xdev_ext_ce_lease_acquire(&group->state, &group->slots[slot],
					      xdev_ext_mech_batch_id(b), conflict);
	mutex_unlock(&xdev_ext_ce_lease_lock);
	return ret;
}

/* All CE stages see the same final batch fate. The slot marker releases
 * exactly once, and an unknown batch keeps the entire group quarantined.
 */
static void xdev_ext_ce_batch_release(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, bool sequestered)
{
	struct xdev_ext_ce_stage *cs = st->priv;
	struct xdev_ext_ce_lease_group *group = cs->lease_group;
	u32 slot = xdev_ext_mech_batch_slot(b);
	int ret;

	if (WARN_ON_ONCE(slot >= group->depth))
		return;
	mutex_lock(&xdev_ext_ce_lease_lock);
	ret = xdev_ext_ce_lease_finish(&group->state, &group->slots[slot],
				     xdev_ext_mech_batch_id(b), sequestered);
	WARN_ON_ONCE(ret && ret != -EBUSY);
	mutex_unlock(&xdev_ext_ce_lease_lock);
}

/* Checked cleanup holds exclusion before entering either native unmap. */
static int xdev_ext_ce_lease_cleanup_begin(struct xdev_ext_ce_stage *cs)
{
	struct xdev_ext_ce_lease_group *group = cs->lease_group;

	if (!group)
		return 0;
	mutex_lock(&xdev_ext_ce_lease_lock);
	if (group->state.active_batches || group->state.quarantined) {
		mutex_unlock(&xdev_ext_ce_lease_lock);
		return -EBUSY;
	}
	if (!cs->cleanup_held) {
		cs->cleanup_held = true;
		group->cleanup_holds++;
	}
	mutex_unlock(&xdev_ext_ce_lease_lock);
	return 0;
}

/* Both native handles are clear; release this hold and range atomically. */
static bool xdev_ext_ce_lease_unbind(struct xdev_ext_ce_stage *cs)
{
	struct xdev_ext_ce_lease_group *group = cs->lease_group;
	bool empty;

	mutex_lock(&xdev_ext_ce_lease_lock);
	if (WARN_ON_ONCE(group->state.active_batches || group->state.quarantined)) {
		mutex_unlock(&xdev_ext_ce_lease_lock);
		return false;
	}
	if (cs->cleanup_held) {
		group->cleanup_holds--;
		cs->cleanup_held = false;
	}
	list_del(&cs->lease_node);
	cs->lease_group = NULL;
	empty = list_empty(&group->regions);
	if (empty)
		list_del(&group->node);
	mutex_unlock(&xdev_ext_ce_lease_lock);
	if (empty)
		kvfree(group);
	return true;
}

static int xdev_ext_ce_copy_lease_get(struct xdev_ext_comp_copy_stage *copy,
	struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_ce_stage *cs = container_of(copy, struct xdev_ext_ce_stage, copy);

	return xdev_ext_ce_lease_get(cs, b);
}

/* Native callbacks retain the typed batch array, never the worker scratch. */
static int xdev_ext_ce_copy_submit(struct xdev_ext_comp_copy_stage *copy,
	struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
	const struct xdev_ext_comp_copy_transfer *x, u32 n, u64 total,
	struct xdev_ext_comp_copy_cookie *ck, u64 ticket)
{
	struct xdev_ext_ce_stage *cs = container_of(copy, struct xdev_ext_ce_stage, copy);
	struct xdev_ext_ce_batch *cb = xdev_ext_mech_batch_priv(b);
	u32 i;

	for (i = 0; i < n; i++)
		cb->x[i] = (struct xdev_ext_ce_xfer){
			.owner = x[i].owner,
			.generation = x[i].generation,
			.host_byte_off = x[i].host_byte_off,
			.gpu_off = x[i].device_off,
			.len = x[i].len,
			.flags = x[i].flags,
		};
	cb->n = n;
	cb->total = total;
	return cs->ops->submit(&cs->region, copy->host, st->direction,
		cb->x, cb->n, (struct xdev_ext_ce_cookie *)ck, ticket);
}

static u32 xdev_ext_ce_copy_classify(struct xdev_ext_mech_batch *b, u64 ticket,
	int *status, bool *hw_submitted, u64 bytes_done)
{
	const struct xdev_ext_ce_batch *cb = xdev_ext_mech_batch_priv(b);

	*status = xdev_ext_ce_completion_status(*status, *hw_submitted, bytes_done,
		cb->total);
	return xdev_ext_ce_classify(*status, *hw_submitted);
}

static int xdev_ext_ce_copy_unbind_begin(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_ce_stage *cs = container_of(copy, struct xdev_ext_ce_stage, copy);

	return xdev_ext_ce_lease_cleanup_begin(cs);
}

static int xdev_ext_ce_copy_unbind_host(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_ce_stage *cs = container_of(copy, struct xdev_ext_ce_stage, copy);

	return cs->ops->unbind_host(copy->host);
}

static int xdev_ext_ce_copy_unbind_region(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_ce_stage *cs = container_of(copy, struct xdev_ext_ce_stage, copy);
	int err;

	if (!cs->region.priv)
		return 0;
	err = cs->ops->unbind_region(&cs->region);
	if (err)
		return err;
	cs->region.priv = NULL;
	return 0;
}

static int xdev_ext_ce_copy_unbind_end(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_ce_stage *cs = container_of(copy, struct xdev_ext_ce_stage, copy);

	if (cs->lease_group && !xdev_ext_ce_lease_unbind(cs))
		return -EBUSY;
	return 0;
}

static void xdev_ext_ce_copy_warn(bool refused_submit)
{
	if (refused_submit)
		WARN_ONCE(1, "xdev_ext_mech_ce: backend completed a refused submit\n");
	else
		WARN_ONCE(1, "xdev_ext_mech_ce: completion without an accepted submit\n");
}

static const struct xdev_ext_comp_copy_legacy_ops xdev_ext_ce_copy_ops = {
	.lease_get = xdev_ext_ce_copy_lease_get,
	.submit = xdev_ext_ce_copy_submit,
	.classify = xdev_ext_ce_copy_classify,
	.unbind_begin = xdev_ext_ce_copy_unbind_begin,
	.unbind_host = xdev_ext_ce_copy_unbind_host,
	.unbind_region = xdev_ext_ce_copy_unbind_region,
	.unbind_end = xdev_ext_ce_copy_unbind_end,
	.warn = xdev_ext_ce_copy_warn,
};

static int xdev_ext_ce_bind(struct xdev_ext_mech_stage *st,
		       const struct xdev_ext_mech_stage_uapi *u)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	const struct xdev_ext_ce_backend_ops *ops;
	struct xdev_ext_ce_stage *cs;
	struct xdev_ext_window_copy_geom geom;
	int err;

	if (u->flags || (st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
			 st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
		return -EINVAL;
	if (!pool || !pool->pages)
		return -EINVAL;
	if (!u->arg1 || u->arg0 > U64_MAX - u->arg1)
		return -EINVAL;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return -ENOMEM;
	ops = xdev_ext_ce_backend_get(st->file);
	if (!ops) {
		err = -ENODEV;
		goto free;
	}
	/* Publish ownership and configured exclusion before native effects. A
	 * failed bind stays in checked CREATE rollback, with its original pool
	 * pins and exclusion retained if native cleanup refuses.
	 */
	cs->ops = ops;
	cs->copy.ops = &xdev_ext_ce_copy_ops;
	cs->region.ops = ops;
	st->priv = cs;
	err = xdev_ext_ce_lease_bind(st, cs, u->arg0, u->arg1);
	if (err)
		return err;
	err = cs->ops->bind_region(st->file, u->arg0, u->arg1, &cs->region);
	cs->region.ops = cs->ops;
	if (err)
		return err;
	err = xdev_ext_ce_geom_init(&cs->geom, u->arg1, cs->region.len,
			cs->region.seg_size, cs->region.max_entry_len,
			(u64)pool->nr_pages << PAGE_SHIFT,
			pool->first_page_off, pool->frame_size, pool->nr_frames);
	if (err)
		return err;
	geom = xdev_ext_ce_window_geom(&cs->geom);
	err = xdev_ext_comp_copy_prepare(&cs->copy.window, XDEV_EXT_COMP_COPY_WINDOW, &geom,
		st->direction, xdev_ext_mech_session_depth(st->s),
		xdev_ext_mech_session_layout(st->s)->group_bytes);
	if (err)
		return err;
	err = cs->ops->bind_host(&cs->region, pool->pages, pool->nr_pages, &cs->copy.host);
	if (err)
		return err;
	xdev_ext_ce_lease_bind_ready(cs);
	return 0;
free:
	kfree(cs);
	return err;
}

static int xdev_ext_ce_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_ce_stage *cs = st->priv;
	const struct xdev_ext_ce_backend_ops *native_ops;
	int err;

	if (!cs)
		return 0;
	native_ops = cs->ops;
	err = xdev_ext_comp_copy_unbind(&cs->copy);
	if (err)
		return err;
	st->priv = NULL;
	kfree(cs);
	module_put(native_ops->owner);
	return 0;
}

static void xdev_ext_ce_fill_info(struct xdev_ext_mech_stage *st,
			     struct xdev_ext_mech_batch *b, void *info)
{
	struct xdev_ext_ce_stage *cs = st->priv;
	int nr = b ? xdev_ext_comp_copy_collect(&cs->copy, b) : 0;

	/* Unreadable frames show as none; validate then refuses the batch. */
	if (nr < 0)
		nr = 0;
	xdev_ext_ce_info_fill(info, xdev_ext_mech_session_layout(st->s), &cs->geom,
			 cs->copy.fi, nr);
	if (b) {
		struct xdev_ext_ce_mech_info *ci = info;

		ci->window_slot = xdev_ext_mech_batch_slot(b);
		ci->window_depth = xdev_ext_mech_session_depth(st->s);
		ci->lease_generation = xdev_ext_mech_batch_id(b);
	}
}

static int xdev_ext_ce_validate(struct xdev_ext_mech_stage *st,
	struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
	struct xdev_ext_ce_stage *cs = st->priv;

	return xdev_ext_comp_copy_stage_validate(&cs->copy, b, scratch, n,
		XDEV_EXT_CE_MAX_ENTRIES, XDEV_EXT_CE_F_KNOWN_MASK);
}

static int xdev_ext_ce_submit(struct xdev_ext_mech_stage *st,
	struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_ce_stage *cs = st->priv;

	return xdev_ext_comp_copy_stage_submit(&cs->copy, st, b);
}

bool xdev_ext_ce_owners_valid(struct xdev_ext_ce_cookie *native_ck, u64 ticket,
	const struct xdev_ext_ce_xfer *x, u32 n)
{
	struct xdev_ext_comp_copy_cookie *ck = (struct xdev_ext_comp_copy_cookie *)native_ck;

	/* b is stable; the core admits the ticket before reading transfers. */
	return ck && ck->b && xdev_ext_mech_batch_ce_owners_valid(ck->b, ticket, x, n);
}
EXPORT_SYMBOL_GPL(xdev_ext_ce_owners_valid);

void xdev_ext_ce_complete(struct xdev_ext_ce_cookie *ck, u64 ticket, int status,
	bool hw_submitted, u64 bytes_done)
{
	xdev_ext_comp_copy_complete((struct xdev_ext_comp_copy_cookie *)ck, ticket,
		status, hw_submitted, bytes_done, &xdev_ext_ce_copy_ops);
}
EXPORT_SYMBOL_GPL(xdev_ext_ce_complete);

static void xdev_ext_ce_fill_cqe(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			    void *cqe)
{
	const struct xdev_ext_ce_batch *cb = xdev_ext_mech_batch_priv(b);
	const struct xdev_ext_comp_copy_cookie *ck = xdev_ext_mech_batch_cookie(b);

	xdev_ext_ce_cqe_fill(cqe, READ_ONCE(ck->state), ck->outcome, ck->status,
			ck->bytes_done, cb->total, cb->n);
}

static void xdev_ext_ce_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_ce_stage *cs = st->priv;

	xdev_ext_comp_copy_mark_dead(&cs->copy);
}

static const struct xdev_ext_comp_hooks xdev_ext_ce_comp_hooks = {
	.hdr = { .family = XDEV_EXT_FAMILY_COMPUTE },
	.kinds = 1U << XDEV_EXT_COMP_COPY_WINDOW,
	.producer_visibility = XDEV_EXT_CAP_NOT_WIRED,
};

static const struct xdev_ext_mech_class_ops xdev_ext_ce_class = {
 .decl = &xdev_ext_mech_class_decls[XDEV_EXT_MECH_CLASS_CE],
	.class_id	= XDEV_EXT_MECH_CLASS_CE,
	.desc_size	= sizeof(struct xdev_ext_ce_copy_desc),
	.desc_cap	= XDEV_EXT_CE_MAX_ENTRIES,
	.info_size	= sizeof(struct xdev_ext_ce_mech_info),
	.cqe_size	= sizeof(struct xdev_ext_ce_mech_cqe),
	.cqe_cap	= 1,
	.batch_priv_size = sizeof(struct xdev_ext_ce_batch),
	.batch_cookie_size = sizeof(struct xdev_ext_comp_copy_cookie),
	.owner		= THIS_MODULE,
	.bind		= xdev_ext_ce_bind,
	.unbind_checked	= xdev_ext_ce_unbind,
	.fill_info	= xdev_ext_ce_fill_info,
	.validate	= xdev_ext_ce_validate,
	.submit		= xdev_ext_ce_submit,
	.fill_cqe	= xdev_ext_ce_fill_cqe,
	.mark_dead	= xdev_ext_ce_mark_dead,
	.batch_release	= xdev_ext_ce_batch_release,
	.fam.comp	= &xdev_ext_ce_comp_hooks,
};

/* After every late_initcall, so the core's own initialisation has run. */
static int __init xdev_ext_mech_ce_init(void)
{
	int err = xdev_ext_mech_class_register(&xdev_ext_ce_class);

	if (err)
		pr_err("xdev_ext_mech_ce: class registration failed: %d\n", err);
	return err;
}
late_initcall_sync(xdev_ext_mech_ce_init);
