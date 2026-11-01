// SPDX-License-Identifier: GPL-2.0
/*
 * Generic registered DMA provider class of the XDEV_EXT mechanism layer.
 *
 * A DMA stage binds one device window through the provider driver whose
 * file_operations the stage fd carries, and hands the session pool pages to
 * that provider once at CREATE.  The class program fills struct
 * xdev_ext_dma_copy_desc entries in the scratch area; C validates them against the
 * window, its contiguous segments and the batch frame spans, translates them
 * into struct xdev_ext_dma_xfer and submits them through the provider from the
 * session worker.  The provider reports once through xdev_ext_dma_complete(), from
 * any context.  C classifies the result: a failure after a native queue or doorbell
 * was written is AMBIGUOUS, sequesters the batch whatever the program
 * returns, and parks the stage's window, host mapping and provider module
 * reference for good.
 */
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xdev_ext_compfam.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_dma_core.h"
#include "xdev_ext_mech_native_cookie.h"
#include "xdev_ext_mech_ce_lease.h"
#include "xdev_ext_mech_window.h"

/* The creator ref is owned by the real backing space, without a module self-pin.
 * Every external ref separately pins this object's release-code owner. */
struct xdev_ext_dma_scope {
	refcount_t refs;
	struct module *owner;
	void *private_data;
	void (*release)(void *private_data);
};

struct xdev_ext_dma_scope *xdev_ext_dma_scope_create(struct module *owner,
		void *private_data, void (*release)(void *private_data))
{
	struct xdev_ext_dma_scope *scope;

	if (!release)
		return ERR_PTR(-EINVAL);
	scope = kmalloc(sizeof(*scope), GFP_KERNEL);
	if (!scope)
		return ERR_PTR(-ENOMEM);
	refcount_set(&scope->refs, 1);
	scope->owner = owner;
	scope->private_data = private_data;
	scope->release = release;
	return scope;
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_scope_create);

static void xdev_ext_dma_scope_ref_put(struct xdev_ext_dma_scope *scope)
{
	if (refcount_dec_and_test(&scope->refs)) {
		scope->release(scope->private_data);
		kfree(scope);
	}
}

void xdev_ext_dma_scope_owner_put(struct xdev_ext_dma_scope *scope)
{
	xdev_ext_dma_scope_ref_put(scope);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_scope_owner_put);

int xdev_ext_dma_scope_get(struct xdev_ext_dma_scope *scope)
{
	struct module *owner;

	if (!scope)
		return -EINVAL;
	owner = scope->owner;
	if (!try_module_get(owner))
		return -ENODEV;
	if (!refcount_inc_not_zero(&scope->refs)) {
		module_put(owner);
		return -ESTALE;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_scope_get);

void xdev_ext_dma_scope_put(struct xdev_ext_dma_scope *scope)
{
	struct module *owner = scope->owner;

	xdev_ext_dma_scope_ref_put(scope);
	module_put(owner);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_scope_put);

/* Registry has no fixed provider count; sessions pin ops->owner under lock. */
struct xdev_ext_dma_provider {
	struct list_head node;
	const struct xdev_ext_dma_provider_ops *ops;
	const struct xdev_ext_dma_scope_ops *scope_ops;
};

/* A session atomically owns ALL its bound DMA windows while any batch can
 * use them. Reentrant batches keep per-slot depth parallelism for matching
 * bases or disjoint windows; shifted overlapping bases serialize batches.
 * Legacy providers compare numeric windows. Scoped providers supply immutable
 * canonical coordinates and a pinned backing identity; unknown or mixed
 * identities conservatively exclude the whole provider namespace.
 */
struct xdev_ext_dma_lease_group {
	struct list_head node;
	struct list_head regions;
	struct xdev_ext_mech_session *session;
	struct xdev_ext_ce_lease_state state;
	u32 depth;
 u32 cleanup_holds; /* refused unmaps retain cross-session exclusion */
	struct xdev_ext_ce_lease_slot slots[];
};

static DEFINE_MUTEX(xdev_ext_dma_lease_lock);
static LIST_HEAD(xdev_ext_dma_lease_groups);

/* One DMA stage from bind to unbind; parked for good after AMBIGUOUS. */
struct xdev_ext_dma_stage {
 const struct xdev_ext_dma_provider_ops *ops; /* C-owned identity and pin */
	struct list_head lease_node;
	struct xdev_ext_dma_lease_group *lease_group;
	struct xdev_ext_dma_scope_key key;
	struct xdev_ext_dma_scope *scope; /* one owned external ref; key borrows it */
 bool cleanup_held;
	struct xdev_ext_dma_region region;
	void *host;			/* bind_host() handle of the pool pages */
	struct xdev_ext_dma_geom geom;
	atomic_t ambiguous;		/* AMBIGUOUS completions on this stage */
	bool dead;
	/* session worker only: the plan validate accepted, until submit */
	struct xdev_ext_mech_batch *staged;
	struct xdev_ext_dma_plan plan;
	struct xdev_ext_dma_copy_desc d[XDEV_EXT_DMA_MAX_ENTRIES];
	struct xdev_ext_mech_frame_info fi[XDEV_EXT_MECH_MAX_FRAMES];
	u32 index[XDEV_EXT_MECH_MAX_FRAMES];
};

/* Stable per-batch storage: never overwritten by another stage's private area.
 * b is initialized once and remains safe to dereference for stale-ticket rejection.
 */
struct xdev_ext_dma_cookie {
	struct xdev_ext_mech_batch *b;
	struct xdev_ext_dma_stage *cs;
	u64 bytes_done;
	int status;
	u32 outcome;			/* enum xdev_ext_dma_outcome */
	u8 state;			/* enum xdev_ext_dma_cookie_state */
};
XDEV_EXT_NATIVE_COOKIE_ASSERT(struct xdev_ext_dma_cookie);

struct xdev_ext_dma_batch {
	u64 total;
	u32 n;
	struct xdev_ext_dma_xfer x[XDEV_EXT_DMA_MAX_ENTRIES];
};

static DEFINE_MUTEX(xdev_ext_dma_provider_lock);
static LIST_HEAD(xdev_ext_dma_providers);

static int xdev_ext_dma_provider_register_common(
 const struct xdev_ext_dma_provider_ops *ops,
 const struct xdev_ext_dma_scope_ops *scope_ops, bool scoped)
{
	struct xdev_ext_dma_provider *p, *new;
	int err = 0;

	if (!ops || !ops->fops || !ops->bind_region || !ops->unbind_region ||
	    !ops->bind_host || !ops->unbind_host || !ops->submit)
		return -EINVAL;
	if (scoped) {
		if (!scope_ops || scope_ops->size != sizeof(*scope_ops))
			return -EINVAL;
		if (scope_ops->version != XDEV_EXT_DMA_SCOPE_OPS_VERSION)
			return -EOPNOTSUPP;
		if (scope_ops->flags || scope_ops->reserved || !scope_ops->acquire)
			return -EINVAL;
	}
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	new->ops = ops;
	new->scope_ops = scope_ops;
	mutex_lock(&xdev_ext_dma_provider_lock);
	list_for_each_entry(p, &xdev_ext_dma_providers, node) {
		if (p->ops->fops == ops->fops) {
			err = -EBUSY;
			break;
		}
	}
	if (!err)
		list_add_tail(&new->node, &xdev_ext_dma_providers);
	mutex_unlock(&xdev_ext_dma_provider_lock);
	if (err)
		kfree(new);
	return err;
}
int xdev_ext_dma_provider_register(const struct xdev_ext_dma_provider_ops *ops)
{
 return xdev_ext_dma_provider_register_common(ops, NULL, false);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_provider_register);

int xdev_ext_dma_provider_register_scoped(const struct xdev_ext_dma_provider_ops *ops,
 const struct xdev_ext_dma_scope_ops *scope_ops)
{
 return xdev_ext_dma_provider_register_common(ops, scope_ops, true);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_provider_register_scoped);

void xdev_ext_dma_provider_unregister(const struct xdev_ext_dma_provider_ops *ops)
{
	struct xdev_ext_dma_provider *p, *found = NULL;

	mutex_lock(&xdev_ext_dma_provider_lock);
	list_for_each_entry(p, &xdev_ext_dma_providers, node) {
		if (p->ops == ops) {
			list_del(&p->node);
			found = p;
			break;
		}
	}
	mutex_unlock(&xdev_ext_dma_provider_lock);
	WARN_ON_ONCE(!found);
	kfree(found);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_provider_unregister);

/* CREATE: select by file operations and pin before releasing registry lock. */
static const struct xdev_ext_dma_provider_ops *xdev_ext_dma_provider_get(
 struct file *file, const struct xdev_ext_dma_scope_ops **scope_ops)
{
	const struct xdev_ext_dma_provider_ops *ops = NULL;
	struct xdev_ext_dma_provider *p;

	*scope_ops = NULL;
	mutex_lock(&xdev_ext_dma_provider_lock);
	list_for_each_entry(p, &xdev_ext_dma_providers, node) {
		if (p->ops->fops == file->f_op && try_module_get(p->ops->owner)) {
			ops = p->ops;
			*scope_ops = p->scope_ops;
			break;
		}
	}
	mutex_unlock(&xdev_ext_dma_provider_lock);
	return ops;
}

/* No native effects here. A non-NULL output always transfers one get-ref,
 * even on provider error; checked CREATE rollback will return it exactly once. */
static int xdev_ext_dma_stage_scope(struct xdev_ext_dma_stage *cs,
 const struct xdev_ext_dma_scope_ops *scope_ops, struct file *file, u64 start, u64 len)
{
 struct xdev_ext_dma_scope_info info = { .kind = XDEV_EXT_DMA_SCOPE_UNKNOWN };
 int err;

 cs->key = (struct xdev_ext_dma_scope_key) {
  .provider = cs->ops, .kind = XDEV_EXT_DMA_SCOPE_LEGACY,
  .start = start, .len = len,
 };
 if (!scope_ops)
  return 0;
 err = scope_ops->acquire(file, start, len, &info);
 cs->scope = info.scope;
 if (err)
  return err < 0 ? err : -EPROTO;
 if (info.reserved ||
     (info.kind != XDEV_EXT_DMA_SCOPE_UNKNOWN && info.kind != XDEV_EXT_DMA_SCOPE_KNOWN) ||
     (info.kind == XDEV_EXT_DMA_SCOPE_KNOWN && info.canonical_len != len))
  return -EPROTO;
 cs->key = (struct xdev_ext_dma_scope_key) {
  .provider = cs->ops, .kind = info.kind, .scope = info.scope,
  .start = info.canonical_start, .len = info.canonical_len,
 };
 return xdev_ext_dma_scope_key_valid(&cs->key) ? 0 : -EPROTO;
}

/* CREATE cannot activate a session until every bound region is registered. */
static int xdev_ext_dma_lease_bind(struct xdev_ext_mech_stage *st,
		struct xdev_ext_dma_stage *cs)
{
	struct xdev_ext_dma_lease_group *group, *found = NULL;
	struct xdev_ext_dma_stage *other;
	u32 depth = xdev_ext_mech_session_depth(st->s);

	mutex_lock(&xdev_ext_dma_lease_lock);
	list_for_each_entry(group, &xdev_ext_dma_lease_groups, node)
		if (group->session == st->s) {
			found = group;
			break;
		}
	if (!found) {
		found = kvzalloc(struct_size(found, slots, depth), GFP_KERNEL);
		if (!found) {
			mutex_unlock(&xdev_ext_dma_lease_lock);
			return -ENOMEM;
		}
		INIT_LIST_HEAD(&found->regions);
		found->session = st->s;
		found->depth = depth;
		list_add_tail(&found->node, &xdev_ext_dma_lease_groups);
	}
	/* Relative slot offsets are shared across stages. With shifted bases,
	 * slot N of one stage may overlap slot M of another. Bind finishes
	 * before ACTIVE, so this conservative group policy is then immutable.
	 */
	list_for_each_entry(other, &found->regions, lease_node)
		if (xdev_ext_dma_scope_serial(&other->key, &cs->key))
			found->state.serial_batches = true;
	cs->lease_group = found;
	list_add_tail(&cs->lease_node, &found->regions);
	mutex_unlock(&xdev_ext_dma_lease_lock);
	return 0;
}

/* Worker: acquire all ranges in one transaction, before any native DMA work.
 * EAGAIN uses the core's preaccept retry; no accepted command is replayed.
 */
static int xdev_ext_dma_lease_get(struct xdev_ext_dma_stage *cs,
		struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_dma_lease_group *group = cs->lease_group, *other;
	struct xdev_ext_dma_stage *a, *held;
	u32 slot = xdev_ext_mech_batch_slot(b);
	bool conflict = false, cleanup_conflict = false;
	int ret;

	if (slot >= group->depth)
		return -ERANGE;
	mutex_lock(&xdev_ext_dma_lease_lock);
 list_for_each_entry(other, &xdev_ext_dma_lease_groups, node) {
   if (other == group || (!other->cleanup_holds &&
       (group->state.active_batches || !other->state.active_batches)))
    continue;
			list_for_each_entry(a, &group->regions, lease_node)
				list_for_each_entry(held, &other->regions, lease_node)
					if (xdev_ext_dma_scope_overlap(&a->key, &held->key)) {
						conflict = true;
      cleanup_conflict = other->cleanup_holds;
						goto checked;
					}
		}
checked:
 if (cleanup_conflict) {
  mutex_unlock(&xdev_ext_dma_lease_lock);
  return -EAGAIN; /* includes idempotent same-batch next-stage submits */
 }
 if (group->cleanup_holds) {
  mutex_unlock(&xdev_ext_dma_lease_lock);
  return -EBUSY;
 }
	ret = xdev_ext_ce_lease_acquire(&group->state, &group->slots[slot],
				      xdev_ext_mech_batch_id(b), conflict);
	mutex_unlock(&xdev_ext_dma_lease_lock);
	return ret;
}

/* All DMA stages see the same final batch fate. The slot marker releases
 * exactly once, and an unknown batch keeps the entire group quarantined.
 */
static void xdev_ext_dma_batch_release(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, bool sequestered)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	struct xdev_ext_dma_lease_group *group = cs->lease_group;
	u32 slot = xdev_ext_mech_batch_slot(b);
	int ret;

	if (WARN_ON_ONCE(slot >= group->depth))
		return;
	mutex_lock(&xdev_ext_dma_lease_lock);
	ret = xdev_ext_ce_lease_finish(&group->state, &group->slots[slot],
				     xdev_ext_mech_batch_id(b), sequestered);
	WARN_ON_ONCE(ret && ret != -EBUSY);
	mutex_unlock(&xdev_ext_dma_lease_lock);
}

static bool xdev_ext_dma_lease_unbind(struct xdev_ext_dma_stage *cs)
{
	struct xdev_ext_dma_lease_group *group = cs->lease_group;
	bool empty;

	mutex_lock(&xdev_ext_dma_lease_lock);
	if (WARN_ON_ONCE(group->state.active_batches || group->state.quarantined)) {
		mutex_unlock(&xdev_ext_dma_lease_lock);
		return false;
	}
	list_del(&cs->lease_node);
	empty = list_empty(&group->regions);
	if (empty)
		list_del(&group->node);
	mutex_unlock(&xdev_ext_dma_lease_lock);
	if (empty)
		kvfree(group);
	return true;
}

/* A refusing unmap retains its whole configured range until cleanup succeeds,
 * even after its last batch released. This does not manufacture an active batch. */
static void xdev_ext_dma_lease_cleanup(struct xdev_ext_dma_stage *cs, bool hold)
{
 if (!cs->lease_group)
  return;
 mutex_lock(&xdev_ext_dma_lease_lock);
 if (cs->cleanup_held != hold) {
  if (hold)
   cs->lease_group->cleanup_holds++;
  else
   cs->lease_group->cleanup_holds--;
  cs->cleanup_held = hold;
 }
 mutex_unlock(&xdev_ext_dma_lease_lock);
}

static bool xdev_ext_dma_lease_busy(struct xdev_ext_dma_stage *cs)
{
 bool busy;

 mutex_lock(&xdev_ext_dma_lease_lock);
 busy = cs->lease_group->state.active_batches || cs->lease_group->state.quarantined;
 mutex_unlock(&xdev_ext_dma_lease_lock);
 return busy;
}

static int xdev_ext_dma_bind(struct xdev_ext_mech_stage *st,
                       const struct xdev_ext_mech_stage_uapi *u)
{
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 const struct xdev_ext_dma_provider_ops *ops;
 const struct xdev_ext_dma_scope_ops *scope_ops;
 struct xdev_ext_dma_stage *cs;
 u64 offset;
 int err;

 if (u->flags || (st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
                 st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
  return -EINVAL;
 if (!pool || !pool->pages || !u->arg1 || u->arg0 > U64_MAX - u->arg1)
  return -EINVAL;
 cs = kzalloc(sizeof(*cs), GFP_KERNEL);
 if (!cs)
  return -ENOMEM;
 ops = xdev_ext_dma_provider_get(st->file, &scope_ops);
 if (!ops) {
  kfree(cs);
  return -ENODEV;
 }
 if (st->poll && !ops->poll) {
  module_put(ops->owner);
  kfree(cs);
  return -EOPNOTSUPP;
 }
 /* Failed native binds can retain partial mappings. Publish them for the
  * core's checked CREATE rollback before entering either provider hook. */
 cs->ops = ops;
 cs->region.ops = ops;
 cs->region.polled = st->poll;
 st->priv = cs;
 /* Pin and publish trusted identity before a mapping can become residual.
  * Provider region initialization cannot erase this separate C-owned key. */
 err = xdev_ext_dma_stage_scope(cs, scope_ops, st->file, u->arg0, u->arg1);
 if (err)
  return err;
 err = xdev_ext_dma_lease_bind(st, cs);
 if (err)
  return err;
 err = ops->bind_region(st->file, u->arg0, u->arg1, &cs->region);
 cs->region.ops = ops; /* providers may initialize their whole output */
 if (err)
  return err;
 if (cs->region.polled != st->poll)
  return -EPROTO;
 err = xdev_ext_dma_geom_init(&cs->geom, u->arg1, cs->region.len,
   cs->region.segment_size, cs->region.max_entry_len,
   (u64)pool->nr_pages << PAGE_SHIFT, pool->first_page_off,
   pool->frame_size, pool->nr_frames, cs->region.alignment, cs->region.directions);
 if (err)
  return err;
 if (!(cs->geom.directions & (1U << st->direction)))
  return -EOPNOTSUPP;
 err = xdev_ext_mech_window_offset(0, xdev_ext_mech_session_depth(st->s),
   xdev_ext_mech_session_layout(st->s)->group_bytes, cs->geom.window_len, &offset);
 if (err)
  return err;
 err = ops->bind_host(&cs->region, pool->pages, pool->nr_pages, &cs->host);
 if (err)
  return err;
 return 0;
}

static int xdev_ext_dma_unbind(struct xdev_ext_mech_stage *st)
{
 struct xdev_ext_dma_stage *cs = st->priv;
 const struct xdev_ext_dma_provider_ops *ops;
 int err;

 if (!cs)
  return 0;
 ops = cs->ops;
 if (atomic_read(&cs->ambiguous))
  return -EBUSY;
 if (cs->lease_group && xdev_ext_dma_lease_busy(cs))
  return -EBUSY;
 /* No new foreign native access may race the unmap result itself. */
 xdev_ext_dma_lease_cleanup(cs, true);
 if (cs->host) {
  err = ops->unbind_host(cs->host);
  if (err)
   goto retain;
  cs->host = NULL;
 }
 if (cs->region.priv) {
  err = ops->unbind_region(&cs->region);
  if (err)
   goto retain;
  cs->region.priv = NULL;
 }
 xdev_ext_dma_lease_cleanup(cs, false);
 if (cs->lease_group) {
  if (!xdev_ext_dma_lease_unbind(cs))
   return -EBUSY;
  cs->lease_group = NULL;
 }
 if (cs->scope) {
  xdev_ext_dma_scope_put(cs->scope);
  cs->scope = NULL;
 }
 st->priv = NULL;
 kfree(cs);
 module_put(ops->owner);
 return 0;
retain:
 xdev_ext_dma_lease_cleanup(cs, true);
 return err;
}

/* Worker or CREATE: data spans and pool chunk indices of @b's frames. */
static int xdev_ext_dma_collect(struct xdev_ext_dma_stage *cs, struct xdev_ext_mech_batch *b)
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
			.umem_addr	= f.umem_addr,
			.data_off	= f.data_off,
			.data_len	= f.data_len,
		};
		cs->index[i] = f.index;
	}
	return nr;
}

static void xdev_ext_dma_fill_info(struct xdev_ext_mech_stage *st,
			     struct xdev_ext_mech_batch *b, void *info)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	int nr = b ? xdev_ext_dma_collect(cs, b) : 0;

	/* Unreadable frames show as none; validate then refuses the batch. */
	if (nr < 0)
		nr = 0;
	xdev_ext_dma_info_fill(info, xdev_ext_mech_session_layout(st->s), &cs->geom,
			 cs->fi, nr);
 if (b) {
  struct xdev_ext_dma_mech_info *di = info;
  di->window_slot = xdev_ext_mech_batch_slot(b);
  di->window_depth = xdev_ext_mech_session_depth(st->s);
  di->lease_generation = xdev_ext_mech_batch_id(b);
 }
}

static int xdev_ext_dma_validate(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			   const u8 *scratch, u32 n)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	int nr, err;
 u64 offset;
 u32 i, group_bytes = xdev_ext_mech_session_layout(st->s)->group_bytes;

	cs->staged = NULL;
 if (!b)
  return -EINVAL;
	if (n > XDEV_EXT_DMA_MAX_ENTRIES)
		return -E2BIG;
	nr = xdev_ext_dma_collect(cs, b);
	if (nr < 0)
		return nr;
	memcpy(cs->d, scratch, n * sizeof(cs->d[0]));
	err = xdev_ext_dma_plan_check(&cs->geom, cs->fi, cs->index, nr, st->direction, cs->d, n,
				&cs->plan);
	if (err)
		return err;
 err = xdev_ext_mech_window_offset(xdev_ext_mech_batch_slot(b),
   xdev_ext_mech_session_depth(st->s), group_bytes, cs->geom.window_len, &offset);
 if (err)
  return err;
 for (i = 0; i < n; i++)
  if (cs->d[i].device_off < offset ||
      !xdev_ext_mech_span_in(cs->d[i].device_off - offset, cs->d[i].len, group_bytes))
   return -ERANGE;
	cs->staged = b;
	return 0;
}

/* Worker: the plan validate accepted for @b, as provider transfers. */
static int xdev_ext_dma_stage_xfers(struct xdev_ext_dma_stage *cs, struct xdev_ext_mech_batch *b,
			      struct xdev_ext_dma_batch *cb)
{
	struct xdev_ext_mech_batch *staged = cs->staged;
	u32 i;

	cs->staged = NULL;
	if (READ_ONCE(cs->dead))
		return -ENODEV;
	if (staged != b)
		return -EPROTO;
	for (i = 0; i < cs->plan.n; i++) {
		cb->x[i] = (struct xdev_ext_dma_xfer){
			.host_byte_off	= cs->plan.host_off[i],
			.device_off	= cs->d[i].device_off,
			.len		= cs->d[i].len,
			.flags		= cs->d[i].flags,
		};
  if (xdev_ext_mech_batch_frame_claim(b, cs->d[i].frame_pos,
       &cb->x[i].owner, &cb->x[i].generation))
   return -ESTALE;
 }
	cb->n = cs->plan.n;
	cb->total = cs->plan.total;
	return 0;
}

static int xdev_ext_dma_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	struct xdev_ext_dma_batch *cb = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_dma_cookie *ck = xdev_ext_mech_batch_cookie(b);
	int err;

	err = xdev_ext_dma_lease_get(cs, b);
	if (err)
		return err;
	if (!xdev_ext_dma_cookie_arm(&ck->state))
		return -EBUSY;
	if (!ck->b)
		ck->b = b;
	ck->cs = cs;
	err = xdev_ext_dma_stage_xfers(cs, b, cb);
	if (!err)
		err = cs->ops->submit(&cs->region, cs->host,
					     st->direction, cb->x, cb->n, ck,
					     xdev_ext_mech_batch_ticket(b));
	if (err >= 0)
		return 0;
	if (!xdev_ext_dma_cookie_disarm(&ck->state)) {
		/* Completed, so it reached the device path despite the error. */
		WARN_ONCE(1, "xdev_ext_mech_dma: provider completed a refused submit\n");
		return 0;
	}
	ck->status = err;
	return err;
}

bool xdev_ext_dma_owners_valid(struct xdev_ext_dma_cookie *ck, u64 ticket,
 const struct xdev_ext_dma_xfer *x, u32 n)
{
 return ck && ck->b && xdev_ext_mech_batch_dma_owners_valid(ck->b, ticket, x, n);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_owners_valid);

void xdev_ext_dma_complete(struct xdev_ext_dma_cookie *ck, u64 ticket, int status,
		     bool hw_submitted, u64 bytes_done)
{
	const struct xdev_ext_dma_batch *cb;
	u32 outcome;
	int err;

	/* Validate the immutable native ticket before touching reused cookie data. */
	if (xdev_ext_mech_batch_completion_claim(ck->b, ticket))
		return;
	if (WARN_ONCE(!xdev_ext_dma_cookie_finish(&ck->state),
		      "xdev_ext_mech_dma: completion without an accepted submit\n")) {
		atomic_inc(&ck->cs->ambiguous);
		xdev_ext_mech_batch_completion_publish(ck->b, ticket, -EPROTO, true);
		return;
	}
	cb = xdev_ext_mech_batch_priv(ck->b);
 if (!xdev_ext_mech_batch_dma_owners_valid(ck->b, ticket, cb->x, cb->n)) {
  status = -ESTALE;
  hw_submitted = true; /* Accepted access cannot be proved to belong to us. */
 }
	if (!status && !hw_submitted)
		status = -EIO;
	outcome = xdev_ext_dma_classify(status, hw_submitted, bytes_done, cb->total);
	ck->outcome = outcome;
	ck->status = status;
	ck->bytes_done = bytes_done;
	if (xdev_ext_dma_disposition(outcome, status, &err)) {
		atomic_inc(&ck->cs->ambiguous);
		xdev_ext_mech_batch_completion_publish(ck->b, ticket, err, true);
		return;
	}
	xdev_ext_mech_batch_completion_publish(ck->b, ticket, err, false);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_complete);

static void xdev_ext_dma_fill_cqe(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			    void *cqe)
{
	const struct xdev_ext_dma_batch *cb = xdev_ext_mech_batch_priv(b);
	const struct xdev_ext_dma_cookie *ck = xdev_ext_mech_batch_cookie(b);

	xdev_ext_dma_cqe_fill(cqe, READ_ONCE(ck->state), ck->outcome, ck->status,
			ck->bytes_done, cb->total, cb->n);
}

static void xdev_ext_dma_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_dma_stage *cs = st->priv;

	WRITE_ONCE(cs->dead, true);
}

/* Session worker, polled stage: the provider's completion pass of the region. */
static int xdev_ext_dma_poll(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_dma_stage *cs = st->priv;

	return cs->ops->poll(&cs->region);
}

static const struct xdev_ext_comp_hooks xdev_ext_dma_comp_hooks = {
	.hdr = { .family = XDEV_EXT_FAMILY_COMPUTE },
	.kinds = 1U << XDEV_EXT_COMP_COPY_WINDOW,
	.producer_visibility = XDEV_EXT_CAP_NOT_WIRED,
};

static const struct xdev_ext_mech_class_ops xdev_ext_dma_class = {
 .decl = &xdev_ext_mech_class_decls[XDEV_EXT_MECH_CLASS_DMA],
	.class_id	= XDEV_EXT_MECH_CLASS_DMA,
	.desc_size	= sizeof(struct xdev_ext_dma_copy_desc),
	.desc_cap	= XDEV_EXT_DMA_MAX_ENTRIES,
	.info_size	= sizeof(struct xdev_ext_dma_mech_info),
	.cqe_size	= sizeof(struct xdev_ext_dma_mech_cqe),
	.cqe_cap	= 1,
	.batch_priv_size = sizeof(struct xdev_ext_dma_batch),
	.batch_cookie_size = sizeof(struct xdev_ext_dma_cookie),
	.owner		= THIS_MODULE,
	.bind		= xdev_ext_dma_bind,
	.unbind_checked	= xdev_ext_dma_unbind,
	.fill_info	= xdev_ext_dma_fill_info,
	.validate	= xdev_ext_dma_validate,
	.submit		= xdev_ext_dma_submit,
	.fill_cqe	= xdev_ext_dma_fill_cqe,
	.mark_dead	= xdev_ext_dma_mark_dead,
	.poll		= xdev_ext_dma_poll,
	.batch_release	= xdev_ext_dma_batch_release,
	.fam.comp	= &xdev_ext_dma_comp_hooks,
};

/* After every late_initcall, so the core's own initialisation has run. */
static int __init xdev_ext_mech_dma_init(void)
{
	int err = xdev_ext_mech_class_register(&xdev_ext_dma_class);

	if (err)
		pr_err("xdev_ext_mech_dma: class registration failed: %d\n", err);
	return err;
}
late_initcall_sync(xdev_ext_mech_dma_init);
