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
#include "xdev_ext_compfam_copy_runtime.h"
#include "xdev_ext_compfam_copy_lease.h"
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

/* A session atomically owns ALL its bound DMA windows while any batch can
 * use them. Reentrant batches keep per-slot depth parallelism for matching
 * bases or disjoint windows; shifted overlapping bases serialize batches.
 * Legacy providers compare numeric windows. Scoped providers supply immutable
 * canonical coordinates and a pinned backing identity; unknown or mixed
 * identities conservatively exclude the whole provider namespace.
 */
/* One DMA stage from bind to unbind; parked for good after AMBIGUOUS. */
struct xdev_ext_dma_stage {
 const struct xdev_ext_dma_provider_ops *ops; /* C-owned identity and pin */
	struct xdev_ext_comp_copy_lease_region lease;
	struct xdev_ext_dma_scope_key key;
	struct xdev_ext_dma_scope *scope; /* one owned external ref; key borrows it */
	struct xdev_ext_dma_region region;
	struct xdev_ext_dma_geom geom;
	struct xdev_ext_comp_copy_stage copy;
};

_Static_assert(XDEV_EXT_DMA_MAX_ENTRIES <=
	       sizeof(((struct xdev_ext_comp_copy_plan *)0)->entry) /
	       sizeof(struct xdev_ext_comp_copy_entry),
	       "DMA entries exceed the common copy plan capacity");

struct xdev_ext_dma_batch {
	u64 total;
	u32 n;
	struct xdev_ext_dma_xfer x[XDEV_EXT_DMA_MAX_ENTRIES];
};

static struct xdev_ext_comp_copy_registry xdev_ext_dma_registry = {
	.lock = __MUTEX_INITIALIZER(xdev_ext_dma_registry.lock),
	.members = LIST_HEAD_INIT(xdev_ext_dma_registry.members),
};

static int xdev_ext_dma_provider_register_common(
 const struct xdev_ext_dma_provider_ops *ops,
 const struct xdev_ext_dma_scope_ops *scope_ops, bool scoped)
{
	struct xdev_ext_comp_copy_member member;

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
	member = (struct xdev_ext_comp_copy_member){
		.identity = ops,
		.fops = ops->fops,
		.owner = ops->owner,
		.scope_ops = scope_ops,
	};
	return xdev_ext_comp_copy_registry_register(&xdev_ext_dma_registry, &member);
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
	WARN_ON_ONCE(!xdev_ext_comp_copy_registry_unregister(&xdev_ext_dma_registry, ops));
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_provider_unregister);

/* CREATE: select by file operations and pin before releasing registry lock. */
static const struct xdev_ext_dma_provider_ops *xdev_ext_dma_provider_get(
	struct file *file, const struct xdev_ext_dma_scope_ops **scope_ops)
{
	struct xdev_ext_comp_copy_member member;

	xdev_ext_comp_copy_registry_get(&xdev_ext_dma_registry, file, &member);
	*scope_ops = member.scope_ops;
	return member.identity;
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

static bool xdev_ext_dma_lease_key_overlap(const void *a, const void *b)
{
	return xdev_ext_dma_scope_overlap(a, b);
}

static bool xdev_ext_dma_lease_key_serial(const void *a, const void *b)
{
	return xdev_ext_dma_scope_serial(a, b);
}

static const struct xdev_ext_comp_copy_lease_policy xdev_ext_dma_lease_policy = {
	.overlap = xdev_ext_dma_lease_key_overlap,
	.serial = xdev_ext_dma_lease_key_serial,
};

static struct xdev_ext_comp_copy_lease_domain xdev_ext_dma_lease_domain = {
	.lock = __MUTEX_INITIALIZER(xdev_ext_dma_lease_domain.lock),
	.groups = LIST_HEAD_INIT(xdev_ext_dma_lease_domain.groups),
	.policy = &xdev_ext_dma_lease_policy,
};

/* All stages share final batch fate; quarantine retains slot ownership. */
static void xdev_ext_dma_batch_release(struct xdev_ext_mech_stage *st,
		struct xdev_ext_mech_batch *b, bool sequestered)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	int ret;

	ret = xdev_ext_comp_copy_lease_finish(&cs->lease,
		xdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b), sequestered);
	if (WARN_ON_ONCE(ret == -ERANGE))
		return;
	WARN_ON_ONCE(ret && ret != -EBUSY);
}

static int xdev_ext_dma_copy_lease_get(struct xdev_ext_comp_copy_stage *copy,
	struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_dma_stage *cs = container_of(copy, struct xdev_ext_dma_stage, copy);

	return xdev_ext_comp_copy_lease_get(&cs->lease,
		xdev_ext_mech_batch_slot(b), xdev_ext_mech_batch_id(b));
}

/* Native callbacks retain the typed batch array, never the worker scratch. */
static int xdev_ext_dma_copy_submit(struct xdev_ext_comp_copy_stage *copy,
	struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
	const struct xdev_ext_comp_copy_transfer *x, u32 n, u64 total,
	struct xdev_ext_comp_copy_cookie *ck, u64 ticket)
{
	struct xdev_ext_dma_stage *cs = container_of(copy, struct xdev_ext_dma_stage, copy);
	struct xdev_ext_dma_batch *cb = xdev_ext_mech_batch_priv(b);
	u32 i;

	for (i = 0; i < n; i++)
		cb->x[i] = (struct xdev_ext_dma_xfer){
			.owner = x[i].owner,
			.generation = x[i].generation,
			.host_byte_off = x[i].host_byte_off,
			.device_off = x[i].device_off,
			.len = x[i].len,
			.flags = x[i].flags,
		};
	cb->n = n;
	cb->total = total;
	return cs->ops->submit(&cs->region, copy->host, st->direction,
		cb->x, cb->n, (struct xdev_ext_dma_cookie *)ck, ticket);
}

static u32 xdev_ext_dma_copy_classify(struct xdev_ext_mech_batch *b, u64 ticket,
	int *status, bool *hw_submitted, u64 bytes_done)
{
	const struct xdev_ext_dma_batch *cb = xdev_ext_mech_batch_priv(b);

	if (!xdev_ext_mech_batch_dma_owners_valid(b, ticket, cb->x, cb->n)) {
		*status = -ESTALE;
		*hw_submitted = true;
	}
	if (!*status && !*hw_submitted)
		*status = -EIO;
	return xdev_ext_dma_classify(*status, *hw_submitted, bytes_done, cb->total);
}

static int xdev_ext_dma_copy_unbind_begin(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_dma_stage *cs = container_of(copy, struct xdev_ext_dma_stage, copy);

	if (cs->lease.group && xdev_ext_comp_copy_lease_busy(&cs->lease))
		return -EBUSY;
	/* Retain configured exclusion throughout either native unmap. */
	xdev_ext_comp_copy_lease_hold(&cs->lease, true);
	return 0;
}

static int xdev_ext_dma_copy_unbind_host(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_dma_stage *cs = container_of(copy, struct xdev_ext_dma_stage, copy);

	return cs->ops->unbind_host(copy->host);
}

static int xdev_ext_dma_copy_unbind_region(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_dma_stage *cs = container_of(copy, struct xdev_ext_dma_stage, copy);
	int err;

	if (!cs->region.priv)
		return 0;
	err = cs->ops->unbind_region(&cs->region);
	if (err)
		return err;
	cs->region.priv = NULL;
	return 0;
}

static int xdev_ext_dma_copy_unbind_end(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_dma_stage *cs = container_of(copy, struct xdev_ext_dma_stage, copy);

	xdev_ext_comp_copy_lease_hold(&cs->lease, false);
	if (cs->lease.group &&
	    WARN_ON_ONCE(!xdev_ext_comp_copy_lease_unbind(&cs->lease, false)))
		return -EBUSY;
	if (cs->scope) {
		xdev_ext_dma_scope_put(cs->scope);
		cs->scope = NULL;
	}
	return 0;
}

static int xdev_ext_dma_copy_poll(struct xdev_ext_comp_copy_stage *copy)
{
	struct xdev_ext_dma_stage *cs = container_of(copy, struct xdev_ext_dma_stage, copy);

	return cs->ops->poll(&cs->region);
}

static void xdev_ext_dma_copy_warn(bool refused_submit)
{
	if (refused_submit)
		WARN_ONCE(1, "xdev_ext_mech_dma: provider completed a refused submit\n");
	else
		WARN_ONCE(1, "xdev_ext_mech_dma: completion without an accepted submit\n");
}

static const struct xdev_ext_comp_copy_legacy_ops xdev_ext_dma_copy_ops = {
	.lease_get = xdev_ext_dma_copy_lease_get,
	.submit = xdev_ext_dma_copy_submit,
	.classify = xdev_ext_dma_copy_classify,
	.unbind_begin = xdev_ext_dma_copy_unbind_begin,
	.unbind_host = xdev_ext_dma_copy_unbind_host,
	.unbind_region = xdev_ext_dma_copy_unbind_region,
	.unbind_end = xdev_ext_dma_copy_unbind_end,
	.poll = xdev_ext_dma_copy_poll,
	.warn = xdev_ext_dma_copy_warn,
};

static int xdev_ext_dma_bind(struct xdev_ext_mech_stage *st,
                       const struct xdev_ext_mech_stage_uapi *u)
{
 struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
 const struct xdev_ext_dma_provider_ops *ops;
 const struct xdev_ext_dma_scope_ops *scope_ops;
 struct xdev_ext_dma_stage *cs;
 struct xdev_ext_window_copy_geom geom;
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
 cs->copy.ops = &xdev_ext_dma_copy_ops;
 cs->region.ops = ops;
 cs->region.polled = st->poll;
 st->priv = cs;
 /* Pin and publish trusted identity before a mapping can become residual.
  * Provider region initialization cannot erase this separate C-owned key. */
 err = xdev_ext_dma_stage_scope(cs, scope_ops, st->file, u->arg0, u->arg1);
 if (err)
  return err;
 err = xdev_ext_comp_copy_lease_bind(&xdev_ext_dma_lease_domain, &cs->lease,
   st->s, xdev_ext_mech_session_depth(st->s), &cs->key, false);
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
 geom = xdev_ext_dma_window_geom(&cs->geom);
 err = xdev_ext_comp_copy_prepare(&cs->copy.window, XDEV_EXT_COMP_COPY_WINDOW, &geom,
   st->direction, xdev_ext_mech_session_depth(st->s),
   xdev_ext_mech_session_layout(st->s)->group_bytes);
 if (err)
  return err;
 err = ops->bind_host(&cs->region, pool->pages, pool->nr_pages, &cs->copy.host);
 if (err)
  return err;
 return 0;
}

static int xdev_ext_dma_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	const struct xdev_ext_dma_provider_ops *native_ops;
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

static void xdev_ext_dma_fill_info(struct xdev_ext_mech_stage *st,
			     struct xdev_ext_mech_batch *b, void *info)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	int nr = b ? xdev_ext_comp_copy_collect(&cs->copy, b) : 0;

	/* Unreadable frames show as none; validate then refuses the batch. */
	if (nr < 0)
		nr = 0;
	xdev_ext_dma_info_fill(info, xdev_ext_mech_session_layout(st->s), &cs->geom,
			 cs->copy.fi, nr);
 if (b) {
  struct xdev_ext_dma_mech_info *di = info;
  di->window_slot = xdev_ext_mech_batch_slot(b);
  di->window_depth = xdev_ext_mech_session_depth(st->s);
  di->lease_generation = xdev_ext_mech_batch_id(b);
 }
}

static int xdev_ext_dma_validate(struct xdev_ext_mech_stage *st,
	struct xdev_ext_mech_batch *b, const u8 *scratch, u32 n)
{
	struct xdev_ext_dma_stage *cs = st->priv;

	return xdev_ext_comp_copy_stage_validate(&cs->copy, b, scratch, n,
		XDEV_EXT_DMA_MAX_ENTRIES, XDEV_EXT_DMA_F_KNOWN_MASK);
}

static int xdev_ext_dma_submit(struct xdev_ext_mech_stage *st,
	struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_dma_stage *cs = st->priv;

	return xdev_ext_comp_copy_stage_submit(&cs->copy, st, b);
}

bool xdev_ext_dma_owners_valid(struct xdev_ext_dma_cookie *native_ck, u64 ticket,
	const struct xdev_ext_dma_xfer *x, u32 n)
{
	struct xdev_ext_comp_copy_cookie *ck = (struct xdev_ext_comp_copy_cookie *)native_ck;

	return ck && ck->b && xdev_ext_mech_batch_dma_owners_valid(ck->b, ticket, x, n);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_owners_valid);

void xdev_ext_dma_complete(struct xdev_ext_dma_cookie *ck, u64 ticket, int status,
	bool hw_submitted, u64 bytes_done)
{
	xdev_ext_comp_copy_complete((struct xdev_ext_comp_copy_cookie *)ck, ticket,
		status, hw_submitted, bytes_done, &xdev_ext_dma_copy_ops);
}
EXPORT_SYMBOL_GPL(xdev_ext_dma_complete);

static void xdev_ext_dma_fill_cqe(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			    void *cqe)
{
	const struct xdev_ext_dma_batch *cb = xdev_ext_mech_batch_priv(b);
	const struct xdev_ext_comp_copy_cookie *ck = xdev_ext_mech_batch_cookie(b);

	xdev_ext_dma_cqe_fill(cqe, READ_ONCE(ck->state), ck->outcome, ck->status,
			ck->bytes_done, cb->total, cb->n);
}

static void xdev_ext_dma_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_dma_stage *cs = st->priv;

	xdev_ext_comp_copy_mark_dead(&cs->copy);
}

/* Session worker, polled stage: the provider's completion pass of the region. */
static int xdev_ext_dma_poll(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_dma_stage *cs = st->priv;

	return xdev_ext_comp_copy_poll(&cs->copy);
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
	.batch_cookie_size = sizeof(struct xdev_ext_comp_copy_cookie),
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
