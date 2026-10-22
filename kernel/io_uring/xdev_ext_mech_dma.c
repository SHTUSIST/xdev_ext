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
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_dma_core.h"
#include "xdev_ext_mech_native_cookie.h"

/* Registry has no fixed provider count; sessions pin ops->owner under lock. */
struct xdev_ext_dma_provider {
	struct list_head node;
	const struct xdev_ext_dma_provider_ops *ops;
};

/* One DMA stage from bind to unbind; parked for good after AMBIGUOUS. */
struct xdev_ext_dma_stage {
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

int xdev_ext_dma_provider_register(const struct xdev_ext_dma_provider_ops *ops)
{
	struct xdev_ext_dma_provider *p, *new;
	int err = 0;

	if (!ops || !ops->fops || !ops->bind_region || !ops->unbind_region ||
	    !ops->bind_host || !ops->unbind_host || !ops->submit)
		return -EINVAL;
	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;
	new->ops = ops;
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
EXPORT_SYMBOL_GPL(xdev_ext_dma_provider_register);

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
static const struct xdev_ext_dma_provider_ops *xdev_ext_dma_provider_get(struct file *file)
{
	const struct xdev_ext_dma_provider_ops *ops = NULL;
	struct xdev_ext_dma_provider *p;

	mutex_lock(&xdev_ext_dma_provider_lock);
	list_for_each_entry(p, &xdev_ext_dma_providers, node) {
		if (p->ops->fops == file->f_op && try_module_get(p->ops->owner)) {
			ops = p->ops;
			break;
		}
	}
	mutex_unlock(&xdev_ext_dma_provider_lock);
	return ops;
}

static int xdev_ext_dma_bind(struct xdev_ext_mech_stage *st,
		       const struct xdev_ext_mech_stage_uapi *u)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	const struct xdev_ext_dma_provider_ops *ops;
	struct xdev_ext_dma_stage *cs;
	int err;

	if (u->flags || (st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
			 st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
		return -EINVAL;
	if (!pool || !pool->pages)
		return -EINVAL;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return -ENOMEM;
	ops = xdev_ext_dma_provider_get(st->file);
	if (!ops) {
		err = -ENODEV;
		goto free;
	}
	err = ops->bind_region(st->file, u->arg0, u->arg1, &cs->region);
	if (err)
		goto put;
	cs->region.ops = ops;
	err = xdev_ext_dma_geom_init(&cs->geom, u->arg1, cs->region.len,
			       cs->region.segment_size, cs->region.max_entry_len,
			       (u64)pool->nr_pages << PAGE_SHIFT,
			       pool->first_page_off, pool->frame_size,
			       pool->nr_frames, cs->region.alignment,
			       cs->region.directions);
	if (err)
		goto unbind_region;
	if (!(cs->geom.directions & (1U << st->direction))) {
		err = -EOPNOTSUPP;
		goto unbind_region;
	}
	/* The UMEM keeps the pages pinned; the provider does not pin again. */
	err = ops->bind_host(&cs->region, pool->pages, pool->nr_pages,
			     &cs->host);
	if (err)
		goto unbind_region;
	st->priv = cs;
	return 0;

unbind_region:
	ops->unbind_region(&cs->region);
put:
	module_put(ops->owner);
free:
	kfree(cs);
	return err;
}

static void xdev_ext_dma_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	const struct xdev_ext_dma_provider_ops *ops = cs->region.ops;

	/*
	 * After an AMBIGUOUS outcome the device may still read or write the
	 * window and the pool pages: keep both bound and the provider module
	 * pinned for good.
	 */
	if (atomic_read(&cs->ambiguous))
		return;
	ops->unbind_host(cs->host);
	ops->unbind_region(&cs->region);
	st->priv = NULL;
	kfree(cs);
	module_put(ops->owner);
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
}

static int xdev_ext_dma_validate(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			   const u8 *scratch, u32 n)
{
	struct xdev_ext_dma_stage *cs = st->priv;
	int nr, err;

	cs->staged = NULL;
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
	for (i = 0; i < cs->plan.n; i++)
		cb->x[i] = (struct xdev_ext_dma_xfer){
			.host_byte_off	= cs->plan.host_off[i],
			.device_off	= cs->d[i].device_off,
			.len		= cs->d[i].len,
			.flags		= cs->d[i].flags,
		};
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

	if (!xdev_ext_dma_cookie_arm(&ck->state))
		return -EBUSY;
	if (!ck->b)
		ck->b = b;
	ck->cs = cs;
	err = xdev_ext_dma_stage_xfers(cs, b, cb);
	if (!err)
		err = cs->region.ops->submit(&cs->region, cs->host,
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

static const struct xdev_ext_mech_class_ops xdev_ext_dma_class = {
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
	.unbind		= xdev_ext_dma_unbind,
	.fill_info	= xdev_ext_dma_fill_info,
	.validate	= xdev_ext_dma_validate,
	.submit		= xdev_ext_dma_submit,
	.fill_cqe	= xdev_ext_dma_fill_cqe,
	.mark_dead	= xdev_ext_dma_mark_dead,
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
