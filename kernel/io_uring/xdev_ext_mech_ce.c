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
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_ce_core.h"
#include "xdev_ext_mech_native_cookie.h"

#define XDEV_EXT_CE_MAX_BACKENDS	4

/* One CE stage from bind to unbind; parked for good after AMBIGUOUS. */
struct xdev_ext_ce_stage {
	struct xdev_ext_ce_region region;
	void *host;			/* bind_host() handle of the pool pages */
	struct xdev_ext_ce_geom geom;
	atomic_t ambiguous;		/* AMBIGUOUS completions on this stage */
	bool dead;
	/* session worker only: the plan validate accepted, until submit */
	struct xdev_ext_mech_batch *staged;
	struct xdev_ext_ce_plan plan;
	struct xdev_ext_ce_copy_desc d[XDEV_EXT_CE_MAX_ENTRIES];
	struct xdev_ext_mech_frame_info fi[XDEV_EXT_MECH_MAX_FRAMES];
	u32 index[XDEV_EXT_MECH_MAX_FRAMES];
};

/* Stable per-batch storage: never overwritten by another stage's private area.
 * b is initialized once and remains safe to dereference for stale-ticket rejection.
 */
struct xdev_ext_ce_cookie {
	struct xdev_ext_mech_batch *b;
	struct xdev_ext_ce_stage *cs;
	u64 bytes_done;
	int status;
	u32 outcome;			/* enum xdev_ext_ce_outcome */
	u8 state;			/* enum xdev_ext_ce_cookie_state */
};
XDEV_EXT_NATIVE_COOKIE_ASSERT(struct xdev_ext_ce_cookie);

struct xdev_ext_ce_batch {
	u64 total;
	u32 n;
	struct xdev_ext_ce_xfer x[XDEV_EXT_CE_MAX_ENTRIES];
};

static DEFINE_MUTEX(xdev_ext_ce_backend_lock);
static const struct xdev_ext_ce_backend_ops *xdev_ext_ce_backends[XDEV_EXT_CE_MAX_BACKENDS];

int xdev_ext_ce_backend_register(const struct xdev_ext_ce_backend_ops *ops)
{
	int i, slot = -1, err = 0;

	if (!ops || !ops->fops || !ops->bind_region || !ops->unbind_region ||
	    !ops->bind_host || !ops->unbind_host || !ops->submit)
		return -EINVAL;

	mutex_lock(&xdev_ext_ce_backend_lock);
	for (i = 0; i < XDEV_EXT_CE_MAX_BACKENDS; i++) {
		if (!xdev_ext_ce_backends[i]) {
			if (slot < 0)
				slot = i;
		} else if (xdev_ext_ce_backends[i]->fops == ops->fops) {
			err = -EBUSY;
			break;
		}
	}
	if (!err && slot < 0)
		err = -ENOSPC;
	if (!err)
		xdev_ext_ce_backends[slot] = ops;
	mutex_unlock(&xdev_ext_ce_backend_lock);
	return err;
}
EXPORT_SYMBOL_GPL(xdev_ext_ce_backend_register);

void xdev_ext_ce_backend_unregister(const struct xdev_ext_ce_backend_ops *ops)
{
	int i;

	mutex_lock(&xdev_ext_ce_backend_lock);
	for (i = 0; i < XDEV_EXT_CE_MAX_BACKENDS; i++) {
		if (xdev_ext_ce_backends[i] == ops) {
			xdev_ext_ce_backends[i] = NULL;
			break;
		}
	}
	mutex_unlock(&xdev_ext_ce_backend_lock);
	WARN_ON_ONCE(i == XDEV_EXT_CE_MAX_BACKENDS);
}
EXPORT_SYMBOL_GPL(xdev_ext_ce_backend_unregister);

/* CREATE, process context: the backend of @file, its module pinned. */
static const struct xdev_ext_ce_backend_ops *xdev_ext_ce_backend_get(struct file *file)
{
	const struct xdev_ext_ce_backend_ops *ops = NULL;
	int i;

	mutex_lock(&xdev_ext_ce_backend_lock);
	for (i = 0; i < XDEV_EXT_CE_MAX_BACKENDS; i++) {
		const struct xdev_ext_ce_backend_ops *b = xdev_ext_ce_backends[i];

		if (b && b->fops == file->f_op && try_module_get(b->owner)) {
			ops = b;
			break;
		}
	}
	mutex_unlock(&xdev_ext_ce_backend_lock);
	return ops;
}

static int xdev_ext_ce_bind(struct xdev_ext_mech_stage *st,
		       const struct xdev_ext_mech_stage_uapi *u)
{
	struct xdev_ext_mech_pool *pool = xdev_ext_mech_session_pool(st->s);
	const struct xdev_ext_ce_backend_ops *ops;
	struct xdev_ext_ce_stage *cs;
	u64 offset;
	int err;

	if (u->flags || (st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
			 st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
		return -EINVAL;
	if (!pool || !pool->pages)
		return -EINVAL;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return -ENOMEM;
	ops = xdev_ext_ce_backend_get(st->file);
	if (!ops) {
		err = -ENODEV;
		goto free;
	}
	err = ops->bind_region(st->file, u->arg0, u->arg1, &cs->region);
	if (err)
		goto put;
	cs->region.ops = ops;
	err = xdev_ext_ce_geom_init(&cs->geom, u->arg1, cs->region.len,
			       cs->region.seg_size, cs->region.max_entry_len,
			       (u64)pool->nr_pages << PAGE_SHIFT,
			       pool->first_page_off, pool->frame_size,
			       pool->nr_frames);
	if (err)
		goto unbind_region;
	err = xdev_ext_mech_window_offset(0, xdev_ext_mech_session_depth(st->s),
		xdev_ext_mech_session_layout(st->s)->group_bytes, cs->geom.window_len,
		&offset);
	if (err)
		goto unbind_region;
	/* The UMEM keeps the pages pinned; the backend does not pin again. */
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

static void xdev_ext_ce_unbind(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_ce_stage *cs = st->priv;
	const struct xdev_ext_ce_backend_ops *ops = cs->region.ops;

	/*
	 * After an AMBIGUOUS outcome the device may still read or write the
	 * window and the pool pages: keep both bound and the backend module
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
static int xdev_ext_ce_collect(struct xdev_ext_ce_stage *cs, struct xdev_ext_mech_batch *b)
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

static void xdev_ext_ce_fill_info(struct xdev_ext_mech_stage *st,
			     struct xdev_ext_mech_batch *b, void *info)
{
	struct xdev_ext_ce_stage *cs = st->priv;
	int nr = b ? xdev_ext_ce_collect(cs, b) : 0;

	/* Unreadable frames show as none; validate then refuses the batch. */
	if (nr < 0)
		nr = 0;
	xdev_ext_ce_info_fill(info, xdev_ext_mech_session_layout(st->s), &cs->geom,
			 cs->fi, nr);
	if (b) {
		struct xdev_ext_ce_mech_info *ci = info;

		ci->window_slot = xdev_ext_mech_batch_slot(b);
		ci->window_depth = xdev_ext_mech_session_depth(st->s);
		ci->lease_generation = xdev_ext_mech_batch_id(b);
	}
}

static int xdev_ext_ce_validate(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			   const u8 *scratch, u32 n)
{
	struct xdev_ext_ce_stage *cs = st->priv;
	u64 offset;
	u32 i, group_bytes = xdev_ext_mech_session_layout(st->s)->group_bytes;
	int nr, err;

	cs->staged = NULL;
	if (!b)
		return -EINVAL;
	if (n > XDEV_EXT_CE_MAX_ENTRIES)
		return -E2BIG;
	nr = xdev_ext_ce_collect(cs, b);
	if (nr < 0)
		return nr;
	memcpy(cs->d, scratch, n * sizeof(cs->d[0]));
	err = xdev_ext_ce_plan_check(&cs->geom, cs->fi, cs->index, nr, cs->d, n,
				&cs->plan);
	if (err)
		return err;
	err = xdev_ext_mech_window_offset(xdev_ext_mech_batch_slot(b),
		xdev_ext_mech_session_depth(st->s), group_bytes, cs->geom.window_len,
		&offset);
	if (err)
		return err;
	for (i = 0; i < n; i++)
		if (cs->d[i].gpu_off < offset ||
		    !xdev_ext_mech_span_in(cs->d[i].gpu_off - offset,
				      cs->d[i].len, group_bytes))
			return -ERANGE;
	cs->staged = b;
	return 0;
}

/* Worker: the plan validate accepted for @b, as backend transfers. */
static int xdev_ext_ce_stage_xfers(struct xdev_ext_ce_stage *cs, struct xdev_ext_mech_batch *b,
			      struct xdev_ext_ce_batch *cb)
{
	struct xdev_ext_mech_batch *staged = cs->staged;
	u32 i;

	cs->staged = NULL;
	if (READ_ONCE(cs->dead))
		return -ENODEV;
	if (staged != b)
		return -EPROTO;
	for (i = 0; i < cs->plan.n; i++)
		cb->x[i] = (struct xdev_ext_ce_xfer){
			.host_byte_off	= cs->plan.host_off[i],
			.gpu_off	= cs->d[i].gpu_off,
			.len		= cs->d[i].len,
			.flags		= cs->d[i].flags,
		};
	cb->n = cs->plan.n;
	cb->total = cs->plan.total;
	return 0;
}

static int xdev_ext_ce_submit(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b)
{
	struct xdev_ext_ce_stage *cs = st->priv;
	struct xdev_ext_ce_batch *cb = xdev_ext_mech_batch_priv(b);
	struct xdev_ext_ce_cookie *ck = xdev_ext_mech_batch_cookie(b);
	int err;

	if (!xdev_ext_ce_cookie_arm(&ck->state))
		return -EBUSY;
	if (!ck->b)
		ck->b = b;
	ck->cs = cs;
	err = xdev_ext_ce_stage_xfers(cs, b, cb);
	if (!err)
		err = cs->region.ops->submit(&cs->region, cs->host,
					     st->direction, cb->x, cb->n, ck,
					     xdev_ext_mech_batch_ticket(b));
	if (err >= 0)
		return 0;
	if (!xdev_ext_ce_cookie_disarm(&ck->state)) {
		/* Completed, so it reached the device path despite the error. */
		WARN_ONCE(1, "xdev_ext_mech_ce: backend completed a refused submit\n");
		return 0;
	}
	ck->status = err;
	return err;
}

void xdev_ext_ce_complete(struct xdev_ext_ce_cookie *ck, u64 ticket, int status,
		     bool hw_submitted, u64 bytes_done)
{
	u32 outcome;
	int err;

	/* Validate the immutable native ticket before touching reused cookie data. */
	if (xdev_ext_mech_batch_completion_claim(ck->b, ticket))
		return;
	if (WARN_ONCE(!xdev_ext_ce_cookie_finish(&ck->state),
		      "xdev_ext_mech_ce: completion without an accepted submit\n")) {
		atomic_inc(&ck->cs->ambiguous);
		xdev_ext_mech_batch_completion_publish(ck->b, ticket, -EPROTO, true);
		return;
	}
	status = xdev_ext_ce_completion_status(status, hw_submitted, bytes_done,
		((const struct xdev_ext_ce_batch *)xdev_ext_mech_batch_priv(ck->b))->total);
	outcome = xdev_ext_ce_classify(status, hw_submitted);
	ck->outcome = outcome;
	ck->status = status;
	ck->bytes_done = bytes_done;
	if (xdev_ext_ce_disposition(outcome, status, &err)) {
		atomic_inc(&ck->cs->ambiguous);
		xdev_ext_mech_batch_completion_publish(ck->b, ticket, err, true);
		return;
	}
	xdev_ext_mech_batch_completion_publish(ck->b, ticket, err, false);
}
EXPORT_SYMBOL_GPL(xdev_ext_ce_complete);

static void xdev_ext_ce_fill_cqe(struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
			    void *cqe)
{
	const struct xdev_ext_ce_batch *cb = xdev_ext_mech_batch_priv(b);
	const struct xdev_ext_ce_cookie *ck = xdev_ext_mech_batch_cookie(b);

	xdev_ext_ce_cqe_fill(cqe, READ_ONCE(ck->state), ck->outcome, ck->status,
			ck->bytes_done, cb->total, cb->n);
}

static void xdev_ext_ce_mark_dead(struct xdev_ext_mech_stage *st)
{
	struct xdev_ext_ce_stage *cs = st->priv;

	WRITE_ONCE(cs->dead, true);
}

static const struct xdev_ext_mech_class_ops xdev_ext_ce_class = {
	.class_id	= XDEV_EXT_MECH_CLASS_CE,
	.desc_size	= sizeof(struct xdev_ext_ce_copy_desc),
	.desc_cap	= XDEV_EXT_CE_MAX_ENTRIES,
	.info_size	= sizeof(struct xdev_ext_ce_mech_info),
	.cqe_size	= sizeof(struct xdev_ext_ce_mech_cqe),
	.cqe_cap	= 1,
	.batch_priv_size = sizeof(struct xdev_ext_ce_batch),
	.batch_cookie_size = sizeof(struct xdev_ext_ce_cookie),
	.owner		= THIS_MODULE,
	.bind		= xdev_ext_ce_bind,
	.unbind		= xdev_ext_ce_unbind,
	.fill_info	= xdev_ext_ce_fill_info,
	.validate	= xdev_ext_ce_validate,
	.submit		= xdev_ext_ce_submit,
	.fill_cqe	= xdev_ext_ce_fill_cqe,
	.mark_dead	= xdev_ext_ce_mark_dead,
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
