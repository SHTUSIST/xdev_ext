// SPDX-License-Identifier: GPL-2.0
/*
 * XDEV_EXT UMEM: Unified buffer memory for zero-copy io_uring unified ops.
 *
 * Registers a user memory region, pins pages, and creates a kernel
 * virtual mapping (vmap).  unified_ops can then read/compute/send
 * directly on the pinned pages without copy_to/from_user.
 */

#include "xdev_ext_config.h"

#ifdef XDEV_EXT_UMEM_ZEROCOPY

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/refcount.h>
#include <linux/sched/mm.h>
#include <linux/vmalloc.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "xdev_ext_umem.h"

#ifdef CONFIG_XDEV_EXT_MECH
#include <linux/spinlock.h>
#include <linux/xdev_ext_mech.h>

#include "xdev_ext_mech_core.h"
#endif

/*
 * Global UMEM registry: allows multiple io_ring_ctx instances to share
 * the same UMEM (identified by mm, user virtual address, and the pages pinned
 * for that registration). This enables
 * threads in one address space to use per-thread io_uring rings while
 * sharing a single pinned UMEM region without aliasing an unrelated process
 * that happens to map the same numeric address.
 *
 * Protected by xdev_ext_umem_lock.  Entries are refcounted; the UMEM is
 * freed when the last ring unreferences it.
 */
static DEFINE_MUTEX(xdev_ext_umem_lock);
static LIST_HEAD(xdev_ext_umem_list);

struct xdev_ext_umem_entry {
	struct list_head	list;
	struct io_xdev_ext_umem	*umem;
};

static bool xdev_ext_umem_pages_match(const struct io_xdev_ext_umem *umem,
				 struct page **pages, u32 nr_pages)
{
	u32 i;

	if (umem->nr_pages != nr_pages)
		return false;
	for (i = 0; i < nr_pages; i++) {
		if (umem->pages[i] != pages[i])
			return false;
	}
	return true;
}

/* Find an existing UMEM with the same pinned mapping (caller holds lock). */
static struct io_xdev_ext_umem *xdev_ext_umem_find_locked(struct mm_struct *mm,
						u64 user_addr, u64 size,
						u32 frame_size,
						struct page **pages, u32 nr_pages)
{
	struct xdev_ext_umem_entry *entry;

	list_for_each_entry(entry, &xdev_ext_umem_list, list) {
		if (entry->umem->mm == mm &&
		    entry->umem->user_addr == user_addr &&
		    entry->umem->size == size &&
		    entry->umem->frame_size == frame_size &&
		    xdev_ext_umem_pages_match(entry->umem, pages, nr_pages))
			return entry->umem;
	}
	return NULL;
}

/* Add a new UMEM to the global list (caller holds xdev_ext_umem_lock) */
static int xdev_ext_umem_add_locked(struct io_xdev_ext_umem *umem)
{
	struct xdev_ext_umem_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	entry->umem = umem;
	list_add_tail(&entry->list, &xdev_ext_umem_list);
	return 0;
}

/* Remove a UMEM from the global list (caller holds xdev_ext_umem_lock) */
static void xdev_ext_umem_remove_locked(struct io_xdev_ext_umem *umem)
{
	struct xdev_ext_umem_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &xdev_ext_umem_list, list) {
		if (entry->umem == umem) {
			list_del(&entry->list);
			kfree(entry);
			return;
		}
	}
}

static void io_xdev_ext_umem_free(struct io_xdev_ext_umem *umem)
{
	if (umem->vmap_addr)
		vunmap(umem->vmap_addr);
#ifdef XDEV_EXT_LIFECYCLE_SM
	kvfree(umem->frames);
#endif
#ifdef CONFIG_XDEV_EXT_MECH
	kvfree(umem->mech_state);
#endif
	if (umem->pages) {
		unpin_user_pages(umem->pages, umem->nr_pages);
		kvfree(umem->pages);
	}
	if (umem->mm)
		mmdrop(umem->mm);
	kfree(umem);
}

void io_xdev_ext_umem_get(struct io_xdev_ext_umem *umem)
{
	refcount_inc(&umem->refcount);
}

/*
 * Safely acquire the ctx's current UMEM for io-wq issue paths. unregister()
 * clears ctx->xdev_ext_umem under the same lock before dropping its reference, so
 * a non-NULL result here is pinned until io_xdev_ext_umem_put().
 */
struct io_xdev_ext_umem *io_xdev_ext_umem_get_ctx_with_stats(
		struct io_ring_ctx *ctx,
		struct io_uring_unified_shared __user **shared)
{
	struct io_xdev_ext_umem *umem;

	if (shared)
		*shared = NULL;
	mutex_lock(&xdev_ext_umem_lock);
	umem = ctx->xdev_ext_umem;
	if (umem) {
		io_xdev_ext_umem_get(umem);
		if (shared)
			*shared = ctx->xdev_ext_umem_shared;
	}
	mutex_unlock(&xdev_ext_umem_lock);

	return umem;
}

struct io_xdev_ext_umem *io_xdev_ext_umem_get_ctx(struct io_ring_ctx *ctx)
{
	return io_xdev_ext_umem_get_ctx_with_stats(ctx, NULL);
}

/* Task context only: may take xdev_ext_umem_lock and free the UMEM. */
void io_xdev_ext_umem_put(struct io_xdev_ext_umem *umem)
{
	if (refcount_dec_and_mutex_lock(&umem->refcount, &xdev_ext_umem_lock)) {
		xdev_ext_umem_remove_locked(umem);
		mutex_unlock(&xdev_ext_umem_lock);
		io_xdev_ext_umem_free(umem);
	}
}

int io_xdev_ext_umem_register(struct io_ring_ctx *ctx, void __user *arg)
{
	struct io_uring_xdev_ext_umem_reg reg;
	struct io_xdev_ext_umem *umem, *existing = NULL;
	struct mm_struct *mm = current->mm;
	unsigned long start;
	u32 nr_pages, pg_off;
	int ret;

	if (!mm)
		return -EINVAL;

	mutex_lock(&xdev_ext_umem_lock);
	if (ctx->xdev_ext_umem) {
		mutex_unlock(&xdev_ext_umem_lock);
		return -EBUSY;
	}
	mutex_unlock(&xdev_ext_umem_lock);

	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;

	if (!reg.size || !reg.frame_size)
		return -EINVAL;
	if (reg.frame_size & (reg.frame_size - 1))
		return -EINVAL;
	if (reg.size & (reg.frame_size - 1))
		return -EINVAL;
	if (reg.flags != 0)
		return -EINVAL;
	if (reg.size > (1ULL << 30))	/* 1 GB cap */
		return -EINVAL;

	/*
	 * Always pin a snapshot before looking for a shareable registration. A
	 * process may unmap and replace the same numeric VA while an older ring
	 * still owns long-term pins; address-only lookup would then route DMA to
	 * stale pages. The final locked lookup compares the pinned page identities.
	 */
	start  = reg.addr & PAGE_MASK;
	pg_off = reg.addr & ~PAGE_MASK;
	nr_pages = (pg_off + reg.size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return -ENOMEM;
	umem->mm = mm;
	mmgrab(mm);

	umem->pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!umem->pages) {
		ret = -ENOMEM;
		goto err_umem;
	}

	ret = pin_user_pages_fast(start, nr_pages, FOLL_WRITE | FOLL_LONGTERM,
				  umem->pages);
	if (ret < 0)
		goto err_pages;
	if (ret != nr_pages) {
		unpin_user_pages(umem->pages, ret);
		ret = -EFAULT;
		goto err_pages;
	}

	umem->vmap_addr = vmap(umem->pages, nr_pages, VM_MAP, PAGE_KERNEL);
	if (!umem->vmap_addr) {
		unpin_user_pages(umem->pages, nr_pages);
		ret = -ENOMEM;
		goto err_pages;
	}

	umem->page_offset = pg_off;
	umem->user_addr   = reg.addr;
	umem->size         = reg.size;
	umem->nr_pages     = nr_pages;
	umem->frame_size   = reg.frame_size;
	umem->nr_frames    = reg.size / reg.frame_size;
	refcount_set(&umem->refcount, 1);

#ifdef XDEV_EXT_LIFECYCLE_SM
	umem->frames = kvcalloc(umem->nr_frames, sizeof(*umem->frames),
				GFP_KERNEL);
	if (!umem->frames) {
		vunmap(umem->vmap_addr);
		unpin_user_pages(umem->pages, nr_pages);
		ret = -ENOMEM;
		goto err_pages;
	}
	xdev_ext_pool_init(&umem->frame_pool, umem->frames, umem->nr_frames, false);
#endif

	/*
	 * Re-check after pinning: another ring may have installed this key while
	 * the candidate was prepared. In that case share the winner and release
	 * the duplicate pins.
	 */
	mutex_lock(&xdev_ext_umem_lock);
	if (ctx->xdev_ext_umem) {
		ret = -EBUSY;
	} else {
		existing = xdev_ext_umem_find_locked(mm, reg.addr, reg.size,
						 reg.frame_size, umem->pages,
						 umem->nr_pages);
		if (existing) {
			refcount_inc(&existing->refcount);
			ctx->xdev_ext_umem = existing;
			ctx->xdev_ext_umem_shared =
				(struct io_uring_unified_shared __user *)
						(uintptr_t)reg.shared_addr;
			ret = 0;
		} else {
			ret = xdev_ext_umem_add_locked(umem);
			if (!ret) {
				ctx->xdev_ext_umem = umem;
				ctx->xdev_ext_umem_shared =
					(struct io_uring_unified_shared __user *)
							(uintptr_t)reg.shared_addr;
			}
		}
	}
	mutex_unlock(&xdev_ext_umem_lock);
	if (ret < 0 || existing) {
		io_xdev_ext_umem_free(umem);
		if (ret < 0)
			return ret;
	}

	return 0;

err_pages:
	kvfree(umem->pages);
err_umem:
	mmdrop(umem->mm);
	kfree(umem);
	return ret;
}

int io_xdev_ext_umem_unregister(struct io_ring_ctx *ctx)
{
	struct io_xdev_ext_umem *umem;

	mutex_lock(&xdev_ext_umem_lock);
	umem = ctx->xdev_ext_umem;
	if (!umem) {
		mutex_unlock(&xdev_ext_umem_lock);
		return -EINVAL;
	}
	ctx->xdev_ext_umem = NULL;
	ctx->xdev_ext_umem_shared = NULL;
	mutex_unlock(&xdev_ext_umem_lock);

	/* Drop refcount; only free when last ring/op user is gone. */
	io_xdev_ext_umem_put(umem);
	return 0;
}

void io_xdev_ext_umem_destroy(struct io_ring_ctx *ctx)
{
	io_xdev_ext_umem_unregister(ctx);
}

#ifdef CONFIG_XDEV_EXT_MECH
/*
 * Pool provider of mechanism sessions on this ring's UMEM.  The session
 * holds its own UMEM reference, so IORING_UNREGISTER_XDEV_EXT_UMEM leaves the
 * pages and the ownership words alive until the session lets go.  Each
 * session queues, in START order, the K_FREE frames user space handed it.
 */
struct io_xdev_ext_umem_mech {
	struct io_xdev_ext_umem	*umem;
	spinlock_t		lock;		/* head, nr, idx */
	u32			head;
	u32			nr;		/* K_FREE frames queued */
	u32			idx[];		/* umem->nr_frames slots */
};

/* Session worker: the oldest @nr queued frames, K_FREE -> HELD. */
static int io_xdev_ext_umem_mech_alloc(struct xdev_ext_mech_pool *pool,
				  struct xdev_ext_mech_frame *f, u32 nr)
{
	struct io_xdev_ext_umem_mech *m = pool->priv;
	unsigned long flags;
	int ret = 0;
	u32 i;

	spin_lock_irqsave(&m->lock, flags);
	if (m->nr < nr) {
		ret = -ENOSPC;
		goto out;
	}
	for (i = 0; i < nr; i++) {
		f[i].index = m->idx[(m->head + i) % pool->nr_frames];
		ret = xdev_ext_mech_frame_move(&pool->state[f[i].index],
					  XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_HELD);
		if (ret)
			break;
	}
	if (ret) {
		while (i--)
			xdev_ext_mech_frame_move(&pool->state[f[i].index],
					    XDEV_EXT_MECH_F_HELD, XDEV_EXT_MECH_F_K_FREE);
		goto out;
	}
	m->head = (m->head + nr) % pool->nr_frames;
	m->nr -= nr;
out:
	spin_unlock_irqrestore(&m->lock, flags);
	return ret;
}

static int io_xdev_ext_umem_mech_resolve(struct xdev_ext_mech_pool *pool,
				    struct xdev_ext_mech_frame *f)
{
	if (f->index >= pool->nr_frames)
		return -ERANGE;
	f->umem_addr = (u64)f->index * pool->frame_size;
	f->kaddr = pool->vaddr + f->umem_addr;
	f->pool_priv = NULL;
	return 0;
}

/* Any context: a K_FREE frame joins the tail of the queue. */
static void io_xdev_ext_umem_mech_recycle(struct xdev_ext_mech_pool *pool,
				     struct xdev_ext_mech_frame *f)
{
	struct io_xdev_ext_umem_mech *m = pool->priv;
	unsigned long flags;

	spin_lock_irqsave(&m->lock, flags);
	if (!WARN_ON_ONCE(m->nr >= pool->nr_frames ||
			  f->index >= pool->nr_frames)) {
		m->idx[(m->head + m->nr) % pool->nr_frames] = f->index;
		m->nr++;
	}
	spin_unlock_irqrestore(&m->lock, flags);
}

/* Process context, never for a quarantined session. */
static void io_xdev_ext_umem_mech_release(struct xdev_ext_mech_pool *pool)
{
	struct io_xdev_ext_umem_mech *m = pool->priv;
	u32 i;

	/* Frames handed in but never used go back to user space. */
	for (i = 0; i < m->nr; i++)
		xdev_ext_mech_frame_move(&pool->state[m->idx[(m->head + i) %
							 pool->nr_frames]],
				    XDEV_EXT_MECH_F_K_FREE, XDEV_EXT_MECH_F_USER);
	io_xdev_ext_umem_put(m->umem);
	kvfree(m);
}

static const struct xdev_ext_mech_pool_ops io_xdev_ext_umem_mech_pool_ops = {
	.alloc = io_xdev_ext_umem_mech_alloc,
	.resolve = io_xdev_ext_umem_mech_resolve,
	.recycle = io_xdev_ext_umem_mech_recycle,
	.release = io_xdev_ext_umem_mech_release,
};

int io_xdev_ext_umem_mech_pool_bind(struct xdev_ext_mech_pool *pool,
			       struct io_ring_ctx *ctx,
			       const struct xdev_ext_mech_layout *l)
{
	struct io_xdev_ext_umem_mech *m;
	struct io_xdev_ext_umem *umem;
	u8 *state;
	int ret;

	umem = io_xdev_ext_umem_get_ctx(ctx);
	if (!umem)
		return -ENXIO;
	ret = -EINVAL;
	if (l->frame_size != umem->frame_size || !umem->nr_frames)
		goto err_put;
	ret = -ENOMEM;
	m = kvzalloc(struct_size(m, idx, umem->nr_frames), GFP_KERNEL);
	if (!m)
		goto err_put;

	mutex_lock(&xdev_ext_umem_lock);
	if (!umem->mech_state)
		umem->mech_state = kvzalloc(umem->nr_frames, GFP_KERNEL);
	state = umem->mech_state;
	mutex_unlock(&xdev_ext_umem_lock);
	if (!state) {
		kvfree(m);
		goto err_put;
	}

	spin_lock_init(&m->lock);
	m->umem = umem;
	*pool = (struct xdev_ext_mech_pool) {
		.ops = &io_xdev_ext_umem_mech_pool_ops,
		.priv = m,
		.state = state,
		.pages = umem->pages,
		.vaddr = umem->vmap_addr + umem->page_offset,
		.size = umem->size,
		.kind = XDEV_EXT_MECH_POOL_IOU_UMEM,
		.frame_size = umem->frame_size,
		.nr_frames = umem->nr_frames,
		.nr_pages = umem->nr_pages,
		.first_page_off = umem->page_offset,
	};
	return 0;

err_put:
	io_xdev_ext_umem_put(umem);
	return ret;
}
#endif /* CONFIG_XDEV_EXT_MECH */

#endif /* XDEV_EXT_UMEM_ZEROCOPY */
