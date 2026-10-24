/*
 * SPDX-FileCopyrightText: Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 *
 * Copy-engine backend of the XDEV_EXT mechanism layer (include/linux/xdev_ext_mech.h).
 *
 * The XDEV_EXT kernel's CE class owns the stage: the class program builds a copy
 * plan, C validates it against the window, its device-contiguous segments
 * and the batch frames, and the session worker hands it to this backend.  A
 * stage fd is an opened /dev/nvidiaN.  bind_region binds the stage window to
 * the CREATE caller's vidmem allocation (nv_p2p_vidmem_bind(): the RM dup
 * keeps the FB pages allocated, the device reference keeps the GPU open);
 * bind_host maps the already pinned pool for the GPU DMA device. CeUtils
 * semaphore events queue retirement work, which validates the saved frame
 * claims and reports each ticket once through xdev_ext_ce_complete().  After an AMBIGUOUS outcome the class never
 * unbinds the stage, so the window, the host mapping and the module
 * reference the class took stay held for good.
 */

#define  __NO_VERSION__

#include "os-interface.h"
#include "nv-linux.h"
#include "nv-lock.h"
#include "nv-p2p.h"
#include "nv-xdev_ext-ce-backend.h"
#include "nv-xdev_ext-ce-classify.h"
#include "nv-xdev_ext-ce-plan.h"
#include "nv-xdev_ext-ce-async.h"

#if defined(XDEV_EXT_ENABLE_GPU_CE_DMA) && defined(CONFIG_XDEV_EXT_MECH_CE)

#include <linux/xdev_ext_mech.h>
#include <linux/dma-mapping.h>
#include <linux/scatterlist.h>
#include <linux/timer.h>
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
#include <linux/hrtimer.h>
#endif

/* The pure headers' numbering is the kernel's. */
static_assert((int)NV_XDEV_EXT_GPU_TO_DEVICE == (int)XDEV_EXT_MECH_DIR_TO_DEVICE);
static_assert((int)NV_XDEV_EXT_GPU_FROM_DEVICE == (int)XDEV_EXT_MECH_DIR_FROM_DEVICE);
static_assert((int)NV_XDEV_EXT_CE_OK == (int)XDEV_EXT_CE_OK);
static_assert((int)NV_XDEV_EXT_CE_PRE_SUBMIT_FAILED == (int)XDEV_EXT_CE_PRE_SUBMIT_FAILED);
static_assert((int)NV_XDEV_EXT_CE_AMBIGUOUS == (int)XDEV_EXT_CE_AMBIGUOUS);

/* One bound stage window. */
struct nv_xdev_ext_ce_region {
    nv_p2p_vidmem_binding_t *vidmem;
    struct device *dev;         /* the GPU, for bind_host's IOMMU check */
    NvBool ambiguous;           /* an AMBIGUOUS outcome: never unbound */
};

/* Request storage and RM stack are allocated once, before any submission. */
#define NV_XDEV_EXT_CE_REQUEST_SLOTS 64U
#define NV_XDEV_EXT_CE_TIMEOUT (30 * HZ)
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
static unsigned int nv_xdev_ext_ce_poll_us = 5;
module_param_named(xdev_ext_ce_poll_us, nv_xdev_ext_ce_poll_us, uint, 0644);
MODULE_PARM_DESC(xdev_ext_ce_poll_us, "XDEV_EXT native CE progress polling base in us (1-100)");
static unsigned int nv_xdev_ext_ce_poll_base(void)
{ return clamp_t(unsigned int, READ_ONCE(nv_xdev_ext_ce_poll_us), 1, 100); }
#endif
struct nv_xdev_ext_ce_request {
    struct xdev_ext_ce_xfer x[NV_XDEV_EXT_CE_MAX_XFERS];
    u32 n;
};
struct nv_xdev_ext_ce_host {
    struct nv_xdev_ext_ce_region *region;
    nv_p2p_ce_host_t *rm;
    NvU64 bytes;
    struct mutex lock;
    struct work_struct progress;
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
    struct hrtimer timer;
    unsigned int backoff;
#else
    struct timer_list watchdog; /* deadline only; never polls ordinary progress */
#endif
    spinlock_t event_lock;
    u64 watermark, submitted;
    struct { u64 late, stale; } stats;
#ifndef NV_XDEV_EXT_CE_PHYS_ADDR
    struct sg_table sgt;
#endif
    struct nv_xdev_ext_ce_async_pool pool;
    struct nv_xdev_ext_ce_async_slot slots[NV_XDEV_EXT_CE_REQUEST_SLOTS];
    struct nv_xdev_ext_ce_async_completion completions[NV_XDEV_EXT_CE_REQUEST_SLOTS];
    struct nv_xdev_ext_ce_request requests[NV_XDEV_EXT_CE_REQUEST_SLOTS];
    struct nv_xdev_ext_ce_request completed[NV_XDEV_EXT_CE_REQUEST_SLOTS];
    unsigned long deadlines[NV_XDEV_EXT_CE_REQUEST_SLOTS];
    nv_p2p_umem_xfer_t xfers[NV_XDEV_EXT_CE_MAX_XFERS];
};

#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
static enum hrtimer_restart nv_xdev_ext_ce_poll_timer(struct hrtimer *timer)
{
    struct nv_xdev_ext_ce_host *h = container_of(timer, struct nv_xdev_ext_ce_host, timer);
    queue_work(system_unbound_wq, &h->progress);
    return HRTIMER_NORESTART;
}
#else
static void nv_xdev_ext_ce_deadline(struct timer_list *timer)
{
    struct nv_xdev_ext_ce_host *h = timer_container_of(h, timer, watchdog);
    queue_work(system_unbound_wq, &h->progress);
}

/* No mutex/RM reentry: this can run before submit publishes its token. The
 * worker waits on the submission mutex, then compares against submitted. */
static void nv_xdev_ext_ce_event(void *arg, NvU64 watermark)
{
    struct nv_xdev_ext_ce_host *h = arg;
    unsigned long flags;
    spin_lock_irqsave(&h->event_lock, flags);
    if (watermark <= h->watermark) h->stats.late++;
    else h->watermark = watermark;
    spin_unlock_irqrestore(&h->event_lock, flags);
    queue_work(system_unbound_wq, &h->progress);
}
#endif

/* A streaming mapping's original segment base is the DMA API handle. Sync
 * only the touched ranges, so disjoint in-flight batches keep their ownership. */
static void nv_xdev_ext_ce_sync(struct nv_xdev_ext_ce_host *h,
    const struct nv_xdev_ext_ce_request *request, bool cpu)
{
#ifndef NV_XDEV_EXT_CE_PHYS_ADDR
    struct scatterlist *sg;
    u32 i, j;
    u64 base = 0;
    for_each_sgtable_dma_sg(&h->sgt, sg, i) {
        u64 end = base + sg_dma_len(sg);
        for (j = 0; j < request->n; j++) {
            u64 start = max(base, request->x[j].host_byte_off);
            u64 stop = min(end, request->x[j].host_byte_off + request->x[j].len);
            if (start >= stop) continue;
            if (cpu)
                dma_sync_single_range_for_cpu(h->region->dev, sg_dma_address(sg),
                    start - base, stop - start, DMA_BIDIRECTIONAL);
            else
                dma_sync_single_range_for_device(h->region->dev, sg_dma_address(sg),
                    start - base, stop - start, DMA_BIDIRECTIONAL);
        }
        base = end;
    }
#else
    (void)h; (void)request; (void)cpu;
#endif
}

/* Single work item serializes retirement. Save complete immutable requests
 * separately before releasing slots; a new submit cannot overwrite callbacks. */
static void nv_xdev_ext_ce_progress(struct work_struct *work)
{
    struct nv_xdev_ext_ce_host *h = container_of(work, struct nv_xdev_ext_ce_host, progress);
    NvU64 watermark = 0;
    unsigned int i, count = 0, pending = 0;
    unsigned long earliest = 0, flags;
    bool failed = false;

    mutex_lock(&h->lock);
    for (i = 0; i < NV_XDEV_EXT_CE_REQUEST_SLOTS; i++)
        if (h->slots[i].state == NV_XDEV_EXT_CE_ASYNC_PENDING) {
            pending++;
            if (time_after_eq(jiffies, h->deadlines[i])) failed = true;
        }
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
    if (pending && !h->pool.quarantined && !failed) {
        NV_STATUS status;
        down_read(&nv_system_pm_lock);
        status = nv_p2p_ce_progress(h->rm, &watermark);
        up_read(&nv_system_pm_lock);
        failed = status != NV_OK;
    }
#else
    spin_lock_irqsave(&h->event_lock, flags);
    watermark = h->watermark;
    if (watermark > h->submitted && !h->pool.quarantined) {
        h->stats.stale++;
        failed = true;
    }
    spin_unlock_irqrestore(&h->event_lock, flags);
#endif
    if (failed) {
        h->pool.quarantined = h->pool.stopping = 1;
        WRITE_ONCE(h->region->ambiguous, NV_TRUE);
    }
    pending = 0;
    for (i = 0; i < NV_XDEV_EXT_CE_REQUEST_SLOTS; i++) {
        struct nv_xdev_ext_ce_async_slot *slot = &h->slots[i];
        if (slot->state != NV_XDEV_EXT_CE_ASYNC_PENDING) continue;
        if (h->pool.quarantined) {
            struct nv_xdev_ext_ce_async_completion *c = &h->completions[count];
            c->ticket = slot->ticket; c->token = slot->token;
            c->cookie = slot->cookie; c->bytes = 0;
            h->completed[count++] = h->requests[i];
            slot->state = NV_XDEV_EXT_CE_ASYNC_QUARANTINED;
        } else if (nv_xdev_ext_ce_async_ready(&h->pool, slot, watermark,
                                            &h->completions[count])) {
            h->completed[count++] = h->requests[i];
        } else {
            if (!pending || time_before(h->deadlines[i], earliest)) earliest = h->deadlines[i];
            pending++;
        }
    }
    if (pending) {
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
        h->backoff = count ? nv_xdev_ext_ce_poll_base() : min(h->backoff * 2, 100U);
        hrtimer_start(&h->timer, ns_to_ktime((u64)h->backoff * NSEC_PER_USEC),
                      HRTIMER_MODE_REL);
#else
        mod_timer(&h->watchdog, earliest);
#endif
    }
    failed = h->pool.quarantined;
    mutex_unlock(&h->lock);
    for (i = 0; i < count; i++) {
        struct nv_xdev_ext_ce_async_completion *c = &h->completions[i];
        struct nv_xdev_ext_ce_request *saved = &h->completed[i];
        if (!xdev_ext_ce_owners_valid(c->cookie, c->ticket, saved->x, saved->n)) {
            spin_lock_irqsave(&h->event_lock, flags);
            h->stats.stale++;
            spin_unlock_irqrestore(&h->event_lock, flags);
            mutex_lock(&h->lock);
            h->pool.quarantined = h->pool.stopping = 1;
            WRITE_ONCE(h->region->ambiguous, NV_TRUE);
            mutex_unlock(&h->lock);
            continue; /* never publish/release a reused frame's ownership */
        }
        if (!failed) nv_xdev_ext_ce_sync(h, saved, true);
        xdev_ext_ce_complete(c->cookie, c->ticket, failed ? -EIO : 0,
                            NV_TRUE, failed ? 0 : c->bytes);
    }
}

/* CREATE caller's process context. */
static int nv_xdev_ext_ce_bind_region(struct file *f, u64 gpu_va, u64 len,
                                 struct xdev_ext_ce_region *out)
{
    nv_linux_file_private_t *nvlfp = NV_GET_LINUX_FILE_PRIVATE(f);
    struct nv_xdev_ext_ce_region *region;
    nv_p2p_vidmem_binding_t *residual = NULL;
    nv_linux_state_t *nvl;
    nvidia_stack_t *sp = NULL;
    const NvU8 *uuid;
    NV_STATUS status;
    NvU32 seg_size;
    int rc;

    if (nv_is_control_device(NV_FILE_INODE(f)))
        return -EINVAL;

    rc = nv_wait_open_complete_interruptible(nvlfp);
    if (rc != 0)
        return rc;

    nvl = nvlfp->nvptr;
    if (nvlfp->open_rc != 0 || nvl == NULL)
        return -ENODEV;

    region = kzalloc(sizeof(*region), GFP_KERNEL);
    if (region == NULL)
        return -ENOMEM;

    rc = nv_down_read_interruptible(&nv_system_pm_lock);
    if (rc < 0)
        goto free_region;

    rc = nv_kmem_cache_alloc_stack(&sp);
    if (rc != 0)
        goto pm_unlock;

    uuid = rm_get_gpu_uuid_raw(sp, NV_STATE_PTR(nvl));
    if (uuid == NULL)
    {
        rc = -ENODEV;
        goto free_stack;
    }

    status = nv_p2p_vidmem_bind(uuid, gpu_va, len, &region->vidmem,
                                &seg_size, &residual);
    if (status != NV_OK)
    {
        rc = nv_p2p_umem_errno(status);
        if (residual != NULL)
        {
            region->vidmem = residual;
            region->dev = nvl->dev;
            region->ambiguous = NV_TRUE;
            out->priv = region; /* failed CREATE still owns this allocation */
        }
        goto free_stack;
    }

    region->dev = nvl->dev;
    out->priv = region;
    out->len = len;
    out->seg_size = seg_size;
    out->max_entry_len = 0;

free_stack:
    nv_kmem_cache_free_stack(sp);
pm_unlock:
    up_read(&nv_system_pm_lock);
free_region:
    if (rc != 0 && residual == NULL)
        kfree(region);
    return rc;
}

/* Process context, after drain; never after an AMBIGUOUS outcome. */
static int nv_xdev_ext_ce_unbind_region(struct xdev_ext_ce_region *r)
{
    struct nv_xdev_ext_ce_region *region = r->priv;
    NV_STATUS status;
    if (region == NULL) return 0;
    if (WARN_ON_ONCE(READ_ONCE(region->ambiguous))) return -EIO;
    down_read(&nv_system_pm_lock);
    status = nv_p2p_vidmem_unbind(region->vidmem);
    up_read(&nv_system_pm_lock);
    if (status != NV_OK) {
        WRITE_ONCE(region->ambiguous, NV_TRUE);
        return nv_p2p_umem_errno(status);
    }
    r->priv = NULL;
    kfree(region);
    return 0;
}

/* CREATE, process context: UMEM owns and pins these ordinary cached pages. */
static int nv_xdev_ext_ce_bind_host(struct xdev_ext_ce_region *r, struct page **pages,
                               u32 nr, void **host)
{
    struct nv_xdev_ext_ce_region *region = r->priv;
    struct nv_xdev_ext_ce_host *h;
    NvU64 *phys;
    NV_STATUS status;
    u32 i;
    int rc;
#ifndef NV_XDEV_EXT_CE_PHYS_ADDR
    struct scatterlist *sg;
    u32 page = 0;
#endif
    if (!nr || !pages || !host) return -EINVAL;
    *host = NULL;
#ifdef NV_XDEV_EXT_CE_PHYS_ADDR
    if (!nv_p2p_umem_iommu_untranslated(region->dev)) return -EOPNOTSUPP;
#endif
    h = kvzalloc(sizeof(*h), GFP_KERNEL);
    if (!h) return -ENOMEM;
    phys = kvmalloc_array(nr, sizeof(*phys), GFP_KERNEL);
    if (!phys) { kvfree(h); return -ENOMEM; }
    h->region = region; h->bytes = (NvU64)nr << PAGE_SHIFT;
#ifdef NV_XDEV_EXT_CE_PHYS_ADDR
    for (i = 0; i < nr; i++) phys[i] = page_to_phys(pages[i]);
#else
    rc = sg_alloc_table_from_pages(&h->sgt, pages, nr, 0, h->bytes, GFP_KERNEL);
    if (rc) goto free_arrays;
    rc = dma_map_sgtable(region->dev, &h->sgt, DMA_BIDIRECTIONAL, 0);
    if (rc) goto free_sg;
    for_each_sgtable_dma_sg(&h->sgt, sg, i) {
        u64 off;
        if ((sg_dma_address(sg) | sg_dma_len(sg)) & (PAGE_SIZE - 1)) {
            rc = -EINVAL; goto unmap;
        }
        for (off = 0; off < sg_dma_len(sg); off += PAGE_SIZE) {
            if (page >= nr) { rc = -EINVAL; goto unmap; }
            phys[page++] = sg_dma_address(sg) + off;
        }
    }
    if (page != nr) { rc = -EINVAL; goto unmap; }
    dma_sync_sgtable_for_cpu(region->dev, &h->sgt, DMA_BIDIRECTIONAL);
#endif
    mutex_init(&h->lock);
    spin_lock_init(&h->event_lock);
    INIT_WORK(&h->progress, nv_xdev_ext_ce_progress);
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
    hrtimer_setup(&h->timer, nv_xdev_ext_ce_poll_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    h->backoff = nv_xdev_ext_ce_poll_base();
#else
    timer_setup(&h->watchdog, nv_xdev_ext_ce_deadline, 0);
#endif
    nv_xdev_ext_ce_async_init(&h->pool, h->slots, NV_XDEV_EXT_CE_REQUEST_SLOTS);
    down_read(&nv_system_pm_lock);
    status = nv_p2p_ce_host_bind(region->vidmem, phys, nr, PAGE_SIZE, h->bytes,
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
                                NULL, NULL,
#else
                                nv_xdev_ext_ce_event, h,
#endif
                                &h->rm);
    up_read(&nv_system_pm_lock);
    if (status != NV_OK) { rc = nv_p2p_umem_errno(status); goto unmap; }
    kvfree(phys);
    *host = h;
    return 0;
unmap:
#ifndef NV_XDEV_EXT_CE_PHYS_ADDR
    dma_unmap_sgtable(region->dev, &h->sgt, DMA_BIDIRECTIONAL, 0);
free_sg:
    sg_free_table(&h->sgt);
free_arrays:
#endif
    kvfree(phys);
    kvfree(h);
    return rc;
}

static int nv_xdev_ext_ce_unbind_host(void *host)
{
    struct nv_xdev_ext_ce_host *h = host;
    NV_STATUS status;
    if (h == NULL) return 0;
    mutex_lock(&h->lock);
    nv_xdev_ext_ce_async_stop(&h->pool);
    if (WARN_ON_ONCE(!nv_xdev_ext_ce_async_can_release(&h->pool))) {
        WRITE_ONCE(h->region->ambiguous, NV_TRUE);
        mutex_unlock(&h->lock);
        return -EBUSY;
    }
    mutex_unlock(&h->lock);
    /* Producer disconnect precedes the final worker drain: RM teardown may
     * run one last already queued CeUtils callback while h is still live. */
    down_read(&nv_system_pm_lock);
    status = nv_p2p_ce_host_unbind(h->rm);
    up_read(&nv_system_pm_lock);
    if (status != NV_OK) {
        WRITE_ONCE(h->region->ambiguous, NV_TRUE);
        return nv_p2p_umem_errno(status);
    }
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
    hrtimer_cancel(&h->timer);
#else
    timer_delete_sync(&h->watchdog);
#endif
    cancel_work_sync(&h->progress);
#ifndef NV_XDEV_EXT_CE_PHYS_ADDR
    dma_unmap_sgtable(h->region->dev, &h->sgt, DMA_BIDIRECTIONAL, 0);
    sg_free_table(&h->sgt);
#endif
    kvfree(h);
    return 0;
}

/* Session worker may sleep on CPU submission; never waits for DMA completion. */
static int nv_xdev_ext_ce_submit(struct xdev_ext_ce_region *r, void *host, u32 dir,
                            const struct xdev_ext_ce_xfer *x, u32 n,
                            struct xdev_ext_ce_cookie *ck, u64 ticket)
{
    struct nv_xdev_ext_ce_host *h = host;
    struct nv_xdev_ext_ce_async_slot *slot;
    enum nv_xdev_ext_ce_outcome outcome;
    NvBool issued = NV_FALSE;
    NvU64 token = 0, bytes = 0;
    NV_STATUS status;
    NvU32 rm_dir;
    u32 i;
    int rc;
    struct nv_xdev_ext_ce_request *saved;

    if (!h || h->region != r->priv || !ck || !x) return -EINVAL;
    rc = nv_xdev_ext_ce_rm_direction(dir, &rm_dir);
    if (rc) return rc;
    if (!nv_xdev_ext_ce_count_ok(n)) return -EINVAL;
    /* Entire plan validated before reserving or entering RM. */
    for (i = 0; i < n; i++) {
        if (!nv_xdev_ext_ce_entry_ok(x[i].host_byte_off, x[i].gpu_off, x[i].len,
                                r->len, h->bytes)) return -ERANGE;
        bytes += x[i].len;
    }
    mutex_lock(&h->lock);
    for (i = 0; i < NV_XDEV_EXT_CE_REQUEST_SLOTS; i++)
        if (h->slots[i].state != NV_XDEV_EXT_CE_ASYNC_FREE && h->slots[i].cookie == ck) {
            rc = -EBUSY; goto unlock;
        }
    if (!xdev_ext_ce_owners_valid(ck, ticket, x, n)) { rc = -ESTALE; goto unlock; }
    rc = nv_xdev_ext_ce_async_reserve(&h->pool, ticket, ck, bytes, &slot);
    if (rc) goto unlock;
    saved = &h->requests[slot - h->slots];
    saved->n = n;
    memcpy(saved->x, x, n * sizeof(*x));
    for (i = 0; i < n; i++) {
        h->xfers[i].umemOffset = x[i].host_byte_off;
        h->xfers[i].gpuOffset = x[i].gpu_off;
        h->xfers[i].size = x[i].len;
    }
    rc = nv_down_read_interruptible(&nv_system_pm_lock);
    if (rc < 0) {
        nv_xdev_ext_ce_async_submitted(&h->pool, slot, rc, 0, 0);
        goto unlock;
    }
    nv_xdev_ext_ce_sync(h, saved, false);
    status = nv_p2p_ce_async_submit(h->rm, h->xfers, n, rm_dir, &issued, &token);
    up_read(&nv_system_pm_lock);
    outcome = nv_xdev_ext_ce_async_submitted(&h->pool, slot, status, issued, token);
    if (outcome == NV_XDEV_EXT_CE_OK) {
        h->deadlines[slot - h->slots] = jiffies + NV_XDEV_EXT_CE_TIMEOUT;
        h->submitted = token;
#ifdef NV_XDEV_EXT_CE_POLL_COMPLETION
        h->backoff = nv_xdev_ext_ce_poll_base();
#endif
        queue_work(system_unbound_wq, &h->progress);
        rc = 0;
    } else if (outcome == NV_XDEV_EXT_CE_AMBIGUOUS) {
        WRITE_ONCE(h->region->ambiguous, NV_TRUE);
        /* The failed slot completes here; progress retires other accepted work. */
        queue_work(system_unbound_wq, &h->progress);
        mutex_unlock(&h->lock);
        if (xdev_ext_ce_owners_valid(ck, ticket, saved->x, saved->n))
            xdev_ext_ce_complete(ck, ticket, status ? nv_p2p_umem_errno(status) : -EIO,
                                NV_TRUE, 0);
        return 0;
    } else {
        /* No DMA was issued; return the touched ranges to CPU ownership. */
        nv_xdev_ext_ce_sync(h, saved, true);
        rc = nv_p2p_umem_errno(status);
    }
unlock:
    mutex_unlock(&h->lock);
    return rc;
}

static struct xdev_ext_ce_backend_ops nv_xdev_ext_ce_backend = {
    .owner         = THIS_MODULE,
    .bind_region   = nv_xdev_ext_ce_bind_region,
    .unbind_region = nv_xdev_ext_ce_unbind_region,
    .bind_host     = nv_xdev_ext_ce_bind_host,
    .unbind_host   = nv_xdev_ext_ce_unbind_host,
    .submit        = nv_xdev_ext_ce_submit,
};

static NvBool nv_xdev_ext_ce_backend_registered;

void nv_xdev_ext_ce_backend_init(const struct file_operations *fops)
{
    int rc;

    if (NVreg_EnableXdevExtCeDma == 0)
        return;

    nv_xdev_ext_ce_backend.fops = fops;
    rc = xdev_ext_ce_backend_register(&nv_xdev_ext_ce_backend);
    if (rc != 0)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: XDEV_EXT CE mechanism backend not registered: %d\n", rc);
        return;
    }
    nv_xdev_ext_ce_backend_registered = NV_TRUE;
}

/* Sessions pin this module, so none is left by the time exit runs. */
void nv_xdev_ext_ce_backend_exit(void)
{
    if (!nv_xdev_ext_ce_backend_registered)
        return;

    xdev_ext_ce_backend_unregister(&nv_xdev_ext_ce_backend);
    nv_xdev_ext_ce_backend_registered = NV_FALSE;
}

#endif /* XDEV_EXT_ENABLE_GPU_CE_DMA && CONFIG_XDEV_EXT_MECH_CE */
