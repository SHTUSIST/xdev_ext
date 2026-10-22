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
 * bind_host takes the pool pages, already pinned by their UMEM, as CPU
 * physical addresses for an ADDR_SYSMEM surface; submit enqueues native CE ASYNC work under the RM API lock. A bounded
 * kernel worker polls the channel watermark and reports each ticket exactly
 * once through xdev_ext_ce_complete().  After an AMBIGUOUS outcome the class never
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
#include <linux/hrtimer.h>

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
static unsigned int nv_xdev_ext_ce_poll_us = 5;
module_param_named(xdev_ext_ce_poll_us, nv_xdev_ext_ce_poll_us, uint, 0644);
MODULE_PARM_DESC(xdev_ext_ce_poll_us, "XDEV_EXT native CE progress polling base in us (1-100)");

static unsigned int nv_xdev_ext_ce_poll_base(void)
{ return clamp_t(unsigned int, READ_ONCE(nv_xdev_ext_ce_poll_us), 1, 100); }
struct nv_xdev_ext_ce_host {
    struct nv_xdev_ext_ce_region *region;
    nv_p2p_ce_host_t *rm;
    NvU64 bytes;
    struct mutex lock;
    struct work_struct progress;
    struct hrtimer timer;
    struct nv_xdev_ext_ce_async_pool pool;
    struct nv_xdev_ext_ce_async_slot slots[NV_XDEV_EXT_CE_REQUEST_SLOTS];
    struct nv_xdev_ext_ce_async_completion completions[NV_XDEV_EXT_CE_REQUEST_SLOTS];
    unsigned long deadlines[NV_XDEV_EXT_CE_REQUEST_SLOTS];
    nv_p2p_umem_xfer_t xfers[NV_XDEV_EXT_CE_MAX_XFERS];
    unsigned int backoff;
};

static enum hrtimer_restart nv_xdev_ext_ce_poll_timer(struct hrtimer *timer)
{
    struct nv_xdev_ext_ce_host *h = container_of(timer, struct nv_xdev_ext_ce_host, timer);
    queue_work(system_unbound_wq, &h->progress);
    return HRTIMER_NORESTART;
}

/* Native async submission, bounded kernel polling completion, no user continuation. */
static void nv_xdev_ext_ce_progress(struct work_struct *work)
{
    struct nv_xdev_ext_ce_host *h = container_of(work, struct nv_xdev_ext_ce_host, progress);
    NvU64 watermark = 0;
    NV_STATUS status = NV_OK;
    unsigned int i, count = 0, pending = 0;
    bool failed = false;

    mutex_lock(&h->lock);
    for (i = 0; i < NV_XDEV_EXT_CE_REQUEST_SLOTS; i++)
        if (h->slots[i].state == NV_XDEV_EXT_CE_ASYNC_PENDING) {
            pending++;
            if (time_after_eq(jiffies, h->deadlines[i])) failed = true;
        }
    if (pending && !h->pool.quarantined && !failed) {
        down_read(&nv_system_pm_lock);
        status = nv_p2p_ce_progress(h->rm, &watermark);
        up_read(&nv_system_pm_lock);
        failed = status != NV_OK;
    }
    if (failed) {
        h->pool.quarantined = h->pool.stopping = 1;
        WRITE_ONCE(h->region->ambiguous, NV_TRUE);
    }
    pending = 0;
    for (i = 0; i < NV_XDEV_EXT_CE_REQUEST_SLOTS; i++) {
        struct nv_xdev_ext_ce_async_slot *slot = &h->slots[i];
        if (slot->state != NV_XDEV_EXT_CE_ASYNC_PENDING) continue;
        if (h->pool.quarantined) {
            struct nv_xdev_ext_ce_async_completion *c = &h->completions[count++];
            c->ticket = slot->ticket; c->token = slot->token;
            c->cookie = slot->cookie; c->bytes = 0;
            slot->state = NV_XDEV_EXT_CE_ASYNC_QUARANTINED;
        } else if (nv_xdev_ext_ce_async_ready(&h->pool, slot, watermark,
                                         &h->completions[count])) {
            count++;
        } else pending++;
    }
    if (pending) {
        h->backoff = count ? nv_xdev_ext_ce_poll_base() : min(h->backoff * 2, 100U);
        /* Microsecond timer avoids adding a scheduler tick to every stage.
         * Each poll still pays a worker wakeup and one RM API lock acquisition.
         */
        hrtimer_start(&h->timer, ns_to_ktime((u64)h->backoff * NSEC_PER_USEC),
                      HRTIMER_MODE_REL);
    }
    failed = h->pool.quarantined;
    mutex_unlock(&h->lock);
    /* Close cancels synchronously before freeing h, including these callbacks. */
    for (i = 0; i < count; i++) {
        struct nv_xdev_ext_ce_async_completion *c = &h->completions[i];
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
                                &seg_size);
    if (status != NV_OK)
    {
        rc = nv_p2p_umem_errno(status);
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
    if (rc != 0)
        kfree(region);
    return rc;
}

/* Process context, after drain; never after an AMBIGUOUS outcome. */
static void nv_xdev_ext_ce_unbind_region(struct xdev_ext_ce_region *r)
{
    struct nv_xdev_ext_ce_region *region = r->priv;

    /* The device may still use the window: keep it bound for good. */
    if (WARN_ON_ONCE(READ_ONCE(region->ambiguous)))
        return;

    down_read(&nv_system_pm_lock);
    nv_p2p_vidmem_unbind(region->vidmem);
    up_read(&nv_system_pm_lock);
    kfree(region);
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

    if (!nv_p2p_umem_iommu_untranslated(region->dev)) return -EOPNOTSUPP;
    if (!nr) return -EINVAL;
    h = kvzalloc(sizeof(*h), GFP_KERNEL);
    if (!h) return -ENOMEM;
    phys = kvmalloc_array(nr, sizeof(*phys), GFP_KERNEL);
    if (!phys) { kvfree(h); return -ENOMEM; }
    for (i = 0; i < nr; i++) phys[i] = page_to_phys(pages[i]);
    h->region = region; h->bytes = (NvU64)nr << PAGE_SHIFT;
    mutex_init(&h->lock);
    INIT_WORK(&h->progress, nv_xdev_ext_ce_progress);
    hrtimer_setup(&h->timer, nv_xdev_ext_ce_poll_timer,
                  CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    nv_xdev_ext_ce_async_init(&h->pool, h->slots, NV_XDEV_EXT_CE_REQUEST_SLOTS);
    h->backoff = nv_xdev_ext_ce_poll_base();
    down_read(&nv_system_pm_lock);
    status = nv_p2p_ce_host_bind(region->vidmem, phys, nr, PAGE_SIZE,
                                h->bytes, &h->rm);
    up_read(&nv_system_pm_lock);
    kvfree(phys);
    if (status != NV_OK) { kvfree(h); return nv_p2p_umem_errno(status); }
    *host = h;
    return 0;
}

static void nv_xdev_ext_ce_unbind_host(void *host)
{
    struct nv_xdev_ext_ce_host *h = host;
    NV_STATUS status;
    mutex_lock(&h->lock);
    nv_xdev_ext_ce_async_stop(&h->pool);
    /* The CE class drains accepted work before unbind. Never cancel live DMA. */
    if (WARN_ON_ONCE(!nv_xdev_ext_ce_async_can_release(&h->pool))) {
        WRITE_ONCE(h->region->ambiguous, NV_TRUE);
        mutex_unlock(&h->lock);
        return;
    }
    mutex_unlock(&h->lock);
    hrtimer_cancel(&h->timer);
    cancel_work_sync(&h->progress);
    down_read(&nv_system_pm_lock);
    status = nv_p2p_ce_host_unbind(h->rm);
    up_read(&nv_system_pm_lock);
    if (status != NV_OK) {
        WRITE_ONCE(h->region->ambiguous, NV_TRUE);
        return;
    }
    kvfree(h);
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
    rc = nv_xdev_ext_ce_async_reserve(&h->pool, ticket, ck, bytes, &slot);
    if (rc) goto unlock;
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
    status = nv_p2p_ce_async_submit(h->rm, h->xfers, n, rm_dir, &issued, &token);
    up_read(&nv_system_pm_lock);
    outcome = nv_xdev_ext_ce_async_submitted(&h->pool, slot, status, issued, token);
    if (outcome == NV_XDEV_EXT_CE_OK) {
        h->deadlines[slot - h->slots] = jiffies + NV_XDEV_EXT_CE_TIMEOUT;
        h->backoff = nv_xdev_ext_ce_poll_base();
        queue_work(system_unbound_wq, &h->progress);
        rc = 0;
    } else if (outcome == NV_XDEV_EXT_CE_AMBIGUOUS) {
        WRITE_ONCE(h->region->ambiguous, NV_TRUE);
        /* The failed slot completes here; progress retires other accepted work. */
        queue_work(system_unbound_wq, &h->progress);
        mutex_unlock(&h->lock);
        xdev_ext_ce_complete(ck, ticket, status ? nv_p2p_umem_errno(status) : -EIO,
                        NV_TRUE, 0);
        return 0;
    } else rc = nv_p2p_umem_errno(status);
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
