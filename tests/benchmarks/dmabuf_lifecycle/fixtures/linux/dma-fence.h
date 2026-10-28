/* SPDX-License-Identifier: GPL-2.0 */
/* HOST CONTRACT SHIM ONLY. Not Linux runtime, DMA, concurrency, or timing evidence.
 * This checks calls made by the actual lifecycle_core.h. It is not a second
 * lifecycle implementation. The real module must use Linux's original header.
 */
#ifndef XB_CONTRACT_DMA_FENCE_H
#define XB_CONTRACT_DMA_FENCE_H
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>

typedef __u64 u64;
typedef __u32 u32;
typedef int spinlock_t;
#define spin_lock_init(p) (*(p) = 0)
#define spin_lock(p) ((void)(p))
#define spin_unlock(p) ((void)(p))
#define spin_lock_irqsave(p, flags) do { (void)(p); (flags) = 0; } while (0)
#define spin_unlock_irqrestore(p, flags) do { (void)(p); (void)(flags); } while (0)
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define READ_ONCE(v) (v)
#define WRITE_ONCE(v, n) ((v) = (n))

struct dma_fence;
struct dma_fence_cb {
    struct dma_fence_cb *next;
    void (*func)(struct dma_fence *, struct dma_fence_cb *);
    bool linked;
};
struct dma_fence_ops {
    const char *(*get_driver_name)(struct dma_fence *);
    const char *(*get_timeline_name)(struct dma_fence *);
    bool (*enable_signaling)(struct dma_fence *);
    bool (*signaled)(struct dma_fence *);
    void (*release)(struct dma_fence *);
};
struct dma_fence {
    const struct dma_fence_ops *ops;
    spinlock_t *lock;
    struct dma_fence_cb *callbacks;
    u64 context, seqno;
    int refs;
    bool signaled;
};

/* An address ledger catches reinit even if the tested code first memsets the
 * embedded fence, which would otherwise erase the shim's live-ref evidence. */
struct xb_shim_live { struct dma_fence *address; unsigned refs; };
static struct xb_shim_live xb_shim_ledger[128];
static unsigned xb_shim_add_calls, xb_shim_fail_add_at, xb_shim_callbacks;
static unsigned xb_shim_inits, xb_shim_releases, xb_shim_signal_calls;

static struct xb_shim_live *xb_shim_entry(struct dma_fence *f)
{
    unsigned i;
    for (i = 0; i < 128; ++i)
        if (xb_shim_ledger[i].address == f) return &xb_shim_ledger[i];
    for (i = 0; i < 128; ++i)
        if (!xb_shim_ledger[i].address) {
            xb_shim_ledger[i].address = f;
            return &xb_shim_ledger[i];
        }
    abort();
}

static inline u64 dma_fence_context_alloc(unsigned count)
{
    static u64 next = 1;
    u64 result = next;
    next += count;
    return result;
}

static inline void dma_fence_init(struct dma_fence *f,
                                 const struct dma_fence_ops *ops,
                                 spinlock_t *lock, u64 context, u64 seqno)
{
    struct xb_shim_live *entry = xb_shim_entry(f);
    assert(entry->refs == 0 && "reinitialized fence with outstanding references");
    assert(ops && ops->release && "embedded fence needs custom release");
    entry->refs = 1;
    *f = (struct dma_fence){.ops = ops, .lock = lock, .context = context,
                           .seqno = seqno, .refs = 1};
    ++xb_shim_inits;
}

static inline struct dma_fence *dma_fence_get(struct dma_fence *f)
{
    if (f) {
        assert(f->refs > 0);
        ++f->refs;
        ++xb_shim_entry(f)->refs;
    }
    return f;
}

static inline void dma_fence_put(struct dma_fence *f)
{
    if (!f) return;
    assert(f->refs > 0 && "double put or stale fence reference");
    assert(xb_shim_entry(f)->refs == (unsigned)f->refs);
    --xb_shim_entry(f)->refs;
    if (--f->refs == 0) {
        assert(!f->callbacks && "last reference released with callback still registered");
        ++xb_shim_releases;
        f->ops->release(f);
    }
}

static inline int dma_fence_add_callback(struct dma_fence *f, struct dma_fence_cb *cb,
                                        void (*func)(struct dma_fence *, struct dma_fence_cb *))
{
    assert(f->refs > 0);
    ++xb_shim_add_calls;
    if (xb_shim_add_calls == xb_shim_fail_add_at) return -ENOMEM;
    if (f->signaled) return -ENOENT;
    assert(!cb->linked && "callback registered twice");
    cb->func = func;
    cb->linked = true;
    cb->next = f->callbacks;
    f->callbacks = cb;
    return 0;
}

static inline bool dma_fence_remove_callback(struct dma_fence *f, struct dma_fence_cb *cb)
{
    struct dma_fence_cb **cursor = &f->callbacks;
    while (*cursor) {
        if (*cursor == cb) {
            *cursor = cb->next;
            cb->linked = false;
            cb->next = NULL;
            return true;
        }
        cursor = &(*cursor)->next;
    }
    return false;
}

static inline int dma_fence_signal(struct dma_fence *f)
{
    assert(f->refs > 0);
    ++xb_shim_signal_calls;
    if (f->signaled) return -EINVAL;
    f->signaled = true;
    while (f->callbacks) {
        struct dma_fence_cb *cb = f->callbacks;
        f->callbacks = cb->next;
        cb->linked = false;
        cb->next = NULL;
        ++xb_shim_callbacks;
        cb->func(f, cb);
    }
    return 0;
}

static inline int dma_fence_signal_locked(struct dma_fence *f) { return dma_fence_signal(f); }
static inline bool dma_fence_is_signaled(struct dma_fence *f) { return f->signaled; }
static inline bool dma_fence_is_signaled_locked(struct dma_fence *f) { return f->signaled; }
static inline int dma_fence_get_status(struct dma_fence *f) { return f->signaled ? 1 : 0; }
#endif
