// SPDX-License-Identifier: GPL-2.0
/* Persistent device memory, distinct from the host struct-page UMEM pool.
 * All control operations are process context and may sleep. The native driver
 * must defer end_io release to a worker. Provider mappings remain resident
 * throughout native request ownership; uncertain DMA retains every reference
 * until the requester's driver proves a later DMA-stop epoch, if ever.
 */
#ifndef XDEV_EXT_PEER_HOST_TEST
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/xdev_ext_peer.h>
#else
#include "../include/linux/xdev_ext_peer.h"
#endif
struct xdev_ext_peer_provider {
 struct list_head node;
 const struct xdev_ext_peer_provider_ops *ops;
 u32 allocations;
};
struct xdev_ext_peer_region {
 struct mutex lock;
 struct list_head maps;
 struct xdev_ext_peer_provider *provider;
 const struct xdev_ext_peer_provider_ops *ops;
 struct file *file;
 void *allocation;
 u64 len, generation;
 bool invalid, quarantined;
 /* Quarantine causes. permanent: provider failure or UNKNOWN without
  * evidence binding. pending: mappings with an uncovered requester record.
  * queued/qnode: on the recovery list (quarantine lock). orphaned: the owner
  * released it; the core tears it down when no cause remains. */
 bool permanent, queued, orphaned;
 u32 pending;
 struct list_head qnode;
};
struct xdev_ext_peer_mapping {
 struct list_head node;
 struct xdev_ext_peer_region *region;
 struct pci_dev *peer;
 struct xdev_ext_peer_dma dma;
 enum dma_data_direction direction;
 u32 users, active;
 struct xdev_ext_peer_lease *leases;
 /* Uncovered UNKNOWN record: requester instance and highest epoch. */
 struct xdev_ext_peer_requester *unknown;
 u64 unknown_epoch;
};
struct xdev_ext_peer_requester {
 struct mutex lock; /* proven */
 struct pci_dev *pdev;
 atomic64_t started;
 u64 proven;
 u32 refs; /* driver and mapping records; quarantine lock */
};
static DEFINE_MUTEX(xdev_ext_peer_registry_lock);
static LIST_HEAD(xdev_ext_peer_providers);
static atomic64_t xdev_ext_peer_serial = ATOMIC64_INIT(0);
int xdev_ext_peer_provider_register(const struct xdev_ext_peer_provider_ops *ops)
{
 struct xdev_ext_peer_provider *p, *new;
 if (!ops || !ops->fops || !ops->pin || !ops->unpin || !ops->map || !ops->unmap)
  return -EINVAL;
 new = kzalloc(sizeof(*new), GFP_KERNEL);
 if (!new) return -ENOMEM;
 new->ops = ops;
 mutex_lock(&xdev_ext_peer_registry_lock);
 list_for_each_entry(p, &xdev_ext_peer_providers, node)
  if (p->ops->fops == ops->fops) {
   mutex_unlock(&xdev_ext_peer_registry_lock); kfree(new); return -EEXIST;
  }
 list_add_tail(&new->node, &xdev_ext_peer_providers);
 mutex_unlock(&xdev_ext_peer_registry_lock);
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_provider_register);
int xdev_ext_peer_provider_unregister(const struct xdev_ext_peer_provider_ops *ops)
{
 struct xdev_ext_peer_provider *p;
 int ret = -ENOENT;
 mutex_lock(&xdev_ext_peer_registry_lock);
 list_for_each_entry(p, &xdev_ext_peer_providers, node)
  if (p->ops == ops) {
   if (p->allocations) { ret = -EBUSY; break; }
   list_del(&p->node); kfree(p); ret = 0; break;
  }
 mutex_unlock(&xdev_ext_peer_registry_lock);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_provider_unregister);
static void xdev_ext_peer_region_init(struct xdev_ext_peer_region *r,
                                     const struct xdev_ext_peer_provider_ops *ops,
                                     struct file *file, u64 len)
{
 mutex_init(&r->lock); INIT_LIST_HEAD(&r->maps);
 r->ops = ops;
 get_file(file); r->file = file; r->len = len;
 r->generation = atomic64_inc_return(&xdev_ext_peer_serial);
 if (!r->generation) r->generation = atomic64_inc_return(&xdev_ext_peer_serial);
}
int xdev_ext_peer_region_create(const struct xdev_ext_peer_provider_ops *ops,
                               struct file *file, void *allocation, u64 len,
                               struct xdev_ext_peer_region **out)
{
 struct xdev_ext_peer_region *r;
 if (!out) return -EINVAL;
 *out = NULL;
 if (!ops || !ops->map || !ops->unmap || !ops->unpin ||
     !file || !allocation || !len) return -EINVAL;
 r = kzalloc(sizeof(*r), GFP_KERNEL);
 if (!r) return -ENOMEM;
 if (!try_module_get(ops->owner)) { kfree(r); return -ENODEV; }
 xdev_ext_peer_region_init(r, ops, file, len);
 r->allocation = allocation;
 *out = r;
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_region_create);
/* Caller holds r->lock. Stale never permits another borrower; draining an
 * existing lease is deliberately independent of this check. */
static bool xdev_ext_peer_stale(struct xdev_ext_peer_region *r)
{
 return r->invalid || r->quarantined ||
        (r->ops->is_stale && r->ops->is_stale(r->allocation));
}
int xdev_ext_peer_pin(struct file *file, u64 va, u64 len, struct xdev_ext_peer_region **out)
{
 struct xdev_ext_peer_region *r;
 struct xdev_ext_peer_provider *p;
 int ret = -ENODEV;
 if (!file || !out || !len || va + len < va) return -EINVAL;
 *out = NULL;
 r = kzalloc(sizeof(*r), GFP_KERNEL);
 if (!r) return -ENOMEM;
 mutex_lock(&xdev_ext_peer_registry_lock);
 list_for_each_entry(p, &xdev_ext_peer_providers, node)
  if (p->ops->fops == file->f_op) {
   if (!try_module_get(p->ops->owner)) { ret = -ENODEV; break; }
   if (p->allocations == U32_MAX) {
    module_put(p->ops->owner); ret = -EOVERFLOW; break;
   }
   p->allocations++; r->provider = p; r->ops = p->ops; ret = 0; break;
  }
 mutex_unlock(&xdev_ext_peer_registry_lock);
 if (ret) { kfree(r); return ret; }
 p = r->provider;
 ret = p->ops->pin(file, va, len, &r->allocation);
 if (ret) {
  mutex_lock(&xdev_ext_peer_registry_lock); p->allocations--;
  mutex_unlock(&xdev_ext_peer_registry_lock);
  module_put(r->ops->owner); kfree(r); return ret;
 }
 xdev_ext_peer_region_init(r, p->ops, file, len);
 *out = r;
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_pin);
u64 xdev_ext_peer_generation(struct xdev_ext_peer_region *r)
{ return r ? r->generation : 0; }
EXPORT_SYMBOL_GPL(xdev_ext_peer_generation);
int xdev_ext_peer_drainable(struct xdev_ext_peer_region *r)
{
 struct xdev_ext_peer_mapping *m;
 int ret = 0;
 if (!r) return -EINVAL;
 mutex_lock(&r->lock);
 if (r->quarantined) ret = -EIO;
 if (!ret)
  list_for_each_entry(m, &r->maps, node)
   if (m->active) { ret = -EBUSY; break; }
 mutex_unlock(&r->lock);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_drainable);
int xdev_ext_peer_info(struct xdev_ext_peer_region *r, u64 *len, u64 *generation, bool idle)
{
 struct xdev_ext_peer_mapping *m;
 int ret = 0;
 if (!r || !len || !generation) return -EINVAL;
 mutex_lock(&r->lock);
 if (xdev_ext_peer_stale(r)) ret = -ESTALE;
 if (!ret && idle)
  list_for_each_entry(m, &r->maps, node)
   if (m->active) { ret = -EBUSY; break; }
 if (!ret) { *len = r->len; *generation = r->generation; }
 mutex_unlock(&r->lock);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_info);
int xdev_ext_peer_describe(struct xdev_ext_peer_region *r, struct pci_dev *requester,
                          struct xdev_ext_peer_backing *out)
{
 int ret;

 if (!r || !requester || !out)
  return -EINVAL;
 *out = (struct xdev_ext_peer_backing){};
 mutex_lock(&r->lock);
 if (xdev_ext_peer_stale(r))
  ret = -ESTALE;
 else if (!r->ops->describe)
  ret = -EOPNOTSUPP;
 else
  ret = r->ops->describe(r->allocation, requester, out);
 mutex_unlock(&r->lock);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_describe);
static bool xdev_ext_peer_direction_valid(enum dma_data_direction dir)
{ return dir == DMA_BIDIRECTIONAL || dir == DMA_TO_DEVICE || dir == DMA_FROM_DEVICE; }
int xdev_ext_peer_map(struct xdev_ext_peer_region *r, struct pci_dev *peer,
                     enum dma_data_direction dir, struct xdev_ext_peer_mapping **out)
{
 struct xdev_ext_peer_mapping *m;
 int ret = 0;
 if (!r || !peer || !out || !xdev_ext_peer_direction_valid(dir)) return -EINVAL;
 *out = NULL;
 mutex_lock(&r->lock);
 if (xdev_ext_peer_stale(r)) { ret = -ESTALE; goto done; }
 list_for_each_entry(m, &r->maps, node)
  if (m->peer == peer) {
   if (m->direction != dir && m->direction != DMA_BIDIRECTIONAL) { ret = -EACCES; goto done; }
   if (m->users == U32_MAX) { ret = -EOVERFLOW; goto done; }
   m->users++; *out = m; goto done;
  }
 m = kzalloc(sizeof(*m), GFP_KERNEL);
 if (!m) { ret = -ENOMEM; goto done; }
 m->region = r; m->peer = pci_dev_get(peer); m->direction = dir;
 ret = r->ops->map(r->allocation, peer, &m->dma);
 if (ret) goto free;
 if (xdev_ext_peer_stale(r)) { ret = -ESTALE; goto rollback; }
 if (!m->dma.addresses || !m->dma.entries || m->dma.page_shift < 12 ||
     m->dma.page_shift > 31 || (u64)m->dma.entries << m->dma.page_shift < r->len) {
  ret = -EPROTO;
rollback:
  /* Even malformed provider geometry cannot bypass native cleanup failure. */
  if (r->ops->unmap(r->allocation, peer, &m->dma)) {
   r->invalid = r->quarantined = r->permanent = true; m->users = 1;
   list_add_tail(&m->node, &r->maps); goto done;
  }
  goto free;
 }
 m->users = 1; list_add_tail(&m->node, &r->maps); *out = m;
 goto done;
free:
 pci_dev_put(m->peer); kfree(m);
done:
 mutex_unlock(&r->lock); return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_map);
int xdev_ext_peer_acquire(struct xdev_ext_peer_mapping *m, u64 generation,
                         u64 offset, u32 len, enum dma_data_direction dir,
                         struct xdev_ext_peer_lease *lease)
{
 struct xdev_ext_peer_region *r;
 u64 page_size, address;
 int ret = 0;
 if (!m || !lease || !xdev_ext_peer_direction_valid(dir) || dir == DMA_BIDIRECTIONAL)
  return -EINVAL;
 r = m->region; mutex_lock(&r->lock);
 if (lease->mapping) { ret = -EBUSY; goto done; }
 if (xdev_ext_peer_stale(r) || generation != r->generation) { ret = -ESTALE; goto done; }
 if (m->direction != DMA_BIDIRECTIONAL && m->direction != dir) { ret = -EACCES; goto done; }
 page_size = 1ULL << m->dma.page_shift;
 if (!len || offset >= r->len || len > r->len - offset ||
     len > page_size - (offset & (page_size - 1))) { ret = -ERANGE; goto done; }
 address = m->dma.addresses[offset >> m->dma.page_shift];
 if (address + (offset & (page_size - 1)) < address ||
     address + (offset & (page_size - 1)) + len - 1 < address) { ret = -EOVERFLOW; goto done; }
 if (m->active == U32_MAX) { ret = -EOVERFLOW; goto done; }
 /* Last, so only an otherwise valid lease is refused, and only for now. */
 if (r->ops->may_access) {
  ret = r->ops->may_access(r->allocation, dir);
  if (ret) goto done;
 }
 lease->dma_address = address + (offset & (page_size - 1));
 lease->len = len; lease->mapping = m;
 lease->ticket = atomic64_inc_return(&xdev_ext_peer_serial);
 if (!lease->ticket) lease->ticket = atomic64_inc_return(&xdev_ext_peer_serial);
 lease->next = m->leases; m->leases = lease; m->active++;
done:
 mutex_unlock(&r->lock); return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_acquire);
int xdev_ext_peer_release(struct xdev_ext_peer_lease *lease, u64 ticket, bool quiesced)
{
 struct xdev_ext_peer_mapping *m;
 struct xdev_ext_peer_region *r;
 struct xdev_ext_peer_lease **cursor;
 if (!lease || !lease->mapping) return -EINVAL;
 m = lease->mapping; r = m->region; mutex_lock(&r->lock);
 for (cursor = &m->leases; *cursor && *cursor != lease; cursor = &(*cursor)->next) { }
 if (!*cursor || ticket != lease->ticket) { mutex_unlock(&r->lock); return -ESTALE; }
 *cursor = lease->next; lease->next = NULL;
 if (!quiesced) r->invalid = r->quarantined = true;
 if (!quiesced) r->permanent = true; /* no evidence binding */
 m->active--; lease->mapping = NULL; lease->dma_address = 0; lease->len = 0;
 mutex_unlock(&r->lock); return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_release);
void xdev_ext_peer_invalidate(struct xdev_ext_peer_region *r)
{
 if (!r) return;
 mutex_lock(&r->lock); r->invalid = true; mutex_unlock(&r->lock);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_invalidate);
int xdev_ext_peer_unmap(struct xdev_ext_peer_mapping *m)
{
 struct xdev_ext_peer_region *r;
 int ret = 0;
 if (!m) return -EINVAL;
 r = m->region; mutex_lock(&r->lock);
 if (r->quarantined) { ret = -EIO; goto done; }
 if (m->active) { ret = -EBUSY; goto done; }
 if (m->users > 1) { m->users--; goto done; }
 ret = r->ops->unmap(r->allocation, m->peer, &m->dma);
 if (ret) { r->invalid = r->quarantined = r->permanent = true; goto done; }
 list_del(&m->node); pci_dev_put(m->peer); kfree(m);
done:
 mutex_unlock(&r->lock); return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_unmap);
int xdev_ext_peer_unpin(struct xdev_ext_peer_region *r)
{
 struct xdev_ext_peer_provider *p;
 struct module *owner;
 int ret;
 if (!r) return -EINVAL;
 mutex_lock(&r->lock);
 if (r->quarantined) { ret = -EIO; goto done; }
 if (!list_empty(&r->maps)) { ret = -EBUSY; goto done; }
 r->invalid = true; p = r->provider; owner = r->ops->owner;
 ret = r->ops->unpin(r->allocation);
 if (ret) { r->quarantined = r->permanent = true; goto done; }
 mutex_unlock(&r->lock);
 if (p) {
  mutex_lock(&xdev_ext_peer_registry_lock); p->allocations--;
  mutex_unlock(&xdev_ext_peer_registry_lock);
 }
 fput(r->file); module_put(owner); kfree(r); return 0;
done:
 mutex_unlock(&r->lock); return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_unpin);

/*
 * Recovery after UNKNOWN native DMA.  An UNKNOWN lease bound to the requester
 * instance that received it, and to the epoch it received it in, leaves a
 * record in its mapping.  The record is covered once that requester proves a
 * later epoch: the epoch began after the command became visible to the
 * device, so the proven stop includes it.  A region with no uncovered record
 * and no permanent cause leaves quarantine; it stays invalid.
 * Lock order: xdev_ext_peer_quarantine_lock, region lock, requester lock.
 */
static DEFINE_MUTEX(xdev_ext_peer_quarantine_lock);
static LIST_HEAD(xdev_ext_peer_quarantined);
/* Called after each recovery pass, no other peer lock held. */
static DEFINE_MUTEX(xdev_ext_peer_watch_lock);
static LIST_HEAD(xdev_ext_peer_watchers);
static void xdev_ext_peer_recovery_work(struct work_struct *work);
static DECLARE_WORK(xdev_ext_peer_recovery, xdev_ext_peer_recovery_work);
struct xdev_ext_peer_requester *xdev_ext_peer_requester_register(struct pci_dev *pdev)
{
 struct xdev_ext_peer_requester *rq;
 if (!pdev) return NULL;
 rq = kzalloc(sizeof(*rq), GFP_KERNEL);
 if (!rq) return NULL;
 mutex_init(&rq->lock);
 rq->pdev = pci_dev_get(pdev);
 rq->refs = 1;
 return rq;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_requester_register);
/* Caller holds xdev_ext_peer_quarantine_lock. */
static void xdev_ext_peer_requester_put_locked(struct xdev_ext_peer_requester *rq)
{
 if (--rq->refs) return;
 pci_dev_put(rq->pdev);
 kfree(rq);
}
/* The driver instance is gone: no further epoch begins or is proven. */
void xdev_ext_peer_requester_unregister(struct xdev_ext_peer_requester *rq)
{
 if (!rq) return;
 mutex_lock(&xdev_ext_peer_quarantine_lock);
 xdev_ext_peer_requester_put_locked(rq);
 mutex_unlock(&xdev_ext_peer_quarantine_lock);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_requester_unregister);
u64 xdev_ext_peer_requester_begin(struct xdev_ext_peer_requester *rq)
{
 return rq ? (u64)atomic64_inc_return(&rq->started) : 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_requester_begin);
u64 xdev_ext_peer_requester_epoch(struct xdev_ext_peer_requester *rq)
{
 return rq ? (u64)atomic64_read(&rq->started) : XDEV_EXT_PEER_EPOCH_NONE;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_requester_epoch);
/* Takes no core lock beyond the requester's own: callable from a driver's
 * reset path. Recovery itself runs later in process context. */
void xdev_ext_peer_requester_quiesced(struct xdev_ext_peer_requester *rq, u64 epoch)
{
 bool advanced = false;
 if (!rq || !epoch || epoch > (u64)atomic64_read(&rq->started)) return;
 mutex_lock(&rq->lock);
 if (epoch > rq->proven) { rq->proven = epoch; advanced = true; }
 mutex_unlock(&rq->lock);
 if (advanced) schedule_work(&xdev_ext_peer_recovery);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_requester_quiesced);
static bool xdev_ext_peer_requester_covers(struct xdev_ext_peer_requester *rq, u64 epoch)
{
 bool covers;
 mutex_lock(&rq->lock); covers = rq->proven > epoch; mutex_unlock(&rq->lock);
 return covers;
}
/* Process context: what @rq can prove about a command it received in @epoch. */
int xdev_ext_peer_requester_evidence(struct xdev_ext_peer_requester *rq, u64 epoch)
{
 if (!rq || epoch == XDEV_EXT_PEER_EPOCH_NONE) return XDEV_EXT_PEER_EVIDENCE_NEVER;
 return xdev_ext_peer_requester_covers(rq, epoch) ? XDEV_EXT_PEER_EVIDENCE_COVERED :
        XDEV_EXT_PEER_EVIDENCE_PENDING;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_requester_evidence);
void xdev_ext_peer_recovery_watch(struct xdev_ext_peer_recovery_watch *w)
{
 mutex_lock(&xdev_ext_peer_watch_lock);
 list_add_tail(&w->node, &xdev_ext_peer_watchers);
 mutex_unlock(&xdev_ext_peer_watch_lock);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_recovery_watch);
void xdev_ext_peer_recovery_unwatch(struct xdev_ext_peer_recovery_watch *w)
{
 mutex_lock(&xdev_ext_peer_watch_lock);
 list_del(&w->node);
 mutex_unlock(&xdev_ext_peer_watch_lock);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_recovery_unwatch);
int xdev_ext_peer_release_unknown(struct xdev_ext_peer_lease *lease, u64 ticket,
                                  struct xdev_ext_peer_requester *rq, u64 epoch, bool *quiesced)
{
 struct xdev_ext_peer_mapping *m;
 struct xdev_ext_peer_region *r;
 struct xdev_ext_peer_lease **cursor;
 bool bound, covered = false;
 if (quiesced) *quiesced = false;
 if (!lease || !lease->mapping) return -EINVAL;
 m = lease->mapping; r = m->region;
 mutex_lock(&xdev_ext_peer_quarantine_lock); mutex_lock(&r->lock);
 for (cursor = &m->leases; *cursor && *cursor != lease; cursor = &(*cursor)->next) { }
 if (!*cursor || ticket != lease->ticket) {
  mutex_unlock(&r->lock); mutex_unlock(&xdev_ext_peer_quarantine_lock);
  return -ESTALE;
 }
 *cursor = lease->next; lease->next = NULL;
 m->active--; lease->mapping = NULL; lease->dma_address = 0; lease->len = 0;
 bound = rq && rq->pdev == m->peer && epoch != XDEV_EXT_PEER_EPOCH_NONE &&
         (!m->unknown || m->unknown == rq);
 /* Read under the quarantine lock: a proof stored after this read is
  * followed by recovery work that finds this region queued below. */
 if (bound && xdev_ext_peer_requester_covers(rq, epoch)) {
  covered = true;
 } else {
  r->invalid = r->quarantined = true;
  if (!bound) {
   r->permanent = true;
  } else {
   if (!m->unknown) {
    m->unknown = rq; rq->refs++; m->unknown_epoch = epoch; r->pending++;
   } else if (epoch > m->unknown_epoch) {
    m->unknown_epoch = epoch;
   }
   if (!r->queued) {
    list_add_tail(&r->qnode, &xdev_ext_peer_quarantined); r->queued = true;
   }
  }
 }
 mutex_unlock(&r->lock); mutex_unlock(&xdev_ext_peer_quarantine_lock);
 if (quiesced) *quiesced = covered;
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_release_unknown);
/* Process context, no lock held: no owner and no UNKNOWN DMA remain. A
 * provider failure on the way keeps everything not yet released for good. */
static void xdev_ext_peer_region_retire(struct xdev_ext_peer_region *r)
{
 struct xdev_ext_peer_mapping *m;
 for (;;) {
  mutex_lock(&r->lock);
  if (list_empty(&r->maps)) { mutex_unlock(&r->lock); break; }
  m = container_of(r->maps.next, struct xdev_ext_peer_mapping, node);
  mutex_unlock(&r->lock);
  /* Each call drops one borrower of the gone owner's cache. */
  if (xdev_ext_peer_unmap(m)) return;
 }
 xdev_ext_peer_unpin(r);
}
static void xdev_ext_peer_recovery_work(struct work_struct *work)
{
 LIST_HEAD(keep);
 LIST_HEAD(retire);
 struct xdev_ext_peer_recovery_watch *w;
 struct xdev_ext_peer_region *r;
 struct xdev_ext_peer_mapping *m;
 (void)work;
 mutex_lock(&xdev_ext_peer_quarantine_lock);
 while (!list_empty(&xdev_ext_peer_quarantined)) {
  r = container_of(xdev_ext_peer_quarantined.next, struct xdev_ext_peer_region, qnode);
  list_del(&r->qnode);
  mutex_lock(&r->lock);
  list_for_each_entry(m, &r->maps, node)
   if (m->unknown && xdev_ext_peer_requester_covers(m->unknown, m->unknown_epoch)) {
    xdev_ext_peer_requester_put_locked(m->unknown);
    m->unknown = NULL; r->pending--;
   }
  if (r->pending) {
   list_add_tail(&r->qnode, &keep);
  } else {
   r->queued = false;
   if (!r->permanent) {
    r->quarantined = false;
    if (r->orphaned) list_add_tail(&r->qnode, &retire);
   }
  }
  mutex_unlock(&r->lock);
 }
 while (!list_empty(&keep)) {
  r = container_of(keep.next, struct xdev_ext_peer_region, qnode);
  list_del(&r->qnode); list_add_tail(&r->qnode, &xdev_ext_peer_quarantined);
 }
 mutex_unlock(&xdev_ext_peer_quarantine_lock);
 while (!list_empty(&retire)) {
  r = container_of(retire.next, struct xdev_ext_peer_region, qnode);
  list_del(&r->qnode);
  xdev_ext_peer_region_retire(r);
 }
 /* Holders of other evidence-bound state re-check after this pass. */
 mutex_lock(&xdev_ext_peer_watch_lock);
 list_for_each_entry(w, &xdev_ext_peer_watchers, node)
  w->recovered(w);
 mutex_unlock(&xdev_ext_peer_watch_lock);
}
void xdev_ext_peer_orphan(struct xdev_ext_peer_region *r)
{
 bool retire;
 if (!r) return;
 mutex_lock(&r->lock);
 r->orphaned = true;
 retire = !r->quarantined;
 mutex_unlock(&r->lock);
 if (retire) xdev_ext_peer_region_retire(r);
}
