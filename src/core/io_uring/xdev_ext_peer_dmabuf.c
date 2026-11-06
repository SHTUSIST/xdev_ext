// SPDX-License-Identifier: GPL-2.0
/* Persistent, whole-export DMA-BUF authority. No frame pool export, and no
 * fence is ever added for xdev_ext device access: native DMA can end UNKNOWN,
 * which would leave such a fence unsignaled forever, and a session may run
 * indefinitely. The application orders later consumers after completion.
 * Unknown native DMA retains the entire ledger in peer core.
 * With IMPORT_UNDESCRIBED, an exporter that registered no descriptor imports
 * with no backing facts (descriptor == NULL); each requester then uses only
 * the exporter's own mapping for that device, and a lease that a pending
 * implicit-sync fence orders is refused (xdev_ext_dmabuf_may_access). A
 * described exporter keeps the contract in which the application also orders
 * implicit-sync producers before the device access.
 */
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/dma-buf.h>
#include <linux/dma-map-ops.h>
#include <linux/dma-mapping.h>
#include <linux/dma-resv.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/resource.h>
#include <linux/scatterlist.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/user.h>
#include <linux/slab.h>
#include <linux/swiotlb.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_peer_dmabuf.h>
#include <uapi/linux/xdev_ext_mech.h>

#define XDEV_EXT_DMABUF_MAX_REQUESTERS 64U
#define XDEV_EXT_DMABUF_PAGE_SHIFT 12U
#define XDEV_EXT_DMABUF_PAGE_SIZE (1ULL << XDEV_EXT_DMABUF_PAGE_SHIFT)

struct xdev_ext_dmabuf_descriptor {
 struct list_head node;
 const struct xdev_ext_peer_dmabuf_desc_ops *ops;
 u32 live;
};
struct xdev_ext_dmabuf_allocation {
 struct list_head identity;
 struct dma_buf *buf;
 struct xdev_ext_dmabuf_descriptor *descriptor; /* NULL: undescribed */
 struct user_struct *user;
 struct mm_struct *mm;
 unsigned long pages;
 u64 len;
 atomic_t stale;
 /* Serialized by the owning region's mutex, including rollback/unmap. */
 u32 requesters;
};
struct xdev_ext_dmabuf_map {
 struct dma_buf_attachment *attachment;
 struct sg_table *sgt;
 u64 *addresses;
};
static DEFINE_MUTEX(xdev_ext_dmabuf_registry_lock);
static LIST_HEAD(xdev_ext_dmabuf_descriptors);
static LIST_HEAD(xdev_ext_dmabuf_identities);

int xdev_ext_peer_dmabuf_desc_register(const struct xdev_ext_peer_dmabuf_desc_ops *ops)
{
 struct xdev_ext_dmabuf_descriptor *d, *new;
 if (!ops || !ops->ops || !ops->describe) return -EINVAL;
 new = kzalloc(sizeof(*new), GFP_KERNEL);
 if (!new) return -ENOMEM;
 new->ops = ops;
 mutex_lock(&xdev_ext_dmabuf_registry_lock);
 list_for_each_entry(d, &xdev_ext_dmabuf_descriptors, node)
  if (d->ops->ops == ops->ops) {
   mutex_unlock(&xdev_ext_dmabuf_registry_lock);
   kfree(new); return -EEXIST;
  }
 list_add_tail(&new->node, &xdev_ext_dmabuf_descriptors);
 mutex_unlock(&xdev_ext_dmabuf_registry_lock);
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_dmabuf_desc_register);

int xdev_ext_peer_dmabuf_desc_unregister(const struct xdev_ext_peer_dmabuf_desc_ops *ops)
{
 struct xdev_ext_dmabuf_descriptor *d;
 int ret = -ENOENT;
 mutex_lock(&xdev_ext_dmabuf_registry_lock);
 list_for_each_entry(d, &xdev_ext_dmabuf_descriptors, node)
  if (d->ops == ops) {
   if (d->live) { ret = -EBUSY; break; }
   list_del(&d->node); kfree(d); ret = 0; break;
  }
 mutex_unlock(&xdev_ext_dmabuf_registry_lock);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_dmabuf_desc_unregister);

/* Identity reservation and descriptor acquisition are one transaction; no
 * exporter callback or DMA-BUF operation may run under this registry lock.
 */
static int xdev_ext_dmabuf_reserve(struct xdev_ext_dmabuf_allocation *a, u32 flags)
{
 struct xdev_ext_dmabuf_allocation *other;
 struct xdev_ext_dmabuf_descriptor *d;
 bool described = false;
 int ret = -EOPNOTSUPP;
 mutex_lock(&xdev_ext_dmabuf_registry_lock);
 list_for_each_entry(other, &xdev_ext_dmabuf_identities, identity)
  if (other->buf == a->buf) { ret = -EBUSY; goto done; }
 list_for_each_entry(d, &xdev_ext_dmabuf_descriptors, node)
  if (d->ops->ops == a->buf->ops) {
   described = true;
   if (d->live == U32_MAX) { ret = -EOVERFLOW; break; }
   if (!try_module_get(d->ops->owner)) { ret = -ENODEV; break; }
   d->live++; a->descriptor = d;
   list_add_tail(&a->identity, &xdev_ext_dmabuf_identities);
   ret = 0; break;
  }
 /* A described exporter, even a dying one, never falls back. */
 if (!described && (flags & XDEV_EXT_PEER_DMABUF_IMPORT_UNDESCRIBED)) {
  a->descriptor = NULL;
  list_add_tail(&a->identity, &xdev_ext_dmabuf_identities);
  ret = 0;
 }
done:
 mutex_unlock(&xdev_ext_dmabuf_registry_lock);
 return ret;
}
static void xdev_ext_dmabuf_unreserve(struct xdev_ext_dmabuf_allocation *a)
{
 struct module *owner = a->descriptor ? a->descriptor->ops->owner : NULL;
 mutex_lock(&xdev_ext_dmabuf_registry_lock);
 list_del(&a->identity);
 if (a->descriptor) a->descriptor->live--;
 mutex_unlock(&xdev_ext_dmabuf_registry_lock);
 if (a->descriptor) module_put(owner);
}

/* Unlike a load/add pair, CAS also respects a concurrent charge by another
 * subsystem using this user's locked_vm. No capability bypasses accounting.
 */
static int xdev_ext_dmabuf_charge(struct xdev_ext_dmabuf_allocation *a, u64 len)
{
 unsigned long limit = rlimit(RLIMIT_MEMLOCK);
 unsigned long pages;
 long old, next;
 s64 pinned, pinned_next;
 u64 count = ((len - 1) >> PAGE_SHIFT) + 1;

 if (count > LONG_MAX || count > S64_MAX) return -EOVERFLOW;
 if (!current->mm) return -EINVAL;
 pages = count;
 a->user = get_current_user();
 a->mm = current->mm;
 mmgrab(a->mm);
 old = atomic_long_read(&a->user->locked_vm);
 do {
  if (old < 0 || check_add_overflow(old, (long)pages, &next))
   goto overflow;
  if (limit != RLIM_INFINITY && (unsigned long)next > (limit >> PAGE_SHIFT)) {
   mmdrop(a->mm); free_uid(a->user); return -ENOMEM;
  }
 } while (!atomic_long_try_cmpxchg(&a->user->locked_vm, &old, next));
 pinned = atomic64_read(&a->mm->pinned_vm);
 do {
  if (pinned < 0 || check_add_overflow(pinned, (s64)pages, &pinned_next)) {
   atomic_long_sub(pages, &a->user->locked_vm);
   goto overflow;
  }
 } while (!atomic64_try_cmpxchg(&a->mm->pinned_vm, &pinned, pinned_next));
 a->pages = pages;
 return 0;
overflow:
 mmdrop(a->mm); free_uid(a->user); return -EOVERFLOW;
}
static void xdev_ext_dmabuf_uncharge(struct xdev_ext_dmabuf_allocation *a)
{
 atomic64_sub(a->pages, &a->mm->pinned_vm);
 atomic_long_sub(a->pages, &a->user->locked_vm);
 mmdrop(a->mm); free_uid(a->user);
}

int xdev_ext_peer_dmabuf_geometry(const struct sg_table *sgt, u64 len,
                                 u64 **addresses, u32 *entries)
{
 struct scatterlist *sg;
 u64 total = 0, count, end, *pages;
 unsigned int i;
 u32 cursor = 0;
 if (!addresses || !entries) return -EINVAL;
 *addresses = NULL; *entries = 0;
 if (!sgt || !sgt->sgl || !sgt->nents || !len ||
     (len & (XDEV_EXT_DMABUF_PAGE_SIZE - 1))) return -EINVAL;
 count = len >> XDEV_EXT_DMABUF_PAGE_SHIFT;
 if (count > U32_MAX || count > SIZE_MAX / sizeof(*pages)) return -EOVERFLOW;
 for_each_sgtable_dma_sg(sgt, sg, i) {
  u64 address = sg_dma_address(sg), bytes = sg_dma_len(sg);
  if (!bytes || ((address | bytes) & (XDEV_EXT_DMABUF_PAGE_SIZE - 1)))
   return -EINVAL;
  if (check_add_overflow(address, bytes - 1, &end) ||
      check_add_overflow(total, bytes, &total)) return -EOVERFLOW;
  if (total > len) return -EINVAL;
 }
 if (total != len) return -EINVAL;
 pages = kvcalloc(count, sizeof(*pages), GFP_KERNEL);
 if (!pages) return -ENOMEM;
 for_each_sgtable_dma_sg(sgt, sg, i) {
  u64 off, bytes = sg_dma_len(sg), address = sg_dma_address(sg);
  for (off = 0; off < bytes; off += XDEV_EXT_DMABUF_PAGE_SIZE)
   pages[cursor++] = address + off;
 }
 *addresses = pages; *entries = cursor;
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_dmabuf_geometry);

static bool xdev_ext_dmabuf_stale(void *allocation)
{
 struct xdev_ext_dmabuf_allocation *a = allocation;
 if (READ_ONCE(a->buf->size) != a->len) atomic_set(&a->stale, 1);
 return atomic_read(&a->stale) != 0;
}
static void xdev_ext_dmabuf_move_notify(struct dma_buf_attachment *attachment)
{
 struct xdev_ext_dmabuf_allocation *a = attachment->importer_priv;
 /* Called with exporter/resv locks: never enter a region or wait here. */
 atomic_set(&a->stale, 1);
}
static const struct dma_buf_attach_ops xdev_ext_dmabuf_attach_ops = {
 .allow_peer2peer = true,
 .move_notify = xdev_ext_dmabuf_move_notify,
};
static int xdev_ext_dmabuf_describe(void *allocation, struct pci_dev *peer,
                                   struct xdev_ext_peer_backing *out)
{
 struct xdev_ext_dmabuf_allocation *a = allocation;
 struct xdev_ext_peer_backing backing = {};
 int ret;

 *out = (struct xdev_ext_peer_backing){};
 if (a->buf->size != a->len || xdev_ext_dmabuf_stale(a)) return -ESTALE;
 if (!a->descriptor) {
  /* Nothing is known beyond the mapping the exporter returns for this
   * device, so refuse every requester whose mapping could be bounced or
   * need CPU cache maintenance before the exporter is asked to attach. */
  if (peer->untrusted || is_swiotlb_force_bounce(&peer->dev)) return -EXDEV;
  if (!dev_is_dma_coherent(&peer->dev)) return -EOPNOTSUPP;
  *out = (struct xdev_ext_peer_backing){ .flags = XDEV_EXT_PEER_BACKING_UNDESCRIBED };
  return 0;
 }
 ret = a->descriptor->ops->describe(a->buf, peer, &backing);
 if (ret) return ret;
 if (backing.flags & XDEV_EXT_PEER_BACKING_HOST_SYSTEM) {
  if (backing.flags != (XDEV_EXT_PEER_BACKING_HOST_SYSTEM |
                        XDEV_EXT_PEER_BACKING_STRUCT_PAGE)) return -EOPNOTSUPP;
  if (peer->untrusted || is_swiotlb_force_bounce(&peer->dev)) return -EXDEV;
  if (!dev_is_dma_coherent(&peer->dev)) return -EOPNOTSUPP;
 }
 *out = backing;
 return 0;
}
/* Region lock held; must not sleep. Implicit sync (include/linux/dma-buf.h):
 * a device read waits for writers, a device write also for readers, and
 * KERNEL fences order both (dma_resv_usage_rw). The lease path cannot wait on
 * a fence, so the lease is refused and the caller retries after it signals. */
static int xdev_ext_dmabuf_may_access(void *allocation, enum dma_data_direction dir)
{
 struct xdev_ext_dmabuf_allocation *a = allocation;
 if (a->descriptor) return 0;
 return dma_resv_test_signaled(a->buf->resv,
                               dma_resv_usage_rw(dir == DMA_FROM_DEVICE)) ? 0 : -EBUSY;
}
static int xdev_ext_dmabuf_map(void *allocation, struct pci_dev *peer,
                              struct xdev_ext_peer_dma *out)
{
 struct xdev_ext_dmabuf_allocation *a = allocation;
 struct xdev_ext_peer_backing backing = {};
 struct xdev_ext_dmabuf_map *m;
 struct scatterlist *sg;
 unsigned int i;
 bool pinned = false;
 u32 entries;
 long ready;
 int ret;

 if (a->requesters == XDEV_EXT_DMABUF_MAX_REQUESTERS) return -ENOSPC;
 ret = xdev_ext_dmabuf_describe(a, peer, &backing);
 if (ret) return ret;
 m = kzalloc(sizeof(*m), GFP_KERNEL);
 if (!m) return -ENOMEM;
 m->attachment = dma_buf_dynamic_attach(a->buf, &peer->dev,
                                        &xdev_ext_dmabuf_attach_ops, a);
 if (IS_ERR(m->attachment)) { ret = PTR_ERR(m->attachment); goto free; }
 ret = dma_resv_lock(a->buf->resv, NULL);
 if (ret) goto detach;
 if (xdev_ext_dmabuf_stale(a) || a->buf->size != a->len) {
  ret = -ESTALE; goto unlock;
 }
 ret = dma_buf_pin(m->attachment);
 if (ret) goto unlock;
 pinned = true;
 ready = dma_resv_wait_timeout(a->buf->resv, DMA_RESV_USAGE_KERNEL,
                               true, MAX_SCHEDULE_TIMEOUT);
 if (ready <= 0) { ret = ready < 0 ? ready : -ETIMEDOUT; goto unlock; }
 m->sgt = dma_buf_map_attachment(m->attachment, DMA_BIDIRECTIONAL);
 if (IS_ERR(m->sgt)) { ret = PTR_ERR(m->sgt); m->sgt = NULL; goto unlock; }
 if (backing.flags & (XDEV_EXT_PEER_BACKING_HOST_SYSTEM |
                      XDEV_EXT_PEER_BACKING_UNDESCRIBED))
  for_each_sgtable_dma_sg(m->sgt, sg, i)
   if (dma_need_sync(&peer->dev, sg_dma_address(sg))) {
    ret = -EOPNOTSUPP; goto unlock;
   }
 /* dma-direct marks no SG flag on bounce; the certifier checks addresses. */
 if ((backing.flags & XDEV_EXT_PEER_BACKING_UNDESCRIBED) &&
     !dma_sgtable_is_unbounced(&peer->dev, m->sgt)) {
  ret = -EXDEV; goto unlock;
 }
 ret = xdev_ext_peer_dmabuf_geometry(m->sgt, a->len, &m->addresses, &entries);
 if (ret) goto unlock;
 if (xdev_ext_dmabuf_stale(a) || a->buf->size != a->len) {
  ret = -ESTALE; goto unlock;
 }
 dma_resv_unlock(a->buf->resv);
 a->requesters++;
 *out = (struct xdev_ext_peer_dma) {
  .private = m, .addresses = m->addresses, .entries = entries,
  .page_shift = XDEV_EXT_DMABUF_PAGE_SHIFT,
 };
 return 0;
unlock:
 kvfree(m->addresses);
 if (m->sgt) dma_buf_unmap_attachment(m->attachment, m->sgt, DMA_BIDIRECTIONAL);
 if (pinned) dma_buf_unpin(m->attachment);
 dma_resv_unlock(a->buf->resv);
detach:
 dma_buf_detach(a->buf, m->attachment);
free:
 kfree(m);
 return ret;
}
static int xdev_ext_dmabuf_unmap(void *allocation, struct pci_dev *peer,
                                struct xdev_ext_peer_dma *dma)
{
 struct xdev_ext_dmabuf_allocation *a = allocation;
 struct xdev_ext_dmabuf_map *m = dma->private;
 int ret;
 if (!m) return -EINVAL;
 ret = dma_resv_lock(a->buf->resv, NULL);
 if (ret) return ret;
 kvfree(m->addresses);
 dma_buf_unmap_attachment(m->attachment, m->sgt, DMA_BIDIRECTIONAL);
 dma_buf_unpin(m->attachment);
 dma_resv_unlock(a->buf->resv);
 dma_buf_detach(a->buf, m->attachment);
 a->requesters--;
 kfree(m);
 *dma = (struct xdev_ext_peer_dma){};
 return 0;
}
static int xdev_ext_dmabuf_unpin(void *allocation)
{
 struct xdev_ext_dmabuf_allocation *a = allocation;
 if (a->requesters) return -EBUSY;
 xdev_ext_dmabuf_unreserve(a);
 xdev_ext_dmabuf_uncharge(a);
 dma_buf_put(a->buf);
 kfree(a);
 return 0;
}
static const struct xdev_ext_peer_provider_ops xdev_ext_dmabuf_ops = {
 .owner = THIS_MODULE,
 .unpin = xdev_ext_dmabuf_unpin,
 .map = xdev_ext_dmabuf_map,
 .unmap = xdev_ext_dmabuf_unmap,
 .describe = xdev_ext_dmabuf_describe,
 .is_stale = xdev_ext_dmabuf_stale,
 .may_access = xdev_ext_dmabuf_may_access,
};
int xdev_ext_peer_dmabuf_import_flags(struct dma_buf *buf, u64 len, u32 flags,
                                     struct xdev_ext_peer_region **out)
{
 struct xdev_ext_dmabuf_allocation *a;
 int ret;
 if (!out) return -EINVAL;
 *out = NULL;
 if (flags & ~XDEV_EXT_PEER_DMABUF_IMPORT_UNDESCRIBED) return -EINVAL;
 if (!buf || !len || len != buf->size ||
     (len & (XDEV_EXT_DMABUF_PAGE_SIZE - 1))) return -EINVAL;
 a = kzalloc(sizeof(*a), GFP_KERNEL);
 if (!a) return -ENOMEM;
 a->buf = buf; a->len = len; atomic_set(&a->stale, 0);
 ret = xdev_ext_dmabuf_reserve(a, flags);
 if (ret) goto free;
 ret = xdev_ext_dmabuf_charge(a, len);
 if (ret) goto unreserve;
 ret = xdev_ext_peer_region_create(&xdev_ext_dmabuf_ops, buf->file, a, len, out);
 if (!ret) return 0;
 xdev_ext_dmabuf_uncharge(a);
unreserve:
 xdev_ext_dmabuf_unreserve(a);
free:
 kfree(a);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_dmabuf_import_flags);
int xdev_ext_peer_dmabuf_import(struct dma_buf *buf, u64 len,
                               struct xdev_ext_peer_region **out)
{
 return xdev_ext_peer_dmabuf_import_flags(buf, len, 0, out);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_dmabuf_import);
MODULE_IMPORT_NS("DMA_BUF");
