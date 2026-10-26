// SPDX-License-Identifier: GPL-2.0
/* Persistent device memory, distinct from the host struct-page UMEM pool.
 * All control operations are process context and may sleep. The native driver
 * must defer end_io release to a worker. Provider mappings remain resident
 * throughout native request ownership; uncertain DMA retains every reference.
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
 struct file *file;
 void *allocation;
 u64 len, generation;
 bool invalid, quarantined;
};
struct xdev_ext_peer_mapping {
 struct list_head node;
 struct xdev_ext_peer_region *region;
 struct pci_dev *peer;
 struct xdev_ext_peer_dma dma;
 enum dma_data_direction direction;
 u32 users, active;
 struct xdev_ext_peer_lease *leases;
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
int xdev_ext_peer_pin(struct file *file, u64 va, u64 len, struct xdev_ext_peer_region **out)
{
 struct xdev_ext_peer_region *r;
 struct xdev_ext_peer_provider *p;
 int ret = -ENODEV;
 if (!file || !out || !len || va + len < va) return -EINVAL;
 *out = NULL;
 r = kzalloc(sizeof(*r), GFP_KERNEL);
 if (!r) return -ENOMEM;
 mutex_init(&r->lock); INIT_LIST_HEAD(&r->maps);
 mutex_lock(&xdev_ext_peer_registry_lock);
 list_for_each_entry(p, &xdev_ext_peer_providers, node)
  if (p->ops->fops == file->f_op && try_module_get(p->ops->owner)) {
   ret = p->ops->pin(file, va, len, &r->allocation);
   if (ret) { module_put(p->ops->owner); break; }
   p->allocations++; r->provider = p; break;
  }
 mutex_unlock(&xdev_ext_peer_registry_lock);
 if (ret) { kfree(r); return ret; }
 get_file(file); r->file = file; r->len = len;
 r->generation = atomic64_inc_return(&xdev_ext_peer_serial);
 if (!r->generation) r->generation = atomic64_inc_return(&xdev_ext_peer_serial);
 *out = r;
 return 0;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_pin);
u64 xdev_ext_peer_generation(struct xdev_ext_peer_region *r)
{ return r ? r->generation : 0; }
EXPORT_SYMBOL_GPL(xdev_ext_peer_generation);
int xdev_ext_peer_info(struct xdev_ext_peer_region *r, u64 *len, u64 *generation, bool idle)
{
 struct xdev_ext_peer_mapping *m;
 int ret = 0;
 if (!r || !len || !generation) return -EINVAL;
 mutex_lock(&r->lock);
 if (r->invalid || r->quarantined) ret = -ESTALE;
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
 if (r->invalid || r->quarantined)
  ret = -ESTALE;
 else if (!r->provider->ops->describe)
  ret = -EOPNOTSUPP;
 else
  ret = r->provider->ops->describe(r->allocation, requester, out);
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
 if (r->invalid || r->quarantined) { ret = -ESTALE; goto done; }
 list_for_each_entry(m, &r->maps, node)
  if (m->peer == peer) {
   if (m->direction != dir && m->direction != DMA_BIDIRECTIONAL) { ret = -EACCES; goto done; }
   if (m->users == U32_MAX) { ret = -EOVERFLOW; goto done; }
   m->users++; *out = m; goto done;
  }
 m = kzalloc(sizeof(*m), GFP_KERNEL);
 if (!m) { ret = -ENOMEM; goto done; }
 m->region = r; m->peer = pci_dev_get(peer); m->direction = dir;
 ret = r->provider->ops->map(r->allocation, peer, &m->dma);
 if (ret) goto free;
 if (!m->dma.addresses || !m->dma.entries || m->dma.page_shift < 12 ||
     m->dma.page_shift > 31 || (u64)m->dma.entries << m->dma.page_shift < r->len) {
  ret = -EPROTO;
  /* Even malformed provider geometry cannot bypass native cleanup failure. */
  if (r->provider->ops->unmap(r->allocation, peer, &m->dma)) {
   r->invalid = r->quarantined = true; m->users = 1;
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
 if (r->invalid || r->quarantined || generation != r->generation) { ret = -ESTALE; goto done; }
 if (m->direction != DMA_BIDIRECTIONAL && m->direction != dir) { ret = -EACCES; goto done; }
 page_size = 1ULL << m->dma.page_shift;
 if (!len || offset >= r->len || len > r->len - offset ||
     len > page_size - (offset & (page_size - 1))) { ret = -ERANGE; goto done; }
 address = m->dma.addresses[offset >> m->dma.page_shift];
 if (address + (offset & (page_size - 1)) < address ||
     address + (offset & (page_size - 1)) + len - 1 < address) { ret = -EOVERFLOW; goto done; }
 if (m->active == U32_MAX) { ret = -EOVERFLOW; goto done; }
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
 ret = r->provider->ops->unmap(r->allocation, m->peer, &m->dma);
 if (ret) { r->invalid = r->quarantined = true; goto done; }
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
 r->invalid = true; p = r->provider; owner = p->ops->owner;
 ret = p->ops->unpin(r->allocation);
 if (ret) { r->quarantined = true; goto done; }
 mutex_unlock(&r->lock);
 mutex_lock(&xdev_ext_peer_registry_lock); p->allocations--;
 mutex_unlock(&xdev_ext_peer_registry_lock);
 fput(r->file); module_put(owner); kfree(r); return 0;
done:
 mutex_unlock(&r->lock); return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_unpin);
