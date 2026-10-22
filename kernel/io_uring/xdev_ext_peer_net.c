// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/file.h>
#include <linux/netdevice.h>
#include <linux/nsproxy.h>
#include <linux/pci.h>
#include <linux/refcount.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/xdev_ext_peer.h>
#include <net/net_namespace.h>
#include <uapi/linux/xdev_ext_peer.h>
#include "xdev_ext_peer_net_core.h"
struct xdev_ext_peer_tx_wait {
 struct xdev_ext_peer_tx tx;
 struct xdev_ext_peer_fd_lease handle;
 struct completion done;
 struct work_struct work;
 refcount_t refs; /* caller, native driver, and queued work */
 atomic_t claimed;
 int status;
 bool quiesced;
 u8 header[XDEV_EXT_PEER_NET_HEADER_MAX];
};
static void xdev_ext_peer_tx_put(struct xdev_ext_peer_tx_wait *p)
{ if (refcount_dec_and_test(&p->refs)) kfree(p); }
static void xdev_ext_peer_tx_work(struct work_struct *work)
{
 struct xdev_ext_peer_tx_wait *p = container_of(work, struct xdev_ext_peer_tx_wait, work);
 xdev_ext_peer_fd_release(&p->handle, p->quiesced);
 complete(&p->done);
 xdev_ext_peer_tx_put(p);
}
static void xdev_ext_peer_tx_finish(struct xdev_ext_peer_tx_wait *p, int status, bool quiesced)
{
 if (atomic_cmpxchg(&p->claimed, 0, 1)) return;
 p->status = status; p->quiesced = quiesced;
 refcount_inc(&p->refs);
 queue_work(system_unbound_wq, &p->work);
}
static void xdev_ext_peer_tx_complete(struct xdev_ext_peer_tx *tx, int status, bool quiesced)
{
 struct xdev_ext_peer_tx_wait *p = container_of(tx, struct xdev_ext_peer_tx_wait, tx);
 xdev_ext_peer_tx_finish(p, status, quiesced);
 xdev_ext_peer_tx_put(p); /* driver's exactly-once native completion */
}
static int xdev_ext_peer_net_one(struct net_device *dev, struct pci_dev *peer,
                                struct file *allocation, u64 generation, u32 queue,
                                const struct xdev_ext_peer_net_desc *d)
{
 struct xdev_ext_peer_tx_wait *p;
 int ret;
 p = kzalloc(sizeof(*p), GFP_KERNEL);
 if (!p) return -ENOMEM;
 init_completion(&p->done); INIT_WORK(&p->work, xdev_ext_peer_tx_work);
 refcount_set(&p->refs, 2); atomic_set(&p->claimed, 0);
 ret = xdev_ext_peer_file_acquire(allocation, peer, generation, d->offset,
                                 d->bytes, DMA_TO_DEVICE, &p->handle);
 if (ret) { kfree(p); return ret; }
 memcpy(p->header, d->header, d->header_len);
 p->tx = (struct xdev_ext_peer_tx){ .dma_address = p->handle.lease.dma_address,
   .len = d->bytes, .header_len = d->header_len, .header = p->header,
   .complete = xdev_ext_peer_tx_complete };
 /* RTNL and TX queue lock are released before waiting for CQE/recovery. */
 rtnl_lock();
 if (!netif_running(dev) || !netif_device_present(dev)) ret = -ENETDOWN;
 else ret = dev->netdev_ops->ndo_xdev_ext_peer_tx(dev, queue, &p->tx);
 rtnl_unlock();
 if (ret) {
  xdev_ext_peer_tx_finish(p, ret, true);
  xdev_ext_peer_tx_put(p); /* refused request: no native owner */
 } else if (!wait_for_completion_timeout(&p->done, 30 * HZ)) {
  /* Unknown native ownership: keep driver reference until a late CQE or
   * native teardown. Worker permanently quarantines the allocation mapping.
   */
  xdev_ext_peer_tx_finish(p, -ETIMEDOUT, false);
 }
 wait_for_completion(&p->done);
 ret = p->status;
 xdev_ext_peer_tx_put(p);
 return ret;
}
long xdev_ext_peer_net_ioctl(unsigned long arg)
{
 struct xdev_ext_peer_net_batch *u;
 struct net_device *dev = NULL;
 struct pci_dev *peer = NULL;
 struct file *allocation = NULL;
 u32 i;
 int ret;
 if (!capable(CAP_SYS_RAWIO) || !capable(CAP_NET_RAW)) return -EPERM;
 u = memdup_user((void __user *)arg, sizeof(*u));
 if (IS_ERR(u)) return PTR_ERR(u);
 if (u->flags) { ret = -EOPNOTSUPP; goto out; }
 if (u->reserved || u->completed || u->status || !u->nr ||
     u->nr > XDEV_EXT_PEER_NET_MAX_DESCS) { ret = -EINVAL; goto out; }
 dev = dev_get_by_index(current->nsproxy->net_ns, u->ifindex);
 if (!dev) { ret = -ENODEV; goto out; }
 rtnl_lock();
 if (!dev->netdev_ops->ndo_xdev_ext_peer_device || !dev->netdev_ops->ndo_xdev_ext_peer_tx)
  ret = -EOPNOTSUPP;
 else if (u->queue >= dev->real_num_tx_queues) ret = -EINVAL;
 else {
  peer = dev->netdev_ops->ndo_xdev_ext_peer_device(dev);
  ret = peer ? 0 : -EOPNOTSUPP;
 }
 if (!ret) pci_dev_get(peer);
 for (i = 0; !ret && i < u->nr; i++) {
  if (u->desc[i].reserved) ret = -EINVAL;
  else ret = xdev_ext_peer_net_check(dev->mtu, u->desc[i].header_len, u->desc[i].bytes, 0);
 }
 rtnl_unlock();
 if (ret) goto out;
 allocation = fget(u->allocation_fd);
 if (!allocation) { ret = -EBADF; goto out; }
 for (i = 0; i < u->nr; i++) {
  ret = xdev_ext_peer_net_one(dev, peer, allocation, u->generation, u->queue, &u->desc[i]);
  u->status = ret;
  if (ret) break;
  u->completed++;
 }
 if (copy_to_user((void __user *)arg, u, sizeof(*u))) ret = -EFAULT;
out:
 if (allocation) fput(allocation);
 if (peer) pci_dev_put(peer);
 if (dev) dev_put(dev);
 kfree(u);
 return ret;
}
