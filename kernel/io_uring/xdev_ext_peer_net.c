// SPDX-License-Identifier: GPL-2.0
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/minmax.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/nsproxy.h>
#include <linux/pci.h>
#include <linux/refcount.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/xdev_ext_peer.h>
#include <net/net_namespace.h>
#include <uapi/linux/xdev_ext_peer.h>
#include "xdev_ext_peer_net_core.h"
#include "xdev_ext_policy.h"
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
/* A native wait allows 30 s; once the caller stopped, at most a further grace
 * that keeps the session worker well inside its 5 s drain timeout.
 */
#define XDEV_EXT_PEER_NET_TIMEOUT xdev_ext_policy_peer_net_timeout()
#define XDEV_EXT_PEER_NET_STOP_SLICE (HZ / 20)
#define XDEV_EXT_PEER_NET_STOP_GRACE HZ
static void xdev_ext_peer_tx_put(struct xdev_ext_peer_tx_wait *p)
{ if (refcount_dec_and_test(&p->refs)) kfree(p); }
/* Park a context with no other owner for the endpoint's next descriptor. */
static void xdev_ext_peer_tx_keep(struct xdev_ext_peer_tx_wait **spare,
                                  struct xdev_ext_peer_tx_wait *p)
{ kfree(xchg(spare, p)); }
static void xdev_ext_peer_tx_work(struct work_struct *work)
{
 struct xdev_ext_peer_tx_wait *p = container_of(work, struct xdev_ext_peer_tx_wait, work);
 xdev_ext_peer_fd_release(&p->handle, p->quiesced);
 /* The waiter holds its reference until done, so this put is never the last
  * and p may be reused as soon as the waiter returns.
  */
 xdev_ext_peer_tx_put(p);
 complete(&p->done);
}
/* The claimant hands one reference to the queued work. */
static bool xdev_ext_peer_tx_finish(struct xdev_ext_peer_tx_wait *p, int status, bool quiesced)
{
 if (atomic_cmpxchg(&p->claimed, 0, 1)) return false;
 /* Native ownership is authoritative even when the driver reports zero
  * status. Never expose an unquiesced command as successful/reusable.
  */
 p->status = !quiesced && !status ? -EIO : status;
 p->quiesced = quiesced;
 queue_work(system_unbound_wq, &p->work);
 return true;
}
static void xdev_ext_peer_tx_complete(struct xdev_ext_peer_tx *tx, int status, bool quiesced)
{
 struct xdev_ext_peer_tx_wait *p = container_of(tx, struct xdev_ext_peer_tx_wait, tx);
 /* The driver's exactly-once native reference goes to the work or ends. */
 if (!xdev_ext_peer_tx_finish(p, status, quiesced)) xdev_ext_peer_tx_put(p);
}
/* The caller keeps @dev alive. @stopped, when given, is polled while a native
 * completion is outstanding; @spare holds a context reused across calls.
 */
static int xdev_ext_peer_net_one(struct net_device *dev, struct pci_dev *peer,
                                struct file *allocation, u64 generation, u32 queue,
                                const struct xdev_ext_peer_net_desc *d, bool *accepted,
                                struct xdev_ext_peer_tx_wait **spare,
                                bool (*stopped)(void *), void *arg)
{
 struct xdev_ext_peer_tx_wait *p = xchg(spare, NULL);
 unsigned long left = XDEV_EXT_PEER_NET_TIMEOUT, step;
 bool stopping = false, completed = false;
 int ret;
 if (accepted) *accepted = false;
 if (!p) {
  /* Zeroed: file acquire refuses a handle that is not empty. */
  p = kzalloc(sizeof(*p), GFP_KERNEL);
  if (!p) return -ENOMEM;
  INIT_WORK(&p->work, xdev_ext_peer_tx_work);
 }
 init_completion(&p->done);
 refcount_set(&p->refs, 2); atomic_set(&p->claimed, 0);
 p->status = 0; p->quiesced = false;
 ret = xdev_ext_peer_file_acquire(allocation, peer, generation, d->offset,
                                 d->bytes, DMA_TO_DEVICE, &p->handle);
 if (ret) { xdev_ext_peer_tx_keep(spare, p); return ret; }
 memcpy(p->header, d->header, d->header_len);
 p->tx = (struct xdev_ext_peer_tx){ .dma_address = p->handle.lease.dma_address,
   .len = d->bytes, .header_len = d->header_len, .header = p->header,
   .complete = xdev_ext_peer_tx_complete };
 /* No RTNL: like ndo_start_xmit, the driver serializes on its TX queue lock
  * and refuses a stopped, detached or reconfiguring queue.
  */
 if (!netif_running(dev) || !netif_device_present(dev)) ret = -ENETDOWN;
 else {
  rcu_read_lock();
  ret = dev->netdev_ops->ndo_xdev_ext_peer_tx(dev, queue, &p->tx);
  rcu_read_unlock();
 }
 if (!ret && accepted) *accepted = true;
 if (ret) {
  xdev_ext_peer_tx_finish(p, ret, true); /* refused: no native owner */
 } else {
  for (;;) {
   step = stopped ? min(left, (unsigned long)XDEV_EXT_PEER_NET_STOP_SLICE) : left;
   /* A successful timed wait consumes the only complete(). */
   if (wait_for_completion_timeout(&p->done, step)) { completed = true; break; }
   left -= step;
   if (stopped && !stopping && stopped(arg)) {
    stopping = true; left = min(left, (unsigned long)XDEV_EXT_PEER_NET_STOP_GRACE);
   }
   if (left) continue;
   /* Unknown native ownership: the driver keeps its reference until a late
    * CQE or native teardown. Worker permanently quarantines the allocation
    * mapping.
    */
   refcount_inc(&p->refs);
   if (!xdev_ext_peer_tx_finish(p, stopping ? -ECANCELED : -ETIMEDOUT, false))
    xdev_ext_peer_tx_put(p);
   break;
  }
 }
 if (!completed) wait_for_completion(&p->done);
 ret = p->status;
 /* A late native callback still holds a reference and frees the context. */
 if (refcount_dec_not_one(&p->refs)) return ret;
 /* Only an empty handle is reused. A refused lease release keeps the file
  * and mapping; the context is then dropped as a per-send context was.
  */
 if (p->handle.file || p->handle.lease.mapping) kfree(p);
 else xdev_ext_peer_tx_keep(spare, p);
 return ret;
}
/* A configured native endpoint is reusable by every device-memory producer.
 * Namespace and device authority are captured once in the CREATE caller.
 * NETDEV_UNREGISTER drops the device reference and reports the endpoint dead.
 */
struct xdev_ext_peer_net_endpoint {
 struct list_head node; /* xdev_ext_peer_net_endpoints */
 spinlock_t lock; /* dev */
 struct net_device *dev; /* NULL once the device unregisters */
 netdevice_tracker tracker;
 struct pci_dev *peer;
 struct xdev_ext_peer_tx_wait *spare;
 void (*dead)(void *arg);
 void *arg;
 u32 queue;
 u64 rx_owner;
 bool rx;
};
static LIST_HEAD(xdev_ext_peer_net_endpoints);
static DEFINE_MUTEX(xdev_ext_peer_net_lock); /* the list; nests inside RTNL */
static bool xdev_ext_peer_net_notifier_ready;
/* RTNL serializes allocation. Never recycle tokens, even across native queue
 * or device/profile replacement. Saturation refuses a bind rather than ABA. */
static u64 xdev_ext_peer_net_rx_owner;
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_dir(u32 ifindex, u32 queue, bool rx,
                                                            void (*dead)(void *), void *arg)
{
 struct xdev_ext_peer_net_endpoint *endpoint;
 struct net_device *dev;
 struct pci_dev *peer = NULL;
 int ret = 0;
 if (!capable(CAP_SYS_RAWIO) || !capable(CAP_NET_RAW)) return ERR_PTR(-EPERM);
 if (!READ_ONCE(xdev_ext_peer_net_notifier_ready)) return ERR_PTR(-ENODEV);
 endpoint = kzalloc(sizeof(*endpoint), GFP_KERNEL);
 if (!endpoint) return ERR_PTR(-ENOMEM);
 spin_lock_init(&endpoint->lock);
 endpoint->dead = dead; endpoint->arg = arg; endpoint->queue = queue; endpoint->rx = rx;
 dev = netdev_get_by_index(current->nsproxy->net_ns, ifindex, &endpoint->tracker, GFP_KERNEL);
 if (!dev) { kfree(endpoint); return ERR_PTR(-ENODEV); }
 rtnl_lock();
 if (xdev_ext_peer_net_cap_check(xdev_ext_peer_net_caps(
      !!dev->netdev_ops->ndo_xdev_ext_peer_device, !!dev->netdev_ops->ndo_xdev_ext_peer_tx,
      !!dev->netdev_ops->ndo_xdev_ext_peer_rx, !!dev->netdev_ops->ndo_xdev_ext_peer_rx_flush), rx))
  ret = -EOPNOTSUPP;
 else if (rx && !dev->netdev_ops->ndo_xdev_ext_peer_rx_open) ret = -EOPNOTSUPP;
 /* NETDEV_UNREGISTER runs under RTNL after reg_state leaves REGISTERED. */
 else if (dev->reg_state != NETREG_REGISTERED) ret = -ENODEV;
 else if (queue >= (rx ? dev->real_num_rx_queues : dev->real_num_tx_queues)) ret = -EINVAL;
 else if (!netif_running(dev) || !netif_device_present(dev)) ret = -ENETDOWN;
 else {
  peer = dev->netdev_ops->ndo_xdev_ext_peer_device(dev);
  if (!peer) ret = -EOPNOTSUPP;
  else pci_dev_get(peer);
 }
 if (!ret && rx) {
  if (xdev_ext_peer_net_rx_owner == U64_MAX) ret = -EOVERFLOW;
  else {
   endpoint->rx_owner = ++xdev_ext_peer_net_rx_owner;
   ret = dev->netdev_ops->ndo_xdev_ext_peer_rx_open(dev, queue, endpoint->rx_owner);
  }
  if (ret) pci_dev_put(peer);
 }
 if (!ret) {
  endpoint->dev = dev; endpoint->peer = peer;
  mutex_lock(&xdev_ext_peer_net_lock);
  list_add_tail(&endpoint->node, &xdev_ext_peer_net_endpoints);
  mutex_unlock(&xdev_ext_peer_net_lock);
 }
 rtnl_unlock();
 if (ret) { netdev_put(dev, &endpoint->tracker); kfree(endpoint); return ERR_PTR(ret); }
 return endpoint;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_bind_dir);
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_stage(u32 ifindex, u32 queue,
                                                              void (*dead)(void *), void *arg)
{ return xdev_ext_peer_net_bind_dir(ifindex, queue, false, dead, arg); }
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_bind_stage);
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind(u32 ifindex, u32 queue)
{ return xdev_ext_peer_net_bind_stage(ifindex, queue, NULL, NULL); }
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_bind);
/* No send runs any more; a concurrent NETDEV_UNREGISTER is excluded. */
void xdev_ext_peer_net_unbind(struct xdev_ext_peer_net_endpoint *endpoint)
{
 struct net_device *dev;
 if (endpoint->rx) xdev_ext_peer_net_rx_flush(endpoint);
 mutex_lock(&xdev_ext_peer_net_lock);
 list_del(&endpoint->node);
 mutex_unlock(&xdev_ext_peer_net_lock);
 spin_lock(&endpoint->lock);
 dev = endpoint->dev; endpoint->dev = NULL;
 spin_unlock(&endpoint->lock);
 netdev_put(dev, &endpoint->tracker);
 pci_dev_put(endpoint->peer); kfree(endpoint->spare); kfree(endpoint);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_unbind);
/* Zero after unregistration, which no plan or descriptor fits. */
u32 xdev_ext_peer_net_mtu(struct xdev_ext_peer_net_endpoint *endpoint)
{
 u32 mtu = 0;
 spin_lock(&endpoint->lock);
 if (endpoint->dev) mtu = READ_ONCE(endpoint->dev->mtu);
 spin_unlock(&endpoint->lock);
 return mtu;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_mtu);
/* Each post holds a short netdev reference across the native hook. Accepted
 * elements belong to the driver and are retired by CQ or queue teardown. */
struct pci_dev *xdev_ext_peer_net_peer(struct xdev_ext_peer_net_endpoint *ep)
{ return ep->peer; }
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_peer);
int xdev_ext_peer_net_post_tx(struct xdev_ext_peer_net_endpoint *ep, struct xdev_ext_peer_tx *chain)
{
 netdevice_tracker tracker;
 struct net_device *dev;
 int ret;
 if (!ep || !chain || ep->rx) return -EINVAL;
 spin_lock(&ep->lock);
 dev = ep->dev;
 netdev_hold(dev, &tracker, GFP_ATOMIC);
 spin_unlock(&ep->lock);
 if (!dev) return -ENODEV;
 rcu_read_lock();
 ret = !netif_running(dev) || !netif_device_present(dev) ? -ENETDOWN :
       dev->netdev_ops->ndo_xdev_ext_peer_tx(dev, ep->queue, chain);
 rcu_read_unlock();
 netdev_put(dev, &tracker);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_post_tx);
int xdev_ext_peer_net_post_rx(struct xdev_ext_peer_net_endpoint *ep, struct xdev_ext_peer_rx *chain)
{
 netdevice_tracker tracker;
 struct net_device *dev;
 int ret;
 if (!ep || !chain || !ep->rx) return -EINVAL;
 spin_lock(&ep->lock);
 dev = ep->dev;
 netdev_hold(dev, &tracker, GFP_ATOMIC);
 spin_unlock(&ep->lock);
 if (!dev) return -ENODEV;
 ret = !netif_running(dev) || !netif_device_present(dev) ? -ENETDOWN :
       dev->netdev_ops->ndo_xdev_ext_peer_rx(dev, ep->queue, ep->rx_owner, chain);
 netdev_put(dev, &tracker);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_post_rx);
int xdev_ext_peer_net_rx_flush(struct xdev_ext_peer_net_endpoint *ep)
{
 struct net_device *dev;
 int ret;
 if (!ep || !ep->rx) return -EINVAL;
 /* Flush may sleep and must not race native channel reconfiguration. */
 rtnl_lock();
 dev = ep->dev;
 ret = dev ? dev->netdev_ops->ndo_xdev_ext_peer_rx_flush(dev, ep->queue, ep->rx_owner) : -ENODEV;
 rtnl_unlock();
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_rx_flush);
int xdev_ext_peer_net_send_stoppable(struct xdev_ext_peer_net_endpoint *endpoint,
                                     struct file *allocation, u64 generation,
                                     const struct xdev_ext_peer_net_desc *desc, bool *accepted,
                                     bool (*stopped)(void *), void *arg)
{
 netdevice_tracker tracker;
 struct net_device *dev;
 int ret;
 if (accepted) *accepted = false;
 if (!endpoint || !desc || desc->reserved) return -EINVAL;
 /* A per-send reference: unregistration waits at most for this one send. */
 spin_lock(&endpoint->lock);
 dev = endpoint->dev;
 netdev_hold(dev, &tracker, GFP_ATOMIC);
 spin_unlock(&endpoint->lock);
 if (!dev) return -ENODEV;
 ret = xdev_ext_peer_net_check(READ_ONCE(dev->mtu), desc->header_len, desc->bytes, 0);
 if (!ret)
  ret = xdev_ext_peer_net_one(dev, endpoint->peer, allocation, generation, endpoint->queue,
                              desc, accepted, &endpoint->spare, stopped, arg);
 netdev_put(dev, &tracker);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_send_stoppable);
int xdev_ext_peer_net_send(struct xdev_ext_peer_net_endpoint *endpoint,
                           struct file *allocation, u64 generation,
                           const struct xdev_ext_peer_net_desc *desc, bool *accepted)
{
 return xdev_ext_peer_net_send_stoppable(endpoint, allocation, generation, desc, accepted,
                                         NULL, NULL);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_net_send);
/* RTNL. In-flight sends hold their own reference; dead() must not block. */
static int xdev_ext_peer_net_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
 struct net_device *dev = netdev_notifier_info_to_dev(ptr);
 struct xdev_ext_peer_net_endpoint *endpoint;
 (void)nb;
 if (event != NETDEV_UNREGISTER) return NOTIFY_DONE;
 mutex_lock(&xdev_ext_peer_net_lock);
 list_for_each_entry(endpoint, &xdev_ext_peer_net_endpoints, node) {
  if (endpoint->dev != dev) continue;
  spin_lock(&endpoint->lock);
  endpoint->dev = NULL;
  spin_unlock(&endpoint->lock);
  netdev_put(dev, &endpoint->tracker);
  if (endpoint->dead)
   endpoint->dead(endpoint->arg);
 }
 mutex_unlock(&xdev_ext_peer_net_lock);
 return NOTIFY_DONE;
}
static struct notifier_block xdev_ext_peer_net_notifier = {
 .notifier_call = xdev_ext_peer_net_event,
};
static int __init xdev_ext_peer_net_init(void)
{
 int ret = register_netdevice_notifier(&xdev_ext_peer_net_notifier);
 if (!ret) WRITE_ONCE(xdev_ext_peer_net_notifier_ready, true);
 return ret;
}
device_initcall(xdev_ext_peer_net_init);
long xdev_ext_peer_net_ioctl(unsigned long arg)
{
 struct xdev_ext_peer_net_batch *u;
 struct net_device *dev = NULL;
 struct pci_dev *peer = NULL;
 struct file *allocation = NULL;
 struct xdev_ext_peer_tx_wait *spare = NULL;
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
  ret = xdev_ext_peer_net_one(dev, peer, allocation, u->generation, u->queue, &u->desc[i],
                              NULL, &spare, NULL, NULL);
  u->status = ret;
  if (ret) break;
  u->completed++;
 }
 if (copy_to_user((void __user *)arg, u, sizeof(*u))) ret = -EFAULT;
out:
 kfree(spare);
 if (allocation) fput(allocation);
 if (peer) pci_dev_put(peer);
 if (dev) dev_put(dev);
 kfree(u);
 return ret;
}
