// SPDX-License-Identifier: GPL-2.0
/* GUEST TEST ONLY: contiguous host RAM stands in for provider device memory.
 * This exercises the real provider registry and NVMe PCI DMA API, not VRAM.
 */
#include <linux/dma-mapping.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/xdev_ext_peer.h>
#include "sw_provider_uapi.h"

static bool guest_only;
module_param(guest_only, bool, 0400);
MODULE_PARM_DESC(guest_only, "explicit guest-only opt-in; never load on the host");
static atomic64_t opens, closes, pins, unpins, maps, unmaps, live_pins, live_maps;
struct sw_allocation {
	struct mutex lock;
	struct list_head maps;
	void *data;
	u32 pins;
	bool reject_map;
};
struct sw_mapping {
	struct list_head node;
	struct device *dev;
	dma_addr_t dma;
	u64 address;
};
static int sw_open(struct inode *inode, struct file *file)
{
	struct sw_allocation *a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a) return -ENOMEM;
	a->data = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(PEER_SW_BYTES));
	if (!a->data) { kfree(a); return -ENOMEM; }
	mutex_init(&a->lock); INIT_LIST_HEAD(&a->maps);
	file->private_data = a;
	atomic64_inc(&opens);
	return 0;
}
static int sw_close(struct inode *inode, struct file *file)
{
	struct sw_allocation *a = file->private_data;
	if (WARN_ON(a->pins || !list_empty(&a->maps))) return 0;
	free_pages((unsigned long)a->data, get_order(PEER_SW_BYTES));
	kfree(a); atomic64_inc(&closes);
	return 0;
}
static ssize_t sw_access(struct file *file, char __user *buf, size_t len, loff_t *ppos, bool write)
{
	struct sw_allocation *a = file->private_data;
	struct sw_mapping *m;
	ssize_t ret;
	if (*ppos < 0 || *ppos > PEER_SW_BYTES) return -EINVAL;
	len = min_t(size_t, len, PEER_SW_BYTES - *ppos);
	mutex_lock(&a->lock);
	/* Tests access only after native synchronous completion, never during DMA. */
	list_for_each_entry(m, &a->maps, node)
		dma_sync_single_for_cpu(m->dev, m->dma, PEER_SW_BYTES, DMA_BIDIRECTIONAL);
	if (write) ret = copy_from_user(a->data + *ppos, buf, len) ? -EFAULT : len;
	else ret = copy_to_user(buf, a->data + *ppos, len) ? -EFAULT : len;
	list_for_each_entry(m, &a->maps, node)
		dma_sync_single_for_device(m->dev, m->dma, PEER_SW_BYTES, DMA_BIDIRECTIONAL);
	mutex_unlock(&a->lock);
	if (ret > 0) *ppos += ret;
	return ret;
}
static ssize_t sw_read(struct file *f, char __user *b, size_t n, loff_t *p)
{ return sw_access(f, b, n, p, false); }
static ssize_t sw_write(struct file *f, const char __user *b, size_t n, loff_t *p)
{ return sw_access(f, (char __user *)b, n, p, true); }
static long sw_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sw_allocation *a = file->private_data;
	struct peer_sw_stats s;
	if (cmd == PEER_SW_STATS) {
		s = (struct peer_sw_stats){
			.opens = atomic64_read(&opens), .closes = atomic64_read(&closes),
			.pins = atomic64_read(&pins), .unpins = atomic64_read(&unpins),
			.maps = atomic64_read(&maps), .unmaps = atomic64_read(&unmaps),
			.live_pins = atomic64_read(&live_pins), .live_maps = atomic64_read(&live_maps),
		};
		return copy_to_user((void __user *)arg, &s, sizeof(s)) ? -EFAULT : 0;
	}
	if (cmd == PEER_SW_REJECT_MAP) {
		mutex_lock(&a->lock);
		if (a->pins || !list_empty(&a->maps)) { mutex_unlock(&a->lock); return -EBUSY; }
		a->reject_map = true;
		mutex_unlock(&a->lock); return 0;
	}
	return -ENOTTY;
}
static const struct file_operations sw_fops = {
	.owner = THIS_MODULE, .open = sw_open, .release = sw_close,
	.read = sw_read, .write = sw_write, .llseek = default_llseek,
	.unlocked_ioctl = sw_ioctl,
};
static int sw_pin(struct file *file, u64 va, u64 len, void **out)
{
	struct sw_allocation *a = file->private_data;
	if (va != PEER_SW_VA || len != PEER_SW_BYTES) return -EINVAL;
	mutex_lock(&a->lock); a->pins++; mutex_unlock(&a->lock);
	atomic64_inc(&pins); atomic64_inc(&live_pins); *out = a;
	return 0;
}
static int sw_unpin(void *allocation)
{
	struct sw_allocation *a = allocation;
	mutex_lock(&a->lock);
	if (!a->pins || !list_empty(&a->maps)) { mutex_unlock(&a->lock); return -EBUSY; }
	a->pins--; mutex_unlock(&a->lock);
	atomic64_inc(&unpins); atomic64_dec(&live_pins);
	return 0;
}
static int sw_map(void *allocation, struct pci_dev *peer, struct xdev_ext_peer_dma *out)
{
	struct sw_allocation *a = allocation;
	struct sw_mapping *m;
	mutex_lock(&a->lock);
	if (a->reject_map) { mutex_unlock(&a->lock); return -EOPNOTSUPP; }
	if (!a->pins || peer->class != PCI_CLASS_STORAGE_EXPRESS) {
		mutex_unlock(&a->lock); return -EINVAL;
	}
	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m) { mutex_unlock(&a->lock); return -ENOMEM; }
	m->dev = &peer->dev;
	m->dma = dma_map_single(m->dev, a->data, PEER_SW_BYTES, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(m->dev, m->dma)) {
		kfree(m); mutex_unlock(&a->lock); return -EIO;
	}
	m->address = m->dma; list_add_tail(&m->node, &a->maps);
	*out = (struct xdev_ext_peer_dma){.private = m, .addresses = &m->address, .entries = 1, .page_shift = 16};
	mutex_unlock(&a->lock); atomic64_inc(&maps); atomic64_inc(&live_maps);
	return 0;
}
static int sw_unmap(void *allocation, struct pci_dev *peer, struct xdev_ext_peer_dma *dma)
{
	struct sw_allocation *a = allocation;
	struct sw_mapping *m = dma->private;
	if (!m || m->dev != &peer->dev) return -EINVAL;
	mutex_lock(&a->lock);
	dma_unmap_single(m->dev, m->dma, PEER_SW_BYTES, DMA_BIDIRECTIONAL);
	list_del(&m->node); kfree(m); memset(dma, 0, sizeof(*dma));
	mutex_unlock(&a->lock); atomic64_inc(&unmaps); atomic64_dec(&live_maps);
	return 0;
}
static const struct xdev_ext_peer_provider_ops sw_ops = {
	.owner = THIS_MODULE, .fops = &sw_fops, .pin = sw_pin, .unpin = sw_unpin,
	.map = sw_map, .unmap = sw_unmap,
};
static struct miscdevice sw_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "xdev_ext_peer_sw", .mode = 0600, .fops = &sw_fops,
};
static int __init sw_init(void)
{
	int ret;
	if (!guest_only) return -EPERM;
	ret = xdev_ext_peer_provider_register(&sw_ops);
	if (ret) return ret;
	ret = misc_register(&sw_device);
	if (ret) xdev_ext_peer_provider_unregister(&sw_ops);
	return ret;
}
static void __exit sw_exit(void)
{
	misc_deregister(&sw_device);
	WARN_ON(xdev_ext_peer_provider_unregister(&sw_ops));
}
module_init(sw_init); module_exit(sw_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Guest-only host RAM stand-in for native peer NVMe DMA validation");
