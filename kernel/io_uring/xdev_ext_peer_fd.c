// SPDX-License-Identifier: GPL-2.0
/* User-visible allocation authority. This fd contains VRAM, never a UMEM
 * host-page pool. PCI mappings are cached until the last allocation fd closes.
 */
#include <linux/anon_inodes.h>
#include <linux/compat.h>
#include <linux/capability.h>
#include <linux/list.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/xdev_ext_peer.h>
#include <uapi/linux/xdev_ext_peer.h>
struct xdev_ext_peer_fd {
 struct mutex lock;
 struct xdev_ext_peer_region *region;
 struct list_head maps;
};
struct xdev_ext_peer_fd_map {
 struct list_head node;
 struct pci_dev *peer;
 struct xdev_ext_peer_mapping *mapping;
};
static int xdev_ext_peer_fd_close(struct inode *inode, struct file *file)
{
 struct xdev_ext_peer_fd *p = file->private_data;
 struct xdev_ext_peer_fd_map *m, *next;
 bool retained = false;
 (void)inode;
 xdev_ext_peer_invalidate(p->region);
 list_for_each_entry_safe(m, next, &p->maps, node) {
  if (xdev_ext_peer_unmap(m->mapping)) retained = true;
  list_del(&m->node); kfree(m);
 }
 if (!retained) xdev_ext_peer_unpin(p->region);
 /* On uncertain native ownership the region itself retains GPU file, provider
  * module, peer PCI reference and the persistent allocation indefinitely.
  */
 kfree(p);
 return 0;
}
static const struct file_operations xdev_ext_peer_allocation_fops = {
 .owner = THIS_MODULE, .release = xdev_ext_peer_fd_close,
};
int xdev_ext_peer_file_acquire(struct file *file, struct pci_dev *peer, u64 generation,
                            u64 offset, u32 len, enum dma_data_direction dir,
                            struct xdev_ext_peer_fd_lease *handle)
{
 struct xdev_ext_peer_fd *p;
 struct xdev_ext_peer_fd_map *m;
 int ret;
 if (!handle || handle->file || handle->lease.mapping) return -EINVAL;
 if (!file) return -EBADF;
 if (file->f_op != &xdev_ext_peer_allocation_fops) return -EINVAL;
 get_file(file);
 p = file->private_data;
 mutex_lock(&p->lock);
 list_for_each_entry(m, &p->maps, node)
  if (m->peer == peer) goto acquire;
 m = kzalloc(sizeof(*m), GFP_KERNEL);
 if (!m) { ret = -ENOMEM; goto unlock; }
 ret = xdev_ext_peer_map(p->region, peer, DMA_BIDIRECTIONAL, &m->mapping);
 if (ret) { kfree(m); goto unlock; }
 m->peer = peer; list_add_tail(&m->node, &p->maps);
acquire:
 ret = xdev_ext_peer_acquire(m->mapping, generation, offset, len, dir, &handle->lease);
 if (!ret) handle->file = file;
unlock:
 mutex_unlock(&p->lock);
 if (ret) fput(file);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_file_acquire);
int xdev_ext_peer_fd_acquire(int fd, struct pci_dev *peer, u64 generation,
                            u64 offset, u32 len, enum dma_data_direction dir,
                            struct xdev_ext_peer_fd_lease *handle)
{
 struct file *file = fget(fd);
 int ret;
 if (!file) return -EBADF;
 ret = xdev_ext_peer_file_acquire(file, peer, generation, offset, len, dir, handle);
 fput(file);
 return ret;
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_fd_acquire);
void xdev_ext_peer_fd_release(struct xdev_ext_peer_fd_lease *handle, bool quiesced)
{
 struct file *file;
 if (!handle || !handle->file) return;
 file = handle->file;
 if (xdev_ext_peer_release(&handle->lease, handle->lease.ticket, quiesced))
  return;
 handle->file = NULL;
 fput(file);
}
EXPORT_SYMBOL_GPL(xdev_ext_peer_fd_release);
static long xdev_ext_peer_ctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
 struct xdev_ext_peer_register u;
 struct xdev_ext_peer_fd *p;
 struct file *gpu, *allocation;
 int fd, ret;
 (void)file;
 if (cmd == XDEV_EXT_PEER_NET_TX) return xdev_ext_peer_net_ioctl(arg);
 if (cmd != XDEV_EXT_PEER_REGISTER) return -ENOTTY;
 if (!capable(CAP_SYS_RAWIO)) return -EPERM;
 if (copy_from_user(&u, (void __user *)arg, sizeof(u))) return -EFAULT;
 if (u.flags || u.generation) return -EINVAL;
 gpu = fget(u.gpu_fd);
 if (!gpu) return -EBADF;
 p = kzalloc(sizeof(*p), GFP_KERNEL);
 if (!p) { fput(gpu); return -ENOMEM; }
 ret = xdev_ext_peer_pin(gpu, u.gpu_va, u.len, &p->region);
 fput(gpu);
 if (ret) { kfree(p); return ret; }
 mutex_init(&p->lock); INIT_LIST_HEAD(&p->maps);
 allocation = anon_inode_getfile("xdev_ext_peer", &xdev_ext_peer_allocation_fops, p, O_RDWR);
 if (IS_ERR(allocation)) {
  ret = PTR_ERR(allocation); xdev_ext_peer_unpin(p->region); kfree(p); return ret;
 }
 fd = get_unused_fd_flags(O_CLOEXEC);
 if (fd < 0) { fput(allocation); return fd; }
 u.generation = xdev_ext_peer_generation(p->region);
 if (copy_to_user((void __user *)arg, &u, sizeof(u))) {
  put_unused_fd(fd); fput(allocation); return -EFAULT;
 }
 fd_install(fd, allocation);
 return fd;
}
static const struct file_operations xdev_ext_peer_ctl_fops = {
 .owner = THIS_MODULE, .unlocked_ioctl = xdev_ext_peer_ctl_ioctl,
 .compat_ioctl = compat_ptr_ioctl,
};
static struct miscdevice xdev_ext_peer_ctl = {
 .minor = MISC_DYNAMIC_MINOR, .name = "xdev_ext_peer", .mode = 0600,
 .fops = &xdev_ext_peer_ctl_fops,
};
static int __init xdev_ext_peer_fd_init(void) { return misc_register(&xdev_ext_peer_ctl); }
late_initcall(xdev_ext_peer_fd_init);
