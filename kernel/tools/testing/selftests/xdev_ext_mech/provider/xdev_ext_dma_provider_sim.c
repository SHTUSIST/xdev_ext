// SPDX-License-Identifier: GPL-2.0
/* Independent dynamically registered DMA provider. CPU memcpy simulation ONLY.
 * This is deliberately not the CE backend and makes no physical DMA claim.
 * Native providers replace this file through the exact same production ABI.
 */
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/xdev_ext_mech.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include "dma_provider_fixture.h"

/* Dedicated guest fault controls; change only between fixture invocations. */
static unsigned int fail_mode, delay_us, stale_replays;
module_param(fail_mode, uint, 0644);
MODULE_PARM_DESC(fail_mode, "0 normal, 1 reject before accept, 2 short, 3 ambiguous");
module_param(delay_us, uint, 0644);
module_param(stale_replays, uint, 0644);
MODULE_PARM_DESC(stale_replays, "0..2 old accepted-ticket replays before the current completion");

struct sim_device {
 void *window;
 struct mutex lock;
 struct dma_fixture_stats stats;
 struct { struct xdev_ext_dma_cookie *cookie; u64 ticket; } history[32];
 u32 history_next;
};
struct sim_region { struct sim_device *dev; u64 base; };
struct sim_host { void *addr; u64 bytes; struct sim_device *dev; };
struct sim_request {
 struct work_struct work;
 struct xdev_ext_dma_cookie *cookie;
 u64 ticket, old_ticket;
 struct sim_region *region;
 struct sim_host *host;
 u32 direction, n;
 struct xdev_ext_dma_xfer x[];
};
static struct workqueue_struct *sim_wq;
static bool span(u64 off, u64 len, u64 capacity)
{
 u64 end;
 return !check_add_overflow(off,len,&end) && end<=capacity;
}
static int sim_open(struct inode *inode, struct file *file)
{
 struct sim_device *d=kzalloc(sizeof(*d),GFP_KERNEL);
 if (!d) return -ENOMEM;
 d->window=vmalloc_user(DMA_FIXTURE_MAP_BYTES);
 if (!d->window) { kfree(d); return -ENOMEM; }
 mutex_init(&d->lock);
 file->private_data=d;
 return 0;
}
static int sim_release(struct inode *inode, struct file *file)
{
 struct sim_device *d=file->private_data;
 /* Stages retain file and module refs until all accepted work completes. */
 vfree(d->window); kfree(d); return 0;
}
static int sim_mmap(struct file *file, struct vm_area_struct *vma)
{
 struct sim_device *d=file->private_data;
 if (vma->vm_pgoff || vma->vm_end-vma->vm_start!=DMA_FIXTURE_MAP_BYTES)
  return -EINVAL;
 return remap_vmalloc_range(vma,d->window,0);
}
static long sim_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
 struct sim_device *d=file->private_data;
 struct dma_fixture_stats snapshot;
 if (cmd!=DMA_FIXTURE_STATS) return -ENOTTY;
 mutex_lock(&d->lock); snapshot=d->stats; mutex_unlock(&d->lock);
 return copy_to_user((void __user *)arg,&snapshot,sizeof(snapshot)) ? -EFAULT : 0;
}
static const struct file_operations sim_fops={
 .owner=THIS_MODULE,.open=sim_open,.release=sim_release,
 .mmap=sim_mmap,.unlocked_ioctl=sim_ioctl,
};
static struct miscdevice sim_misc={
 .minor=MISC_DYNAMIC_MINOR,.name="xdev_ext_dma_provider_sim",.fops=&sim_fops,.mode=0600,
};
static int sim_bind_region(struct file *file,u64 off,u64 len,struct xdev_ext_dma_region *out)
{
 struct sim_device *d=file->private_data;
 struct sim_region *r;
 /* Fixture has exactly two independently bound windows. */
 if (len!=DMA_FIXTURE_WINDOW_BYTES ||
     (off!=DMA_FIXTURE_INPUT_OFF && off!=DMA_FIXTURE_OUTPUT_OFF)) return -EINVAL;
 r=kzalloc(sizeof(*r),GFP_KERNEL);
 if (!r) return -ENOMEM;
 r->dev=d; r->base=off;
 out->priv=r; out->len=len; out->segment_size=4096;
 out->max_entry_len=4096; out->alignment=1;
 out->directions=XDEV_EXT_DMA_DIR_TO_DEVICE|XDEV_EXT_DMA_DIR_FROM_DEVICE;
 mutex_lock(&d->lock); d->stats.region_binds++; mutex_unlock(&d->lock);
 return 0;
}
static void sim_unbind_region(struct xdev_ext_dma_region *region)
{
 struct sim_region *r=region->priv;
 mutex_lock(&r->dev->lock); r->dev->stats.region_unbinds++; mutex_unlock(&r->dev->lock);
 kfree(r);
}
static int sim_bind_host(struct xdev_ext_dma_region *region,struct page **pages,u32 nr,void **host)
{
 struct sim_region *r=region->priv;
 struct sim_host *h=kzalloc(sizeof(*h),GFP_KERNEL);
 if (!h) return -ENOMEM;
 h->addr=vmap(pages,nr,VM_MAP,PAGE_KERNEL);
 if (!h->addr) { kfree(h); return -ENOMEM; }
 h->bytes=(u64)nr<<PAGE_SHIFT; h->dev=r->dev;
 mutex_lock(&h->dev->lock); h->dev->stats.host_binds++; mutex_unlock(&h->dev->lock);
 *host=h; return 0;
}
static void sim_unbind_host(void *host)
{
 struct sim_host *h=host;
 mutex_lock(&h->dev->lock); h->dev->stats.host_unbinds++; mutex_unlock(&h->dev->lock);
 vunmap(h->addr); kfree(h);
}
static void sim_work(struct work_struct *work)
{
 struct sim_request *r=container_of(work,struct sim_request,work);
 struct sim_device *d=r->region->dev;
 u64 bytes=0;
 u32 i, replays=min(READ_ONCE(stale_replays),2U);
 unsigned int delay=min(READ_ONCE(delay_us),1000000U);
 unsigned int mode=READ_ONCE(fail_mode);
 if (delay) usleep_range(delay,delay+100);
 for (i=0;i<r->n;i++) {
  void *device=d->window+r->region->base+r->x[i].device_off;
  void *host=r->host->addr+r->x[i].host_byte_off;
  if (r->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE) memcpy(host,device,r->x[i].len);
  else memcpy(device,host,r->x[i].len);
  bytes+=r->x[i].len;
 }
 mutex_lock(&d->lock);
 d->stats.completed++; d->stats.pending--; d->stats.bytes+=bytes;
 if (r->direction==XDEV_EXT_MECH_DIR_FROM_DEVICE) d->stats.from_device++;
 else d->stats.to_device++;
 mutex_unlock(&d->lock);
 /* Every replay happens while this accepted request still owns its cookie.
  * The final callback may release the cookie; never touch it afterwards. */
 if (r->old_ticket) for (i=0;i<replays;i++) {
  mutex_lock(&d->lock); d->stats.stale_callbacks++; mutex_unlock(&d->lock);
  xdev_ext_dma_complete(r->cookie,r->old_ticket,-ESTALE,true,0);
 }
 xdev_ext_dma_complete(r->cookie,r->ticket,mode==3 ? -EIO : 0,true,
                      mode==2 && bytes ? bytes-1 : bytes);
 kfree(r);
}
static int sim_submit(struct xdev_ext_dma_region *region,void *host,u32 direction,
                      const struct xdev_ext_dma_xfer *x,u32 n,
                      struct xdev_ext_dma_cookie *cookie,u64 ticket)
{
 struct sim_region *reg=region->priv;
 struct sim_host *h=host;
 struct sim_request *r;
 u32 i;
 if (!n || n>32 || (direction!=XDEV_EXT_MECH_DIR_FROM_DEVICE &&
                    direction!=XDEV_EXT_MECH_DIR_TO_DEVICE)) return -EINVAL;
 /* Defense in depth: reject the whole list before moving a single byte. */
 for (i=0;i<n;i++) if (!span(x[i].device_off,x[i].len,region->len) ||
                           !span(x[i].host_byte_off,x[i].len,h->bytes)) return -ERANGE;
 if (READ_ONCE(fail_mode)==1) return -EIO;
 r=kzalloc(struct_size(r,x,n),GFP_KERNEL);
 if (!r) return -ENOMEM;
 INIT_WORK(&r->work,sim_work);
 r->cookie=cookie; r->ticket=ticket; r->region=reg; r->host=h;
 r->direction=direction; r->n=n; memcpy(r->x,x,n*sizeof(*x));
 mutex_lock(&reg->dev->lock);
 reg->dev->stats.accepted++; reg->dev->stats.pending++;
 reg->dev->stats.peak_pending=max(reg->dev->stats.peak_pending,reg->dev->stats.pending);
 for (i=0;i<ARRAY_SIZE(reg->dev->history);i++)
  if (reg->dev->history[i].cookie==cookie) {
   r->old_ticket=reg->dev->history[i].ticket; break;
  }
 if (i==ARRAY_SIZE(reg->dev->history)) i=reg->dev->history_next++%ARRAY_SIZE(reg->dev->history);
 reg->dev->history[i].cookie=cookie; reg->dev->history[i].ticket=ticket;
 mutex_unlock(&reg->dev->lock);
 queue_work(sim_wq,&r->work); return 0;
}
static const struct xdev_ext_dma_provider_ops sim_ops={
 .owner=THIS_MODULE,.fops=&sim_fops,.bind_region=sim_bind_region,
 .unbind_region=sim_unbind_region,.bind_host=sim_bind_host,
 .unbind_host=sim_unbind_host,.submit=sim_submit,
};
static int __init sim_init(void)
{
 int err;
 sim_wq=alloc_workqueue("xdev_ext_dma_provider_sim",WQ_UNBOUND,0);
 if (!sim_wq) return -ENOMEM;
 err=misc_register(&sim_misc); if (err) goto free_queue;
 err=xdev_ext_dma_provider_register(&sim_ops); if (!err) return 0;
 misc_deregister(&sim_misc);
free_queue: destroy_workqueue(sim_wq); return err;
}
static void __exit sim_exit(void)
{
 xdev_ext_dma_provider_unregister(&sim_ops);
 misc_deregister(&sim_misc); destroy_workqueue(sim_wq);
}
module_init(sim_init); module_exit(sim_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Independent DMA provider CPU memcpy fixture; not physical DMA");
