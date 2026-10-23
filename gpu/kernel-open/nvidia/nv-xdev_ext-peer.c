/* SPDX-License-Identifier: MIT */
/* Real persistent VRAM and per-PCI-device peer DMA mappings. No host pages,
 * CPU physical address conversion or memcpy substitute participates here.
 * Persistent API holds allocation lifetime until an explicit, drained unpin;
 * it does not use the revocable get_pages callback API.
 */
#define __NO_VERSION__
#include "os-interface.h"
#include "nv-linux.h"
#include "nv-lock.h"
#include "nv-p2p.h"
#include "nv-xdev_ext-peer.h"
#include <linux/xdev_ext_peer.h>
struct nv_xdev_ext_peer_allocation {
 struct nvidia_p2p_page_table *pages;
 u64 va;
 struct list_head quarantine;
};
static LIST_HEAD(nv_xdev_ext_peer_quarantined);
static DEFINE_MUTEX(nv_xdev_ext_peer_quarantine_lock);
static void nv_xdev_ext_peer_quarantine(struct nv_xdev_ext_peer_allocation *a)
{
 __module_get(THIS_MODULE);
 mutex_lock(&nv_xdev_ext_peer_quarantine_lock);
 list_add_tail(&a->quarantine, &nv_xdev_ext_peer_quarantined);
 mutex_unlock(&nv_xdev_ext_peer_quarantine_lock);
}
static int nv_xdev_ext_peer_pin(struct file *f, u64 va, u64 len, void **out)
{
 nv_linux_file_private_t *nvlfp = NV_GET_LINUX_FILE_PRIVATE(f);
 nv_linux_state_t *nvl;
 struct nv_xdev_ext_peer_allocation *a;
 nvidia_stack_t *sp = NULL;
 const NvU8 *uuid;
 int rc;
 if (!out) return -EINVAL;
 *out = NULL;
 if ((va | len) & 65535 || !len || nv_is_control_device(NV_FILE_INODE(f)))
  return -EINVAL;
 rc = nv_wait_open_complete_interruptible(nvlfp);
 if (rc) return rc;
 nvl = nvlfp->nvptr;
 if (nvlfp->open_rc || !nvl) return -ENODEV;
 a = kzalloc(sizeof(*a), GFP_KERNEL);
 if (!a) return -ENOMEM;
 a->va = va;
 rc = nv_down_read_interruptible(&nv_system_pm_lock);
 if (rc) goto free;
 rc = nv_kmem_cache_alloc_stack(&sp);
 if (rc) goto unlock;
 uuid = rm_get_gpu_uuid_raw(sp, NV_STATE_PTR(nvl));
 if (!uuid) { rc = -ENODEV; goto stack; }
 /* NVIDIA resolves va in the calling process's CUDA VA space, verifies
  * pinned GPU-resident allocation type and holds the allocation itself.
  */
 rc = nvidia_p2p_get_pages_persistent(va, len, &a->pages, NVIDIA_P2P_FLAGS_DEFAULT);
 if (rc) goto stack;
 if (!NVIDIA_P2P_PAGE_TABLE_VERSION_COMPATIBLE(a->pages) ||
     !a->pages->gpu_uuid || memcmp(uuid, a->pages->gpu_uuid, NVIDIA_P2P_GPU_UUID_LEN)) {
  rc = -EXDEV;
  /* A failed put cannot justify losing a persistent allocation handle. */
  if (nvidia_p2p_put_pages_persistent(va, a->pages, NVIDIA_P2P_FLAGS_DEFAULT)) {
   nv_xdev_ext_peer_quarantine(a);
   nv_printf(NV_DBG_ERRORS, "NVRM: XDEV_EXT peer pin cleanup failed; retaining allocation\n");
   a = NULL;
  }
  goto stack;
 }
 *out = a;
stack:
 nv_kmem_cache_free_stack(sp);
unlock:
 up_read(&nv_system_pm_lock);
free:
 if (rc) kfree(a);
 return rc;
}
static int nv_xdev_ext_peer_unpin(void *private)
{
 struct nv_xdev_ext_peer_allocation *a = private;
 int rc;
 down_read(&nv_system_pm_lock);
 rc = nvidia_p2p_put_pages_persistent(a->va, a->pages, NVIDIA_P2P_FLAGS_DEFAULT);
 up_read(&nv_system_pm_lock);
 if (!rc) kfree(a);
 return rc;
}
static int nv_xdev_ext_peer_map(void *private, struct pci_dev *peer,
                              struct xdev_ext_peer_dma *out)
{
 struct nv_xdev_ext_peer_allocation *a = private;
 struct nvidia_p2p_dma_mapping *m = NULL;
 int rc;
 down_read(&nv_system_pm_lock);
 rc = nvidia_p2p_dma_map_pages(peer, a->pages, &m);
 up_read(&nv_system_pm_lock);
 if (rc) return rc;
 /* Returning malformed geometry lets the common layer preserve the handle
  * and quarantine if even the native unmap fails.
  */
 out->private = m;
 out->addresses = m->dma_addresses;
 out->entries = m->entries;
 if (!NVIDIA_P2P_DMA_MAPPING_VERSION_COMPATIBLE(m)) out->page_shift = 0;
 else if (m->page_size_type == NVIDIA_P2P_PAGE_SIZE_64KB) out->page_shift = 16;
 else if (m->page_size_type == NVIDIA_P2P_PAGE_SIZE_128KB) out->page_shift = 17;
 else out->page_shift = 0;
 return 0;
}
static int nv_xdev_ext_peer_unmap(void *private, struct pci_dev *peer,
                                struct xdev_ext_peer_dma *dma)
{
 struct nv_xdev_ext_peer_allocation *a = private;
 int rc;
 down_read(&nv_system_pm_lock);
 rc = nvidia_p2p_dma_unmap_pages(peer, a->pages, dma->private);
 up_read(&nv_system_pm_lock);
 return rc;
}
static struct xdev_ext_peer_provider_ops nv_xdev_ext_peer_ops = {
 .owner = THIS_MODULE,
 .pin = nv_xdev_ext_peer_pin, .unpin = nv_xdev_ext_peer_unpin,
 .map = nv_xdev_ext_peer_map, .unmap = nv_xdev_ext_peer_unmap,
};
static bool nv_xdev_ext_peer_registered;
void nv_xdev_ext_peer_init(const struct file_operations *fops)
{
 int rc;
 nv_xdev_ext_peer_ops.fops = fops;
 rc = xdev_ext_peer_provider_register(&nv_xdev_ext_peer_ops);
 if (rc) nv_printf(NV_DBG_ERRORS, "NVRM: XDEV_EXT peer provider registration failed: %d\n", rc);
 else nv_xdev_ext_peer_registered = true;
}
void nv_xdev_ext_peer_exit(void)
{
 if (nv_xdev_ext_peer_registered)
  WARN_ON(xdev_ext_peer_provider_unregister(&nv_xdev_ext_peer_ops));
}
