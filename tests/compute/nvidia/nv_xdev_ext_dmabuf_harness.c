/* SPDX-License-Identifier: MIT */
/* Dependency boundaries only: actual descriptor bodies come from actual.inc. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
typedef uint32_t NvU32;
typedef uint64_t NvU64;
typedef uint8_t NvU8;
typedef uint32_t NvHandle;
typedef bool NvBool;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned nv_memory_type_t;
#define NV_MEMORY_TYPE_SYSTEM 0
#define NV_MEMORY_TYPE_REGISTERS 1
#define NV_MEMORY_TYPE_FRAMEBUFFER 2
#define NV_MEMORY_TYPE_DEVICE_MMIO 3
#define NV_DMABUF_EXPORT_MAPPING_TYPE_DEFAULT 0
#define NV_DMABUF_EXPORT_MAPPING_TYPE_FORCE_PCIE 1
#define NV_DMA_REMAP_PEER_MMIO_DISABLE 0
#define NV_DMA_REMAP_PEER_MMIO_ENABLE 1
#define XDEV_EXT_PEER_BACKING_MMIO_BAR 1U
#define XDEV_EXT_PEER_BACKING_EXTERNAL 8U
#define XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR 16U
#define PAGE_SIZE 4096U
struct module { unsigned tag; } module;
#define THIS_MODULE (&module)
struct dma_map_ops { void *map_phys, *map_resource; };
struct device { const struct dma_map_ops *dma_ops; };
struct pci_dev { struct device dev; };
typedef struct { unsigned numRanges; void *pRanges; } MemoryArea;
typedef struct { void *os_state; bool coherent, mem_has_struct_page, is_external_gpu; } nv_state_t;
typedef struct { struct pci_dev *pci_dev; } nv_linux_state_t;
#define NV_GET_NVL_FROM_NV_STATE(nv) ((nv_linux_state_t *)(nv)->os_state)
struct mutex { unsigned held; };
static void mutex_lock(struct mutex *m) { if (m->held++) abort(); }
static void mutex_unlock(struct mutex *m) { if (!m->held--) abort(); }
struct dma_buf_ops { unsigned tag; };
static const struct dma_buf_ops nv_dma_buf_ops = { 55 };
struct dma_buf { const struct dma_buf_ops *ops; void *priv; size_t size; };
static NvU32 nv_dma_remap_peer_mmio = NV_DMA_REMAP_PEER_MMIO_ENABLE;
static const struct dma_map_ops *get_dma_ops(struct device *d) { return d->dma_ops; }
struct xdev_ext_peer_dmabuf_desc_ops;
static const struct xdev_ext_peer_dmabuf_desc_ops *descriptor;
static int registration_error, unregister_count;
static int xdev_ext_peer_dmabuf_desc_register(const struct xdev_ext_peer_dmabuf_desc_ops *d)
{ if (registration_error) return registration_error; if (descriptor) return -EEXIST; descriptor = d; return 0; }
static int xdev_ext_peer_dmabuf_desc_unregister(const struct xdev_ext_peer_dmabuf_desc_ops *d)
{ if (descriptor != d) return -ENOENT; descriptor = NULL; unregister_count++; return 0; }
#define WARN_ON(v) ((v) ? (abort(), 1) : 0)
#include "actual.inc"

static unsigned checks;
#define CHECK(v) do { checks++; if (!(v)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #v); return 1; } } while (0)
static struct pci_dev gpu, requester;
static nv_linux_state_t nvl = { .pci_dev = &gpu };
static nv_state_t nv = { .os_state = &nvl };
static nv_dma_buf_file_private_t priv;
static struct dma_buf buf;
static void reset(void)
{
 memset(&priv, 0, sizeof(priv));
 nv.coherent = nv.mem_has_struct_page = nv.is_external_gpu = false;
 nvl.pci_dev = &gpu;
 priv.nv = &nv; priv.total_objects = priv.num_objects = 1;
 priv.total_size = priv.attached_size = 8192;
 priv.map_attrs.cached = true;
 priv.map_attrs.memory_type = NV_MEMORY_TYPE_FRAMEBUFFER;
 buf = (struct dma_buf){ .ops = &nv_dma_buf_ops, .priv = &priv, .size = 8192 };
 requester.dev.dma_ops = NULL;
 nv_dma_remap_peer_mmio = NV_DMA_REMAP_PEER_MMIO_ENABLE;
}
static int check_desc(int expected, unsigned flags)
{
 struct xdev_ext_peer_backing out = { .owner = (void *)1, .flags = 0xdead };
 int rc = descriptor->describe(&buf, &requester, &out);
 CHECK(rc == expected);
 CHECK(out.flags == flags);
 CHECK(out.owner == (expected ? NULL : &gpu));
 CHECK(!priv.lock.held);
 return 0;
}
int main(void)
{
 struct dma_map_ops maps = { .map_phys = (void *)1, .map_resource = (void *)1 };
 struct dma_buf_ops foreign = nv_dma_buf_ops;
 int before;
 CHECK(nv_xdev_ext_dmabuf_init() == 0);
 if (!descriptor) { puts("NVIDIA descriptor is not registered"); return 1; }
 CHECK(descriptor->ops == &nv_dma_buf_ops && descriptor->owner == THIS_MODULE);
 reset(); CHECK(check_desc(0, TEST_DIRECT ? 1 : 17) == 0);
 requester.dev.dma_ops = &maps; CHECK(check_desc(0, 1) == 0);
 nv.is_external_gpu = true; CHECK(check_desc(0, 9) == 0);
 nv_dma_remap_peer_mmio = 0; CHECK(check_desc(0, 25) == 0);
 reset(); requester.dev.dma_ops = &maps;
 if (TEST_PHYS) maps.map_phys = NULL; else maps.map_resource = NULL;
 CHECK(check_desc(0, 17) == 0);
 reset(); buf.ops = &foreign; buf.priv = (void *)1;
 CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 reset(); buf.priv = NULL; CHECK(check_desc(-EINVAL, 0) == 0);
 reset(); priv.nv = NULL; CHECK(check_desc(-ENODEV, 0) == 0);
 reset(); nv.os_state = NULL; CHECK(check_desc(-ENODEV, 0) == 0); nv.os_state = &nvl;
 reset(); nvl.pci_dev = NULL; CHECK(check_desc(-ENODEV, 0) == 0);
 reset(); priv.total_objects = 0; CHECK(check_desc(-EINVAL, 0) == 0);
 reset(); priv.num_objects = 0; CHECK(check_desc(-EINVAL, 0) == 0);
 reset(); priv.attached_size = 4096; CHECK(check_desc(-EINVAL, 0) == 0);
 reset(); priv.total_size = 4096; CHECK(check_desc(-EINVAL, 0) == 0);
 reset(); priv.total_size = priv.attached_size = buf.size = 0; CHECK(check_desc(-EINVAL, 0) == 0);
 reset(); priv.total_size = priv.attached_size = buf.size = 8191; CHECK(check_desc(-EINVAL, 0) == 0);
 reset(); priv.map_attrs.cached = false; CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 for (unsigned type = 0; type <= 3; type++) {
  if (type == NV_MEMORY_TYPE_FRAMEBUFFER) continue;
  reset(); priv.map_attrs.memory_type = type; CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 }
 reset(); priv.map_attrs.read_only_mem = true; CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 reset(); nv.coherent = true; CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 reset(); nv.mem_has_struct_page = true; CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 reset(); nv.coherent = nv.mem_has_struct_page = true; CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 reset(); priv.mapping_type = NV_DMABUF_EXPORT_MAPPING_TYPE_FORCE_PCIE;
 CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 reset(); priv.mapping_type = 2; CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 reset(); priv.skip_iommu = true; CHECK(check_desc(-EOPNOTSUPP, 0) == 0);
 reset(); struct xdev_ext_peer_backing out;
 CHECK(descriptor->describe(NULL, &requester, &out) == -EINVAL);
 CHECK(descriptor->describe(&buf, NULL, &out) == -EINVAL);
 CHECK(descriptor->describe(&buf, &requester, NULL) == -EINVAL);
 before = unregister_count;
 nv_xdev_ext_dmabuf_exit(); CHECK(!descriptor && unregister_count == before + 1);
 nv_xdev_ext_dmabuf_exit(); CHECK(unregister_count == before + 1);
 registration_error = -ENOMEM;
 CHECK(nv_xdev_ext_dmabuf_init() == -ENOMEM);
 nv_xdev_ext_dmabuf_exit(); CHECK(!descriptor && unregister_count == before + 1);
 registration_error = 0;
 CHECK(nv_xdev_ext_dmabuf_init() == 0 && descriptor);
 nv_xdev_ext_dmabuf_exit(); CHECK(!descriptor);
 printf("PASS %u descriptor and lifecycle assertions\n", checks);
 return 0;
}
