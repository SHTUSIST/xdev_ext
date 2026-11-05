/* SPDX-License-Identifier: GPL-2.0 */
/*
 * --pool host: kernel declarations the production requester unit
 * (io_uring/family/xdev_ext_requester.c) reaches in the XDOMAIN stack
 * environment, beyond stack_kernel_compat.h.  The DMA API is implemented by
 * chain_boundary.c, which maps a page into the requester's own window.
 * The PEER branch of the requester is compiled but not reached here.
 */
#ifndef CHAIN_HOST_ENV_H
#define CHAIN_HOST_ENV_H
#define CAP_SYS_ADMIN 21
#define capable(c) (true)
#define DMA_ATTR_SKIP_CPU_SYNC (1UL << 5)
#define DMA_MAPPING_ERROR (~(dma_addr_t)0)
static inline void atomic_inc(atomic_t *a) { a->n++; }
static inline void atomic_dec(atomic_t *a) { a->n--; }
#define smp_mb__before_atomic() __atomic_thread_fence(__ATOMIC_SEQ_CST)
struct page;
dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page, size_t offset, size_t size,
			      enum dma_data_direction dir, unsigned long attrs);
void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
			  enum dma_data_direction dir, unsigned long attrs);
int dma_mapping_error(struct device *dev, dma_addr_t addr);
bool dma_need_sync(struct device *dev, dma_addr_t addr);
void dma_sync_single_for_device(struct device *dev, dma_addr_t addr, size_t size,
				enum dma_data_direction dir);
void dma_sync_single_for_cpu(struct device *dev, dma_addr_t addr, size_t size,
			     enum dma_data_direction dir);
int pci_p2pdma_distance(struct pci_dev *provider, struct device *client, bool verbose);
bool is_swiotlb_force_bounce(struct device *dev);
bool use_dma_iommu(struct device *dev);
const void *get_dma_ops(struct device *dev);
static inline int pci_domain_nr(struct pci_bus *bus) { (void)bus; return 0; }
#endif
