// SPDX-License-Identifier: GPL-2.0
/* Kernel services for the requester unit: DMA API and PCI recorder, PEER
 * provider stand-ins and allocations. No production algorithm is restated. */
#include "shim.h"
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include "boundary.h"

#define RH_WINDOW_PAGES 64U

struct rh_event rh_log[RH_EVENTS];
unsigned rh_events, rh_fail_map_at, rh_live_allocs, shim_spins, shim_warnings;
static unsigned rh_maps;
static struct file rh_authority = { .id = 1 };
struct pci_dev rh_gpu = { .dev = { .dma_coherent = true, .id = 9 } };

static void record(struct rh_event e)
{
	assert(rh_events < RH_EVENTS);
	rh_log[rh_events++] = e;
}

dma_addr_t rh_window(const struct device *dev, unsigned index, size_t offset)
{
	assert(index < RH_WINDOW_PAGES && offset < PAGE_SIZE);
	return 0x100000000ULL * (dev->id + 1) +
	       (dma_addr_t)(RH_WINDOW_PAGES - 1 - index) * PAGE_SIZE + offset;
}

static void (*rh_pending)(void);
static unsigned rh_pending_reads;
unsigned rh_scheduled_runs;

void rh_reset(void)
{
	rh_events = 0;
	rh_maps = 0;
	rh_fail_map_at = 0;
	rh_pending = NULL;
	rh_pending_reads = 0;
	rh_scheduled_runs = 0;
	memset(rh_log, 0, sizeof(rh_log));
}

void rh_schedule_after_reads(unsigned n, void (*fn)(void))
{
	assert(n && fn && !rh_pending);
	rh_pending_reads = n;
	rh_pending = fn;
}

void rh_after_shared_read(void)
{
	void (*fn)(void) = rh_pending;

	if (!fn || --rh_pending_reads)
		return;
	rh_pending = NULL;
	rh_scheduled_runs++;
	fn();
}

unsigned rh_count(enum rh_kind kind)
{
	unsigned i, n = 0;

	for (i = 0; i < rh_events; i++)
		n += rh_log[i].kind == kind;
	return n;
}

dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page, size_t offset, size_t size,
			      enum dma_data_direction dir, unsigned long attrs)
{
	dma_addr_t addr = ++rh_maps == rh_fail_map_at ? DMA_MAPPING_ERROR :
			  rh_window(dev, page->index, offset);

	record((struct rh_event){ .kind = RH_MAP, .dev = dev, .page = page, .addr = addr,
		.offset = offset, .size = size, .dir = dir, .attrs = attrs });
	return addr;
}

void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
			  enum dma_data_direction dir, unsigned long attrs)
{
	record((struct rh_event){ .kind = RH_UNMAP, .dev = dev, .addr = addr, .size = size,
		.dir = dir, .attrs = attrs });
}

int dma_mapping_error(struct device *dev, dma_addr_t addr)
{
	(void)dev;
	return addr == DMA_MAPPING_ERROR;
}

/* As in dma-direct: a non-coherent device or a forced bounce needs CPU sync. */
bool dma_need_sync(struct device *dev, dma_addr_t addr)
{
	(void)addr;
	return !dev->dma_coherent || dev->force_bounce;
}

void dma_sync_single_for_device(struct device *dev, dma_addr_t addr, size_t size,
				enum dma_data_direction dir)
{
	record((struct rh_event){ .kind = RH_SYNC_DEVICE, .dev = dev, .addr = addr, .size = size,
		.dir = dir });
}

void dma_sync_single_for_cpu(struct device *dev, dma_addr_t addr, size_t size,
			     enum dma_data_direction dir)
{
	record((struct rh_event){ .kind = RH_SYNC_CPU, .dev = dev, .addr = addr, .size = size,
		.dir = dir });
}

struct pci_dev *pci_dev_get(struct pci_dev *p)
{
	assert(p);
	p->refs++;
	return p;
}

void pci_dev_put(struct pci_dev *p)
{
	if (!p)
		return;
	assert(p->refs);
	p->refs--;
}

int pci_p2pdma_distance(struct pci_dev *provider, struct device *client, bool verbose)
{
	(void)provider; (void)client; (void)verbose;
	return 0;
}

bool is_swiotlb_force_bounce(struct device *d) { return d->force_bounce; }
bool use_dma_iommu(struct device *d) { return d->iommu; }
const void *get_dma_ops(struct device *d) { (void)d; return NULL; }

void *shim_alloc(size_t n, bool zero)
{
	void *p = malloc(n ? n : 1);

	assert(p);
	if (zero)
		memset(p, 0, n ? n : 1);
	rh_live_allocs++;
	return p;
}

void shim_free(const void *p)
{
	if (!p)
		return;
	assert(rh_live_allocs);
	rh_live_allocs--;
	free((void *)p);
}

struct xdev_ext_mech_pool *xdev_ext_mech_session_pool(struct xdev_ext_mech_session *s)
{
	return &s->pool;
}

struct file *xdev_ext_peer_mech_pool_file(struct xdev_ext_mech_pool *pool)
{
	return pool && pool->kind == XDEV_EXT_MECH_POOL_PEER ? &rh_authority : NULL;
}

u64 xdev_ext_peer_mech_pool_generation(struct xdev_ext_mech_pool *pool)
{
	return xdev_ext_peer_mech_pool_file(pool) ? 17 : 0;
}

int xdev_ext_peer_file_describe(struct file *authority, struct pci_dev *requester,
				struct xdev_ext_peer_backing *b)
{
	assert(authority == &rh_authority);
	record((struct rh_event){ .kind = RH_DESCRIBE, .dev = &requester->dev });
	*b = (struct xdev_ext_peer_backing){ .owner = &rh_gpu, .flags = XDEV_EXT_PEER_BACKING_MMIO_BAR };
	return 0;
}

int xdev_ext_peer_file_premap(struct file *authority, struct pci_dev *requester)
{
	assert(authority == &rh_authority);
	record((struct rh_event){ .kind = RH_PREMAP, .dev = &requester->dev });
	return 0;
}

int xdev_ext_peer_file_acquire(struct file *f, struct pci_dev *p, u64 generation, u64 off,
			       u32 len, enum dma_data_direction dir, struct xdev_ext_peer_fd_lease *l)
{
	(void)f; (void)p; (void)generation; (void)off; (void)len; (void)dir; (void)l;
	return -EOPNOTSUPP;
}
