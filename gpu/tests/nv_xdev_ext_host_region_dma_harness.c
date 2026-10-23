/* SPDX-License-Identifier: MIT */
/*
 * Host fixture for the actual nv_pin_host_region(), nv_unpin_host_region()
 * and nv_host_region_dma_map() bodies (G2, ioctl path).  GUP, quota charge,
 * mm reference and the DMA-mapping API are stubs with counters; nothing is
 * pinned or mapped.  HAVE_DMA_MAP is set by the runner when the production
 * file defines nv_host_region_dma_map().
 */
#include <limits.h>
#include <stddef.h>
#include "nv_xdev_ext_host_env.h"

#ifndef HAVE_DMA_MAP
#define HAVE_DMA_MAP 0
#endif
#if defined(NV_XDEV_EXT_CE_PHYS_ADDR)
#define VARIANT_IOVA 0
#else
#define VARIANT_IOVA 1
#endif

typedef uint32_t u32;
typedef uint64_t u64;
typedef u64 dma_addr_t;
typedef unsigned int gfp_t;
#define unlikely(x) (x)
#define likely(x) (x)
#define GFP_KERNEL 0u
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1UL))
#define FOLL_WRITE 1
#define FOLL_LONGTERM 2
#define NV_P2P_UMEM_MAX_PIN_SIZE (1ULL << 40)
#define NV_P2P_UMEM_MAX_PIN_PAGES (1UL << 28)
#ifndef NV_P2P_UMEM_STRICT_SECURITY_CHECKS
#define NV_P2P_UMEM_STRICT_SECURITY_CHECKS 1
#endif
#define NV_DBG_ERRORS 4
#define NV_DBG_INFO 1
#define nv_printf(...) ((void)0)
#define WARN_ON(c) ({ int w_ = !!(c); w_; })
#define WARN_ON_ONCE(c) (!!(c))

struct page { unsigned int index; };
struct device { int translated; };
struct list_head { void *next, *prev; };
struct mm_struct { int refs; };
static struct mm_struct host_mm;
static struct { struct mm_struct *mm; } host_current = { &host_mm };
#define current (&host_current)
#define mmgrab(m) ((void)((m)->refs++))
#define mmdrop(m) ((void)((m)->refs--))

static struct {
	unsigned int live, charges, uncharges, pins, unpins, dirty;
	unsigned int dma_map, dma_unmap, sg_alloc, sg_free, bad_dir, map_fail;
	struct device *dma_dev;
	char order[256];
	u64 iova[64];
} F;
static struct page pages_store[64];

static void order(const char *s)
{
	if (strlen(F.order) + strlen(s) + 2 < sizeof(F.order)) {
		strcat(F.order, s);
		strcat(F.order, " ");
	}
}
static void *harness_alloc(size_t n) { F.live++; return calloc(1, n ? n : 1); }
static void harness_free(void *p) { if (p) { F.live--; free(p); } }
#define kzalloc(n, g) harness_alloc(n)
#define kmalloc(n, g) harness_alloc(n)
#define kmalloc_array(n, s, g) harness_alloc((size_t)(n) * (s))
#define kcalloc(n, s, g) harness_alloc((size_t)(n) * (s))
#define kvmalloc_array(n, s, g) harness_alloc((size_t)(n) * (s))
#define vmalloc(n) harness_alloc(n)
#define vzalloc(n) harness_alloc(n)
#define kfree(p) harness_free(p)
#define vfree(p) harness_free(p)
#define kvfree(p) harness_free(p)

struct nv_xdev_ext_pin_charge_ops { int unused; };
static const struct nv_xdev_ext_pin_charge_ops nv_p2p_umem_pin_charge_ops;
static NV_STATUS nv_xdev_ext_pin_charge(const struct nv_xdev_ext_pin_charge_ops *o, void *mm,
				   NvU64 b, NvU32 p)
{ (void)o; (void)mm; (void)b; (void)p; F.charges++; return NV_OK; }
static NV_STATUS nv_xdev_ext_pin_uncharge(const struct nv_xdev_ext_pin_charge_ops *o, void *mm,
				     NvU64 b, NvU32 p)
{ (void)o; (void)mm; (void)b; (void)p; F.uncharges++; return NV_OK; }
static void nv_mmap_read_lock(struct mm_struct *mm) { (void)mm; }
static void nv_mmap_read_unlock(struct mm_struct *mm) { (void)mm; }
static int host_pin(unsigned long start, unsigned int n, unsigned int flags, struct page **pg)
{
	unsigned int i;
	(void)start; (void)flags;
	for (i = 0; i < n && i < 64; i++) {
		pages_store[i].index = i;
		pg[i] = &pages_store[i];
	}
	F.pins += n;
	return (int)n;
}
#define NV_PIN_USER_PAGES(s, n, f, p) host_pin(s, n, f, p)
static void host_unpin(struct page *p) { (void)p; F.unpins++; order("unpin"); }
#define NV_UNPIN_USER_PAGE(p) host_unpin(p)
static void set_page_dirty_lock(struct page *p) { (void)p; F.dirty++; }
static NvU64 page_to_phys(struct page *p) { return 0x40000000ULL + (NvU64)p->index * 3 * PAGE_SIZE; }

/* DMA-mapping API stubs */
enum dma_data_direction { DMA_BIDIRECTIONAL = 0, DMA_TO_DEVICE = 1, DMA_FROM_DEVICE = 2 };
struct scatterlist {
	struct page *page;
	unsigned int offset, length;
	dma_addr_t dma_address;
	unsigned int dma_length;
	int last;
};
struct sg_table { struct scatterlist *sgl; unsigned int nents, orig_nents; };
#define sg_dma_address(sg) ((sg)->dma_address)
#define sg_dma_len(sg) ((sg)->dma_length)
static struct scatterlist *sg_next(struct scatterlist *sg) { return sg->last ? NULL : sg + 1; }
#define for_each_sg(sglist, sg, nr, i) \
	for ((i) = 0, (sg) = (sglist); (i) < (nr); (i)++, (sg) = sg_next(sg))
#define for_each_sgtable_sg(sgt, sg, i) for_each_sg((sgt)->sgl, sg, (sgt)->orig_nents, i)
#define for_each_sgtable_dma_sg(sgt, sg, i) for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)
static int sg_alloc_table_from_pages_segment(struct sg_table *sgt, struct page **pg,
	unsigned int n, unsigned int off, unsigned long size, unsigned int maxseg, gfp_t gfp)
{
	unsigned int i;
	(void)maxseg; (void)gfp;
	if (!n || off || size != (unsigned long)n << PAGE_SHIFT)
		return -EINVAL;
	sgt->sgl = harness_alloc(sizeof(*sgt->sgl) * n);
	for (i = 0; i < n; i++) {
		sgt->sgl[i].page = pg[i];
		sgt->sgl[i].length = PAGE_SIZE;
		sgt->sgl[i].last = i + 1 == n;
	}
	sgt->nents = sgt->orig_nents = n;
	F.sg_alloc++;
	return 0;
}
static int sg_alloc_table_from_pages(struct sg_table *sgt, struct page **pg, unsigned int n,
	unsigned int off, unsigned long size, gfp_t gfp)
{ return sg_alloc_table_from_pages_segment(sgt, pg, n, off, size, ~0u, gfp); }
static void sg_free_table(struct sg_table *sgt)
{
	if (!sgt->sgl)
		return;
	harness_free(sgt->sgl);
	sgt->sgl = NULL;
	F.sg_free++;
	order("sg_free");
}
static int dma_map_sgtable(struct device *dev, struct sg_table *sgt,
			   enum dma_data_direction dir, unsigned long attrs)
{
	unsigned int i;
	(void)attrs;
	F.dma_map++;
	F.dma_dev = dev;
	if (dir != DMA_BIDIRECTIONAL)
		F.bad_dir++;
	order("dma_map");
	if (F.map_fail)
		return -ENOMEM;
	sgt->sgl[0].dma_address = 0xA00000000ULL;
	sgt->sgl[0].dma_length = sgt->orig_nents * PAGE_SIZE;
	sgt->nents = 1;
	for (i = 0; i < sgt->orig_nents && i < 64; i++)
		F.iova[i] = 0xA00000000ULL + (u64)i * PAGE_SIZE;
	return 0;
}
static void dma_unmap_sgtable(struct device *dev, struct sg_table *sgt,
			      enum dma_data_direction dir, unsigned long attrs)
{
	(void)dev; (void)sgt; (void)attrs;
	if (dir != DMA_BIDIRECTIONAL)
		F.bad_dir++;
	F.dma_unmap++;
	order("dma_unmap");
}
static NvBool nv_p2p_umem_iommu_untranslated(struct device *dev) { return dev && !dev->translated; }

#include "nv_xdev_ext_host_region_actual.inc"

/* ================================================================ cases */
static struct device gpu_dev = { .translated = 1 };
#define NPAGES 4

static nv_p2p_umem_buffer_t *pin(void)
{
	void *h = NULL;
	NV_STATUS st = nv_pin_host_region(0x10000000ULL, NPAGES * PAGE_SIZE, 4096, &h);
	if (st != NV_OK) {
		printf("FAIL pin: status 0x%x\n", st);
		return NULL;
	}
	return h;
}

static void require_map(void)
{
	CHECK(HAVE_DMA_MAP, "G2: nv_host_region_dma_map() is missing; registered host pages "
	      "are never mapped through the DMA API for the GPU device");
}

#if HAVE_DMA_MAP
#define MAP(h, d) nv_host_region_dma_map(h, d)
#else
#define MAP(h, d) ((void)(h), (void)(d), (NV_STATUS)NV_ERR_NOT_SUPPORTED)
#endif

static void case_pin_no_phys(void)
{
	nv_p2p_umem_buffer_t *b = pin();
	unsigned int i, exposed = 0;
	REQUIRE(b, "pin");
	for (i = 0; i < NPAGES; i++)
		exposed += b->physAddrs[i] == page_to_phys(&pages_store[i]);
	CHECK(exposed == 0, "G2: default build stored %u CPU physical addresses as CE "
	      "addresses at pin time", exposed);
	CHECK(F.dma_map == 0, "pin must not map; mapping is per GPU device");
	nv_unpin_host_region(b);
}

static void case_map_iova(void)
{
	nv_p2p_umem_buffer_t *b = pin();
	unsigned int i;
	REQUIRE(b, "pin");
	require_map();
	CHECK(MAP(b, &gpu_dev) == NV_OK, "G2: map behind a translating IOMMU failed");
	CHECK(F.dma_map == 1 && F.dma_dev == &gpu_dev && F.bad_dir == 0,
	      "G2: dma_map_sgtable calls=%u dev ok=%d dir ok=%d", F.dma_map,
	      F.dma_dev == &gpu_dev, F.bad_dir == 0);
	for (i = 0; i < NPAGES; i++)
		CHECK(b->physAddrs[i] == 0xA00000000ULL + i * PAGE_SIZE,
		      "G2: page %u CE address 0x%llx is not its IOVA", i,
		      (unsigned long long)b->physAddrs[i]);
	nv_unpin_host_region(b);
}

static void case_map_twice(void)
{
	nv_p2p_umem_buffer_t *b = pin();
	REQUIRE(b, "pin");
	require_map();
	REQUIRE(MAP(b, &gpu_dev) == NV_OK, "first map");
	CHECK(MAP(b, &gpu_dev) == NV_ERR_STATE_IN_USE && F.dma_map == 1,
	      "G2: second map must be refused without remapping (maps=%u)", F.dma_map);
	nv_unpin_host_region(b);
	CHECK(F.dma_unmap == 1, "unmapped %u times", F.dma_unmap);
}

static void case_map_fail(void)
{
	nv_p2p_umem_buffer_t *b = pin();
	unsigned int i, nonzero = 0;
	REQUIRE(b, "pin");
	require_map();
	F.map_fail = 1;
	CHECK(MAP(b, &gpu_dev) == NV_ERR_NO_MEMORY, "G2: failed mapping must return NO_MEMORY");
	CHECK(F.dma_map == 1, "G2: mapping not attempted");
	for (i = 0; i < NPAGES; i++)
		nonzero += b->physAddrs[i] != 0;
	CHECK(nonzero == 0, "G2: %u CE addresses published after a failed mapping", nonzero);
	CHECK(F.sg_alloc == F.sg_free, "sg table leaked");
	nv_unpin_host_region(b);
	CHECK(F.dma_unmap == 0, "unmapped a mapping that never existed");
}

static void case_unpin_order(void)
{
	nv_p2p_umem_buffer_t *b = pin();
	const char *unmap, *unpin;
	REQUIRE(b, "pin");
	require_map();
	REQUIRE(MAP(b, &gpu_dev) == NV_OK, "map");
	F.order[0] = 0;
	CHECK(nv_unpin_host_region(b) == NV_OK, "unpin");
	unmap = strstr(F.order, "dma_unmap");
	unpin = strstr(F.order, "unpin");
	CHECK(unmap && unpin && unmap < unpin,
	      "G2: pages must be DMA-unmapped before they are unpinned: '%s'", F.order);
	CHECK(F.dma_unmap == 1 && F.sg_free == 1 && F.unpins == NPAGES,
	      "unmap=%u sg_free=%u unpins=%u", F.dma_unmap, F.sg_free, F.unpins);
	CHECK(F.live == 0, "allocations leaked: %u", F.live);
}

static void case_phys_pin(void)
{
	nv_p2p_umem_buffer_t *b = pin();
	unsigned int i;
	REQUIRE(b, "pin");
	for (i = 0; i < NPAGES; i++)
		CHECK(b->physAddrs[i] == page_to_phys(&pages_store[i]),
		      "PHYS build page %u address 0x%llx", i, (unsigned long long)b->physAddrs[i]);
	CHECK(F.dma_map == 0, "PHYS build mapped");
	nv_unpin_host_region(b);
	CHECK(F.live == 0, "allocations leaked: %u", F.live);
}

static void case_phys_map(void)
{
	nv_p2p_umem_buffer_t *b = pin();
	struct device identity = { .translated = 0 };
	REQUIRE(b, "pin");
	require_map();
	CHECK(MAP(b, &gpu_dev) == NV_ERR_NOT_SUPPORTED,
	      "PHYS build must refuse a translating IOMMU");
	CHECK(MAP(b, &identity) == NV_OK, "PHYS build must accept an identity domain");
	CHECK(F.dma_map == 0, "PHYS build used the DMA API");
	nv_unpin_host_region(b);
}

struct named_case { const char *name; void (*fn)(void); };
static const struct named_case cases[] = {
	{ "pin-no-phys", case_pin_no_phys },
	{ "map-iova", case_map_iova },
	{ "map-twice", case_map_twice },
	{ "map-fail", case_map_fail },
	{ "unpin-order", case_unpin_order },
	{ "phys-pin", case_phys_pin },
	{ "phys-map", case_phys_map },
};

int main(int argc, char **argv)
{
	unsigned int i;
	setvbuf(stdout, NULL, _IONBF, 0);
	for (i = 0; argc == 2 && i < sizeof(cases) / sizeof(cases[0]); i++)
		if (!strcmp(argv[1], cases[i].name)) {
			cases[i].fn();
			return env_report(argv[1]);
		}
	printf("usage: case name\n");
	return 2;
}
