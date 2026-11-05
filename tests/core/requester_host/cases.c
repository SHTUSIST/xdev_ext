// SPDX-License-Identifier: GPL-2.0
/*
 * Requirement (42-XDOMAIN-HOST): the requester an XDOMAIN stage binds for its
 * NHI accepts the ring's IOU_UMEM host pages.  It maps every pool page for the
 * NHI with the stage's DMA direction, refuses pools whose pages would expose
 * bytes outside the pool or whose 4 KiB NHI elements would straddle pages,
 * hands each element the DMA address of its own page and offset, refuses spans
 * the NHI descriptor cannot carry (more than one page, more than one frame,
 * outside the pool, wrong direction), synchronizes for the device before use
 * and for the CPU after a definite receive when the mapping needs it, and
 * after an element ends with unknown device access never unmaps or reuses the
 * mapping; the PEER requester path is unchanged.
 *
 * Expected values are literals or come from the fixture window (rh_window),
 * never from the code under test.
 */
#include "shim.h"
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_requester.h>
#include "boundary.h"

/* Weak, so a tree without the host requester still compiles and fails here. */
int xdev_ext_requester_host_lease(struct xdev_ext_requester *rq, u64 off, u32 len,
				  enum dma_data_direction dir, u64 *dma) __attribute__((weak));
void xdev_ext_requester_host_release(struct xdev_ext_requester *rq, u64 dma, u32 len,
				     bool quiesced) __attribute__((weak));
int xdev_ext_requester_host_settled(const struct xdev_ext_requester *rq) __attribute__((weak));

static unsigned assertions;
static const char *case_name;
#define CHECK(c, why) do { assertions++; if (!(c)) { \
	fprintf(stderr, "REQUESTER_HOST_ASSERT %s: %s (%s:%d)\n", case_name, why, __FILE__, __LINE__); \
	exit(1); } } while (0)

static struct page pages[16];
static struct page *page_ptrs[16];
static struct pci_bus bus = { .number = 0x3a };
static struct pci_dev nhi = { .dev = { .dma_coherent = true, .id = 1 }, .bus = &bus, .devfn = 0x10 };
static struct xdev_ext_mech_session session;
static struct xdev_ext_mech_stage stage;
static struct xdev_ext_requester rq;
static unsigned base_allocs;

static void need_api(void)
{
	CHECK(xdev_ext_requester_host_lease && xdev_ext_requester_host_release &&
	      xdev_ext_requester_host_settled, "host requester lease/release/settled API exists");
}

/* An IOU_UMEM pool as io_xdev_ext_umem_mech_pool_bind() describes one. */
static void host_pool(u32 frame_size, u32 nr_frames, u32 first_page_off, u32 direction)
{
	u64 size = (u64)frame_size * nr_frames;
	u32 i;

	rh_reset();
	for (i = 0; i < ARRAY_SIZE(pages); i++) {
		pages[i].index = i;
		page_ptrs[i] = &pages[i];
	}
	session.pool = (struct xdev_ext_mech_pool){ .kind = XDEV_EXT_MECH_POOL_IOU_UMEM,
		.pages = page_ptrs, .size = size, .frame_size = frame_size, .nr_frames = nr_frames,
		.nr_pages = (u32)((first_page_off + size + PAGE_SIZE - 1) / PAGE_SIZE),
		.first_page_off = first_page_off };
	assert(session.pool.nr_pages <= ARRAY_SIZE(pages));
	stage = (struct xdev_ext_mech_stage){ .s = &session, .class_id = XDEV_EXT_MECH_CLASS_XDOMAIN,
		.direction = direction, .index = direction == XDEV_EXT_MECH_DIR_FROM_DEVICE ? 0 : 1 };
	/* What the core records first for a non-PEER stage (stage_caps_default). */
	stage.caps = (struct xdev_ext_mech_stage_caps){ .size = sizeof(stage.caps),
		.version = XDEV_EXT_MECH_STAGE_CAPS_VERSION, .family = XDEV_EXT_FAMILY_NETWORK,
		.export_authority = XDEV_EXT_CAP_NOT_APPLICABLE, .reachability = XDEV_EXT_CAP_NOT_APPLICABLE,
		.requester_mapping = XDEV_EXT_CAP_NOT_APPLICABLE, .p2p_distance = -1 };
	rq = (struct xdev_ext_requester){};
	nhi.refs = 1;
	nhi.dev.dma_coherent = true;
	nhi.dev.force_bounce = false;
	base_allocs = rh_live_allocs;
}

static const struct rh_event *nth(enum rh_kind kind, unsigned n)
{
	unsigned i;

	for (i = 0; i < rh_events; i++)
		if (rh_log[i].kind == kind && !n--)
			return &rh_log[i];
	return NULL;
}

static void check_maps(u32 nr_pages, int dir)
{
	u32 i;

	CHECK(rh_count(RH_MAP) == nr_pages, "one mapping per pool page");
	for (i = 0; i < nr_pages; i++) {
		const struct rh_event *m = nth(RH_MAP, i);

		CHECK(m && m->dev == &nhi.dev, "every pool page is mapped for the NHI");
		CHECK(m->page == &pages[i] && m->offset == 0 && m->size == PAGE_SIZE,
		      "page i mapped whole, in pool order");
		CHECK(m->dir == dir, "mapping direction is the stage direction");
		CHECK(m->attrs & DMA_ATTR_SKIP_CPU_SYNC, "bind maps without CPU sync; leases synchronize");
	}
}

static void host_bind_maps_every_page(void)
{
	host_pool(8192, 2, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "IOU_UMEM pool binds the NHI");
	check_maps(4, DMA_TO_DEVICE);
	CHECK(rq.pdev == &nhi, "the requester is the NHI");
	CHECK(rh_count(RH_DESCRIBE) == 0 && rh_count(RH_PREMAP) == 0, "no PEER provider call");
	CHECK(rh_count(RH_SYNC_DEVICE) == 0 && rh_count(RH_SYNC_CPU) == 0, "bind does not sync");
	CHECK(stage.caps.reachability == XDEV_EXT_CAP_HOST_DMA_MAPPED,
	      "caps: host pages reached through a DMA-API mapping");
	CHECK(stage.caps.requester_mapping == XDEV_EXT_CAP_ESTABLISHED, "caps: requester mapping established");
	CHECK(stage.caps.backing == (XDEV_EXT_PEER_BACKING_HOST_SYSTEM | XDEV_EXT_PEER_BACKING_STRUCT_PAGE),
	      "caps: host RAM with struct pages");
	CHECK(stage.caps.refused == 0 && stage.caps.p2p_distance == -1, "caps: no refusal, no P2P distance");
	CHECK(rq.adm.reachability == XDEV_EXT_CAP_HOST_DMA_MAPPED && rq.adm.refused == 0,
	      "admission record: host DMA mapped, nothing refused");
	CHECK(nhi.refs > 1, "a bound mapping holds the NHI");
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == -EINVAL, "a bound requester cannot bind again");
	CHECK(rh_count(RH_MAP) == 4, "the refused second bind maps nothing");
	xdev_ext_requester_unbind(&rq);
	CHECK(nhi.refs == 1 && rh_live_allocs == base_allocs, "unbind returns every reference and allocation");
}

static void host_bind_rx_maps_from_device(void)
{
	host_pool(4096, 3, 0, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "RX stage binds an IOU_UMEM pool");
	check_maps(3, DMA_FROM_DEVICE);
	xdev_ext_requester_unbind(&rq);
	CHECK(rh_count(RH_UNMAP) == 3, "each RX page unmapped at unbind");
}

static void refused_geometry(u32 frame_size, u32 nr_frames, u32 first_page_off, u32 nr_pages)
{
	host_pool(frame_size, nr_frames, first_page_off, XDEV_EXT_MECH_DIR_TO_DEVICE);
	if (nr_pages)
		session.pool.nr_pages = nr_pages;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == -EINVAL, "pool geometry refused with -EINVAL");
	CHECK(rh_events == 0, "a refused pool is never mapped or described");
	CHECK(rq.pdev == NULL && nhi.refs == 1 && rh_live_allocs == base_allocs,
	      "a refused bind keeps no reference or allocation");
}

/* A UMEM registered at a non-page-aligned address: each 4 KiB element would
 * straddle two pages that need not be contiguous for the NHI. */
static void host_bind_refuses_misaligned_pool(void)
{
	refused_geometry(4096, 2, 256, 0);
	refused_geometry(8192, 1, 2048, 0);
	/* Also when the description counts only whole pages: an element address
	 * is its page's mapping plus the offset, valid only from a page-aligned
	 * pool start. */
	refused_geometry(4096, 2, 256, 2);
}

/* The last page would expose bytes beyond the pool to the NHI. */
static void host_bind_refuses_partial_page(void)
{
	refused_geometry(2048, 3, 0, 0);
}

static void host_bind_map_error_unwinds(void)
{
	dma_addr_t first, second;

	host_pool(4096, 4, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	rh_fail_map_at = 3;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == -ENOMEM, "a mapping error fails the bind");
	CHECK(rh_count(RH_MAP) == 3, "mapping stops at the failed page");
	first = rh_window(&nhi.dev, 0, 0);
	second = rh_window(&nhi.dev, 1, 0);
	CHECK(rh_count(RH_UNMAP) == 2, "exactly the two mapped pages are unmapped");
	CHECK(nth(RH_UNMAP, 0)->addr != nth(RH_UNMAP, 1)->addr, "two different pages unmapped");
	CHECK((nth(RH_UNMAP, 0)->addr == first || nth(RH_UNMAP, 0)->addr == second) &&
	      (nth(RH_UNMAP, 1)->addr == first || nth(RH_UNMAP, 1)->addr == second),
	      "the unmapped addresses are the two mapped pages");
	CHECK(nth(RH_UNMAP, 0)->size == PAGE_SIZE && nth(RH_UNMAP, 0)->dir == DMA_TO_DEVICE,
	      "unwind uses the mapping's size and direction");
	CHECK(rq.pdev == NULL && nhi.refs == 1 && rh_live_allocs == base_allocs,
	      "a failed bind keeps no reference or allocation");
}

static void host_lease_page_address(void)
{
	u64 dma = 0;

	need_api();
	host_pool(8192, 2, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "bind");
	CHECK(xdev_ext_requester_host_lease(&rq, 8192, 4096, DMA_TO_DEVICE, &dma) == 0,
	      "full 4096-byte element: the data ring carries payload only");
	CHECK(dma == rh_window(&nhi.dev, 2, 0), "frame 1 element 0 is page 2");
	xdev_ext_requester_host_release(&rq, dma, 4096, true);
	CHECK(xdev_ext_requester_host_lease(&rq, 8192 + 4096 + 100, 300, DMA_TO_DEVICE, &dma) == 0,
	      "short element inside one page");
	CHECK(dma == rh_window(&nhi.dev, 3, 100), "page 3 plus the offset inside it");
	xdev_ext_requester_host_release(&rq, dma, 300, true);
	CHECK(xdev_ext_requester_host_lease(&rq, 0, 4096, DMA_TO_DEVICE, &dma) == 0, "first element");
	CHECK(dma == rh_window(&nhi.dev, 0, 0), "page 0");
	xdev_ext_requester_host_release(&rq, dma, 4096, true);
	CHECK(xdev_ext_requester_host_settled(&rq) == 0, "every lease ended quiesced");
	xdev_ext_requester_unbind(&rq);
}

static void host_lease_refuses_spans(void)
{
	u64 dma = 0x5a5a;

	need_api();
	host_pool(8192, 2, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "bind");
	CHECK(xdev_ext_requester_host_lease(&rq, 4096 - 100, 200, DMA_TO_DEVICE, &dma) == -ERANGE,
	      "an element crossing a page boundary is refused");
	CHECK(xdev_ext_requester_host_lease(&rq, 2048, 4096, DMA_TO_DEVICE, &dma) == -ERANGE,
	      "a misaligned 4096-byte element is refused");
	CHECK(xdev_ext_requester_host_lease(&rq, 16384 - 100, 200, DMA_TO_DEVICE, &dma) == -ERANGE,
	      "an element past the pool end is refused");
	CHECK(xdev_ext_requester_host_lease(&rq, 16384, 1, DMA_TO_DEVICE, &dma) == -ERANGE,
	      "an element starting at the pool end is refused");
	CHECK(xdev_ext_requester_host_lease(&rq, 0, 0, DMA_TO_DEVICE, &dma) == -ERANGE,
	      "an empty element is refused");
	CHECK(xdev_ext_requester_host_lease(&rq, 0, 8192, DMA_TO_DEVICE, &dma) == -ERANGE,
	      "an element larger than a page is refused");
	CHECK(xdev_ext_requester_host_lease(&rq, 0, 4096, DMA_FROM_DEVICE, &dma) == -EACCES,
	      "a lease against the mapping direction is refused");
	CHECK(dma == 0x5a5a, "a refused lease returns no address");
	CHECK(rh_count(RH_SYNC_DEVICE) == 0, "a refused lease syncs nothing");
	CHECK(xdev_ext_requester_host_settled(&rq) == 0, "refusals leave no outstanding lease");
	xdev_ext_requester_unbind(&rq);

	/* Frames smaller than a page: one element must stay inside one frame. */
	host_pool(2048, 4, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "bind 2048-byte frames");
	CHECK(xdev_ext_requester_host_lease(&rq, 2000, 100, DMA_TO_DEVICE, &dma) == -ERANGE,
	      "an element crossing into the next frame is refused even inside one page");
	CHECK(xdev_ext_requester_host_lease(&rq, 2048, 2048, DMA_TO_DEVICE, &dma) == 0,
	      "a whole small frame");
	CHECK(dma == rh_window(&nhi.dev, 0, 2048), "frame 1 is the upper half of page 0");
	xdev_ext_requester_host_release(&rq, dma, 2048, true);
	xdev_ext_requester_unbind(&rq);

	/* A PEER requester has no host mapping to lease from. */
	host_pool(8192, 2, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	session.pool.kind = XDEV_EXT_MECH_POOL_PEER;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "PEER bind");
	CHECK(xdev_ext_requester_host_lease(&rq, 0, 4096, DMA_TO_DEVICE, &dma) == -EINVAL,
	      "no host lease on a PEER requester");
	CHECK(xdev_ext_requester_host_settled(&rq) == 0, "a PEER requester is always settled");
	xdev_ext_requester_unbind(&rq);
}

static void host_noncoherent_sync(void)
{
	u64 dma = 0;
	unsigned before;

	need_api();
	host_pool(8192, 2, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	nhi.dev.dma_coherent = false;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "non-coherent NHI binds host pages");
	CHECK(rh_count(RH_SYNC_DEVICE) == 0, "bind itself does not sync");
	CHECK(xdev_ext_requester_host_lease(&rq, 4096 + 512, 1000, DMA_TO_DEVICE, &dma) == 0, "TX lease");
	CHECK(rh_count(RH_SYNC_DEVICE) == 1, "one sync for the device per TX lease");
	CHECK(rh_log[rh_events - 1].kind == RH_SYNC_DEVICE, "the sync is the lease's last effect, before any post");
	CHECK(nth(RH_SYNC_DEVICE, 0)->dev == &nhi.dev && nth(RH_SYNC_DEVICE, 0)->addr == rh_window(&nhi.dev, 1, 512) &&
	      nth(RH_SYNC_DEVICE, 0)->size == 1000 && nth(RH_SYNC_DEVICE, 0)->dir == DMA_TO_DEVICE,
	      "TX sync covers exactly the element, toward the device");
	before = rh_events;
	xdev_ext_requester_host_release(&rq, dma, 1000, true);
	CHECK(rh_events == before, "a definite TX end needs no CPU sync");
	xdev_ext_requester_unbind(&rq);

	host_pool(4096, 2, 0, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	nhi.dev.dma_coherent = false;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "non-coherent NHI binds RX host pages");
	CHECK(xdev_ext_requester_host_lease(&rq, 4096, 4096, DMA_FROM_DEVICE, &dma) == 0, "RX lease");
	CHECK(rh_count(RH_SYNC_DEVICE) == 1 && nth(RH_SYNC_DEVICE, 0)->addr == rh_window(&nhi.dev, 1, 0) &&
	      nth(RH_SYNC_DEVICE, 0)->size == 4096 && nth(RH_SYNC_DEVICE, 0)->dir == DMA_FROM_DEVICE,
	      "RX buffer handed to the device first");
	CHECK(rh_count(RH_SYNC_CPU) == 0, "no CPU sync while the device owns the buffer");
	xdev_ext_requester_host_release(&rq, dma, 4096, true);
	CHECK(rh_count(RH_SYNC_CPU) == 1 && nth(RH_SYNC_CPU, 0)->addr == rh_window(&nhi.dev, 1, 0) &&
	      nth(RH_SYNC_CPU, 0)->size == 4096 && nth(RH_SYNC_CPU, 0)->dir == DMA_FROM_DEVICE,
	      "a definite RX end makes the whole device-written buffer CPU visible");
	xdev_ext_requester_unbind(&rq);

	/* A forced bounce buffer needs the same synchronization. */
	host_pool(4096, 1, 0, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	nhi.dev.force_bounce = true;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "bounced NHI binds host pages");
	CHECK(xdev_ext_requester_host_lease(&rq, 0, 4096, DMA_FROM_DEVICE, &dma) == 0, "bounced RX lease");
	xdev_ext_requester_host_release(&rq, dma, 4096, true);
	CHECK(rh_count(RH_SYNC_DEVICE) == 1 && rh_count(RH_SYNC_CPU) == 1, "bounced RX synchronized both ways");
	xdev_ext_requester_unbind(&rq);
}

static void host_coherent_no_sync(void)
{
	u64 dma = 0;

	need_api();
	host_pool(4096, 2, 0, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "coherent NHI binds RX host pages");
	CHECK(xdev_ext_requester_host_lease(&rq, 0, 4096, DMA_FROM_DEVICE, &dma) == 0, "RX lease");
	xdev_ext_requester_host_release(&rq, dma, 4096, true);
	CHECK(rh_count(RH_SYNC_DEVICE) == 0 && rh_count(RH_SYNC_CPU) == 0,
	      "a coherent unbounced mapping needs no sync calls");
	xdev_ext_requester_unbind(&rq);
}

static void host_unknown_retains_mapping(void)
{
	u64 dma = 0, other = 0x77;

	need_api();
	host_pool(4096, 2, 0, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	nhi.dev.dma_coherent = false;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "bind");
	CHECK(xdev_ext_requester_host_lease(&rq, 0, 4096, DMA_FROM_DEVICE, &dma) == 0, "RX lease");
	xdev_ext_requester_host_release(&rq, dma, 4096, false);
	CHECK(rh_count(RH_SYNC_CPU) == 0, "an unknown end never hands the buffer to the CPU");
	CHECK(xdev_ext_requester_host_settled(&rq) == -EIO, "unknown device access is not settled");
	CHECK(xdev_ext_requester_host_lease(&rq, 4096, 4096, DMA_FROM_DEVICE, &other) == -ESTALE,
	      "no new lease from a mapping with unknown device access");
	CHECK(other == 0x77, "the refused lease returns no address");
	xdev_ext_requester_unbind(&rq);
	CHECK(rh_count(RH_UNMAP) == 0, "unknown device access: the mapping is never unmapped");
	CHECK(rq.pdev == NULL, "the requester itself is unbound");
	CHECK(nhi.refs > 1, "the retained mapping still holds the NHI");
	CHECK(rh_live_allocs > base_allocs, "the retained mapping record is kept");
}

static void host_outstanding_lease_retains_mapping(void)
{
	u64 dma = 0;

	need_api();
	host_pool(4096, 2, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "bind");
	CHECK(xdev_ext_requester_host_lease(&rq, 4096, 4096, DMA_TO_DEVICE, &dma) == 0, "TX lease");
	CHECK(xdev_ext_requester_host_settled(&rq) == -EIO, "an outstanding lease is not settled");
	xdev_ext_requester_unbind(&rq);
	CHECK(rh_count(RH_UNMAP) == 0, "an outstanding lease keeps the whole mapping");
	CHECK(nhi.refs > 1, "the retained mapping still holds the NHI");
}

static void host_quiesced_unbind_unmaps_once(void)
{
	u64 dma = 0;
	u32 i, j;

	need_api();
	host_pool(8192, 3, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	nhi.dev.dma_coherent = false;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "bind");
	for (i = 0; i < 6; i++) {
		CHECK(xdev_ext_requester_host_lease(&rq, (u64)i * 4096, 4096, DMA_TO_DEVICE, &dma) == 0, "lease");
		xdev_ext_requester_host_release(&rq, dma, 4096, true);
	}
	CHECK(xdev_ext_requester_host_settled(&rq) == 0, "every lease ended quiesced");
	CHECK(rh_count(RH_UNMAP) == 0, "nothing unmapped while bound");
	xdev_ext_requester_unbind(&rq);
	CHECK(rh_count(RH_UNMAP) == 6, "each page unmapped exactly once");
	for (i = 0; i < 6; i++) {
		const struct rh_event *u = nth(RH_UNMAP, i);
		unsigned same = 0;

		CHECK(u->dev == &nhi.dev && u->size == PAGE_SIZE && u->dir == DMA_TO_DEVICE &&
		      (u->attrs & DMA_ATTR_SKIP_CPU_SYNC), "unmap matches the mapping");
		for (j = 0; j < 6; j++)
			same += u->addr == rh_window(&nhi.dev, j, 0);
		CHECK(same == 1, "an unmapped address is one mapped page");
		for (j = 0; j < i; j++)
			CHECK(nth(RH_UNMAP, j)->addr != u->addr, "no page unmapped twice");
	}
	CHECK(rq.pdev == NULL && nhi.refs == 1 && rh_live_allocs == base_allocs,
	      "a settled unbind returns every reference and allocation");
}

static void peer_bind_unchanged(void)
{
	host_pool(8192, 2, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	session.pool.kind = XDEV_EXT_MECH_POOL_PEER;
	stage.caps.reachability = XDEV_EXT_CAP_UNKNOWN;
	stage.caps.requester_mapping = XDEV_EXT_CAP_UNKNOWN;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "PEER bind");
	CHECK(rh_count(RH_DESCRIBE) == 1 && rh_count(RH_PREMAP) == 1, "PEER describe then premap");
	CHECK(rh_count(RH_MAP) == 0, "PEER pages are not mapped by the requester");
	CHECK(stage.caps.reachability == XDEV_EXT_CAP_TOPOLOGY_PASSED && stage.caps.p2p_distance == 0,
	      "PEER BAR reachability is the topology result");
	CHECK(stage.caps.backing == XDEV_EXT_PEER_BACKING_MMIO_BAR, "PEER backing as described");
	CHECK(stage.caps.requester_mapping == XDEV_EXT_CAP_ESTABLISHED, "PEER requester mapping established");
	CHECK(rq.pdev == &nhi && rq.generation == 17, "PEER requester and generation");
	xdev_ext_requester_unbind(&rq);
	CHECK(nhi.refs == 1 && rh_count(RH_UNMAP) == 0, "PEER unbind drops only its reference");
}

static void host_create_report(void)
{
	host_pool(4096, 2, 0, XDEV_EXT_MECH_DIR_TO_DEVICE);
	stage.create_reporting = true;
	CHECK(xdev_ext_requester_bind(&rq, &stage, &nhi, 0) == 0, "bind");
	CHECK(stage.create_requester == &nhi, "CREATE report names the NHI requester");
	CHECK(stage.create_requester_id.bus == 0x3a && stage.create_requester_id.devfn == 0x10 &&
	      stage.create_requester_id.domain == 0, "requester identity");
	CHECK((stage.create_valid & XDEV_EXT_MECH_CREATE_VALID_REQUESTER) &&
	      (stage.create_valid & XDEV_EXT_MECH_CREATE_VALID_DECIDED), "requester and decision reported");
	CHECK(!(stage.create_valid & XDEV_EXT_MECH_CREATE_VALID_DESCRIBED), "no provider description for host pages");
	pci_dev_put(stage.create_requester);	/* the core drops the report reference */
	xdev_ext_requester_unbind(&rq);
	CHECK(nhi.refs == 1, "report and requester references both returned");
}

static const struct { const char *name; void (*fn)(void); } cases[] = {
	{ "host_bind_maps_every_page", host_bind_maps_every_page },
	{ "host_bind_rx_maps_from_device", host_bind_rx_maps_from_device },
	{ "host_bind_refuses_misaligned_pool", host_bind_refuses_misaligned_pool },
	{ "host_bind_refuses_partial_page", host_bind_refuses_partial_page },
	{ "host_bind_map_error_unwinds", host_bind_map_error_unwinds },
	{ "host_lease_page_address", host_lease_page_address },
	{ "host_lease_refuses_spans", host_lease_refuses_spans },
	{ "host_noncoherent_sync", host_noncoherent_sync },
	{ "host_coherent_no_sync", host_coherent_no_sync },
	{ "host_unknown_retains_mapping", host_unknown_retains_mapping },
	{ "host_outstanding_lease_retains_mapping", host_outstanding_lease_retains_mapping },
	{ "host_quiesced_unbind_unmaps_once", host_quiesced_unbind_unmaps_once },
	{ "peer_bind_unchanged", peer_bind_unchanged },
	{ "host_create_report", host_create_report },
};

int main(int argc, char **argv)
{
	size_t i;

	if (argc != 2)
		return 2;
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		if (strcmp(argv[1], cases[i].name))
			continue;
		case_name = cases[i].name;
		cases[i].fn();
		assert(!shim_spins);
		printf("REQUESTER_HOST_CASE %s assertions=%u\n", case_name, assertions);
		return 0;
	}
	fprintf(stderr, "unknown case %s\n", argv[1]);
	return 2;
}
