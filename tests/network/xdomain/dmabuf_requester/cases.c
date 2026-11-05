// SPDX-License-Identifier: GPL-2.0
/*
 * Can a system-heap DMA-BUF, registered through the real REGISTER ioctl and
 * bound as a PEER frame pool, admit the Thunderbolt NHI as the requester that
 * an XDOMAIN stage binds (xdev_ext_xdomain_class.c bind -> netfam attach ->
 * xdev_ext_requester_bind(nhi_pdev))?  Expectations below follow the story and
 * the UAPI meaning of each reported field, not production internals:
 *  - host RAM with struct pages is the system heap's backing;
 *  - a trusted, coherent, non-bounced requester gets a DMA-API mapping
 *    ("coherent host DMA-API mapping established") and nothing is refused;
 *  - the requester recorded by the bind is exactly the device that asked;
 *  - every lease names an address that the exporter returned for that same
 *    requester's attachment, never another device's;
 *  - a requester that cannot use such a mapping safely is refused before any
 *    mapping is left behind.
 * Host software only: no DMA, no NHI hardware, no kernel run.
 */
#include "kernel_shim.h"
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_peer.h>
#include <linux/xdev_ext_requester.h>
#include <uapi/linux/xdev_ext_mech.h>
#include <uapi/linux/xdev_ext_peer.h>
#include "boundary.h"

static unsigned assertions;
static const char *case_name = "?";
#define CHECK(c, why) do { assertions++; if (!(c)) { \
	fprintf(stderr, "DMABUF_REQ_ASSERT %s: %s (%s:%d)\n", case_name, why, __FILE__, __LINE__); \
	exit(1); } } while (0)

/* A Thunderbolt host controller is an internal PCIe function: trusted,
 * cache coherent on x86 and not forced through swiotlb.  The NVMe controller
 * shares the same frames through its own attachment. */
static struct io_tlb_mem no_bounce = {.force_bounce = false};
static struct io_tlb_mem forced_bounce = {.force_bounce = true};
static struct pci_bus bus_nhi = {.number = 0x02}, bus_nvme = {.number = 0x05};
static struct pci_dev nhi, nvme;

static void devices(void)
{
	nhi = (struct pci_dev){.dev = {.dma_coherent = true, .dma_io_tlb_mem = &no_bounce},
		.id = 0x15ea, .bus = &bus_nhi, .devfn = 0};
	nvme = (struct pci_dev){.dev = {.dma_coherent = true, .dma_io_tlb_mem = &no_bounce},
		.id = 0x0a54, .bus = &bus_nvme, .devfn = 0};
}

/* Exporter addresses per attachment: the fixture exporter copies env.sg at
 * attach time, so each requester gets its own, independently chosen window. */
static void exporter_window(u64 first, u64 second)
{
	env.sg[0] = (struct scatterlist){.dma_address = first, .dma_length = 8192,
		.length = 8192, .next = &env.sg[1]};
	env.sg[1] = (struct scatterlist){.dma_address = second, .dma_length = 4096,
		.length = 4096};
}

#define NHI_FIRST  0x7a000000ULL
#define NHI_SECOND 0x7b000000ULL
#define NVME_FIRST 0x3c000000ULL
#define NVME_SECOND 0x3d000000ULL
#define EXPORT_BYTES 12288U
#define FRAME_BYTES 4096U

struct world {
	int allocation_fd;
	struct file *allocation;
	struct xdev_ext_mech_stage xdomain, nvme_stage;
	struct xdev_ext_requester nhi_rq, nvme_rq;
	u64 generation;
};

static void registered(struct world *w)
{
	struct xdev_ext_peer_register reg = {.gpu_fd = 7, .flags = XDEV_EXT_PEER_REGISTER_F_DMABUF,
		.len = EXPORT_BYTES};
	long fd;

	memset(w, 0, sizeof(*w));
	devices();
	fixture_reset(fixture_system_heap_ops());
	CHECK(fixture_system_heap_register() == 0, "system heap descriptor registers once");
	fd = fixture_ctl_ioctl(XDEV_EXT_PEER_REGISTER, &reg);
	CHECK(fd >= 0, "REGISTER of a system-heap DMA-BUF returns an allocation fd");
	CHECK(reg.generation != 0, "REGISTER reports a nonzero region generation");
	w->allocation_fd = (int)fd;
	w->generation = reg.generation;
	w->allocation = fixture_fget(w->allocation_fd);
	CHECK(w->allocation != NULL, "allocation fd resolves to its file");
}

static void pool_bound(struct world *w)
{
	struct xdev_ext_mech_layout layout = {.frame_size = FRAME_BYTES, .seg_len = FRAME_BYTES,
		.group_bytes = 2 * FRAME_BYTES};
	struct xdev_ext_mech_pool *pool = fixture_pool();

	CHECK(xdev_ext_peer_mech_pool_bind(pool, w->allocation, &layout) == 0,
	      "CREATE pool bind accepts the DMA-BUF allocation as a PEER pool");
	CHECK(pool->kind == XDEV_EXT_MECH_POOL_PEER,
	      "bound pool kind is PEER: the XDOMAIN bind's pool-kind check sees PEER");
	CHECK(pool->nr_frames == EXPORT_BYTES / FRAME_BYTES, "frames cover the whole export");
	CHECK(xdev_ext_peer_mech_pool_file(pool) != NULL, "pool holds the claimed authority");
	CHECK(xdev_ext_peer_mech_pool_generation(pool) == w->generation,
	      "pool generation is the REGISTER generation");
	w->xdomain = (struct xdev_ext_mech_stage){.s = fixture_session(), .index = 1,
		.class_id = XDEV_EXT_MECH_CLASS_XDOMAIN, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE};
	w->nvme_stage = (struct xdev_ext_mech_stage){.s = fixture_session(), .index = 0,
		.class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE};
}

static void nhi_admitted_case(void)
{
	struct world w;
	struct xdev_ext_peer_fd_lease lease = {0};
	unsigned attaches;

	registered(&w);
	pool_bound(&w);
	exporter_window(NHI_FIRST, NHI_SECOND);
	attaches = env.attaches;
	w.xdomain.create_reporting = true;
	CHECK(xdev_ext_requester_bind(&w.nhi_rq, &w.xdomain, &nhi, 0) == 0,
	      "XDOMAIN requester bind admits the NHI for system-heap frames");
	CHECK(w.nhi_rq.pdev == &nhi, "bound requester is the NHI function itself");
	/* The bind, the CREATE report and the premapped attachment each hold the
	 * NHI; the attachment stays cached until the allocation fd closes. */
	CHECK(nhi.refs == 3, "bind, CREATE report and cached NHI mapping each hold the NHI");
	CHECK(w.nhi_rq.adm.backing == (XDEV_EXT_PEER_BACKING_HOST_SYSTEM |
				       XDEV_EXT_PEER_BACKING_STRUCT_PAGE),
	      "reported backing is host RAM with struct pages");
	CHECK(w.nhi_rq.adm.refused == 0, "no refusal reason for the NHI");
	CHECK(w.xdomain.caps.reachability == XDEV_EXT_CAP_HOST_DMA_MAPPED,
	      "stage reachability says a host DMA-API mapping exists");
	CHECK(w.xdomain.caps.requester_mapping == XDEV_EXT_CAP_ESTABLISHED,
	      "stage records an established requester mapping");
	CHECK(w.xdomain.create_requester == &nhi &&
	      (w.xdomain.create_valid & XDEV_EXT_MECH_CREATE_VALID_REQUESTER),
	      "CREATE report names the NHI as requester");
	CHECK(w.xdomain.create_requester_id.bus == 0x02,
	      "CREATE report carries the NHI bus number");
	CHECK(env.attaches == attaches + 1 && env.last_attach &&
	      env.last_attach->dev == &nhi.dev,
	      "exactly one exporter attachment, for the NHI device");
	CHECK(env.pins >= 1 && env.maps >= 1, "NHI attachment pinned and mapped before data use");
	/* A data lease, as XDOMAIN netfam takes it for a TX element. */
	CHECK(xdev_ext_peer_lease_split(w.nhi_rq.authority, w.nhi_rq.pdev, w.nhi_rq.generation,
					FRAME_BYTES + 512, 1024, DMA_TO_DEVICE, &lease) == 0,
	      "NHI lease inside frame 1");
	CHECK(lease.lease.dma_address == NHI_FIRST + FRAME_BYTES + 512,
	      "lease address is the NHI attachment's address for that byte");
	CHECK(lease.lease.len == 1024, "lease covers exactly the requested bytes");
	xdev_ext_peer_fd_release(&lease, true);
	CHECK(lease.file == NULL, "quiesced release drops the lease file reference");
	xdev_ext_requester_unbind(&w.nhi_rq);
	CHECK(nhi.refs == 2, "unbind drops only the bind's NHI PCI reference");
	pci_dev_put(w.xdomain.create_requester); /* the CREATE report consumer's put */
	fixture_finish(&w.allocation);
	CHECK(nhi.refs == 0, "closing the allocation fd drops the cached NHI mapping");
	printf("DMABUF_REQ_CASE nhi_admitted assertions=%u\n", assertions);
}

static void shared_pool_case(void)
{
	struct world w;
	struct xdev_ext_peer_fd_lease to_nhi = {0}, from_nvme = {0};

	registered(&w);
	pool_bound(&w);
	exporter_window(NVME_FIRST, NVME_SECOND);
	CHECK(xdev_ext_requester_bind(&w.nvme_rq, &w.nvme_stage, &nvme, 0) == 0,
	      "NVMe stage 0 requester bind on the same DMA-BUF pool");
	exporter_window(NHI_FIRST, NHI_SECOND);
	CHECK(xdev_ext_requester_bind(&w.nhi_rq, &w.xdomain, &nhi, 0) == 0,
	      "XDOMAIN stage 1 requester bind on the same pool");
	CHECK(env.attaches == 2, "one attachment per requester device");
	CHECK(w.nvme_rq.pdev == &nvme && w.nhi_rq.pdev == &nhi, "each stage keeps its own requester");
	/* NVMe READ fills frame 2; XDOMAIN TX sends the same bytes. */
	CHECK(xdev_ext_peer_lease_split(w.nvme_rq.authority, w.nvme_rq.pdev, w.nvme_rq.generation,
					2 * FRAME_BYTES, FRAME_BYTES, DMA_FROM_DEVICE, &from_nvme) == 0,
	      "NVMe lease on frame 2");
	CHECK(xdev_ext_peer_lease_split(w.nhi_rq.authority, w.nhi_rq.pdev, w.nhi_rq.generation,
					2 * FRAME_BYTES, FRAME_BYTES, DMA_TO_DEVICE, &to_nhi) == 0,
	      "NHI lease on frame 2");
	CHECK(from_nvme.lease.dma_address == NVME_SECOND,
	      "NVMe sees frame 2 through its own attachment");
	CHECK(to_nhi.lease.dma_address == NHI_SECOND,
	      "NHI sees frame 2 through its own attachment, not the NVMe address");
	xdev_ext_peer_fd_release(&from_nvme, true);
	xdev_ext_peer_fd_release(&to_nhi, true);
	xdev_ext_requester_unbind(&w.nhi_rq);
	xdev_ext_requester_unbind(&w.nvme_rq);
	CHECK(nhi.refs == 1 && nvme.refs == 1, "each cached mapping still holds its own device");
	fixture_finish(&w.allocation);
	CHECK(nhi.refs == 0 && nvme.refs == 0, "fd close releases both cached mappings");
	printf("DMABUF_REQ_CASE shared_pool assertions=%u\n", assertions);
}

/* Each refusal must leave no requester reference and no live attachment. */
static void refused(struct world *w, int expected, u32 refused_bits, const char *why)
{
	unsigned attaches = env.attaches, detaches = env.detaches;
	int ret = xdev_ext_requester_bind(&w->nhi_rq, &w->xdomain, &nhi, 0);

	CHECK(ret == expected, why);
	CHECK(w->nhi_rq.pdev == NULL, "refused bind records no requester");
	CHECK(nhi.refs == 0, "refused bind keeps no NHI reference");
	CHECK(env.attaches - attaches == env.detaches - detaches,
	      "refused bind leaves no exporter attachment behind");
	if (refused_bits != UINT32_MAX)
		CHECK(w->nhi_rq.adm.refused == refused_bits, "refusal reason bits");
}

static void untrusted_case(void)
{
	struct world w;
	registered(&w);
	pool_bound(&w);
	nhi.untrusted = 1;
	refused(&w, -EXDEV, UINT32_MAX, "an untrusted requester is refused with EXDEV");
	fixture_finish(&w.allocation);
	printf("DMABUF_REQ_CASE untrusted assertions=%u\n", assertions);
}

static void swiotlb_case(void)
{
	struct world w;
	registered(&w);
	pool_bound(&w);
	nhi.dev.dma_io_tlb_mem = &forced_bounce;
	refused(&w, -EXDEV, UINT32_MAX, "a swiotlb-forced requester is refused with EXDEV");
	fixture_finish(&w.allocation);
	printf("DMABUF_REQ_CASE swiotlb assertions=%u\n", assertions);
}

static void noncoherent_case(void)
{
	struct world w;
	registered(&w);
	pool_bound(&w);
	nhi.dev.dma_coherent = false;
	/* Host RAM without coherent DMA cannot be described as safe backing;
	 * an undescribed allocation has no P2P path and an unsupported backing. */
	refused(&w, -EXDEV, XDEV_EXT_PEER_REFUSE_NO_P2P_PATH | XDEV_EXT_PEER_REFUSE_BACKING,
		"a non-coherent requester is refused with EXDEV");
	fixture_finish(&w.allocation);
	printf("DMABUF_REQ_CASE noncoherent assertions=%u\n", assertions);
}

static void need_sync_case(void)
{
	struct world w;
	registered(&w);
	pool_bound(&w);
	exporter_window(NHI_FIRST, NHI_SECOND);
	env.needs_sync_address = NHI_SECOND;
	refused(&w, -EOPNOTSUPP, UINT32_MAX,
		"a mapping that needs CPU sync for the NHI is refused at premap");
	fixture_finish(&w.allocation);
	printf("DMABUF_REQ_CASE need_sync assertions=%u\n", assertions);
}

static void unregistered_exporter_case(void)
{
	struct xdev_ext_peer_register reg = {.gpu_fd = 7, .flags = XDEV_EXT_PEER_REGISTER_F_DMABUF,
		.len = EXPORT_BYTES};

	devices();
	fixture_reset(fixture_other_exporter_ops());
	CHECK(fixture_system_heap_register() == 0, "system heap descriptor registers");
	CHECK(fixture_ctl_ioctl(XDEV_EXT_PEER_REGISTER, &reg) == -EOPNOTSUPP,
	      "REGISTER of an exporter without a describe hook fails with EOPNOTSUPP");
	CHECK(fixture_live_fds() == 0, "no allocation fd is created");
	fixture_finish(NULL);
	printf("DMABUF_REQ_CASE unregistered_exporter assertions=%u\n", assertions);
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	case_name = argv[1];
	if (!strcmp(argv[1], "nhi_admitted")) nhi_admitted_case();
	else if (!strcmp(argv[1], "shared_pool")) shared_pool_case();
	else if (!strcmp(argv[1], "untrusted")) untrusted_case();
	else if (!strcmp(argv[1], "swiotlb")) swiotlb_case();
	else if (!strcmp(argv[1], "noncoherent")) noncoherent_case();
	else if (!strcmp(argv[1], "need_sync")) need_sync_case();
	else if (!strcmp(argv[1], "unregistered_exporter")) unregistered_exporter_case();
	else return 2;
	return 0;
}
