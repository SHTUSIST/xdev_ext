/* SPDX-License-Identifier: MIT */
/*
 * Host fixture for the active caller-bound Direct CE path (G08-G10 controls):
 * actual RmP2PUmemDmaRequestDirect and _p2pCreateMemDesc (p2p_umem.c) and the
 * rm_p2p_umem_dma_request bridge (osapi.c), with the real chunk and window
 * helper headers.  Stubs: memdesc accessors, memmgrMemCopyUsesCe and
 * memmgrMemCopy (records surfaces/offsets/bytes, can fail on a chosen call),
 * the API lock, GPU lookup and the bound-allocation resolve.  Nothing is
 * copied; no GPU exists.
 */
#include <stddef.h>
#include "nv_xdev_ext_host_env.h"

#define NV_INLINE inline
#define NV_PRINTF(...) ((void)0)
#define NV_ASSERT_OR_RETURN(c, e) do { if (!(c)) return (e); } while (0)
#define LEVEL_INFO 0
#define LEVEL_ERROR 1
#define RM_SHA1_GID_SIZE 16
#ifndef NV_P2P_UMEM_STRICT_SECURITY_CHECKS
#define NV_P2P_UMEM_STRICT_SECURITY_CHECKS 1
#endif

enum { PDB_PROP_GPU_IS_LOST };
typedef struct OBJGPU OBJGPU;
struct OBJGPU { int id; NvBool bIsSOC; NvBool (*getProperty)(OBJGPU *, int); };
static NvBool harness_get_property(OBJGPU *g, int p) { (void)g; (void)p; return NV_FALSE; }
typedef struct { int unused; } KernelBus;
static KernelBus harness_bus;
#define GPU_GET_KERNEL_BUS(g) ((void)(g), &harness_bus)
typedef struct { int unused; } MemoryManager;
static MemoryManager harness_mm;
#define GPU_GET_MEMORY_MANAGER(g) ((void)(g), &harness_mm)
enum { ADDR_UNKNOWN, ADDR_SYSMEM, ADDR_FBMEM };
#define NV_MEMORY_UNCACHED 0
#define NV_MEMORY_CACHED 1
#define MEMDESC_FLAGS_NONE 0
#define AT_GPU 1
typedef struct MEMORY_DESCRIPTOR {
	int aspace;
	NvU64 size, pageSize, PteAdjust;
	RmPhysAddr pages[64];
	NvU32 count;
	int host;
} MEMORY_DESCRIPTOR;
static struct {
	unsigned int created, destroyed, copies, uses_ce_false, fail_copy_at;
	struct { MEMORY_DESCRIPTOR *src, *dst; NvU64 src_off, dst_off; NvU32 size; } copy[64];
	MEMORY_DESCRIPTOR *host_md;
	int lock_fail;
	NV_STATUS resolve_status;
} D;
static NV_STATUS memdescCreate(MEMORY_DESCRIPTOR **out, OBJGPU *g, NvU64 size, NvU64 align,
	NvBool contig, int aspace, int attr, int flags)
{
	(void)g; (void)align; (void)contig; (void)attr; (void)flags;
	*out = calloc(1, sizeof(**out));
	(*out)->aspace = aspace;
	(*out)->size = size;
	(*out)->host = 1;
	D.created++;
	D.host_md = *out;
	return NV_OK;
}
static void memdescFillPages(MEMORY_DESCRIPTOR *m, NvU32 start, RmPhysAddr *pa, NvU32 n,
			     NvU64 ps)
{
	NvU32 i;
	for (i = 0; i < n && start + i < 64; i++)
		m->pages[start + i] = pa[i];
	m->count = n;
	m->pageSize = ps;
}
static void memdescSetPageSize(MEMORY_DESCRIPTOR *m, int at, NvU64 ps) { (void)at; m->pageSize = ps; }
static void memdescDestroy(MEMORY_DESCRIPTOR *m) { if (m) { D.destroyed++; free(m); } }
static int memdescGetAddressSpace(MEMORY_DESCRIPTOR *m) { return m->aspace; }
static NvU64 memdescGetSize(MEMORY_DESCRIPTOR *m) { return m->size; }
static NvU64 memdescGetPageSize(MEMORY_DESCRIPTOR *m, int at) { (void)at; return m->pageSize; }
static NvU64 memdescGetPteAdjust(MEMORY_DESCRIPTOR *m) { return m->PteAdjust; }
#define portMemAllocNonPaged(n) calloc(1, (n))
#define portMemFree(p) free(p)
#define portMemSet(p, v, n) memset((p), (v), (n))
typedef struct { MEMORY_DESCRIPTOR *pMemDesc; NvU64 offset; } TRANSFER_SURFACE;
#define TRANSFER_FLAGS_PREFER_CE (1u << 0)
#define TRANSFER_FLAGS_REQUIRE_CE (1u << 1)
static NvBool memmgrMemCopyUsesCe(MemoryManager *mm, TRANSFER_SURFACE *dst,
				  TRANSFER_SURFACE *src, NvU32 flags)
{
	(void)mm; (void)dst; (void)src; (void)flags;
	return !D.uses_ce_false;
}
static NV_STATUS memmgrMemCopy(MemoryManager *mm, TRANSFER_SURFACE *dst, TRANSFER_SURFACE *src,
			       NvU32 size, NvU32 flags)
{
	unsigned int i = D.copies++;
	(void)mm; (void)flags;
	if (i < 64) {
		D.copy[i].src = src->pMemDesc;
		D.copy[i].dst = dst->pMemDesc;
		D.copy[i].src_off = src->offset;
		D.copy[i].dst_off = dst->offset;
		D.copy[i].size = size;
	}
	if (D.fail_copy_at && D.copies == D.fail_copy_at)
		return NV_ERR_TIMEOUT;
	return NV_OK;
}

#include "nv_xdev_ext_direct_dma_types.h"    /* P2P types (p2p.h, p2p_umem.c) + helpers */

/* osapi bridge environment */
typedef struct { int unused; } nvidia_stack_t;
typedef struct { int unused; } THREAD_STATE_NODE;
#define THREAD_STATE_FLAGS_NONE 0
#define API_LOCK_FLAGS_NONE 0
#define RM_LOCK_MODULES_P2P 0
#define NV_ENTER_RM_RUNTIME(sp, fp) ((void)(sp), (fp) = NULL)
#define NV_EXIT_RM_RUNTIME(sp, fp) ((void)(sp), (void)(fp))
static void threadStateInit(THREAD_STATE_NODE *t, int f) { (void)t; (void)f; }
static void threadStateFree(THREAD_STATE_NODE *t, int f) { (void)t; (void)f; }
static NV_STATUS rmapiLockAcquire(int f, int m) { (void)f; (void)m; return D.lock_fail ? NV_ERR_INVALID_LOCK_STATE : NV_OK; }
static void rmapiLockRelease(void) {}
#define DRF_DEF(d, r, f, c) 0
static OBJGPU gpu0 = { .getProperty = harness_get_property };
static OBJGPU *gpumgrGetGpuFromUuid(const NvU8 *uuid, NvU32 flags) { (void)uuid; (void)flags; return &gpu0; }
static MEMORY_DESCRIPTOR gpu_md = { .aspace = ADDR_FBMEM, .size = 1 << 22, .pageSize = 1 << 16 };
static NV_STATUS RmP2PUmemVidmemResolve(P2P_UMEM_VIDMEM_BINDING *b, OBJGPU *g,
					MEMORY_DESCRIPTOR **md)
{
	(void)b; (void)g;
	if (D.resolve_status != NV_OK)
		return D.resolve_status;
	*md = &gpu_md;
	return NV_OK;
}

static void memdescDescribe(MEMORY_DESCRIPTOR *m, int aspace, NvU64 base, NvU64 size)
{ m->aspace = aspace; m->pages[0] = base; m->size = size; m->host = 0; }

/* Lower kernel-open pin boundary of the dormant generic/CXL registration.
 * Like the real nv_pin_cxl_buffer(), an unaligned range covers every base
 * page it touches: page-base+1, 4096 bytes -> two pages. */
static struct { unsigned int pins, unpins; NvU64 va, size; NvU64 pages[4]; } L;
static NV_STATUS nv_pin_cxl_buffer(NvU64 va, NvU64 size, void **h)
{
	L.pins++; L.va = va; L.size = size;
	*h = &L;
	return NV_OK;
}
static NV_STATUS nv_unpin_cxl_buffer(void *h) { (void)h; L.unpins++; return NV_OK; }
static NV_STATUS nv_get_cxl_buffer_pages(void *h, NvU64 **pa, NvU32 *count)
{
	NvU64 first = L.va & ~4095ULL, last = (L.va + L.size - 1) & ~4095ULL;
	(void)h;
	L.pages[0] = 0x50000000ULL;
	L.pages[1] = 0x50300000ULL;
	*pa = L.pages;
	*count = (NvU32)((last - first) / 4096 + 1);
	return NV_OK;
}
static NV_STATUS nv_pin_cxl_buffer_hugepages(NvU64 va, NvU64 size, NvU32 ps, void **h)
{ (void)va; (void)size; (void)ps; (void)h; return NV_ERR_NOT_SUPPORTED; }
static NV_STATUS nv_get_cxl_buffer_hugepages(void *h, NvU64 **pa, NvU32 *c, NvU32 *ps)
{ (void)h; (void)pa; (void)c; (void)ps; return NV_ERR_NOT_SUPPORTED; }
static NV_STATUS nv_pin_host_region(NvU64 a, NvU64 s, NvU32 f, void **h)
{ (void)a; (void)s; (void)f; (void)h; return NV_ERR_NOT_SUPPORTED; }
static NV_STATUS nv_unpin_host_region(void *h) { (void)h; return NV_OK; }
static NV_STATUS nv_get_host_region_pages(void *h, NvU64 o, NvU64 s, NvU64 **p, NvU32 *c, NvU32 *f)
{ (void)h; (void)o; (void)s; (void)p; (void)c; (void)f; return NV_ERR_NOT_SUPPORTED; }
static NV_STATUS nv_register_gpu_umem(void *g, NvU64 o, NvU64 s, NvU32 f, void **h)
{ (void)g; (void)o; (void)s; (void)f; (void)h; return NV_ERR_NOT_SUPPORTED; }
static NV_STATUS nv_unregister_gpu_umem(void *h) { (void)h; return NV_OK; }

#include "nv_xdev_ext_direct_dma_actual.inc"

/* ================================================================ cases */
#define HOST_PAGES 8
static NvU64 host_pages[HOST_PAGES];

static NV_STATUS direct(const P2P_UMEM_XFER *x, NvU32 n, NvU64 window_off, NvU64 window_len,
			NvU32 page_count, NvU64 buffer_size, NvBool *hw, NvU64 *done)
{
	return RmP2PUmemDmaRequestDirect(&gpu0, host_pages, page_count, 4096, buffer_size,
					 &gpu_md, window_off, window_len, x, n, 0x1, hw, done);
}

static void expect_refused(const char *what, const P2P_UMEM_XFER *x, NvU32 n,
			   NvU64 window_off, NvU64 window_len, NvU32 page_count, NvU64 buffer)
{
	NvBool hw = NV_TRUE;
	NvU64 done = 77;
	unsigned int copies = D.copies, created = D.created;
	NV_STATUS st = direct(x, n, window_off, window_len, page_count, buffer, &hw, &done);
	CHECK(st != NV_OK && !hw && done == 0 && D.copies == copies && D.created == created,
	      "G08 %s: st=0x%x hw=%d done=%llu copies=%u memdesc=%u", what, st, hw,
	      (unsigned long long)done, D.copies - copies, D.created - created);
}

static void case_refuse_before_push(void)
{
	const NvU64 buf = HOST_PAGES * 4096ULL, win = 1 << 20;
	P2P_UMEM_XFER ok = { 0, 0, 4096 };
	P2P_UMEM_XFER zero = { 0, 0, 0 };
	P2P_UMEM_XFER big = { 0, 0, (NvU64)NV_U32_MAX + 1 };
	P2P_UMEM_XFER host_off = { buf + 1, 0, 1 };
	P2P_UMEM_XFER host_wrap = { buf - 1, 0, 2 };
	P2P_UMEM_XFER host_u64 = { UINT64_MAX, 0, 2 };
	P2P_UMEM_XFER gpu_off = { 0, win + 1, 1 };
	P2P_UMEM_XFER gpu_wrap = { 0, win - 1, 2 };
	P2P_UMEM_XFER gpu_u64 = { 0, UINT64_MAX, 4096 };
	P2P_UMEM_XFER batch[3] = { { 0, 0, 4096 }, { 4096, 4096, 4096 }, { 0, win, 1 } };
	expect_refused("zero length", &zero, 1, 0, win, HOST_PAGES, buf);
	expect_refused(">U32 length", &big, 1, 0, win, HOST_PAGES, buf);
	expect_refused("host offset", &host_off, 1, 0, win, HOST_PAGES, buf);
	expect_refused("host wrap", &host_wrap, 1, 0, win, HOST_PAGES, buf);
	expect_refused("host u64 wrap", &host_u64, 1, 0, win, HOST_PAGES, buf);
	expect_refused("window offset", &gpu_off, 1, 0, win, HOST_PAGES, buf);
	expect_refused("window wrap", &gpu_wrap, 1, 0, win, HOST_PAGES, buf);
	expect_refused("window u64 wrap", &gpu_u64, 1, 0, win, HOST_PAGES, buf);
	expect_refused("allocation-window overflow", &ok, 1, (1 << 22) - 4096, 8192, HOST_PAGES, buf);
	expect_refused("allocation-window wrap", &ok, 1, UINT64_MAX - 4095, 8192, HOST_PAGES, buf);
	expect_refused("short host coverage", &ok, 1, 0, win, 2, 3 * 4096ULL);
	expect_refused("invalid entry later in batch", batch, 3, 0, win, HOST_PAGES, buf);
	expect_refused("zero count", &ok, 0, 0, win, HOST_PAGES, buf);
	expect_refused("count above max", &ok, P2P_UMEM_MAX_XFERS + 1, 0, win, HOST_PAGES, buf);
}

static void case_offsets_and_segments(void)
{
	/* window at 0x3000 of the allocation; entry at window offset 0x1000 */
	P2P_UMEM_XFER x = { 0x800, 0x1000, 0x2000 };
	NvBool hw = NV_FALSE;
	NvU64 done = 0, total = 0;
	unsigned int i;
	NV_STATUS st;
	gpu_md.pageSize = 4096;
	st = direct(&x, 1, 0x3000, 1 << 20, HOST_PAGES, HOST_PAGES * 4096ULL, &hw, &done);
	CHECK(st == NV_OK && hw && done == 0x2000, "G09: st=0x%x hw=%d done=%llu", st, hw,
	      (unsigned long long)done);
	CHECK(D.copies >= 3, "G09: an unaligned 8 KiB copy touches at least 3 host pages (%u)",
	      D.copies);
	CHECK(D.copy[0].dst == &gpu_md && D.copy[0].dst_off == 0x4000 &&
	      D.copy[0].src_off == 0x800,
	      "G09: first chunk dst=%p off=0x%llx src off=0x%llx", (void *)D.copy[0].dst,
	      (unsigned long long)D.copy[0].dst_off, (unsigned long long)D.copy[0].src_off);
	for (i = 0; i < D.copies && i < 64; i++) {
		CHECK(D.copy[i].dst == &gpu_md && D.copy[i].src == D.host_md,
		      "G09: chunk %u changed allocation identity", i);
		CHECK(i == 0 || D.copy[i].dst_off == D.copy[i - 1].dst_off + D.copy[i - 1].size,
		      "G09: chunk %u GPU offset not contiguous", i);
		CHECK(D.copy[i].src_off % 4096 + D.copy[i].size <= 4096,
		      "G09: chunk %u crosses a host page boundary", i);
		CHECK(D.copy[i].dst_off % 4096 + D.copy[i].size <= 4096,
		      "G09: chunk %u crosses a GPU page boundary", i);
		total += D.copy[i].size;
	}
	CHECK(total == 0x2000, "G09: chunk bytes %llu", (unsigned long long)total);
	CHECK(D.destroyed == 1, "temporary host memdesc released once after success");
	gpu_md.pageSize = 1 << 16;
}

static void case_refusal_vs_entered_copy(void)
{
	P2P_UMEM_XFER x = { 0, 0, 3 * 4096 };
	NvBool hw = NV_TRUE;
	NvU64 done = 0;
	NV_STATUS st;
	D.uses_ce_false = 1;
	st = direct(&x, 1, 0, 1 << 20, HOST_PAGES, HOST_PAGES * 4096ULL, &hw, &done);
	CHECK(st == NV_ERR_NOT_SUPPORTED && !hw && D.copies == 0 && D.destroyed == 1,
	      "G10: CE refusal before submit: st=0x%x hw=%d copies=%u destroyed=%u", st, hw,
	      D.copies, D.destroyed);
	D.uses_ce_false = 0;
	D.fail_copy_at = 2;
	st = direct(&x, 1, 0, 1 << 20, HOST_PAGES, HOST_PAGES * 4096ULL, &hw, &done);
	CHECK(st != NV_OK && hw && done == 4096,
	      "G10: entered-copy failure: st=0x%x hw=%d done=%llu", st, hw,
	      (unsigned long long)done);
	CHECK(D.destroyed == 1 && D.created == 2,
	      "G10: host memdesc released after a failure inside the copy (destroyed=%u)",
	      D.destroyed);
}

static void case_bridge_poison(void)
{
	P2P_UMEM_VIDMEM_BINDING b = { .pGpu = &gpu0, .length = 1 << 20 };
	P2P_UMEM_XFER x = { 0, 0, 4096 };
	nvidia_stack_t sp;
	NvBool hw = NV_FALSE;
	NvU64 done = 0;
	unsigned int copies;
	D.fail_copy_at = 1;
	CHECK(rm_p2p_umem_dma_request(&sp, host_pages, HOST_PAGES, 4096, HOST_PAGES * 4096ULL,
				      &b, &x, 1, 1, &hw, &done) != NV_OK && hw,
	      "G10: first request must fail inside the copy");
	D.fail_copy_at = 0;
	copies = D.copies;
	CHECK(rm_p2p_umem_dma_request(&sp, host_pages, HOST_PAGES, 4096, HOST_PAGES * 4096ULL,
				      &b, &x, 1, 1, &hw, &done) == NV_ERR_INVALID_STATE &&
	      !hw && D.copies == copies,
	      "G10: bridge must poison later synchronous submissions after ambiguity");
}

/* Physical byte a surface offset names in a stub page-array memdesc. */
static NvU64 surface_byte(MEMORY_DESCRIPTOR *m, NvU64 off)
{
	NvU64 o = off + m->PteAdjust;
	return m->pages[o / m->pageSize] + o % m->pageSize;
}

static void cxl_case(NvU64 va, NvU64 expected_first_byte, int may_refuse)
{
	void *h = NULL;
	NV_STATUS st = RmP2PRegisterUmemBuffer(1 /* NV_P2P_BUFFER_TYPE_CXL */, va, 4096, 0,
					       NULL, 0, &h);
	if (st != NV_OK) {
		CHECK(may_refuse, "aligned CXL registration refused (0x%x)", st);
		CHECK(L.pins == L.unpins, "G18: refused registration leaked a lower pin");
		return;
	}
	REQUIRE(RmP2PUmemDmaRequest(&gpu0, h, 0, 0, 16, 0x1) == NV_OK, "legacy DMA");
	REQUIRE(D.copies == 1 && D.copy[0].src, "one copy");
	CHECK(surface_byte(D.copy[0].src, D.copy[0].src_off) == expected_first_byte,
	      "G18: registered byte 0 at VA 0x%llx reached the CE as physical 0x%llx, "
	      "expected 0x%llx (first-page offset lost)", (unsigned long long)va,
	      (unsigned long long)surface_byte(D.copy[0].src, D.copy[0].src_off),
	      (unsigned long long)expected_first_byte);
	RmP2PUnregisterUmemBuffer(h);
	CHECK(L.pins == L.unpins, "lower pin not released");
}
static void case_cxl_aligned(void) { cxl_case(0x10000, 0x50000000ULL, 0); }
static void case_cxl_unaligned(void) { cxl_case(0x10001, 0x50000001ULL, 1); }

struct named_case { const char *name; void (*fn)(void); };
static const struct named_case cases[] = {
	{ "refuse-before-push", case_refuse_before_push },
	{ "offsets-and-segments", case_offsets_and_segments },
	{ "refusal-vs-entered-copy", case_refusal_vs_entered_copy },
	{ "bridge-poison", case_bridge_poison },
	{ "cxl-aligned", case_cxl_aligned },
	{ "cxl-unaligned", case_cxl_unaligned },
};

int main(int argc, char **argv)
{
	unsigned int i;
	setvbuf(stdout, NULL, _IONBF, 0);
	for (i = 0; i < HOST_PAGES; i++)
		host_pages[i] = 0xA00000000ULL + i * 0x10000ULL;
	for (i = 0; argc == 2 && i < sizeof(cases) / sizeof(cases[0]); i++)
		if (!strcmp(argv[1], cases[i].name)) {
			cases[i].fn();
			return env_report(argv[1]);
		}
	printf("usage: case name\n");
	return 2;
}
