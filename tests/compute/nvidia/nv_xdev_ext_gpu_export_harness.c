/* SPDX-License-Identifier: MIT */
/* Independent host observations of actual C bodies. No device or DMA runs. */
#include <nvtypes.h>
#include <nvstatus.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NV_API_CALL
#define GFP_KERNEL 0
#define NV_P2P_UMEM_MAX_PIN_SIZE (1ULL << 40)
#define NV_P2P_UMEM_MAX_PIN_PAGES (1UL << 28)
#define NV_PRINTF(...) ((void)0)
#define nv_printf(...) ((void)0)
#define P2P_PAGE_SIZE_4K (4ULL * 1024)
#define P2P_PAGE_SIZE_2M (2ULL * 1024 * 1024)
#define P2P_MAX_BUFFER_SIZE (1ULL << 40)
#define P2P_MAX_REGISTERED_BUFFERS 256
#define P2P_DMA_FLAG_TO_GPU 1
#define ADDR_SYSMEM 1
#define ADDR_FBMEM 2
#define NV_MEMORY_UNCACHED 0
#define MEMDESC_FLAGS_NONE 0
#define AT_GPU 0
#define PDB_PROP_GPU_IS_LOST 0
#define TRANSFER_FLAGS_PREFER_CE 1
#define TRANSFER_FLAGS_REQUIRE_CE 2
struct page { int unused; };
struct list_head { void *next, *prev; };
struct mm_struct { int unused; };
typedef struct MEMORY_DESCRIPTOR { unsigned marker; NvU64 size; int space; } MEMORY_DESCRIPTOR;
typedef struct MemoryManager { int unused; } MemoryManager;
typedef struct KernelBus { int unused; } KernelBus;
typedef struct OBJGPU { NvBool bIsSOC; NvBool (*getProperty)(struct OBJGPU *, int); } OBJGPU;
typedef struct TRANSFER_SURFACE { MEMORY_DESCRIPTOR *pMemDesc; NvU64 offset; } TRANSFER_SURFACE;
typedef NvU64 RmPhysAddr;
static MemoryManager manager;
static KernelBus bus __attribute__((unused));
#define GPU_GET_MEMORY_MANAGER(g) ((void)(g), &manager)
#define GPU_GET_KERNEL_BUS(g) ((void)(g), &bus)
static NvBool property(OBJGPU *gpu, int name) { (void)gpu; (void)name; return NV_FALSE; }
static OBJGPU gpu = { NV_FALSE, property };

static struct {
    unsigned allocations, frees, live, fail_allocation, bad_free;
    unsigned reserve_calls, release_calls, quota_count;
    NvU64 quota_bytes; NvU32 quota_pages;
    NvBool quota_fail;
    unsigned pin_calls, get_calls, unpin_calls, pinned, bad_unpin;
    NvBool pin_fail, get_fail;
    unsigned md_create, md_destroy, md_fill, md_describe, ce_calls, ce_null, ce_raw;
    NvBool ce_fail;
} obs;
static void *live_alloc[128];
static unsigned host_cookie;
/* Non-address labels used only for a dependency interface; never dereferenced. */
static NvU64 host_page_labels[2] = { 0x10203040ULL, 0x50607080ULL };
static void *allocate(size_t size, int zero)
{
    unsigned i;
    void *p;
    ++obs.allocations;
    if (obs.allocations == obs.fail_allocation) return NULL;
    p = zero ? calloc(1, size) : malloc(size);
    if (!p) { fprintf(stderr, "fixture allocator exhausted\n"); exit(3); }
    for (i = 0; i < 128; ++i) if (!live_alloc[i]) { live_alloc[i] = p; ++obs.live; return p; }
    fprintf(stderr, "fixture tracking exhausted\n"); exit(3);
}
static void release(void *p)
{
    unsigned i;
    if (!p) return;
    for (i = 0; i < 128; ++i) if (live_alloc[i] == p) {
        live_alloc[i] = NULL; ++obs.frees; --obs.live; free(p); return;
    }
    ++obs.bad_free;
}
static void *kzalloc(size_t size, int flags) { (void)flags; return allocate(size, 1); }
static void kfree(void *p) { release(p); }
static void *portMemAllocNonPaged(size_t size) { return allocate(size, 0); }
static void portMemFree(void *p) { release(p); }
#define portMemSet memset
static NV_STATUS nv_p2p_umem_reserve_quota(NvU64 bytes, NvU32 pages)
{
    ++obs.reserve_calls;
    if (obs.quota_fail) return NV_ERR_INSUFFICIENT_RESOURCES;
    ++obs.quota_count; obs.quota_bytes += bytes; obs.quota_pages += pages;
    return NV_OK;
}
static NV_STATUS nv_p2p_umem_release_quota(NvU64 bytes, NvU32 pages)
{
    ++obs.release_calls;
    if (!obs.quota_count || obs.quota_bytes < bytes || obs.quota_pages < pages)
        return NV_ERR_INVALID_STATE;
    --obs.quota_count; obs.quota_bytes -= bytes; obs.quota_pages -= pages;
    return NV_OK;
}
static NV_STATUS host_pin(NvU64 address, NvU64 size, void **out)
{
    (void)address; (void)size; ++obs.pin_calls;
    if (obs.pin_fail) return NV_ERR_INSUFFICIENT_RESOURCES;
    ++obs.pinned; *out = &host_cookie; return NV_OK;
}
static NV_STATUS host_unpin(void *p)
{
    ++obs.unpin_calls;
    if (p != &host_cookie || obs.pinned == 0) ++obs.bad_unpin;
    else --obs.pinned;
    return NV_OK;
}
static NV_STATUS host_get(void *p, NvU64 **pages, NvU32 *count, NvU32 *size)
{
    ++obs.get_calls;
    if (p != &host_cookie || !obs.pinned) return NV_ERR_INVALID_STATE;
    if (obs.get_fail) return NV_ERR_INVALID_STATE;
    *pages = host_page_labels; *count = 2; if (size) *size = 4096; return NV_OK;
}
static NV_STATUS nv_pin_cxl_buffer(NvU64 a, NvU64 n, void **p) { return host_pin(a,n,p); }
static NV_STATUS nv_unpin_cxl_buffer(void *p) { return host_unpin(p); }
static NV_STATUS nv_get_cxl_buffer_pages(void *p, NvU64 **a, NvU32 *n) { return host_get(p,a,n,NULL); }
static NV_STATUS nv_pin_cxl_buffer_hugepages(NvU64 a, NvU64 n, NvU32 z, void **p)
{ (void)z; return host_pin(a,n,p); }
static NV_STATUS nv_get_cxl_buffer_hugepages(void *p, NvU64 **a, NvU32 *n, NvU32 *z)
{ return host_get(p,a,n,z); }
static NV_STATUS nv_pin_host_region(NvU64 a, NvU64 n, NvU32 z, void **p)
{ (void)z; return host_pin(a,n,p); }
static NV_STATUS nv_unpin_host_region(void *p) { return host_unpin(p); }
static NV_STATUS nv_get_host_region_pages(void *p, NvU64 o, NvU64 n, NvU64 **a, NvU32 *c, NvU32 *z)
{ (void)o; (void)n; return host_get(p,a,c,z); }
static NV_STATUS memdescCreate(MEMORY_DESCRIPTOR **out, OBJGPU *g, NvU64 size, NvU64 align,
    NvBool contiguous, int space, int cache, int flags)
{
    (void)g; (void)align; (void)contiguous; (void)cache; (void)flags;
    ++obs.md_create; *out = allocate(sizeof(**out), 1);
    if (!*out) return NV_ERR_NO_MEMORY;
    (*out)->marker = 0; (*out)->size = size; (*out)->space = space; return NV_OK;
}
static void memdescDestroy(MEMORY_DESCRIPTOR *p) { ++obs.md_destroy; release(p); }
static void memdescFillPages(MEMORY_DESCRIPTOR *p, NvU64 offset, RmPhysAddr *pages, NvU32 count, NvU32 size)
{ (void)offset; (void)size; ++obs.md_fill; if (pages && count) p->marker = 0xc001; }
static void memdescSetPageSize(MEMORY_DESCRIPTOR *p, int which, NvU32 size)
{ (void)p; (void)which; (void)size; }
static void memdescDescribe(MEMORY_DESCRIPTOR *p, int space, NvU64 address, NvU64 size)
{ (void)space; (void)address; (void)size; ++obs.md_describe; p->marker = 0xdead; }
static NV_STATUS memmgrMemCopy(MemoryManager *m, TRANSFER_SURFACE *dst, TRANSFER_SURFACE *src, NvU32 size, NvU32 flags)
{
    (void)m; (void)size; (void)flags; ++obs.ce_calls;
    if (!dst->pMemDesc || !src->pMemDesc) ++obs.ce_null;
    if ((dst->pMemDesc && dst->pMemDesc->marker == 0xdead) ||
        (src->pMemDesc && src->pMemDesc->marker == 0xdead)) ++obs.ce_raw;
    /* A deliberately permissive last-boundary dependency exposes bad callers.
     * Returning success here is not evidence of DMA or a hardware crash. */
    return obs.ce_fail ? NV_ERR_INVALID_STATE : NV_OK;
}
static NvU32 g_p2pRegisteredBufferCount;
static NvU64 g_p2pTotalRegisteredSize;
#include "independent_export_actual.inc"

static unsigned checks, failures;
#define CHECK(want, got) do { \
    unsigned long long expected_ = (unsigned long long)(want); \
    unsigned long long actual_ = (unsigned long long)(got); ++checks; \
    if (expected_ != actual_) { ++failures; fprintf(stderr, \
        "ORACLE %s:%d %s expected=%llu actual=%llu\n", __FILE__, __LINE__, #got, expected_, actual_); } \
} while (0)
static void balanced(void)
{
    CHECK(0, obs.live); CHECK(0, obs.bad_free); CHECK(0, obs.quota_count);
    CHECK(0, obs.quota_bytes); CHECK(0, obs.quota_pages); CHECK(0, obs.pinned);
    CHECK(0, obs.bad_unpin); CHECK(0, g_p2pRegisteredBufferCount); CHECK(0, g_p2pTotalRegisteredSize);
}
static NV_STATUS register_rm(void **out, NvU64 offset, NvU64 size, NvU32 frame)
{ return RmP2PRegisterUmemBuffer(NV_P2P_BUFFER_TYPE_GPU_EXPORT, 0, size, frame,
                              (void *)(uintptr_t)0x12345678, offset, out); }
static void refuse(NV_STATUS status, void *handle)
{
    CHECK(NV_ERR_NOT_SUPPORTED, status); CHECK(1, handle == NULL);
    CHECK(0, obs.live); CHECK(0, obs.quota_count); CHECK(0, g_p2pRegisteredBufferCount);
    CHECK(0, g_p2pTotalRegisteredSize);
}
static void cleanup(void *handle, int lower)
{ if (handle) CHECK(NV_OK, lower ? nv_unregister_gpu_umem(handle) : RmP2PUnregisterUmemBuffer(handle)); }

static void legacy_request(int pages, NvU32 direction)
{
    void *out = NULL;
    P2P_UMEM_BUFFER_HANDLE old = {0};
    NV_STATUS status = register_rm(&out, 0, 8192, 4096);
    void *target = out;
    /* Also protect cleanup-era records after registration starts refusing. The
     * real historical layout is seeded, not a replacement registration path. */
    if (!out) {
        CHECK(NV_ERR_NOT_SUPPORTED, status);
        old.size = 8192; old.frameSize = 4096; old.pageSize = 4096;
        old.pageCount = 2; old.bufferType = NV_P2P_BUFFER_TYPE_GPU_EXPORT;
        old.bRegistered = NV_TRUE; old.bGpuBacked = NV_TRUE;
        old.gpuMemHandle = (void *)(uintptr_t)0x12345678; target = &old;
    }
    if (pages) {
        NvU64 addresses[2] = { UINT64_C(0xa5a5a5a5a5a5a5a5), UINT64_C(0xa5a5a5a5a5a5a5a5) };
        NvU32 count = 0xabababab, size = 0xcdcdcdcd;
        status = RmP2PGetUmemPages(target, 0, 8192, addresses, &count, &size);
        printf("OBS pages status=%u count=%u size=%u address0=%llx address1=%llx\n", status,
            count, size, (unsigned long long)addresses[0], (unsigned long long)addresses[1]);
        CHECK(1, status != NV_OK); /* no address export exists for this record */
        CHECK(0xababababU, count); CHECK(0xcdcdcdcdU, size);
        CHECK(UINT64_C(0xa5a5a5a5a5a5a5a5), addresses[0]);
        CHECK(UINT64_C(0xa5a5a5a5a5a5a5a5), addresses[1]);
    } else {
        status = RmP2PUmemDmaRequest(&gpu, target, 0x4000, 0, 4096, direction);
        printf("OBS legacy status=%u direction=%u ce_calls=%u ce_null=%u md_create=%u md_fill=%u\n",
            status, direction, obs.ce_calls, obs.ce_null, obs.md_create, obs.md_fill);
        CHECK(1, status != NV_OK); CHECK(0, obs.ce_calls); CHECK(0, obs.ce_null);
        CHECK(0, obs.md_create); CHECK(0, obs.md_describe);
    }
    cleanup(out, 0); balanced();
}
static void host_case(const char *name)
{
    int host = strstr(name, "host") != NULL;
    void *out = NULL;
    NvU64 addresses[2] = {0,0}; NvU32 count = 0, size = 0;
    NV_STATUS status;
    obs.get_fail = strstr(name, "get-fail") != NULL;
    obs.pin_fail = strstr(name, "pin-fail") != NULL;
    status = RmP2PRegisterUmemBuffer(host ? NV_P2P_BUFFER_TYPE_HOST_REGION : NV_P2P_BUFFER_TYPE_CXL,
                                   4096, 8192, 4096, NULL, 0, &out);
    if (obs.get_fail || obs.pin_fail) {
        CHECK(1, status != NV_OK); CHECK(1, out == NULL);
        CHECK(obs.pin_fail ? 0 : 1, obs.unpin_calls);
    } else {
        CHECK(NV_OK, status); CHECK(1, out != NULL);
        if (out) {
            CHECK(NV_OK, RmP2PGetUmemPages(out, 0, 8192, addresses, &count, &size));
            CHECK(2, count); CHECK(4096, size);
            CHECK(host_page_labels[0], addresses[0]); CHECK(host_page_labels[1], addresses[1]);
            CHECK(0, ((P2P_UMEM_BUFFER_HANDLE *)out)->bGpuBacked);
            cleanup(out, 0); CHECK(1, obs.unpin_calls);
        }
    }
    CHECK(1, obs.pin_calls); balanced();
}
static void old_cleanup(void)
{
    nv_p2p_umem_buffer_t *lower = kzalloc(sizeof(*lower), GFP_KERNEL);
    P2P_UMEM_BUFFER_HANDLE *rm = portMemAllocNonPaged(sizeof(*rm));
    if (!lower || !rm) exit(3);
    memset(rm, 0, sizeof(*rm));
    CHECK(NV_OK, nv_p2p_umem_reserve_quota(8192, 2));
    lower->bufferType = NV_P2P_BUFFER_TYPE_GPU_EXPORT; lower->size = 8192;
    lower->pageCount = 2; lower->bGpuBacked = NV_TRUE;
    rm->pKernelHandle = lower; rm->bufferType = NV_P2P_BUFFER_TYPE_GPU_EXPORT;
    rm->size = 8192; rm->bRegistered = NV_TRUE; rm->bGpuBacked = NV_TRUE;
    g_p2pRegisteredBufferCount = 1; g_p2pTotalRegisteredSize = 8192;
    CHECK(NV_OK, RmP2PUnregisterUmemBuffer(rm)); CHECK(1, obs.release_calls);
    CHECK(2, obs.frees); balanced();
}
int main(int argc, char **argv)
{
    const char *name;
    NV_STATUS status;
    void *out = NULL;
    if (argc != 2) return 3;
    name = argv[1];
    if (!strcmp(name, "fixture-selfcheck")) {
        void *p = allocate(8, 1); release(p); release(p);
        CHECK(1, obs.bad_free); obs.bad_free = 0;
        obs.fail_allocation = obs.allocations + 1; CHECK(1, allocate(8, 0) == NULL);
        obs.fail_allocation = 0; obs.quota_fail = NV_TRUE;
        CHECK(NV_ERR_INSUFFICIENT_RESOURCES, nv_p2p_umem_reserve_quota(8,1));
        obs.quota_fail = NV_FALSE; CHECK(0, obs.quota_count);
        obs.ce_fail = NV_TRUE;
        { TRANSFER_SURFACE a = {0}, b = {0};
          CHECK(NV_ERR_INVALID_STATE, memmgrMemCopy(&manager,&a,&b,1,0)); CHECK(1, obs.ce_null); }
        balanced();
    } else if (!strcmp(name, "G01-lower")) {
        status = nv_register_gpu_umem((void *)(uintptr_t)0x12345678, 0, 4096, 4096, &out);
        refuse(status, out); cleanup(out, 1); balanced();
    } else if (!strcmp(name, "G01-rm")) {
        status = register_rm(&out, 0, 4096, 4096); refuse(status, out); cleanup(out, 0); balanced();
    } else if (!strcmp(name, "G02-to") || !strcmp(name, "G02-from")) {
        legacy_request(0, !strcmp(name, "G02-to"));
    } else if (!strcmp(name, "G03-pages")) {
        legacy_request(1, 0);
    } else if (!strncmp(name, "G04-", 4)) {
        NvU64 offset = 0, size = 8192; NvU32 frame = 4096;
        if (!strcmp(name, "G04-wrap")) offset = UINT64_MAX - 4095;
        else if (!strcmp(name, "G04-zero-frame")) frame = 0;
        else if (!strcmp(name, "G04-nonpower")) frame = 3;
        else if (!strcmp(name, "G04-nonmultiple")) size = 8193;
        else if (!strcmp(name, "G04-count")) { frame = 1; size = (NvU64)NV_P2P_UMEM_MAX_PIN_PAGES + 1; }
        else return 3;
        status = nv_register_gpu_umem((void *)(uintptr_t)0x12345678, offset, size, frame, &out);
        CHECK(1, status != NV_OK); CHECK(1, out == NULL); cleanup(out,1); balanced();
        out = NULL; status = register_rm(&out, offset, size, frame);
        CHECK(1, status != NV_OK); CHECK(1, out == NULL); cleanup(out,0); balanced();
    } else if (!strcmp(name, "G05-repeat")) {
        unsigned i;
        for (i = 0; i < 8; ++i) { out = NULL; status = register_rm(&out, i * 4096, 4096, 4096);
            refuse(status, out); cleanup(out,0); balanced(); }
    } else if (!strcmp(name, "G05-old-cleanup")) {
        old_cleanup();
    } else if (!strncmp(name, "G05-", 4)) {
        int lower = 0;
        if (!strcmp(name, "G05-quota")) obs.quota_fail = NV_TRUE;
        else if (!strcmp(name, "G05-lower-alloc")) { obs.fail_allocation = 1; lower = 1; }
        else if (!strcmp(name, "G05-rm-alloc")) obs.fail_allocation = 1;
        else if (!strcmp(name, "G05-inner-alloc")) obs.fail_allocation = 2;
        else return 3;
        status = lower ? nv_register_gpu_umem((void *)(uintptr_t)0x12345678,0,4096,4096,&out)
                       : register_rm(&out,0,4096,4096);
        CHECK(1, status != NV_OK); CHECK(1, out == NULL); balanced();
    } else if (!strcmp(name, "G06-xsk")) {
        status = RmP2PRegisterUmemBuffer(NV_P2P_BUFFER_TYPE_VERIFIED_XSK,4096,8192,4096,NULL,0,&out);
        CHECK(NV_ERR_INSUFFICIENT_PERMISSIONS, status); CHECK(1, out == NULL);
        CHECK(0, obs.pin_calls); balanced();
    } else if (!strncmp(name, "G06-", 4)) {
        host_case(name);
    } else return 3;
    printf("OBS case=%s allocations=%u frees=%u live=%u quota=%u rm_count=%u pin=%u unpin=%u ce=%u null=%u\n",
        name, obs.allocations, obs.frees, obs.live, obs.quota_count, g_p2pRegisteredBufferCount,
        obs.pin_calls, obs.unpin_calls, obs.ce_calls, obs.ce_null);
    printf("CHECKS %u failures=%u; ordinary host dependency observations only\n", checks, failures);
    return failures ? 1 : 0;
}
