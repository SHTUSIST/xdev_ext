/* SPDX-License-Identifier: MIT */
/* Host-only bookkeeping test. No kernel pin, GPU, MMIO or transfer executes. */
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t NvU64;
typedef uint32_t NvU32;
typedef int NvBool;
typedef int NV_STATUS;
#define NV_TRUE 1
#define NV_FALSE 0
#define NV_OK 0
#define NV_ERR_INVALID_ARGUMENT 2
#define NV_ERR_INVALID_STATE 3
#define NV_ERR_NO_MEMORY 4
#define NV_ERR_INSUFFICIENT_RESOURCES 5
#define NV_API_CALL
#define unlikely(x) (x)
#define GFP_KERNEL 0
#define FOLL_WRITE 1
#define FOLL_LONGTERM 2
#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1UL))
#define NV_P2P_UMEM_MAX_PIN_SIZE (1ULL << 40)
#define NV_P2P_UMEM_MAX_PIN_PAGES (1UL << 28)
#ifndef NV_P2P_UMEM_STRICT_SECURITY_CHECKS
#define NV_P2P_UMEM_STRICT_SECURITY_CHECKS 1
#endif
#define CXL_HUGEPAGE_SIZE (2ULL * 1024 * 1024)
#define CXL_HUGEPAGE_SHIFT 21
#define nv_printf(...) ((void)0)

struct page { unsigned index; };
struct list_head { void *next, *prev; };
struct mm_struct { int unused; };
static struct mm_struct host_mm;
static struct { struct mm_struct *mm; } host_current = { &host_mm };
#define current (&host_current)

static struct {
    unsigned allocations, releases, live, fail_allocation;
    size_t array_bytes[2];
    unsigned reserve_calls, reserved_calls, release_calls;
    int quota_failure;
    NvU64 reserved_bytes, released_bytes;
    NvU32 reserved_pages, released_pages;
    unsigned pin_calls, unpin_calls, requested_pages, duplicate_unpins;
    int pin_result, null_entry;
    unsigned lock_calls, unlock_calls;
    unsigned allocator_mismatches, vmalloc_calls;
    int lock_depth, pin_without_lock;
    unsigned char unpinned[1024];
} fixture;
static struct page host_pages[1024];
static struct { void *pointer; int kind; } host_allocations[3];

static void *host_alloc(size_t bytes, int zero, int kind)
{
    void *result;
    ++fixture.allocations;
    if (fixture.allocations == fixture.fail_allocation || bytes > 1024 * 1024)
        return NULL;
    if (fixture.allocations > 1 && fixture.allocations <= 3)
        fixture.array_bytes[fixture.allocations - 2] = bytes;
    result = zero ? calloc(1, bytes) : malloc(bytes);
    if (result) {
        host_allocations[fixture.allocations-1].pointer = result;
        host_allocations[fixture.allocations-1].kind = kind;
        ++fixture.live;
        fixture.vmalloc_calls += (kind == 1);
    }
    return result;
}
static void *kzalloc(size_t bytes, int flags)
{ (void)flags; return host_alloc(bytes, 1, 0); }
static void *kmalloc(size_t bytes, int flags)
{ (void)flags; return host_alloc(bytes, 0, 0); }
static void *vmalloc(size_t bytes) { return host_alloc(bytes, 0, 1); }
static void host_free(void *item, int kind)
{
    unsigned i;
    if (!item) return;
    for (i = 0; i < 3; ++i) {
        if (host_allocations[i].pointer == item) {
            if (host_allocations[i].kind != kind) ++fixture.allocator_mismatches;
            host_allocations[i].pointer = NULL;
            ++fixture.releases; --fixture.live; free(item); return;
        }
    }
    ++fixture.allocator_mismatches;
}
static void kfree(void *item) { host_free(item, 0); }
static void vfree(void *item) { host_free(item, 1); }
static NV_STATUS cxl_reserve_quota(NvU64 bytes, NvU32 pages)
{
    ++fixture.reserve_calls;
    if (fixture.quota_failure) return NV_ERR_INSUFFICIENT_RESOURCES;
    ++fixture.reserved_calls;
    fixture.reserved_bytes = bytes; fixture.reserved_pages = pages;
    return NV_OK;
}
static NV_STATUS cxl_release_quota(NvU64 bytes, NvU32 pages)
{
    ++fixture.release_calls;
    fixture.released_bytes = bytes; fixture.released_pages = pages;
    return NV_OK;
}
static void nv_mmap_read_lock(struct mm_struct *mm)
{ (void)mm; ++fixture.lock_calls; ++fixture.lock_depth; }
static void nv_mmap_read_unlock(struct mm_struct *mm)
{ (void)mm; ++fixture.unlock_calls; --fixture.lock_depth; }
static int host_pin(unsigned long start, unsigned count, unsigned flags,
                    struct page **pages)
{
    unsigned returned, i;
    int result = fixture.pin_result == INT_MAX ? (int)count : fixture.pin_result;
    (void)start; (void)flags;
    ++fixture.pin_calls; fixture.requested_pages = count;
    if (fixture.lock_depth != 1) ++fixture.pin_without_lock;
    returned = result > 0 ? (unsigned)result : 0;
    if (returned > count || count > 1024) return -ENOMEM;
    for (i = 0; i < returned; ++i) {
        host_pages[i].index = i;
        pages[i] = fixture.null_entry == (int)i ? NULL : &host_pages[i];
    }
    return result;
}
#define NV_PIN_USER_PAGES(start, count, flags, pages) host_pin(start,count,flags,pages)
static void host_unpin(struct page *page)
{
    if (!page) return;
    ++fixture.unpin_calls;
    if (fixture.unpinned[page->index]++) ++fixture.duplicate_unpins;
}
#define NV_UNPIN_USER_PAGE(page) host_unpin(page)
/* Opaque nonzero test label only; never a physical address or DMA mapping. */
#define page_to_phys(page) ((NvU64)((page)->index + 1U))

/* Generated from the actual checked-out source, with bodies unchanged. */
#include "nv_xdev_ext_umem_host_contract_actual.inc"

static unsigned checks, failures;
#define CHECK(want, got) do { \
    unsigned long long expected_ = (unsigned long long)(want); \
    unsigned long long actual_ = (unsigned long long)(got); ++checks; \
    if (expected_ != actual_) { ++failures; \
        fprintf(stderr, "%s:%d %s expected=%llu actual=%llu\n", \
                __FILE__, __LINE__, #got, expected_, actual_); } \
} while (0)

static NV_STATUS pin(int huge, NvU64 address, NvU64 bytes, void **handle)
{
    return huge ? nv_pin_cxl_buffer_hugepages(address, bytes, CXL_HUGEPAGE_SIZE, handle)
                : nv_pin_cxl_buffer(address, bytes, handle);
}
static void balanced(void)
{
    CHECK(0, fixture.live);
    CHECK(0, fixture.lock_depth);
    CHECK(fixture.lock_calls, fixture.unlock_calls);
    CHECK(0, fixture.pin_without_lock);
    CHECK(0, fixture.duplicate_unpins);
    CHECK(0, fixture.allocator_mismatches);
    CHECK(fixture.reserved_calls, fixture.release_calls);
    if (fixture.reserved_calls) {
        CHECK(fixture.reserved_bytes, fixture.released_bytes);
        CHECK(fixture.reserved_pages, fixture.released_pages);
    }
}

static void test_span(int huge, NvU64 offset, NvU64 bytes, unsigned wanted)
{
    NvU64 address = CXL_HUGEPAGE_SIZE + offset;
    void *handle = NULL;
    nv_p2p_umem_buffer_t *buffer;
    CHECK(NV_OK, pin(huge, address, bytes, &handle));
    if (!handle) return;
    buffer = handle;
    CHECK(wanted, fixture.requested_pages);
    CHECK(wanted, fixture.reserved_pages);
    CHECK(wanted, buffer->pageCount);
    CHECK(PAGE_SIZE, buffer->pageSize);
    CHECK(NV_FALSE, buffer->bHugePages);
    CHECK(wanted * sizeof(NvU64), fixture.array_bytes[0]);
    CHECK(wanted * sizeof(struct page *), fixture.array_bytes[1]);
    CHECK(wanted > 512 ? 2 : 0, fixture.vmalloc_calls);
    CHECK(bytes, buffer->size);
    CHECK(address, buffer->userVirtAddr);
    CHECK(NV_OK, nv_unpin_cxl_buffer(handle));
    CHECK(wanted, fixture.unpin_calls);
    balanced();
}
static void test_success(int huge, int unaligned, unsigned pages)
{
    if (unaligned == 1) test_span(huge, 1, 2 * PAGE_SIZE, 3);
    else if (unaligned == 2) test_span(huge, 0, 2 * PAGE_SIZE + 1, 3);
    else test_span(huge, 0, (NvU64)pages * PAGE_SIZE, pages);
}

static void test_failure(int huge, int pin_result, unsigned fail_alloc, int null_entry)
{
    void *handle = NULL;
    unsigned wanted_pins;
    fixture.pin_result = pin_result;
    fixture.fail_allocation = fail_alloc;
    fixture.null_entry = null_entry;
    CHECK(NV_ERR_NO_MEMORY, pin(huge, CXL_HUGEPAGE_SIZE, 4 * PAGE_SIZE, &handle));
    CHECK(0, handle != NULL);
    wanted_pins = fail_alloc ? 0 : (pin_result > 0 && pin_result != INT_MAX ? (unsigned)pin_result : 0);
    if (null_entry >= 0) wanted_pins = 3;
    CHECK(wanted_pins, fixture.unpin_calls);
    balanced();
}

static void test_invalid(int huge, const char *kind)
{
    NvU64 address = PAGE_SIZE, bytes = PAGE_SIZE;
    void *handle = (void *)(uintptr_t)1;
    if (!strcmp(kind, "zero")) bytes = 0;
    else if (!strcmp(kind, "overflow")) address = UINT64_MAX - PAGE_SIZE + 1;
    else if (!strcmp(kind, "narrow")) bytes = ((NvU64)UINT32_MAX + 2) * PAGE_SIZE;
    else if (!strcmp(kind, "narrowzero")) bytes = ((NvU64)UINT32_MAX + 1) * PAGE_SIZE;
    else if (!strcmp(kind, "limit")) bytes = ((NvU64)NV_P2P_UMEM_MAX_PIN_PAGES + 1) * PAGE_SIZE;
    CHECK(NV_ERR_INVALID_ARGUMENT, pin(huge, address, bytes, &handle));
    CHECK(1, handle == (void *)(uintptr_t)1 || handle == NULL);
    CHECK(0, fixture.allocations);
    CHECK(0, fixture.reserve_calls);
    CHECK(0, fixture.pin_calls);
    balanced();
}

static void test_null_output_or_quota_refusal(int huge, int null_output)
{
    void *handle = NULL;
    fixture.quota_failure = !null_output;
    CHECK(null_output ? NV_ERR_INVALID_ARGUMENT : NV_ERR_INSUFFICIENT_RESOURCES,
          pin(huge, CXL_HUGEPAGE_SIZE, PAGE_SIZE, null_output ? NULL : &handle));
    CHECK(0, fixture.allocations); CHECK(0, fixture.pin_calls);
    CHECK(null_output ? 0 : 1, fixture.reserve_calls);
    balanced();
}

static void test_info(const char *kind)
{
    nv_p2p_umem_buffer_t buffer;
    NvU32 type = 91, frame_size = 92, frame_count = 93;
    NvU64 size = 94;
    NvBool gpu = 95;
    NV_STATUS result;
    memset(&buffer, 0, sizeof(buffer));
    buffer.size = 8192; buffer.frameSize = 2048;
    buffer.bufferType = NV_P2P_BUFFER_TYPE_CXL;
    if (!strcmp(kind, "zero")) buffer.frameSize = 0;
    if (!strcmp(kind, "nondiv")) buffer.size++;
    if (!strcmp(kind, "wide")) buffer.size = ((NvU64)UINT32_MAX + 1) * buffer.frameSize;
    if (!strcmp(kind, "max")) buffer.size = (NvU64)UINT32_MAX * buffer.frameSize;
    if (!strcmp(kind, "optional")) {
        buffer.frameSize = 0;
        CHECK(NV_OK, nv_get_umem_buffer_info(&buffer, &type, &size, &frame_size, NULL, &gpu));
        CHECK(8192, size); CHECK(0, frame_size);
        return;
    }
    result = nv_get_umem_buffer_info(&buffer, &type, &size, &frame_size, &frame_count, &gpu);
    if (!strcmp(kind, "valid") || !strcmp(kind, "max")) {
        CHECK(NV_OK, result); CHECK(!strcmp(kind, "max") ? UINT32_MAX : 4, frame_count);
        CHECK(buffer.size, size);
        CHECK(2048, frame_size); CHECK(NV_P2P_BUFFER_TYPE_CXL, type); CHECK(0, gpu);
    } else {
        CHECK(NV_ERR_INVALID_STATE, result);
        CHECK(91, type); CHECK(92, frame_size); CHECK(93, frame_count);
        CHECK(94, size); CHECK(95, gpu);
    }
}

int main(int argc, char **argv)
{
    int huge;
    if (argc != 3) return 2;
    huge = atoi(argv[1]); fixture.pin_result = INT_MAX; fixture.null_entry = -1;
    if (!strcmp(argv[2], "normal")) test_success(huge, 0, 2);
    else if (!strcmp(argv[2], "hint2m")) test_success(huge, 0, (unsigned)(CXL_HUGEPAGE_SIZE / PAGE_SIZE));
    else if (!strcmp(argv[2], "array512")) test_success(huge, 0, 512);
    else if (!strcmp(argv[2], "array513")) test_success(huge, 0, 513);
    else if (!strcmp(argv[2], "unaligned")) test_success(huge, 1, 0);
    else if (!strcmp(argv[2], "unaligned-length")) test_success(huge, 2, 0);
    else if (!strcmp(argv[2], "bytes1")) test_span(huge, 0, 1, 1);
    else if (!strcmp(argv[2], "bytes-page-minus1")) test_span(huge, 0, PAGE_SIZE-1, 1);
    else if (!strcmp(argv[2], "bytes-page")) test_span(huge, 0, PAGE_SIZE, 1);
    else if (!strcmp(argv[2], "bytes-page-plus1")) test_span(huge, 0, PAGE_SIZE+1, 2);
    else if (!strcmp(argv[2], "offset-page-minus1")) test_span(huge, 1, PAGE_SIZE-1, 1);
    else if (!strcmp(argv[2], "offset-page")) test_span(huge, 1, PAGE_SIZE, 2);
    else if (!strcmp(argv[2], "null-output")) test_null_output_or_quota_refusal(huge, 1);
    else if (!strcmp(argv[2], "quota-refusal")) test_null_output_or_quota_refusal(huge, 0);
    else if (!strcmp(argv[2], "short")) test_failure(huge, 2, 0, -1);
    else if (!strcmp(argv[2], "pinerror")) test_failure(huge, -ENOMEM, 0, -1);
    else if (!strcmp(argv[2], "pinnone")) test_failure(huge, 0, 0, -1);
    else if (!strcmp(argv[2], "nullentry")) test_failure(huge, INT_MAX, 0, 1);
    else if (!strncmp(argv[2], "alloc", 5)) test_failure(huge, INT_MAX, (unsigned)atoi(argv[2]+5), -1);
    else if (!strncmp(argv[2], "invalid-", 8)) test_invalid(huge, argv[2]+8);
    else if (!strncmp(argv[2], "info-", 5)) test_info(argv[2]+5);
    else return 2;
    if (failures) { fprintf(stderr, "FAIL %u/%u checks\n", failures, checks); return 1; }
    printf("PASS %u ordinary host bookkeeping checks\n", checks);
    return 0;
}
