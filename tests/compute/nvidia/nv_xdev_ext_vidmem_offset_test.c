// SPDX-License-Identifier: MIT
/*
 * Offset arithmetic of a CE window bound to a vidmem allocation: the GPU side
 * of every XDEV_EXT CE transfer is (vidmem memdesc, offset), never a P2P page table
 * address.
 */
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

typedef uint8_t NvBool;
typedef uint32_t NvU32;
typedef uint64_t NvU64;
#define NV_TRUE ((NvBool)1)
#define NV_FALSE ((NvBool)0)
#define NV_U32_MAX UINT32_MAX
#define NV_INLINE inline

#include "../src/nvidia/inc/kernel/mem_mgr/p2p_umem_vidmem.h"

static unsigned int checks;
static unsigned int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, \
                    #cond);                                                  \
            failures++;                                                      \
        }                                                                    \
    } while (0)

#define KB(x) ((NvU64)(x) << 10)
#define MB(x) ((NvU64)(x) << 20)

static NvBool xfer(NvU64 winOff, NvU64 winLen, NvU64 gpuOff, NvU64 size,
                   NvU64 expect)
{
    NvU64 got = 0xdeadbeef;

    if (!nvP2PVidmemXferOffset(winOff, winLen, gpuOff, size, &got))
        return NV_FALSE;
    return got == expect;
}

static NvBool xfer_refused(NvU64 winOff, NvU64 winLen, NvU64 gpuOff,
                           NvU64 size)
{
    NvU64 got = 0xdeadbeef;

    return !nvP2PVidmemXferOffset(winOff, winLen, gpuOff, size, &got) &&
           got == 0xdeadbeef;
}

static NvBool seg(NvU64 windowStart, NvU64 pageSize, NvBool contiguous,
                  NvU32 expect)
{
    NvU32 got = 0xdeadbeef;

    return nvP2PVidmemSegSize(windowStart, pageSize, contiguous, &got) &&
           got == expect;
}

static NvBool seg_refused(NvU64 pageSize)
{
    NvU32 got = 0xdeadbeef;

    return !nvP2PVidmemSegSize(0, pageSize, NV_FALSE, &got) &&
           got == 0xdeadbeef;
}

int main(void)
{
    /* A registered GPU VA range: non-empty and not wrapping. */
    CHECK(!nvP2PVidmemRangeValid(0, 0));
    CHECK(nvP2PVidmemRangeValid(0, 1));
    CHECK(nvP2PVidmemRangeValid(UINT64_MAX, 1));
    CHECK(!nvP2PVidmemRangeValid(UINT64_MAX, 2));
    CHECK(nvP2PVidmemRangeValid(UINT64_MAX - KB(4) + 1, KB(4)));
    CHECK(!nvP2PVidmemRangeValid(UINT64_MAX - KB(4) + 1, KB(4) + 1));
    CHECK(!nvP2PVidmemRangeValid(KB(64), UINT64_MAX));

    /* The window lies inside the allocation's memdesc. */
    CHECK(nvP2PVidmemWindowValid(MB(8), 0, MB(8)));
    CHECK(nvP2PVidmemWindowValid(MB(8), KB(4), MB(8) - KB(4)));
    CHECK(!nvP2PVidmemWindowValid(MB(8), KB(4), MB(8)));
    CHECK(!nvP2PVidmemWindowValid(MB(8), MB(8), 1));
    CHECK(!nvP2PVidmemWindowValid(MB(8), 0, 0));
    CHECK(!nvP2PVidmemWindowValid(MB(8), UINT64_MAX, 1));
    CHECK(!nvP2PVidmemWindowValid(MB(8), 1, UINT64_MAX));

    /* Window-relative transfer -> memdesc offset, subtraction form. */
    CHECK(xfer(KB(64), KB(128), 0, KB(128), KB(64)));
    CHECK(xfer(KB(64), KB(128), KB(128) - 16, 16, KB(64) + KB(128) - 16));
    CHECK(xfer(0, MB(8), MB(2) - 1, 2, MB(2) - 1));
    CHECK(xfer_refused(KB(64), KB(128), KB(128) - 16, 17));
    CHECK(xfer_refused(KB(64), KB(128), KB(128), 1));
    CHECK(xfer_refused(KB(64), KB(128), 0, 0));
    CHECK(xfer_refused(KB(64), KB(128), UINT64_MAX, 1));
    CHECK(xfer_refused(KB(64), KB(128), 1, UINT64_MAX));
    CHECK(xfer_refused(UINT64_MAX, 2, 1, 1));
    CHECK(xfer(UINT64_MAX - 1, 1, 0, 1, UINT64_MAX - 1));

    /*
     * Device-contiguous segment of the window in window offsets: a
     * contiguous allocation is one segment (0); otherwise the GPU page,
     * shrunk to the largest power of two that keeps window offset 0 on a
     * segment boundary of the physical pages.
     */
    CHECK(seg(0, KB(64), NV_TRUE, 0));
    CHECK(seg(KB(4), KB(64), NV_TRUE, 0));
    CHECK(seg(0, KB(64), NV_FALSE, KB(64)));
    CHECK(seg(KB(64), KB(64), NV_FALSE, KB(64)));
    CHECK(seg(MB(6), MB(2), NV_FALSE, MB(2)));
    CHECK(seg(KB(4), KB(64), NV_FALSE, KB(4)));
    CHECK(seg(KB(12), KB(64), NV_FALSE, KB(4)));
    CHECK(seg(KB(96), KB(64), NV_FALSE, KB(32)));
    CHECK(seg(KB(64) + 256, KB(64), NV_FALSE, 256));
    CHECK(seg(1, KB(4), NV_FALSE, 1));
    CHECK(seg(0, KB(4), NV_FALSE, KB(4)));
    CHECK(seg_refused(0));
    CHECK(seg_refused(KB(48)));
    CHECK(seg_refused((NvU64)1 << 32));

    printf("nv_xdev_ext_vidmem_offset_test: %u checks, %u failures\n", checks,
           failures);
    return failures != 0;
}
