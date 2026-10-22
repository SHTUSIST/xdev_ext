// SPDX-License-Identifier: MIT
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t NvU32;
typedef uint64_t NvU64;
#define NV_INLINE inline

#include "../src/nvidia/inc/kernel/mem_mgr/p2p_umem_chunk.h"

static unsigned int checks;

#define CHECK_EQ(actual, expected)                                            \
    do {                                                                      \
        NvU32 got_ = (actual);                                                \
        NvU32 want_ = (expected);                                             \
        checks++;                                                             \
        if (got_ != want_) {                                                  \
            fprintf(stderr, "%s:%d: got %" PRIu32 ", want %" PRIu32 "\n", \
                    __FILE__, __LINE__, got_, want_);                         \
            return 1;                                                         \
        }                                                                     \
    } while (0)

int main(void)
{
    /* A CE call must never span either scatter/gather page boundary. */
    CHECK_EQ(nvP2PUmemCeChunkSize(0, 4096, 0, 65536, 8192), 4096);
    CHECK_EQ(nvP2PUmemCeChunkSize(4095, 4096, 0, 65536, 8192), 1);
    CHECK_EQ(nvP2PUmemCeChunkSize(0, 4096, 65535, 65536, 8192), 1);
    CHECK_EQ(nvP2PUmemCeChunkSize(2048, 4096, 63488, 65536, 8192), 2048);

    /* The final call is bounded by the bytes left, including large pages. */
    CHECK_EQ(nvP2PUmemCeChunkSize(0, 2U * 1024U * 1024U,
                                 0, 128U * 1024U, 4032), 4032);
    CHECK_EQ(nvP2PUmemCeChunkSize(0, 4096, 0, 65536, UINT32_MAX), 4096);

    /* Invalid state fails closed instead of permitting a zero-progress loop. */
    CHECK_EQ(nvP2PUmemCeChunkSize(0, 0, 0, 65536, 1), 0);
    CHECK_EQ(nvP2PUmemCeChunkSize(0, 4096, 0, 0, 1), 0);
    CHECK_EQ(nvP2PUmemCeChunkSize(0, 4096, 0, 65536, 0), 0);

    printf("nv_xdev_ext_ce_chunk_test: PASS (%u checks)\n", checks);
    return 0;
}
