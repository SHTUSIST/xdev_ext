// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * GPU XDP P2P - host-UMEM staged networking with GPU acceleration
 *
 * This application demonstrates:
 * 1. AF_XDP UMEM setup on eno1
 * 2. GPU P2P DMA registration of UMEM
 * 3. CPU-copy-free CE transfers between host XSK UMEM and VRAM
 * 4. GPU processing and TX back
 *
 * This is not NIC-to-VRAM GPUDirect: the NIC and GPU share packet data through
 * registered host XSK UMEM.
 *
 * Requires:
 * - NVIDIA driver with P2P UMEM support (580.126.09+)
 * - libxdp, libbpf
 * - CUDA toolkit (for GPU kernels)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* CUDA headers must precede libc math declarations for nvcc host builds. */
#include <cuda.h>
#include <cuda_runtime.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "../../../../tools/include/xdev_ext_gpu_identity.h"
#include "../../../../tools/include/xdev_ext_nv_p2p_ioctl.h"
#include "../../../../tools/include/xdev_ext_xsk_redirect.h"
#include "gpu_xdp_frame_runtime.h"

#ifdef __cplusplus
#define XDEV_EXT_ZERO_INIT {}
#else
#define XDEV_EXT_ZERO_INIT { 0 }
#endif

/*
 * Configuration
 */
#define INTERFACE_NAME      "eno1"
#define NUM_FRAMES          4096
#define FRAME_SIZE          XSK_UMEM__DEFAULT_FRAME_SIZE  /* 4096 */
#define UMEM_SIZE           (NUM_FRAMES * FRAME_SIZE)
#define BATCH_SIZE          64
#define FILL_RING_SIZE      NUM_FRAMES
#define COMP_RING_SIZE      NUM_FRAMES
#define GPU_BUFFER_SIZE     UMEM_SIZE

#define RX_BATCH_SIZE       64
#define TX_BATCH_SIZE       64
#define XSK_REDIRECT_DETACH_ATTEMPTS 3
#define GPU_XDP_FLOW_MAGIC UINT32_C(0x55425247) /* "UBRG", network order */
/* Minimum Ethernet frame without FCS.  The UDP payload begins with UBRG and
 * the remaining bytes are stable zero padding covered by the IP/UDP lengths. */
#define GPU_XDP_SOURCE_PACKET_SIZE 60U

enum gpu_xdp_mode {
    GPU_XDP_MODE_ROUNDTRIP = 0,
    GPU_XDP_MODE_NIC_TO_GPU,
    GPU_XDP_MODE_GPU_TO_NIC,
};

struct gpu_xdp_source_config {
    uint8_t source_mac[ETH_ALEN];
    uint8_t destination_mac[ETH_ALEN];
    uint32_t source_ipv4;
    uint32_t destination_ipv4;
    uint16_t source_port;
    uint16_t destination_port;
};

/*
 * GPU P2P handle structure
 */
typedef struct {
    void        *umem_buffer;       /* User UMEM buffer (mmap'd) */
    size_t       umem_size;         /* UMEM size */
    void        *gpu_buffer;        /* GPU device memory */
    size_t       gpu_buffer_size;   /* GPU buffer size */
    CUdeviceptr  gpu_dptr;          /* CUDA device pointer */
    int          gpu_fd;            /* NVIDIA driver fd */
    void        *p2p_handle;        /* P2P registration handle */
    int          gpu_id;            /* GPU device ID */
    int          allow_cuda_staging;/* Explicit non-P2P fallback opt-in */
    int          dma_sequestered;   /* Completion was not proven */
    cudaStream_t stream;            /* CUDA stream for async ops */
} gpu_p2p_ctx_t;

/*
 * XSK context
 */
typedef struct {
    struct xsk_socket       *xsk;
    struct xsk_umem         *umem;
    struct xsk_ring_prod     fq;
    struct xsk_ring_cons     cq;
    struct xsk_ring_prod     tx;
    struct xsk_ring_cons     rx;
    void                    *umem_buffer;
    int                      queue_id;
    gpu_p2p_ctx_t           *gpu_ctx;
    struct gpu_xdp_frame_runtime frames;
    struct xdev_ext_xsk_redirect      redirect;
    uint8_t                  frame_states[NUM_FRAMES];
    uint64_t                 recycle_entries[NUM_FRAMES];
    uint64_t                 expected_tx_addrs[NUM_FRAMES];
    uint32_t                 source_packet_length;
} xsk_ctx_t;

/*
 * Statistics
 */
typedef struct {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t ce_transfers;
    uint64_t cuda_staging_transfers;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t errors;
} stats_t;

static volatile int running = 1;
static stats_t stats = XDEV_EXT_ZERO_INIT;

/*
 * Signal handler
 */
static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}

static int parse_queue_id(const char *text, int *queue_id)
{
    char *end = NULL;
    long value;

    if (!text || !queue_id || !*text)
        return -EINVAL;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || !end || *end || value < 0 ||
        value >= XDEV_EXT_XSK_REDIRECT_MAX_QUEUES)
        return -ERANGE;
    *queue_id = (int)value;
    return 0;
}

static int parse_gpu_id(const char *text, int *gpu_id)
{
    char *end = NULL;
    long value;

    if (!text || !gpu_id || !*text)
        return -EINVAL;
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno || !end || *end || value < 0 || value > INT_MAX)
        return -ERANGE;
    *gpu_id = (int)value;
    return 0;
}

static const char *mode_name(enum gpu_xdp_mode mode)
{
    switch (mode) {
    case GPU_XDP_MODE_ROUNDTRIP:
        return "roundtrip";
    case GPU_XDP_MODE_NIC_TO_GPU:
        return "nic-to-gpu";
    case GPU_XDP_MODE_GPU_TO_NIC:
        return "gpu-to-nic";
    }
    return "invalid";
}

static int parse_mode(const char *text, enum gpu_xdp_mode *mode)
{
    if (!text || !mode)
        return -EINVAL;
    if (!strcmp(text, "roundtrip"))
        *mode = GPU_XDP_MODE_ROUNDTRIP;
    else if (!strcmp(text, "nic-to-gpu"))
        *mode = GPU_XDP_MODE_NIC_TO_GPU;
    else if (!strcmp(text, "gpu-to-nic"))
        *mode = GPU_XDP_MODE_GPU_TO_NIC;
    else
        return -EINVAL;
    return 0;
}

static int parse_mac(const char *text, uint8_t mac[ETH_ALEN])
{
    unsigned int values[ETH_ALEN];
    char trailing;

    if (!text || !mac || strlen(text) != 17)
        return -EINVAL;
    for (size_t i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (text[i] != ':')
                return -EINVAL;
        } else if (!isxdigit((unsigned char)text[i])) {
            return -EINVAL;
        }
    }
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5], &trailing) != ETH_ALEN)
        return -EINVAL;
    for (size_t i = 0; i < ETH_ALEN; i++)
        mac[i] = (uint8_t)values[i];
    return 0;
}

static int parse_filter_ipv4(const char *text, uint32_t *host_address)
{
    struct in_addr address;

    if (!text || !host_address || inet_pton(AF_INET, text, &address) != 1)
        return -EINVAL;
    *host_address = ntohl(address.s_addr);
    return 0;
}

static int parse_filter_port(const char *text, uint16_t *port)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !port || !*text)
        return -EINVAL;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end || !value || value > UINT16_MAX)
        return -ERANGE;
    *port = (uint16_t)value;
    return 0;
}

/*
 * CUDA error checking macro
 */
#define CUDA_CHECK(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error at %s:%d: %s\n", \
                __FILE__, __LINE__, cudaGetErrorString(err)); \
        return -1; \
    } \
} while(0)

#define CU_CHECK(call) do { \
    CUresult err = call; \
    if (err != CUDA_SUCCESS) { \
        const char *errStr; \
        cuGetErrorString(err, &errStr); \
        fprintf(stderr, "CUDA driver error at %s:%d: %s\n", \
                __FILE__, __LINE__, errStr); \
        return -1; \
    } \
} while(0)

/* Require one visible CUDA ordinal, and the requested ordinal, for the BDF. */
static int gpu_p2p_match_cuda_device(int gpu_id, int num_devices,
                                      const char *opened_bdf)
{
    unsigned int matches = 0;
    int matched_ordinal = -1;

    for (int ordinal = 0; ordinal < num_devices; ordinal++) {
        char cuda_bdf[32] = XDEV_EXT_ZERO_INIT;
        cudaError_t err;

        err = cudaDeviceGetPCIBusId(cuda_bdf, sizeof(cuda_bdf), ordinal);
        if (err != cudaSuccess) {
            fprintf(stderr, "Failed to query CUDA device %d PCI BDF: %s\n",
                    ordinal, cudaGetErrorString(err));
            return -EIO;
        }
        if (!xdev_ext_gpu_identity_is_pci_bdf(cuda_bdf)) {
            fprintf(stderr, "CUDA device %d returned invalid PCI BDF '%s'\n",
                    ordinal, cuda_bdf);
            return -ENODEV;
        }
        if (!strcasecmp(cuda_bdf, opened_bdf)) {
            matches++;
            matched_ordinal = ordinal;
        }
    }
    if (matches != 1 || matched_ordinal != gpu_id) {
        fprintf(stderr,
                "CUDA ordinal %d does not uniquely match opened GPU PCI BDF %s "
                "(matches=%u, matched ordinal=%d)\n",
                gpu_id, opened_bdf, matches, matched_ordinal);
        return matches > 1 ? -EEXIST : -EXDEV;
    }
    return 0;
}

/*
 * Initialize GPU P2P context
 */
static int gpu_p2p_init(gpu_p2p_ctx_t *ctx, void *umem_buffer,
                        size_t umem_size, int gpu_id, int xsk_fd,
                        int allow_cuda_staging)
{
    char opened_bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = XDEV_EXT_ZERO_INIT;
    char dev_path[64];
    int num_devices;
    int ret;

    memset(ctx, 0, sizeof(*ctx));
    ctx->gpu_fd = -1;
    ctx->umem_buffer = umem_buffer;
    ctx->umem_size = umem_size;
    ctx->gpu_id = gpu_id;
    ctx->allow_cuda_staging = allow_cuda_staging;

    /* Initialize CUDA */
    CUDA_CHECK(cudaGetDeviceCount(&num_devices));
    if (gpu_id < 0 || gpu_id >= num_devices) {
        fprintf(stderr, "GPU %d not found (have %d GPUs)\n", gpu_id, num_devices);
        return -1;
    }

    CUDA_CHECK(cudaSetDevice(gpu_id));

    /* Get device properties */
    struct cudaDeviceProp props;
    CUDA_CHECK(cudaGetDeviceProperties(&props, gpu_id));
    printf("Using GPU %d: %s (SM %d.%d)\n", gpu_id, props.name,
           props.major, props.minor);

    /* Check for P2P DMA capability */
    int p2p_capable = 0;
    CU_CHECK(cuDeviceGetAttribute(&p2p_capable,
             CU_DEVICE_ATTRIBUTE_GPU_DIRECT_RDMA_SUPPORTED, gpu_id));
    if (!p2p_capable) {
        fprintf(stderr, "Warning: GPU does not advertise GPUDirect RDMA support\n");
    }

    /* Open and prove the identity of the exact RM device before pinning. */
    if (snprintf(dev_path, sizeof(dev_path), "/dev/nvidia%d", gpu_id) >=
        (int)sizeof(dev_path))
        return -1;
    ctx->gpu_fd = open(dev_path, O_RDWR | O_CLOEXEC);
    if (ctx->gpu_fd < 0) {
        fprintf(stderr, "Failed to open exact NVIDIA device %s: %s\n",
                dev_path, strerror(errno));
        ctx->gpu_fd = -1;
        goto fail;
    }
    ret = xdev_ext_gpu_identity_from_opened(ctx->gpu_fd, dev_path,
                                       (unsigned int)gpu_id, opened_bdf);
    if (ret) {
        fprintf(stderr, "Failed to identify opened NVIDIA device %s: %s\n",
                dev_path, strerror(-ret));
        goto fail;
    }
    ret = gpu_p2p_match_cuda_device(gpu_id, num_devices, opened_bdf);
    if (ret)
        goto fail;
    printf("Verified CUDA ordinal %d and %s at PCI %s\n",
           gpu_id, dev_path, opened_bdf);

    /* Allocate GPU buffer for packet processing */
    ctx->gpu_buffer_size = GPU_BUFFER_SIZE;
    if (cudaMalloc(&ctx->gpu_buffer, ctx->gpu_buffer_size) != cudaSuccess) {
        fprintf(stderr, "Failed to allocate GPU packet buffer\n");
        goto fail;
    }
    ctx->gpu_dptr = (CUdeviceptr)ctx->gpu_buffer;
    printf("Allocated %zu bytes GPU buffer at %p\n",
           ctx->gpu_buffer_size, ctx->gpu_buffer);

    /* Create CUDA stream for async operations */
    if (cudaStreamCreate(&ctx->stream) != cudaSuccess) {
        fprintf(stderr, "Failed to create CUDA stream\n");
        goto fail;
    }

    /* Register UMEM with GPU for P2P DMA */
    if (ctx->gpu_fd >= 0) {
        struct xdev_ext_nv_p2p_pin_umem pin_params = XDEV_EXT_ZERO_INIT;

        pin_params.umem_addr = (uint64_t)umem_buffer;
        pin_params.size = umem_size;
        pin_params.frame_size = FRAME_SIZE;
        pin_params.xsk_fd = xsk_fd;

        ret = xdev_ext_nv_p2p_pin_umem(ctx->gpu_fd, &pin_params);
        if (ret == 0) {
            ctx->p2p_handle = (void *)pin_params.handle;
            printf("Registered UMEM with GPU P2P: handle=%p\n", ctx->p2p_handle);
        } else {
            fprintf(stderr,
                    "P2P UMEM registration failed: %s (NV_STATUS=0x%x)\n",
                    strerror(errno), pin_params.status);
            ctx->p2p_handle = NULL;
            if (!allow_cuda_staging)
                goto fail;
        }
    }

    if (!ctx->p2p_handle) {
        fprintf(stderr,
                "CUDA staging mode was explicitly requested; this mode is not P2P or zero-copy.\n");
    }
    return 0;

fail:
    fprintf(stderr,
            "CE-required mode cannot start without a verified XSK UMEM handle; "
            "use -s only for explicit CUDA staging.\n");
    if (ctx->gpu_fd >= 0) {
        close(ctx->gpu_fd);
        ctx->gpu_fd = -1;
    }
    if (ctx->stream) {
        (void)cudaStreamDestroy(ctx->stream);
        ctx->stream = NULL;
    }
    if (ctx->gpu_buffer) {
        (void)cudaFree(ctx->gpu_buffer);
        ctx->gpu_buffer = NULL;
    }
    return -1;
}

/*
 * Cleanup GPU P2P context
 */
static int gpu_p2p_cleanup(gpu_p2p_ctx_t *ctx)
{
    if (ctx->dma_sequestered) {
        fprintf(stderr,
                "GPU DMA completion was not proven; refusing explicit unpin/backing release\n");
        return -1;
    }

    if (ctx->stream && cudaStreamSynchronize(ctx->stream) != cudaSuccess) {
        ctx->dma_sequestered = 1;
        fprintf(stderr,
                "CUDA stream did not quiesce; quarantining registered backing\n");
        return -1;
    }

    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        struct xdev_ext_nv_p2p_unpin_umem unpin_params = XDEV_EXT_ZERO_INIT;

        unpin_params.handle = (uint64_t)ctx->p2p_handle;
        if (xdev_ext_nv_p2p_unpin_umem(ctx->gpu_fd, &unpin_params) != 0) {
            ctx->dma_sequestered = 1;
            fprintf(stderr,
                    "P2P UMEM unregistration failed: %s (NV_STATUS=0x%x)\n",
                    strerror(errno), unpin_params.status);
            return -1;
        }
        ctx->p2p_handle = NULL;
    }

    if (ctx->gpu_fd >= 0) {
        close(ctx->gpu_fd);
    }

    if (ctx->stream) {
        cudaStreamDestroy(ctx->stream);
    }

    if (ctx->gpu_buffer) {
        cudaFree(ctx->gpu_buffer);
    }

    return 0;
}

/*
 * A failed synchronous DMA/unpin operation has an ambiguous ownership result.
 * Keep every owning fd and mapping alive until an operator has reset or otherwise
 * proven the device quiescent.  Normal termination signals are ignored; SIGKILL
 * remains the explicit post-quiescence escape hatch.
 */
static void hold_sequestered_backing(void)
{
    fprintf(stderr,
            "GPU DMA state is sequestered; retaining process, fds, and mappings. "
            "Reset/verify device quiescence before SIGKILL.\n");
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
    for (;;)
        (void)pause();
}

static void sequester_active_frames(xsk_ctx_t *ctx,
                                     const uint64_t *frame_bases,
                                     int count)
{
    ctx->gpu_ctx->dma_sequestered = 1;
    running = 0;
    for (int i = 0; i < count; i++) {
        if (gpu_xdp_frame_sequester_rx(&ctx->frames, frame_bases[i]))
            stats.errors++;
    }
}

static void sequester_source_frames(xsk_ctx_t *ctx,
                                     const uint64_t *frame_bases,
                                     int count)
{
    ctx->gpu_ctx->dma_sequestered = 1;
    running = 0;
    for (int i = 0; i < count; i++) {
        if (gpu_xdp_frame_sequester_app(&ctx->frames, frame_bases[i]))
            stats.errors++;
    }
}

static void sequester_unpublished_source_frames(
    xsk_ctx_t *ctx, const uint64_t *frame_bases, int count, int tx_count)
{
    ctx->gpu_ctx->dma_sequestered = 1;
    running = 0;
    for (int i = 0; i < count; i++) {
        int ret;

        if (i < tx_count)
            ret = gpu_xdp_frame_sequester_unpublished_tx(&ctx->frames,
                                                           frame_bases[i]);
        else
            ret = gpu_xdp_frame_sequester_app(&ctx->frames,
                                                frame_bases[i]);
        if (ret)
            stats.errors++;
    }
}

/*
 * Transfer packets from UMEM to GPU
 * Uses P2P DMA if available, falls back to cudaMemcpy
 */
static int gpu_transfer_to_gpu(gpu_p2p_ctx_t *ctx, uint64_t umem_offset,
                               uint64_t gpu_offset, size_t size)
{
    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        /* Use P2P DMA */
        struct xdev_ext_nv_p2p_dma_xfer dma_params = XDEV_EXT_ZERO_INIT;

        dma_params.handle = (uint64_t)ctx->p2p_handle;
        dma_params.gpu_offset = (uint64_t)ctx->gpu_buffer + gpu_offset;
        dma_params.umem_offset = umem_offset;
        dma_params.size = size;
        dma_params.direction = XDEV_EXT_NV_P2P_UMEM_TO_GPU;

        int ret = xdev_ext_nv_p2p_dma_xfer(ctx->gpu_fd, &dma_params);
        if (ret == 0) {
            stats.ce_transfers++;
            return 0;
        }
        fprintf(stderr, "P2P UMEM->GPU CE transfer failed: %s (NV_STATUS=0x%x)\n",
                strerror(errno), dma_params.status);
        stats.errors++;
        return -1;
    }

    if (!ctx->allow_cuda_staging) {
        stats.errors++;
        return -1;
    }

    /* Explicit non-P2P CUDA staging mode. */
    void *src = (char *)ctx->umem_buffer + umem_offset;
    void *dst = (char *)ctx->gpu_buffer + gpu_offset;

    cudaError_t err = cudaMemcpyAsync(dst, src, size,
                                       cudaMemcpyHostToDevice, ctx->stream);
    if (err != cudaSuccess) {
        stats.errors++;
        return -1;
    }

    stats.cuda_staging_transfers++;
    return 0;
}

/*
 * Transfer packets from GPU back to UMEM
 */
static int gpu_transfer_from_gpu(gpu_p2p_ctx_t *ctx, uint64_t gpu_offset,
                                  uint64_t umem_offset, size_t size)
{
    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        /* Use P2P DMA */
        struct xdev_ext_nv_p2p_dma_xfer dma_params = XDEV_EXT_ZERO_INIT;

        dma_params.handle = (uint64_t)ctx->p2p_handle;
        dma_params.gpu_offset = (uint64_t)ctx->gpu_buffer + gpu_offset;
        dma_params.umem_offset = umem_offset;
        dma_params.size = size;
        dma_params.direction = XDEV_EXT_NV_P2P_GPU_TO_UMEM;

        int ret = xdev_ext_nv_p2p_dma_xfer(ctx->gpu_fd, &dma_params);
        if (ret == 0) {
            stats.ce_transfers++;
            return 0;
        }
        fprintf(stderr, "P2P GPU->UMEM CE transfer failed: %s (NV_STATUS=0x%x)\n",
                strerror(errno), dma_params.status);
        stats.errors++;
        return -1;
    }

    if (!ctx->allow_cuda_staging) {
        stats.errors++;
        return -1;
    }

    /* Explicit non-P2P CUDA staging mode. */
    void *src = (char *)ctx->gpu_buffer + gpu_offset;
    void *dst = (char *)ctx->umem_buffer + umem_offset;

    cudaError_t err = cudaMemcpyAsync(dst, src, size,
                                       cudaMemcpyDeviceToHost, ctx->stream);
    if (err != cudaSuccess) {
        stats.errors++;
        return -1;
    }

    stats.cuda_staging_transfers++;
    return 0;
}

/* Submit one bounded ioctl for the whole UMEM->GPU packet batch. */
static int gpu_transfer_batch_to_gpu(gpu_p2p_ctx_t *ctx,
                                     const uint64_t *umem_offsets,
                                     const uint32_t *lengths,
                                     int num_packets)
{
    if (num_packets <= 0)
        return 0;
    if (num_packets > (int)XDEV_EXT_NV_P2P_MAX_BATCH) {
        stats.errors++;
        return -1;
    }

    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        struct xdev_ext_nv_p2p_dma_batch batch = XDEV_EXT_ZERO_INIT;

        batch.handle = (uint64_t)ctx->p2p_handle;
        batch.count = (uint32_t)num_packets;

        for (int i = 0; i < num_packets; i++) {
            batch.entries[i].gpu_offset =
                (uint64_t)ctx->gpu_buffer + (uint64_t)i * FRAME_SIZE;
            batch.entries[i].umem_offset = umem_offsets[i];
            batch.entries[i].size = lengths[i];
            batch.entries[i].direction = XDEV_EXT_NV_P2P_UMEM_TO_GPU;
        }

        if (xdev_ext_nv_p2p_dma_batch(ctx->gpu_fd, &batch) != 0) {
            stats.ce_transfers += batch.completed;
            fprintf(stderr,
                    "P2P UMEM->GPU CE batch stopped after %u/%u items "
                    "(failed index=%u, NV_STATUS=0x%x): %s\n",
                    batch.completed, batch.count, batch.failed_index,
                    batch.status, strerror(errno));
            stats.errors++;
            return -1;
        }
        stats.ce_transfers += batch.completed;
        return 0;
    }

    for (int i = 0; i < num_packets; i++) {
        if (gpu_transfer_to_gpu(ctx, umem_offsets[i],
                                (uint64_t)i * FRAME_SIZE, lengths[i]))
            return -1;
    }
    return 0;
}

/* Submit one bounded ioctl for the whole GPU->UMEM packet batch. */
static int gpu_transfer_batch_from_gpu(gpu_p2p_ctx_t *ctx,
                                       const uint64_t *umem_offsets,
                                       const uint32_t *lengths,
                                       int num_packets)
{
    if (num_packets <= 0)
        return 0;
    if (num_packets > (int)XDEV_EXT_NV_P2P_MAX_BATCH) {
        stats.errors++;
        return -1;
    }

    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        struct xdev_ext_nv_p2p_dma_batch batch = XDEV_EXT_ZERO_INIT;

        batch.handle = (uint64_t)ctx->p2p_handle;
        batch.count = (uint32_t)num_packets;

        for (int i = 0; i < num_packets; i++) {
            batch.entries[i].gpu_offset =
                (uint64_t)ctx->gpu_buffer + (uint64_t)i * FRAME_SIZE;
            batch.entries[i].umem_offset = umem_offsets[i];
            batch.entries[i].size = lengths[i];
            batch.entries[i].direction = XDEV_EXT_NV_P2P_GPU_TO_UMEM;
        }

        if (xdev_ext_nv_p2p_dma_batch(ctx->gpu_fd, &batch) != 0) {
            stats.ce_transfers += batch.completed;
            fprintf(stderr,
                    "P2P GPU->UMEM CE batch stopped after %u/%u items "
                    "(failed index=%u, NV_STATUS=0x%x): %s\n",
                    batch.completed, batch.count, batch.failed_index,
                    batch.status, strerror(errno));
            stats.errors++;
            return -1;
        }
        stats.ce_transfers += batch.completed;
        return 0;
    }

    for (int i = 0; i < num_packets; i++) {
        if (gpu_transfer_from_gpu(ctx, (uint64_t)i * FRAME_SIZE,
                                  umem_offsets[i], lengths[i]))
            return -1;
    }
    return 0;
}

/* GPU packet processing kernel for a validated Ethernet/IPv4/UDP reply. */
__global__ void gpu_process_packets(uint8_t *packets, uint32_t *lengths,
                                     int num_packets, int frame_size)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_packets) return;

    uint8_t *pkt = packets + (idx * frame_size);
    uint32_t len = lengths[idx];

    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) +
              sizeof(struct udphdr))
        return;

    /* The selective XDP program admits fixed-header IPv4/UDP.  Swap both
     * endpoints so the processed frame is a valid reply, not merely an
     * Ethernet reflection whose L3/L4 destination still names this host.
     * Swapping 16-bit words preserves the existing IP and UDP checksums.
     * The packet starts at a frame-aligned offset, so the IPv4 header is at
     * an address that is 2 mod 4, where a 4-byte global access faults: copy
     * the IPv4 and UDP headers through byte pointers into local structs and
     * back instead of addressing them in place. */
    struct ethhdr *eth = (struct ethhdr *)pkt;
    uint8_t *ip_bytes = pkt + sizeof(*eth);
    uint8_t *udp_bytes = ip_bytes + sizeof(struct iphdr);
    struct iphdr ip;
    struct udphdr udp;
    uint8_t tmp[6];
    uint32_t tmp_addr;
    uint16_t tmp_port;

    memcpy(&ip, ip_bytes, sizeof(ip));
    if (ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_UDP)
        return;
    memcpy(&udp, udp_bytes, sizeof(udp));
    memcpy(tmp, eth->h_dest, 6);
    memcpy(eth->h_dest, eth->h_source, 6);
    memcpy(eth->h_source, tmp, 6);
    tmp_addr = ip.daddr;
    ip.daddr = ip.saddr;
    ip.saddr = tmp_addr;
    tmp_port = udp.dest;
    udp.dest = udp.source;
    udp.source = tmp_port;
    memcpy(ip_bytes, &ip, sizeof(ip));
    memcpy(udp_bytes, &udp, sizeof(udp));

    /* Could add more processing here:
     * - Checksum recalculation
     * - Payload modification
     * - Encryption/decryption
     * - ML inference
     */
}

/*
 * Launch GPU processing kernel
 */
static int gpu_process_batch(gpu_p2p_ctx_t *ctx, uint64_t *pkt_offsets,
                              uint32_t *pkt_lengths, int num_packets)
{
    static uint32_t *d_lengths = NULL;
    static int max_packets = 0;

    (void)pkt_offsets;

    if (num_packets <= 0) return 0;

    /* Allocate device memory for lengths if needed */
    if (num_packets > max_packets) {
        if (d_lengths) cudaFree(d_lengths);
        CUDA_CHECK(cudaMalloc(&d_lengths, num_packets * sizeof(uint32_t)));
        max_packets = num_packets;
    }

    /* Copy lengths to device */
    CUDA_CHECK(cudaMemcpyAsync(d_lengths, pkt_lengths,
                                num_packets * sizeof(uint32_t),
                                cudaMemcpyHostToDevice, ctx->stream));

    /* Launch kernel */
    int threads = 256;
    int blocks = (num_packets + threads - 1) / threads;

    gpu_process_packets<<<blocks, threads, 0, ctx->stream>>>(
        (uint8_t *)ctx->gpu_buffer, d_lengths, num_packets, FRAME_SIZE);

    return 0;
}

static uint16_t ipv4_checksum(const void *header, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)header;
    uint32_t sum = 0;

    while (length >= 2) {
        sum += ((uint32_t)bytes[0] << 8) | bytes[1];
        bytes += 2;
        length -= 2;
    }
    if (length)
        sum += (uint32_t)bytes[0] << 8;
    while (sum >> 16)
        sum = (sum & UINT16_MAX) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static int build_source_packet(uint8_t *packet, size_t capacity,
                               const struct gpu_xdp_source_config *config)
{
    struct ethhdr *ethernet;
    struct iphdr ipv4;
    struct udphdr udp;
    uint32_t magic = htonl(GPU_XDP_FLOW_MAGIC);
    const size_t udp_payload_length = GPU_XDP_SOURCE_PACKET_SIZE -
                                      sizeof(*ethernet) - sizeof(ipv4) -
                                      sizeof(udp);

    if (!packet || !config || capacity < GPU_XDP_SOURCE_PACKET_SIZE)
        return -EINVAL;
    memset(packet, 0, capacity);
    ethernet = (struct ethhdr *)packet;

    memcpy(ethernet->h_source, config->source_mac, ETH_ALEN);
    memcpy(ethernet->h_dest, config->destination_mac, ETH_ALEN);
    ethernet->h_proto = htons(ETH_P_IP);

    /* The frame is frame-aligned, so its IPv4 header is only 2-byte
     * aligned: build both headers in local structs and copy them in. */
    memset(&ipv4, 0, sizeof(ipv4));
    ipv4.version = 4;
    ipv4.ihl = 5;
    ipv4.ttl = 64;
    ipv4.protocol = IPPROTO_UDP;
    ipv4.tot_len = htons(sizeof(ipv4) + sizeof(udp) + udp_payload_length);
    ipv4.saddr = htonl(config->source_ipv4);
    ipv4.daddr = htonl(config->destination_ipv4);
    ipv4.check = ipv4_checksum(&ipv4, sizeof(ipv4));

    memset(&udp, 0, sizeof(udp));
    udp.source = htons(config->source_port);
    udp.dest = htons(config->destination_port);
    udp.len = htons(sizeof(udp) + udp_payload_length);
    /* A zero UDP checksum is valid for IPv4. */
    udp.check = 0;

    memcpy(packet + sizeof(*ethernet), &ipv4, sizeof(ipv4));
    memcpy(packet + sizeof(*ethernet) + sizeof(ipv4), &udp, sizeof(udp));
    memcpy(packet + sizeof(*ethernet) + sizeof(ipv4) + sizeof(udp), &magic,
           sizeof(magic));
    return (int)GPU_XDP_SOURCE_PACKET_SIZE;
}

static int gpu_prepare_source_templates(
    gpu_p2p_ctx_t *ctx, const struct gpu_xdp_source_config *config,
    uint32_t *packet_length)
{
    const size_t templates_size = (size_t)BATCH_SIZE * FRAME_SIZE;
    uint8_t *templates;
    int length = -EINVAL;
    cudaError_t cuda_ret;

    if (!ctx || !config || !packet_length ||
        templates_size > ctx->gpu_buffer_size)
        return -EINVAL;
    templates = (uint8_t *)calloc(1, templates_size);
    if (!templates)
        return -ENOMEM;
    for (int i = 0; i < BATCH_SIZE; i++) {
        length = build_source_packet(templates + (size_t)i * FRAME_SIZE,
                                     FRAME_SIZE, config);
        if (length < 0) {
            free(templates);
            return length;
        }
    }

    cuda_ret = cudaMemcpyAsync(ctx->gpu_buffer, templates, templates_size,
                               cudaMemcpyHostToDevice, ctx->stream);
    if (cuda_ret != cudaSuccess) {
        fprintf(stderr, "Failed to upload GPU packet templates: %s\n",
                cudaGetErrorString(cuda_ret));
        ctx->dma_sequestered = 1;
        free(templates);
        return -EIO;
    }
    cuda_ret = cudaStreamSynchronize(ctx->stream);
    if (cuda_ret != cudaSuccess) {
        fprintf(stderr, "GPU packet template upload did not quiesce: %s\n",
                cudaGetErrorString(cuda_ret));
        /* The async copy may still reference this allocation.  The caller's
         * sequester hold deliberately retains this otherwise leaked backing. */
        ctx->dma_sequestered = 1;
        return -EIO;
    }
    free(templates);
    *packet_length = (uint32_t)length;
    return 0;
}

/*
 * Create UMEM
 */
static int create_umem(xsk_ctx_t *ctx)
{
    struct xsk_umem_config cfg = {
        .fill_size = FILL_RING_SIZE,
        .comp_size = COMP_RING_SIZE,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    /* Allocate UMEM buffer */
    ctx->umem_buffer = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (ctx->umem_buffer == MAP_FAILED) {
        /* Fall back to regular pages */
        ctx->umem_buffer = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ctx->umem_buffer == MAP_FAILED) {
            perror("mmap UMEM");
            return -1;
        }
        printf("Using regular pages for UMEM\n");
    } else {
        printf("Using huge pages for UMEM\n");
    }

    /* Create UMEM */
    int ret = xsk_umem__create(&ctx->umem, ctx->umem_buffer, UMEM_SIZE,
                                &ctx->fq, &ctx->cq, &cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create failed: %s\n", strerror(-ret));
        munmap(ctx->umem_buffer, UMEM_SIZE);
        return ret;
    }

    printf("Created UMEM: %zu bytes, %d frames\n", (size_t)UMEM_SIZE, NUM_FRAMES);
    return 0;
}

/*
 * Create XSK socket
 */
static int create_xsk(xsk_ctx_t *ctx, const char *ifname, int queue_id,
                      const struct xdev_ext_xsk_flow_filter *flow_filter,
                      enum gpu_xdp_mode mode)
{
    unsigned int ifindex;
    struct xsk_socket_config cfg = {
        .rx_size = FILL_RING_SIZE,
        .tx_size = COMP_RING_SIZE,
        .libbpf_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .bind_flags = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP,
    };

    ctx->queue_id = queue_id;
    xdev_ext_xsk_redirect_init(&ctx->redirect);

    int ret = xsk_socket__create(&ctx->xsk, ifname, queue_id,
                                  ctx->umem, &ctx->rx, &ctx->tx, &cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(-ret));
        return ret;
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        ret = errno ? -errno : -ENODEV;
        xsk_socket__delete(ctx->xsk);
        ctx->xsk = NULL;
        return ret;
    }
    if (mode != GPU_XDP_MODE_GPU_TO_NIC) {
        ret = xdev_ext_xsk_redirect_attach(&ctx->redirect, flow_filter,
                                      (int)ifindex, (uint32_t)queue_id,
                                      xsk_socket__fd(ctx->xsk),
                                      cfg.xdp_flags);
        if (ret) {
            fprintf(stderr, "XSK redirect attach failed: %s\n", strerror(-ret));
            if (!xdev_ext_xsk_redirect_is_active(&ctx->redirect)) {
                xsk_socket__delete(ctx->xsk);
                ctx->xsk = NULL;
            }
            return ret;
        }
    }

    ret = gpu_xdp_frame_runtime_init(&ctx->frames, ctx->frame_states,
                                     ctx->recycle_entries,
                                     ctx->expected_tx_addrs,
                                     NUM_FRAMES, FRAME_SIZE);
    if (ret)
        return ret;
    for (uint32_t i = 0; i < NUM_FRAMES; i++) {
        ret = xdev_ext_xsk_recycle_push(&ctx->frames.recycle,
                                   (uint64_t)i * FRAME_SIZE);
        if (ret)
            return ret;
    }
    if (mode != GPU_XDP_MODE_GPU_TO_NIC) {
        ret = gpu_xdp_refill(&ctx->frames, &ctx->fq, NUM_FRAMES);
        if (ret != NUM_FRAMES) {
            fprintf(stderr, "Failed to populate fill ring: %d/%d\n",
                    ret, NUM_FRAMES);
            return ret < 0 ? ret : -ENOSPC;
        }
    }

    printf("Created XSK on %s queue %d\n", ifname, queue_id);
    return 0;
}

/*
 * Process received packets through GPU and send back
 */
static int process_packets(xsk_ctx_t *ctx)
{
    uint32_t idx_rx = 0, idx_tx = 0;
    uint64_t desc_addrs[BATCH_SIZE];
    uint64_t frame_bases[BATCH_SIZE];
    uint64_t pkt_offsets[BATCH_SIZE];
    uint32_t pkt_lengths[BATCH_SIZE];
    int active = 0;
    int tx_count = 0;
    int fatal_ret = 0;
    int ret;

    ret = gpu_xdp_reap_completions(&ctx->frames, &ctx->cq, BATCH_SIZE);
    if (ret < 0)
        return ret;
    ret = gpu_xdp_refill(&ctx->frames, &ctx->fq, BATCH_SIZE);
    if (ret < 0)
        return ret;

    /* Receive packets */
    int rcvd = xsk_ring_cons__peek(&ctx->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        if (xsk_ring_prod__needs_wakeup(&ctx->fq)) {
            recvfrom(xsk_socket__fd(ctx->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
        }
        return 0;
    }

    /* Acquire packet ownership and validate the data range within each frame. */
    for (int i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&ctx->rx, idx_rx + i);

        stats.rx_packets++;
        stats.rx_bytes += desc->len;
        ret = gpu_xdp_frame_accept_rx(&ctx->frames, desc, UMEM_SIZE,
                                      &frame_bases[active],
                                      &pkt_offsets[active]);
        if (ret) {
            stats.errors++;
            if (ret == -EPROTO || ret == -ERANGE || ret == -EINVAL) {
                running = 0;
                fatal_ret = ret;
            }
            continue;
        }
        desc_addrs[active] = desc->addr;
        pkt_lengths[active] = desc->len;
        active++;
    }

    /* One ioctl covers the bounded batch; failed-item acceptance is ambiguous. */
    if (active && gpu_transfer_batch_to_gpu(ctx->gpu_ctx, pkt_offsets,
                                            pkt_lengths, active)) {
        sequester_active_frames(ctx, frame_bases, active);
        stats.errors += active;
        active = 0;
        fatal_ret = -EIO;
    }

    /* Process on GPU */
    if (active && gpu_process_batch(ctx->gpu_ctx, pkt_offsets,
                                    pkt_lengths, active)) {
        sequester_active_frames(ctx, frame_bases, active);
        stats.errors += active;
        active = 0;
        fatal_ret = -EIO;
    }

    /* The CUDA kernel must complete before the independent RM CE reads it. */
    if (active && cudaStreamSynchronize(ctx->gpu_ctx->stream) != cudaSuccess) {
        sequester_active_frames(ctx, frame_bases, active);
        stats.errors += active;
        active = 0;
        fatal_ret = -EIO;
    }

    /* Do not publish any descriptor unless the entire return batch completed. */
    if (active && gpu_transfer_batch_from_gpu(ctx->gpu_ctx, pkt_offsets,
                                              pkt_lengths, active)) {
        sequester_active_frames(ctx, frame_bases, active);
        stats.errors += active;
        active = 0;
        fatal_ret = -EIO;
    }

    /* Only the explicit cudaMemcpyAsync staging return needs this barrier. */
    if (active && ctx->gpu_ctx->allow_cuda_staging &&
        !ctx->gpu_ctx->p2p_handle &&
        cudaStreamSynchronize(ctx->gpu_ctx->stream) != cudaSuccess) {
        sequester_active_frames(ctx, frame_bases, active);
        stats.errors += active;
        active = 0;
        fatal_ret = -EIO;
    }
    for (int i = 0; i < active; i++) {
        desc_addrs[tx_count] = desc_addrs[i];
        frame_bases[tx_count] = frame_bases[i];
        pkt_lengths[tx_count] = pkt_lengths[i];
        tx_count++;
    }

    /* Reserve TX descriptors */
    ret = tx_count ? xsk_ring_prod__reserve(&ctx->tx, tx_count, &idx_tx) : 0;
    if (ret < 0)
        ret = 0;
    for (int i = 0; i < ret; i++) {
        if (gpu_xdp_frame_submit_tx(&ctx->frames, frame_bases[i],
                                    desc_addrs[i])) {
            running = 0;
            stats.errors++;
            xsk_ring_cons__release(&ctx->rx, rcvd);
            return -EPROTO;
        }
        {
            struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&ctx->tx, idx_tx + i);

            tx_desc->addr = desc_addrs[i];
            tx_desc->len = pkt_lengths[i];
            tx_desc->options = 0;
        }
        stats.tx_packets++;
        stats.tx_bytes += pkt_lengths[i];
    }
    if (ret)
        xsk_ring_prod__submit(&ctx->tx, ret);
    for (int i = ret; i < tx_count; i++) {
        (void)gpu_xdp_frame_drop_rx(&ctx->frames, frame_bases[i]);
        stats.errors++;
    }

    /* Release RX descriptors */
    xsk_ring_cons__release(&ctx->rx, rcvd);

    if (ret && xsk_ring_prod__needs_wakeup(&ctx->tx))
        (void)sendto(xsk_socket__fd(ctx->xsk), NULL, 0,
                     MSG_DONTWAIT, NULL, 0);
    ret = gpu_xdp_reap_completions(&ctx->frames, &ctx->cq, BATCH_SIZE);
    if (ret < 0) {
        running = 0;
        return ret;
    }
    ret = gpu_xdp_refill(&ctx->frames, &ctx->fq, BATCH_SIZE);
    if (ret < 0) {
        running = 0;
        return ret;
    }

    return fatal_ret ? fatal_ret : rcvd;
}

/*
 * Roundtrip CQ/FQ maintenance that does not depend on new ingress.  The last
 * TX completions can arrive after ingress stops; without them the frames stay
 * in TX and never return to the fill ring.  Reap first, so only an exact TX
 * completion returns a frame to FREE, then refill from those FREE frames.
 * This path runs at most once per RX batch plus once per poll timeout, so it
 * takes every completion that is present instead of one RX batch.
 */
static int maintain_roundtrip(xsk_ctx_t *ctx)
{
    int reaped;
    int ret;

    reaped = gpu_xdp_reap_completions(&ctx->frames, &ctx->cq,
                                      COMP_RING_SIZE);
    if (reaped < 0) {
        running = 0;
        return reaped;
    }
    ret = gpu_xdp_refill(&ctx->frames, &ctx->fq, FILL_RING_SIZE);
    if (ret < 0) {
        running = 0;
        return ret;
    }
    if (xsk_ring_prod__needs_wakeup(&ctx->fq))
        (void)recvfrom(xsk_socket__fd(ctx->xsk), NULL, 0,
                       MSG_DONTWAIT, NULL, NULL);
    return reaped;
}

/* Independent NIC->GPU sink: one bounded CE batch, then recycle each RX
 * frame only after completion has been proven. */
static int process_nic_to_gpu(xsk_ctx_t *ctx)
{
    uint32_t idx_rx = 0;
    uint64_t frame_bases[BATCH_SIZE];
    uint64_t pkt_offsets[BATCH_SIZE];
    uint32_t pkt_lengths[BATCH_SIZE];
    int fatal_ret = 0;
    int active = 0;
    int ret;
    int rcvd;

    ret = gpu_xdp_reap_completions(&ctx->frames, &ctx->cq, BATCH_SIZE);
    if (ret < 0)
        return ret;
    ret = gpu_xdp_refill(&ctx->frames, &ctx->fq, BATCH_SIZE);
    if (ret < 0)
        return ret;

    rcvd = xsk_ring_cons__peek(&ctx->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd) {
        if (xsk_ring_prod__needs_wakeup(&ctx->fq))
            (void)recvfrom(xsk_socket__fd(ctx->xsk), NULL, 0,
                           MSG_DONTWAIT, NULL, NULL);
        return 0;
    }

    for (int i = 0; i < rcvd; i++) {
        const struct xdp_desc *desc =
            xsk_ring_cons__rx_desc(&ctx->rx, idx_rx + i);

        stats.rx_packets++;
        stats.rx_bytes += desc->len;
        ret = gpu_xdp_frame_accept_rx(&ctx->frames, desc, UMEM_SIZE,
                                      &frame_bases[active],
                                      &pkt_offsets[active]);
        if (ret) {
            stats.errors++;
            if (ret == -EPROTO || ret == -ERANGE || ret == -EINVAL) {
                running = 0;
                fatal_ret = ret;
            }
            continue;
        }
        pkt_lengths[active] = desc->len;
        active++;
    }

    if (active && gpu_transfer_batch_to_gpu(ctx->gpu_ctx, pkt_offsets,
                                            pkt_lengths, active)) {
        sequester_active_frames(ctx, frame_bases, active);
        stats.errors += active;
        active = 0;
        fatal_ret = -EIO;
    }

    /* cudaMemcpyAsync staging must finish before reuse.  Synchronizing the
     * CE mode's otherwise idle stream also proves no earlier CUDA work remains. */
    if (active && cudaStreamSynchronize(ctx->gpu_ctx->stream) != cudaSuccess) {
        sequester_active_frames(ctx, frame_bases, active);
        stats.errors += active;
        active = 0;
        fatal_ret = -EIO;
    }

    for (int i = 0; i < active; i++) {
        if (gpu_xdp_frame_drop_rx(&ctx->frames, frame_bases[i])) {
            stats.errors++;
            running = 0;
            fatal_ret = -EPROTO;
        }
    }
    xsk_ring_cons__release(&ctx->rx, rcvd);

    if (!ctx->gpu_ctx->dma_sequestered) {
        ret = gpu_xdp_refill(&ctx->frames, &ctx->fq, BATCH_SIZE);
        if (ret < 0) {
            running = 0;
            return ret;
        }
    }
    return fatal_ret ? fatal_ret : rcvd;
}

/* Independent GPU->NIC source.  Frames come from a private FREE/APP pool,
 * never from FILL/RX.  Exact TX completions return them to that pool. */
static int process_gpu_to_nic(xsk_ctx_t *ctx, uint32_t packet_length)
{
    uint64_t frame_bases[BATCH_SIZE];
    uint64_t umem_offsets[BATCH_SIZE];
    uint32_t pkt_lengths[BATCH_SIZE];
    uint32_t idx_tx = 0;
    uint32_t wanted;
    uint32_t reserved = 0;
    int acquired = 0;
    int ret;

    ret = gpu_xdp_reap_completions(&ctx->frames, &ctx->cq, BATCH_SIZE);
    if (ret < 0)
        return ret;
    wanted = ctx->frames.recycle.count;
    if (wanted > BATCH_SIZE)
        wanted = BATCH_SIZE;
    if (!wanted)
        return 0;

    ret = xsk_ring_prod__reserve(&ctx->tx, wanted, &idx_tx);
    if (ret <= 0) {
        if (xsk_ring_prod__needs_wakeup(&ctx->tx))
            (void)sendto(xsk_socket__fd(ctx->xsk), NULL, 0,
                         MSG_DONTWAIT, NULL, 0);
        return ret < 0 ? ret : 0;
    }
    reserved = (uint32_t)ret;

    for (int i = 0; i < ret; i++) {
        int owner_ret = gpu_xdp_frame_acquire_app(&ctx->frames,
                                                   &frame_bases[i]);

        if (owner_ret) {
            gpu_xdp_ring_prod_cancel(&ctx->tx, reserved);
            for (int j = 0; j < acquired; j++)
                (void)gpu_xdp_frame_release_app(&ctx->frames,
                                                frame_bases[j]);
            running = 0;
            stats.errors++;
            return owner_ret;
        }
        umem_offsets[i] = frame_bases[i];
        pkt_lengths[i] = packet_length;
        acquired++;
    }

    if (gpu_transfer_batch_from_gpu(ctx->gpu_ctx, umem_offsets,
                                    pkt_lengths, acquired)) {
        gpu_xdp_ring_prod_cancel(&ctx->tx, reserved);
        sequester_source_frames(ctx, frame_bases, acquired);
        stats.errors += acquired;
        return -EIO;
    }
    if (ctx->gpu_ctx->allow_cuda_staging && !ctx->gpu_ctx->p2p_handle &&
        cudaStreamSynchronize(ctx->gpu_ctx->stream) != cudaSuccess) {
        gpu_xdp_ring_prod_cancel(&ctx->tx, reserved);
        sequester_source_frames(ctx, frame_bases, acquired);
        stats.errors += acquired;
        return -EIO;
    }

    /* Validate the whole batch before changing any APP frame to TX. */
    for (int i = 0; i < acquired; i++) {
        ret = gpu_xdp_frame_validate_app_tx(&ctx->frames, frame_bases[i],
                                            frame_bases[i]);
        if (ret) {
            gpu_xdp_ring_prod_cancel(&ctx->tx, reserved);
            for (int j = 0; j < acquired; j++)
                (void)gpu_xdp_frame_release_app(&ctx->frames,
                                                frame_bases[j]);
            running = 0;
            stats.errors++;
            return ret;
        }
    }
    for (int i = 0; i < acquired; i++) {
        struct xdp_desc *tx_desc;

        ret = gpu_xdp_frame_submit_app_tx(&ctx->frames, frame_bases[i],
                                          frame_bases[i]);
        if (ret) {
            gpu_xdp_ring_prod_cancel(&ctx->tx, reserved);
            sequester_unpublished_source_frames(ctx, frame_bases,
                                                  acquired, i);
            stats.errors++;
            return ret;
        }
        tx_desc = xsk_ring_prod__tx_desc(&ctx->tx, idx_tx + i);
        tx_desc->addr = frame_bases[i];
        tx_desc->len = pkt_lengths[i];
        tx_desc->options = 0;
    }
    xsk_ring_prod__submit(&ctx->tx, (uint32_t)acquired);
    stats.tx_packets += (uint64_t)acquired;
    stats.tx_bytes += (uint64_t)acquired * packet_length;

    if (xsk_ring_prod__needs_wakeup(&ctx->tx))
        (void)sendto(xsk_socket__fd(ctx->xsk), NULL, 0,
                     MSG_DONTWAIT, NULL, 0);
    ret = gpu_xdp_reap_completions(&ctx->frames, &ctx->cq, BATCH_SIZE);
    if (ret < 0) {
        running = 0;
        return ret;
    }
    return acquired;
}

/*
 * Print statistics
 */
static void print_stats(void)
{
    static uint64_t last_rx = 0, last_tx = 0;
    static struct timespec last_time = XDEV_EXT_ZERO_INIT;
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    if (last_time.tv_sec != 0) {
        double dt = (now.tv_sec - last_time.tv_sec) +
                    (now.tv_nsec - last_time.tv_nsec) / 1e9;

        uint64_t rx_pps = (stats.rx_packets - last_rx) / dt;
        uint64_t tx_pps = (stats.tx_packets - last_tx) / dt;

        printf("\rRX: %'lu pps (%'lu total) | TX: %'lu pps (%'lu total) | "
               "CE: %'lu | CUDA fallback: %'lu | Errors: %lu",
               rx_pps, stats.rx_packets, tx_pps, stats.tx_packets,
               stats.ce_transfers, stats.cuda_staging_transfers, stats.errors);
        fflush(stdout);
    }

    last_rx = stats.rx_packets;
    last_tx = stats.tx_packets;
    last_time = now;
}

/*
 * Main loop
 */
static int run_loop(xsk_ctx_t *ctx, enum gpu_xdp_mode mode)
{
    struct pollfd fds[1];
    time_t last_stats = 0;
    int roundtrip_pollout_armed = 0;
    int loop_status = 0;

    fds[0].fd = xsk_socket__fd(ctx->xsk);

    printf("Starting %s packet processing loop...\n", mode_name(mode));
    printf("Press Ctrl+C to stop\n\n");

    while (running) {
        int should_process = 0;
        int should_maintain = 0;

        /* An XSK with TX ring space is always writable.  The GPU->NIC
         * source is paced by that space; the roundtrip asks for POLLOUT
         * only while one CQ/FQ maintenance opportunity is armed; the
         * NIC->GPU sink has no TX work and waits only for ingress. */
        if (mode == GPU_XDP_MODE_GPU_TO_NIC)
            fds[0].events = POLLOUT;
        else if (mode == GPU_XDP_MODE_ROUNDTRIP && roundtrip_pollout_armed)
            fds[0].events = POLLIN | POLLOUT;
        else
            fds[0].events = POLLIN;
        fds[0].revents = 0;
        int ret = poll(fds, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            loop_status = -errno;
            break;
        }

        if (ret > 0 && (fds[0].revents &
                        (POLLERR | POLLHUP | POLLNVAL))) {
            fprintf(stderr, "AF_XDP poll failed, revents=0x%x\n",
                    fds[0].revents);
            if (fds[0].revents & POLLNVAL)
                loop_status = -EBADF;
            else if (fds[0].revents & POLLHUP)
                loop_status = -ENOTCONN;
            else
                loop_status = -EIO;
            running = 0;
            break;
        }

        if (mode == GPU_XDP_MODE_GPU_TO_NIC)
            should_process = ret == 0 ||
                             (fds[0].revents & POLLOUT);
        else
            should_process = ret > 0 && (fds[0].revents & POLLIN);

        /* process_packets() reaps and refills around its own RX work.
         * Without ingress, the roundtrip still advances CQ/FQ on the poll
         * timeout and on the one POLLOUT armed after its last RX batch. */
        if (ret == 0 && mode == GPU_XDP_MODE_ROUNDTRIP)
            should_maintain = 1;
        else if (roundtrip_pollout_armed && !should_process &&
                 (fds[0].revents & POLLOUT))
            should_maintain = 1;

        if (should_process) {
            int process_ret;

            switch (mode) {
            case GPU_XDP_MODE_ROUNDTRIP:
                process_ret = process_packets(ctx);
                break;
            case GPU_XDP_MODE_NIC_TO_GPU:
                process_ret = process_nic_to_gpu(ctx);
                break;
            case GPU_XDP_MODE_GPU_TO_NIC:
                process_ret = process_gpu_to_nic(
                    ctx, ctx->source_packet_length);
                break;
            default:
                process_ret = -EINVAL;
                break;
            }

            if (process_ret < 0) {
                fprintf(stderr, "Frame ownership failure; stopping\n");
                loop_status = process_ret;
                break;
            }
            /* TX completions for this RX batch may land after ingress
             * stops, so RX work arms one POLLOUT maintenance opportunity.
             * An empty RX pass already reaped and refilled. */
            if (mode == GPU_XDP_MODE_ROUNDTRIP)
                roundtrip_pollout_armed = process_ret > 0;
        }

        if (should_maintain) {
            int maintain_ret = maintain_roundtrip(ctx);

            roundtrip_pollout_armed = 0;
            if (maintain_ret < 0) {
                fprintf(stderr, "Frame ownership failure; stopping\n");
                loop_status = maintain_ret;
                break;
            }
        }

        /* Print stats every second */
        time_t now = time(NULL);
        if (now != last_stats) {
            print_stats();
            last_stats = now;
        }
    }

    printf("\n\nFinal Statistics:\n");
    printf("  RX packets: %'lu (%'lu bytes)\n", stats.rx_packets, stats.rx_bytes);
    printf("  TX packets: %'lu (%'lu bytes)\n", stats.tx_packets, stats.tx_bytes);
    printf("  CE transfers: %'lu\n", stats.ce_transfers);
    printf("  CUDA staging transfers (non-P2P): %'lu\n",
           stats.cuda_staging_transfers);
    printf("  Errors: %lu\n", stats.errors);
    return loop_status;
}

static int drain_tx_completions(xsk_ctx_t *ctx, unsigned int timeout_ms)
{
    struct timespec start;
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (xdev_ext_xsk_frame_count_state(&ctx->frames.owner,
                                     XDEV_EXT_XSK_FRAME_TX) != 0) {
        int64_t elapsed_ms;

        (void)sendto(xsk_socket__fd(ctx->xsk), NULL, 0,
                     MSG_DONTWAIT, NULL, 0);
        int ret = gpu_xdp_reap_completions(&ctx->frames, &ctx->cq,
                                           BATCH_SIZE);

        if (ret < 0)
            return ret;
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_ms = (int64_t)(now.tv_sec - start.tv_sec) * 1000 +
                     (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed_ms >= (int64_t)timeout_ms)
            break;
        (void)poll(NULL, 0, 1);
    }
    if (xdev_ext_xsk_frame_count_state(&ctx->frames.owner,
                                  XDEV_EXT_XSK_FRAME_TX) != 0) {
        fprintf(stderr,
                "TX completion was not proven; retaining registered backing\n");
        return -ETIMEDOUT;
    }
    return 0;
}

static int detach_xsk_redirect(struct xdev_ext_xsk_redirect *redirect)
{
    int ret = 0;

    for (unsigned int attempt = 0;
         attempt < XSK_REDIRECT_DETACH_ATTEMPTS &&
         xdev_ext_xsk_redirect_is_active(redirect);
         attempt++) {
        ret = xdev_ext_xsk_redirect_detach(redirect);
        if (!xdev_ext_xsk_redirect_is_active(redirect))
            break;
        if (attempt + 1 < XSK_REDIRECT_DETACH_ATTEMPTS)
            (void)poll(NULL, 0, 10);
    }
    if (xdev_ext_xsk_redirect_is_active(redirect) && !ret)
        ret = -EBUSY;
    return ret;
}

static void hold_redirect_backing(void)
{
    fprintf(stderr,
            "XSK redirect remains active; retaining process, socket, UMEM, "
            "and GPU backing. Remove or replace the XDP program before SIGKILL.\n");
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    for (;;)
        (void)pause();
}

/*
 * Usage
 */
static void usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -i <ifname>   Interface name (default: %s)\n", INTERFACE_NAME);
    printf("  -q <queue>    Queue ID (default: 0)\n");
    printf("  -g <gpu>      GPU device ID (default: 0)\n");
    printf("  -m <mode>     roundtrip, nic-to-gpu, or gpu-to-nic (default: roundtrip)\n");
    printf("  -A <src-ip>   Exact flow/source IPv4 (default: 192.0.2.1)\n");
    printf("  -a <dst-ip>   Exact flow/destination IPv4 (default: 192.0.2.2)\n");
    printf("  -P <src-port> Exact flow/source UDP port (default: 54321)\n");
    printf("  -p <dst-port> Exact flow/destination UDP port (default: 12345)\n");
    printf("  -S <src-mac>  Source Ethernet address (required by gpu-to-nic)\n");
    printf("  -D <dst-mac>  Destination Ethernet address (required by gpu-to-nic)\n");
    printf("  -s            Explicitly allow CUDA staging if CE registration is unavailable\n");
    printf("  -h            Show this help\n");
    printf("Input flow: untagged, unfragmented IPv4/UDP whose payload starts with bytes 55 42 52 47 ('UBRG'); other traffic stays in the host stack.\n");
}

int main(int argc, char **argv)
{
    const char *ifname = INTERFACE_NAME;
    int queue_id = 0;
    int gpu_id = 0;
    int allow_cuda_staging = 0;
    enum gpu_xdp_mode mode = GPU_XDP_MODE_ROUNDTRIP;
    struct gpu_xdp_source_config source_config = XDEV_EXT_ZERO_INIT;
    int source_mac_set = 0;
    int destination_mac_set = 0;
    int exit_status = 0;
    int opt;
    struct xdev_ext_xsk_flow_filter flow_filter = {
        .flags = XDEV_EXT_XSK_FILTER_F_ALL,
        .src_ipv4 = UINT32_C(0xc0000201),
        .dst_ipv4 = UINT32_C(0xc0000202),
        .payload_magic = GPU_XDP_FLOW_MAGIC,
        .src_port = 54321,
        .dst_port = 12345,
        .dst_mac = { 0 },
        .max_len = 0,
    };

    /* Parse arguments */
    while ((opt = getopt(argc, argv, "i:q:g:m:A:a:P:p:S:D:sh")) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'q':
            if (parse_queue_id(optarg, &queue_id)) {
                fprintf(stderr, "Invalid queue ID\n");
                return 1;
            }
            break;
        case 'g':
            if (parse_gpu_id(optarg, &gpu_id)) {
                fprintf(stderr, "Invalid GPU ID\n");
                return 1;
            }
            break;
        case 'm':
            if (parse_mode(optarg, &mode)) {
                fprintf(stderr, "Invalid mode\n");
                return 1;
            }
            break;
        case 'A':
            if (parse_filter_ipv4(optarg, &flow_filter.src_ipv4)) {
                fprintf(stderr, "Invalid ingress source IPv4\n");
                return 1;
            }
            break;
        case 'a':
            if (parse_filter_ipv4(optarg, &flow_filter.dst_ipv4)) {
                fprintf(stderr, "Invalid ingress destination IPv4\n");
                return 1;
            }
            break;
        case 'P':
            if (parse_filter_port(optarg, &flow_filter.src_port)) {
                fprintf(stderr, "Invalid ingress source port\n");
                return 1;
            }
            break;
        case 'p':
            if (parse_filter_port(optarg, &flow_filter.dst_port)) {
                fprintf(stderr, "Invalid ingress destination port\n");
                return 1;
            }
            break;
        case 'S':
            if (parse_mac(optarg, source_config.source_mac)) {
                fprintf(stderr, "Invalid source MAC address\n");
                return 1;
            }
            source_mac_set = 1;
            break;
        case 'D':
            if (parse_mac(optarg, source_config.destination_mac)) {
                fprintf(stderr, "Invalid destination MAC address\n");
                return 1;
            }
            destination_mac_set = 1;
            break;
        case 's':
            allow_cuda_staging = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }
    if (optind != argc) {
        usage(argv[0]);
        return 1;
    }
    if (mode == GPU_XDP_MODE_GPU_TO_NIC &&
        (!source_mac_set || !destination_mac_set)) {
        fprintf(stderr,
                "Source mode requires both -S and -D MAC addresses\n");
        return 1;
    }
    source_config.source_ipv4 = flow_filter.src_ipv4;
    source_config.destination_ipv4 = flow_filter.dst_ipv4;
    source_config.source_port = flow_filter.src_port;
    source_config.destination_port = flow_filter.dst_port;

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Increase memory limits */
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    printf("GPU XDP P2P Demo\n");
    printf("================\n");
    printf("Interface: %s, Queue: %d, GPU: %d, Mode: %s\n\n",
           ifname, queue_id, gpu_id, mode_name(mode));
    printf("%s: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, "
           "payload magic UBRG (0x%08x)\n",
           mode == GPU_XDP_MODE_GPU_TO_NIC ? "Source packet template" :
                                              "XDP flow filter",
           flow_filter.src_ipv4 >> 24, (flow_filter.src_ipv4 >> 16) & 0xff,
           (flow_filter.src_ipv4 >> 8) & 0xff, flow_filter.src_ipv4 & 0xff,
           flow_filter.src_port,
           flow_filter.dst_ipv4 >> 24, (flow_filter.dst_ipv4 >> 16) & 0xff,
           (flow_filter.dst_ipv4 >> 8) & 0xff, flow_filter.dst_ipv4 & 0xff,
           flow_filter.dst_port, GPU_XDP_FLOW_MAGIC);

    /* Initialize contexts */
    xsk_ctx_t xsk_ctx = XDEV_EXT_ZERO_INIT;
    gpu_p2p_ctx_t gpu_ctx = XDEV_EXT_ZERO_INIT;

    gpu_ctx.gpu_fd = -1;

    /* Create UMEM */
    if (create_umem(&xsk_ctx)) {
        fprintf(stderr, "Failed to create UMEM\n");
        return 1;
    }

    /* Create XSK socket */
    if (create_xsk(&xsk_ctx, ifname, queue_id, &flow_filter, mode)) {
        fprintf(stderr, "Failed to create XSK\n");
        exit_status = 1;
        goto cleanup;
    }

    /* Pin only after the same virtual range is registered as XSK UMEM. */
    if (gpu_p2p_init(&gpu_ctx, xsk_ctx.umem_buffer, UMEM_SIZE, gpu_id,
                     xsk_socket__fd(xsk_ctx.xsk), allow_cuda_staging)) {
        fprintf(stderr, "Failed to initialize GPU P2P\n");
        exit_status = 1;
        goto cleanup;
    }
    xsk_ctx.gpu_ctx = &gpu_ctx;

    if (mode == GPU_XDP_MODE_GPU_TO_NIC &&
        gpu_prepare_source_templates(&gpu_ctx, &source_config,
                                     &xsk_ctx.source_packet_length)) {
        fprintf(stderr, "Failed to prepare GPU-resident packet templates\n");
        exit_status = 1;
        goto cleanup;
    }

    /* Run main loop */
    if (run_loop(&xsk_ctx, mode)) {
        /* A frame/CQ protocol failure can consume the bad CQ while leaving
         * no counted TX frame.  Latch ambiguity independently of the count. */
        gpu_ctx.dma_sequestered = 1;
        exit_status = 1;
    }

cleanup:
    printf("Cleaning up...\n");

    if (xsk_ctx.xsk) {
        int redirect_ret = detach_xsk_redirect(&xsk_ctx.redirect);

        if (redirect_ret) {
            fprintf(stderr, "XSK redirect detach failed: %s\n",
                    strerror(-redirect_ret));
            exit_status = 1;
        }
        if (xdev_ext_xsk_redirect_is_active(&xsk_ctx.redirect))
            hold_redirect_backing();
        if (drain_tx_completions(&xsk_ctx, 1000)) {
            gpu_ctx.dma_sequestered = 1;
            exit_status = 1;
        }
    }
    if (gpu_p2p_cleanup(&gpu_ctx) == 0) {
        if (xsk_ctx.xsk) {
            xsk_socket__delete(xsk_ctx.xsk);
        }
        if (xsk_ctx.umem) {
            xsk_umem__delete(xsk_ctx.umem);
        }
        if (xsk_ctx.umem_buffer) {
            munmap(xsk_ctx.umem_buffer, UMEM_SIZE);
        }
    } else {
        fprintf(stderr,
                "Backing release skipped because DMA quiescence/unpin was not confirmed\n");
        exit_status = 1;
        hold_sequestered_backing();
    }

    printf("Done.\n");
    return exit_status;
}
