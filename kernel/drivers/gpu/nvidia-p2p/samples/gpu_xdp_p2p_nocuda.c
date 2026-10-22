// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * GPU XDP frame pipeline (No CUDA)
 *
 * This application demonstrates:
 * 1. AF_XDP UMEM setup on network interface
 * 2. CPU-based packet processing and TX with exact frame ownership
 *
 * This version does not allocate GPU memory and therefore does not issue GPU
 * DMA.  Use gpu_xdp_p2p.c for the CE path; this variant exercises the same
 * AF_XDP ownership and failure handling with a CPU staging buffer.
 *
 * Requires libxdp and libbpf.  It neither opens an NVIDIA device nor pins
 * memory through the NVIDIA ABI; use the CUDA variant for that path.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "../../../../tools/include/xdev_ext_nv_p2p_ioctl.h"
#include "../../../../tools/include/xdev_ext_xsk_redirect.h"
#include "gpu_xdp_frame_runtime.h"

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

#define RX_BATCH_SIZE       64
#define TX_BATCH_SIZE       64
#define TX_RETRY_POLL_MS    1   /* re-poll while TX descriptors wait */
#define XSK_REDIRECT_DETACH_ATTEMPTS 3
#define GPU_XDP_FLOW_MAGIC UINT32_C(0x55425247) /* "UBRG", network order */

/*
 * GPU P2P handle structure (no CUDA)
 */
typedef struct {
    void        *umem_buffer;       /* User UMEM buffer (mmap'd) */
    size_t       umem_size;         /* UMEM size */
    int          gpu_fd;            /* NVIDIA driver fd */
    void        *p2p_handle;        /* P2P registration handle */
    uint64_t     gpu_addr;          /* GPU memory address */
    int          gpu_id;            /* GPU device ID */
    int          p2p_available;     /* P2P DMA available flag */

    /* Staging buffer for CPU fallback */
    void        *staging_buffer;
    size_t       staging_size;
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
    int                      tx_copy_mode;  /* TX moves only on a kick */
    gpu_p2p_ctx_t           *gpu_ctx;
    struct gpu_xdp_frame_runtime frames;
    struct xdev_ext_xsk_redirect      redirect;
    uint8_t                  frame_states[NUM_FRAMES];
    uint64_t                 recycle_entries[NUM_FRAMES];
    uint64_t                 expected_tx_addrs[NUM_FRAMES];
} xsk_ctx_t;

/*
 * Statistics
 */
typedef struct {
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t gpu_transfers;
    uint64_t cpu_fallbacks;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t errors;
} stats_t;

static volatile int running = 1;
static stats_t stats = {0};

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
 * Initialize GPU P2P context (without CUDA)
 */
static int gpu_p2p_init(gpu_p2p_ctx_t *ctx, void *umem_buffer,
                        size_t umem_size, int gpu_id, int xsk_fd)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->gpu_fd = -1;
    ctx->umem_buffer = umem_buffer;
    ctx->umem_size = umem_size;
    ctx->gpu_id = gpu_id;
    ctx->p2p_available = 0;
    (void)xsk_fd;

    /* No CUDA allocation/VA exists, so do not register a fake GPU endpoint. */
    /* Allocate CPU staging buffer for fallback */
    ctx->staging_size = BATCH_SIZE * FRAME_SIZE;
    ctx->staging_buffer = mmap(NULL, ctx->staging_size,
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ctx->staging_buffer == MAP_FAILED) {
        int saved_errno = errno;

        perror("mmap staging buffer");
        ctx->staging_buffer = NULL;
        ctx->staging_size = 0;
        return -saved_errno;
    }

    printf("\n*** Running in CPU-only mode (no GPU allocation/VA) ***\n");
    printf("Packets will be processed through CPU staging.\n");

    return 0;
}

/*
 * Cleanup GPU P2P context
 */
static void gpu_p2p_cleanup(gpu_p2p_ctx_t *ctx)
{
    if (ctx->p2p_handle && ctx->gpu_fd >= 0) {
        struct xdev_ext_nv_p2p_unpin_umem unpin_params = {
            .handle = (uint64_t)ctx->p2p_handle,
        };
        if (xdev_ext_nv_p2p_unpin_umem(ctx->gpu_fd, &unpin_params) != 0)
            fprintf(stderr,
                    "P2P UMEM unregistration failed: %s (NV_STATUS=0x%x)\n",
                    strerror(errno), unpin_params.status);
    }

    if (ctx->gpu_fd >= 0) {
        close(ctx->gpu_fd);
    }

    if (ctx->staging_buffer) {
        munmap(ctx->staging_buffer, ctx->staging_size);
    }
}

/*
 * Copy packets from UMEM to the explicit CPU staging area.
 */
static int gpu_transfer_to_gpu(gpu_p2p_ctx_t *ctx, uint64_t umem_offset,
                               uint64_t gpu_offset, size_t size)
{
    /* CPU staging; this no-CUDA binary never claims CE passthrough. */
    if (ctx->staging_buffer && gpu_offset <= ctx->staging_size &&
        size <= ctx->staging_size - gpu_offset) {
        void *src = (char *)ctx->umem_buffer + umem_offset;
        void *dst = (char *)ctx->staging_buffer + gpu_offset;
        memcpy(dst, src, size);
        stats.cpu_fallbacks++;
        return 0;
    }

    stats.errors++;
    return -1;
}

/*
 * Copy processed packets from the CPU staging area back to UMEM.
 */
static int gpu_transfer_from_gpu(gpu_p2p_ctx_t *ctx, uint64_t gpu_offset,
                                  uint64_t umem_offset, size_t size)
{
    /* CPU staging; this no-CUDA binary never claims CE passthrough. */
    if (ctx->staging_buffer && gpu_offset <= ctx->staging_size &&
        size <= ctx->staging_size - gpu_offset) {
        void *src = (char *)ctx->staging_buffer + gpu_offset;
        void *dst = (char *)ctx->umem_buffer + umem_offset;
        memcpy(dst, src, size);
        stats.cpu_fallbacks++;
        return 0;
    }

    stats.errors++;
    return -1;
}

/*
 * CPU packet processing (MAC swap for demo)
 * In P2P mode, the GPU would do this; here we simulate it on CPU
 */
static void cpu_process_packet(uint8_t *pkt, uint32_t len)
{
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) +
              sizeof(struct udphdr))
        return;

    /* Endpoint exchange preserves the IP/UDP checksum word sum.  The packet
     * starts at a frame-aligned offset, so the IPv4 header is at an address
     * that is 2 mod 4: copy the IPv4 and UDP headers through byte pointers
     * into local structs and back instead of addressing them in place. */
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
}

/*
 * Process batch of packets
 * With P2P: transfers to GPU, processes there, transfers back
 * Without P2P: processes on CPU using staging buffer
 */
static int process_packet_batch(gpu_p2p_ctx_t *ctx, uint64_t *pkt_offsets,
                                 uint32_t *pkt_lengths, int num_packets)
{
    (void)pkt_offsets;

    if (num_packets <= 0) return 0;

    /* Process packets in the CPU staging buffer. */
    for (int i = 0; i < num_packets; i++) {
        uint64_t gpu_offset = i * FRAME_SIZE;
        if (gpu_offset + pkt_lengths[i] <= ctx->staging_size) {
            uint8_t *pkt = (uint8_t *)ctx->staging_buffer + gpu_offset;
            cpu_process_packet(pkt, pkt_lengths[i]);
        }
    }

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

    /* Try huge pages first to reduce page-management overhead. */
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
                      const struct xdev_ext_xsk_flow_filter *flow_filter)
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
        /* Try without zero-copy */
        fprintf(stderr, "Zero-copy XSK failed, trying copy mode: %s\n", strerror(-ret));
        cfg.bind_flags = XDP_USE_NEED_WAKEUP;
        cfg.xdp_flags = XDP_FLAGS_SKB_MODE;

        ret = xsk_socket__create(&ctx->xsk, ifname, queue_id,
                                  ctx->umem, &ctx->rx, &ctx->tx, &cfg);
        if (ret) {
            fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(-ret));
            return ret;
        }
        ctx->tx_copy_mode = 1;
        printf("Created XSK in copy mode (zero-copy not supported by driver)\n");
    } else {
        printf("Created XSK in zero-copy mode\n");
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        ret = errno ? -errno : -ENODEV;
        xsk_socket__delete(ctx->xsk);
        ctx->xsk = NULL;
        return ret;
    }
    ret = xdev_ext_xsk_redirect_attach(&ctx->redirect, flow_filter, (int)ifindex,
                                  (uint32_t)queue_id,
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
    ret = gpu_xdp_refill(&ctx->frames, &ctx->fq, NUM_FRAMES);
    if (ret != NUM_FRAMES) {
        fprintf(stderr, "Failed to populate fill ring: %d/%d\n",
                ret, NUM_FRAMES);
        return ret < 0 ? ret : -ENOSPC;
    }

    printf("Created XSK on %s queue %d\n", ifname, queue_id);
    return 0;
}

/*
 * TX descriptors published on the ring that the kernel has not consumed yet.
 * In copy mode (the XDP_FLAGS_SKB_MODE fallback) TX moves only when sendto()
 * or poll() runs the kernel's transmit pass, at most 32 descriptors per pass,
 * and a pass that hits -EAGAIN (socket send buffer full, driver busy) leaves
 * the rest on the ring for userspace to retry.
 */
static int tx_ring_pending(xsk_ctx_t *ctx)
{
    return xsk_prod_nb_free(&ctx->tx, ctx->tx.size) < ctx->tx.size;
}

/* Copy mode needs the kick for every transmit; zero-copy only when the
 * driver asks for a wakeup. */
static void kick_tx(xsk_ctx_t *ctx)
{
    if (ctx->tx_copy_mode || xsk_ring_prod__needs_wakeup(&ctx->tx))
        (void)sendto(xsk_socket__fd(ctx->xsk), NULL, 0,
                     MSG_DONTWAIT, NULL, 0);
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

    /* Transfer packets to GPU (or staging) */
    int kept = 0;
    for (int i = 0; i < active; i++) {
        if (gpu_transfer_to_gpu(ctx->gpu_ctx, pkt_offsets[i],
                                (uint64_t)kept * FRAME_SIZE,
                                pkt_lengths[i])) {
            (void)gpu_xdp_frame_drop_rx(&ctx->frames, frame_bases[i]);
            stats.errors++;
            continue;
        }
        if (kept != i) {
            desc_addrs[kept] = desc_addrs[i];
            frame_bases[kept] = frame_bases[i];
            pkt_offsets[kept] = pkt_offsets[i];
            pkt_lengths[kept] = pkt_lengths[i];
        }
        kept++;
    }
    active = kept;

    /* Process on GPU (or CPU in fallback mode) */
    if (active && process_packet_batch(ctx->gpu_ctx, pkt_offsets,
                                       pkt_lengths, active)) {
        for (int i = 0; i < active; i++)
            (void)gpu_xdp_frame_drop_rx(&ctx->frames, frame_bases[i]);
        stats.errors += active;
        active = 0;
    }

    /* Transfer processed packets back from GPU (or staging) */
    for (int i = 0; i < active; i++) {
        if (gpu_transfer_from_gpu(ctx->gpu_ctx, (uint64_t)i * FRAME_SIZE,
                                  pkt_offsets[i], pkt_lengths[i])) {
            (void)gpu_xdp_frame_drop_rx(&ctx->frames, frame_bases[i]);
            stats.errors++;
            continue;
        }
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

    if (ret)
        kick_tx(ctx);
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
 * CQ/FQ maintenance for the RX -> CPU staging -> TX roundtrip that does not
 * depend on new ingress.  The last TX completions can arrive after ingress
 * stops; without them the frames stay in TX and never return to the fill
 * ring.  Reap first, so only an exact TX completion returns a frame to FREE,
 * then refill from those FREE frames.  This path runs at most once per RX
 * batch plus once per poll timeout, so it takes every completion that is
 * present instead of one RX batch.  TX descriptors that are still waiting
 * get another transmit kick.
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
    if (tx_ring_pending(ctx))
        kick_tx(ctx);
    return reaped;
}

/*
 * Print statistics
 */
static void print_stats(void)
{
    static uint64_t last_rx = 0, last_tx = 0;
    static struct timespec last_time = {0};
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    if (last_time.tv_sec != 0) {
        double dt = (now.tv_sec - last_time.tv_sec) +
                    (now.tv_nsec - last_time.tv_nsec) / 1e9;

        uint64_t rx_pps = (uint64_t)((stats.rx_packets - last_rx) / dt);
        uint64_t tx_pps = (uint64_t)((stats.tx_packets - last_tx) / dt);

        printf("\rRX: %lu pps (%lu total) | TX: %lu pps (%lu total) | "
               "GPU DMA (disabled): %lu | CPU: %lu | Err: %lu",
               rx_pps, stats.rx_packets, tx_pps, stats.tx_packets,
               stats.gpu_transfers, stats.cpu_fallbacks, stats.errors);
        fflush(stdout);
    }

    last_rx = stats.rx_packets;
    last_tx = stats.tx_packets;
    last_time = now;
}

/*
 * Main loop
 */
static int run_loop(xsk_ctx_t *ctx)
{
    struct pollfd fds[1];
    time_t last_stats = 0;
    int roundtrip_pollout_armed = 0;
    int loop_status = 0;

    fds[0].fd = xsk_socket__fd(ctx->xsk);

    printf("Starting packet processing loop...\n");
    printf("Press Ctrl+C to stop\n\n");

    while (running) {
        int should_process = 0;
        int should_maintain = 0;
        int poll_timeout_ms = 1000;

        /* An XSK with TX ring space is always writable.  Ask for POLLOUT
         * only while one CQ/FQ maintenance opportunity is armed; otherwise
         * wait for ingress or the timeout. */
        if (roundtrip_pollout_armed)
            fds[0].events = POLLIN | POLLOUT;
        else
            fds[0].events = POLLIN;
        /* Freed send-buffer space wakes POLLOUT waiters only, so TX
         * descriptors left after -EAGAIN would wait the full timeout.
         * While any wait, re-poll soon; the timeout maintenance kicks
         * them again.  An empty TX ring keeps the full timeout. */
        if (tx_ring_pending(ctx))
            poll_timeout_ms = TX_RETRY_POLL_MS;
        fds[0].revents = 0;
        int ret = poll(fds, 1, poll_timeout_ms);
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

        should_process = ret > 0 && (fds[0].revents & POLLIN);

        /* process_packets() reaps and refills around its own RX work.
         * Without ingress, CQ/FQ still advance on the poll timeout and on
         * the one POLLOUT armed after the last RX batch. */
        if (ret == 0)
            should_maintain = 1;
        else if (roundtrip_pollout_armed && !should_process &&
                 (fds[0].revents & POLLOUT))
            should_maintain = 1;

        if (should_process) {
            int process_ret = process_packets(ctx);

            if (process_ret < 0) {
                fprintf(stderr, "Frame ownership failure; stopping\n");
                loop_status = process_ret;
                break;
            }
            /* TX completions for this RX batch may land after ingress
             * stops, so RX work arms one POLLOUT maintenance opportunity.
             * An empty RX pass already reaped and refilled. */
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
    printf("  RX packets: %lu (%lu bytes)\n", stats.rx_packets, stats.rx_bytes);
    printf("  TX packets: %lu (%lu bytes)\n", stats.tx_packets, stats.tx_bytes);
    printf("  GPU DMA transfers (disabled): %lu\n", stats.gpu_transfers);
    printf("  CPU fallback transfers: %lu\n", stats.cpu_fallbacks);
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
            "XSK redirect remains active; retaining process, socket, and UMEM. "
            "Remove or replace the XDP program before SIGKILL.\n");
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    for (;;)
        (void)pause();
}

/*
 * A missing exact TX completion leaves NIC ownership ambiguous.  Closing the
 * socket is not a DMA barrier, so retain every fd and mapping until an operator
 * has independently quiesced the queue.  SIGKILL is the post-quiescence escape.
 */
static void hold_unquiesced_backing(void)
{
    fprintf(stderr,
            "TX DMA state is unquiesced; retaining process, fds, and mappings. "
            "Verify device quiescence before SIGKILL.\n");
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
    printf("\n");
    printf("GPU XDP ownership demo (No CUDA version)\n");
    printf("Receives packets via AF_XDP, processes them through CPU staging,\n");
    printf("and reuses frames only after TX completion.\n");
    printf("\n");
    printf("Options:\n");
    printf("  -i <ifname>   Interface name (default: %s)\n", INTERFACE_NAME);
    printf("  -q <queue>    Queue ID (default: 0)\n");
    printf("  -g <gpu>      Compatibility option only; no GPU is opened\n");
    printf("  -A <src-ip>   Exact ingress source IPv4 (default: 192.0.2.1)\n");
    printf("  -a <dst-ip>   Exact ingress destination IPv4 (default: 192.0.2.2)\n");
    printf("  -P <src-port> Exact ingress UDP source port (default: 54321)\n");
    printf("  -p <dst-port> Exact ingress UDP destination port (default: 12345)\n");
    printf("  -h            Show this help\n");
    printf("Input flow: untagged, unfragmented IPv4/UDP whose payload starts with bytes 55 42 52 47 ('UBRG'); other traffic stays in the host stack.\n");
    printf("\n");
    printf("Requirements:\n");
    printf("  - libxdp, libbpf\n");
    printf("\n");
    printf("GPU CE DMA requires the CUDA variant, which owns a valid GPU VA.\n");
}

int main(int argc, char **argv)
{
    const char *ifname = INTERFACE_NAME;
    int queue_id = 0;
    int gpu_id = 0;
    int exit_status = 0;
    bool backing_sequestered = false;
    int opt;
    struct xdev_ext_xsk_flow_filter flow_filter = {
        .flags = XDEV_EXT_XSK_FILTER_F_ALL,
        .src_ipv4 = UINT32_C(0xc0000201),
        .dst_ipv4 = UINT32_C(0xc0000202),
        .payload_magic = GPU_XDP_FLOW_MAGIC,
        .src_port = 54321,
        .dst_port = 12345,
    };

    /* Parse arguments */
    while ((opt = getopt(argc, argv, "i:q:g:A:a:P:p:h")) != -1) {
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
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Increase memory limits */
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    printf("====================================\n");
    printf("GPU XDP ownership demo (No CUDA version)\n");
    printf("====================================\n");
    printf("Interface: %s, Queue: %d, compatibility GPU ID: %d\n\n",
           ifname, queue_id, gpu_id);
    printf("XDP flow filter: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u, "
           "payload magic UBRG (0x%08x)\n",
           flow_filter.src_ipv4 >> 24, (flow_filter.src_ipv4 >> 16) & 0xff,
           (flow_filter.src_ipv4 >> 8) & 0xff, flow_filter.src_ipv4 & 0xff,
           flow_filter.src_port,
           flow_filter.dst_ipv4 >> 24, (flow_filter.dst_ipv4 >> 16) & 0xff,
           (flow_filter.dst_ipv4 >> 8) & 0xff, flow_filter.dst_ipv4 & 0xff,
           flow_filter.dst_port, GPU_XDP_FLOW_MAGIC);

    /* Initialize contexts */
    xsk_ctx_t xsk_ctx = {0};
    gpu_p2p_ctx_t gpu_ctx = { .gpu_fd = -1 };

    /* Create UMEM */
    if (create_umem(&xsk_ctx)) {
        fprintf(stderr, "Failed to create UMEM\n");
        return 1;
    }

    /* Create XSK socket */
    if (create_xsk(&xsk_ctx, ifname, queue_id, &flow_filter)) {
        fprintf(stderr, "Failed to create XSK\n");
        exit_status = 1;
        goto cleanup;
    }

    if (gpu_p2p_init(&gpu_ctx, xsk_ctx.umem_buffer, UMEM_SIZE, gpu_id,
                     xsk_socket__fd(xsk_ctx.xsk))) {
        fprintf(stderr, "Failed to initialize CPU staging context\n");
        exit_status = 1;
        goto cleanup;
    }
    xsk_ctx.gpu_ctx = &gpu_ctx;

    /* Run main loop */
    if (run_loop(&xsk_ctx)) {
        /* A malformed/stale CQ can be consumed before TX state reaches zero;
         * preserve an independent ambiguity latch for cleanup. */
        backing_sequestered = true;
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
            backing_sequestered = true;
            exit_status = 1;
        }
    }
    if (backing_sequestered)
        hold_unquiesced_backing();
    gpu_p2p_cleanup(&gpu_ctx);
    if (xsk_ctx.xsk) {
        xsk_socket__delete(xsk_ctx.xsk);
    }
    if (xsk_ctx.umem) {
        xsk_umem__delete(xsk_ctx.umem);
    }
    if (xsk_ctx.umem_buffer) {
        munmap(xsk_ctx.umem_buffer, UMEM_SIZE);
    }

    printf("Done.\n");
    return exit_status;
}
