/*
 * NVMe to AF_XDP Pipeline using io_uring unified ops
 *
 * Uses IORING_OP_URING_CMD to issue NVMe passthrough commands directly,
 * performs userspace computation, and transmits via AF_XDP UMEM.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

/* New liburing releases carry a matching io_uring UAPI header.  Include that
 * header first when its version marker exists, otherwise a newer project UAPI
 * shim can be shadowed by (and made incompatible with) the installed library.
 * liburing 2.1 has no version header, so local compatibility builds continue
 * to take the project shim first and are rejected by the runtime layout gate. */
#if defined(__has_include)
#if __has_include(<liburing/io_uring_version.h>)
#include <liburing.h>
#define NXP_LIBURING_INCLUDED_FIRST 1
#endif
#endif

#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/random.h>
#include <sys/uio.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/fs.h>
#include <xdp/xsk.h>          /* libxdp xsk API (well-tested) — replaces hand-rolled AF_XDP rings */
#include <linux/io_uring.h>
#include <linux/nvme_ioctl.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <time.h>
#include <dirent.h>
#include <dlfcn.h>

#include "nvme_xdp_pipeline_core.h"
#include "tools/nvme_gpu_nic_chain_core.h"
#include "tools/nvme_gpu_nic_runtime.h"
#include "tools/include/xdev_ext_xsk_redirect.h"

/* Configuration */
/* io_uring SQ/CQ depth must cover the max batched in-flight NVMe window (-Q depth). */
#define QUEUE_DEPTH         4096
/* AF_XDP UMEM chunks are 4096 bytes.  Each ordinary UDP packet occupies one
 * chunk, while one LBA-aligned logical NVMe IO_VEC command may span several
 * chunks/packets.  Network segment offsets stay contiguous and segment starts
 * retain the alignment required by the direct vector mapping. */
/* UMEM has 4096 frames (16 MiB), but the usable in-flight window is the minimum
 * of this pool and every 2048-entry AF_XDP ring.  Startup checks
 * depth*segments_per_group against each bound; the old single-frame assumption
 * that every -Q <= 2048 fits is invalid for the default six-frame transfer. */
#define NUM_FRAMES          4096
/* Max logical NVMe commands accepted by the CLI before segment/ring checks. */
#define MAX_INFLIGHT        2048
/* ETH(14)+IP(20)+UDP(8) = 42B.  The on-wire packet starts at frame+22,
 * the 40-byte wire header starts at frame+64, and NVMe payload DMA starts at
 * frame+104.  Thus headers abut payload while every direct IO_VEC address is
 * naturally aligned. */
#define PKT_HDR_SIZE        (14 + 20 + 8)
#define PKT_HEADER_ROOM     64
#define PKT_START_OFF       (PKT_HEADER_ROOM - PKT_HDR_SIZE)
#define NXP_WIRE_OFFSET     PKT_HEADER_ROOM
#define NXP_DATA_OFFSET     (NXP_WIRE_OFFSET + NXP_WIRE_HEADER_LEN)
#define NXP_VECTOR_ALIGNMENT ((uint32_t)sizeof(uint64_t))
#define NXP_RX_PACKET_OFFSET (XDP_PACKET_HEADROOM + PKT_START_OFF)
#define NXP_RX_DATA_OFFSET  (NXP_RX_PACKET_OFFSET + PKT_HDR_SIZE + \
                             NXP_WIRE_HEADER_LEN)
/* Use the tighter RX layout when planning a wire format that both endpoints
 * can consume directly.  At MTU1500 the MTU remains the limiting bound. */
#define NXP_LAYOUT_DATA_OFFSET NXP_RX_DATA_OFFSET
#define NXP_SINGLE_FRAME_DATA_MAX (FRAME_SIZE - NXP_LAYOUT_DATA_OFFSET)
#define FRAME_SIZE          4096
#define UMEM_SIZE           (NUM_FRAMES * FRAME_SIZE)
#define INVALID_UMEM_FRAME  UINT64_MAX
#define NXP_MAX_TRANSIENT_RETRIES 64U
#define NXP_WAIT_TIMEOUT_NS  UINT64_C(100000000)
#define NXP_RX_GROUP_TIMEOUT_NS UINT64_C(1000000000)
#define NXP_RX_IDLE_TIMEOUT_NS UINT64_C(5000000000)
#define NXP_REDIRECT_DETACH_RETRIES 3U

_Static_assert(PKT_START_OFF + PKT_HDR_SIZE == NXP_WIRE_OFFSET,
               "TX packet headers must end at the NXP wire header");
_Static_assert(NXP_DATA_OFFSET % NXP_VECTOR_ALIGNMENT == 0,
               "TX vector payload must be naturally aligned");
_Static_assert(NXP_RX_DATA_OFFSET % NXP_VECTOR_ALIGNMENT == 0,
               "RX vector payload must be naturally aligned");

#include "xdev_ext_frame_sm.h"   /* per-frame 4-state lifecycle SM (paper §Lifecycle) */

/* Device-reported LBA size.  -b, when supplied, is only an assertion against
 * this value; it never overrides namespace geometry. */
static uint32_t g_lba_size;
static uint32_t g_expected_lba_size;
/* Logical NVMe command size in bytes; overridable via -B. Default 8192.
 * The logical size is LBA aligned and may span multiple MTU-sized frames.
 * Standard MTU 1500 yields six ordinary UDP packets (1432*5 + 1032) while
 * preserving one fixed registered NVMe IO_VEC command. */
static uint32_t g_block_size = 8192;
static int g_staging = 0;  /* -Z: NVMe read into a separate buffer + memcpy into UMEM (no zero-copy DMA into the AF_XDP-pinned UMEM) — crash-bisect diagnostic */
static int g_depth = 1;        /* -Q <depth>: max logical NVMe commands in flight */
static int g_zerocopy = 1;     /* default ON: zero-copy IS the paper datapath. Auto-falls back to XDP_COPY if the NIC/queue can't ZC (veth, 1GbE). -C forces copy. */
static int g_need_wakeup = 0;  /* set when ZC bind used XDP_USE_NEED_WAKEUP */
static int g_tx_full_poll = 0; /* -W: poll(POLLOUT) while the AF_XDP TX ring is full */
static int g_fixed_file = 0;    /* -F: registered-file arm */
static int g_fixed_buffer = 0;  /* -R: registered-buffer arm */
static int g_iopoll = 0;        /* -I: true io_uring IOPOLL, after sysfs proof */
/* --revalidate-every N (measurement only): re-prove the namespace before
 * every Nth submit batch; 1 (default) is every batch, 0 never. */
static uint32_t g_revalidate_every = 1;

enum pipeline_direction {
    PIPELINE_NVME_TO_NIC = 0,
    PIPELINE_NIC_TO_NVME,
};

enum pipeline_transform {
    PIPELINE_TRANSFORM_NONE = 0,
    PIPELINE_TRANSFORM_XOR,
};

static enum pipeline_direction g_direction = PIPELINE_NVME_TO_NIC;
/* Byte-preserving transfer is the default.  XOR remains an explicit
 * end-to-end transformation diagnostic for the reversible KVM exercise. */
static enum pipeline_transform g_transform = PIPELINE_TRANSFORM_NONE;

static int pipeline_validate_transform(enum pipeline_direction direction,
                                       enum pipeline_transform transform)
{
    if ((direction != PIPELINE_NVME_TO_NIC &&
         direction != PIPELINE_NIC_TO_NVME) ||
        (transform != PIPELINE_TRANSFORM_NONE &&
         transform != PIPELINE_TRANSFORM_XOR))
        return -EINVAL;
    if (direction == PIPELINE_NIC_TO_NVME &&
        transform != PIPELINE_TRANSFORM_NONE)
        return -EINVAL;
    return 0;
}

/* NVMe opcodes */
#define NVME_CMD_READ       0x02
#define NVME_CMD_WRITE      0x01

/* io_uring opcodes from kernel */
#ifndef IORING_OP_URING_CMD
#define IORING_OP_URING_CMD 46
#endif

/* Syscall number for io_uring_sched_hints */
#ifndef __NR_io_uring_sched_hints
#define __NR_io_uring_sched_hints 468
#endif

/* Scheduler hint flags and structure for older userspace UAPI headers. */
#ifndef IO_URING_SCHED_HINT_NVME_XDP
#define IO_URING_SCHED_HINT_LATENCY     (1U << 0)
#define IO_URING_SCHED_HINT_THROUGHPUT  (1U << 1)
#define IO_URING_SCHED_HINT_REALTIME    (1U << 2)
#define IO_URING_SCHED_HINT_NVME_XDP    (1U << 3)

struct io_uring_sched_hints {
    uint64_t read_freq_ns;
    uint64_t send_freq_ns;
    uint32_t batch_size;
    uint32_t flags;
    uint64_t __resv[2];
};
#endif

/* Syscall wrapper for io_uring_sched_hints */
static int io_uring_sched_hints_set(struct io_uring_sched_hints *hints)
{
    return syscall(__NR_io_uring_sched_hints, 0, hints, 0);
}

static __attribute__((unused)) int io_uring_sched_hints_get(struct io_uring_sched_hints *hints)
{
    return syscall(__NR_io_uring_sched_hints, 1, hints, 0);
}

#ifndef NXP_LIBURING_INCLUDED_FIRST
#include <liburing.h>   /* old-header compatibility; runtime gate rejects 2.1 */
#endif

_Static_assert(sizeof(struct nvme_uring_cmd) <= 80,
               "NVMe command must fit an SQE128 command payload");
_Static_assert(sizeof(struct io_uring_sqe) == 64,
               "SQE128 addressing assumes a 64-byte base SQE");
_Static_assert(sizeof(struct io_uring_cqe) == 16,
               "CQE32 addressing assumes a 16-byte base CQE");
_Static_assert(PKT_HEADER_ROOM >= PKT_HDR_SIZE,
               "packet headers must fit before the DMA payload");
_Static_assert(NUM_FRAMES > MAX_INFLIGHT,
               "the UMEM pool needs TX slack beyond the NVMe window");

/* io_uring context (liburing) for NVMe passthrough via URING_CMD */
struct uring_ctx {
    struct io_uring ring;
    bool initialized;
    bool fixed_file_registered;
    bool fixed_buffer_registered;
    /* rx-write without IOPOLL: an eventfd registered on the ring, signalled
     * for every CQE, so one poll() can wait on WRITE completions and the RX
     * ring together. */
    bool cq_eventfd_registered;
    int cq_eventfd;
};

struct pipeline_ctx;

/* Every fallible boundary used by the production loop is behind this small
 * adapter.  Production supplies the syscall/liburing implementation; the
 * selftest supplies deterministic failures and exercises the same control
 * flow without requiring NVMe or AF_XDP hardware. */
struct pipeline_adapter {
    int (*revalidate)(struct pipeline_ctx *ctx);
    int (*require_extended_layout)(struct pipeline_ctx *ctx);
    int (*prove_iopoll)(struct pipeline_ctx *ctx);
    int (*ring_init)(struct pipeline_ctx *ctx);
    int (*ring_close)(struct pipeline_ctx *ctx);
    int (*submit)(struct pipeline_ctx *ctx);
    int (*enter)(struct pipeline_ctx *ctx, unsigned int to_submit);
    int (*peek_cqe)(struct pipeline_ctx *ctx, struct io_uring_cqe **cqe);
    int (*progress_iopoll)(struct pipeline_ctx *ctx);
    int (*monotonic_ns)(struct pipeline_ctx *ctx, uint64_t *now_ns);
    int (*wait_cqe_timeout)(struct pipeline_ctx *ctx,
                            struct io_uring_cqe **cqe,
                            uint64_t timeout_ns);
    /* One bounded wait for either a CQE notification or an RX descriptor.
     * 0 when either fd became ready (CQEs are then found with peek_cqe), -ETIME
     * on timeout, a negative errno otherwise; *rx_revents is the XSK fd's
     * revents. */
    int (*wait_cqe_or_rx)(struct pipeline_ctx *ctx, uint64_t timeout_ns,
                          short *rx_revents);
    int (*unregister_buffers)(struct pipeline_ctx *ctx);
    int (*unregister_files)(struct pipeline_ctx *ctx);
};

/* XDP socket context (libxdp). The 4 hand-rolled manual rings were replaced by
 * libxdp's xsk_ring_prod/xsk_ring_cons — the hand-rolled TX reported
 * "transmitted/completed" but no packets ever egressed the NIC. */
struct xsk_ctx {
    int xsk_fd;
    void *umem_area;                /* plain anonymous mmap (NOT MAP_HUGETLB) */
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    struct xdev_ext_xsk_redirect redirect;
    struct xsk_ring_prod fq;        /* fill ring (unused for TX-only) */
    struct xsk_ring_cons cq;        /* completion ring */
    struct xsk_ring_prod tx;        /* TX ring */
    struct xsk_ring_cons rx;        /* RX ring (unused) */
    /* AF_XDP CQ entries contain addresses but no generation.  Once an
     * unattributed entry is observed, this socket and its UMEM stay invalidated
     * and no frame may be allocated or reclaimed again. */
    bool protocol_invalidated;

    /* Per-frame lifecycle SM; its Treiber stack IS the FREE-state container
     * (replaces the old umem_frame_addr[] LIFO + umem_frame_free count). */
    struct xdev_ext_pool pool;
    struct xdev_ext_frame pool_frames[NUM_FRAMES];
    /* Composite-chain journal storage for frames already published to TX.
     * Before publication the same journal lives in its inflight_slot; moving
     * it here keeps one owner record through the exact AF_XDP CQ address. */
    struct ngn_frame_journal chain_frames[NUM_FRAMES];
};

/* Pipeline context */
struct pipeline_ctx {
    struct uring_ctx uring;
    struct xsk_ctx xsk;
    int nvme_fd;
    int block_fd;
    char *nvme_device;
    char *block_device;
    char derived_block_device[PATH_MAX];
    char char_sysfs[PATH_MAX];
    char controller_sysfs[PATH_MAX];
    char block_sysfs[PATH_MAX];
    char *net_iface;
    int ifindex;
    int queue_id;
    uint32_t nsid;  /* NVMe namespace ID */
    uint32_t mtu;
    struct nxp_namespace namespace;
    struct nxp_io_limits io_limits;
    struct nxp_stats stats;
    int first_error;
    bool ring_close_failed;
    bool unmatched_io_retained;
    bool backing_quiescence_failed;
    bool chain_sequestered;
    bool gpu_enabled;
    const char *gpu_device;
    uint64_t chain_id;
    struct ngn_gpu_runtime gpu;
    const struct pipeline_adapter *adapter;
    void *adapter_data;

    /* Remote destination */
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint32_t dst_ip;
    uint32_t src_ip;
    uint16_t dst_port;
    uint16_t src_port;
    uint64_t session_id;
    uint64_t submit_batches;  /* batches that reached the revalidation point */
};

static int pipeline_chain_tx_complete(struct pipeline_ctx *ctx,
				      uint64_t frame_addr);

static int production_revalidate(struct pipeline_ctx *ctx);
static int production_require_extended_layout(struct pipeline_ctx *ctx);
static int production_prove_iopoll(struct pipeline_ctx *ctx);
static int production_ring_init(struct pipeline_ctx *ctx);
static int production_ring_close(struct pipeline_ctx *ctx);
static int production_submit(struct pipeline_ctx *ctx);
static int production_enter(struct pipeline_ctx *ctx,
                            unsigned int to_submit);
static int production_peek_cqe(struct pipeline_ctx *ctx,
                               struct io_uring_cqe **cqe);
static int production_progress_iopoll(struct pipeline_ctx *ctx);
static int production_monotonic_ns(struct pipeline_ctx *ctx,
                                   uint64_t *now_ns);
static int production_wait_cqe_timeout(struct pipeline_ctx *ctx,
                                       struct io_uring_cqe **cqe,
                                       uint64_t timeout_ns);
static int production_wait_cqe_or_rx(struct pipeline_ctx *ctx,
                                     uint64_t timeout_ns, short *rx_revents);
static int production_unregister_buffers(struct pipeline_ctx *ctx);
static int production_unregister_files(struct pipeline_ctx *ctx);

static const struct pipeline_adapter production_adapter = {
    .revalidate = production_revalidate,
    .require_extended_layout = production_require_extended_layout,
    .prove_iopoll = production_prove_iopoll,
    .ring_init = production_ring_init,
    .ring_close = production_ring_close,
    .submit = production_submit,
    .enter = production_enter,
    .peek_cqe = production_peek_cqe,
    .progress_iopoll = production_progress_iopoll,
    .monotonic_ns = production_monotonic_ns,
    .wait_cqe_timeout = production_wait_cqe_timeout,
    .wait_cqe_or_rx = production_wait_cqe_or_rx,
    .unregister_buffers = production_unregister_buffers,
    .unregister_files = production_unregister_files,
};

/* Initialize io_uring with 128-byte SQE support for URING_CMD */
static int init_io_uring(struct uring_ctx *ctx)
{
    struct io_uring_params params;
    int ret;

    memset(&ctx->ring, 0, sizeof(ctx->ring));
    memset(&params, 0, sizeof(params));
    /* 128-byte SQE holds nvme_uring_cmd; 32-byte CQE is REQUIRED for NVMe passthrough completion */
    params.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
    if (g_iopoll)
        params.flags |= IORING_SETUP_IOPOLL;

    ret = io_uring_queue_init_params(QUEUE_DEPTH, &ctx->ring, &params);
    if (ret < 0) {
        fprintf(stderr, "io_uring_queue_init_params: %s\n", strerror(-ret));
        return ret;
    }
    ctx->initialized = true;
    return 0;
}

/* Allocate UMEM frame: FREE -> IO_PENDING (stack pop + CAS claim). */
static uint64_t xsk_alloc_umem_frame(struct xsk_ctx *xsk)
{
    xdev_ext_sm_u32 idx;

    if (xsk->protocol_invalidated)
        return INVALID_UMEM_FRAME;
    if (xdev_ext_frame_alloc(&xsk->pool, &idx) != 0)
        return INVALID_UMEM_FRAME;
    return (uint64_t)idx * FRAME_SIZE;
}

/* TX completion: the (single) consumer retires TX_PENDING -> FREE. */
static void xsk_retire_umem_frame(struct xsk_ctx *xsk, uint64_t addr)
{
    if (xdev_ext_frame_consumer_done(&xsk->pool, addr / FRAME_SIZE) != 0)
        fprintf(stderr, "BUG: retire on frame %lu in wrong state\n",
                (unsigned long)(addr / FRAME_SIZE));
}

/* Initialize AF_XDP socket with UMEM via libxdp (xsk_umem__create /
 * xsk_socket__create). libxdp takes an IFNAME (string), not an ifindex, so this
 * takes the iface name. Uses a PLAIN MAP_ANONYMOUS UMEM (NOT MAP_HUGETLB, which
 * was a hang factor) and requests XDP_ZEROCOPY by default, falling back to
 * XDP_COPY on NICs lacking zero-copy support. */
static int init_xsk(struct xsk_ctx *xsk, const char *ifname, int queue_id,
		    const struct xdev_ext_xsk_flow_filter *flow_filter)
{
    unsigned int ifindex;
    int ret;

    xdev_ext_xsk_redirect_init(&xsk->redirect);

    /* --- PLAIN anonymous UMEM (NOT MAP_HUGETLB) --- */
    xsk->umem_area = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (xsk->umem_area == MAP_FAILED) {
        perror("mmap umem (anon)");
        return -1;
    }

    /* --- Create UMEM (registers it + sets up fill/comp rings) ---
     * In XDP_ZEROCOPY mode the mlx5 driver DMAs straight from the descriptor address
     * and, with an ALIGNED UMEM, requires that address to be chunk(frame)-aligned. Our
     * on-wire packet starts at frame_addr + PKT_START_OFF (a +22 byte offset, NOT
     * frame-aligned), so an aligned ZC UMEM rejects every TX desc (mlx5 tx_xsk_err++,
     * tx_packets stays 0). XDP_UMEM_UNALIGNED_CHUNK_FLAG lets a descriptor address sit at
     * an arbitrary offset within its chunk, which is exactly what the header-abutting
     * layout needs. COPY mode copies into an skb and tolerates any offset, so the flag is
     * only required (and only set) for ZC. */
    struct xsk_umem_config ucfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = FRAME_SIZE,
        /* RX data starts after the kernel's XDP_PACKET_HEADROOM.  Adding the
         * same 22-byte packet offset used by TX places the 40-byte wire header
         * at frame+320 and its IO_VEC payload at frame+360 (8-byte aligned).
         * No payload copy is needed before the NVMe WRITE. */
        .frame_headroom = PKT_START_OFF,
        .flags          = g_zerocopy ? XDP_UMEM_UNALIGNED_CHUNK_FLAG : 0,
    };
    ret = xsk_umem__create(&xsk->umem, xsk->umem_area, UMEM_SIZE,
                           &xsk->fq, &xsk->cq, &ucfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create: %s\n", strerror(-ret));
        munmap(xsk->umem_area, UMEM_SIZE);
        return -1;
    }

    /* --- Bind XSK to iface/queue ---
     * Default requests NEED_WAKEUP|XDP_ZEROCOPY. If the driver rejects it,
     * retry plain XDP_ZEROCOPY and then fall back to XDP_COPY. */
    struct xsk_socket_config scfg = {
        .rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        /* The project owns the redirect program/map and their teardown.
         * Avoid libxdp's packaged xsk_def_xdp_prog.o dependency. */
        .libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags    = g_zerocopy ? XDP_FLAGS_DRV_MODE :
                                         XDP_FLAGS_SKB_MODE,
        .bind_flags   = XDP_COPY,
    };
    if (g_zerocopy) {
        /* mlx5 AF_XDP ZC TX requires NEED_WAKEUP: the driver only services the TX ring
         * after a sendto() wakeup when it has set the need-wakeup flag. Binding plain
         * XDP_ZEROCOPY succeeds but never actually transmits (completions return, but
         * tx_packets stays 0). So request NEED_WAKEUP|ZEROCOPY first, fall back to plain
         * ZEROCOPY only if that bind is rejected. */
        scfg.bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY;
        g_need_wakeup = 1;
    }

    ret = xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem,
                             &xsk->rx, &xsk->tx, &scfg);
    if (ret && g_zerocopy) {
        fprintf(stderr, "xsk_socket__create(%s) NEED_WAKEUP|ZEROCOPY failed: %s — retrying plain XDP_ZEROCOPY\n",
                ifname, strerror(-ret));
        scfg.bind_flags = XDP_ZEROCOPY;
        g_need_wakeup = 0;
        ret = xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem,
                                 &xsk->rx, &xsk->tx, &scfg);
    }
    if (ret && g_zerocopy) {
        /* NIC/queue can't do AF_XDP zero-copy (veth, 1GbE igb/atlantic) — fall back to copy. */
        fprintf(stderr, "xsk_socket__create(%s): zero-copy unavailable (%s) — falling back to XDP_COPY\n",
                ifname, strerror(-ret));
        g_zerocopy = 0; g_need_wakeup = 0;
        scfg.bind_flags = XDP_COPY;
        scfg.xdp_flags = XDP_FLAGS_SKB_MODE;
        ret = xsk_socket__create(&xsk->xsk, ifname, queue_id, xsk->umem,
                                 &xsk->rx, &xsk->tx, &scfg);
    }
    if (ret) {
        fprintf(stderr, "xsk_socket__create(%s): %s%s\n", ifname, strerror(-ret),
                g_zerocopy ? " (XDP_ZEROCOPY not available on this iface/queue — see diagnosis below)" : "");
        xsk_umem__delete(xsk->umem);
        munmap(xsk->umem_area, UMEM_SIZE);
        return -1;
    }
    if (g_zerocopy)
        printf("AF_XDP bound in XDP_ZEROCOPY mode%s\n", g_need_wakeup ? " (need-wakeup)" : "");

    xsk->xsk_fd = xsk_socket__fd(xsk->xsk);

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        ret = errno ? -errno : -ENODEV;
        goto redirect_fail;
    }
    ret = xdev_ext_xsk_redirect_attach(&xsk->redirect, flow_filter, (int)ifindex,
                                  (uint32_t)queue_id, xsk->xsk_fd,
                                  scfg.xdp_flags);
    if (ret) {
        fprintf(stderr, "XSK redirect attach failed: %s\n", strerror(-ret));
        goto redirect_fail;
    }

    /* All frames start FREE on the SM's lock-free stack. */
    if (xdev_ext_pool_init(&xsk->pool, xsk->pool_frames, NUM_FRAMES, true) != 0) {
        /* The caller performs ordered redirect -> socket -> UMEM teardown. */
        return -ENOMEM;
    }

    return 0;

redirect_fail:
    /* If attach rollback proved the program/map inactive, local teardown is
     * safe.  Otherwise retain the socket and UMEM so main can retry an exact
     * owner detach before releasing backing. */
    if (!xdev_ext_xsk_redirect_is_active(&xsk->redirect)) {
        xsk_socket__delete(xsk->xsk);
        xsk->xsk = NULL;
        xsk_umem__delete(xsk->umem);
        xsk->umem = NULL;
        munmap(xsk->umem_area, UMEM_SIZE);
        xsk->umem_area = MAP_FAILED;
    }
    return ret;
}

static void fill_nvme_read_sqe(struct pipeline_ctx *ctx,
                               struct io_uring_sqe *sqe, void *buf,
                               const struct nxp_nvme_read *read,
                               uint64_t user_data, uint16_t buf_index)
{
    struct nvme_uring_cmd *cmd;

    memset(sqe, 0, 128);  /* SQE128 */
    sqe->opcode = IORING_OP_URING_CMD;
    if (ctx->uring.fixed_file_registered) {
        sqe->fd = 0;
        sqe->flags |= IOSQE_FIXED_FILE;
    } else {
        sqe->fd = ctx->nvme_fd;
    }
    sqe->cmd_op = NVME_URING_CMD_IO;
    sqe->user_data = user_data;
    if (ctx->uring.fixed_buffer_registered) {
        sqe->uring_cmd_flags |= IORING_URING_CMD_FIXED;
        sqe->buf_index = buf_index;
    }

    /* NVMe Read command embedded in the SQE cmd field */
    cmd = (struct nvme_uring_cmd *)sqe->cmd;
    cmd->opcode = NVME_CMD_READ;
    cmd->nsid = ctx->nsid;
    cmd->addr = (uint64_t)(uintptr_t)buf;
    cmd->data_len = read->data_len;
    cmd->cdw10 = read->cdw10;
    cmd->cdw11 = read->cdw11;
    cmd->cdw12 = read->cdw12;
    cmd->rsvd2 = NVME_URING_CMD_F_XDEV_EXT;
}

/* Encode one scatter/gather command.  XDEV_EXT intentionally accepts IO_VEC only
 * against an io_uring registered buffer: the iovec array is imported once and
 * every range is checked against buf_index before the NVMe request is built. */
static int fill_nvme_vector_sqe(struct pipeline_ctx *ctx,
                                struct io_uring_sqe *sqe,
                                const struct iovec *vector,
                                uint32_t vector_count,
                                const struct nxp_nvme_io_plan *plan,
                                uint64_t user_data, uint16_t buf_index)
{
    struct nvme_uring_cmd *cmd;

    if (!ctx || !sqe || !vector || !vector_count || !plan ||
        (plan->direction != NXP_IO_READ &&
         plan->direction != NXP_IO_WRITE) ||
        plan->opcode != (plan->direction == NXP_IO_READ ?
                         NXP_NVME_OP_READ : NXP_NVME_OP_WRITE))
        return -EINVAL;
    if (!ctx->uring.fixed_buffer_registered)
        return -EOPNOTSUPP;

    memset(sqe, 0, 128);
    sqe->opcode = IORING_OP_URING_CMD;
    if (ctx->uring.fixed_file_registered) {
        sqe->fd = 0;
        sqe->flags |= IOSQE_FIXED_FILE;
    } else {
        sqe->fd = ctx->nvme_fd;
    }
    sqe->cmd_op = NVME_URING_CMD_IO_VEC;
    sqe->user_data = user_data;
    sqe->uring_cmd_flags = IORING_URING_CMD_FIXED;
    sqe->buf_index = buf_index;

    cmd = (struct nvme_uring_cmd *)sqe->cmd;
    cmd->opcode = plan->opcode;
    cmd->nsid = ctx->nsid;
    cmd->addr = (uint64_t)(uintptr_t)vector;
    /* IO_VEC overloads data_len with the iovec count.  Kernel policy derives
     * the byte length from the imported immutable fixed-vector snapshot. */
    cmd->data_len = vector_count;
    cmd->cdw10 = plan->cdw10;
    cmd->cdw11 = plan->cdw11;
    cmd->cdw12 = plan->cdw12;
    cmd->rsvd2 = NVME_URING_CMD_F_XDEV_EXT;
    return 0;
}

/* liburing before 2.2 indexed these arrays at their base UAPI sizes even when
 * SQE128/CQE32 was requested.  The initialization gate rejects those DSOs;
 * these small accessors also make the required doubled stride explicit. */
static int pipeline_get_sqe(struct pipeline_ctx *ctx,
                            struct io_uring_sqe **sqe_out)
{
    struct io_uring_sq *sq;
    unsigned int head, tail, entries, mask, shift;
    size_t offset;
    int ret;

    if (!ctx || !sqe_out)
        return -EINVAL;
    *sqe_out = NULL;
    if (!(ctx->uring.ring.flags & IORING_SETUP_SQE128))
        return -EOPNOTSUPP;
    sq = &ctx->uring.ring.sq;
    if (!sq->khead || !sq->kring_entries || !sq->kring_mask || !sq->sqes)
        return -ENXIO;
    head = __atomic_load_n(sq->khead, __ATOMIC_ACQUIRE);
    tail = sq->sqe_tail;
    entries = *sq->kring_entries;
    mask = *sq->kring_mask;
    if (!entries || tail - head >= entries)
        return -EBUSY;
    shift = !!(ctx->uring.ring.flags & IORING_SETUP_SQE128);
    ret = nxp_ring_entry_offset(tail, mask, sizeof(struct io_uring_sqe),
                                shift, &offset);
    if (ret)
        return ret;
    *sqe_out = (struct io_uring_sqe *)((unsigned char *)sq->sqes + offset);
    sq->sqe_tail = tail + 1;
    return 0;
}

static int pipeline_peek_cqe_raw(struct pipeline_ctx *ctx,
                                 struct io_uring_cqe **cqe_out)
{
    struct io_uring_cq *cq;
    unsigned int head, tail, mask, shift;
    size_t offset;
    int ret;

    if (!ctx || !cqe_out)
        return -EINVAL;
    *cqe_out = NULL;
    if (!(ctx->uring.ring.flags & IORING_SETUP_CQE32))
        return -EOPNOTSUPP;
    cq = &ctx->uring.ring.cq;
    if (!cq->khead || !cq->ktail || !cq->kring_mask || !cq->cqes)
        return -ENXIO;
    head = __atomic_load_n(cq->khead, __ATOMIC_ACQUIRE);
    tail = __atomic_load_n(cq->ktail, __ATOMIC_ACQUIRE);
    if (head == tail)
        return -EAGAIN;
    mask = *cq->kring_mask;
    shift = !!(ctx->uring.ring.flags & IORING_SETUP_CQE32);
    ret = nxp_ring_entry_offset(head, mask, sizeof(struct io_uring_cqe),
                                shift, &offset);
    if (ret)
        return ret;
    *cqe_out = (struct io_uring_cqe *)((unsigned char *)cq->cqes + offset);
    return 0;
}

/* Prep an NVMe read SQE (IORING_OP_URING_CMD) WITHOUT submitting. Returns 0 on
 * success, -EBUSY if the SQ is full. Used by both the serial and batched paths so
 * batching can fill many SQEs and submit them with one io_uring_submit(). */
static int prep_nvme_read_cmd(struct pipeline_ctx *ctx, void *buf,
                              const struct nxp_nvme_read *read,
                              uint64_t user_data, uint16_t buf_index)
{
    struct io_uring_sqe *sqe;
    int ret = pipeline_get_sqe(ctx, &sqe);

    if (ret)
        return ret;
    fill_nvme_read_sqe(ctx, sqe, buf, read, user_data, buf_index);

    return 0;
}

/* Submit NVMe read using IORING_OP_URING_CMD (liburing) — serial path: prep + submit. */
/* Compute checksum */
static uint16_t compute_checksum(void *data, int len)
{
    uint32_t sum = 0;
    uint16_t *ptr = data;

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint8_t *)ptr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;
}

/* Optional userspace computation.  Passthrough defaults to byte-preserving;
 * the reversible XOR arm is enabled only by an explicit CLI request. */
static void process_data(void *data, size_t len)
{
    uint64_t *p = data;
    size_t count = len / sizeof(uint64_t);

    if (g_transform == PIPELINE_TRANSFORM_NONE)
        return;
    for (size_t i = 0; i < count; i++)
        p[i] = p[i] ^ 0xDEADBEEFCAFEBABEULL;
}

/* Build UDP packet headers in UMEM frame.
 * When payload is already at frame + PKT_HEADER_ROOM (zero-copy NVMe path),
 * pass payload=NULL to skip the memcpy.
 * When payload is in a separate buffer, pass non-NULL to copy it. */
static size_t build_packet(struct pipeline_ctx *ctx, void *frame,
                           void *payload, size_t payload_len)
{
    struct ethhdr *eth = (void *)((char *)frame + PKT_START_OFF);
    struct iphdr *ip = (void *)eth + sizeof(*eth);
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    void *data = (void *)udp + sizeof(*udp);
    size_t total_len;

    /* Ethernet header */
    memcpy(eth->h_dest, ctx->dst_mac, 6);
    memcpy(eth->h_source, ctx->src_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    /* IP header */
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(*ip) + sizeof(*udp) + payload_len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = ctx->src_ip;
    ip->daddr = ctx->dst_ip;
    ip->check = compute_checksum(ip, sizeof(*ip));

    /* UDP header */
    udp->source = htons(ctx->src_port);
    udp->dest = htons(ctx->dst_port);
    udp->len = htons(sizeof(*udp) + payload_len);
    udp->check = 0;

    /* Copy payload only if provided (non-zero-copy fallback) */
    if (payload)
        memcpy(data, payload, payload_len);

    total_len = sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + payload_len;
    return total_len;
}

struct pipeline_rx_packet {
    struct nxp_wire_segment segment;
    unsigned char *data;
    uint32_t data_len;
};

/* Build one ordinary-MTU UDP packet.  NVMe vector DMA targets start at
 * NXP_DATA_OFFSET; the fixed 40-byte wire header sits immediately before the
 * data and contains no namespace or SLBA supplied by the peer. */
static int build_wire_packet(struct pipeline_ctx *ctx, void *frame,
                             const void *payload,
                             const struct nxp_wire_segment *segment,
                             uint32_t *packet_len_out)
{
    struct nxp_wire_span span;
    uint32_t packet_len;
    int ret;

    if (!ctx || !frame || !segment || !packet_len_out ||
        segment->payload_len > NXP_SINGLE_FRAME_DATA_MAX)
        return -EINVAL;
    if (payload)
        memcpy((unsigned char *)frame + NXP_DATA_OFFSET, payload,
               segment->payload_len);
    span.data = (unsigned char *)frame + NXP_DATA_OFFSET;
    span.len = segment->payload_len;
    ret = nxp_wire_header_encode((unsigned char *)frame + NXP_WIRE_OFFSET,
                                 NXP_WIRE_HEADER_LEN, segment, &span, 1);
    if (ret)
        return ret;
    packet_len = (uint32_t)build_packet(ctx, frame, NULL,
                                       NXP_WIRE_HEADER_LEN +
                                       segment->payload_len);
    if (packet_len > FRAME_SIZE - PKT_START_OFF ||
        (ctx->mtu && packet_len - sizeof(struct ethhdr) > ctx->mtu))
        return -EMSGSIZE;
    *packet_len_out = packet_len;
    return 0;
}

/* Parse the exact Ethernet/IPv4/UDP tuple configured for this pipeline, then
 * use CRC32C to detect damaged or misdelivered NXP header/payload bytes.  CRC
 * is not authentication.  Callers still choose the storage position from
 * their local monotonically increasing group index. */
static int parse_wire_packet(struct pipeline_ctx *ctx, void *packet,
                             uint32_t packet_len,
                             struct pipeline_rx_packet *out)
{
    const unsigned char *bytes = packet;
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    unsigned char *wire;
    struct nxp_wire_span span;
    uint32_t ip_len, udp_len;
    int ret;

    if (!ctx || !packet || !out ||
        packet_len < PKT_HDR_SIZE + NXP_WIRE_HEADER_LEN)
        return -EMSGSIZE;
    memcpy(&eth, bytes, sizeof(eth));
    if (memcmp(eth.h_dest, ctx->dst_mac, ETH_ALEN) ||
        memcmp(eth.h_source, ctx->src_mac, ETH_ALEN))
        return -EACCES;
    if (ntohs(eth.h_proto) != ETH_P_IP)
        return -EPROTO;
    memcpy(&ip, bytes + sizeof(eth), sizeof(ip));
    if (ip.version != 4 || ip.ihl != 5 ||
        ip.protocol != IPPROTO_UDP ||
        ip.saddr != ctx->src_ip || ip.daddr != ctx->dst_ip ||
        (ntohs(ip.frag_off) & (UINT16_C(0x2000) | UINT16_C(0x1fff))))
        return -EACCES;
    ip_len = ntohs(ip.tot_len);
    if (ip_len != packet_len - sizeof(eth) ||
        (ctx->mtu && ip_len > ctx->mtu) ||
        ip_len < sizeof(ip) + sizeof(udp) + NXP_WIRE_HEADER_LEN ||
        compute_checksum(&ip, sizeof(ip)) != 0)
        return -EPROTO;
    memcpy(&udp, bytes + sizeof(eth) + sizeof(ip), sizeof(udp));
    udp_len = ntohs(udp.len);
    if (udp.source != htons(ctx->src_port) ||
        udp.dest != htons(ctx->dst_port))
        return -EACCES;
    if (udp_len != ip_len - sizeof(ip) ||
        udp_len < sizeof(udp) + NXP_WIRE_HEADER_LEN)
        return -EPROTO;
    wire = (unsigned char *)bytes + sizeof(eth) + sizeof(ip) + sizeof(udp);
    span.data = wire + NXP_WIRE_HEADER_LEN;
    span.len = udp_len - sizeof(udp) - NXP_WIRE_HEADER_LEN;
    ret = nxp_wire_header_parse(wire, NXP_WIRE_HEADER_LEN, &span, 1,
                                &out->segment);
    if (ret)
        return ret;
    out->data = (unsigned char *)span.data;
    out->data_len = span.len;
    return 0;
}

/* Decode both aligned/COPY and unaligned/ZC descriptor address forms.  RX
 * packets are admitted only at the offset established by init_xsk()'s UMEM
 * headroom; consequently the payload address used by IO_VEC is aligned without
 * a staging copy. */
static int pipeline_decode_rx_descriptor(const struct xdp_desc *descriptor,
                                         uint64_t *frame_base,
                                         uint64_t *data_addr)
{
    uint64_t data, base, offset;

    if (!descriptor || !frame_base || !data_addr)
        return -EINVAL;
    if (descriptor->options)
        return -EOPNOTSUPP;
    data = xsk_umem__add_offset_to_addr(descriptor->addr);
    if (data >= UMEM_SIZE)
        return -ERANGE;
    base = data & ~((uint64_t)FRAME_SIZE - 1);
    offset = data - base;
    if (offset != NXP_RX_PACKET_OFFSET)
        return -EINVAL;
    if (descriptor->len > FRAME_SIZE - offset)
        return -EMSGSIZE;
    if ((data + PKT_HDR_SIZE + NXP_WIRE_HEADER_LEN) &
        (NXP_VECTOR_ALIGNMENT - 1))
        return -EINVAL;
    *frame_base = base;
    *data_addr = data;
    return 0;
}

static int pipeline_validate_rx_packet(struct pipeline_ctx *ctx,
                                       const struct pipeline_rx_packet *packet)
{
    struct nxp_wire_layout layout;
    struct nxp_wire_segment expected;
    int ret;

    if (!ctx || !packet || !packet->data || packet->data_len !=
        packet->segment.payload_len)
        return -EINVAL;
    if (packet->segment.direction == NXP_IO_READ)
        return -EACCES;
    if (packet->segment.direction != NXP_IO_WRITE)
        return -EPROTO;
    if (packet->segment.total_len != g_block_size)
        return -EPROTO;
    if ((uintptr_t)packet->data & (NXP_VECTOR_ALIGNMENT - 1))
        return -EINVAL;
    if (packet->segment.session_id != ctx->session_id)
        return -ESTALE;
    ret = nxp_wire_mtu_layout_plan(ctx->session_id,
                                   packet->segment.generation, g_block_size,
                                   ctx->mtu, FRAME_SIZE,
                                   NXP_LAYOUT_DATA_OFFSET,
                                   NXP_VECTOR_ALIGNMENT, &layout);
    if (ret)
        return ret;
    ret = nxp_wire_segment_at(&layout, NXP_IO_WRITE,
                              packet->segment.segment_index, &expected);
    if (ret ||
        packet->segment.segment_count != expected.segment_count ||
        packet->segment.relative_offset != expected.relative_offset ||
        packet->segment.payload_len != expected.payload_len)
        return -EPROTO;
    return 0;
}

/* Kick TX. With XDP_USE_NEED_WAKEUP, only syscall when the driver asks for it
 * (xsk_ring_prod__needs_wakeup) — otherwise the busy NIC keeps draining TX itself
 * and the syscall is pure overhead. Without need-wakeup, always kick. */
static int xsk_tx_kick(struct xsk_ctx *xsk)
{
    int ret;

    if (g_need_wakeup && !xsk_ring_prod__needs_wakeup(&xsk->tx))
        return 0;
    ret = sendto(xsk->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
    return ret < 0 ? -errno : ret;
}

/* Complete TX and reclaim frames (libxdp completion ring).
 *
 * The CQ UAPI reports only a UMEM address, not a descriptor generation.  The
 * normal fast path therefore depends on the kernel/driver exact-once
 * completion contract.  A delayed duplicate that happens to match a later
 * reuse of the same address is intrinsically indistinguishable here.  Any
 * anomaly we can observe invalidates the socket immediately; later CQ entries are
 * consumed without reclaiming frames, and cleanup retains the XSK/UMEM until
 * process teardown. */
static void xsk_tx_complete(struct pipeline_ctx *ctx)
{
    struct xsk_ctx *xsk = &ctx->xsk;
    uint32_t idx;
    uint32_t n = xsk_ring_cons__peek(&xsk->cq, NUM_FRAMES, &idx);

    for (uint32_t i = 0; i < n; i++) {
        uint64_t a = *xsk_ring_cons__comp_addr(&xsk->cq, idx + i);
        uint64_t offset = xsk_umem__add_offset_to_addr(a);
        uint64_t base;

        if (xsk->protocol_invalidated)
            continue;
        if (offset < PKT_START_OFF || offset >= UMEM_SIZE) {
            fprintf(stderr, "AF_XDP protocol error: invalid completion address %#lx\n",
                    (unsigned long)offset);
            nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
            nxp_latch_error(&ctx->first_error, -EPROTO);
            xsk->protocol_invalidated = true;
            continue;
        }
        /* completion carries the packet-start addr; round down to frame base */
        base = offset & ~((uint64_t)FRAME_SIZE - 1);
        if ((offset - base) != PKT_START_OFF ||
            xdev_ext_frame_state(&xsk->pool, base / FRAME_SIZE) !=
                XDEV_EXT_FRAME_TX_PENDING) {
            fprintf(stderr, "AF_XDP protocol error: duplicate/stray completion %#lx\n",
                    (unsigned long)offset);
            nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
            nxp_latch_error(&ctx->first_error, -EPROTO);
            xsk->protocol_invalidated = true;
            continue;
        }
        if (pipeline_chain_tx_complete(ctx, base) != 0) {
            fprintf(stderr,
                    "composite-chain journal rejected TX completion %#lx\n",
                    (unsigned long)offset);
            nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
            nxp_latch_error(&ctx->first_error, -EPROTO);
            xsk->protocol_invalidated = true;
            ctx->backing_quiescence_failed = true;
            ctx->chain_sequestered = true;
            continue;
        }
        xsk_retire_umem_frame(xsk, base);
        nxp_stats_note(&ctx->stats, NXP_STAT_TX_RECLAIMED);
    }

    if (n)
        xsk_ring_cons__release(&xsk->cq, n);
}

/* Set scheduler hints for the pipeline */
static int setup_sched_hints(uint64_t read_freq_ns, uint64_t send_freq_ns, int batch_size)
{
    struct io_uring_sched_hints hints;
    int ret;

    memset(&hints, 0, sizeof(hints));
    hints.read_freq_ns = read_freq_ns;
    hints.send_freq_ns = send_freq_ns;
    hints.batch_size = batch_size;
    hints.flags = IO_URING_SCHED_HINT_NVME_XDP | IO_URING_SCHED_HINT_LATENCY;

    ret = io_uring_sched_hints_set(&hints);
    if (ret < 0) {
        fprintf(stderr, "Warning: Failed to set scheduler hints: %s\n", strerror(errno));
        return ret;
    }

    printf("Set scheduler hints: read_freq=%llu ns, send_freq=%llu ns, batch=%d\n",
           (unsigned long long)hints.read_freq_ns,
           (unsigned long long)hints.send_freq_ns, hints.batch_size);
    return 0;
}

static int path_join(char *dst, size_t size, const char *base,
                     const char *name)
{
    int n = snprintf(dst, size, "%s/%s", base, name);

    return n < 0 || (size_t)n >= size ? -ENAMETOOLONG : 0;
}

static int read_text_file(const char *path, char *buf, size_t size)
{
    FILE *f;
    size_t len;

    if (!size)
        return -EINVAL;
    f = fopen(path, "re");
    if (!f)
        return -errno;
    if (!fgets(buf, size, f)) {
        int ret = ferror(f) ? (errno ? -errno : -EIO) : -ENODATA;

        fclose(f);
        return ret;
    }
    fclose(f);
    len = strlen(buf);
    while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                   buf[len - 1] == ' ' || buf[len - 1] == '\t'))
        buf[--len] = '\0';
    return len ? 0 : -ENODATA;
}

static int read_u64_file(const char *path, uint64_t *value)
{
    char buf[64] = { 0 };
    int ret;

    ret = read_text_file(path, buf, sizeof(buf));
    if (ret)
        return ret;
    return nxp_parse_u64(buf, value);
}

static uint16_t load_le16(const unsigned char *p)
{
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static uint64_t load_le64(const unsigned char *p)
{
    uint64_t v = 0;

    for (unsigned int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (i * 8);
    return v;
}

static int decode_identify_namespace(const unsigned char *id, size_t id_len,
                                     uint32_t *lba_size,
                                     uint64_t *capacity_lbas,
                                     uint16_t *metadata_size,
                                     uint8_t *pi_type)
{
    unsigned int lbaf;

    if (!id || id_len < 4096 || !lba_size || !capacity_lbas ||
        !metadata_size || !pi_type)
        return -EINVAL;
    lbaf = (id[26] & 0x0f) | ((id[26] & 0x60) >> 1);
    if (lbaf >= 64 || id[128 + lbaf * 4 + 2] >= 32)
        return -EOPNOTSUPP;
    *capacity_lbas = load_le64(id);
    *metadata_size = load_le16(id + 128 + lbaf * 4);
    *lba_size = UINT32_C(1) << id[128 + lbaf * 4 + 2];
    *pi_type = id[29] & 0x7;
    return 0;
}

static int identify_namespace(int fd, uint32_t nsid,
                              uint32_t *lba_size, uint64_t *capacity_lbas,
                              uint16_t *metadata_size, uint8_t *pi_type)
{
    struct nvme_admin_cmd cmd;
    unsigned char *id = NULL;
    int ret;

    if (posix_memalign((void **)&id, 4096, 4096))
        return -ENOMEM;
    memset(id, 0, 4096);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0x06; /* Identify */
    cmd.nsid = nsid;
    cmd.addr = (uint64_t)(uintptr_t)id;
    cmd.data_len = 4096;
    cmd.cdw10 = 0; /* CNS: Identify Namespace */
    ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (ret) {
        ret = ret < 0 ? -errno : -EIO;
        free(id);
        return ret;
    }

    ret = decode_identify_namespace(id, 4096, lba_size, capacity_lbas,
                                    metadata_size, pi_type);
    free(id);
    return ret;
}

static uint64_t encoded_rdev(dev_t dev)
{
    return (uint64_t)major(dev) << 32 | minor(dev);
}

static int find_block_namespace_sibling_at(const char *controller_sysfs,
                                           const char *char_sysfs,
                                           uint64_t char_nsid,
                                           const char *sys_dev_block_root,
                                           const char *dev_root,
                                           char *block_device,
                                           size_t block_device_size)
{
    DIR *dir;
    struct dirent *entry;
    unsigned int matches = 0;
    int scan_error = 0;

    if (!controller_sysfs || !char_sysfs || !char_nsid ||
        !sys_dev_block_root || !dev_root || !block_device ||
        !block_device_size)
        return -EINVAL;
    dir = opendir(controller_sysfs);
    if (!dir)
        return -errno;
    for (;;) {
        char candidate_sysfs[PATH_MAX];
        char nsid_path[PATH_MAX];
        char dev_path[PATH_MAX];
        char dev_text[64] = { 0 };
        uint64_t candidate_nsid;

        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno && !scan_error)
                scan_error = -errno;
            break;
        }
        if (entry->d_name[0] == '.' ||
            path_join(candidate_sysfs, sizeof(candidate_sysfs),
                      controller_sysfs, entry->d_name) ||
            strcmp(candidate_sysfs, char_sysfs) == 0 ||
            path_join(nsid_path, sizeof(nsid_path), candidate_sysfs,
                      "nsid") ||
            read_u64_file(nsid_path, &candidate_nsid) ||
            candidate_nsid != char_nsid ||
            path_join(dev_path, sizeof(dev_path), candidate_sysfs, "dev") ||
            read_text_file(dev_path, dev_text, sizeof(dev_text)))
            continue;
        /* Require the block-device reverse link to resolve to this exact
         * sibling.  This excludes the generic character node and aliases. */
        {
            unsigned int dev_major, dev_minor;
            char reverse[PATH_MAX];
            char resolved[PATH_MAX];
            char trailing;

            if (sscanf(dev_text, "%u:%u%c", &dev_major, &dev_minor,
                       &trailing) != 2 ||
                snprintf(reverse, sizeof(reverse), "%s/%u:%u",
                         sys_dev_block_root, dev_major, dev_minor) >=
                    (int)sizeof(reverse) ||
                !realpath(reverse, resolved) ||
                strcmp(resolved, candidate_sysfs) != 0)
                continue;
        }
        matches++;
        if (matches == 1 &&
            snprintf(block_device, block_device_size, "%s/%s", dev_root,
                     entry->d_name) >= (int)block_device_size)
            scan_error = -ENAMETOOLONG;
    }
    if (closedir(dir) && !scan_error)
        scan_error = -errno;
    if (scan_error)
        return scan_error;
    if (!matches)
        return -ENODEV;
    return matches == 1 ? 0 : -ENOTUNIQ;
}

static int resolve_device_paths(struct pipeline_ctx *ctx)
{
    struct stat st;
    char link[PATH_MAX];
    uint64_t char_nsid;
    char *slash;
    int ioctl_nsid;

    if (fstat(ctx->nvme_fd, &st))
        return -errno;
    if (!S_ISCHR(st.st_mode))
        return -ENOTTY;
    snprintf(link, sizeof(link), "/sys/dev/char/%u:%u",
             major(st.st_rdev), minor(st.st_rdev));
    if (!realpath(link, ctx->char_sysfs))
        return -errno;

    if (snprintf(ctx->controller_sysfs, sizeof(ctx->controller_sysfs),
                 "%s", ctx->char_sysfs) >=
        (int)sizeof(ctx->controller_sysfs))
        return -ENAMETOOLONG;
    slash = strrchr(ctx->controller_sysfs, '/');
    if (!slash || slash == ctx->controller_sysfs)
        return -EXDEV;
    *slash = '\0';

    ioctl_nsid = ioctl(ctx->nvme_fd, NVME_IOCTL_ID);
    if (ioctl_nsid <= 0)
        return ioctl_nsid < 0 ? -errno : -ENODEV;
    char_nsid = (uint32_t)ioctl_nsid;

    if (!ctx->block_device) {
        int ret = find_block_namespace_sibling_at(
            ctx->controller_sysfs, ctx->char_sysfs, char_nsid,
            "/sys/dev/block", "/dev", ctx->derived_block_device,
            sizeof(ctx->derived_block_device));

        if (ret)
            return ret;
        ctx->block_device = ctx->derived_block_device;
    }
    ctx->block_fd = open(ctx->block_device, O_RDONLY | O_CLOEXEC);
    if (ctx->block_fd < 0)
        return -errno;
    if (fstat(ctx->block_fd, &st))
        return -errno;
    if (!S_ISBLK(st.st_mode))
        return -ENOTBLK;
    snprintf(link, sizeof(link), "/sys/dev/block/%u:%u",
             major(st.st_rdev), minor(st.st_rdev));
    if (!realpath(link, ctx->block_sysfs))
        return -errno;

    /* ngXnY and nvmeXnY are controller siblings in the standard Linux NVMe
     * topology.  An explicit partition, another controller, or a multipath
     * namespace without one controller/BDF therefore fails closed here. */
    if (!nxp_paths_share_parent(ctx->char_sysfs, ctx->block_sysfs) ||
        strncmp(ctx->block_sysfs, ctx->controller_sysfs,
                strlen(ctx->controller_sysfs)) != 0)
        return -EXDEV;
    return 0;
}

static int collect_namespace_snapshot(struct pipeline_ctx *ctx,
                                      struct nxp_namespace *ns)
{
    struct stat char_st, block_st;
    uint64_t capacity_bytes, diskseq, sysfs_nsid, csi;
    uint32_t block_lbs;
    char path[PATH_MAX];
    char stable_id[NXP_STABLE_ID_MAX + 2] = { 0 };
    char controller_serial[NXP_CONTROLLER_SERIAL_MAX + 2] = { 0 };
    char pci_bdf[NXP_PCI_BDF_MAX + 2] = { 0 };
    char transport[32] = { 0 };
    char pci_link[PATH_MAX];
    char pci_sysfs[PATH_MAX];
    int ioctl_nsid;
    int ret;

    memset(ns, 0, sizeof(*ns));
    if (fstat(ctx->nvme_fd, &char_st) || fstat(ctx->block_fd, &block_st))
        return -errno;
    ns->char_is_namespace = S_ISCHR(char_st.st_mode);
    ns->block_is_whole_namespace = S_ISBLK(block_st.st_mode);
    ns->same_namespace = ns->char_is_namespace &&
                         ns->block_is_whole_namespace;
    ns->char_rdev = encoded_rdev(char_st.st_rdev);
    ns->block_rdev = encoded_rdev(block_st.st_rdev);

    ioctl_nsid = ioctl(ctx->nvme_fd, NVME_IOCTL_ID);
    if (ioctl_nsid <= 0)
        return ioctl_nsid < 0 ? -errno : -ENODEV;
    ns->nsid = (uint32_t)ioctl_nsid;

    if (ioctl(ctx->block_fd, BLKSSZGET, &block_lbs) < 0)
        return -errno;
    if (!block_lbs)
        return -EUCLEAN;
    if (ioctl(ctx->block_fd, BLKGETSIZE64, &capacity_bytes) < 0)
        return -errno;
    if (capacity_bytes % block_lbs)
        return -EUCLEAN;
    ns->lba_size = block_lbs;
    ns->capacity_lbas = capacity_bytes / block_lbs;
    if (ioctl(ctx->block_fd, BLKGETDISKSEQ, &diskseq) < 0)
        return -errno;
    if (!diskseq)
        return -ENODATA;
    ns->diskseq = diskseq;

    ret = path_join(path, sizeof(path), ctx->block_sysfs, "nsid");
    if (ret || (ret = read_u64_file(path, &sysfs_nsid)) != 0)
        return ret;
    if (sysfs_nsid != ns->nsid)
        return -EXDEV;
    ret = path_join(path, sizeof(path), ctx->block_sysfs, "csi");
    if (ret || (ret = read_u64_file(path, &csi)) != 0)
        return ret;
    if (csi != 0) /* This encoder emits NVM command-set READ. */
        return -EOPNOTSUPP;
    ret = path_join(path, sizeof(path), ctx->block_sysfs, "wwid");
    if (ret || (ret = read_text_file(path, stable_id,
                                     sizeof(stable_id))) != 0)
        return ret;
    ns->stable_id_len = (uint8_t)strlen(stable_id);
    if (!ns->stable_id_len || ns->stable_id_len > NXP_STABLE_ID_MAX)
        return -ENODATA;
    memcpy(ns->stable_id, stable_id, ns->stable_id_len);
    ns->stable_id_present = true;

    ret = path_join(path, sizeof(path), ctx->controller_sysfs, "serial");
    if (ret || (ret = read_text_file(path, controller_serial,
                                     sizeof(controller_serial))) != 0)
        return ret;
    ns->controller_serial_len = (uint8_t)strlen(controller_serial);
    if (!ns->controller_serial_len ||
        ns->controller_serial_len > NXP_CONTROLLER_SERIAL_MAX)
        return -ENODATA;
    memcpy(ns->controller_serial, controller_serial,
           ns->controller_serial_len);
    ns->controller_serial_present = true;

    ret = path_join(path, sizeof(path), ctx->controller_sysfs, "transport");
    if (ret || (ret = read_text_file(path, transport, sizeof(transport))) != 0)
        return ret;
    if (strcmp(transport, "pcie") != 0)
        return -EOPNOTSUPP;

    ret = path_join(path, sizeof(path), ctx->controller_sysfs, "address");
    if (ret || (ret = read_text_file(path, pci_bdf, sizeof(pci_bdf))) != 0)
        return ret;
    ns->pci_bdf_len = (uint8_t)strlen(pci_bdf);
    if (!nxp_is_pci_bdf(pci_bdf) ||
        ns->pci_bdf_len > NXP_PCI_BDF_MAX)
        return -ENODATA;
    if (snprintf(pci_link, sizeof(pci_link), "/sys/bus/pci/devices/%s",
                 pci_bdf) >= (int)sizeof(pci_link) ||
        !realpath(pci_link, pci_sysfs))
        return -ENODEV;
    if (strncmp(ctx->controller_sysfs, pci_sysfs, strlen(pci_sysfs)) != 0 ||
        ctx->controller_sysfs[strlen(pci_sysfs)] != '/')
        return -EXDEV;
    memcpy(ns->pci_bdf, pci_bdf, ns->pci_bdf_len);
    ns->pci_bdf_present = true;

    {
        uint32_t identify_lbs = 0;
        uint64_t identify_capacity = 0;

        ret = identify_namespace(ctx->nvme_fd, ns->nsid, &identify_lbs,
                                 &identify_capacity, &ns->metadata_size,
                                 &ns->pi_type);
        if (ret)
            return ret;
        if (identify_lbs != ns->lba_size ||
            identify_capacity != ns->capacity_lbas)
            return -EUCLEAN;
    }
    return nxp_namespace_validate(ns);
}

static int prove_iopoll(const struct pipeline_ctx *ctx)
{
    char path[PATH_MAX];
    uint64_t controller_poll_queues, namespace_io_poll;
    int ret;

    ret = read_u64_file("/sys/module/nvme/parameters/poll_queues",
                        &controller_poll_queues);
    if (ret)
        return -EOPNOTSUPP;
    ret = path_join(path, sizeof(path), ctx->block_sysfs, "queue/io_poll");
    if (ret || read_u64_file(path, &namespace_io_poll) ||
        !nxp_iopoll_proven(controller_poll_queues, namespace_io_poll))
        return -EOPNOTSUPP;
    return 0;
}

static int collect_namespace_epoch(struct pipeline_ctx *ctx,
				   struct nxp_namespace_epoch *epoch)
{
    struct stat char_st, block_st;
    uint64_t diskseq;
    int ioctl_nsid;

    memset(epoch, 0, sizeof(*epoch));
    if (fstat(ctx->nvme_fd, &char_st))
        return -errno;
    if (fstat(ctx->block_fd, &block_st))
        return -errno;
    epoch->char_is_namespace = S_ISCHR(char_st.st_mode);
    epoch->block_is_whole_namespace = S_ISBLK(block_st.st_mode);
    epoch->char_rdev = encoded_rdev(char_st.st_rdev);
    epoch->block_rdev = encoded_rdev(block_st.st_rdev);

    ioctl_nsid = ioctl(ctx->nvme_fd, NVME_IOCTL_ID);
    if (ioctl_nsid <= 0)
        return ioctl_nsid < 0 ? -errno : -ENODEV;
    epoch->nsid = (uint32_t)ioctl_nsid;
    if (ioctl(ctx->block_fd, BLKGETDISKSEQ, &diskseq) < 0)
        return -errno;
    epoch->diskseq = diskseq;
    return nxp_namespace_epoch_check_one(epoch);
}

static int revalidate_namespace(struct pipeline_ctx *ctx)
{
    struct nxp_namespace_epoch frozen, current;
    int ret;

    ret = nxp_namespace_epoch_from_snapshot(&ctx->namespace, &frozen);
    if (ret)
        return ret;
    ret = collect_namespace_epoch(ctx, &current);
    if (ret)
        return ret;
    return nxp_namespace_epoch_validate(&frozen, &current);
}

static int register_fixed_file(struct pipeline_ctx *ctx)
{
    int fd = ctx->nvme_fd;
    int ret;

    if (!g_fixed_file)
        return 0;
    ret = io_uring_register_files(&ctx->uring.ring, &fd, 1);
    if (ret < 0)
        return ret;
    ctx->uring.fixed_file_registered = true;
    return 0;
}

static int production_revalidate(struct pipeline_ctx *ctx)
{
    return revalidate_namespace(ctx);
}

typedef int (*nxp_io_uring_get_events_fn)(struct io_uring *ring);

static pthread_once_t get_events_once = PTHREAD_ONCE_INIT;
static nxp_io_uring_get_events_fn get_events_fn;

static void production_resolve_get_events(void)
{
    void *symbol;

    /* A direct weak reference acquires a LIBURING_2.3 ELF version at link
     * time and can make the loader abort before main() on a 2.1 host.  Resolve
     * the versioned symbol explicitly so the program can report a controlled,
     * pre-mmap -EOPNOTSUPP instead. */
    dlerror();
    symbol = dlvsym(RTLD_DEFAULT, "io_uring_get_events", "LIBURING_2.3");
    if (dlerror() || !symbol)
        return;
    _Static_assert(sizeof(get_events_fn) == sizeof(symbol),
                   "dlsym function-pointer representation mismatch");
    memcpy(&get_events_fn, &symbol, sizeof(get_events_fn));
}

static nxp_io_uring_get_events_fn production_get_events(void)
{
    if (pthread_once(&get_events_once, production_resolve_get_events) != 0)
        return NULL;
    return get_events_fn;
}

static int production_require_extended_layout(struct pipeline_ctx *ctx)
{
    (void)ctx;
    /* SQE128/CQE32 arrived in liburing 2.2, and 2.3 added the nonblocking
     * IOPOLL kernel-entry primitive used below.  The symbol check is against
     * the DSO actually loaded at runtime and therefore also catches a new
     * build header paired with an old shared library. */
    return production_get_events() ? 0 : -EOPNOTSUPP;
}

static int production_prove_iopoll(struct pipeline_ctx *ctx)
{
    return prove_iopoll(ctx);
}

static int pipeline_open_cq_eventfd(struct uring_ctx *uring)
{
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    int ret;

    if (fd < 0)
        return -errno;
    ret = io_uring_register_eventfd(&uring->ring, fd);
    if (ret < 0) {
        close(fd);
        return ret;
    }
    uring->cq_eventfd = fd;
    uring->cq_eventfd_registered = true;
    return 0;
}

static int production_ring_init(struct pipeline_ctx *ctx)
{
    int ret = init_io_uring(&ctx->uring);

    /* Only rx-write waits on completions and the RX ring together; IOPOLL
     * completions are reaped by polling and never signal an eventfd. */
    if (ret || g_direction != PIPELINE_NIC_TO_NVME || g_iopoll)
        return ret;
    ret = pipeline_open_cq_eventfd(&ctx->uring);
    if (ret) {
        io_uring_queue_exit(&ctx->uring.ring);
        ctx->uring.initialized = false;
    }
    return ret;
}

static int production_ring_close(struct pipeline_ctx *ctx)
{
    io_uring_queue_exit(&ctx->uring.ring);
    if (ctx->uring.cq_eventfd_registered) {
        close(ctx->uring.cq_eventfd);
        ctx->uring.cq_eventfd_registered = false;
    }
    return 0;
}

static int production_submit(struct pipeline_ctx *ctx)
{
    return io_uring_submit(&ctx->uring.ring);
}

static int production_enter(struct pipeline_ctx *ctx,
                            unsigned int to_submit)
{
    int ret = syscall(__NR_io_uring_enter, ctx->uring.ring.ring_fd,
                      to_submit, 0, 0, NULL, 0);

    return ret < 0 ? -errno : ret;
}

static int production_peek_cqe(struct pipeline_ctx *ctx,
                               struct io_uring_cqe **cqe)
{
    return pipeline_peek_cqe_raw(ctx, cqe);
}

static int production_progress_iopoll(struct pipeline_ctx *ctx)
{
    nxp_io_uring_get_events_fn get_events = production_get_events();

    if (!get_events)
        return -EOPNOTSUPP;
    /* io_uring_get_events() performs exactly one io_uring_enter(GETEVENTS)
     * with min_complete=0.  It drives IOPOLL without putting a kernel timeout
     * request into the ring or looping inside liburing. */
    return get_events(&ctx->uring.ring);
}

static int production_monotonic_ns(struct pipeline_ctx *ctx, uint64_t *now_ns)
{
    struct timespec now;

    (void)ctx;
    if (!now_ns)
        return -EINVAL;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -errno;
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L ||
        (uint64_t)now.tv_sec >
            (UINT64_MAX - (uint64_t)now.tv_nsec) / UINT64_C(1000000000))
        return -EOVERFLOW;
    *now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
              (uint64_t)now.tv_nsec;
    return 0;
}

static int production_wait_cqe_timeout(struct pipeline_ctx *ctx,
                                       struct io_uring_cqe **cqe,
                                       uint64_t timeout_ns)
{
    struct __kernel_timespec timeout = {
        .tv_sec = (int64_t)(timeout_ns / UINT64_C(1000000000)),
        .tv_nsec = (long)(timeout_ns % UINT64_C(1000000000)),
    };

    return io_uring_wait_cqe_timeout(&ctx->uring.ring, cqe, &timeout);
}

/* rx-write's completion wait, in the shape of the traditional receiver's
 * (tools/xdev_ext_sendpath_baseline.c): one poll() on the ring's CQ eventfd and the
 * XSK fd.  A signalled eventfd is drained here; the CQE itself is read by the
 * caller with peek_cqe. */
static int production_wait_cqe_or_rx(struct pipeline_ctx *ctx,
                                     uint64_t timeout_ns, short *rx_revents)
{
    uint64_t timeout_ms = timeout_ns / UINT64_C(1000000) +
                          (timeout_ns % UINT64_C(1000000) != 0);
    struct pollfd fds[2];
    int ret;

    *rx_revents = 0;
    if (!ctx->uring.cq_eventfd_registered)
        return -EBADF;
    fds[0] = (struct pollfd) { .fd = ctx->uring.cq_eventfd, .events = POLLIN };
    fds[1] = (struct pollfd) { .fd = ctx->xsk.xsk_fd, .events = POLLIN };
    ret = poll(fds, 2, timeout_ms > INT_MAX ? INT_MAX : (int)timeout_ms);
    if (ret < 0)
        return -errno;
    if (!ret)
        return -ETIME;
    *rx_revents = fds[1].revents;
    if (fds[0].revents & POLLNVAL)
        return -EBADF;
    if (fds[0].revents & (POLLERR | POLLHUP))
        return -EIO;
    if (fds[0].revents & POLLIN) {
        uint64_t count;

        if (read(fds[0].fd, &count, sizeof(count)) < 0 &&
            errno != EAGAIN && errno != EINTR)
            return -errno;
    }
    return 0;
}

static int production_unregister_buffers(struct pipeline_ctx *ctx)
{
    return io_uring_unregister_buffers(&ctx->uring.ring);
}

static int production_unregister_files(struct pipeline_ctx *ctx)
{
    return io_uring_unregister_files(&ctx->uring.ring);
}

static void pipeline_update_backing_guard(struct pipeline_ctx *ctx)
{
    ctx->backing_quiescence_failed |= ctx->ring_close_failed ||
                                      ctx->unmatched_io_retained;
}

/* The process may still be the source or sink of device DMA it cannot prove
 * finished: such a run ends in the hold for unquiesced backing, never in
 * process exit. */
static bool pipeline_retains_backing(const struct pipeline_ctx *ctx)
{
    return ctx->backing_quiescence_failed || ctx->unmatched_io_retained ||
           ctx->chain_sequestered;
}

static bool pipeline_can_destroy_xsk(const struct pipeline_ctx *ctx)
{
    return !ctx->backing_quiescence_failed &&
           !ctx->chain_sequestered &&
           !ctx->xsk.protocol_invalidated &&
           !xdev_ext_xsk_redirect_is_active(&ctx->xsk.redirect);
}

/* Stop ingress before any GPU/NVMe/XSK backing teardown.  The helper keeps
 * exact ownership state and fds on a failed map delete or atomic detach, so a
 * bounded retry can make progress without ever detaching another program. */
static int pipeline_detach_xsk_redirect(struct pipeline_ctx *ctx)
{
    int ret = 0;

    if (!ctx || !ctx->xsk.xsk)
        return 0;
    for (unsigned int attempt = 0;
         attempt < NXP_REDIRECT_DETACH_RETRIES; attempt++) {
        ret = xdev_ext_xsk_redirect_detach(&ctx->xsk.redirect);
        if (!xdev_ext_xsk_redirect_is_active(&ctx->xsk.redirect))
            return ret;
        (void)poll(NULL, 0, 1);
    }
    /* An attached redirect or live XSKMAP entry is still able to hand NIC
     * ownership to this socket.  Prevent explicit backing destruction. */
    ctx->xsk.protocol_invalidated = true;
    return ret ? ret : -EBUSY;
}

static uint64_t pipeline_handle_xsk_drain_timeout(struct pipeline_ctx *ctx)
{
    uint64_t missing;

    if (ctx->stats.tx_reclaimed >= ctx->stats.tx_submitted)
        return 0;
    missing = ctx->stats.tx_submitted - ctx->stats.tx_reclaimed;
    ctx->stats.drops += missing;
    /* No terminal CQ means NIC ownership of at least one UMEM frame remains
     * unproven.  Treat this like an unattributed CQ: prohibit address reuse and
     * retain the socket/UMEM backing through process teardown. */
    ctx->xsk.protocol_invalidated = true;
    nxp_latch_error(&ctx->first_error, -ETIMEDOUT);
    return missing;
}

/* io_uring_queue_exit() closes/unmaps the userspace ring, but this kernel may
 * defer io_ring_ctx teardown to exit_work.  This operation is deliberately
 * named close: it is not a synchronous NVMe DMA-quiescence proof. */
static int pipeline_close_ring(struct pipeline_ctx *ctx)
{
    int ret;

    if (!ctx->uring.initialized) {
        ctx->ring_close_failed = false;
        pipeline_update_backing_guard(ctx);
        return 0;
    }
    ret = ctx->adapter->ring_close(ctx);
    if (!ret) {
        memset(&ctx->uring, 0, sizeof(ctx->uring));
        ctx->ring_close_failed = false;
    } else {
        ctx->ring_close_failed = true;
    }
    pipeline_update_backing_guard(ctx);
    return ret;
}

static int pipeline_init_ring(struct pipeline_ctx *ctx)
{
    int ret;

    /* This must precede io_uring_queue_init_params(): liburing 2.1 maps only
     * 64/16 bytes per entry even when the kernel accepts SQE128/CQE32. */
    ret = ctx->adapter->require_extended_layout(ctx);
    if (ret)
        return ret;
    if (g_iopoll) {
        ret = ctx->adapter->prove_iopoll(ctx);
        if (ret)
            return ret;
    }
    return ctx->adapter->ring_init(ctx);
}

static int pipeline_unregister_buffers(struct pipeline_ctx *ctx)
{
    int ret, close_ret;

    if (!ctx->uring.fixed_buffer_registered)
        return 0;
    ret = ctx->adapter->unregister_buffers(ctx);
    if (!ret) {
        ctx->uring.fixed_buffer_registered = false;
        return 0;
    }
    /* unregister_buffers() is the synchronous ownership boundary for the
     * UMEM-backed iovecs.  A later successful ring close only starts deferred
     * io_ring_ctx teardown; it cannot prove that device DMA has quiesced. */
    ctx->backing_quiescence_failed = true;
    nxp_latch_error(&ctx->first_error, ret);
    close_ret = pipeline_close_ring(ctx);
    nxp_latch_error(&ctx->first_error, close_ret);
    return ret;
}

static int pipeline_unregister_files(struct pipeline_ctx *ctx)
{
    int ret, close_ret;

    if (!ctx->uring.fixed_file_registered)
        return 0;
    ret = ctx->adapter->unregister_files(ctx);
    if (!ret) {
        ctx->uring.fixed_file_registered = false;
        return 0;
    }
    nxp_latch_error(&ctx->first_error, ret);
    close_ret = pipeline_close_ring(ctx);
    nxp_latch_error(&ctx->first_error, close_ret);
    return ret;
}

/* Fixed buffers are the first cleanup layer.  A failed ring close is retried
 * before any caller destroys XSK/UMEM backing.  An unmatched I/O retention
 * guard survives a successful close because close is not a DMA barrier. */
static int pipeline_prepare_backing_cleanup(struct pipeline_ctx *ctx)
{
    int unregister_ret = pipeline_unregister_buffers(ctx);
    int close_ret;

    if (!ctx->backing_quiescence_failed)
        return unregister_ret;
    close_ret = pipeline_close_ring(ctx);
    nxp_latch_error(&ctx->first_error, close_ret);
    return close_ret ? close_ret : unregister_ret;
}

/* One completion probe is bounded by construction: raw CQ loads, at most one
 * min_complete=0 IOPOLL enter, then one final raw CQ load. */
static int pipeline_cqe_step(struct pipeline_ctx *ctx,
                             struct io_uring_cqe **cqe)
{
    int progress_ret, peek_ret;

    peek_ret = ctx->adapter->peek_cqe(ctx, cqe);
    if (peek_ret != -EAGAIN || !g_iopoll)
        return peek_ret;
    progress_ret = ctx->adapter->progress_iopoll(ctx);
    /* A completion can become visible even when enter was interrupted.  Always
     * make the promised second raw probe and give an exact CQE precedence. */
    peek_ret = ctx->adapter->peek_cqe(ctx, cqe);
    if (!peek_ret || peek_ret != -EAGAIN)
        return peek_ret;
    return progress_ret < 0 ? progress_ret : -EAGAIN;
}

static int pipeline_wait_bounded(struct pipeline_ctx *ctx,
                                 struct io_uring_cqe **cqe)
{
    uint64_t start, deadline, now, previous;
    int ret;

    ret = ctx->adapter->monotonic_ns(ctx, &start);
    if (ret) {
        nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
        return ret;
    }
    deadline = start > UINT64_MAX - NXP_WAIT_TIMEOUT_NS ?
               UINT64_MAX : start + NXP_WAIT_TIMEOUT_NS;
    now = start;

    for (;;) {
        int step_ret;

        if (now >= deadline) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return -ETIMEDOUT;
        }
        if (g_iopoll) {
            step_ret = pipeline_cqe_step(ctx, cqe);
        } else {
            step_ret = ctx->adapter->wait_cqe_timeout(ctx, cqe,
                                                       deadline - now);
        }
        if (!step_ret)
            return 0;
        if (!nxp_retryable_error(step_ret, true)) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return step_ret;
        }
        previous = now;
        ret = ctx->adapter->monotonic_ns(ctx, &now);
        if (ret) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return ret;
        }
        if (now < previous) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return -EIO;
        }
        if (now >= deadline) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return -ETIMEDOUT;
        }
        if (g_iopoll)
            sched_yield();
    }
}

/* rx-write's bounded completion wait.  It returns 0 once a WRITE CQE is
 * visible or, with watch_rx, once the RX ring holds a descriptor the loop can
 * take, so a packet that arrives while a WRITE is in flight is examined, and
 * its arrival time read, without waiting for that WRITE's CQE.  The deadline
 * is the caller's: armed by the first wait after the last reaped CQE and kept
 * across RX wakeups, so RX traffic never extends the bound on an NVMe
 * completion.  Failures are those of pipeline_wait_bounded() and go to
 * pipeline_handle_wait_failure(); an XSK socket error is returned in
 * *rx_error instead and does not end the wait for the CQE. */
static int pipeline_rx_wait_bounded(struct pipeline_ctx *ctx,
                                    uint64_t *deadline_ns, bool watch_rx,
                                    int *rx_error)
{
    struct io_uring_cqe *cqe;
    uint64_t now, previous;
    int ret;

    if (!deadline_ns || !rx_error)
        return -EINVAL;
    ret = ctx->adapter->monotonic_ns(ctx, &now);
    if (ret) {
        nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
        return ret;
    }
    if (!*deadline_ns)
        *deadline_ns = now > UINT64_MAX - NXP_WAIT_TIMEOUT_NS ?
                       UINT64_MAX : now + NXP_WAIT_TIMEOUT_NS;

    for (;;) {
        short rx_revents = 0;
        int step_ret;

        if (now >= *deadline_ns) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return -ETIMEDOUT;
        }
        if (watch_rx && xsk_cons_nb_avail(&ctx->xsk.rx, 1))
            return 0;
        if (g_iopoll) {
            step_ret = pipeline_cqe_step(ctx, &cqe);
        } else if (watch_rx) {
            step_ret = ctx->adapter->wait_cqe_or_rx(ctx, *deadline_ns - now,
                                                    &rx_revents);
            if (rx_revents) {
                int rx_ret = nxp_rx_idle_poll_result(1, rx_revents, now,
                                                     UINT64_MAX);

                if (rx_ret != -EAGAIN) {
                    *rx_error = rx_ret;
                    return 0;
                }
            }
            /* The eventfd only wakes this wait; a CQE in the ring is what
             * ends it, so the CQ is read after a wakeup, an interrupt and a
             * timeout alike. */
            if (!step_ret || nxp_retryable_error(step_ret, true)) {
                int peek_ret = ctx->adapter->peek_cqe(ctx, &cqe);

                if (!peek_ret)
                    return 0;
                if (!step_ret || !nxp_retryable_error(peek_ret, true))
                    step_ret = peek_ret;
            }
        } else {
            step_ret = ctx->adapter->wait_cqe_timeout(ctx, &cqe,
                                                       *deadline_ns - now);
        }
        if (!step_ret)
            return 0;
        if (!nxp_retryable_error(step_ret, true)) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return step_ret;
        }
        previous = now;
        ret = ctx->adapter->monotonic_ns(ctx, &now);
        if (ret) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return ret;
        }
        if (now < previous) {
            nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
            return -EIO;
        }
        if (g_iopoll)
            sched_yield();
    }
}

/* Per-in-flight-read slot. Indexed by user_data (0..g_depth-1). Tracks which UMEM
 * frame a given NVMe read is DMAing into, so on completion we build+TX that exact
 * frame. CORRECTNESS: a frame is allocated when its read is issued and only freed
 * after its TX completes (xsk_tx_complete), so a frame used as a live NVMe DMA target
 * is never reused — no aliasing. Every issued read is TX'd exactly once. */
struct inflight_slot {
    uint64_t frame_addr;   /* UMEM offset of the frame this read DMAs into */
    void *staging_buf;     /* -Z only: per-slot staging buffer (NULL otherwise) */
    uint64_t block_index;
    struct nxp_request request;
    struct nxp_data_progress data_progress;
    struct nxp_nvme_io_plan io_plan;
    struct nxp_wire_layout wire_layout;
    uint64_t frame_addrs[NXP_WIRE_MAX_SEGMENTS];
    struct iovec vector[NXP_WIRE_MAX_SEGMENTS];
    struct ngn_frame_journal chain_journals[NXP_WIRE_MAX_SEGMENTS];
    uint16_t segment_count;
    struct nxp_wire_group_rx rx_group;
    bool collecting_rx;
};

struct pipeline_loop_state {
    bool stop_issuing;
    bool cqe_attribution_fault;
};

static int pipeline_chain_abort_slot(struct pipeline_ctx *ctx,
                                     struct inflight_slot *slot)
{
    int first = 0;

    if (!ctx->gpu_enabled)
        return 0;
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        struct ngn_frame_journal *journal = &slot->chain_journals[i];
        int ret;

        if (!journal->owns_backing)
            continue;
        ret = ngn_journal_abort_private(journal);
        if (ret && !first)
            first = ret;
    }
    if (first) {
        ctx->chain_sequestered = true;
        ctx->backing_quiescence_failed = true;
    }
    return first;
}

static int pipeline_chain_begin_tx(struct pipeline_ctx *ctx,
                                   struct inflight_slot *slot,
                                   uint64_t request_id,
                                   uint32_t wire_generation)
{
    if (!ctx->gpu_enabled)
        return 0;
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        int ret = ngn_journal_begin(&slot->chain_journals[i],
                                    NGN_NVME_GPU_NIC, ctx->chain_id,
                                    request_id, wire_generation,
                                    slot->frame_addrs[i]);

        if (ret) {
            (void)pipeline_chain_abort_slot(ctx, slot);
            return ret;
        }
    }
    return 0;
}

static int pipeline_chain_begin_rx_frame(struct pipeline_ctx *ctx,
                                         struct inflight_slot *slot,
                                         uint16_t segment,
                                         uint64_t request_id,
                                         uint32_t wire_generation,
                                         uint64_t frame_addr)
{
    struct ngn_frame_journal *journal;
    int ret;

    if (!ctx->gpu_enabled)
        return 0;
    if (segment >= NXP_WIRE_MAX_SEGMENTS)
        return -E2BIG;
    journal = &slot->chain_journals[segment];
    ret = ngn_journal_begin(journal, NGN_NIC_GPU_NVME, ctx->chain_id,
                            request_id, wire_generation, frame_addr);
    if (!ret)
        ret = ngn_journal_source_accept(journal);
    if (!ret)
        ret = ngn_journal_source_complete(journal);
    if (ret && journal->owns_backing &&
        journal->stage != NGN_STAGE_SOURCE_ACCEPTED)
        (void)ngn_journal_abort_private(journal);
    return ret;
}

static int pipeline_chain_nvme_accept(struct pipeline_ctx *ctx,
                                      struct inflight_slot *slot)
{
    int first = 0;

    if (!ctx->gpu_enabled)
        return 0;
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        int ret;

        if (g_direction == PIPELINE_NVME_TO_NIC)
            ret = ngn_journal_source_accept(&slot->chain_journals[i]);
        else
            ret = ngn_journal_sink_accept(&slot->chain_journals[i]);
        if (ret && !first)
            first = ret;
    }
    if (first) {
        ngn_journal_sequester(slot->chain_journals,
                               slot->segment_count);
        ctx->chain_sequestered = true;
        ctx->backing_quiescence_failed = true;
    }
    return first;
}

static int pipeline_chain_nvme_complete(struct pipeline_ctx *ctx,
                                        struct inflight_slot *slot)
{
    int first = 0;

    if (!ctx->gpu_enabled)
        return 0;
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        int ret;

        if (g_direction == PIPELINE_NVME_TO_NIC)
            ret = ngn_journal_source_complete(
                &slot->chain_journals[i]);
        else
            ret = ngn_journal_sink_complete(
                &slot->chain_journals[i]);
        if (ret && !first)
            first = ret;
    }
    if (first) {
        ngn_journal_sequester(slot->chain_journals,
                               slot->segment_count);
        ctx->chain_sequestered = true;
        ctx->backing_quiescence_failed = true;
    }
    return first;
}

static int pipeline_chain_gpu_roundtrip(struct pipeline_ctx *ctx,
                                        struct inflight_slot *slot)
{
#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
    struct ngn_frame_journal *journals[NGN_GPU_MAX_BATCH];
    struct ngn_gpu_span spans[NGN_GPU_MAX_BATCH];
    const struct ngn_gpu_ops ops = {
        .submit_sync = ngn_gpu_runtime_submit,
    };
    const struct ngn_gpu_window window = {
        .umem_bytes = UMEM_SIZE,
        .gpu_bytes = UMEM_SIZE,
        .frame_size = FRAME_SIZE,
    };

    if (!ctx->gpu_enabled)
        return 0;
    if (!slot->segment_count ||
        slot->segment_count > NGN_GPU_MAX_BATCH)
        return -E2BIG;
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        uintptr_t address = (uintptr_t)slot->vector[i].iov_base;
        uintptr_t begin = (uintptr_t)ctx->xsk.umem_area;
        uint64_t offset;

        if (address < begin || address - begin >= UMEM_SIZE)
            return -ERANGE;
        offset = (uint64_t)(address - begin);
        journals[i] = &slot->chain_journals[i];
        spans[i] = (struct ngn_gpu_span) {
            .frame_addr = slot->frame_addrs[i],
            .umem_offset = offset,
            .gpu_offset = offset,
            .length = slot->vector[i].iov_len,
        };
    }
    {
        int ret = ngn_gpu_roundtrip_frames(journals,
                                           slot->segment_count, spans,
                                           &window, &ops, &ctx->gpu);

        if (ret) {
            ctx->chain_sequestered = true;
            ctx->backing_quiescence_failed = true;
            ctx->xsk.protocol_invalidated = true;
        }
        return ret;
    }
#else
    (void)slot;
    return ctx->gpu_enabled ? -EOPNOTSUPP : 0;
#endif
}

static int pipeline_chain_publish_tx(struct pipeline_ctx *ctx,
                                     struct inflight_slot *slot)
{
    if (!ctx->gpu_enabled)
        return 0;
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        struct ngn_frame_journal *source = &slot->chain_journals[i];
        struct ngn_frame_journal *target;
        uint64_t frame_addr = slot->frame_addrs[i];

        if (frame_addr >= UMEM_SIZE || frame_addr % FRAME_SIZE)
            return -ERANGE;
        target = &ctx->xsk.chain_frames[frame_addr / FRAME_SIZE];
        if (!source->owns_backing ||
            source->stage != NGN_STAGE_GPU_DONE ||
            source->frame_addr != frame_addr ||
            target->owns_backing ||
            (target->stage != NGN_STAGE_FREE &&
             target->stage != NGN_STAGE_COMPLETE))
            return -EPROTO;
    }
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        struct ngn_frame_journal *source = &slot->chain_journals[i];
        struct ngn_frame_journal *target =
            &ctx->xsk.chain_frames[
                slot->frame_addrs[i] / FRAME_SIZE];

        if (ngn_journal_sink_accept(source) != 0) {
            ngn_journal_sequester(slot->chain_journals,
                                   slot->segment_count);
            ctx->chain_sequestered = true;
            ctx->backing_quiescence_failed = true;
            return -EPROTO;
        }
        *target = *source;
        *source = (struct ngn_frame_journal) { 0 };
    }
    return 0;
}

static int pipeline_chain_tx_complete(struct pipeline_ctx *ctx,
                                      uint64_t frame_addr)
{
    struct ngn_frame_journal *journal;

    if (!ctx->gpu_enabled)
        return 0;
    if (frame_addr >= UMEM_SIZE || frame_addr % FRAME_SIZE)
        return -ERANGE;
    journal = &ctx->xsk.chain_frames[frame_addr / FRAME_SIZE];
    return ngn_journal_sink_complete(journal);
}

/* NVMe completions are allowed to arrive out of order, while the receiver
 * deliberately accepts only generation 1 followed by last_generation + 1.
 * Keep completed payloads private until the next logical request is ready for
 * publication.  This preserves queue depth without turning CQ order into wire
 * order. */
static int pipeline_find_next_tx_group(const struct inflight_slot *slots,
                                       int depth, uint64_t next_request)
{
    uint32_t expected_generation;
    int found = -1;

    if (!slots || depth < 1)
        return -EINVAL;
    if (next_request >= UINT32_MAX)
        return -EOVERFLOW;
    expected_generation = (uint32_t)next_request + 1;

    for (int i = 0; i < depth; i++) {
        const struct inflight_slot *slot = &slots[i];

        if (!slot->segment_count &&
            slot->frame_addr == INVALID_UMEM_FRAME)
            continue;
        if (slot->block_index != next_request)
            continue;
        if (found >= 0)
            return -EPROTO;
        found = i;
        if (!slot->segment_count ||
            slot->frame_addr == INVALID_UMEM_FRAME ||
            slot->wire_layout.generation != expected_generation)
            return -EPROTO;
    }
    if (found < 0)
        return -EAGAIN;
    if (slots[found].request.state != NXP_REQ_COMPLETED ||
        slots[found].request.owns_backing ||
        slots[found].data_progress.stage != NXP_DATA_PROCESSED)
        return -EAGAIN;
    return found;
}

static inline int slot_is_free(const struct inflight_slot *s)
{
    return s->frame_addr == INVALID_UMEM_FRAME && !s->request.owns_backing;
}

static void pipeline_clear_group(struct inflight_slot *slot)
{
    uint32_t last_rx_generation = slot->rx_group.last_generation;

    slot->frame_addr = INVALID_UMEM_FRAME;
    slot->segment_count = 0;
    memset(&slot->io_plan, 0, sizeof(slot->io_plan));
    memset(&slot->wire_layout, 0, sizeof(slot->wire_layout));
    memset(slot->chain_journals, 0, sizeof(slot->chain_journals));
    memset(&slot->rx_group, 0, sizeof(slot->rx_group));
    slot->rx_group.last_generation = last_rx_generation;
    slot->collecting_rx = false;
}

static int pipeline_abort_group_frames(struct pipeline_ctx *ctx,
                                       struct inflight_slot *slot)
{
    uint16_t count;
    int first = 0;

    if (!ctx || !slot)
        return -EINVAL;
    first = pipeline_chain_abort_slot(ctx, slot);
    if (first)
        return first;
    count = slot->segment_count ? slot->segment_count :
            (slot->frame_addr != INVALID_UMEM_FRAME ? 1 : 0);
    for (uint16_t i = 0; i < count; i++) {
        uint64_t addr = slot->segment_count ? slot->frame_addrs[i] :
                                             slot->frame_addr;

        if (addr >= UMEM_SIZE || addr % FRAME_SIZE ||
            xdev_ext_frame_abort(&ctx->xsk.pool, addr / FRAME_SIZE) != 0)
            first = first ? first : -EPROTO;
        if (slot->segment_count) {
            slot->frame_addrs[i] = INVALID_UMEM_FRAME;
            slot->vector[i] = (struct iovec) { 0 };
        }
    }
    pipeline_clear_group(slot);
    return first;
}

/* Give back a command that is still private to userspace.  This is never
 * valid after an accepted prefix has reached the kernel. */
static int pipeline_abort_private_group(struct pipeline_ctx *ctx,
                                        struct inflight_slot *slot)
{
    int first = 0;

    if (!ctx || !slot)
        return -EINVAL;
    if (slot->request.owns_backing) {
        int ret = nxp_request_release_unaccepted(&slot->request, false);

        if (ret)
            return ret;
    }
    first = pipeline_abort_group_frames(ctx, slot);
    return first;
}

/* Mirror the fixed-buffer boundary before publishing IO_VEC metadata.  The
 * kernel independently imports and revalidates this vector against buf_index
 * 0; this userspace check catches construction bugs before any SQE is visible. */
static int pipeline_validate_umem_vector(struct pipeline_ctx *ctx,
                                         const struct iovec *vector,
                                         uint16_t count,
                                         uint64_t expected_total)
{
    uintptr_t begin, end;
    uint64_t total = 0;

    if (!ctx || !vector || !count || !expected_total ||
        !ctx->uring.fixed_buffer_registered || !ctx->xsk.umem_area ||
        ctx->xsk.umem_area == MAP_FAILED)
        return -EINVAL;
    begin = (uintptr_t)ctx->xsk.umem_area;
    if (begin > UINTPTR_MAX - UMEM_SIZE)
        return -EOVERFLOW;
    end = begin + UMEM_SIZE;
    for (uint16_t i = 0; i < count; i++) {
        uintptr_t address = (uintptr_t)vector[i].iov_base;
        size_t len = vector[i].iov_len;
        size_t frame_offset;

        if (!len || address < begin || address >= end || len > end - address)
            return -ERANGE;
        if (address & (NXP_VECTOR_ALIGNMENT - 1))
            return -EINVAL;
        frame_offset = (size_t)(address - begin) % FRAME_SIZE;
        if (len > FRAME_SIZE - frame_offset)
            return -ERANGE;
        if (total > UINT64_MAX - len)
            return -EOVERFLOW;
        total += len;
    }
    return total == expected_total ? 0 : -EMSGSIZE;
}

/* The staging arm deliberately keeps NVMe DMA in a separate registered
 * buffer, then scatters one completed logical transfer into the same ordinary
 * MTU frame group used by the direct IO_VEC arm. */
static int pipeline_prepare_staging_frames(struct pipeline_ctx *ctx,
					   struct inflight_slot *slot,
					   uint64_t request_index,
					   uint32_t wire_generation)
{
	int ret;

	if (!ctx || !slot || !slot->staging_buf || !wire_generation ||
	    !slot_is_free(slot))
		return -EINVAL;
	ret = nxp_wire_mtu_layout_plan(ctx->session_id, wire_generation,
				       g_block_size, ctx->mtu, FRAME_SIZE,
				       NXP_LAYOUT_DATA_OFFSET,
				       NXP_VECTOR_ALIGNMENT,
				       &slot->wire_layout);
	if (ret)
		return ret;
	for (uint16_t i = 0; i < slot->wire_layout.segment_count; i++) {
		struct nxp_wire_segment segment;
		uint64_t frame_addr;

		ret = nxp_wire_segment_at(&slot->wire_layout, NXP_IO_READ, i,
					  &segment);
		if (ret)
			goto abort;
		frame_addr = xsk_alloc_umem_frame(&ctx->xsk);
		if (frame_addr == INVALID_UMEM_FRAME) {
			ret = -ENOBUFS;
			goto abort;
		}
		slot->frame_addrs[slot->segment_count] = frame_addr;
		slot->vector[slot->segment_count] = (struct iovec) {
			.iov_base = (unsigned char *)ctx->xsk.umem_area +
				frame_addr + NXP_DATA_OFFSET,
			.iov_len = segment.payload_len,
		};
		slot->segment_count++;
	}
	slot->frame_addr = slot->frame_addrs[0];
	slot->block_index = request_index;
	ret = pipeline_chain_begin_tx(ctx, slot, request_index, wire_generation);
	if (ret)
		goto abort;
	return 0;

abort:
	if (pipeline_abort_group_frames(ctx, slot) != 0)
		return -EPROTO;
	return ret;
}

static int pipeline_copy_staging_group(struct pipeline_ctx *ctx,
				       struct inflight_slot *slot)
{
	size_t copied = 0;

	if (!ctx || !slot || !slot->staging_buf || !slot->segment_count ||
	    slot->segment_count != slot->wire_layout.segment_count)
		return -EINVAL;
	for (uint16_t i = 0; i < slot->segment_count; i++) {
		struct nxp_wire_segment segment;
		uint64_t addr = slot->frame_addrs[i];
		int ret = nxp_wire_segment_at(&slot->wire_layout, NXP_IO_READ, i,
					      &segment);

		if (ret || addr >= UMEM_SIZE || addr % FRAME_SIZE ||
		    slot->vector[i].iov_base !=
			(unsigned char *)ctx->xsk.umem_area + addr +
			NXP_DATA_OFFSET ||
		    slot->vector[i].iov_len != segment.payload_len ||
		    copied > g_block_size || segment.payload_len >
			g_block_size - copied ||
		    xdev_ext_frame_state(&ctx->xsk.pool, addr / FRAME_SIZE) !=
			XDEV_EXT_FRAME_IO_PENDING)
			return ret ? ret : -EPROTO;
		memcpy(slot->vector[i].iov_base,
		       (unsigned char *)slot->staging_buf + copied,
		       segment.payload_len);
		copied += segment.payload_len;
	}
	return copied == g_block_size ? 0 : -EMSGSIZE;
}

/* Prepare one logical NVMe READ into a scatter vector of packet payloads.
 * All frames are claimed before the one SQE is published; every error before
 * publication returns the entire group to the FREE pool. */
static int pipeline_prepare_tx_group(struct pipeline_ctx *ctx,
                                     struct inflight_slot *slot,
                                     uint32_t slot_index,
                                     uint64_t request_index,
                                     uint32_t *request_generation,
                                     uint32_t wire_generation)
{
    struct nxp_local_io_position position = {
        .request_index = request_index,
    };
    struct io_uring_sqe *sqe;
    unsigned int private_tail;
    int ret;

    if (!ctx || !slot || !request_generation || !wire_generation ||
        !slot_is_free(slot))
        return -EINVAL;
    ret = nxp_wire_mtu_layout_plan(ctx->session_id, wire_generation,
                                   g_block_size, ctx->mtu,
                                   FRAME_SIZE, NXP_LAYOUT_DATA_OFFSET,
                                   NXP_VECTOR_ALIGNMENT,
                                   &slot->wire_layout);
    if (ret)
        return ret;
    if (slot->wire_layout.segment_count > NXP_WIRE_MAX_SEGMENTS)
        return -E2BIG;
    ret = nxp_plan_nvme_io(&ctx->namespace, &ctx->io_limits, NXP_IO_READ,
                           &position, g_block_size, &slot->io_plan);
    if (ret)
        return ret;

    for (uint16_t i = 0; i < slot->wire_layout.segment_count; i++) {
        struct nxp_wire_segment segment;
        uint64_t frame_addr;

        ret = nxp_wire_segment_at(&slot->wire_layout, NXP_IO_READ, i,
                                  &segment);
        if (ret) {
            goto abort;
        }
        frame_addr = xsk_alloc_umem_frame(&ctx->xsk);
        if (frame_addr == INVALID_UMEM_FRAME) {
            ret = -ENOBUFS;
            goto abort;
        }
        slot->frame_addrs[slot->segment_count] = frame_addr;
        slot->vector[slot->segment_count].iov_base =
            (unsigned char *)ctx->xsk.umem_area + frame_addr +
            NXP_DATA_OFFSET;
        slot->vector[slot->segment_count].iov_len = segment.payload_len;
        slot->segment_count++;
    }
    ret = pipeline_validate_umem_vector(ctx, slot->vector,
                                        slot->segment_count, g_block_size);
    if (ret)
        goto abort;
    slot->frame_addr = slot->frame_addrs[0];
    slot->block_index = request_index;
    ret = pipeline_chain_begin_tx(ctx, slot, request_index,
                                  wire_generation);
    if (ret)
        goto abort;
    ret = nxp_request_prepare(&slot->request, slot_index,
                              request_generation);
    if (ret)
        goto abort;
    private_tail = ctx->uring.ring.sq.sqe_tail;
    ret = pipeline_get_sqe(ctx, &sqe);
    if (ret)
        goto abort;
    ret = fill_nvme_vector_sqe(ctx, sqe, slot->vector,
                               slot->segment_count, &slot->io_plan,
                               slot->request.token, 0);
    if (ret) {
        ctx->uring.ring.sq.sqe_tail = private_tail;
        goto abort;
    }
    nxp_data_begin(&slot->data_progress, false);
    return 0;

abort:
    (void)pipeline_abort_private_group(ctx, slot);
    return ret;
}

static int pipeline_prepare_rx_write(struct pipeline_ctx *ctx,
                                     struct inflight_slot *slot,
                                     uint32_t slot_index,
                                     uint64_t local_group_index,
                                     uint32_t *request_generation)
{
    struct nxp_local_io_position position = {
        .request_index = local_group_index,
    };
    struct io_uring_sqe *sqe;
    unsigned int private_tail;
    uint64_t total = 0;
    int ret;

    if (!ctx || !slot || !request_generation || !slot->segment_count ||
        nxp_wire_group_finish(&slot->rx_group) != 0 ||
        slot->rx_group.direction != NXP_IO_WRITE)
        return -EINVAL;
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        if (!slot->vector[i].iov_base || !slot->vector[i].iov_len)
            return -EINVAL;
        total += slot->vector[i].iov_len;
    }
    if (total != slot->rx_group.total_len || total != g_block_size)
        return -EMSGSIZE;
    ret = pipeline_validate_umem_vector(ctx, slot->vector,
                                        slot->segment_count, total);
    if (ret)
        return ret;
    ret = nxp_plan_nvme_io(&ctx->namespace, &ctx->io_limits, NXP_IO_WRITE,
                           &position, total, &slot->io_plan);
    if (ret)
        return ret;
    ret = nxp_request_prepare(&slot->request, slot_index,
                              request_generation);
    if (ret)
        return ret;
    private_tail = ctx->uring.ring.sq.sqe_tail;
    ret = pipeline_get_sqe(ctx, &sqe);
    if (ret)
        goto release;
    ret = fill_nvme_vector_sqe(ctx, sqe, slot->vector,
                               slot->segment_count, &slot->io_plan,
                               slot->request.token, 0);
    if (ret) {
        ctx->uring.ring.sq.sqe_tail = private_tail;
        goto release;
    }
    return 0;

release:
    (void)nxp_request_release_unaccepted(&slot->request, false);
    return ret;
}

static int register_fixed_buffers(struct pipeline_ctx *ctx,
                                  struct inflight_slot *slots, int depth)
{
    struct iovec *iov;
    unsigned int nr;
    int ret;

    if (!g_fixed_buffer)
        return 0;
    nr = g_staging ? (unsigned int)depth : 1;
    iov = calloc(nr, sizeof(*iov));
    if (!iov)
        return -ENOMEM;
    if (g_staging) {
        for (unsigned int i = 0; i < nr; i++) {
            iov[i].iov_base = slots[i].staging_buf;
            iov[i].iov_len = g_block_size;
        }
    } else {
        iov[0].iov_base = ctx->xsk.umem_area;
        iov[0].iov_len = UMEM_SIZE;
    }
    ret = io_uring_register_buffers(&ctx->uring.ring, iov, nr);
    free(iov);
    if (ret < 0)
        return ret;
    ctx->uring.fixed_buffer_registered = true;
    return 0;
}

static int pipeline_claim_cqe(struct pipeline_ctx *ctx,
                              struct inflight_slot *slots, int depth,
                              uint64_t token, uint32_t *slot_out)
{
    uint32_t slot = (uint32_t)token;
    int ret;

    if (slot >= (uint32_t)depth) {
        nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
        nxp_latch_error(&ctx->first_error, -EPROTO);
        return -EPROTO;
    }
    ret = nxp_request_complete(&slots[slot].request, token);
    if (ret) {
        nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
        nxp_latch_error(&ctx->first_error, -EPROTO);
        return -EPROTO;
    }
    *slot_out = slot;
    ret = pipeline_chain_nvme_complete(ctx, &slots[slot]);
    if (ret) {
        nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
        nxp_latch_error(&ctx->first_error, -EPROTO);
        return -EPROTO;
    }
    return 0;
}

static bool pipeline_has_owned_request(const struct inflight_slot *slots,
                                       int depth)
{
    for (int i = 0; i < depth; i++) {
        if (slots[i].request.owns_backing)
            return true;
    }
    return false;
}

/* A token/wait/submit attribution failure leaves an unknown command lifetime.
 * Closing the ring prevents further userspace publication, but is asynchronous
 * in this kernel and therefore cannot authorize recycling DMA backing.  Keep
 * every unmatched frame/staging buffer until process teardown. */
static int pipeline_retain_unmatched_requests(struct pipeline_ctx *ctx,
                                              struct inflight_slot *slots,
                                              int depth)
{
    int ret;

    if (!pipeline_has_owned_request(slots, depth))
        return 0;
    ctx->unmatched_io_retained = true;
    pipeline_update_backing_guard(ctx);
    ret = pipeline_close_ring(ctx);
    nxp_latch_error(&ctx->first_error, ret);
    if (ctx->first_error)
        return ctx->first_error;
    nxp_latch_error(&ctx->first_error, -EPROTO);
    return ctx->first_error;
}

static int pipeline_handle_cqe(struct pipeline_ctx *ctx,
                               struct inflight_slot *slots, int depth,
                               uint64_t token, int result,
                               struct pipeline_loop_state *flow,
                               uint32_t *slot_out)
{
    int ret;

    if (!flow || !slot_out)
        return -EINVAL;
    *slot_out = UINT32_MAX;
    ret = pipeline_claim_cqe(ctx, slots, depth, token, slot_out);
    if (ret) {
        flow->stop_issuing = true;
        flow->cqe_attribution_fault = true;
        return ret;
    }
    if (!result) {
        nxp_stats_note(&ctx->stats, NXP_STAT_READ_OK);
        return 0;
    }
    ret = nxp_nvme_result_errno(result);
    nxp_stats_note(&ctx->stats, NXP_STAT_READ_FAILED);
    nxp_latch_error(&ctx->first_error, ret);
    flow->stop_issuing = true;
    return ret;
}

static int pipeline_finish_nvme_fault(struct pipeline_ctx *ctx,
                                      struct inflight_slot *slots, int depth,
                                      struct pipeline_loop_state *flow)
{
    int ret;

    if (!flow || !flow->cqe_attribution_fault)
        return 0;
    ret = pipeline_retain_unmatched_requests(ctx, slots, depth);
    if (!pipeline_has_owned_request(slots, depth))
        flow->cqe_attribution_fault = false;
    return ret;
}

static int pipeline_handle_wait_failure(struct pipeline_ctx *ctx,
                                        struct inflight_slot *slots, int depth,
                                        int error,
                                        struct pipeline_loop_state *flow)
{
    if (!flow)
        return -EINVAL;
    for (int i = 0; i < depth; i++) {
        if (slots[i].request.state == NXP_REQ_ACCEPTED &&
            slots[i].request.owns_backing)
            (void)nxp_request_wait_failed(&slots[i].request, error);
    }
    nxp_latch_error(&ctx->first_error, error);
    flow->stop_issuing = true;
    flow->cqe_attribution_fault = true;
    return pipeline_finish_nvme_fault(ctx, slots, depth, flow);
}

/* The nonblocking drain feeds every probe result through this boundary.  An
 * empty/transient probe falls through to pipeline_wait_bounded(); a hard ring
 * error immediately stops publication and retains all unmatched DMA backing. */
static bool pipeline_handle_cqe_probe_result(
    struct pipeline_ctx *ctx, struct inflight_slot *slots, int depth,
    int probe_result, struct pipeline_loop_state *flow)
{
    if (!probe_result || nxp_retryable_error(probe_result, true))
        return false;
    (void)pipeline_handle_wait_failure(ctx, slots, depth, probe_result, flow);
    return true;
}

static bool pipeline_handle_kick_result(struct pipeline_ctx *ctx, int ret,
                                        struct pipeline_loop_state *flow)
{
    if (ret >= 0 || ret == -EAGAIN || ret == -EBUSY || ret == -ENOBUFS)
        return false;
    nxp_stats_note(&ctx->stats, NXP_STAT_KICK_ERROR);
    nxp_latch_error(&ctx->first_error, ret);
    if (flow)
        flow->stop_issuing = true;
    return true;
}

static void pipeline_handle_drop(struct pipeline_ctx *ctx, int error,
                                 struct pipeline_loop_state *flow)
{
    nxp_stats_note(&ctx->stats, NXP_STAT_DROP);
    nxp_latch_error(&ctx->first_error, error);
    if (flow)
        flow->stop_issuing = true;
}

/* After any fatal condition, exact NVMe CQEs are still consumed to terminate
 * DMA ownership, but their payloads must never cross a later publication
 * boundary.  Retire only the still-private IO_PENDING frame. */
static bool pipeline_discard_completed_after_fatal(
    struct pipeline_ctx *ctx, struct inflight_slot *slot,
    struct pipeline_loop_state *flow)
{
    if (!flow || (!flow->stop_issuing && !ctx->first_error))
        return false;
    if (pipeline_abort_group_frames(ctx, slot) != 0) {
        nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
        nxp_latch_error(&ctx->first_error, -EPROTO);
        ctx->xsk.protocol_invalidated = true;
    }
    pipeline_handle_drop(ctx, -ECANCELED, flow);
    return true;
}

/* Commit every ordinary-MTU packet produced by one logical NVMe command as
 * one AF_XDP producer transaction.  The NVMe command has already completed,
 * but each UMEM frame stays owned until its exact address appears on the XSK
 * completion ring. */
static int pipeline_submit_tx_group(struct pipeline_ctx *ctx,
                                    struct inflight_slot *slot,
                                    uint32_t descriptor_index)
{
    uint32_t packet_len[NXP_WIRE_MAX_SEGMENTS];
    int ret;

    if (!ctx || !slot || !slot->segment_count ||
        slot->segment_count != slot->wire_layout.segment_count ||
        slot->wire_layout.segment_count > NXP_WIRE_MAX_SEGMENTS ||
        ctx->xsk.protocol_invalidated)
        return -EINVAL;

    /* Complete every fallible packet/header check while all frames are still
     * private IO_PENDING objects, so a normal error can abort the whole group. */
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        struct nxp_wire_segment segment;
        uint64_t addr = slot->frame_addrs[i];

        /* The local producer filled this payload with an NVMe READ.  The wire
         * field names the only storage action authorized at the destination,
         * so a receiving endpoint sees a STORE/WRITE request and can never be
         * induced to perform a READ by network input. */
        ret = nxp_wire_segment_at(&slot->wire_layout, NXP_IO_WRITE, i,
                                  &segment);
        if (ret || addr >= UMEM_SIZE ||
            addr % FRAME_SIZE ||
            slot->vector[i].iov_base !=
                (unsigned char *)ctx->xsk.umem_area + addr +
                NXP_DATA_OFFSET ||
            slot->vector[i].iov_len != segment.payload_len ||
            xdev_ext_frame_state(&ctx->xsk.pool, addr / FRAME_SIZE) !=
                XDEV_EXT_FRAME_IO_PENDING)
            return ret ? ret : -EPROTO;
        ret = build_wire_packet(ctx,
                                (unsigned char *)ctx->xsk.umem_area + addr,
                                NULL, &segment, &packet_len[i]);
        if (ret)
            return ret;
    }
    if (nxp_data_headers(&slot->data_progress) != 0 ||
        nxp_data_publish(&slot->data_progress) != 0)
        return -EPROTO;

    for (uint16_t i = 0; i < slot->segment_count; i++) {
        uint64_t addr = slot->frame_addrs[i];

        if (xdev_ext_frame_publish(&ctx->xsk.pool, addr / FRAME_SIZE,
                              (uint32_t)slot->vector[i].iov_len) != 0 ||
            xdev_ext_frame_acquire_ready(&ctx->xsk.pool,
                                    addr / FRAME_SIZE, NULL) != 0 ||
            xdev_ext_frame_to_tx(&ctx->xsk.pool, addr / FRAME_SIZE, 1) != 0) {
            nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
            nxp_latch_error(&ctx->first_error, -EPROTO);
            ctx->xsk.protocol_invalidated = true;
            pipeline_update_backing_guard(ctx);
            return -EPROTO;
        }
    }
    for (uint16_t i = 0; i < slot->segment_count; i++) {
        struct xdp_desc *descriptor =
            xsk_ring_prod__tx_desc(&ctx->xsk.tx, descriptor_index + i);

        descriptor->addr = slot->frame_addrs[i] + PKT_START_OFF;
        descriptor->len = packet_len[i];
        descriptor->options = 0;
    }
    ret = pipeline_chain_publish_tx(ctx, slot);
    if (ret) {
        nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
        nxp_latch_error(&ctx->first_error, ret);
        ctx->xsk.protocol_invalidated = true;
        ctx->chain_sequestered = true;
        ctx->backing_quiescence_failed = true;
        return ret;
    }
    xsk_ring_prod__submit(&ctx->xsk.tx, slot->segment_count);
    for (uint16_t i = 0; i < slot->segment_count; i++)
        nxp_stats_note(&ctx->stats, NXP_STAT_TX_SUBMITTED);
    return 0;
}

static unsigned int ring_sq_head(const struct uring_ctx *uring)
{
    return __atomic_load_n(uring->ring.sq.khead, __ATOMIC_ACQUIRE);
}

/* Publish one prepared batch, then prove exactly how much of its prefix the
 * kernel accepted.  A zero/short/retryable enter keeps the published tail and
 * enters only the still-unaccepted suffix. */
static int submit_prepared_batch(struct pipeline_ctx *ctx,
                                 struct inflight_slot *slots,
                                 const int *order, unsigned int nr,
                                 unsigned int private_sqe_tail,
                                 unsigned int *accepted_out)
{
    unsigned int head_start, accepted = 0;
    unsigned int retries = NXP_MAX_TRANSIENT_RETRIES;
    int ret;

    *accepted_out = 0;
    /* io_uring_get_sqe() advances sqe_tail; those SQEs stay private until
     * submit flushes them by advancing sqe_head.  Re-prove the live device
     * immediately before that publication point; on failure, retract the
     * private suffix by restoring sqe_tail.  --revalidate-every thins this
     * to every Nth batch, or none, for the U' measurement arm only. */
    if (g_revalidate_every &&
        ctx->submit_batches++ % g_revalidate_every == 0) {
        ret = ctx->adapter->revalidate(ctx);
        if (ret) {
            ctx->uring.ring.sq.sqe_tail = private_sqe_tail;
            return ret;
        }
    }
    for (unsigned int i = 0; i < nr; i++) {
        ret = nxp_request_publish(&slots[order[i]].request);
        if (ret)
            return ret;
    }

    head_start = ring_sq_head(&ctx->uring);
    ret = ctx->adapter->submit(ctx);
    for (;;) {
        unsigned int now = ring_sq_head(&ctx->uring);
        unsigned int consumed = now - head_start;
        unsigned int proved;
        unsigned int accepted_before = accepted;
        unsigned int returned_proved = accepted_before;
        struct nxp_submit_result classification;

        /* Compare the kernel head against the original batch head.  A
         * successful submit/enter return can prove an accepted prefix before
         * the shared SQ head becomes observable; rebasing the unsigned head
         * on that inferred prefix would look like a wrap and falsely invalidate a
         * valid short submission. */
        classification = nxp_submit_classify(ret, nr, head_start, now);
        if (ret > 0) {
            unsigned int returned = (unsigned int)ret;

            if (returned > nr - accepted_before) {
                classification.invalidate = true;
                returned = nr - accepted_before;
            }
            returned_proved += returned;
        }
        if (consumed > nr) {
            classification.invalidate = true;
            consumed = nr;
        }
        proved = consumed > returned_proved ? consumed : returned_proved;
        while (accepted < proved) {
            struct inflight_slot *slot = &slots[order[accepted]];

            if (nxp_request_accept(&slot->request) != 0) {
                classification.invalidate = true;
                break;
            }
            if (pipeline_chain_nvme_accept(ctx, slot) != 0)
                classification.invalidate = true;
            nxp_stats_note(&ctx->stats, NXP_STAT_READ_ISSUED);
            accepted++;
        }
        *accepted_out = accepted;

        if (ret < 0)
            nxp_stats_note(&ctx->stats, NXP_STAT_SUBMIT_ERROR);
        if (classification.invalidate)
            return ret < 0 ? ret : -EUCLEAN;
        if (accepted == nr)
            return 0;
        if (accepted > accepted_before) {
            retries = NXP_MAX_TRANSIENT_RETRIES;
        } else {
            int terminal = nxp_retry_consume(ret ? ret : -EAGAIN, false,
                                             &retries);

            if (terminal) {
                nxp_stats_note(&ctx->stats, NXP_STAT_SUBMIT_ERROR);
                return terminal;
            }
        }
        sched_yield();
        ret = ctx->adapter->enter(ctx, nr - accepted);
    }
}

static int pipeline_publish_ready_tx_groups(struct pipeline_ctx *ctx,
                                            struct inflight_slot *slots,
                                            int depth,
                                            uint64_t *next_request,
                                            struct pipeline_loop_state *flow,
                                            unsigned int *published_out);

/* Staging NVMe->AF_XDP loop.  Each logical read lands in a separate registered
 * buffer, then scatters into an ordinary-MTU frame group.  -Q keeps multiple
 * reads in flight, batches the TX kick, and reclaims every frame exactly once. */
static int run_pipeline_batched(struct pipeline_ctx *ctx, uint64_t start_lba, int num_blocks)
{
    int depth = g_depth;
    if (depth > MAX_INFLIGHT) depth = MAX_INFLIGHT;

    struct inflight_slot *slots = calloc(depth, sizeof(*slots));
    if (!slots) {
        perror("calloc slots");
        nxp_latch_error(&ctx->first_error, -ENOMEM);
        return ctx->first_error;
    }
    /* frame addr 0 is VALID (first frame); INVALID marks an unbound slot */
    for (int s = 0; s < depth; s++)
        pipeline_clear_group(&slots[s]);

    if (g_staging) {
        for (int s = 0; s < depth; s++) {
            if (posix_memalign(&slots[s].staging_buf, 4096,
                               g_block_size)) {
                perror("posix_memalign staging");
                for (int j = 0; j < s; j++) free(slots[j].staging_buf);
                free(slots);
                nxp_latch_error(&ctx->first_error, -ENOMEM);
                return ctx->first_error;
            }
        }
    }

    {
        int ret = register_fixed_buffers(ctx, slots, depth);

        if (ret < 0) {
            fprintf(stderr, "fixed-buffer registration failed: %s\n",
                    strerror(-ret));
            if (g_staging)
                for (int s = 0; s < depth; s++) free(slots[s].staging_buf);
            free(slots);
            nxp_latch_error(&ctx->first_error, ret);
            return ctx->first_error;
        }
    }

    printf("Batched pipeline: depth=%d, %s, %d blocks from LBA %lu\n",
           depth, g_zerocopy ? "XDP_ZEROCOPY" : "XDP_COPY", num_blocks, start_lba);

    int next_issue = 0;     /* number of reads whose acceptance is proven */
    int finished_reads = 0; /* accepted reads with one terminal CQE */
    int inflight = 0;       /* reads currently in flight */
    long tx_pending_kick = 0; /* TX descs submitted since last kick */
    int slot_rr = 0;        /* round-robin search start for a free slot */
    int dbg = getenv("PIPE_DBG") != NULL;
    uint32_t generation = 0;
    uint64_t next_publish = 0;
    unsigned int frame_wait_retries = NXP_MAX_TRANSIENT_RETRIES;
    struct pipeline_loop_state flow = { 0 };
    long n_submits = 0, n_waits = 0, n_loops = 0, max_inflight = 0; long reap_hist[8] = {0};
    struct timespec t_start; clock_gettime(CLOCK_MONOTONIC, &t_start);
    #define ELAPSED_MS() ({ struct timespec _t; clock_gettime(CLOCK_MONOTONIC,&_t); \
        (_t.tv_sec - t_start.tv_sec)*1000.0 + (_t.tv_nsec - t_start.tv_nsec)/1e6; })

    /* Find a free slot (bound frame not IO_PENDING). Returns -1 if none. */
    #define FIND_FREE_SLOT(out) do {                       \
        out = -1;                                          \
        for (int _k = 0; _k < depth; _k++) {               \
            int _s = (slot_rr + _k) % depth;               \
            if (slot_is_free(&slots[_s])) { out = _s; slot_rr = (_s + 1) % depth; break; } \
        }                                                  \
    } while (0)

    while (finished_reads < num_blocks) {
        uint64_t reclaimed_before_loop = ctx->stats.tx_reclaimed;
        /* 1) Issue reads to fill the in-flight window. */
        int prepared_order[MAX_INFLIGHT];
        unsigned int prepared = 0;
        unsigned int private_sqe_tail = ctx->uring.ring.sq.sqe_tail;

        /* The retained-fd namespace epoch is revalidated in
         * submit_prepared_batch(), immediately before SQ publication.  The
         * kernel XDEV_EXT passthrough hook then validates live identity, geometry,
         * readiness, and command bounds after mapping and before dispatch. */
        while (!flow.cqe_attribution_fault && !flow.stop_issuing &&
               inflight + (int)prepared < depth &&
               next_issue + (int)prepared < num_blocks) {
            int slot;
            FIND_FREE_SLOT(slot);
            if (slot < 0) break;  /* no free slot (shouldn't happen: inflight<depth) */

            void *nvme_buf = slots[slot].staging_buf;
            struct nxp_nvme_read read;
            uint64_t block_index = (uint64_t)next_issue + prepared;
            uint32_t wire_generation = (uint32_t)block_index + 1;
            int ret;

            if (!wire_generation) {
                nxp_latch_error(&ctx->first_error, -EOVERFLOW);
                flow.stop_issuing = true;
                break;
            }
            ret = pipeline_prepare_staging_frames(
                ctx, &slots[slot], block_index, wire_generation);
            if (ret) {
                if (ret == -ENOBUFS)
                    break; /* drain published TX groups and retry */
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                break;
            }
            ret = nxp_encode_read(&ctx->namespace, &ctx->io_limits,
                                  start_lba, block_index, g_block_size,
                                  &read);
            if (ret < 0) {
                fprintf(stderr, "read preflight failed for block %lu: %s\n",
                        (unsigned long)block_index, strerror(-ret));
                (void)pipeline_abort_group_frames(ctx, &slots[slot]);
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                break;
            }
            ret = nxp_request_prepare(&slots[slot].request, (uint32_t)slot,
                                      &generation);
            if (ret < 0) {
                (void)pipeline_abort_group_frames(ctx, &slots[slot]);
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                break;
            }
            ret = prep_nvme_read_cmd(ctx, nvme_buf, &read,
                                     slots[slot].request.token,
                                     g_staging ? (uint16_t)slot : 0);
            if (ret < 0) {
                nxp_request_release_unaccepted(&slots[slot].request, false);
                (void)pipeline_abort_group_frames(ctx, &slots[slot]);
                if (!prepared) {
                    nxp_latch_error(&ctx->first_error, ret);
                    flow.stop_issuing = true;
                }
                break;
            }
            nxp_data_begin(&slots[slot].data_progress, g_staging);
            prepared_order[prepared++] = slot;
        }
        if (prepared && flow.stop_issuing) {
            ctx->uring.ring.sq.sqe_tail = private_sqe_tail;
            for (unsigned int i = 0; i < prepared; i++)
                (void)pipeline_abort_private_group(ctx,
                                                   &slots[prepared_order[i]]);
            prepared = 0;
        }
        if (prepared) {
            unsigned int accepted = 0;
            int ret = submit_prepared_batch(ctx, slots, prepared_order,
                                            prepared, private_sqe_tail,
                                            &accepted);

            n_submits++;
            inflight += (int)accepted;
            next_issue += (int)accepted;
            if (accepted)
                frame_wait_retries = NXP_MAX_TRANSIENT_RETRIES;
            if (ret < 0) {
                bool private_failure = accepted == 0 &&
                    slots[prepared_order[0]].request.state == NXP_REQ_PREPARED;

                fprintf(stderr, "NVMe batch failed after accepting %u/%u: %s\n",
                        accepted, prepared, strerror(-ret));
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                if (private_failure) {
                    for (unsigned int i = 0; i < prepared; i++) {
                        int slot = prepared_order[i];

                        if (pipeline_abort_private_group(
                                ctx, &slots[slot]) != 0) {
                            nxp_stats_note(&ctx->stats,
                                           NXP_STAT_PROTOCOL_ERROR);
                            nxp_latch_error(&ctx->first_error, -EPROTO);
                        }
                    }
                } else {
                    flow.cqe_attribution_fault = true;
                }
            }
        }
        if (inflight > max_inflight) max_inflight = inflight;
        n_loops++;

        /* 2) Drain NVMe completions non-blocking; build+TX each completed block. */
        struct io_uring_cqe *cqe;
        int reaped = 0;
        int probe_ret;
        bool fatal_cqe_probe = false;

        while ((probe_ret = pipeline_cqe_step(ctx, &cqe)) == 0) {
            uint64_t token = cqe->user_data;
            uint32_t slot;
            int result = cqe->res;
            io_uring_cqe_seen(&ctx->uring.ring, cqe);

            int cqe_ret = pipeline_handle_cqe(ctx, slots, depth, token,
                                              result, &flow, &slot);

            if (slot == UINT32_MAX) {
                fprintf(stderr, "BUG: wrong/duplicate CQE token=%#lx\n",
                        (unsigned long)token);
                continue;
            }
            void *nvme_buf = slots[slot].staging_buf;

            inflight--;
            reaped++;
            finished_reads++;

            if (cqe_ret != 0) {
                if (result < 0)
                    fprintf(stderr, "NVMe read errno %d (%s)\n", -result, strerror(-result));
                else
                    fprintf(stderr, "NVMe status 0x%x\n", result);
                (void)pipeline_abort_group_frames(ctx, &slots[slot]);
                continue;
            }

            if (pipeline_discard_completed_after_fatal(ctx, &slots[slot],
                                                       &flow))
                continue;

            if (nxp_data_dma_done(&slots[slot].data_progress) != 0) {
                nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
                nxp_latch_error(&ctx->first_error, -EPROTO);
                flow.stop_issuing = true;
                (void)pipeline_abort_group_frames(ctx, &slots[slot]);
                continue;
            }
            if (g_staging) {
                int copy_ret = pipeline_copy_staging_group(
                    ctx, &slots[slot]);

                if (copy_ret ||
                    nxp_data_copy(&slots[slot].data_progress) != 0) {
                    nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
                    nxp_latch_error(&ctx->first_error,
                                    copy_ret ? copy_ret : -EPROTO);
                    flow.stop_issuing = true;
                    (void)pipeline_abort_group_frames(ctx, &slots[slot]);
                    continue;
                }
                for (uint16_t i = 0; i < slots[slot].segment_count; i++)
                    process_data(slots[slot].vector[i].iov_base,
                                 slots[slot].vector[i].iov_len);
            } else {
                process_data(nvme_buf, g_block_size);
            }
            if (nxp_data_process(&slots[slot].data_progress) != 0) {
                nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
                nxp_latch_error(&ctx->first_error, -EPROTO);
                flow.stop_issuing = true;
                (void)pipeline_abort_group_frames(ctx, &slots[slot]);
                continue;
            }
            {
                int gpu_ret = pipeline_chain_gpu_roundtrip(
                    ctx, &slots[slot]);

                if (gpu_ret) {
                    nxp_latch_error(&ctx->first_error, gpu_ret);
                    flow.stop_issuing = true;
                    continue;
                }
            }
        }
        fatal_cqe_probe = pipeline_handle_cqe_probe_result(
            ctx, slots, depth, probe_ret, &flow);
        if (fatal_cqe_probe)
            fprintf(stderr, "io_uring completion probe failed: %s\n",
                    strerror(-probe_ret));
        if (!flow.stop_issuing && !flow.cqe_attribution_fault) {
            unsigned int published = 0;
            int ret = pipeline_publish_ready_tx_groups(
                ctx, slots, depth, &next_publish, &flow, &published);

            tx_pending_kick += published;
            if (ret) {
                if (ret == -EPROTO)
                    nxp_stats_note(&ctx->stats,
                                   NXP_STAT_PROTOCOL_ERROR);
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
            }
        }
        /* 3) Kick TX once for the whole batch, then reclaim completed frames. */
        if (tx_pending_kick) {
            int ret = xsk_tx_kick(&ctx->xsk);
            if (pipeline_handle_kick_result(ctx, ret, &flow)) {
                fprintf(stderr, "xsk_tx_kick: %s\n", strerror(-ret));
            }
            tx_pending_kick = 0;
        }
        xsk_tx_complete(ctx);
        if (ctx->first_error)
            flow.stop_issuing = true;
        if (fatal_cqe_probe)
            break;
        if (reaped || ctx->stats.tx_reclaimed != reclaimed_before_loop)
            frame_wait_retries = NXP_MAX_TRANSIENT_RETRIES;

        if (flow.cqe_attribution_fault && inflight == 0) {
            int ret = pipeline_finish_nvme_fault(ctx, slots, depth, &flow);

            if (ret < 0) {
                fprintf(stderr, "retaining unmatched NVMe DMA backing: %s\n",
                        strerror(-ret));
                nxp_latch_error(&ctx->first_error, ret);
                break;
            }
        }

        if (flow.stop_issuing && inflight == 0)
            break;

        /* 4) If we made no forward progress (no reap, can't issue), wait briefly so
         * we don't spin a core: either NVMe completions or TX frames are pending. */
        if (dbg) { reap_hist[reaped < 7 ? reaped : 7]++; }
        if (reaped == 0 && inflight > 0) {
            /* Bounded timed waits make repeated EINTR/EAGAIN/EBUSY and a
             * lost completion terminable.  If no exact CQE arrives, backing
             * remains retained because closing the ring is not a DMA proof. */
            n_waits++;
            int ret = pipeline_wait_bounded(ctx, &cqe);

            if (ret < 0) {
                (void)pipeline_handle_wait_failure(ctx, slots, depth,
                                                   ret, &flow);
                break;
            }
        } else if (reaped == 0 && inflight == 0 &&
                   next_issue >= num_blocks) {
            break;  /* nothing left */
        } else if (reaped == 0) {
            /* Frame-starved: drive TX completions so frames free up. */
            struct pollfd pfd = { .fd = ctx->xsk.xsk_fd, .events = POLLOUT };
            uint64_t reclaimed_before_wait = ctx->stats.tx_reclaimed;
            int ret = xsk_tx_kick(&ctx->xsk);

            (void)pipeline_handle_kick_result(ctx, ret, &flow);
            poll(&pfd, 1, 1);
            xsk_tx_complete(ctx);
            if (ctx->first_error)
                flow.stop_issuing = true;
            if (ctx->stats.tx_reclaimed != reclaimed_before_wait) {
                frame_wait_retries = NXP_MAX_TRANSIENT_RETRIES;
            } else if (!flow.stop_issuing) {
                ret = nxp_retry_consume(-EAGAIN, false,
                                        &frame_wait_retries);
                if (ret) {
                    nxp_stats_note(&ctx->stats, NXP_STAT_WAIT_ERROR);
                    nxp_latch_error(&ctx->first_error, ret);
                    flow.stop_issuing = true;
                }
            }
        }
    }

    if (!ctx->first_error && next_publish != (uint64_t)num_blocks) {
        nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
        nxp_latch_error(&ctx->first_error, -EPROTO);
    }

    if (dbg) {
        fprintf(stderr, "DBG: mainloop_done @%.1fms loops=%ld submits=%ld waits=%ld max_inflight=%ld free_frames=%u reap_hist[0..7]=%ld %ld %ld %ld %ld %ld %ld %ld\n",
                ELAPSED_MS(), n_loops, n_submits, n_waits, max_inflight, xdev_ext_pool_free_count(&ctx->xsk.pool),
                reap_hist[0],reap_hist[1],reap_hist[2],reap_hist[3],reap_hist[4],reap_hist[5],reap_hist[6],reap_hist[7]);
    }

    /* Drain only descriptors actually handed to AF_XDP.  Pool-free count also
     * includes non-TX lifecycle failures and therefore cannot prove TX drain. */
    {
        struct pollfd pfd = { .fd = ctx->xsk.xsk_fd, .events = POLLOUT };
        int spins = 0;
        while (ctx->stats.tx_reclaimed < ctx->stats.tx_submitted &&
               spins++ < 1000) {
            int ret = xsk_tx_kick(&ctx->xsk);
            if (pipeline_handle_kick_result(ctx, ret, &flow)) {
                fprintf(stderr, "xsk_tx_kick (drain): %s\n",
                        strerror(-ret));
            }
            poll(&pfd, 1, 1);
            xsk_tx_complete(ctx);
        }
        if (ctx->stats.tx_reclaimed < ctx->stats.tx_submitted) {
            uint64_t missing = pipeline_handle_xsk_drain_timeout(ctx);

            fprintf(stderr, "ERROR: %lu TX frame(s) never completed before drain timeout (spins=%d)\n",
                    (unsigned long)missing, spins);
        }
        if (dbg) fprintf(stderr, "DBG: drain_done @%.1fms spins=%d\n", ELAPSED_MS(), spins);
    }

    /* Host-observed AF_XDP completion rate.  A completion reclaims UMEM; it is
     * not evidence that the packet reached the wire or a remote receiver. */
    {
        double ms = ELAPSED_MS();
        double secs = ms / 1000.0;
        uint64_t completion_bytes =
            next_publish * (uint64_t)g_block_size +
            ctx->stats.tx_reclaimed *
                (uint64_t)(PKT_HDR_SIZE + NXP_WIRE_HEADER_LEN);
        double gbps = secs > 0 ? (completion_bytes * 8.0) / secs / 1e9 : 0;
        double mbps = secs > 0 ? completion_bytes / secs / 1e6 : 0;
        double cps  = secs > 0 ? ctx->stats.tx_reclaimed / secs : 0;
        fprintf(stderr,
            "RESULT: mode=%s depth=%d block=%u blocks=%d dataplane_ms=%.2f "
            "completion_Gbit/s=%.3f completion_MB/s=%.1f completions/s=%.0f "
            "completion_bytes=%llu (host reclaim, not wire delivery)\n",
            g_zerocopy ? "zerocopy" : "copy", depth, g_block_size,
            finished_reads,
            ms, gbps, mbps, cps,
            (unsigned long long)completion_bytes);
        fprintf(stderr, "STATS: read_issued=%lu read_ok=%lu read_failed=%lu "
                "submit_errors=%lu wait_errors=%lu tx_submitted=%lu tx_reclaimed=%lu "
                "kick_errors=%lu drops=%lu protocol_errors=%lu\n",
                (unsigned long)ctx->stats.read_issued,
                (unsigned long)ctx->stats.read_ok,
                (unsigned long)ctx->stats.read_failed,
                (unsigned long)ctx->stats.submit_errors,
                (unsigned long)ctx->stats.wait_errors,
                (unsigned long)ctx->stats.tx_submitted,
                (unsigned long)ctx->stats.tx_reclaimed,
                (unsigned long)ctx->stats.kick_errors,
                (unsigned long)ctx->stats.drops,
                (unsigned long)ctx->stats.protocol_errors);
    }

    if (!ctx->backing_quiescence_failed)
        (void)pipeline_unregister_buffers(ctx);
    /* An unmatched command has no synchronous teardown proof in this kernel.
     * Retain its staging/UMEM backing until process teardown even after a
     * successful ring close. */
    if (g_staging && !ctx->backing_quiescence_failed)
        for (int s = 0; s < depth; s++) free(slots[s].staging_buf);
    if (!ctx->backing_quiescence_failed)
        for (int s = 0; s < depth; s++)
            if (slots[s].segment_count &&
                !slots[s].request.owns_backing)
                (void)pipeline_abort_group_frames(ctx, &slots[s]);
    free(slots);
    #undef ELAPSED_MS
    #undef FIND_FREE_SLOT
    return ctx->first_error;
}

static int pipeline_reserve_tx_group(struct pipeline_ctx *ctx, uint16_t count,
                                     uint32_t *descriptor_index,
                                     struct pipeline_loop_state *flow)
{
    unsigned int retries = NXP_MAX_TRANSIENT_RETRIES;

    while (xsk_ring_prod__reserve(&ctx->xsk.tx, count,
                                   descriptor_index) != count) {
        int ret = xsk_tx_kick(&ctx->xsk);

        if (pipeline_handle_kick_result(ctx, ret, flow))
            return ret;
        xsk_tx_complete(ctx);
        if (ctx->first_error)
            return ctx->first_error;
        if (g_tx_full_poll) {
            struct pollfd pfd = {
                .fd = ctx->xsk.xsk_fd,
                .events = POLLOUT,
            };

            ret = poll(&pfd, 1, 1);
            if (ret < 0 && errno != EINTR)
                return -errno;
        } else {
            sched_yield();
        }
        ret = nxp_retry_consume(-EAGAIN, false, &retries);
        if (ret)
            return ret;
    }
    return 0;
}

static int pipeline_publish_ready_tx_groups(struct pipeline_ctx *ctx,
                                            struct inflight_slot *slots,
                                            int depth,
                                            uint64_t *next_request,
                                            struct pipeline_loop_state *flow,
                                            unsigned int *published_out)
{
    unsigned int published = 0;

    if (!ctx || !slots || !next_request || !flow || !published_out)
        return -EINVAL;
    *published_out = 0;

    while (!flow->stop_issuing && !flow->cqe_attribution_fault) {
        uint32_t descriptor_index = 0;
        struct inflight_slot *slot;
        uint16_t count;
        int slot_index;
        int ret;

        slot_index = pipeline_find_next_tx_group(slots, depth,
                                                 *next_request);
        if (slot_index == -EAGAIN)
            break;
        if (slot_index < 0)
            return slot_index;
        slot = &slots[slot_index];
        count = slot->segment_count;
        ret = pipeline_reserve_tx_group(ctx, count, &descriptor_index, flow);
        if (ret)
            return ret;
        ret = pipeline_submit_tx_group(ctx, slot, descriptor_index);
        if (ret) {
            /* No descriptor tail was published when the group helper fails.
             * Retract the producer reservation; a invalidated lifecycle keeps all
             * backing sequestered, otherwise normal cleanup can abort it. */
            ctx->xsk.tx.cached_prod -= count;
            if (ctx->xsk.protocol_invalidated)
                ctx->backing_quiescence_failed = true;
            return ret;
        }
        pipeline_clear_group(slot);
        (*next_request)++;
        published++;
        /* A later ready group can still fail validation or reservation after
         * this descriptor prefix has become visible to the kernel.  Report
         * each committed prefix immediately so the caller will kick/drain it
         * even when this helper returns an error for the tail. */
        *published_out = published;
    }
    return 0;
}

/* Default NVMe->NIC path.  One logical request is one fixed registered
 * NVME_URING_CMD_IO_VEC even when it is packetized into several ordinary-MTU
 * datagrams.  Accepted SQ prefixes are never re-prepared or replayed. */
static int run_vector_tx_pipeline(struct pipeline_ctx *ctx,
                                  uint64_t start_lba, int num_groups)
{
    struct nxp_wire_layout sizing;
    struct inflight_slot *slots;
    struct pipeline_loop_state flow = { 0 };
    uint32_t request_generation = 0;
    uint64_t next_publish = 0;
    int depth = g_depth;
    int next_issue = 0;
    int finished = 0;
    int inflight = 0;
    int slot_rr = 0;
    int ret;

    (void)start_lba;
    ret = nxp_wire_mtu_layout_plan(ctx->session_id, 1, g_block_size,
                                   ctx->mtu, FRAME_SIZE,
                                   NXP_LAYOUT_DATA_OFFSET,
                                   NXP_VECTOR_ALIGNMENT,
                                   &sizing);
    if (ret)
        return ret;
    if (depth < 1 || depth > MAX_INFLIGHT)
        return -EINVAL;
    ret = nxp_group_capacity_validate(
        (uint32_t)depth, sizing.segment_count, NUM_FRAMES,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
        XSK_RING_CONS__DEFAULT_NUM_DESCS,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
        XSK_RING_CONS__DEFAULT_NUM_DESCS);
    if (ret)
        return ret;

    slots = calloc((size_t)depth, sizeof(*slots));
    if (!slots)
        return -ENOMEM;
    for (int i = 0; i < depth; i++)
        pipeline_clear_group(&slots[i]);

    /* IO_VEC is deliberately fixed-only in the XDEV_EXT NVMe boundary. */
    g_fixed_buffer = 1;
    ret = register_fixed_buffers(ctx, slots, depth);
    if (ret) {
        free(slots);
        return ret;
    }

    while (finished < num_groups) {
        int order[MAX_INFLIGHT];
        unsigned int prepared = 0;
        unsigned int private_tail = ctx->uring.ring.sq.sqe_tail;
        int reaped = 0;
        struct io_uring_cqe *cqe;
        int probe_ret;

        while (!flow.stop_issuing && !flow.cqe_attribution_fault &&
               inflight + (int)prepared < depth &&
               next_issue + (int)prepared < num_groups) {
            int slot = -1;
            uint64_t request_index = (uint64_t)next_issue + prepared;
            uint32_t wire_generation = (uint32_t)request_index + 1;

            for (int off = 0; off < depth; off++) {
                int candidate = (slot_rr + off) % depth;

                if (slot_is_free(&slots[candidate])) {
                    slot = candidate;
                    slot_rr = (candidate + 1) % depth;
                    break;
                }
            }
            if (slot < 0)
                break;
            if (!wire_generation) {
                ret = -EOVERFLOW;
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                break;
            }
            ret = pipeline_prepare_tx_group(ctx, &slots[slot],
                                            (uint32_t)slot, request_index,
                                            &request_generation,
                                            wire_generation);
            if (ret == -ENOBUFS)
                break;
            if (ret) {
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                break;
            }
            order[prepared++] = slot;
        }

        if (prepared && flow.stop_issuing) {
            ctx->uring.ring.sq.sqe_tail = private_tail;
            for (unsigned int i = 0; i < prepared; i++)
                (void)pipeline_abort_private_group(ctx,
                                                   &slots[order[i]]);
            prepared = 0;
        }
        if (prepared) {
            unsigned int accepted = 0;

            ret = submit_prepared_batch(ctx, slots, order, prepared,
                                        private_tail, &accepted);
            inflight += (int)accepted;
            next_issue += (int)accepted;
            if (ret) {
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                /* Revalidation failure happens before publication and is the
                 * only ordinary path on which every prepared group is private. */
                if (!accepted &&
                    slots[order[0]].request.state == NXP_REQ_PREPARED) {
                    for (unsigned int i = 0; i < prepared; i++)
                        (void)pipeline_abort_private_group(
                            ctx, &slots[order[i]]);
                } else {
                    /* A published, unaccepted suffix is ambiguous too.  Keep
                     * all of its frame/iovec backing until process teardown. */
                    flow.cqe_attribution_fault = true;
                }
            }
        }

        while ((probe_ret = pipeline_cqe_step(ctx, &cqe)) == 0) {
            uint64_t token = cqe->user_data;
            uint32_t slot_index = UINT32_MAX;
            int result = cqe->res;
            int completion;
            struct inflight_slot *slot;

            io_uring_cqe_seen(&ctx->uring.ring, cqe);
            completion = pipeline_handle_cqe(ctx, slots, depth, token,
                                             result, &flow, &slot_index);
            if (slot_index == UINT32_MAX)
                continue;
            slot = &slots[slot_index];
            inflight--;
            finished++;
            reaped++;
            if (completion) {
                (void)pipeline_abort_group_frames(ctx, slot);
                continue;
            }
            if (pipeline_discard_completed_after_fatal(ctx, slot, &flow))
                continue;
            if (nxp_data_dma_done(&slot->data_progress) != 0) {
                nxp_latch_error(&ctx->first_error, -EPROTO);
                flow.stop_issuing = true;
                (void)pipeline_abort_group_frames(ctx, slot);
                continue;
            }
            for (uint16_t i = 0; i < slot->segment_count; i++)
                process_data(slot->vector[i].iov_base,
                             slot->vector[i].iov_len);
            if (nxp_data_process(&slot->data_progress) != 0) {
                nxp_latch_error(&ctx->first_error, -EPROTO);
                flow.stop_issuing = true;
                (void)pipeline_abort_group_frames(ctx, slot);
                continue;
            }
            ret = pipeline_chain_gpu_roundtrip(ctx, slot);
            if (ret) {
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                continue;
            }
        }

        if (pipeline_handle_cqe_probe_result(ctx, slots, depth, probe_ret,
                                             &flow))
            break;
        if (!flow.stop_issuing && !flow.cqe_attribution_fault) {
            unsigned int published = 0;

            ret = pipeline_publish_ready_tx_groups(ctx, slots, depth,
                                                   &next_publish, &flow,
                                                   &published);
            if (ret) {
                if (ret == -EPROTO)
                    nxp_stats_note(&ctx->stats,
                                   NXP_STAT_PROTOCOL_ERROR);
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
            }
        }
        ret = xsk_tx_kick(&ctx->xsk);
        (void)pipeline_handle_kick_result(ctx, ret, &flow);
        xsk_tx_complete(ctx);
        if (ctx->first_error)
            flow.stop_issuing = true;

        if (flow.cqe_attribution_fault && inflight == 0) {
            (void)pipeline_finish_nvme_fault(ctx, slots, depth, &flow);
            break;
        }
        if (flow.stop_issuing && inflight == 0)
            break;
        if (!reaped && inflight > 0) {
            ret = pipeline_wait_bounded(ctx, &cqe);
            if (ret) {
                (void)pipeline_handle_wait_failure(ctx, slots, depth,
                                                   ret, &flow);
                break;
            }
        } else if (!reaped && inflight == 0 && next_issue < num_groups) {
            struct pollfd pfd = {
                .fd = ctx->xsk.xsk_fd,
                .events = POLLOUT,
            };

            (void)poll(&pfd, 1, 1);
            xsk_tx_complete(ctx);
        }
    }

    if (!ctx->first_error && next_publish != (uint64_t)num_groups) {
        nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
        nxp_latch_error(&ctx->first_error, -EPROTO);
    }

    for (unsigned int retries = 0;
         ctx->stats.tx_reclaimed < ctx->stats.tx_submitted &&
         retries < NXP_MAX_TRANSIENT_RETRIES; retries++) {
        struct pollfd pfd = {
            .fd = ctx->xsk.xsk_fd,
            .events = POLLOUT,
        };

        (void)xsk_tx_kick(&ctx->xsk);
        (void)poll(&pfd, 1, 1);
        xsk_tx_complete(ctx);
    }
    if (ctx->stats.tx_reclaimed < ctx->stats.tx_submitted)
        (void)pipeline_handle_xsk_drain_timeout(ctx);

    if (!ctx->backing_quiescence_failed)
        (void)pipeline_unregister_buffers(ctx);
    if (ctx->backing_quiescence_failed) {
        /* slots contains live vector metadata for potentially accepted work. */
        return ctx->first_error ? ctx->first_error : -EPROTO;
    }
    for (int i = 0; i < depth; i++) {
        if (slots[i].segment_count && !slots[i].request.owns_backing)
            (void)pipeline_abort_group_frames(ctx, &slots[i]);
    }
    free(slots);
    return ctx->first_error;
}

static int pipeline_refill_rx_frames(struct pipeline_ctx *ctx,
                                     enum nxp_rx_frame_state *states,
                                     uint32_t *cursor)
{
    uint32_t frames[XSK_RING_PROD__DEFAULT_NUM_DESCS];
    uint32_t free_slots, count = 0, scan;
    uint32_t scanned = 0;
    uint32_t index;

    if (!ctx || !states || !cursor || !ctx->xsk.fq.size ||
        ctx->xsk.fq.size > XSK_RING_PROD__DEFAULT_NUM_DESCS)
        return -EINVAL;
    free_slots = xsk_prod_nb_free(&ctx->xsk.fq, ctx->xsk.fq.size);
    if (free_slots > ctx->xsk.fq.size)
        free_slots = ctx->xsk.fq.size;
    scan = *cursor;
    while (scanned < NUM_FRAMES && count < free_slots) {
        uint32_t frame = scan;

        scan = (scan + 1) % NUM_FRAMES;
        scanned++;
        if (states[frame] == NXP_RX_FRAME_FREE)
            frames[count++] = frame;
    }
    if (!count) {
        *cursor = scan;
        return 0;
    }
    if (xsk_ring_prod__reserve(&ctx->xsk.fq, count, &index) != count)
        return -EAGAIN;
    for (uint32_t i = 0; i < count; i++) {
        if (nxp_rx_frame_to_fill(&states[frames[i]]) != 0) {
            while (i)
                states[frames[--i]] = NXP_RX_FRAME_FREE;
            ctx->xsk.fq.cached_prod -= count;
            return -EPROTO;
        }
        *xsk_ring_prod__fill_addr(&ctx->xsk.fq, index + i) =
            (uint64_t)frames[i] * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&ctx->xsk.fq, count);
    *cursor = scan;
    return (int)count;
}

/* PIPELINE_RX_SUMMARY accounting of the latest run_rx_write_pipeline() call.
 * The definitions are those of the traditional recv() -> O_DIRECT baseline
 * (see nvme_xdp_pipeline_core.h); the arrays exist only during that call.
 * The RX frame helpers below count each frame they return to FREE. */
static struct nxp_rx_summary g_rx_summary;

static int pipeline_recycle_rx_group(enum nxp_rx_frame_state *states,
                                     struct inflight_slot *slot)
{
    int first = 0;

    for (uint16_t i = 0; i < slot->segment_count; i++) {
        uint64_t addr = slot->frame_addrs[i];
        uint32_t frame;
        int ret;

        if (addr >= UMEM_SIZE || addr % FRAME_SIZE) {
            first = first ? first : -EPROTO;
            continue;
        }
        frame = (uint32_t)(addr / FRAME_SIZE);
        ret = nxp_rx_frame_recycle_after_io(&states[frame]);
        if (ret)
            first = first ? first : ret;
        else
            nxp_rx_summary_note_frame_returned(&g_rx_summary);
    }
    pipeline_clear_group(slot);
    return first;
}

static int pipeline_chain_recycle_rx_group(
    struct pipeline_ctx *ctx, enum nxp_rx_frame_state *states,
    struct inflight_slot *slot)
{
    int ret = pipeline_chain_abort_slot(ctx, slot);

    if (ret)
        return ret;
    return pipeline_recycle_rx_group(states, slot);
}

/* A packet has already crossed the selective XDP boundary, but its wire
 * contents are still untrusted.  Malformed, stale-session, duplicate, and
 * out-of-order datagrams are ordinary input loss: recycle only that RX frame
 * and leave first_error untouched so a valid retry can still complete. */
static int pipeline_rx_drop_external(struct pipeline_ctx *ctx,
                                     enum nxp_rx_frame_state *states,
                                     uint32_t frame)
{
    int ret;

    if (!ctx || !states || frame >= NUM_FRAMES)
        return -EINVAL;
    ret = nxp_rx_frame_drop(&states[frame]);
    if (ret)
        return ret;
    nxp_rx_summary_note_frame_returned(&g_rx_summary);
    nxp_stats_note(&ctx->stats, NXP_STAT_DROP);
    return 0;
}

/* Do not let one missing UDP segment retain FQ frames forever.  Generation is
 * committed only after a complete group, so expiry permits the sender to
 * retry the same logical group without shifting the local NVMe request map. */
static int pipeline_rx_expire_group(struct pipeline_ctx *ctx,
                                    enum nxp_rx_frame_state *states,
                                    struct inflight_slot *slots,
                                    int *active_slot,
                                    uint64_t *started_ns,
                                    uint64_t now_ns)
{
    int ret;

    if (!ctx || !states || !slots || !active_slot || !started_ns)
        return -EINVAL;
    if (*active_slot < 0)
        return 0;
    if (*active_slot >= g_depth)
        return -ERANGE;
    if (now_ns < *started_ns ||
        now_ns - *started_ns < NXP_RX_GROUP_TIMEOUT_NS)
        return 0;
    ret = pipeline_chain_recycle_rx_group(ctx, states,
                                          &slots[*active_slot]);
    if (ret) {
        nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
        return ret;
    }
    *active_slot = -1;
    *started_ns = 0;
    nxp_stats_note(&ctx->stats, NXP_STAT_DROP);
    return 1;
}

static int pipeline_rx_wakeup(struct pipeline_ctx *ctx)
{
    int ret;

    if (!xsk_ring_prod__needs_wakeup(&ctx->xsk.fq))
        return 0;
    ret = recvfrom(ctx->xsk.xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
    if (ret < 0 && errno != EAGAIN && errno != EBUSY && errno != EINTR)
        return -errno;
    return 0;
}

/* Print the one PIPELINE_RX_SUMMARY line of an rx-write run whose receive
 * loop started, on success and on failure alike. */
static int pipeline_print_rx_summary(const struct rusage *start,
                                     const struct rusage *end)
{
    struct nxp_rx_summary_report report;
    char line[NXP_RX_SUMMARY_LINE_MAX];
    uint64_t user_us = nxp_cpu_delta_us(nxp_timeval_us(&start->ru_utime),
                                        nxp_timeval_us(&end->ru_utime));
    uint64_t sys_us = nxp_cpu_delta_us(nxp_timeval_us(&start->ru_stime),
                                       nxp_timeval_us(&end->ru_stime));
    int ret;

    ret = nxp_rx_summary_report(&g_rx_summary, user_us, sys_us, &report);
    if (!ret) {
        ret = nxp_rx_summary_format(&report, line, sizeof(line));
        if (ret >= 0) {
            printf("%s\n", line);
            ret = 0;
        }
    }
    fflush(stdout);
    return ret;
}

/* Graceful stop of rx-write.  SIGTERM or SIGINT received while the receive
 * loop runs records the signal; the loop then issues no new NVMe WRITE,
 * drains the ones in flight with the bounded completion wait, returns every
 * frame, prints PIPELINE_RX_SUMMARY and fails with -EINTR when groups are
 * left unwritten (nxp_rx_stop_result()).  A signal that was ignored when the
 * loop started stays ignored.  A run that retained DMA backing does not put
 * the previous (in production, default) action back: the teardown in main
 * still runs before pipeline_hold_unquiesced_backing() ignores these
 * signals, so such a run ignores them itself (pipeline_rx_stop_ignore()). */
static volatile sig_atomic_t g_rx_stop_signal;

struct pipeline_rx_stop_handlers {
    struct sigaction previous[2];
    bool replaced[2];
};

static const int pipeline_rx_stop_signals[2] = { SIGTERM, SIGINT };

static void pipeline_rx_stop_handler(int signo)
{
    g_rx_stop_signal = signo;
}

static int pipeline_rx_stop_signal(void)
{
    return (int)g_rx_stop_signal;
}

static void pipeline_rx_stop_restore(struct pipeline_rx_stop_handlers *saved)
{
    for (int i = 1; i >= 0; i--) {
        if (!saved->replaced[i])
            continue;
        (void)sigaction(pipeline_rx_stop_signals[i], &saved->previous[i],
                        NULL);
        saved->replaced[i] = false;
    }
}

/* Instead of the restore, for a run that retained DMA backing: every signal
 * the run took over is ignored from here on, as the hold will do.  Should
 * sigaction() fail, the recording handler stays, which does not terminate
 * the process either. */
static void pipeline_rx_stop_ignore(struct pipeline_rx_stop_handlers *saved)
{
    struct sigaction ignore;

    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    for (int i = 1; i >= 0; i--) {
        if (!saved->replaced[i])
            continue;
        (void)sigaction(pipeline_rx_stop_signals[i], &ignore, NULL);
        saved->replaced[i] = false;
    }
}

static int pipeline_rx_stop_install(struct pipeline_rx_stop_handlers *saved)
{
    struct sigaction action;

    memset(saved, 0, sizeof(*saved));
    memset(&action, 0, sizeof(action));
    action.sa_handler = pipeline_rx_stop_handler;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    g_rx_stop_signal = 0;
    for (int i = 0; i < 2; i++) {
        int signo = pipeline_rx_stop_signals[i];

        if (sigaction(signo, NULL, &saved->previous[i]) != 0)
            goto fail;
        if (saved->previous[i].sa_handler == SIG_IGN)
            continue;
        if (sigaction(signo, &action, NULL) != 0)
            goto fail;
        saved->replaced[i] = true;
    }
    return 0;
fail:
    {
        int ret = -errno;

        pipeline_rx_stop_restore(saved);
        return ret;
    }
}

/* A recorded stop request ends issuing; the caller keeps draining. */
static void pipeline_rx_note_stop(struct pipeline_loop_state *flow)
{
    if (g_rx_stop_signal)
        flow->stop_issuing = true;
}

/* NIC->NVMe WRITE path.  The peer supplies only ordered data offsets within a
 * CRC-checked logical group.  The namespace position is derived solely from
 * local start_lba/authorized_lbas and the local group counter. */
static int run_rx_write_pipeline(struct pipeline_ctx *ctx,
                                 uint64_t start_lba, int num_groups)
{
    struct nxp_wire_layout sizing;
    enum nxp_rx_frame_state *frame_states;
    struct inflight_slot *slots;
    struct nxp_rx_group_clock *group_clocks = NULL;
    uint64_t *service_ns = NULL;
    uint64_t *post_arrival_ns = NULL;
    struct rusage usage_start, usage_end;
    struct pipeline_loop_state flow = { 0 };
    struct pipeline_rx_stop_handlers stop_handlers = { 0 };
    uint32_t refill_cursor = 0;
    uint32_t request_generation = 0;
    uint32_t last_wire_generation = 0;
    uint64_t active_group_started_ns = 0;
    uint64_t rx_idle_deadline_ns = 0;
    uint64_t cqe_deadline_ns = 0;
    int active_slot = -1;
    int depth = g_depth;
    int next_group = 0;
    int finished = 0;
    int inflight = 0;
    int ret = 0;

    (void)start_lba;
    if (depth < 1 || depth > MAX_INFLIGHT)
        return -EINVAL;
    ret = nxp_wire_mtu_layout_plan(ctx->session_id, 1, g_block_size,
                                   ctx->mtu, FRAME_SIZE,
                                   NXP_LAYOUT_DATA_OFFSET,
                                   NXP_VECTOR_ALIGNMENT,
                                   &sizing);
    if (ret)
        return ret;
    ret = nxp_group_capacity_validate(
        (uint32_t)depth, sizing.segment_count, NUM_FRAMES,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
        XSK_RING_CONS__DEFAULT_NUM_DESCS,
        XSK_RING_PROD__DEFAULT_NUM_DESCS,
        XSK_RING_CONS__DEFAULT_NUM_DESCS);
    if (ret)
        return ret;
    slots = calloc((size_t)depth, sizeof(*slots));
    frame_states = calloc(NUM_FRAMES, sizeof(*frame_states));
    if (!slots || !frame_states) {
        free(slots);
        free(frame_states);
        return -ENOMEM;
    }
    for (int i = 0; i < depth; i++)
        pipeline_clear_group(&slots[i]);
    /* One clock per slot; one service-time and one post-arrival sample per
     * logical group. */
    group_clocks = calloc((size_t)depth, sizeof(*group_clocks));
    service_ns = calloc(num_groups > 0 ? (size_t)num_groups : 1,
                        sizeof(*service_ns));
    post_arrival_ns = calloc(num_groups > 0 ? (size_t)num_groups : 1,
                             sizeof(*post_arrival_ns));
    if (!group_clocks || !service_ns || !post_arrival_ns ||
        nxp_rx_summary_init(&g_rx_summary, service_ns,
                            num_groups > 0 ? (size_t)num_groups : 0,
                            group_clocks, (size_t)depth) != 0 ||
        nxp_rx_summary_track_post_arrival(
            &g_rx_summary, post_arrival_ns,
            num_groups > 0 ? (size_t)num_groups : 0) != 0) {
        free(group_clocks);
        free(service_ns);
        free(post_arrival_ns);
        free(slots);
        free(frame_states);
        return -ENOMEM;
    }

    g_fixed_buffer = 1;
    ret = register_fixed_buffers(ctx, slots, depth);
    if (ret)
        goto out;
    ret = pipeline_refill_rx_frames(ctx, frame_states, &refill_cursor);
    if (ret <= 0) {
        ret = ret ? ret : -ENOBUFS;
        goto out;
    }
    ret = pipeline_rx_wakeup(ctx);
    if (ret)
        goto out;
    {
        uint64_t now_ns;

        ret = ctx->adapter->monotonic_ns(ctx, &now_ns);
        if (ret)
            goto out;
        rx_idle_deadline_ns =
            now_ns > UINT64_MAX - NXP_RX_IDLE_TIMEOUT_NS ?
            UINT64_MAX : now_ns + NXP_RX_IDLE_TIMEOUT_NS;
    }
    ret = pipeline_rx_stop_install(&stop_handlers);
    if (ret)
        goto out;
    /* The receive loop starts here: from now on PIPELINE_RX_SUMMARY is
     * printed exactly once, whatever the outcome. */
    if (getrusage(RUSAGE_SELF, &usage_start) != 0) {
        ret = -errno;
        goto out;
    }

    while (finished < num_groups) {
        int order[MAX_INFLIGHT];
        unsigned int prepared = 0;
        unsigned int private_tail = ctx->uring.ring.sq.sqe_tail;
        struct io_uring_cqe *cqe;
        int probe_ret;
        int reaped = 0;
        uint32_t rx_index = 0;
        uint32_t available;
        uint32_t consumed = 0;

        pipeline_rx_note_stop(&flow);
        if (active_slot >= 0) {
            uint64_t now_ns;

            ret = ctx->adapter->monotonic_ns(ctx, &now_ns);
            if (ret) {
                nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
            } else {
                ret = pipeline_rx_expire_group(
                    ctx, frame_states, slots, &active_slot,
                    &active_group_started_ns, now_ns);
                if (ret < 0) {
                    nxp_latch_error(&ctx->first_error, ret);
                    flow.stop_issuing = true;
                } else if (ret > 0) {
                    rx_idle_deadline_ns =
                        now_ns > UINT64_MAX - NXP_RX_IDLE_TIMEOUT_NS ?
                        UINT64_MAX : now_ns + NXP_RX_IDLE_TIMEOUT_NS;
                }
            }
        }

        while ((probe_ret = pipeline_cqe_step(ctx, &cqe)) == 0) {
            uint32_t slot_index = UINT32_MAX;
            int completion;

            completion = pipeline_handle_cqe(ctx, slots, depth,
                                             cqe->user_data, cqe->res,
                                             &flow, &slot_index);
            io_uring_cqe_seen(&ctx->uring.ring, cqe);
            if (slot_index == UINT32_MAX)
                continue;
            inflight--;
            finished++;
            reaped++;
            {
                /* This group's NVMe WRITE CQE was reaped: the end of its
                 * service time, and of the wall clock so far. */
                uint64_t done_ns = 0;
                int clock_ret = ctx->adapter->monotonic_ns(ctx, &done_ns);

                if (clock_ret) {
                    nxp_latch_error(&ctx->first_error, clock_ret);
                    flow.stop_issuing = true;
                }
                if (nxp_rx_summary_note_completion(
                        &g_rx_summary, slot_index, completion == 0,
                        g_block_size, clock_ret ? NULL : &done_ns) != 0) {
                    nxp_latch_error(&ctx->first_error, -EPROTO);
                    flow.stop_issuing = true;
                }
            }
            /* An exact CQE ends NVMe DMA ownership on both success and error. */
            if (pipeline_chain_recycle_rx_group(
                    ctx, frame_states, &slots[slot_index]) != 0) {
                nxp_latch_error(&ctx->first_error, -EPROTO);
                flow.stop_issuing = true;
            }
            if (completion)
                flow.stop_issuing = true;
        }
        if (pipeline_handle_cqe_probe_result(ctx, slots, depth, probe_ret,
                                             &flow))
            break;
        /* A reaped CQE re-arms the bound on the next completion. */
        if (reaped)
            cqe_deadline_ns = 0;
        ret = pipeline_refill_rx_frames(ctx, frame_states, &refill_cursor);
        if (ret < 0) {
            nxp_latch_error(&ctx->first_error, ret);
            flow.stop_issuing = true;
        }
        if (flow.cqe_attribution_fault && inflight == 0) {
            (void)pipeline_finish_nvme_fault(ctx, slots, depth, &flow);
            break;
        }
        if (flow.stop_issuing && inflight == 0)
            break;

        available = flow.stop_issuing ? 0 :
            xsk_ring_cons__peek(&ctx->xsk.rx, QUEUE_DEPTH, &rx_index);
        while (consumed < available &&
               inflight + (int)prepared < depth &&
               next_group + (int)prepared < num_groups) {
            const struct xdp_desc *descriptor =
                xsk_ring_cons__rx_desc(&ctx->xsk.rx,
                                       rx_index + consumed);
            uint64_t base;
            uint64_t data_addr;
            struct pipeline_rx_packet packet;
            uint32_t frame = UINT32_MAX;
            uint16_t segment_index;
            struct inflight_slot *slot;
            uint64_t packet_ns = 0;
            bool packet_timed = false;
            bool packet_accepted = false;
            int drop_ret;

            /* Read the arrival time only for a packet that starts the wall
             * clock, may be the first accepted packet of a group, or may
             * complete the group (its arrival ends rx_span_us and starts the
             * group's post-arrival time). */
            if (!g_rx_summary.first_rx_seen || active_slot < 0 ||
                !slots[active_slot].segment_count ||
                slots[active_slot].rx_group.next_segment + 1 >=
                    slots[active_slot].rx_group.segment_count) {
                ret = ctx->adapter->monotonic_ns(ctx, &packet_ns);
                if (ret) {
                    /* Not consumed: the descriptor stays unexamined. */
                    nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
                    nxp_latch_error(&ctx->first_error, ret);
                    flow.stop_issuing = true;
                    break;
                }
                packet_timed = true;
            }
            consumed++;
            if (packet_timed)
                nxp_rx_summary_note_rx(&g_rx_summary, packet_ns);
            ret = pipeline_decode_rx_descriptor(descriptor, &base,
                                                &data_addr);
            if (ret)
                goto rx_protocol_error;
            frame = (uint32_t)(base / FRAME_SIZE);
            ret = nxp_rx_frame_to_received(&frame_states[frame]);
            if (ret)
                goto rx_protocol_error;
            nxp_rx_summary_note_frame_received(&g_rx_summary);
            ret = parse_wire_packet(ctx,
                                    (unsigned char *)ctx->xsk.umem_area +
                                    data_addr, descriptor->len, &packet);
            if (ret)
                goto rx_external_drop;
            ret = pipeline_validate_rx_packet(ctx, &packet);
            if (ret)
                goto rx_external_drop;
            if (active_slot < 0) {
                for (int i = 0; i < depth; i++) {
                    if (slot_is_free(&slots[i])) {
                        active_slot = i;
                        break;
                    }
                }
                if (active_slot < 0) {
                    ret = -ENOBUFS;
                    goto rx_external_drop;
                }
                slots[active_slot].rx_group.last_generation =
                    last_wire_generation;
                ret = nxp_wire_group_begin(
                    &slots[active_slot].rx_group,
                    ctx->session_id, packet.segment.generation, NXP_IO_WRITE,
                    packet.segment.total_len,
                    packet.segment.segment_count);
                if (ret) {
                    active_slot = -1;
                    goto rx_external_drop;
                }
                ret = ctx->adapter->monotonic_ns(
                    ctx, &active_group_started_ns);
                if (ret)
                    goto rx_protocol_error;
                slots[active_slot].collecting_rx = true;
                slots[active_slot].block_index =
                    (uint64_t)next_group + prepared;
            }
            slot = &slots[active_slot];
            ret = nxp_wire_group_accept(&slot->rx_group,
                                        &packet.segment);
            if (ret)
                goto rx_external_drop;
            packet_accepted = true;
            nxp_rx_summary_note_packet(&g_rx_summary, true);
            if (!slot->segment_count) {
                /* The first accepted packet of this group: its service
                 * time starts at this packet's arrival. */
                ret = packet_timed ?
                    nxp_rx_summary_arm_group(&g_rx_summary,
                                             (uint32_t)active_slot,
                                             packet_ns) : -EPROTO;
                if (ret)
                    goto rx_protocol_error;
            }
            ret = nxp_rx_frame_hold_for_io(&frame_states[frame]);
            if (ret)
                goto rx_protocol_error;
            if (slot->segment_count >= NXP_WIRE_MAX_SEGMENTS) {
                ret = -E2BIG;
                goto rx_protocol_error;
            }
            segment_index = slot->segment_count;
            slot->frame_addrs[segment_index] = base;
            slot->vector[segment_index] = (struct iovec) {
                .iov_base = packet.data,
                .iov_len = packet.data_len,
            };
            /* From this point cleanup owns the current IO-held frame even if
             * composite journal setup fails before accepting the next stage. */
            slot->segment_count++;
            ret = pipeline_chain_begin_rx_frame(
                ctx, slot, segment_index, slot->block_index,
                packet.segment.generation, base);
            if (ret)
                goto rx_protocol_error;
            slot->frame_addr = slot->frame_addrs[0];

            if (nxp_wire_group_finish(&slot->rx_group) == 0) {
                /* This packet completed the group: the group arrived. */
                ret = packet_timed ?
                    nxp_rx_summary_note_group_arrived(&g_rx_summary,
                                                      (uint32_t)active_slot,
                                                      packet_ns) : -EPROTO;
                if (ret)
                    goto rx_protocol_error;
                ret = pipeline_chain_gpu_roundtrip(ctx, slot);
                if (ret)
                    goto rx_protocol_error;
                ret = pipeline_prepare_rx_write(
                    ctx, slot, (uint32_t)active_slot,
                    (uint64_t)next_group + prepared,
                    &request_generation);
                if (ret) {
                    /* A complete group whose WRITE cannot be submitted. */
                    nxp_rx_summary_note_submit_failed(&g_rx_summary, 1);
                    goto rx_protocol_error;
                }
                slot->collecting_rx = false;
                last_wire_generation = packet.segment.generation;
                order[prepared++] = active_slot;
                active_slot = -1;
                active_group_started_ns = 0;
            }
            continue;

rx_external_drop:
            drop_ret = pipeline_rx_drop_external(ctx, frame_states, frame);
            if (drop_ret) {
                ret = drop_ret;
                goto rx_protocol_error;
            }
            nxp_rx_summary_note_packet(&g_rx_summary, false);
            continue;
rx_protocol_error:
            /* An examined packet is counted once: accepted above, or here. */
            if (!packet_accepted)
                nxp_rx_summary_note_packet(&g_rx_summary, false);
            if (frame < NUM_FRAMES &&
                frame_states[frame] == NXP_RX_FRAME_RECEIVED &&
                nxp_rx_frame_drop(&frame_states[frame]) == 0)
                nxp_rx_summary_note_frame_returned(&g_rx_summary);
            nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
            nxp_latch_error(&ctx->first_error, ret ? ret : -EPROTO);
            flow.stop_issuing = true;
            if (active_slot >= 0) {
                (void)pipeline_chain_recycle_rx_group(
                    ctx, frame_states, &slots[active_slot]);
                active_slot = -1;
                active_group_started_ns = 0;
            }
            break;
        }
        /* Hand back what was peeked but not consumed (depth or -n limit,
         * or a stop): those descriptors stay on the RX ring, unexamined. */
        if (available > consumed)
            xsk_ring_cons__cancel(&ctx->xsk.rx, available - consumed);
        if (consumed)
            xsk_ring_cons__release(&ctx->xsk.rx, consumed);

        /* A stop received while this batch was examined still keeps its
         * prepared WRITEs from being issued. */
        pipeline_rx_note_stop(&flow);
        if (prepared && flow.stop_issuing) {
            ctx->uring.ring.sq.sqe_tail = private_tail;
            for (unsigned int i = 0; i < prepared; i++) {
                (void)nxp_request_release_unaccepted(
                    &slots[order[i]].request, false);
                (void)pipeline_chain_recycle_rx_group(
                    ctx, frame_states, &slots[order[i]]);
            }
            prepared = 0;
        }
        if (prepared) {
            unsigned int accepted = 0;

            ret = submit_prepared_batch(ctx, slots, order, prepared,
                                        private_tail, &accepted);
            inflight += (int)accepted;
            next_group += (int)accepted;
            nxp_rx_summary_note_submitted(&g_rx_summary, accepted);
            if (ret) {
                /* Complete groups whose WRITE the kernel did not accept. */
                nxp_rx_summary_note_submit_failed(&g_rx_summary,
                                                  prepared - accepted);
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
                if (!accepted &&
                    slots[order[0]].request.state == NXP_REQ_PREPARED) {
                    for (unsigned int i = 0; i < prepared; i++) {
                        (void)nxp_request_release_unaccepted(
                            &slots[order[i]].request, false);
                        (void)pipeline_chain_recycle_rx_group(
                            ctx, frame_states, &slots[order[i]]);
                    }
                } else {
                    flow.cqe_attribution_fault = true;
                }
            }
        }
        ret = pipeline_refill_rx_frames(ctx, frame_states, &refill_cursor);
        if (ret < 0) {
            nxp_latch_error(&ctx->first_error, ret);
            flow.stop_issuing = true;
        }
        ret = pipeline_rx_wakeup(ctx);
        if (ret) {
            nxp_latch_error(&ctx->first_error, ret);
            flow.stop_issuing = true;
        }

        if (reaped || consumed || prepared) {
            uint64_t now_ns;

            ret = ctx->adapter->monotonic_ns(ctx, &now_ns);
            if (ret) {
                nxp_latch_error(&ctx->first_error, ret);
                flow.stop_issuing = true;
            } else {
                rx_idle_deadline_ns =
                    now_ns > UINT64_MAX - NXP_RX_IDLE_TIMEOUT_NS ?
                    UINT64_MAX : now_ns + NXP_RX_IDLE_TIMEOUT_NS;
            }
            continue;
        }
        if (inflight > 0) {
            /* Packets arriving while WRITEs are in flight are noticed
             * without waiting for a CQE, whenever the loop could take them
             * (same conditions as the RX loop above). */
            bool watch_rx = !flow.stop_issuing && inflight < depth &&
                            next_group < num_groups;
            int rx_error = 0;

            ret = pipeline_rx_wait_bounded(ctx, &cqe_deadline_ns, watch_rx,
                                           &rx_error);
            if (ret) {
                (void)pipeline_handle_wait_failure(ctx, slots, depth,
                                                   ret, &flow);
                break;
            }
            if (rx_error) {
                /* The XSK socket failed: stop issuing, keep draining. */
                nxp_latch_error(&ctx->first_error, rx_error);
                flow.stop_issuing = true;
            }
        } else {
            struct pollfd pfd = {
                .fd = ctx->xsk.xsk_fd,
                .events = POLLIN,
            };

            ret = poll(&pfd, 1, 10);
            if (ret < 0 && errno != EINTR) {
                nxp_latch_error(&ctx->first_error, -errno);
                flow.stop_issuing = true;
            } else {
                uint64_t now_ns;
                int idle_ret;

                if (ret < 0)
                    ret = 0; /* EINTR shares the same absolute deadline. */
                idle_ret = ctx->adapter->monotonic_ns(ctx, &now_ns);
                if (!idle_ret)
                    idle_ret = nxp_rx_idle_poll_result(
                        ret, pfd.revents, now_ns, rx_idle_deadline_ns);
                if (idle_ret != -EAGAIN) {
                    nxp_latch_error(&ctx->first_error, idle_ret);
                    flow.stop_issuing = true;
                }
                ret = 0;
            }
        }
    }
    if (getrusage(RUSAGE_SELF, &usage_end) != 0)
        usage_end = usage_start;
    {
        uint64_t end_ns;

        /* Without any completion, the wall clock ends with the loop. */
        if (ctx->adapter->monotonic_ns(ctx, &end_ns) == 0)
            nxp_rx_summary_note_loop_end(&g_rx_summary, end_ns);
    }

    if (active_slot >= 0 && !slots[active_slot].request.owns_backing)
        (void)pipeline_chain_recycle_rx_group(
            ctx, frame_states, &slots[active_slot]);
    {
        /* Every frame the loop received must have been returned exactly
         * once.  A frame still RECEIVED or IO here was never released (or is
         * retained with unproven NVMe DMA): report it and fail closed. */
        struct nxp_rx_frame_census census;

        if (nxp_rx_frame_census_take(frame_states, NUM_FRAMES,
                                     &census) != 0 ||
            nxp_rx_summary_note_census(&g_rx_summary, &census) != 0) {
            nxp_stats_note(&ctx->stats, NXP_STAT_PROTOCOL_ERROR);
            nxp_latch_error(&ctx->first_error, -EPROTO);
        }
    }
    if (nxp_rx_stop_result(pipeline_rx_stop_signal(), (uint64_t)finished,
                           (uint64_t)num_groups) != 0) {
        fprintf(stderr,
                "rx-write stopped by signal %d after %d of %d group(s)\n",
                pipeline_rx_stop_signal(), finished, num_groups);
        nxp_latch_error(&ctx->first_error, -EINTR);
    }
    if (pipeline_print_rx_summary(&usage_start, &usage_end) != 0)
        nxp_latch_error(&ctx->first_error, -EPROTO);
out:
    g_rx_summary.service_ns = NULL;
    g_rx_summary.service_capacity = 0;
    g_rx_summary.post_arrival_ns = NULL;
    g_rx_summary.post_arrival_capacity = 0;
    g_rx_summary.clocks = NULL;
    g_rx_summary.clock_count = 0;
    free(service_ns);
    free(post_arrival_ns);
    free(group_clocks);
    if (!ctx->backing_quiescence_failed &&
        ctx->uring.fixed_buffer_registered)
        (void)pipeline_unregister_buffers(ctx);
    /* Decided after the unregistration, whose failure also retains the
     * backing: a retaining run never gets the default action back. */
    if (pipeline_retains_backing(ctx))
        pipeline_rx_stop_ignore(&stop_handlers);
    else
        pipeline_rx_stop_restore(&stop_handlers);
    if (ctx->backing_quiescence_failed)
        return ctx->first_error ? ctx->first_error : -EPROTO;
    free(frame_states);
    free(slots);
    if (ret < 0)
        nxp_latch_error(&ctx->first_error, ret);
    return ctx->first_error;
}

/* Main pipeline loop using io_uring unified ops */
static int run_pipeline(struct pipeline_ctx *ctx, uint64_t start_lba, int num_blocks)
{
    /* This hint syscall is optional instrumentation; it does not enable NVMe
     * polling and a missing custom syscall must not change I/O correctness. */
    (void)setup_sched_hints(100000, 50000, num_blocks);
    if (!g_staging || g_direction == PIPELINE_NIC_TO_NVME)
        g_fixed_buffer = 1;

    printf("Starting %s pipeline: depth=%d "
           "session=%llu file=%s buffer=%s nvme_completion=%s "
           "tx_full_wait=%s staging=%s transform=%s\n",
           g_direction == PIPELINE_NIC_TO_NVME ?
               "AF_XDP -> NVMe URING_CMD WRITE" :
               "NVMe URING_CMD READ -> AF_XDP",
           g_depth, (unsigned long long)ctx->session_id,
           g_fixed_file ? "fixed" : "ordinary",
           g_fixed_buffer ? "fixed" : "ordinary",
           g_iopoll ? "iopoll" : "cq-wait",
           g_tx_full_poll ? "poll" : "spin",
           g_staging ? "copy" : "direct",
           g_transform == PIPELINE_TRANSFORM_XOR ? "xor" : "none");
    printf("Transferring %d logical group(s) at local LBA %lu using verified namespace geometry\n",
           num_blocks, start_lba);
    if (g_direction == PIPELINE_NIC_TO_NVME)
        return run_rx_write_pipeline(ctx, start_lba, num_blocks);
    if (!g_staging)
        return run_vector_tx_pipeline(ctx, start_lba, num_blocks);
    return run_pipeline_batched(ctx, start_lba, num_blocks);
}

/* Parse MAC address */
static int parse_mac(const char *str, uint8_t *mac)
{
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ? 0 : -1;
}

static int get_iface_mac(const char *ifname, uint8_t mac[6])
{
    struct ifreq ifr;
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        ret = -errno;
        close(fd);
        return ret;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int get_iface_mtu(const char *ifname, uint32_t *mtu)
{
    struct ifreq ifr;
    int fd, ret;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ret = ioctl(fd, SIOCGIFMTU, &ifr);
    if (ret < 0)
        ret = -errno;
    else if (ifr.ifr_mtu <= 0)
        ret = -EINVAL;
    else {
        *mtu = (uint32_t)ifr.ifr_mtu;
        ret = 0;
    }
    close(fd);
    return ret;
}

static void pipeline_hold_unquiesced_backing(const char *reason)
    __attribute__((noreturn));

static void pipeline_hold_unquiesced_backing(const char *reason)
{
    (void)signal(SIGHUP, SIG_IGN);
    (void)signal(SIGINT, SIG_IGN);
    (void)signal(SIGQUIT, SIG_IGN);
    (void)signal(SIGTERM, SIG_IGN);
    fprintf(stderr,
            "%s; retaining process, device/ring fds, and DMA backing. Reset "
            "or independently prove every device quiescent before SIGKILL.\n",
            reason ? reason : "DMA/CQ ownership is unproven");
    fflush(NULL);
    for (;;)
        (void)pause();
}

#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
static int pipeline_random_chain_id(uint64_t *identity)
{
    ssize_t bytes;

    if (!identity)
        return -EINVAL;
    do {
        bytes = getrandom(identity, sizeof(*identity), 0);
    } while (bytes < 0 && errno == EINTR);
    if (bytes < 0)
        return -errno;
    if (bytes != (ssize_t)sizeof(*identity) || !*identity)
        return -ENODATA;
    return 0;
}
#endif

/* Print usage */
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "\nBidirectional NVMe <-> AF_XDP pipeline using io_uring unified ops\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -d <device>     NVMe device (default: /dev/ng0n1 for char device)\n");
    fprintf(stderr, "  -k <device>     Matching whole-namespace block device (default: derive from sysfs)\n");
    fprintf(stderr, "  -i <interface>  Network interface (default: eth0)\n");
    fprintf(stderr, "  -q <queue>      XDP queue ID (default: 0)\n");
    fprintf(stderr, "  -l <lba>        Start LBA (default: 0)\n");
    fprintf(stderr, "  -n <groups>     Number of logical transfers (default: 10)\n");
    fprintf(stderr, "  -m <mode>       Direction: tx (NVMe->NIC, default) or rx-write (NIC->NVMe)\n");
    fprintf(stderr, "  -D <mac>        Destination MAC (default: ff:ff:ff:ff:ff:ff)\n");
    fprintf(stderr, "  -S <mac>        Source MAC (default: interface hardware MAC)\n");
    fprintf(stderr, "  -a <ip>         Destination IP (default: 192.168.1.1)\n");
    fprintf(stderr, "  -s <ip>         Source IP (default: 192.168.1.2)\n");
    fprintf(stderr, "  -p <port>       Destination port (default: 12345)\n");
    fprintf(stderr, "  -P <port>       Source port (default: 54321)\n");
    fprintf(stderr, "  -e <session>    Required nonzero 64-bit session identity; peers must match\n");
    fprintf(stderr, "  -t <transform>  TX payload transform: none (default) or xor (diagnostic); rx-write requires none\n");
    fprintf(stderr, "  -b <lba_size>   Assert the device-reported LBA size (never overrides device geometry)\n");
    fprintf(stderr, "  -B <bytes>      Bytes per logical NVMe command (default: 8192; total LBA-aligned; MTU segments 8-byte aligned)\n");
    fprintf(stderr, "  -Z              Staging mode: NVMe->separate buf->memcpy->UMEM (diagnostic; no zero-copy DMA into pinned UMEM)\n");
    fprintf(stderr, "  -Q <depth>      Batched pipeline: max logical NVMe commands in flight (default 1; bounded by frames and every XSK ring)\n");
    fprintf(stderr, "  -C              Force AF_XDP copy bind (XDP_COPY)\n");
    fprintf(stderr, "  -z              AF_XDP zero-copy bind (default; falls back to XDP_COPY if unavailable)\n");
    fprintf(stderr, "  -W              AF_XDP TX-ring-full wait: poll(POLLOUT); NVMe completions stay CQ-driven\n");
    fprintf(stderr, "  -F              Register the retained NVMe character fd (fixed-file arm)\n");
    fprintf(stderr, "  -R              Register UMEM/staging buffers (fixed-buffer arm)\n");
    fprintf(stderr, "  -I              IOPOLL arm; fail unless controller poll queues and this namespace io_poll=1 are proven\n");
#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
    fprintf(stderr, "  -g <device>     Required NVIDIA GPU character device for the synchronous CE roundtrip\n");
#endif
    fprintf(stderr, "  --revalidate-every <n>\n"
                    "                  Measurement only: re-prove the namespace before every nth submit\n"
                    "                  batch (default: 1, every batch; 0: never)\n");
    fprintf(stderr, "  -h              Show this help\n");
    fprintf(stderr, "\nNote: Use NVMe character device (e.g., /dev/ng0n1) for URING_CMD\n");
}

#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
#define NXP_PIPELINE_GETOPT "d:k:i:q:l:n:m:D:S:a:s:p:P:e:t:b:B:g:ZQ:CzWFRIh"
#else
#define NXP_PIPELINE_GETOPT "d:k:i:q:l:n:m:D:S:a:s:p:P:e:t:b:B:ZQ:CzWFRIh"
#endif

/* Long-only options use values outside the short-option character range. */
enum {
    NXP_OPT_REVALIDATE_EVERY = 0x100,
};

static const struct option nxp_pipeline_long_options[] = {
    { "revalidate-every", required_argument, NULL, NXP_OPT_REVALIDATE_EVERY },
    { NULL, 0, NULL, 0 },
};

int main(int argc, char **argv)
{
    struct pipeline_ctx ctx;
    int opt;
    uint64_t start_lba = 0;
    int num_blocks = 10;
    int src_mac_set = 0;
    int ret;
    int exit_status = 1;
    int teardown_error = 0;
    bool xsk_ready = false;
    uint64_t authorized_lbas;
    uint64_t parsed_u64;
    uint32_t parsed_u32;
    int parsed_int;

    /* Initialize defaults */
    memset(&ctx, 0, sizeof(ctx));
    ctx.adapter = &production_adapter;
    ctx.nvme_fd = -1;
    ctx.block_fd = -1;
    ctx.gpu = (struct ngn_gpu_runtime)NGN_GPU_RUNTIME_INIT;
    ctx.xsk.umem_area = MAP_FAILED;
    ctx.nvme_device = "/dev/ng0n1";  /* NVMe generic char device */
    ctx.net_iface = "eth0";
    ctx.queue_id = 0;

    /* Default network config */
    memset(ctx.dst_mac, 0xff, 6);
    memset(ctx.src_mac, 0, 6);
    ctx.dst_ip = inet_addr("192.168.1.1");
    ctx.src_ip = inet_addr("192.168.1.2");
    ctx.dst_port = 12345;
    ctx.src_port = 54321;

    /* Parse arguments */
    while ((opt = getopt_long(argc, argv, NXP_PIPELINE_GETOPT,
                              nxp_pipeline_long_options, NULL)) != -1) {
        switch (opt) {
        case 'd':
            ctx.nvme_device = optarg;
            break;
        case 'k':
            ctx.block_device = optarg;
            break;
        case 'i':
            ctx.net_iface = optarg;
            break;
        case 'q':
            if (nxp_parse_u32(optarg, &parsed_u32) ||
                parsed_u32 >= XDEV_EXT_XSK_REDIRECT_MAX_QUEUES) {
                fprintf(stderr, "Invalid XDP queue ID\n");
                return 1;
            }
            ctx.queue_id = (int)parsed_u32;
            break;
        case 'l':
            if (nxp_parse_u64(optarg, &start_lba)) {
                fprintf(stderr, "Invalid start LBA\n");
                return 1;
            }
            break;
        case 'n':
            if (nxp_parse_positive_int(optarg, INT_MAX, &num_blocks)) {
                fprintf(stderr, "Invalid block count\n");
                return 1;
            }
            break;
        case 'm':
            if (!strcmp(optarg, "tx"))
                g_direction = PIPELINE_NVME_TO_NIC;
            else if (!strcmp(optarg, "rx-write"))
                g_direction = PIPELINE_NIC_TO_NVME;
            else {
                fprintf(stderr, "Invalid mode: use tx or rx-write\n");
                return 1;
            }
            break;
        case 'D':
            if (parse_mac(optarg, ctx.dst_mac) < 0) {
                fprintf(stderr, "Invalid destination MAC\n");
                return 1;
            }
            break;
        case 'S':
            if (parse_mac(optarg, ctx.src_mac) < 0) {
                fprintf(stderr, "Invalid source MAC\n");
                return 1;
            }
            src_mac_set = 1;
            break;
        case 'a':
            if (inet_pton(AF_INET, optarg, &ctx.dst_ip) != 1) {
                fprintf(stderr, "Invalid destination IPv4 address\n");
                return 1;
            }
            break;
        case 's':
            if (inet_pton(AF_INET, optarg, &ctx.src_ip) != 1) {
                fprintf(stderr, "Invalid source IPv4 address\n");
                return 1;
            }
            break;
        case 'p':
            if (nxp_parse_u64(optarg, &parsed_u64) || parsed_u64 > UINT16_MAX) {
                fprintf(stderr, "Invalid destination port\n");
                return 1;
            }
            ctx.dst_port = (uint16_t)parsed_u64;
            break;
        case 'P':
            if (nxp_parse_u64(optarg, &parsed_u64) || parsed_u64 > UINT16_MAX) {
                fprintf(stderr, "Invalid source port\n");
                return 1;
            }
            ctx.src_port = (uint16_t)parsed_u64;
            break;
        case 'e':
            if (nxp_parse_u64(optarg, &ctx.session_id) || !ctx.session_id) {
                fprintf(stderr, "Invalid session identity: must be nonzero\n");
                return 1;
            }
            break;
        case 't':
            if (!strcmp(optarg, "none"))
                g_transform = PIPELINE_TRANSFORM_NONE;
            else if (!strcmp(optarg, "xor"))
                g_transform = PIPELINE_TRANSFORM_XOR;
            else {
                fprintf(stderr, "Invalid transform: use none or xor\n");
                return 1;
            }
            break;
        case 'b':
            if (nxp_parse_u32(optarg, &g_expected_lba_size)) {
                fprintf(stderr, "Invalid LBA size\n");
                return 1;
            }
            if (g_expected_lba_size == 0 ||
                (g_expected_lba_size & (g_expected_lba_size - 1)) != 0) {
                fprintf(stderr, "Invalid LBA size: must be a power of 2\n");
                return 1;
            }
            break;
        case 'B':
            if (nxp_parse_u32(optarg, &g_block_size) || g_block_size == 0) {
                fprintf(stderr, "Invalid -B block size\n");
                return 1;
            }
            break;
#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
        case 'g':
            ctx.gpu_device = optarg;
            break;
#endif
        case 'Z':
            g_staging = 1;   /* staging diagnostic: avoid zero-copy DMA into the pinned UMEM */
            break;
        case 'Q':
            if (nxp_parse_positive_int(optarg, INT_MAX, &parsed_int)) {
                fprintf(stderr, "Invalid -Q depth: must be >= 1\n");
                return 1;
            }
            g_depth = parsed_int;
            if (g_depth > MAX_INFLIGHT) {
                fprintf(stderr, "-Q depth %d exceeds MAX_INFLIGHT %d\n",
                        g_depth, MAX_INFLIGHT);
                return 1;
            }
            break;
        case 'C':
            g_zerocopy = 0;
            break;
        case 'z':
            g_zerocopy = 1;  /* bind AF_XDP in XDP_ZEROCOPY mode */
            break;
        case 'W':
            g_tx_full_poll = 1;
            break;
        case 'F':
            g_fixed_file = 1;
            break;
        case 'R':
            g_fixed_buffer = 1;
            break;
        case 'I':
            g_iopoll = 1;
            break;
        case NXP_OPT_REVALIDATE_EVERY:
            if (nxp_parse_u32(optarg, &g_revalidate_every)) {
                fprintf(stderr, "Invalid --revalidate-every count\n");
                return 1;
            }
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (num_blocks <= 0) {
        fprintf(stderr, "Number of blocks must be positive\n");
        return 1;
    }
    if (!ctx.session_id) {
        fprintf(stderr, "A nonzero per-run session identity is required with -e\n");
        return 1;
    }
    ret = pipeline_validate_transform(g_direction, g_transform);
    if (ret) {
        fprintf(stderr,
                "The xor transform is sender-side only; rx-write requires -t none\n");
        return 1;
    }
    /* Device-independent checks.  LBA divisibility and namespace bounds are
     * checked only after real namespace geometry has been captured. */
    if (g_staging && g_direction == PIPELINE_NIC_TO_NVME) {
        fprintf(stderr, "-Z staging is a TX-only diagnostic\n");
        return 1;
    }
#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
    if (!ctx.gpu_device) {
        fprintf(stderr, "The composite NVMe<->GPU<->NIC pipeline requires -g <device>\n");
        return 1;
    }
    if (g_staging) {
        fprintf(stderr,
                "The composite pipeline owns one shared XSK UMEM journal; -Z is unsupported\n");
        return 1;
    }
#ifndef XDEV_EXT_NVME_GPU_NIC_WITH_CUDA
    fprintf(stderr,
            "This nvme_gpu_nic_pipeline_host build has no CUDA driver runtime; use it for build/help validation only\n");
    return 1;
#endif
#endif
    /* Keep every fixed IO_VEC segment naturally aligned.  The optional XOR
     * diagnostic also operates on complete u64 lanes. */
    if (g_block_size % sizeof(uint64_t) != 0) {
        fprintf(stderr, "Block size %u must be a multiple of 8\n", g_block_size);
        return 1;
    }
    /* Get interface index */
    ctx.ifindex = if_nametoindex(ctx.net_iface);
    if (ctx.ifindex == 0) {
        fprintf(stderr, "Interface %s not found\n", ctx.net_iface);
        return 1;
    }
    if (!src_mac_set) {
        ret = get_iface_mac(ctx.net_iface, ctx.src_mac);
        if (ret < 0) {
            fprintf(stderr, "Cannot auto-detect source MAC for %s: %s. Use -S <mac>.\n",
                    ctx.net_iface, strerror(-ret));
            return 1;
        }
    }
    ret = get_iface_mtu(ctx.net_iface, &ctx.mtu);
    if (ret < 0) {
        fprintf(stderr, "Cannot read MTU for %s: %s\n",
                ctx.net_iface, strerror(-ret));
        return 1;
    }

    {
        struct nxp_wire_layout layout;

        ret = nxp_wire_mtu_layout_plan(ctx.session_id, 1,
                                       g_block_size, ctx.mtu,
                                       FRAME_SIZE, NXP_LAYOUT_DATA_OFFSET,
                                       NXP_VECTOR_ALIGNMENT, &layout);
        if (ret < 0) {
            fprintf(stderr, "Logical transfer cannot be packetized safely: %s\n",
                    strerror(ret < 0 ? -ret : EMSGSIZE));
            return 1;
        }
#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
        if (layout.segment_count > NGN_GPU_MAX_BATCH) {
            fprintf(stderr,
                    "Logical transfer needs %u CE entries; composite GPU batches are limited to %u\n",
                    layout.segment_count, NGN_GPU_MAX_BATCH);
            return 1;
        }
#endif
        ret = nxp_group_capacity_validate(
            (uint32_t)g_depth, layout.segment_count, NUM_FRAMES,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
            XSK_RING_CONS__DEFAULT_NUM_DESCS);
        if (ret) {
            fprintf(stderr,
                    "-Q depth %d with %u segments/group exceeds UMEM/XSK ring capacity\n",
                    g_depth, layout.segment_count);
            return 1;
        }
    }

    /* Open NVMe character device for URING_CMD */
    ctx.nvme_fd = open(ctx.nvme_device,
                       (g_direction == PIPELINE_NIC_TO_NVME ? O_RDWR : O_RDONLY) |
                       O_CLOEXEC);
    if (ctx.nvme_fd < 0) {
        perror("open nvme device");
        fprintf(stderr, "Note: URING_CMD requires NVMe char device (e.g., /dev/ng0n1)\n");
        goto out;
    }

    ret = resolve_device_paths(&ctx);
    if (ret < 0) {
        fprintf(stderr, "Cannot prove NVMe char/block pairing: %s\n",
                strerror(-ret));
        goto out;
    }
    ret = collect_namespace_snapshot(&ctx, &ctx.namespace);
    if (ret < 0) {
        fprintf(stderr, "Cannot establish namespace identity/geometry: %s\n",
                strerror(-ret));
        goto out;
    }
    ctx.nsid = ctx.namespace.nsid;
    g_lba_size = ctx.namespace.lba_size;
    if (g_expected_lba_size && g_expected_lba_size != g_lba_size) {
        fprintf(stderr, "-b assertion %u disagrees with device LBA size %u\n",
                g_expected_lba_size, g_lba_size);
        goto out;
    }
    if (g_lba_size > g_block_size || g_block_size % g_lba_size) {
        fprintf(stderr, "Device LBA size %u must divide payload size %u\n",
                g_lba_size, g_block_size);
        goto out;
    }
    if (nxp_u64_mul_overflow((uint64_t)num_blocks,
                             g_block_size / g_lba_size,
                             &authorized_lbas)) {
        fprintf(stderr, "Requested namespace span overflows\n");
        goto out;
    }
    ctx.io_limits = (struct nxp_io_limits) {
        .authorized_first_lba = start_lba,
        .authorized_lbas = authorized_lbas,
        .frame_size = FRAME_SIZE,
        .payload_offset = NXP_DATA_OFFSET,
        .packet_header_len = PKT_HDR_SIZE + NXP_WIRE_HEADER_LEN,
        .l2_header_len = sizeof(struct ethhdr),
        .mtu = ctx.mtu,
    };
    {
        struct nxp_nvme_io_plan last;
        struct nxp_local_io_position position = {
            .request_index = (uint64_t)num_blocks - 1,
        };

        ret = nxp_plan_nvme_io(&ctx.namespace, &ctx.io_limits,
                               g_direction == PIPELINE_NIC_TO_NVME ?
                                   NXP_IO_WRITE : NXP_IO_READ,
                               &position, g_block_size, &last);
        if (ret < 0) {
            fprintf(stderr, "Requested span/payload is unsafe: %s\n",
                    strerror(-ret));
            goto out;
        }
    }
    printf("Verified NVMe namespace: char=%s block=%s nsid=%u lbs=%u "
           "capacity_lbas=%lu diskseq=%lu wwid=%.*s serial=%.*s "
           "pci_bdf=%.*s metadata=0 pi=0\n",
           ctx.nvme_device, ctx.block_device, ctx.nsid, g_lba_size,
           (unsigned long)ctx.namespace.capacity_lbas,
           (unsigned long)ctx.namespace.diskseq,
           ctx.namespace.stable_id_len, ctx.namespace.stable_id,
           ctx.namespace.controller_serial_len,
           ctx.namespace.controller_serial,
           ctx.namespace.pci_bdf_len, ctx.namespace.pci_bdf);

    /* Initialize io_uring with SQE128 for URING_CMD */
    ret = pipeline_init_ring(&ctx);
    if (ret < 0) {
        if (g_iopoll && ret == -EOPNOTSUPP)
            fprintf(stderr, "IOPOLL requested but controller poll queues and exact namespace queue/io_poll=1 were not both proven\n");
        else
            fprintf(stderr, "Failed to initialize io_uring with SQE128: %s\n",
                    strerror(-ret));
        nxp_latch_error(&ctx.first_error, ret);
        goto out;
    }

    ret = register_fixed_file(&ctx);
    if (ret < 0) {
        fprintf(stderr, "fixed-file registration failed: %s\n", strerror(-ret));
        nxp_latch_error(&ctx.first_error, ret);
        goto out;
    }

    printf("Initialized io_uring with 128-byte SQE for URING_CMD\n");

    /* Initialize AF_XDP socket (libxdp takes the iface NAME, not ifindex) */
    {
        const struct xdev_ext_xsk_flow_filter flow_filter = {
            .flags = XDEV_EXT_XSK_FILTER_F_ALL,
            .src_ipv4 = ntohl(ctx.src_ip),
            .dst_ipv4 = ntohl(ctx.dst_ip),
            .payload_magic = NXP_WIRE_MAGIC,
            .src_port = ctx.src_port,
            .dst_port = ctx.dst_port,
        };

        ret = init_xsk(&ctx.xsk, ctx.net_iface, ctx.queue_id,
                       &flow_filter);
    }
    xsk_ready = ctx.xsk.xsk != NULL;
    if (ret < 0) {
        fprintf(stderr, "Failed to initialize AF_XDP socket\n");
        nxp_latch_error(&ctx.first_error, ret);
        goto out;
    }
    printf("Initialized AF_XDP on %s queue %d\n", ctx.net_iface, ctx.queue_id);

#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
    ret = pipeline_random_chain_id(&ctx.chain_id);
    if (ret < 0) {
        fprintf(stderr, "Cannot create composite-chain identity: %s\n",
                strerror(-ret));
        nxp_latch_error(&ctx.first_error, ret);
        goto out;
    }
    ret = ngn_gpu_runtime_init(&ctx.gpu, ctx.gpu_device, ctx.xsk.xsk_fd,
                               ctx.xsk.umem_area, UMEM_SIZE, FRAME_SIZE);
    if (ret < 0) {
        fprintf(stderr,
                "Cannot pin the XSK UMEM and initialize the NVIDIA CE path: %s\n",
                strerror(-ret));
        nxp_latch_error(&ctx.first_error, ret);
        goto out;
    }
    ctx.gpu_enabled = true;
    printf("Initialized composite chain id=%#lx: %s through host XSK UMEM "
           "and synchronous NVIDIA CE roundtrip (host-staged, not GPUDirect)\n",
           (unsigned long)ctx.chain_id,
           g_direction == PIPELINE_NIC_TO_NVME ?
               "AF_XDP RX -> GPU -> NVMe WRITE" :
               "NVMe READ -> GPU -> AF_XDP TX");
#endif

    /* Run pipeline */
    ret = run_pipeline(&ctx, start_lba, num_blocks);
    if (ret < 0) {
        nxp_latch_error(&ctx.first_error, ret);
        fprintf(stderr, "Pipeline failed: %s\n", strerror(-ret));
    } else {
        exit_status = 0;
    }

out:
    /* Reverse initialization order.  Accepted NVMe work is drained by the
     * pipeline before it returns, and AF_XDP is detached before UMEM unmap. */
    ret = pipeline_detach_xsk_redirect(&ctx);
    nxp_latch_error(&ctx.first_error, ret);
    nxp_latch_error(&teardown_error, ret);
    (void)pipeline_prepare_backing_cleanup(&ctx);
#ifdef XDEV_EXT_NVME_GPU_NIC_CHAIN
    if (ctx.gpu.sequestered)
        pipeline_hold_unquiesced_backing(
            "GPU CE completion or unpin is ambiguous");
    if (ctx.gpu.active || ctx.gpu.gpu_fd >= 0 ||
        ctx.gpu.cuda_primary_retained) {
        ret = ngn_gpu_runtime_cleanup(&ctx.gpu);
        nxp_latch_error(&ctx.first_error, ret);
        nxp_latch_error(&teardown_error, ret);
    }
    if (ctx.gpu.sequestered)
        pipeline_hold_unquiesced_backing(
            "GPU CE completion or unpin is ambiguous");
    if (ctx.gpu_enabled)
        printf("Composite GPU CE batches=%lu completed_items=%lu\n",
               (unsigned long)ctx.gpu.batch_calls,
               (unsigned long)ctx.gpu.completed_items);
#endif
    if (!pipeline_can_destroy_xsk(&ctx)) {
        /* Returning would let process teardown close fds and unmap addresses,
         * which is not a synchronous DMA barrier.  Keep the address space and
         * every owner alive until an operator has quiesced/reset the devices. */
        pipeline_hold_unquiesced_backing("DMA/CQ ownership is unproven");
    }
    if (xsk_ready) {
        xsk_socket__delete(ctx.xsk.xsk);
        xsk_umem__delete(ctx.xsk.umem);
        if (ctx.xsk.umem_area != MAP_FAILED)
            munmap(ctx.xsk.umem_area, UMEM_SIZE);
    }
    (void)pipeline_unregister_files(&ctx);
    ret = pipeline_close_ring(&ctx);
    nxp_latch_error(&ctx.first_error, ret);
    nxp_latch_error(&teardown_error, ret);
    if (ctx.block_fd >= 0)
        close(ctx.block_fd);
    if (ctx.nvme_fd >= 0)
        close(ctx.nvme_fd);

    /* An rx-write run ended early by SIGTERM/SIGINT exits 128 + signal;
     * every other failure exits 1. */
    if (ctx.first_error)
        exit_status = nxp_stop_exit_status(ctx.first_error, teardown_error,
                                           pipeline_rx_stop_signal());
    if (!exit_status)
        printf("Pipeline completed\n");
    return exit_status;
}
