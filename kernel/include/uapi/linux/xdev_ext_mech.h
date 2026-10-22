/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_XDEV_EXT_MECH_H
#define _UAPI_LINUX_XDEV_EXT_MECH_H

/*
 * XDEV_EXT mechanism layer.  One struct_ops type per device class; its eBPF
 * programs fill native descriptors in a C-owned bounded scratch area and
 * interpret native completions.  C keeps admission, DMA mapping, the real
 * queues and doorbells, completion classification, lifecycle and teardown,
 * and validates every descriptor field before anything reaches a device.
 *
 * The policy-layer ABI v2 in xdev_ext_binding.h stays frozen; the mechanism ctx
 * embeds its ctx as a read-only base.
 */

#include <linux/types.h>
#include "xdev_ext_binding.h"

#define XDEV_EXT_MECH_ABI_VERSION		1U
/* CE build requires a C-issued batch window lease; old CE ops are rejected. */
#define XDEV_EXT_CE_MECH_ABI_VERSION		2U
#define XDEV_EXT_MECH_MAX_FRAMES		32
#define XDEV_EXT_MECH_MAX_STAGES		4
#define XDEV_EXT_AFXDP_MECH_STATE_SIZE	256U

/* Existing ids reuse policy numbers; new mechanisms have their own range. */
enum xdev_ext_mech_class {
	XDEV_EXT_MECH_CLASS_AFXDP	= XDEV_EXT_BINDING_BACKEND_AFXDP,
	XDEV_EXT_MECH_CLASS_NVME	= XDEV_EXT_BINDING_BACKEND_NVME,
	XDEV_EXT_MECH_CLASS_CE	= XDEV_EXT_BINDING_BACKEND_GPU,
	XDEV_EXT_MECH_CLASS_IAA	= 4,
	XDEV_EXT_MECH_CLASS_DMA	= 6,
	XDEV_EXT_MECH_CLASS_SOCKET = 7,
	XDEV_EXT_MECH_CLASS_NET = 8,
	XDEV_EXT_MECH_CLASS_MAX	= 9,
};

/* Stage direction, relative to the stage's device. */
enum xdev_ext_mech_dir {
	/* NVMe WRITE, AF_XDP TX, CE host-to-device */
	XDEV_EXT_MECH_DIR_TO_DEVICE		= XDEV_EXT_BINDING_DIRECTION_TO_DEVICE,
	/* NVMe READ, AF_XDP RX, CE device-to-host */
	XDEV_EXT_MECH_DIR_FROM_DEVICE	= XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
};

enum xdev_ext_mech_member {
	XDEV_EXT_MECH_MEMBER_PREPARE		= 1,	/* sleepable, optional */
	XDEV_EXT_MECH_MEMBER_BUILD		= 2,
	XDEV_EXT_MECH_MEMBER_COMPLETE	= 3,
};

enum xdev_ext_mech_callsite {
	XDEV_EXT_MECH_SITE_WORKER		= 0,	/* session kthread_worker */
	XDEV_EXT_MECH_SITE_RX_GENERIC	= 1,	/* xsk_generic_rcv, pool->rx_lock held */
	XDEV_EXT_MECH_SITE_RX_NATIVE		= 2,	/* native RX, pool->rx_lock held */
	XDEV_EXT_MECH_SITE_URING_CMD		= 3,	/* NVMe uring_cmd issue and task_work */
	XDEV_EXT_MECH_SITE_CREATE		= 4,	/* IORING_REGISTER_XDEV_EXT_MECH CREATE */
	XDEV_EXT_MECH_SITE_RX_HOLD_RESULT	= 5,	/* admission result, RX lock held */
};

/*
 * Callback argument, read-only to the program.  base comes from the
 * xdev_ext_binding_make_*_ctx() builder of the stage's class with base.backend
 * equal to class_id; base.request_id is batch_id, base.chain_id is
 * session_id, base.src_offset is the batch key (RX hold key or START
 * sequence) and base.length the batch payload bytes.
 */
struct xdev_ext_mech_ctx {
	struct xdev_ext_binding_ctx_v2 base;
	__u32 mech_abi_version;
	__u32 member;			/* enum xdev_ext_mech_member */
	__u32 class_id;			/* enum xdev_ext_mech_class */
	__u32 callsite;			/* enum xdev_ext_mech_callsite */
	__u32 nr_frames;
	__u32 desc_cap;
	__aligned_u64 session_id;
	__aligned_u64 batch_id;
};

/* One frame of a batch: chunk base as a UMEM offset, data span in the chunk. */
struct xdev_ext_mech_frame_info {
	__aligned_u64 umem_addr;
	__u32 data_off;
	__u32 data_len;
};

/*
 * Frame layout of a session: a batch carries group_bytes of payload in
 * DIV_ROUND_UP(group_bytes, seg_len) frames, each with hdr_room bytes of
 * header space before its data.
 */
struct xdev_ext_mech_layout {
	__u32 frame_size;
	__u32 hdr_room;
	__u32 seg_len;
	__u32 group_bytes;
};

/* AF_XDP endpoint pair; addresses and ports in network byte order. */
struct xdev_ext_mech_peer {
	__u8 local_mac[6];
	__u8 peer_mac[6];
	__be32 local_ip;
	__be32 peer_ip;
	__be16 local_port;
	__be16 peer_port;
};

/* Read-only class information returned by bpf_xdev_ext_info(). */
struct xdev_ext_nvme_mech_info {
	struct xdev_ext_mech_layout l;
	__u32 lba_shift;
	__u32 max_nlb;
	__aligned_u64 window_slba;
	__aligned_u64 window_nlb;
	__aligned_u64 capacity_lbas;
	__u32 sgl;
	__u32 nr_frames;
	struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
};

/* Opt-in AF_XDP v3. arg0 is wire session, arg1 points to this CREATE-only config. */
#define XDEV_EXT_AFXDP_F_RELIABLE (1U << 0)
#define XDEV_EXT_AFXDP_F_FINITE (1U << 1) /* requires RELIABLE; extended config */
struct xdev_ext_afxdp_reliable_config {
 __aligned_u64 first_group;
 __aligned_u64 timeout_ns;
 __u32 window;
 __u32 max_attempts;
};
/* FINITE selects this 32-byte CREATE input. RELIABLE alone still copies only
 * the unchanged 24-byte base. Receive admission is independent of NOTIFY_ARM. */
struct xdev_ext_afxdp_reliable_finite_config {
 struct xdev_ext_afxdp_reliable_config base;
 __aligned_u64 nr_groups;
};

/* At an RX complete f[0] is the frame just received. */
struct xdev_ext_afxdp_mech_info {
	struct xdev_ext_mech_layout l;
	__u32 mtu;
	__u32 nr_frames;
	struct xdev_ext_mech_peer peer;
	struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
};

/* Extended BPF view; legacy AF_XDP info remains a byte-identical prefix. */
struct xdev_ext_afxdp_reliable_info {
 struct xdev_ext_afxdp_mech_info base;
 __aligned_u64 wire_session, wire_group, wire_credit;
 __u32 wire_attempt, wire_type;
};

struct xdev_ext_ce_mech_info {
	struct xdev_ext_mech_layout l;
	__aligned_u64 gpu_window_len;
	__u32 gpu_seg_size;
	__u32 max_entry_len;
	__u32 nr_frames;
	__u32 rsvd;
	struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
	__u32 window_slot;
	__u32 window_depth;
	__aligned_u64 lease_generation;
};

/*
 * Scratch descriptors returned by bpf_xdev_ext_desc().  NVMe: one 64-byte SQE,
 * read through struct nvme_command from vmlinux.  AF_XDP TX: one
 * struct xdp_desc per frame.  CE: one struct xdev_ext_ce_copy_desc per entry.
 * A slot is used when any of its bytes is non-zero; used slots start at 0
 * and are contiguous.
 */
#define XDEV_EXT_NVME_MECH_DESC_SIZE		64

struct xdev_ext_ce_copy_desc {
	__u32 frame_pos;
	__u32 frame_off;		/* chunk offset, inside the frame's data span */
	__aligned_u64 gpu_off;		/* offset in the bound device window */
	__u32 len;
	__u32 flags;			/* XDEV_EXT_CE_F_* */
};

#define XDEV_EXT_CE_F_COMPLETION_POINT	(1U << 0)
#define XDEV_EXT_CE_F_BARRIER		(1U << 1)
#define XDEV_EXT_CE_F_KNOWN_MASK		0x00000003U

/* Completion copies returned by bpf_xdev_ext_cqe(); RX passes its struct xdp_desc. */
struct xdev_ext_nvme_mech_cqe {
	__aligned_u64 result;
	__u16 status;			/* nvme_req(req)->status as completed */
	__u16 rsvd;
	__s32 err;
};

/* RX_HOLD_RESULT: C already decided ownership; the program commits order. */
struct xdev_ext_afxdp_rx_hold_cqe {
	__u64 key;
	__u32 pos;
	__s32 err;
};

struct xdev_ext_afxdp_tx_cqe {
	__s32 err;			/* xsk_kernel_xmit() result of this frame */
	__u32 rsvd;
};

/* Classified by C; a program cannot turn AMBIGUOUS into anything else. */
enum xdev_ext_ce_outcome {
	XDEV_EXT_CE_OK			= 0,
	XDEV_EXT_CE_PRE_SUBMIT_FAILED	= 1,	/* hardware never saw it */
	XDEV_EXT_CE_AMBIGUOUS		= 2,	/* hardware may have seen it */
};

struct xdev_ext_ce_mech_cqe {
	__u32 outcome;			/* enum xdev_ext_ce_outcome */
	__u32 backend_status;
	__aligned_u64 bytes_done;
	__u32 entries_done;
	__u32 rsvd;
};

/* Generic registered-provider window <-> shared host pool copies. */
#define XDEV_EXT_DMA_MAX_ENTRIES 32
#define XDEV_EXT_DMA_F_COMPLETION_POINT (1U << 0)
#define XDEV_EXT_DMA_F_BARRIER (1U << 1)
#define XDEV_EXT_DMA_F_KNOWN_MASK 3U
#define XDEV_EXT_DMA_DIR_TO_DEVICE (1U << XDEV_EXT_MECH_DIR_TO_DEVICE)
#define XDEV_EXT_DMA_DIR_FROM_DEVICE (1U << XDEV_EXT_MECH_DIR_FROM_DEVICE)
#define XDEV_EXT_DMA_DIR_KNOWN_MASK (XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE)
struct xdev_ext_dma_copy_desc {
	__u32 frame_pos, frame_off;
	__aligned_u64 device_off;
	__u32 len, flags;
};
struct xdev_ext_dma_mech_info {
	struct xdev_ext_mech_layout l;
	__aligned_u64 window_len;
	__u32 segment_size, max_entry_len, alignment, directions, nr_frames;
	__u32 rsvd;
	struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
};
enum xdev_ext_dma_outcome {
	XDEV_EXT_DMA_OK = 0,
	XDEV_EXT_DMA_PRE_SUBMIT_FAILED = 1,
	XDEV_EXT_DMA_AMBIGUOUS = 2,
};
struct xdev_ext_dma_mech_cqe {
	__u32 outcome, provider_status;
	__aligned_u64 bytes_done;
	__u32 entries_done, rsvd;
};

/* IAA: TO_DEVICE compresses, FROM_DEVICE decompresses. arg0 is the first
 * output frame; arg1 is per-batch destination capacity. CREATE reserves
 * depth * ceil(arg1 / seg_len) frames. fd is a lifetime token. Hardware is
 * deflate-iaa; the explicit software flag is only a functional test path.
 */
#define XDEV_EXT_IAA_F_SOFTWARE (1U << 0)
struct xdev_ext_iaa_mech_info {
 struct xdev_ext_mech_layout l;
 __u32 nr_frames, dst_frames, dst_capacity, software;
 struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_iaa_desc { __u32 src_len, dst_capacity, flags, reserved; };
struct xdev_ext_iaa_mech_cqe { __s32 status; __u32 produced, capacity, reserved; };

/* Connected AF_INET/AF_INET6 UDP compatibility sink. One batch is one
 * datagram, at most 65507 bytes; every descriptor is exactly one complete
 * frame data span, in batch order, flags 0. Native socket copying is explicit:
 * there is no zero-copy/DMA or remote-ACK claim. Local send completion means
 * the socket no longer references pool payload, not delivery to the peer.
 * The caller lends the connected socket configuration until STOP: it must
 * not reconnect, cork, segment, or concurrently send corked messages.
 */
#define XDEV_EXT_SOCKET_MAX_DATAGRAM 65507U
struct xdev_ext_socket_send_desc {
	__u32 frame_pos, frame_off, len, flags;
};
struct xdev_ext_socket_mech_info {
	struct xdev_ext_mech_layout l;
	__u32 nr_frames, max_datagram;
	struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_socket_mech_cqe {
	__s32 status;
	__u32 bytes_sent, reserved[2];
};

/* Native NIC peer TX, separate CPU headers and device-memory payload.
 * The program writes offsets within the current frame, never DMA addresses.
 */
#define XDEV_EXT_NET_MAX_ENTRIES 16U
#define XDEV_EXT_NET_HEADER_MAX 128U
struct xdev_ext_net_send_desc {
 __u32 frame_pos, frame_off, len, flags;
 __u32 header_len, reserved;
 __u8 header[XDEV_EXT_NET_HEADER_MAX];
};
struct xdev_ext_net_mech_info {
 struct xdev_ext_mech_layout l;
 __aligned_u64 generation;
 __u32 nr_frames, mtu;
 struct xdev_ext_mech_peer peer;
 struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_net_mech_cqe {
 __s32 status;
 __u32 bytes_sent, entries_done, outcome; /* 0 OK; 1 refused; 2 ambiguous */
};

enum xdev_ext_mech_build_ret {
	XDEV_EXT_MECH_BUILD_DEFAULT	= 0,	/* class default_build, if it has one */
	XDEV_EXT_MECH_BUILD_SUBMIT	= 1,
	XDEV_EXT_MECH_BUILD_ABORT	= 2,
};

/* complete return values; HOLD, PUBLISH and RECYCLE are AF_XDP RX only. */
enum xdev_ext_mech_next {
	XDEV_EXT_MECH_NEXT		= 0,
	XDEV_EXT_MECH_DONE		= 1,
	XDEV_EXT_MECH_RETRY		= 2,
	XDEV_EXT_MECH_ABORT		= 3,
	XDEV_EXT_MECH_HOLD		= 4,
	XDEV_EXT_MECH_PUBLISH	= 5,
	XDEV_EXT_MECH_RECYCLE	= 6,
};

/*
 * Control plane: io_uring_register(fd, IORING_REGISTER_XDEV_EXT_MECH, &req, 1).
 * arg points to struct xdev_ext_mech_create, xdev_ext_mech_start, xdev_ext_mech_stats or
 * xdev_ext_mech_notify_arm; for STOP it is the session id itself.
 */
enum xdev_ext_mech_op {
	XDEV_EXT_MECH_OP_CREATE	= 1,
	XDEV_EXT_MECH_OP_START	= 2,
	XDEV_EXT_MECH_OP_STOP	= 3,
	XDEV_EXT_MECH_OP_STATS	= 4,
	XDEV_EXT_MECH_OP_NOTIFY_ARM	= 5,
	XDEV_EXT_MECH_OP_TRANSPORT_STATS = 6,
};

#define XDEV_EXT_MECH_TRANSPORT_STATS_VERSION 1U
/* Separate from the frozen 168-byte legacy STATS layout. All output words
 * after session_id must be zero on input. */
struct xdev_ext_mech_transport_stats {
	__u32 size;
	__u32 version;
	__aligned_u64 session_id;
	__u32 native_controls;
	__u32 pending_acks;
	__u32 uncertain_controls;
	__u32 rsvd;
};

struct io_uring_xdev_ext_mech {
	__u32 op;			/* enum xdev_ext_mech_op */
	__u32 rsvd;
	__aligned_u64 arg;
};

/* Where batch frames live; XSK pool_fd is an AF_XDP socket, IOU_UMEM uses -1. */
enum xdev_ext_mech_pool_kind {
	XDEV_EXT_MECH_POOL_XSK	= 1,	/* the socket's AF_XDP UMEM, aligned, copy mode */
	XDEV_EXT_MECH_POOL_IOU_UMEM	= 2,	/* this ring's IORING_REGISTER_XDEV_EXT_UMEM */
	XDEV_EXT_MECH_POOL_PEER = 3, /* authoritative allocation fd, no CPU pages */
};

/*
 * NVMe: fd = /dev/ngXnY, arg0/arg1 = LBA window start/count.
 * AF_XDP: fd = bound AF_XDP socket.
 * CE: fd = backend device, arg0/arg1 = device VA/length of the window.
 * DMA: fd = provider device, arg0/arg1 = provider window offset/length.
 * SOCKET: fd = connected UDP socket, TO_DEVICE only; flags/arg0/arg1 = 0.
 */
struct xdev_ext_mech_stage_uapi {
	__u32 class_id;			/* enum xdev_ext_mech_class */
	__u32 direction;		/* enum xdev_ext_mech_dir */
	__s32 fd;
	__u32 flags;			/* AF_XDP: XDEV_EXT_AFXDP_F_*; others 0 */
	__aligned_u64 arg0;
	__aligned_u64 arg1;
};

struct xdev_ext_mech_create {
	__u32 abi_version;		/* XDEV_EXT_MECH_ABI_VERSION */
	__u32 nr_stages;		/* 1..XDEV_EXT_MECH_MAX_STAGES */
	__u32 pool_kind;		/* enum xdev_ext_mech_pool_kind */
	__s32 pool_fd;
	struct xdev_ext_mech_layout layout;
	__u32 depth;			/* batches in flight at most */
	__s32 eventfd;			/* per finished batch unless armed; -1 for none */
	struct xdev_ext_mech_peer peer;
	struct xdev_ext_mech_stage_uapi st[XDEV_EXT_MECH_MAX_STAGES];
	__aligned_u64 session_id;	/* out */
};

/* IOU_UMEM only: the listed frames move USER -> kernel before the batches. */
#define XDEV_EXT_MECH_START_F_USER_FRAMES	(1U << 0)
/*
 * USER_FRAMES only: lend exactly min(nr_batches, CREATE depth) groups once.
 * Frames recycle in the kernel until this single START drains, then return
 * USER. The caller must not touch them before final completion. Device-
 * ambiguous frames remain sequestered. No new user payload is synthesized.
 */
#define XDEV_EXT_MECH_START_F_RECYCLE		(1U << 1)
/* USER_FRAMES, one batch and one frame only; user_frames instead points to
 * xdev_ext_mech_user_span. len is actual source bytes, not layout capacity.
 * Not combinable with RECYCLE. START requires no preceding in-flight batch.
 */
#define XDEV_EXT_MECH_START_F_USER_SPANS	(1U << 2)
#define XDEV_EXT_MECH_START_KNOWN_FLAGS	0x00000007U

struct xdev_ext_mech_user_span {
	__u32 index;
	__u32 len;
};

/*
 * Start nr_batches source batches with keys first_seq, first_seq + 1, ...
 * user_frames points to nr_user_frames __u32 frame indices.
 */
struct xdev_ext_mech_start {
	__aligned_u64 session_id;
	__aligned_u64 nr_batches;
	__aligned_u64 first_seq;
	__u32 flags;			/* XDEV_EXT_MECH_START_F_* */
	__u32 nr_user_frames;
	__aligned_u64 user_frames;
};

/*
 * Opt into one eventfd notification when every nonzero absolute target is
 * reached, or when an error/stop interrupts the run.  At least one target
 * is required.  Arm before START or receiver readiness.  Arming after a
 * target/terminal condition immediately signals; rearming is explicit.
 * After a signal coarse mode remains enabled.  A stop/error notification
 * does not imply accepted DMA has drained; use STATS and normal teardown.
 */
struct xdev_ext_mech_notify_arm {
	__aligned_u64 session_id;
	__aligned_u64 batches_target;	/* cumulative batches_done + batches_abort */
	__aligned_u64 published_target;	/* cumulative published frames */
	__u32 flags;			/* must be 0 */
	__u32 rsvd;			/* must be 0 */
};

enum xdev_ext_mech_session_state {
	XDEV_EXT_MECH_SESSION_NONE		= 0,
	XDEV_EXT_MECH_SESSION_ACTIVE		= 1,
	XDEV_EXT_MECH_SESSION_ERROR		= 2,	/* a batch was sequestered */
	XDEV_EXT_MECH_SESSION_STOPPING	= 3,
	XDEV_EXT_MECH_SESSION_STOPPED	= 4,
	XDEV_EXT_MECH_SESSION_ZOMBIE		= 5,	/* drain timed out or sequestered */
};

/* Counters are cumulative except inflight; frames are counted per frame. */
struct xdev_ext_mech_stats {
	__aligned_u64 session_id;	/* in */
	__aligned_u64 batches_done;
	__aligned_u64 batches_abort;
	__aligned_u64 rejects;		/* descriptors refused by validation */
	__aligned_u64 recycled;
	__aligned_u64 held;
	__aligned_u64 sequestered;
	__aligned_u64 timeouts;
	__aligned_u64 inflight;
	__aligned_u64 native_publish;	/* RX at RX_NATIVE published without HOLD */
	__aligned_u64 protocol_err;
	__aligned_u64 published;	/* frames handed to user space */
	__aligned_u64 submitted[XDEV_EXT_MECH_MAX_STAGES];	/* native commands per stage */
	__aligned_u64 completed[XDEV_EXT_MECH_MAX_STAGES];
	__s32 last_err;
	__u32 state;			/* enum xdev_ext_mech_session_state */
};

#endif /* _UAPI_LINUX_XDEV_EXT_MECH_H */
