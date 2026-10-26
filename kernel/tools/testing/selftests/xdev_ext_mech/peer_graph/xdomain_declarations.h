/* SPDX-License-Identifier: GPL-2.0 */
/* DECLARATIONS ONLY from frozen §4.1; never part of a behavior build.
 * Preinclude after the real current UAPI in --syntax-only mode.
 */
#include "include/uapi/linux/xdev_ext_mech.h"
#ifndef XDEV_EXT_XDOMAIN_PROTO_VERSION
#define XDEV_EXT_MECH_CLASS_XDOMAIN 11
#define XDEV_EXT_MECH_SITE_WORKER_PROTOCOL 7
#define XDEV_EXT_XDOMAIN_F_ALLOW_UNVERIFIED (1U << 0)	/* CAP_SYS_ADMIN: bind without a judged P2P path */
#define XDEV_EXT_XDOMAIN_KNOWN_FLAGS	0x00000001U
#define XDEV_EXT_XDOMAIN_MAX_FRAME	4096U	/* bytes of one NHI ring frame */
#define XDEV_EXT_XDOMAIN_MAX_ELEMS	64U	/* NHI frames per batch */
#define XDEV_EXT_XDOMAIN_TAG_LEN	24U
#define XDEV_EXT_XDOMAIN_PROTO_VERSION 1U
#define XDEV_EXT_XDP_F_LINK_UP          (1U << 0)
#define XDEV_EXT_XDP_F_ADMITS           (1U << 1)
#define XDEV_EXT_XDP_F_STAGE_DEAD       (1U << 2)
#define XDEV_EXT_XDP_F_STOPPING         (1U << 3)
#define XDEV_EXT_XDP_F_LOCAL_KNOWN      (1U << 4)
#define XDEV_EXT_XDP_F_LOCAL_QUIESCED   (1U << 5)
#define XDEV_EXT_XDP_F_NATIVE_POSTED    (1U << 6)
#define XDEV_EXT_XDP_F_WITHDRAWN        (1U << 7)
#define XDEV_EXT_XDP_F_CHAIN_DONE       (1U << 8)
#define XDEV_EXT_XDP_F_CHAIN_SEQUESTERED (1U << 9)
#define XDEV_EXT_XDP_F_RTS_CANCELED     (1U << 10)
#define XDEV_EXT_XDP_F_CTS_RECEIVED     (1U << 11)
#define XDEV_EXT_XDP_F_NATIVE_PENDING   (1U << 12)
#define XDEV_EXT_XDP_F_CTS_OWED         (1U << 13)
#define XDEV_EXT_XDP_F_FINAL_OWED       (1U << 14)
enum xdev_ext_xdomain_proto_event {
	XDEV_EXT_XDP_EV_TX_SUBMIT = 1,
	XDEV_EXT_XDP_EV_RX_SUBMIT = 2,
	XDEV_EXT_XDP_EV_RTS = 3,
	XDEV_EXT_XDP_EV_CTS = 4,
	XDEV_EXT_XDP_EV_HELD = 5,
	XDEV_EXT_XDP_EV_ACK = 6,
	XDEV_EXT_XDP_EV_FAIL = 7,
	XDEV_EXT_XDP_EV_CANCEL = 8,
	XDEV_EXT_XDP_EV_LOCAL = 9,
	XDEV_EXT_XDP_EV_CHAIN_END = 10,
	XDEV_EXT_XDP_EV_TIMER = 11,
	XDEV_EXT_XDP_EV_STOP = 12,
	XDEV_EXT_XDP_EV_LINK_DOWN = 13,
	XDEV_EXT_XDP_EV_POST_RESULT = 14,
	XDEV_EXT_XDP_EV_REPLY_DUE = 15,
	XDEV_EXT_XDP_EV_READY = 16,
	XDEV_EXT_XDP_EV_DUPLICATE = 17,
};
enum xdev_ext_xdomain_proto_action {
	XDEV_EXT_XDP_ACT_INVALID = 0,
	XDEV_EXT_XDP_ACT_WAIT = 1,
	XDEV_EXT_XDP_ACT_IGNORE = 2,
	XDEV_EXT_XDP_ACT_TX_ANNOUNCE = 3,
	XDEV_EXT_XDP_ACT_RX_ARM = 4,
	XDEV_EXT_XDP_ACT_RX_POST = 5,
	XDEV_EXT_XDP_ACT_TX_POST = 6,
	XDEV_EXT_XDP_ACT_ACCEPT_HELD = 7,
	XDEV_EXT_XDP_ACT_ACCEPT_ACK = 8,
	XDEV_EXT_XDP_ACT_ACCEPT_FAIL = 9,
	XDEV_EXT_XDP_ACT_PUBLISH = 10,
	XDEV_EXT_XDP_ACT_SEND_CTS = 11,
	XDEV_EXT_XDP_ACT_SEND_ACK = 12,
	XDEV_EXT_XDP_ACT_SEND_FAIL = 13,
	XDEV_EXT_XDP_ACT_WITHDRAW = 14,
	XDEV_EXT_XDP_ACT_REJECT_RTS = 15,
	XDEV_EXT_XDP_ACT_FAIL_LINK = 16,
	XDEV_EXT_XDP_ACT_CANCEL_ARMED = 17,
};
struct xdev_ext_xdomain_desc {
	__u32 frame_pos;		/* batch frame */
	__u32 frame_off;		/* chunk offset, a multiple of 4096, inside the data span */
	__u32 len;			/* bytes; C cuts the span into NHI frames of at most 4096 */
	__u32 flags;			/* 0 */
	__aligned_u64 group;		/* slot 0: TX the info's next_group, RX 0; other slots 0 */
	__u8 tag[XDEV_EXT_XDOMAIN_TAG_LEN];	/* slot 0, TX only: opaque bytes for the receiver */
	__u8 rsvd[16];			/* 0 */
};
struct xdev_ext_xdomain_mech_info {
	struct xdev_ext_mech_layout l;
	__aligned_u64 generation;	/* pool generation */
	__aligned_u64 local_inc;	/* this host's link incarnation */
	__aligned_u64 remote_inc;	/* the peer's incarnation, 0 while the link is down */
	__aligned_u64 next_group;	/* TX: the group this build must name; RX: 0 */
	__aligned_u64 credit;		/* TX: groups below this may be announced */
	__u32 direction, channel;
	__u32 max_frame;		/* XDEV_EXT_XDOMAIN_MAX_FRAME */
	__u32 max_elems;		/* XDEV_EXT_XDOMAIN_MAX_ELEMS */
	__u32 nr_frames, rsvd;
	__u8 remote_uuid[16];
	struct xdev_ext_mech_frame_info f[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_xdomain_mech_cqe {
	__s32 status;			/* batch status as published */
	__u32 outcome;			/* enum xdev_ext_mech_outcome of local DMA */
	__u32 remote;			/* XDEV_EXT_NET_REMOTE_* (TX) */
	__u32 elems_done;
	__aligned_u64 group;
	__aligned_u64 bytes;
	__u32 crc_errors;		/* RX elements the NHI flagged */
	__u32 rsvd;
	__u8 tag[XDEV_EXT_XDOMAIN_TAG_LEN];	/* RX: tag from the announcement */
};
struct xdev_ext_xdomain_proto_info {
	__u32 size, version, event, direction;
	__aligned_u64 event_id, epoch, pool_generation, local_inc, remote_inc;
	__aligned_u64 stream, group, now_ns, hard_deadline_ns, policy_deadline_ns;
	__aligned_u64 base_group, next_group, credit, msg_credit, data_seq, expected_seq;
	__u32 state, remote, facts, msg_type;
	__u32 total_len, count, want_len, want_count, posted_groups;
	__s32 local_status, chain_status;
	__u32 attempt, channel, ctl_room;
	__u8 tag[XDEV_EXT_XDOMAIN_TAG_LEN];
	__aligned_u64 reserved[4];
};
struct xdev_ext_xdomain_proto_verdict {
	__u32 size, version, action, flags; /* flags must be zero */
	__aligned_u64 event_id, epoch;
	__aligned_u64 wake_ns, credit;
	__s32 status;
	__u32 reserved0;
	__aligned_u64 reserved1;
};
#endif
