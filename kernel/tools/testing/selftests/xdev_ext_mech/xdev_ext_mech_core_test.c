// SPDX-License-Identifier: GPL-2.0
/*
 * User-space checks of the XDEV_EXT mechanism-layer UAPI layout and of the pure
 * rules in io_uring/xdev_ext_mech_core.h that the kernel runs unchanged.
 * Build with -I <kernel tree>.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_core.h"
#include "nvme_xdp_pipeline_core.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                              \
	long long _expected = (long long)(expected);                          \
	checks++;                                                              \
	if (_actual != _expected) {                                            \
		fprintf(stderr, "%s:%d: got %lld, expected %lld\n",             \
			__FILE__, __LINE__, _actual, _expected);                    \
		failures++;                                                     \
	}                                                                       \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

/* Every UAPI field sits at a fixed offset; a u64 is 8-byte aligned. */
#define AT(type, member, off)						\
	_Static_assert(offsetof(struct type, member) == (off),		\
		       #type "." #member " moved")
#define SIZE(type, size)						\
	_Static_assert(sizeof(struct type) == (size),			\
		       "struct " #type " has implicit padding or grew")
#define U64(type, member)						\
	_Static_assert(offsetof(struct type, member) % 8 == 0 &&	\
		       __alignof__(((struct type *)0)->member) == 8,	\
		       #type "." #member " is not an aligned u64")

_Static_assert(XDEV_EXT_MECH_ABI_VERSION == 1, "mechanism ABI changed");
_Static_assert(XDEV_EXT_MECH_MAX_FRAMES == 32, "frame cap changed");
_Static_assert(XDEV_EXT_MECH_MAX_STAGES == 4, "stage cap changed");
_Static_assert(IORING_REGISTER_XDEV_EXT_MECH == 37, "register opcode moved");
_Static_assert(IORING_REGISTER_XDEV_EXT_UMEM == 35 &&
	       IORING_UNREGISTER_XDEV_EXT_UMEM == 36, "UMEM opcodes moved");

/* Class ids are the policy-layer backend numbers. */
_Static_assert((int)XDEV_EXT_MECH_CLASS_AFXDP == (int)XDEV_EXT_BINDING_BACKEND_AFXDP &&
	       XDEV_EXT_MECH_CLASS_AFXDP == 2, "AF_XDP class id");
_Static_assert((int)XDEV_EXT_MECH_CLASS_NVME == (int)XDEV_EXT_BINDING_BACKEND_NVME &&
	       XDEV_EXT_MECH_CLASS_NVME == 3, "NVMe class id");
_Static_assert((int)XDEV_EXT_MECH_CLASS_CE == (int)XDEV_EXT_BINDING_BACKEND_GPU &&
	       XDEV_EXT_MECH_CLASS_CE == 5, "CE class id");
_Static_assert((int)XDEV_EXT_MECH_DIR_TO_DEVICE ==
	       (int)XDEV_EXT_BINDING_DIRECTION_TO_DEVICE &&
	       (int)XDEV_EXT_MECH_DIR_FROM_DEVICE ==
	       (int)XDEV_EXT_BINDING_DIRECTION_FROM_DEVICE,
	       "stage direction values");

_Static_assert(XDEV_EXT_MECH_MEMBER_PREPARE == 1 && XDEV_EXT_MECH_MEMBER_BUILD == 2 &&
	       XDEV_EXT_MECH_MEMBER_COMPLETE == 3, "member values");
_Static_assert(XDEV_EXT_MECH_SITE_WORKER == 0 && XDEV_EXT_MECH_SITE_RX_GENERIC == 1 &&
	       XDEV_EXT_MECH_SITE_RX_NATIVE == 2 && XDEV_EXT_MECH_SITE_URING_CMD == 3 &&
	       XDEV_EXT_MECH_SITE_CREATE == 4, "callsite values");
_Static_assert(XDEV_EXT_MECH_BUILD_DEFAULT == 0 && XDEV_EXT_MECH_BUILD_SUBMIT == 1 &&
	       XDEV_EXT_MECH_BUILD_ABORT == 2, "build return values");
_Static_assert(XDEV_EXT_MECH_NEXT == 0 && XDEV_EXT_MECH_DONE == 1 &&
	       XDEV_EXT_MECH_RETRY == 2 && XDEV_EXT_MECH_ABORT == 3 &&
	       XDEV_EXT_MECH_HOLD == 4 && XDEV_EXT_MECH_PUBLISH == 5 &&
	       XDEV_EXT_MECH_RECYCLE == 6, "complete return values");
_Static_assert(XDEV_EXT_CE_OK == 0 && XDEV_EXT_CE_PRE_SUBMIT_FAILED == 1 &&
	       XDEV_EXT_CE_AMBIGUOUS == 2, "CE outcome values");
_Static_assert(XDEV_EXT_CE_F_COMPLETION_POINT == 1 && XDEV_EXT_CE_F_BARRIER == 2 &&
	       XDEV_EXT_CE_F_KNOWN_MASK == 3, "CE flag bits");
_Static_assert(XDEV_EXT_MECH_OP_CREATE == 1 && XDEV_EXT_MECH_OP_START == 2 &&
	       XDEV_EXT_MECH_OP_STOP == 3 && XDEV_EXT_MECH_OP_STATS == 4, "op codes");
_Static_assert(XDEV_EXT_MECH_POOL_XSK == 1 && XDEV_EXT_MECH_POOL_IOU_UMEM == 2,
	       "pool kinds");
_Static_assert(XDEV_EXT_MECH_START_F_USER_FRAMES == 1 &&
	       XDEV_EXT_MECH_START_F_RECYCLE == 2 &&
	       XDEV_EXT_MECH_START_F_USER_SPANS == 4 &&
	       XDEV_EXT_MECH_START_KNOWN_FLAGS == 7, "START flags");
_Static_assert(sizeof(struct xdev_ext_mech_start) == 40, "START v1 size unchanged");
_Static_assert(sizeof(struct xdev_ext_mech_user_span) == 8, "explicit source span size");
_Static_assert(XDEV_EXT_MECH_SESSION_NONE == 0 && XDEV_EXT_MECH_SESSION_ACTIVE == 1 &&
	       XDEV_EXT_MECH_SESSION_ERROR == 2 && XDEV_EXT_MECH_SESSION_STOPPING == 3 &&
	       XDEV_EXT_MECH_SESSION_STOPPED == 4 && XDEV_EXT_MECH_SESSION_ZOMBIE == 5,
	       "session states");
_Static_assert(XDEV_EXT_NVME_MECH_DESC_SIZE == 64, "NVMe descriptor is one SQE");

_Static_assert(sizeof(struct xdev_ext_binding_ctx_v2) == 136, "binding ctx size");
AT(xdev_ext_mech_ctx, base, 0);
AT(xdev_ext_mech_ctx, mech_abi_version, 136);
AT(xdev_ext_mech_ctx, member, 140);
AT(xdev_ext_mech_ctx, class_id, 144);
AT(xdev_ext_mech_ctx, callsite, 148);
AT(xdev_ext_mech_ctx, nr_frames, 152);
AT(xdev_ext_mech_ctx, desc_cap, 156);
AT(xdev_ext_mech_ctx, session_id, 160);
AT(xdev_ext_mech_ctx, batch_id, 168);
U64(xdev_ext_mech_ctx, session_id);
U64(xdev_ext_mech_ctx, batch_id);
SIZE(xdev_ext_mech_ctx, 176);

AT(xdev_ext_mech_frame_info, umem_addr, 0);
AT(xdev_ext_mech_frame_info, data_off, 8);
AT(xdev_ext_mech_frame_info, data_len, 12);
U64(xdev_ext_mech_frame_info, umem_addr);
SIZE(xdev_ext_mech_frame_info, 16);

AT(xdev_ext_mech_layout, frame_size, 0);
AT(xdev_ext_mech_layout, hdr_room, 4);
AT(xdev_ext_mech_layout, seg_len, 8);
AT(xdev_ext_mech_layout, group_bytes, 12);
SIZE(xdev_ext_mech_layout, 16);

AT(xdev_ext_mech_peer, local_mac, 0);
AT(xdev_ext_mech_peer, peer_mac, 6);
AT(xdev_ext_mech_peer, local_ip, 12);
AT(xdev_ext_mech_peer, peer_ip, 16);
AT(xdev_ext_mech_peer, local_port, 20);
AT(xdev_ext_mech_peer, peer_port, 22);
SIZE(xdev_ext_mech_peer, 24);

AT(xdev_ext_nvme_mech_info, l, 0);
AT(xdev_ext_nvme_mech_info, lba_shift, 16);
AT(xdev_ext_nvme_mech_info, max_nlb, 20);
AT(xdev_ext_nvme_mech_info, window_slba, 24);
AT(xdev_ext_nvme_mech_info, window_nlb, 32);
AT(xdev_ext_nvme_mech_info, capacity_lbas, 40);
AT(xdev_ext_nvme_mech_info, sgl, 48);
AT(xdev_ext_nvme_mech_info, nr_frames, 52);
AT(xdev_ext_nvme_mech_info, f, 56);
U64(xdev_ext_nvme_mech_info, window_slba);
U64(xdev_ext_nvme_mech_info, window_nlb);
U64(xdev_ext_nvme_mech_info, capacity_lbas);
SIZE(xdev_ext_nvme_mech_info, 56 + 32 * 16);

AT(xdev_ext_afxdp_mech_info, l, 0);
AT(xdev_ext_afxdp_mech_info, mtu, 16);
AT(xdev_ext_afxdp_mech_info, nr_frames, 20);
AT(xdev_ext_afxdp_mech_info, peer, 24);
AT(xdev_ext_afxdp_mech_info, f, 48);
SIZE(xdev_ext_afxdp_mech_info, 48 + 32 * 16);

AT(xdev_ext_ce_mech_info, l, 0);
AT(xdev_ext_ce_mech_info, gpu_window_len, 16);
AT(xdev_ext_ce_mech_info, gpu_seg_size, 24);
AT(xdev_ext_ce_mech_info, max_entry_len, 28);
AT(xdev_ext_ce_mech_info, nr_frames, 32);
AT(xdev_ext_ce_mech_info, rsvd, 36);
AT(xdev_ext_ce_mech_info, f, 40);
U64(xdev_ext_ce_mech_info, gpu_window_len);
SIZE(xdev_ext_ce_mech_info, 56 + 32 * 16);
_Static_assert(XDEV_EXT_CE_MECH_ABI_VERSION == 2, "CE lease ABI");

AT(xdev_ext_ce_copy_desc, frame_pos, 0);
AT(xdev_ext_ce_copy_desc, frame_off, 4);
AT(xdev_ext_ce_copy_desc, gpu_off, 8);
AT(xdev_ext_ce_copy_desc, len, 16);
AT(xdev_ext_ce_copy_desc, flags, 20);
U64(xdev_ext_ce_copy_desc, gpu_off);
SIZE(xdev_ext_ce_copy_desc, 24);

AT(xdev_ext_nvme_mech_cqe, result, 0);
AT(xdev_ext_nvme_mech_cqe, status, 8);
AT(xdev_ext_nvme_mech_cqe, rsvd, 10);
AT(xdev_ext_nvme_mech_cqe, err, 12);
U64(xdev_ext_nvme_mech_cqe, result);
SIZE(xdev_ext_nvme_mech_cqe, 16);

AT(xdev_ext_afxdp_tx_cqe, err, 0);
AT(xdev_ext_afxdp_tx_cqe, rsvd, 4);
SIZE(xdev_ext_afxdp_tx_cqe, 8);

AT(xdev_ext_ce_mech_cqe, outcome, 0);
AT(xdev_ext_ce_mech_cqe, backend_status, 4);
AT(xdev_ext_ce_mech_cqe, bytes_done, 8);
AT(xdev_ext_ce_mech_cqe, entries_done, 16);
AT(xdev_ext_ce_mech_cqe, rsvd, 20);
U64(xdev_ext_ce_mech_cqe, bytes_done);
SIZE(xdev_ext_ce_mech_cqe, 24);

AT(io_uring_xdev_ext_mech, op, 0);
AT(io_uring_xdev_ext_mech, rsvd, 4);
AT(io_uring_xdev_ext_mech, arg, 8);
U64(io_uring_xdev_ext_mech, arg);
SIZE(io_uring_xdev_ext_mech, 16);

AT(xdev_ext_mech_stage_uapi, class_id, 0);
AT(xdev_ext_mech_stage_uapi, direction, 4);
AT(xdev_ext_mech_stage_uapi, fd, 8);
AT(xdev_ext_mech_stage_uapi, flags, 12);
AT(xdev_ext_mech_stage_uapi, arg0, 16);
AT(xdev_ext_mech_stage_uapi, arg1, 24);
U64(xdev_ext_mech_stage_uapi, arg0);
U64(xdev_ext_mech_stage_uapi, arg1);
SIZE(xdev_ext_mech_stage_uapi, 32);

AT(xdev_ext_mech_create, abi_version, 0);
AT(xdev_ext_mech_create, nr_stages, 4);
AT(xdev_ext_mech_create, pool_kind, 8);
AT(xdev_ext_mech_create, pool_fd, 12);
AT(xdev_ext_mech_create, layout, 16);
AT(xdev_ext_mech_create, depth, 32);
AT(xdev_ext_mech_create, eventfd, 36);
AT(xdev_ext_mech_create, peer, 40);
AT(xdev_ext_mech_create, st, 64);
AT(xdev_ext_mech_create, session_id, 192);
U64(xdev_ext_mech_create, session_id);
SIZE(xdev_ext_mech_create, 200);

AT(xdev_ext_mech_start, session_id, 0);
AT(xdev_ext_mech_start, nr_batches, 8);
AT(xdev_ext_mech_start, first_seq, 16);
AT(xdev_ext_mech_start, flags, 24);
AT(xdev_ext_mech_start, nr_user_frames, 28);
AT(xdev_ext_mech_start, user_frames, 32);
U64(xdev_ext_mech_start, session_id);
U64(xdev_ext_mech_start, nr_batches);
U64(xdev_ext_mech_start, first_seq);
U64(xdev_ext_mech_start, user_frames);
SIZE(xdev_ext_mech_start, 40);

AT(xdev_ext_mech_stats, session_id, 0);
AT(xdev_ext_mech_stats, batches_done, 8);
AT(xdev_ext_mech_stats, batches_abort, 16);
AT(xdev_ext_mech_stats, rejects, 24);
AT(xdev_ext_mech_stats, recycled, 32);
AT(xdev_ext_mech_stats, held, 40);
AT(xdev_ext_mech_stats, sequestered, 48);
AT(xdev_ext_mech_stats, timeouts, 56);
AT(xdev_ext_mech_stats, inflight, 64);
AT(xdev_ext_mech_stats, native_publish, 72);
AT(xdev_ext_mech_stats, protocol_err, 80);
AT(xdev_ext_mech_stats, published, 88);
AT(xdev_ext_mech_stats, submitted, 96);
AT(xdev_ext_mech_stats, completed, 128);
AT(xdev_ext_mech_stats, last_err, 160);
AT(xdev_ext_mech_stats, state, 164);
U64(xdev_ext_mech_stats, session_id);
U64(xdev_ext_mech_stats, inflight);
U64(xdev_ext_mech_stats, published);
SIZE(xdev_ext_mech_stats, 168);

static void test_uapi_values(void)
{
	struct xdev_ext_mech_create create = { .abi_version = XDEV_EXT_MECH_ABI_VERSION };
	struct xdev_ext_mech_stats stats = { 0 };

	/* Array members cover every stage and frame slot. */
	EXPECT_EQ(sizeof(create.st) / sizeof(create.st[0]), XDEV_EXT_MECH_MAX_STAGES);
	EXPECT_EQ(sizeof(stats.submitted) / sizeof(stats.submitted[0]),
		  XDEV_EXT_MECH_MAX_STAGES);
	EXPECT_EQ(sizeof(stats.completed) / sizeof(stats.completed[0]),
		  XDEV_EXT_MECH_MAX_STAGES);
	EXPECT_EQ(sizeof(((struct xdev_ext_nvme_mech_info *)0)->f) /
		  sizeof(struct xdev_ext_mech_frame_info), XDEV_EXT_MECH_MAX_FRAMES);
	EXPECT_EQ(create.abi_version, 1);
}

static const char *const frame_name[] = {
	"USER", "K_FREE", "HELD", "INFLIGHT", "SEQUESTERED", "NIC_RX",
};

static bool frame_edge_expected(unsigned int from, unsigned int to)
{
	switch (from) {
	case XDEV_EXT_MECH_F_USER:
		return to == XDEV_EXT_MECH_F_K_FREE || to == XDEV_EXT_MECH_F_HELD ||
		       to == XDEV_EXT_MECH_F_NIC_RX;
	case XDEV_EXT_MECH_F_K_FREE:
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_USER ||
		       to == XDEV_EXT_MECH_F_NIC_RX;
	case XDEV_EXT_MECH_F_NIC_RX:
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_K_FREE ||
		       to == XDEV_EXT_MECH_F_USER || to == XDEV_EXT_MECH_F_SEQUESTERED;
	case XDEV_EXT_MECH_F_HELD:
		return to == XDEV_EXT_MECH_F_INFLIGHT || to == XDEV_EXT_MECH_F_K_FREE ||
		       to == XDEV_EXT_MECH_F_USER || to == XDEV_EXT_MECH_F_SEQUESTERED;
	case XDEV_EXT_MECH_F_INFLIGHT:
		return to == XDEV_EXT_MECH_F_HELD || to == XDEV_EXT_MECH_F_SEQUESTERED;
	default:
		return false;
	}
}

static void test_frame_states(void)
{
	unsigned int from, to;
	__u8 word;

	/* A zeroed state array means every frame is still the user's. */
	EXPECT_EQ(XDEV_EXT_MECH_F_USER, 0);
	EXPECT_EQ(XDEV_EXT_MECH_F_NR, 6);
	for (from = 0; from < XDEV_EXT_MECH_F_NR; from++) {
		for (to = 0; to < XDEV_EXT_MECH_F_NR; to++) {
			bool ok = frame_edge_expected(from, to);

			word = from;
			EXPECT_EQ(xdev_ext_mech_frame_edge_ok(from, to), ok);
			EXPECT_EQ(xdev_ext_mech_frame_move(&word, from, to),
				  ok ? 0 : -EINVAL);
			EXPECT_EQ(word, ok ? to : from);
			if (!ok)
				continue;
			/* The CAS fails when another owner moved the word. */
			word = (from + 1) % XDEV_EXT_MECH_F_NR;
			EXPECT_EQ(xdev_ext_mech_frame_move(&word, from, to), -EBUSY);
			EXPECT_EQ(word, (from + 1) % XDEV_EXT_MECH_F_NR);
		}
	}
	/* Unknown states are never a legal source or target. */
	word = XDEV_EXT_MECH_F_NR;
	EXPECT_EQ(xdev_ext_mech_frame_move(&word, XDEV_EXT_MECH_F_NR, XDEV_EXT_MECH_F_USER),
		  -EINVAL);
	EXPECT_FALSE(xdev_ext_mech_frame_edge_ok(XDEV_EXT_MECH_F_HELD, 0xff));
	/* A sequestered frame never leaves that state. */
	word = XDEV_EXT_MECH_F_SEQUESTERED;
	for (to = 0; to < XDEV_EXT_MECH_F_NR; to++)
		EXPECT_EQ(xdev_ext_mech_frame_move(&word, XDEV_EXT_MECH_F_SEQUESTERED, to),
			  -EINVAL);
	EXPECT_EQ(xdev_ext_mech_frame_state(&word), XDEV_EXT_MECH_F_SEQUESTERED);
	(void)frame_name;
}

/* Events that change a batch in @state; every other one must be refused. */
static bool batch_event_expected(unsigned int state, unsigned int ev)
{
	switch (ev) {
	case XDEV_EXT_MECH_EV_OPEN:
		return state == XDEV_EXT_MECH_B_FREE;
	case XDEV_EXT_MECH_EV_READY:
		return state == XDEV_EXT_MECH_B_FREE || state == XDEV_EXT_MECH_B_OPEN;
	case XDEV_EXT_MECH_EV_SUBMIT:
		return state == XDEV_EXT_MECH_B_READY;
	case XDEV_EXT_MECH_EV_NEXT:
	case XDEV_EXT_MECH_EV_RETRY:
	case XDEV_EXT_MECH_EV_DONE:
	case XDEV_EXT_MECH_EV_SEQUESTER:
		return state == XDEV_EXT_MECH_B_IN_FLIGHT;
	case XDEV_EXT_MECH_EV_ABORT:
		return state == XDEV_EXT_MECH_B_OPEN || state == XDEV_EXT_MECH_B_READY ||
		       state == XDEV_EXT_MECH_B_IN_FLIGHT;
	case XDEV_EXT_MECH_EV_RELEASE:
		return state == XDEV_EXT_MECH_B_DONE || state == XDEV_EXT_MECH_B_ABORT;
	default:
		return false;
	}
}

static void batch_put(struct xdev_ext_mech_bstate *b, unsigned int state)
{
	xdev_ext_mech_bstate_init(b, 3);
	b->state = state;
	b->stage = state == XDEV_EXT_MECH_B_READY || state == XDEV_EXT_MECH_B_IN_FLIGHT;
}

static void test_batch_state_machine(void)
{
	struct xdev_ext_mech_bstate b, before;
	unsigned int state, ev;

	xdev_ext_mech_bstate_init(&b, 3);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_FREE);
	EXPECT_EQ(b.nr_stages, 3);

	/* Every (state, event) pair: legal edges move, the rest leave b alone. */
	for (state = 0; state < XDEV_EXT_MECH_B_NR; state++) {
		for (ev = 0; ev <= XDEV_EXT_MECH_EV_RELEASE + 1; ev++) {
			bool ok = batch_event_expected(state, ev);

			batch_put(&b, state);
			before = b;
			EXPECT_EQ(xdev_ext_mech_batch_step(&b, ev, 2), ok ? 0 : -EINVAL);
			if (!ok)
				EXPECT_EQ(memcmp(&b, &before, sizeof(b)), 0);
		}
	}

	/* RX source: OPEN, grouped into stage 1, then through stages 1 and 2. */
	xdev_ext_mech_bstate_init(&b, 3);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_OPEN, 0), 0);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_OPEN);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_READY, 3), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_READY, 1), 0);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_READY);
	EXPECT_EQ(b.stage, 1);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_SUBMIT, 0), 0);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_IN_FLIGHT);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_RETRY, 0), 0);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_READY);
	EXPECT_EQ(b.stage, 1);
	EXPECT_EQ(b.retries, 1);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_SUBMIT, 0), 0);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_NEXT, 0), 0);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_READY);
	EXPECT_EQ(b.stage, 2);
	EXPECT_EQ(b.retries, 0);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_SUBMIT, 0), 0);
	/* NEXT after the last stage finishes the batch. */
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_NEXT, 0), 0);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_DONE);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_RELEASE, 0), 0);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_FREE);
	EXPECT_EQ(b.stage, 0);

	/* START source: FREE straight to READY(0); DONE from any stage. */
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_READY, 0), 0);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_SUBMIT, 0), 0);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_DONE, 0), 0);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_DONE);

	/* A sequestered batch has no way out, RELEASE included. */
	batch_put(&b, XDEV_EXT_MECH_B_IN_FLIGHT);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_SEQUESTER, 0), 0);
	for (ev = 0; ev <= XDEV_EXT_MECH_EV_RELEASE; ev++)
		EXPECT_EQ(xdev_ext_mech_batch_step(&b, ev, 0), -EINVAL);
	EXPECT_EQ(b.state, XDEV_EXT_MECH_B_SEQUESTERED);

	/* At most one stage is ever in flight: SUBMIT needs READY. */
	batch_put(&b, XDEV_EXT_MECH_B_IN_FLIGHT);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_SUBMIT, 0), -EINVAL);
	/* A session has between one and XDEV_EXT_MECH_MAX_STAGES stages. */
	xdev_ext_mech_bstate_init(&b, 0);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_READY, 0), -EINVAL);
	xdev_ext_mech_bstate_init(&b, XDEV_EXT_MECH_MAX_STAGES + 1);
	EXPECT_EQ(xdev_ext_mech_batch_step(&b, XDEV_EXT_MECH_EV_READY, 0), -EINVAL);
}

static void test_slots(void)
{
	__u8 scratch[4 * 24];

	memset(scratch, 0, sizeof(scratch));
	EXPECT_EQ(xdev_ext_mech_slots_used(scratch, 24, 4), 0);
	scratch[0] = 1;
	EXPECT_EQ(xdev_ext_mech_slots_used(scratch, 24, 4), 1);
	/* Any non-zero byte marks a slot used, not only a key field. */
	scratch[24 + 23] = 1;
	EXPECT_EQ(xdev_ext_mech_slots_used(scratch, 24, 4), 2);
	scratch[3 * 24 + 5] = 1;
	EXPECT_EQ(xdev_ext_mech_slots_used(scratch, 24, 4), -EPROTO);
	scratch[2 * 24 + 16] = 1;
	EXPECT_EQ(xdev_ext_mech_slots_used(scratch, 24, 4), 4);
	memset(scratch, 0, sizeof(scratch));
	scratch[24] = 1;
	EXPECT_EQ(xdev_ext_mech_slots_used(scratch, 24, 4), -EPROTO);
	EXPECT_EQ(xdev_ext_mech_slots_used(scratch, 0, 4), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_slots_used(scratch, 24, 0), 0);
}

static void test_spans_and_windows(void)
{
	const __u64 max = UINT64_MAX;

	EXPECT_TRUE(xdev_ext_mech_span_in(0, 4096, 4096));
	EXPECT_TRUE(xdev_ext_mech_span_in(4096, 0, 4096));
	EXPECT_FALSE(xdev_ext_mech_span_in(1, 4096, 4096));
	EXPECT_FALSE(xdev_ext_mech_span_in(4097, 0, 4096));
	EXPECT_FALSE(xdev_ext_mech_span_in(max, 2, max));
	EXPECT_FALSE(xdev_ext_mech_span_in(2, max, max));
	EXPECT_TRUE(xdev_ext_mech_span_in(max - 1, 1, max));

	/* A window span is non-empty and inside [base, base + size). */
	EXPECT_TRUE(xdev_ext_mech_window_ok(100, 16, 100, 16));
	EXPECT_TRUE(xdev_ext_mech_window_ok(115, 1, 100, 16));
	EXPECT_FALSE(xdev_ext_mech_window_ok(99, 1, 100, 16));
	EXPECT_FALSE(xdev_ext_mech_window_ok(100, 17, 100, 16));
	EXPECT_FALSE(xdev_ext_mech_window_ok(100, 0, 100, 16));
	EXPECT_FALSE(xdev_ext_mech_window_ok(max, 1, max - 1, 2));
	EXPECT_FALSE(xdev_ext_mech_window_ok(max - 1, 2, max - 1, 2));
	EXPECT_FALSE(xdev_ext_mech_window_ok(2, max - 1, 0, max));
	EXPECT_FALSE(xdev_ext_mech_window_ok(0, 1, max, 2));

	EXPECT_TRUE(xdev_ext_mech_spans_overlap(0, 10, 9, 1));
	EXPECT_FALSE(xdev_ext_mech_spans_overlap(0, 10, 10, 1));
	EXPECT_FALSE(xdev_ext_mech_spans_overlap(10, 1, 0, 10));
	EXPECT_FALSE(xdev_ext_mech_spans_overlap(0, 0, 0, 10));
	EXPECT_TRUE(xdev_ext_mech_spans_overlap(max - 1, 1, max - 4, 8));

	/* A device-contiguous segment must not be crossed. */
	EXPECT_TRUE(xdev_ext_mech_span_one_segment(0, 65536, 65536));
	EXPECT_TRUE(xdev_ext_mech_span_one_segment(65535, 1, 65536));
	EXPECT_FALSE(xdev_ext_mech_span_one_segment(65535, 2, 65536));
	EXPECT_TRUE(xdev_ext_mech_span_one_segment(65535, 2, 0));
	EXPECT_FALSE(xdev_ext_mech_span_one_segment(0, 0, 65536));
	EXPECT_FALSE(xdev_ext_mech_span_one_segment(max, 2, 65536));
}

static void test_cover(void)
{
	const struct xdev_ext_mech_frame_info f[3] = {
		{ .umem_addr = 0, .data_off = 360, .data_len = 1432 },
		{ .umem_addr = 4096, .data_off = 360, .data_len = 0 },
		{ .umem_addr = 8192, .data_off = 360, .data_len = 1032 },
	};
	struct xdev_ext_mech_cover c;

	xdev_ext_mech_cover_init(&c, f, 3);
	EXPECT_FALSE(xdev_ext_mech_cover_done(&c));
	/* Split frame 0, skip the empty frame 1, then cover frame 2. */
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 0, 360, 1000), 0);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 0, 1360, 432), 0);
	EXPECT_EQ(c.pos, 2);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 2, 360, 1032), 0);
	EXPECT_TRUE(xdev_ext_mech_cover_done(&c));
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 2, 1392, 1), -ERANGE);

	/* Gap, overlap, wrong frame, past the data, empty, out of order. */
	xdev_ext_mech_cover_init(&c, f, 3);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 0, 361, 10), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 0, 360, 100), 0);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 0, 450, 10), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 2, 360, 10), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 0, 460, 1333), -ERANGE);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 0, 460, 0), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 0, 460, UINT32_MAX), -ERANGE);
	EXPECT_FALSE(xdev_ext_mech_cover_done(&c));
	EXPECT_EQ(xdev_ext_mech_cover_take(&c, 3, 0, 1), -EINVAL);

	/* A batch with no data at all is covered from the start. */
	xdev_ext_mech_cover_init(&c, &f[1], 1);
	EXPECT_TRUE(xdev_ext_mech_cover_done(&c));
	xdev_ext_mech_cover_init(&c, f, 0);
	EXPECT_TRUE(xdev_ext_mech_cover_done(&c));
}

static void test_layout(void)
{
	struct xdev_ext_mech_layout l = {
		.frame_size = 4096, .hdr_room = 360, .seg_len = 1432,
		.group_bytes = 8192,
	};
	__u32 off = 0, len = 0, i, sum = 0;
	int nr;

	/* The NXP group: 6 frames, 1432 x 5 + 1032 bytes. */
	nr = xdev_ext_mech_layout_frames(&l);
	EXPECT_EQ(nr, 6);
	for (i = 0; i < 6; i++) {
		EXPECT_EQ(xdev_ext_mech_layout_span(&l, i, &off, &len), 0);
		EXPECT_EQ(off, 360);
		EXPECT_EQ(len, i < 5 ? 1432 : 1032);
		sum += len;
	}
	EXPECT_EQ(sum, 8192);
	EXPECT_EQ(xdev_ext_mech_layout_span(&l, 6, &off, &len), -ERANGE);

	l.group_bytes = 1432 * 32;
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), 32);
	l.group_bytes++;
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), -E2BIG);
	l.group_bytes = 8192;
	l.hdr_room = 4096 - 1432 + 1;
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), -EINVAL);
	l.hdr_room = UINT32_MAX;
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), -EINVAL);
	l.hdr_room = 0;
	l.seg_len = 0;
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), -EINVAL);
	l.seg_len = 4096;
	l.group_bytes = 0;
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), -EINVAL);
	l.group_bytes = 4096;
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), 1);
	l.frame_size = 0;
	EXPECT_EQ(xdev_ext_mech_layout_frames(&l), -EINVAL);
}

static void test_hold_and_group(void)
{
	struct xdev_ext_mech_group g;
	__u32 pos;

	/* Intent: pos < count <= 32, a non-empty span inside the packet. */
	EXPECT_EQ(xdev_ext_mech_hold_check(0, 6, 360, 1432, 278, 1514), 0);
	EXPECT_EQ(xdev_ext_mech_hold_check(5, 6, 360, 1032, 278, 1114), 0);
	EXPECT_EQ(xdev_ext_mech_hold_check(6, 6, 360, 1432, 278, 1514), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_hold_check(0, 0, 360, 1432, 278, 1514), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_hold_check(0, 33, 360, 1432, 278, 1514), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_hold_check(0, 6, 360, 0, 278, 1514), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_hold_check(0, 6, 277, 10, 278, 1514), -ERANGE);
	EXPECT_EQ(xdev_ext_mech_hold_check(0, 6, 360, 1433, 278, 1514), -ERANGE);
	EXPECT_EQ(xdev_ext_mech_hold_check(0, 6, UINT32_MAX, 2, 278, 1514), -ERANGE);
	EXPECT_EQ(xdev_ext_mech_hold_check(0, 6, 360, 1, UINT32_MAX, 2), -ERANGE);

	xdev_ext_mech_group_init(&g, 77, 6);
	EXPECT_EQ(g.key, 77);
	for (pos = 0; pos < 6; pos++) {
		EXPECT_FALSE(xdev_ext_mech_group_full(&g));
		EXPECT_EQ(xdev_ext_mech_group_add(&g, 77, 5 - pos, 6), 0);
		EXPECT_EQ(xdev_ext_mech_group_add(&g, 77, 5 - pos, 6), -EEXIST);
	}
	EXPECT_TRUE(xdev_ext_mech_group_full(&g));
	xdev_ext_mech_group_init(&g, 77, 6);
	EXPECT_EQ(xdev_ext_mech_group_add(&g, 78, 0, 6), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_group_add(&g, 77, 0, 5), -EINVAL);
	EXPECT_EQ(xdev_ext_mech_group_add(&g, 77, 6, 6), -EINVAL);
	xdev_ext_mech_group_init(&g, 1, 32);
	for (pos = 0; pos < 32; pos++)
		EXPECT_EQ(xdev_ext_mech_group_add(&g, 1, pos, 32), 0);
	EXPECT_TRUE(xdev_ext_mech_group_full(&g));
}

static void test_session_rules(void)
{
	struct xdev_ext_mech_sess s;
	__u32 st;

	xdev_ext_mech_sess_init(&s);
	EXPECT_EQ(s.state, XDEV_EXT_MECH_SESSION_ACTIVE);
	EXPECT_EQ(s.refs, 1);
	EXPECT_TRUE(xdev_ext_mech_sess_admits(&s));

	/* Every batch in flight holds a session reference. */
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), 0);
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), 0);
	EXPECT_EQ(s.refs, 3);
	EXPECT_EQ(s.inflight, 2);
	EXPECT_FALSE(xdev_ext_mech_sess_batch_end(&s, false));
	EXPECT_EQ(s.refs, 2);

	/* A sequestered batch stops admission and survives STOP. */
	EXPECT_FALSE(xdev_ext_mech_sess_batch_end(&s, true));
	EXPECT_EQ(s.state, XDEV_EXT_MECH_SESSION_ERROR);
	EXPECT_EQ(s.sequestered, 1);
	EXPECT_FALSE(xdev_ext_mech_sess_admits(&s));
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), -ESHUTDOWN);
	EXPECT_EQ(xdev_ext_mech_sess_stop(&s), 0);
	EXPECT_EQ(s.state, XDEV_EXT_MECH_SESSION_STOPPING);
	EXPECT_EQ(xdev_ext_mech_sess_stop(&s), -EALREADY);
	EXPECT_EQ(xdev_ext_mech_sess_drain(&s, false), XDEV_EXT_MECH_SESSION_ZOMBIE);
	EXPECT_EQ(xdev_ext_mech_sess_ref_fate(&s), XDEV_EXT_MECH_REFS_QUARANTINE);
	EXPECT_EQ(xdev_ext_mech_sess_drain(&s, true), -EINVAL);
	/* The creator reference is the last one: the object goes, the refs stay. */
	EXPECT_TRUE(xdev_ext_mech_sess_put(&s));
	EXPECT_EQ(xdev_ext_mech_sess_ref_fate(&s), XDEV_EXT_MECH_REFS_QUARANTINE);

	/* Clean stop: wait while in flight, STOPPED once drained. */
	xdev_ext_mech_sess_init(&s);
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), 0);
	EXPECT_EQ(xdev_ext_mech_sess_ref_fate(&s), XDEV_EXT_MECH_REFS_KEEP);
	EXPECT_EQ(xdev_ext_mech_sess_stop(&s), 0);
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), -ESHUTDOWN);
	EXPECT_EQ(xdev_ext_mech_sess_drain(&s, false), XDEV_EXT_MECH_SESSION_STOPPING);
	EXPECT_EQ(xdev_ext_mech_sess_ref_fate(&s), XDEV_EXT_MECH_REFS_KEEP);
	EXPECT_FALSE(xdev_ext_mech_sess_batch_end(&s, false));
	EXPECT_EQ(xdev_ext_mech_sess_drain(&s, false), XDEV_EXT_MECH_SESSION_STOPPED);
	EXPECT_EQ(xdev_ext_mech_sess_ref_fate(&s), XDEV_EXT_MECH_REFS_RELEASE);
	EXPECT_TRUE(xdev_ext_mech_sess_put(&s));

	/* Drain timeout with a batch still in flight: ZOMBIE, object kept. */
	xdev_ext_mech_sess_init(&s);
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), 0);
	EXPECT_EQ(xdev_ext_mech_sess_stop(&s), 0);
	EXPECT_EQ(xdev_ext_mech_sess_drain(&s, true), XDEV_EXT_MECH_SESSION_ZOMBIE);
	EXPECT_EQ(xdev_ext_mech_sess_ref_fate(&s), XDEV_EXT_MECH_REFS_QUARANTINE);
	EXPECT_FALSE(xdev_ext_mech_sess_put(&s));
	/* The late completion drops the last reference. */
	EXPECT_TRUE(xdev_ext_mech_sess_batch_end(&s, false));
	EXPECT_EQ(s.state, XDEV_EXT_MECH_SESSION_ZOMBIE);

	/* No stop before a stop; refs never wrap. */
	xdev_ext_mech_sess_init(&s);
	EXPECT_EQ(xdev_ext_mech_sess_drain(&s, false), -EINVAL);
	s.refs = UINT32_MAX;
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), -EOVERFLOW);

	/* CREATE binds in NONE and admits nothing; activation happens once. */
	xdev_ext_mech_sess_init(&s);
	s.state = XDEV_EXT_MECH_SESSION_NONE;
	EXPECT_FALSE(xdev_ext_mech_sess_admits(&s));
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), -ESHUTDOWN);
	EXPECT_EQ(xdev_ext_mech_sess_activate(&s), 0);
	EXPECT_EQ(s.state, XDEV_EXT_MECH_SESSION_ACTIVE);
	EXPECT_TRUE(xdev_ext_mech_sess_admits(&s));
	EXPECT_EQ(xdev_ext_mech_sess_activate(&s), -ESHUTDOWN);
	EXPECT_EQ(s.state, XDEV_EXT_MECH_SESSION_ACTIVE);

	/*
	 * A stop while CREATE still binds (a stage's device went away) is
	 * kept: the activation that follows fails and nothing is admitted.
	 */
	xdev_ext_mech_sess_init(&s);
	s.state = XDEV_EXT_MECH_SESSION_NONE;
	EXPECT_EQ(xdev_ext_mech_sess_stop(&s), 0);
	EXPECT_EQ(s.state, XDEV_EXT_MECH_SESSION_STOPPING);
	EXPECT_EQ(xdev_ext_mech_sess_activate(&s), -ESHUTDOWN);
	EXPECT_FALSE(xdev_ext_mech_sess_admits(&s));
	EXPECT_EQ(xdev_ext_mech_sess_batch_begin(&s), -ESHUTDOWN);
	EXPECT_EQ(xdev_ext_mech_sess_drain(&s, false), XDEV_EXT_MECH_SESSION_STOPPED);
	EXPECT_EQ(xdev_ext_mech_sess_activate(&s), -ESHUTDOWN);
	EXPECT_EQ(xdev_ext_mech_sess_ref_fate(&s), XDEV_EXT_MECH_REFS_RELEASE);
	EXPECT_TRUE(xdev_ext_mech_sess_put(&s));

	/* Only NONE activates. */
	for (st = XDEV_EXT_MECH_SESSION_ACTIVE; st <= XDEV_EXT_MECH_SESSION_ZOMBIE; st++) {
		xdev_ext_mech_sess_init(&s);
		s.state = st;
		EXPECT_EQ(xdev_ext_mech_sess_activate(&s), -ESHUTDOWN);
		EXPECT_EQ(s.state, st);
	}
}

static void test_quarantine(void)
{
	struct xdev_ext_mech_quarantine q = { 0 };

	xdev_ext_mech_quarantine_add(&q, 3, 6);
	xdev_ext_mech_quarantine_add(&q, 1, 0);
	EXPECT_EQ(q.objects, 4);
	EXPECT_EQ(q.frames, 6);
	q.frames = UINT64_MAX - 1;
	xdev_ext_mech_quarantine_add(&q, 0, 5);
	EXPECT_EQ(q.frames, UINT64_MAX);
	EXPECT_EQ(q.objects, 4);
}

static bool ret_expected(__u32 cls, __u32 member, __u32 site, __s32 ret)
{
	switch (member) {
	case XDEV_EXT_MECH_MEMBER_PREPARE:
		return site == XDEV_EXT_MECH_SITE_CREATE && ret <= 0 && ret >= -4095;
	case XDEV_EXT_MECH_MEMBER_BUILD:
		if (site != XDEV_EXT_MECH_SITE_WORKER &&
		    !(site == XDEV_EXT_MECH_SITE_URING_CMD && cls == XDEV_EXT_MECH_CLASS_NVME))
			return false;
		return ret >= XDEV_EXT_MECH_BUILD_DEFAULT && ret <= XDEV_EXT_MECH_BUILD_ABORT;
	case XDEV_EXT_MECH_MEMBER_COMPLETE:
		if (site == XDEV_EXT_MECH_SITE_WORKER)
			return ret >= XDEV_EXT_MECH_NEXT && ret <= XDEV_EXT_MECH_ABORT;
		if (site == XDEV_EXT_MECH_SITE_URING_CMD && cls == XDEV_EXT_MECH_CLASS_NVME)
			return ret == XDEV_EXT_MECH_DONE || ret == XDEV_EXT_MECH_ABORT;
		if ((site == XDEV_EXT_MECH_SITE_RX_GENERIC ||
		     site == XDEV_EXT_MECH_SITE_RX_NATIVE ||
		     site == XDEV_EXT_MECH_SITE_RX_HOLD_RESULT) &&
		    cls == XDEV_EXT_MECH_CLASS_AFXDP)
			return ret >= XDEV_EXT_MECH_HOLD && ret <= XDEV_EXT_MECH_RECYCLE;
		return false;
	default:
		return false;
	}
}

static void test_return_values(void)
{
	static const __u32 classes[] = {
		XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_CLASS_CE,
	};
	static const __s32 rets[] = {
		INT32_MIN, -4096, -4095, -1, 0, 1, 2, 3, 4, 5, 6, 7, INT32_MAX,
	};
	__u32 c, member, site, r;
	bool illegal;

	for (c = 0; c < 3; c++)
		for (member = 0; member <= 4; member++)
			for (site = 0; site <= 6; site++)
				for (r = 0; r < sizeof(rets) / sizeof(rets[0]); r++)
					EXPECT_EQ(xdev_ext_mech_ret_legal(classes[c], member,
								     site, rets[r]),
						  ret_expected(classes[c], member,
							       site, rets[r]));
	/* No other class id is legal anywhere. */
	EXPECT_FALSE(xdev_ext_mech_ret_legal(XDEV_EXT_BINDING_BACKEND_SOCKET,
					XDEV_EXT_MECH_MEMBER_BUILD,
					XDEV_EXT_MECH_SITE_WORKER, 1));

	/* Fail-closed replacements for an illegal value. */
	EXPECT_EQ(xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_MEMBER_COMPLETE,
				       XDEV_EXT_MECH_SITE_WORKER, XDEV_EXT_MECH_HOLD,
				       &illegal), XDEV_EXT_MECH_ABORT);
	EXPECT_TRUE(illegal);
	EXPECT_EQ(xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_MEMBER_COMPLETE,
				       XDEV_EXT_MECH_SITE_WORKER, XDEV_EXT_MECH_DONE,
				       &illegal), XDEV_EXT_MECH_DONE);
	EXPECT_FALSE(illegal);
	EXPECT_EQ(xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_MEMBER_BUILD,
				       XDEV_EXT_MECH_SITE_WORKER, 9, &illegal),
		  XDEV_EXT_MECH_BUILD_ABORT);
	EXPECT_TRUE(illegal);
	EXPECT_EQ(xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_AFXDP,
				       XDEV_EXT_MECH_MEMBER_COMPLETE,
				       XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_DONE,
				       &illegal), XDEV_EXT_MECH_PUBLISH);
	EXPECT_TRUE(illegal);
	EXPECT_EQ(xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_MEMBER_PREPARE,
				       XDEV_EXT_MECH_SITE_CREATE, 1, &illegal),
		  -EPROTO);
	EXPECT_TRUE(illegal);
	EXPECT_EQ(xdev_ext_mech_ret_resolve(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_MEMBER_PREPARE,
				       XDEV_EXT_MECH_SITE_CREATE, -EPERM, &illegal),
		  -EPERM);
	EXPECT_FALSE(illegal);
}

static void test_rx_resolve(void)
{
	bool proto, native;

	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_HOLD,
				      true, &proto, &native), XDEV_EXT_MECH_HOLD);
	EXPECT_FALSE(proto);
	EXPECT_FALSE(native);
	/* HOLD without a valid intent publishes and counts a protocol error. */
	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_HOLD,
				      false, &proto, &native), XDEV_EXT_MECH_PUBLISH);
	EXPECT_TRUE(proto);
	EXPECT_FALSE(native);
	/* A recorded intent is dropped unless the program returns HOLD. */
	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_RECYCLE,
				      true, &proto, &native), XDEV_EXT_MECH_RECYCLE);
	EXPECT_FALSE(proto);
	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_PUBLISH,
				      true, &proto, &native), XDEV_EXT_MECH_PUBLISH);
	EXPECT_FALSE(proto);
	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_NEXT,
				      false, &proto, &native), XDEV_EXT_MECH_PUBLISH);
	EXPECT_TRUE(proto);
	/* Native ZC owns the original buffer and can hold or recycle it. */
	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_RX_NATIVE, XDEV_EXT_MECH_HOLD,
				      true, &proto, &native), XDEV_EXT_MECH_HOLD);
	EXPECT_FALSE(proto);
	EXPECT_FALSE(native);
	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_RX_NATIVE, XDEV_EXT_MECH_RECYCLE,
				      false, &proto, &native), XDEV_EXT_MECH_RECYCLE);
	EXPECT_FALSE(native);
	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_RX_NATIVE, XDEV_EXT_MECH_HOLD,
				      false, &proto, &native), XDEV_EXT_MECH_PUBLISH);
	EXPECT_TRUE(proto);
	EXPECT_TRUE(native);
	EXPECT_EQ(xdev_ext_mech_rx_resolve(XDEV_EXT_MECH_SITE_WORKER, XDEV_EXT_MECH_HOLD,
				      true, &proto, &native), XDEV_EXT_MECH_PUBLISH);
	EXPECT_TRUE(proto);
}

static void test_retry(void)
{
	/* NVMe: a status without DNR, bounded. */
	EXPECT_TRUE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_NVME, 0, 0x0002));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_NVME, 0, 0x4002));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_NVME, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_NVME, 0, 0x2000));
	EXPECT_TRUE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_NVME,
				      XDEV_EXT_MECH_RETRY_MAX_NVME - 1, 0x0371));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_NVME,
				       XDEV_EXT_MECH_RETRY_MAX_NVME, 0x0371));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_NVME, 0, -EIO));
	/* AF_XDP TX: only -EAGAIN. */
	EXPECT_TRUE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP, 0, -EAGAIN));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP, 0, -ENXIO));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				       XDEV_EXT_MECH_RETRY_MAX_AFXDP, -EAGAIN));
	/* CE: only a failure the hardware never saw. */
	EXPECT_TRUE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_CE, 0,
				      XDEV_EXT_CE_PRE_SUBMIT_FAILED));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_CE, 0, XDEV_EXT_CE_AMBIGUOUS));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_CE, 0, XDEV_EXT_CE_OK));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_RETRY_MAX_CE,
				       XDEV_EXT_CE_PRE_SUBMIT_FAILED));
	EXPECT_FALSE(xdev_ext_mech_retry_ok(XDEV_EXT_BINDING_BACKEND_IAA, 0, -EAGAIN));
}

/* Plain bitwise CRC32C update: no pre- or post-inversion. */
static __u32 crc32c_bitwise(__u32 crc, const void *p, size_t len)
{
	const __u8 *b = p;

	while (len--) {
		crc ^= *b++;
		for (int i = 0; i < 8; i++)
			crc = (crc >> 1) ^ (0x82f63b78U & -(crc & 1));
	}
	return crc;
}

/* The slice-by-1 table walk of lib/crc32.c crc32c_base(). */
static __u32 crc32c_table[256];

static void crc32c_table_init(void)
{
	for (__u32 i = 0; i < 256; i++)
		crc32c_table[i] = crc32c_bitwise(0, &(__u8){ (__u8)i }, 1);
}

static __u32 crc32c_base_like(__u32 crc, const void *p, size_t len)
{
	const __u8 *b = p;

	while (len--)
		crc = (crc >> 8) ^ crc32c_table[(crc & 255) ^ *b++];
	return crc;
}

#if defined(__x86_64__)
/* The non-PCLMUL loop of arch/x86/lib/crc32.c crc32c_arch(). */
__attribute__((target("sse4.2")))
static __u32 crc32c_sse42_like(__u32 crc, const void *p, size_t len)
{
	const __u8 *b = p;
	__u64 c = crc;

	for (; len >= 8; len -= 8, b += 8) {
		__u64 v;

		memcpy(&v, b, 8);
		c = __builtin_ia32_crc32di(c, v);
	}
	crc = (__u32)c;
	if (len & 4) {
		__u32 v;

		memcpy(&v, b, 4);
		crc = __builtin_ia32_crc32si(crc, v);
		b += 4;
	}
	if (len & 2) {
		__u16 v;

		memcpy(&v, b, 2);
		crc = __builtin_ia32_crc32hi(crc, v);
		b += 2;
	}
	if (len & 1)
		crc = __builtin_ia32_crc32qi(crc, *b);
	return crc;
}
#endif

static __u64 lcg_state = 0x9e3779b97f4a7c15ULL;

static __u8 lcg_byte(void)
{
	lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
	return (__u8)(lcg_state >> 56);
}

/* What an eBPF program does with the two CRC kfuncs. */
static __u32 program_style(__u32 (*update)(__u32, const void *, size_t),
			   const __u8 *hdr, const __u8 *payload, __u32 len)
{
	__u8 copy[XDEV_EXT_MECH_NXP_HDR_LEN];
	__u32 crc;

	memcpy(copy, hdr, sizeof(copy));
	memset(copy + XDEV_EXT_MECH_NXP_CSUM_OFF, 0, 4);
	crc = update(XDEV_EXT_MECH_CRC32C_SEED, copy, sizeof(copy));
	crc = update(crc, payload, len / 3);
	crc = update(crc, payload + len / 3, len - len / 3);
	return ~crc;
}

static void test_nxp_crc_convention(void)
{
	static __u8 payload[1432];
	__u8 hdr[NXP_WIRE_HEADER_LEN];
	struct nxp_wire_span span;
	int round;
	bool sse42 = false;

	_Static_assert(XDEV_EXT_MECH_NXP_HDR_LEN == NXP_WIRE_HEADER_LEN,
		       "NXP header length");
	crc32c_table_init();
	/* Check value of the CRC-32C catalogue. */
	EXPECT_EQ(~crc32c_bitwise(~0U, "123456789", 9), 0xe3069283U);
	EXPECT_EQ(~crc32c_base_like(~0U, "123456789", 9), 0xe3069283U);
#if defined(__x86_64__)
	__builtin_cpu_init();
	sse42 = __builtin_cpu_supports("sse4.2");
	if (sse42)
		EXPECT_EQ(~crc32c_sse42_like(~0U, "123456789", 9), 0xe3069283U);
#endif
	for (round = 0; round < 64; round++) {
		__u32 len = round == 0 ? 0 : 1 + (round * 37) % sizeof(payload);
		__u32 want;

		for (size_t i = 0; i < sizeof(hdr); i++)
			hdr[i] = lcg_byte();
		for (__u32 i = 0; i < len; i++)
			payload[i] = lcg_byte();
		span.data = payload;
		span.len = len;
		want = nxp_wire_checksum(hdr, &span, len ? 1 : 0);

		EXPECT_EQ(xdev_ext_mech_nxp_csum(crc32c_bitwise, hdr, payload, len),
			  want);
		EXPECT_EQ(xdev_ext_mech_nxp_csum(crc32c_base_like, hdr, payload, len),
			  want);
		EXPECT_EQ(program_style(crc32c_base_like, hdr, payload, len),
			  want);
#if defined(__x86_64__)
		if (sse42) {
			EXPECT_EQ(xdev_ext_mech_nxp_csum(crc32c_sse42_like, hdr,
						    payload, len), want);
			EXPECT_EQ(program_style(crc32c_sse42_like, hdr, payload,
						len), want);
		}
#endif
		/* The checksum field itself never feeds the CRC. */
		hdr[XDEV_EXT_MECH_NXP_CSUM_OFF + round % 4] ^= 0xff;
		EXPECT_EQ(xdev_ext_mech_nxp_csum(crc32c_base_like, hdr, payload, len),
			  want);
	}
	if (!sse42)
		printf("SKIP: SSE4.2 crc32 instruction path\n");
}

int main(void)
{
	test_uapi_values();
	test_frame_states();
	test_batch_state_machine();
	test_slots();
	test_spans_and_windows();
	test_cover();
	test_layout();
	test_hold_and_group();
	test_session_rules();
	test_quarantine();
	test_return_values();
	test_rx_resolve();
	test_retry();
	test_nxp_crc_convention();

	if (failures) {
		fprintf(stderr, "FAIL: %u of %u checks\n", failures, checks);
		return 1;
	}
	printf("PASS: %u XDEV_EXT mechanism core checks\n", checks);
	return 0;
}
