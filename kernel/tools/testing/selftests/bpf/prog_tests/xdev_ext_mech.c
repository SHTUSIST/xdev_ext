// SPDX-License-Identifier: GPL-2.0

#include <fcntl.h>
#include <linux/if_xdp.h>
#include <bpf/btf.h>
#include <test_progs.h>

/* This tree's mechanism UAPI, and the user-space NXP encoder as the oracle. */
#include "../../../../../include/uapi/linux/xdev_ext_mech.h"
#include "../../../../../nvme_xdp_pipeline_core.h"
#include "../xdev_ext_mech_test.h"
#include "xdev_ext_mech_afxdp.skel.h"
#include "xdev_ext_mech_binding_loads.skel.h"
#include "xdev_ext_mech_ce.skel.h"
#include "xdev_ext_mech_fail_binding_calls_mech.skel.h"
#include "xdev_ext_mech_fail_compute_desc.skel.h"
#include "xdev_ext_mech_fail_compute_rw_build.skel.h"
#include "xdev_ext_mech_fail_compute_set_len_complete.skel.h"
#include "xdev_ext_mech_fail_compute_sleepable.skel.h"
#include "xdev_ext_mech_fail_compute_view_past.skel.h"
#include "xdev_ext_mech_fail_compute_view_size.skel.h"
#include "xdev_ext_mech_fail_compute_wrong_class.skel.h"
#include "xdev_ext_mech_fail_desc_complete.skel.h"
#include "xdev_ext_mech_fail_dma_desc_complete.skel.h"
#include "xdev_ext_mech_fail_dma_wrong_class_hold.skel.h"
#include "xdev_ext_mech_fail_forged_ctx.skel.h"
#include "xdev_ext_mech_fail_frame_write.skel.h"
#include "xdev_ext_mech_fail_sleepable_build.skel.h"
#include "xdev_ext_mech_fail_view_size.skel.h"
#include "xdev_ext_mech_fail_write_ctx.skel.h"
#include "xdev_ext_mech_fail_wrong_class_hold.skel.h"
#include "xdev_ext_mech_mk3.skel.h"
#include "xdev_ext_mech_nvme.skel.h"
#include "xdev_ext_mech_nxp.skel.h"

/*
 * Batches use the S1 frame layout (plan section 4.3): 8 KiB in six frames of
 * 1432 bytes and a 1032-byte tail, data at 360 after the header room.
 */
#define XDEV_EXT_MECH_T_FRAME_SIZE		4096U
#define XDEV_EXT_MECH_T_HDR_ROOM		360U
#define XDEV_EXT_MECH_T_SEGMENTS		6U
#define XDEV_EXT_MECH_T_SEG_LEN		1432U
#define XDEV_EXT_MECH_T_GROUP		8192U
#define XDEV_EXT_MECH_T_UMEM_BASE		0x100000ULL
#define XDEV_EXT_MECH_T_RX_OFF		278U	/* XDP_PACKET_HEADROOM + 22 */
#define XDEV_EXT_MECH_T_RX_L2L4		42U	/* Ethernet, IPv4, UDP */
#define XDEV_EXT_MECH_T_MTU			1500U
#define XDEV_EXT_MECH_T_BATCH_ID		5ULL
#define XDEV_EXT_MECH_T_KEY			7ULL	/* NXP generation */
#define XDEV_EXT_MECH_T_SESSION		0x1122334455667788ULL
#define XDEV_EXT_MECH_T_LBA_SHIFT		9U
#define XDEV_EXT_MECH_T_WINDOW_SLBA		2048ULL
#define XDEV_EXT_MECH_T_WINDOW_NLB		1024ULL
#define XDEV_EXT_MECH_T_CAPACITY		(1ULL << 20)
#define XDEV_EXT_MECH_T_GPU_BASE		0x10000ULL
#define XDEV_EXT_MECH_T_GPU_WINDOW		(1ULL << 20)
#define XDEV_EXT_MECH_T_GPU_DEPTH		16U
#define XDEV_EXT_MECH_MK3_ITERS		1000000ULL

static const struct xdev_ext_mech_layout xdev_ext_mech_t_layout = {
	.frame_size = XDEV_EXT_MECH_T_FRAME_SIZE,
	.hdr_room = XDEV_EXT_MECH_T_HDR_ROOM,
	.seg_len = XDEV_EXT_MECH_T_SEG_LEN,
	.group_bytes = XDEV_EXT_MECH_T_GROUP,
};

/*
 * The mechanism layer exists when vmlinux BTF carries its three struct_ops
 * types and its kfuncs; without CONFIG_XDEV_EXT_MECH every subtest skips.
 */
static bool xdev_ext_mech_btf_available(void)
{
	static const char *const types[] = {
		"xdev_ext_mech_ctx", "xdev_ext_nvme_mech_ops", "xdev_ext_afxdp_mech_ops",
		"xdev_ext_ce_mech_ops",
	};
	static const char *const kfuncs[] = {
		"bpf_xdev_ext_info", "bpf_xdev_ext_desc", "bpf_xdev_ext_cqe", "bpf_xdev_ext_frame",
		"bpf_xdev_ext_frame_crc32c", "bpf_xdev_ext_crc32c", "bpf_xdev_ext_afxdp_hdr",
		"bpf_xdev_ext_afxdp_hold",
	};
	bool found = true;
	struct btf *btf;
	size_t i;

	btf = btf__load_vmlinux_btf();
	if (libbpf_get_error(btf)) {
		test__skip();
		return false;
	}
	for (i = 0; i < ARRAY_SIZE(types); i++)
		found &= btf__find_by_name_kind(btf, types[i],
						BTF_KIND_STRUCT) > 0;
	for (i = 0; i < ARRAY_SIZE(kfuncs); i++)
		found &= btf__find_by_name_kind(btf, kfuncs[i],
						BTF_KIND_FUNC) > 0;
	btf__free(btf);
	if (!found)
		test__skip();
	return found;
}

static int xdev_ext_mech_command(struct bpf_testmod_xdev_ext_mech *io)
{
	ssize_t len;
	int err = 0;
	int fd;

	fd = open(BPF_TESTMOD_XDEV_EXT_MECH_FILE, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	len = pwrite(fd, io, sizeof(*io), 0);
	if (len != sizeof(*io)) {
		err = len < 0 ? -errno : -EIO;
		goto out;
	}
	len = pread(fd, io, sizeof(*io), 0);
	if (len != sizeof(*io))
		err = len < 0 ? -errno : -EIO;
out:
	close(fd);
	return err;
}

static bool xdev_ext_mech_seam_available(void)
{
	struct bpf_testmod_xdev_ext_mech io = {
		.command = BPF_TESTMOD_XDEV_EXT_MECH_FRAME_READ,
	};

	if (access(BPF_TESTMOD_XDEV_EXT_MECH_FILE, R_OK | W_OK) ||
	    xdev_ext_mech_command(&io) ||
	    !(io.out.config & BPF_TESTMOD_XDEV_EXT_MECH_CFG_MECH)) {
		test__skip();
		return false;
	}
	return true;
}

static int xdev_ext_mech_frame_io(__u32 command, __u32 frame, __u32 off,
			     __u8 *data, __u32 len)
{
	struct bpf_testmod_xdev_ext_mech io;
	__u32 done, n;
	int err;

	for (done = 0; done < len; done += n) {
		n = MIN(len - done, (__u32)BPF_TESTMOD_XDEV_EXT_MECH_DATA_MAX);
		memset(&io, 0, sizeof(io));
		io.command = command;
		io.frame = frame;
		io.offset = off + done;
		io.length = n;
		if (command == BPF_TESTMOD_XDEV_EXT_MECH_FRAME_WRITE)
			memcpy(io.data, data + done, n);
		err = xdev_ext_mech_command(&io);
		if (!err)
			err = io.out.return_value;
		if (err)
			return err;
		if (command == BPF_TESTMOD_XDEV_EXT_MECH_FRAME_READ)
			memcpy(data + done, io.data, n);
	}
	return 0;
}

static __u32 xdev_ext_mech_crc(const __u8 *data, __u32 len)
{
	/* crc32c() of the kernel: seed ~0, no final inversion. */
	return nxp_wire_crc32c_update(~0U, data, len);
}

static __u32 xdev_ext_mech_seg_len(__u32 i)
{
	return i + 1 < XDEV_EXT_MECH_T_SEGMENTS ? XDEV_EXT_MECH_T_SEG_LEN :
	       XDEV_EXT_MECH_T_GROUP - (XDEV_EXT_MECH_T_SEGMENTS - 1) * XDEV_EXT_MECH_T_SEG_LEN;
}

static void xdev_ext_mech_payload(__u32 frame, __u8 *data, __u32 len)
{
	__u32 i;

	for (i = 0; i < len; i++)
		data[i] = (__u8)(frame * 37 + i * 11 + 5);
}

/* A CALL request for one S1 group whose frame i holds segment i's payload. */
static int xdev_ext_mech_group(struct bpf_testmod_xdev_ext_mech *io, __u32 class_id,
			  __u32 member, __u32 direction)
{
	__u8 data[XDEV_EXT_MECH_T_SEG_LEN];
	__u32 i, len;
	int err;

	memset(io, 0, sizeof(*io));
	io->command = BPF_TESTMOD_XDEV_EXT_MECH_CALL;
	io->class_id = class_id;
	io->member = member;
	io->callsite = member == XDEV_EXT_MECH_MEMBER_PREPARE ?
		       XDEV_EXT_MECH_SITE_CREATE : XDEV_EXT_MECH_SITE_WORKER;
	io->direction = direction;
	io->nr_frames = XDEV_EXT_MECH_T_SEGMENTS;
	io->frame_size = XDEV_EXT_MECH_T_FRAME_SIZE;
	io->hdr_room = XDEV_EXT_MECH_T_HDR_ROOM;
	io->batch_id = XDEV_EXT_MECH_T_BATCH_ID;
	io->key = XDEV_EXT_MECH_T_KEY;
	io->bytes = XDEV_EXT_MECH_T_GROUP;
	for (i = 0; i < XDEV_EXT_MECH_T_SEGMENTS; i++) {
		len = xdev_ext_mech_seg_len(i);
		io->frames[i] = (struct bpf_testmod_xdev_ext_mech_frame) {
			.umem_addr = XDEV_EXT_MECH_T_UMEM_BASE +
				     i * XDEV_EXT_MECH_T_FRAME_SIZE,
			.data_off = XDEV_EXT_MECH_T_HDR_ROOM,
			.data_len = len,
		};
		xdev_ext_mech_payload(i, data, len);
		err = xdev_ext_mech_frame_io(BPF_TESTMOD_XDEV_EXT_MECH_FRAME_WRITE, i,
					XDEV_EXT_MECH_T_HDR_ROOM, data, len);
		if (err)
			return err;
	}
	return 0;
}

static void xdev_ext_mech_frames_info(const struct bpf_testmod_xdev_ext_mech *io,
				 struct xdev_ext_mech_frame_info *f)
{
	__u32 i;

	for (i = 0; i < io->nr_frames; i++)
		f[i] = (struct xdev_ext_mech_frame_info) {
			.umem_addr = io->frames[i].umem_addr,
			.data_off = io->frames[i].data_off,
			.data_len = io->frames[i].data_len,
		};
}

static void xdev_ext_mech_nvme_info(struct bpf_testmod_xdev_ext_mech *io)
{
	struct xdev_ext_nvme_mech_info info = {
		.l = xdev_ext_mech_t_layout,
		.lba_shift = XDEV_EXT_MECH_T_LBA_SHIFT,
		.max_nlb = 65536,
		.window_slba = XDEV_EXT_MECH_T_WINDOW_SLBA,
		.window_nlb = XDEV_EXT_MECH_T_WINDOW_NLB,
		.capacity_lbas = XDEV_EXT_MECH_T_CAPACITY,
		.sgl = 1,
		.nr_frames = io->nr_frames,
	};

	xdev_ext_mech_frames_info(io, info.f);
	memcpy(io->info, &info, sizeof(info));
	io->info_size = sizeof(info);
}

/* The receiver's view: local is this host, peer is the sender. */
static void xdev_ext_mech_peer(struct xdev_ext_mech_peer *peer)
{
	static const __u8 local_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x02 };
	static const __u8 peer_mac[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0x01 };

	memset(peer, 0, sizeof(*peer));
	memcpy(peer->local_mac, local_mac, ETH_ALEN);
	memcpy(peer->peer_mac, peer_mac, ETH_ALEN);
	peer->local_ip = htonl(0x0a000002);
	peer->peer_ip = htonl(0x0a000001);
	peer->local_port = htons(4791);
	peer->peer_port = htons(4790);
}

static void xdev_ext_mech_afxdp_info(struct bpf_testmod_xdev_ext_mech *io)
{
	struct xdev_ext_afxdp_mech_info info = {
		.l = xdev_ext_mech_t_layout,
		.mtu = XDEV_EXT_MECH_T_MTU,
		.nr_frames = io->nr_frames,
	};

	xdev_ext_mech_peer(&info.peer);
	xdev_ext_mech_frames_info(io, info.f);
	memcpy(io->info, &info, sizeof(info));
	io->info_size = sizeof(info);
}

static void xdev_ext_mech_ce_info(struct bpf_testmod_xdev_ext_mech *io)
{
	struct xdev_ext_ce_mech_info info = {
		.l = xdev_ext_mech_t_layout,
		.gpu_window_len = XDEV_EXT_MECH_T_GPU_WINDOW,
		.max_entry_len = XDEV_EXT_MECH_T_GROUP,
		.nr_frames = io->nr_frames,
		.window_slot = ~0U,
	};

	/* CREATE has no batch lease; worker views mirror C fill_info. */
	if (io->member != XDEV_EXT_MECH_MEMBER_PREPARE) {
		info.window_slot = XDEV_EXT_MECH_T_GPU_BASE / XDEV_EXT_MECH_T_GROUP;
		info.window_depth = XDEV_EXT_MECH_T_GPU_DEPTH;
		info.lease_generation = io->batch_id;
	}
	xdev_ext_mech_frames_info(io, info.f);
	memcpy(io->info, &info, sizeof(info));
	io->info_size = sizeof(info);
}

/* Frame 0's payload as build and complete saw it through the kfuncs. */
static void xdev_ext_mech_check_obs(const struct xdev_ext_mech_obs *obs, __u64 calls,
			       const char *name)
{
	__u8 data[XDEV_EXT_MECH_T_SEG_LEN];
	__u64 head = 0;
	int i;

	xdev_ext_mech_payload(0, data, sizeof(data));
	for (i = 7; i >= 0; i--)
		head = head << 8 | data[i];
	ASSERT_EQ(obs->calls, calls, name);
	ASSERT_EQ(obs->head, head, name);
	ASSERT_EQ(obs->head_crc, xdev_ext_mech_crc(data, 8), name);
	ASSERT_EQ(obs->data_crc, xdev_ext_mech_crc(data, sizeof(data)), name);
}

static void xdev_ext_mech_check_tag(__u32 crc, const char *name)
{
	ASSERT_EQ(crc, xdev_ext_mech_crc((const __u8 *)"xdev_ext-mech", 8), name);
}

static void xdev_ext_mech_put_le(__u8 *p, __u64 v, int bytes)
{
	int i;

	for (i = 0; i < bytes; i++)
		p[i] = (__u8)(v >> (8 * i));
}

static void xdev_ext_mech_check_call(const struct bpf_testmod_xdev_ext_mech *io,
				__s32 prog_ret, __s32 resolved, bool illegal,
				const char *name)
{
	ASSERT_OK(io->out.return_value, name);
	ASSERT_EQ(io->out.prog_ret, prog_ret, name);
	ASSERT_EQ(io->out.resolved, resolved, name);
	ASSERT_EQ(io->out.illegal, illegal, name);
}

/* With nothing published a call fails closed instead of running C. */
static void test_no_program(void)
{
	struct bpf_testmod_xdev_ext_mech io;
	static const __u32 classes[] = {
		XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_CLASS_CE,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(classes); i++) {
		if (!ASSERT_OK(xdev_ext_mech_group(&io, classes[i],
					      XDEV_EXT_MECH_MEMBER_BUILD,
					      XDEV_EXT_MECH_DIR_TO_DEVICE),
			       "no_program_frames"))
			return;
		io.desc_size = 16;
		io.desc_cap = 1;
		ASSERT_OK(xdev_ext_mech_command(&io), "no_program_call");
		ASSERT_EQ(io.out.return_value, -ENOENT, "no_program_enoent");
		ASSERT_EQ(io.out.slots_used, 0, "no_program_no_slots");
	}
}

static int xdev_ext_mech_nvme_build(struct xdev_ext_mech_nvme *skel, __u32 mode,
			       struct bpf_testmod_xdev_ext_mech *io)
{
	int err;

	err = xdev_ext_mech_group(io, XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_MEMBER_BUILD,
			     XDEV_EXT_MECH_DIR_TO_DEVICE);
	if (err)
		return err;
	xdev_ext_mech_nvme_info(io);
	io->desc_size = XDEV_EXT_NVME_MECH_DESC_SIZE;
	io->desc_cap = 1;
	skel->bss->nvme_mode = mode;
	return xdev_ext_mech_command(io);
}

/* The SQE the NVMe program writes: opcode, SLBA, NLB - 1, optional cdw13. */
static void xdev_ext_mech_check_sqe(const struct bpf_testmod_xdev_ext_mech *io,
			       __u64 slba, __u32 cdw13, const char *name)
{
	__u8 sqe[XDEV_EXT_NVME_MECH_DESC_SIZE] = {};
	__u64 nlb = XDEV_EXT_MECH_T_GROUP >> XDEV_EXT_MECH_T_LBA_SHIFT;

	sqe[0] = 0x01;					/* nvme_cmd_write */
	xdev_ext_mech_put_le(sqe + 40, slba, 8);		/* cdw10..11 */
	xdev_ext_mech_put_le(sqe + 48, nlb - 1, 2);		/* cdw12[15:0] */
	xdev_ext_mech_put_le(sqe + 52, cdw13, 4);
	ASSERT_OK(memcmp(io->scratch, sqe, sizeof(sqe)), name);
}

static void test_nvme_members(void)
{
	__u64 nlb = XDEV_EXT_MECH_T_GROUP >> XDEV_EXT_MECH_T_LBA_SHIFT;
	__u64 slba = XDEV_EXT_MECH_T_WINDOW_SLBA +
		     XDEV_EXT_MECH_T_BATCH_ID % (XDEV_EXT_MECH_T_WINDOW_NLB / nlb) * nlb;
	struct xdev_ext_nvme_mech_cqe cqe = { .result = 0x1234 };
	struct bpf_testmod_xdev_ext_mech io;
	struct xdev_ext_mech_nvme *skel;
	struct bpf_link *link;

	skel = xdev_ext_mech_nvme__open_and_load();
	if (!ASSERT_OK_PTR(skel, "nvme_open_and_load"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.nvme_ops);
	if (!ASSERT_OK_PTR(link, "nvme_attach"))
		goto out;

	/* prepare: sleepable, at CREATE, info and crc32c only */
	if (!ASSERT_OK(xdev_ext_mech_group(&io, XDEV_EXT_MECH_CLASS_NVME,
				      XDEV_EXT_MECH_MEMBER_PREPARE,
				      XDEV_EXT_MECH_DIR_TO_DEVICE), "nvme_frames"))
		goto out;
	xdev_ext_mech_nvme_info(&io);
	ASSERT_OK(xdev_ext_mech_command(&io), "nvme_prepare_call");
	xdev_ext_mech_check_call(&io, 0, 0, false, "nvme_prepare");
	ASSERT_EQ(skel->bss->prepare_calls, 1, "nvme_prepare_calls");
	ASSERT_EQ(skel->bss->prepare_lba_shift, XDEV_EXT_MECH_T_LBA_SHIFT,
		  "nvme_prepare_info");
	xdev_ext_mech_check_tag(skel->bss->prepare_tag_crc, "nvme_prepare_crc");

	/* build: SLBA from the batch id inside the window; C admits it */
	ASSERT_OK(xdev_ext_mech_nvme_build(skel, 0, &io), "nvme_build_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_BUILD_SUBMIT, XDEV_EXT_MECH_BUILD_SUBMIT,
			    false, "nvme_build");
	ASSERT_EQ(io.out.slots_used, 1, "nvme_build_slots");
	ASSERT_OK(io.out.validate_ret, "nvme_build_validate");
	xdev_ext_mech_check_sqe(&io, slba, 0, "nvme_build_sqe");
	xdev_ext_mech_check_obs(&skel->bss->build_obs, 1, "nvme_build_obs");

	/* C refuses what the program cannot be trusted to keep */
	ASSERT_OK(xdev_ext_mech_nvme_build(skel, 1, &io), "nvme_past_window_call");
	ASSERT_EQ(io.out.prog_ret, XDEV_EXT_MECH_BUILD_SUBMIT, "nvme_past_window");
	ASSERT_EQ(io.out.validate_ret, -ERANGE, "nvme_past_window_erange");
	xdev_ext_mech_check_sqe(&io, XDEV_EXT_MECH_T_WINDOW_SLBA + XDEV_EXT_MECH_T_WINDOW_NLB,
			   0, "nvme_past_window_sqe");
	ASSERT_OK(xdev_ext_mech_nvme_build(skel, 2, &io), "nvme_reserved_call");
	ASSERT_EQ(io.out.validate_ret, -EPERM, "nvme_reserved_eperm");
	xdev_ext_mech_check_sqe(&io, slba, 1, "nvme_reserved_sqe");

	/* a view of the wrong size is NULL: the program aborts, nothing written */
	if (!ASSERT_OK(xdev_ext_mech_nvme_build(skel, 0, &io), "nvme_frames2"))
		goto out;
	io.info_size -= 8;
	ASSERT_OK(xdev_ext_mech_command(&io), "nvme_info_size_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_BUILD_ABORT, XDEV_EXT_MECH_BUILD_ABORT,
			    false, "nvme_info_size");
	ASSERT_EQ(io.out.slots_used, 0, "nvme_info_size_no_slots");

	/* complete: the native status decides; URING_CMD allows DONE/ABORT */
	if (!ASSERT_OK(xdev_ext_mech_group(&io, XDEV_EXT_MECH_CLASS_NVME,
				      XDEV_EXT_MECH_MEMBER_COMPLETE,
				      XDEV_EXT_MECH_DIR_TO_DEVICE), "nvme_frames3"))
		goto out;
	xdev_ext_mech_nvme_info(&io);
	io.cqe_size = sizeof(cqe);
	io.cqe_cap = 1;
	memcpy(io.cqe, &cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "nvme_complete_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_DONE, XDEV_EXT_MECH_DONE, false,
			    "nvme_complete");
	ASSERT_EQ(skel->bss->complete_result, 0x1234, "nvme_complete_result");
	xdev_ext_mech_check_obs(&skel->bss->complete_obs, 1, "nvme_complete_obs");

	cqe.status = 0x4002;			/* DNR, invalid field */
	memcpy(io.cqe, &cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "nvme_complete_err_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_ABORT, XDEV_EXT_MECH_ABORT, false,
			    "nvme_complete_err");
	ASSERT_EQ(skel->bss->complete_status, 0x4002, "nvme_complete_status");

	cqe.status = 0;
	memcpy(io.cqe, &cqe, sizeof(cqe));
	io.callsite = XDEV_EXT_MECH_SITE_URING_CMD;
	ASSERT_OK(xdev_ext_mech_command(&io), "nvme_complete_uring_cmd_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_DONE, XDEV_EXT_MECH_DONE, false,
			    "nvme_complete_uring_cmd");

	/* detached: the class has no generation to run */
	bpf_link__destroy(link);
	link = NULL;
	ASSERT_OK(xdev_ext_mech_command(&io), "nvme_detached_call");
	ASSERT_EQ(io.out.return_value, -ENOENT, "nvme_detached_enoent");
out:
	bpf_link__destroy(link);
	xdev_ext_mech_nvme__destroy(skel);
}

/* The NXP header nxp_wire_header_encode() gives for segment i of the group. */
static void xdev_ext_mech_expect_nxp(__u32 i, __u32 rel, __u8 *hdr)
{
	__u8 data[XDEV_EXT_MECH_T_SEG_LEN];
	__u32 len = xdev_ext_mech_seg_len(i);
	struct nxp_wire_segment segment = {
		.direction = NXP_IO_WRITE,
		.session_id = XDEV_EXT_MECH_T_SESSION,
		.generation = XDEV_EXT_MECH_T_KEY,
		.segment_index = i,
		.segment_count = XDEV_EXT_MECH_T_SEGMENTS,
		.total_len = XDEV_EXT_MECH_T_GROUP,
		.relative_offset = rel,
		.payload_len = len,
	};
	struct nxp_wire_span span = { .data = data, .len = len };

	xdev_ext_mech_payload(i, data, len);
	ASSERT_OK(nxp_wire_header_encode(hdr, NXP_WIRE_HEADER_LEN, &segment,
					 &span, 1), "nxp_encode");
}

/* Frames per batch C hands an RX complete: the count a hold records. */
static __u32 xdev_ext_mech_rx_batch_frames = XDEV_EXT_MECH_T_SEGMENTS;

static int xdev_ext_mech_rx_call(struct bpf_testmod_xdev_ext_mech *io, __u32 callsite,
			    __u8 *pkt, __u32 len)
{
	struct xdp_desc desc = { .addr = XDEV_EXT_MECH_T_RX_OFF, .len = len };
	int err;

	memset(io, 0, sizeof(*io));
	io->command = BPF_TESTMOD_XDEV_EXT_MECH_CALL;
	io->class_id = XDEV_EXT_MECH_CLASS_AFXDP;
	io->member = XDEV_EXT_MECH_MEMBER_COMPLETE;
	io->callsite = callsite;
	io->direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	io->nr_frames = 1;
	io->frame_size = XDEV_EXT_MECH_T_FRAME_SIZE;
	io->batch_frames = xdev_ext_mech_rx_batch_frames;
	io->bytes = len;
	io->frames[0] = (struct bpf_testmod_xdev_ext_mech_frame) {
		.data_off = XDEV_EXT_MECH_T_RX_OFF,
		.data_len = len,
	};
	xdev_ext_mech_afxdp_info(io);
	io->cqe_size = sizeof(desc);
	io->cqe_cap = 1;
	memcpy(io->cqe, &desc, sizeof(desc));
	err = xdev_ext_mech_frame_io(BPF_TESTMOD_XDEV_EXT_MECH_FRAME_WRITE, 0,
				XDEV_EXT_MECH_T_RX_OFF, pkt, len);
	return err ?: xdev_ext_mech_command(io);
}

static void xdev_ext_mech_check_hold(const struct bpf_testmod_xdev_ext_mech *io,
				__u64 key, __u32 pos, __u32 count,
				__u32 span_off, __u32 span_len,
				const char *name)
{
	ASSERT_EQ(io->out.hold_key, key, name);
	ASSERT_EQ(io->out.hold_pos, pos, name);
	ASSERT_EQ(io->out.hold_count, count, name);
	ASSERT_EQ(io->out.hold_span_off, span_off, name);
	ASSERT_EQ(io->out.hold_span_len, span_len, name);
}

static void test_afxdp_tx(struct xdev_ext_mech_afxdp *skel)
{
	struct xdev_ext_afxdp_tx_cqe cqe[XDEV_EXT_MECH_T_SEGMENTS] = {};
	__u8 expected[NXP_WIRE_HEADER_LEN], hdr[NXP_WIRE_HEADER_LEN];
	__u32 hdr_off = XDEV_EXT_MECH_T_HDR_ROOM - NXP_WIRE_HEADER_LEN;
	const struct xdp_desc *desc;
	struct bpf_testmod_xdev_ext_mech io;
	__u32 i, rel = 0;

	/* build: one NXP header and one xdp_desc per frame */
	skel->bss->tx_session = XDEV_EXT_MECH_T_SESSION;
	if (!ASSERT_OK(xdev_ext_mech_group(&io, XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_DIR_TO_DEVICE), "tx_frames"))
		return;
	xdev_ext_mech_afxdp_info(&io);
	io.desc_size = sizeof(struct xdp_desc);
	io.desc_cap = XDEV_EXT_MECH_MAX_FRAMES;
	ASSERT_OK(xdev_ext_mech_command(&io), "tx_build_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_BUILD_SUBMIT, XDEV_EXT_MECH_BUILD_SUBMIT,
			    false, "tx_build");
	ASSERT_EQ(io.out.slots_used, XDEV_EXT_MECH_T_SEGMENTS, "tx_build_slots");
	desc = (const void *)io.scratch;
	for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++) {
		struct xdp_desc want = {};

		if (i < XDEV_EXT_MECH_T_SEGMENTS)
			want = (struct xdp_desc) {
				.addr = io.frames[i].umem_addr + hdr_off,
				.len = NXP_WIRE_HEADER_LEN + io.frames[i].data_len,
			};
		ASSERT_OK(memcmp(&desc[i], &want, sizeof(want)), "tx_desc");
	}
	for (i = 0; i < XDEV_EXT_MECH_T_SEGMENTS; i++) {
		xdev_ext_mech_expect_nxp(i, rel, expected);
		rel += xdev_ext_mech_seg_len(i);
		ASSERT_OK(xdev_ext_mech_frame_io(BPF_TESTMOD_XDEV_EXT_MECH_FRAME_READ, i,
					    hdr_off, hdr, sizeof(hdr)),
			  "tx_hdr_read");
		ASSERT_OK(memcmp(hdr, expected, sizeof(hdr)), "tx_nxp_header");
	}
	xdev_ext_mech_check_obs(&skel->bss->build_obs, 1, "tx_build_obs");

	/* complete: one xsk_kernel_xmit() result per frame */
	io.member = XDEV_EXT_MECH_MEMBER_COMPLETE;
	io.cqe_size = sizeof(cqe[0]);
	io.cqe_cap = XDEV_EXT_MECH_T_SEGMENTS;
	memcpy(io.cqe, cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "tx_complete_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_DONE, XDEV_EXT_MECH_DONE, false,
			    "tx_complete");
	ASSERT_EQ(skel->bss->tx_cqes, XDEV_EXT_MECH_T_SEGMENTS, "tx_complete_cqes");
	/*
	 * C stops at the first failed send and reports -ECANCELED for every
	 * later frame (xsk_xdev_ext_mech_tx_run()): only the failure decides.
	 */
	cqe[3].err = -EAGAIN;
	cqe[4].err = -ECANCELED;
	cqe[5].err = -ECANCELED;
	memcpy(io.cqe, cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "tx_complete_eagain_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_RETRY, XDEV_EXT_MECH_RETRY, false,
			    "tx_complete_eagain");
	cqe[3].err = -ENXIO;
	memcpy(io.cqe, cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "tx_complete_enxio_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_ABORT, XDEV_EXT_MECH_ABORT, false,
			    "tx_complete_enxio");
	for (i = 0; i < XDEV_EXT_MECH_T_SEGMENTS; i++)
		cqe[i].err = i ? -ECANCELED : -EAGAIN;
	memcpy(io.cqe, cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "tx_complete_eagain_first_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_RETRY, XDEV_EXT_MECH_RETRY, false,
			    "tx_complete_eagain_first");
	xdev_ext_mech_check_obs(&skel->bss->complete_obs, 4, "tx_complete_obs");
}

/* Ownerless diagnostic RX is explicitly unsupported. Real session RX and
 * ownership transitions are covered by the private guest integration. */
static void test_afxdp_rx(struct xdev_ext_mech_afxdp *skel)
{
 const __u32 sites[] = { XDEV_EXT_MECH_SITE_RX_GENERIC,
  XDEV_EXT_MECH_SITE_RX_NATIVE, XDEV_EXT_MECH_SITE_RX_HOLD_RESULT };
 const __s32 verdicts[] = { XDEV_EXT_MECH_HOLD, XDEV_EXT_MECH_PUBLISH,
  XDEV_EXT_MECH_RECYCLE, XDEV_EXT_MECH_DONE };
 __u32 len = XDEV_EXT_MECH_T_RX_L2L4 + NXP_WIRE_HEADER_LEN + XDEV_EXT_MECH_T_SEG_LEN;
 __u8 pkt[XDEV_EXT_MECH_T_RX_L2L4 + NXP_WIRE_HEADER_LEN + XDEV_EXT_MECH_T_SEG_LEN];
 struct bpf_testmod_xdev_ext_mech io;
 unsigned int site, verdict;

 xdev_ext_mech_payload(9, pkt, len);
 skel->bss->rx_hold_ret = 0x1234567;
 skel->bss->rx_desc_len = 0x1234567;
 for (site = 0; site < ARRAY_SIZE(sites); site++)
  for (verdict = 0; verdict < ARRAY_SIZE(verdicts); verdict++) {
   skel->bss->rx_verdict = verdicts[verdict];
   ASSERT_OK(xdev_ext_mech_rx_call(&io, sites[site], pkt, len), "ownerless_rx_transport");
   ASSERT_EQ(io.out.return_value, -EOPNOTSUPP, "ownerless_rx_rejected");
   ASSERT_EQ(io.out.prog_ret, 0, "ownerless_rx_no_callback_result");
   xdev_ext_mech_check_hold(&io, 0, 0, 0, 0, 0, "ownerless_rx_no_hold");
   ASSERT_EQ(skel->bss->rx_hold_ret, 0x1234567, "ownerless_rx_hold_not_called");
   ASSERT_EQ(skel->bss->rx_desc_len, 0x1234567, "ownerless_rx_cqe_not_read");
  }
}

static void test_afxdp_members(void)
{
	struct bpf_testmod_xdev_ext_mech io;
	struct xdev_ext_mech_afxdp *skel;
	struct bpf_link *link;

	skel = xdev_ext_mech_afxdp__open_and_load();
	if (!ASSERT_OK_PTR(skel, "afxdp_open_and_load"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.afxdp_ops);
	if (!ASSERT_OK_PTR(link, "afxdp_attach"))
		goto out;

	if (!ASSERT_OK(xdev_ext_mech_group(&io, XDEV_EXT_MECH_CLASS_AFXDP,
				      XDEV_EXT_MECH_MEMBER_PREPARE,
				      XDEV_EXT_MECH_DIR_TO_DEVICE), "afxdp_frames"))
		goto out;
	xdev_ext_mech_afxdp_info(&io);
	ASSERT_OK(xdev_ext_mech_command(&io), "afxdp_prepare_call");
	xdev_ext_mech_check_call(&io, 0, 0, false, "afxdp_prepare");
	ASSERT_EQ(skel->bss->prepare_mtu, XDEV_EXT_MECH_T_MTU, "afxdp_prepare_info");
	xdev_ext_mech_check_tag(skel->bss->prepare_tag_crc, "afxdp_prepare_crc");

	test_afxdp_tx(skel);
	test_afxdp_rx(skel);
out:
	bpf_link__destroy(link);
	xdev_ext_mech_afxdp__destroy(skel);
}

static void test_ce_members(void)
{
	struct xdev_ext_ce_mech_cqe cqe = {
		.outcome = XDEV_EXT_CE_OK,
		.bytes_done = XDEV_EXT_MECH_T_GROUP,
		.entries_done = XDEV_EXT_MECH_T_SEGMENTS,
	};
	const struct xdev_ext_ce_copy_desc *desc;
	struct bpf_testmod_xdev_ext_mech io;
	struct xdev_ext_mech_ce *skel;
	struct bpf_link *link;
	__u64 gpu = XDEV_EXT_MECH_T_GPU_BASE;
	__u32 i;

	skel = xdev_ext_mech_ce__open_and_load();
	if (!ASSERT_OK_PTR(skel, "ce_open_and_load"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.ce_ops);
	if (!ASSERT_OK_PTR(link, "ce_attach"))
		goto out;

	if (!ASSERT_OK(xdev_ext_mech_group(&io, XDEV_EXT_MECH_CLASS_CE,
				      XDEV_EXT_MECH_MEMBER_PREPARE,
				      XDEV_EXT_MECH_DIR_TO_DEVICE), "ce_frames"))
		goto out;
	xdev_ext_mech_ce_info(&io);
	ASSERT_OK(xdev_ext_mech_command(&io), "ce_prepare_call");
	xdev_ext_mech_check_call(&io, 0, 0, false, "ce_prepare");
	ASSERT_EQ(skel->bss->prepare_window_len, XDEV_EXT_MECH_T_GPU_WINDOW,
		  "ce_prepare_info");
	xdev_ext_mech_check_tag(skel->bss->prepare_tag_crc, "ce_prepare_crc");

	/* build: one entry per frame covering its data, the last completes */
	io.member = XDEV_EXT_MECH_MEMBER_BUILD;
	io.callsite = XDEV_EXT_MECH_SITE_WORKER;
	xdev_ext_mech_ce_info(&io);
	io.desc_size = sizeof(struct xdev_ext_ce_copy_desc);
	io.desc_cap = XDEV_EXT_MECH_MAX_FRAMES;
	ASSERT_OK(xdev_ext_mech_command(&io), "ce_build_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_BUILD_SUBMIT, XDEV_EXT_MECH_BUILD_SUBMIT,
			    false, "ce_build");
	ASSERT_EQ(io.out.slots_used, XDEV_EXT_MECH_T_SEGMENTS, "ce_build_slots");
	desc = (const void *)io.scratch;
	for (i = 0; i < XDEV_EXT_MECH_MAX_FRAMES; i++) {
		struct xdev_ext_ce_copy_desc want = {};

		if (i < XDEV_EXT_MECH_T_SEGMENTS) {
			want = (struct xdev_ext_ce_copy_desc) {
				.frame_pos = i,
				.frame_off = XDEV_EXT_MECH_T_HDR_ROOM,
				.gpu_off = gpu,
				.len = xdev_ext_mech_seg_len(i),
				.flags = i + 1 == XDEV_EXT_MECH_T_SEGMENTS ?
					 XDEV_EXT_CE_F_COMPLETION_POINT : 0,
			};
			gpu += want.len;
		}
		ASSERT_OK(memcmp(&desc[i], &want, sizeof(want)), "ce_desc");
	}
	xdev_ext_mech_check_obs(&skel->bss->build_obs, 1, "ce_build_obs");

	/* A positive CE build still refuses missing or invalid C leases. */
	((struct xdev_ext_ce_mech_info *)io.info)->lease_generation = 0;
	ASSERT_OK(xdev_ext_mech_command(&io), "ce_no_lease_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_BUILD_ABORT, XDEV_EXT_MECH_BUILD_ABORT,
			    false, "ce_no_lease");
	xdev_ext_mech_ce_info(&io);
	((struct xdev_ext_ce_mech_info *)io.info)->window_slot = XDEV_EXT_MECH_T_GPU_DEPTH;
	ASSERT_OK(xdev_ext_mech_command(&io), "ce_bad_slot_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_BUILD_ABORT, XDEV_EXT_MECH_BUILD_ABORT,
			    false, "ce_bad_slot");
	xdev_ext_mech_ce_info(&io);

	/* complete: C's outcome decides; only PRE_SUBMIT_FAILED retries */
	io.member = XDEV_EXT_MECH_MEMBER_COMPLETE;
	io.cqe_size = sizeof(cqe);
	io.cqe_cap = 1;
	memcpy(io.cqe, &cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "ce_complete_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_NEXT, XDEV_EXT_MECH_NEXT, false,
			    "ce_complete");
	ASSERT_EQ(skel->bss->complete_bytes, XDEV_EXT_MECH_T_GROUP, "ce_bytes");
	ASSERT_EQ(skel->bss->complete_entries, XDEV_EXT_MECH_T_SEGMENTS,
		  "ce_entries");
	xdev_ext_mech_check_obs(&skel->bss->complete_obs, 1, "ce_complete_obs");
	cqe.outcome = XDEV_EXT_CE_PRE_SUBMIT_FAILED;
	memcpy(io.cqe, &cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "ce_presubmit_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_RETRY, XDEV_EXT_MECH_RETRY, false,
			    "ce_presubmit");
	cqe.outcome = XDEV_EXT_CE_AMBIGUOUS;
	memcpy(io.cqe, &cqe, sizeof(cqe));
	ASSERT_OK(xdev_ext_mech_command(&io), "ce_ambiguous_call");
	xdev_ext_mech_check_call(&io, XDEV_EXT_MECH_ABORT, XDEV_EXT_MECH_ABORT, false,
			    "ce_ambiguous");
out:
	bpf_link__destroy(link);
	xdev_ext_mech_ce__destroy(skel);
}

enum xdev_ext_mech_nxp_mangle {
	XDEV_EXT_MECH_NXP_INTACT,
	XDEV_EXT_MECH_NXP_PAYLOAD,		/* last payload byte flipped: bad CRC */
	XDEV_EXT_MECH_NXP_PORT,		/* another UDP port: not this flow */
};

/* Ethernet, IPv4, UDP and NXP headers plus payload, as the sender emits them. */
static __u32 xdev_ext_mech_nxp_packet(__u8 *pkt, __u64 session, __u32 generation,
				 __u16 seg, enum xdev_ext_mech_nxp_mangle mangle)
{
	__u8 *ip = pkt + ETH_HLEN, *udp = ip + 20, *nxp = udp + 8;
	__u8 *payload = nxp + NXP_WIRE_HEADER_LEN;
	__u32 len = xdev_ext_mech_seg_len(seg);
	struct nxp_wire_segment segment = {
		.direction = NXP_IO_WRITE,
		.session_id = session,
		.generation = generation,
		.segment_index = seg,
		.segment_count = XDEV_EXT_MECH_T_SEGMENTS,
		.total_len = XDEV_EXT_MECH_T_GROUP,
		.relative_offset = seg * XDEV_EXT_MECH_T_SEG_LEN,
		.payload_len = len,
	};
	struct nxp_wire_span span = { .data = payload, .len = len };
	struct xdev_ext_mech_peer peer;

	xdev_ext_mech_peer(&peer);
	memcpy(pkt, peer.local_mac, ETH_ALEN);
	memcpy(pkt + ETH_ALEN, peer.peer_mac, ETH_ALEN);
	nxp_wire_put_be16(pkt + 12, ETH_P_IP);
	memset(ip, 0, 20 + 8);
	ip[0] = 0x45;
	nxp_wire_put_be16(ip + 2, 20 + 8 + NXP_WIRE_HEADER_LEN + len);
	nxp_wire_put_be16(ip + 6, 0x4000);		/* DF */
	ip[8] = 64;
	ip[9] = IPPROTO_UDP;
	memcpy(ip + 12, &peer.peer_ip, 4);
	memcpy(ip + 16, &peer.local_ip, 4);
	memcpy(udp, &peer.peer_port, 2);
	memcpy(udp + 2, &peer.local_port, 2);
	nxp_wire_put_be16(udp + 4, 8 + NXP_WIRE_HEADER_LEN + len);
	xdev_ext_mech_payload(generation * 8 + seg, payload, len);
	if (nxp_wire_header_encode(nxp, NXP_WIRE_HEADER_LEN, &segment, &span, 1))
		return 0;
	if (mangle == XDEV_EXT_MECH_NXP_PAYLOAD)
		payload[len - 1] ^= 0x5a;
	if (mangle == XDEV_EXT_MECH_NXP_PORT)
		udp[3] ^= 1;
	return XDEV_EXT_MECH_T_RX_L2L4 + NXP_WIRE_HEADER_LEN + len;
}

static void xdev_ext_mech_nxp_rx(__u32 callsite, __u64 session, __u32 generation,
			    __u16 seg, enum xdev_ext_mech_nxp_mangle mangle,
			    const char *name)
{
	__u8 pkt[XDEV_EXT_MECH_T_RX_L2L4 + NXP_WIRE_HEADER_LEN + XDEV_EXT_MECH_T_SEG_LEN];
	struct bpf_testmod_xdev_ext_mech io;
	__u32 len;

	len = xdev_ext_mech_nxp_packet(pkt, session, generation, seg, mangle);
	if (!ASSERT_GT(len, 0, name) ||
	    !ASSERT_OK(xdev_ext_mech_rx_call(&io, callsite, pkt, len), name))
		return;
	ASSERT_EQ(io.out.return_value, -EOPNOTSUPP, name);
	xdev_ext_mech_check_hold(&io, 0, 0, 0, 0, 0, name);
}

/*
 * Stateless diagnostic packets of every shape require a real RX owner.
 * These cases assert rejection and unchanged program state; they do not
 * certify session RX protocol handling, which the guest integration runs.
 */
static void test_nxp_rx_cases(void)
{
	struct xdev_ext_mech_nxp *skel;
	struct bpf_link *link;
	__u16 seg;

	skel = xdev_ext_mech_nxp__open_and_load();
	if (!ASSERT_OK_PTR(skel, "nxp_open_and_load"))
		return;
	skel->bss->nxp_session = XDEV_EXT_MECH_T_SESSION;
	skel->bss->nxp_total_len = XDEV_EXT_MECH_T_GROUP;
	skel->bss->nxp_segments = XDEV_EXT_MECH_T_SEGMENTS;
	skel->bss->nxp_next_generation = 1;
	link = bpf_map__attach_struct_ops(skel->maps.nxp_afxdp_ops);
	if (!ASSERT_OK_PTR(link, "nxp_attach"))
		goto out;

	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION, 1, 0,
			XDEV_EXT_MECH_NXP_INTACT, "correct_first");
	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION, 1, 2,
			XDEV_EXT_MECH_NXP_INTACT, "out_of_order");
	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION, 1, 0,
			XDEV_EXT_MECH_NXP_INTACT, "duplicate");
	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION, 1, 1,
			XDEV_EXT_MECH_NXP_PAYLOAD, "bad_crc");
	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION + 1, 1, 1,
			XDEV_EXT_MECH_NXP_INTACT, "wrong_session");
	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION, 1, 1,
			XDEV_EXT_MECH_NXP_PORT, "not_nxp");
	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_NATIVE, XDEV_EXT_MECH_T_SESSION, 1, 1,
			XDEV_EXT_MECH_NXP_INTACT, "rx_native");
	for (seg = 2; seg < XDEV_EXT_MECH_T_SEGMENTS; seg++)
		xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION,
				1, seg, XDEV_EXT_MECH_NXP_INTACT,
				"correct_rest");
	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION, 1, 0,
			XDEV_EXT_MECH_NXP_INTACT,
			"duplicate_generation");
	xdev_ext_mech_nxp_rx(XDEV_EXT_MECH_SITE_RX_GENERIC, XDEV_EXT_MECH_T_SESSION, 2, 0,
			XDEV_EXT_MECH_NXP_INTACT, "correct_next");

	ASSERT_EQ(skel->bss->nxp_held, 0, "nxp_held");
	ASSERT_EQ(skel->bss->nxp_recycled, 0, "nxp_recycled");
	ASSERT_EQ(skel->bss->nxp_published, 0, "nxp_published");
	ASSERT_EQ(skel->bss->nxp_next_generation, 1, "nxp_generation");
	ASSERT_EQ(skel->bss->nxp_next_segment, 0, "nxp_segment");
out:
	bpf_link__destroy(link);
	xdev_ext_mech_nxp__destroy(skel);
}

/* One MK3 arm; prints the marker line the harness collects. */
static void xdev_ext_mech_mk3_arm(__u32 arm, const char *label)
{
	struct bpf_testmod_xdev_ext_mech io;

	if (!ASSERT_OK(xdev_ext_mech_group(&io, XDEV_EXT_MECH_CLASS_NVME,
				      XDEV_EXT_MECH_MEMBER_BUILD,
				      XDEV_EXT_MECH_DIR_TO_DEVICE), "mk3_frames"))
		return;
	xdev_ext_mech_nvme_info(&io);
	io.command = BPF_TESTMOD_XDEV_EXT_MECH_MK3;
	io.arm = arm;
	io.desc_size = XDEV_EXT_NVME_MECH_DESC_SIZE;
	io.desc_cap = 1;
	io.iterations = XDEV_EXT_MECH_MK3_ITERS;
	if (!ASSERT_OK(xdev_ext_mech_command(&io), "mk3_call") ||
	    !ASSERT_OK(io.out.return_value, label))
		return;
	ASSERT_EQ(io.out.done, XDEV_EXT_MECH_MK3_ITERS, label);
	ASSERT_EQ(io.out.c_calls,
		  arm == BPF_TESTMOD_XDEV_EXT_MECH_ARM_C ? XDEV_EXT_MECH_MK3_ITERS : 0,
		  label);
	if (ASSERT_GT(io.out.elapsed_ns, 0, label))
		printf("XDEV_EXT_MECH_MK3 arm=%s ns_per_iter=%.1f\n", label,
		       (double)io.out.elapsed_ns / io.out.done);
}

/*
 * MK3 (plan section 6.2): 10^6 NVMe builds plus validation in the kernel,
 * eBPF against the same specialised C.  The numbers are only reported.
 */
static void test_mk3(void)
{
	struct bpf_testmod_xdev_ext_mech io = {
		.command = BPF_TESTMOD_XDEV_EXT_MECH_FRAME_READ,
	};
	struct xdev_ext_mech_mk3 *skel;
	struct bpf_link *link;

	skel = xdev_ext_mech_mk3__open_and_load();
	if (!ASSERT_OK_PTR(skel, "mk3_open_and_load"))
		return;
	link = bpf_map__attach_struct_ops(skel->maps.mk3_nvme_ops);
	if (!ASSERT_OK_PTR(link, "mk3_attach"))
		goto out;
	xdev_ext_mech_mk3_arm(BPF_TESTMOD_XDEV_EXT_MECH_ARM_E, "E");
	if (!ASSERT_OK(xdev_ext_mech_command(&io), "mk3_config"))
		goto out;
	if (io.out.config & BPF_TESTMOD_XDEV_EXT_MECH_CFG_C_REFERENCE)
		xdev_ext_mech_mk3_arm(BPF_TESTMOD_XDEV_EXT_MECH_ARM_C, "C");
	else
		printf("XDEV_EXT_MECH_MK3 arm=C skip=no-c-reference\n");
out:
	bpf_link__destroy(link);
	xdev_ext_mech_mk3__destroy(skel);
}

void serial_test_xdev_ext_mech(void)
{
	if (!xdev_ext_mech_btf_available())
		return;

	if (xdev_ext_mech_seam_available()) {
		if (test__start_subtest("no_program"))
			test_no_program();
		if (test__start_subtest("nvme_members"))
			test_nvme_members();
		if (test__start_subtest("afxdp_members"))
			test_afxdp_members();
		if (test__start_subtest("ce_members"))
			test_ce_members();
		if (test__start_subtest("nxp_rx_requires_owner"))
			test_nxp_rx_cases();
		if (test__start_subtest("mk3"))
			test_mk3();
	}

	RUN_TESTS(xdev_ext_mech_fail_write_ctx);
	RUN_TESTS(xdev_ext_mech_fail_desc_complete);
	RUN_TESTS(xdev_ext_mech_fail_dma_desc_complete);
	RUN_TESTS(xdev_ext_mech_fail_dma_wrong_class_hold);
	RUN_TESTS(xdev_ext_mech_fail_sleepable_build);
	RUN_TESTS(xdev_ext_mech_fail_view_size);
	RUN_TESTS(xdev_ext_mech_fail_binding_calls_mech);
	RUN_TESTS(xdev_ext_mech_fail_wrong_class_hold);
	RUN_TESTS(xdev_ext_mech_fail_forged_ctx);
	RUN_TESTS(xdev_ext_mech_fail_frame_write);
	RUN_TESTS(xdev_ext_mech_fail_compute_desc);
	RUN_TESTS(xdev_ext_mech_fail_compute_rw_build);
	RUN_TESTS(xdev_ext_mech_fail_compute_set_len_complete);
	RUN_TESTS(xdev_ext_mech_fail_compute_sleepable);
	RUN_TESTS(xdev_ext_mech_fail_compute_view_past);
	RUN_TESTS(xdev_ext_mech_fail_compute_view_size);
	RUN_TESTS(xdev_ext_mech_fail_compute_wrong_class);
	RUN_TESTS(xdev_ext_mech_binding_loads);
}
