// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define main nvme_xdp_pipeline_program_main
#include "../../../../nvme_xdp_pipeline.c"
#undef main

#define TEST_WIRE_SESSION UINT64_C(0x1122334455667788)

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                               \
	long long _expected = (long long)(expected);                           \
	checks++;                                                               \
	if (_actual != _expected) {                                             \
		fprintf(stderr, "%s:%d: got %lld, expected %lld\n",              \
			__func__, __LINE__, _actual, _expected);                       \
		failures++;                                                        \
	}                                                                        \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

struct fake_adapter_state {
	int revalidate_result;
	int layout_result;
	int prove_iopoll_result;
	int ring_init_result;
	int ring_close_result;
	int submit_result;
	int enter_result;
	int peek_result;
	int progress_iopoll_result;
	int progress_results[4];
	unsigned int progress_results_nr;
	bool change_peek_after_progress;
	unsigned int change_peek_after_progress_call;
	int peek_result_after_progress;
	int monotonic_result;
	unsigned int monotonic_fail_after_call;
	int wait_result;
	int wait_results[4];
	unsigned int wait_results_nr;
	int unregister_buffers_result;
	int unregister_files_result;
	int event_wait_result;
	short event_rx_revents;
	unsigned int event_wait_calls;
	uint64_t monotonic_ns;
	uint64_t monotonic_step_ns;
	uint64_t cqe_storage[4];
	unsigned int submit_head_advance;
	unsigned int enter_head_advance;
	unsigned int revalidate_calls;
	unsigned int layout_calls;
	unsigned int prove_iopoll_calls;
	unsigned int ring_init_calls;
	unsigned int ring_close_calls;
	unsigned int submit_calls;
	unsigned int enter_calls;
	unsigned int peek_calls;
	unsigned int progress_iopoll_calls;
	unsigned int monotonic_calls;
	unsigned int wait_calls;
	uint64_t last_wait_timeout_ns;
	unsigned int unregister_buffers_calls;
	unsigned int unregister_files_calls;
	/* When set, a scripted NIC/NVMe peer for whole-loop tests (see
	 * struct fake_rx_world); NULL keeps every fake exactly as above. */
	struct fake_rx_world *world;
};

struct fake_rx_world;
static int fake_world_submit(struct pipeline_ctx *ctx,
			     struct fake_rx_world *w);
static int fake_world_peek(struct fake_rx_world *w,
			   struct io_uring_cqe **cqe);
static int fake_world_wait(struct fake_rx_world *w,
			   struct io_uring_cqe **cqe);
static int fake_world_event_wait(struct fake_rx_world *w, short *rx_revents);
static void fake_world_step(struct fake_rx_world *w);

static struct fake_adapter_state *fake_state(struct pipeline_ctx *ctx)
{
	return ctx->adapter_data;
}

static int fake_revalidate(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->revalidate_calls++;
	return s->revalidate_result;
}

static int fake_prove_iopoll(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->prove_iopoll_calls++;
	return s->prove_iopoll_result;
}

static int fake_require_extended_layout(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->layout_calls++;
	return s->layout_result;
}

static int fake_ring_init(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->ring_init_calls++;
	if (!s->ring_init_result)
		ctx->uring.initialized = true;
	return s->ring_init_result;
}

static int fake_ring_close(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->ring_close_calls++;
	return s->ring_close_result;
}

static int fake_submit(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->submit_calls++;
	if (s->world)
		return fake_world_submit(ctx, s->world);
	if (s->submit_head_advance)
		*ctx->uring.ring.sq.khead += s->submit_head_advance;
	return s->submit_result;
}

static int fake_enter(struct pipeline_ctx *ctx, unsigned int to_submit)
{
	struct fake_adapter_state *s = fake_state(ctx);

	(void)to_submit;
	s->enter_calls++;
	if (s->enter_head_advance)
		*ctx->uring.ring.sq.khead += s->enter_head_advance;
	return s->enter_result;
}

static int fake_peek_cqe(struct pipeline_ctx *ctx, struct io_uring_cqe **cqe)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->peek_calls++;
	if (s->world)
		return fake_world_peek(s->world, cqe);
	if (!s->peek_result && cqe)
		*cqe = (struct io_uring_cqe *)s->cqe_storage;
	return s->peek_result;
}

static int fake_progress_iopoll(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);
	int ret;

	s->progress_iopoll_calls++;
	if (s->progress_iopoll_calls <= s->progress_results_nr)
		ret = s->progress_results[s->progress_iopoll_calls - 1];
	else
		ret = s->progress_iopoll_result;
	if (s->change_peek_after_progress &&
	    s->progress_iopoll_calls >=
		(s->change_peek_after_progress_call ?
		 s->change_peek_after_progress_call : 1))
		s->peek_result = s->peek_result_after_progress;
	return ret;
}

static int fake_monotonic_ns(struct pipeline_ctx *ctx, uint64_t *now_ns)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->monotonic_calls++;
	if (s->world)
		fake_world_step(s->world);
	if (s->monotonic_result &&
	    (!s->monotonic_fail_after_call ||
	     s->monotonic_calls >= s->monotonic_fail_after_call))
		return s->monotonic_result;
	*now_ns = s->monotonic_ns;
	s->monotonic_ns += s->monotonic_step_ns;
	return 0;
}

static int fake_wait_cqe_timeout(struct pipeline_ctx *ctx,
				 struct io_uring_cqe **cqe,
				 uint64_t timeout_ns)
{
	struct fake_adapter_state *s = fake_state(ctx);
	int ret;

	s->wait_calls++;
	s->last_wait_timeout_ns = timeout_ns;
	if (s->world)
		return fake_world_wait(s->world, cqe);
	if (s->wait_calls <= s->wait_results_nr)
		ret = s->wait_results[s->wait_calls - 1];
	else
		ret = s->wait_result;
	if (!ret && cqe)
		*cqe = (struct io_uring_cqe *)s->cqe_storage;
	return ret;
}

static int fake_wait_cqe_or_rx(struct pipeline_ctx *ctx, uint64_t timeout_ns,
			       short *rx_revents)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->event_wait_calls++;
	s->last_wait_timeout_ns = timeout_ns;
	*rx_revents = 0;
	if (s->world)
		return fake_world_event_wait(s->world, rx_revents);
	*rx_revents = s->event_rx_revents;
	return s->event_wait_result;
}

static int fake_unregister_buffers(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->unregister_buffers_calls++;
	return s->unregister_buffers_result;
}

static int fake_unregister_files(struct pipeline_ctx *ctx)
{
	struct fake_adapter_state *s = fake_state(ctx);

	s->unregister_files_calls++;
	return s->unregister_files_result;
}

static const struct pipeline_adapter fake_adapter = {
	.revalidate = fake_revalidate,
	.require_extended_layout = fake_require_extended_layout,
	.prove_iopoll = fake_prove_iopoll,
	.ring_init = fake_ring_init,
	.ring_close = fake_ring_close,
	.submit = fake_submit,
	.enter = fake_enter,
	.peek_cqe = fake_peek_cqe,
	.progress_iopoll = fake_progress_iopoll,
	.monotonic_ns = fake_monotonic_ns,
	.wait_cqe_timeout = fake_wait_cqe_timeout,
	.wait_cqe_or_rx = fake_wait_cqe_or_rx,
	.unregister_buffers = fake_unregister_buffers,
	.unregister_files = fake_unregister_files,
};

static void init_fake_ctx(struct pipeline_ctx *ctx,
			  struct fake_adapter_state *state)
{
	memset(ctx, 0, sizeof(*ctx));
	memset(state, 0, sizeof(*state));
	ctx->nvme_fd = 41;
	ctx->block_fd = -1;
	ctx->adapter = &fake_adapter;
	ctx->adapter_data = state;
	ctx->session_id = TEST_WIRE_SESSION;
}

static void setup_fake_cq(struct pipeline_ctx *ctx, uint64_t *entries,
			  uint32_t nr, uint32_t *producer,
			  uint32_t *consumer);

static void test_final_revalidation_precedes_publication(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot = { 0 };
	uint32_t generation = 0;
	unsigned int accepted = 99;
	int order[] = { 0 };
	int ret;

	init_fake_ctx(&ctx, &state);
	state.revalidate_result = -ESTALE;
	ctx.uring.ring.sq.sqe_head = 23;
	ctx.uring.ring.sq.sqe_tail = 8;
	EXPECT_EQ(nxp_request_prepare(&slot.request, 0, &generation), 0);
	ret = submit_prepared_batch(&ctx, &slot, order, 1, 7, &accepted);
	EXPECT_EQ(ret, -ESTALE);
	EXPECT_EQ(state.revalidate_calls, 1);
	EXPECT_EQ(state.submit_calls, 0);
	EXPECT_EQ(accepted, 0);
	EXPECT_EQ(ctx.uring.ring.sq.sqe_head, 23);
	EXPECT_EQ(ctx.uring.ring.sq.sqe_tail, 7);
	EXPECT_EQ(slot.request.state, NXP_REQ_PREPARED);
	EXPECT_TRUE(slot.request.owns_backing);
}

static void test_fixed_sqe_fields_are_independent(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	union {
		max_align_t align;
		unsigned char bytes[128];
	} storage;
	struct io_uring_sqe *sqe = (struct io_uring_sqe *)storage.bytes;
	struct nxp_nvme_read read = {
		.data_len = 4096,
		.cdw10 = 0x89abcdef,
		.cdw11 = 0x01234567,
		.cdw12 = 7,
	};
	struct nvme_uring_cmd *cmd;

	init_fake_ctx(&ctx, &state);
	ctx.nsid = 9;
	memset(&storage, 0xff, sizeof(storage));
	fill_nvme_read_sqe(&ctx, sqe, (void *)(uintptr_t)0x1234000,
			   &read, UINT64_C(0xaabbccdd), 17);
	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	EXPECT_EQ(sqe->fd, 41);
	EXPECT_FALSE(sqe->flags & IOSQE_FIXED_FILE);
	EXPECT_FALSE(sqe->uring_cmd_flags & IORING_URING_CMD_FIXED);
	EXPECT_EQ(cmd->nsid, 9);
	EXPECT_EQ(cmd->data_len, 4096);
	EXPECT_EQ(cmd->cdw10, 0x89abcdef);
	EXPECT_EQ(cmd->cdw11, 0x01234567);
	EXPECT_EQ(cmd->cdw12, 7);
	EXPECT_EQ(cmd->rsvd2, NVME_URING_CMD_F_XDEV_EXT);
	EXPECT_EQ(cmd->rsvd2 & ~NVME_URING_CMD_F_KNOWN_MASK, 0);

	ctx.uring.fixed_file_registered = true;
	fill_nvme_read_sqe(&ctx, sqe, (void *)(uintptr_t)0x1234000,
			   &read, UINT64_C(0xaabbccdd), 17);
	EXPECT_EQ(sqe->fd, 0);
	EXPECT_TRUE(sqe->flags & IOSQE_FIXED_FILE);
	EXPECT_FALSE(sqe->uring_cmd_flags & IORING_URING_CMD_FIXED);

	ctx.uring.fixed_file_registered = false;
	ctx.uring.fixed_buffer_registered = true;
	fill_nvme_read_sqe(&ctx, sqe, (void *)(uintptr_t)0x1234000,
			   &read, UINT64_C(0xaabbccdd), 17);
	EXPECT_EQ(sqe->fd, 41);
	EXPECT_FALSE(sqe->flags & IOSQE_FIXED_FILE);
	EXPECT_TRUE(sqe->uring_cmd_flags & IORING_URING_CMD_FIXED);
	EXPECT_EQ(sqe->buf_index, 17);

	ctx.uring.fixed_file_registered = true;
	fill_nvme_read_sqe(&ctx, sqe, (void *)(uintptr_t)0x1234000,
			   &read, UINT64_C(0xaabbccdd), 17);
	EXPECT_EQ(sqe->fd, 0);
	EXPECT_TRUE(sqe->flags & IOSQE_FIXED_FILE);
	EXPECT_TRUE(sqe->uring_cmd_flags & IORING_URING_CMD_FIXED);
}

static void test_vector_sqe_is_one_fixed_registered_nvme_command(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	union {
		max_align_t align;
		unsigned char bytes[128];
	} storage;
	struct io_uring_sqe *sqe = (struct io_uring_sqe *)storage.bytes;
	struct iovec vector[6] = { 0 };
	struct nxp_nvme_io_plan plan = {
		.direction = NXP_IO_READ,
		.opcode = NXP_NVME_OP_READ,
		.slba = UINT64_C(0x123456789),
		.blocks = 16,
		.nlb = 15,
		.data_len = 8192,
		.cdw10 = 0x23456789,
		.cdw11 = 1,
		.cdw12 = 15,
	};
	struct nvme_uring_cmd *cmd;

	init_fake_ctx(&ctx, &state);
	ctx.nsid = 4;
	EXPECT_EQ(fill_nvme_vector_sqe(&ctx, sqe, vector, 6, &plan,
				       UINT64_C(0x11223344), 0),
		  -EOPNOTSUPP);
	ctx.uring.fixed_buffer_registered = true;
	EXPECT_EQ(fill_nvme_vector_sqe(&ctx, sqe, vector, 6, &plan,
				       UINT64_C(0x11223344), 0), 0);
	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	EXPECT_EQ(sqe->opcode, IORING_OP_URING_CMD);
	EXPECT_EQ(sqe->cmd_op, NVME_URING_CMD_IO_VEC);
	EXPECT_TRUE(sqe->uring_cmd_flags & IORING_URING_CMD_FIXED);
	EXPECT_EQ(sqe->buf_index, 0);
	EXPECT_EQ(sqe->user_data, UINT64_C(0x11223344));
	EXPECT_EQ(cmd->opcode, NVME_CMD_READ);
	EXPECT_EQ(cmd->nsid, 4);
	EXPECT_EQ(cmd->addr, (uintptr_t)vector);
	EXPECT_EQ(cmd->data_len, 6);
	EXPECT_EQ(cmd->cdw10, 0x23456789);
	EXPECT_EQ(cmd->cdw11, 1);
	EXPECT_EQ(cmd->cdw12, 15);
	EXPECT_EQ(cmd->rsvd2, NVME_URING_CMD_F_XDEV_EXT);

	plan.direction = NXP_IO_WRITE;
	plan.opcode = NXP_NVME_OP_WRITE;
	EXPECT_EQ(fill_nvme_vector_sqe(&ctx, sqe, vector, 6, &plan, 9, 0), 0);
	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	EXPECT_EQ(cmd->opcode, NVME_CMD_WRITE);
	EXPECT_EQ(fill_nvme_vector_sqe(&ctx, sqe, vector, 0, &plan, 9, 0),
		  -EINVAL);
}

static void test_wire_packet_builder_and_strict_receiver_share_real_bytes(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	unsigned char frame[FRAME_SIZE] = { 0 };
	unsigned char rx_frame[FRAME_SIZE] __attribute__((aligned(FRAME_SIZE))) = { 0 };
	unsigned char payload[1024];
	struct nxp_wire_segment tx = {
		.direction = NXP_IO_WRITE,
		.session_id = TEST_WIRE_SESSION,
		.generation = 19,
		.segment_index = 0,
		.segment_count = 1,
		.total_len = sizeof(payload),
		.relative_offset = 0,
		.payload_len = sizeof(payload),
	};
	struct pipeline_rx_packet rx;
	struct xdp_desc rx_descriptor = { 0 };
	uint64_t rx_base = UINT64_MAX;
	uint64_t rx_data = UINT64_MAX;
	uint32_t packet_len = 0;
	uint32_t saved_block_size = g_block_size;

	init_fake_ctx(&ctx, &state);
	memcpy(ctx.src_mac, "\x02\x00\x00\x00\x00\x01", 6);
	memcpy(ctx.dst_mac, "\x02\x00\x00\x00\x00\x02", 6);
	ctx.src_ip = inet_addr("192.0.2.1");
	ctx.dst_ip = inet_addr("192.0.2.2");
	ctx.src_port = 12000;
	ctx.dst_port = 13000;
	ctx.mtu = 1500;
	g_block_size = sizeof(payload);
	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (unsigned char)(i * 17U);

	EXPECT_EQ(build_wire_packet(&ctx, frame, payload, &tx, &packet_len), 0);
	EXPECT_EQ(packet_len, PKT_HDR_SIZE + NXP_WIRE_HEADER_LEN + sizeof(payload));
	EXPECT_EQ(parse_wire_packet(&ctx, frame + PKT_START_OFF, packet_len,
				    &rx), 0);
	EXPECT_EQ(rx.segment.direction, NXP_IO_WRITE);
	EXPECT_EQ(rx.segment.generation, 19);
	EXPECT_EQ(rx.data_len, sizeof(payload));
	EXPECT_EQ(memcmp(rx.data, payload, sizeof(payload)), 0);
	EXPECT_EQ(pipeline_validate_rx_packet(&ctx, &rx), 0);

	/* Exercise the actual endpoint layout too: a NIC places the exact wire
	 * bytes at the RX headroom offset, descriptor decoding locates that packet,
	 * and the parser returns the aligned payload used by fixed IO_VEC. */
	memcpy(rx_frame + NXP_RX_PACKET_OFFSET, frame + PKT_START_OFF,
	       packet_len);
	rx_descriptor.addr = NXP_RX_PACKET_OFFSET;
	rx_descriptor.len = packet_len;
	EXPECT_EQ(pipeline_decode_rx_descriptor(&rx_descriptor, &rx_base,
						 &rx_data), 0);
	EXPECT_EQ(rx_base, 0);
	EXPECT_EQ(rx_data, NXP_RX_PACKET_OFFSET);
	EXPECT_EQ(parse_wire_packet(&ctx, rx_frame + rx_data,
				    rx_descriptor.len, &rx), 0);
	EXPECT_EQ(pipeline_validate_rx_packet(&ctx, &rx), 0);
	EXPECT_EQ(rx.data, rx_frame + NXP_RX_DATA_OFFSET);
	EXPECT_EQ((uintptr_t)rx.data % NXP_VECTOR_ALIGNMENT, 0);
	rx.segment.direction = NXP_IO_READ;
	EXPECT_EQ(pipeline_validate_rx_packet(&ctx, &rx), -EACCES);
	rx.segment.direction = (enum nxp_io_direction)3;
	EXPECT_EQ(pipeline_validate_rx_packet(&ctx, &rx), -EPROTO);
	rx.segment.direction = NXP_IO_WRITE;

	frame[NXP_DATA_OFFSET + 7] ^= 1;
	EXPECT_EQ(parse_wire_packet(&ctx, frame + PKT_START_OFF, packet_len,
				    &rx), -EBADMSG);
	frame[NXP_DATA_OFFSET + 7] ^= 1;
	frame[PKT_START_OFF] ^= 1; /* exact destination MAC tuple */
	EXPECT_EQ(parse_wire_packet(&ctx, frame + PKT_START_OFF, packet_len,
				    &rx), -EACCES);
	g_block_size = saved_block_size;
}

static void test_default_8k_transfer_is_six_mtu_packets_and_depth_bounded(void)
{
	struct nxp_wire_layout layout = { 0 };

	EXPECT_EQ(g_block_size, 8192);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 1, g_block_size, 1500, FRAME_SIZE,
					 NXP_LAYOUT_DATA_OFFSET,
					 NXP_VECTOR_ALIGNMENT,
					 &layout), 0);
	EXPECT_EQ(layout.segment_data_limit, 1432);
	EXPECT_EQ(layout.segment_count, 6);
	EXPECT_EQ(nxp_group_capacity_validate(
		341, layout.segment_count, NUM_FRAMES,
		XSK_RING_PROD__DEFAULT_NUM_DESCS,
		XSK_RING_CONS__DEFAULT_NUM_DESCS,
		XSK_RING_PROD__DEFAULT_NUM_DESCS,
		XSK_RING_CONS__DEFAULT_NUM_DESCS), 0);
	EXPECT_EQ(nxp_group_capacity_validate(
		342, layout.segment_count, NUM_FRAMES,
		XSK_RING_PROD__DEFAULT_NUM_DESCS,
		XSK_RING_CONS__DEFAULT_NUM_DESCS,
		XSK_RING_PROD__DEFAULT_NUM_DESCS,
		XSK_RING_CONS__DEFAULT_NUM_DESCS), -E2BIG);
}

static void test_transform_defaults_to_identity_and_xor_is_explicit(void)
{
	uint64_t value = UINT64_C(0x0123456789abcdef);
	uint64_t original = value;
	enum pipeline_transform saved = g_transform;

	g_transform = PIPELINE_TRANSFORM_NONE;
	process_data(&value, sizeof(value));
	EXPECT_EQ(value, original);
	g_transform = PIPELINE_TRANSFORM_XOR;
	process_data(&value, sizeof(value));
	EXPECT_EQ(value, original ^ UINT64_C(0xdeadbeefcafebabe));
	g_transform = saved;
}

static void test_rx_write_rejects_sender_only_transform(void)
{
	EXPECT_EQ(pipeline_validate_transform(PIPELINE_NVME_TO_NIC,
					      PIPELINE_TRANSFORM_NONE), 0);
	EXPECT_EQ(pipeline_validate_transform(PIPELINE_NVME_TO_NIC,
					      PIPELINE_TRANSFORM_XOR), 0);
	EXPECT_EQ(pipeline_validate_transform(PIPELINE_NIC_TO_NVME,
					      PIPELINE_TRANSFORM_NONE), 0);
	EXPECT_EQ(pipeline_validate_transform(PIPELINE_NIC_TO_NVME,
					      PIPELINE_TRANSFORM_XOR), -EINVAL);
}

static void test_8k_staging_scatters_one_nvme_buffer_into_six_frames(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot = { 0 };
	uint32_t saved_block_size = g_block_size;
	unsigned char *staging;
	size_t copied = 0;

	init_fake_ctx(&ctx, &state);
	ctx.mtu = 1500;
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	EXPECT_EQ(posix_memalign((void **)&staging, 4096, 8192), 0);
	for (size_t i = 0; i < 8192; i++)
		staging[i] = (unsigned char)(i * 29U);
	slot.frame_addr = INVALID_UMEM_FRAME;
	slot.staging_buf = staging;
	g_block_size = 8192;

	EXPECT_EQ(pipeline_prepare_staging_frames(&ctx, &slot, 3, 4), 0);
	EXPECT_EQ(slot.segment_count, 6);
	EXPECT_EQ(pipeline_copy_staging_group(&ctx, &slot), 0);
	for (uint16_t i = 0; i < slot.segment_count; i++) {
		EXPECT_EQ(memcmp(slot.vector[i].iov_base, staging + copied,
				 slot.vector[i].iov_len), 0);
		copied += slot.vector[i].iov_len;
	}
	EXPECT_EQ(copied, 8192);
	EXPECT_EQ(pipeline_abort_group_frames(&ctx, &slot), 0);
	EXPECT_EQ(xdev_ext_pool_free_count(&ctx.xsk.pool), NUM_FRAMES);

	g_block_size = saved_block_size;
	free(staging);
	free(ctx.xsk.umem_area);
}

static void test_prepare_8k_tx_group_owns_six_frames_and_one_sqe(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot;
	union {
		max_align_t align;
		unsigned char bytes[128];
	} sq_storage;
	unsigned int sq_head = 0, sq_mask = 0, sq_entries = 1;
	uint32_t request_generation = 0;
	uint32_t saved_block_size = g_block_size;
	size_t total = 0;

	init_fake_ctx(&ctx, &state);
	memset(&slot, 0, sizeof(slot));
	slot.frame_addr = INVALID_UMEM_FRAME;
	ctx.mtu = 1500;
	ctx.nsid = 1;
	ctx.namespace = (struct nxp_namespace) {
		.nsid = 1, .lba_size = 512, .capacity_lbas = 4096,
		.char_is_namespace = true, .block_is_whole_namespace = true,
		.same_namespace = true, .stable_id_present = true,
		.controller_serial_present = true, .pci_bdf_present = true,
		.char_rdev = 1, .block_rdev = 2, .diskseq = 3,
		.stable_id_len = 1, .controller_serial_len = 1,
		.pci_bdf_len = 1,
	};
	ctx.io_limits.authorized_first_lba = 100;
	ctx.io_limits.authorized_lbas = 32;
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.fixed_buffer_registered = true;
	ctx.uring.ring.flags = IORING_SETUP_SQE128;
	ctx.uring.ring.sq.khead = &sq_head;
	ctx.uring.ring.sq.kring_mask = &sq_mask;
	ctx.uring.ring.sq.kring_entries = &sq_entries;
	ctx.uring.ring.sq.sqes = (struct io_uring_sqe *)sq_storage.bytes;
	g_block_size = 8192;

	EXPECT_EQ(pipeline_prepare_tx_group(&ctx, &slot, 0, 0,
					    &request_generation, 77), 0);
	EXPECT_EQ(slot.segment_count, 6);
	EXPECT_EQ(ctx.uring.ring.sq.sqe_tail, 1);
	for (uint16_t i = 0; i < slot.segment_count; i++) {
		EXPECT_EQ(slot.vector[i].iov_base,
			  ctx.xsk.umem_area + slot.frame_addrs[i] +
			  NXP_DATA_OFFSET);
		EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool,
					 slot.frame_addrs[i] / FRAME_SIZE),
			  XDEV_EXT_FRAME_IO_PENDING);
		total += slot.vector[i].iov_len;
	}
	EXPECT_EQ(total, 8192);
	EXPECT_EQ(((struct io_uring_sqe *)sq_storage.bytes)->cmd_op,
		  NVME_URING_CMD_IO_VEC);
	EXPECT_EQ(((struct nvme_uring_cmd *)
		  ((struct io_uring_sqe *)sq_storage.bytes)->cmd)->data_len, 6);
	EXPECT_EQ(pipeline_abort_private_group(&ctx, &slot), 0);
	EXPECT_EQ(xdev_ext_pool_free_count(&ctx.xsk.pool), NUM_FRAMES);

	g_block_size = saved_block_size;
	free(ctx.xsk.umem_area);
}

static void test_tx_group_publishes_six_descriptors_and_reclaims_each_once(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot;
	struct xdp_desc tx_entries[8] = { 0 };
	uint64_t cq_entries[8] = { 0 };
	uint32_t tx_producer = 0, tx_consumer = 0;
	uint32_t cq_producer = 0, cq_consumer = 0;
	uint32_t descriptor_index = 0;
	struct nxp_wire_group_rx rx_group = { 0 };
	struct nxp_nvme_io_plan write_plan;
	struct nxp_local_io_position write_position = { .request_index = 2 };
	struct nxp_namespace namespace = {
		.nsid = 1, .lba_size = 512, .capacity_lbas = 4096,
		.char_is_namespace = true, .block_is_whole_namespace = true,
		.same_namespace = true, .stable_id_present = true,
		.controller_serial_present = true, .pci_bdf_present = true,
		.char_rdev = 1, .block_rdev = 2, .diskseq = 3,
		.stable_id_len = 1, .controller_serial_len = 1,
		.pci_bdf_len = 1,
	};
	struct nxp_io_limits limits = {
		.authorized_first_lba = 100, .authorized_lbas = 64,
	};

	init_fake_ctx(&ctx, &state);
	memset(&slot, 0, sizeof(slot));
	memcpy(ctx.src_mac, "\x02\x00\x00\x00\x00\x01", 6);
	memcpy(ctx.dst_mac, "\x02\x00\x00\x00\x00\x02", 6);
	ctx.src_ip = inet_addr("192.0.2.1");
	ctx.dst_ip = inet_addr("192.0.2.2");
	ctx.src_port = 12000;
	ctx.dst_port = 13000;
	ctx.mtu = 1500;
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 1, 8192, 1500, FRAME_SIZE,
					 NXP_LAYOUT_DATA_OFFSET,
					 NXP_VECTOR_ALIGNMENT,
					 &slot.wire_layout), 0);
	slot.segment_count = slot.wire_layout.segment_count;
	for (uint16_t i = 0; i < slot.segment_count; i++) {
		struct nxp_wire_segment segment = { 0 };

		slot.frame_addrs[i] = xsk_alloc_umem_frame(&ctx.xsk);
		EXPECT_TRUE(slot.frame_addrs[i] != INVALID_UMEM_FRAME);
		EXPECT_EQ(nxp_wire_segment_at(&slot.wire_layout, NXP_IO_READ, i,
					      &segment), 0);
		slot.vector[i].iov_base = ctx.xsk.umem_area +
			slot.frame_addrs[i] + NXP_DATA_OFFSET;
		slot.vector[i].iov_len = segment.payload_len;
		memset(slot.vector[i].iov_base, (int)(i + 1),
		       slot.vector[i].iov_len);
	}
	nxp_data_begin(&slot.data_progress, false);
	EXPECT_EQ(nxp_data_dma_done(&slot.data_progress), 0);
	EXPECT_EQ(nxp_data_process(&slot.data_progress), 0);
	ctx.xsk.tx = (struct xsk_ring_prod) {
		.cached_prod = 0, .cached_cons = 8, .mask = 7, .size = 8,
		.producer = &tx_producer, .consumer = &tx_consumer,
		.ring = tx_entries,
	};
	for (size_t i = 0; i < 8; i++)
		tx_entries[i].options = UINT32_MAX;
	EXPECT_EQ(xsk_ring_prod__reserve(&ctx.xsk.tx, slot.segment_count,
					 &descriptor_index), slot.segment_count);
	EXPECT_EQ(pipeline_submit_tx_group(&ctx, &slot, descriptor_index), 0);
	EXPECT_EQ(tx_producer, 6);
	EXPECT_EQ(ctx.stats.tx_submitted, 6);
	for (uint16_t i = 0; i < slot.segment_count; i++) {
		struct pipeline_rx_packet packet = { 0 };

		EXPECT_EQ(tx_entries[i].addr,
			  slot.frame_addrs[i] + PKT_START_OFF);
		EXPECT_EQ(tx_entries[i].options, 0);
		EXPECT_EQ(parse_wire_packet(&ctx,
					    ctx.xsk.umem_area + tx_entries[i].addr,
					    tx_entries[i].len, &packet), 0);
		/* The source operation was an NVMe READ, while the wire action is
		 * the only operation the destination is allowed to execute: WRITE. */
		EXPECT_EQ(packet.segment.direction, NXP_IO_WRITE);
		if (!i)
			EXPECT_EQ(nxp_wire_group_begin(&rx_group, TEST_WIRE_SESSION,
						       packet.segment.generation,
						       NXP_IO_WRITE,
						       packet.segment.total_len,
						       packet.segment.segment_count), 0);
		EXPECT_EQ(nxp_wire_group_accept(&rx_group, &packet.segment), 0);
		EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool,
					 slot.frame_addrs[i] / FRAME_SIZE),
			  XDEV_EXT_FRAME_TX_PENDING);
		cq_entries[slot.segment_count - i - 1] = tx_entries[i].addr;
	}
	EXPECT_EQ(nxp_wire_group_finish(&rx_group), 0);
	EXPECT_EQ(nxp_plan_nvme_io(&namespace, &limits, NXP_IO_WRITE,
				   &write_position, 8192, &write_plan), 0);
	EXPECT_EQ(write_plan.opcode, NVME_CMD_WRITE);
	EXPECT_EQ(write_plan.slba, 132);
	setup_fake_cq(&ctx, cq_entries, slot.segment_count,
		      &cq_producer, &cq_consumer);
	xsk_tx_complete(&ctx);
	EXPECT_EQ(ctx.stats.tx_reclaimed, 6);
	EXPECT_EQ(xdev_ext_pool_free_count(&ctx.xsk.pool), NUM_FRAMES);

	/* A repeated completion can never release the address twice. */
	cq_entries[0] = tx_entries[0].addr;
	setup_fake_cq(&ctx, cq_entries, 1, &cq_producer, &cq_consumer);
	xsk_tx_complete(&ctx);
	EXPECT_TRUE(ctx.xsk.protocol_invalidated);
	EXPECT_EQ(ctx.stats.tx_reclaimed, 6);
	free(ctx.xsk.umem_area);
}

static void test_fatal_completion_aborts_every_private_vector_frame(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot = { 0 };
	struct pipeline_loop_state flow = { .stop_issuing = true };

	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	slot.segment_count = 2;
	for (uint16_t i = 0; i < slot.segment_count; i++) {
		slot.frame_addrs[i] = xsk_alloc_umem_frame(&ctx.xsk);
		EXPECT_TRUE(slot.frame_addrs[i] != INVALID_UMEM_FRAME);
	}
	slot.frame_addr = slot.frame_addrs[0];
	EXPECT_TRUE(pipeline_discard_completed_after_fatal(&ctx, &slot, &flow));
	EXPECT_EQ(xdev_ext_pool_free_count(&ctx.xsk.pool), NUM_FRAMES);
	EXPECT_EQ(slot.segment_count, 0);
}

static void test_out_of_order_nvme_completions_wait_for_wire_generation(void)
{
	struct inflight_slot slots[3] = { 0 };

	for (size_t i = 0; i < 3; i++)
		pipeline_clear_group(&slots[i]);

	/* Request 1 (wire generation 2) completed first.  It must remain private
	 * until request 0 is ready, otherwise the strict receiver observes a gap. */
	slots[0].frame_addr = 0;
	slots[0].segment_count = 1;
	slots[0].block_index = 1;
	slots[0].wire_layout.generation = 2;
	slots[0].request.state = NXP_REQ_COMPLETED;
	slots[0].data_progress.stage = NXP_DATA_PROCESSED;
	EXPECT_EQ(pipeline_find_next_tx_group(slots, 3, 0), -EAGAIN);

	slots[1].frame_addr = FRAME_SIZE;
	slots[1].segment_count = 1;
	slots[1].block_index = 0;
	slots[1].wire_layout.generation = 1;
	slots[1].request.state = NXP_REQ_COMPLETED;
	slots[1].data_progress.stage = NXP_DATA_PROCESSED;
	EXPECT_EQ(pipeline_find_next_tx_group(slots, 3, 0), 1);
	EXPECT_EQ(pipeline_find_next_tx_group(slots, 3, 1), 0);

	/* Duplicate ready storage for one logical request is an attribution fault,
	 * not a reason to publish either copy. */
	slots[2] = slots[0];
	slots[2].frame_addr = 2 * FRAME_SIZE;
	EXPECT_EQ(pipeline_find_next_tx_group(slots, 3, 1), -EPROTO);
}

static void test_out_of_order_nvme_completions_publish_wire_in_order(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slots[2] = { 0 };
	struct pipeline_loop_state flow = { 0 };
	struct xdp_desc tx_entries[4] = { 0 };
	uint64_t cq_entries[2] = { 0 };
	uint32_t tx_producer = 0, tx_consumer = 0;
	uint32_t cq_producer = 0, cq_consumer = 0;
	uint32_t saved_block_size = g_block_size;
	uint64_t next_request = 0;
	unsigned int published = 0;

	init_fake_ctx(&ctx, &state);
	memcpy(ctx.src_mac, "\x02\x00\x00\x00\x00\x01", 6);
	memcpy(ctx.dst_mac, "\x02\x00\x00\x00\x00\x02", 6);
	ctx.src_ip = inet_addr("192.0.2.1");
	ctx.dst_ip = inet_addr("192.0.2.2");
	ctx.src_port = 12000;
	ctx.dst_port = 13000;
	ctx.mtu = 1500;
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.xsk.tx = (struct xsk_ring_prod) {
		.cached_prod = 0, .cached_cons = 4, .mask = 3, .size = 4,
		.producer = &tx_producer, .consumer = &tx_consumer,
		.ring = tx_entries,
	};
	g_block_size = 1024;

	/* Array order deliberately disagrees with logical/wire order. */
	for (size_t i = 0; i < 2; i++) {
		uint64_t request = i ? 0 : 1;
		struct nxp_wire_segment segment = { 0 };

		pipeline_clear_group(&slots[i]);
		EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, (uint32_t)request + 1,
						 g_block_size, ctx.mtu,
						 FRAME_SIZE,
						 NXP_LAYOUT_DATA_OFFSET,
						 NXP_VECTOR_ALIGNMENT,
						 &slots[i].wire_layout), 0);
		EXPECT_EQ(slots[i].wire_layout.segment_count, 1);
		EXPECT_EQ(nxp_wire_segment_at(&slots[i].wire_layout, NXP_IO_READ,
					      0, &segment), 0);
		slots[i].frame_addrs[0] = xsk_alloc_umem_frame(&ctx.xsk);
		EXPECT_TRUE(slots[i].frame_addrs[0] != INVALID_UMEM_FRAME);
		slots[i].frame_addr = slots[i].frame_addrs[0];
		slots[i].segment_count = 1;
		slots[i].block_index = request;
		slots[i].vector[0] = (struct iovec) {
			.iov_base = ctx.xsk.umem_area + slots[i].frame_addr +
				NXP_DATA_OFFSET,
			.iov_len = segment.payload_len,
		};
		memset(slots[i].vector[0].iov_base, (int)(i + 1),
		       slots[i].vector[0].iov_len);
		slots[i].request.state = NXP_REQ_COMPLETED;
		nxp_data_begin(&slots[i].data_progress, false);
		EXPECT_EQ(nxp_data_dma_done(&slots[i].data_progress), 0);
		EXPECT_EQ(nxp_data_process(&slots[i].data_progress), 0);
	}

	EXPECT_EQ(pipeline_publish_ready_tx_groups(&ctx, slots, 2,
						    &next_request, &flow,
						    &published), 0);
	EXPECT_EQ(published, 2);
	EXPECT_EQ(next_request, 2);
	EXPECT_EQ(tx_producer, 2);
	for (size_t i = 0; i < 2; i++) {
		struct pipeline_rx_packet packet = { 0 };

		EXPECT_EQ(parse_wire_packet(&ctx,
					    ctx.xsk.umem_area + tx_entries[i].addr,
					    tx_entries[i].len, &packet), 0);
		EXPECT_EQ(packet.segment.generation, i + 1);
		cq_entries[i] = tx_entries[i].addr;
	}
	setup_fake_cq(&ctx, cq_entries, 2, &cq_producer, &cq_consumer);
	xsk_tx_complete(&ctx);
	EXPECT_EQ(ctx.stats.tx_reclaimed, 2);
	EXPECT_EQ(xdev_ext_pool_free_count(&ctx.xsk.pool), NUM_FRAMES);

	g_block_size = saved_block_size;
	free(ctx.xsk.umem_area);
}

static void test_ordered_publisher_reports_committed_prefix_on_tail_error(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slots[2] = { 0 };
	struct pipeline_loop_state flow = { 0 };
	struct xdp_desc tx_entries[4] = { 0 };
	uint64_t cq_entries[2] = { 0 };
	uint32_t tx_producer = 0, tx_consumer = 0;
	uint32_t cq_producer = 0, cq_consumer = 0;
	uint32_t saved_block_size = g_block_size;
	uint64_t next_request = 0;
	unsigned int published = 99;

	init_fake_ctx(&ctx, &state);
	memcpy(ctx.src_mac, "\x02\x00\x00\x00\x00\x01", 6);
	memcpy(ctx.dst_mac, "\x02\x00\x00\x00\x00\x02", 6);
	ctx.src_ip = inet_addr("192.0.2.1");
	ctx.dst_ip = inet_addr("192.0.2.2");
	ctx.src_port = 12000;
	ctx.dst_port = 13000;
	ctx.mtu = 1500;
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.xsk.tx = (struct xsk_ring_prod) {
		.cached_prod = 0, .cached_cons = 4, .mask = 3, .size = 4,
		.producer = &tx_producer, .consumer = &tx_consumer,
		.ring = tx_entries,
	};
	g_block_size = 1024;

	for (size_t i = 0; i < 2; i++) {
		struct nxp_wire_segment segment = { 0 };

		pipeline_clear_group(&slots[i]);
		EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, (uint32_t)i + 1,
						 g_block_size, ctx.mtu,
						 FRAME_SIZE,
						 NXP_LAYOUT_DATA_OFFSET,
						 NXP_VECTOR_ALIGNMENT,
						 &slots[i].wire_layout), 0);
		EXPECT_EQ(nxp_wire_segment_at(&slots[i].wire_layout, NXP_IO_READ,
					      0, &segment), 0);
		slots[i].frame_addrs[0] = xsk_alloc_umem_frame(&ctx.xsk);
		EXPECT_TRUE(slots[i].frame_addrs[0] != INVALID_UMEM_FRAME);
		slots[i].frame_addr = slots[i].frame_addrs[0];
		slots[i].segment_count = 1;
		slots[i].block_index = i;
		slots[i].vector[0] = (struct iovec) {
			.iov_base = ctx.xsk.umem_area + slots[i].frame_addr +
				NXP_DATA_OFFSET,
			.iov_len = segment.payload_len,
		};
		memset(slots[i].vector[0].iov_base, (int)(0x40 + i),
		       slots[i].vector[0].iov_len);
		slots[i].request.state = NXP_REQ_COMPLETED;
		nxp_data_begin(&slots[i].data_progress, false);
		EXPECT_EQ(nxp_data_dma_done(&slots[i].data_progress), 0);
		EXPECT_EQ(nxp_data_process(&slots[i].data_progress), 0);
	}
	/* Corrupt only the second group after it is logically ready.  The first
	 * descriptor is already committed and must be reported to the caller so
	 * it can kick/drain that accepted TX prefix. */
	slots[1].vector[0].iov_base =
		(unsigned char *)slots[1].vector[0].iov_base +
		NXP_VECTOR_ALIGNMENT;
	EXPECT_EQ(pipeline_publish_ready_tx_groups(&ctx, slots, 2,
						    &next_request, &flow,
						    &published), -EPROTO);
	EXPECT_EQ(published, 1);
	EXPECT_EQ(next_request, 1);
	EXPECT_EQ(tx_producer, 1);
	EXPECT_EQ(ctx.stats.tx_submitted, 1);
	EXPECT_EQ(slots[0].segment_count, 0);
	EXPECT_EQ(slots[1].segment_count, 1);

	cq_entries[0] = tx_entries[0].addr;
	setup_fake_cq(&ctx, cq_entries, 1, &cq_producer, &cq_consumer);
	xsk_tx_complete(&ctx);
	EXPECT_EQ(ctx.stats.tx_reclaimed, 1);
	EXPECT_EQ(pipeline_abort_group_frames(&ctx, &slots[1]), 0);
	EXPECT_EQ(xdev_ext_pool_free_count(&ctx.xsk.pool), NUM_FRAMES);

	g_block_size = saved_block_size;
	free(ctx.xsk.umem_area);
}

static void test_rx_write_uses_local_group_index_not_wire_addressing(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot = { 0 };
	struct nxp_wire_layout layout = { 0 };
	union {
		max_align_t align;
		unsigned char bytes[128];
	} sq_storage;
	unsigned int sq_head = 0, sq_mask = 0, sq_entries = 1;
	uint32_t generation = 0;
	uint32_t saved_block_size = g_block_size;
	struct nvme_uring_cmd *cmd;

	init_fake_ctx(&ctx, &state);
	ctx.nsid = 9;
	ctx.namespace = (struct nxp_namespace) {
		.nsid = 9, .lba_size = 512, .capacity_lbas = 4096,
		.char_is_namespace = true, .block_is_whole_namespace = true,
		.same_namespace = true, .stable_id_present = true,
		.controller_serial_present = true, .pci_bdf_present = true,
		.char_rdev = 1, .block_rdev = 2, .diskseq = 3,
		.stable_id_len = 1, .controller_serial_len = 1,
		.pci_bdf_len = 1,
	};
	ctx.io_limits.authorized_first_lba = 100;
	ctx.io_limits.authorized_lbas = 64;
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	ctx.uring.fixed_buffer_registered = true;
	ctx.uring.ring.flags = IORING_SETUP_SQE128;
	ctx.uring.ring.sq.khead = &sq_head;
	ctx.uring.ring.sq.kring_mask = &sq_mask;
	ctx.uring.ring.sq.kring_entries = &sq_entries;
	ctx.uring.ring.sq.sqes = (struct io_uring_sqe *)sq_storage.bytes;
	g_block_size = 8192;
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 1, g_block_size, 1500, FRAME_SIZE,
					 NXP_LAYOUT_DATA_OFFSET,
					 NXP_VECTOR_ALIGNMENT, &layout), 0);
	EXPECT_EQ(layout.segment_count, 6);
	EXPECT_EQ(nxp_wire_group_begin(&slot.rx_group, TEST_WIRE_SESSION, layout.generation,
				       NXP_IO_WRITE, g_block_size,
				       layout.segment_count), 0);
	for (uint16_t i = 0; i < layout.segment_count; i++) {
		struct nxp_wire_segment segment = { 0 };

		EXPECT_EQ(nxp_wire_segment_at(&layout, NXP_IO_WRITE, i,
					      &segment), 0);
		EXPECT_EQ(nxp_wire_group_accept(&slot.rx_group, &segment), 0);
		slot.frame_addrs[i] = (uint64_t)i * FRAME_SIZE;
		slot.vector[i] = (struct iovec) {
			.iov_base = ctx.xsk.umem_area + slot.frame_addrs[i] +
				NXP_RX_DATA_OFFSET,
			.iov_len = segment.payload_len,
		};
	}
	slot.segment_count = layout.segment_count;
	EXPECT_EQ(pipeline_prepare_rx_write(&ctx, &slot, 0, 2,
					    &generation), 0);
	cmd = (struct nvme_uring_cmd *)
		((struct io_uring_sqe *)sq_storage.bytes)->cmd;
	EXPECT_EQ(cmd->opcode, NVME_CMD_WRITE);
	EXPECT_EQ(cmd->data_len, 6);
	EXPECT_EQ(cmd->cdw10, 132); /* 100 + local group 2 * sixteen LBAs */
	EXPECT_EQ(cmd->cdw11, 0);
	EXPECT_EQ(cmd->cdw12, 15);
	EXPECT_EQ(cmd->addr, (uintptr_t)slot.vector);
	EXPECT_EQ(nxp_request_release_unaccepted(&slot.request, false), 0);
	g_block_size = saved_block_size;
	free(ctx.xsk.umem_area);
}

static void test_rx_qd2_batches_six_frame_groups_and_reaps_out_of_order(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slots[2] = { 0 };
	struct pipeline_loop_state flow = { 0 };
	struct nxp_wire_layout layouts[2] = { 0 };
	enum nxp_rx_frame_state *frame_states;
	union {
		max_align_t align;
		unsigned char bytes[2 * 128];
	} sq_storage;
	unsigned int sq_head = 0, sq_mask = 1, sq_entries = 2;
	unsigned int accepted = 0;
	uint32_t request_generation = 0;
	uint32_t claimed = UINT32_MAX;
	uint32_t saved_block_size = g_block_size;
	uint64_t tokens[2];
	int order[] = { 0, 1 };

	init_fake_ctx(&ctx, &state);
	ctx.nsid = 9;
	ctx.namespace = (struct nxp_namespace) {
		.nsid = 9, .lba_size = 512, .capacity_lbas = 4096,
		.char_is_namespace = true, .block_is_whole_namespace = true,
		.same_namespace = true, .stable_id_present = true,
		.controller_serial_present = true, .pci_bdf_present = true,
		.char_rdev = 1, .block_rdev = 2, .diskseq = 3,
		.stable_id_len = 1, .controller_serial_len = 1,
		.pci_bdf_len = 1,
	};
	ctx.io_limits.authorized_first_lba = 100;
	ctx.io_limits.authorized_lbas = 32;
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	frame_states = calloc(NUM_FRAMES, sizeof(*frame_states));
	EXPECT_TRUE(frame_states != NULL);
	ctx.uring.fixed_buffer_registered = true;
	ctx.uring.ring.flags = IORING_SETUP_SQE128;
	ctx.uring.ring.sq.khead = &sq_head;
	ctx.uring.ring.sq.kring_mask = &sq_mask;
	ctx.uring.ring.sq.kring_entries = &sq_entries;
	ctx.uring.ring.sq.sqes = (struct io_uring_sqe *)sq_storage.bytes;
	memset(&sq_storage, 0, sizeof(sq_storage));
	g_block_size = 8192;

	for (uint32_t group = 0; group < 2; group++) {
		struct nvme_uring_cmd *cmd;

		EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, group + 1, g_block_size,
						 1500, FRAME_SIZE,
						 NXP_LAYOUT_DATA_OFFSET,
						 NXP_VECTOR_ALIGNMENT,
						 &layouts[group]), 0);
		EXPECT_EQ(layouts[group].segment_count, 6);
		slots[group].rx_group.last_generation = group;
		EXPECT_EQ(nxp_wire_group_begin(&slots[group].rx_group, TEST_WIRE_SESSION,
					       group + 1, NXP_IO_WRITE,
					       g_block_size,
					       layouts[group].segment_count), 0);
		for (uint16_t i = 0; i < layouts[group].segment_count; i++) {
			struct nxp_wire_segment segment = { 0 };
			uint32_t frame = group * layouts[group].segment_count + i;

			EXPECT_EQ(nxp_wire_segment_at(&layouts[group],
						      NXP_IO_WRITE, i, &segment), 0);
			EXPECT_EQ(nxp_wire_group_accept(&slots[group].rx_group,
						       &segment), 0);
			EXPECT_EQ(nxp_rx_frame_to_fill(&frame_states[frame]), 0);
			EXPECT_EQ(nxp_rx_frame_to_received(&frame_states[frame]), 0);
			EXPECT_EQ(nxp_rx_frame_hold_for_io(&frame_states[frame]), 0);
			slots[group].frame_addrs[i] = (uint64_t)frame * FRAME_SIZE;
			slots[group].vector[i] = (struct iovec) {
				.iov_base = ctx.xsk.umem_area +
					slots[group].frame_addrs[i] +
					NXP_RX_DATA_OFFSET,
				.iov_len = segment.payload_len,
			};
		}
		slots[group].segment_count = layouts[group].segment_count;
		slots[group].frame_addr = slots[group].frame_addrs[0];
		EXPECT_EQ(pipeline_prepare_rx_write(&ctx, &slots[group], group,
						    group,
						    &request_generation), 0);
		tokens[group] = slots[group].request.token;
		cmd = (struct nvme_uring_cmd *)(sq_storage.bytes + group * 128 +
						    offsetof(struct io_uring_sqe, cmd));
		EXPECT_EQ(cmd->opcode, NVME_CMD_WRITE);
		EXPECT_EQ(cmd->data_len, 6);
		EXPECT_EQ(cmd->cdw10, 100 + group * 16);
		EXPECT_EQ(cmd->cdw12, 15);
	}

	state.submit_result = 2;
	EXPECT_EQ(submit_prepared_batch(&ctx, slots, order, 2, 0,
						&accepted), 0);
	EXPECT_EQ(accepted, 2);
	EXPECT_EQ(ctx.stats.read_issued, 2);
	EXPECT_EQ(slots[0].request.state, NXP_REQ_ACCEPTED);
	EXPECT_EQ(slots[1].request.state, NXP_REQ_ACCEPTED);

	/* NVMe WRITE CQEs may arrive in either order; the token owns the exact
	 * six-frame group, so reaping group 1 cannot recycle group 0's FQ frames. */
	EXPECT_EQ(pipeline_handle_cqe(&ctx, slots, 2, tokens[1], 0, &flow,
					    &claimed), 0);
	EXPECT_EQ(claimed, 1);
	EXPECT_EQ(pipeline_recycle_rx_group(frame_states, &slots[1]), 0);
	for (uint32_t frame = 0; frame < 6; frame++)
		EXPECT_EQ(frame_states[frame], NXP_RX_FRAME_IO);
	for (uint32_t frame = 6; frame < 12; frame++)
		EXPECT_EQ(frame_states[frame], NXP_RX_FRAME_FREE);

	EXPECT_EQ(pipeline_handle_cqe(&ctx, slots, 2, tokens[0], 0, &flow,
					    &claimed), 0);
	EXPECT_EQ(claimed, 0);
	EXPECT_EQ(pipeline_recycle_rx_group(frame_states, &slots[0]), 0);
	for (uint32_t frame = 0; frame < 12; frame++)
		EXPECT_EQ(frame_states[frame], NXP_RX_FRAME_FREE);
	EXPECT_EQ(ctx.stats.read_ok, 2);
	EXPECT_FALSE(flow.stop_issuing);
	EXPECT_FALSE(flow.cqe_attribution_fault);

	g_block_size = saved_block_size;
	free(frame_states);
	free(ctx.xsk.umem_area);
}

static void test_external_rx_drop_and_partial_group_timeout_are_recoverable(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slots[1] = { 0 };
	enum nxp_rx_frame_state *frame_states;
	uint64_t started_ns = 100;
	int active_slot = 0;

	init_fake_ctx(&ctx, &state);
	frame_states = calloc(NUM_FRAMES, sizeof(*frame_states));
	EXPECT_TRUE(frame_states != NULL);
	EXPECT_EQ(nxp_rx_frame_to_fill(&frame_states[0]), 0);
	EXPECT_EQ(nxp_rx_frame_to_received(&frame_states[0]), 0);
	EXPECT_EQ(pipeline_rx_drop_external(&ctx, frame_states, 0), 0);
	EXPECT_EQ(frame_states[0], NXP_RX_FRAME_FREE);
	EXPECT_EQ(ctx.stats.drops, 1);
	EXPECT_EQ(ctx.first_error, 0);

	pipeline_clear_group(&slots[0]);
	EXPECT_EQ(nxp_wire_group_begin(&slots[0].rx_group, TEST_WIRE_SESSION,
				       1, NXP_IO_WRITE, 4096, 2), 0);
	EXPECT_EQ(nxp_rx_frame_to_fill(&frame_states[1]), 0);
	EXPECT_EQ(nxp_rx_frame_to_received(&frame_states[1]), 0);
	EXPECT_EQ(nxp_rx_frame_hold_for_io(&frame_states[1]), 0);
	slots[0].frame_addr = FRAME_SIZE;
	slots[0].frame_addrs[0] = FRAME_SIZE;
	slots[0].segment_count = 1;
	slots[0].collecting_rx = true;

	EXPECT_EQ(pipeline_rx_expire_group(&ctx, frame_states, slots,
					   &active_slot, &started_ns,
					   100 + NXP_RX_GROUP_TIMEOUT_NS - 1), 0);
	EXPECT_EQ(active_slot, 0);
	EXPECT_EQ(frame_states[1], NXP_RX_FRAME_IO);
	EXPECT_EQ(pipeline_rx_expire_group(&ctx, frame_states, slots,
					   &active_slot, &started_ns,
					   100 + NXP_RX_GROUP_TIMEOUT_NS), 1);
	EXPECT_EQ(active_slot, -1);
	EXPECT_EQ(started_ns, 0);
	EXPECT_EQ(frame_states[1], NXP_RX_FRAME_FREE);
	EXPECT_EQ(slots[0].rx_group.last_generation, 0);
	EXPECT_EQ(ctx.stats.drops, 2);
	EXPECT_EQ(ctx.first_error, 0);
	free(frame_states);
}

static void test_fixed_vector_rejects_unregistered_unaligned_and_outside_umem(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct iovec vector[2];
	void *valid_base;

	init_fake_ctx(&ctx, &state);
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	valid_base = ctx.xsk.umem_area + NXP_DATA_OFFSET;
	vector[0] = (struct iovec) {
		.iov_base = valid_base,
		.iov_len = 1440,
	};
	vector[1] = (struct iovec) {
		.iov_base = ctx.xsk.umem_area + FRAME_SIZE + NXP_DATA_OFFSET,
		.iov_len = 992,
	};

	EXPECT_EQ(pipeline_validate_umem_vector(&ctx, vector, 2, 2432),
		  -EINVAL);
	ctx.uring.fixed_buffer_registered = true;
	EXPECT_EQ(pipeline_validate_umem_vector(&ctx, vector, 2, 2432), 0);

	vector[0].iov_base = (unsigned char *)valid_base + 1;
	EXPECT_EQ(pipeline_validate_umem_vector(&ctx, vector, 2, 2432),
		  -EINVAL);
	vector[0].iov_base = valid_base;
	vector[1].iov_base = ctx.xsk.umem_area + UMEM_SIZE;
	EXPECT_EQ(pipeline_validate_umem_vector(&ctx, vector, 2, 2432),
		  -ERANGE);
	vector[1].iov_base = ctx.xsk.umem_area + FRAME_SIZE + NXP_DATA_OFFSET;
	EXPECT_EQ(pipeline_validate_umem_vector(&ctx, vector, 2, 2433),
		  -EMSGSIZE);
	vector[0].iov_base = ctx.xsk.umem_area + FRAME_SIZE - 8;
	vector[0].iov_len = 16;
	EXPECT_EQ(pipeline_validate_umem_vector(&ctx, vector, 1, 16),
		  -ERANGE);
	vector[0].iov_base = valid_base;
	vector[0].iov_len = 1440;
	vector[1].iov_len = 0;
	EXPECT_EQ(pipeline_validate_umem_vector(&ctx, vector, 2, 1440),
		  -ERANGE);

	free(ctx.xsk.umem_area);
}

static void test_rx_fill_ring_walks_each_free_frame_once_in_order(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	enum nxp_rx_frame_state *states;
	uint64_t entries[4] = { UINT64_MAX, UINT64_MAX,
				UINT64_MAX, UINT64_MAX };
	uint32_t producer = 0, consumer = 0, cursor = 0;

	init_fake_ctx(&ctx, &state);
	states = calloc(NUM_FRAMES, sizeof(*states));
	EXPECT_TRUE(states != NULL);
	ctx.xsk.fq = (struct xsk_ring_prod) {
		.cached_prod = 0, .cached_cons = 4, .mask = 3, .size = 4,
		.producer = &producer, .consumer = &consumer, .ring = entries,
	};
	EXPECT_EQ(pipeline_refill_rx_frames(&ctx, states, &cursor), 4);
	EXPECT_EQ(producer, 4);
	EXPECT_EQ(cursor, 4);
	for (uint32_t i = 0; i < 4; i++) {
		EXPECT_EQ(entries[i], (uint64_t)i * FRAME_SIZE);
		EXPECT_EQ(states[i], NXP_RX_FRAME_FILL);
	}
	free(states);
}

static void test_rx_descriptor_layout_keeps_vector_payload_aligned(void)
{
	struct xdp_desc descriptor = {
		.addr = FRAME_SIZE |
			((uint64_t)(XDP_PACKET_HEADROOM + PKT_START_OFF) <<
			 XSK_UNALIGNED_BUF_OFFSET_SHIFT),
		.len = PKT_HDR_SIZE + NXP_WIRE_HEADER_LEN + 512,
	};
	uint64_t frame_base = UINT64_MAX;
	uint64_t data_addr = UINT64_MAX;

	/* Unaligned-mode RX descriptors keep the frame base in the low bits and
	 * encode the data offset in the high bits. */
	EXPECT_EQ(pipeline_decode_rx_descriptor(&descriptor, &frame_base,
						 &data_addr), 0);
	EXPECT_EQ(frame_base, FRAME_SIZE);
	EXPECT_EQ(data_addr,
		  FRAME_SIZE + XDP_PACKET_HEADROOM + PKT_START_OFF);
	EXPECT_EQ((data_addr + PKT_HDR_SIZE + NXP_WIRE_HEADER_LEN) %
		  NXP_VECTOR_ALIGNMENT, 0);

	/* COPY/aligned mode reports the actual packet address directly. */
	descriptor.addr = FRAME_SIZE + XDP_PACKET_HEADROOM + PKT_START_OFF;
	EXPECT_EQ(pipeline_decode_rx_descriptor(&descriptor, &frame_base,
						 &data_addr), 0);
	EXPECT_EQ(frame_base, FRAME_SIZE);

	/* The old zero-user-headroom layout put payload at frame+330 and must
	 * fail before its address is admitted into NVME_URING_CMD_IO_VEC. */
	descriptor.addr = FRAME_SIZE |
		((uint64_t)XDP_PACKET_HEADROOM <<
		 XSK_UNALIGNED_BUF_OFFSET_SHIFT);
	EXPECT_EQ(pipeline_decode_rx_descriptor(&descriptor, &frame_base,
						 &data_addr), -EINVAL);
	descriptor.addr = (UMEM_SIZE - FRAME_SIZE) |
		((uint64_t)(XDP_PACKET_HEADROOM + PKT_START_OFF) <<
		 XSK_UNALIGNED_BUF_OFFSET_SHIFT);
	descriptor.len = FRAME_SIZE - XDP_PACKET_HEADROOM - PKT_START_OFF + 1;
	EXPECT_EQ(pipeline_decode_rx_descriptor(&descriptor, &frame_base,
						 &data_addr), -EMSGSIZE);
	descriptor.options = 1;
	EXPECT_EQ(pipeline_decode_rx_descriptor(&descriptor, &frame_base,
						 &data_addr), -EOPNOTSUPP);
}

static void test_iopoll_refusal_precedes_ring_init(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	int saved_iopoll = g_iopoll;

	init_fake_ctx(&ctx, &state);
	state.prove_iopoll_result = -EOPNOTSUPP;
	g_iopoll = 1;
	EXPECT_EQ(pipeline_init_ring(&ctx), -EOPNOTSUPP);
	EXPECT_EQ(state.prove_iopoll_calls, 1);
	EXPECT_EQ(state.ring_init_calls, 0);
	EXPECT_FALSE(ctx.uring.initialized);
	g_iopoll = saved_iopoll;
}

static void test_extended_layout_gate_and_correct_stride(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct io_uring_sqe *sqe = NULL;
	struct io_uring_cqe *cqe = NULL;
	unsigned int sq_head = 0, sq_mask = 3, sq_entries = 4;
	unsigned int cq_head = 1, cq_tail = 2, cq_mask = 3;
	union {
		max_align_t align;
		unsigned char bytes[4 * 128];
	} sq_storage;
	union {
		max_align_t align;
		unsigned char bytes[4 * 32];
	} cq_storage;
	int saved_iopoll = g_iopoll;

	/* An old liburing must be rejected before IOPOLL proof or any ring mmap. */
	init_fake_ctx(&ctx, &state);
	state.layout_result = -EOPNOTSUPP;
	g_iopoll = 1;
	EXPECT_EQ(pipeline_init_ring(&ctx), -EOPNOTSUPP);
	EXPECT_EQ(state.layout_calls, 1);
	EXPECT_EQ(state.prove_iopoll_calls, 0);
	EXPECT_EQ(state.ring_init_calls, 0);

	/* The accessors used by production must address doubled SQE/CQE slots. */
	init_fake_ctx(&ctx, &state);
	memset(&sq_storage, 0, sizeof(sq_storage));
	memset(&cq_storage, 0, sizeof(cq_storage));
	ctx.uring.ring.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	ctx.uring.ring.sq.khead = &sq_head;
	ctx.uring.ring.sq.kring_mask = &sq_mask;
	ctx.uring.ring.sq.kring_entries = &sq_entries;
	ctx.uring.ring.sq.sqes = (struct io_uring_sqe *)sq_storage.bytes;
	ctx.uring.ring.sq.sqe_tail = 1;
	EXPECT_EQ(pipeline_get_sqe(&ctx, &sqe), 0);
	EXPECT_EQ((unsigned char *)sqe - sq_storage.bytes, 128);
	EXPECT_EQ(ctx.uring.ring.sq.sqe_tail, 2);

	ctx.uring.ring.cq.khead = &cq_head;
	ctx.uring.ring.cq.ktail = &cq_tail;
	ctx.uring.ring.cq.kring_mask = &cq_mask;
	ctx.uring.ring.cq.cqes = (struct io_uring_cqe *)cq_storage.bytes;
	EXPECT_EQ(pipeline_peek_cqe_raw(&ctx, &cqe), 0);
	EXPECT_EQ((unsigned char *)cqe - cq_storage.bytes, 32);

	ctx.uring.ring.flags = IORING_SETUP_CQE32;
	ctx.uring.ring.sq.sqe_tail = 2;
	EXPECT_EQ(pipeline_get_sqe(&ctx, &sqe), -EOPNOTSUPP);
	EXPECT_EQ(ctx.uring.ring.sq.sqe_tail, 2);
	ctx.uring.ring.flags = IORING_SETUP_SQE128;
	EXPECT_EQ(pipeline_peek_cqe_raw(&ctx, &cqe), -EOPNOTSUPP);
	g_iopoll = saved_iopoll;
}

static void test_init_and_unregister_failures_are_terminal(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;

	init_fake_ctx(&ctx, &state);
	state.ring_init_result = -ENOMEM;
	EXPECT_EQ(pipeline_init_ring(&ctx), -ENOMEM);
	EXPECT_FALSE(ctx.uring.initialized);

	init_fake_ctx(&ctx, &state);
	ctx.uring.initialized = true;
	ctx.uring.fixed_buffer_registered = true;
	state.unregister_buffers_result = -EIO;
	EXPECT_EQ(pipeline_unregister_buffers(&ctx), -EIO);
	EXPECT_EQ(ctx.first_error, -EIO);
	EXPECT_EQ(state.unregister_buffers_calls, 1);
	EXPECT_EQ(state.ring_close_calls, 1);
	EXPECT_FALSE(ctx.uring.initialized);
	EXPECT_FALSE(ctx.uring.fixed_buffer_registered);
	/* A successful close after buffer-unregister failure is not a DMA
	 * quiescence proof: io_uring may still finish deferred teardown. */
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_FALSE(pipeline_can_destroy_xsk(&ctx));

	init_fake_ctx(&ctx, &state);
	ctx.uring.initialized = true;
	ctx.uring.fixed_file_registered = true;
	ctx.first_error = -ENXIO;
	state.unregister_files_result = -EIO;
	EXPECT_EQ(pipeline_unregister_files(&ctx), -EIO);
	EXPECT_EQ(ctx.first_error, -ENXIO);
	EXPECT_EQ(state.unregister_files_calls, 1);
	EXPECT_EQ(state.ring_close_calls, 1);

	init_fake_ctx(&ctx, &state);
	ctx.uring.initialized = true;
	ctx.uring.fixed_file_registered = true;
	state.unregister_files_result = -EIO;
	state.ring_close_result = -EBUSY;
	EXPECT_EQ(pipeline_unregister_files(&ctx), -EIO);
	EXPECT_EQ(ctx.first_error, -EIO);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(ctx.uring.initialized);
	EXPECT_TRUE(ctx.uring.fixed_file_registered);
	EXPECT_EQ(state.unregister_files_calls, 1);
	EXPECT_EQ(state.ring_close_calls, 1);
}

static void test_cleanup_refuses_backing_release_after_close_failure(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;

	init_fake_ctx(&ctx, &state);
	ctx.uring.initialized = true;
	ctx.uring.fixed_buffer_registered = true;
	state.unregister_buffers_result = -EIO;
	state.ring_close_result = -EBUSY;
	EXPECT_EQ(pipeline_prepare_backing_cleanup(&ctx), -EBUSY);
	EXPECT_EQ(ctx.first_error, -EIO);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(ctx.uring.initialized);
	EXPECT_TRUE(ctx.uring.fixed_buffer_registered);
	EXPECT_EQ(state.unregister_buffers_calls, 1);
	/* unregister's failed close plus the final cleanup retry */
	EXPECT_EQ(state.ring_close_calls, 2);

	/* Once teardown has failed, a later close cannot retroactively prove that
	 * device DMA was quiescent throughout the failed interval. */
	state.ring_close_result = 0;
	EXPECT_EQ(pipeline_prepare_backing_cleanup(&ctx), -EIO);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_FALSE(ctx.ring_close_failed);
	EXPECT_FALSE(ctx.uring.initialized);
	EXPECT_EQ(state.unregister_buffers_calls, 2);
	EXPECT_EQ(state.ring_close_calls, 3);
}

static void test_chain_sequester_latch_survives_successful_ring_close(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;

	init_fake_ctx(&ctx, &state);
	ctx.uring.initialized = true;
	ctx.chain_sequestered = true;
	ctx.backing_quiescence_failed = true;
	state.ring_close_result = 0;

	EXPECT_EQ(pipeline_close_ring(&ctx), 0);
	EXPECT_FALSE(ctx.uring.initialized);
	EXPECT_FALSE(ctx.ring_close_failed);
	EXPECT_TRUE(ctx.chain_sequestered);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_FALSE(pipeline_can_destroy_xsk(&ctx));
}

static void prepare_accepted_slot(struct pipeline_ctx *ctx,
				  struct inflight_slot *slot,
				  uint32_t *generation)
{
	uint64_t addr = xsk_alloc_umem_frame(&ctx->xsk);

	memset(slot, 0, sizeof(*slot));
	slot->frame_addr = addr;
	slot->frame_addrs[0] = addr;
	slot->segment_count = 1;
	EXPECT_TRUE(addr != INVALID_UMEM_FRAME);
	EXPECT_EQ(nxp_request_prepare(&slot->request, 0, generation), 0);
	EXPECT_EQ(nxp_request_publish(&slot->request), 0);
	EXPECT_EQ(nxp_request_accept(&slot->request), 0);
}

static void test_stale_then_exact_and_lost_attribution_teardown(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot;
	uint32_t generation = 0;
	uint32_t claimed = UINT32_MAX;
	uint64_t exact;
	uint64_t frame_addr;

	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	exact = slot.request.token;
	EXPECT_EQ(pipeline_claim_cqe(&ctx, &slot, 1,
				     exact + (UINT64_C(1) << 32), &claimed),
		  -EPROTO);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(state.ring_close_calls, 0);
	EXPECT_EQ(pipeline_claim_cqe(&ctx, &slot, 1, exact, &claimed), 0);
	EXPECT_EQ(claimed, 0);
	EXPECT_FALSE(slot.request.owns_backing);
	EXPECT_EQ(state.ring_close_calls, 0);
	EXPECT_EQ(pipeline_abort_group_frames(&ctx, &slot), 0);

	ctx.first_error = 0;
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	exact = slot.request.token;
	frame_addr = slot.frame_addr;
	EXPECT_EQ(pipeline_claim_cqe(&ctx, &slot, 1, exact + 1, &claimed),
		  -EPROTO);
	EXPECT_TRUE(slot.request.owns_backing);
	/* Closing an io_uring fd is asynchronous in this kernel.  A successful
	 * close is not proof that an unattributed NVMe command stopped DMA. */
	EXPECT_EQ(pipeline_retain_unmatched_requests(&ctx, &slot, 1), -EPROTO);
	EXPECT_EQ(state.ring_close_calls, 1);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool,
				  frame_addr / FRAME_SIZE), XDEV_EXT_FRAME_IO_PENDING);
}

static void test_failed_quiescence_never_releases_dma_backing(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot;
	uint32_t generation = 0;
	uint64_t frame_addr;

	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	frame_addr = slot.frame_addr;
	state.ring_close_result = -EBUSY;
	EXPECT_EQ(pipeline_retain_unmatched_requests(&ctx, &slot, 1), -EBUSY);
	EXPECT_EQ(ctx.first_error, -EBUSY);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(ctx.uring.initialized);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(slot.request.state, NXP_REQ_ACCEPTED);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, frame_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_IO_PENDING);

	state.ring_close_result = 0;
	EXPECT_EQ(pipeline_retain_unmatched_requests(&ctx, &slot, 1), -EBUSY);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, frame_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_IO_PENDING);
}

static void test_successful_async_close_is_not_a_dma_proof(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot;
	uint32_t generation = 0;
	uint64_t frame_addr;

	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	frame_addr = slot.frame_addr;
	state.ring_close_result = 0;
	EXPECT_EQ(pipeline_retain_unmatched_requests(&ctx, &slot, 1), -EPROTO);
	EXPECT_EQ(state.ring_close_calls, 1);
	EXPECT_FALSE(ctx.uring.initialized);
	EXPECT_TRUE(ctx.unmatched_io_retained);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(slot.request.state, NXP_REQ_ACCEPTED);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, frame_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_IO_PENDING);
}

static void test_wait_errors_are_bounded(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct io_uring_cqe *cqe = NULL;
	int saved_iopoll = g_iopoll;

	init_fake_ctx(&ctx, &state);
	g_iopoll = 0;
	state.wait_result = -EINTR;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
	EXPECT_EQ(pipeline_wait_bounded(&ctx, &cqe), -ETIMEDOUT);
	EXPECT_EQ(state.wait_calls, 4);
	EXPECT_EQ(ctx.stats.wait_errors, 1);

	/* A normal non-IOPOLL wait may see transient emptiness and still complete
	 * before the shared absolute deadline. */
	init_fake_ctx(&ctx, &state);
	state.wait_results[0] = -EAGAIN;
	state.wait_results[1] = -EAGAIN;
	state.wait_results[2] = 0;
	state.wait_results_nr = 3;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 10;
	EXPECT_EQ(pipeline_wait_bounded(&ctx, &cqe), 0);
	EXPECT_EQ(state.wait_calls, 3);
	EXPECT_TRUE(state.last_wait_timeout_ns <= NXP_WAIT_TIMEOUT_NS);
	EXPECT_EQ(ctx.stats.wait_errors, 0);
	g_iopoll = saved_iopoll;
}

/* An AF_XDP RX ring of four entries over caller storage, for the rx-write
 * completion wait's RX check. */
static void init_fake_rx_ring(struct pipeline_ctx *ctx,
			      struct xdp_desc *entries, uint32_t *producer,
			      uint32_t *consumer, uint32_t *flags)
{
	ctx->xsk.rx = (struct xsk_ring_cons) {
		.mask = 3, .size = 4, .producer = producer,
		.consumer = consumer, .ring = entries, .flags = flags,
	};
}

/* The rx-write completion wait returns at once for an RX descriptor the loop
 * can take, but the deadline it arms on its first call is kept across those
 * wakeups: with the CQE still missing, the wait fails at the deadline even
 * though RX keeps arriving. */
static void test_rx_wait_deadline_survives_rx_wakeups(void)
{
	struct fake_adapter_state state;
	struct pipeline_ctx ctx;
	struct xdp_desc entries[4] = { 0 };
	uint32_t producer = 1, consumer = 0, flags = 0;
	uint64_t deadline = 0;
	int saved_iopoll = g_iopoll;
	int rx_error = 0;

	init_fake_ctx(&ctx, &state);
	init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
	g_iopoll = 0;
	state.monotonic_ns = 1000;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
	state.event_wait_result = -ETIME;
	state.peek_result = -EAGAIN;
	for (int i = 0; i < 4; i++) {
		EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true,
						   &rx_error), 0);
		EXPECT_EQ(deadline, 1000 + NXP_WAIT_TIMEOUT_NS);
	}
	EXPECT_EQ(state.event_wait_calls, 0);
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, &rx_error),
		  -ETIMEDOUT);
	EXPECT_EQ(ctx.stats.wait_errors, 1);
	EXPECT_EQ(rx_error, 0);

	/* A caller that reaped a CQE re-arms it by clearing the deadline. */
	deadline = 0;
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, &rx_error),
		  0);
	EXPECT_EQ(deadline, 1000 + 5 * (NXP_WAIT_TIMEOUT_NS / 4) +
		  NXP_WAIT_TIMEOUT_NS);
	g_iopoll = saved_iopoll;
}

/* Without RX, the wait polls the CQ notification and the XSK fd together and
 * returns once a CQE is visible; without either it times out like
 * pipeline_wait_bounded(), and a hard poll failure is a wait failure. */
static void test_rx_wait_returns_on_a_cqe_and_fails_like_the_cq_wait(void)
{
	struct fake_adapter_state state;
	struct pipeline_ctx ctx;
	struct xdp_desc entries[4] = { 0 };
	uint32_t producer = 0, consumer = 0, flags = 0;
	uint64_t deadline = 0;
	int saved_iopoll = g_iopoll;
	int rx_error = 0;

	init_fake_ctx(&ctx, &state);
	init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
	g_iopoll = 0;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 10;
	state.event_wait_result = 0;
	state.peek_result = 0;
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, &rx_error),
		  0);
	EXPECT_EQ(state.event_wait_calls, 1);
	EXPECT_EQ(state.peek_calls, 1);
	EXPECT_EQ(state.last_wait_timeout_ns, NXP_WAIT_TIMEOUT_NS);
	EXPECT_EQ(state.wait_calls, 0);

	/* A stale notification (no CQE behind it) waits again. */
	init_fake_ctx(&ctx, &state);
	init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
	deadline = 0;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
	state.event_wait_result = 0;
	state.peek_result = -EAGAIN;
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, &rx_error),
		  -ETIMEDOUT);
	EXPECT_EQ(state.event_wait_calls, 4);
	EXPECT_EQ(ctx.stats.wait_errors, 1);

	init_fake_ctx(&ctx, &state);
	init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
	deadline = 0;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
	state.event_wait_result = -EINTR;
	state.peek_result = -EAGAIN; /* interrupted, and no CQE in the ring */
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, &rx_error),
		  -ETIMEDOUT);
	EXPECT_EQ(state.event_wait_calls, 4);

	init_fake_ctx(&ctx, &state);
	init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
	deadline = 0;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
	state.event_wait_result = -EBADF;
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, &rx_error),
		  -EBADF);
	EXPECT_EQ(state.event_wait_calls, 1);
	EXPECT_EQ(ctx.stats.wait_errors, 1);
	EXPECT_EQ(rx_error, 0);
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, NULL, true, &rx_error),
		  -EINVAL);
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, NULL),
		  -EINVAL);
	g_iopoll = saved_iopoll;
}

/* The CQ eventfd only wakes the wait; a CQE in the ring is what ends it.  A
 * CQE that is visible when the poll times out or is interrupted still ends
 * the wait, as io_uring_wait_cqe_timeout() would find it, instead of turning
 * into a completion-wait failure at the deadline. */
static void test_rx_wait_finds_a_cqe_without_a_notification(void)
{
	static const int results[] = { -ETIME, -EINTR };
	struct fake_adapter_state state;
	struct pipeline_ctx ctx;
	struct xdp_desc entries[4] = { 0 };
	uint32_t producer = 0, consumer = 0, flags = 0;
	int saved_iopoll = g_iopoll;

	g_iopoll = 0;
	for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); i++) {
		uint64_t deadline = 0;
		int rx_error = 0;

		init_fake_ctx(&ctx, &state);
		init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
		state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
		state.event_wait_result = results[i];
		state.peek_result = 0;
		EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true,
						   &rx_error), 0);
		EXPECT_EQ(state.event_wait_calls, 1);
		EXPECT_EQ(ctx.stats.wait_errors, 0);
	}

	/* A hard CQ failure found by that peek is a wait failure. */
	{
		uint64_t deadline = 0;
		int rx_error = 0;

		init_fake_ctx(&ctx, &state);
		init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
		state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
		state.event_wait_result = -ETIME;
		state.peek_result = -EOVERFLOW;
		EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true,
						   &rx_error), -EOVERFLOW);
		EXPECT_EQ(ctx.stats.wait_errors, 1);
	}
	g_iopoll = saved_iopoll;
}

/* An XSK socket error seen during the wait is handed back in *rx_error and
 * is not a completion-wait failure: the caller stops issuing and keeps
 * draining its WRITEs. */
static void test_rx_wait_reports_an_xsk_error_apart(void)
{
	static const short errors[] = { POLLERR, POLLHUP, POLLNVAL };
	static const int expected[] = { -EIO, -EPIPE, -EBADF };
	struct fake_adapter_state state;
	struct pipeline_ctx ctx;
	struct xdp_desc entries[4] = { 0 };
	uint32_t producer = 0, consumer = 0, flags = 0;
	int saved_iopoll = g_iopoll;

	g_iopoll = 0;
	for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
		uint64_t deadline = 0;
		int rx_error = 0;

		init_fake_ctx(&ctx, &state);
		init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
		state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
		state.event_wait_result = 0;
		state.event_rx_revents = errors[i];
		state.peek_result = -EAGAIN;
		EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true,
						   &rx_error), 0);
		EXPECT_EQ(rx_error, expected[i]);
		EXPECT_EQ(ctx.stats.wait_errors, 0);
	}
	g_iopoll = saved_iopoll;
}

/* When the loop cannot take a packet (depth reached, all groups issued, or
 * stopping), the wait is the CQ-only wait, and RX does not wake it. */
static void test_rx_wait_without_watch_is_the_cq_only_wait(void)
{
	struct fake_adapter_state state;
	struct pipeline_ctx ctx;
	struct xdp_desc entries[4] = { 0 };
	uint32_t producer = 1, consumer = 0, flags = 0;
	uint64_t deadline = 0;
	int saved_iopoll = g_iopoll;
	int rx_error = 0;

	init_fake_ctx(&ctx, &state);
	init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
	g_iopoll = 0;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 10;
	state.wait_results[0] = -ETIME;
	state.wait_results[1] = 0;
	state.wait_results_nr = 2;
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, false, &rx_error),
		  0);
	EXPECT_EQ(state.wait_calls, 2);
	EXPECT_EQ(state.event_wait_calls, 0);
	EXPECT_TRUE(state.last_wait_timeout_ns < NXP_WAIT_TIMEOUT_NS);
	g_iopoll = saved_iopoll;
}

/* IOPOLL reaps by polling, so the wait checks the RX ring between bounded
 * completion steps instead of sleeping on an eventfd. */
static void test_rx_wait_iopoll_checks_rx_between_steps(void)
{
	struct fake_adapter_state state;
	struct pipeline_ctx ctx;
	struct xdp_desc entries[4] = { 0 };
	uint32_t producer = 0, consumer = 0, flags = 0;
	uint64_t deadline = 0;
	int saved_iopoll = g_iopoll;
	int rx_error = 0;

	init_fake_ctx(&ctx, &state);
	init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
	g_iopoll = 1;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
	state.peek_result = -EAGAIN;
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, &rx_error),
		  -ETIMEDOUT);
	EXPECT_EQ(state.progress_iopoll_calls, 4);
	EXPECT_EQ(state.event_wait_calls, 0);
	EXPECT_EQ(state.wait_calls, 0);

	init_fake_ctx(&ctx, &state);
	init_fake_rx_ring(&ctx, entries, &producer, &consumer, &flags);
	deadline = 0;
	producer = 1;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 4;
	state.peek_result = -EAGAIN;
	EXPECT_EQ(pipeline_rx_wait_bounded(&ctx, &deadline, true, &rx_error),
		  0);
	EXPECT_EQ(state.progress_iopoll_calls, 0);
	g_iopoll = saved_iopoll;
}

static uint64_t test_elapsed_ns(const struct timespec *t0,
				const struct timespec *t1)
{
	return (uint64_t)(t1->tv_sec - t0->tv_sec) * UINT64_C(1000000000) +
	       (uint64_t)t1->tv_nsec - (uint64_t)t0->tv_nsec;
}

/* The production wait on the CQ notification and the XSK fd, on real
 * descriptors of this host: an eventfd opened as pipeline_open_cq_eventfd()
 * opens it stands for the ring's CQ eventfd, and a pipe's read end for the
 * XSK fd.  A timeout below one millisecond is rounded up, not down to a poll
 * that returns at once; a CQE notification ends the wait with no RX revents
 * and is drained; the XSK fd's own revents, readiness or hangup, are handed
 * back; an unregistered or closed eventfd is -EBADF. */
static void test_production_wait_cqe_or_rx_on_an_eventfd_and_a_pipe(void)
{
	struct pipeline_ctx ctx;
	struct timespec t0, t1;
	uint64_t one = 1, count = 0;
	short rx = -1;
	ssize_t got;
	int p[2] = { -1, -1 };
	int efd, err;
	char c = 0;

	memset(&ctx, 0, sizeof(ctx));
	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	EXPECT_TRUE(efd >= 0);
	EXPECT_EQ(pipe(p), 0);
	if (efd < 0 || p[0] < 0) {
		if (efd >= 0)
			close(efd);
		return;
	}
	ctx.uring.cq_eventfd = efd;
	ctx.uring.cq_eventfd_registered = true;
	ctx.xsk.xsk_fd = p[0];

	/* Nothing ready: -ETIME, and not before the requested 500 us. */
	EXPECT_EQ(clock_gettime(CLOCK_MONOTONIC, &t0), 0);
	EXPECT_EQ(production_wait_cqe_or_rx(&ctx, UINT64_C(500000), &rx),
		  -ETIME);
	EXPECT_EQ(clock_gettime(CLOCK_MONOTONIC, &t1), 0);
	EXPECT_TRUE(test_elapsed_ns(&t0, &t1) >= UINT64_C(500000));
	EXPECT_EQ(rx, 0);

	/* A CQE notification: 0 with no RX revents, and the eventfd is left
	 * drained. */
	rx = -1;
	EXPECT_EQ(write(efd, &one, sizeof(one)), (ssize_t)sizeof(one));
	EXPECT_EQ(production_wait_cqe_or_rx(&ctx, UINT64_C(5000000), &rx), 0);
	EXPECT_EQ(rx, 0);
	got = read(efd, &count, sizeof(count));
	err = errno;
	EXPECT_EQ(got, -1);
	EXPECT_EQ(err, EAGAIN);

	/* RX readiness on the XSK fd: 0 with its POLLIN. */
	rx = 0;
	EXPECT_EQ(write(p[1], "x", 1), 1);
	EXPECT_EQ(production_wait_cqe_or_rx(&ctx, UINT64_C(5000000), &rx), 0);
	EXPECT_TRUE(rx & POLLIN);
	EXPECT_EQ(read(p[0], &c, 1), 1);

	/* The XSK fd's hangup is handed back for the caller to fail on. */
	rx = 0;
	close(p[1]);
	p[1] = -1;
	EXPECT_EQ(production_wait_cqe_or_rx(&ctx, UINT64_C(5000000), &rx), 0);
	EXPECT_TRUE(rx & POLLHUP);

	/* No registered eventfd, or a closed one: -EBADF. */
	ctx.uring.cq_eventfd_registered = false;
	EXPECT_EQ(production_wait_cqe_or_rx(&ctx, UINT64_C(1000000), &rx),
		  -EBADF);
	ctx.uring.cq_eventfd_registered = true;
	close(efd);
	EXPECT_EQ(production_wait_cqe_or_rx(&ctx, UINT64_C(1000000), &rx),
		  -EBADF);
	close(p[0]);
}

static void test_iopoll_step_and_monotonic_deadline_retain_backing(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot;
	struct pipeline_loop_state flow = { 0 };
	struct io_uring_cqe *cqe = NULL;
	uint32_t generation = 0;
	uint64_t frame_addr;
	int saved_iopoll = g_iopoll;
	int ret;

	/* An already-visible CQE never enters the kernel. */
	init_fake_ctx(&ctx, &state);
	state.peek_result = 0;
	g_iopoll = 1;
	EXPECT_EQ(pipeline_cqe_step(&ctx, &cqe), 0);
	EXPECT_EQ(state.peek_calls, 1);
	EXPECT_EQ(state.progress_iopoll_calls, 0);
	EXPECT_TRUE(cqe != NULL);

	/* One nonblocking progress call may make a CQE visible. */
	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.change_peek_after_progress = true;
	state.peek_result_after_progress = 0;
	EXPECT_EQ(pipeline_cqe_step(&ctx, &cqe), 0);
	EXPECT_EQ(state.peek_calls, 2);
	EXPECT_EQ(state.progress_iopoll_calls, 1);

	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.change_peek_after_progress = true;
	state.change_peek_after_progress_call = 3;
	state.peek_result_after_progress = 0;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 10;
	EXPECT_EQ(pipeline_wait_bounded(&ctx, &cqe), 0);
	EXPECT_EQ(state.progress_iopoll_calls, 3);
	EXPECT_EQ(ctx.stats.wait_errors, 0);

	/* A CQE made visible alongside EINTR wins over the progress errno. */
	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.progress_iopoll_result = -EINTR;
	state.change_peek_after_progress = true;
	state.peek_result_after_progress = 0;
	EXPECT_EQ(pipeline_cqe_step(&ctx, &cqe), 0);
	EXPECT_EQ(state.peek_calls, 2);
	EXPECT_EQ(state.progress_iopoll_calls, 1);

	/* With no CQE, a hard progress error is returned after the final peek. */
	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.progress_iopoll_result = -EIO;
	EXPECT_EQ(pipeline_cqe_step(&ctx, &cqe), -EIO);
	EXPECT_EQ(state.peek_calls, 2);
	EXPECT_EQ(state.progress_iopoll_calls, 1);

	/* A hard ring error is the first error even if a later clock read would
	 * fail or report that the deadline has elapsed. */
	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.progress_iopoll_result = -EIO;
	state.monotonic_result = -EFAULT;
	state.monotonic_fail_after_call = 2;
	EXPECT_EQ(pipeline_wait_bounded(&ctx, &cqe), -EIO);
	EXPECT_EQ(state.monotonic_calls, 1);
	EXPECT_EQ(ctx.stats.wait_errors, 1);
	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.progress_iopoll_result = -EBADR;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS;
	EXPECT_EQ(pipeline_wait_bounded(&ctx, &cqe), -EBADR);
	EXPECT_EQ(state.monotonic_calls, 1);
	EXPECT_EQ(ctx.stats.wait_errors, 1);

	/* EINTR, EAGAIN, and EBUSY share one absolute userspace deadline; none
	 * resets it and normal empty probes do not inflate wait-error stats. */
	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.progress_results[0] = -EINTR;
	state.progress_results[1] = -EAGAIN;
	state.progress_results[2] = -EBUSY;
	state.progress_results_nr = 3;
	state.progress_iopoll_result = -EAGAIN;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS / 3;
	ret = pipeline_wait_bounded(&ctx, &cqe);
	EXPECT_EQ(ret, -ETIMEDOUT);
	EXPECT_EQ(state.progress_iopoll_calls, 4);
	EXPECT_EQ(state.peek_calls, state.progress_iopoll_calls * 2);
	EXPECT_EQ(ctx.stats.wait_errors, 1);

	/* A clock failure is terminal before any potentially repeated progress. */
	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.monotonic_result = -EIO;
	EXPECT_EQ(pipeline_wait_bounded(&ctx, &cqe), -EIO);
	EXPECT_EQ(state.peek_calls, 0);
	EXPECT_EQ(ctx.stats.wait_errors, 1);

	init_fake_ctx(&ctx, &state);
	state.peek_result = -EAGAIN;
	state.progress_iopoll_result = -EAGAIN;
	state.monotonic_step_ns = NXP_WAIT_TIMEOUT_NS;
	ret = pipeline_wait_bounded(&ctx, &cqe);
	EXPECT_EQ(ret, -ETIMEDOUT);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	frame_addr = slot.frame_addr;
	EXPECT_EQ(pipeline_handle_wait_failure(&ctx, &slot, 1, ret, &flow),
		  -ETIMEDOUT);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, frame_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_IO_PENDING);
	g_iopoll = saved_iopoll;
}

static void test_production_fault_steps_drive_retention_and_stop(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot;
	struct pipeline_loop_state flow = { 0 };
	uint32_t generation = 0;
	uint32_t claimed = UINT32_MAX;
	uint64_t exact;
	uint64_t frame_addr;

	/* A unique wrong token follows the same handler used by the production
	 * loop: publication stops, close is attempted, and close success still
	 * cannot authorize reuse of unattributed DMA backing. */
	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	frame_addr = slot.frame_addr;
	exact = slot.request.token;
	EXPECT_EQ(pipeline_handle_cqe(&ctx, &slot, 1, exact + 1, 0,
				      &flow, &claimed), -EPROTO);
	EXPECT_TRUE(flow.stop_issuing);
	EXPECT_TRUE(flow.cqe_attribution_fault);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(state.ring_close_calls, 0);
	EXPECT_EQ(pipeline_finish_nvme_fault(&ctx, &slot, 1, &flow),
		  -EPROTO);
	EXPECT_EQ(state.ring_close_calls, 1);
	EXPECT_FALSE(ctx.uring.initialized);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, frame_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_IO_PENDING);
	EXPECT_EQ(ctx.first_error, -EPROTO);

	/* An extra stale CQE latches the first error, but an exact terminal CQE
	 * can still establish ownership and avoids the retention path. */
	init_fake_ctx(&ctx, &state);
	memset(&flow, 0, sizeof(flow));
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	exact = slot.request.token;
	EXPECT_EQ(pipeline_handle_cqe(&ctx, &slot, 1,
				      exact + (UINT64_C(1) << 32), 0,
				      &flow, &claimed), -EPROTO);
	EXPECT_EQ(pipeline_handle_cqe(&ctx, &slot, 1, exact, 0,
				      &flow, &claimed), 0);
	EXPECT_EQ(claimed, 0);
	EXPECT_FALSE(slot.request.owns_backing);
	EXPECT_EQ(pipeline_finish_nvme_fault(&ctx, &slot, 1, &flow), 0);
	EXPECT_EQ(state.ring_close_calls, 0);
	EXPECT_FALSE(ctx.backing_quiescence_failed);
	EXPECT_EQ(pipeline_abort_group_frames(&ctx, &slot), 0);

	/* A terminal wait failure closes the ring but retains the accepted frame. */
	init_fake_ctx(&ctx, &state);
	memset(&flow, 0, sizeof(flow));
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	frame_addr = slot.frame_addr;
	EXPECT_EQ(pipeline_handle_wait_failure(&ctx, &slot, 1, -ETIMEDOUT,
					       &flow), -ETIMEDOUT);
	EXPECT_TRUE(flow.stop_issuing);
	EXPECT_TRUE(flow.cqe_attribution_fault);
	EXPECT_EQ(state.ring_close_calls, 1);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, frame_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_IO_PENDING);

	init_fake_ctx(&ctx, &state);
	memset(&flow, 0, sizeof(flow));
	EXPECT_FALSE(pipeline_handle_kick_result(&ctx, -EAGAIN, &flow));
	EXPECT_FALSE(flow.stop_issuing);
	EXPECT_TRUE(pipeline_handle_kick_result(&ctx, -EIO, &flow));
	EXPECT_TRUE(flow.stop_issuing);
	EXPECT_EQ(ctx.first_error, -EIO);
	EXPECT_EQ(ctx.stats.kick_errors, 1);
	pipeline_handle_drop(&ctx, -ENOBUFS, &flow);
	EXPECT_EQ(ctx.first_error, -EIO);
	EXPECT_EQ(ctx.stats.drops, 1);

	/* The production drain's probe-result handler must not discard a hard
	 * IOPOLL/ring errno before the bounded-wait path. */
	init_fake_ctx(&ctx, &state);
	memset(&flow, 0, sizeof(flow));
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	ctx.uring.initialized = true;
	prepare_accepted_slot(&ctx, &slot, &generation);
	frame_addr = slot.frame_addr;
	EXPECT_TRUE(pipeline_handle_cqe_probe_result(&ctx, &slot, 1, -EIO,
					     &flow));
	EXPECT_EQ(ctx.first_error, -EIO);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slot.request.owns_backing);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, frame_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_IO_PENDING);
}

static void prepare_accepted_slot_at(struct pipeline_ctx *ctx,
				     struct inflight_slot *slot,
				     uint32_t slot_index,
				     uint32_t *generation)
{
	uint64_t addr = xsk_alloc_umem_frame(&ctx->xsk);

	memset(slot, 0, sizeof(*slot));
	slot->frame_addr = addr;
	EXPECT_TRUE(addr != INVALID_UMEM_FRAME);
	EXPECT_EQ(nxp_request_prepare(&slot->request, slot_index, generation), 0);
	EXPECT_EQ(nxp_request_publish(&slot->request), 0);
	EXPECT_EQ(nxp_request_accept(&slot->request), 0);
}

static void test_fatal_cqe_drains_later_exact_without_tx_publish(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slots[2];
	struct pipeline_loop_state flow = { 0 };
	uint32_t generation = 0;
	uint32_t claimed = UINT32_MAX;
	uint64_t second_addr;

	/* A native NVMe failure stops publication.  The following exact success
	 * still drains request ownership, then aborts its IO_PENDING frame. */
	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	prepare_accepted_slot_at(&ctx, &slots[0], 0, &generation);
	prepare_accepted_slot_at(&ctx, &slots[1], 1, &generation);
	second_addr = slots[1].frame_addr;
	EXPECT_EQ(pipeline_handle_cqe(&ctx, slots, 2, slots[0].request.token,
				      -EIO, &flow, &claimed), -EIO);
	EXPECT_TRUE(flow.stop_issuing);
	EXPECT_EQ(pipeline_handle_cqe(&ctx, slots, 2, slots[1].request.token,
				      0, &flow, &claimed), 0);
	EXPECT_EQ(claimed, 1);
	EXPECT_FALSE(slots[1].request.owns_backing);
	EXPECT_TRUE(pipeline_discard_completed_after_fatal(&ctx, &slots[1],
						   &flow));
	EXPECT_EQ(slots[1].frame_addr, INVALID_UMEM_FRAME);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, second_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(slots[1].data_progress.stage, NXP_DATA_EMPTY);
	EXPECT_EQ(ctx.stats.tx_submitted, 0);

	/* An unattributed token also stops publication, while a later exact token
	 * remains usable solely to drain the accepted command. */
	init_fake_ctx(&ctx, &state);
	memset(&flow, 0, sizeof(flow));
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	prepare_accepted_slot_at(&ctx, &slots[0], 0, &generation);
	second_addr = slots[0].frame_addr;
	EXPECT_EQ(pipeline_handle_cqe(&ctx, slots, 1,
				      slots[0].request.token +
				      (UINT64_C(1) << 32), 0,
				      &flow, &claimed), -EPROTO);
	EXPECT_EQ(pipeline_handle_cqe(&ctx, slots, 1, slots[0].request.token,
				      0, &flow, &claimed), 0);
	EXPECT_FALSE(slots[0].request.owns_backing);
	EXPECT_TRUE(pipeline_discard_completed_after_fatal(&ctx, &slots[0],
						   &flow));
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, second_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_FREE);
	EXPECT_EQ(slots[0].data_progress.stage, NXP_DATA_EMPTY);
	EXPECT_EQ(ctx.stats.tx_submitted, 0);
}

static void init_submit_case(struct pipeline_ctx *ctx,
			     struct fake_adapter_state *state,
			     struct inflight_slot *slots, size_t nr,
			     uint32_t *generation, uint32_t *kernel_head)
{
	init_fake_ctx(ctx, state);
	ctx->uring.initialized = true;
	ctx->uring.ring.sq.khead = kernel_head;
	for (size_t i = 0; i < nr; i++) {
		memset(&slots[i], 0, sizeof(slots[i]));
		slots[i].frame_addr = INVALID_UMEM_FRAME;
		EXPECT_EQ(nxp_request_prepare(&slots[i].request, (uint32_t)i,
					      generation), 0);
	}
}

/* Submit @batches one-command batches on one ctx; return the revalidations. */
static unsigned int revalidations_over_batches(uint32_t every,
					       unsigned int batches)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slot;
	uint32_t generation = 0;
	uint32_t kernel_head = 10;
	uint32_t saved = g_revalidate_every;
	unsigned int accepted;
	int order[] = { 0 };

	g_revalidate_every = every;
	init_submit_case(&ctx, &state, &slot, 1, &generation, &kernel_head);
	state.submit_result = 1;
	for (unsigned int i = 0; i < batches; i++) {
		if (i)
			EXPECT_EQ(nxp_request_prepare(&slot.request, 0,
						      &generation), 0);
		accepted = 0;
		EXPECT_EQ(submit_prepared_batch(&ctx, &slot, order, 1, 0,
						&accepted), 0);
		EXPECT_EQ(accepted, 1);
		EXPECT_EQ(nxp_request_complete(&slot.request,
					       slot.request.token), 0);
	}
	EXPECT_EQ(state.submit_calls, batches);
	g_revalidate_every = saved;
	return state.revalidate_calls;
}

/*
 * --revalidate-every is the U' measurement arm.  The default re-proves the
 * namespace before every batch, as before; N re-proves before batches 0, N,
 * 2N, ...; 0 never calls revalidation on the submit path.
 */
static void test_revalidate_every_thins_submit_revalidation(void)
{
	EXPECT_EQ(g_revalidate_every, 1);
	EXPECT_EQ(revalidations_over_batches(1, 7), 7);
	EXPECT_EQ(revalidations_over_batches(0, 7), 0);
	EXPECT_EQ(revalidations_over_batches(3, 7), 3);
	EXPECT_EQ(revalidations_over_batches(8, 7), 1);
	EXPECT_EQ(g_revalidate_every, 1);
}

static int run_program_main(int argc, char **argv)
{
	optind = 0;	/* glibc: reinitialise getopt for a new argv */
	return nvme_xdp_pipeline_program_main(argc, argv);
}

/* Each run stops at the missing -e session, after option parsing. */
static void test_revalidate_every_option(void)
{
	char prog[] = "nvme_xdp_pipeline";
	char opt[] = "--revalidate-every";
	char zero[] = "0", five[] = "5", word[] = "x", negative[] = "-1";
	char too_big[] = "4294967296", empty[] = "";
	char *argv[] = { prog, opt, NULL, NULL };
	char *invalid[] = { word, negative, too_big, empty };

	argv[2] = zero;
	EXPECT_EQ(run_program_main(3, argv), 1);
	EXPECT_EQ(g_revalidate_every, 0);
	argv[2] = five;
	EXPECT_EQ(run_program_main(3, argv), 1);
	EXPECT_EQ(g_revalidate_every, 5);
	g_revalidate_every = 1;
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		argv[2] = invalid[i];
		EXPECT_EQ(run_program_main(3, argv), 1);
		EXPECT_EQ(g_revalidate_every, 1);
	}
}

static void test_submit_adapter_full_short_fatal_and_bounded_retry(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	struct inflight_slot slots[3];
	uint32_t generation = 0;
	uint32_t kernel_head = 10;
	unsigned int accepted;
	int order[] = { 0, 1, 2 };
	int ret;

	/* A positive full result proves kernel acceptance even before SQ head
	 * observation advances. */
	init_submit_case(&ctx, &state, slots, 1, &generation, &kernel_head);
	state.submit_result = 1;
	accepted = 0;
	EXPECT_EQ(submit_prepared_batch(&ctx, slots, order, 1, 0,
					&accepted), 0);
	EXPECT_EQ(state.revalidate_calls, 1);
	EXPECT_EQ(accepted, 1);
	EXPECT_EQ(slots[0].request.state, NXP_REQ_ACCEPTED);
	EXPECT_EQ(nxp_request_complete(&slots[0].request,
				       slots[0].request.token), 0);

	/* A zero submit is retried without guessing acceptance. */
	init_submit_case(&ctx, &state, slots, 1, &generation, &kernel_head);
	state.submit_result = 0;
	state.enter_result = 1;
	accepted = 0;
	EXPECT_EQ(submit_prepared_batch(&ctx, slots, order, 1, 0,
					&accepted), 0);
	EXPECT_EQ(accepted, 1);
	EXPECT_EQ(state.enter_calls, 1);
	EXPECT_EQ(nxp_request_complete(&slots[0].request,
				       slots[0].request.token), 0);

	/* A short result followed by an exact enter result accepts the prefix in
	 * order without attributing either completion to the wrong slot. */
	init_submit_case(&ctx, &state, slots, 2, &generation, &kernel_head);
	state.submit_result = 1;
	state.enter_result = 1;
	accepted = 0;
	EXPECT_EQ(submit_prepared_batch(&ctx, slots, order, 2, 0,
					&accepted), 0);
	EXPECT_EQ(accepted, 2);
	EXPECT_EQ(state.enter_calls, 1);
	EXPECT_EQ(nxp_request_complete(&slots[0].request,
				       slots[0].request.token), 0);
	EXPECT_EQ(nxp_request_complete(&slots[1].request,
				       slots[1].request.token), 0);

	/* Head movement can prove one accepted entry even when submit returns
	 * zero; a later positive enter result proves additional suffix entries. */
	init_submit_case(&ctx, &state, slots, 3, &generation, &kernel_head);
	state.submit_result = 0;
	state.submit_head_advance = 1;
	state.enter_result = 2;
	accepted = 0;
	EXPECT_EQ(submit_prepared_batch(&ctx, slots, order, 3, 0,
					&accepted), 0);
	EXPECT_EQ(accepted, 3);
	EXPECT_EQ(state.enter_calls, 1);
	for (size_t i = 0; i < 3; i++)
		EXPECT_EQ(nxp_request_complete(&slots[i].request,
					       slots[i].request.token), 0);

	/* A fatal submit errno is preserved, and no backing is released before
	 * teardown proves that the published entry can no longer be consumed. */
	init_submit_case(&ctx, &state, slots, 1, &generation, &kernel_head);
	state.submit_result = -ENXIO;
	accepted = 99;
	ret = submit_prepared_batch(&ctx, slots, order, 1, 0, &accepted);
	EXPECT_EQ(ret, -ENXIO);
	nxp_latch_error(&ctx.first_error, ret);
	EXPECT_EQ(accepted, 0);
	EXPECT_EQ(state.enter_calls, 0);
	EXPECT_TRUE(slots[0].request.owns_backing);
	EXPECT_EQ(pipeline_retain_unmatched_requests(&ctx, slots, 1), -ENXIO);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slots[0].request.owns_backing);

	/* A fatal enter with no SQ-head progress leaves the published backing
	 * owned through ring close and until process teardown. */
	init_submit_case(&ctx, &state, slots, 1, &generation, &kernel_head);
	state.submit_result = 0;
	state.enter_result = -EIO;
	accepted = 99;
	ret = submit_prepared_batch(&ctx, slots, order, 1, 0, &accepted);
	EXPECT_EQ(ret, -EIO);
	EXPECT_EQ(accepted, 0);
	EXPECT_EQ(slots[0].request.state, NXP_REQ_PUBLISHED);
	EXPECT_TRUE(slots[0].request.owns_backing);
	EXPECT_EQ(state.enter_calls, 1);
	nxp_latch_error(&ctx.first_error, ret);
	EXPECT_EQ(pipeline_retain_unmatched_requests(&ctx, slots, 1), -EIO);
	EXPECT_EQ(ctx.first_error, -EIO);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slots[0].request.owns_backing);

	/* A permanently interrupted/busy submit path has a finite bound. */
	init_submit_case(&ctx, &state, slots, 1, &generation, &kernel_head);
	state.submit_result = -EINTR;
	state.enter_result = -EAGAIN;
	accepted = 99;
	ret = submit_prepared_batch(&ctx, slots, order, 1, 0, &accepted);
	EXPECT_EQ(ret, -ETIMEDOUT);
	nxp_latch_error(&ctx.first_error, ret);
	EXPECT_EQ(accepted, 0);
	EXPECT_EQ(state.submit_calls, 1);
	EXPECT_EQ(state.enter_calls, NXP_MAX_TRANSIENT_RETRIES);
	EXPECT_TRUE(slots[0].request.owns_backing);
	EXPECT_EQ(pipeline_retain_unmatched_requests(&ctx, slots, 1), -ETIMEDOUT);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_TRUE(slots[0].request.owns_backing);
}

static void move_frame_to_tx_pending(struct pipeline_ctx *ctx, uint64_t addr)
{
	uint32_t frame = (uint32_t)(addr / FRAME_SIZE);

	EXPECT_EQ(xdev_ext_frame_publish(&ctx->xsk.pool, frame, 1), 0);
	EXPECT_EQ(xdev_ext_frame_acquire_ready(&ctx->xsk.pool, frame, NULL), 0);
	EXPECT_EQ(xdev_ext_frame_to_tx(&ctx->xsk.pool, frame, 1), 0);
}

static void setup_fake_cq(struct pipeline_ctx *ctx, uint64_t *entries,
			  uint32_t nr, uint32_t *producer,
			  uint32_t *consumer)
{
	uint32_t size = nr > 2 ? 8 : 2;

	*producer = nr;
	*consumer = 0;
	ctx->xsk.cq = (struct xsk_ring_cons) {
		.cached_prod = 0,
		.cached_cons = 0,
		.mask = size - 1,
		.size = size,
		.producer = producer,
		.consumer = consumer,
		.ring = entries,
	};
}

static void test_pre_submit_frame_cannot_be_reclaimed_by_cq(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	uint64_t cq_entries[1];
	uint64_t addr;
	uint32_t cq_producer;
	uint32_t cq_consumer;

	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	addr = xsk_alloc_umem_frame(&ctx.xsk);
	EXPECT_TRUE(addr != INVALID_UMEM_FRAME);
	EXPECT_EQ(xdev_ext_frame_publish(&ctx.xsk.pool, addr / FRAME_SIZE, 1024), 0);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_READY);
	cq_entries[0] = addr + PKT_START_OFF;
	setup_fake_cq(&ctx, cq_entries, 1, &cq_producer, &cq_consumer);
	xsk_tx_complete(&ctx);
	EXPECT_EQ(ctx.first_error, -EPROTO);
	EXPECT_TRUE(ctx.xsk.protocol_invalidated);
	EXPECT_FALSE(pipeline_can_destroy_xsk(&ctx));
	EXPECT_EQ(ctx.stats.tx_reclaimed, 0);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_READY);

	/* Invalidate is sticky: clearing the errno cannot authorize allocation on an
	 * address-only completion ring.  Group publication checks the same flag
	 * before it mutates any frame or TX descriptor. */
	ctx.first_error = 0;
	EXPECT_EQ(xsk_alloc_umem_frame(&ctx.xsk), INVALID_UMEM_FRAME);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_READY);
}

static void test_xsk_bad_and_duplicate_completions_latch_protocol_error(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;
	uint64_t entries[2];
	uint64_t addr;
	uint64_t second_addr;
	uint32_t producer;
	uint32_t consumer;

	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	addr = xsk_alloc_umem_frame(&ctx.xsk);
	EXPECT_TRUE(addr != INVALID_UMEM_FRAME);
	move_frame_to_tx_pending(&ctx, addr);
	second_addr = xsk_alloc_umem_frame(&ctx.xsk);
	EXPECT_TRUE(second_addr != INVALID_UMEM_FRAME);
	move_frame_to_tx_pending(&ctx, second_addr);
	entries[0] = UMEM_SIZE + PKT_START_OFF;
	entries[1] = second_addr + PKT_START_OFF;
	setup_fake_cq(&ctx, entries, 2, &producer, &consumer);
	xsk_tx_complete(&ctx);
	EXPECT_EQ(ctx.first_error, -EPROTO);
	EXPECT_TRUE(ctx.xsk.protocol_invalidated);
	EXPECT_FALSE(pipeline_can_destroy_xsk(&ctx));
	EXPECT_EQ(ctx.stats.protocol_errors, 1);
	EXPECT_EQ(ctx.stats.tx_reclaimed, 0);
	EXPECT_EQ(consumer, 2);
	/* The malformed address cannot identify a frame, so the live backing is
	 * retained until XSK teardown rather than guessed and recycled. */
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_TX_PENDING);
	/* Once one address is unattributed, even a syntactically valid following
	 * address is not reclaimed.  CQ addresses carry no generation token. */
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, second_addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_TX_PENDING);

	init_fake_ctx(&ctx, &state);
	EXPECT_EQ(xdev_ext_pool_init(&ctx.xsk.pool, ctx.xsk.pool_frames,
				NUM_FRAMES, true), 0);
	addr = xsk_alloc_umem_frame(&ctx.xsk);
	EXPECT_TRUE(addr != INVALID_UMEM_FRAME);
	move_frame_to_tx_pending(&ctx, addr);
	entries[0] = addr + PKT_START_OFF;
	entries[1] = addr + PKT_START_OFF;
	setup_fake_cq(&ctx, entries, 2, &producer, &consumer);
	xsk_tx_complete(&ctx);
	EXPECT_EQ(ctx.first_error, -EPROTO);
	EXPECT_TRUE(ctx.xsk.protocol_invalidated);
	EXPECT_EQ(ctx.stats.protocol_errors, 1);
	EXPECT_EQ(ctx.stats.tx_reclaimed, 1);
	EXPECT_EQ(consumer, 2);
	EXPECT_EQ(xdev_ext_frame_state(&ctx.xsk.pool, addr / FRAME_SIZE),
		  XDEV_EXT_FRAME_FREE);
}

static void test_unreclaimed_xsk_tx_retains_umem(void)
{
	struct pipeline_ctx ctx;
	struct fake_adapter_state state;

	init_fake_ctx(&ctx, &state);
	ctx.stats.tx_submitted = 7;
	ctx.stats.tx_reclaimed = 5;
	pipeline_handle_xsk_drain_timeout(&ctx);
	EXPECT_EQ(ctx.first_error, -ETIMEDOUT);
	EXPECT_EQ(ctx.stats.drops, 2);
	EXPECT_TRUE(ctx.xsk.protocol_invalidated);
	EXPECT_FALSE(pipeline_can_destroy_xsk(&ctx));

	init_fake_ctx(&ctx, &state);
	ctx.stats.tx_submitted = 7;
	ctx.stats.tx_reclaimed = 7;
	EXPECT_EQ(pipeline_handle_xsk_drain_timeout(&ctx), 0);
	EXPECT_EQ(ctx.first_error, 0);
	EXPECT_EQ(ctx.stats.drops, 0);
	EXPECT_FALSE(ctx.xsk.protocol_invalidated);
	EXPECT_TRUE(pipeline_can_destroy_xsk(&ctx));
}

static void test_write_text_file(const char *path, const char *text)
{
	FILE *file = fopen(path, "we");

	EXPECT_TRUE(file != NULL);
	if (!file)
		return;
	EXPECT_TRUE(fputs(text, file) >= 0);
	EXPECT_EQ(fclose(file), 0);
}

static void test_fake_sysfs_sibling_resolution_and_identify_decode(void)
{
	char root[] = "/tmp/nxp-sysfs-XXXXXX";
	char controller[PATH_MAX];
	char char_node[PATH_MAX];
	char block_node[PATH_MAX];
	char second_block_node[PATH_MAX];
	char reverse_root[PATH_MAX];
	char reverse_link[PATH_MAX];
	char second_reverse_link[PATH_MAX];
	char path[PATH_MAX];
	char dev_root[PATH_MAX];
	char block_device[PATH_MAX];
	unsigned char identify[4096] = { 0 };
	uint32_t lba_size = 0;
	uint64_t capacity_lbas = 0;
	uint16_t metadata_size = 0;
	uint8_t pi_type = 0;

	EXPECT_TRUE(mkdtemp(root) != NULL);
	EXPECT_TRUE(snprintf(controller, sizeof(controller), "%s/nvme0", root) > 0);
	EXPECT_TRUE(snprintf(char_node, sizeof(char_node), "%s/ng0n1",
			     controller) > 0);
	EXPECT_TRUE(snprintf(block_node, sizeof(block_node), "%s/nvme0n1",
			     controller) > 0);
	EXPECT_TRUE(snprintf(second_block_node, sizeof(second_block_node),
			     "%s/nvme0n1-alt", controller) > 0);
	EXPECT_TRUE(snprintf(reverse_root, sizeof(reverse_root), "%s/dev-block",
			     root) > 0);
	EXPECT_TRUE(snprintf(reverse_link, sizeof(reverse_link), "%s/259:0",
			     reverse_root) > 0);
	EXPECT_TRUE(snprintf(second_reverse_link, sizeof(second_reverse_link),
			     "%s/259:1", reverse_root) > 0);
	EXPECT_TRUE(snprintf(dev_root, sizeof(dev_root), "%s/dev", root) > 0);
	EXPECT_EQ(mkdir(controller, 0700), 0);
	EXPECT_EQ(mkdir(char_node, 0700), 0);
	EXPECT_EQ(mkdir(block_node, 0700), 0);
	EXPECT_EQ(mkdir(reverse_root, 0700), 0);
	EXPECT_EQ(mkdir(dev_root, 0700), 0);
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/nsid", block_node) > 0);
	test_write_text_file(path, "1\n");
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/dev", block_node) > 0);
	test_write_text_file(path, "259:0\n");
	EXPECT_EQ(symlink(block_node, reverse_link), 0);
	EXPECT_EQ(find_block_namespace_sibling_at(controller, char_node, 1,
					  reverse_root, dev_root,
					  block_device,
					  sizeof(block_device)), 0);
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/nvme0n1", dev_root) > 0);
	EXPECT_EQ(strcmp(block_device, path), 0);

	/* A reverse block-device link that points at any other node cannot prove
	 * identity, even when the candidate's nsid/dev text looks plausible. */
	EXPECT_EQ(unlink(reverse_link), 0);
	EXPECT_EQ(symlink(char_node, reverse_link), 0);
	EXPECT_EQ(find_block_namespace_sibling_at(controller, char_node, 1,
					  reverse_root, dev_root,
					  block_device,
					  sizeof(block_device)), -ENODEV);
	EXPECT_EQ(unlink(reverse_link), 0);
	EXPECT_EQ(symlink(block_node, reverse_link), 0);

	/* Two exact block siblings with the same NSID are ambiguous and fail
	 * closed rather than selecting by directory iteration order. */
	EXPECT_EQ(mkdir(second_block_node, 0700), 0);
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/nsid",
			     second_block_node) > 0);
	test_write_text_file(path, "1\n");
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/dev",
			     second_block_node) > 0);
	test_write_text_file(path, "259:1\n");
	EXPECT_EQ(symlink(second_block_node, second_reverse_link), 0);
	EXPECT_EQ(find_block_namespace_sibling_at(controller, char_node, 1,
					  reverse_root, dev_root,
					  block_device,
					  sizeof(block_device)), -ENOTUNIQ);

	/* NSZE=0x1000, FLBAS=0, LBAF0 metadata=8 and LBADS=12, DPS PI type=1. */
	identify[1] = 0x10;
	identify[26] = 0;
	identify[29] = 1;
	identify[128] = 8;
	identify[130] = 12;
	EXPECT_EQ(decode_identify_namespace(identify, sizeof(identify),
					    &lba_size, &capacity_lbas,
					    &metadata_size, &pi_type), 0);
	EXPECT_EQ(lba_size, 4096);
	EXPECT_EQ(capacity_lbas, 4096);
	EXPECT_EQ(metadata_size, 8);
	EXPECT_EQ(pi_type, 1);
	EXPECT_EQ(decode_identify_namespace(identify, 383, &lba_size,
					    &capacity_lbas, &metadata_size,
					    &pi_type), -EINVAL);

	/* Extended FLBAS bits select LBAF16; an impossible LBADS is rejected. */
	identify[26] = 0x20;
	identify[128 + 16 * 4] = 0;
	identify[128 + 16 * 4 + 1] = 0;
	identify[128 + 16 * 4 + 2] = 9;
	EXPECT_EQ(decode_identify_namespace(identify, sizeof(identify),
					    &lba_size, &capacity_lbas,
					    &metadata_size, &pi_type), 0);
	EXPECT_EQ(lba_size, 512);
	identify[128 + 16 * 4 + 2] = 32;
	EXPECT_EQ(decode_identify_namespace(identify, sizeof(identify),
					    &lba_size, &capacity_lbas,
					    &metadata_size, &pi_type),
		  -EOPNOTSUPP);

	EXPECT_EQ(unlink(reverse_link), 0);
	EXPECT_EQ(unlink(second_reverse_link), 0);
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/dev",
			     second_block_node) > 0);
	EXPECT_EQ(unlink(path), 0);
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/nsid",
			     second_block_node) > 0);
	EXPECT_EQ(unlink(path), 0);
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/dev", block_node) > 0);
	EXPECT_EQ(unlink(path), 0);
	EXPECT_TRUE(snprintf(path, sizeof(path), "%s/nsid", block_node) > 0);
	EXPECT_EQ(unlink(path), 0);
	EXPECT_EQ(rmdir(dev_root), 0);
	EXPECT_EQ(rmdir(reverse_root), 0);
	EXPECT_EQ(rmdir(second_block_node), 0);
	EXPECT_EQ(rmdir(block_node), 0);
	EXPECT_EQ(rmdir(char_node), 0);
	EXPECT_EQ(rmdir(controller), 0);
	EXPECT_EQ(rmdir(root), 0);
}

/* ---- run_rx_write_pipeline() end to end: the PIPELINE_RX_SUMMARY line ----
 *
 * These tests run the real rx-write receive loop against a scripted peer:
 *  - a fake NIC takes frames from the pipeline's AF_XDP fill ring, writes real
 *    wire packets there with build_wire_packet() at the RX headroom, and posts
 *    them on the RX ring, one phase at a time;
 *  - a fake NVMe device completes every WRITE SQE the pipeline submits, either
 *    at once or, with hold_cqes, one per bounded wait.
 * A phase is delivered from the fake clock only after the pipeline released
 * every earlier RX descriptor and while at most when_inflight_at_most WRITEs
 * are unreaped.  The loop peeks the RX ring before checking its depth limit and
 * does not hand back what it peeked but did not consume, so the peer never
 * posts while the loop cannot consume. */

/* register_fixed_buffers() calls liburing's io_uring_register_buffers()
 * directly rather than through the adapter.  This test binary supplies that
 * symbol (a link-time seam), so the loop runs without an io_uring instance. */
static int fake_register_buffers_result;
static unsigned int fake_register_buffers_calls;

int io_uring_register_buffers(struct io_uring *ring,
			      const struct iovec *iovecs, unsigned nr_iovecs)
{
	(void)ring;
	(void)iovecs;
	(void)nr_iovecs;
	fake_register_buffers_calls++;
	return fake_register_buffers_result;
}

#define FAKE_RX_RING 64U
#define FAKE_SQ_ENTRIES 8U
#define FAKE_CQ_ENTRIES 16U
#define FAKE_CQE_STRIDE 32U
#define FAKE_MAX_PACKETS 48U
#define FAKE_MAX_PHASES 4U

struct fake_rx_packet {
	uint64_t session_id;
	uint32_t generation;
	uint16_t segment;
	bool bad_descriptor;	/* descriptor options the decoder rejects */
};

struct fake_rx_phase {
	unsigned int first;
	unsigned int count;
	uint64_t clock_jump_ns;
	unsigned int when_inflight_at_most;
	bool during_wait;	/* delivered only inside a completion wait */
};

struct fake_rx_world {
	struct pipeline_ctx *ctx;
	struct fake_adapter_state *state;
	/* AF_XDP fill and RX rings shared with the pipeline. */
	uint64_t fq_entries[FAKE_RX_RING];
	struct xdp_desc rx_entries[FAKE_RX_RING];
	uint32_t fq_producer;
	uint32_t fq_consumer;
	uint32_t rx_producer;
	uint32_t rx_consumer;
	uint32_t ring_flags;
	struct fake_rx_packet packets[FAKE_MAX_PACKETS];
	unsigned int packet_count;
	struct fake_rx_phase phases[FAKE_MAX_PHASES];
	unsigned int phase_count;
	unsigned int next_phase;
	bool delivery_failed;
	/* io_uring SQ/CQ shared with the pipeline. */
	union {
		max_align_t align;
		unsigned char bytes[FAKE_SQ_ENTRIES * 128];
	} sq;
	unsigned int sq_head;
	unsigned int sq_mask;
	unsigned int sq_entries;
	unsigned int sq_seen;
	union {
		max_align_t align;
		unsigned char bytes[FAKE_CQ_ENTRIES * FAKE_CQE_STRIDE];
	} cq;
	unsigned int cq_head;
	unsigned int cq_tail;
	bool cq_overflow;
	bool hold_cqes;
	uint64_t held_user_data[FAKE_CQ_ENTRIES];
	int held_res[FAKE_CQ_ENTRIES];
	unsigned int held_count;
	unsigned int held_next;
	int write_results[FAKE_CQ_ENTRIES]; /* res of the n-th WRITE submitted */
	unsigned int submitted;
	unsigned int max_unreaped;
	bool foreign_sqe;
	/* With raise_signal set, the raise_on_wait-th completion wait raises
	 * it and returns -EINTR without posting, as an interrupted wait. */
	int raise_signal;
	unsigned int raise_on_wait;
	unsigned int waits;
	/* With batch_signal set, it is raised once by the first clock read the
	 * loop makes while it holds a peeked RX batch (peeked, not yet released
	 * or handed back) after at least batch_signal_after_submitted WRITEs
	 * were issued: a stop that arrives after the loop-top check, while a
	 * batch is examined. */
	int batch_signal;
	unsigned int batch_signal_after_submitted;
	bool batch_signal_raised;
	/* With never_complete set, the device never completes a held WRITE:
	 * every completion wait returns without a CQE.  Each wait records the
	 * protocol-error count it saw. */
	bool never_complete;
	uint64_t protocol_errors_at_wait;
	/* With miscount_received set, the next CQ-only completion wait adds
	 * one to the rx summary's received-frame count and clears the flag:
	 * a counting defect after which the counted transitions no longer add
	 * up to the frame states, with no frame outstanding and no error
	 * latched before the census. */
	bool miscount_received;
	/* Each held CQE's release advances the clock by cqe_release_jump_ns
	 * (the WRITE's device time) and records, at that instant, the release
	 * time and the rx summary's armed group clocks. */
	uint64_t cqe_release_jump_ns;
	/* With xsk_error_revents set, the xsk_error_on_wait-th wait on the CQ
	 * notification and the XSK fd reports them for the XSK fd. */
	short xsk_error_revents;
	unsigned int xsk_error_on_wait;
	uint64_t release_ns[FAKE_CQ_ENTRIES];
	unsigned int armed_at_release[FAKE_CQ_ENTRIES];
	uint64_t newest_first_accept_at_release[FAKE_CQ_ENTRIES];
};

static struct io_uring_cqe *fake_world_cqe(struct fake_rx_world *w,
					   unsigned int index)
{
	return (struct io_uring_cqe *)(w->cq.bytes +
				       (index % FAKE_CQ_ENTRIES) *
				       FAKE_CQE_STRIDE);
}

static void fake_world_post(struct fake_rx_world *w, uint64_t user_data,
			    int res)
{
	struct io_uring_cqe *cqe;

	if (w->cq_tail - w->cq_head >= FAKE_CQ_ENTRIES) {
		w->cq_overflow = true;
		return;
	}
	cqe = fake_world_cqe(w, w->cq_tail);
	cqe->user_data = user_data;
	cqe->res = res;
	cqe->flags = 0;
	__atomic_store_n(&w->cq_tail, w->cq_tail + 1, __ATOMIC_RELEASE);
}

static void fake_world_deliver(struct fake_rx_world *w,
			       const struct fake_rx_phase *phase)
{
	for (unsigned int i = 0; i < phase->count; i++) {
		const struct fake_rx_packet *packet =
			&w->packets[phase->first + i];
		struct nxp_wire_layout layout;
		struct nxp_wire_segment segment;
		struct xdp_desc *descriptor;
		uint32_t packet_len = 0;
		uint64_t frame;

		if (w->fq_consumer ==
			    __atomic_load_n(&w->fq_producer, __ATOMIC_ACQUIRE) ||
		    w->rx_producer - w->rx_consumer >= FAKE_RX_RING) {
			w->delivery_failed = true;
			return;
		}
		frame = w->fq_entries[w->fq_consumer % FAKE_RX_RING];
		__atomic_store_n(&w->fq_consumer, w->fq_consumer + 1,
				 __ATOMIC_RELEASE);
		if (nxp_wire_mtu_layout_plan(packet->session_id,
					     packet->generation, g_block_size,
					     w->ctx->mtu, FRAME_SIZE,
					     NXP_LAYOUT_DATA_OFFSET,
					     NXP_VECTOR_ALIGNMENT, &layout) ||
		    nxp_wire_segment_at(&layout, NXP_IO_WRITE, packet->segment,
					&segment) ||
		    build_wire_packet(w->ctx,
				      (unsigned char *)w->ctx->xsk.umem_area +
				      frame + XDP_PACKET_HEADROOM, NULL,
				      &segment, &packet_len)) {
			w->delivery_failed = true;
			return;
		}
		descriptor = &w->rx_entries[w->rx_producer % FAKE_RX_RING];
		descriptor->addr = frame + NXP_RX_PACKET_OFFSET;
		descriptor->len = packet_len;
		descriptor->options = packet->bad_descriptor ? 1 : 0;
		__atomic_store_n(&w->rx_producer, w->rx_producer + 1,
				 __ATOMIC_RELEASE);
	}
}

static void fake_world_step_phase(struct fake_rx_world *w, bool in_wait)
{
	const struct fake_rx_phase *phase;

	if (w->next_phase >= w->phase_count)
		return;
	phase = &w->phases[w->next_phase];
	if (phase->during_wait != in_wait ||
	    __atomic_load_n(&w->rx_consumer, __ATOMIC_ACQUIRE) !=
		    w->rx_producer ||
	    w->submitted - w->cq_head > phase->when_inflight_at_most)
		return;
	w->next_phase++;
	w->state->monotonic_ns += phase->clock_jump_ns;
	fake_world_deliver(w, phase);
}

static void fake_world_step(struct fake_rx_world *w)
{
	if (w->batch_signal && !w->batch_signal_raised &&
	    w->submitted >= w->batch_signal_after_submitted &&
	    w->ctx->xsk.rx.cached_cons !=
		    __atomic_load_n(&w->rx_consumer, __ATOMIC_ACQUIRE)) {
		w->batch_signal_raised = true;
		(void)raise(w->batch_signal);
	}
	fake_world_step_phase(w, false);
}

/* Post the next held CQE, as the device completing that WRITE. */
static void fake_world_release_held(struct fake_rx_world *w)
{
	unsigned int n = w->held_next;
	unsigned int armed = 0;
	uint64_t newest = 0;

	w->state->monotonic_ns += w->cqe_release_jump_ns;
	for (size_t i = 0; g_rx_summary.clocks && i < g_rx_summary.clock_count;
	     i++) {
		if (!g_rx_summary.clocks[i].armed)
			continue;
		armed++;
		if (g_rx_summary.clocks[i].first_accept_ns > newest)
			newest = g_rx_summary.clocks[i].first_accept_ns;
	}
	w->release_ns[n] = w->state->monotonic_ns;
	w->armed_at_release[n] = armed;
	w->newest_first_accept_at_release[n] = newest;
	fake_world_post(w, w->held_user_data[n], w->held_res[n]);
	w->held_next++;
}

static int fake_world_submit(struct pipeline_ctx *ctx,
			     struct fake_rx_world *w)
{
	unsigned int tail = ctx->uring.ring.sq.sqe_tail;
	unsigned int count = tail - w->sq_seen;

	for (unsigned int i = 0; i < count; i++) {
		const struct io_uring_sqe *sqe = (const struct io_uring_sqe *)
			(w->sq.bytes + ((w->sq_seen + i) & w->sq_mask) * 128);
		const struct nvme_uring_cmd *cmd =
			(const struct nvme_uring_cmd *)sqe->cmd;
		int res = w->submitted < FAKE_CQ_ENTRIES ?
			  w->write_results[w->submitted] : 0;

		if (sqe->opcode != IORING_OP_URING_CMD ||
		    cmd->opcode != NVME_CMD_WRITE)
			w->foreign_sqe = true;
		if (w->hold_cqes && w->held_count < FAKE_CQ_ENTRIES) {
			w->held_user_data[w->held_count] = sqe->user_data;
			w->held_res[w->held_count] = res;
			w->held_count++;
		} else {
			fake_world_post(w, sqe->user_data, res);
		}
		w->submitted++;
	}
	w->sq_seen = tail;
	__atomic_store_n(&w->sq_head, w->sq_head + count, __ATOMIC_RELEASE);
	if (w->submitted - w->cq_head > w->max_unreaped)
		w->max_unreaped = w->submitted - w->cq_head;
	return (int)count;
}

static int fake_world_peek(struct fake_rx_world *w,
			   struct io_uring_cqe **cqe)
{
	if (__atomic_load_n(&w->cq_head, __ATOMIC_ACQUIRE) == w->cq_tail)
		return -EAGAIN;
	if (cqe)
		*cqe = fake_world_cqe(w, w->cq_head);
	return 0;
}

static int fake_world_wait(struct fake_rx_world *w,
			   struct io_uring_cqe **cqe)
{
	w->waits++;
	w->protocol_errors_at_wait = w->ctx->stats.protocol_errors;
	if (w->miscount_received) {
		w->miscount_received = false;
		g_rx_summary.frames_received++;
	}
	if (w->raise_signal && w->waits == w->raise_on_wait) {
		(void)raise(w->raise_signal);
		return -EINTR;
	}
	/* The NIC may deliver while the pipeline waits; a CQ-only wait still
	 * returns only with a CQE. */
	fake_world_step_phase(w, true);
	if (!w->never_complete && w->held_next < w->held_count) {
		fake_world_release_held(w);
		return fake_world_peek(w, cqe);
	}
	return -ETIME;
}

/* The poll() on the CQ eventfd and the XSK fd: ready when the NIC delivered
 * (a phase due inside a wait) or when the device completes the next held
 * WRITE; a signal interrupts it like the CQ-only wait. */
static int fake_world_event_wait(struct fake_rx_world *w, short *rx_revents)
{
	w->waits++;
	w->protocol_errors_at_wait = w->ctx->stats.protocol_errors;
	if (w->raise_signal && w->waits == w->raise_on_wait) {
		(void)raise(w->raise_signal);
		return -EINTR;
	}
	if (w->xsk_error_revents && w->waits == w->xsk_error_on_wait) {
		*rx_revents = w->xsk_error_revents;
		return 0;
	}
	fake_world_step_phase(w, true);
	if (__atomic_load_n(&w->rx_producer, __ATOMIC_ACQUIRE) !=
	    w->rx_consumer) {
		*rx_revents = POLLIN;
		return 0;
	}
	if (!w->never_complete && w->held_next < w->held_count) {
		fake_world_release_held(w);
		return 0;
	}
	return -ETIME;
}

struct rx_globals {
	uint32_t block_size;
	int depth;
	int fixed_buffer;
	int staging;
	int iopoll;
	enum pipeline_direction direction;
	enum pipeline_transform transform;
};

static void rx_globals_save(struct rx_globals *g)
{
	*g = (struct rx_globals) {
		.block_size = g_block_size, .depth = g_depth,
		.fixed_buffer = g_fixed_buffer, .staging = g_staging,
		.iopoll = g_iopoll, .direction = g_direction,
		.transform = g_transform,
	};
}

static void rx_globals_restore(const struct rx_globals *g)
{
	g_block_size = g->block_size;
	g_depth = g->depth;
	g_fixed_buffer = g->fixed_buffer;
	g_staging = g->staging;
	g_iopoll = g->iopoll;
	g_direction = g->direction;
	g_transform = g->transform;
	fake_register_buffers_result = 0;
}

static void rx_world_init(struct pipeline_ctx *ctx,
			  struct fake_adapter_state *state,
			  struct fake_rx_world *w, int depth, uint32_t groups)
{
	init_fake_ctx(ctx, state);
	memset(w, 0, sizeof(*w));
	w->ctx = ctx;
	w->state = state;
	state->world = w;
	state->monotonic_ns = UINT64_C(1000000000);
	state->monotonic_step_ns = 1000;
	memcpy(ctx->src_mac, "\x02\x00\x00\x00\x00\x01", 6);
	memcpy(ctx->dst_mac, "\x02\x00\x00\x00\x00\x02", 6);
	ctx->src_ip = inet_addr("192.0.2.1");
	ctx->dst_ip = inet_addr("192.0.2.2");
	ctx->src_port = 12000;
	ctx->dst_port = 13000;
	ctx->mtu = 1500;
	ctx->nsid = 9;
	ctx->namespace = (struct nxp_namespace) {
		.nsid = 9, .lba_size = 512, .capacity_lbas = 4096,
		.char_is_namespace = true, .block_is_whole_namespace = true,
		.same_namespace = true, .stable_id_present = true,
		.controller_serial_present = true, .pci_bdf_present = true,
		.char_rdev = 1, .block_rdev = 2, .diskseq = 3,
		.stable_id_len = 1, .controller_serial_len = 1,
		.pci_bdf_len = 1,
	};
	ctx->io_limits.authorized_first_lba = 100;
	ctx->io_limits.authorized_lbas = (uint64_t)groups * 16;
	ctx->xsk.xsk_fd = -1;
	ctx->xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx->xsk.umem_area != NULL);
	ctx->xsk.fq = (struct xsk_ring_prod) {
		.cached_cons = FAKE_RX_RING, .mask = FAKE_RX_RING - 1,
		.size = FAKE_RX_RING, .producer = &w->fq_producer,
		.consumer = &w->fq_consumer, .ring = w->fq_entries,
		.flags = &w->ring_flags,
	};
	ctx->xsk.rx = (struct xsk_ring_cons) {
		.mask = FAKE_RX_RING - 1, .size = FAKE_RX_RING,
		.producer = &w->rx_producer, .consumer = &w->rx_consumer,
		.ring = w->rx_entries, .flags = &w->ring_flags,
	};
	w->sq_mask = FAKE_SQ_ENTRIES - 1;
	w->sq_entries = FAKE_SQ_ENTRIES;
	ctx->uring.ring.flags = IORING_SETUP_SQE128;
	ctx->uring.ring.sq.khead = &w->sq_head;
	ctx->uring.ring.sq.kring_mask = &w->sq_mask;
	ctx->uring.ring.sq.kring_entries = &w->sq_entries;
	ctx->uring.ring.sq.sqes = (struct io_uring_sqe *)w->sq.bytes;
	ctx->uring.ring.cq.khead = &w->cq_head;
	g_block_size = 8192;
	g_depth = depth;
	g_direction = PIPELINE_NIC_TO_NVME;
	g_staging = 0;
	g_iopoll = 0;
	g_transform = PIPELINE_TRANSFORM_NONE;
	fake_register_buffers_result = 0;
	fake_register_buffers_calls = 0;
}

static void rx_world_phase(struct fake_rx_world *w, uint64_t clock_jump_ns,
			   unsigned int when_inflight_at_most)
{
	struct fake_rx_phase *phase;

	EXPECT_TRUE(w->phase_count < FAKE_MAX_PHASES);
	if (w->phase_count >= FAKE_MAX_PHASES)
		return;
	phase = &w->phases[w->phase_count++];
	*phase = (struct fake_rx_phase) {
		.first = w->packet_count,
		.clock_jump_ns = clock_jump_ns,
		.when_inflight_at_most = when_inflight_at_most,
	};
}

/* A phase the NIC delivers while the pipeline is blocked in a completion
 * wait with at most when_inflight_at_most WRITEs unreaped. */
static void rx_world_wait_phase(struct fake_rx_world *w,
				unsigned int when_inflight_at_most)
{
	rx_world_phase(w, 0, when_inflight_at_most);
	if (w->phase_count)
		w->phases[w->phase_count - 1].during_wait = true;
}

static void rx_world_packet(struct fake_rx_world *w, uint64_t session_id,
			    uint32_t generation, uint16_t segment,
			    bool bad_descriptor)
{
	EXPECT_TRUE(w->phase_count > 0 && w->packet_count < FAKE_MAX_PACKETS);
	if (!w->phase_count || w->packet_count >= FAKE_MAX_PACKETS)
		return;
	w->packets[w->packet_count++] = (struct fake_rx_packet) {
		.session_id = session_id, .generation = generation,
		.segment = segment, .bad_descriptor = bad_descriptor,
	};
	w->phases[w->phase_count - 1].count++;
}

static void rx_world_group(struct fake_rx_world *w, uint32_t generation,
			   uint16_t first_segment, uint16_t count)
{
	for (uint16_t i = 0; i < count; i++)
		rx_world_packet(w, TEST_WIRE_SESSION, generation,
				(uint16_t)(first_segment + i), false);
}

struct rx_run {
	int ret;
	unsigned int summaries;
	bool parsed;
	struct nxp_rx_summary_report line;
	char output[16384];
	/* SIGTERM and SIGINT as a retaining run left them; see
	 * rx_world_run_retaining(). */
	struct sigaction stop_after[2];
};

static const int test_stop_signals[2] = { SIGTERM, SIGINT };

static unsigned int count_occurrences(const char *text, const char *needle)
{
	unsigned int count = 0;

	for (const char *at = strstr(text, needle); at;
	     at = strstr(at + 1, needle))
		count++;
	return count;
}

/* The exact contract line, at the start of a line and ending with '\n'. */
static int parse_rx_summary(const char *output,
			    struct nxp_rx_summary_report *r)
{
	const char *line = strstr(output, "PIPELINE_RX_SUMMARY ");
	unsigned long long v[19];
	int end = -1;

	if (!line || (line != output && line[-1] != '\n'))
		return -ENOENT;
	if (sscanf(line,
		   "PIPELINE_RX_SUMMARY groups=%llu packets_accepted=%llu "
		   "packets_dropped=%llu bytes_written=%llu write_errors=%llu "
		   "cpu_user_us=%llu cpu_sys_us=%llu wall_us=%llu "
		   "group_service_us_p50=%llu group_service_us_p99=%llu "
		   "nvme_cmds=%llu max_inflight=%llu frames_received=%llu "
		   "frames_returned=%llu frames_outstanding=%llu "
		   "rx_span_us=%llu tail_us=%llu "
		   "group_post_arrival_us_p50=%llu "
		   "group_post_arrival_us_p99=%llu%n",
		   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7],
		   &v[8], &v[9], &v[10], &v[11], &v[12], &v[13], &v[14],
		   &v[15], &v[16], &v[17], &v[18], &end) != 19 ||
	    end < 0 || line[end] != '\n')
		return -EPROTO;
	*r = (struct nxp_rx_summary_report) {
		.groups = v[0], .packets_accepted = v[1],
		.packets_dropped = v[2], .bytes_written = v[3],
		.write_errors = v[4], .cpu_user_us = v[5], .cpu_sys_us = v[6],
		.wall_us = v[7], .group_service_us_p50 = v[8],
		.group_service_us_p99 = v[9], .nvme_cmds = v[10],
		.max_inflight = v[11], .frames_received = v[12],
		.frames_returned = v[13], .frames_outstanding = v[14],
		.rx_span_us = v[15], .tail_us = v[16],
		.group_post_arrival_us_p50 = v[17],
		.group_post_arrival_us_p99 = v[18],
	};
	return 0;
}

struct stdout_capture {
	FILE *file;
	int saved;
};

static bool capture_stdout_begin(struct stdout_capture *capture)
{
	fflush(stdout);
	capture->saved = -1;
	capture->file = tmpfile();
	if (!capture->file)
		return false;
	capture->saved = dup(STDOUT_FILENO);
	if (capture->saved < 0 ||
	    dup2(fileno(capture->file), STDOUT_FILENO) < 0) {
		if (capture->saved >= 0)
			close(capture->saved);
		fclose(capture->file);
		capture->file = NULL;
		return false;
	}
	return true;
}

static void capture_stdout_end(struct stdout_capture *capture, char *buf,
			       size_t size)
{
	size_t len = 0;

	buf[0] = '\0';
	if (!capture->file)
		return;
	fflush(stdout);
	(void)dup2(capture->saved, STDOUT_FILENO);
	close(capture->saved);
	rewind(capture->file);
	len = fread(buf, 1, size - 1, capture->file);
	buf[len] = '\0';
	fclose(capture->file);
	capture->file = NULL;
}

/* One rx-write run with stdout captured. */
static void rx_world_run(struct pipeline_ctx *ctx, int groups,
			 struct rx_run *run)
{
	struct stdout_capture capture;
	bool captured;

	memset(run, 0, sizeof(*run));
	captured = capture_stdout_begin(&capture);
	EXPECT_TRUE(captured);
	run->ret = run_rx_write_pipeline(ctx, 0, groups);
	if (captured)
		capture_stdout_end(&capture, run->output, sizeof(run->output));
	run->summaries = count_occurrences(run->output, "PIPELINE_RX_SUMMARY");
	run->parsed = parse_rx_summary(run->output, &run->line) == 0;
}

#if defined(__SANITIZE_ADDRESS__)
#define NXP_TEST_LSAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define NXP_TEST_LSAN 1
#endif
#endif
#ifdef NXP_TEST_LSAN
#include <sanitizer/lsan_interface.h>
#endif

/* rx_world_run() for a run that ends with DMA backing retained.  Such a run
 * returns before freeing its slot and frame-state arrays, and main() then
 * holds the process in pipeline_hold_unquiesced_backing(), so the leak
 * checker of the sanitize build must not count them. */
static void rx_world_run_retaining(struct pipeline_ctx *ctx, int groups,
				   struct rx_run *run)
{
	struct sigaction before[2];

	for (int i = 0; i < 2; i++)
		EXPECT_EQ(sigaction(test_stop_signals[i], NULL, &before[i]), 0);
#ifdef NXP_TEST_LSAN
	__lsan_disable();
#endif
	rx_world_run(ctx, groups, run);
#ifdef NXP_TEST_LSAN
	__lsan_enable();
#endif
	/* A retaining run leaves the stop signals ignored for the hold that
	 * main() would enter.  Record that for the test, then put back what
	 * the test had, so later tests can still be stopped by a signal. */
	for (int i = 0; i < 2; i++) {
		EXPECT_EQ(sigaction(test_stop_signals[i], NULL,
				    &run->stop_after[i]), 0);
		EXPECT_EQ(sigaction(test_stop_signals[i], &before[i], NULL), 0);
	}
}

/* The frame census of a run whose loop started: every frame the loop took
 * off the RX ring was returned exactly once, and none is outstanding.  A
 * macro, so that a failure names the calling test. */
#define EXPECT_FRAMES_RETIRED(run, received) do {                            \
	EXPECT_TRUE((run)->parsed);                                            \
	EXPECT_EQ((run)->line.frames_received, (received));                    \
	EXPECT_EQ((run)->line.frames_returned, (received));                    \
	EXPECT_EQ((run)->line.frames_outstanding, 0);                          \
} while (0)

/* The arrival fields of a run in which every group was written: the receive
 * span and the tail add up to wall_us to within the truncation of each to
 * whole microseconds, and a group's post-arrival time, which starts at its
 * last packet, is never longer than its service time, which starts at its
 * first.  A macro, so that a failure names the calling test. */
#define EXPECT_ARRIVAL_FIELDS_CONSISTENT(run) do {                          \
	EXPECT_TRUE((run)->parsed);                                            \
	EXPECT_TRUE((run)->line.rx_span_us + (run)->line.tail_us <=            \
		    (run)->line.wall_us);                                      \
	EXPECT_TRUE((run)->line.rx_span_us + (run)->line.tail_us + 1 >=        \
		    (run)->line.wall_us);                                      \
	EXPECT_TRUE((run)->line.group_post_arrival_us_p50 <=                   \
		    (run)->line.group_post_arrival_us_p99);                    \
	EXPECT_TRUE((run)->line.group_post_arrival_us_p50 <=                   \
		    (run)->line.group_service_us_p50);                         \
	EXPECT_TRUE((run)->line.group_post_arrival_us_p99 <=                   \
		    (run)->line.group_service_us_p99);                         \
} while (0)

static void rx_world_finish(struct pipeline_ctx *ctx,
			    struct fake_adapter_state *state,
			    const struct rx_globals *saved)
{
	state->world = NULL;
	free(ctx->xsk.umem_area);
	ctx->xsk.umem_area = NULL;
	rx_globals_restore(saved);
}

static void test_rx_summary_success_line_describes_the_run(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 2);
	rx_world_phase(&world, 0, 0);
	rx_world_packet(&world, TEST_WIRE_SESSION, 1, 0, false);
	/* A duplicate and a datagram from another session are dropped. */
	rx_world_packet(&world, TEST_WIRE_SESSION, 1, 0, false);
	rx_world_packet(&world, TEST_WIRE_SESSION + 1, 1, 1, false);
	rx_world_group(&world, 1, 1, 5);
	rx_world_group(&world, 2, 0, 6);
	rx_world_run(&ctx, 2, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	EXPECT_EQ(run.line.groups, 2);
	EXPECT_EQ(run.line.packets_accepted, 12);
	EXPECT_EQ(run.line.packets_dropped, 2);
	/* Every descriptor the loop consumed is counted exactly once, with the
	 * loop's own accept/drop decisions. */
	EXPECT_EQ(world.rx_consumer, 14);
	EXPECT_EQ(run.line.packets_accepted + run.line.packets_dropped,
		  world.rx_consumer);
	EXPECT_EQ(run.line.packets_dropped, ctx.stats.drops);
	EXPECT_EQ(run.line.bytes_written, 2 * 8192);
	EXPECT_EQ(run.line.write_errors, 0);
	EXPECT_EQ(run.line.nvme_cmds, 2);
	EXPECT_EQ(run.line.nvme_cmds, world.submitted);
	EXPECT_EQ(run.line.max_inflight, 2);
	EXPECT_EQ(run.line.max_inflight, world.max_unreaped);
	EXPECT_TRUE(run.line.group_service_us_p50 > 0);
	EXPECT_TRUE(run.line.group_service_us_p50 <=
		    run.line.group_service_us_p99);
	EXPECT_TRUE(run.line.group_service_us_p99 <= run.line.wall_us);
	EXPECT_EQ(g_rx_summary.service_count, 2);
	EXPECT_EQ(g_rx_summary.post_arrival_count, 2);
	EXPECT_EQ(g_rx_summary.inflight, 0);
	EXPECT_TRUE(run.line.rx_span_us > 0);
	EXPECT_ARRIVAL_FIELDS_CONSISTENT(&run);
	/* The summary's arrays are released with the run. */
	EXPECT_TRUE(g_rx_summary.service_ns == NULL);
	EXPECT_TRUE(g_rx_summary.post_arrival_ns == NULL);
	EXPECT_TRUE(g_rx_summary.clocks == NULL);
	EXPECT_EQ(fake_register_buffers_calls, 1);
	/* The duplicate and the foreign datagram are returned too. */
	EXPECT_FRAMES_RETIRED(&run, 14);
	rx_world_finish(&ctx, &state, &saved);
}

static void test_rx_summary_failed_write_is_an_error_not_a_sample(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 2);
	world.write_results[0] = -EIO;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run(&ctx, 2, &run);

	EXPECT_EQ(run.ret, -EIO);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 0);
	EXPECT_EQ(run.line.bytes_written, 0);
	EXPECT_EQ(run.line.write_errors, 1);
	EXPECT_EQ(run.line.packets_accepted, 6);
	EXPECT_EQ(run.line.packets_dropped, 0);
	EXPECT_EQ(run.line.nvme_cmds, 1);
	EXPECT_EQ(run.line.max_inflight, 1);
	EXPECT_EQ(run.line.group_service_us_p50, 0);
	EXPECT_EQ(run.line.group_service_us_p99, 0);
	/* The failed completion still ends the wall clock. */
	EXPECT_TRUE(run.line.wall_us > 0);
	EXPECT_EQ(g_rx_summary.service_count, 0);
	/* The failed WRITE's CQE still returns its six frames. */
	EXPECT_FRAMES_RETIRED(&run, 6);
	rx_world_finish(&ctx, &state, &saved);
}

static void test_rx_summary_idle_timeout_prints_one_empty_line(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	state.monotonic_step_ns = UINT64_C(1000000000);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -ETIMEDOUT);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 0);
	EXPECT_EQ(run.line.packets_accepted, 0);
	EXPECT_EQ(run.line.packets_dropped, 0);
	EXPECT_EQ(run.line.bytes_written, 0);
	EXPECT_EQ(run.line.write_errors, 0);
	EXPECT_EQ(run.line.wall_us, 0);
	EXPECT_EQ(run.line.group_service_us_p50, 0);
	EXPECT_EQ(run.line.group_service_us_p99, 0);
	EXPECT_EQ(run.line.nvme_cmds, 0);
	EXPECT_EQ(run.line.max_inflight, 0);
	EXPECT_FRAMES_RETIRED(&run, 0);
	rx_world_finish(&ctx, &state, &saved);
}

static void test_rx_summary_expired_group_is_never_sampled(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 3);
	/* 1.5 s later, past the 1 s group timeout, the sender retries the
	 * same generation from segment 0. */
	rx_world_phase(&world, UINT64_C(1500000000), 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_EQ(run.line.groups, 1);
	/* Packets of the expired group stay accepted, as in the baseline. */
	EXPECT_EQ(run.line.packets_accepted, 9);
	EXPECT_EQ(run.line.packets_dropped, 0);
	EXPECT_EQ(ctx.stats.drops, 1); /* the loop's expiry, not a packet */
	EXPECT_EQ(run.line.nvme_cmds, 1);
	/* The sample runs from the retry's first packet, not the expired
	 * group's 1.5 s earlier. */
	EXPECT_EQ(g_rx_summary.service_count, 1);
	EXPECT_TRUE(run.line.group_service_us_p99 < 1000000);
	EXPECT_TRUE(run.line.wall_us >= 1500000);
	/* The expired group's three frames are returned at expiry. */
	EXPECT_FRAMES_RETIRED(&run, 9);
	rx_world_finish(&ctx, &state, &saved);
}

/* Wall time starts at the first packet examined, even a dropped one; service
 * time starts at the group's first ACCEPTED packet, not at the packet that
 * began the group. */
static void test_rx_summary_clocks_start_at_the_defined_packets(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	rx_world_phase(&world, 0, 0);
	/* Dropped: another session; then segment 1 first, which begins the
	 * group but is dropped as out of order. */
	rx_world_packet(&world, TEST_WIRE_SESSION + 1, 1, 0, false);
	rx_world_packet(&world, TEST_WIRE_SESSION, 1, 1, false);
	/* 600 ms later (inside the 1 s group timeout) the group arrives in
	 * order. */
	rx_world_phase(&world, UINT64_C(600000000), 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_EQ(run.line.packets_accepted, 6);
	EXPECT_EQ(run.line.packets_dropped, 2);
	EXPECT_EQ(ctx.stats.drops, 2); /* no expiry happened */
	EXPECT_EQ(g_rx_summary.service_count, 1);
	EXPECT_TRUE(run.line.wall_us >= 600000);
	EXPECT_TRUE(run.line.group_service_us_p50 > 0);
	EXPECT_TRUE(run.line.group_service_us_p99 < 600000);
	/* Foreign-session and out-of-order frames are returned. */
	EXPECT_FRAMES_RETIRED(&run, 8);
	rx_world_finish(&ctx, &state, &saved);
}

/* Service time runs from the group's FIRST accepted packet, as in the
 * baseline (first_accept_ns is taken at next_segment == 1), and not from any
 * later accepted packet: segment 0 arrives 300 ms before segments 1-5 (inside
 * the 1 s group timeout), so the one sample is the 300 ms gap plus the fake
 * clock's few microseconds, never a few microseconds alone. */
static void test_rx_summary_service_time_starts_at_first_accepted_packet(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 1);
	rx_world_phase(&world, UINT64_C(300000000), 0);
	rx_world_group(&world, 1, 1, 5);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_EQ(world.next_phase, 2); /* segments 1-5 came in the later phase */
	EXPECT_EQ(world.rx_consumer, 6);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_EQ(run.line.packets_accepted, 6);
	EXPECT_EQ(run.line.packets_dropped, 0);
	EXPECT_EQ(ctx.stats.drops, 0); /* no expiry happened */
	EXPECT_EQ(run.line.nvme_cmds, 1);
	EXPECT_EQ(g_rx_summary.service_count, 1);
	EXPECT_TRUE(run.line.group_service_us_p50 >= 300000);
	EXPECT_TRUE(run.line.group_service_us_p50 < 301000);
	EXPECT_EQ(run.line.group_service_us_p99, run.line.group_service_us_p50);
	EXPECT_TRUE(run.line.group_service_us_p99 <= run.line.wall_us);
	EXPECT_FRAMES_RETIRED(&run, 6);
	rx_world_finish(&ctx, &state, &saved);
}

/* Each group's service time starts at its own first accepted packet: group 1
 * waits 300 ms between segment 0 and segments 1-5, group 2 arrives whole right
 * behind it.  With two samples, nearest rank gives p50 = the shorter (group 2)
 * and p99 = the longer (group 1). */
static void test_rx_summary_service_time_is_per_group(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 2);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 1);
	rx_world_phase(&world, UINT64_C(300000000), 0);
	rx_world_group(&world, 1, 1, 5);
	rx_world_group(&world, 2, 0, 6);
	rx_world_run(&ctx, 2, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_EQ(world.next_phase, 2);
	EXPECT_EQ(world.rx_consumer, 12);
	EXPECT_EQ(run.line.groups, 2);
	EXPECT_EQ(run.line.packets_accepted, 12);
	EXPECT_EQ(run.line.packets_dropped, 0);
	EXPECT_EQ(run.line.nvme_cmds, 2);
	EXPECT_EQ(g_rx_summary.service_count, 2);
	EXPECT_TRUE(run.line.group_service_us_p50 > 0);
	EXPECT_TRUE(run.line.group_service_us_p50 < 1000);
	EXPECT_TRUE(run.line.group_service_us_p99 >= 300000);
	EXPECT_TRUE(run.line.group_service_us_p99 < 301000);
	EXPECT_TRUE(run.line.group_service_us_p99 <= run.line.wall_us);
	EXPECT_FRAMES_RETIRED(&run, 12);
	rx_world_finish(&ctx, &state, &saved);
}

/* The receive span ends at the arrival of the packet that completes the last
 * group, and that packet starts the group's post-arrival time: segments 0-4
 * arrive at once, segment 5 300 ms later (inside the 1 s group timeout), and
 * the WRITE completes at once.  So the span and the service time hold the
 * 300 ms gap, which the sender sets, while the post-arrival time and the tail
 * hold only the receiver's few microseconds after segment 5. */
static void test_rx_summary_receive_span_ends_at_the_last_group_packet(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 5);
	rx_world_phase(&world, UINT64_C(300000000), 0);
	rx_world_group(&world, 1, 5, 1);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_EQ(world.next_phase, 2);
	EXPECT_EQ(world.rx_consumer, 6);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_EQ(g_rx_summary.post_arrival_count, 1);
	EXPECT_TRUE(run.line.rx_span_us >= 300000);
	EXPECT_TRUE(run.line.rx_span_us < 301000);
	EXPECT_TRUE(run.line.group_service_us_p50 >= 300000);
	EXPECT_TRUE(run.line.group_post_arrival_us_p50 < 1000);
	EXPECT_EQ(run.line.group_post_arrival_us_p99,
		  run.line.group_post_arrival_us_p50);
	EXPECT_TRUE(run.line.tail_us < 1000);
	EXPECT_ARRIVAL_FIELDS_CONSISTENT(&run);
	EXPECT_FRAMES_RETIRED(&run, 6);
	rx_world_finish(&ctx, &state, &saved);
}

/* Descriptors the loop peeked but could not consume (here: the depth limit at
 * -Q 1 while group 1's WRITE is prepared) stay on the RX ring and are
 * examined later; none is skipped. */
static void test_rx_write_leaves_unconsumed_descriptors_on_the_ring(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 2);
	/* 100 ms per clock read: a skipped group ends in the 5 s idle timeout
	 * quickly; each group still fits in one RX batch (three reads: its
	 * first packet, the group begin and its last packet), well inside the
	 * 1 s group timeout. */
	state.monotonic_step_ns = UINT64_C(100000000);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_group(&world, 2, 0, 6);
	rx_world_run(&ctx, 2, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_EQ(world.rx_consumer, 12);
	EXPECT_EQ(ctx.xsk.rx.cached_cons, world.rx_consumer);
	EXPECT_EQ(run.line.groups, 2);
	EXPECT_EQ(run.line.packets_accepted, 12);
	EXPECT_EQ(run.line.packets_dropped, 0);
	EXPECT_EQ(run.line.nvme_cmds, 2);
	EXPECT_EQ(run.line.max_inflight, 1);
	/* Descriptors left on the ring are not received until taken. */
	EXPECT_FRAMES_RETIRED(&run, 12);
	rx_world_finish(&ctx, &state, &saved);
}

static void test_rx_summary_max_inflight_reaches_but_never_exceeds_depth(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 3);
	world.hold_cqes = true;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_group(&world, 2, 0, 6);
	rx_world_phase(&world, 0, 1);
	rx_world_group(&world, 3, 0, 6);
	rx_world_run(&ctx, 3, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_EQ(run.line.groups, 3);
	EXPECT_EQ(run.line.packets_accepted, 18);
	EXPECT_EQ(run.line.nvme_cmds, 3);
	EXPECT_EQ(run.line.max_inflight, 2);
	EXPECT_EQ(run.line.max_inflight, world.max_unreaped);
	EXPECT_TRUE(run.line.max_inflight <= (unsigned int)g_depth);
	EXPECT_EQ(g_rx_summary.service_count, 3);
	EXPECT_TRUE(state.wait_calls >= 3);
	EXPECT_FRAMES_RETIRED(&run, 18);
	rx_world_finish(&ctx, &state, &saved);
}

static void test_rx_summary_unaccepted_submission_is_a_write_error(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	state.revalidate_result = -ESTALE;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -ESTALE);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(world.submitted, 0);
	EXPECT_EQ(run.line.groups, 0);
	EXPECT_EQ(run.line.write_errors, 1);
	EXPECT_EQ(run.line.nvme_cmds, 0);
	EXPECT_EQ(run.line.max_inflight, 0);
	EXPECT_EQ(run.line.packets_accepted, 6);
	EXPECT_EQ(g_rx_summary.service_count, 0);
	/* A WRITE the kernel did not accept returns its frames. */
	EXPECT_FRAMES_RETIRED(&run, 6);
	rx_world_finish(&ctx, &state, &saved);
}

/* A complete group whose WRITE cannot even be prepared (here: outside the
 * authorized LBA window) is a write error; its packets stay accepted. */
static void test_rx_summary_unpreparable_write_is_a_write_error(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	ctx.io_limits.authorized_lbas = 8; /* one group needs sixteen */
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -EACCES);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(world.submitted, 0);
	EXPECT_EQ(world.rx_consumer, 6);
	EXPECT_EQ(run.line.packets_accepted, 6);
	EXPECT_EQ(run.line.packets_dropped, 0);
	EXPECT_EQ(run.line.write_errors, 1);
	EXPECT_EQ(run.line.groups, 0);
	EXPECT_EQ(run.line.nvme_cmds, 0);
	EXPECT_EQ(g_rx_summary.service_count, 0);
	/* A WRITE that could not be prepared returns its frames. */
	EXPECT_FRAMES_RETIRED(&run, 6);
	rx_world_finish(&ctx, &state, &saved);
}

static void test_rx_summary_protocol_error_counts_the_examined_packet(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	rx_world_phase(&world, 0, 0);
	rx_world_packet(&world, TEST_WIRE_SESSION, 1, 0, false);
	rx_world_packet(&world, TEST_WIRE_SESSION, 1, 1, true);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -EOPNOTSUPP);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(world.rx_consumer, 2);
	EXPECT_EQ(run.line.packets_accepted, 1);
	EXPECT_EQ(run.line.packets_dropped, 1);
	EXPECT_EQ(run.line.groups, 0);
	EXPECT_EQ(run.line.nvme_cmds, 0);
	EXPECT_EQ(g_rx_summary.service_count, 0);
	/* The rejected descriptor names no frame; the group's one frame is
	 * returned. */
	EXPECT_FRAMES_RETIRED(&run, 1);
	rx_world_finish(&ctx, &state, &saved);
}

/* A protocol error on a frame that is still RECEIVED, not yet held for a
 * WRITE: the clock read that begins the group of the first packet fails.
 * Clock reads in this run: 1 arms the idle deadline before the loop, 2 times
 * the first packet's arrival, 3 begins its group.  The packet was taken off
 * the ring and its frame marked received, but it was never accepted into the
 * group, so the group's recycle does not return it: the protocol-error path
 * drops the frame and counts it as returned.  The run fails with the clock's
 * error, prints one summary, and retires the one frame it received. */
static void test_rx_summary_protocol_error_returns_a_received_frame(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	state.monotonic_result = -EIO;
	state.monotonic_fail_after_call = 3;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -EIO);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(ctx.backing_quiescence_failed);
	EXPECT_EQ(world.submitted, 0);
	/* Only the first packet was examined, and it was not accepted. */
	EXPECT_EQ(world.rx_consumer, 1);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.packets_accepted, 0);
	EXPECT_EQ(run.line.packets_dropped, 1);
	EXPECT_EQ(run.line.groups, 0);
	EXPECT_EQ(run.line.nvme_cmds, 0);
	/* One protocol error: the clock failure.  A census that did not add
	 * up would count a second one. */
	EXPECT_EQ(ctx.stats.protocol_errors, 1);
	EXPECT_FRAMES_RETIRED(&run, 1);
	rx_world_finish(&ctx, &state, &saved);
}

/* ---- rx-write: packets that arrive while a WRITE is in flight ---- */

/* Group 2 arrives while group 1's WRITE is in flight and its CQE is held.
 * The loop must examine it, and read its arrival time, without waiting for
 * group 1's CQE: when that CQE is released, group 2's first-packet time is
 * already recorded and is no later than the release.  Each WRITE takes 50 ms
 * of device time, so group 2's service time includes the 50 ms it waited
 * behind group 1 plus its own 50 ms. */
static void test_rx_write_examines_packets_while_a_write_is_in_flight(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 2);
	world.hold_cqes = true;
	world.cqe_release_jump_ns = UINT64_C(50000000);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_wait_phase(&world, 1);
	rx_world_group(&world, 2, 0, 6);
	rx_world_run(&ctx, 2, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	EXPECT_EQ(world.next_phase, 2);
	EXPECT_EQ(world.held_next, 2);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_EQ(run.line.groups, 2);
	EXPECT_EQ(run.line.packets_accepted, 12);
	/* When group 1's CQE was released, both groups' clocks were armed,
	 * and the newer one (group 2's first packet) was no later than the
	 * release. */
	EXPECT_EQ(world.armed_at_release[0], 2);
	EXPECT_TRUE(world.newest_first_accept_at_release[0] > 0);
	EXPECT_TRUE(world.newest_first_accept_at_release[0] <=
		    world.release_ns[0]);
	/* Group 2 was submitted before group 1 completed. */
	EXPECT_EQ(run.line.max_inflight, 2);
	EXPECT_TRUE(run.line.group_service_us_p50 >= 50000);
	EXPECT_TRUE(run.line.group_service_us_p99 >= 100000);
	/* Each group's last packet arrived before its 50 ms WRITE ended. */
	EXPECT_TRUE(run.line.group_post_arrival_us_p50 >= 50000);
	EXPECT_ARRIVAL_FIELDS_CONSISTENT(&run);
	EXPECT_FRAMES_RETIRED(&run, 12);
	rx_world_finish(&ctx, &state, &saved);
}

/* Each WRITE completion has its own 100 ms bound (NXP_WAIT_TIMEOUT_NS), as
 * with the CQ-only wait used before the RX ring was watched: three groups at
 * depth 1, each WRITE taking 50 ms of device time.  Every WRITE completes
 * inside its bound, but the three waits together take 150 ms, so a bound that
 * is not re-armed after a reaped CQE fails the third wait and retains the DMA
 * backing although no WRITE was late. */
static void test_rx_write_completion_bound_is_per_write(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 3);
	world.hold_cqes = true;
	world.cqe_release_jump_ns = UINT64_C(50000000);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_group(&world, 2, 0, 6);
	rx_world_group(&world, 3, 0, 6);
	/* A run that fails here retains its backing (see the helper). */
	rx_world_run_retaining(&ctx, 3, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	/* At depth 1 the loop cannot take a packet while a WRITE is in
	 * flight, so each in-flight wait is the CQ-only one. */
	EXPECT_TRUE(state.wait_calls >= 3);
	EXPECT_EQ(state.event_wait_calls, 0);
	EXPECT_EQ(ctx.stats.wait_errors, 0);
	EXPECT_EQ(world.submitted, 3);
	EXPECT_EQ(world.held_next, 3);
	EXPECT_EQ(world.cq_head, 3);
	/* The waits together outlast one bound: the third WRITE completed at
	 * least 100 ms after the first. */
	EXPECT_TRUE(world.release_ns[0] > 0);
	EXPECT_TRUE(world.release_ns[2] >=
		    world.release_ns[0] + UINT64_C(100000000));
	EXPECT_FALSE(ctx.unmatched_io_retained);
	EXPECT_FALSE(ctx.backing_quiescence_failed);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_EQ(run.line.groups, 3);
	EXPECT_EQ(run.line.nvme_cmds, 3);
	EXPECT_EQ(run.line.write_errors, 0);
	EXPECT_FRAMES_RETIRED(&run, 18);
	rx_world_finish(&ctx, &state, &saved);
}

/* The XSK socket reports an error while group 1's WRITE is in flight: the
 * loop stops issuing and fails with that error, but it is not a completion
 * wait failure: the WRITE is still waited for and reaped, its backing is not
 * retained, and every frame is returned. */
static void test_rx_write_xsk_error_in_flight_stops_and_drains(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 2);
	world.hold_cqes = true;
	world.xsk_error_revents = POLLERR;
	world.xsk_error_on_wait = 1;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_group(&world, 2, 0, 3);
	rx_world_run(&ctx, 2, &run);

	EXPECT_EQ(run.ret, -EIO);
	EXPECT_EQ(world.submitted, 1);
	EXPECT_EQ(world.held_next, 1);
	EXPECT_EQ(world.cq_head, 1);
	EXPECT_EQ(ctx.stats.wait_errors, 0);
	EXPECT_FALSE(ctx.backing_quiescence_failed);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_FRAMES_RETIRED(&run, 9);
	rx_world_finish(&ctx, &state, &saved);
}

/* Frames still owned when the loop ends, with no defect in the loop: the
 * device never completes group 1's WRITE, so the bounded completion wait
 * times out.  pipeline_handle_wait_failure() retains the WRITE's DMA backing
 * and its six frames stay held for it.  The census reports them as
 * outstanding and fails closed (one more protocol error), and the run returns
 * the wait failure, which was latched first.  With one group requested the
 * loop cannot take another packet, so the wait is the CQ-only one; with two
 * it is the wait on the CQ notification and the XSK fd. */
static void test_rx_write_frames_held_by_a_failed_wait_fail_closed(int groups)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, (uint32_t)groups);
	world.hold_cqes = true;
	world.never_complete = true;
	/* Every clock read moves 1 ms, so the 100 ms bound runs out. */
	state.monotonic_step_ns = UINT64_C(1000000);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run_retaining(&ctx, groups, &run);

	EXPECT_EQ(run.ret, -ETIMEDOUT);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	EXPECT_EQ(world.submitted, 1);
	EXPECT_EQ(world.cq_head, 0);
	if (groups > 1) {
		EXPECT_TRUE(state.event_wait_calls > 0);
		EXPECT_EQ(state.wait_calls, 0);
	} else {
		EXPECT_TRUE(state.wait_calls > 0);
		EXPECT_EQ(state.event_wait_calls, 0);
	}
	/* The timeout went through the wait-failure handling: one wait error,
	 * and the WRITE's DMA backing retained, not unregistered. */
	EXPECT_EQ(ctx.stats.wait_errors, 1);
	EXPECT_TRUE(ctx.unmatched_io_retained);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_EQ(state.unregister_buffers_calls, 0);
	EXPECT_TRUE(ctx.uring.fixed_buffer_registered);
	/* The census found the six held frames and failed closed: one protocol
	 * error more than when the loop last waited. */
	EXPECT_EQ(world.protocol_errors_at_wait, 0);
	EXPECT_EQ(ctx.stats.protocol_errors, world.protocol_errors_at_wait + 1);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 0);
	EXPECT_EQ(run.line.nvme_cmds, 1);
	EXPECT_EQ(run.line.packets_accepted, 6);
	EXPECT_EQ(run.line.frames_received, 6);
	EXPECT_EQ(run.line.frames_returned, 0);
	EXPECT_EQ(run.line.frames_outstanding, 6);
	EXPECT_EQ(run.line.frames_received - run.line.frames_returned,
		  run.line.frames_outstanding);
	rx_world_finish(&ctx, &state, &saved);
}

/* A census that does not add up fails the run by itself: one group whose
 * WRITE completes normally, so no error is latched before the loop ends, but
 * the received-frame count is one too high (a counting defect, injected from
 * the completion wait).  The census finds 7 received against 6 returned and
 * none outstanding, counts one protocol error and latches -EPROTO; the summary
 * is still printed with the mismatch, and the run does not report success. */
static void test_rx_census_mismatch_alone_fails_the_run(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	world.hold_cqes = true;
	world.miscount_received = true;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -EPROTO);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	/* The defect was injected, and nothing else failed before the census:
	 * the WRITE completed and was reaped, with no wait error and no
	 * protocol error up to the last wait. */
	EXPECT_FALSE(world.miscount_received);
	EXPECT_EQ(world.submitted, 1);
	EXPECT_EQ(world.held_next, 1);
	EXPECT_EQ(world.cq_head, 1);
	EXPECT_EQ(ctx.stats.wait_errors, 0);
	EXPECT_FALSE(ctx.backing_quiescence_failed);
	EXPECT_EQ(world.protocol_errors_at_wait, 0);
	EXPECT_EQ(ctx.stats.protocol_errors, 1);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_EQ(run.line.nvme_cmds, 1);
	EXPECT_EQ(run.line.write_errors, 0);
	EXPECT_EQ(run.line.frames_received, 7);
	EXPECT_EQ(run.line.frames_returned, 6);
	EXPECT_EQ(run.line.frames_outstanding, 0);
	rx_world_finish(&ctx, &state, &saved);
}

/* ---- rx-write graceful stop ---- */

static unsigned int test_stop_handler_calls;

static void test_stop_fallback_handler(int signo)
{
	(void)signo;
	test_stop_handler_calls++;
}

/* SIGTERM or SIGINT while rx-write runs, mid-group: group 1's WRITE is in
 * flight (its CQE held) and group 2 has three of its six segments.  The
 * signal interrupts the bounded completion wait.  No WRITE is issued after
 * it, the in-flight one is reaped by the bounded wait, every frame is
 * returned, the summary is still printed, and the run fails with -EINTR.
 * The test's own handler stands in for the default action, so a run that
 * ignores the stop completes all three groups instead of ending the test. */
static void test_rx_write_stop_request_drains_and_returns_every_frame(int signo)
{
	struct sigaction fallback, previous, after;
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	memset(&fallback, 0, sizeof(fallback));
	fallback.sa_handler = test_stop_fallback_handler;
	sigemptyset(&fallback.sa_mask);
	EXPECT_EQ(sigaction(signo, &fallback, &previous), 0);
	test_stop_handler_calls = 0;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 3);
	world.hold_cqes = true;
	world.raise_signal = signo;
	world.raise_on_wait = 1;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_group(&world, 2, 0, 3);
	/* The rest arrives only after group 1's CQE was reaped. */
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 2, 3, 3);
	rx_world_group(&world, 3, 0, 6);
	rx_world_run(&ctx, 3, &run);

	EXPECT_EQ(run.ret, -EINTR);
	EXPECT_EQ(test_stop_handler_calls, 0); /* the run's handler took it */
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	/* No WRITE after the stop; the one in flight was waited for and
	 * reaped. */
	EXPECT_EQ(world.submitted, 1);
	EXPECT_EQ(world.held_next, 1);
	EXPECT_EQ(world.cq_head, 1);
	EXPECT_TRUE(world.waits >= 2);
	/* No packet was examined after the stop. */
	EXPECT_EQ(world.rx_consumer, 9);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_EQ(run.line.bytes_written, 8192);
	EXPECT_EQ(run.line.nvme_cmds, 1);
	EXPECT_EQ(run.line.write_errors, 0);
	EXPECT_EQ(run.line.packets_accepted, 9);
	EXPECT_EQ(run.line.packets_dropped, 0);
	/* Group 2's three frames are returned with group 1's six. */
	EXPECT_FRAMES_RETIRED(&run, 9);
	/* The run put back the disposition it found. */
	EXPECT_EQ(sigaction(signo, NULL, &after), 0);
	EXPECT_TRUE(after.sa_handler == test_stop_fallback_handler);
	rx_world_finish(&ctx, &state, &saved);
	EXPECT_EQ(sigaction(signo, &previous, NULL), 0);
}

/* The stop arrives after the loop-top check, while the loop examines a batch
 * that completes group 2 with group 1's WRITE in flight (its CQE held): the
 * clock read that times group 2's first packet raises the signal.  The batch
 * is still examined, but group 2's prepared WRITE is withdrawn before
 * submission and its six frames are returned; group 1's WRITE is waited for
 * and reaped, and the run fails with -EINTR. */
static void test_rx_write_stop_during_a_batch_issues_no_prepared_write(
	int signo)
{
	struct sigaction fallback, previous, after;
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	memset(&fallback, 0, sizeof(fallback));
	fallback.sa_handler = test_stop_fallback_handler;
	sigemptyset(&fallback.sa_mask);
	EXPECT_EQ(sigaction(signo, &fallback, &previous), 0);
	test_stop_handler_calls = 0;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 2);
	world.hold_cqes = true;
	world.batch_signal = signo;
	world.batch_signal_after_submitted = 1;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	/* Group 2 arrives once group 1's WRITE was issued. */
	rx_world_phase(&world, 0, 1);
	rx_world_group(&world, 2, 0, 6);
	rx_world_run(&ctx, 2, &run);

	EXPECT_EQ(run.ret, -EINTR);
	EXPECT_EQ(test_stop_handler_calls, 0); /* the run's handler took it */
	EXPECT_TRUE(world.batch_signal_raised);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	EXPECT_EQ(world.next_phase, 2);
	/* The batch the signal arrived in was examined to its end ... */
	EXPECT_EQ(world.rx_consumer, 12);
	/* ... but no WRITE was issued after the stop; group 1's was waited
	 * for and reaped. */
	EXPECT_EQ(world.submitted, 1);
	EXPECT_EQ(world.held_next, 1);
	EXPECT_EQ(world.cq_head, 1);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_EQ(run.line.nvme_cmds, 1);
	EXPECT_EQ(run.line.bytes_written, 8192);
	/* A WRITE withdrawn because of the stop was never issued: it is not a
	 * write error. */
	EXPECT_EQ(run.line.write_errors, 0);
	EXPECT_EQ(run.line.packets_accepted, 12);
	EXPECT_EQ(run.line.packets_dropped, 0);
	/* Group 2's six frames are returned with group 1's six. */
	EXPECT_FRAMES_RETIRED(&run, 12);
	EXPECT_EQ(sigaction(signo, NULL, &after), 0);
	EXPECT_TRUE(after.sa_handler == test_stop_fallback_handler);
	rx_world_finish(&ctx, &state, &saved);
	EXPECT_EQ(sigaction(signo, &previous, NULL), 0);
}

/* A stop drain with packets waiting on the RX ring: SIGTERM interrupts the
 * first completion wait, with group 1's WRITE in flight (its CQE held), and
 * the packets of groups 2 and 3 reach the RX ring during the following wait.
 * A stopping loop takes no packet, so the drain must wait for group 1's CQE
 * alone: it must not return for RX it will not examine.  A drain that did
 * would never wait for the CQE and would run into the completion bound, fail
 * the wait and retain the WRITE's DMA backing.  The packets of groups 2 and 3
 * stay on the ring, unexamined.  Every requested group is delivered, so a run
 * that ignored the stop would complete all three (and fail the checks below)
 * instead of waiting for traffic that never comes. */
static void test_rx_write_stop_drain_waits_for_the_cqe_not_for_rx(void)
{
	struct sigaction fallback, previous, after;
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	memset(&fallback, 0, sizeof(fallback));
	fallback.sa_handler = test_stop_fallback_handler;
	sigemptyset(&fallback.sa_mask);
	EXPECT_EQ(sigaction(SIGTERM, &fallback, &previous), 0);
	test_stop_handler_calls = 0;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 3);
	world.hold_cqes = true;
	world.raise_signal = SIGTERM;
	world.raise_on_wait = 1;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	/* Groups 2 and 3 reach the ring inside a completion wait after the
	 * stop, with group 1's WRITE still in flight. */
	rx_world_wait_phase(&world, 1);
	rx_world_group(&world, 2, 0, 6);
	rx_world_group(&world, 3, 0, 6);
	rx_world_run(&ctx, 3, &run);

	EXPECT_EQ(run.ret, -EINTR);
	EXPECT_EQ(test_stop_handler_calls, 0); /* the run's handler took it */
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	/* Groups 2 and 3 were on the ring during the drain ... */
	EXPECT_EQ(world.next_phase, 2);
	EXPECT_EQ(world.rx_producer, 18);
	/* ... and were not examined. */
	EXPECT_EQ(world.rx_consumer, 6);
	/* The drain waited for the in-flight WRITE and reaped its CQE, with no
	 * wait failure and no DMA backing retained. */
	EXPECT_EQ(world.submitted, 1);
	EXPECT_EQ(world.held_next, 1);
	EXPECT_EQ(world.cq_head, 1);
	EXPECT_EQ(ctx.stats.wait_errors, 0);
	EXPECT_FALSE(ctx.unmatched_io_retained);
	EXPECT_FALSE(ctx.backing_quiescence_failed);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_EQ(run.line.nvme_cmds, 1);
	EXPECT_EQ(run.line.write_errors, 0);
	EXPECT_EQ(run.line.packets_accepted, 6);
	EXPECT_FRAMES_RETIRED(&run, 6);
	EXPECT_EQ(sigaction(SIGTERM, NULL, &after), 0);
	EXPECT_TRUE(after.sa_handler == test_stop_fallback_handler);
	rx_world_finish(&ctx, &state, &saved);
	EXPECT_EQ(sigaction(SIGTERM, &previous, NULL), 0);
}

/* A signal that was ignored when rx-write started stays ignored (a
 * background job started without job control has SIGINT ignored): it neither
 * stops the run nor is replaced by the stop handler.  The signal is raised in
 * the first completion wait, while group 1's WRITE is in flight and groups 2
 * and 3 have not arrived yet (they arrive only after group 1's CQE was
 * reaped), so a run that took the signal as a stop would issue no further
 * WRITE and end with -EINTR after one group. */
static void test_rx_write_leaves_an_ignored_signal_ignored(void)
{
	struct sigaction ignore, previous, after;
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	memset(&ignore, 0, sizeof(ignore));
	ignore.sa_handler = SIG_IGN;
	sigemptyset(&ignore.sa_mask);
	EXPECT_EQ(sigaction(SIGINT, &ignore, &previous), 0);

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 3);
	world.hold_cqes = true;
	world.raise_signal = SIGINT;
	world.raise_on_wait = 1;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	/* The rest arrives only after group 1's CQE was reaped. */
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 2, 0, 6);
	rx_world_group(&world, 3, 0, 6);
	rx_world_run(&ctx, 3, &run);

	EXPECT_EQ(run.ret, 0);
	EXPECT_FALSE(world.delivery_failed);
	EXPECT_FALSE(world.foreign_sqe);
	/* The signal was raised, and groups 2 and 3 arrived after it. */
	EXPECT_TRUE(world.waits >= world.raise_on_wait);
	EXPECT_EQ(world.next_phase, 2);
	/* Every group was issued, written and reaped. */
	EXPECT_EQ(world.submitted, 3);
	EXPECT_EQ(world.held_next, 3);
	EXPECT_EQ(world.cq_head, 3);
	EXPECT_EQ(world.rx_consumer, 18);
	EXPECT_EQ(run.summaries, 1);
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 3);
	EXPECT_EQ(run.line.nvme_cmds, 3);
	EXPECT_EQ(run.line.bytes_written, 3 * 8192);
	EXPECT_EQ(run.line.write_errors, 0);
	EXPECT_FRAMES_RETIRED(&run, 18);
	EXPECT_EQ(sigaction(SIGINT, NULL, &after), 0);
	EXPECT_TRUE(after.sa_handler == SIG_IGN);
	rx_world_finish(&ctx, &state, &saved);
	EXPECT_EQ(sigaction(SIGINT, &previous, NULL), 0);
}

/* SIGTERM and SIGINT start at the default action, as in production. */
static void test_stop_signals_default(struct sigaction previous[2])
{
	struct sigaction dfl;

	memset(&dfl, 0, sizeof(dfl));
	dfl.sa_handler = SIG_DFL;
	sigemptyset(&dfl.sa_mask);
	for (int i = 0; i < 2; i++)
		EXPECT_EQ(sigaction(test_stop_signals[i], &dfl, &previous[i]),
			  0);
}

/* After a run that retained DMA backing, neither signal may have the
 * default action back: main() still detaches the redirect program and
 * prepares cleanup before pipeline_hold_unquiesced_backing() ignores them,
 * and a signal that terminated the process in that window would close the
 * fds and unmap the UMEM that may still be the source of an unproven NVMe
 * WRITE.  The run ignores them until the hold takes over.  A macro, so that
 * a failure names the calling test; it checks the dispositions the run left
 * (recorded by rx_world_run_retaining()) and puts back the test's own. */
#define EXPECT_STOP_SIGNALS_IGNORED(run, previous) do {                     \
	for (int _i = 0; _i < 2; _i++) {                                       \
		EXPECT_TRUE((run).stop_after[_i].sa_handler != SIG_DFL);       \
		EXPECT_TRUE((run).stop_after[_i].sa_handler == SIG_IGN);       \
		EXPECT_EQ(sigaction(test_stop_signals[_i], &(previous)[_i],    \
				    NULL), 0);                                 \
	}                                                                      \
} while (0)

/* The WRITE never completes: the bounded wait fails, the WRITE's backing is
 * retained and main() would hold the process. */
static void test_rx_write_retained_backing_keeps_stop_signals_ignored(void)
{
	struct sigaction previous[2];
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	test_stop_signals_default(previous);
	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 2, 1);
	world.hold_cqes = true;
	world.never_complete = true;
	/* Every clock read moves 1 ms, so the 100 ms bound runs out. */
	state.monotonic_step_ns = UINT64_C(1000000);
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run_retaining(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -ETIMEDOUT);
	EXPECT_EQ(world.submitted, 1);
	EXPECT_TRUE(ctx.unmatched_io_retained);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_FALSE(pipeline_can_destroy_xsk(&ctx));
	EXPECT_EQ(run.summaries, 1);
	EXPECT_STOP_SIGNALS_IGNORED(run, previous);
	rx_world_finish(&ctx, &state, &saved);
}

/* The decision follows the run's own buffer unregistration: every WRITE
 * completed, but the unregistration that would end the kernel's use of the
 * UMEM-backed vectors fails, so the backing is retained all the same. */
static void test_rx_write_failed_unregister_keeps_stop_signals_ignored(void)
{
	struct sigaction previous[2];
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	test_stop_signals_default(previous);
	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	state.unregister_buffers_result = -EIO;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run_retaining(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -EIO);
	EXPECT_EQ(world.submitted, 1);
	EXPECT_EQ(world.cq_head, 1);
	EXPECT_EQ(state.unregister_buffers_calls, 1);
	EXPECT_FALSE(ctx.unmatched_io_retained);
	EXPECT_TRUE(ctx.backing_quiescence_failed);
	EXPECT_FALSE(pipeline_can_destroy_xsk(&ctx));
	EXPECT_TRUE(run.parsed);
	EXPECT_EQ(run.line.groups, 1);
	EXPECT_STOP_SIGNALS_IGNORED(run, previous);
	rx_world_finish(&ctx, &state, &saved);
}

static void test_rx_summary_is_not_printed_when_setup_fails(void)
{
	struct fake_adapter_state state;
	struct fake_rx_world world;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	struct rx_run run;

	rx_globals_save(&saved);
	rx_world_init(&ctx, &state, &world, 1, 1);
	fake_register_buffers_result = -ENOMEM;
	rx_world_phase(&world, 0, 0);
	rx_world_group(&world, 1, 0, 6);
	rx_world_run(&ctx, 1, &run);

	EXPECT_EQ(run.ret, -ENOMEM);
	EXPECT_EQ(fake_register_buffers_calls, 1);
	EXPECT_EQ(run.summaries, 0);
	EXPECT_FALSE(run.parsed);
	EXPECT_EQ(world.rx_consumer, 0);
	rx_world_finish(&ctx, &state, &saved);
}

/* TX mode never prints the line, also when its loop fails. */
static void test_rx_summary_is_not_printed_in_tx_mode(void)
{
	struct fake_adapter_state state;
	struct stdout_capture capture;
	struct pipeline_ctx ctx;
	struct rx_globals saved;
	uint64_t cq_entries[2] = { 0 };
	uint32_t cq_producer = 0, cq_consumer = 0;
	char output[4096];
	bool captured;
	int ret;

	rx_globals_save(&saved);
	init_fake_ctx(&ctx, &state);
	ctx.mtu = 1500;
	ctx.xsk.xsk_fd = -1;
	ctx.xsk.umem_area = calloc(1, UMEM_SIZE);
	EXPECT_TRUE(ctx.xsk.umem_area != NULL);
	setup_fake_cq(&ctx, cq_entries, 0, &cq_producer, &cq_consumer);
	state.peek_result = -EAGAIN;
	g_block_size = 8192;
	g_depth = 1;
	g_direction = PIPELINE_NVME_TO_NIC;
	g_staging = 0;
	g_iopoll = 0;
	fake_register_buffers_result = 0;
	fake_register_buffers_calls = 0;

	captured = capture_stdout_begin(&capture);
	EXPECT_TRUE(captured);
	/* The namespace was never proven, so the first NVMe READ cannot be
	 * planned: the TX loop starts and fails. */
	ret = run_vector_tx_pipeline(&ctx, 0, 1);
	if (captured)
		capture_stdout_end(&capture, output, sizeof(output));
	else
		output[0] = '\0';
	EXPECT_TRUE(ret < 0);
	EXPECT_EQ(fake_register_buffers_calls, 1);
	EXPECT_TRUE(state.peek_calls > 0); /* the loop ran */
	EXPECT_EQ(count_occurrences(output, "PIPELINE_RX_SUMMARY"), 0);
	free(ctx.xsk.umem_area);
	rx_globals_restore(&saved);
}

/* A test that ends with SIGTERM or SIGINT at a different disposition than it
 * found leaves every later test unable to be stopped by the kselftest
 * runner's timeout. */
static void expect_stop_signals_unchanged(const struct sigaction found[2],
					  const char *after_test)
{
	for (int i = 0; i < 2; i++) {
		struct sigaction now;

		EXPECT_EQ(sigaction(i ? SIGINT : SIGTERM, NULL, &now), 0);
		if (now.sa_handler != found[i].sa_handler)
			fprintf(stderr, "%s left signal %d at a new disposition\n",
				after_test, i ? SIGINT : SIGTERM);
		EXPECT_TRUE(now.sa_handler == found[i].sa_handler);
	}
}

int main(void)
{
	struct sigaction stop_found[2];

	EXPECT_EQ(sigaction(SIGTERM, NULL, &stop_found[0]), 0);
	EXPECT_EQ(sigaction(SIGINT, NULL, &stop_found[1]), 0);
	test_default_8k_transfer_is_six_mtu_packets_and_depth_bounded();
	test_transform_defaults_to_identity_and_xor_is_explicit();
	test_rx_write_rejects_sender_only_transform();
	test_8k_staging_scatters_one_nvme_buffer_into_six_frames();
	test_final_revalidation_precedes_publication();
	test_revalidate_every_thins_submit_revalidation();
	test_revalidate_every_option();
	test_fixed_sqe_fields_are_independent();
	test_vector_sqe_is_one_fixed_registered_nvme_command();
	test_wire_packet_builder_and_strict_receiver_share_real_bytes();
	test_prepare_8k_tx_group_owns_six_frames_and_one_sqe();
	test_tx_group_publishes_six_descriptors_and_reclaims_each_once();
	test_fatal_completion_aborts_every_private_vector_frame();
	test_out_of_order_nvme_completions_wait_for_wire_generation();
	test_out_of_order_nvme_completions_publish_wire_in_order();
	test_ordered_publisher_reports_committed_prefix_on_tail_error();
	test_rx_write_uses_local_group_index_not_wire_addressing();
	test_rx_qd2_batches_six_frame_groups_and_reaps_out_of_order();
	test_external_rx_drop_and_partial_group_timeout_are_recoverable();
	test_fixed_vector_rejects_unregistered_unaligned_and_outside_umem();
	test_rx_fill_ring_walks_each_free_frame_once_in_order();
	test_rx_descriptor_layout_keeps_vector_payload_aligned();
	test_iopoll_refusal_precedes_ring_init();
	test_extended_layout_gate_and_correct_stride();
	test_init_and_unregister_failures_are_terminal();
	test_cleanup_refuses_backing_release_after_close_failure();
	test_chain_sequester_latch_survives_successful_ring_close();
	test_stale_then_exact_and_lost_attribution_teardown();
	test_failed_quiescence_never_releases_dma_backing();
	test_successful_async_close_is_not_a_dma_proof();
	test_wait_errors_are_bounded();
	test_rx_wait_deadline_survives_rx_wakeups();
	test_rx_wait_returns_on_a_cqe_and_fails_like_the_cq_wait();
	test_rx_wait_finds_a_cqe_without_a_notification();
	test_rx_wait_reports_an_xsk_error_apart();
	test_rx_wait_without_watch_is_the_cq_only_wait();
	test_rx_wait_iopoll_checks_rx_between_steps();
	test_production_wait_cqe_or_rx_on_an_eventfd_and_a_pipe();
	test_iopoll_step_and_monotonic_deadline_retain_backing();
	test_production_fault_steps_drive_retention_and_stop();
	test_fatal_cqe_drains_later_exact_without_tx_publish();
	test_submit_adapter_full_short_fatal_and_bounded_retry();
	test_pre_submit_frame_cannot_be_reclaimed_by_cq();
	test_xsk_bad_and_duplicate_completions_latch_protocol_error();
	test_unreclaimed_xsk_tx_retains_umem();
	test_fake_sysfs_sibling_resolution_and_identify_decode();
	test_rx_summary_success_line_describes_the_run();
	test_rx_summary_failed_write_is_an_error_not_a_sample();
	test_rx_summary_idle_timeout_prints_one_empty_line();
	test_rx_summary_expired_group_is_never_sampled();
	test_rx_summary_clocks_start_at_the_defined_packets();
	test_rx_summary_service_time_starts_at_first_accepted_packet();
	test_rx_summary_service_time_is_per_group();
	test_rx_summary_receive_span_ends_at_the_last_group_packet();
	test_rx_write_leaves_unconsumed_descriptors_on_the_ring();
	test_rx_summary_max_inflight_reaches_but_never_exceeds_depth();
	test_rx_summary_unaccepted_submission_is_a_write_error();
	test_rx_summary_unpreparable_write_is_a_write_error();
	test_rx_summary_protocol_error_counts_the_examined_packet();
	test_rx_summary_protocol_error_returns_a_received_frame();
	test_rx_summary_is_not_printed_when_setup_fails();
	test_rx_summary_is_not_printed_in_tx_mode();
	test_rx_write_examines_packets_while_a_write_is_in_flight();
	test_rx_write_completion_bound_is_per_write();
	expect_stop_signals_unchanged(stop_found,
				      "test_rx_write_completion_bound_is_per_write");
	test_rx_write_xsk_error_in_flight_stops_and_drains();
	test_rx_write_frames_held_by_a_failed_wait_fail_closed(1);
	test_rx_write_frames_held_by_a_failed_wait_fail_closed(2);
	expect_stop_signals_unchanged(stop_found,
				      "test_rx_write_frames_held_by_a_failed_wait_fail_closed");
	test_rx_census_mismatch_alone_fails_the_run();
	test_rx_write_stop_request_drains_and_returns_every_frame(SIGTERM);
	test_rx_write_stop_request_drains_and_returns_every_frame(SIGINT);
	test_rx_write_stop_during_a_batch_issues_no_prepared_write(SIGTERM);
	test_rx_write_stop_during_a_batch_issues_no_prepared_write(SIGINT);
	test_rx_write_stop_drain_waits_for_the_cqe_not_for_rx();
	test_rx_write_leaves_an_ignored_signal_ignored();
	test_rx_write_retained_backing_keeps_stop_signals_ignored();
	test_rx_write_failed_unregister_keeps_stop_signals_ignored();
	expect_stop_signals_unchanged(stop_found, "the signal tests");

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return 1;
	}
	printf("PASS: %u adapter checks\n", checks);
	return 0;
}
