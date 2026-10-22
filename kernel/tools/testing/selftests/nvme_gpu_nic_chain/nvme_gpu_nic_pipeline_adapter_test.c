// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XDEV_EXT_NVME_GPU_NIC_CHAIN
#define main nvme_gpu_nic_pipeline_program_main
#include "../../../../nvme_xdp_pipeline.c"
#undef main

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                    \
	long long _actual = (long long)(actual);                              \
	long long _expected = (long long)(expected);                          \
	checks++;                                                             \
	if (_actual != _expected) {                                           \
		fprintf(stderr, "%s:%d: got %lld, expected %lld\n",            \
			__func__, __LINE__, _actual, _expected);                    \
		failures++;                                                       \
	}                                                                      \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

struct fake_gpu_state {
	unsigned int calls;
	enum ngn_gpu_direction direction[4];
	uint32_t count[4];
	uint32_t completed[4];
	int result[4];
	bool ambiguous[4];
};

static struct fake_gpu_state fake_gpu;

int ngn_gpu_runtime_init(struct ngn_gpu_runtime *runtime,
			 const char *gpu_device, int xsk_fd, void *umem,
			 size_t umem_bytes, uint32_t frame_size)
{
	(void)runtime;
	(void)gpu_device;
	(void)xsk_fd;
	(void)umem;
	(void)umem_bytes;
	(void)frame_size;
	return -EOPNOTSUPP;
}

int ngn_gpu_runtime_submit(void *opaque, enum ngn_gpu_direction direction,
			   const struct ngn_gpu_transfer *transfers,
			   uint32_t count, uint32_t *completed,
			   bool *ambiguous)
{
	struct ngn_gpu_runtime *runtime = opaque;
	unsigned int call = fake_gpu.calls++;

	EXPECT_TRUE(runtime != NULL);
	EXPECT_TRUE(transfers != NULL);
	EXPECT_TRUE(call < 4);
	fake_gpu.direction[call] = direction;
	fake_gpu.count[call] = count;
	*completed = fake_gpu.completed[call];
	*ambiguous = fake_gpu.ambiguous[call];
	if (*ambiguous)
		runtime->sequestered = true;
	return fake_gpu.result[call];
}

int ngn_gpu_runtime_cleanup(struct ngn_gpu_runtime *runtime)
{
	return runtime ? 0 : -EINVAL;
}

static void init_context(struct pipeline_ctx *ctx, void *umem)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->gpu = (struct ngn_gpu_runtime)NGN_GPU_RUNTIME_INIT;
	ctx->gpu_enabled = true;
	ctx->chain_id = UINT64_C(0x12345678);
	ctx->xsk.umem_area = umem;
}

static void init_slot(struct inflight_slot *slot, void *umem)
{
	memset(slot, 0, sizeof(*slot));
	slot->segment_count = 2;
	slot->frame_addr = 0;
	slot->frame_addrs[0] = 0;
	slot->frame_addrs[1] = 3 * FRAME_SIZE;
	slot->vector[0] = (struct iovec) {
		.iov_base = (unsigned char *)umem + NXP_DATA_OFFSET,
		.iov_len = 512,
	};
	slot->vector[1] = (struct iovec) {
		.iov_base = (unsigned char *)umem + 3 * FRAME_SIZE +
			NXP_DATA_OFFSET,
		.iov_len = 768,
	};
}

static void fake_gpu_full_success(void)
{
	memset(&fake_gpu, 0, sizeof(fake_gpu));
	fake_gpu.completed[0] = 2;
	fake_gpu.completed[1] = 2;
}

static void test_forward_journal_moves_to_exact_tx_completion(void *umem)
{
	struct pipeline_ctx ctx;
	struct inflight_slot slot;

	init_context(&ctx, umem);
	init_slot(&slot, umem);
	fake_gpu_full_success();
	g_direction = PIPELINE_NVME_TO_NIC;

	EXPECT_EQ(pipeline_chain_begin_tx(&ctx, &slot, 7, 11), 0);
	EXPECT_EQ(pipeline_chain_nvme_accept(&ctx, &slot), 0);
	EXPECT_EQ(pipeline_chain_nvme_complete(&ctx, &slot), 0);
	EXPECT_EQ(pipeline_chain_gpu_roundtrip(&ctx, &slot), 0);
	EXPECT_EQ(fake_gpu.calls, 2);
	EXPECT_EQ(fake_gpu.direction[0], NGN_GPU_UMEM_TO_GPU);
	EXPECT_EQ(fake_gpu.direction[1], NGN_GPU_GPU_TO_UMEM);
	EXPECT_EQ(fake_gpu.count[0], 2);
	EXPECT_EQ(fake_gpu.count[1], 2);
	EXPECT_EQ(pipeline_chain_publish_tx(&ctx, &slot), 0);
	EXPECT_FALSE(slot.chain_journals[0].owns_backing);
	EXPECT_FALSE(slot.chain_journals[1].owns_backing);
	EXPECT_EQ(ctx.xsk.chain_frames[0].stage,
		  NGN_STAGE_SINK_ACCEPTED);
	EXPECT_EQ(ctx.xsk.chain_frames[3].stage,
		  NGN_STAGE_SINK_ACCEPTED);
	EXPECT_EQ(pipeline_chain_tx_complete(&ctx, 3 * FRAME_SIZE), 0);
	EXPECT_FALSE(ctx.xsk.chain_frames[3].owns_backing);
	EXPECT_TRUE(ctx.xsk.chain_frames[0].owns_backing);
	EXPECT_EQ(pipeline_chain_tx_complete(&ctx, 0), 0);
	EXPECT_FALSE(ctx.xsk.chain_frames[0].owns_backing);
	EXPECT_EQ(pipeline_chain_tx_complete(&ctx, 0), -EALREADY);
}

static void test_reverse_journal_ends_only_at_nvme_cqe(void *umem)
{
	struct pipeline_ctx ctx;
	struct inflight_slot slot;

	init_context(&ctx, umem);
	init_slot(&slot, umem);
	fake_gpu_full_success();
	g_direction = PIPELINE_NIC_TO_NVME;

	for (uint16_t i = 0; i < slot.segment_count; i++)
		EXPECT_EQ(pipeline_chain_begin_rx_frame(
			&ctx, &slot, i, 19, 23, slot.frame_addrs[i]), 0);
	EXPECT_EQ(pipeline_chain_gpu_roundtrip(&ctx, &slot), 0);
	EXPECT_EQ(pipeline_chain_nvme_accept(&ctx, &slot), 0);
	for (uint16_t i = 0; i < slot.segment_count; i++) {
		EXPECT_EQ(slot.chain_journals[i].stage,
			  NGN_STAGE_SINK_ACCEPTED);
		EXPECT_TRUE(slot.chain_journals[i].owns_backing);
	}
	EXPECT_EQ(pipeline_chain_nvme_complete(&ctx, &slot), 0);
	for (uint16_t i = 0; i < slot.segment_count; i++) {
		EXPECT_EQ(slot.chain_journals[i].stage, NGN_STAGE_COMPLETE);
		EXPECT_FALSE(slot.chain_journals[i].owns_backing);
	}
}

static void test_ambiguous_ce_failure_sequesters_without_retry(void *umem)
{
	struct pipeline_ctx ctx;
	struct inflight_slot slot;

	init_context(&ctx, umem);
	init_slot(&slot, umem);
	memset(&fake_gpu, 0, sizeof(fake_gpu));
	fake_gpu.completed[0] = 1;
	fake_gpu.result[0] = -ETIMEDOUT;
	fake_gpu.ambiguous[0] = true;
	g_direction = PIPELINE_NVME_TO_NIC;

	EXPECT_EQ(pipeline_chain_begin_tx(&ctx, &slot, 29, 31), 0);
	EXPECT_EQ(pipeline_chain_nvme_accept(&ctx, &slot), 0);
	EXPECT_EQ(pipeline_chain_nvme_complete(&ctx, &slot), 0);
	EXPECT_EQ(pipeline_chain_gpu_roundtrip(&ctx, &slot), -ETIMEDOUT);
	EXPECT_EQ(fake_gpu.calls, 1);
	EXPECT_TRUE(ctx.gpu.sequestered);
	EXPECT_TRUE(ctx.chain_sequestered);
	EXPECT_TRUE(ctx.xsk.protocol_invalidated);
	EXPECT_FALSE(pipeline_can_destroy_xsk(&ctx));
	for (uint16_t i = 0; i < slot.segment_count; i++) {
		EXPECT_EQ(slot.chain_journals[i].stage,
			  NGN_STAGE_SEQUESTERED);
		EXPECT_TRUE(slot.chain_journals[i].owns_backing);
	}
	EXPECT_EQ(pipeline_chain_abort_slot(&ctx, &slot), -EBUSY);
	EXPECT_EQ(fake_gpu.calls, 1);
}

int main(void)
{
	void *umem = aligned_alloc(FRAME_SIZE, UMEM_SIZE);

	if (!umem) {
		perror("aligned_alloc");
		return 1;
	}
	memset(umem, 0, UMEM_SIZE);
	test_forward_journal_moves_to_exact_tx_completion(umem);
	test_reverse_journal_ends_only_at_nvme_cqe(umem);
	test_ambiguous_ce_failure_sequesters_without_retry(umem);
	free(umem);

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u composite adapter checks failed\n",
			failures, checks);
		return 1;
	}
	printf("PASS: %u composite pipeline adapter checks\n", checks);
	return 0;
}
