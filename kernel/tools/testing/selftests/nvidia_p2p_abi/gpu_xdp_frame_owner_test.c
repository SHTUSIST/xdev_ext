// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "../../../../drivers/gpu/nvidia-p2p/samples/gpu_xdp_frame_runtime.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(expected, actual) do {                                    \
	long long expected_ = (long long)(expected);                           \
	long long actual_ = (long long)(actual);                               \
	checks++;                                                              \
	if (expected_ != actual_) {                                            \
		fprintf(stderr, "%s:%d expected %lld, got %lld\n",             \
			__FILE__, __LINE__, expected_, actual_);                    \
		failures++;                                                       \
	}                                                                      \
} while (0)

static void test_rx_tx_requires_completion_before_reuse(void)
{
	uint8_t states[4];
	struct xdev_ext_xsk_frame_owner owner;

	EXPECT_EQ(0, xdev_ext_xsk_frame_owner_init(&owner, states, 4, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_from_rx(&owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_tx(&owner, 0));
	EXPECT_EQ(-EBUSY, xdev_ext_xsk_frame_to_fill(&owner, 0));
	EXPECT_EQ(-EBUSY, xdev_ext_xsk_frame_drop_rx(&owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_complete_tx(&owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&owner, 0));
}

static void test_drop_can_recycle_without_tx(void)
{
	uint8_t states[2];
	struct xdev_ext_xsk_frame_owner owner;

	EXPECT_EQ(0, xdev_ext_xsk_frame_owner_init(&owner, states, 2, 2048));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&owner, 2048));
	EXPECT_EQ(0, xdev_ext_xsk_frame_from_rx(&owner, 2048));
	EXPECT_EQ(0, xdev_ext_xsk_frame_drop_rx(&owner, 2048));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[1]);
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&owner, 2048));
}

static void test_wrong_generation_and_bad_addresses_fail_closed(void)
{
	uint8_t states[2];
	struct xdev_ext_xsk_frame_owner owner;

	EXPECT_EQ(0, xdev_ext_xsk_frame_owner_init(&owner, states, 2, 4096));
	EXPECT_EQ(-EINVAL, xdev_ext_xsk_frame_to_fill(&owner, 1));
	EXPECT_EQ(-ERANGE, xdev_ext_xsk_frame_to_fill(&owner, 8192));
	EXPECT_EQ(-EPROTO, xdev_ext_xsk_frame_from_rx(&owner, 0));
	EXPECT_EQ(-EPROTO, xdev_ext_xsk_frame_complete_tx(&owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&owner, 0));
	EXPECT_EQ(-EBUSY, xdev_ext_xsk_frame_to_fill(&owner, 0));
	EXPECT_EQ(-EPROTO, xdev_ext_xsk_frame_complete_tx(&owner, 0));
}

static void test_independent_frames_and_reset(void)
{
	uint8_t states[3];
	struct xdev_ext_xsk_frame_owner owner;

	EXPECT_EQ(0, xdev_ext_xsk_frame_owner_init(&owner, states, 3, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&owner, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_frame_from_rx(&owner, 4096));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FILL, states[0]);
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_RX, states[1]);
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[2]);
	xdev_ext_xsk_frame_owner_reset(&owner);
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[0]);
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[1]);
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[2]);
}

static void test_uncertain_gpu_dma_sequesters_frame(void)
{
	uint8_t states[2];
	struct xdev_ext_xsk_frame_owner owner;

	EXPECT_EQ(0, xdev_ext_xsk_frame_owner_init(&owner, states, 2, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_from_rx(&owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_sequester_rx(&owner, 0));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_SEQUESTERED, states[0]);
	EXPECT_EQ(-EBUSY, xdev_ext_xsk_frame_to_fill(&owner, 0));
	EXPECT_EQ(-EBUSY, xdev_ext_xsk_frame_drop_rx(&owner, 0));
	EXPECT_EQ(-EPROTO, xdev_ext_xsk_frame_to_tx(&owner, 0));
	EXPECT_EQ(-EPROTO, xdev_ext_xsk_frame_complete_tx(&owner, 0));
}

static void test_rx_descriptor_options_fail_closed_and_recycle(void)
{
	uint64_t recycle_entries[2];
	uint64_t expected_tx_addrs[2];
	uint8_t states[2];
	struct gpu_xdp_frame_runtime runtime;
	struct xdp_desc desc = {
		.addr = 0,
		.len = 64,
		/* XDP_PKT_CONTD is bit 0; older installed UAPI headers omit the name. */
		.options = 1U,
	};
	uint64_t frame_base = UINT64_MAX;
	uint64_t data_offset = UINT64_MAX;
	uint64_t recycled = UINT64_MAX;

	EXPECT_EQ(0, gpu_xdp_frame_runtime_init(&runtime, states,
					       recycle_entries,
					       expected_tx_addrs, 2, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&runtime.owner, 0));
	EXPECT_EQ(-EOPNOTSUPP,
		  gpu_xdp_frame_accept_rx(&runtime, &desc, 8192,
					  &frame_base, &data_offset));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[0]);
	EXPECT_EQ(1, runtime.recycle.count);
	EXPECT_EQ(0, xdev_ext_xsk_recycle_peek(&runtime.recycle, 0, &recycled));
	EXPECT_EQ(0, recycled);
}

static void test_aligned_rx_data_address_maps_to_owning_frame(void)
{
	uint64_t recycle_entries[2];
	uint64_t expected_tx_addrs[2];
	uint8_t states[2];
	struct gpu_xdp_frame_runtime runtime;
	struct xdp_desc desc = {
		/* Aligned UMEM RX descriptors include the XDP data headroom. */
		.addr = 4096 + 256,
		.len = 64,
		.options = 0,
	};
	uint64_t frame_base = UINT64_MAX;
	uint64_t data_offset = UINT64_MAX;

	EXPECT_EQ(0, gpu_xdp_frame_runtime_init(&runtime, states,
					       recycle_entries,
					       expected_tx_addrs, 2, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&runtime.owner, 4096));
	EXPECT_EQ(0, gpu_xdp_frame_accept_rx(&runtime, &desc, 8192,
						  &frame_base, &data_offset));
	EXPECT_EQ(4096, frame_base);
	EXPECT_EQ(4096 + 256, data_offset);
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_RX, states[1]);
}

static void test_aligned_tx_completion_maps_to_owning_frame(void)
{
	uint64_t recycle_entries[2];
	uint64_t expected_tx_addrs[2];
	uint64_t completions[2] = { 256, 0 };
	uint8_t states[2];
	uint32_t producer = 1;
	uint32_t consumer = 0;
	uint32_t flags = 0;
	struct gpu_xdp_frame_runtime runtime;
	struct xsk_ring_cons cq = {
		.mask = 1,
		.size = 2,
		.producer = &producer,
		.consumer = &consumer,
		.ring = completions,
		.flags = &flags,
	};
	uint64_t recycled = UINT64_MAX;

	EXPECT_EQ(0, gpu_xdp_frame_runtime_init(&runtime, states,
					       recycle_entries,
					       expected_tx_addrs, 2, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&runtime.owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_from_rx(&runtime.owner, 0));
	EXPECT_EQ(0, gpu_xdp_frame_submit_tx(&runtime, 0, 256));
	EXPECT_EQ(1, gpu_xdp_reap_completions(&runtime, &cq, 1));
	EXPECT_EQ(1, consumer);
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[0]);
	EXPECT_EQ(1, runtime.recycle.count);
	EXPECT_EQ(0, xdev_ext_xsk_recycle_peek(&runtime.recycle, 0, &recycled));
	EXPECT_EQ(0, recycled);
}

static void test_tx_completion_requires_exact_descriptor_address(void)
{
	uint64_t recycle_entries[2];
	uint64_t expected_tx_addrs[2];
	uint64_t completions[4] = { 512, 4096 + 256, 256, 256 };
	uint8_t states[2];
	uint32_t producer = 2;
	uint32_t consumer = 0;
	uint32_t flags = 0;
	struct gpu_xdp_frame_runtime runtime;
	struct xsk_ring_cons cq = {
		.mask = 3,
		.size = 4,
		.producer = &producer,
		.consumer = &consumer,
		.ring = completions,
		.flags = &flags,
	};

	EXPECT_EQ(0, gpu_xdp_frame_runtime_init(&runtime, states,
					       recycle_entries,
					       expected_tx_addrs, 2, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_frame_to_fill(&runtime.owner, 0));
	EXPECT_EQ(0, xdev_ext_xsk_frame_from_rx(&runtime.owner, 0));
	EXPECT_EQ(0, gpu_xdp_frame_submit_tx(&runtime, 0, 256));
	/* Same frame/wrong offset and a stray frame are both invalidate. */
	EXPECT_EQ(-EPROTO, gpu_xdp_reap_completions(&runtime, &cq, 2));
	EXPECT_EQ(2, consumer);
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_TX, states[0]);
	EXPECT_EQ(256, expected_tx_addrs[0]);
	EXPECT_EQ(0, runtime.recycle.count);

	/* The later exact completion retires ownership once. */
	producer = 3;
	EXPECT_EQ(1, gpu_xdp_reap_completions(&runtime, &cq, 1));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[0]);
	EXPECT_EQ(UINT64_MAX, expected_tx_addrs[0]);
	EXPECT_EQ(1, runtime.recycle.count);

	/* A duplicate exact address is invalidate and cannot recycle twice. */
	producer = 4;
	EXPECT_EQ(-EPROTO, gpu_xdp_reap_completions(&runtime, &cq, 1));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[0]);
	EXPECT_EQ(1, runtime.recycle.count);
}

static void test_recycle_queue_wrap_and_capacity(void)
{
	uint64_t entries[3];
	uint64_t addr = 0;
	struct xdev_ext_xsk_recycle_queue queue;

	EXPECT_EQ(0, xdev_ext_xsk_recycle_init(&queue, entries, 3));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&queue, 0));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&queue, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&queue, 8192));
	EXPECT_EQ(-ENOSPC, xdev_ext_xsk_recycle_push(&queue, 12288));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_peek(&queue, 1, &addr));
	EXPECT_EQ(4096, addr);
	EXPECT_EQ(0, xdev_ext_xsk_recycle_consume(&queue, 2));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&queue, 12288));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&queue, 16384));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_peek(&queue, 0, &addr));
	EXPECT_EQ(8192, addr);
	EXPECT_EQ(0, xdev_ext_xsk_recycle_peek(&queue, 2, &addr));
	EXPECT_EQ(16384, addr);
	EXPECT_EQ(-EINVAL, xdev_ext_xsk_recycle_consume(&queue, 4));
}

static void test_app_owned_source_frame_requires_exact_completion(void)
{
	uint64_t recycle_entries[2];
	uint64_t expected_tx_addrs[2];
	uint64_t completions[2] = { 0, 0 };
	uint8_t states[2];
	uint32_t producer = 1;
	uint32_t consumer = 0;
	uint32_t flags = 0;
	struct gpu_xdp_frame_runtime runtime;
	struct xsk_ring_cons cq = {
		.mask = 1,
		.size = 2,
		.producer = &producer,
		.consumer = &consumer,
		.ring = completions,
		.flags = &flags,
	};
	uint64_t frame_base = UINT64_MAX;

	EXPECT_EQ(0, gpu_xdp_frame_runtime_init(&runtime, states,
					       recycle_entries,
					       expected_tx_addrs, 2, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&runtime.recycle, 0));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&runtime.recycle, 4096));
	EXPECT_EQ(0, gpu_xdp_frame_acquire_app(&runtime, &frame_base));
	EXPECT_EQ(0, frame_base);
	EXPECT_EQ(GPU_XDP_FRAME_APP, states[0]);
	EXPECT_EQ(1, runtime.recycle.count);
	/* A source frame never fabricates an RX transition. */
	EXPECT_EQ(-EPROTO, xdev_ext_xsk_frame_from_rx(&runtime.owner, 0));
	EXPECT_EQ(-EBUSY, xdev_ext_xsk_frame_to_fill(&runtime.owner, 0));
	EXPECT_EQ(0, gpu_xdp_frame_submit_app_tx(&runtime, 0, 0));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_TX, states[0]);
	EXPECT_EQ(-EPROTO, gpu_xdp_frame_submit_app_tx(&runtime, 0, 0));
	EXPECT_EQ(1, gpu_xdp_reap_completions(&runtime, &cq, 1));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_FREE, states[0]);
	EXPECT_EQ(2, runtime.recycle.count);
	EXPECT_EQ(0, gpu_xdp_frame_acquire_app(&runtime, &frame_base));
	EXPECT_EQ(4096, frame_base);
	EXPECT_EQ(GPU_XDP_FRAME_APP, states[1]);
}

static void test_uncertain_source_dma_sequesters_app_frame(void)
{
	uint64_t recycle_entries[1];
	uint64_t expected_tx_addrs[1];
	uint8_t states[1];
	struct gpu_xdp_frame_runtime runtime;
	uint64_t frame_base = UINT64_MAX;

	EXPECT_EQ(0, gpu_xdp_frame_runtime_init(&runtime, states,
					       recycle_entries,
					       expected_tx_addrs, 1, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&runtime.recycle, 0));
	EXPECT_EQ(0, gpu_xdp_frame_acquire_app(&runtime, &frame_base));
	EXPECT_EQ(0, gpu_xdp_frame_sequester_app(&runtime, frame_base));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_SEQUESTERED, states[0]);
	EXPECT_EQ(-EPROTO,
		  gpu_xdp_frame_submit_app_tx(&runtime, frame_base, frame_base));
	EXPECT_EQ(-EBUSY, gpu_xdp_frame_sequester_app(&runtime, frame_base));
}

static void test_source_tx_reservation_cancel_is_exact(void)
{
	struct xdp_desc descriptors[8] = { 0 };
	uint32_t producer = 3;
	uint32_t consumer = 3;
	uint32_t flags = 0;
	uint32_t index = UINT32_MAX;
	struct xsk_ring_prod tx = {
		.cached_prod = 3,
		.cached_cons = 11,
		.mask = 7,
		.size = 8,
		.producer = &producer,
		.consumer = &consumer,
		.ring = descriptors,
		.flags = &flags,
	};

	EXPECT_EQ(4, xsk_ring_prod__reserve(&tx, 4, &index));
	EXPECT_EQ(3, index);
	EXPECT_EQ(7, tx.cached_prod);
	EXPECT_EQ(3, producer);
	gpu_xdp_ring_prod_cancel(&tx, 4);
	EXPECT_EQ(3, tx.cached_prod);
	EXPECT_EQ(3, producer);
}

static void test_unpublished_source_tx_is_sequestered_not_recycled(void)
{
	uint64_t recycle_entries[1];
	uint64_t expected_tx_addrs[1];
	uint8_t states[1];
	struct gpu_xdp_frame_runtime runtime;
	uint64_t frame_base = UINT64_MAX;

	EXPECT_EQ(0, gpu_xdp_frame_runtime_init(&runtime, states,
					       recycle_entries,
					       expected_tx_addrs, 1, 4096));
	EXPECT_EQ(0, xdev_ext_xsk_recycle_push(&runtime.recycle, 0));
	EXPECT_EQ(0, gpu_xdp_frame_acquire_app(&runtime, &frame_base));
	EXPECT_EQ(0, gpu_xdp_frame_submit_app_tx(&runtime, frame_base,
					 frame_base));
	EXPECT_EQ(0, gpu_xdp_frame_sequester_unpublished_tx(&runtime,
							 frame_base));
	EXPECT_EQ(XDEV_EXT_XSK_FRAME_SEQUESTERED, states[0]);
	EXPECT_EQ(0, runtime.recycle.count);
	EXPECT_EQ(-EPROTO,
		  gpu_xdp_frame_submit_app_tx(&runtime, frame_base, frame_base));
}

int main(void)
{
	test_rx_tx_requires_completion_before_reuse();
	test_drop_can_recycle_without_tx();
	test_wrong_generation_and_bad_addresses_fail_closed();
	test_independent_frames_and_reset();
	test_uncertain_gpu_dma_sequesters_frame();
	test_rx_descriptor_options_fail_closed_and_recycle();
	test_aligned_rx_data_address_maps_to_owning_frame();
	test_aligned_tx_completion_maps_to_owning_frame();
	test_tx_completion_requires_exact_descriptor_address();
	test_recycle_queue_wrap_and_capacity();
	test_app_owned_source_frame_requires_exact_completion();
	test_uncertain_source_dma_sequesters_app_frame();
	test_source_tx_reservation_cancel_is_exact();
	test_unpublished_source_tx_is_sequestered_not_recycled();
	printf("gpu_xdp_frame_owner: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
