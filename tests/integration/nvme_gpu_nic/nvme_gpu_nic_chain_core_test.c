// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../nvme_gpu_nic_chain_core.h"

static int assertions;
static int failures;

#define EXPECT_TRUE(value) do { \
	assertions++; \
	if (!(value)) { \
		fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n", \
			__FILE__, __LINE__, #value); \
		failures++; \
	} \
} while (0)

#define EXPECT_EQ(expected, actual) do { \
	long long _expected = (long long)(expected); \
	long long _actual = (long long)(actual); \
	assertions++; \
	if (_expected != _actual) { \
		fprintf(stderr, "%s:%d: expected %lld, got %lld\n", \
			__FILE__, __LINE__, _expected, _actual); \
		failures++; \
	} \
} while (0)

struct fake_gpu {
	unsigned int calls;
	enum ngn_gpu_direction directions[4];
	uint32_t requested[4];
	uint32_t completed[4];
	int results[4];
	bool ambiguous[4];
};

static int fake_submit(void *opaque, enum ngn_gpu_direction direction,
		       const struct ngn_gpu_transfer *transfers,
		       uint32_t count, uint32_t *completed, bool *ambiguous)
{
	struct fake_gpu *gpu = opaque;
	unsigned int call = gpu->calls++;

	EXPECT_TRUE(transfers != NULL);
	EXPECT_TRUE(call < 4);
	gpu->directions[call] = direction;
	gpu->requested[call] = count;
	*completed = gpu->completed[call];
	*ambiguous = gpu->ambiguous[call];
	return gpu->results[call];
}

static void begin_frames(struct ngn_frame_journal *journals,
			 uint32_t count, enum ngn_chain_direction direction)
{
	for (uint32_t i = 0; i < count; i++) {
		EXPECT_EQ(0, ngn_journal_begin(&journals[i], direction,
				UINT64_C(0x1234), 7, 9, (uint64_t)i * 4096));
		EXPECT_EQ(0, ngn_journal_source_accept(&journals[i]));
		EXPECT_EQ(0, ngn_journal_source_complete(&journals[i]));
	}
}

static void test_forward_roundtrip_and_exact_sink_completion(void)
{
	struct ngn_frame_journal journals[2] = { 0 };
	const struct ngn_gpu_span spans[2] = {
		{ .frame_addr = 0, .umem_offset = 128, .gpu_offset = 128,
		  .length = 1024 },
		{ .frame_addr = 4096, .umem_offset = 4096 + 128,
		  .gpu_offset = 4096 + 128, .length = 512 },
	};
	struct fake_gpu gpu = {
		.completed = { 2, 2 },
	};
	const struct ngn_gpu_ops ops = { .submit_sync = fake_submit };
	struct ngn_gpu_window window = {
		.umem_bytes = 8192,
		.gpu_bytes = 8192,
		.frame_size = 4096,
	};

	begin_frames(journals, 2, NGN_NVME_GPU_NIC);
	EXPECT_EQ(0, ngn_gpu_roundtrip(journals, 2, spans, &window,
				       &ops, &gpu));
	EXPECT_EQ(2, gpu.calls);
	EXPECT_EQ(NGN_GPU_UMEM_TO_GPU, gpu.directions[0]);
	EXPECT_EQ(NGN_GPU_GPU_TO_UMEM, gpu.directions[1]);
	for (uint32_t i = 0; i < 2; i++) {
		EXPECT_EQ(NGN_STAGE_GPU_DONE, journals[i].stage);
		EXPECT_TRUE(journals[i].owns_backing);
		EXPECT_EQ(0, ngn_journal_sink_accept(&journals[i]));
		EXPECT_EQ(0, ngn_journal_sink_complete(&journals[i]));
		EXPECT_EQ(NGN_STAGE_COMPLETE, journals[i].stage);
		EXPECT_TRUE(!journals[i].owns_backing);
		EXPECT_EQ(-EALREADY, ngn_journal_sink_complete(&journals[i]));
	}
}

static void test_reverse_uses_same_journal(void)
{
	struct ngn_frame_journal journal = { 0 };
	const struct ngn_gpu_span span = {
		.frame_addr = 0, .umem_offset = 256, .gpu_offset = 256,
		.length = 2048,
	};
	struct fake_gpu gpu = { .completed = { 1, 1 } };
	const struct ngn_gpu_ops ops = { .submit_sync = fake_submit };
	struct ngn_gpu_window window = {
		.umem_bytes = 4096, .gpu_bytes = 4096, .frame_size = 4096,
	};

	begin_frames(&journal, 1, NGN_NIC_GPU_NVME);
	EXPECT_EQ(0, ngn_gpu_roundtrip(&journal, 1, &span, &window,
				       &ops, &gpu));
	EXPECT_EQ(0, ngn_journal_sink_accept(&journal));
	EXPECT_EQ(0, ngn_journal_sink_complete(&journal));
	EXPECT_EQ(NGN_NIC_GPU_NVME, journal.direction);
	EXPECT_TRUE(!journal.owns_backing);
}

static void test_gpu_failure_sequesters_whole_group_without_retry(void)
{
	struct ngn_frame_journal journals[3] = { 0 };
	const struct ngn_gpu_span spans[3] = {
		{ .frame_addr = 0, .umem_offset = 64, .gpu_offset = 64,
		  .length = 100 },
		{ .frame_addr = 4096, .umem_offset = 4160,
		  .gpu_offset = 4160, .length = 100 },
		{ .frame_addr = 8192, .umem_offset = 8256,
		  .gpu_offset = 8256, .length = 100 },
	};
	struct fake_gpu gpu = {
		.completed = { 1 },
		.results = { -EIO },
		.ambiguous = { true },
	};
	const struct ngn_gpu_ops ops = { .submit_sync = fake_submit };
	struct ngn_gpu_window window = {
		.umem_bytes = 12288, .gpu_bytes = 12288, .frame_size = 4096,
	};

	begin_frames(journals, 3, NGN_NVME_GPU_NIC);
	EXPECT_EQ(-EIO, ngn_gpu_roundtrip(journals, 3, spans, &window,
					  &ops, &gpu));
	EXPECT_EQ(1, gpu.calls);
	for (uint32_t i = 0; i < 3; i++) {
		EXPECT_EQ(NGN_STAGE_SEQUESTERED, journals[i].stage);
		EXPECT_TRUE(journals[i].owns_backing);
		EXPECT_EQ(-EBUSY, ngn_journal_abort_private(&journals[i]));
	}
}

static void test_return_leg_failure_is_not_replayed(void)
{
	struct ngn_frame_journal journals[2] = { 0 };
	const struct ngn_gpu_span spans[2] = {
		{ .frame_addr = 0, .umem_offset = 128, .gpu_offset = 128,
		  .length = 512 },
		{ .frame_addr = 4096, .umem_offset = 4224,
		  .gpu_offset = 4224, .length = 512 },
	};
	struct fake_gpu gpu = {
		.completed = { 2, 0 },
		.results = { 0, -ETIMEDOUT },
		.ambiguous = { false, true },
	};
	const struct ngn_gpu_ops ops = { .submit_sync = fake_submit };
	struct ngn_gpu_window window = {
		.umem_bytes = 8192, .gpu_bytes = 8192, .frame_size = 4096,
	};

	begin_frames(journals, 2, NGN_NIC_GPU_NVME);
	EXPECT_EQ(-ETIMEDOUT,
		  ngn_gpu_roundtrip(journals, 2, spans, &window, &ops, &gpu));
	EXPECT_EQ(2, gpu.calls);
	EXPECT_EQ(NGN_GPU_UMEM_TO_GPU, gpu.directions[0]);
	EXPECT_EQ(NGN_GPU_GPU_TO_UMEM, gpu.directions[1]);
	EXPECT_EQ(NGN_STAGE_SEQUESTERED, journals[0].stage);
	EXPECT_EQ(NGN_STAGE_SEQUESTERED, journals[1].stage);
}

static void test_validation_rejects_aliases_and_bad_order_before_dma(void)
{
	struct ngn_frame_journal journals[2] = { 0 };
	struct ngn_gpu_span spans[2] = {
		{ .frame_addr = 0, .umem_offset = 64, .gpu_offset = 64,
		  .length = 512 },
		{ .frame_addr = 0, .umem_offset = 128, .gpu_offset = 4096,
		  .length = 512 },
	};
	struct fake_gpu gpu = { .completed = { 2, 2 } };
	const struct ngn_gpu_ops ops = { .submit_sync = fake_submit };
	struct ngn_gpu_window window = {
		.umem_bytes = 8192, .gpu_bytes = 8192, .frame_size = 4096,
	};

	begin_frames(journals, 2, NGN_NVME_GPU_NIC);
	EXPECT_EQ(-EEXIST, ngn_gpu_roundtrip(journals, 2, spans, &window,
					     &ops, &gpu));
	EXPECT_EQ(0, gpu.calls);
	spans[1].frame_addr = 4096;
	spans[1].umem_offset = 8192;
	EXPECT_EQ(-ERANGE, ngn_gpu_roundtrip(journals, 2, spans, &window,
					     &ops, &gpu));
	EXPECT_EQ(0, gpu.calls);
	EXPECT_EQ(0, ngn_journal_abort_private(&journals[0]));
	EXPECT_EQ(0, ngn_journal_abort_private(&journals[1]));
	EXPECT_TRUE(!journals[0].owns_backing);
	EXPECT_TRUE(!journals[1].owns_backing);
	EXPECT_EQ(-EINVAL, ngn_journal_source_complete(&journals[0]));
}

static void test_identity_and_batch_limits_fail_closed(void)
{
	struct ngn_frame_journal journal = { 0 };
	struct ngn_gpu_span span = {
		.frame_addr = 0, .umem_offset = 64, .gpu_offset = 64, .length = 64,
	};
	struct fake_gpu gpu = { .completed = { 1, 1 } };
	const struct ngn_gpu_ops ops = { .submit_sync = fake_submit };
	struct ngn_gpu_window window = {
		.umem_bytes = 4096, .gpu_bytes = 4096, .frame_size = 4096,
	};

	EXPECT_EQ(-ENODATA, ngn_journal_begin(&journal, NGN_NVME_GPU_NIC,
					      0, 1, 1, 0));
	EXPECT_EQ(0, ngn_journal_begin(&journal, NGN_NVME_GPU_NIC,
				       1, 1, 1, 0));
	EXPECT_EQ(-EINVAL, ngn_journal_source_complete(&journal));
	EXPECT_EQ(0, ngn_journal_source_accept(&journal));
	EXPECT_EQ(0, ngn_journal_source_complete(&journal));
	EXPECT_EQ(-E2BIG, ngn_gpu_roundtrip(&journal,
					    NGN_GPU_MAX_BATCH + 1, &span,
					    &window, &ops, &gpu));
	EXPECT_EQ(0, gpu.calls);
	EXPECT_EQ(0, ngn_journal_abort_private(&journal));
}

static void test_noncontiguous_frame_journals_share_one_batch(void)
{
	struct ngn_frame_journal storage[5] = { 0 };
	struct ngn_frame_journal *journals[2] = {
		&storage[1], &storage[4],
	};
	const struct ngn_gpu_span spans[2] = {
		{ .frame_addr = 4096, .umem_offset = 4160,
		  .gpu_offset = 4160, .length = 128 },
		{ .frame_addr = 16384, .umem_offset = 16448,
		  .gpu_offset = 16448, .length = 128 },
	};
	struct fake_gpu gpu = { .completed = { 2, 2 } };
	const struct ngn_gpu_ops ops = { .submit_sync = fake_submit };
	struct ngn_gpu_window window = {
		.umem_bytes = 20480, .gpu_bytes = 20480, .frame_size = 4096,
	};

	EXPECT_EQ(0, ngn_journal_begin(journals[0], NGN_NVME_GPU_NIC,
				       77, 5, 3, 4096));
	EXPECT_EQ(0, ngn_journal_begin(journals[1], NGN_NVME_GPU_NIC,
				       77, 5, 3, 16384));
	for (uint32_t i = 0; i < 2; i++) {
		EXPECT_EQ(0, ngn_journal_source_accept(journals[i]));
		EXPECT_EQ(0, ngn_journal_source_complete(journals[i]));
	}
	EXPECT_EQ(0, ngn_gpu_roundtrip_frames(journals, 2, spans, &window,
					      &ops, &gpu));
	EXPECT_EQ(NGN_STAGE_GPU_DONE, journals[0]->stage);
	EXPECT_EQ(NGN_STAGE_GPU_DONE, journals[1]->stage);
	EXPECT_EQ(NGN_STAGE_FREE, storage[0].stage);
	EXPECT_EQ(NGN_STAGE_FREE, storage[2].stage);
}

int main(void)
{
	test_forward_roundtrip_and_exact_sink_completion();
	test_reverse_uses_same_journal();
	test_gpu_failure_sequesters_whole_group_without_retry();
	test_return_leg_failure_is_not_replayed();
	test_validation_rejects_aliases_and_bad_order_before_dma();
	test_identity_and_batch_limits_fail_closed();
	test_noncontiguous_frame_journals_share_one_batch();

	if (failures) {
		fprintf(stderr, "FAIL: %d/%d assertions failed\n",
			failures, assertions);
		return 1;
	}
	printf("PASS: %d chain journal assertions\n", assertions);
	return 0;
}
