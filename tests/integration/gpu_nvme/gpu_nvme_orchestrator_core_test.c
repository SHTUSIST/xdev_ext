// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "../../../gpu_nvme_orchestrator_core.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	checks++;                                                            \
	if (actual_ != expected_) {                                          \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__func__, __LINE__, #actual_expr, actual_, expected_);  \
		failures++;                                                    \
	}                                                                    \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

#define MAX_FAKE 16U

enum fake_event {
	FAKE_GPU_TO_DEVICE = 1,
	FAKE_GPU_FROM_DEVICE,
	FAKE_PREPARE_READ,
	FAKE_PREPARE_WRITE,
	FAKE_SUBMIT,
	FAKE_CQE,
	FAKE_COMPARE,
	FAKE_ABORT,
};

struct fake_backend {
	unsigned int prepare_calls;
	unsigned int submit_calls;
	unsigned int cqe_calls;
	unsigned int gpu_calls;
	unsigned int gpu_batch_calls;
	unsigned int compare_calls;
	unsigned int abort_calls;
	unsigned int fail_prepare_at;
	unsigned int fail_gpu_at;
	unsigned int fail_compare_at;
	bool fail_gpu_before_submit;
	bool gpu_ambiguous_on_failure;
	int submit_ret;
	uint32_t submit_accepted;
	bool submit_ambiguous;
	uint64_t cqe_tokens[MAX_FAKE];
	int cqe_results[MAX_FAKE];
	unsigned int cqe_count;
	uint64_t prepared_tokens[MAX_FAKE];
	unsigned int prepared_count;
	enum fake_event events[128];
	unsigned int event_count;
};

static void fake_event_add(struct fake_backend *fake, enum fake_event event)
{
	fake->events[fake->event_count++] = event;
}

static int fake_prepare(void *opaque, uint32_t slot,
			const struct nxp_nvme_io_plan *plan,
			const struct iovec *vector, uint32_t vector_count,
			uint64_t token)
{
	struct fake_backend *fake = opaque;

	(void)slot;
	(void)vector;
	(void)vector_count;
	fake->prepare_calls++;
	if (fake->prepared_count < MAX_FAKE)
		fake->prepared_tokens[fake->prepared_count++] = token;
	fake_event_add(fake, plan->direction == NXP_IO_READ ?
		       FAKE_PREPARE_READ : FAKE_PREPARE_WRITE);
	if (fake->fail_prepare_at &&
	    fake->prepare_calls == fake->fail_prepare_at)
		return -ENOSPC;
	return 0;
}

static int fake_abort(void *opaque)
{
	struct fake_backend *fake = opaque;

	fake->abort_calls++;
	fake_event_add(fake, FAKE_ABORT);
	return 0;
}

static int fake_submit(void *opaque, uint32_t wanted, uint32_t *accepted,
		       bool *ambiguous)
{
	struct fake_backend *fake = opaque;

	fake->submit_calls++;
	fake_event_add(fake, FAKE_SUBMIT);
	*accepted = fake->submit_accepted > wanted ? wanted :
		fake->submit_accepted;
	*ambiguous = fake->submit_ambiguous;
	return fake->submit_ret;
}

static int fake_next_cqe(void *opaque, uint64_t *token, int *result)
{
	struct fake_backend *fake = opaque;
	unsigned int index = fake->cqe_calls++;

	fake_event_add(fake, FAKE_CQE);
	if (!fake->cqe_count) {
		if (index >= fake->prepared_count)
			return -ETIMEDOUT;
		*token = fake->prepared_tokens[index];
		*result = 0;
		return 0;
	}
	if (index >= fake->cqe_count)
		return -ETIMEDOUT;
	*token = fake->cqe_tokens[index];
	*result = fake->cqe_results[index];
	return 0;
}

static int fake_gpu_batch(void *opaque,
			  const struct gno_gpu_transfer *transfers,
			  uint32_t count, uint32_t *completed,
			  bool *ambiguous)
{
	struct fake_backend *fake = opaque;

	fake->gpu_batch_calls++;
	*completed = 0;
	*ambiguous = false;
	if (fake->fail_gpu_before_submit)
		return -EINVAL;
	for (uint32_t i = 0; i < count; i++) {
		fake->gpu_calls++;
		fake_event_add(fake,
			transfers[i].direction == XDEV_EXT_NV_P2P_UMEM_TO_GPU ?
			FAKE_GPU_TO_DEVICE : FAKE_GPU_FROM_DEVICE);
		if (fake->fail_gpu_at &&
		    fake->gpu_calls == fake->fail_gpu_at) {
			*ambiguous = fake->gpu_ambiguous_on_failure;
			return -EIO;
		}
		(*completed)++;
	}
	return 0;
}

static int fake_compare(void *opaque, uint32_t slot, uint64_t left_offset,
			uint64_t right_offset, uint64_t length)
{
	struct fake_backend *fake = opaque;

	(void)slot;
	(void)left_offset;
	(void)right_offset;
	(void)length;
	fake->compare_calls++;
	fake_event_add(fake, FAKE_COMPARE);
	if (fake->fail_compare_at &&
	    fake->compare_calls == fake->fail_compare_at)
		return -EILSEQ;
	return 0;
}

static const struct gno_backend_ops fake_ops = {
	.prepare_nvme = fake_prepare,
	.abort_private_nvme = fake_abort,
	.submit_nvme = fake_submit,
	.next_nvme_cqe = fake_next_cqe,
	.gpu_batch_sync = fake_gpu_batch,
	.compare_umem = fake_compare,
};

static struct gno_config valid_config(enum gno_mode mode,
				      uint32_t request_count)
{
	struct gno_config config = {
		.mode = mode,
		.ns = {
			.nsid = 7,
			.lba_size = 4096,
			.capacity_lbas = 4096,
			.char_is_namespace = true,
			.block_is_whole_namespace = true,
			.same_namespace = true,
			.stable_id_present = true,
			.controller_serial_present = true,
			.pci_bdf_present = true,
			.char_rdev = 1,
			.block_rdev = 2,
			.diskseq = 3,
			.stable_id = { 'n', 's' },
			.stable_id_len = 2,
			.controller_serial = { 's' },
			.controller_serial_len = 1,
			.pci_bdf = { '0', '0', '0', '0', ':', '0', '1', ':',
				     '0', '0', '.', '0' },
			.pci_bdf_len = 12,
		},
		.limits = {
			.authorized_first_lba = 64,
			.authorized_lbas = 512,
		},
		.transfer_bytes = 8192,
		.max_transfer_bytes = 128 * 1024,
		.vector_bytes = 4096,
		.request_index = 1,
		.request_count = request_count,
		.umem_bytes = 32768,
		.gpu_bytes = 32768,
		.allow_write = mode == GNO_NVME_TO_GPU,
		.local_chain_id = 11,
		.local_nvme_endpoint_id = 12,
		.local_gpu_endpoint_id = 13,
		.local_host_buffer_id = 14,
	};

	if (mode != GNO_NVME_TO_GPU)
		config.allow_write = true;
	return config;
}

static void init_batch(struct gno_batch *batch, struct gno_slot *slots,
		       struct iovec *vectors, uint32_t count)
{
	memset(batch, 0, sizeof(*batch));
	memset(slots, 0, sizeof(*slots) * count);
	memset(vectors, 0, sizeof(*vectors) * count * 2U);
	batch->slots = slots;
	batch->slot_capacity = count;
	batch->vectors = vectors;
	batch->vector_capacity = count * 2U;
}

static void load_read_tokens(struct gno_batch *batch,
			     struct fake_backend *fake,
			     const unsigned int *order, unsigned int count)
{
	fake->cqe_count = count;
	for (unsigned int i = 0; i < count; i++)
		fake->cqe_tokens[i] = batch->slots[order[i]].token;
}

static void test_configuration_and_vector_boundaries(void)
{
	struct gno_config config = valid_config(GNO_NVME_TO_GPU, 3);
	struct iovec vector[4];
	unsigned char storage[16384];
	uint32_t count = 0;

	EXPECT_EQ(gno_config_validate(&config), 0);
	config.allow_write = false;
	config.mode = GNO_GPU_TO_NVME;
	EXPECT_EQ(gno_config_validate(&config), -EPERM);
	config.allow_write = true;
	config.transfer_bytes = 132 * 1024;
	EXPECT_EQ(gno_config_validate(&config), -E2BIG);
	config.transfer_bytes = 8192;
	config.request_index = 255;
	config.request_count = 2;
	EXPECT_EQ(gno_config_validate(&config), -EACCES);
	config = valid_config(GNO_NVME_TO_GPU, 1);
	config.local_chain_id = 0;
	EXPECT_EQ(gno_config_validate(&config), -ENODATA);
	config = valid_config(GNO_NVME_TO_GPU, 1);
	config.ns.lba_size = 0;
	EXPECT_EQ(gno_config_validate(&config), -EINVAL);
	config = valid_config(GNO_NVME_TO_GPU,
			      XDEV_EXT_NV_P2P_MAX_BATCH + 1);
	config.umem_bytes = config.request_count * config.transfer_bytes;
	config.gpu_bytes = config.umem_bytes;
	EXPECT_EQ(gno_config_validate(&config), -E2BIG);
	config = valid_config(GNO_NVME_TO_GPU, 1);
	config.ns.lba_size = 512;
	config.transfer_bytes = 512;
	config.vector_bytes = 512;
	config.umem_bytes = 512;
	config.gpu_bytes = 512;
	EXPECT_EQ(gno_config_validate(&config), -EINVAL);
	config.umem_bytes = 4096;
	EXPECT_EQ(gno_config_validate(&config), 0);

	EXPECT_EQ(gno_iov_fill(storage, sizeof(storage), 4096, 8192, 4096,
			       vector, 4, &count), 0);
	EXPECT_EQ(count, 2);
	EXPECT_TRUE(vector[0].iov_base == storage + 4096);
	EXPECT_EQ(vector[0].iov_len, 4096);
	EXPECT_TRUE(vector[1].iov_base == storage + 8192);
	EXPECT_EQ(vector[1].iov_len, 4096);
	EXPECT_EQ(gno_iov_fill(storage, sizeof(storage), 12288, 8192, 4096,
			       vector, 4, &count), -ERANGE);
	EXPECT_EQ(gno_iov_fill(storage, sizeof(storage), 0, 8192, 4096,
			       vector, 1, &count), -ENOSPC);
}

static void test_batch_geometry_and_local_lba_sequence(void)
{
	struct gno_config config = valid_config(GNO_NVME_TO_GPU, 3);
	struct gno_slot slots[3];
	struct iovec vectors[6];
	struct gno_batch batch;
	unsigned char umem[32768] = { 0 };
	int error = 0;

	EXPECT_EQ(gno_required_registered_umem(&config, &error), 24576);
	EXPECT_EQ(error, 0);
	init_batch(&batch, slots, vectors, 3);
	batch.vector_capacity--;
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)),
		  -ENOSPC);
	init_batch(&batch, slots, vectors, 3);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	EXPECT_EQ(batch.vectors_per_slot, 2);
	EXPECT_EQ(batch.vector_capacity, 6);
	EXPECT_EQ(slots[0].plan.slba, 66);
	EXPECT_EQ(slots[1].plan.slba, 68);
	EXPECT_EQ(slots[2].plan.slba, 70);
	EXPECT_EQ(slots[0].plan.nlb, 1);
	EXPECT_TRUE(slots[0].token != slots[1].token);
	EXPECT_TRUE(slots[1].token != slots[2].token);

	config = valid_config(GNO_ROUNDTRIP_SAFE, 1);
	config.ns.lba_size = 512;
	config.transfer_bytes = 512;
	config.vector_bytes = 512;
	config.umem_bytes = 4096;
	config.gpu_bytes = 512;
	EXPECT_EQ(gno_required_umem(&config, &error), 1024);
	EXPECT_EQ(error, 0);
	EXPECT_EQ(gno_required_registered_umem(&config, &error), 4096);
	EXPECT_EQ(error, 0);
}

static void test_nvme_to_gpu_out_of_order(void)
{
	struct gno_config config = valid_config(GNO_NVME_TO_GPU, 3);
	struct gno_slot slots[3];
	struct iovec vectors[6];
	struct gno_batch batch;
	struct fake_backend fake = { .submit_accepted = 3 };
	const unsigned int order[] = { 2, 0, 1 };
	unsigned char umem[32768] = { 0 };

	init_batch(&batch, slots, vectors, 3);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	load_read_tokens(&batch, &fake, order, 3);
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), 0);
	EXPECT_EQ(fake.prepare_calls, 3);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.cqe_calls, 3);
	EXPECT_EQ(fake.gpu_calls, 3);
	EXPECT_EQ(fake.gpu_batch_calls, 1);
	EXPECT_FALSE(batch.retain_backing);
	EXPECT_TRUE(gno_batch_may_destroy_backing(&batch));
	for (unsigned int i = 0; i < 3; i++) {
		EXPECT_EQ(slots[i].state, GNO_SLOT_COMPLETE);
		EXPECT_EQ(slots[i].nvme_completions, 1);
		EXPECT_EQ(slots[i].gpu_completions, 1);
		EXPECT_FALSE(slots[i].owns_backing);
	}
	/* Every CQE is consumed before the first GPU publication boundary. */
	EXPECT_EQ(fake.events[3], FAKE_SUBMIT);
	EXPECT_EQ(fake.events[4], FAKE_CQE);
	EXPECT_EQ(fake.events[6], FAKE_CQE);
	EXPECT_EQ(fake.events[7], FAKE_GPU_TO_DEVICE);
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -EALREADY);
	EXPECT_EQ(fake.submit_calls, 1);
}

static void test_partial_acceptance_never_replays(void)
{
	struct gno_config config = valid_config(GNO_NVME_TO_GPU, 3);
	struct gno_slot slots[3];
	struct iovec vectors[6];
	struct gno_batch batch;
	struct fake_backend fake = {
		.submit_ret = -ETIMEDOUT,
		.submit_accepted = 2,
		.submit_ambiguous = true,
		.cqe_count = 2,
	};
	unsigned char umem[32768] = { 0 };

	init_batch(&batch, slots, vectors, 3);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	fake.cqe_tokens[0] = slots[1].token;
	fake.cqe_tokens[1] = slots[0].token;
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -ETIMEDOUT);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.cqe_calls, 2);
	EXPECT_EQ(fake.gpu_calls, 0);
	EXPECT_TRUE(batch.retain_backing);
	EXPECT_FALSE(gno_batch_may_destroy_backing(&batch));
	EXPECT_EQ(gno_batch_shutdown(&batch), -EBUSY);
	EXPECT_EQ(fake.submit_calls, 1);
}

static void test_nvme_error_blocks_gpu(void)
{
	struct gno_config config = valid_config(GNO_NVME_TO_GPU, 2);
	struct gno_slot slots[2];
	struct iovec vectors[4];
	struct gno_batch batch;
	struct fake_backend fake = {
		.submit_accepted = 2,
		.cqe_count = 2,
	};
	unsigned char umem[32768] = { 0 };

	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	fake.cqe_tokens[0] = slots[0].token;
	fake.cqe_tokens[1] = slots[1].token;
	fake.cqe_results[1] = -EIO;
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -EIO);
	EXPECT_EQ(fake.cqe_calls, 2);
	EXPECT_EQ(fake.gpu_calls, 0);
	EXPECT_TRUE(gno_batch_may_destroy_backing(&batch));
}

static void test_wrong_and_duplicate_completion_retain(void)
{
	struct gno_config config = valid_config(GNO_NVME_TO_GPU, 2);
	struct gno_slot slots[2];
	struct iovec vectors[4];
	struct gno_batch batch;
	struct fake_backend fake = {
		.submit_accepted = 2,
		.cqe_count = 2,
	};
	unsigned char umem[32768] = { 0 };

	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	fake.cqe_tokens[0] = UINT64_C(0xdeadbeef);
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -EPROTO);
	EXPECT_TRUE(batch.retain_backing);
	EXPECT_FALSE(gno_batch_may_destroy_backing(&batch));

	fake = (struct fake_backend) {
		.submit_accepted = 2,
		.cqe_count = 2,
	};
	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	fake.cqe_tokens[0] = slots[0].token;
	fake.cqe_tokens[1] = slots[0].token;
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -EPROTO);
	EXPECT_EQ(fake.cqe_calls, 2);
	EXPECT_TRUE(batch.retain_backing);
}

static void test_gpu_to_nvme_order_and_failure_gate(void)
{
	struct gno_config config = valid_config(GNO_GPU_TO_NVME, 2);
	struct gno_slot slots[2];
	struct iovec vectors[4];
	struct gno_batch batch;
	struct fake_backend fake = {
		.fail_gpu_at = 2,
		.gpu_ambiguous_on_failure = true,
	};
	unsigned char umem[32768] = { 0 };

	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -EIO);
	EXPECT_EQ(fake.gpu_calls, 2);
	EXPECT_EQ(fake.gpu_batch_calls, 1);
	EXPECT_EQ(fake.prepare_calls, 0);
	EXPECT_EQ(fake.submit_calls, 0);
	EXPECT_EQ(slots[0].gpu_completions, 1);
	EXPECT_EQ(slots[1].gpu_completions, 0);
	EXPECT_TRUE(batch.retain_backing);
	EXPECT_FALSE(gno_batch_may_destroy_backing(&batch));
	EXPECT_EQ(fake.gpu_batch_calls, 1);

	fake = (struct fake_backend) { .fail_gpu_before_submit = true };
	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -EINVAL);
	EXPECT_FALSE(batch.retain_backing);
	EXPECT_TRUE(gno_batch_may_destroy_backing(&batch));
	EXPECT_EQ(fake.gpu_calls, 0);
	EXPECT_EQ(fake.submit_calls, 0);

	fake = (struct fake_backend) { .submit_accepted = 2 };
	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	/* Tokens change when the write SQEs are prepared, so the fake backend
	 * mirrors them after prepare via its default-order completion mode. */
	fake.cqe_count = 0;
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), 0);
	EXPECT_EQ(fake.gpu_calls, 2);
	EXPECT_EQ(fake.gpu_batch_calls, 1);
	EXPECT_EQ(fake.prepare_calls, 2);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.events[0], FAKE_GPU_FROM_DEVICE);
	EXPECT_EQ(fake.events[1], FAKE_GPU_FROM_DEVICE);
	EXPECT_EQ(fake.events[2], FAKE_PREPARE_WRITE);
}

static void test_gpu_batch_is_bounded_and_not_replayed(void)
{
	const uint32_t count = XDEV_EXT_NV_P2P_MAX_BATCH;
	struct gno_config config = valid_config(GNO_GPU_TO_NVME, count);
	struct gno_slot *slots = calloc(count, sizeof(*slots));
	struct iovec *vectors = calloc(count * 2U, sizeof(*vectors));
	unsigned char *umem = calloc(count, (size_t)config.transfer_bytes);
	struct gno_batch batch;
	struct fake_backend fake = { 0 };

	EXPECT_TRUE(slots != NULL);
	EXPECT_TRUE(vectors != NULL);
	EXPECT_TRUE(umem != NULL);
	if (!slots || !vectors || !umem)
		goto out;
	config.umem_bytes = (uint64_t)count * config.transfer_bytes;
	config.gpu_bytes = config.umem_bytes;
	init_batch(&batch, slots, vectors, count);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem,
				    (size_t)config.umem_bytes), 0);
	EXPECT_EQ(gno_gpu_stage(&batch, &fake_ops, &fake,
				XDEV_EXT_NV_P2P_GPU_TO_UMEM, true), 0);
	EXPECT_EQ(fake.gpu_batch_calls, 1);
	EXPECT_EQ(fake.gpu_calls, count);
	for (uint32_t i = 0; i < count; i++)
		EXPECT_EQ(slots[i].gpu_completions, 1);
out:
	free(umem);
	free(vectors);
	free(slots);
}

static void test_roundtrip_mismatch_never_writes(void)
{
	struct gno_config config = valid_config(GNO_ROUNDTRIP_SAFE, 2);
	struct gno_slot slots[2];
	struct iovec vectors[4];
	struct gno_batch batch;
	struct fake_backend fake = {
		.submit_accepted = 2,
		.cqe_count = 2,
		.fail_compare_at = 2,
	};
	unsigned char umem[65536] = { 0 };

	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	fake.cqe_tokens[0] = slots[0].token;
	fake.cqe_tokens[1] = slots[1].token;
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -EILSEQ);
	EXPECT_EQ(fake.gpu_calls, 4);
	EXPECT_EQ(fake.gpu_batch_calls, 2);
	EXPECT_EQ(fake.compare_calls, 2);
	EXPECT_EQ(fake.prepare_calls, 2);
	EXPECT_EQ(fake.submit_calls, 1);
	for (unsigned int i = 0; i < fake.event_count; i++)
		EXPECT_FALSE(fake.events[i] == FAKE_PREPARE_WRITE);
	EXPECT_FALSE(batch.retain_backing);
	EXPECT_TRUE(gno_batch_may_destroy_backing(&batch));
}

static void test_roundtrip_success_is_bidirectional(void)
{
	struct gno_config config = valid_config(GNO_ROUNDTRIP_SAFE, 2);
	struct gno_slot slots[2];
	struct iovec vectors[4];
	struct gno_batch batch;
	struct fake_backend fake = { .submit_accepted = 2 };
	unsigned char umem[65536] = { 0 };

	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), 0);
	EXPECT_EQ(fake.prepare_calls, 4);
	EXPECT_EQ(fake.submit_calls, 2);
	EXPECT_EQ(fake.cqe_calls, 4);
	EXPECT_EQ(fake.gpu_calls, 4);
	EXPECT_EQ(fake.gpu_batch_calls, 2);
	EXPECT_EQ(fake.compare_calls, 2);
	EXPECT_FALSE(batch.retain_backing);
	EXPECT_TRUE(gno_batch_may_destroy_backing(&batch));
	for (unsigned int i = 0; i < 2; i++) {
		EXPECT_EQ(slots[i].state, GNO_SLOT_COMPLETE);
		EXPECT_EQ(slots[i].nvme_completions, 2);
		EXPECT_EQ(slots[i].gpu_completions, 2);
		EXPECT_FALSE(slots[i].owns_backing);
	}
}

static void test_private_prepare_abort_is_releasable(void)
{
	struct gno_config config = valid_config(GNO_NVME_TO_GPU, 2);
	struct gno_slot slots[2];
	struct iovec vectors[4];
	struct gno_batch batch;
	struct fake_backend fake = { .fail_prepare_at = 2 };
	unsigned char umem[32768] = { 0 };

	init_batch(&batch, slots, vectors, 2);
	EXPECT_EQ(gno_batch_prepare(&batch, &config, umem, sizeof(umem)), 0);
	EXPECT_EQ(gno_execute(&batch, &fake_ops, &fake), -ENOSPC);
	EXPECT_EQ(fake.abort_calls, 1);
	EXPECT_EQ(fake.submit_calls, 0);
	EXPECT_FALSE(batch.retain_backing);
	EXPECT_TRUE(gno_batch_may_destroy_backing(&batch));
}

int main(void)
{
	test_configuration_and_vector_boundaries();
	test_batch_geometry_and_local_lba_sequence();
	test_nvme_to_gpu_out_of_order();
	test_partial_acceptance_never_replays();
	test_nvme_error_blocks_gpu();
	test_wrong_and_duplicate_completion_retain();
	test_gpu_to_nvme_order_and_failure_gate();
	test_gpu_batch_is_bounded_and_not_replayed();
	test_roundtrip_mismatch_never_writes();
	test_roundtrip_success_is_bidirectional();
	test_private_prepare_abort_is_releasable();
	printf("gpu_nvme_orchestrator_core: %u checks, %u failures\n",
	       checks, failures);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
