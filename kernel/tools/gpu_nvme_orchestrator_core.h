/* SPDX-License-Identifier: GPL-2.0 */
#ifndef GPU_NVME_ORCHESTRATOR_CORE_H
#define GPU_NVME_ORCHESTRATOR_CORE_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/uio.h>

#include "../nvme_xdp_pipeline_core.h"
#include "include/xdev_ext_nv_p2p_ioctl.h"

#define GNO_MAX_BATCH XDEV_EXT_NV_P2P_MAX_BATCH
#define GNO_HOST_FRAME_SIZE UINT64_C(4096)
#define GNO_TOKEN_STAGE_READ UINT8_C(1)
#define GNO_TOKEN_STAGE_WRITE UINT8_C(2)

enum gno_mode {
	GNO_NVME_TO_GPU = 1,
	GNO_GPU_TO_NVME,
	GNO_ROUNDTRIP_SAFE,
};

enum gno_slot_state {
	GNO_SLOT_LOCAL = 0,
	GNO_SLOT_NVME_PREPARED,
	GNO_SLOT_NVME_ACCEPTED,
	GNO_SLOT_NVME_DONE,
	GNO_SLOT_GPU_DONE,
	GNO_SLOT_COMPLETE,
	GNO_SLOT_RETAINED,
};

struct gno_config {
	enum gno_mode mode;
	struct nxp_namespace ns;
	struct nxp_io_limits limits;
	uint64_t transfer_bytes;
	uint64_t max_transfer_bytes;
	uint64_t vector_bytes;
	uint64_t request_index;
	uint32_t request_count;
	uint64_t umem_bytes;
	uint64_t gpu_bytes;
	bool allow_write;
	/* These are process-local correlation identities.  The GPU and NVMe
	 * kernel hooks independently derive their trusted BPF identities. */
	uint64_t local_chain_id;
	uint64_t local_nvme_endpoint_id;
	uint64_t local_gpu_endpoint_id;
	uint64_t local_host_buffer_id;
};

struct gno_slot {
	enum gno_slot_state state;
	struct nxp_nvme_io_plan plan;
	struct iovec *vector;
	uint32_t vector_count;
	uint32_t index;
	uint64_t token;
	uint64_t original_offset;
	uint64_t returned_offset;
	uint64_t gpu_offset;
	uint32_t nvme_completions;
	uint32_t gpu_completions;
	bool owns_backing;
};

struct gno_batch {
	struct gno_config config;
	struct gno_slot *slots;
	uint32_t slot_capacity;
	struct iovec *vectors;
	uint32_t vector_capacity;
	uint32_t vectors_per_slot;
	uint32_t count;
	uint32_t next_generation;
	void *umem;
	size_t umem_capacity;
	int first_error;
	bool executed;
	bool retain_backing;
};

struct gno_gpu_transfer {
	uint32_t slot;
	enum xdev_ext_nv_p2p_direction direction;
	uint64_t umem_offset;
	uint64_t gpu_offset;
	uint64_t length;
};

struct gno_backend_ops {
	int (*prepare_nvme)(void *opaque, uint32_t slot,
			    const struct nxp_nvme_io_plan *plan,
			    const struct iovec *vector,
			    uint32_t vector_count, uint64_t token);
	int (*abort_private_nvme)(void *opaque);
	/* accepted is the exact consumed prefix.  ambiguous means at least one
	 * remaining command might still be reachable by the kernel. */
	int (*submit_nvme)(void *opaque, uint32_t wanted, uint32_t *accepted,
			   bool *ambiguous);
	int (*next_nvme_cqe)(void *opaque, uint64_t *token, int *result);
	/* This callback must return only after every completed CE request is
	 * terminal.  completed is an exact prefix; ambiguous prohibits backing
	 * reuse even when the syscall did not report a completed item. */
	int (*gpu_batch_sync)(void *opaque,
			      const struct gno_gpu_transfer *transfers,
			      uint32_t count, uint32_t *completed,
			      bool *ambiguous);
	int (*compare_umem)(void *opaque, uint32_t slot, uint64_t left_offset,
			    uint64_t right_offset, uint64_t length);
};

static inline bool gno_u64_add_overflow(uint64_t left, uint64_t right,
					uint64_t *sum)
{
	*sum = left + right;
	return *sum < left;
}

static inline bool gno_u64_mul_overflow(uint64_t left, uint64_t right,
					uint64_t *product)
{
	if (left && right > UINT64_MAX / left)
		return true;
	*product = left * right;
	return false;
}

static inline uint64_t gno_required_umem(const struct gno_config *config,
					 int *error)
{
	uint64_t bytes;

	if (error)
		*error = 0;
	if (!config || !config->request_count || !config->transfer_bytes ||
	    gno_u64_mul_overflow(config->request_count,
				 config->transfer_bytes, &bytes) ||
	    (config->mode == GNO_ROUNDTRIP_SAFE &&
	     gno_u64_mul_overflow(bytes, 2, &bytes))) {
		if (error)
			*error = -EOVERFLOW;
		return 0;
	}
	return bytes;
}

static inline uint64_t
gno_required_registered_umem(const struct gno_config *config, int *error)
{
	uint64_t bytes = gno_required_umem(config, error);

	if (!bytes)
		return 0;
	if (bytes > UINT64_MAX - (GNO_HOST_FRAME_SIZE - 1)) {
		if (error)
			*error = -EOVERFLOW;
		return 0;
	}
	return (bytes + GNO_HOST_FRAME_SIZE - 1) &
		~(GNO_HOST_FRAME_SIZE - 1);
}

static inline int gno_plan_at(const struct gno_config *config,
			      uint32_t slot, enum nxp_io_direction direction,
			      struct nxp_nvme_io_plan *plan)
{
	struct nxp_local_io_position position;
	uint64_t request_index;

	if (!config || !plan || slot >= config->request_count ||
	    gno_u64_add_overflow(config->request_index, slot,
				 &request_index))
		return -EOVERFLOW;
	position = (struct nxp_local_io_position) {
		.request_index = request_index,
		.block_offset = 0,
	};
	return nxp_plan_nvme_io(&config->ns, &config->limits, direction,
				&position, config->transfer_bytes, plan);
}

static inline int gno_config_validate(const struct gno_config *config)
{
	struct nxp_nvme_io_plan plan;
	uint64_t batch_bytes, required_umem;
	uint64_t vector_count;
	int error;

	if (!config || (config->mode != GNO_NVME_TO_GPU &&
			config->mode != GNO_GPU_TO_NVME &&
			config->mode != GNO_ROUNDTRIP_SAFE))
		return -EINVAL;
	if (!config->request_count || !config->transfer_bytes ||
	    !config->max_transfer_bytes ||
	    !config->vector_bytes || !config->umem_bytes ||
	    !config->gpu_bytes)
		return -EINVAL;
	if (config->request_count > GNO_MAX_BATCH)
		return -E2BIG;
	if ((config->mode == GNO_GPU_TO_NVME ||
	     config->mode == GNO_ROUNDTRIP_SAFE) && !config->allow_write)
		return -EPERM;
	if (!config->local_chain_id || !config->local_nvme_endpoint_id ||
	    !config->local_gpu_endpoint_id || !config->local_host_buffer_id)
		return -ENODATA;
	error = nxp_namespace_validate(&config->ns);
	if (error)
		return error;
	if (config->transfer_bytes > config->max_transfer_bytes)
		return -E2BIG;
	if (config->vector_bytes > SIZE_MAX ||
	    config->transfer_bytes > SIZE_MAX)
		return -EOVERFLOW;
	if (config->vector_bytes % config->ns.lba_size)
		return -EINVAL;
	vector_count = 1 + (config->transfer_bytes - 1) /
		config->vector_bytes;
	if (!vector_count || vector_count > UINT32_MAX ||
	    vector_count > UIO_MAXIOV)
		return -E2BIG;
	if (gno_u64_mul_overflow(config->request_count,
				 config->transfer_bytes, &batch_bytes) ||
	    batch_bytes > config->gpu_bytes)
		return -ENOBUFS;
	required_umem = gno_required_registered_umem(config, &error);
	if (error)
		return error;
	if (config->umem_bytes % GNO_HOST_FRAME_SIZE)
		return -EINVAL;
	if (required_umem > config->umem_bytes)
		return -ENOBUFS;
	error = gno_plan_at(config, 0,
		config->mode == GNO_GPU_TO_NVME ? NXP_IO_WRITE : NXP_IO_READ,
		&plan);
	if (error)
		return error;
	return gno_plan_at(config, config->request_count - 1,
		config->mode == GNO_GPU_TO_NVME ? NXP_IO_WRITE : NXP_IO_READ,
		&plan);
}

static inline int gno_iov_fill(void *umem, size_t umem_capacity,
			       uint64_t offset, uint64_t length,
			       uint64_t vector_bytes, struct iovec *vector,
			       uint32_t vector_capacity, uint32_t *vector_count)
{
	uint64_t end, count;

	if (!umem || !length || !vector_bytes || !vector || !vector_count)
		return -EINVAL;
	if (gno_u64_add_overflow(offset, length, &end) ||
	    end > umem_capacity || offset > SIZE_MAX || length > SIZE_MAX)
		return -ERANGE;
	count = 1 + (length - 1) / vector_bytes;
	if (count > vector_capacity)
		return -ENOSPC;
	for (uint64_t i = 0; i < count; i++) {
		uint64_t part_offset = i * vector_bytes;
		uint64_t remaining = length - part_offset;
		uint64_t part = remaining < vector_bytes ? remaining :
			vector_bytes;

		vector[i].iov_base = (unsigned char *)umem + offset +
			part_offset;
		vector[i].iov_len = (size_t)part;
	}
	*vector_count = (uint32_t)count;
	return 0;
}

static inline uint64_t gno_next_token(struct gno_batch *batch,
				      uint8_t stage, uint32_t slot)
{
	uint32_t generation = ++batch->next_generation;

	if (!generation)
		generation = ++batch->next_generation;
	return ((uint64_t)generation << 32) |
	       ((uint64_t)stage << 24) | ((uint64_t)slot + 1);
}

static inline int gno_batch_prepare(struct gno_batch *batch,
			    const struct gno_config *config, void *umem,
			    size_t umem_capacity)
{
	uint64_t batch_bytes;
	uint64_t vector_count;
	int ret;

	if (!batch || !batch->slots || !batch->vectors || !umem)
		return -EINVAL;
	ret = gno_config_validate(config);
	if (ret)
		return ret;
	if (config->request_count > batch->slot_capacity ||
	    config->umem_bytes > umem_capacity)
		return -ENOSPC;
	vector_count = 1 + (config->transfer_bytes - 1) /
		config->vector_bytes;
	if (vector_count > UINT32_MAX ||
	    vector_count * config->request_count > batch->vector_capacity)
		return -ENOSPC;
	if (gno_u64_mul_overflow(config->request_count,
				 config->transfer_bytes, &batch_bytes))
		return -EOVERFLOW;

	batch->config = *config;
	batch->count = config->request_count;
	batch->vectors_per_slot = (uint32_t)vector_count;
	batch->umem = umem;
	batch->umem_capacity = umem_capacity;
	batch->first_error = 0;
	batch->executed = false;
	batch->retain_backing = false;
	batch->next_generation = (uint32_t)config->local_chain_id;
	for (uint32_t i = 0; i < batch->count; i++) {
		struct gno_slot *slot = &batch->slots[i];
		uint64_t offset;
		enum nxp_io_direction direction;

		memset(slot, 0, sizeof(*slot));
		if (gno_u64_mul_overflow(i, config->transfer_bytes, &offset))
			return -EOVERFLOW;
		slot->state = GNO_SLOT_LOCAL;
		slot->index = i;
		slot->original_offset = offset;
		slot->returned_offset = config->mode == GNO_ROUNDTRIP_SAFE ?
			batch_bytes + offset : offset;
		slot->gpu_offset = offset;
		slot->vector = batch->vectors + i * vector_count;
		slot->vector_count = (uint32_t)vector_count;
		slot->owns_backing = true;
		direction = config->mode == GNO_GPU_TO_NVME ?
			NXP_IO_WRITE : NXP_IO_READ;
		ret = gno_plan_at(config, i, direction, &slot->plan);
		if (ret)
			return ret;
		slot->token = gno_next_token(batch,
			direction == NXP_IO_READ ? GNO_TOKEN_STAGE_READ :
			GNO_TOKEN_STAGE_WRITE, i);
		ret = gno_iov_fill(umem, umem_capacity,
			direction == NXP_IO_READ ? slot->original_offset :
			slot->returned_offset, config->transfer_bytes,
			config->vector_bytes, slot->vector,
			slot->vector_count, &slot->vector_count);
		if (ret)
			return ret;
	}
	return 0;
}

static inline void gno_release_all(struct gno_batch *batch)
{
	for (uint32_t i = 0; i < batch->count; i++) {
		batch->slots[i].owns_backing = false;
		batch->slots[i].state = GNO_SLOT_COMPLETE;
	}
}

static inline void gno_retain_all(struct gno_batch *batch)
{
	batch->retain_backing = true;
	for (uint32_t i = 0; i < batch->count; i++) {
		batch->slots[i].owns_backing = true;
		batch->slots[i].state = GNO_SLOT_RETAINED;
	}
}

static inline void gno_latch_error(struct gno_batch *batch, int error)
{
	if (!batch->first_error && error)
		batch->first_error = error < 0 ? error : -EIO;
}

static inline int gno_prepare_nvme(struct gno_batch *batch,
			   const struct gno_backend_ops *ops, void *opaque,
			   enum nxp_io_direction direction)
{
	uint32_t prepared = 0;
	int ret;

	for (uint32_t i = 0; i < batch->count; i++) {
		struct gno_slot *slot = &batch->slots[i];
		uint64_t offset = direction == NXP_IO_READ ?
			slot->original_offset : slot->returned_offset;

		if (slot->plan.direction != direction)
			slot->token = gno_next_token(batch,
				direction == NXP_IO_READ ?
				GNO_TOKEN_STAGE_READ : GNO_TOKEN_STAGE_WRITE, i);
		ret = gno_plan_at(&batch->config, i, direction, &slot->plan);
		if (ret)
			goto abort;
		ret = gno_iov_fill(batch->umem, batch->umem_capacity, offset,
			batch->config.transfer_bytes,
			batch->config.vector_bytes, slot->vector,
			batch->vectors_per_slot, &slot->vector_count);
		if (ret)
			goto abort;
		ret = ops->prepare_nvme(opaque, i, &slot->plan, slot->vector,
					slot->vector_count, slot->token);
		if (ret)
			goto abort;
		slot->state = GNO_SLOT_NVME_PREPARED;
		prepared++;
	}
	return 0;

abort:
	if (prepared) {
		int abort_ret = ops->abort_private_nvme(opaque);

		if (abort_ret) {
			gno_latch_error(batch, abort_ret);
			gno_retain_all(batch);
			return batch->first_error;
		}
	}
	gno_latch_error(batch, ret);
	gno_release_all(batch);
	return batch->first_error;
}

static inline int gno_find_completion(struct gno_batch *batch,
			      uint64_t token, uint32_t *slot_index)
{
	for (uint32_t i = 0; i < batch->count; i++) {
		struct gno_slot *slot = &batch->slots[i];

		if (slot->token != token)
			continue;
		if (slot->state != GNO_SLOT_NVME_ACCEPTED ||
		    !slot->owns_backing)
			return -EALREADY;
		*slot_index = i;
		return 0;
	}
	return -ESTALE;
}

static inline int gno_drain_nvme(struct gno_batch *batch,
			 const struct gno_backend_ops *ops, void *opaque,
			 uint32_t accepted, bool final_stage)
{
	for (uint32_t seen = 0; seen < accepted; seen++) {
		uint64_t token = 0;
		uint32_t slot_index;
		int result = 0;
		int ret = ops->next_nvme_cqe(opaque, &token, &result);

		if (ret) {
			gno_latch_error(batch, ret);
			gno_retain_all(batch);
			return batch->first_error;
		}
		ret = gno_find_completion(batch, token, &slot_index);
		if (ret) {
			gno_latch_error(batch, -EPROTO);
			gno_retain_all(batch);
			return batch->first_error;
		}
		batch->slots[slot_index].nvme_completions++;
		batch->slots[slot_index].state = final_stage ?
			GNO_SLOT_COMPLETE : GNO_SLOT_NVME_DONE;
		if (result)
			gno_latch_error(batch, result < 0 ? result : -EIO);
	}
	return batch->first_error;
}

static inline int gno_nvme_stage(struct gno_batch *batch,
			 const struct gno_backend_ops *ops, void *opaque,
			 enum nxp_io_direction direction, bool final_stage)
{
	uint32_t accepted = 0;
	bool ambiguous = false;
	int submit_ret;
	int ret;

	ret = gno_prepare_nvme(batch, ops, opaque, direction);
	if (ret)
		return ret;
	submit_ret = ops->submit_nvme(opaque, batch->count, &accepted,
				      &ambiguous);
	if (accepted > batch->count) {
		gno_latch_error(batch, -EPROTO);
		gno_retain_all(batch);
		return batch->first_error;
	}
	for (uint32_t i = 0; i < accepted; i++)
		batch->slots[i].state = GNO_SLOT_NVME_ACCEPTED;
	if (accepted != batch->count || ambiguous) {
		if (accepted)
			(void)gno_drain_nvme(batch, ops, opaque, accepted,
					     final_stage);
		if (!accepted && !ambiguous) {
			ret = ops->abort_private_nvme(opaque);
			if (!ret) {
				gno_latch_error(batch, submit_ret ? submit_ret :
						-ECANCELED);
				gno_release_all(batch);
				return batch->first_error;
			}
			gno_latch_error(batch, ret);
		}
		gno_latch_error(batch, submit_ret ? submit_ret : -EPROTO);
		gno_retain_all(batch);
		return batch->first_error;
	}
	/* A negative submit return can race with SQ-head consumption.  Once the
	 * complete prefix is proven accepted, completion is authoritative. */
	ret = gno_drain_nvme(batch, ops, opaque, accepted, final_stage);
	if (ret) {
		if (!batch->retain_backing)
			gno_release_all(batch);
		return ret;
	}
	return 0;
}

static inline int gno_gpu_stage(struct gno_batch *batch,
			const struct gno_backend_ops *ops, void *opaque,
			enum xdev_ext_nv_p2p_direction direction,
			bool use_returned_region)
{
	struct gno_gpu_transfer transfers[XDEV_EXT_NV_P2P_MAX_BATCH];
	uint32_t completed = 0;
	bool ambiguous = false;
	int ret;

	if (batch->count > XDEV_EXT_NV_P2P_MAX_BATCH) {
		gno_latch_error(batch, -E2BIG);
		gno_release_all(batch);
		return batch->first_error;
	}
	for (uint32_t i = 0; i < batch->count; i++) {
		struct gno_slot *slot = &batch->slots[i];

		transfers[i] = (struct gno_gpu_transfer) {
			.slot = i,
			.direction = direction,
			.umem_offset = use_returned_region ?
				slot->returned_offset : slot->original_offset,
			.gpu_offset = slot->gpu_offset,
			.length = batch->config.transfer_bytes,
		};
	}
	ret = ops->gpu_batch_sync(opaque, transfers, batch->count, &completed,
				  &ambiguous);
	if (completed > batch->count) {
		gno_latch_error(batch, -EPROTO);
		gno_retain_all(batch);
		return batch->first_error;
	}
	for (uint32_t i = 0; i < completed; i++) {
		batch->slots[i].gpu_completions++;
		batch->slots[i].state = GNO_SLOT_GPU_DONE;
	}
	if (ret || ambiguous || completed != batch->count) {
		gno_latch_error(batch, ret ? ret : -EPROTO);
		if (ambiguous || !ret)
			gno_retain_all(batch);
		else
			gno_release_all(batch);
		return batch->first_error;
	}
	return 0;
}

static inline int gno_execute(struct gno_batch *batch,
			      const struct gno_backend_ops *ops, void *opaque)
{
	int ret;

	if (!batch || !ops || !ops->prepare_nvme ||
	    !ops->abort_private_nvme || !ops->submit_nvme ||
	    !ops->next_nvme_cqe || !ops->gpu_batch_sync ||
	    !ops->compare_umem || !batch->count)
		return -EINVAL;
	if (batch->executed)
		return -EALREADY;
	batch->executed = true;

	if (batch->config.mode == GNO_GPU_TO_NVME) {
		ret = gno_gpu_stage(batch, ops, opaque,
				    XDEV_EXT_NV_P2P_GPU_TO_UMEM, true);
		if (ret)
			return ret;
		ret = gno_nvme_stage(batch, ops, opaque, NXP_IO_WRITE, true);
		if (!ret)
			gno_release_all(batch);
		return ret;
	}

	ret = gno_nvme_stage(batch, ops, opaque, NXP_IO_READ, false);
	if (ret)
		return ret;
	ret = gno_gpu_stage(batch, ops, opaque, XDEV_EXT_NV_P2P_UMEM_TO_GPU,
			    false);
	if (ret)
		return ret;
	if (batch->config.mode == GNO_NVME_TO_GPU) {
		gno_release_all(batch);
		return 0;
	}

	ret = gno_gpu_stage(batch, ops, opaque, XDEV_EXT_NV_P2P_GPU_TO_UMEM,
			    true);
	if (ret)
		return ret;
	for (uint32_t i = 0; i < batch->count; i++) {
		ret = ops->compare_umem(opaque, i,
			batch->slots[i].original_offset,
			batch->slots[i].returned_offset,
			batch->config.transfer_bytes);
		if (ret) {
			gno_latch_error(batch, ret);
			gno_release_all(batch);
			return batch->first_error;
		}
	}
	ret = gno_nvme_stage(batch, ops, opaque, NXP_IO_WRITE, true);
	if (!ret)
		gno_release_all(batch);
	return ret;
}

static inline bool gno_batch_may_destroy_backing(const struct gno_batch *batch)
{
	if (!batch || batch->retain_backing)
		return false;
	for (uint32_t i = 0; i < batch->count; i++) {
		if (batch->slots[i].owns_backing)
			return false;
	}
	return true;
}

static inline int gno_batch_shutdown(const struct gno_batch *batch)
{
	return gno_batch_may_destroy_backing(batch) ? 0 : -EBUSY;
}

#endif /* GPU_NVME_ORCHESTRATOR_CORE_H */
