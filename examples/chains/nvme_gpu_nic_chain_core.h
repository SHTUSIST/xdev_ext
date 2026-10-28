/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NVME_GPU_NIC_CHAIN_CORE_H
#define NVME_GPU_NIC_CHAIN_CORE_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NGN_GPU_MAX_BATCH UINT32_C(64)

enum ngn_chain_direction {
	NGN_NVME_GPU_NIC = 1,
	NGN_NIC_GPU_NVME,
};

enum ngn_chain_stage {
	NGN_STAGE_FREE = 0,
	NGN_STAGE_PRIVATE,
	NGN_STAGE_SOURCE_ACCEPTED,
	NGN_STAGE_SOURCE_DONE,
	NGN_STAGE_GPU_TO_DONE,
	NGN_STAGE_GPU_DONE,
	NGN_STAGE_SINK_ACCEPTED,
	NGN_STAGE_COMPLETE,
	NGN_STAGE_SEQUESTERED,
};

enum ngn_gpu_direction {
	NGN_GPU_GPU_TO_UMEM = 0,
	NGN_GPU_UMEM_TO_GPU = 1,
};

/*
 * One entry follows one XSK frame from its source boundary to the exact sink
 * completion.  The entry is deliberately independent of NVMe and AF_XDP ring
 * indices: both rings can complete out of order, while frame_addr remains the
 * stable backing identity.
 */
struct ngn_frame_journal {
	enum ngn_chain_direction direction;
	enum ngn_chain_stage stage;
	uint64_t chain_id;
	uint64_t request_id;
	uint32_t generation;
	uint64_t frame_addr;
	bool owns_backing;
};

struct ngn_gpu_span {
	uint64_t frame_addr;
	uint64_t umem_offset;
	uint64_t gpu_offset;
	uint64_t length;
};

struct ngn_gpu_transfer {
	uint64_t umem_offset;
	uint64_t gpu_offset;
	uint64_t length;
};

struct ngn_gpu_window {
	uint64_t umem_bytes;
	uint64_t gpu_bytes;
	uint32_t frame_size;
};

struct ngn_gpu_ops {
	/*
	 * This operation is synchronous. completed is the exact successful
	 * prefix.  ambiguous is true when an item outside that prefix might have
	 * reached hardware.  Callers never replay a failed call.
	 */
	int (*submit_sync)(void *opaque, enum ngn_gpu_direction direction,
			   const struct ngn_gpu_transfer *transfers,
			   uint32_t count, uint32_t *completed,
			   bool *ambiguous);
};

static inline bool ngn_u64_add_overflow(uint64_t left, uint64_t right,
					uint64_t *sum)
{
	*sum = left + right;
	return *sum < left;
}

static inline int
ngn_journal_begin(struct ngn_frame_journal *journal,
		  enum ngn_chain_direction direction, uint64_t chain_id,
		  uint64_t request_id, uint32_t generation, uint64_t frame_addr)
{
	if (!journal ||
	    (direction != NGN_NVME_GPU_NIC &&
	     direction != NGN_NIC_GPU_NVME))
		return -EINVAL;
	if (!chain_id || !generation)
		return -ENODATA;
	if (journal->owns_backing ||
	    (journal->stage != NGN_STAGE_FREE &&
	     journal->stage != NGN_STAGE_COMPLETE))
		return -EBUSY;
	*journal = (struct ngn_frame_journal) {
		.direction = direction,
		.stage = NGN_STAGE_PRIVATE,
		.chain_id = chain_id,
		.request_id = request_id,
		.generation = generation,
		.frame_addr = frame_addr,
		.owns_backing = true,
	};
	return 0;
}

static inline int
ngn_journal_source_accept(struct ngn_frame_journal *journal)
{
	if (!journal || !journal->owns_backing ||
	    journal->stage != NGN_STAGE_PRIVATE)
		return -EINVAL;
	journal->stage = NGN_STAGE_SOURCE_ACCEPTED;
	return 0;
}

static inline int
ngn_journal_source_complete(struct ngn_frame_journal *journal)
{
	if (!journal || !journal->owns_backing ||
	    journal->stage != NGN_STAGE_SOURCE_ACCEPTED)
		return -EINVAL;
	journal->stage = NGN_STAGE_SOURCE_DONE;
	return 0;
}

static inline int
ngn_journal_sink_accept(struct ngn_frame_journal *journal)
{
	if (!journal || !journal->owns_backing ||
	    journal->stage != NGN_STAGE_GPU_DONE)
		return -EINVAL;
	journal->stage = NGN_STAGE_SINK_ACCEPTED;
	return 0;
}

static inline int
ngn_journal_sink_complete(struct ngn_frame_journal *journal)
{
	if (!journal)
		return -EINVAL;
	if (journal->stage == NGN_STAGE_COMPLETE && !journal->owns_backing)
		return -EALREADY;
	if (!journal->owns_backing ||
	    journal->stage != NGN_STAGE_SINK_ACCEPTED)
		return -EINVAL;
	journal->stage = NGN_STAGE_COMPLETE;
	journal->owns_backing = false;
	return 0;
}

static inline int
ngn_journal_abort_private(struct ngn_frame_journal *journal)
{
	if (!journal || !journal->owns_backing)
		return -EINVAL;
	if (journal->stage == NGN_STAGE_SOURCE_ACCEPTED ||
	    journal->stage == NGN_STAGE_SINK_ACCEPTED ||
	    journal->stage == NGN_STAGE_SEQUESTERED)
		return -EBUSY;
	if (journal->stage != NGN_STAGE_PRIVATE &&
	    journal->stage != NGN_STAGE_SOURCE_DONE &&
	    journal->stage != NGN_STAGE_GPU_DONE)
		return -EPROTO;
	journal->stage = NGN_STAGE_COMPLETE;
	journal->owns_backing = false;
	return 0;
}

static inline void
ngn_journal_sequester(struct ngn_frame_journal *journals, uint32_t count)
{
	if (!journals)
		return;
	for (uint32_t i = 0; i < count; i++) {
		journals[i].stage = NGN_STAGE_SEQUESTERED;
		journals[i].owns_backing = true;
	}
}

static inline int
ngn_gpu_validate_frames(struct ngn_frame_journal *const *journals,
			uint32_t count, const struct ngn_gpu_span *spans,
			const struct ngn_gpu_window *window,
			struct ngn_gpu_transfer *transfers)
{
	uint64_t first_chain;
	uint64_t first_request;
	uint32_t first_generation;
	enum ngn_chain_direction first_direction;

	if (!journals || !spans || !window || !transfers || !count)
		return -EINVAL;
	if (count > NGN_GPU_MAX_BATCH)
		return -E2BIG;
	if (!window->umem_bytes || !window->gpu_bytes ||
	    !window->frame_size ||
	    (window->frame_size & (window->frame_size - 1)))
		return -EINVAL;
	if (!journals[0])
		return -EINVAL;
	first_chain = journals[0]->chain_id;
	first_request = journals[0]->request_id;
	first_generation = journals[0]->generation;
	first_direction = journals[0]->direction;
	for (uint32_t i = 0; i < count; i++) {
		const struct ngn_frame_journal *journal = journals[i];
		const struct ngn_gpu_span *span = &spans[i];
		uint64_t frame_end;
		uint64_t umem_end;
		uint64_t gpu_end;

		for (uint32_t j = 0; j < i; j++) {
			if (span->frame_addr == spans[j].frame_addr)
				return -EEXIST;
		}
		if (!journal || !journal->owns_backing ||
		    journal->stage != NGN_STAGE_SOURCE_DONE)
			return -EBUSY;
		if (!journal->chain_id || !journal->generation ||
		    journal->chain_id != first_chain ||
		    journal->request_id != first_request ||
		    journal->generation != first_generation ||
		    journal->direction != first_direction)
			return -ESTALE;
		if (span->frame_addr != journal->frame_addr ||
		    span->frame_addr % window->frame_size ||
		    ngn_u64_add_overflow(span->frame_addr, window->frame_size,
					 &frame_end) ||
		    frame_end > window->umem_bytes || !span->length ||
		    span->umem_offset < span->frame_addr ||
		    ngn_u64_add_overflow(span->umem_offset, span->length,
					 &umem_end) ||
		    umem_end > frame_end ||
		    ngn_u64_add_overflow(span->gpu_offset, span->length,
					 &gpu_end) ||
		    gpu_end > window->gpu_bytes)
			return -ERANGE;
		for (uint32_t j = 0; j < i; j++) {
			uint64_t prev_gpu_end =
				spans[j].gpu_offset + spans[j].length;

			if (span->gpu_offset < prev_gpu_end &&
			    spans[j].gpu_offset < gpu_end)
				return -EEXIST;
		}
		transfers[i] = (struct ngn_gpu_transfer) {
			.umem_offset = span->umem_offset,
			.gpu_offset = span->gpu_offset,
			.length = span->length,
		};
	}
	return 0;
}

static inline void
ngn_journal_sequester_frames(struct ngn_frame_journal *const *journals,
			      uint32_t count)
{
	if (!journals)
		return;
	for (uint32_t i = 0; i < count; i++) {
		if (!journals[i])
			continue;
		journals[i]->stage = NGN_STAGE_SEQUESTERED;
		journals[i]->owns_backing = true;
	}
}

static inline int
ngn_gpu_roundtrip_frames(struct ngn_frame_journal *const *journals,
			 uint32_t count, const struct ngn_gpu_span *spans,
			 const struct ngn_gpu_window *window,
			 const struct ngn_gpu_ops *ops, void *opaque)
{
	struct ngn_gpu_transfer transfers[NGN_GPU_MAX_BATCH];
	uint32_t completed = 0;
	bool ambiguous = false;
	int ret;

	if (!ops || !ops->submit_sync)
		return -EINVAL;
	ret = ngn_gpu_validate_frames(journals, count, spans, window, transfers);
	if (ret)
		return ret;
	ret = ops->submit_sync(opaque, NGN_GPU_UMEM_TO_GPU, transfers, count,
			       &completed, &ambiguous);
	if (ret || ambiguous || completed != count) {
		ngn_journal_sequester_frames(journals, count);
		return ret < 0 ? ret : -EPROTO;
	}
	for (uint32_t i = 0; i < count; i++)
		journals[i]->stage = NGN_STAGE_GPU_TO_DONE;

	completed = 0;
	ambiguous = false;
	ret = ops->submit_sync(opaque, NGN_GPU_GPU_TO_UMEM, transfers, count,
			       &completed, &ambiguous);
	if (ret || ambiguous || completed != count) {
		ngn_journal_sequester_frames(journals, count);
		return ret < 0 ? ret : -EPROTO;
	}
	for (uint32_t i = 0; i < count; i++)
		journals[i]->stage = NGN_STAGE_GPU_DONE;
	return 0;
}

static inline int
ngn_gpu_roundtrip(struct ngn_frame_journal *journals, uint32_t count,
		  const struct ngn_gpu_span *spans,
		  const struct ngn_gpu_window *window,
		  const struct ngn_gpu_ops *ops, void *opaque)
{
	struct ngn_frame_journal *frames[NGN_GPU_MAX_BATCH];

	if (!journals || !count)
		return -EINVAL;
	if (count > NGN_GPU_MAX_BATCH)
		return -E2BIG;
	for (uint32_t i = 0; i < count; i++)
		frames[i] = &journals[i];
	return ngn_gpu_roundtrip_frames(frames, count, spans, window,
					ops, opaque);
}

#endif /* NVME_GPU_NIC_CHAIN_CORE_H */
