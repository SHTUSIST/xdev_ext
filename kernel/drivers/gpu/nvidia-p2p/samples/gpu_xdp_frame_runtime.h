/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef GPU_XDP_FRAME_RUNTIME_H
#define GPU_XDP_FRAME_RUNTIME_H

#include <errno.h>
#include <stdint.h>
#include <xdp/xsk.h>

#include "../../../../tools/include/xdev_ext_xsk_frame_owner.h"

struct gpu_xdp_frame_runtime {
	struct xdev_ext_xsk_frame_owner owner;
	struct xdev_ext_xsk_recycle_queue recycle;
	uint64_t *expected_tx_addrs;
};

/* TX-only frames are acquired directly by the application and never pass
 * through FILL/RX ownership.  Keep the value outside the shared AF_XDP state
 * enum because this state is private to the CUDA sample's source pool. */
enum gpu_xdp_frame_state {
	GPU_XDP_FRAME_APP = XDEV_EXT_XSK_FRAME_SEQUESTERED + 1,
};

/* libxdp 1.6.x does not expose the producer-side cancel helper carried by
 * current kernel AF_XDP selftests.  A reservation only advances cached_prod;
 * rolling it back before submit must leave the shared producer untouched. */
static inline void
gpu_xdp_ring_prod_cancel(struct xsk_ring_prod *producer, uint32_t reserved)
{
	producer->cached_prod -= reserved;
}

static inline int
gpu_xdp_frame_runtime_init(struct gpu_xdp_frame_runtime *runtime,
			   uint8_t *states, uint64_t *recycle_entries,
			   uint64_t *expected_tx_addrs,
			   uint32_t frame_count, uint32_t frame_size)
{
	uint32_t i;
	int ret;

	if (!runtime || !expected_tx_addrs)
		return -EINVAL;
	ret = xdev_ext_xsk_frame_owner_init(&runtime->owner, states, frame_count,
				       frame_size);
	if (ret)
		return ret;
	ret = xdev_ext_xsk_recycle_init(&runtime->recycle, recycle_entries,
				   frame_count);
	if (ret)
		return ret;
	runtime->expected_tx_addrs = expected_tx_addrs;
	for (i = 0; i < frame_count; i++)
		runtime->expected_tx_addrs[i] = UINT64_MAX;
	return 0;
}

static inline uint64_t
gpu_xdp_frame_base(const struct gpu_xdp_frame_runtime *runtime,
		   uint64_t descriptor_addr)
{
	uint64_t addr = xsk_umem__extract_addr(descriptor_addr);

	return addr & ~((uint64_t)runtime->owner.frame_size - 1);
}

static inline int
gpu_xdp_frame_accept_rx(struct gpu_xdp_frame_runtime *runtime,
			const struct xdp_desc *desc, uint64_t umem_size,
			uint64_t *frame_base, uint64_t *data_offset)
{
	uint64_t base;
	uint64_t data;
	uint64_t in_frame;
	int ret;

	if (!runtime || !desc || !frame_base || !data_offset)
		return -EINVAL;
	base = gpu_xdp_frame_base(runtime, desc->addr);
	ret = xdev_ext_xsk_frame_from_rx(&runtime->owner, base);
	if (ret)
		return ret;
	/* This sample does not enable XDP_USE_SG or TX metadata. */
	if (desc->options) {
		ret = -EOPNOTSUPP;
		goto invalid;
	}
	data = xsk_umem__add_offset_to_addr(desc->addr);
	if (data < base) {
		ret = -ERANGE;
		goto invalid;
	}
	in_frame = data - base;
	if (base >= umem_size || data >= umem_size ||
	    in_frame >= runtime->owner.frame_size ||
	    desc->len > runtime->owner.frame_size - in_frame ||
	    desc->len > umem_size - data) {
		ret = -EMSGSIZE;
		goto invalid;
	}
	*frame_base = base;
	*data_offset = data;
	return 0;

invalid:
	if (xdev_ext_xsk_frame_drop_rx(&runtime->owner, base) ||
	    xdev_ext_xsk_recycle_push(&runtime->recycle, base))
		return -EPROTO;
	return ret;
}

static inline int
gpu_xdp_frame_drop_rx(struct gpu_xdp_frame_runtime *runtime,
		      uint64_t frame_base)
{
	int ret;

	ret = xdev_ext_xsk_frame_drop_rx(&runtime->owner, frame_base);
	if (ret)
		return ret;
	return xdev_ext_xsk_recycle_push(&runtime->recycle, frame_base);
}

static inline int
gpu_xdp_frame_sequester_rx(struct gpu_xdp_frame_runtime *runtime,
			    uint64_t frame_base)
{
	return xdev_ext_xsk_frame_sequester_rx(&runtime->owner, frame_base);
}

static inline int
gpu_xdp_frame_acquire_app(struct gpu_xdp_frame_runtime *runtime,
			  uint64_t *frame_base)
{
	uint64_t addr;
	uint32_t frame_index;
	int ret;

	if (!runtime || !frame_base)
		return -EINVAL;
	ret = xdev_ext_xsk_recycle_peek(&runtime->recycle, 0, &addr);
	if (ret)
		return ret;
	ret = xdev_ext_xsk_frame_index(&runtime->owner, addr, &frame_index);
	if (ret)
		return ret;
	if (runtime->owner.states[frame_index] != XDEV_EXT_XSK_FRAME_FREE)
		return -EPROTO;
	ret = xdev_ext_xsk_frame_transition(&runtime->owner, addr,
				       XDEV_EXT_XSK_FRAME_FREE,
				       GPU_XDP_FRAME_APP, -EBUSY);
	if (ret)
		return ret;
	ret = xdev_ext_xsk_recycle_consume(&runtime->recycle, 1);
	if (ret) {
		(void)xdev_ext_xsk_frame_transition(&runtime->owner, addr,
					       GPU_XDP_FRAME_APP,
					       XDEV_EXT_XSK_FRAME_FREE, -EPROTO);
		return ret;
	}
	*frame_base = addr;
	return 0;
}

static inline int
gpu_xdp_frame_sequester_app(struct gpu_xdp_frame_runtime *runtime,
			     uint64_t frame_base)
{
	if (!runtime)
		return -EINVAL;
	return xdev_ext_xsk_frame_transition(&runtime->owner, frame_base,
					GPU_XDP_FRAME_APP,
					XDEV_EXT_XSK_FRAME_SEQUESTERED, -EBUSY);
}

static inline int
gpu_xdp_frame_sequester_unpublished_tx(
	struct gpu_xdp_frame_runtime *runtime, uint64_t frame_base)
{
	if (!runtime)
		return -EINVAL;
	return xdev_ext_xsk_frame_transition(&runtime->owner, frame_base,
					XDEV_EXT_XSK_FRAME_TX,
					XDEV_EXT_XSK_FRAME_SEQUESTERED, -EBUSY);
}

static inline int
gpu_xdp_frame_release_app(struct gpu_xdp_frame_runtime *runtime,
			  uint64_t frame_base)
{
	int ret;

	if (!runtime)
		return -EINVAL;
	ret = xdev_ext_xsk_frame_transition(&runtime->owner, frame_base,
				       GPU_XDP_FRAME_APP,
				       XDEV_EXT_XSK_FRAME_FREE, -EBUSY);
	if (ret)
		return ret;
	ret = xdev_ext_xsk_recycle_push(&runtime->recycle, frame_base);
	if (ret) {
		(void)xdev_ext_xsk_frame_transition(&runtime->owner, frame_base,
					       XDEV_EXT_XSK_FRAME_FREE,
					       GPU_XDP_FRAME_APP, -EPROTO);
		return ret;
	}
	return 0;
}

static inline int
gpu_xdp_frame_submit_tx(struct gpu_xdp_frame_runtime *runtime,
			uint64_t frame_base, uint64_t descriptor_addr)
{
	uint32_t frame_index;
	int ret;

	if (!runtime || !runtime->expected_tx_addrs)
		return -EINVAL;
	if (gpu_xdp_frame_base(runtime, descriptor_addr) != frame_base)
		return -EXDEV;
	ret = xdev_ext_xsk_frame_index(&runtime->owner, frame_base, &frame_index);
	if (ret)
		return ret;
	if (runtime->expected_tx_addrs[frame_index] != UINT64_MAX)
		return -EPROTO;
	ret = xdev_ext_xsk_frame_to_tx(&runtime->owner, frame_base);
	if (ret)
		return ret;
	runtime->expected_tx_addrs[frame_index] = descriptor_addr;
	return 0;
}

static inline int
gpu_xdp_frame_validate_app_tx(struct gpu_xdp_frame_runtime *runtime,
			      uint64_t frame_base, uint64_t descriptor_addr)
{
	uint32_t frame_index;
	int ret;

	if (!runtime || !runtime->expected_tx_addrs)
		return -EINVAL;
	if (gpu_xdp_frame_base(runtime, descriptor_addr) != frame_base)
		return -EXDEV;
	ret = xdev_ext_xsk_frame_index(&runtime->owner, frame_base, &frame_index);
	if (ret)
		return ret;
	if (runtime->expected_tx_addrs[frame_index] != UINT64_MAX)
		return -EPROTO;
	if (runtime->owner.states[frame_index] != GPU_XDP_FRAME_APP)
		return -EPROTO;
	return 0;
}

static inline int
gpu_xdp_frame_submit_app_tx(struct gpu_xdp_frame_runtime *runtime,
			    uint64_t frame_base, uint64_t descriptor_addr)
{
	uint32_t frame_index;
	int ret;

	ret = gpu_xdp_frame_validate_app_tx(runtime, frame_base,
					    descriptor_addr);
	if (ret)
		return ret;
	ret = xdev_ext_xsk_frame_index(&runtime->owner, frame_base, &frame_index);
	if (ret)
		return ret;
	ret = xdev_ext_xsk_frame_transition(&runtime->owner, frame_base,
				       GPU_XDP_FRAME_APP,
				       XDEV_EXT_XSK_FRAME_TX, -EPROTO);
	if (ret)
		return ret;
	runtime->expected_tx_addrs[frame_index] = descriptor_addr;
	return 0;
}

static inline int
gpu_xdp_reap_completions(struct gpu_xdp_frame_runtime *runtime,
			 struct xsk_ring_cons *cq, uint32_t budget)
{
	uint32_t index;
	uint32_t completed;
	uint32_t i;
	int ret = 0;

	completed = xsk_ring_cons__peek(cq, budget, &index);
	for (i = 0; i < completed; i++) {
		uint64_t completion_addr =
			*xsk_ring_cons__comp_addr(cq, index + i);
		uint64_t base = gpu_xdp_frame_base(runtime, completion_addr);
		uint32_t frame_index;

		if (xdev_ext_xsk_frame_index(&runtime->owner, base, &frame_index) ||
		    runtime->expected_tx_addrs[frame_index] != completion_addr ||
		    xdev_ext_xsk_frame_complete_tx(&runtime->owner, base)) {
			ret = -EPROTO;
			continue;
		}
		runtime->expected_tx_addrs[frame_index] = UINT64_MAX;
		if (xdev_ext_xsk_recycle_push(&runtime->recycle, base))
			ret = -EPROTO;
	}
	if (completed)
		xsk_ring_cons__release(cq, completed);
	return ret ? ret : (int)completed;
}

static inline int
gpu_xdp_refill(struct gpu_xdp_frame_runtime *runtime,
	       struct xsk_ring_prod *fq, uint32_t budget)
{
	uint32_t index;
	uint32_t wanted;
	uint32_t reserved;
	uint32_t i;
	uint64_t addr;

	if (!runtime || !fq)
		return -EINVAL;
	wanted = runtime->recycle.count;
	if (wanted > budget)
		wanted = budget;
	if (!wanted)
		return 0;

	/* Validate the complete batch before reserving producer entries. */
	for (i = 0; i < wanted; i++) {
		uint32_t frame_index;

		if (xdev_ext_xsk_recycle_peek(&runtime->recycle, i, &addr) ||
		    xdev_ext_xsk_frame_index(&runtime->owner, addr, &frame_index) ||
		    runtime->owner.states[frame_index] != XDEV_EXT_XSK_FRAME_FREE)
			return -EPROTO;
	}

	reserved = xsk_ring_prod__reserve(fq, wanted, &index);
	for (i = 0; i < reserved; i++) {
		(void)xdev_ext_xsk_recycle_peek(&runtime->recycle, i, &addr);
		if (xdev_ext_xsk_frame_to_fill(&runtime->owner, addr))
			return -EPROTO;
		*xsk_ring_prod__fill_addr(fq, index + i) = addr;
	}
	if (reserved) {
		xsk_ring_prod__submit(fq, reserved);
		(void)xdev_ext_xsk_recycle_consume(&runtime->recycle, reserved);
	}
	return (int)reserved;
}

#endif /* GPU_XDP_FRAME_RUNTIME_H */
