/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_XSK_FRAME_OWNER_H
#define XDEV_EXT_XSK_FRAME_OWNER_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

enum xdev_ext_xsk_frame_state {
	XDEV_EXT_XSK_FRAME_FREE = 0,
	XDEV_EXT_XSK_FRAME_FILL,
	XDEV_EXT_XSK_FRAME_RX,
	XDEV_EXT_XSK_FRAME_TX,
	XDEV_EXT_XSK_FRAME_SEQUESTERED,
};

struct xdev_ext_xsk_frame_owner {
	uint8_t *states;
	uint32_t frame_count;
	uint32_t frame_size;
};

struct xdev_ext_xsk_recycle_queue {
	uint64_t *entries;
	uint32_t capacity;
	uint32_t head;
	uint32_t count;
};

static inline int
xdev_ext_xsk_recycle_init(struct xdev_ext_xsk_recycle_queue *queue, uint64_t *entries,
		     uint32_t capacity)
{
	if (!queue || !entries || !capacity)
		return -EINVAL;
	queue->entries = entries;
	queue->capacity = capacity;
	queue->head = 0;
	queue->count = 0;
	return 0;
}

static inline int
xdev_ext_xsk_recycle_push(struct xdev_ext_xsk_recycle_queue *queue, uint64_t frame_addr)
{
	uint32_t tail;

	if (!queue || !queue->entries || !queue->capacity)
		return -EINVAL;
	if (queue->count == queue->capacity)
		return -ENOSPC;
	tail = (queue->head + queue->count) % queue->capacity;
	queue->entries[tail] = frame_addr;
	queue->count++;
	return 0;
}

static inline int
xdev_ext_xsk_recycle_peek(const struct xdev_ext_xsk_recycle_queue *queue,
		     uint32_t offset, uint64_t *frame_addr)
{
	if (!queue || !queue->entries || !frame_addr || offset >= queue->count)
		return -ENOENT;
	*frame_addr = queue->entries[(queue->head + offset) % queue->capacity];
	return 0;
}

static inline int
xdev_ext_xsk_recycle_consume(struct xdev_ext_xsk_recycle_queue *queue, uint32_t count)
{
	if (!queue || count > queue->count)
		return -EINVAL;
	queue->head = (queue->head + count) % queue->capacity;
	queue->count -= count;
	return 0;
}

static inline uint32_t
xdev_ext_xsk_frame_count_state(const struct xdev_ext_xsk_frame_owner *owner, uint8_t state)
{
	uint32_t count = 0;
	uint32_t i;

	if (!owner || !owner->states)
		return 0;
	for (i = 0; i < owner->frame_count; i++)
		count += owner->states[i] == state;
	return count;
}

static inline int
xdev_ext_xsk_frame_owner_init(struct xdev_ext_xsk_frame_owner *owner, uint8_t *states,
			 uint32_t frame_count, uint32_t frame_size)
{
	if (!owner || !states || !frame_count || !frame_size ||
	    (frame_size & (frame_size - 1)))
		return -EINVAL;
	owner->states = states;
	owner->frame_count = frame_count;
	owner->frame_size = frame_size;
	memset(states, XDEV_EXT_XSK_FRAME_FREE, frame_count);
	return 0;
}

static inline void
xdev_ext_xsk_frame_owner_reset(struct xdev_ext_xsk_frame_owner *owner)
{
	if (owner && owner->states)
		memset(owner->states, XDEV_EXT_XSK_FRAME_FREE, owner->frame_count);
}

static inline int
xdev_ext_xsk_frame_index(const struct xdev_ext_xsk_frame_owner *owner,
		    uint64_t frame_addr, uint32_t *frame_index)
{
	uint64_t index;

	if (!owner || !owner->states || !frame_index || !owner->frame_size)
		return -EINVAL;
	if (frame_addr % owner->frame_size)
		return -EINVAL;
	index = frame_addr / owner->frame_size;
	if (index >= owner->frame_count)
		return -ERANGE;
	*frame_index = (uint32_t)index;
	return 0;
}

static inline int
xdev_ext_xsk_frame_transition(struct xdev_ext_xsk_frame_owner *owner,
			 uint64_t frame_addr, uint8_t from, uint8_t to,
			 int state_error)
{
	uint32_t frame_index;
	int ret;

	ret = xdev_ext_xsk_frame_index(owner, frame_addr, &frame_index);
	if (ret)
		return ret;
	if (owner->states[frame_index] != from)
		return state_error;
	owner->states[frame_index] = to;
	return 0;
}

static inline int
xdev_ext_xsk_frame_to_fill(struct xdev_ext_xsk_frame_owner *owner, uint64_t frame_addr)
{
	return xdev_ext_xsk_frame_transition(owner, frame_addr, XDEV_EXT_XSK_FRAME_FREE,
					XDEV_EXT_XSK_FRAME_FILL, -EBUSY);
}

static inline int
xdev_ext_xsk_frame_from_rx(struct xdev_ext_xsk_frame_owner *owner, uint64_t frame_addr)
{
	return xdev_ext_xsk_frame_transition(owner, frame_addr, XDEV_EXT_XSK_FRAME_FILL,
					XDEV_EXT_XSK_FRAME_RX, -EPROTO);
}

static inline int
xdev_ext_xsk_frame_to_tx(struct xdev_ext_xsk_frame_owner *owner, uint64_t frame_addr)
{
	return xdev_ext_xsk_frame_transition(owner, frame_addr, XDEV_EXT_XSK_FRAME_RX,
					XDEV_EXT_XSK_FRAME_TX, -EPROTO);
}

static inline int
xdev_ext_xsk_frame_drop_rx(struct xdev_ext_xsk_frame_owner *owner, uint64_t frame_addr)
{
	return xdev_ext_xsk_frame_transition(owner, frame_addr, XDEV_EXT_XSK_FRAME_RX,
					XDEV_EXT_XSK_FRAME_FREE, -EBUSY);
}

static inline int
xdev_ext_xsk_frame_sequester_rx(struct xdev_ext_xsk_frame_owner *owner,
			    uint64_t frame_addr)
{
	return xdev_ext_xsk_frame_transition(owner, frame_addr, XDEV_EXT_XSK_FRAME_RX,
					XDEV_EXT_XSK_FRAME_SEQUESTERED, -EBUSY);
}

static inline int
xdev_ext_xsk_frame_complete_tx(struct xdev_ext_xsk_frame_owner *owner,
			  uint64_t frame_addr)
{
	return xdev_ext_xsk_frame_transition(owner, frame_addr, XDEV_EXT_XSK_FRAME_TX,
					XDEV_EXT_XSK_FRAME_FREE, -EPROTO);
}

#endif /* XDEV_EXT_XSK_FRAME_OWNER_H */
