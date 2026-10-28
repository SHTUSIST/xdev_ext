/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_TRACE_JOURNAL_H
#define _LINUX_XDEV_EXT_TRACE_JOURNAL_H
#ifndef XDEV_EXT_TRACE_JOURNAL_HOST
#include <linux/types.h>
#include <linux/errno.h>
#endif
/* Caller serializes this bounded metadata FIFO. No payload or DMA state. */
struct xdev_ext_trace_entry {
	u64 sequence, address;
	u32 bytes;
	int status;
};
struct xdev_ext_trace_journal {
	struct xdev_ext_trace_entry *entries;
	u32 capacity, head, count;
	u64 sequence;
};
static inline int xdev_ext_trace_push(struct xdev_ext_trace_journal *j,
				     u64 address, u32 bytes,
				     struct xdev_ext_trace_entry *out)
{
	if (j->count == j->capacity)
		return -ENOSPC;
	if (j->sequence == ~(u64)0)
		return -EOVERFLOW;
	*out = (struct xdev_ext_trace_entry) {
		.sequence = ++j->sequence, .address = address, .bytes = bytes,
	};
	j->entries[(j->head + j->count++) % j->capacity] = *out;
	return 0;
}
static inline int xdev_ext_trace_pop(struct xdev_ext_trace_journal *j,
				    struct xdev_ext_trace_entry *out)
{
	if (!j->count)
		return -ENODATA;
	*out = j->entries[j->head];
	j->head = (j->head + 1) % j->capacity;
	j->count--;
	return 0;
}
/* An error tag is observed native metadata, never successful DMA evidence. */
static inline int xdev_ext_trace_tail(struct xdev_ext_trace_journal *j,
				     u32 count, int status)
{
	u32 i;

	if (count > j->count)
		return -ENODATA;
	for (i = 0; i < count; i++)
		j->entries[(j->head + j->count - 1 - i) % j->capacity].status = status;
	return 0;
}
#endif
