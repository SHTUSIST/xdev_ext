/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_USER_CORE_H
#define XDEV_EXT_MECH_USER_CORE_H

/*
 * Pure rules of the USER stage class (io_uring/xdev_ext_mech_user.c,
 * Documentation/userspace-api/xdev_ext-user-stage.rst): the register-op
 * request, the shared-region layout, ring index arithmetic, completion
 * status and length rules.  The stage description CREATE accepts is in
 * xdev_ext_mech_step.h.
 * The kernel and tools/testing/selftests/xdev_ext_mech/user_stage compile
 * the same code.  Nothing here reads user memory: callers pass values they
 * already copied.
 */

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#endif
#include "../include/uapi/linux/xdev_ext_mech.h"

#define XDEV_EXT_USER_ERRNO_MAX		4095
#define XDEV_EXT_USER_ALIGN(x, a)	(((__u64)(x) + (a) - 1) & ~((__u64)(a) - 1))

static inline bool xdev_ext_user_pow2(__u32 n)
{
	return n && !(n & (n - 1));
}

/* 0, or -EINVAL unless @entries is a power of two in [1, XDEV_EXT_USER_RING_MAX]. */
static inline int xdev_ext_user_entries_check(__u32 entries)
{
	return xdev_ext_user_pow2(entries) && entries <= XDEV_EXT_USER_RING_MAX ? 0 : -EINVAL;
}

/* XDEV_EXT_MECH_OP_USER_STAGE request, as copied from user space. */
static inline int xdev_ext_user_request_check(const struct xdev_ext_mech_user_stage *r)
{
	if (r->size != sizeof(*r) || (r->flags & ~XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL) ||
	    r->rsvd || r->fd || r->off.mmap_size || r->off.hdr || r->off.ready ||
	    r->off.done || r->off.slots)
		return -EINVAL;
	if (r->eventfd < -1)
		return -EBADF;
	return xdev_ext_user_entries_check(r->entries);
}

/*
 * Offsets of the shared region for @entries: the header, then the ready
 * ring, the completion ring and the slot table, each 64-byte aligned;
 * mmap_size rounded up to @page_size.
 */
static inline int xdev_ext_user_layout(__u32 entries, __u32 page_size,
				       struct xdev_ext_user_ring_offsets *o)
{
	__u64 end;

	if (xdev_ext_user_entries_check(entries) || !xdev_ext_user_pow2(page_size))
		return -EINVAL;
	o->hdr = 0;
	o->ready = XDEV_EXT_USER_ALIGN(sizeof(struct xdev_ext_user_ring_hdr), 64);
	o->done = XDEV_EXT_USER_ALIGN(o->ready + (__u64)entries * sizeof(struct xdev_ext_user_ready), 64);
	o->slots = XDEV_EXT_USER_ALIGN(o->done + (__u64)entries * sizeof(struct xdev_ext_user_done), 64);
	end = o->slots + (__u64)entries * sizeof(struct xdev_ext_user_slot);
	o->mmap_size = XDEV_EXT_USER_ALIGN(end, page_size);
	return 0;
}

/* Entries between consumer and producer, or -EOVERFLOW past @entries. */
static inline int xdev_ext_user_ring_count(__u32 prod, __u32 cons, __u32 entries)
{
	__u32 n = prod - cons;

	return n <= entries ? (int)n : -EOVERFLOW;
}

/* Kernel producer: places left; 0 when full or the user's @cons is bogus. */
static inline __u32 xdev_ext_user_ring_room(__u32 prod, __u32 cons, __u32 entries)
{
	__u32 n = prod - cons;

	return n < entries ? entries - n : 0;
}

/*
 * ->submit, @room places left in the ready ring: 0 to hand the batch out.
 * A full ring is -EAGAIN, which the core retries, until the ring stayed full
 * for @timeout jiffies since the first refusal (*@since, *@full); then
 * -ETIMEDOUT fails the batch, as a held batch fails at its deadline.  Only
 * the user thread frees places, so room ends the wait.
 */
static inline int xdev_ext_user_full_wait(__u32 room, bool *full, unsigned long *since,
					  unsigned long now, unsigned long timeout)
{
	if (room) {
		*full = false;
		return 0;
	}
	if (!*full) {
		*full = true;
		*since = now;
	}
	return (long)(now - *since) >= (long)timeout ? -ETIMEDOUT : -EAGAIN;
}

/*
 * Kernel consumer of a ring user space produces: how many entries to read
 * at *@cons.  A producer more than @entries ahead overwrote entries: read the
 * newest @entries.  One behind the consumer is garbage: read none.  Both
 * move *@cons and set *@bad (one reject).
 */
static inline __u32 xdev_ext_user_done_window(__u32 prod, __u32 *cons, __u32 entries, bool *bad)
{
	__u32 n = prod - *cons;

	*bad = false;
	if (n <= entries)
		return n;
	*bad = true;
	if (n < 0x80000000U) {
		*cons = prod - entries;
		return entries;
	}
	*cons = prod;
	return 0;
}

/* Error a completion status fails the batch with; *@bad for a non-errno. */
static inline int xdev_ext_user_status_err(__s32 status, bool *bad)
{
	*bad = false;
	if (!status)
		return 0;
	if (status < 0 && status >= -XDEV_EXT_USER_ERRNO_MAX)
		return status;
	*bad = true;
	return -EPROTO;
}

/* One frame's output length: 1..@capacity, and in + @delta unless @varlen. */
static inline bool xdev_ext_user_len_ok(__u32 in_len, __u32 out_len, __u32 capacity,
					__s64 delta, bool varlen)
{
	if (!out_len || out_len > capacity)
		return false;
	return varlen || (__s64)out_len == (__s64)in_len + delta;
}

/* ->validate: exactly one descriptor, version 1, no flags. */
static inline int xdev_ext_user_desc_check(const struct xdev_ext_user_desc *d, __u32 n)
{
	return n == 1 && d->version == XDEV_EXT_USER_DESC_VERSION && !d->flags ? 0 : -EINVAL;
}
#endif
