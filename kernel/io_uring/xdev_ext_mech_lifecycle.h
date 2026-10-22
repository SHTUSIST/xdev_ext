/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_LIFECYCLE_H
#define IO_URING_XDEV_EXT_MECH_LIFECYCLE_H

/* CPU ownership publication only; device DMA synchronization is separate. */
#ifdef __KERNEL__
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/types.h>
#define XDEV_EXT_L_LOAD(p) smp_load_acquire(p)
#define XDEV_EXT_L_STORE(p, v) smp_store_release(p, v)
#define XDEV_EXT_L_CAS(p, old, v) try_cmpxchg(p, old, v)
#else
#include <errno.h>
#include <stdbool.h>
#include <linux/types.h>
#define XDEV_EXT_L_LOAD(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)
#define XDEV_EXT_L_STORE(p, v) __atomic_store_n(p, v, __ATOMIC_RELEASE)
#define XDEV_EXT_L_CAS(p, old, v) \
	__atomic_compare_exchange_n(p, old, v, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
#endif

#define XDEV_EXT_MECH_L_FREE 0U
#define XDEV_EXT_MECH_L_IO_PENDING 1U
#define XDEV_EXT_MECH_L_READY 2U
#define XDEV_EXT_MECH_L_OUT_PENDING 3U
#define XDEV_EXT_MECH_L_GEN_MAX ((~(__u64)0) >> 3)
/* Remember the original READY phase without adding a second owner word. */
#define XDEV_EXT_MECH_L_IO_FROM_READY 5U
#define XDEV_EXT_MECH_L_PUBLISHING 6U
#define XDEV_EXT_MECH_L_MASK 7U

struct xdev_ext_mech_life {
	__u64 ctrl __attribute__((aligned(8)));
	__u32 valid_len;
};

static inline void xdev_ext_mech_life_init(struct xdev_ext_mech_life *l)
{
	l->valid_len = 0;
	l->ctrl = 0;
}

static inline __u32 xdev_ext_mech_life_phase(const struct xdev_ext_mech_life *l)
{
	__u32 p = XDEV_EXT_L_LOAD(&l->ctrl) & XDEV_EXT_MECH_L_MASK;

	return p == XDEV_EXT_MECH_L_IO_FROM_READY || p == XDEV_EXT_MECH_L_PUBLISHING ?
		XDEV_EXT_MECH_L_IO_PENDING : p;
}

static inline __u64 xdev_ext_mech_life_token(const struct xdev_ext_mech_life *l)
{
	return XDEV_EXT_L_LOAD(&l->ctrl) >> 3;
}

static inline int xdev_ext_mech_life_begin_produce(struct xdev_ext_mech_life *l,
					     bool from_ready, __u64 *token)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;
	__u32 from = from_ready ? XDEV_EXT_MECH_L_READY : XDEV_EXT_MECH_L_FREE;

	if ((old & XDEV_EXT_MECH_L_MASK) != from)
		return -EBUSY;
	if ((old >> 3) == XDEV_EXT_MECH_L_GEN_MAX)
		return -EOVERFLOW;
	next = (((old >> 3) + 1) << 3) |
		(from_ready ? XDEV_EXT_MECH_L_IO_FROM_READY : XDEV_EXT_MECH_L_IO_PENDING);
	if (!XDEV_EXT_L_CAS(&l->ctrl, &old, next))
		return -EBUSY;
	*token = next >> 3;
	return 0;
}

static inline int xdev_ext_mech_life_publish(struct xdev_ext_mech_life *l,
				       __u64 token, __u32 valid_len)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl);
	__u32 p = old & XDEV_EXT_MECH_L_MASK;

	if (!token || token > XDEV_EXT_MECH_L_GEN_MAX || (old >> 3) != token ||
	    (p != XDEV_EXT_MECH_L_IO_PENDING && p != XDEV_EXT_MECH_L_IO_FROM_READY))
		return -ESTALE;
	if (!XDEV_EXT_L_CAS(&l->ctrl, &old, (token << 3) | XDEV_EXT_MECH_L_PUBLISHING))
		return -ESTALE;
	/* Only the winner writes metadata, before READY release publication. */
	l->valid_len = valid_len;
	XDEV_EXT_L_STORE(&l->ctrl, (token << 3) | XDEV_EXT_MECH_L_READY);
	return 0;
}

static inline int xdev_ext_mech_life_begin_consume(struct xdev_ext_mech_life *l,
					     __u64 *token)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;

	if ((old & XDEV_EXT_MECH_L_MASK) != XDEV_EXT_MECH_L_READY)
		return -EBUSY;
	if ((old >> 3) == XDEV_EXT_MECH_L_GEN_MAX)
		return -EOVERFLOW;
	next = (((old >> 3) + 1) << 3) | XDEV_EXT_MECH_L_OUT_PENDING;
	if (!XDEV_EXT_L_CAS(&l->ctrl, &old, next))
		return -EBUSY;
	*token = next >> 3;
	return 0;
}

static inline int xdev_ext_mech_life_complete_consume(struct xdev_ext_mech_life *l,
						__u64 token)
{
	__u64 old = (token << 3) | XDEV_EXT_MECH_L_OUT_PENDING;

	if (!token || token > XDEV_EXT_MECH_L_GEN_MAX ||
	    !XDEV_EXT_L_CAS(&l->ctrl, &old, (token << 3) | XDEV_EXT_MECH_L_READY))
		return -ESTALE;
	return 0;
}

static inline int xdev_ext_mech_life_rollback(struct xdev_ext_mech_life *l, __u64 token,
					__u32 previous_phase)
{
	__u64 old;
	__u32 p;

	if (!token || token > XDEV_EXT_MECH_L_GEN_MAX)
		return -ESTALE;
	old = XDEV_EXT_L_LOAD(&l->ctrl);
	p = old & XDEV_EXT_MECH_L_MASK;
	if ((old >> 3) != token)
		return -ESTALE;
	if (!((p == XDEV_EXT_MECH_L_IO_PENDING && previous_phase == XDEV_EXT_MECH_L_FREE) ||
	      (p == XDEV_EXT_MECH_L_IO_FROM_READY && previous_phase == XDEV_EXT_MECH_L_READY) ||
	      (p == XDEV_EXT_MECH_L_OUT_PENDING && previous_phase == XDEV_EXT_MECH_L_READY)))
		return -EINVAL;
	return XDEV_EXT_L_CAS(&l->ctrl, &old, (token << 3) | previous_phase) ? 0 : -ESTALE;
}

/* Accepted producer failure invalidates any prior payload; never publish READY. */
static inline int xdev_ext_mech_life_fail_produce(struct xdev_ext_mech_life *l, __u64 token)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl);
	__u32 p = old & XDEV_EXT_MECH_L_MASK;

	if (!token || token > XDEV_EXT_MECH_L_GEN_MAX || (old >> 3) != token ||
	    (p != XDEV_EXT_MECH_L_IO_PENDING && p != XDEV_EXT_MECH_L_IO_FROM_READY))
		return -ESTALE;
	return XDEV_EXT_L_CAS(&l->ctrl, &old, token << 3) ? 0 : -ESTALE;
}

static inline int xdev_ext_mech_life_release(struct xdev_ext_mech_life *l, __u64 token)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl);

	if (!token || token > XDEV_EXT_MECH_L_GEN_MAX || (old >> 3) != token)
		return -ESTALE;
	if ((old & XDEV_EXT_MECH_L_MASK) == XDEV_EXT_MECH_L_FREE)
		return 0;
	if ((old & XDEV_EXT_MECH_L_MASK) != XDEV_EXT_MECH_L_READY)
		return -EBUSY;
	return XDEV_EXT_L_CAS(&l->ctrl, &old, token << 3) ? 0 : -ESTALE;
}

/* Native callback ownership, independent of the per-frame lifecycle. */
#define XDEV_EXT_MECH_C_IDLE 0U
#define XDEV_EXT_MECH_C_SUBMITTED 1U
#define XDEV_EXT_MECH_C_COMPLETING 2U
#define XDEV_EXT_MECH_C_LANDED 3U
#define XDEV_EXT_MECH_C_CONSUMING 4U
#define XDEV_EXT_MECH_C_PUBLISHING 5U
struct xdev_ext_mech_completion {
	__u64 ctrl __attribute__((aligned(8)));
	int result;
};

static inline void xdev_ext_mech_completion_init(struct xdev_ext_mech_completion *c)
{
	c->ctrl = 0;
	c->result = 0;
}

static inline int xdev_ext_mech_completion_begin(struct xdev_ext_mech_completion *c,
					   __u64 *ticket)
{
	__u64 old = XDEV_EXT_L_LOAD(&c->ctrl), next;

	if ((old & 7) != XDEV_EXT_MECH_C_IDLE)
		return -EBUSY;
	if ((old >> 3) == XDEV_EXT_MECH_L_GEN_MAX)
		return -EOVERFLOW;
	next = (((old >> 3) + 1) << 3) | XDEV_EXT_MECH_C_SUBMITTED;
	if (!XDEV_EXT_L_CAS(&c->ctrl, &old, next))
		return -EBUSY;
	*ticket = next >> 3;
	return 0;
}

static inline int xdev_ext_mech_completion_claim(struct xdev_ext_mech_completion *c,
					   __u64 ticket)
{
	__u64 old = (ticket << 3) | XDEV_EXT_MECH_C_SUBMITTED;

	if (!ticket || ticket > XDEV_EXT_MECH_L_GEN_MAX ||
	    !XDEV_EXT_L_CAS(&c->ctrl, &old, (ticket << 3) | XDEV_EXT_MECH_C_COMPLETING))
		return -ESTALE;
	return 0;
}

/* Split publication also protects the core's quarantine metadata. */
static inline int xdev_ext_mech_completion_publish_begin(struct xdev_ext_mech_completion *c,
						   __u64 ticket)
{
	__u64 old = (ticket << 3) | XDEV_EXT_MECH_C_COMPLETING;

	if (!ticket || ticket > XDEV_EXT_MECH_L_GEN_MAX ||
	    !XDEV_EXT_L_CAS(&c->ctrl, &old, (ticket << 3) | XDEV_EXT_MECH_C_PUBLISHING))
		return -ESTALE;
	return 0;
}

static inline void xdev_ext_mech_completion_publish_end(struct xdev_ext_mech_completion *c,
						  __u64 ticket, int result)
{
	c->result = result;
	XDEV_EXT_L_STORE(&c->ctrl, (ticket << 3) | XDEV_EXT_MECH_C_LANDED);
}

static inline int xdev_ext_mech_completion_publish(struct xdev_ext_mech_completion *c,
					     __u64 ticket, int result)
{
	int ret = xdev_ext_mech_completion_publish_begin(c, ticket);

	if (ret)
		return ret;
	xdev_ext_mech_completion_publish_end(c, ticket, result);
	return 0;
}

static inline int xdev_ext_mech_completion_consume(struct xdev_ext_mech_completion *c,
					     __u64 ticket, int *result)
{
	__u64 old = (ticket << 3) | XDEV_EXT_MECH_C_LANDED;

	if (!ticket || ticket > XDEV_EXT_MECH_L_GEN_MAX ||
	    !XDEV_EXT_L_CAS(&c->ctrl, &old, (ticket << 3) | XDEV_EXT_MECH_C_CONSUMING))
		return -ESTALE;
	*result = c->result;
	XDEV_EXT_L_STORE(&c->ctrl, ticket << 3);
	return 0;
}

static inline int xdev_ext_mech_completion_cancel(struct xdev_ext_mech_completion *c,
					    __u64 ticket)
{
	__u64 old = (ticket << 3) | XDEV_EXT_MECH_C_SUBMITTED;

	if (!ticket || ticket > XDEV_EXT_MECH_L_GEN_MAX ||
	    !XDEV_EXT_L_CAS(&c->ctrl, &old, ticket << 3))
		return -ESTALE;
	return 0;
}
#endif
