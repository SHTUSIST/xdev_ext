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

#ifdef XDEV_EXT_MECH_LIFE_LEGACY
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

#else
#define XDEV_EXT_MECH_LIFE_REFS 1
#define XDEV_EXT_MECH_L_FREE 0U
#define XDEV_EXT_MECH_L_IO_PENDING 1U
#define XDEV_EXT_MECH_L_READY 2U
#define XDEV_EXT_MECH_L_OUT_PENDING 3U
#define XDEV_EXT_MECH_L_STATE_MASK 0x3ULL
#define XDEV_EXT_MECH_L_BUSY_SHIFT 2
#define XDEV_EXT_MECH_L_BUSY_MASK (0xfULL << 2)
#define XDEV_EXT_MECH_L_REFS_SHIFT 6
#define XDEV_EXT_MECH_L_REFS_MASK (0x7ULL << 6)
#define XDEV_EXT_MECH_L_OWNER_SHIFT 9
#define XDEV_EXT_MECH_L_OWNER_MASK (0x7ULL << 9)
#define XDEV_EXT_MECH_L_GEN_SHIFT 12
#define XDEV_EXT_MECH_L_GEN_MAX ((~(__u64)0) >> 12)
#define XDEV_EXT_MECH_L_REFS_MAX 4U
#define XDEV_EXT_MECH_L_OWNER_START 4U
#define XDEV_EXT_MECH_L_OWNER_MAX 4U
#define XDEV_EXT_MECH_L_NO_OWNER (~0U)
#define XDEV_EXT_MECH_L_CLAIM_PRODUCE 1U
#define XDEV_EXT_MECH_L_CLAIM_SHARED 2U
#define XDEV_EXT_MECH_L_CLAIM_EXCLUSIVE 3U
#define XDEV_EXT_MECH_L_ACQ_FANOUT (1U << 0)
#define XDEV_EXT_MECH_L_ACQ_EXCLUSIVE (1U << 1)
#define XDEV_EXT_MECH_L_KEPT 0
#define XDEV_EXT_MECH_L_FREED 1

struct xdev_ext_mech_life {
	__u64 ctrl __attribute__((aligned(8)));
	__u32 valid_len;
};

static inline __u64 xdev_ext_mech_life_claim_gen(__u64 claim)
{
	return claim >> XDEV_EXT_MECH_L_GEN_SHIFT;
}

static inline __u32 xdev_ext_mech_life_claim_owner(__u64 claim)
{
	__u32 owner = (claim & XDEV_EXT_MECH_L_OWNER_MASK) >> XDEV_EXT_MECH_L_OWNER_SHIFT;

	return owner ? owner - 1 : XDEV_EXT_MECH_L_NO_OWNER;
}

static inline void xdev_ext_mech_life_init(struct xdev_ext_mech_life *l)
{
	l->ctrl = 0;
	l->valid_len = 0;
}

static inline __u32 xdev_ext_mech_life_phase(const struct xdev_ext_mech_life *l)
{
	return XDEV_EXT_L_LOAD(&l->ctrl) & XDEV_EXT_MECH_L_STATE_MASK;
}

static inline __u64 xdev_ext_mech_life_gen(const struct xdev_ext_mech_life *l)
{
	return XDEV_EXT_L_LOAD(&l->ctrl) >> XDEV_EXT_MECH_L_GEN_SHIFT;
}

static inline __u32 xdev_ext_mech_life_refs(const struct xdev_ext_mech_life *l)
{
	return (XDEV_EXT_L_LOAD(&l->ctrl) & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT;
}

static inline __u32 xdev_ext_mech_life_busy(const struct xdev_ext_mech_life *l)
{
	return (XDEV_EXT_L_LOAD(&l->ctrl) & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT;
}

static inline __u32 xdev_ext_mech_life_owner(const struct xdev_ext_mech_life *l)
{
	return xdev_ext_mech_life_claim_owner(XDEV_EXT_L_LOAD(&l->ctrl));
}

static inline __u64 xdev_ext_mech_life_word(__u64 gen, __u32 state,
		__u32 refs, __u32 busy, __u32 owner)
{
	return (gen << XDEV_EXT_MECH_L_GEN_SHIFT) | state |
		((__u64)refs << XDEV_EXT_MECH_L_REFS_SHIFT) |
		((__u64)busy << XDEV_EXT_MECH_L_BUSY_SHIFT) |
		((__u64)owner << XDEV_EXT_MECH_L_OWNER_SHIFT);
}

/* Check a single acquired snapshot; shared fan-out claims carry their own owner. */
static inline bool xdev_ext_mech_life_matches(__u64 word, __u64 claim)
{
	__u32 tag = xdev_ext_mech_life_claim_owner(claim);
	__u32 kind = claim & XDEV_EXT_MECH_L_STATE_MASK;
	__u32 state = word & XDEV_EXT_MECH_L_STATE_MASK;
	__u32 owner = xdev_ext_mech_life_claim_owner(word);
	__u32 busy = (word & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT;

	if (!claim || tag > XDEV_EXT_MECH_L_OWNER_MAX ||
	    xdev_ext_mech_life_claim_gen(word) != xdev_ext_mech_life_claim_gen(claim))
		return false;
	if (kind == XDEV_EXT_MECH_L_CLAIM_PRODUCE)
		return state == XDEV_EXT_MECH_L_IO_PENDING && owner == tag;
	if (state != XDEV_EXT_MECH_L_OUT_PENDING || tag >= XDEV_EXT_MECH_L_REFS_MAX ||
	    !(busy & (1U << tag)))
		return false;
	if (kind == XDEV_EXT_MECH_L_CLAIM_EXCLUSIVE)
		return owner == tag && busy == (1U << tag);
	return kind == XDEV_EXT_MECH_L_CLAIM_SHARED && owner == XDEV_EXT_MECH_L_NO_OWNER;
}

static inline int xdev_ext_mech_life_claim(struct xdev_ext_mech_life *l,
		__u32 owner, __u64 *claim)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;

	if (owner > XDEV_EXT_MECH_L_OWNER_MAX)
		return -EINVAL;
	if (xdev_ext_mech_life_claim_gen(old) == XDEV_EXT_MECH_L_GEN_MAX)
		return -EOVERFLOW;
	if ((old & XDEV_EXT_MECH_L_STATE_MASK) != XDEV_EXT_MECH_L_FREE)
		return -EBUSY;
	next = old | ((__u64)(owner + 1) << XDEV_EXT_MECH_L_OWNER_SHIFT) |
		XDEV_EXT_MECH_L_IO_PENDING;
	if (!XDEV_EXT_L_CAS(&l->ctrl, &old, next))
		return -EBUSY;
	*claim = next;
	return 0;
}

/* The batch completion-ticket winner alone calls publish/republish: validation
 * precedes the metadata store, then one release CAS publishes it. No transient
 * fifth state or second control-word store is needed. */
static inline int xdev_ext_mech_life_publish(struct xdev_ext_mech_life *l,
		__u64 claim, __u32 refs, __u32 valid_len)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;

	if (refs > XDEV_EXT_MECH_L_REFS_MAX)
		return -EINVAL;
	if ((claim & XDEV_EXT_MECH_L_STATE_MASK) != XDEV_EXT_MECH_L_CLAIM_PRODUCE ||
	    !xdev_ext_mech_life_matches(old, claim))
		return -ESTALE;
	next = xdev_ext_mech_life_word(xdev_ext_mech_life_claim_gen(old),
		XDEV_EXT_MECH_L_READY, refs, 0, 0);
	l->valid_len = valid_len;
	return XDEV_EXT_L_CAS(&l->ctrl, &old, next) ? 0 : -ESTALE;
}

static inline int xdev_ext_mech_life_acquire(struct xdev_ext_mech_life *l,
		__u32 stage, __u32 flags, __u64 *claim)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;
	__u32 state, busy, refs, exclusive = flags & XDEV_EXT_MECH_L_ACQ_EXCLUSIVE;

	if (stage >= XDEV_EXT_MECH_L_REFS_MAX ||
	    (flags & ~(XDEV_EXT_MECH_L_ACQ_FANOUT | XDEV_EXT_MECH_L_ACQ_EXCLUSIVE)) ||
	    flags == (XDEV_EXT_MECH_L_ACQ_FANOUT | XDEV_EXT_MECH_L_ACQ_EXCLUSIVE))
		return -EINVAL;
	do {
		state = old & XDEV_EXT_MECH_L_STATE_MASK;
		busy = (old & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT;
		refs = (old & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT;
		if (state != XDEV_EXT_MECH_L_READY &&
		    (state != XDEV_EXT_MECH_L_OUT_PENDING || !(flags & XDEV_EXT_MECH_L_ACQ_FANOUT)))
			return -EBUSY;
		if (busy & (1U << stage))
			return -EALREADY;
		if (exclusive && refs > 1)
			return -EBUSY;
		if (refs <= (__u32)__builtin_popcount(busy))
			return -ENOENT;
		if (old & XDEV_EXT_MECH_L_OWNER_MASK)
			return -EBUSY;
		next = xdev_ext_mech_life_word(xdev_ext_mech_life_claim_gen(old),
			XDEV_EXT_MECH_L_OUT_PENDING, refs, busy | (1U << stage), exclusive ? stage + 1 : 0);
	} while (!XDEV_EXT_L_CAS(&l->ctrl, &old, next));
	*claim = (next & ~((1ULL << XDEV_EXT_MECH_L_GEN_SHIFT) - 1)) |
		((__u64)(stage + 1) << XDEV_EXT_MECH_L_OWNER_SHIFT) |
		(exclusive ? XDEV_EXT_MECH_L_CLAIM_EXCLUSIVE : XDEV_EXT_MECH_L_CLAIM_SHARED);
	return 0;
}

static inline int xdev_ext_mech_life_drop(struct xdev_ext_mech_life *l,
		__u64 claim, bool failed)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;
	__u32 busy, refs;

	do {
		if ((claim & XDEV_EXT_MECH_L_STATE_MASK) == XDEV_EXT_MECH_L_CLAIM_PRODUCE ||
		    !xdev_ext_mech_life_matches(old, claim))
			return -ESTALE;
		busy = ((old & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT) &
			~(1U << xdev_ext_mech_life_claim_owner(claim));
		refs = failed ? (__u32)__builtin_popcount(busy) :
			((old & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT) - 1;
		next = xdev_ext_mech_life_word(xdev_ext_mech_life_claim_gen(old) + !refs,
			!refs ? XDEV_EXT_MECH_L_FREE : busy ? XDEV_EXT_MECH_L_OUT_PENDING : XDEV_EXT_MECH_L_READY,
			refs, busy, 0);
	} while (!XDEV_EXT_L_CAS(&l->ctrl, &old, next));
	return refs ? XDEV_EXT_MECH_L_KEPT : XDEV_EXT_MECH_L_FREED;
}

static inline int xdev_ext_mech_life_put(struct xdev_ext_mech_life *l, __u64 claim)
{
	return xdev_ext_mech_life_drop(l, claim, false);
}

static inline int xdev_ext_mech_life_fail_put(struct xdev_ext_mech_life *l, __u64 claim)
{
	return xdev_ext_mech_life_drop(l, claim, true);
}

static inline int xdev_ext_mech_life_fail_produce(struct xdev_ext_mech_life *l, __u64 claim)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;

	if ((claim & XDEV_EXT_MECH_L_STATE_MASK) != XDEV_EXT_MECH_L_CLAIM_PRODUCE ||
	    !xdev_ext_mech_life_matches(old, claim))
		return -ESTALE;
	next = (xdev_ext_mech_life_claim_gen(old) + 1) << XDEV_EXT_MECH_L_GEN_SHIFT;
	return XDEV_EXT_L_CAS(&l->ctrl, &old, next) ? 0 : -ESTALE;
}

static inline int xdev_ext_mech_life_rollback(struct xdev_ext_mech_life *l, __u64 claim)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;
	__u32 busy, refs;

	do {
		if (!xdev_ext_mech_life_matches(old, claim))
			return -ESTALE;
		if ((claim & XDEV_EXT_MECH_L_STATE_MASK) == XDEV_EXT_MECH_L_CLAIM_PRODUCE) {
			next = xdev_ext_mech_life_claim_gen(old) << XDEV_EXT_MECH_L_GEN_SHIFT;
		} else {
			busy = ((old & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT) &
				~(1U << xdev_ext_mech_life_claim_owner(claim));
			refs = (old & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT;
			next = xdev_ext_mech_life_word(xdev_ext_mech_life_claim_gen(old),
				busy ? XDEV_EXT_MECH_L_OUT_PENDING : XDEV_EXT_MECH_L_READY, refs, busy, 0);
		}
	} while (!XDEV_EXT_L_CAS(&l->ctrl, &old, next));
	return 0;
}

static inline int xdev_ext_mech_life_republish(struct xdev_ext_mech_life *l,
		__u64 claim, __u32 refs, __u32 valid_len)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl), next;

	if (refs > XDEV_EXT_MECH_L_REFS_MAX)
		return -EINVAL;
	if ((claim & XDEV_EXT_MECH_L_STATE_MASK) != XDEV_EXT_MECH_L_CLAIM_EXCLUSIVE ||
	    !xdev_ext_mech_life_matches(old, claim))
		return -ESTALE;
	next = xdev_ext_mech_life_word(xdev_ext_mech_life_claim_gen(old), XDEV_EXT_MECH_L_READY, refs, 0, 0);
	l->valid_len = valid_len;
	return XDEV_EXT_L_CAS(&l->ctrl, &old, next) ? 0 : -ESTALE;
}

static inline int xdev_ext_mech_life_release(struct xdev_ext_mech_life *l, __u64 gen)
{
	__u64 old = XDEV_EXT_L_LOAD(&l->ctrl);
	__u32 state = old & XDEV_EXT_MECH_L_STATE_MASK;

	if (state == XDEV_EXT_MECH_L_FREE)
		return -ENOENT;
	if (state != XDEV_EXT_MECH_L_READY)
		return -EBUSY;
	if (xdev_ext_mech_life_claim_gen(old) != gen)
		return -ESTALE;
	return XDEV_EXT_L_CAS(&l->ctrl, &old, (gen + 1) << XDEV_EXT_MECH_L_GEN_SHIFT) ? 0 : -ESTALE;
}

/* binding and dma are provider capability/mapping snapshots, not duplicate
 * ownership. closing belongs to the pool and is sampled by its frame accessor. */
struct xdev_ext_mech_frame_rec {
	__u64 pool_off, gen;
	__u32 page_pos, frame_size, valid_len, state, refs, busy, owner;
	__u32 binding, dma, closing;
};

static inline void xdev_ext_mech_frame_rec_fill(struct xdev_ext_mech_frame_rec *r,
		const struct xdev_ext_mech_life *l, __u32 index, __u32 frame_size,
		__u32 first_page_off, __u32 page_shift, __u32 binding, __u32 dma, bool closing)
{
	__u64 word = XDEV_EXT_L_LOAD(&l->ctrl);

	r->pool_off = (__u64)index * frame_size;
	r->page_pos = (first_page_off + r->pool_off) >> page_shift;
	r->frame_size = frame_size;
	r->valid_len = l->valid_len;
	r->gen = xdev_ext_mech_life_claim_gen(word);
	r->state = word & XDEV_EXT_MECH_L_STATE_MASK;
	r->refs = (word & XDEV_EXT_MECH_L_REFS_MASK) >> XDEV_EXT_MECH_L_REFS_SHIFT;
	r->busy = (word & XDEV_EXT_MECH_L_BUSY_MASK) >> XDEV_EXT_MECH_L_BUSY_SHIFT;
	r->owner = xdev_ext_mech_life_claim_owner(word);
	r->binding = binding;
	r->dma = dma;
	r->closing = closing;
}
#endif

/* Native callback ownership, independent of the per-frame lifecycle. */
#define XDEV_EXT_MECH_C_GEN_MAX ((~(__u64)0) >> 3)
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
	if ((old >> 3) == XDEV_EXT_MECH_C_GEN_MAX)
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

	if (!ticket || ticket > XDEV_EXT_MECH_C_GEN_MAX ||
	    !XDEV_EXT_L_CAS(&c->ctrl, &old, (ticket << 3) | XDEV_EXT_MECH_C_COMPLETING))
		return -ESTALE;
	return 0;
}

/* Split publication also protects the core's quarantine metadata. */
static inline int xdev_ext_mech_completion_publish_begin(struct xdev_ext_mech_completion *c,
						   __u64 ticket)
{
	__u64 old = (ticket << 3) | XDEV_EXT_MECH_C_COMPLETING;

	if (!ticket || ticket > XDEV_EXT_MECH_C_GEN_MAX ||
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

	if (!ticket || ticket > XDEV_EXT_MECH_C_GEN_MAX ||
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

	if (!ticket || ticket > XDEV_EXT_MECH_C_GEN_MAX ||
	    !XDEV_EXT_L_CAS(&c->ctrl, &old, ticket << 3))
		return -ESTALE;
	return 0;
}
#endif
