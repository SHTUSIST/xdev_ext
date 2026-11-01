/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_STEP_H
#define IO_URING_XDEV_EXT_MECH_STEP_H

/*
 * Pure decisions of the mechanism core (io_uring/xdev_ext_mech.c): admission of a
 * session composition at CREATE and START, class table sizes, and the step
 * the session worker takes after a build or complete callback.  Built on the
 * rules in xdev_ext_mech_core.h; the kernel and tools/testing/selftests/xdev_ext_mech
 * compile the same code.
 */

#include "xdev_ext_mech_core.h"
#include "xdev_ext_mech_cpu_core.h"
#ifdef __KERNEL__
#include <linux/xdev_ext_family_core.h>
#include <linux/xdev_ext_compfam_core.h>
#else
#include "../include/linux/xdev_ext_family_core.h"
#include "../include/linux/xdev_ext_compfam_core.h"
#endif

#define XDEV_EXT_MECH_MAX_DEPTH		64	/* live batches per session */
#define XDEV_EXT_MECH_CLASS_SIZE_MAX		4096	/* info, scratch, copies, batch area */

/* What the worker does next with a batch. */
enum xdev_ext_mech_step {
	XDEV_EXT_MECH_STEP_SUBMIT	= 0,	/* validate the program's scratch, submit */
	XDEV_EXT_MECH_STEP_DEFAULT,		/* the class default_build fills the scratch */
	XDEV_EXT_MECH_STEP_NEXT,		/* next stage, DONE after the last */
	XDEV_EXT_MECH_STEP_DONE,
	XDEV_EXT_MECH_STEP_RETRY,		/* the same stage again */
	XDEV_EXT_MECH_STEP_ABORT,
	XDEV_EXT_MECH_STEP_SEQUESTER,	/* the device may still use the frames */
};

static inline bool xdev_ext_mech_stage_zero(const struct xdev_ext_mech_stage_uapi *u)
{
	return !u->class_id && !u->direction && !u->fd && !u->flags &&
	       !u->arg0 && !u->arg1;
}

static inline int xdev_ext_mech_stage_role_desc(const struct xdev_ext_mech_class_desc *d,
 const struct xdev_ext_mech_stage_uapi *u)
{
 if (!d || !d->family || !d->role ||
     (u->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE && u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE))
  return -EINVAL;
 return d->role(u);
}

static inline int xdev_ext_mech_stage_role(const struct xdev_ext_mech_stage_uapi *u)
{
 return xdev_ext_mech_stage_role_desc(xdev_ext_mech_class_desc(u->class_id), u);
}

/* This header is also compiled by host tests without <assert.h>. */
_Static_assert(XDEV_EXT_MECH_ROLE_PRODUCER == 1 &&
	       XDEV_EXT_MECH_ROLE_CONSUMER == 2 &&
	       XDEV_EXT_MECH_ROLE_INPLACE == 3 &&
	       XDEV_EXT_MECH_ROLE_TRANSFORM == 4,
	       "xdev_ext_comp_kind_of_role() numbers the roles");

static inline int xdev_ext_comp_kind_of_desc(const struct xdev_ext_mech_class_desc *d,
 const struct xdev_ext_mech_stage_uapi *u)
{
 return xdev_ext_comp_kind_of_role_desc(d, xdev_ext_mech_stage_role_desc(d, u));
}

static inline int xdev_ext_comp_kind_of(const struct xdev_ext_mech_stage_uapi *u)
{
 return xdev_ext_comp_kind_of_desc(xdev_ext_mech_class_desc(u->class_id), u);
}

/* One role decision for both explicit-row and compatibility traversals. */
static inline bool xdev_ext_mech_chain_ref_next(int role, __u32 *refs)
{
 if (role < 0 || role == XDEV_EXT_MECH_ROLE_PRODUCER)
  return false;
 (*refs)++;
 return role == XDEV_EXT_MECH_ROLE_CONSUMER;
}

static inline __u32 xdev_ext_mech_chain_refs_desc(const struct xdev_ext_mech_stage_uapi *st,
 const struct xdev_ext_mech_class_desc *const *rows, __u32 nr_stages, __u32 from)
{
 __u32 refs = 0;

 for (; from < nr_stages; from++)
  if (!xdev_ext_mech_chain_ref_next(xdev_ext_mech_stage_role_desc(rows[from], &st[from]), &refs))
   break;
 return refs;
}

static inline __u32 xdev_ext_mech_chain_refs(const struct xdev_ext_mech_stage_uapi *st,
 __u32 nr_stages, __u32 from)
{
 __u32 refs = 0;

 for (; from < nr_stages; from++)
  if (!xdev_ext_mech_chain_ref_next(xdev_ext_mech_stage_role(&st[from]), &refs))
   break;
 return refs;
}

static inline __u32 xdev_ext_mech_stage_group_end(const struct xdev_ext_mech_stage_uapi *st,
 __u32 nr_stages, __u32 first)
{
 __u32 end = first + 1;

 while (end < nr_stages && (st[end].flags & XDEV_EXT_MECH_STAGE_F_FANOUT))
  end++;
 return end;
}

/*
 * Device-memory (PEER) pool: frames live in a provider allocation and have
 * no CPU address.  Which classes may DMA such a frame, and in which
 * direction, is one capability table per class; the chain shape is free.
 * The device capability of the bound endpoint is checked again at bind.
 * CE copies between host pages and a GPU window, so it never addresses a
 * PEER frame.
 */
#define XDEV_EXT_MECH_PEER_CAPS 1
#define XDEV_EXT_MECH_PEER_FRAME_MIN 4096U
#define XDEV_EXT_MECH_PEER_FRAME_MAX 2097152U /* 2 MiB */
/* XDEV_EXT_DMA_DIR_* bits each class implements over a PEER pool. */
static inline __u32 xdev_ext_mech_peer_dirs(__u32 class_id)
{
 return xdev_ext_mech_class_desc(class_id)->peer_dirs;
}
/* PEER frame capability; ordinary layout checks bound headroom and spans. */
static inline int xdev_ext_mech_peer_layout_check(const struct xdev_ext_mech_layout *l)
{
 if (!l || l->frame_size < XDEV_EXT_MECH_PEER_FRAME_MIN ||
     l->frame_size > XDEV_EXT_MECH_PEER_FRAME_MAX || (l->frame_size & (l->frame_size - 1)))
  return -EOPNOTSUPP;
 return 0;
}

/* CREATE: what every stage records before its class adds facts. */
static inline void xdev_ext_mech_stage_caps_default_desc(
 const struct xdev_ext_mech_class_desc *d, const struct xdev_ext_mech_stage_uapi *u,
						  __u32 pool_kind,
						  struct xdev_ext_mech_stage_caps *c)
{
	bool peer = d && d->family && pool_kind == XDEV_EXT_MECH_POOL_PEER &&
		    (d->peer_dirs & (1U << u->direction));
	__u32 na = XDEV_EXT_CAP_NOT_APPLICABLE;

	*c = (struct xdev_ext_mech_stage_caps){
		.size = sizeof(*c),
		.version = XDEV_EXT_MECH_STAGE_CAPS_VERSION,
		.family = d ? d->family : XDEV_EXT_FAMILY_NONE,
		.export_authority = peer ? XDEV_EXT_CAP_ESTABLISHED : na,
		.reachability = peer ? XDEV_EXT_CAP_UNKNOWN : na,
		.requester_mapping = peer ? XDEV_EXT_CAP_UNKNOWN : na,
		.native_queue = XDEV_EXT_CAP_UNKNOWN,
		.producer_visibility = peer ? XDEV_EXT_CAP_NOT_WIRED : na,
		.last_use_quiescence = peer ? XDEV_EXT_CAP_NOT_WIRED : na,
		.invalidation = peer ? XDEV_EXT_CAP_NOT_WIRED : na,
		.p2p_distance = -1,
	};
}

static inline void xdev_ext_mech_stage_caps_default(const struct xdev_ext_mech_stage_uapi *u,
 __u32 pool_kind, struct xdev_ext_mech_stage_caps *c)
{
 xdev_ext_mech_stage_caps_default_desc(xdev_ext_mech_class_desc(u->class_id), u, pool_kind, c);
}

/*
 * CREATE: 0 with *@frames the frames per batch, or -errno.  An AF_XDP stage
 * needs the socket's UMEM as the pool; AF_XDP RX feeds a chain, so it is
 * stage 0 of at least two.  On a PEER pool the generic checks of every stage
 * run first, then the geometry, then each stage's class capability.
 */
static inline int xdev_ext_mech_create_check_desc(const struct xdev_ext_mech_create *c,
 const struct xdev_ext_mech_class_desc *const rows[XDEV_EXT_MECH_MAX_STAGES], __u32 *frames)
{
	__u32 i;
	int nr;

	if (c->abi_version != XDEV_EXT_MECH_ABI_VERSION || !c->nr_stages ||
	    c->nr_stages > XDEV_EXT_MECH_MAX_STAGES)
		return -EINVAL;
	switch (c->pool_kind) {
	case XDEV_EXT_MECH_POOL_PEER:
	case XDEV_EXT_MECH_POOL_XSK:
		if (c->pool_fd < 0)
			return -EBADF;
		break;
	case XDEV_EXT_MECH_POOL_IOU_UMEM:
		if (c->pool_fd != -1)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	if (!c->depth || c->depth > XDEV_EXT_MECH_MAX_DEPTH || c->eventfd < -1)
		return -EINVAL;
	nr = xdev_ext_mech_layout_frames(&c->layout);
	if (nr < 0)
		return nr;

	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++) {
		struct xdev_ext_mech_stage_uapi clean = c->st[i];
		const struct xdev_ext_mech_stage_uapi *u = &clean;

		if (i >= c->nr_stages) {
			if (!xdev_ext_mech_stage_zero(u))
				return -EINVAL;
			continue;
		}
		/* Generic, for every class; its capability is checked at bind. */
		clean.flags &= ~XDEV_EXT_MECH_STAGE_F_POLL;
  if (u->flags & XDEV_EXT_MECH_STAGE_F_FANOUT) {
   if (!i || xdev_ext_mech_stage_role_desc(rows[i], u) != XDEV_EXT_MECH_ROLE_CONSUMER ||
       xdev_ext_mech_stage_role_desc(rows[i - 1], &c->st[i - 1]) != XDEV_EXT_MECH_ROLE_CONSUMER)
    return -EINVAL;
   clean.flags &= ~XDEV_EXT_MECH_STAGE_F_FANOUT;
  }
  /* A class whose DMA reaches device memory only. */
  if (rows[i] && rows[i]->peer_only && c->pool_kind != XDEV_EXT_MECH_POOL_PEER)
   return -EOPNOTSUPP;
  {
   const struct xdev_ext_mech_class_desc *d = rows[i];
   struct xdev_ext_mech_stage_facts facts = {};
   __u32 j;
   int err;

   if (!d || !d->family ||
       (!d->flags_later && ((u->flags & ~d->known_flags) || (d->flags_ok && !d->flags_ok(u->flags)))) ||
       (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE && u->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
    return -EINVAL;
   if (!d->check_stage)
    return -EINVAL;
   err = d->check_stage(c, i, u, &facts);
   if (err)
    return err;
   for (j = i + 1; facts.restrict_fixed_followers && j < c->nr_stages; j++) {
    if (xdev_ext_mech_stage_role_desc(rows[j], &c->st[j]) == XDEV_EXT_MECH_ROLE_TRANSFORM)
     break;
    if (rows[j] && rows[j]->fixed_group)
     return -EOPNOTSUPP;
   }
  }
	}
 if (c->pool_kind == XDEV_EXT_MECH_POOL_PEER) {
  int ret = xdev_ext_mech_peer_layout_check(&c->layout);

  if (ret)
   return ret;
  for (i = 0; i < c->nr_stages; i++)
   if (!rows[i] || !(rows[i]->peer_dirs & (1U << c->st[i].direction)))
    return -EOPNOTSUPP;
 }
	*frames = (__u32)nr;
	return 0;
}

static inline int xdev_ext_mech_create_check(const struct xdev_ext_mech_create *c, __u32 *frames)
{
 const struct xdev_ext_mech_class_desc *rows[XDEV_EXT_MECH_MAX_STAGES];
 __u32 i;

 for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++)
  rows[i] = xdev_ext_mech_class_desc(c->st[i].class_id);
 return xdev_ext_mech_create_check_desc(c, rows, frames);
}

/*
 * START of a session whose stage 0 is not AF_XDP RX.  User frames are for
 * the ring's UMEM only and must be exactly one span per batch, since every
 * batch hands its frames back to user space when it ends.  Explicit RECYCLE
 * instead keeps a depth-sized pool until the single START drains.  Keys
 * first_seq .. first_seq + nr_batches - 1 and the next sequence must not
 * wrap: an ordered stage holds a key only behind smaller keys.
 */
static inline int xdev_ext_mech_start_check(const struct xdev_ext_mech_start *st,
				       __u32 pool_kind, bool rx_first,
				       __u32 frames, __u32 pool_frames)
{
	__u64 need;

	if ((st->flags & ~XDEV_EXT_MECH_START_KNOWN_FLAGS) || rx_first ||
	    !st->nr_batches || st->nr_batches > XDEV_EXT_MECH_U64_MAX - st->first_seq)
		return -EINVAL;
	if (st->flags & XDEV_EXT_MECH_START_F_ORDERED_FRAMES) {
		if (!(st->flags & XDEV_EXT_MECH_START_F_USER_FRAMES))
			return -EINVAL;
		if (pool_kind == XDEV_EXT_MECH_POOL_XSK ||
		    (st->flags & XDEV_EXT_MECH_START_F_USER_SPANS))
			return -EOPNOTSUPP;
	}
	if (pool_kind == XDEV_EXT_MECH_POOL_PEER &&
	    (st->flags & XDEV_EXT_MECH_START_F_USER_FRAMES) &&
	    !(st->flags & XDEV_EXT_MECH_START_F_ORDERED_FRAMES))
		return -EOPNOTSUPP;
	if ((st->flags & XDEV_EXT_MECH_START_F_USER_SPANS) &&
	    (!(st->flags & XDEV_EXT_MECH_START_F_USER_FRAMES) ||
	     (st->flags & XDEV_EXT_MECH_START_F_RECYCLE) ||
	     frames != 1 || st->nr_batches != 1 || st->nr_user_frames != 1))
		return -EINVAL;
	if (!(st->flags & XDEV_EXT_MECH_START_F_USER_FRAMES))
		return st->nr_user_frames || st->user_frames ||
		       (st->flags & XDEV_EXT_MECH_START_F_RECYCLE) ? -EINVAL : 0;

	if (st->flags & XDEV_EXT_MECH_START_F_ORDERED_FRAMES) {
		if (!frames || (pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM &&
				pool_kind != XDEV_EXT_MECH_POOL_PEER))
			return -EINVAL;
		if (st->flags & XDEV_EXT_MECH_START_F_RECYCLE) {
			if (!st->nr_user_frames || st->nr_user_frames % frames ||
			    st->nr_user_frames / frames > st->nr_batches)
				return -EINVAL;
			need = st->nr_user_frames;
		} else {
			if (st->nr_batches > XDEV_EXT_MECH_U32_MAX / frames)
				return -EINVAL;
			need = st->nr_batches * frames;
			if (st->nr_user_frames != need)
				return -EINVAL;
		}
		if (need > pool_frames)
			return -ENOSPC;
		return st->user_frames ? 0 : -EFAULT;
	}
	if (pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM || !frames ||
	    st->nr_batches > XDEV_EXT_MECH_U32_MAX / frames)
		return -EINVAL;
	need = st->nr_batches * frames;
	if (st->flags & XDEV_EXT_MECH_START_F_RECYCLE) {
		/* CREATE depth bounds the exact pool size in the caller. */
		if (!st->nr_user_frames || st->nr_user_frames % frames ||
		    st->nr_user_frames > need)
			return -EINVAL;
		need = st->nr_user_frames;
	} else if (st->nr_user_frames != need)
		return -EINVAL;
	if (need > pool_frames)
		return -ENOSPC;
	return st->user_frames ? 0 : -EFAULT;
}

/*
 * A class table: per-slot scratch and per-copy completion sizes are bounded
 * so the session can size its buffers once at CREATE.
 */
static inline bool xdev_ext_mech_class_sizes_ok(__u32 info_size, __u32 desc_size,
					   __u32 desc_cap, __u32 cqe_size,
					   __u32 cqe_cap, __u32 batch_priv_size)
{
	if (!desc_size || !desc_cap || desc_cap > XDEV_EXT_MECH_MAX_FRAMES ||
	    !cqe_size != !cqe_cap || cqe_cap > XDEV_EXT_MECH_MAX_FRAMES)
		return false;
	return info_size <= XDEV_EXT_MECH_CLASS_SIZE_MAX &&
	       batch_priv_size <= XDEV_EXT_MECH_CLASS_SIZE_MAX &&
	       (__u64)desc_size * desc_cap <= XDEV_EXT_MECH_CLASS_SIZE_MAX &&
	       (__u64)cqe_size * cqe_cap <= XDEV_EXT_MECH_CLASS_SIZE_MAX;
}

/* A completion status as an errno: positive class statuses read as -EIO. */
static inline int xdev_ext_mech_status_errno(__s32 status)
{
	if (!status)
		return 0;
	if (status < 0 && status >= -XDEV_EXT_MECH_ERRNO_MAX)
		return status;
	return -EIO;
}

/* After build, with @ret already resolved by xdev_ext_mech_ret_resolve(). */
static inline int xdev_ext_mech_build_step(__s32 ret, bool has_default, int *err)
{
	*err = 0;
	switch (ret) {
	case XDEV_EXT_MECH_BUILD_SUBMIT:
		return XDEV_EXT_MECH_STEP_SUBMIT;
	case XDEV_EXT_MECH_BUILD_DEFAULT:
		if (has_default)
			return XDEV_EXT_MECH_STEP_DEFAULT;
		*err = -EOPNOTSUPP;
		return XDEV_EXT_MECH_STEP_ABORT;
	case XDEV_EXT_MECH_BUILD_ABORT:
		*err = -ECANCELED;
		return XDEV_EXT_MECH_STEP_ABORT;
	default:
		*err = -EPROTO;
		return XDEV_EXT_MECH_STEP_ABORT;
	}
}

/*
 * After a worker complete, with @ret already resolved by
 * xdev_ext_mech_ret_resolve().  @status is what the class completed the native
 * command with (0, -errno, or a positive class status such as the NVMe
 * status word or a CE outcome).  C, not the program, has the last word: a
 * sequestered batch or a completion after the drain timed out stays
 * sequestered, a failed command never advances, and RETRY is honoured only
 * within xdev_ext_mech_retry_ok().  *@err is the errno an ABORT or SEQUESTER
 * records.
 */
static inline int xdev_ext_mech_complete_step_desc(const struct xdev_ext_mech_class_desc *d, __s32 ret,
					 __s32 status, bool sequestered,
					 bool zombie, __u32 retries, int *err)
{
	int serr = xdev_ext_mech_status_errno(status);

	*err = 0;
	if (zombie) {
		*err = -ETIMEDOUT;
		return XDEV_EXT_MECH_STEP_SEQUESTER;
	}
	if (sequestered) {
		*err = serr ? serr : -EIO;
		return XDEV_EXT_MECH_STEP_SEQUESTER;
	}
	switch (ret) {
	case XDEV_EXT_MECH_NEXT:
	case XDEV_EXT_MECH_DONE:
		if (!status)
			return ret == XDEV_EXT_MECH_NEXT ? XDEV_EXT_MECH_STEP_NEXT :
						      XDEV_EXT_MECH_STEP_DONE;
		*err = serr;
		return XDEV_EXT_MECH_STEP_ABORT;
	case XDEV_EXT_MECH_RETRY:
	case XDEV_EXT_MECH_ABORT:
		if (ret == XDEV_EXT_MECH_RETRY &&
		    xdev_ext_mech_retry_ok_desc(d, retries, status))
			return XDEV_EXT_MECH_STEP_RETRY;
		*err = serr ? serr : -ECANCELED;
		return XDEV_EXT_MECH_STEP_ABORT;
	default:
		*err = -EPROTO;
		return XDEV_EXT_MECH_STEP_ABORT;
	}
}

static inline int xdev_ext_mech_complete_step(__u32 class_id, __s32 ret,
 __s32 status, bool sequestered, bool zombie, __u32 retries, int *err)
{
 return xdev_ext_mech_complete_step_desc(xdev_ext_mech_class_desc(class_id), ret,
  status, sequestered, zombie, retries, err);
}

/*
 * A stage whose class sends in key order (AF_XDP TX: the NXP receiver takes
 * generations only in order) normally waits for smaller keys to retire.
 * A certified native FIFO may instead release a same-stage barrier once
 * the earlier descriptors have been accepted; accepted bytes never retry.
 * True when @other still holds @key back at @stage.
 */
static inline bool xdev_ext_mech_order_holds_ex(__u64 key, __u32 stage,
					   __u64 other_key,
					   const struct xdev_ext_mech_bstate *other,
					   bool fifo_accepted)
{
	if (other_key >= key)
		return false;
	switch (other->state) {
	case XDEV_EXT_MECH_B_OPEN:
		return true;
	case XDEV_EXT_MECH_B_READY:
		return other->stage <= stage;
	case XDEV_EXT_MECH_B_IN_FLIGHT:
		if (other->stage == stage && fifo_accepted)
			return false;
		return other->stage <= stage;
	default:
		return false;
	}
}

static inline bool xdev_ext_mech_order_holds(__u64 key, __u32 stage,
					__u64 other_key,
					const struct xdev_ext_mech_bstate *other)
{
	return xdev_ext_mech_order_holds_ex(key, stage, other_key, other, false);
}

#endif /* IO_URING_XDEV_EXT_MECH_STEP_H */
