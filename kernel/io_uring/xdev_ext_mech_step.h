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

enum xdev_ext_mech_stage_role {
 XDEV_EXT_MECH_ROLE_PRODUCER = 1,
 XDEV_EXT_MECH_ROLE_CONSUMER = 2,
 XDEV_EXT_MECH_ROLE_INPLACE = 3,
 XDEV_EXT_MECH_ROLE_TRANSFORM = 4,
};

static inline int xdev_ext_mech_stage_role(const struct xdev_ext_mech_stage_uapi *u)
{
 if (!xdev_ext_mech_class_known(u->class_id) ||
     (u->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE && u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE))
  return -EINVAL;
 if (u->class_id == XDEV_EXT_MECH_CLASS_IAA)
  return XDEV_EXT_MECH_ROLE_TRANSFORM;
 if (u->class_id == XDEV_EXT_MECH_CLASS_CPU) {
  if (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE || u->arg0 >= XDEV_EXT_CPU_XFORM_MAX)
   return -EINVAL;
  if (xdev_ext_mech_cpu_xform_fixed(u->arg0))
   return XDEV_EXT_MECH_ROLE_INPLACE;
  return xdev_ext_mech_cpu_xform_variable(u->arg0) ? XDEV_EXT_MECH_ROLE_TRANSFORM : -EINVAL;
 }
 return u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE ?
  XDEV_EXT_MECH_ROLE_PRODUCER : XDEV_EXT_MECH_ROLE_CONSUMER;
}

static inline __u32 xdev_ext_mech_chain_refs(const struct xdev_ext_mech_stage_uapi *st,
 __u32 nr_stages, __u32 from)
{
 __u32 refs = 0;

 for (; from < nr_stages; from++) {
  int role = xdev_ext_mech_stage_role(&st[from]);

  if (role < 0 || role == XDEV_EXT_MECH_ROLE_PRODUCER)
   break;
  refs++;
  if (role != XDEV_EXT_MECH_ROLE_CONSUMER)
   break;
 }
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
 switch (class_id) {
 case XDEV_EXT_MECH_CLASS_NVME:
 case XDEV_EXT_MECH_CLASS_NET:
  return XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE;
 default:
  return 0; /* AF_XDP, socket, IAA, DMA, CE: host-page classes */
 }
}
/* 0, or -EOPNOTSUPP: frame_size not a power of two in [MIN, MAX], or hdr_room != 0. */
static inline int xdev_ext_mech_peer_layout_check(const struct xdev_ext_mech_layout *l)
{
 if (!l || l->hdr_room || l->frame_size < XDEV_EXT_MECH_PEER_FRAME_MIN ||
     l->frame_size > XDEV_EXT_MECH_PEER_FRAME_MAX || (l->frame_size & (l->frame_size - 1)))
  return -EOPNOTSUPP;
 return 0;
}

/*
 * CREATE: 0 with *@frames the frames per batch, or -errno.  An AF_XDP stage
 * needs the socket's UMEM as the pool; AF_XDP RX feeds a chain, so it is
 * stage 0 of at least two.  On a PEER pool the generic checks of every stage
 * run first, then the geometry, then each stage's class capability.
 */
static inline int xdev_ext_mech_create_check(const struct xdev_ext_mech_create *c,
					__u32 *frames)
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
   if (!i || xdev_ext_mech_stage_role(u) != XDEV_EXT_MECH_ROLE_CONSUMER ||
       xdev_ext_mech_stage_role(&c->st[i - 1]) != XDEV_EXT_MECH_ROLE_CONSUMER)
    return -EINVAL;
   clean.flags &= ~XDEV_EXT_MECH_STAGE_F_FANOUT;
  }
  /* NET DMAs device memory only. */
  if (u->class_id == XDEV_EXT_MECH_CLASS_NET && c->pool_kind != XDEV_EXT_MECH_POOL_PEER)
   return -EOPNOTSUPP;
		if (!xdev_ext_mech_class_known(u->class_id) ||
		    (u->flags && u->class_id == XDEV_EXT_MECH_CLASS_IAA &&
             (u->flags & ~XDEV_EXT_IAA_F_SOFTWARE)) ||
            (u->flags && u->class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
             (u->flags & ~XDEV_EXT_SOCKET_F_NXP)) ||
            (u->flags && u->class_id != XDEV_EXT_MECH_CLASS_SOCKET &&
             u->class_id != XDEV_EXT_MECH_CLASS_IAA &&
             (u->class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
		     (u->flags & ~(XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) ||
		     ((u->flags & (XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) &&
		      !(u->flags & XDEV_EXT_AFXDP_F_RELIABLE)))) ||
		    (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
		     u->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE))
			return -EINVAL;
  if (u->class_id == XDEV_EXT_MECH_CLASS_CPU) {
   __s64 delta;
   __u32 j;

   if (u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE || u->fd != -1 || u->flags ||
       u->arg0 >= XDEV_EXT_CPU_XFORM_MAX)
    return -EINVAL;
   if (xdev_ext_mech_cpu_xform_variable(u->arg0)) {
    if (!u->arg1 || u->arg1 > (__u64)XDEV_EXT_MECH_MAX_FRAMES * c->layout.seg_len)
     return -EINVAL;
   } else {
    if (xdev_ext_mech_cpu_len_delta(u->arg0, u->arg1, &delta))
     return -EINVAL;
    for (j = i + 1; delta && j < c->nr_stages; j++) {
     if (xdev_ext_mech_stage_role(&c->st[j]) == XDEV_EXT_MECH_ROLE_TRANSFORM)
      break;
     if (c->st[j].class_id == XDEV_EXT_MECH_CLASS_NVME ||
         c->st[j].class_id == XDEV_EXT_MECH_CLASS_AFXDP)
      return -EOPNOTSUPP;
    }
   }
   continue;
  }
  if (u->class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
      (u->flags & XDEV_EXT_SOCKET_F_NXP) &&
      (!u->arg0 || u->arg1 <= 68 || u->arg1 > 0xffffffffULL))
   return -EINVAL;
		if (u->fd < 0)
			return -EBADF;
		if (u->class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
		    u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&
		    (i || c->nr_stages < 2))
			return -EINVAL;
		if (u->class_id != XDEV_EXT_MECH_CLASS_AFXDP ||
      c->pool_kind == XDEV_EXT_MECH_POOL_PEER)
			continue;
		if (c->pool_kind != XDEV_EXT_MECH_POOL_XSK)
			return -EINVAL;
		if (u->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&
		    (i || c->nr_stages < 2))
			return -EINVAL;
	}
 if (c->pool_kind == XDEV_EXT_MECH_POOL_PEER) {
  int ret = xdev_ext_mech_peer_layout_check(&c->layout);

  if (ret)
   return ret;
  for (i = 0; i < c->nr_stages; i++)
   if (!(xdev_ext_mech_peer_dirs(c->st[i].class_id) & (1U << c->st[i].direction)))
    return -EOPNOTSUPP;
 }
	*frames = (__u32)nr;
	return 0;
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
	if ((st->flags & XDEV_EXT_MECH_START_F_USER_SPANS) &&
	    (!(st->flags & XDEV_EXT_MECH_START_F_USER_FRAMES) ||
	     (st->flags & XDEV_EXT_MECH_START_F_RECYCLE) ||
	     frames != 1 || st->nr_batches != 1 || st->nr_user_frames != 1))
		return -EINVAL;
	if (!(st->flags & XDEV_EXT_MECH_START_F_USER_FRAMES))
		return st->nr_user_frames || st->user_frames ||
		       (st->flags & XDEV_EXT_MECH_START_F_RECYCLE) ? -EINVAL : 0;

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
static inline int xdev_ext_mech_complete_step(__u32 class_id, __s32 ret,
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
		    xdev_ext_mech_retry_ok(class_id, retries, status))
			return XDEV_EXT_MECH_STEP_RETRY;
		*err = serr ? serr : -ECANCELED;
		return XDEV_EXT_MECH_STEP_ABORT;
	default:
		*err = -EPROTO;
		return XDEV_EXT_MECH_STEP_ABORT;
	}
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
