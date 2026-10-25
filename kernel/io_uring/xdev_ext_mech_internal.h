/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_INTERNAL_H
#define IO_URING_XDEV_EXT_MECH_INTERNAL_H

/*
 * Between the two halves of the mechanism core: xdev_ext_mech_ops.c (struct_ops
 * types, kfuncs, class registry) and xdev_ext_mech.c (sessions, batches, worker,
 * control plane, teardown).
 */

#include <linux/types.h>
#include <linux/xdev_ext_mech.h>

struct xdev_ext_mech_class_ops;

/* Who a callback runs for: the core fills ctx identities from it. */
struct xdev_ext_mech_target {
	struct xdev_ext_mech_session *s;	/* NULL for xdev_ext_mech_call_active() */
	struct xdev_ext_mech_stage *st;
	u64 session_id;
	u64 batch_id;
	u64 key;			/* base.src_offset when batch is set */
	u64 bytes;			/* base.length when batch is set */
	u32 class_id;
	u32 frame_size;
	u32 hdr_room;
	u32 batch_frames;		/* frames per batch: the RX hold count */
	bool batch;
};

/* Process context: the struct_ops types registered and found in vmlinux BTF. */
bool xdev_ext_mech_ready(void);

/* Process context: the class table with its owner pinned, or NULL. */
const struct xdev_ext_mech_class_ops *xdev_ext_mech_class_get(u32 class_id);
/* Process context. */
void xdev_ext_mech_class_put(const struct xdev_ext_mech_class_ops *cls);

/*
 * Process context: the callbacks a new session of @class_id runs, the C
 * reference table when one is set, with its module held (*@owner, NULL for
 * built-in code), otherwise the published struct_ops generation pinned once
 * for the session's life (*@pinned).  NULL when neither exists, or when the
 * table's module is going away.
 */
const void *xdev_ext_mech_ops_get(u32 class_id, bool *pinned,
			     struct module **owner);
/* Process context: give back what xdev_ext_mech_ops_get() took. */
void xdev_ext_mech_ops_put(const void *ops, bool pinned, struct module *owner);
/* Any context: @ops is still what a new session of @class_id would get. */
bool xdev_ext_mech_ops_current(u32 class_id, const void *ops, bool pinned);

/*
 * Context of the member: run @a->member of @ops for @t with a sealed
 * envelope on this stack.  0 with *@ret the raw program value, -EPROTO when
 * a kfunc latched misuse, -ENOENT when @ops has no such member, -EINVAL for
 * bad @a.
 */
int xdev_ext_mech_invoke(const void *ops, const struct xdev_ext_mech_target *t,
		    const struct xdev_ext_mech_call_args *a, s32 *ret,
		    struct xdev_ext_mech_hold_intent *hold);

/* Any context: @ops (a pinned generation or C table) has a callback for @member. */
bool xdev_ext_mech_ops_has_member(const void *ops, u32 member);

/*
 * Process context, from struct_ops ->unreg or when a C reference table is
 * cleared or replaced: @ops of @class_id is no longer what new sessions get;
 * sessions on it stop admitting with -ECANCELED.
 */
void xdev_ext_mech_generation_gone(u32 class_id, const void *ops);

#endif /* IO_URING_XDEV_EXT_MECH_INTERNAL_H */
