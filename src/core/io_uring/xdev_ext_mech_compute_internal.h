/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_COMPUTE_INTERNAL_H
#define IO_URING_XDEV_EXT_MECH_COMPUTE_INTERNAL_H

#include <linux/xdev_ext_mech.h>

struct xdev_ext_mech_life;
struct xdev_ext_mech_transform_state;

/* Borrowed for one already-authorized call; these views acquire no lifetime. */
struct xdev_ext_mech_compute_session_access {
	struct xdev_ext_mech_pool *pool;
	struct xdev_ext_mech_life *life;
	u8 *transform_owner;
};

struct xdev_ext_mech_compute_batch_access {
	struct xdev_ext_mech_frame *f;
	const u64 *life_token;
	u32 life_active;
	u32 *nr_frames;
	u32 *bytes;
	u32 *present;
	struct xdev_ext_mech_transform_state *transform;
};

void xdev_ext_mech_compute_session_access(struct xdev_ext_mech_session *s,
		struct xdev_ext_mech_compute_session_access *a);
void xdev_ext_mech_compute_batch_access(struct xdev_ext_mech_batch *b,
		struct xdev_ext_mech_compute_batch_access *a);
const struct xdev_ext_mech_transform_state *
xdev_ext_mech_compute_transform_state(const struct xdev_ext_mech_batch *b);

/* Existing generic core bodies; no ownership moves into the compute TU. */
int xdev_ext_mech_frames_move(struct xdev_ext_mech_session *s,
		struct xdev_ext_mech_batch *b, u32 from, u32 to);
int xdev_ext_mech_frames_release(struct xdev_ext_mech_session *s,
		struct xdev_ext_mech_batch *b);
struct xdev_ext_binding_ctx_v2
xdev_ext_mech_base(const struct xdev_ext_mech_stage *st, u64 bytes);
void xdev_ext_mech_worker_args(struct xdev_ext_mech_session *s,
		struct xdev_ext_mech_stage *st, struct xdev_ext_mech_batch *b,
		u32 member, const struct xdev_ext_binding_ctx_v2 *base,
		struct xdev_ext_mech_call_args *a);

#endif /* IO_URING_XDEV_EXT_MECH_COMPUTE_INTERNAL_H */
