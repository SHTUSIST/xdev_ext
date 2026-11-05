/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_COMPFAM_TRANSFORM_H
#define IO_URING_XDEV_EXT_COMPFAM_TRANSFORM_H

#include <linux/xdev_ext_mech.h>

/* Storage remains embedded in the core-owned batch. */
struct xdev_ext_mech_transform_state {
	struct xdev_ext_mech_frame dst[XDEV_EXT_MECH_MAX_FRAMES];
	u64 token[XDEV_EXT_MECH_MAX_FRAMES];
	u32 nr, produced;
	bool active;
};

void xdev_ext_mech_transform_undo(struct xdev_ext_mech_session *s,
				struct xdev_ext_mech_batch *b);
bool xdev_ext_mech_transform_landed(struct xdev_ext_mech_session *s,
				  struct xdev_ext_mech_batch *b, bool seq);
int xdev_ext_mech_transform_handoff(struct xdev_ext_mech_batch *b,
				   u32 refs, int err, bool *sequester);

#endif /* IO_URING_XDEV_EXT_COMPFAM_TRANSFORM_H */
