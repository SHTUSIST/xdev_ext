/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_COMPFAM_CORE_H
#define _LINUX_XDEV_EXT_COMPFAM_CORE_H

/*
 * Pure rules of the compute family (CE, DMA, IAA, CPU, USER). Shared compute
 * helpers already in the tree: io_uring/xdev_ext_mech_window_copy_core.h
 * (CE, DMA), the core transform API (IAA, variable CPU) and the in-place
 * length API (CPU, USER).
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/xdev_ext_family_core.h>
#else
#include <errno.h>
#include "xdev_ext_family_core.h"
#endif

enum xdev_ext_comp_kind {
	XDEV_EXT_COMP_COPY_WINDOW	= 1,
	XDEV_EXT_COMP_INPLACE		= 2,
	XDEV_EXT_COMP_TRANSFORM		= 3,
};

/* @role is xdev_ext_mech_stage_role(u) (io_uring/xdev_ext_mech_step.h). */
static inline int xdev_ext_comp_kind_of_role(__u32 class_id, int role)
{
	if (xdev_ext_mech_class_family(class_id) != XDEV_EXT_FAMILY_COMPUTE)
		return -EINVAL;
	if (role == 3 /* XDEV_EXT_MECH_ROLE_INPLACE */)
		return XDEV_EXT_COMP_INPLACE;
	if (role == 4 /* XDEV_EXT_MECH_ROLE_TRANSFORM */)
		return XDEV_EXT_COMP_TRANSFORM;
	if (role == 1 /* XDEV_EXT_MECH_ROLE_PRODUCER */ ||
	    role == 2 /* XDEV_EXT_MECH_ROLE_CONSUMER */)
		return XDEV_EXT_COMP_COPY_WINDOW;
	return -EINVAL;
}

static inline bool xdev_ext_comp_kind_ok(__u32 kinds, int kind)
{
	return kind > 0 && kind < 32 && (kinds & (1U << kind));
}

#endif /* _LINUX_XDEV_EXT_COMPFAM_CORE_H */
