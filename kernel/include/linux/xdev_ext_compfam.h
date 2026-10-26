/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_COMPFAM_H
#define _LINUX_XDEV_EXT_COMPFAM_H

/*
 * Compute family contract. Shared helpers remain at their existing paths:
 * io_uring/xdev_ext_mech_window_copy_core.h for CE and DMA;
 * xdev_ext_mech_transform_reserve()/xdev_ext_mech_batch_transform_begin()
 * for IAA and variable CPU transforms; the in-place length API for CPU
 * and USER stages.
 */
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_compfam_core.h>

struct xdev_ext_comp_hooks {
	struct xdev_ext_family_hooks_hdr hdr;
	u32 kinds;			/* bit (1 << kind) for each accepted kind */
	u32 producer_visibility;	/* enum xdev_ext_cap_state */
};

#endif /* _LINUX_XDEV_EXT_COMPFAM_H */
