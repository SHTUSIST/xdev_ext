/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_COMPFAM_H
#define _LINUX_XDEV_EXT_COMPFAM_H

/*
 * Compute family contract. Shared runtime helpers live at:
 * io_uring/xdev_ext_mech_window_copy_core.h for CE and DMA;
 * io_uring/xdev_ext_compfam_transform.c for IAA and variable CPU transforms
 * and the in-place length API for CPU and USER stages. Its private state
 * and worker/callback hooks are in io_uring/xdev_ext_compfam_transform.h.
 */
#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_compfam_core.h>

struct xdev_ext_comp_hooks {
	struct xdev_ext_family_hooks_hdr hdr;
	u32 kinds;			/* bit (1 << kind) for each accepted kind */
	u32 producer_visibility;	/* enum xdev_ext_cap_state */
};

#endif /* _LINUX_XDEV_EXT_COMPFAM_H */
