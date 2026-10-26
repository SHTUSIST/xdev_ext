/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_STORFAM_H
#define _LINUX_XDEV_EXT_STORFAM_H

#include <linux/xdev_ext_mech.h>
#include <linux/xdev_ext_storfam_core.h>

struct xdev_ext_stor_hooks {
	struct xdev_ext_family_hooks_hdr hdr;
	u32 extent_align_mask;
	u32 max_extents;
};

#endif
