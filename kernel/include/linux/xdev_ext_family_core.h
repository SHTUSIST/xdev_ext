/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_FAMILY_CORE_H
#define _LINUX_XDEV_EXT_FAMILY_CORE_H

/* Pure class-to-family table, shared by the kernel and the host tests. */
#ifdef __KERNEL__
#include <linux/types.h>
#include <uapi/linux/xdev_ext_mech.h>
#else
#include <stdbool.h>
#include <linux/types.h>
#include "../uapi/linux/xdev_ext_mech.h"
#endif

static inline __u32 xdev_ext_mech_class_family(__u32 class_id)
{
	switch (class_id) {
	case XDEV_EXT_MECH_CLASS_NET:
	case XDEV_EXT_MECH_CLASS_AFXDP:
	case XDEV_EXT_MECH_CLASS_SOCKET:
		return XDEV_EXT_FAMILY_NETWORK;
	case XDEV_EXT_MECH_CLASS_NVME:
		return XDEV_EXT_FAMILY_STORAGE;
	case XDEV_EXT_MECH_CLASS_CE:
	case XDEV_EXT_MECH_CLASS_DMA:
	case XDEV_EXT_MECH_CLASS_IAA:
	case XDEV_EXT_MECH_CLASS_CPU:
	case XDEV_EXT_MECH_CLASS_USER:
		return XDEV_EXT_FAMILY_COMPUTE;
	default:
		return XDEV_EXT_FAMILY_NONE;
	}
}

/* @hooks_family is &ops->fam.hdr->family, or NULL for optional hooks. */
static inline bool xdev_ext_family_hooks_ok(__u32 class_id,
					  const __u32 *hooks_family)
{
	__u32 family = xdev_ext_mech_class_family(class_id);

	return !hooks_family || (family != XDEV_EXT_FAMILY_NONE &&
				 *hooks_family == family);
}

#endif /* _LINUX_XDEV_EXT_FAMILY_CORE_H */
