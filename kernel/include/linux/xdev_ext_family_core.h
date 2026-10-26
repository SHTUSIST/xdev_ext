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

enum xdev_ext_mech_role_rule {
	XDEV_EXT_ROLE_RULE_DIRECTION	= 1,
	XDEV_EXT_ROLE_RULE_TRANSFORM	= 2,
	XDEV_EXT_ROLE_RULE_INPLACE_TX	= 3,
	XDEV_EXT_ROLE_RULE_CPU_XFORM	= 4,
};

enum xdev_ext_mech_ctx_rule {
	XDEV_EXT_CTX_RULE_GPU		= 1,
	XDEV_EXT_CTX_RULE_NVME		= 2,
	XDEV_EXT_CTX_RULE_AFXDP		= 3,
	XDEV_EXT_CTX_RULE_COMMON		= 4,
};

struct xdev_ext_mech_class_desc {
	__u32 family;
	__u32 peer_dirs;
	__u32 known_flags;
	__u8 peer_only;
	__u8 flags_later;
	__u8 role_rule;
	__u8 ctx_rule;
	__u8 no_file;
	bool (*flags_ok)(__u32 flags);
};

/* AF_XDP: FINITE and POLICY extend a RELIABLE stage only. */
static inline bool xdev_ext_afxdp_flags_ok(__u32 flags)
{
	return !((flags & (XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY)) &&
		 !(flags & XDEV_EXT_AFXDP_F_RELIABLE));
}

/* One row per class; unknown ids share the all-zero NONE descriptor. */
static inline const struct xdev_ext_mech_class_desc *
xdev_ext_mech_class_desc(__u32 class_id)
{
	static const struct xdev_ext_mech_class_desc none;
	static const struct xdev_ext_mech_class_desc tab[XDEV_EXT_MECH_CLASS_MAX] = {
		[XDEV_EXT_MECH_CLASS_AFXDP] = { .family = XDEV_EXT_FAMILY_NETWORK,
			.known_flags = XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE | XDEV_EXT_AFXDP_F_POLICY,
			.flags_ok = xdev_ext_afxdp_flags_ok,
			.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION, .ctx_rule = XDEV_EXT_CTX_RULE_AFXDP },
		[XDEV_EXT_MECH_CLASS_NVME] = { .family = XDEV_EXT_FAMILY_STORAGE,
			.peer_dirs = XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE,
			.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION, .ctx_rule = XDEV_EXT_CTX_RULE_NVME },
		[XDEV_EXT_MECH_CLASS_IAA] = { .family = XDEV_EXT_FAMILY_COMPUTE,
			.known_flags = XDEV_EXT_IAA_F_SOFTWARE,
			.role_rule = XDEV_EXT_ROLE_RULE_TRANSFORM, .ctx_rule = XDEV_EXT_CTX_RULE_COMMON },
		[XDEV_EXT_MECH_CLASS_CE] = { .family = XDEV_EXT_FAMILY_COMPUTE,
			.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION, .ctx_rule = XDEV_EXT_CTX_RULE_GPU },
		[XDEV_EXT_MECH_CLASS_DMA] = { .family = XDEV_EXT_FAMILY_COMPUTE,
			.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION, .ctx_rule = XDEV_EXT_CTX_RULE_COMMON },
		[XDEV_EXT_MECH_CLASS_SOCKET] = { .family = XDEV_EXT_FAMILY_NETWORK,
			.known_flags = XDEV_EXT_SOCKET_F_NXP,
			.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION, .ctx_rule = XDEV_EXT_CTX_RULE_COMMON },
		[XDEV_EXT_MECH_CLASS_NET] = { .family = XDEV_EXT_FAMILY_NETWORK,
			.peer_dirs = XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE,
			.peer_only = 1,
			.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION, .ctx_rule = XDEV_EXT_CTX_RULE_COMMON },
		[XDEV_EXT_MECH_CLASS_XDOMAIN] = { .family = XDEV_EXT_FAMILY_NETWORK,
			.peer_dirs = XDEV_EXT_DMA_DIR_TO_DEVICE | XDEV_EXT_DMA_DIR_FROM_DEVICE,
			.known_flags = XDEV_EXT_XDOMAIN_KNOWN_FLAGS, .peer_only = 1,
			.role_rule = XDEV_EXT_ROLE_RULE_DIRECTION, .ctx_rule = XDEV_EXT_CTX_RULE_COMMON },
		[XDEV_EXT_MECH_CLASS_CPU] = { .family = XDEV_EXT_FAMILY_COMPUTE, .no_file = 1,
			.role_rule = XDEV_EXT_ROLE_RULE_CPU_XFORM, .ctx_rule = XDEV_EXT_CTX_RULE_COMMON },
		[XDEV_EXT_MECH_CLASS_USER] = { .family = XDEV_EXT_FAMILY_COMPUTE, .no_file = 1,
			.flags_later = 1, /* xdev_ext_user_stage_check() checks VARLEN */
			.role_rule = XDEV_EXT_ROLE_RULE_INPLACE_TX, .ctx_rule = XDEV_EXT_CTX_RULE_COMMON },
	};

	if (class_id >= XDEV_EXT_MECH_CLASS_MAX || !tab[class_id].family)
		return &none;
	return &tab[class_id];
}

static inline __u32 xdev_ext_mech_class_family(__u32 class_id)
{
	return xdev_ext_mech_class_desc(class_id)->family;
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
