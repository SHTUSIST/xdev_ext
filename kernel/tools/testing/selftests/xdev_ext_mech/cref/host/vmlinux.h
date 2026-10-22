/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CREF_HOST_VMLINUX_H
#define XDEV_EXT_MECH_CREF_HOST_VMLINUX_H

/*
 * Host stand-in for the vmlinux.h that tools/xdev_ext_mech/nxp_mech.bpf.c
 * includes, so xdev_ext_mech_cref_test.c can compile that program as host C:
 * the UAPI types plus the struct_ops types of include/linux/xdev_ext_mech.h.
 */

#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>

#include "include/uapi/linux/if_xdp.h"
#include "include/uapi/linux/xdev_ext_mech.h"

#define XDEV_EXT_MECH_CREF_HOST_OPS(name)					\
struct name {								\
	__u32 abi_version;						\
	__u32 flags;							\
	__s32 (*prepare)(const struct xdev_ext_mech_ctx *ctx);		\
	__s32 (*build)(const struct xdev_ext_mech_ctx *ctx);			\
	__s32 (*complete)(const struct xdev_ext_mech_ctx *ctx);		\
}

XDEV_EXT_MECH_CREF_HOST_OPS(xdev_ext_nvme_mech_ops);
XDEV_EXT_MECH_CREF_HOST_OPS(xdev_ext_afxdp_mech_ops);

#endif /* XDEV_EXT_MECH_CREF_HOST_VMLINUX_H */
