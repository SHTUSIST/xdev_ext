/* SPDX-License-Identifier: GPL-2.0 */
#ifndef DMA_REFERENCE_HOST_VMLINUX_H
#define DMA_REFERENCE_HOST_VMLINUX_H
#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>
#include <linux/if_xdp.h>
#include "xdev_ext_mech.h"
struct xdev_ext_dma_mech_ops {
 __u32 abi_version, flags;
 __s32 (*prepare)(const struct xdev_ext_mech_ctx *);
 __s32 (*build)(const struct xdev_ext_mech_ctx *);
 __s32 (*complete)(const struct xdev_ext_mech_ctx *);
 __s32 (*compute)(const struct xdev_ext_mech_ctx *);
};
#endif
