/*
 * SPDX-FileCopyrightText: Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 */
#ifndef _NV_XDEV_EXT_CE_BACKEND_H_
#define _NV_XDEV_EXT_CE_BACKEND_H_

struct file_operations;

/*
 * Copy-engine backend of the XDEV_EXT mechanism layer, built with
 * XDEV_EXT_ENABLE_GPU_CE_DMA=1 against a kernel with CONFIG_XDEV_EXT_MECH_CE.
 * nv_xdev_ext_ce_backend_init(): module init, once the char devices exist with
 * @fops; registers only when loaded with NVreg_EnableXdevExtCeDma=1.
 * nv_xdev_ext_ce_backend_exit(): module exit, before the char devices go.
 */
#if defined(XDEV_EXT_ENABLE_GPU_CE_DMA) && defined(CONFIG_XDEV_EXT_MECH_CE)
void nv_xdev_ext_ce_backend_init(const struct file_operations *fops);
void nv_xdev_ext_ce_backend_exit(void);
#else
static inline void nv_xdev_ext_ce_backend_init(const struct file_operations *fops)
{
}

static inline void nv_xdev_ext_ce_backend_exit(void)
{
}
#endif

#endif /* _NV_XDEV_EXT_CE_BACKEND_H_ */
