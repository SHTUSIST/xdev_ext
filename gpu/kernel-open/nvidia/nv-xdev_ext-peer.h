/* SPDX-License-Identifier: MIT */
#ifndef _NV_XDEV_EXT_PEER_H
#define _NV_XDEV_EXT_PEER_H
struct file_operations;
#ifdef CONFIG_XDEV_EXT_MECH
void nv_xdev_ext_peer_init(const struct file_operations *fops);
void nv_xdev_ext_peer_exit(void);
#else
static inline void nv_xdev_ext_peer_init(const struct file_operations *fops) { (void)fops; }
static inline void nv_xdev_ext_peer_exit(void) { }
#endif
#endif
