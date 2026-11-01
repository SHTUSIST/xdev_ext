/* SPDX-License-Identifier: MIT */
#ifndef _NV_XDEV_EXT_DMABUF_H_
#define _NV_XDEV_EXT_DMABUF_H_

#if defined(CONFIG_XDEV_EXT_PEER_DMABUF) && defined(CONFIG_DMA_SHARED_BUFFER)
int nv_xdev_ext_dmabuf_init(void);
void nv_xdev_ext_dmabuf_exit(void);
#else
static inline int nv_xdev_ext_dmabuf_init(void) { return 0; }
static inline void nv_xdev_ext_dmabuf_exit(void) { }
#endif
#endif
