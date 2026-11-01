/* SPDX-License-Identifier: GPL-2.0 */
/* Signature-only baseline bridge: independently frozen comparator ABI. */
#ifndef INDEPENDENT_DMA_SCOPE_CONTRACT_H
#define INDEPENDENT_DMA_SCOPE_CONTRACT_H
#include <linux/types.h>
struct xdev_ext_dma_scope;
enum xdev_ext_dma_scope_kind {XDEV_EXT_DMA_SCOPE_LEGACY=0,XDEV_EXT_DMA_SCOPE_UNKNOWN=1,XDEV_EXT_DMA_SCOPE_KNOWN=2};
struct xdev_ext_dma_scope_key {
 const void *provider;__u32 kind;const struct xdev_ext_dma_scope *scope;__u64 start,len;
};
#endif
