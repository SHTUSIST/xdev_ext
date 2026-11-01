/* SPDX-License-Identifier: GPL-2.0 */
/* Root admission required. This bridge deliberately ignores new metadata and
 * calls the real old comparator. It contains no substitute interval rule. */
#ifndef INDEPENDENT_DMA_SCOPE_LEGACY_ADAPTER_H
#define INDEPENDENT_DMA_SCOPE_LEGACY_ADAPTER_H
static inline bool xdev_ext_dma_scope_overlap(const struct xdev_ext_dma_scope_key *a,
 const struct xdev_ext_dma_scope_key *b)
{
 return xdev_ext_ce_lease_overlap(a->provider,a->start,a->len,b->provider,b->start,b->len);
}
#endif
