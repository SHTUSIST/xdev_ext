/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_DMA_SCOPE_CORE_H
#define _LINUX_XDEV_EXT_DMA_SCOPE_CORE_H

#include <linux/types.h>
#ifndef __KERNEL__
#include <stdbool.h>
#endif

struct xdev_ext_dma_scope;

enum xdev_ext_dma_scope_kind {
	XDEV_EXT_DMA_SCOPE_LEGACY = 0,
	XDEV_EXT_DMA_SCOPE_UNKNOWN = 1,
	XDEV_EXT_DMA_SCOPE_KNOWN = 2,
};

/* Trusted C metadata. The stage owns the scope reference; this key borrows it.
 * LEGACY coordinates are requested numeric offsets, KNOWN coordinates are
 * canonical bytes, and UNKNOWN has no coordinates or scope. */
struct xdev_ext_dma_scope_key {
	const void *provider;
	__u32 kind;
	const struct xdev_ext_dma_scope *scope;
	__u64 start, len;
};

static inline bool xdev_ext_dma_scope_key_valid(const struct xdev_ext_dma_scope_key *key)
{
	if (!key)
		return false;
	switch (key->kind) {
	case XDEV_EXT_DMA_SCOPE_UNKNOWN:
		return !key->scope && !key->start && !key->len;
	case XDEV_EXT_DMA_SCOPE_LEGACY:
		if (key->scope)
			return false;
		break;
	case XDEV_EXT_DMA_SCOPE_KNOWN:
		if (!key->scope)
			return false;
		break;
	default:
		return false;
	}
	return key->len && key->start <= ~(__u64)0 - key->len;
}

/* Callers supply valid key-record addresses and trusted provider identities;
 * provider and scope tokens are compared only, never dereferenced here.
 * A missing record cannot authorize sharing. Different providers retain the
 * existing namespace boundary, even when their metadata is malformed. */
static inline bool xdev_ext_dma_scope_overlap(const struct xdev_ext_dma_scope_key *a,
					     const struct xdev_ext_dma_scope_key *b)
{
	if (!a || !b)
		return true;
	if (a->provider != b->provider)
		return false;
	if (!xdev_ext_dma_scope_key_valid(a) || !xdev_ext_dma_scope_key_valid(b))
		return true;
	if (a->kind == XDEV_EXT_DMA_SCOPE_KNOWN && b->kind == XDEV_EXT_DMA_SCOPE_KNOWN) {
		if (a->scope != b->scope)
			return false;
	} else if (a->kind != XDEV_EXT_DMA_SCOPE_LEGACY ||
		   b->kind != XDEV_EXT_DMA_SCOPE_LEGACY) {
		return true;
	}
	return a->start < b->start + b->len && b->start < a->start + a->len;
}

/* Equal comparable bases give corresponding batch slots the same coordinates.
 * Shifted aliases and all uncertain/mixed pairs must serialize instead. */
static inline bool xdev_ext_dma_scope_serial(const struct xdev_ext_dma_scope_key *a,
					    const struct xdev_ext_dma_scope_key *b)
{
	if (!xdev_ext_dma_scope_overlap(a, b))
		return false;
	if (!xdev_ext_dma_scope_key_valid(a) || !xdev_ext_dma_scope_key_valid(b))
		return true;
	if (a->kind == XDEV_EXT_DMA_SCOPE_LEGACY && b->kind == XDEV_EXT_DMA_SCOPE_LEGACY)
		return a->start != b->start;
	if (a->kind == XDEV_EXT_DMA_SCOPE_KNOWN && b->kind == XDEV_EXT_DMA_SCOPE_KNOWN &&
	    a->scope == b->scope)
		return a->start != b->start;
	return true;
}

#endif /* _LINUX_XDEV_EXT_DMA_SCOPE_CORE_H */
