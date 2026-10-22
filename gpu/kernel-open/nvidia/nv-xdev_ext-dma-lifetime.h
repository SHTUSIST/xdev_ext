/* SPDX-License-Identifier: MIT */
#ifndef _NV_XDEV_EXT_DMA_LIFETIME_H_
#define _NV_XDEV_EXT_DMA_LIFETIME_H_

enum nv_xdev_ext_dma_finish_kind {
	NV_XDEV_EXT_DMA_PRE_SUBMIT_FAILURE = 0,
	NV_XDEV_EXT_DMA_COMPLETED = 1,
	NV_XDEV_EXT_DMA_POST_SUBMIT_AMBIGUOUS = 2,
};

struct nv_xdev_ext_dma_lifetime {
	unsigned int quarantined;
	unsigned int quarantine_tracked;
	unsigned int module_ref_count;
};

/* Returns one exactly once, when the caller must perform quarantine effects. */
static inline int
nv_xdev_ext_dma_finish(struct nv_xdev_ext_dma_lifetime *lifetime,
		  enum nv_xdev_ext_dma_finish_kind kind)
{
	if (!lifetime || kind != NV_XDEV_EXT_DMA_POST_SUBMIT_AMBIGUOUS ||
	    lifetime->quarantined)
		return 0;
	lifetime->quarantined = 1;
	lifetime->quarantine_tracked = 1;
	lifetime->module_ref_count = 1;
	return 1;
}

static inline int
nv_xdev_ext_dma_can_submit(const struct nv_xdev_ext_dma_lifetime *lifetime)
{
	return lifetime && !lifetime->quarantined;
}

static inline int
nv_xdev_ext_dma_can_release(const struct nv_xdev_ext_dma_lifetime *lifetime)
{
	return lifetime && !lifetime->quarantined;
}

static inline int
nv_xdev_ext_dma_quarantine_needs_ref(
	const struct nv_xdev_ext_dma_lifetime *lifetime,
	int registry_ref_transferred)
{
	return lifetime && lifetime->quarantine_tracked &&
	       !registry_ref_transferred;
}

#endif /* _NV_XDEV_EXT_DMA_LIFETIME_H_ */
