/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_REQUESTER_CORE_H
#define _LINUX_XDEV_EXT_REQUESTER_CORE_H

/* Pure rules every device-memory requester shares (any family). */
#include <linux/types.h>
#ifdef __KERNEL__
#include <linux/errno.h>
#include <uapi/linux/xdev_ext_mech.h>
#else
#include <stdbool.h>
#include <errno.h>
#include "../uapi/linux/xdev_ext_mech.h"
#endif

#define XDEV_EXT_LEASE_MIN_SHIFT 12U

/*
 * After a provider refuses [off, off + len) with -ERANGE, retry the longest
 * proper prefix ending at a naturally aligned power-of-two page boundary.
 * The cursor starts at 31 and only falls; return 0 when no boundary of at
 * least 1 << min_shift remains.
 */
static inline __u32 xdev_ext_lease_shrink(__u64 off, __u32 len,
				       __u32 *shift, __u32 min_shift)
{
	while (*shift >= min_shift) {
		__u64 page = 1ULL << *shift;
		__u64 end = (off & ~(page - 1)) + page;

		if (end - off < len)
			return (__u32)(end - off);
		(*shift)--;
	}
	return 0;
}

struct xdev_ext_admit_facts {
	__s32 distance;
	__u32 backing;
	bool owner_known;
	bool untrusted;
	bool swiotlb_force;
	bool dma_iommu;
	bool dma_ops;
	bool admin;
};
#define XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED (1U << 0)
struct xdev_ext_admission {
	__u32 reachability;
	__u32 refused;
	__s32 distance;
	__u32 backing;
};

/*
 * Admit only discrete BAR-backed VRAM with a trusted, unbounced requester.
 * A raw bus address cannot cross a translating DMA layer. An explicit admin
 * override admits only a missing topology path, recorded UNVERIFIED_FORCED.
 */
static inline int xdev_ext_admit_decide(const struct xdev_ext_admit_facts *f,
				      __u32 flags, struct xdev_ext_admission *out)
{
	__u32 r = 0;

	out->distance = f->distance;
	out->backing = f->backing;
	if (f->distance < 0)
		r |= XDEV_EXT_PEER_REFUSE_NO_P2P_PATH;
	if (f->swiotlb_force)
		r |= XDEV_EXT_PEER_REFUSE_SWIOTLB_FORCE;
	if (f->untrusted)
		r |= XDEV_EXT_PEER_REFUSE_UNTRUSTED;
	if ((f->dma_iommu || f->dma_ops) &&
	    (f->backing & XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR))
		r |= XDEV_EXT_PEER_REFUSE_IOMMU_RAW_ADDR;
	if (!f->owner_known || !(f->backing & XDEV_EXT_PEER_BACKING_MMIO_BAR) ||
	    (f->backing & (XDEV_EXT_PEER_BACKING_STRUCT_PAGE |
			   XDEV_EXT_PEER_BACKING_COHERENT_C2C)) ||
	    (f->backing & ~(XDEV_EXT_PEER_BACKING_MMIO_BAR |
			    XDEV_EXT_PEER_BACKING_STRUCT_PAGE |
			    XDEV_EXT_PEER_BACKING_COHERENT_C2C |
			    XDEV_EXT_PEER_BACKING_EXTERNAL |
			    XDEV_EXT_PEER_BACKING_RAW_BUS_ADDR)))
		r |= XDEV_EXT_PEER_REFUSE_BACKING;
	if (f->backing & XDEV_EXT_PEER_BACKING_EXTERNAL)
		r |= XDEV_EXT_PEER_REFUSE_EXTERNAL_OWNER;
	out->refused = r;
	if (!(r & XDEV_EXT_PEER_REFUSE_NO_P2P_PATH))
		out->reachability = XDEV_EXT_CAP_TOPOLOGY_PASSED;
	else if ((flags & XDEV_EXT_ADMIT_F_ALLOW_UNVERIFIED) && f->admin)
		out->reachability = XDEV_EXT_CAP_UNVERIFIED_FORCED;
	else
		out->reachability = XDEV_EXT_CAP_TOPOLOGY_FAILED;
	if (r & ~XDEV_EXT_PEER_REFUSE_NO_P2P_PATH)
		return -EXDEV;
	return out->reachability == XDEV_EXT_CAP_TOPOLOGY_FAILED ? -EXDEV : 0;
}

#endif
