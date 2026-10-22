/* SPDX-License-Identifier: MIT */
#ifndef _NV_XDEV_EXT_UMEM_QUOTA_H_
#define _NV_XDEV_EXT_UMEM_QUOTA_H_

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
typedef u32 nv_xdev_ext_quota_u32;
typedef u64 nv_xdev_ext_quota_u64;
#else
#include <errno.h>
#include <stdint.h>
typedef uint32_t nv_xdev_ext_quota_u32;
typedef uint64_t nv_xdev_ext_quota_u64;
#endif

/*
 * Pure quota state transition.  Callers serialize reserve/release around this
 * helper; a successful reserve mutates all three counters in one critical
 * section, so admission cannot race a later accounting update.
 */
struct nv_xdev_ext_umem_quota {
	nv_xdev_ext_quota_u64 bytes;
	nv_xdev_ext_quota_u64 pages;
	nv_xdev_ext_quota_u32 buffers;
	nv_xdev_ext_quota_u64 max_bytes;
	nv_xdev_ext_quota_u32 max_buffers;
};

static inline int
nv_xdev_ext_umem_quota_reserve(struct nv_xdev_ext_umem_quota *quota,
			  nv_xdev_ext_quota_u64 bytes, nv_xdev_ext_quota_u32 pages)
{
	if (!quota || !bytes || !pages)
		return -EINVAL;
	if (quota->buffers == (nv_xdev_ext_quota_u32)~0U ||
	    quota->bytes > (nv_xdev_ext_quota_u64)~0ULL - bytes ||
	    quota->pages > (nv_xdev_ext_quota_u64)~0ULL - pages)
		return -EOVERFLOW;
	if ((quota->max_buffers && quota->buffers >= quota->max_buffers) ||
	    (quota->max_bytes &&
	     (quota->bytes > quota->max_bytes ||
	      bytes > quota->max_bytes - quota->bytes)))
		return -ENOSPC;

	quota->bytes += bytes;
	quota->pages += pages;
	quota->buffers++;
	return 0;
}

static inline int
nv_xdev_ext_umem_quota_release(struct nv_xdev_ext_umem_quota *quota,
			  nv_xdev_ext_quota_u64 bytes, nv_xdev_ext_quota_u32 pages)
{
	if (!quota || !bytes || !pages || !quota->buffers ||
	    quota->bytes < bytes || quota->pages < pages)
		return -EINVAL;

	quota->bytes -= bytes;
	quota->pages -= pages;
	quota->buffers--;
	return 0;
}

/*
 * A host region pin is charged twice: to the global tracker above and to the
 * pinning process's locked_vm (account_locked_vm(), bounded by
 * RLIMIT_MEMLOCK unless CAP_IPC_LOCK).  Each op returns 0 on success or the
 * caller's own failure code, which the helpers pass through unchanged.
 */
struct nv_xdev_ext_pin_charge_ops {
	nv_xdev_ext_quota_u32 (*reserve)(void *owner, nv_xdev_ext_quota_u64 bytes,
				    nv_xdev_ext_quota_u32 pages);
	nv_xdev_ext_quota_u32 (*release)(void *owner, nv_xdev_ext_quota_u64 bytes,
				    nv_xdev_ext_quota_u32 pages);
	nv_xdev_ext_quota_u32 (*lock)(void *owner, nv_xdev_ext_quota_u32 pages);
	void (*unlock)(void *owner, nv_xdev_ext_quota_u32 pages);
};

/* Charge both or neither. */
static inline nv_xdev_ext_quota_u32
nv_xdev_ext_pin_charge(const struct nv_xdev_ext_pin_charge_ops *ops, void *owner,
		  nv_xdev_ext_quota_u64 bytes, nv_xdev_ext_quota_u32 pages)
{
	nv_xdev_ext_quota_u32 status = ops->reserve(owner, bytes, pages);

	if (status)
		return status;
	status = ops->lock(owner, pages);
	if (status)
		ops->release(owner, bytes, pages);
	return status;
}

/* Undo a successful nv_xdev_ext_pin_charge(); returns the tracker's status. */
static inline nv_xdev_ext_quota_u32
nv_xdev_ext_pin_uncharge(const struct nv_xdev_ext_pin_charge_ops *ops, void *owner,
		    nv_xdev_ext_quota_u64 bytes, nv_xdev_ext_quota_u32 pages)
{
	ops->unlock(owner, pages);
	return ops->release(owner, bytes, pages);
}

#endif /* _NV_XDEV_EXT_UMEM_QUOTA_H_ */
