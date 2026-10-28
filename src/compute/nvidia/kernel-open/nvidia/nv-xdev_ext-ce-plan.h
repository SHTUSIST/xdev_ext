/*
 * SPDX-FileCopyrightText: Copyright (c) 2026
 * SPDX-License-Identifier: MIT
 *
 * Pure parts of the copy-engine backend that nvidia.ko registers with the
 * XDEV_EXT mechanism layer: how one submitted plan becomes RM transfers.  The
 * kernel CE class has already validated the plan against the window and the
 * batch frames; the backend checks every entry again against what it bound
 * itself, fail-closed, before anything reaches RM.  No RM or XDEV_EXT dependency,
 * so tests/ exercises it in user space.
 */
#ifndef _NV_XDEV_EXT_CE_PLAN_H_
#define _NV_XDEV_EXT_CE_PLAN_H_

#include "nv-xdev_ext-gpu-policy.h"

/* Entries of one submit; equals RM's P2P_UMEM_MAX_XFERS. */
#define NV_XDEV_EXT_CE_MAX_XFERS 64U

/*
 * A stage direction is relative to the GPU (enum xdev_ext_mech_dir): TO_DEVICE
 * copies host pages into the window, RM direction 1; FROM_DEVICE copies the
 * window back, RM direction 0.
 */
static inline int nv_xdev_ext_ce_rm_direction(nv_xdev_ext_gpu_u32 stage_dir,
					 nv_xdev_ext_gpu_u32 *rm_dir)
{
	switch (stage_dir) {
	case NV_XDEV_EXT_GPU_TO_DEVICE:
		*rm_dir = NV_XDEV_EXT_GPU_UMEM_TO_GPU;
		return 0;
	case NV_XDEV_EXT_GPU_FROM_DEVICE:
		*rm_dir = NV_XDEV_EXT_GPU_GPU_TO_UMEM;
		return 0;
	default:
		return -EINVAL;
	}
}

static inline int nv_xdev_ext_ce_count_ok(nv_xdev_ext_gpu_u32 n)
{
	return n != 0 && n <= NV_XDEV_EXT_CE_MAX_XFERS;
}

/*
 * len bytes at host_off of the bound host pages (host_bytes long) and at
 * gpu_off of the bound window (window_len long), in subtraction form.
 */
static inline int nv_xdev_ext_ce_entry_ok(nv_xdev_ext_gpu_u64 host_off,
				     nv_xdev_ext_gpu_u64 gpu_off,
				     nv_xdev_ext_gpu_u32 len,
				     nv_xdev_ext_gpu_u64 window_len,
				     nv_xdev_ext_gpu_u64 host_bytes)
{
	return len != 0 &&
	       host_off <= host_bytes && len <= host_bytes - host_off &&
	       gpu_off <= window_len && len <= window_len - gpu_off;
}

/*
 * status of xdev_ext_ce_complete(): 0 for NV_OK, else the errno RM's status maps
 * to.  Classification is status-first, so hw_submitted only matters on a
 * failure.
 */
static inline nv_xdev_ext_gpu_s32
nv_xdev_ext_ce_complete_status(nv_xdev_ext_gpu_u32 rm_status,
			  nv_xdev_ext_gpu_s32 mapped_error)
{
	return nv_xdev_ext_gpu_normalize_status(rm_status, mapped_error);
}

#endif /* _NV_XDEV_EXT_CE_PLAN_H_ */
