/* SPDX-License-Identifier: MIT */
/*
 * API declaration only, used to report a missing production feature as a
 * runnable RED test. No implementation or replacement state machine lives here.
 * Once present, nv-xdev_ext-ce-async.h is included directly by the test instead.
 * The caller serializes pool operations; RM validates channel identity before
 * supplying a 64-bit completion watermark from that channel's lifetime.
 */
#ifndef NV_XDEV_EXT_CE_ASYNC_CONTRACT_H
#define NV_XDEV_EXT_CE_ASYNC_CONTRACT_H

#include "../kernel-open/nvidia/nv-xdev_ext-gpu-policy.h"
#include "../kernel-open/nvidia/nv-xdev_ext-ce-classify.h"

enum nv_xdev_ext_ce_async_state {
	NV_XDEV_EXT_CE_ASYNC_FREE = 0,
	NV_XDEV_EXT_CE_ASYNC_RESERVED,
	NV_XDEV_EXT_CE_ASYNC_PENDING,
	NV_XDEV_EXT_CE_ASYNC_QUARANTINED,
};

struct nv_xdev_ext_ce_async_slot {
	nv_xdev_ext_gpu_u64 ticket, token, bytes;
	void *cookie;
	unsigned int state;
};

struct nv_xdev_ext_ce_async_pool {
	struct nv_xdev_ext_ce_async_slot *slots;
	unsigned int capacity, stopping, quarantined;
};

struct nv_xdev_ext_ce_async_completion {
	nv_xdev_ext_gpu_u64 ticket, token, bytes;
	void *cookie;
};

/* Weak declarations permit runtime detection, never replacement behavior. */
extern int nv_xdev_ext_ce_async_init(struct nv_xdev_ext_ce_async_pool *,
	struct nv_xdev_ext_ce_async_slot *, unsigned int) __attribute__((weak));
extern int nv_xdev_ext_ce_async_reserve(struct nv_xdev_ext_ce_async_pool *,
	nv_xdev_ext_gpu_u64, void *, nv_xdev_ext_gpu_u64,
	struct nv_xdev_ext_ce_async_slot **) __attribute__((weak));
extern enum nv_xdev_ext_ce_outcome nv_xdev_ext_ce_async_submitted(
	struct nv_xdev_ext_ce_async_pool *, struct nv_xdev_ext_ce_async_slot *,
	int, int, nv_xdev_ext_gpu_u64) __attribute__((weak));
extern int nv_xdev_ext_ce_async_ready(struct nv_xdev_ext_ce_async_pool *,
	struct nv_xdev_ext_ce_async_slot *, nv_xdev_ext_gpu_u64,
	struct nv_xdev_ext_ce_async_completion *) __attribute__((weak));
extern void nv_xdev_ext_ce_async_stop(struct nv_xdev_ext_ce_async_pool *)
	__attribute__((weak));
extern int nv_xdev_ext_ce_async_can_release(const struct nv_xdev_ext_ce_async_pool *)
	__attribute__((weak));

#endif
