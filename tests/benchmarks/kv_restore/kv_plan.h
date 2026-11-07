/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KV_RESTORE_PLAN_H
#define KV_RESTORE_PLAN_H
/*
 * Restore arithmetic of the K-KV driver (same rules as kv_layout.py).
 *
 * Host 1's NVMe window holds the KV objects.  Its key-based NVMe program
 * reads slot (key mod slots) of the window, so a restore with ordinal r uses
 * keys r * slots + slot0 .. + groups - 1 and key i reads the object's group
 * i; a later restore uses a larger ordinal and therefore larger keys.  Host 2
 * lends frames dst_frame0 .. + groups * frames_per_group - 1 of its device
 * memory pool once, in order, so group i lands at frame dst_frame0 +
 * i * frames_per_group and the KV ends contiguous in device memory.  Host 1
 * recycles min(groups, depth) groups of a depth-sized staging ring.
 *
 * With a CE VMM destination (host2_ring) host 2 receives into a recycled ring
 * of min(groups, depth) groups of host frames, like host 1, and the copy
 * engine places group i at frame dst_frame0 + i * frames_per_group of the
 * GPU allocation; only the ring is lent, so the START frame-index limit does
 * not bound the restore.
 *
 * Include the xdev_ext_mech UAPI header before this one.
 */
#ifndef XDEV_EXT_MECH_ABI_VERSION
#error "include the xdev_ext_mech UAPI header before kv_plan.h"
#endif
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "kv_pattern.h"

#define KV_NHI_FRAME		XDEV_EXT_XDOMAIN_MAX_FRAME
#define KV_NHI_MAX_ELEMS	XDEV_EXT_XDOMAIN_MAX_ELEMS
#define KV_MAX_FRAMES		XDEV_EXT_MECH_MAX_FRAMES
#define KV_PEER_FRAME_MIN	4096u
#define KV_PEER_FRAME_MAX	(2u << 20)
#define KV_MAX_DEPTH		64u
#define KV_MAX_WINDOW		XDEV_EXT_XDOMAIN_MAX_WINDOW
#define KV_MAX_NLB		65536u
#define KV_LIB_MAX_START_FRAMES	65536u

struct kv_window {
	uint64_t slba, nlb;		/* host 1 NVMe stage window (arg0, arg1) */
	uint32_t lba_bytes;
};

struct kv_geometry {
	uint32_t group_bytes, frame_bytes, depth, window;
	bool early;
};

struct kv_request {
	uint64_t object_slba, bytes, ordinal;
	uint32_t dst_frame0;
	uint64_t pool_frames;		/* 0: exactly what the restore needs */
	bool host2_ring;		/* host 2 lends a recycled ring (CE VMM) */
};

struct kv_plan {
	uint64_t groups, blocks_per_group, slots, slot0, ordinal, first_seq;
	uint32_t frames_per_group, host1_pool_frames, host1_recycle_frames, host2_dst_frame0;
	uint64_t host2_frames, host2_pool_frames;
	uint32_t host2_start_frames;	/* frame indices host 2's START lends */
	bool host2_ring;
};

/* One START as libxdev_ext's xdev_ext_session_start_frames() takes it. */
struct kv_start {
	uint64_t nr_batches, first_seq;
	uint32_t nr_frames;
	bool recycle;
};

static inline bool kv_pow2(uint64_t v)
{
	return v && !(v & (v - 1));
}

static inline int kv_geometry_check(const struct kv_geometry *g, uint32_t lba)
{
	uint32_t f = g->frame_bytes, s = g->group_bytes;

	if (!kv_pow2(lba) || lba < 512 || lba > 65536)
		return -EINVAL;
	if (!kv_pow2(f) || f < KV_PEER_FRAME_MIN || f > KV_PEER_FRAME_MAX || s < f || s % f)
		return -EINVAL;
	if (s / f > KV_MAX_FRAMES || s / KV_NHI_FRAME > KV_NHI_MAX_ELEMS)
		return -E2BIG;
	if (s % lba)
		return -EINVAL;
	if (s / lba > KV_MAX_NLB)
		return -E2BIG;
	if (!g->depth || g->depth > KV_MAX_DEPTH || !g->window ||
	    g->window > KV_MAX_WINDOW || g->window > g->depth)
		return -EINVAL;
	return 0;
}

static inline int kv_plan_make(const struct kv_window *w, const struct kv_geometry *g,
			       const struct kv_request *r, struct kv_plan *out)
{
	uint64_t blocks, slots, rel, slot0, groups, frames, need, pool;
	uint32_t fpg, ring;
	int ret;

	memset(out, 0, sizeof(*out));
	ret = kv_geometry_check(g, w->lba_bytes);
	if (ret)
		return ret;
	if (!w->nlb || w->nlb > UINT64_MAX - w->slba || !r->ordinal || !r->bytes ||
	    r->bytes % g->group_bytes)
		return -EINVAL;
	groups = r->bytes / g->group_bytes;
	blocks = g->group_bytes / w->lba_bytes;
	slots = w->nlb / blocks;
	if (!slots || r->object_slba < w->slba)
		return -ERANGE;
	rel = r->object_slba - w->slba;
	if (rel % blocks)
		return -EINVAL;
	slot0 = rel / blocks;
	if (slot0 >= slots || groups > slots - slot0)
		return -ERANGE;
	if (r->ordinal > (UINT64_MAX - slot0 - groups) / slots)
		return -EOVERFLOW;
	fpg = g->group_bytes / g->frame_bytes;
	if (!r->host2_ring && groups > KV_LIB_MAX_START_FRAMES / fpg)
		return -E2BIG;
	ring = (uint32_t)(groups < g->depth ? groups : g->depth) * fpg;
	frames = groups * fpg;
	need = (uint64_t)r->dst_frame0 + frames;
	pool = r->pool_frames ? r->pool_frames : need;
	if (pool > UINT32_MAX)
		return -EINVAL;
	if (pool < need)
		return -ENOSPC;
	*out = (struct kv_plan){
		.groups = groups, .blocks_per_group = blocks, .slots = slots, .slot0 = slot0,
		.ordinal = r->ordinal, .first_seq = r->ordinal * slots + slot0,
		.frames_per_group = fpg, .host1_pool_frames = g->depth * fpg,
		.host1_recycle_frames = ring,
		.host2_dst_frame0 = r->dst_frame0, .host2_frames = frames,
		.host2_pool_frames = pool,
		.host2_start_frames = r->host2_ring ? ring : (uint32_t)frames,
		.host2_ring = r->host2_ring,
	};
	return 0;
}

/* SLBA host 1 reads for group @i of the plan, UINT64_MAX past the plan. */
static inline uint64_t kv_plan_group_slba(const struct kv_plan *p, const struct kv_window *w,
					  uint64_t i)
{
	if (i >= p->groups)
		return UINT64_MAX;
	return w->slba + ((p->first_seq + i) % p->slots) * p->blocks_per_group;
}

/* host2_start_frames entries: the destination frames, or the ring from frame 0. */
static inline void kv_plan_host2_indices(const struct kv_plan *p, uint32_t *idx)
{
	for (uint32_t i = 0; i < p->host2_start_frames; i++)
		idx[i] = (p->host2_ring ? 0 : p->host2_dst_frame0) + i;
}

static inline void kv_plan_host1_indices(const struct kv_plan *p, uint32_t *idx)
{
	for (uint32_t i = 0; i < p->host1_recycle_frames; i++)
		idx[i] = i;
}

static inline void kv_plan_host2_start(const struct kv_plan *p, struct kv_start *s)
{
	*s = (struct kv_start){ .nr_batches = p->groups, .first_seq = p->first_seq,
		.nr_frames = p->host2_start_frames, .recycle = p->host2_ring };
}

static inline void kv_plan_host1_start(const struct kv_plan *p, struct kv_start *s)
{
	*s = (struct kv_start){ .nr_batches = p->groups, .first_seq = p->first_seq,
		.nr_frames = p->host1_recycle_frames, .recycle = true };
}

/* PEER layout: no header room, one segment per frame. */
static inline void kv_plan_layout(const struct kv_geometry *g, struct xdev_ext_mech_layout *l)
{
	*l = (struct xdev_ext_mech_layout){ .frame_size = g->frame_bytes, .hdr_room = 0,
		.seg_len = g->frame_bytes, .group_bytes = g->group_bytes };
}

/* XDOMAIN stage arg1: data channel 0 and the in-flight window. */
static inline __u64 kv_plan_xdomain_arg1(const struct kv_geometry *g)
{
	return (__u64)g->window << XDEV_EXT_XDOMAIN_WINDOW_SHIFT;
}

#endif /* KV_RESTORE_PLAN_H */
