/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NVME_CE_RANDOM_CONTRACT_H
#define NVME_CE_RANDOM_CONTRACT_H
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "include/uapi/linux/xdev_ext_mech.h"

enum { RR_PAYLOAD = 1048576, RR_FRAME = 32768, RR_FRAMES = 32 };
struct rr_geometry {
	uint64_t gpu_bytes, disk_bytes, guard_bytes;
	uint32_t depth, lba_bytes;
};
struct rr_request {
	uint64_t key, nvme_offset, gpu_offset;
	uint32_t bytes, phase;
};
static inline int rr_geometry_check(const struct rr_geometry *g)
{
	if (!g) return -EINVAL;
	if (g->guard_bytes > (UINT64_MAX - g->gpu_bytes) / 2 ||
	    g->guard_bytes > (UINT64_MAX - g->disk_bytes) / 2)
		return -EOVERFLOW;
	if (g->depth < 2 || g->depth > 64 || !g->guard_bytes ||
	    g->lba_bytes < 512 || (g->lba_bytes & (g->lba_bytes - 1)) ||
	    RR_PAYLOAD % g->lba_bytes || g->guard_bytes % g->lba_bytes ||
	    g->gpu_bytes < RR_PAYLOAD || g->disk_bytes < RR_PAYLOAD ||
	    g->disk_bytes % g->lba_bytes)
		return -EINVAL;
	return 0;
}
static inline int rr_validate(const struct rr_geometry *g,
		const struct rr_request *rows, size_t count, bool save)
{
	size_t i, j, phase_begin = 0;
	int ret = rr_geometry_check(g);
	if (ret) return ret;
	if (!rows || !count || count > UINT32_MAX || !rows[0].key || rows[0].phase)
		return -EINVAL;
	/* START must represent the next key after its last accepted request. */
	if (rows[count-1].key == UINT64_MAX) return -EINVAL;
	for (i = 0; i < count; i++) {
		const struct rr_request *r = rows + i;
		if (r->bytes != RR_PAYLOAD || r->nvme_offset % g->lba_bytes)
			return -EINVAL;
		if (r->nvme_offset > UINT64_MAX - RR_PAYLOAD ||
		    r->gpu_offset > UINT64_MAX - RR_PAYLOAD)
			return -EOVERFLOW;
		if (r->gpu_offset > g->gpu_bytes - RR_PAYLOAD ||
		    r->nvme_offset > g->disk_bytes - RR_PAYLOAD)
			return -ERANGE;
		if (i && (rows[i-1].key == UINT64_MAX || r->key != rows[i-1].key + 1 ||
		    r->phase < rows[i-1].phase || r->phase - rows[i-1].phase > 1))
			return -EINVAL;
		if (i && r->phase != rows[i-1].phase) {
			if (i - phase_begin < g->depth) return -EINVAL;
			phase_begin = i;
		}
		for (j = phase_begin; j < i; j++) {
			const struct rr_request *p = rows + j;
			if (r->gpu_offset < p->gpu_offset + RR_PAYLOAD &&
			    p->gpu_offset < r->gpu_offset + RR_PAYLOAD)
				return -EAGAIN;
			if (save && r->nvme_offset < p->nvme_offset + RR_PAYLOAD &&
			    p->nvme_offset < r->nvme_offset + RR_PAYLOAD)
				return -EAGAIN;
		}
	}
	return count - phase_begin < g->depth ? -EINVAL : 0;
}
static inline int rr_create(struct xdev_ext_mech_create *out,
		const struct rr_geometry *g, int nvme, int ce, uint64_t gpu_va,
		uint64_t slba, uint64_t nlb, bool save, int eventfd)
{
	struct xdev_ext_mech_create c = { .abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.nr_stages = 2, .pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1,
		.layout = {RR_FRAME, 0, RR_FRAME, RR_PAYLOAD} };
	int ret = rr_geometry_check(g);
	if (ret) return ret;
	if (!out || nvme < 0 || ce < 0 || !gpu_va || eventfd < -1 || !nlb ||
	    nlb != g->disk_bytes / g->lba_bytes)
		return -EINVAL;
	if (gpu_va > UINT64_MAX - g->gpu_bytes || slba > UINT64_MAX - nlb)
		return -EOVERFLOW;
	c.depth = g->depth; c.eventfd = eventfd;
	c.st[save] = (struct xdev_ext_mech_stage_uapi){
		.class_id = XDEV_EXT_MECH_CLASS_NVME, .fd = nvme,
		.direction = save ? XDEV_EXT_MECH_DIR_TO_DEVICE : XDEV_EXT_MECH_DIR_FROM_DEVICE,
		.arg0 = slba, .arg1 = nlb };
	c.st[1-save] = (struct xdev_ext_mech_stage_uapi){
		.class_id = XDEV_EXT_MECH_CLASS_CE, .fd = ce,
		.direction = save ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE,
		.flags = XDEV_EXT_CE_STAGE_F_TARGET_RANGE,
		.arg0 = gpu_va, .arg1 = g->gpu_bytes };
	*out = c;
	return 0;
}
static inline void rr_selectors(int out[XDEV_EXT_MECH_MAX_STAGES],
		int nvme, int ce, bool save)
{
	unsigned i;
	for (i = 0; i < XDEV_EXT_MECH_MAX_STAGES; i++) out[i] = -1;
	out[save] = nvme; out[1-save] = ce;
}
#endif
