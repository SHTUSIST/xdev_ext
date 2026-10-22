/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NV_CE_RUNTIME_CASES_H
#define NV_CE_RUNTIME_CASES_H

/*
 * Cases of nv_ce_runtime_test, the real-GPU copy-engine round trip through
 * the XDEV_EXT P2P ioctls (tools/include/xdev_ext_nv_p2p_ioctl.h): the geometry of
 * its buffers, the round trips, the error requests, the test pattern and
 * the gate that keeps it from running outside a GPU window.  Pure, so
 * nv_ce_runtime_cases_test checks it where no GPU is.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NV_CE_KIB		1024ULL
#define NV_CE_MIB		(1024ULL * NV_CE_KIB)
#define NV_CE_MAX_SIZE		(64 * NV_CE_MIB)
/* Bytes on each side of a copy that must stay untouched. */
#define NV_CE_GUARD		64ULL
#define NV_CE_GUARD_BYTE	0xa5U
/*
 * One host area and the GPU allocation: the largest copy plus room for
 * offsets.  The pinned host region is a source area then a destination
 * area, in 4 KiB frames.
 */
#define NV_CE_AREA		(NV_CE_MAX_SIZE + 4 * NV_CE_MIB)
#define NV_CE_HOST_BYTES	(2 * NV_CE_AREA)
#define NV_CE_FRAME		4096U
#define NV_CE_BATCH		64U	/* XDEV_EXT_NV_P2P_MAX_BATCH */

/* One copy: @size bytes at @host_off of a host area, @gpu_off of the GPU. */
struct nv_ce_case {
	const char *name;
	uint64_t size;
	uint64_t host_off;
	uint64_t gpu_off;
};

static const struct nv_ce_case nv_ce_cases[] = {
	/* Every power of two from 4 KiB to 64 MiB, page aligned. */
	{ "aligned-4K", 4 * NV_CE_KIB, 4096, 4096 },
	{ "aligned-8K", 8 * NV_CE_KIB, 4096, 4096 },
	{ "aligned-16K", 16 * NV_CE_KIB, 4096, 4096 },
	{ "aligned-32K", 32 * NV_CE_KIB, 4096, 4096 },
	{ "aligned-64K", 64 * NV_CE_KIB, 4096, 4096 },
	{ "aligned-128K", 128 * NV_CE_KIB, 4096, 4096 },
	{ "aligned-256K", 256 * NV_CE_KIB, 4096, 4096 },
	{ "aligned-512K", 512 * NV_CE_KIB, 4096, 4096 },
	{ "aligned-1M", 1 * NV_CE_MIB, 4096, 4096 },
	{ "aligned-2M", 2 * NV_CE_MIB, 4096, 4096 },
	{ "aligned-4M", 4 * NV_CE_MIB, 4096, 4096 },
	{ "aligned-8M", 8 * NV_CE_MIB, 4096, 4096 },
	{ "aligned-16M", 16 * NV_CE_MIB, 4096, 4096 },
	{ "aligned-32M", 32 * NV_CE_MIB, 4096, 4096 },
	{ "aligned-64M", 64 * NV_CE_MIB, 4096, 4096 },
	/* Odd sizes at odd offsets on both sides. */
	{ "unaligned-4K", 4096 + 13, 4096 + 7, 4096 + 3 },
	{ "unaligned-1M", NV_CE_MIB + 5, 8189, 65531 },
	/* Across 64 KiB GPU pages. */
	{ "cross-64K", 200, 4096 + 64, 64 * NV_CE_KIB - 100 },
	{ "cross-64K-pages", 3 * 64 * NV_CE_KIB, 4097, 64 * NV_CE_KIB - 1 },
	/* Across 2 MiB GPU pages. */
	{ "cross-2M", 8192 + 11, 8191, 2 * NV_CE_MIB - 4096 + 5 },
	{ "cross-2M-4M", 4 * NV_CE_MIB + 3, 4099, 2 * NV_CE_MIB - 1 },
	{ "unaligned-64M", NV_CE_MAX_SIZE, 4097, 2 * NV_CE_MIB - 7 },
};

#define NV_CE_NR_CASES	(sizeof(nv_ce_cases) / sizeof(nv_ce_cases[0]))

/* A copy and its guards inside a host area and inside the GPU allocation. */
static inline bool nv_ce_case_fits(const struct nv_ce_case *c)
{
	return c->size && c->size <= NV_CE_MAX_SIZE &&
	       c->host_off >= NV_CE_GUARD && c->gpu_off >= NV_CE_GUARD &&
	       c->host_off <= NV_CE_AREA && c->gpu_off <= NV_CE_AREA &&
	       c->size + NV_CE_GUARD <= NV_CE_AREA - c->host_off &&
	       c->size + NV_CE_GUARD <= NV_CE_AREA - c->gpu_off;
}

/*
 * Entry @i of the batch round trip: NV_CE_BATCH odd-sized copies back to
 * back, starting just below a 64 KiB GPU page.
 */
static inline void nv_ce_batch_entry(uint32_t i, struct nv_ce_case *c)
{
	const uint64_t size = 4096 + 17;

	c->name = "batch";
	c->size = size;
	c->host_off = 4097 + i * size;
	c->gpu_off = 64 * NV_CE_KIB - 4096 + 5 + i * size;
}

/* Requests the driver must refuse before any copy is submitted. */
enum nv_ce_err_kind {
	NV_CE_ERR_SIZE_ZERO,
	NV_CE_ERR_HOST_RANGE,
	NV_CE_ERR_GPU_RANGE,
	NV_CE_ERR_DIRECTION,
	NV_CE_ERR_BAD_HANDLE,
	NV_CE_ERR_STALE_HANDLE,
	NV_CE_ERR_NR,
};

/*
 * @host_off counts from the start of the pinned region, @gpu_off from the
 * GPU allocation; @handle_xor is applied to the live handle.
 */
struct nv_ce_error {
	const char *name;
	enum nv_ce_err_kind kind;
	uint64_t size;
	uint64_t host_off;
	uint64_t gpu_off;
	uint32_t direction;
	uint64_t handle_xor;
};

static const struct nv_ce_error nv_ce_errors[] = {
	{ "size-zero", NV_CE_ERR_SIZE_ZERO, 0, 4096, 4096, 1, 0 },
	{ "host-range", NV_CE_ERR_HOST_RANGE, 8192, NV_CE_HOST_BYTES - 4096,
	  4096, 1, 0 },
	{ "host-end", NV_CE_ERR_HOST_RANGE, 4096, NV_CE_HOST_BYTES, 4096, 1, 0 },
	{ "direction-2", NV_CE_ERR_DIRECTION, 4096, 4096, 4096, 2, 0 },
	/* Another registry slot, and the live slot of an older generation. */
	{ "bad-handle", NV_CE_ERR_BAD_HANDLE, 4096, 4096, 4096, 1, 0x5a5aULL },
	{ "stale-handle", NV_CE_ERR_STALE_HANDLE, 4096, 4096, 4096, 1,
	  1ULL << 32 },
	{ "gpu-range", NV_CE_ERR_GPU_RANGE, 8192, 4096, NV_CE_AREA - 4096, 1,
	  0 },
};

#define NV_CE_NR_ERRORS	(sizeof(nv_ce_errors) / sizeof(nv_ce_errors[0]))

/* Byte @i of a buffer seeded @seed; differs across seeds and 4 KiB pages. */
static inline uint8_t nv_ce_pattern(uint32_t seed, uint64_t i)
{
	uint32_t x = (uint32_t)i * 2654435761U ^
		     (uint32_t)(i >> 12) * 0x9e3779b9U ^ seed * 0x85ebca6bU;

	x ^= x >> 15;
	x *= 0x2c1b3c6dU;
	x ^= x >> 12;
	return (uint8_t)(x ^ (x >> 24));
}

enum nv_ce_gate {
	NV_CE_GATE_RUN,
	NV_CE_GATE_NO_WINDOW,	/* --i-have-the-gpu-window missing */
	NV_CE_GATE_HOST_BUILD,	/* built without CUDA */
};

/* Run only a CUDA build that was told it owns a GPU window. */
static inline enum nv_ce_gate nv_ce_runtime_gate(bool window_flag,
						 bool with_cuda)
{
	if (!with_cuda)
		return NV_CE_GATE_HOST_BUILD;
	return window_flag ? NV_CE_GATE_RUN : NV_CE_GATE_NO_WINDOW;
}

static inline const char *nv_ce_gate_reason(enum nv_ce_gate gate)
{
	switch (gate) {
	case NV_CE_GATE_RUN:
		return "none";
	case NV_CE_GATE_NO_WINDOW:
		return "no-gpu-window-flag";
	default:
		return "host-build";
	}
}

#endif /* NV_CE_RUNTIME_CASES_H */
