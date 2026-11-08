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

/* RM checks every transfer against a 32-bit size. */
#define NV_XDEV_EXT_CE_SPAN_MAX 0xffffffffULL

/* One RM transfer: len bytes at host_off of the host pages, gpu_off of the window. */
struct nv_xdev_ext_ce_span {
	nv_xdev_ext_gpu_u64 host_off;
	nv_xdev_ext_gpu_u64 gpu_off;
	nv_xdev_ext_gpu_u64 len;
};

/*
 * Appends a validated plan entry to the m transfers in s.  A plan writes one
 * entry per frame; an entry that continues the previous transfer in both the
 * host pages and the window extends it (up to NV_XDEV_EXT_CE_SPAN_MAX), so RM
 * sees one transfer it can cover with as few CE commands as the pages allow.
 * s holds at least one slot per entry.
 */
static inline void nv_xdev_ext_ce_span_add(struct nv_xdev_ext_ce_span *s,
					   nv_xdev_ext_gpu_u32 *m,
					   nv_xdev_ext_gpu_u64 host_off,
					   nv_xdev_ext_gpu_u64 gpu_off,
					   nv_xdev_ext_gpu_u64 len)
{
	if (*m) {
		struct nv_xdev_ext_ce_span *last = &s[*m - 1];

		if (last->host_off + last->len == host_off &&
		    last->gpu_off + last->len == gpu_off &&
		    len <= NV_XDEV_EXT_CE_SPAN_MAX - last->len) {
			last->len += len;
			return;
		}
	}
	s[*m].host_off = host_off;
	s[*m].gpu_off = gpu_off;
	s[*m].len = len;
	(*m)++;
}

/*
 * How a batch's n validated plan entries e[] become RM calls.  per_submit 0
 * (the default) is one call with adjacent entries merged; per_submit k > 0 is
 * the measurement-only per-entry mode (module parameter
 * xdev_ext_ce_entries_per_submit): k entries per call, in plan order, merged
 * only within a call.  nv_xdev_ext_ce_plan_next() builds the next call into
 * spans (at least n slots) and returns its transfer count, 0 when the plan is
 * done; nv_xdev_ext_ce_plan_fold() folds one call's result into the batch's
 * and says whether to continue.  Calls go out in order on one channel, so the
 * last call's token completes the whole batch.  A failed call stops the plan;
 * *issued stays set when an earlier call issued work, so the caller's
 * batch-level classification sees an ambiguous outcome, never a clean
 * pre-submit failure.  *token is the last token of issued work.
 */
static inline nv_xdev_ext_gpu_u32 nv_xdev_ext_ce_plan_next(const struct nv_xdev_ext_ce_span *e,
	nv_xdev_ext_gpu_u32 n, nv_xdev_ext_gpu_u32 per_submit, nv_xdev_ext_gpu_u32 *start,
	struct nv_xdev_ext_ce_span *spans)
{
	nv_xdev_ext_gpu_u32 k = per_submit && per_submit < n ? per_submit : n;
	nv_xdev_ext_gpu_u32 end, m = 0, i;

	if (*start >= n)
		return 0;
	end = n - *start > k ? *start + k : n;
	for (i = *start; i < end; i++)
		nv_xdev_ext_ce_span_add(spans, &m, e[i].host_off, e[i].gpu_off, e[i].len);
	*start = end;
	return m;
}

static inline int nv_xdev_ext_ce_plan_fold(nv_xdev_ext_gpu_u32 status, int call_issued,
	nv_xdev_ext_gpu_u64 call_token, int *issued, nv_xdev_ext_gpu_u64 *token)
{
	if (call_issued || status == 0)
		*issued = 1;
	if (status == 0)
		*token = call_token;
	return status == 0;
}

/* One RM call: 0 or an RM status; *issued if it issued work. */
typedef nv_xdev_ext_gpu_u32 (*nv_xdev_ext_ce_submit_fn)(void *ctx,
		const struct nv_xdev_ext_ce_span *s, nv_xdev_ext_gpu_u32 m,
		int *issued, nv_xdev_ext_gpu_u64 *token);

/* The loop nv_xdev_ext_ce_submit() runs, with the RM call as a callback. */
static inline nv_xdev_ext_gpu_u32 nv_xdev_ext_ce_submit_plan(
	const struct nv_xdev_ext_ce_span *e, nv_xdev_ext_gpu_u32 n,
	nv_xdev_ext_gpu_u32 per_submit, struct nv_xdev_ext_ce_span *spans,
	nv_xdev_ext_ce_submit_fn submit, void *ctx, int *issued,
	nv_xdev_ext_gpu_u64 *token, nv_xdev_ext_gpu_u32 *calls)
{
	nv_xdev_ext_gpu_u32 start = 0, status = 0, m;

	*issued = 0;
	*token = 0;
	*calls = 0;
	while ((m = nv_xdev_ext_ce_plan_next(e, n, per_submit, &start, spans))) {
		nv_xdev_ext_gpu_u64 t = 0;
		int iss = 0;

		status = submit(ctx, spans, m, &iss, &t);
		(*calls)++;
		if (!nv_xdev_ext_ce_plan_fold(status, iss, t, issued, token))
			break;
	}
	return status;
}

#endif /* _NV_XDEV_EXT_CE_PLAN_H_ */
