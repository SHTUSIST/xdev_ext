/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NVME_XDEV_EXT_NATIVE_PEER_TRACE_H
#define _NVME_XDEV_EXT_NATIVE_PEER_TRACE_H

#include <linux/errno.h>
#include <trace/events/xdev_ext.h>

#include <linux/xdev_ext_peer.h>

/*
 * Observation fields are immutable while the request can reach an SQ. The
 * owner retains the leases until end_io and worker consumption (or execute
 * returns for synchronous ioctls). NVME_REQ_XDEV_EXT_PEER guards the request
 * pointer; nvme_clear_nvme_request() resets that flag before a request is
 * reused. submit_epoch is not observation: nvme-pci writes the requester's
 * DMA-stop epoch at each SQ preparation; an owner that reads it after
 * completion initializes it to XDEV_EXT_PEER_EPOCH_NONE.
 */
struct nvme_xdev_ext_peer_trace {
	const struct xdev_ext_peer_fd_lease *leases;
	u32 nr_leases, bytes;
	const char *origin;
	u64 cookie;
	u64 submit_epoch;
};

/* Lease retirement is not dma_unmap: UNKNOWN keeps the underlying mapping. */
static inline void nvme_xdev_ext_peer_trace_release(
		const struct nvme_xdev_ext_peer_trace *ctx, bool quiesced)
{
	struct xdev_ext_native_event e;
	bool retired = true;
	u32 i;

	if (!trace_native_event_enabled() || !ctx->cookie)
		return;
	for (i = 0; i < ctx->nr_leases; i++)
		retired &= !ctx->leases[i].file && !ctx->leases[i].lease.mapping;
	e = (struct xdev_ext_native_event) {
		.phase = "peer_dma_release", .origin = ctx->origin, .class_id = 3,
		.cookie = ctx->cookie, .bytes = ctx->bytes, .aux = ctx->nr_leases,
		.accepted = quiesced && retired,
		.status = !retired ? -ESTALE : quiesced ? 0 : -EINPROGRESS,
	};
	trace_native_event(&e);
}
#endif
