/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBXDEV_EXT_FRAME_ENDPOINT_H
#define LIBXDEV_EXT_FRAME_ENDPOINT_H
/*
 * Host-frame XDOMAIN endpoint for a GPU without GPUDirect RDMA.  One
 * endpoint is one session on the ring's own UMEM host frames:
 *
 *   send     [CE FROM_DEVICE, XDOMAIN TO_DEVICE]: the GPU copy engine moves
 *            the group from the batch's slot of the device window into host
 *            frames, then XDOMAIN transmits them.
 *   receive  [XDOMAIN FROM_DEVICE, CE TO_DEVICE + TARGET_RANGE]: XDOMAIN
 *            receives into host frames, then the copy engine writes the
 *            whole group into the device window.
 *
 * The CPU copies no payload byte.  The device window is a CUDA allocation
 * the caller attached to the CE device fd before CREATE.  Each post STARTs
 * one batch keyed by the caller's sequence; the next post needs the previous
 * batch finished.  Depth is 1, so the send group always sits at window
 * offset 0; the receive placement is the CE program's (place() below gives
 * the rule both sides use).
 */
#include "libxdev_ext.h"
#ifdef __cplusplus
extern "C" {
#endif
struct xdev_ext_frame_endpoint;
#define XDEV_EXT_FRAME_ENDPOINT_F_EARLY 1U	/* XDOMAIN early CTS */
struct xdev_ext_frame_endpoint_opts {
	size_t sz;
	int control_fd;		/* /dev/xdev_ext_peer, borrowed until close */
	int ce_fd;		/* CE device fd with the window attached, borrowed */
	__u64 link_token;
	__u32 direction;	/* TO_DEVICE: send; FROM_DEVICE: receive */
	__u32 depth;		/* 1 */
	__u32 group_bytes;	/* multiple of 64, at most 32 frames */
	__u32 flags;		/* XDEV_EXT_FRAME_ENDPOINT_F_* */
	__u64 window_va, window_bytes;	/* CE window: device VA and length */
};
/* Opens the UMEM session and prepares the two stages; no CREATE. A non-NULL
 * output on error owns partial resources and must be closed. */
int xdev_ext_frame_endpoint_open(const struct xdev_ext_frame_endpoint_opts *,
	struct xdev_ext_frame_endpoint **);
int xdev_ext_frame_endpoint_create(struct xdev_ext_frame_endpoint *);
/* Selectors in stage order (send: CE, XDOMAIN; receive: XDOMAIN, CE); -1
 * keeps that stage's global default. */
int xdev_ext_frame_endpoint_create_programs(struct xdev_ext_frame_endpoint *,
	const int *program_fds, __u32 nr_programs,
	struct xdev_ext_mech_create_report *report);
/* Window byte offset and length of the group keyed @sequence. Send: offset
 * 0. Receive: (sequence % (window_bytes / group_bytes)) * group_bytes. */
int xdev_ext_frame_endpoint_place(const struct xdev_ext_frame_endpoint *,
	__u64 sequence, __u64 *offset, __u32 *bytes);
/* START one batch keyed @sequence (nonzero). -EBUSY while one is posted. */
int xdev_ext_frame_endpoint_post(struct xdev_ext_frame_endpoint *, __u64 sequence);
/* Wait for the posted batch @sequence to finish without error. A timeout
 * leaves it posted; any other failure is sticky for the endpoint. */
int xdev_ext_frame_endpoint_wait(struct xdev_ext_frame_endpoint *, __u64 sequence,
	int timeout_ms);
int xdev_ext_frame_endpoint_stop(struct xdev_ext_frame_endpoint *);
int xdev_ext_frame_endpoint_close(struct xdev_ext_frame_endpoint *);
struct xdev_ext_session *xdev_ext_frame_endpoint_session(struct xdev_ext_frame_endpoint *);
#ifdef __cplusplus
}
#endif
#endif
