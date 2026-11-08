/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_CUDA_FRAME_ENDPOINT_OWNER_H
#define XDEV_EXT_CUDA_FRAME_ENDPOINT_OWNER_H
/*
 * Host-frame endpoint owner for TP on a GPU without GPUDirect RDMA: two CUDA
 * VMM windows (send, receive), each exported as a POSIX fd and attached to
 * its own CE device fd, the XDOMAIN class program (global default), one
 * PRIVATE CE program instance per CE stage, and the two host-frame
 * endpoints (libxdev_ext_frame_endpoint.h), created. No START: each TP
 * collective posts its own batches. The TP communicator borrows the view
 * with XDEV_TP_F_HOST_FRAMES.
 */
#include <cuda.h>
#include <stddef.h>
#include <stdint.h>
#include "libxdev_ext_frame_endpoint.h"
#ifdef __cplusplus
extern "C" {
#endif
struct xdev_ext_cuda_frame_owner;
#define XDEV_EXT_CUDA_FRAME_OWNER_VERSION 1U
struct xdev_ext_cuda_frame_owner_opts {
 size_t size;
 uint32_t version, context_mode, device; /* context_mode: enum xdev_ext_cuda_peer_context_mode values */
 CUcontext context;
 CUstream stream;
 const char *nvidia_node;   /* CE device, opened once per CE stage */
 const char *bpf_object;    /* XDOMAIN program object, map xdomain_peer_ops */
 const char *ce_bpf_object; /* tp_ce_place.bpf.o, map tp_ce_ops (PRIVATE) */
 uint64_t link_token, timeout_ns;
 uint32_t group_bytes;      /* one TP message: 64-byte header + payload, 64-aligned */
 uint32_t receive_groups;   /* receive window ring, >= 1 */
 uint32_t endpoint_flags;   /* XDEV_EXT_FRAME_ENDPOINT_F_EARLY */
};
struct xdev_ext_cuda_frame_owner_view {
 size_t size;
 CUcontext context;
 CUstream stream;
 struct xdev_ext_frame_endpoint *tx_frames, *rx_frames;
 CUdeviceptr tx_va, rx_va;     /* CE windows */
 uint64_t tx_bytes, rx_bytes;  /* window lengths given to the CE stages */
 uint32_t group_bytes;
};
/* A non-NULL output on error owns partial resources: retain it until close
 * succeeds. */
int xdev_ext_cuda_frame_owner_open(const struct xdev_ext_cuda_frame_owner_opts *,
 struct xdev_ext_cuda_frame_owner **);
int xdev_ext_cuda_frame_owner_get_view(struct xdev_ext_cuda_frame_owner *,
 struct xdev_ext_cuda_frame_owner_view *);
/* Caller first destroys every borrower. Synchronizes the bound stream, stops
 * and closes both endpoints, then frees programs, fds and VMM windows. Any
 * failure keeps the owner and what remains; success sets *owner = NULL. */
int xdev_ext_cuda_frame_owner_close(struct xdev_ext_cuda_frame_owner **);
#ifdef __cplusplus
}
#endif
#endif
