/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_CUDA_PEER_ENDPOINT_OWNER_H
#define XDEV_EXT_CUDA_PEER_ENDPOINT_OWNER_H
#include "libxdev_ext_cuda.h"
#include "libxdev_ext_peer_message.h"
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct xdev_ext_cuda_peer_owner;
enum xdev_ext_cuda_peer_context_mode {
 XDEV_EXT_CUDA_PEER_BORROW_CURRENT = 1,
 XDEV_EXT_CUDA_PEER_CREATE_OWN = 2,
};
struct xdev_ext_cuda_peer_owner_opts {
 size_t size;
 uint32_t version, mode, context_mode, device;
 CUcontext context;
 CUstream stream;
 const char *nvidia_node, *bpf_object;
 uint64_t link_token, allocation_bytes, nr_batches, first_sequence, timeout_ns;
 uint32_t group_bytes, depth;
 const char *user_bpf_object;
};
struct xdev_ext_cuda_peer_owner_view {
 size_t size;
 CUcontext context;
 CUstream stream;
 struct xdev_ext_peer_endpoint *tx_endpoint, *rx_endpoint;
 CUdeviceptr tx_va, rx_va;
 uint64_t allocation_bytes;
 struct xdev_ext_cuda_user *tx_producer, *tx_terminal, *rx_consumer;
 uint32_t frame_size;
};
/* open prepares two independent admitted authorities, controls and endpoints;
 * it owns explicit XDOMAIN and USER class program references and does not
 * START. A non-NULL output on error owns partial resources and must
 * be retained until close succeeds. D2 uses existing XDEV_EXT_CUDA_PTX config. */
int xdev_ext_cuda_peer_owner_open(const struct xdev_ext_cuda_peer_owner_opts *,
 struct xdev_ext_cuda_peer_owner **);
int xdev_ext_cuda_peer_owner_get_view(struct xdev_ext_cuda_peer_owner *,
 struct xdev_ext_cuda_peer_owner_view *);
int xdev_ext_cuda_peer_owner_start(struct xdev_ext_cuda_peer_owner *);
/* Caller first drains/destroys every borrower (TP comm/work, graph and exec).
 * close records and synchronizes an actual last-use event on the bound stream,
 * then requires native stop/close success. Any unknown usage returns an error
 * with the owner and remaining resources retained. Borrowed context/stream are
 * never destroyed. Success alone sets *owner=NULL. No implicit destructor. */
int xdev_ext_cuda_peer_owner_close(struct xdev_ext_cuda_peer_owner **);
#ifdef __cplusplus
}
#endif
#endif
