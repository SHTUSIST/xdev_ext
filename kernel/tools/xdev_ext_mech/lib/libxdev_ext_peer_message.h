/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBXDEV_EXT_PEER_MESSAGE_H
#define LIBXDEV_EXT_PEER_MESSAGE_H
#include "libxdev_ext.h"
#ifdef __cplusplus
extern "C" {
#endif
struct xdev_ext_peer_endpoint;
enum xdev_ext_peer_role {
	XDEV_EXT_PEER_PRODUCER = 1,
	XDEV_EXT_PEER_RX_CONSUMER = 2,
	XDEV_EXT_PEER_TX_TERMINAL = 3,
};
struct xdev_ext_peer_message {
	struct xdev_ext_user_batch batch;
	enum xdev_ext_peer_role role;
	__u64 origin; /* accidental cross-endpoint misuse cookie, not authority */
};
struct xdev_ext_peer_endpoint_opts {
	size_t sz;
	int allocation_fd, control_fd;
	__u64 link_token;
	__u32 direction, depth, group_bytes, deadline_ms;
	struct xdev_ext_mech_layout layout;
	__u32 flags;
};
#define XDEV_EXT_PEER_ENDPOINT_F_EXTERNAL_CTL 1U
/* open prepares the USER objects. Attach GPU control before create/bind. */
int xdev_ext_peer_endpoint_open(const struct xdev_ext_peer_endpoint_opts *,
	struct xdev_ext_peer_endpoint **);
int xdev_ext_peer_endpoint_create(struct xdev_ext_peer_endpoint *);
int xdev_ext_peer_endpoint_start(struct xdev_ext_peer_endpoint *,
	const struct xdev_ext_start_frames_opts *);
int xdev_ext_peer_endpoint_next(struct xdev_ext_peer_endpoint *, int timeout_ms,
	struct xdev_ext_peer_message *);
/* status0 is an owner assertion of completed producer/consumer work, never
 * inferred by the library from reaching a callback or from a CPU flag. */
int xdev_ext_peer_endpoint_complete(struct xdev_ext_peer_endpoint *,
	const struct xdev_ext_peer_message *, int status);
int xdev_ext_peer_endpoint_stop(struct xdev_ext_peer_endpoint *);
int xdev_ext_peer_endpoint_close(struct xdev_ext_peer_endpoint *);
struct xdev_ext_session *xdev_ext_peer_endpoint_session(struct xdev_ext_peer_endpoint *);
struct xdev_ext_user_stage *xdev_ext_peer_endpoint_user(struct xdev_ext_peer_endpoint *,
	enum xdev_ext_peer_role);
#ifdef __cplusplus
}
#endif
#endif
