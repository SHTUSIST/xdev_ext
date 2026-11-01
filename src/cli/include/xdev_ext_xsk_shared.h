/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_XSK_SHARED_H
#define XDEV_EXT_XSK_SHARED_H
#include "xdev_ext_xsk_redirect.h"
#define XDEV_EXT_XSK_SHARED_ABI 1U
#define XDEV_EXT_XSK_SHARED_MAX_INSNS 256U
struct xdev_ext_xsk_shared;
struct xdev_ext_xsk_shared_opts {
	size_t sz;
	const char *ifname;
	uint32_t queue_id, xdp_flags;
	int xsk_fd;
	struct xdev_ext_xsk_flow_filter filter;
	uint32_t flags;
};
struct xdev_ext_xsk_shared_error {
	int error;
	char operation[32];
	char reason[160];
};
struct xdev_ext_xsk_shared_key {
	uint32_t dst_ipv4, payload_magic;
	uint16_t dst_port, reserved;
};
struct xdev_ext_xsk_shared_flow {
	uint32_t queue_id, flags, src_ipv4;
	uint16_t src_port, max_len;
	uint8_t dst_mac[6];
	uint16_t reserved;
};
#ifdef __cplusplus
extern "C" {
#endif
int xdev_ext_xsk_shared_open(const struct xdev_ext_xsk_shared_opts *opts,
			     struct xdev_ext_xsk_shared **out,
			     struct xdev_ext_xsk_shared_error *error);
/* Read-only admission; call before mutating an owning session or its rings. */
int xdev_ext_xsk_shared_preflight(const struct xdev_ext_xsk_shared *shared,
				  struct xdev_ext_xsk_shared_error *error);
int xdev_ext_xsk_shared_close(struct xdev_ext_xsk_shared *shared,
			      struct xdev_ext_xsk_shared_error *error);
int xdev_ext_xsk_shared_build_program(int xsk_map_fd, int flow_map_fd,
				      struct bpf_insn *program, size_t capacity,
				      size_t *count);
#ifdef __cplusplus
}
#endif
#endif
