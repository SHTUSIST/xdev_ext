/* SPDX-License-Identifier: GPL-2.0 */
/* Independently transcribed frozen v1 interfaces, not candidate headers. */
#ifndef SHARED_RECEIVE_CONTRACT_API_H
#define SHARED_RECEIVE_CONTRACT_API_H
#include <stddef.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include "include/xdev_ext_xsk_redirect.h"
#define XDEV_EXT_XSK_SHARED_MAX_INSNS 256U
struct xdev_ext_xsk_shared;
struct xdev_ext_xsk_shared_opts {
 size_t sz; const char *ifname; uint32_t queue_id; uint32_t xdp_flags;
 int xsk_fd; struct xdev_ext_xsk_flow_filter filter; uint32_t flags;
};
struct xdev_ext_xsk_shared_error { int error; char operation[32]; char reason[160]; };
struct xdev_ext_xsk_shared_key {
 uint32_t dst_ipv4,payload_magic; uint16_t dst_port,reserved;
};
struct xdev_ext_xsk_shared_flow {
 uint32_t queue_id,flags,src_ipv4; uint16_t src_port,max_len;
 uint8_t dst_mac[6]; uint16_t reserved;
};
int xdev_ext_xsk_shared_open(const struct xdev_ext_xsk_shared_opts *,struct xdev_ext_xsk_shared **,struct xdev_ext_xsk_shared_error *);
int xdev_ext_xsk_shared_close(struct xdev_ext_xsk_shared *,struct xdev_ext_xsk_shared_error *);
int xdev_ext_xsk_shared_build_program(int,int,struct bpf_insn *,size_t,size_t *);
#endif
