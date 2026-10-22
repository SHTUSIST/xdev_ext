/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TOOLS_XDEV_EXT_XSK_REDIRECT_H
#define __TOOLS_XDEV_EXT_XSK_REDIRECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/bpf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XDEV_EXT_XSK_REDIRECT_MAX_QUEUES 4096U
#define XDEV_EXT_XSK_REDIRECT_MAX_INSNS 64U

#define XDEV_EXT_XSK_FILTER_F_SRC_IPV4      (1U << 0)
#define XDEV_EXT_XSK_FILTER_F_DST_IPV4      (1U << 1)
#define XDEV_EXT_XSK_FILTER_F_SRC_PORT      (1U << 2)
#define XDEV_EXT_XSK_FILTER_F_DST_PORT      (1U << 3)
#define XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC (1U << 4)
/* The payload-magic flow every existing pipeline requests.  It deliberately
 * excludes the flags below so those programs stay instruction-for-instruction
 * what they were. */
#define XDEV_EXT_XSK_FILTER_F_ALL           ((1U << 5) - 1)
#define XDEV_EXT_XSK_FILTER_F_DST_MAC       (1U << 5)
#define XDEV_EXT_XSK_FILTER_F_MAX_LEN       (1U << 6)
#define XDEV_EXT_XSK_FILTER_F_KNOWN         (XDEV_EXT_XSK_FILTER_F_ALL | \
					XDEV_EXT_XSK_FILTER_F_DST_MAC | \
					XDEV_EXT_XSK_FILTER_F_MAX_LEN)

/* Values are host byte order.  Every admitted packet is untagged Ethernet,
 * fixed-header IPv4, unfragmented UDP, and has mutually consistent bounded
 * IPv4 and UDP lengths.  With XDEV_EXT_XSK_FILTER_F_PAYLOAD_MAGIC it must also
 * carry payload_magic; without it the filter is the tuple alone and must name
 * the destination address and port.  Tuple fields selected by flags are
 * exact matched, dst_mac is the receiving interface's address, and max_len
 * is the longest frame (Ethernet header included) one XSK frame can hold. */
struct xdev_ext_xsk_flow_filter {
	uint32_t flags;
	uint32_t src_ipv4;
	uint32_t dst_ipv4;
	uint32_t payload_magic;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t dst_mac[6];
	uint16_t max_len;
};

struct xdev_ext_xsk_redirect {
	int map_fd;
	int prog_fd;
	int ifindex;
	uint32_t queue_id;
	uint32_t xdp_flags;
	uint32_t prog_id;
	bool attached;
	bool mapped;
};

#define XDEV_EXT_XSK_REDIRECT_INIT { .map_fd = -1, .prog_fd = -1 }

/* Injectable control-plane operations keep the ownership/error paths testable
 * without CAP_BPF or a network device.  Production callers use the wrappers
 * without the _with suffix. */
struct xdev_ext_xsk_redirect_ops {
	int (*map_create)(uint32_t max_entries);
	int (*prog_load)(int map_fd, const struct xdev_ext_xsk_flow_filter *filter);
	int (*prog_id)(int prog_fd, uint32_t *prog_id);
	int (*attach)(int ifindex, int prog_fd, uint32_t xdp_flags);
	int (*query_id)(int ifindex, uint32_t xdp_flags, uint32_t *prog_id);
	int (*map_update)(int map_fd, uint32_t queue_id, int xsk_fd);
	int (*map_delete)(int map_fd, uint32_t queue_id);
	int (*detach)(int ifindex, int expected_prog_fd, uint32_t xdp_flags);
	int (*close_fd)(int fd);
};

void xdev_ext_xsk_redirect_init(struct xdev_ext_xsk_redirect *redirect);

bool xdev_ext_xsk_redirect_is_active(const struct xdev_ext_xsk_redirect *redirect);

int xdev_ext_xsk_redirect_attach_with(struct xdev_ext_xsk_redirect *redirect,
				 const struct xdev_ext_xsk_redirect_ops *ops,
				 const struct xdev_ext_xsk_flow_filter *filter,
				 int ifindex, uint32_t queue_id, int xsk_fd,
				 uint32_t xdp_flags);

int xdev_ext_xsk_redirect_detach_with(struct xdev_ext_xsk_redirect *redirect,
				 const struct xdev_ext_xsk_redirect_ops *ops);

int xdev_ext_xsk_redirect_attach(struct xdev_ext_xsk_redirect *redirect,
			    const struct xdev_ext_xsk_flow_filter *filter, int ifindex,
			    uint32_t queue_id, int xsk_fd,
			    uint32_t xdp_flags);

int xdev_ext_xsk_redirect_build_program(int map_fd,
				   const struct xdev_ext_xsk_flow_filter *filter,
				   struct bpf_insn *program,
				   size_t program_capacity,
				   size_t *program_count);

int xdev_ext_xsk_redirect_detach(struct xdev_ext_xsk_redirect *redirect);

#ifdef __cplusplus
}
#endif

#endif /* __TOOLS_XDEV_EXT_XSK_REDIRECT_H */
