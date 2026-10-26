/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_XDOMAIN_OBSERVER_CONTRACT_H
#define XDEV_EXT_XDOMAIN_OBSERVER_CONTRACT_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#define TB_XD_OBSERVER_VERSION 1U
#define TB_XD_OBSERVER_MAX_GROUPS 10000U
#define TB_XD_OBSERVER_MAX_SPANS 64U
#define TB_XD_OBSERVER_CONFIG_MAP "xd_check_cfg"
#define TB_XD_OBSERVER_RECORD_MAP "xd_check_rec"
#define TB_XD_OBSERVER_OPS_MAP "xdomain_peer_ops"
struct tb_xd_observer_config {
 __u32 size, version;
 __u64 session_id, first_seq, groups, epoch, allocation_bytes;
 __u32 direction, stage;
};
struct tb_xd_observer_span { __u64 allocation_off, data_off, len; };
/* Exact pointer-free public CQE layout; D independently pins every offset. */
struct tb_xd_observer_cqe {
 __s32 status;
 __u32 outcome, remote, elems_done;
 __u64 group, bytes;
 __u32 crc_errors, rsvd;
 __u8 tag[24];
};
struct tb_xd_observer_record {
 __u32 size, version;
 __u64 session_id, batch_id, key, epoch, generation, local_inc, remote_inc;
 __u32 direction, channel, build_attempts, cqe_seen, error_bits, nr_spans;
 __u8 tag[24];
 struct tb_xd_observer_span spans[TB_XD_OBSERVER_MAX_SPANS];
 struct tb_xd_observer_cqe completion;
};
#endif
