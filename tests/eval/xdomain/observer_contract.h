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
#define TB_XD_OBSERVER_ERROR_MAP "xd_check_err"
#define TB_XD_OBS_ERR_CONFIG (1U << 0)
#define TB_XD_OBS_ERR_KEY (1U << 1)
#define TB_XD_OBS_ERR_IDENTITY (1U << 2)
#define TB_XD_OBS_ERR_PLAN (1U << 3)
#define TB_XD_OBS_ERR_BUILD_AFTER_CQE (1U << 4)
#define TB_XD_OBS_ERR_DUP_CQE (1U << 5)
#define TB_XD_OBS_ERR_MISSING_BUILD (1U << 6)
#define TB_XD_OBS_ERR_OVERFLOW (1U << 7)
struct tb_xd_observer_errors { __u64 error_bits, observations_lost; };
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
