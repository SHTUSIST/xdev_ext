/* SPDX-License-Identifier: GPL-2.0 */
/* Independent accepted v1 wire contract. No invented kernel entry point. */
#ifndef ADMISSION_REPORT_WIRE_H
#define ADMISSION_REPORT_WIRE_H
#define R3_OP_CREATE_REPORT 10U
#define R3_REPORT_VERSION 1U
struct r3_requester_id { __u32 domain,bus,devfn,rsvd; };
struct r3_retention_diag {
 __u32 generations,retained_generations;
 __aligned_u64 reserved_bytes,retained_bytes,global_reserved_bytes,global_retained_bytes,global_limit;
};
struct r3_stage_diag {
 __u32 size,version; __aligned_u64 session_id; __u32 stage,class_id,valid,readiness;
 __aligned_u64 token,local_inc,remote_inc,pool_generation,capture_begin_ns,capture_end_ns;
 __u32 native_inflight,software_pending,rx_native_posted,ctl_tx_free;
 __u32 cts_owed,ack_owed,fail_owed,final_waiting_chain,downstream_release_pending,rsvd;
 struct r3_retention_diag retention;
};
struct r3_create_report {
 __u32 size,version; __s32 result,rollback_errno;
 __u32 phase,failed_stage,valid,cleanup; __aligned_u64 session_id;
 struct r3_requester_id requester; struct xdev_ext_mech_stage_caps caps;
 struct r3_stage_diag observed;
};
struct r3_create_with_report {
 __u32 size,version; struct xdev_ext_mech_create create;
 struct r3_create_report report;
};
#endif
