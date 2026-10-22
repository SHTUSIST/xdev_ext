/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_REFERENCE_POLICY_ABI_H
#define XDEV_EXT_REFERENCE_POLICY_ABI_H

#include "../include/uapi/linux/xdev_ext_binding.h"

/*
 * Read-only userspace evidence exported through the BPF object's .bss map.
 * Every counter is monotonic for one loader lifetime.  last_result is only a
 * diagnostic snapshot; result_ok/result_errors are the race-safe accounting.
 */
struct xdev_ext_reference_policy_backend_stats {
	__u64 dispatch_callbacks;
	__u64 dispatch_kfunc_ok;
	__u64 dispatch_kfunc_errors;
	__u64 complete_callbacks;
	__u64 complete_kfunc_ok;
	__u64 complete_kfunc_errors;
	__u64 result_ok;
	__u64 result_errors;
	__u64 bytes_done;
	__s64 last_result;
};

/*
 * backend[] is indexed by ctx->backend and stage[] by ctx->current_stage.
 * Every callback updates one row of each, so a backend row is the sum of the
 * stage rows that backend owns (AF_XDP: AFXDP_TX + AFXDP_RX).
 */
struct xdev_ext_reference_policy_stats {
	struct xdev_ext_reference_policy_backend_stats
		backend[XDEV_EXT_BINDING_BACKEND_MAX];
	struct xdev_ext_reference_policy_backend_stats
		stage[XDEV_EXT_BINDING_STAGE_MAX];
};

#endif /* XDEV_EXT_REFERENCE_POLICY_ABI_H */
