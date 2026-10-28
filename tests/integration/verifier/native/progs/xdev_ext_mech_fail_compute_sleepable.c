// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* compute runs on the session worker inside ->submit and never sleeps. */
SEC("struct_ops.s/compute")
__failure __msg("attach to unsupported member compute of struct xdev_ext_cpu_mech_ops")
__s32 BPF_PROG(sleepable_compute, const struct xdev_ext_mech_ctx *mctx)
{
	return 0;
}

SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops compute_sleepable_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.compute = (void *)sleepable_compute,
};

char _license[] SEC("license") = "GPL";
