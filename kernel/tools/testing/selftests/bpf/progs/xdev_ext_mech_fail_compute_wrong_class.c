// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* Every type carries the member; only the CPU type accepts a program. */
SEC("struct_ops/compute")
__failure __msg("attach to unsupported member compute of struct xdev_ext_nvme_mech_ops")
__s32 BPF_PROG(nvme_compute, const struct xdev_ext_mech_ctx *mctx)
{
	return 0;
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops compute_wrong_class_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.compute = (void *)nvme_compute,
};

char _license[] SEC("license") = "GPL";
