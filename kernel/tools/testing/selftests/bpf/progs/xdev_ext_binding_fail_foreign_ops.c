// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

struct xdev_ext_binding_ctx_v2;

extern int bpf_xdev_ext_dispatch_action(const struct xdev_ext_binding_ctx_v2 *ctx,
				   __u32 action, __u32 recipe,
				   __u32 next_stage, __u32 profile) __ksym;

SEC("struct_ops/test_1")
__failure __msg("calling kernel function bpf_xdev_ext_dispatch_action is not allowed")
int BPF_PROG(foreign_ops_calls_xdev_ext, struct bpf_dummy_ops_state *state)
{
	return bpf_xdev_ext_dispatch_action((const void *)state, 0, 0, 0, 0);
}

SEC(".struct_ops")
struct bpf_dummy_ops foreign_ops = {
	.test_1 = (void *)foreign_ops_calls_xdev_ext,
};

char _license[] SEC("license") = "GPL";
