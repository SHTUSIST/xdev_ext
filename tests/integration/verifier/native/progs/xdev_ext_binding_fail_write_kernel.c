// SPDX-License-Identifier: GPL-2.0

#include "xdev_ext_binding_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

struct task_struct___local {
	int pid;
} __attribute__((preserve_access_index));

SEC("struct_ops/dispatch")
__failure __msg("XDEV_EXT callback kernel BTF objects are read-only at off")
__s32 BPF_PROG(dispatch_write_kernel_btf,
	       const struct xdev_ext_binding_ctx_v2 *binding_ctx)
{
	struct task_struct___local *task =
		(void *)bpf_get_current_task_btf();

	task->pid = 0;
	return bpf_xdev_ext_dispatch_action(binding_ctx, XDEV_EXT_BINDING_ACTION_FALLBACK,
				       0, 0, 0);
}

SEC(".struct_ops.link")
struct xdev_ext_binding_ops kernel_write_policy = {
	.abi_version = XDEV_EXT_BINDING_ABI_VERSION,
	.backend = XDEV_EXT_BINDING_BACKEND_SOCKET,
	.dispatch = (void *)dispatch_write_kernel_btf,
};

char _license[] SEC("license") = "GPL";
