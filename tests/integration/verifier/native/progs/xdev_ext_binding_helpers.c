// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include "xdev_ext_binding_common.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __s32);
} binding_values SEC(".maps");

static __always_inline int lookup_value(void)
{
	__u32 key = 0;
	__s32 *value = bpf_map_lookup_elem(&binding_values, &key);

	return value ? *value : 0;
}

static long bounded_step(__u32 index, void *opaque)
{
	(void)index;
	(void)opaque;
	return 0;
}

static __always_inline int read_kernel(void)
{
	long value = 0;

	return bpf_probe_read_kernel(&value, sizeof(value), (void *)0);
}

static __always_inline int trace_message(void)
{
	char format[] = "binding helper probe\n";

	return bpf_trace_printk(format, sizeof(format));
}

/* Each phase is checked independently by test_loader, without attachment. */
#define BINDING_PROBE(name, phase, verdict, expression) \
	SEC("struct_ops/" #phase) \
	verdict \
	__s32 BPF_PROG(name, const struct xdev_ext_binding_ctx_v2 *binding_ctx) \
	{ \
		(void)binding_ctx; \
		return (expression); \
	} \
	SEC(".struct_ops.link") \
	struct xdev_ext_binding_ops name##_policy = { \
		.abi_version = XDEV_EXT_BINDING_ABI_VERSION, \
		.backend = XDEV_EXT_BINDING_BACKEND_SOCKET, \
		.phase = (void *)name, \
	}

/* Policy maps plus bpf_loop used by the existing concurrent-release test. */
BINDING_PROBE(lookup_dispatch, dispatch, __success, lookup_value());
BINDING_PROBE(lookup_complete, complete, __success, lookup_value());
BINDING_PROBE(loop_dispatch, dispatch, __success,
	      bpf_loop(1, bounded_step, NULL, 0));
BINDING_PROBE(loop_complete, complete, __success,
	      bpf_loop(1, bounded_step, NULL, 0));

#define DENY_KERNEL_READ \
	__failure __msg("program of this type cannot use helper bpf_probe_read_kernel#113")
#define DENY_CURRENT_TASK \
	__failure __msg("program of this type cannot use helper bpf_get_current_task#35")
#define DENY_TRACE \
	__failure __msg("program of this type cannot use helper bpf_trace_printk#6")
#define DENY_TIME \
	__failure __msg("program of this type cannot use helper bpf_ktime_get_ns#5")

BINDING_PROBE(read_dispatch, dispatch, DENY_KERNEL_READ, read_kernel());
BINDING_PROBE(read_complete, complete, DENY_KERNEL_READ, read_kernel());
BINDING_PROBE(task_dispatch, dispatch, DENY_CURRENT_TASK, bpf_get_current_task());
BINDING_PROBE(task_complete, complete, DENY_CURRENT_TASK, bpf_get_current_task());
BINDING_PROBE(trace_dispatch, dispatch, DENY_TRACE, trace_message());
BINDING_PROBE(trace_complete, complete, DENY_TRACE, trace_message());
BINDING_PROBE(time_dispatch, dispatch, DENY_TIME, bpf_ktime_get_ns());
BINDING_PROBE(time_complete, complete, DENY_TIME, bpf_ktime_get_ns());

char _license[] SEC("license") = "GPL";
