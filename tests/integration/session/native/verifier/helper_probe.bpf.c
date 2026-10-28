// SPDX-License-Identifier: GPL-2.0
/* TODO.27-a: compile one full NVMe struct_ops object for each HELPER_ID. */
#include <linux/bpf.h>
#include "xdev_ext_mech_common.h"
#include <bpf/bpf_tracing.h>

#ifndef HELPER_ID
#error "HELPER_ID must name the actual UAPI helper ID under test"
#endif

struct helper_value {
	struct bpf_timer timer;
	__u64 data;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct helper_value);
} helper_values SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} helper_jumps SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} helper_events SEC(".maps");

SEC("struct_ops/build")
__s32 BPF_PROG(helper_build, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
	return XDEV_EXT_MECH_BUILD_ABORT;
}

SEC("struct_ops/complete")
__s32 BPF_PROG(helper_complete, const struct xdev_ext_mech_ctx *mctx)
{
	(void)ctx;
	(void)mctx;
#if HELPER_ID == 1
	__u32 key = 0;
	struct helper_value *value = bpf_map_lookup_elem(&helper_values, &key);
	return value ? (__s32)value->data : 0;
#elif HELPER_ID == 5
	return (__s32)bpf_ktime_get_ns();
#elif HELPER_ID == 113
	__u64 data = 0;
	return bpf_probe_read_kernel(&data, sizeof(data), (const void *)0);
#elif HELPER_ID == 115
	char data[8] = {};
	return bpf_probe_read_kernel_str(data, sizeof(data), (const void *)0);
#elif HELPER_ID == 112
	__u64 data = 0;
	return bpf_probe_read_user(&data, sizeof(data), (const void *)0);
#elif HELPER_ID == 114
	char data[8] = {};
	return bpf_probe_read_user_str(data, sizeof(data), (const void *)0);
#elif HELPER_ID == 35
	return (__s32)bpf_get_current_task();
#elif HELPER_ID == 158
	return bpf_get_current_task_btf() != 0;
#elif HELPER_ID == 6
	char format[] = "helper probe\n";
	return bpf_trace_printk(format, sizeof(format));
#elif HELPER_ID == 177
	char format[] = "helper probe %llu\n";
	__u64 data = 0;
	return bpf_trace_vprintk(format, sizeof(format), &data, sizeof(data));
#elif HELPER_ID == 169
	__u32 key = 0;
	struct helper_value *value = bpf_map_lookup_elem(&helper_values, &key);
	if (!value)
		return 0;
	return bpf_timer_init(&value->timer, &helper_values, 1);
#elif HELPER_ID == 12
	bpf_tail_call((void *)mctx, &helper_jumps, 0);
	return 0;
#elif HELPER_ID == 130
	__u64 data = 0;
	return bpf_ringbuf_output(&helper_events, &data, sizeof(data), 0);
#elif HELPER_ID == 2
	__u32 key = 0;
	struct helper_value value = {};
	return bpf_map_update_elem(&helper_values, &key, &value, BPF_ANY);
#else
#error "Unknown HELPER_ID: never silently compile a no-op probe"
#endif
}

SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops helper_probe_ops = {
	.abi_version = XDEV_EXT_MECH_ABI_VERSION,
	.build = (void *)helper_build,
	.complete = (void *)helper_complete,
};
char _license[] SEC("license") = "GPL";
