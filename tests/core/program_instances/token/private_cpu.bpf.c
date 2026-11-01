// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/xdev_ext_mech.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#ifndef INSTANCE
#define INSTANCE 1
#endif
/* Same BTF view as the existing native verifier common header. */
struct xdev_ext_cpu_mech_ops {
 __u32 abi_version, flags;
 __s32 (*prepare)(const struct xdev_ext_mech_ctx *);
 __s32 (*build)(const struct xdev_ext_mech_ctx *);
 __s32 (*complete)(const struct xdev_ext_mech_ctx *);
 __s32 (*compute)(const struct xdev_ext_mech_ctx *);
} __attribute__((preserve_access_index));
struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __uint(max_entries, 1);
 __type(key, __u32);
 __type(value, __u64);
} selected SEC(".maps");
SEC("struct_ops.s/token_prepare")
__s32 BPF_PROG(token_prepare, const struct xdev_ext_mech_ctx *mctx)
{

#ifndef BAD_HELPER
 __u32 key=0;
 __u64 *value=bpf_map_lookup_elem(&selected,&key);
#endif
 (void)ctx; (void)mctx;
#ifdef BAD_HELPER
 __u64 data=0;
 return bpf_probe_read_kernel(&data,sizeof(data),(const void *)0);
#else
 if (!value) return -22;
 *value += INSTANCE;
 return 0;
#endif
}
SEC("struct_ops/token_build")
__s32 BPF_PROG(token_build, const struct xdev_ext_mech_ctx *mctx)
{ (void)ctx; (void)mctx; return 0; }
SEC("struct_ops/token_complete")
__s32 BPF_PROG(token_complete, const struct xdev_ext_mech_ctx *mctx)
{ (void)ctx; (void)mctx; return XDEV_EXT_MECH_NEXT; }
SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops private_cpu_ops={
 .abi_version=XDEV_EXT_MECH_ABI_VERSION, .flags=XDEV_EXT_MECH_OPS_F_PRIVATE,
 .prepare=(void *)token_prepare, .build=(void *)token_build, .complete=(void *)token_complete,
};
char LICENSE[] SEC("license")="GPL";
