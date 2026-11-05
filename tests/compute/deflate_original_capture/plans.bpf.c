// SPDX-License-Identifier: GPL-2.0
/* Test-only plans; transforms execute unchanged production adapters. */
#include "linux/xdev_ext_mech.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define OPS(name) struct name { \
 __u32 abi_version, flags; \
 __s32 (*prepare)(const struct xdev_ext_mech_ctx *); \
 __s32 (*build)(const struct xdev_ext_mech_ctx *); \
 __s32 (*complete)(const struct xdev_ext_mech_ctx *); \
 __s32 (*compute)(const struct xdev_ext_mech_ctx *); \
} __attribute__((preserve_access_index))
OPS(xdev_ext_cpu_mech_ops);
OPS(xdev_ext_iaa_mech_ops);
OPS(xdev_ext_user_mech_ops);
extern __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *, const __u64 size) __ksym;
extern __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *, __u32, const __u64 size) __ksym;
extern __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *, __u32, const __u64 size) __ksym;
SEC("struct_ops/cpu_build")
__s32 BPF_PROG(cpu_build, const struct xdev_ext_mech_ctx *m)
{
 (void)ctx; (void)m;
 return XDEV_EXT_MECH_BUILD_DEFAULT;
}
SEC("struct_ops/cpu_complete")
__s32 BPF_PROG(cpu_complete, const struct xdev_ext_mech_ctx *m)
{
 (void)ctx; (void)m;
 return XDEV_EXT_MECH_NEXT;
}
SEC("struct_ops/user_build")
__s32 BPF_PROG(user_build, const struct xdev_ext_mech_ctx *m)
{
 (void)ctx; (void)m;
 return XDEV_EXT_MECH_BUILD_DEFAULT;
}
SEC("struct_ops/user_complete")
__s32 BPF_PROG(user_complete, const struct xdev_ext_mech_ctx *m)
{
 (void)ctx; (void)m;
 return XDEV_EXT_MECH_NEXT;
}
SEC("struct_ops/iaa_build")
__s32 BPF_PROG(iaa_build, const struct xdev_ext_mech_ctx *m)
{
 const struct xdev_ext_iaa_mech_info *info;
 struct xdev_ext_iaa_desc *d;
 (void)ctx;
 if (m->class_id != XDEV_EXT_MECH_CLASS_IAA || !m->base.length || m->base.length > 8192)
  return XDEV_EXT_MECH_BUILD_ABORT;
 info = (void *)bpf_xdev_ext_info(m, sizeof(*info));
 d = (void *)bpf_xdev_ext_desc(m, 0, sizeof(*d));
 if (!info || !d || !info->software || !info->nr_frames ||
     (info->dst_capacity != 8192 && info->dst_capacity != 4096))
  return XDEV_EXT_MECH_BUILD_ABORT;
 d->src_len = m->base.length;
 d->dst_capacity = info->dst_capacity;
 d->flags = 0; d->reserved = 0;
 return XDEV_EXT_MECH_BUILD_SUBMIT;
}
SEC("struct_ops/iaa_complete")
__s32 BPF_PROG(iaa_complete, const struct xdev_ext_mech_ctx *m)
{
 const struct xdev_ext_iaa_mech_cqe *c;
 (void)ctx;
 c = (void *)bpf_xdev_ext_cqe(m, 0, sizeof(*c));
 if (!c || c->status || !c->produced || c->produced > c->capacity || c->reserved)
  return XDEV_EXT_MECH_ABORT;
 return XDEV_EXT_MECH_NEXT;
}
SEC(".struct_ops.link") struct xdev_ext_cpu_mech_ops capture_cpu = {
 .abi_version = XDEV_EXT_MECH_CPU_ABI_VERSION,
 .build = (void *)cpu_build, .complete = (void *)cpu_complete,
};
SEC(".struct_ops.link") struct xdev_ext_iaa_mech_ops capture_iaa = {
 .abi_version = XDEV_EXT_MECH_ABI_VERSION,
 .build = (void *)iaa_build, .complete = (void *)iaa_complete,
};
SEC(".struct_ops.link") struct xdev_ext_user_mech_ops capture_user = {
 .abi_version = XDEV_EXT_MECH_ABI_VERSION,
 .build = (void *)user_build, .complete = (void *)user_complete,
};
char LICENSE[] SEC("license") = "GPL";
