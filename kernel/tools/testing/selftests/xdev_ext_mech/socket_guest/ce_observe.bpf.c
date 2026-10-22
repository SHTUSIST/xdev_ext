// SPDX-License-Identifier: GPL-2.0
/* Independent CE observation for the four-stage socket guest campaign. */
#include "include/uapi/linux/xdev_ext_mech.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "observations.h"
struct xdev_ext_ce_mech_ops {
 __u32 abi_version, flags;
 __s32 (*prepare)(const struct xdev_ext_mech_ctx *);
 __s32 (*build)(const struct xdev_ext_mech_ctx *);
 __s32 (*complete)(const struct xdev_ext_mech_ctx *);
} __attribute__((preserve_access_index));
extern __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *,const __u64) __ksym;
extern __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *,__u32,const __u64) __ksym;
extern __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *,__u32,const __u64) __ksym;
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);
 __type(value,struct socket_guest_observations);} socket_observations SEC(".maps");
SEC("struct_ops/socket_guest_ce_build")
__s32 BPF_PROG(socket_guest_ce_build,const struct xdev_ext_mech_ctx *m)
{
 __u32 key=0;
 struct socket_guest_observations *o=bpf_map_lookup_elem(&socket_observations,&key);
 const struct xdev_ext_ce_mech_info *info=(void *)bpf_xdev_ext_info(m,sizeof(*info));
 __u64 off;
 __u32 slot;
 (void)ctx;
 if(!o)return XDEV_EXT_MECH_BUILD_ABORT;
 __sync_fetch_and_add(&o->build,1);
 if(!info) return XDEV_EXT_MECH_BUILD_ABORT;
 slot=info->window_slot;
 if(!info->lease_generation || info->window_depth!=8 || slot>=8 ||
    info->nr_frames!=4 || info->l.group_bytes!=8192 || info->gpu_window_len<8*8192 ||
    m->base.src_offset>=257) {
  __sync_fetch_and_add(&o->invalid,1);return XDEV_EXT_MECH_BUILD_ABORT;
 }
 __sync_fetch_and_or(&o->slot_mask,1ULL<<slot);
 o->last_group[slot]=m->base.src_offset;
 off=(__u64)slot*8192;
 for(__u32 i=0;i<4;i++) {
  struct xdev_ext_ce_copy_desc *d=(void *)bpf_xdev_ext_desc(m,i,sizeof(*d));
  if(!d || info->f[i].data_off!=256 || info->f[i].data_len!=2048)return XDEV_EXT_MECH_BUILD_ABORT;
  d->frame_pos=i;d->frame_off=info->f[i].data_off;d->gpu_off=off;
  d->len=info->f[i].data_len;d->flags=i==3?XDEV_EXT_CE_F_COMPLETION_POINT:0;
  off+=info->f[i].data_len;
 }
 return XDEV_EXT_MECH_BUILD_SUBMIT;
}
SEC("struct_ops/socket_guest_ce_complete")
__s32 BPF_PROG(socket_guest_ce_complete,const struct xdev_ext_mech_ctx *m)
{
 __u32 key=0;
 struct socket_guest_observations *o=bpf_map_lookup_elem(&socket_observations,&key);
 const struct xdev_ext_ce_mech_cqe *c=(void *)bpf_xdev_ext_cqe(m,0,sizeof(*c));
 (void)ctx;
 if(o)__sync_fetch_and_add(&o->complete,1);
 return c && c->outcome==XDEV_EXT_CE_OK ? XDEV_EXT_MECH_NEXT:XDEV_EXT_MECH_ABORT;
}
SEC(".struct_ops.link") struct xdev_ext_ce_mech_ops socket_guest_ce_ops={
 .abi_version=XDEV_EXT_CE_MECH_ABI_VERSION,.build=(void *)socket_guest_ce_build,
 .complete=(void *)socket_guest_ce_complete,
};
char LICENSE[] SEC("license")="GPL";
