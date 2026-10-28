// SPDX-License-Identifier: GPL-2.0
/* One device-neutral DMA pair plus one CE pair, using original view kfuncs. */
#include "include/uapi/linux/xdev_ext_mech.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#define OPS_TYPE(name) struct name { \
 __u32 abi_version,flags; \
 __s32 (*prepare)(const struct xdev_ext_mech_ctx *); \
 __s32 (*build)(const struct xdev_ext_mech_ctx *); \
 __s32 (*complete)(const struct xdev_ext_mech_ctx *); \
} __attribute__((preserve_access_index))
OPS_TYPE(xdev_ext_dma_mech_ops);
OPS_TYPE(xdev_ext_ce_mech_ops);
extern __u8 *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *,const __u64 size) __ksym;
extern __u8 *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *,__u32,const __u64 size) __ksym;
extern __u8 *bpf_xdev_ext_cqe(const struct xdev_ext_mech_ctx *,__u32,const __u64 size) __ksym;
struct observation { __u64 dma_build,dma_complete,ce_build,ce_complete,wrong_base,slot_mask; };
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1);
 __type(key,__u32); __type(value,struct observation); } observations SEC(".maps");
static __always_inline struct observation *observe(void)
{ __u32 key=0; return bpf_map_lookup_elem(&observations,&key); }
SEC("struct_ops/dma_build")
__s32 BPF_PROG(dma_build,const struct xdev_ext_mech_ctx *m)
{
 const struct xdev_ext_dma_mech_info *info;
 struct observation *o=observe();
 __u64 device_off;
 __u32 i,nr;
 (void)ctx;
 if (o) __sync_fetch_and_add(&o->dma_build,1);
 if (m->class_id!=XDEV_EXT_MECH_CLASS_DMA || m->base.backend!=XDEV_EXT_BINDING_BACKEND_UNSPEC) {
  if (o) __sync_fetch_and_add(&o->wrong_base,1);
  return XDEV_EXT_MECH_BUILD_ABORT;
 }
 info=(void *)bpf_xdev_ext_info(m,sizeof(*info));
 if (!info) return XDEV_EXT_MECH_BUILD_ABORT;
 nr=info->nr_frames;
 /* START sequence addresses a distinct campaign group; CE retains its slots. */
 if (!nr || nr>XDEV_EXT_MECH_MAX_FRAMES || info->l.group_bytes>4096 ||
     info->l.group_bytes>info->window_len ||
     m->base.src_offset>(info->window_len-info->l.group_bytes)/4096)
  return XDEV_EXT_MECH_BUILD_ABORT;
 device_off=m->base.src_offset*4096;
 for (i=0;i<XDEV_EXT_MECH_MAX_FRAMES;i++) {
  struct xdev_ext_dma_copy_desc *d;
  const struct xdev_ext_mech_frame_info *f;
  if (i>=nr) break;
  f=&info->f[i];
  if (!f->data_len || f->data_len>info->max_entry_len ||
      device_off>info->window_len || f->data_len>info->window_len-device_off)
   return XDEV_EXT_MECH_BUILD_ABORT;
  d=(void *)bpf_xdev_ext_desc(m,i,sizeof(*d));
  if (!d) return XDEV_EXT_MECH_BUILD_ABORT;
  d->frame_pos=i; d->frame_off=f->data_off; d->device_off=device_off;
  d->len=f->data_len; d->flags=i+1==nr ? XDEV_EXT_DMA_F_COMPLETION_POINT : 0;
  device_off+=f->data_len;
 }
 return XDEV_EXT_MECH_BUILD_SUBMIT;
}
SEC("struct_ops/dma_complete")
__s32 BPF_PROG(dma_complete,const struct xdev_ext_mech_ctx *m)
{
 const struct xdev_ext_dma_mech_cqe *c;
 struct observation *o=observe();
 (void)ctx;
 if (o) __sync_fetch_and_add(&o->dma_complete,1);
 c=(void *)bpf_xdev_ext_cqe(m,0,sizeof(*c));
 if (!c || c->outcome!=XDEV_EXT_DMA_OK || c->bytes_done!=m->base.length)
  return XDEV_EXT_MECH_ABORT;
 return XDEV_EXT_MECH_NEXT;
}
SEC("struct_ops/ce_build")
__s32 BPF_PROG(ce_build,const struct xdev_ext_mech_ctx *m)
{
 const struct xdev_ext_ce_mech_info *info;
 struct observation *o=observe();
 __u64 off;
 __u32 i,nr;
 (void)ctx;
 if (o) __sync_fetch_and_add(&o->ce_build,1);
 info=(void *)bpf_xdev_ext_info(m,sizeof(*info));
 if (!info) return XDEV_EXT_MECH_BUILD_ABORT;
 nr=info->nr_frames;
 if (!nr || nr>XDEV_EXT_MECH_MAX_FRAMES || !info->lease_generation ||
     info->window_slot>=info->window_depth) return XDEV_EXT_MECH_BUILD_ABORT;
 if (info->window_slot>=8) return XDEV_EXT_MECH_BUILD_ABORT;
 if (o) __sync_fetch_and_or(&o->slot_mask,1ULL<<info->window_slot);
 off=(__u64)info->window_slot*info->l.group_bytes;
 for (i=0;i<XDEV_EXT_MECH_MAX_FRAMES;i++) {
  struct xdev_ext_ce_copy_desc *d;
  const struct xdev_ext_mech_frame_info *f;
  if (i>=nr) break;
  f=&info->f[i];
  d=(void *)bpf_xdev_ext_desc(m,i,sizeof(*d));
  if (!d) return XDEV_EXT_MECH_BUILD_ABORT;
  d->frame_pos=i; d->frame_off=f->data_off; d->gpu_off=off;
  d->len=f->data_len; d->flags=i+1==nr ? XDEV_EXT_CE_F_COMPLETION_POINT : 0;
  off+=f->data_len;
 }
 return XDEV_EXT_MECH_BUILD_SUBMIT;
}
SEC("struct_ops/ce_complete")
__s32 BPF_PROG(ce_complete,const struct xdev_ext_mech_ctx *m)
{
 const struct xdev_ext_ce_mech_cqe *c;
 struct observation *o=observe();
 (void)ctx;
 if (o) __sync_fetch_and_add(&o->ce_complete,1);
 c=(void *)bpf_xdev_ext_cqe(m,0,sizeof(*c));
 return c && c->outcome==XDEV_EXT_CE_OK ? XDEV_EXT_MECH_NEXT : XDEV_EXT_MECH_ABORT;
}
SEC(".struct_ops.link") struct xdev_ext_dma_mech_ops dma_pair={
 .abi_version=XDEV_EXT_MECH_ABI_VERSION,.build=(void *)dma_build,.complete=(void *)dma_complete,
};
SEC(".struct_ops.link") struct xdev_ext_ce_mech_ops ce_pair={
 .abi_version=XDEV_EXT_CE_MECH_ABI_VERSION,.build=(void *)ce_build,.complete=(void *)ce_complete,
};
char LICENSE[] SEC("license")="GPL";
