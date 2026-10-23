// SPDX-License-Identifier: GPL-2.0
/* Independent HFT1 source-only measurement policy. No NXP2 protocol change.
 * Application payload is never read by the encoder. Network provider checks,
 * IPv4 finishing, native DMA synchronization and completion remain measured.
 * History is copied in the terminal worker callback, before batch recycle.
 */
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"

__u64 hftb_session;
__u32 hftb_payload;
__u32 hftb_depth;
__u32 hftb_groups;
__u8 hftb_network_template[42];
struct hftb_guard_record {
 __u64 slot_addr;
 __u32 generation,frame_pos,payload_bytes,committed;
 __u8 raw_prefix[430],raw_tail[3072];
};
struct {
 __uint(type,BPF_MAP_TYPE_ARRAY);
 __uint(max_entries,1024);
 __type(key,__u32);
 __type(value,struct hftb_guard_record);
} hftb_guard_history SEC(".maps");

static __always_inline int hftb_geometry(const struct xdev_ext_mech_ctx *mctx,
 const struct xdev_ext_afxdp_mech_info *info,__u32 *generation)
{
 __u64 key=mctx->base.src_offset;
 if(mctx->callsite!=XDEV_EXT_MP_SITE_WORKER||mctx->nr_frames!=1||!info||info->nr_frames!=1||
    !hftb_session||!hftb_depth||hftb_depth>8||!hftb_groups||hftb_groups>1024||
    (hftb_payload!=512&&hftb_payload!=1024)||!key||key>hftb_groups||
    info->l.frame_size!=4096||info->l.hdr_room!=512||info->l.seg_len!=hftb_payload||info->l.group_bytes!=hftb_payload||
    info->f[0].data_off!=512||info->f[0].data_len!=hftb_payload)return -1;
 *generation=(__u32)key;
 /* With exactly 2*depth UMEM frames, the existing source-only allocator
  * owns the latter half. Refuse any divergent address schedule. */
 if(info->f[0].umem_addr!=(__u64)(hftb_depth+((key-1)%hftb_depth))*4096)return -1;
 return 0;
}

SEC("struct_ops/hftb_afxdp_build")
__s32 BPF_PROG(hftb_afxdp_build,const struct xdev_ext_mech_ctx *mctx)
{
 const struct xdev_ext_afxdp_mech_info *info;
 struct xdp_desc *desc;
 __u8 *pkt,*h;__u32 generation;
 (void)ctx;
 info=(const void *)bpf_xdev_ext_info(mctx,sizeof(struct xdev_ext_afxdp_mech_info));
 if(hftb_geometry(mctx,info,&generation))return XDEV_EXT_MP_BUILD_ABORT;
 pkt=bpf_xdev_ext_afxdp_hdr(mctx,0,430,82);
 desc=(void *)bpf_xdev_ext_desc(mctx,0,sizeof(struct xdp_desc));
 if(!pkt||!desc)return XDEV_EXT_MP_BUILD_ABORT;
 __builtin_memcpy(pkt,hftb_network_template,42);
 h=pkt+42;__builtin_memset(h,0,40);
 xdev_ext_mp_put_be32(h,0x48465431);h[4]=1;h[5]=40;h[6]=2;
 xdev_ext_mp_put_be32(h+8,(__u32)(hftb_session>>32));xdev_ext_mp_put_be32(h+12,(__u32)hftb_session);
 xdev_ext_mp_put_be32(h+16,generation);h[23]=1;
 xdev_ext_mp_put_be32(h+24,hftb_payload);xdev_ext_mp_put_be32(h+32,hftb_payload);
 xdev_ext_mp_tx_desc(desc,info->f[0].umem_addr,512,hftb_payload);
 return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/hftb_afxdp_complete")
__s32 BPF_PROG(hftb_afxdp_complete,const struct xdev_ext_mech_ctx *mctx)
{
 const struct xdev_ext_afxdp_tx_cqe *cqe;
 const struct xdev_ext_afxdp_mech_info *info;
 struct hftb_guard_record *r;
 const __u8 *prefix,*tail;__u32 generation,key;
 (void)ctx;
 info=(const void *)bpf_xdev_ext_info(mctx,sizeof(struct xdev_ext_afxdp_mech_info));
 if(hftb_geometry(mctx,info,&generation))return XDEV_EXT_MP_ABORT;
 cqe=(const void *)bpf_xdev_ext_cqe(mctx,0,sizeof(struct xdev_ext_afxdp_tx_cqe));
 if(!cqe||xdev_ext_mp_tx_fold(XDEV_EXT_MP_NEXT,cqe->err)!=XDEV_EXT_MP_NEXT)return XDEV_EXT_MP_ABORT;
 key=generation-1;r=bpf_map_lookup_elem(&hftb_guard_history,&key);
 if(!r||r->committed)return XDEV_EXT_MP_ABORT;
 prefix=bpf_xdev_ext_frame(mctx,0,0,430);
 if(!prefix)return XDEV_EXT_MP_ABORT;
 /* Constant spans for verifier rdonly_buf_size, copied straight into map RAM.
  * A missing view aborts; no synthetic bytes or provider extension. */
 if(hftb_payload==512) {
  tail=bpf_xdev_ext_frame(mctx,0,1024,3072);if(!tail)return XDEV_EXT_MP_ABORT;
  for(__u32 i=0;i<3072;i++)r->raw_tail[i]=tail[i];
 } else {
  tail=bpf_xdev_ext_frame(mctx,0,1536,2560);if(!tail)return XDEV_EXT_MP_ABORT;
  for(__u32 i=0;i<2560;i++)r->raw_tail[i]=tail[i];
 }
 for(__u32 i=0;i<430;i++)r->raw_prefix[i]=prefix[i];
 r->slot_addr=info->f[0].umem_addr;r->generation=generation;
 r->frame_pos=(generation-1)%hftb_depth;r->payload_bytes=hftb_payload;
 r->committed=1;
 return XDEV_EXT_MP_NEXT;
}

SEC("struct_ops/hftb_nvme_build")
__s32 BPF_PROG(hftb_nvme_build,const struct xdev_ext_mech_ctx *mctx)
{
 const struct xdev_ext_nvme_mech_info *info;__u8 *sqe;__u64 slba,key=mctx->base.src_offset;
 (void)ctx;
 info=(const void *)bpf_xdev_ext_info(mctx,sizeof(struct xdev_ext_nvme_mech_info));
 if(!info||!key||key>hftb_groups||mctx->base.length!=hftb_payload||!hftb_session||
    mctx->base.direction!=XDEV_EXT_MP_DIR_FROM_DEVICE)return XDEV_EXT_MP_BUILD_ABORT;
 sqe=bpf_xdev_ext_desc(mctx,0,XDEV_EXT_MP_NVME_DESC_SIZE);
 if(!sqe||xdev_ext_mp_nvme_slba(info->window_slba,info->window_nlb,info->lba_shift,info->l.group_bytes,key-1,0,&slba)||
    xdev_ext_mp_nvme_rw(sqe,mctx->base.direction,slba,hftb_payload,info->lba_shift))return XDEV_EXT_MP_BUILD_ABORT;
 return XDEV_EXT_MP_BUILD_SUBMIT;
}

SEC("struct_ops/hftb_nvme_complete")
__s32 BPF_PROG(hftb_nvme_complete,const struct xdev_ext_mech_ctx *mctx)
{
 const struct xdev_ext_nvme_mech_cqe *cqe;
 (void)ctx;
 cqe=(const void *)bpf_xdev_ext_cqe(mctx,0,sizeof(struct xdev_ext_nvme_mech_cqe));
 if(!cqe)return XDEV_EXT_MP_ABORT;
 return xdev_ext_mp_nvme_next(mctx->callsite,cqe->status,cqe->err);
}
SEC(".struct_ops.link")
struct xdev_ext_afxdp_mech_ops hftb_afxdp_ops={.abi_version=XDEV_EXT_MP_ABI_VERSION,.build=(void *)hftb_afxdp_build,.complete=(void *)hftb_afxdp_complete};
SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops hftb_nvme_ops={.abi_version=XDEV_EXT_MP_ABI_VERSION,.build=(void *)hftb_nvme_build,.complete=(void *)hftb_nvme_complete};
char LICENSE[] SEC("license")="GPL";
