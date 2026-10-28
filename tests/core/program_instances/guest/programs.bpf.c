// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
#ifndef SP_TAG
#define SP_TAG 17
#endif
#ifndef SP_PRIVATE_MODE
#define SP_PRIVATE_MODE 1
#endif
#ifndef SP_FAIL_PREPARE
#define SP_FAIL_PREPARE 0
#endif
#ifndef SP_WRONG_CLASS
#define SP_WRONG_CLASS 0
#endif
SEC("struct_ops.s/sp_prepare")
__s32 BPF_PROG(sp_prepare,const struct xdev_ext_mech_ctx *mctx)
{(void)ctx;(void)mctx;return SP_FAIL_PREPARE?-13:0;}
SEC("struct_ops/sp_build")
__s32 BPF_PROG(sp_build,const struct xdev_ext_mech_ctx *mctx)
{(void)ctx;(void)mctx;return XDEV_EXT_MP_BUILD_DEFAULT;}
SEC("struct_ops/sp_complete")
__s32 BPF_PROG(sp_complete,const struct xdev_ext_mech_ctx *mctx)
{(void)ctx;(void)mctx;return XDEV_EXT_MP_NEXT;}
#if !SP_WRONG_CLASS
SEC("struct_ops/sp_compute")
__s32 BPF_PROG(sp_compute,const struct xdev_ext_mech_ctx *mctx)
{
 __u8 *p;__u64 word=0;
 (void)ctx;
 p=bpf_xdev_ext_frame_rw(mctx,0,0,8);
 if(!p)return -14;
 __builtin_memcpy(&word,p,8);word=(word<<8)|SP_TAG;
 __builtin_memcpy(p,&word,8);return 0;
}
SEC(".struct_ops.link")
struct xdev_ext_cpu_mech_ops sp_ops={.abi_version=XDEV_EXT_MP_ABI_VERSION,.flags=SP_PRIVATE_MODE,
 .prepare=(void *)sp_prepare,.build=(void *)sp_build,.complete=(void *)sp_complete,.compute=(void *)sp_compute};
#else
SEC(".struct_ops.link")
struct xdev_ext_nvme_mech_ops sp_ops={.abi_version=XDEV_EXT_MP_ABI_VERSION,.flags=SP_PRIVATE_MODE,
 .prepare=(void *)sp_prepare,.build=(void *)sp_build,.complete=(void *)sp_complete};
#endif
char LICENSE[] SEC("license")="GPL";
