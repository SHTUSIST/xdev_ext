/* SPDX-License-Identifier: GPL-2.0 */
/* Only kfunc/OS dependencies are shimmed; info and BPF build bodies are real. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_ce_core.h"
#define BPF_PROG(name,...) name(__VA_ARGS__)
#define REAL_DEFINES_UNUSED 1
/* REAL_DEFINES */
/* REAL_LAYOUT */
struct bpf_testmod_xdev_ext_mech { __u32 member,nr_frames,info_size; __u64 batch_id; __u8 info[1024]; };
struct xdev_ext_mech_obs { __u32 calls; };
static struct xdev_ext_ce_mech_info current_info;
static struct xdev_ext_ce_copy_desc descriptors[XDEV_EXT_MECH_MAX_FRAMES];
static struct xdev_ext_mech_obs build_obs;
__u64 gpu_base = XDEV_EXT_MECH_T_GPU_BASE;
static void xdev_ext_mech_frames_info(struct bpf_testmod_xdev_ext_mech *io,struct xdev_ext_mech_frame_info *f) {
 for(__u32 i=0;i<io->nr_frames;i++)f[i]=(struct xdev_ext_mech_frame_info){.data_off=64,.data_len=8192};
}
static void *bpf_xdev_ext_info(const struct xdev_ext_mech_ctx *ctx,size_t size) {(void)ctx;assert(size==sizeof(current_info));return &current_info;}
static void *bpf_xdev_ext_desc(const struct xdev_ext_mech_ctx *ctx,__u32 i,size_t size) {(void)ctx;assert(i<XDEV_EXT_MECH_MAX_FRAMES&&size==sizeof(descriptors[i]));return &descriptors[i];}
static void xdev_ext_mech_observe(const struct xdev_ext_mech_ctx *ctx,const struct xdev_ext_mech_frame_info *f,struct xdev_ext_mech_obs *obs) {(void)ctx;(void)f;obs->calls++;}
/* REAL_INFO */
/* REAL_BUILD */
#define REQUIRE(x,msg) do{if(!(x)){fprintf(stderr,"FAIL: %s\n",msg);return 1;}}while(0)
int main(void) {
 struct bpf_testmod_xdev_ext_mech io={.member=XDEV_EXT_MECH_MEMBER_PREPARE,.nr_frames=1,.batch_id=5};
 struct xdev_ext_mech_ctx ctx={.nr_frames=1};ctx.base.src_offset=~(__u64)0;
 xdev_ext_mech_ce_info(&io);memcpy(&current_info,io.info,sizeof(current_info));
 REQUIRE(!current_info.lease_generation&&!current_info.window_depth,"prepare has no batch lease");
 REQUIRE(ce_build(&ctx)==XDEV_EXT_MECH_BUILD_ABORT,"prepare view cannot build a leased plan");
 io.member=XDEV_EXT_MECH_MEMBER_BUILD;xdev_ext_mech_ce_info(&io);memcpy(&current_info,io.info,sizeof(current_info));
 REQUIRE(current_info.lease_generation==io.batch_id&&current_info.window_depth>current_info.window_slot,"host positive fixture supplies valid batch lease");
 current_info.window_slot=2;gpu_base=~(__u64)0;
 REQUIRE(ce_build(&ctx)==XDEV_EXT_MECH_BUILD_SUBMIT,"valid positive lease must build");
 REQUIRE(descriptors[0].gpu_off==(__u64)current_info.window_slot*current_info.l.group_bytes,"positive build uses slot, independent of sequence or global gpu_base");
 current_info.lease_generation=0;
 REQUIRE(ce_build(&ctx)==XDEV_EXT_MECH_BUILD_ABORT,"missing lease rejected");
 current_info.lease_generation=io.batch_id;current_info.window_slot=current_info.window_depth;
 REQUIRE(ce_build(&ctx)==XDEV_EXT_MECH_BUILD_ABORT,"out-of-depth lease rejected");
 current_info.window_slot=0;current_info.gpu_window_len=(__u64)current_info.window_depth*current_info.l.group_bytes-1;
 REQUIRE(ce_build(&ctx)==XDEV_EXT_MECH_BUILD_ABORT,"window must cover all depth slots");
 current_info.gpu_window_len=XDEV_EXT_MECH_T_GPU_WINDOW;current_info.f[0].data_len=current_info.l.group_bytes+1;
 REQUIRE(ce_build(&ctx)==XDEV_EXT_MECH_BUILD_ABORT,"entry cannot escape its lease slot");
 puts("positive CE fixture lease: PASS");return 0;
}
