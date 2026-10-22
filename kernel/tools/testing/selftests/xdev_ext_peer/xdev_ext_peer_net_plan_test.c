// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#if !__has_include("../../../../io_uring/xdev_ext_mech_net_core.h")
int main(void) { puts("not ok 1 - BPF NET descriptors lack authoritative GPU-span coverage admission"); return 1; }
#else
#include <assert.h>
#include "../../../../io_uring/xdev_ext_mech_net_core.h"
int main(void)
{
 struct xdev_ext_net_mech_info info = {.nr_frames=1,.mtu=1500,.f={{.data_off=0,.data_len=2048}}};
 struct xdev_ext_net_send_desc d[2] = {{.frame_off=0,.len=1024,.header_len=42},{.frame_off=1024,.len=1024,.header_len=42}};
 assert(xdev_ext_net_plan_check(&info,d,2)==0);
 d[1].frame_off=1023; assert(xdev_ext_net_plan_check(&info,d,2)==-ERANGE);
 d[1].frame_off=1025; assert(xdev_ext_net_plan_check(&info,d,2)==-ERANGE);
 d[1].frame_off=1024; d[1].len=1023; assert(xdev_ext_net_plan_check(&info,d,2)==-EMSGSIZE);
 d[1].len=1025; assert(xdev_ext_net_plan_check(&info,d,2)==-ERANGE);
 d[1].len=1024; d[1].frame_pos=1; assert(xdev_ext_net_plan_check(&info,d,2)==-EINVAL);
 d[1].frame_pos=0; d[1].header_len=129; assert(xdev_ext_net_plan_check(&info,d,2)==-EINVAL);
 d[1].header_len=42; d[1].flags=1; assert(xdev_ext_net_plan_check(&info,d,2)==-EINVAL);
 puts("ok 1 - NET accepts exact GPU-span coverage, rejects overlap, gaps, foreign frames and invalid CPU headers");
 return 0;
}
#endif
