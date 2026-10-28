// SPDX-License-Identifier: GPL-2.0
/* NET TX plan over a multi-frame GPU batch (requirement P1: any number of
 * frames per batch, so a NET stage must cover every frame, in order).
 */
#include <stdio.h>
#include <string.h>
#include "../../../../io_uring/xdev_ext_mech_net_core.h"
#ifndef XDEV_EXT_NET_PLAN_FRAMES
int main(void)
{
 puts("not ok 1 - NET plan admission is limited to one GPU frame per batch (XDEV_EXT_NET_PLAN_FRAMES missing)");
 return 1;
}
#else
static int failures;
#define CHECK(c, text) do { if (!(c)) { printf("not ok - %s (line %d)\n", text, __LINE__); failures++; } } while (0)
static struct xdev_ext_net_mech_info info;
static struct xdev_ext_net_send_desc d[XDEV_EXT_NET_MAX_ENTRIES];
static void plan(void)
{
 /* Frame 0: 2000 bytes at 0, frame 1: 1000 bytes at 0, frame 2: 1500 bytes at 64. */
 memset(&info, 0, sizeof(info)); memset(d, 0, sizeof(d));
 info.mtu = 1500; info.nr_frames = 3;
 info.f[0] = (struct xdev_ext_mech_frame_info){ .umem_addr = 0, .data_off = 0, .data_len = 2000 };
 info.f[1] = (struct xdev_ext_mech_frame_info){ .umem_addr = 65536, .data_off = 0, .data_len = 1000 };
 info.f[2] = (struct xdev_ext_mech_frame_info){ .umem_addr = 131072, .data_off = 64, .data_len = 1500 };
 d[0] = (struct xdev_ext_net_send_desc){ .frame_pos = 0, .frame_off = 0, .len = 1000, .header_len = 42 };
 d[1] = (struct xdev_ext_net_send_desc){ .frame_pos = 0, .frame_off = 1000, .len = 1000, .header_len = 42 };
 d[2] = (struct xdev_ext_net_send_desc){ .frame_pos = 1, .frame_off = 0, .len = 1000, .header_len = 42 };
 d[3] = (struct xdev_ext_net_send_desc){ .frame_pos = 2, .frame_off = 64, .len = 1000, .header_len = 42 };
 d[4] = (struct xdev_ext_net_send_desc){ .frame_pos = 2, .frame_off = 1064, .len = 500, .header_len = 42 };
}
int main(void)
{
 plan(); CHECK(!xdev_ext_net_plan_check(&info, d, 5), "ordered exact coverage of three frames");
 plan(); d[2].frame_pos = 2; d[2].frame_off = 64; CHECK(xdev_ext_net_plan_check(&info, d, 5) != 0, "skipping frame 1 refused");
 plan(); d[1].frame_pos = 1; d[1].frame_off = 0; CHECK(xdev_ext_net_plan_check(&info, d, 5) == -EMSGSIZE, "moving on before frame 0 is covered refused");
 plan(); d[3].frame_pos = 0; CHECK(xdev_ext_net_plan_check(&info, d, 5) != 0, "going back to an earlier frame refused");
 plan(); d[4].frame_pos = 3; CHECK(xdev_ext_net_plan_check(&info, d, 5) == -EINVAL, "frame beyond the batch refused");
 plan(); CHECK(xdev_ext_net_plan_check(&info, d, 4) == -EMSGSIZE, "last frame short of coverage refused");
 plan(); d[3].frame_off = 0; CHECK(xdev_ext_net_plan_check(&info, d, 5) == -ERANGE, "frame offset outside the data span refused");
 plan(); d[2].header_len = 13; CHECK(xdev_ext_net_plan_check(&info, d, 5) == -EINVAL, "invalid CPU header still refused per descriptor");
 plan(); info.nr_frames = 0; CHECK(xdev_ext_net_plan_check(&info, d, 5) == -EINVAL, "no frame refused");
 plan(); info.nr_frames = XDEV_EXT_MECH_MAX_FRAMES + 1; CHECK(xdev_ext_net_plan_check(&info, d, 5) == -EINVAL, "too many frames refused");
 plan(); info.nr_frames = 1; info.f[0].data_len = 2000; CHECK(!xdev_ext_net_plan_check(&info, d, 2), "single-frame plan unchanged");
 if (failures) return 1;
 puts("ok 1 - NET TX covers every GPU frame of a batch exactly once, in batch order");
 return 0;
}
#endif
