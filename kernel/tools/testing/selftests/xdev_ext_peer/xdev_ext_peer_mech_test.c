// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include "../../../../io_uring/xdev_ext_mech_step.h"
int main(void)
{
 struct xdev_ext_mech_create c = { .abi_version = 1, .nr_stages = 2,
   .pool_kind = 3, .pool_fd = 4, .layout = {65536, 0, 8192, 8192},
   .depth = 2, .eventfd = -1,
   .st = {{.class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 5},
          {.class_id = 8, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 6}} };
 struct xdev_ext_mech_start start = {.nr_batches = 17};
 __u32 frames = 0;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0 && frames == 1);
 assert(xdev_ext_mech_start_check(&start, c.pool_kind, false, 1, 2) == 0);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_NVME;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_SOCKET;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_CE;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_IAA;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_AFXDP;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 c.st[1].class_id = 8; c.st[1].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 c.st[1].direction = XDEV_EXT_MECH_DIR_TO_DEVICE; c.layout.hdr_room = 14;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 puts("ok 1 - one START composes authoritative GPU spans across native NVMe and NET; host-only stages and NIC RX reject");
 return 0;
}
