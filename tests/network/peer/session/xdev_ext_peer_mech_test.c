// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include "../../../../io_uring/xdev_ext_mech_step.h"
/* Updated for P1: 75b51c2 pinned NET RX and GPU-first chains as -EOPNOTSUPP; admission is now the per-class table. */
#ifndef XDEV_EXT_MECH_PEER_CAPS
int main(void) { puts("not ok 1 - PEER pool capability table (xdev_ext_mech_peer_dirs) missing; NIC RX into GPU memory rejected by chain shape"); return 1; }
#else
int main(void)
{
 struct xdev_ext_mech_create c = { .abi_version = 1, .nr_stages = 2,
   .pool_kind = 3, .pool_fd = 4, .layout = {65536, 0, 8192, 8192},
   .depth = 2, .eventfd = -1,
   .st = {{.class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 5},
          {.class_id = 8, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 6}} };
 struct xdev_ext_mech_start start = {.nr_batches = 17};
 __u32 frames = 0, off, len;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0 && frames == 1);
 assert(xdev_ext_mech_start_check(&start, c.pool_kind, false, 1, 2) == 0);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_NVME;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_SOCKET;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_CE;
 assert(xdev_ext_mech_create_check(&c, &frames) ==
        (xdev_ext_mech_peer_dirs(XDEV_EXT_MECH_CLASS_CE) & XDEV_EXT_DMA_DIR_TO_DEVICE ? 0 : -EOPNOTSUPP));
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_IAA;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 c.st[1].class_id = XDEV_EXT_MECH_CLASS_AFXDP;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
 c.st[1].class_id = 8; c.st[1].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0);
 c.st[0] = c.st[1]; c.st[1].class_id = XDEV_EXT_MECH_CLASS_NVME; c.st[1].direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0); /* NIC RX -> GPU -> NVMe write */
 c.st[0] = c.st[1]; c.st[1].class_id = 8;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0); /* GPU -> NVMe write, GPU -> NIC TX */
 c.st[0].class_id = XDEV_EXT_MECH_CLASS_NVME; c.st[0].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
 c.st[1].direction = XDEV_EXT_MECH_DIR_TO_DEVICE; c.layout.hdr_room = 14;
 /* Generic CREATE bounds headroom; device alignment is checked by each
  * native class. This offset alone is not an NVMe DMA qualification. */
 assert(xdev_ext_mech_create_check(&c, &frames) == 0 && frames == 1);
 assert(xdev_ext_mech_layout_span(&c.layout, 0, &off, &len) == 0 &&
        off == 14 && len == 8192);
 /* Two sector-aligned payload spans retain their frame-local headroom. */
 c.layout = (struct xdev_ext_mech_layout){4096, 512, 3072, 6144};
 assert(xdev_ext_mech_create_check(&c, &frames) == 0 && frames == 2);
 assert(xdev_ext_mech_layout_span(&c.layout, 0, &off, &len) == 0 &&
        off == 512 && len == 3072);
 assert(xdev_ext_mech_layout_span(&c.layout, 1, &off, &len) == 0 &&
        off == 512 && len == 3072 && c.layout.frame_size + off == 4608);
 assert(xdev_ext_mech_layout_span(&c.layout, 2, &off, &len) == -ERANGE);
 c.layout.group_bytes = 4608;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0 && frames == 2);
 assert(xdev_ext_mech_layout_span(&c.layout, 1, &off, &len) == 0 &&
        off == 512 && len == 1536);
 c.layout.hdr_room = 1024;
 assert(xdev_ext_mech_create_check(&c, &frames) == 0 && frames == 2);
 assert(xdev_ext_mech_layout_span(&c.layout, 0, &off, &len) == 0 &&
        off == 1024 && len == 3072 && off + len == 4096);
 c.layout.hdr_room = 1025;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EINVAL);
 assert(xdev_ext_mech_layout_span(&c.layout, 0, &off, &len) == -EINVAL);
 c.layout.hdr_room = UINT32_MAX;
 assert(xdev_ext_mech_create_check(&c, &frames) == -EINVAL);
 assert(xdev_ext_mech_layout_span(&c.layout, 0, &off, &len) == -EINVAL);
 puts("ok 1 - one START composes authoritative GPU spans across native NVMe and NET in both directions; host-only stages reject");
 return 0;
}
#endif
