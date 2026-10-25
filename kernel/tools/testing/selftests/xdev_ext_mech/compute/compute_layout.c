// SPDX-License-Identifier: GPL-2.0
/*
 * Host helper of compute_kvm.sh: the session layout xdev_ext_mech_ctl uses for
 * cpu-chain without a NIC (MTU 1500, 8 KiB groups), from the same header, so
 * the guest probe and the host oracle never hard-code it.
 * Build with -I <kernel tree>.
 */
#include <stdio.h>

#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"

int main(void)
{
	struct xdev_ext_mech_layout l;

	if (xdev_ext_mech_ctl_layout(1500, 8192, &l) || l.hdr_room >= l.frame_size)
		return 1;
	printf("frame_size=%u hdr_room=%u seg_len=%u group_bytes=%u capacity=%u\n",
	       l.frame_size, l.hdr_room, l.seg_len, l.group_bytes, l.frame_size - l.hdr_room);
	return 0;
}
