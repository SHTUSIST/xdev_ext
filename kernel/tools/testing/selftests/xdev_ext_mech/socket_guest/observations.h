/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_SOCKET_GUEST_OBSERVATIONS_H
#define XDEV_SOCKET_GUEST_OBSERVATIONS_H
struct socket_guest_observations {
 __u64 build, complete, slot_mask, invalid;
 __u64 last_group[8];
};
#endif
