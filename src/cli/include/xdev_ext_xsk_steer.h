/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_XSK_STEER_H
#define XDEV_EXT_XSK_STEER_H
#include "xdev_ext_xsk_shared.h"
#include <linux/ethtool.h>
int xdev_ext_xsk_steer_check_interface(const char *ifname,
				       uint32_t expected_ifindex);
int xdev_ext_xsk_steer_add(const char *ifname, uint32_t expected_ifindex,
			   uint32_t queue,
			   const struct xdev_ext_xsk_flow_filter *filter,
			   struct ethtool_rx_flow_spec *owned,
			   bool *insert_uncertain,
			   struct xdev_ext_xsk_shared_error *error);
int xdev_ext_xsk_steer_remove(const char *ifname, uint32_t expected_ifindex,
			      const struct ethtool_rx_flow_spec *owned,
			      struct xdev_ext_xsk_shared_error *error);
#endif
