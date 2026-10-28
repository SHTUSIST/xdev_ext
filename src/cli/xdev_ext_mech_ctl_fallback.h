/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_MECH_CTL_FALLBACK_H
#define XDEV_EXT_MECH_CTL_FALLBACK_H
#include <linux/if_xdp.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "../../include/uapi/linux/xdev_ext_mech.h"

enum xdev_ext_mech_ctl_nic_policy {
	XDEV_EXT_MECH_CTL_NIC_AUTO,
	XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC,
	XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET,
};
enum xdev_ext_mech_ctl_nic_path {
	XDEV_EXT_MECH_CTL_NIC_AFXDP_ZC = 1,
	XDEV_EXT_MECH_CTL_NIC_AFXDP_COPY,
	XDEV_EXT_MECH_CTL_NIC_SOCKET,
};
static inline int xdev_ext_mech_ctl_nic_policy_parse(const char *s, __u32 *policy)
{
	if (!s || !policy)
		return -EINVAL;
	if (!strcmp(s, "auto"))
		*policy = XDEV_EXT_MECH_CTL_NIC_AUTO;
	else if (!strcmp(s, "off"))
		*policy = XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC;
	else if (!strcmp(s, "force"))
		*policy = XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET;
	else
		return -EINVAL;
	return 0;
}
static inline bool xdev_ext_mech_ctl_nic_try_afxdp(__u32 policy)
{
	return policy != XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET;
}
static inline int xdev_ext_mech_ctl_nic_path(__u32 policy, bool copy_mode,
					  int bind_err, __u32 options, __u32 *path)
{
	if (policy > XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET ||
	    (copy_mode && policy != XDEV_EXT_MECH_CTL_NIC_AUTO))
		return -EINVAL;
	if (policy == XDEV_EXT_MECH_CTL_NIC_FORCE_SOCKET) {
		*path = XDEV_EXT_MECH_CTL_NIC_SOCKET;
		return 0;
	}
	if (bind_err) {
		if (!copy_mode && policy == XDEV_EXT_MECH_CTL_NIC_AUTO &&
		    bind_err == -EOPNOTSUPP) {
			*path = XDEV_EXT_MECH_CTL_NIC_SOCKET;
			return 0;
		}
		return bind_err;
	}
	if (copy_mode) {
		if (options & XDP_OPTIONS_ZEROCOPY)
			return -EPROTO;
		*path = XDEV_EXT_MECH_CTL_NIC_AFXDP_COPY;
	} else if (options & XDP_OPTIONS_ZEROCOPY) {
		*path = XDEV_EXT_MECH_CTL_NIC_AFXDP_ZC;
	} else if (policy == XDEV_EXT_MECH_CTL_NIC_REQUIRE_ZC) {
		return -EOPNOTSUPP;
	} else {
		*path = XDEV_EXT_MECH_CTL_NIC_SOCKET;
	}
	return 0;
}
static inline int xdev_ext_mech_ctl_nic_fallback_create(struct xdev_ext_mech_create *c,
						      __u32 nic_stage, int socket_fd)
{
	struct xdev_ext_mech_stage_uapi *st;

	if (!c || nic_stage >= c->nr_stages ||
	    c->st[nic_stage].class_id != XDEV_EXT_MECH_CLASS_AFXDP)
		return -EINVAL;
	st = &c->st[nic_stage];
	if (st->flags)
		return -EOPNOTSUPP;
	if (socket_fd < 0)
		return -EBADF;
	if ((st->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE &&
	     (nic_stage || c->nr_stages < 2)) ||
	    (st->direction == XDEV_EXT_MECH_DIR_TO_DEVICE && nic_stage + 1 != c->nr_stages) ||
	    (st->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE &&
	     st->direction != XDEV_EXT_MECH_DIR_TO_DEVICE))
		return -EINVAL;
	*st = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_SOCKET, .direction = st->direction,
		.fd = socket_fd,
	};
	if (c->pool_kind == XDEV_EXT_MECH_POOL_XSK) {
		c->pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
		c->pool_fd = -1;
	}
	return 0;
}
#endif
