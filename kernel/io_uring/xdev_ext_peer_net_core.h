/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_PEER_NET_CORE_H
#define _XDEV_EXT_PEER_NET_CORE_H
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif
static inline int xdev_ext_peer_net_check(unsigned int mtu, unsigned int header,
                                        unsigned int payload, unsigned int flags)
{
 if (flags) return -EOPNOTSUPP; /* no native RX/header-split contract */
 if (header < 14 || header > 128 || !payload || (payload < 60 && header + payload < 60)) return -EINVAL;
 if (mtu > 65535 || header > mtu + 14 || payload > mtu + 14 - header)
  return -EMSGSIZE;
 return 0;
}
#endif
