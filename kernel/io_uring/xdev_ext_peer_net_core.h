/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_PEER_NET_CORE_H
#define _XDEV_EXT_PEER_NET_CORE_H
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
struct file;
struct xdev_ext_peer_net_desc;
struct xdev_ext_peer_net_endpoint;
/* Mechanism NET stages. @dead runs once under RTNL when the bound device
 * unregisters, after the endpoint dropped its device reference; later sends
 * fail with -ENODEV. A send whose @stopped turns true while it waits for the
 * native completion gives up within about one second, with the lease
 * quarantined as unknown native ownership.
 */
struct xdev_ext_peer_net_endpoint *xdev_ext_peer_net_bind_stage(u32 ifindex, u32 queue,
                                                              void (*dead)(void *), void *arg);
int xdev_ext_peer_net_send_stoppable(struct xdev_ext_peer_net_endpoint *endpoint,
                                     struct file *allocation, u64 generation,
                                     const struct xdev_ext_peer_net_desc *desc, bool *accepted,
                                     bool (*stopped)(void *), void *arg);
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
