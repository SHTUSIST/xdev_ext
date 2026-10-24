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
#include <stdbool.h>
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

#define XDEV_EXT_PEER_NET_RX 1
#define XDEV_EXT_PEER_NET_CAP_TX 1U
#define XDEV_EXT_PEER_NET_CAP_RX 2U
static inline unsigned int xdev_ext_peer_net_caps(bool device, bool tx, bool rx, bool flush)
{
 return (device && tx ? XDEV_EXT_PEER_NET_CAP_TX : 0) |
        (device && rx && flush ? XDEV_EXT_PEER_NET_CAP_RX : 0);
}
static inline int xdev_ext_peer_net_cap_check(unsigned int caps, bool rx)
{
 return caps & (rx ? XDEV_EXT_PEER_NET_CAP_RX : XDEV_EXT_PEER_NET_CAP_TX) ? 0 : -EOPNOTSUPP;
}
static inline int xdev_ext_peer_net_rx_check(unsigned int mtu, unsigned int header_room,
 unsigned int frame_room, unsigned int flags)
{
 if (flags) return -EOPNOTSUPP;
 if (header_room < 14 || header_room > 128 || !frame_room) return -EINVAL;
 if (mtu > 65535 || header_room > mtu + 14 || frame_room < mtu + 14 - header_room)
  return -EMSGSIZE;
 return 0;
}
static inline int xdev_ext_peer_net_rx_result(int status, bool quiesced,
 unsigned int header_room, unsigned int header_len, unsigned int payload_len,
 unsigned int frame_room, bool *sequester)
{
 *sequester = !quiesced;
 if (!quiesced) return status ? status : -EIO;
 if (status) return status;
 if (header_len > header_room || payload_len > frame_room ||
     (payload_len && header_len != header_room)) {
  *sequester = true;
  return -EPROTO;
 }
 return 0;
}
#endif
