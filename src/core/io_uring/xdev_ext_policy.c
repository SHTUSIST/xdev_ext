// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/jiffies.h>
#include "xdev_ext_policy.h"

unsigned long xdev_ext_policy_rx_group_timeout(void)
{
 return msecs_to_jiffies(XDEV_EXT_POLICY_RX_GROUP_TIMEOUT_MS);
}
EXPORT_SYMBOL_GPL(xdev_ext_policy_rx_group_timeout);

unsigned long xdev_ext_policy_peer_net_timeout(void)
{
 return msecs_to_jiffies(XDEV_EXT_POLICY_PEER_NET_TIMEOUT_MS);
}
EXPORT_SYMBOL_GPL(xdev_ext_policy_peer_net_timeout);

unsigned long xdev_ext_policy_iaa_tfm_idle(void)
{
 return msecs_to_jiffies(XDEV_EXT_POLICY_IAA_TFM_IDLE_MS);
}
EXPORT_SYMBOL_GPL(xdev_ext_policy_iaa_tfm_idle);
