/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _XDEV_EXT_POLICY_H
#define _XDEV_EXT_POLICY_H
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/xdev_ext_policy.h>
#include <linux/xdev_ext_mech_reliable_core.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <linux/types.h>
#include "../include/uapi/linux/xdev_ext_policy.h"
#include "../include/linux/xdev_ext_mech_reliable_core.h"
#endif

#define XDEV_EXT_POLICY_DEFAULT_DEPTH 4U
#define XDEV_EXT_POLICY_RX_GROUP_TIMEOUT_MS 1000U
#define XDEV_EXT_POLICY_PEER_NET_TIMEOUT_MS 30000U
#define XDEV_EXT_POLICY_IAA_TFM_IDLE_MS 5000U

static inline void xdev_ext_rel_policy_defaults(struct xdev_ext_rel_policy *p)
{
 *p=(struct xdev_ext_rel_policy){
  .version=XDEV_EXT_REL_POLICY_VERSION,.size=sizeof(*p),
  .window=XDEV_EXT_REL_POLICY_DEFAULT_WINDOW,
  .initial_credit=XDEV_EXT_REL_POLICY_DEFAULT_WINDOW,
  .rto_ns=XDEV_EXT_REL_POLICY_DEFAULT_RTO_NS,
  .max_attempts=XDEV_EXT_REL_POLICY_DEFAULT_MAX_ATTEMPTS,.ack_every=1,
 };
}

static inline int xdev_ext_rel_policy_validate(const struct xdev_ext_rel_policy *p, __u32 *field)
{
 __u32 f=XDEV_EXT_POLICY_F_NONE;
 unsigned int i;
 if (p->version!=XDEV_EXT_REL_POLICY_VERSION) f=XDEV_EXT_POLICY_F_VERSION;
 else if (p->size!=sizeof(*p)) f=XDEV_EXT_POLICY_F_SIZE;
 else if (p->flags) f=XDEV_EXT_POLICY_F_FLAGS;
 else {
  if (p->rsvd0) f=XDEV_EXT_POLICY_F_RSVD;
  for(i=0;i<6;i++) if(p->rsvd[i]) f=XDEV_EXT_POLICY_F_RSVD;
 }
 if (f) goto out;
 if (!p->window || p->window>XDEV_EXT_REL_POLICY_MAX_WINDOW) f=XDEV_EXT_POLICY_F_WINDOW;
 else if (!p->initial_credit || p->initial_credit>p->window) f=XDEV_EXT_POLICY_F_INITIAL_CREDIT;
 else if (p->rto_ns<XDEV_EXT_REL_POLICY_RTO_MIN_NS || p->rto_ns>XDEV_EXT_REL_POLICY_RTO_MAX_NS)
  f=XDEV_EXT_POLICY_F_RTO;
 else if (p->backoff>XDEV_EXT_REL_BACKOFF_EXPONENTIAL) f=XDEV_EXT_POLICY_F_BACKOFF;
 else if (p->backoff==XDEV_EXT_REL_BACKOFF_FIXED ? p->rto_max_ns!=0 :
          p->rto_max_ns<=p->rto_ns || p->rto_max_ns>XDEV_EXT_REL_POLICY_RTO_MAX_NS)
  f=XDEV_EXT_POLICY_F_RTO_MAX;
 else if (!p->max_attempts || p->max_attempts>XDEV_EXT_REL_POLICY_MAX_ATTEMPTS)
  f=XDEV_EXT_POLICY_F_MAX_ATTEMPTS;
 else if (p->ack_rule>XDEV_EXT_REL_ACK_DELAYED) f=XDEV_EXT_POLICY_F_ACK_RULE;
 else if (p->ack_rule==XDEV_EXT_REL_ACK_EACH ? p->ack_every!=1 :
          p->ack_rule==XDEV_EXT_REL_ACK_DELAYED ? p->ack_every!=0 :
          p->ack_every<2 || p->ack_every>p->initial_credit) f=XDEV_EXT_POLICY_F_ACK_EVERY;
 else if (p->ack_rule==XDEV_EXT_REL_ACK_EACH ? p->ack_delay_ns!=0 :
          !p->ack_delay_ns || p->ack_delay_ns>=p->rto_ns) f=XDEV_EXT_POLICY_F_ACK_DELAY;
 else if (p->resend_order>XDEV_EXT_REL_RESEND_ROUND_ROBIN) f=XDEV_EXT_POLICY_F_RESEND_ORDER;
out:
 if (field) *field=f;
 return f ? -EINVAL : 0;
}

static inline void xdev_ext_rel_policy_from_legacy(struct xdev_ext_rel_policy *p,
                                                   __u32 window, __u64 timeout_ns, __u32 max_attempts)
{
 xdev_ext_rel_policy_defaults(p);
 p->window=p->initial_credit=window; p->rto_ns=timeout_ns; p->max_attempts=max_attempts;
}

static inline void xdev_ext_rel_policy_cfg(const struct xdev_ext_rel_policy *p,
                                          struct xdev_ext_rel_cfg *c)
{
 c->window=p->window; c->timeout_ns=p->rto_ns; c->max_attempts=p->max_attempts;
 c->initial_credit=p->initial_credit==p->window ? 0 : p->initial_credit;
 c->rto_max_ns=p->backoff==XDEV_EXT_REL_BACKOFF_FIXED ? 0 : p->rto_max_ns;
 c->ack_delay_ns=p->ack_delay_ns; c->resend_order=p->resend_order;
}

unsigned long xdev_ext_policy_rx_group_timeout(void);
unsigned long xdev_ext_policy_peer_net_timeout(void);
unsigned long xdev_ext_policy_iaa_tfm_idle(void);
#endif
