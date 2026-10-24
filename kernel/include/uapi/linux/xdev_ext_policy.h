/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_XDEV_EXT_POLICY_H
#define _UAPI_LINUX_XDEV_EXT_POLICY_H
#include <linux/types.h>
#include "xdev_ext_mech.h"

#define XDEV_EXT_REL_POLICY_VERSION        1U
#define XDEV_EXT_REL_POLICY_MAX_WINDOW     32U        /* == XDEV_EXT_REL_MAX_WINDOW */
#define XDEV_EXT_REL_POLICY_RTO_MIN_NS     1000ULL    /* 1 us */
#define XDEV_EXT_REL_POLICY_RTO_MAX_NS     86400000000000ULL /* 24 h, the ctl bound today */
#define XDEV_EXT_REL_POLICY_MAX_ATTEMPTS   65535U
/* Defaults = 75b51c2 ctl defaults (xdev_ext_mech_ctl.c:1727-1731, window = default depth 4). */
#define XDEV_EXT_REL_POLICY_DEFAULT_WINDOW        4U
#define XDEV_EXT_REL_POLICY_DEFAULT_RTO_NS        100000000ULL  /* 100 ms */
#define XDEV_EXT_REL_POLICY_DEFAULT_MAX_ATTEMPTS  8U

enum xdev_ext_rel_backoff { XDEV_EXT_REL_BACKOFF_FIXED = 0, XDEV_EXT_REL_BACKOFF_EXPONENTIAL = 1 };
enum xdev_ext_rel_ack_rule {
 XDEV_EXT_REL_ACK_EACH = 0,     /* 75b51c2: an ACK per finished group, immediately */
 XDEV_EXT_REL_ACK_EVERY_N = 1,  /* emit when ack_every ACKs are owed; flush after ack_delay_ns */
 XDEV_EXT_REL_ACK_DELAYED = 2,  /* emit only when the oldest owed ACK is ack_delay_ns old */
};
enum xdev_ext_rel_resend_order {
 XDEV_EXT_REL_RESEND_SLOT = 0,        /* 75b51c2: scan slots 0..window-1 */
 XDEV_EXT_REL_RESEND_OLDEST = 1,      /* scan from slot base_group % window */
 XDEV_EXT_REL_RESEND_ROUND_ROBIN = 2, /* scan from the slot after the last retransmission */
};
enum xdev_ext_policy_field {
 XDEV_EXT_POLICY_F_NONE = 0, XDEV_EXT_POLICY_F_VERSION = 1, XDEV_EXT_POLICY_F_SIZE = 2,
 XDEV_EXT_POLICY_F_FLAGS = 3, XDEV_EXT_POLICY_F_RSVD = 4, XDEV_EXT_POLICY_F_WINDOW = 5,
 XDEV_EXT_POLICY_F_INITIAL_CREDIT = 6, XDEV_EXT_POLICY_F_RTO = 7, XDEV_EXT_POLICY_F_BACKOFF = 8,
 XDEV_EXT_POLICY_F_RTO_MAX = 9, XDEV_EXT_POLICY_F_MAX_ATTEMPTS = 10, XDEV_EXT_POLICY_F_ACK_RULE = 11,
 XDEV_EXT_POLICY_F_ACK_EVERY = 12, XDEV_EXT_POLICY_F_ACK_DELAY = 13, XDEV_EXT_POLICY_F_RESEND_ORDER = 14,
};

struct xdev_ext_rel_policy {           /* sizeof == 120, no implicit padding */
 __u32 version;                       /* XDEV_EXT_REL_POLICY_VERSION */
 __u32 size;                          /* sizeof(struct xdev_ext_rel_policy) */
 __u32 window;                        /* 1..XDEV_EXT_REL_POLICY_MAX_WINDOW */
 __u32 initial_credit;                /* 1..window: groups the sender may open before an ACK */
 __aligned_u64 rto_ns;                /* [RTO_MIN_NS, RTO_MAX_NS] */
 __aligned_u64 rto_max_ns;            /* FIXED: 0; EXPONENTIAL: (rto_ns, RTO_MAX_NS] */
 __u32 backoff;                       /* enum xdev_ext_rel_backoff */
 __u32 max_attempts;                  /* 1..XDEV_EXT_REL_POLICY_MAX_ATTEMPTS */
 __u32 ack_rule;                      /* enum xdev_ext_rel_ack_rule */
 __u32 ack_every;                     /* EACH: 1; EVERY_N: 2..initial_credit; DELAYED: 0 */
 __aligned_u64 ack_delay_ns;          /* EACH: 0; EVERY_N, DELAYED: 1..rto_ns-1 */
 __u32 resend_order;                  /* enum xdev_ext_rel_resend_order */
 __u32 flags;                         /* 0 */
 __u32 bad_field;                     /* out (CREATE -EINVAL): enum xdev_ext_policy_field; ignored in */
 __u32 rsvd0;                         /* 0 */
 __aligned_u64 rsvd[6];               /* 0; growth */
};


/* POLICY requires RELIABLE; arg1 points to this extended configuration. */
struct xdev_ext_afxdp_reliable_policy_config {   /* sizeof == 152 */
 struct xdev_ext_afxdp_reliable_finite_config finite;  /* base.first_group used; base.window,
     base.timeout_ns, base.max_attempts must be 0; nr_groups used iff F_FINITE, else must be 0 */
 struct xdev_ext_rel_policy policy;
};


#define XDEV_EXT_MECH_TRANSPORT_STATS_VERSION_4 4U
struct xdev_ext_mech_transport_stats_v4 {        /* sizeof == 216 */
 struct xdev_ext_mech_transport_stats_v3 v3;
 struct xdev_ext_rel_policy rel_policy;           /* first reliable stage; all zero if none */
};

#endif
