/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_START_QUEUE_H
#define IO_URING_XDEV_EXT_MECH_START_QUEUE_H

#include "xdev_ext_mech_step.h"

/* Queue custody is metadata, independent of the four active frame states. */
struct xdev_ext_mech_start_loan {
 __u32 index;
 __u8 original_state;
};
struct xdev_ext_mech_start_template {
 __u32 first;
 bool active, returned, sequestered;
};
struct xdev_ext_mech_start_queue {
 struct xdev_ext_mech_start_loan *loans;
 struct xdev_ext_mech_start_template *templates;
 __u32 nr_loans, nr_templates, frames;
 __u64 next_ordinal, total;
 bool recycle;
};

/* The initial span is restored on every cycle; no variable output or trim. */
static inline int xdev_ext_mech_start_queue_plan_check(
 const struct xdev_ext_mech_stage_uapi *st, __u32 nr)
{
 __u32 i;

 for (i = 0; i < nr; i++) {
  if (xdev_ext_mech_stage_role(&st[i]) == XDEV_EXT_MECH_ROLE_TRANSFORM)
   return -EOPNOTSUPP;
  if (st[i].class_id == XDEV_EXT_MECH_CLASS_USER &&
      (st[i].arg1 || (st[i].flags & XDEV_EXT_USER_F_VARLEN)))
   return -EOPNOTSUPP;
  if (st[i].class_id == XDEV_EXT_MECH_CLASS_CPU) {
   __s64 delta;

   if (xdev_ext_mech_cpu_len_delta(st[i].arg0, st[i].arg1, &delta) || delta)
    return -EOPNOTSUPP;
  }
  /* Datagram reception may produce fewer bytes/frames than the template. */
  if (st[i].class_id == XDEV_EXT_MECH_CLASS_SOCKET &&
      st[i].direction == XDEV_EXT_MECH_DIR_FROM_DEVICE)
   return -EOPNOTSUPP;
 }
 return 0;
}

static inline bool xdev_ext_mech_start_template_again(
 const struct xdev_ext_mech_start_queue *q, __u64 ordinal)
{
 return q->recycle && ordinal < q->total &&
        q->nr_templates < q->total - ordinal;
}

#endif /* IO_URING_XDEV_EXT_MECH_START_QUEUE_H */
