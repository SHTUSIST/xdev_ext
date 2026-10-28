/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_POLL_H
#define IO_URING_XDEV_EXT_MECH_POLL_H

/*
 * Pure rules of stage polling (Documentation/userspace-api/xdev_ext-poll.rst).
 * The kernel (io_uring/xdev_ext_mech.c) and
 * tools/testing/selftests/xdev_ext_mech/poll compile the same code.
 */

#include "xdev_ext_mech_core.h"

/*
 * CREATE, per bound stage: split the generic stage bits off the class
 * flags.  *@clean is @u without XDEV_EXT_MECH_STAGE_F_POLL and
 * XDEV_EXT_MECH_STAGE_F_FANOUT; it is what the class ->bind sees.  FANOUT is
 * a core scheduling bit kept in the session plan; a class that refuses
 * unknown flags would otherwise fail every fanout member.  -EOPNOTSUPP when
 * the stage asks for polling and its class has no ->poll: there is no
 * interrupt fallback.
 */
static inline int xdev_ext_mech_poll_split(const struct xdev_ext_mech_stage_uapi *u,
					   bool class_polls,
					   struct xdev_ext_mech_stage_uapi *clean,
					   bool *poll)
{
	*clean = *u;
	clean->flags &= ~(XDEV_EXT_MECH_STAGE_F_POLL | XDEV_EXT_MECH_STAGE_F_FANOUT);
	*poll = false;
	if (!(u->flags & XDEV_EXT_MECH_STAGE_F_POLL))
		return 0;
	if (!class_polls)
		return -EOPNOTSUPP;
	*poll = true;
	return 0;
}

/*
 * Session worker, under s->lock, after a poll pass of a session with at
 * least one polled stage: the delay in jiffies before the next pass, or -1
 * for none.  @inflight is the session's live batch count; @rx_source is set
 * when stage 0 is a polled receive source, which has no submit to restart
 * polling.  Accepted commands keep being polled through STOPPING and the
 * bounded drain; a ZOMBIE session still reaps late completions, one jiffy
 * apart.  Nothing is armed once the worker is going away.
 */
static inline long xdev_ext_mech_poll_next(__u32 state, __u32 inflight,
					   bool rx_source, bool worker_gone)
{
	if (worker_gone)
		return -1;
	switch (state) {
	case XDEV_EXT_MECH_SESSION_ACTIVE:
		return inflight || rx_source ? 0 : -1;
	case XDEV_EXT_MECH_SESSION_ERROR:
	case XDEV_EXT_MECH_SESSION_STOPPING:
		return inflight ? 0 : -1;
	case XDEV_EXT_MECH_SESSION_ZOMBIE:
		return inflight ? 1 : -1;
	default:
		return -1;
	}
}

#endif /* IO_URING_XDEV_EXT_MECH_POLL_H */
