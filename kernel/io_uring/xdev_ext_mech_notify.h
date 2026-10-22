/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IO_URING_XDEV_EXT_MECH_NOTIFY_H
#define IO_URING_XDEV_EXT_MECH_NOTIFY_H

/* Pure decisions; all state changes and counter snapshots need one lock. */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/xdev_ext_mech.h>
#else
#include <errno.h>
#include <stdbool.h>
#include <linux/types.h>
#include "../include/uapi/linux/xdev_ext_mech.h"
#endif

struct xdev_ext_mech_notify_state {
	struct xdev_ext_mech_notify_arm target;
	bool coarse;
	bool armed;
};

static inline int
xdev_ext_mech_notify_validate(const struct xdev_ext_mech_notify_arm *arm)
{
	if (!arm || !arm->session_id || arm->flags || arm->rsvd ||
	    (!arm->batches_target && !arm->published_target))
		return -EINVAL;
	return 0;
}

/* STOPPING interrupts a wait; it is not proof that DMA has quiesced. */
static inline bool
xdev_ext_mech_notify_reached(const struct xdev_ext_mech_notify_arm *arm,
			__u64 finished, __u64 published, __u32 state, int err)
{
	if (xdev_ext_mech_notify_validate(arm))
		return false;
	if (err || state == XDEV_EXT_MECH_SESSION_ERROR ||
	    state == XDEV_EXT_MECH_SESSION_STOPPING ||
	    state == XDEV_EXT_MECH_SESSION_STOPPED ||
	    state == XDEV_EXT_MECH_SESSION_ZOMBIE)
		return true;
	return (!arm->batches_target || finished >= arm->batches_target) &&
	       (!arm->published_target || published >= arm->published_target);
}

static inline void xdev_ext_mech_notify_init(struct xdev_ext_mech_notify_state *notify)
{
	*notify = (struct xdev_ext_mech_notify_state) { 0 };
}

static inline int
xdev_ext_mech_notify_arm(struct xdev_ext_mech_notify_state *notify,
		    const struct xdev_ext_mech_notify_arm *arm)
{
	int ret = xdev_ext_mech_notify_validate(arm);

	if (ret)
		return ret;
	notify->target = *arm;
	notify->coarse = true;
	notify->armed = true;
	return 0;
}

/* A true return consumes the coarse arm, never the coarse mode itself. */
static inline bool
xdev_ext_mech_notify_signal(struct xdev_ext_mech_notify_state *notify,
		       __u64 finished, __u64 published, __u32 state, int err,
		       bool legacy_event)
{
	if (!notify->coarse)
		return legacy_event;
	if (!notify->armed ||
	    !xdev_ext_mech_notify_reached(&notify->target, finished, published,
				     state, err))
		return false;
	notify->armed = false;
	return true;
}

#endif /* IO_URING_XDEV_EXT_MECH_NOTIFY_H */
