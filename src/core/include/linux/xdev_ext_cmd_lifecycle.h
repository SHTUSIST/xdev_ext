/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_CMD_LIFECYCLE_H
#define _LINUX_XDEV_EXT_CMD_LIFECYCLE_H

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif
#include <linux/types.h>

enum xdev_ext_cmd_lifecycle {
	XDEV_EXT_CMD_LIFECYCLE_EMPTY = 0,
	XDEV_EXT_CMD_LIFECYCLE_PREPARED = 1,
	XDEV_EXT_CMD_LIFECYCLE_ACCEPTED = 2,
	XDEV_EXT_CMD_LIFECYCLE_COMPLETED = 3,
	XDEV_EXT_CMD_LIFECYCLE_UNWOUND = 4,
};

enum xdev_ext_cmd_cleanup_action {
	XDEV_EXT_CMD_CLEANUP_NONE = 0,
	XDEV_EXT_CMD_CLEANUP_UNMAP = 1,
	XDEV_EXT_CMD_CLEANUP_FREE_REQUEST = 2,
	XDEV_EXT_CMD_CLEANUP_PUT_TOKEN = 3,
	XDEV_EXT_CMD_CLEANUP_COMPLETE_POLICY = 4,
	XDEV_EXT_CMD_CLEANUP_DONE = 5,
};

struct xdev_ext_cmd_resource_state {
	enum xdev_ext_cmd_lifecycle lifecycle;
	__u8 request_allocated;
	__u8 user_mapped;
	__u8 done;
	__u8 reserved;
};

static inline int
xdev_ext_cmd_lifecycle_prepare(enum xdev_ext_cmd_lifecycle *state)
{
	if (!state)
		return -EINVAL;
	/* One io_uring command gets at most one policy dispatch. */
	if (*state != XDEV_EXT_CMD_LIFECYCLE_EMPTY)
		return -EBUSY;
	*state = XDEV_EXT_CMD_LIFECYCLE_PREPARED;
	return 0;
}

static inline int xdev_ext_cmd_lifecycle_accept(enum xdev_ext_cmd_lifecycle *state)
{
	if (!state || *state != XDEV_EXT_CMD_LIFECYCLE_PREPARED)
		return 0;
	*state = XDEV_EXT_CMD_LIFECYCLE_ACCEPTED;
	return 1;
}

static inline int xdev_ext_cmd_lifecycle_complete(enum xdev_ext_cmd_lifecycle *state)
{
	if (!state || *state != XDEV_EXT_CMD_LIFECYCLE_ACCEPTED)
		return 0;
	*state = XDEV_EXT_CMD_LIFECYCLE_COMPLETED;
	return 1;
}

static inline int xdev_ext_cmd_lifecycle_unwind(enum xdev_ext_cmd_lifecycle *state)
{
	if (!state || *state != XDEV_EXT_CMD_LIFECYCLE_PREPARED)
		return 0;
	*state = XDEV_EXT_CMD_LIFECYCLE_UNWOUND;
	return 1;
}

static inline void
xdev_ext_cmd_resource_request_allocated(struct xdev_ext_cmd_resource_state *state)
{
	if (state)
		state->request_allocated = 1;
}

static inline void
xdev_ext_cmd_resource_user_mapped(struct xdev_ext_cmd_resource_state *state)
{
	if (state)
		state->user_mapped = 1;
}

/* Return cleanup work one step at a time in the required ownership order. */
static inline enum xdev_ext_cmd_cleanup_action
xdev_ext_cmd_preaccept_next(struct xdev_ext_cmd_resource_state *state)
{
	if (!state || state->lifecycle == XDEV_EXT_CMD_LIFECYCLE_ACCEPTED ||
	    state->lifecycle == XDEV_EXT_CMD_LIFECYCLE_COMPLETED)
		return XDEV_EXT_CMD_CLEANUP_NONE;
	if (state->user_mapped) {
		state->user_mapped = 0;
		return XDEV_EXT_CMD_CLEANUP_UNMAP;
	}
	if (state->request_allocated) {
		state->request_allocated = 0;
		return XDEV_EXT_CMD_CLEANUP_FREE_REQUEST;
	}
	if (xdev_ext_cmd_lifecycle_unwind(&state->lifecycle))
		return XDEV_EXT_CMD_CLEANUP_PUT_TOKEN;
	return XDEV_EXT_CMD_CLEANUP_NONE;
}

/* Task-work order is unmap, one policy completion (or defensive put), done. */
static inline enum xdev_ext_cmd_cleanup_action
xdev_ext_cmd_completion_next(struct xdev_ext_cmd_resource_state *state)
{
	if (!state || state->done)
		return XDEV_EXT_CMD_CLEANUP_NONE;
	if (state->user_mapped) {
		state->user_mapped = 0;
		return XDEV_EXT_CMD_CLEANUP_UNMAP;
	}
	if (xdev_ext_cmd_lifecycle_complete(&state->lifecycle))
		return XDEV_EXT_CMD_CLEANUP_COMPLETE_POLICY;
	if (xdev_ext_cmd_lifecycle_unwind(&state->lifecycle))
		return XDEV_EXT_CMD_CLEANUP_PUT_TOKEN;
	state->done = 1;
	return XDEV_EXT_CMD_CLEANUP_DONE;
}

/*
 * io_uring retries a nonblocking issue that returned -EAGAIN from io-wq.  For
 * an opted-in command that is correct only while no policy dispatch has
 * happened (the lifecycle is still EMPTY after pre-accept unwind); afterwards
 * the retry would replay policy-visible work, so the command fails with
 * -EBUSY.  Allocation and mapping run before dispatch so that their -EAGAIN
 * stays retryable.
 */
static inline int
xdev_ext_cmd_issue_errno(const struct xdev_ext_cmd_resource_state *state, int ret)
{
	if (ret != -EAGAIN)
		return ret;
	if (!state || state->lifecycle != XDEV_EXT_CMD_LIFECYCLE_EMPTY)
		return -EBUSY;
	return ret;
}

#endif /* _LINUX_XDEV_EXT_CMD_LIFECYCLE_H */
