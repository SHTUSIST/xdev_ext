/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_SPDK_OWNER_H
#define XDEV_SPDK_OWNER_H

/*
 * Single-owner state of the one queue-depth-1 read of the native SPDK
 * pipeline.  One thread submits, polls and owns the command; nothing here
 * calls SPDK, so test_owner.c checks the rules on any host.
 *
 *   IDLE -> SUBMITTED        submission returned 0 (accepted exactly once)
 *   SUBMITTED -> COMPLETED_OK / COMPLETED_ERROR
 *                            the callback ran inside a completion poll that
 *                            returned >= 0 on a healthy transport, i.e. the
 *                            controller posted a completion entry
 *   SUBMITTED -> UNKNOWN     deadline, or the callback ran while the qpair or
 *                            controller failed (the library may complete
 *                            requests in software then: no proof that the
 *                            device stopped writing the buffer)
 *   UNKNOWN -> COMPLETED_*   a later healthy completion (late = true)
 *
 * Only IDLE and COMPLETED_* may reuse or release the DMA buffer, the
 * callback storage, the qpair, the controller or the environment.  A failed
 * transport never becomes proof again.  A negative submission is not
 * accepted and is never replayed.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum sp_state { SP_IDLE, SP_SUBMITTED, SP_COMPLETED_OK, SP_COMPLETED_ERROR, SP_UNKNOWN };

struct sp_owner {
	enum sp_state state;
	uint64_t accepted;	/* submissions that returned 0 */
	bool callback;		/* the callback ran since the last poll */
	bool callback_error;
	bool transport_failed;	/* sticky */
	bool late;		/* completed after the deadline */
	bool spurious;		/* callback without an accepted command */
};

static inline void sp_init(struct sp_owner *o)
{
	memset(o, 0, sizeof(*o));
}

/* @rc: the submission's return value.  0 when accepted. */
static inline int sp_submit(struct sp_owner *o, int rc)
{
	if (o->spurious)
		return -EPROTO;
	if (o->state != SP_IDLE)
		return -EBUSY;
	if (rc)
		return rc < 0 ? rc : -EIO;
	o->state = SP_SUBMITTED;
	o->accepted++;
	return 0;
}

/* From the completion callback: record only; decided after the poll. */
static inline void sp_on_callback(struct sp_owner *o, bool error)
{
	if (o->state != SP_SUBMITTED && o->state != SP_UNKNOWN) {
		o->spurious = true;
		return;
	}
	o->callback = true;
	o->callback_error = error;
}

/*
 * After each completion poll: @rc its return value, @healthy whether the
 * qpair reports no failure reason and the controller is not failed.
 */
static inline void sp_after_poll(struct sp_owner *o, int rc, bool healthy)
{
	if (rc < 0 || !healthy)
		o->transport_failed = true;
	if (!o->callback)
		return;
	o->callback = false;
	if (o->transport_failed) {
		o->state = SP_UNKNOWN;
		return;
	}
	if (o->state == SP_UNKNOWN)
		o->late = true;
	o->state = o->callback_error ? SP_COMPLETED_ERROR : SP_COMPLETED_OK;
}

static inline void sp_on_deadline(struct sp_owner *o)
{
	if (o->state == SP_SUBMITTED)
		o->state = SP_UNKNOWN;
}

static inline bool sp_can_release(const struct sp_owner *o)
{
	return o->state == SP_IDLE || o->state == SP_COMPLETED_OK ||
	       o->state == SP_COMPLETED_ERROR;
}

/* Continue with the next operation: 0 only after an in-time success. */
static inline int sp_next(struct sp_owner *o)
{
	if (o->state == SP_COMPLETED_ERROR)
		return -EIO;
	if (o->state != SP_COMPLETED_OK)
		return -EBUSY;
	if (o->late)
		return -ETIMEDOUT;
	o->state = SP_IDLE;
	return 0;
}

#endif /* XDEV_SPDK_OWNER_H */
