// SPDX-License-Identifier: GPL-2.0
/* Host-frame XDOMAIN endpoint; contract in libxdev_ext_frame_endpoint.h. */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "libxdev_ext_frame_endpoint.h"
#include "libxdev_ext_internal.h"

#define FRAME_MAX_GROUP (XDEV_EXT_MECH_MAX_FRAMES * XDEV_EXT_FRAME_SIZE)

struct xdev_ext_frame_endpoint {
	struct xdev_ext_session *session;
	struct xdev_ext_create_opts create;
	__u32 direction, group_bytes, frames;
	__u64 window_bytes;
	__u64 posted;		/* sequence of the posted batch, 0: none */
	__u64 batches;		/* batches STARTed on this session */
	bool created;
	int error;		/* sticky failure of a posted batch */
	__u32 indices[XDEV_EXT_MECH_MAX_FRAMES];
};

struct xdev_ext_session *xdev_ext_frame_endpoint_session(struct xdev_ext_frame_endpoint *e)
{
	return e ? e->session : NULL;
}

int xdev_ext_frame_endpoint_open(const struct xdev_ext_frame_endpoint_opts *o,
	struct xdev_ext_frame_endpoint **out)
{
	struct xdev_ext_pool_opts pool = { .sz = sizeof(pool), .pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM };
	struct xdev_ext_mech_stage_uapi ce, xdomain;
	struct xdev_ext_frame_endpoint *e;
	bool send;
	int ret;

	if (out)
		*out = NULL;
	if (!o || !out)
		return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret)
		return ret;
	if (o->flags & ~XDEV_EXT_FRAME_ENDPOINT_F_EARLY)
		return -EOPNOTSUPP;
	if (o->control_fd < 0 || o->ce_fd < 0 || !o->link_token || !o->depth ||
	    (o->direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
	     o->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE) ||
	    !o->group_bytes || o->group_bytes % 64 || o->group_bytes > FRAME_MAX_GROUP ||
	    !o->window_va || o->window_bytes < o->group_bytes ||
	    o->window_va > UINT64_MAX - o->window_bytes)
		return -EINVAL;
	/* The send slot is window offset 0 only with one batch slot. */
	if (o->depth != 1)
		return -EOPNOTSUPP;
	send = o->direction == XDEV_EXT_MECH_DIR_TO_DEVICE;
	e = calloc(1, sizeof(*e));
	if (!e)
		return -ENOMEM;
	e->direction = o->direction;
	e->group_bytes = o->group_bytes;
	e->window_bytes = o->window_bytes;
	e->frames = (o->group_bytes + XDEV_EXT_FRAME_SIZE - 1) / XDEV_EXT_FRAME_SIZE;
	for (__u32 i = 0; i < e->frames; i++)
		e->indices[i] = i;
	/* Send: the slot-mode CE reads the batch slot; receive: the CE program
	 * places the whole group (TARGET_RANGE) at its keyed offset. */
	ce = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_CE,
		.direction = send ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE,
		.fd = o->ce_fd, .flags = send ? 0 : XDEV_EXT_CE_STAGE_F_TARGET_RANGE,
		.arg0 = o->window_va, .arg1 = o->window_bytes };
	ret = xdev_ext_stage_xdomain(&xdomain, o->control_fd, o->link_token, o->direction,
		o->flags & XDEV_EXT_FRAME_ENDPOINT_F_EARLY ? XDEV_EXT_XDOMAIN_F_EARLY : 0);
	if (ret) {
		free(e);
		return ret;
	}
	e->create = (struct xdev_ext_create_opts){ .sz = sizeof(e->create),
		.group_bytes = o->group_bytes, .depth = o->depth, .nr_stages = 2,
		.layout = { XDEV_EXT_FRAME_SIZE, 0, XDEV_EXT_FRAME_SIZE, o->group_bytes } };
	e->create.st[0] = send ? ce : xdomain;
	e->create.st[1] = send ? xdomain : ce;
	pool.nr_frames = o->depth * e->frames;
	ret = xdev_ext_session_open(&pool, &e->session);
	if (ret) {
		free(e);
		return ret;
	}
	*out = e;
	return 0;
}

int xdev_ext_frame_endpoint_create(struct xdev_ext_frame_endpoint *e)
{
	int ret;

	if (!e || e->created)
		return -EINVAL;
	ret = xdev_ext_session_create(e->session, &e->create);
	e->created = !ret;
	return ret;
}

int xdev_ext_frame_endpoint_create_programs(struct xdev_ext_frame_endpoint *e,
	const int *program_fds, __u32 nr_programs, struct xdev_ext_mech_create_report *report)
{
	int ret;

	if (!e || e->created || !program_fds || nr_programs != e->create.nr_stages)
		return -EINVAL;
	ret = xdev_ext_session_create_programs(e->session, &e->create, program_fds,
		nr_programs, report);
	e->created = !ret;
	return ret;
}

int xdev_ext_frame_endpoint_place(const struct xdev_ext_frame_endpoint *e, __u64 sequence,
	__u64 *offset, __u32 *bytes)
{
	if (!e || !sequence || !offset || !bytes)
		return -EINVAL;
	*bytes = e->group_bytes;
	*offset = e->direction == XDEV_EXT_MECH_DIR_TO_DEVICE ? 0 :
		(sequence % (e->window_bytes / e->group_bytes)) * e->group_bytes;
	return 0;
}

int xdev_ext_frame_endpoint_post(struct xdev_ext_frame_endpoint *e, __u64 sequence)
{
	struct xdev_ext_start_frames_opts start = { .sz = sizeof(start) };
	int ret;

	if (!e || !sequence)
		return -EINVAL;
	if (e->error)
		return e->error;
	if (!e->created)
		return -ENOTCONN;
	if (e->posted)
		return -EBUSY;
	start.nr_batches = 1;
	start.first_seq = sequence;
	start.indices = e->indices;
	start.nr_indices = e->frames;
	start.flags = XDEV_EXT_MECH_START_F_RECYCLE;
	ret = xdev_ext_session_start_frames(e->session, &start);
	if (ret)
		return ret;
	e->posted = sequence;
	e->batches++;
	return 0;
}

/* Every batch so far finished with no error, abort or sequestered batch. */
static bool finished(const struct xdev_ext_frame_endpoint *e, const struct xdev_ext_mech_stats *st)
{
	return st->batches_done >= e->batches && !st->last_err && !st->batches_abort &&
	       !st->sequestered && st->state == XDEV_EXT_MECH_SESSION_ACTIVE;
}

static bool pending(const struct xdev_ext_frame_endpoint *e, const struct xdev_ext_mech_stats *st)
{
	return st->batches_done < e->batches && !st->last_err && !st->batches_abort &&
	       !st->sequestered && st->state == XDEV_EXT_MECH_SESSION_ACTIVE;
}

static __u64 now_ms(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (__u64)t.tv_sec * 1000 + (__u64)t.tv_nsec / 1000000;
}

int xdev_ext_frame_endpoint_wait(struct xdev_ext_frame_endpoint *e, __u64 sequence, int timeout_ms)
{
	__u64 deadline = timeout_ms >= 0 ? now_ms() + (__u64)timeout_ms : 0;
	struct xdev_ext_mech_stats st;
	int ret, left = timeout_ms;

	if (!e || !sequence)
		return -EINVAL;
	if (e->error)
		return e->error;
	if (!e->posted || e->posted != sequence)
		return -EINVAL;
	for (;;) {
		memset(&st, 0, sizeof(st));
		ret = xdev_ext_session_wait(e->session, left, &st);
		if (ret == -ETIMEDOUT)
			return ret;
		if (!ret && finished(e, &st))
			break;
		/* A wake before this batch finished: wait again, same deadline. */
		if ((!ret || ret == -EIO) && pending(e, &st)) {
			if (timeout_ms >= 0) {
				__u64 now = now_ms();

				if (now >= deadline)
					return -ETIMEDOUT;
				left = (int)(deadline - now);
			}
			continue;
		}
		if (!ret)
			ret = -EIO;
		e->error = ret;
		return ret;
	}
	e->posted = 0;
	return 0;
}

int xdev_ext_frame_endpoint_stop(struct xdev_ext_frame_endpoint *e)
{
	if (!e)
		return -EINVAL;
	return e->created ? xdev_ext_session_stop(e->session) : 0;
}

int xdev_ext_frame_endpoint_close(struct xdev_ext_frame_endpoint *e)
{
	int ret;

	if (!e)
		return -EINVAL;
	if (e->session) {
		if (e->created) {
			ret = xdev_ext_session_stop(e->session);
			if (ret)
				return ret;
		}
		ret = xdev_ext_session_close(e->session);
		if (ret)
			return ret;
		e->session = NULL;
	}
	free(e);
	return 0;
}
