// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "libxdev_ext_peer_message.h"
#include "libxdev_ext_internal.h"

struct xdev_ext_peer_endpoint {
	struct xdev_ext_session *session;
	struct xdev_ext_user_stage *producer, *terminal;
	__u32 direction;
	struct xdev_ext_create_opts create;
	struct {
		__u64 ticket, batch_id, key, arg;
		__u32 nr_frames;
		bool active;
		struct xdev_ext_user_frame frames[XDEV_EXT_MECH_MAX_FRAMES];
	} held[2][XDEV_EXT_USER_RING_MAX];
	int error;
	__u64 origin;
};
static __u64 next_origin = 1;
static __u64 allocate_origin(void)
{
	__u64 value = __atomic_load_n(&next_origin, __ATOMIC_RELAXED);
	while (value) {
		__u64 next = value == UINT64_MAX ? 0 : value + 1;
		if (__atomic_compare_exchange_n(&next_origin, &value, next, false,
			__ATOMIC_RELAXED, __ATOMIC_RELAXED)) return value;
	}
	return 0;
}
struct xdev_ext_session *xdev_ext_peer_endpoint_session(struct xdev_ext_peer_endpoint *e)
{ return e ? e->session : NULL; }
struct xdev_ext_user_stage *xdev_ext_peer_endpoint_user(struct xdev_ext_peer_endpoint *e,
	enum xdev_ext_peer_role role)
{
	if (!e) return NULL;
	if (role == XDEV_EXT_PEER_PRODUCER && e->direction == XDEV_EXT_MECH_DIR_TO_DEVICE)
		return e->producer;
	if ((role == XDEV_EXT_PEER_TX_TERMINAL && e->direction == XDEV_EXT_MECH_DIR_TO_DEVICE) ||
	    (role == XDEV_EXT_PEER_RX_CONSUMER && e->direction == XDEV_EXT_MECH_DIR_FROM_DEVICE))
		return e->terminal;
	return NULL;
}
int xdev_ext_peer_endpoint_open(const struct xdev_ext_peer_endpoint_opts *o,
	struct xdev_ext_peer_endpoint **out)
{
	struct xdev_ext_peer_endpoint *e;
	struct xdev_ext_create_opts create = { .sz = sizeof(create) };
	struct xdev_ext_peer_pool_opts pool = { .sz = sizeof(pool) };
	struct xdev_ext_user_stage_opts user = { .sz = sizeof(user) };
	__u32 entries = 1;
	int ret, control;
	if (!o || !out) return -EINVAL;
	ret = xdev_ext__opts_check(o, o->sz, sizeof(*o));
	if (ret) return ret;
	if (o->flags & ~(XDEV_EXT_PEER_ENDPOINT_F_EXTERNAL_CTL | XDEV_EXT_PEER_ENDPOINT_F_EARLY)) return -EOPNOTSUPP;
	if (o->allocation_fd < 0 || o->control_fd < 0 || !o->link_token ||
	    !o->depth || o->depth > XDEV_EXT_USER_RING_MAX || !o->group_bytes ||
	    !o->deadline_ms || o->deadline_ms > XDEV_EXT_USER_DEADLINE_MAX_MS ||
	    (o->direction != XDEV_EXT_MECH_DIR_TO_DEVICE &&
	     o->direction != XDEV_EXT_MECH_DIR_FROM_DEVICE)) return -EINVAL;
	e = calloc(1, sizeof(*e));
	if (!e) return -ENOMEM;
	e->origin = allocate_origin();
	if (!e->origin) { free(e); return -EOVERFLOW; }
	e->direction = o->direction;
	pool.allocation_fd = o->allocation_fd;
	ret = xdev_ext_session_open_peer(&pool, &e->session);
	if (ret) { free(e); return ret; }
	control = fcntl(o->control_fd, F_DUPFD_CLOEXEC, 0);
	if (control < 0) { ret = -errno; goto fail; }
	ret = xdev_ext__session_own_fd(e->session, control);
	if (ret) { close(control); goto fail; }
	while (entries < o->depth) entries <<= 1;
	user.ring_fd = xdev_ext_session_ring_fd(e->session);
	user.entries = entries;
	if (o->flags & XDEV_EXT_PEER_ENDPOINT_F_EXTERNAL_CTL)
		user.flags = XDEV_EXT_USER_CREATE_F_EXTERNAL_CTL;
	if (o->direction == XDEV_EXT_MECH_DIR_TO_DEVICE)
		ret = xdev_ext_user_stage_open(&user, &e->producer);
	if (!ret) ret = xdev_ext_user_stage_open(&user, &e->terminal);
	if (ret) goto fail;
	create.group_bytes = o->group_bytes;
	create.depth = o->depth;
	create.layout = o->layout;
	create.nr_stages = e->producer ? 3 : 2;
	__u32 native = e->producer ? 1 : 0;
	ret = xdev_ext_stage_xdomain(&create.st[native], control, o->link_token,
		o->direction, o->flags & XDEV_EXT_PEER_ENDPOINT_F_EARLY ? XDEV_EXT_XDOMAIN_F_EARLY : 0);
	if (ret) goto fail;
	struct xdev_ext_mech_stage_uapi strict = {
		.class_id = XDEV_EXT_MECH_CLASS_USER,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
		.flags = XDEV_EXT_USER_F_STRICT_ASYNC | XDEV_EXT_MECH_STAGE_F_POLL,
		.arg0 = o->deadline_ms,
	};
	create.st[native + 1] = strict;
	create.st[native + 1].fd = xdev_ext_user_stage_fd(e->terminal);
	if (e->producer) {
		create.st[0] = strict;
		create.st[0].fd = xdev_ext_user_stage_fd(e->producer);
	}
	e->create = create;
	*out = e;
	return 0;
fail:
	/* Failed CREATE has no accepted payload work. Still preserve any close
	 * failure instead of discarding an authority that the kernel retains. */
	if (xdev_ext_peer_endpoint_close(e)) *out = e;
	return ret;
}
int xdev_ext_peer_endpoint_create(struct xdev_ext_peer_endpoint *e)
{ return e ? xdev_ext_session_create(e->session, &e->create) : -EINVAL; }
int xdev_ext_peer_endpoint_start(struct xdev_ext_peer_endpoint *e,
	const struct xdev_ext_start_frames_opts *o)
{ return !e ? -EINVAL : e->error ? e->error : xdev_ext_session_start_frames(e->session, o); }
static int remember(struct xdev_ext_peer_endpoint *e, const struct xdev_ext_user_batch *b,
	enum xdev_ext_peer_role role)
{
	unsigned int unit = role == XDEV_EXT_PEER_PRODUCER ? 0 : 1;
	if (b->slot >= XDEV_EXT_USER_RING_MAX || e->held[unit][b->slot].active) {
		e->error = -EPROTO;
		return e->error;
	}
	e->held[unit][b->slot].ticket = b->ticket;
	e->held[unit][b->slot].batch_id = b->batch_id;
	e->held[unit][b->slot].key = b->key;
	e->held[unit][b->slot].arg = b->arg;
	e->held[unit][b->slot].nr_frames = b->nr_frames;
	e->held[unit][b->slot].active = true;
	memcpy(e->held[unit][b->slot].frames, b->f, b->nr_frames * sizeof(b->f[0]));
	return 0;
}
int xdev_ext_peer_endpoint_next(struct xdev_ext_peer_endpoint *e, int timeout_ms,
	struct xdev_ext_peer_message *message)
{
	struct timespec deadline, *until = NULL;
	struct xdev_ext_user_stage *users[2];
	size_t nr;
	struct xdev_ext_user_batch *batch;
	int ret;
	if (!e || !message) return -EINVAL;
	batch = &message->batch;
	if (e->error) return e->error;
	users[0] = e->terminal;
	users[1] = e->producer;
	nr = e->producer ? 2 : 1;
	if (timeout_ms > 0) {
		if (clock_gettime(CLOCK_MONOTONIC, &deadline)) return -errno;
		deadline.tv_sec += timeout_ms / 1000;
		deadline.tv_nsec += (timeout_ms % 1000) * 1000000L;
		if (deadline.tv_nsec >= 1000000000L) {
			deadline.tv_sec++;
			deadline.tv_nsec -= 1000000000L;
		}
		until = &deadline;
	}
	for (;;) {
		/* Reject the whole CPU round before taking any ring's custody. */
		for (size_t i = 0; i < nr; i++)
			if (xdev_ext__user_ctl_attached(users[i])) return -EBUSY;
		/* Drain terminal custody before lending more producer work. */
		ret = xdev_ext_user_stage_next(e->terminal, 0, batch);
		if (!ret) {
			message->role = e->producer ? XDEV_EXT_PEER_TX_TERMINAL : XDEV_EXT_PEER_RX_CONSUMER;
			message->origin = e->origin;
			return remember(e, batch, message->role);
		}
		if (ret != -EAGAIN) return ret;
		if (e->producer) {
			ret = xdev_ext_user_stage_next(e->producer, 0, batch);
			if (!ret) {
				message->role = XDEV_EXT_PEER_PRODUCER;
				message->origin = e->origin;
				return remember(e, batch, message->role);
			}
			if (ret != -EAGAIN) return ret;
		}
		if (!timeout_ms) return -EAGAIN;
		ret = xdev_ext__user_wait_any(users, nr, until);
		if (ret) return ret;
	}
}
int xdev_ext_peer_endpoint_complete(struct xdev_ext_peer_endpoint *e,
	const struct xdev_ext_peer_message *message, int status)
{
	if (!e || !message) return -EINVAL;
	const struct xdev_ext_user_batch *batch = &message->batch;
	enum xdev_ext_peer_role role = message->role;
	struct xdev_ext_user_stage *user = xdev_ext_peer_endpoint_user(e, role);
	unsigned int unit = role == XDEV_EXT_PEER_PRODUCER ? 0 : 1;
	int ret;
	if (!user || !batch || batch->slot >= XDEV_EXT_USER_RING_MAX || status > 0) return -EINVAL;
	if (message->origin != e->origin) return -ESTALE;
	if (e->error) return e->error;
	if (!e->held[unit][batch->slot].active ||
	    e->held[unit][batch->slot].ticket != batch->ticket ||
	    e->held[unit][batch->slot].batch_id != batch->batch_id ||
	    e->held[unit][batch->slot].key != batch->key ||
	    e->held[unit][batch->slot].arg != batch->arg ||
	    e->held[unit][batch->slot].nr_frames != batch->nr_frames) return -ESTALE;
	for (__u32 i = 0; i < batch->nr_frames; i++) {
		const struct xdev_ext_user_frame *f = &e->held[unit][batch->slot].frames[i];
		if (batch->data[i] || f->umem_addr != batch->f[i].umem_addr ||
		    f->data_off != batch->f[i].data_off || f->data_len != batch->f[i].data_len ||
		    f->capacity != batch->f[i].capacity) return -ESTALE;
	}
	ret = xdev_ext_user_stage_complete(user, batch, status);
	if (!ret) {
		e->held[unit][batch->slot].active = false;
		if (status < 0) e->error = status;
	} else if (ret != -ENOSPC && ret != -EINVAL)
		e->error = ret; /* A KICK error can follow publication: never retry it. */
	return ret;
}
int xdev_ext_peer_endpoint_stop(struct xdev_ext_peer_endpoint *e)
{ return e && e->session ? xdev_ext_session_stop(e->session) : -EINVAL; }
int xdev_ext_peer_endpoint_close(struct xdev_ext_peer_endpoint *e)
{
	int ret;
	if (!e) return -EINVAL;
	/* An external metadata owner may still enqueue/replay work. Refusing a
	 * whole endpoint close retains its payload/control fds as well as USER
	 * mappings; it does not infer detach from a successful payload STOP. */
	if (xdev_ext__user_ctl_attached(e->producer) ||
	    xdev_ext__user_ctl_attached(e->terminal)) return -EBUSY;
	if (e->session) {
		ret = xdev_ext_session_close(e->session);
		if (ret) return ret;
		e->session = NULL;
	}
	if (e->producer) {
		ret = xdev_ext_user_stage_close(e->producer);
		if (ret) return ret;
		e->producer = NULL;
	}
	if (e->terminal) {
		ret = xdev_ext_user_stage_close(e->terminal);
		if (ret) return ret;
		e->terminal = NULL;
	}
	free(e);
	return 0;
}
