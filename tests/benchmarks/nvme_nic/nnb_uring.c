// SPDX-License-Identifier: GPL-2.0
/*
 * Strong io_uring baseline of the NVMe<->NIC eval.  Each of qd unit slots is
 * one buffer registered once: [NXP2 headers of the unit | payload].
 *   forward  READ_FIXED of the unit, then SENDMSG_ZC with
 *            IORING_RECVSEND_FIXED_BUF (registered vector: header, payload
 *            span, ...) and UDP GSO, one send per GSO run of datagrams.  A
 *            slot is reused only after every send's NOTIF.  ZC_COPIED usage
 *            reports are counted; SEND_ZC success alone is not zero copy.
 *   reverse  READV_FIXED per datagram (header slot + payload position), posted
 *            as IOSQE_IO_LINK chains of up to U_RECV_WINDOW receives, one
 *            chain at a time, so datagram k lands in receive k; then
 *            WRITE_FIXED of the whole unit once its datagrams are in place.
 * Requires a kernel with SENDMSG_ZC fixed vectors and READV_FIXED (6.15+);
 * a kernel or liburing without them refuses with exit 4 before any trial.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "nnb.h"

#ifdef NNB_HAVE_URING
/* The checked-in UAPI names the opcodes; no numeric guessing. */
#include "../../../kernel/include/uapi/linux/io_uring.h"
#include <liburing.h>

#define U_RING_ENTRIES	4096U
#define U_RECV_WINDOW	256U
enum { U_READ = 1, U_SEND, U_RECV, U_WRITE };

struct uslot {
	unsigned char *base, *hdrs, *payload;
	size_t bytes;
	uint64_t unit;
	uint32_t sends_total, next_send, results, notifs_due, recvs_done;
	int busy, read_done;
	struct msghdr *msgs;
	struct iovec *iov;	/* forward: per send; reverse: 2 per datagram */
};

struct upriv {
	struct io_uring ring;
	int ring_ok, registered, fd, sock;
	unsigned outstanding;		/* CQEs still owed by the kernel */
	unsigned cq_entries;
	struct uslot slot[NNB_MAX_QD];
};

static uint64_t ud(unsigned kind, unsigned slot, uint64_t idx)
{
	return (uint64_t)kind << 56 | (uint64_t)slot << 40 | idx;
}

static int u_submit(struct upriv *p)
{
	int n;

	do {
		n = io_uring_submit(&p->ring);
	} while (n == -EINTR);
	return n < 0 ? n : 0;
}

static struct io_uring_sqe *u_sqe(struct upriv *p)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);

	if (!sqe && !u_submit(p))
		sqe = io_uring_get_sqe(&p->ring);
	return sqe;
}

/*
 * Opcodes this arm issues, from the running kernel's probe.  SENDMSG_ZC exists
 * from 6.1, but IORING_RECVSEND_FIXED_BUF on it (a registered vector) only
 * from 6.15, which a probe cannot show; READV_FIXED arrived in the same
 * release, so both directions require it and 6.1..6.14 refuse before a trial
 * instead of failing one with -EINVAL.
 */
static int uring_kernel_ok(struct io_uring_probe *probe, int reverse)
{
	return io_uring_opcode_supported(probe, IORING_OP_READ_FIXED) &&
	       io_uring_opcode_supported(probe, IORING_OP_WRITE_FIXED) &&
	       io_uring_opcode_supported(probe, IORING_OP_READV_FIXED) &&
	       (reverse || io_uring_opcode_supported(probe, IORING_OP_SENDMSG_ZC));
}

static int uring_setup(struct nnb_arm *a)
{
	const struct nnb_cfg *c = a->c;
	const struct nnb_geom *g = a->g;
	struct upriv *p = calloc(1, sizeof(*p));
	struct io_uring_probe *probe;
	struct iovec reg[NNB_MAX_QD];
	size_t hdr_bytes = ((size_t)g->dgrams_per_unit * NNB_HDR_LEN + 4095) & ~(size_t)4095;
	uint32_t sends = g->groups_per_unit * ((g->dgrams - 1) / g->gso_dgrams + 1);
	int ok;

	if (!p)
		return -ENOMEM;
	a->priv = p;
	p->fd = p->sock = -1;
	a->effective_qd = c->qd;
	a->inflight_bytes = (uint64_t)c->qd * g->size;
	p->fd = open(c->source, (c->reverse ? O_RDWR : O_RDONLY) | O_CLOEXEC |
		     (c->direct ? O_DIRECT : 0));
	p->sock = nnb_udp_socket(a, !c->reverse, !c->reverse);
	if (p->fd < 0 || p->sock < 0) {
		nnb_diag(a, "source/socket: %s", strerror(p->fd < 0 ? errno : -p->sock));
		return -ENODEV;
	}
	if (c->reverse) {
		int want = (int)((uint64_t)c->qd * g->size + (8U << 20) > (1U << 30) ?
				 (1U << 30) : (uint64_t)c->qd * g->size + (8U << 20));

		if (setsockopt(p->sock, SOL_SOCKET, SO_RCVBUFFORCE, &want, sizeof(want)))
			setsockopt(p->sock, SOL_SOCKET, SO_RCVBUF, &want, sizeof(want));
	}
	if (io_uring_queue_init(U_RING_ENTRIES, &p->ring, 0) < 0) {
		nnb_diag(a, "io_uring_queue_init refused");
		return -EOPNOTSUPP;
	}
	p->ring_ok = 1;
	p->cq_entries = *p->ring.cq.kring_entries;
	probe = io_uring_get_probe_ring(&p->ring);
	ok = probe && uring_kernel_ok(probe, c->reverse);
	free(probe);
	if (!ok) {
		nnb_diag(a, "kernel lacks READ/WRITE_FIXED, READV_FIXED (6.15 fixed vectors)%s",
			 c->reverse ? "" : " or SENDMSG_ZC");
		return -EOPNOTSUPP;
	}
	for (unsigned i = 0; i < c->qd; i++) {
		struct uslot *s = &p->slot[i];

		s->bytes = hdr_bytes + g->size;
		s->base = nnb_alloc(s->bytes);
		s->msgs = calloc(c->reverse ? 1 : sends, sizeof(*s->msgs));
		s->iov = calloc(2 * (size_t)(c->reverse ? g->dgrams_per_unit :
					     sends * (size_t)g->gso_dgrams), sizeof(*s->iov));
		if (!s->base || !s->msgs || !s->iov)
			return -ENOMEM;
		s->hdrs = s->base;
		s->payload = s->base + hdr_bytes;
		s->sends_total = sends;
		nnb_fill_headers(g, s->hdrs, a->wire_session);
		reg[i] = (struct iovec){ s->base, s->bytes };
	}
	if (io_uring_register_buffers(&p->ring, reg, c->qd) < 0) {
		nnb_diag(a, "buffer registration refused (memlock?)");
		return -EOPNOTSUPP;
	}
	p->registered = 1;
	a->registrations = 1;
	return 0;
}

static int queue_read(struct nnb_arm *a, struct upriv *p, unsigned i, const struct nnb_trial *t,
		      uint64_t u)
{
	struct uslot *s = &p->slot[i];
	struct io_uring_sqe *sqe = u_sqe(p);
	uint64_t dev = a->c->slba * a->c->lba + nnb_unit_offset(a, t, u);

	if (!sqe)
		return -EBUSY;
	s->unit = u, s->busy = 1, s->read_done = 0;
	s->next_send = s->results = s->notifs_due = 0;
	nnb_stamp(t->lat_start, u, nnb_now());
	io_uring_prep_read_fixed(sqe, p->fd, s->payload, a->g->size, dev, (int)i);
	sqe->user_data = ud(U_READ, i, u);
	p->outstanding++;
	return 0;
}

/* Queue sends of read-complete slots while the CQ can hold their CQEs. */
static int pump_sends(struct nnb_arm *a, struct upriv *p, struct nnb_trial *t)
{
	const struct nnb_geom *g = a->g;
	uint32_t per_group = (g->dgrams - 1) / g->gso_dgrams + 1;

	for (unsigned i = 0; i < a->c->qd; i++) {
		struct uslot *s = &p->slot[i];

		while (s->busy && s->read_done && s->next_send < s->sends_total &&
		       p->outstanding + 2 <= p->cq_entries) {
			uint32_t k = s->next_send / per_group, j0 = (s->next_send % per_group) * g->gso_dgrams;
			uint32_t n = g->dgrams - j0 < g->gso_dgrams ? g->dgrams - j0 : g->gso_dgrams;
			struct iovec *iov = s->iov + 2 * (size_t)s->next_send * g->gso_dgrams;
			struct msghdr *msg = &s->msgs[s->next_send];
			struct io_uring_sqe *sqe = u_sqe(p);

			if (!sqe)
				return -EBUSY;
			for (uint32_t d = 0; d < n; d++) {
				uint32_t rel, len;

				nnb_dgram(g, j0 + d, &rel, &len);
				iov[2 * d] = (struct iovec){ s->hdrs +
					((size_t)k * g->dgrams + j0 + d) * NNB_HDR_LEN, NNB_HDR_LEN };
				iov[2 * d + 1] = (struct iovec){ s->payload + (size_t)k * g->group + rel, len };
			}
			*msg = (struct msghdr){ .msg_iov = iov, .msg_iovlen = 2 * n };
			memset(sqe, 0, sizeof(*sqe));
			sqe->opcode = IORING_OP_SENDMSG_ZC;
			sqe->fd = p->sock;
			sqe->addr = (unsigned long)(uintptr_t)msg;
			sqe->len = 1;
			sqe->ioprio = IORING_RECVSEND_FIXED_BUF | IORING_SEND_ZC_REPORT_USAGE;
			sqe->buf_index = (unsigned short)i;
			sqe->user_data = ud(U_SEND, i, s->next_send);
			p->outstanding += 2;	/* result, and NOTIF when MORE */
			s->next_send++;
			t->counts.send_calls++;
		}
	}
	return 0;
}

static uint32_t send_bytes(const struct nnb_geom *g, uint32_t idx)
{
	uint32_t per_group = (g->dgrams - 1) / g->gso_dgrams + 1;
	uint32_t j0 = (idx % per_group) * g->gso_dgrams, bytes = 0;

	for (uint32_t d = j0; d < g->dgrams && d < j0 + g->gso_dgrams; d++) {
		uint32_t rel, len;

		nnb_dgram(g, d, &rel, &len);
		bytes += NNB_HDR_LEN + len;
	}
	return bytes;
}

static int u_wait(struct upriv *p, struct io_uring_cqe **cqe)
{
	struct __kernel_timespec ts = { .tv_sec = 20 };
	int ret;

	do {
		ret = io_uring_wait_cqe_timeout(&p->ring, cqe, &ts);
	} while (ret == -EINTR);
	return ret == -ETIME ? -ETIMEDOUT : ret;
}

static int uring_fwd(struct nnb_arm *a, struct upriv *p, struct nnb_trial *t)
{
	const struct nnb_geom *g = a->g;
	uint64_t next = 0, done = 0;
	int ret = 0;

	for (unsigned i = 0; i < a->c->qd && next < t->units && !ret; i++)
		ret = queue_read(a, p, i, t, next++);
	if (!ret)
		ret = u_submit(p);
	while (!ret && done < t->units) {
		struct io_uring_cqe *cqe;
		unsigned kind, i;
		struct uslot *s;
		uint64_t idx;

		ret = u_wait(p, &cqe);
		if (ret)
			break;
		kind = (unsigned)(cqe->user_data >> 56), i = (unsigned)(cqe->user_data >> 40) & 0xffff;
		idx = cqe->user_data & ((1ULL << 40) - 1);
		s = &p->slot[i];
		t->counts.cqes++;
		p->outstanding--;
		if (i >= a->c->qd || !s->busy) {
			ret = -EPROTO;
		} else if (kind == U_READ) {
			if (cqe->res != (int)g->size || idx != s->unit)
				ret = cqe->res < 0 ? cqe->res : -EIO;
			s->read_done = 1;
			t->counts.read_ops++, t->counts.read_bytes += g->size;
			nnb_set_unit_gen(g, s->hdrs, nnb_unit_gen(t, g, s->unit));
		} else if (kind == U_SEND && (cqe->flags & IORING_CQE_F_NOTIF)) {
			/* REPORT_USAGE: the notification says whether the stack copied. */
			if ((uint32_t)cqe->res & ~IORING_NOTIF_USAGE_ZC_COPIED)
				ret = -EPROTO;
			t->counts.notifs++;
			if ((uint32_t)cqe->res & IORING_NOTIF_USAGE_ZC_COPIED)
				t->counts.zc_copied++;
			s->notifs_due--;
		} else if (kind == U_SEND) {
			uint32_t want = send_bytes(g, (uint32_t)idx);

			if (cqe->res != (int)want)
				ret = cqe->res < 0 ? cqe->res : -EIO;
			if (cqe->flags & IORING_CQE_F_MORE)
				s->notifs_due++;
			else
				p->outstanding--;	/* no NOTIF follows */
			s->results++;
			t->counts.send_bytes += want;
			t->counts.datagrams += (want - 1) / (NNB_HDR_LEN + g->seg) + 1;
		} else {
			ret = -EPROTO;
		}
		io_uring_cqe_seen(&p->ring, cqe);
		if (ret)
			break;
		/* Release: every result seen and no NOTIF still owed for this slot. */
		if (s->read_done && s->results == s->sends_total && !s->notifs_due) {
			nnb_stamp(t->lat_done, s->unit, nnb_now());
			s->busy = 0;
			done++;
			if (next < t->units)
				ret = queue_read(a, p, i, t, next++);
		}
		if (!ret)
			ret = pump_sends(a, p, t);
		if (!ret)
			ret = u_submit(p);
	}
	if (!ret)
		t->t_release = nnb_now();
	return ret;
}

/* One receive SQE of a chain; never submits, so the chain stays whole. */
static struct io_uring_sqe *queue_recv(struct nnb_arm *a, struct upriv *p, unsigned i, uint32_t d)
{
	const struct nnb_geom *g = a->g;
	struct uslot *s = &p->slot[i];
	uint32_t k = d / g->dgrams, j = d % g->dgrams, rel, len;
	struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
	struct iovec *iov = &s->iov[2 * (size_t)d];

	if (!sqe)
		return NULL;
	nnb_dgram(g, j, &rel, &len);
	iov[0] = (struct iovec){ s->hdrs + (size_t)d * NNB_HDR_LEN, NNB_HDR_LEN };
	iov[1] = (struct iovec){ s->payload + (size_t)k * g->group + rel, len };
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_READV_FIXED;
	sqe->fd = p->sock;
	sqe->addr = (unsigned long)(uintptr_t)iov;
	sqe->len = 2;
	sqe->off = 0;		/* a socket refuses any other position */
	sqe->buf_index = (unsigned short)i;
	sqe->user_data = ud(U_RECV, i, d);
	p->outstanding++;
	return sqe;
}

/*
 * Receives complete in a defined order only when they are linked: several
 * READV_FIXED requests outstanding on one socket each arm a non-exclusive poll
 * entry at the head of the wait queue (io_uring/poll.c, add_wait_queue), so a
 * wakeup reaches the newest request first and it takes the oldest datagram.
 * A linked request is issued only after the previous one completed, so the
 * k-th receive of a chain takes the k-th datagram in socket order.  The next
 * chain is posted only when every receive of this one completed (@owed == 0),
 * and a chain is never split across a submit, since links end at a submit
 * boundary.  A short or failed receive breaks the chain (-ECANCELED for the
 * rest) and fails the trial.  Order on a READV_FIXED kernel is unverified.
 */
static int post_recvs(struct nnb_arm *a, struct upriv *p, uint64_t *posted, uint64_t total,
		      unsigned *owed)
{
	const struct nnb_geom *g = a->g;
	unsigned n;
	int ret;

	if (*owed || *posted >= total)
		return 0;
	n = total - *posted < U_RECV_WINDOW ? (unsigned)(total - *posted) : U_RECV_WINDOW;
	/* Every receive of the chain must find a CQ entry (writes take one each too). */
	if (p->outstanding + n + a->c->qd > p->cq_entries)
		return 0;
	if (io_uring_sq_space_left(&p->ring) < n && (ret = u_submit(p)))
		return ret;
	if (io_uring_sq_space_left(&p->ring) < n)
		return -EBUSY;
	for (unsigned i = 0; i < n; i++) {
		struct io_uring_sqe *sqe = queue_recv(a, p, (unsigned)(*posted / g->dgrams_per_unit),
						      (uint32_t)(*posted % g->dgrams_per_unit));

		if (!sqe)
			return -EBUSY;	/* cannot happen: space was checked */
		if (i + 1 < n)
			sqe->flags |= IOSQE_IO_LINK;
		(*posted)++;
	}
	*owed = n;
	return 0;
}

static int uring_rev(struct nnb_arm *a, struct upriv *p, struct nnb_trial *t)
{
	const struct nnb_geom *g = a->g;
	int ret = 0;

	for (uint32_t b = 0; b < t->bursts && !ret; b++) {
		uint64_t u0 = (uint64_t)b * t->burst_units;
		unsigned n = (unsigned)(t->units - u0 < t->burst_units ? t->units - u0 : t->burst_units);
		uint64_t total = (uint64_t)n * g->dgrams_per_unit, posted = 0, written = 0;
		unsigned owed = 0;

		for (unsigned i = 0; i < n; i++)
			p->slot[i] = (struct uslot){ .base = p->slot[i].base, .hdrs = p->slot[i].hdrs,
				.payload = p->slot[i].payload, .bytes = p->slot[i].bytes,
				.msgs = p->slot[i].msgs, .iov = p->slot[i].iov, .unit = u0 + i, .busy = 1 };
		/* Receives are posted before GO; datagrams land at their final position. */
		ret = post_recvs(a, p, &posted, total, &owed);
		if (!ret)
			ret = u_submit(p);
		if (!ret)
			ret = nnb_rev_go(a, t, b);
		while (!ret && written < n) {
			struct io_uring_cqe *cqe;
			unsigned kind, i;
			uint64_t idx;
			struct uslot *s;

			ret = u_wait(p, &cqe);
			if (ret)
				break;
			kind = (unsigned)(cqe->user_data >> 56), i = (unsigned)(cqe->user_data >> 40) & 0xffff;
			idx = cqe->user_data & ((1ULL << 40) - 1);
			s = &p->slot[i];
			t->counts.cqes++;
			p->outstanding--;
			if (i >= n) {
				ret = -EPROTO;
			} else if (kind == U_RECV) {
				uint32_t k = (uint32_t)idx / g->dgrams, j = (uint32_t)idx % g->dgrams;
				struct nnb_seg seg;

				owed--;
				t->counts.recv_calls++;
				/* In socket order by the chain; any other datagram fails the trial. */
				if (cqe->res < 0 || nnb_hdr_parse(s->hdrs + idx * NNB_HDR_LEN,
								  (size_t)cqe->res, g, &seg) ||
				    seg.session != a->wire_session ||
				    seg.gen != (uint32_t)(nnb_unit_gen(t, g, s->unit) + k) || seg.index != j)
					ret = cqe->res < 0 ? cqe->res : -EPROTO;
				t->counts.datagrams++;
				if (!ret && !s->recvs_done)	/* first datagram of the unit */
					nnb_stamp(t->lat_start, s->unit, nnb_now());
				if (!ret && ++s->recvs_done == g->dgrams_per_unit) {
					struct io_uring_sqe *sqe = u_sqe(p);

					if (!sqe) {
						ret = -EBUSY;
					} else {
						io_uring_prep_write_fixed(sqe, p->fd, s->payload, g->size,
							a->c->slba * a->c->lba + nnb_unit_offset(a, t, s->unit),
							(int)i);
						sqe->user_data = ud(U_WRITE, i, s->unit);
						p->outstanding++;
					}
				}
			} else if (kind == U_WRITE) {
				if (cqe->res != (int)g->size)
					ret = cqe->res < 0 ? cqe->res : -EIO;
				else
					nnb_stamp(t->lat_done, s->unit, nnb_now());
				written++;
				t->counts.write_ops++, t->counts.write_bytes += g->size;
			} else {
				ret = -EPROTO;
			}
			io_uring_cqe_seen(&p->ring, cqe);
			if (!ret)
				ret = post_recvs(a, p, &posted, total, &owed);
			if (!ret)
				ret = u_submit(p);
		}
		if (!ret && b + 1 == t->bursts)
			t->t_release = nnb_now();
		if (!ret)
			ret = nnb_rev_sent(a, t, b);
	}
	return ret;
}

static int uring_run(struct nnb_arm *a, struct nnb_trial *t)
{
	struct upriv *p = a->priv;
	int ret = a->c->reverse ? uring_rev(a, p, t) : uring_fwd(a, p, t);

	if (ret) {
		nnb_diag(a, "trial %llu: %s", (unsigned long long)t->trial, strerror(-ret));
		/* Accepted operations may still own the slots: never reuse or free them. */
		if (p->outstanding)
			p->registered = -1;
	}
	return ret;
}

static void uring_teardown(struct nnb_arm *a)
{
	struct upriv *p = a->priv;

	if (!p)
		return;
	if (p->registered < 0) {
		/* Unknown accepted ownership: exit keeps the memory; the kernel drains. */
		fprintf(stderr, "nnb_producer: uring slots retained with %u CQEs owed\n", p->outstanding);
		return;
	}
	if (p->ring_ok)
		io_uring_queue_exit(&p->ring);
	for (unsigned i = 0; i < NNB_MAX_QD; i++)
		free(p->slot[i].base), free(p->slot[i].msgs), free(p->slot[i].iov);
	if (p->fd >= 0)
		close(p->fd);
	if (p->sock >= 0)
		close(p->sock);
	free(p);
	a->priv = NULL;
}
#else
static int uring_setup(struct nnb_arm *a)
{
	nnb_diag(a, "built without liburing (make ENABLE_URING=1)");
	return -EOPNOTSUPP;
}
static int uring_run(struct nnb_arm *a, struct nnb_trial *t) { (void)a; (void)t; return -EOPNOTSUPP; }
static void uring_teardown(struct nnb_arm *a) { (void)a; }
#endif

const struct nnb_arm_ops nnb_uring_ops = { "uring", uring_setup, uring_run, uring_teardown };
