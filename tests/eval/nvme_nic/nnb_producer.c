// SPDX-License-Identifier: GPL-2.0
/*
 * nnb_producer - NVMe<->NIC eval producer (reviewer E3).
 *
 * One invocation runs one configuration (direction, unit size, queue depth)
 * for the selected arms: each arm is set up once (buffers registered once,
 * session created once), runs `warmup` trials, then `pairs` trials in a
 * seeded random order per pair, then one untimed integrity trial.  The C peer
 * (nnb_peer) receives or sends the datagrams; its receipts arrive after the
 * trial or burst, never inside the per-datagram path.
 *
 * Forward  NVMe -> NIC: local_release = first read issued .. every send of
 *          every unit locally complete; receipt = .. the peer's count receipt.
 * Reverse  NIC -> NVMe: durable = first GO .. every unit's write completed.
 *
 * Idea ported from archive/conduit-legacy/eval/benchmark-code/bench_pipeline.c
 * (three-arm read->send comparison over the same file and socket; archived
 * file, untracked, sha256
 * 0dbf6975ab9bb2b080f2d5c397504ce15943dbc84b78fb505c89a41884286204, git blob
 * 200250e0727986933f9773aed9eac09c7fc8b89d).  Its obsolete UMEM opcodes,
 * TCP sink, single-buffer reuse and in-loop printf timing are not imported.
 *
 * Exit status: 0 every trial validated, 1 failure, 2 usage, 4 capability
 * refused before the first trial.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "nnb.h"

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif

/*
 * Negative validation only (--fault, requires --correctness): posix arm, unit 0;
 * thread-create fails pthread_create of forward thread qd/2 at setup.
 */
enum { FAULT_NONE, FAULT_SKIP_DGRAM, FAULT_DUP_DGRAM, FAULT_CORRUPT, FAULT_SKIP_WRITE,
       FAULT_THREAD_CREATE, FAULT_COUNT };
static const char *const fault_names[] = { "none", "skip-datagram", "duplicate-datagram",
					   "corrupt-payload", "skip-write", "thread-create" };
static int nnb_fault;

uint64_t nnb_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

uint64_t nnb_unit_gen(const struct nnb_trial *t, const struct nnb_geom *g, uint64_t u)
{
	return t->first_gen + u * g->groups_per_unit;
}

/* Window byte offset of unit @u of trial @t. */
uint64_t nnb_unit_offset(const struct nnb_arm *a, const struct nnb_trial *t, uint64_t u)
{
	return nnb_gen_offset(a->g, nnb_unit_gen(t, a->g, u));
}

void *nnb_alloc(size_t bytes)
{
	void *p = NULL;

	bytes = (bytes + 4095) & ~(size_t)4095;
	if (posix_memalign(&p, 4096, bytes))
		return NULL;
	memset(p, 0, bytes);
	return p;
}

/* All NXP2 headers of one unit: [group][datagram], generations set per unit. */
int nnb_fill_headers(const struct nnb_geom *g, unsigned char *hdrs, uint64_t session)
{
	for (uint32_t k = 0; k < g->groups_per_unit; k++)
		for (uint32_t j = 0; j < g->dgrams; j++)
			nnb_hdr_encode(hdrs + ((size_t)k * g->dgrams + j) * NNB_HDR_LEN, g,
				       session, 1, j);
	return 0;
}

void nnb_set_unit_gen(const struct nnb_geom *g, unsigned char *hdrs, uint64_t gen0)
{
	for (uint32_t k = 0; k < g->groups_per_unit; k++)
		for (uint32_t j = 0; j < g->dgrams; j++)
			nnb_hdr_set_gen(hdrs + ((size_t)k * g->dgrams + j) * NNB_HDR_LEN,
					(uint32_t)(gen0 + k));
}

static int ipv4(const char *s, struct in_addr *a)
{
	return s && inet_pton(AF_INET, s, a) == 1 ? 0 : -EINVAL;
}

/*
 * A UDP socket of this arm: bound to local_ip:port, optionally connected to
 * the peer data endpoint, with GSO segments of one datagram when @gso.
 */
int nnb_udp_socket(const struct nnb_arm *a, int connect_peer, int gso)
{
	const struct nnb_cfg *c = a->c;
	struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons(a->port) };
	struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = htons(c->peer_port) };
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), one = 1;

	if (fd < 0)
		return -errno;
	if (ipv4(c->local_ip, &local.sin_addr) || ipv4(c->peer_ip, &peer.sin_addr) ||
	    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
	    bind(fd, (struct sockaddr *)&local, sizeof(local)) ||
	    (connect_peer && connect(fd, (struct sockaddr *)&peer, sizeof(peer)))) {
		int err = errno ? -errno : -EINVAL;

		close(fd);
		return err;
	}
	if (gso && a->g->gso_dgrams > 1) {
		int size = (int)(NNB_HDR_LEN + a->g->seg);

		if (setsockopt(fd, IPPROTO_UDP, UDP_SEGMENT, &size, sizeof(size))) {
			int err = -errno;

			close(fd);
			return err;
		}
	}
	return fd;
}

int nnb_rev_go(struct nnb_arm *a, const struct nnb_trial *t, uint32_t burst)
{
	uint64_t first = t->burst_units * (uint64_t)burst, n = t->burst_units;
	uint64_t f[4];

	if (first + n > t->units)
		n = t->units - first;
	f[0] = t->trial, f[1] = burst, f[2] = nnb_unit_gen(t, a->g, first);
	f[3] = n * a->g->groups_per_unit;
	return nnb_msg_send(a->ctl, a->c->run_id, NNB_GO, f, 4);
}

/* The peer's receipt for one burst, read after the burst completed locally. */
int nnb_rev_sent(struct nnb_arm *a, const struct nnb_trial *t, uint32_t burst)
{
	uint64_t first = t->burst_units * (uint64_t)burst, n = t->burst_units;
	struct nnb_msg m;
	int ret = nnb_msg_expect(a->ctl, a->c->run_id, NNB_SENT, &m, 30000);

	if (first + n > t->units)
		n = t->units - first;
	if (ret)
		return ret;
	if (m.f[0] != t->trial || m.f[1] != burst || m.f[4] ||
	    m.f[2] != n * a->g->dgrams_per_unit ||
	    m.f[3] != n * (a->g->size + (uint64_t)a->g->dgrams_per_unit * NNB_HDR_LEN))
		return -EPROTO;
	return 0;
}

/* --- posix: O_DIRECT pread + GSO sendmsg / recvmmsg + O_DIRECT pwrite --- */

struct posix_slot {
	struct nnb_arm *a;
	unsigned id, nthreads;
	pthread_t thread;
	int sock, pipe[2];
	unsigned char *buf, *hdrs;
	struct iovec *iov;
	struct mmsghdr *msgs;
	struct nnb_counts c;
	int err;
};

struct posix_priv {
	int fd, splice, started, stop;
	unsigned nthreads;
	pthread_mutex_t launch;		/* held while threads are created */
	pthread_barrier_t start, done;
	struct nnb_trial *t;
	struct posix_slot slot[NNB_MAX_QD];
};

static int full_pio(int fd, unsigned char *p, size_t n, off_t off, int writing)
{
	while (n) {
		ssize_t r = writing ? pwrite(fd, p, n, off) : pread(fd, p, n, off);

		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return r ? -errno : -EIO;
		p += r, n -= (size_t)r, off += r;
	}
	return 0;
}

static int send_unit(struct posix_slot *s, const struct nnb_trial *t, uint64_t u)
{
	const struct nnb_geom *g = s->a->g;

	nnb_set_unit_gen(g, s->hdrs, nnb_unit_gen(t, g, u));
	for (uint32_t k = 0; k < g->groups_per_unit; k++)
		for (uint32_t j0 = 0; j0 < g->dgrams; j0 += g->gso_dgrams) {
			uint32_t n = g->dgrams - j0 < g->gso_dgrams ? g->dgrams - j0 : g->gso_dgrams;
			struct msghdr msg = { .msg_iov = s->iov, .msg_iovlen = 2 * n };
			size_t want = 0;
			ssize_t r;

			for (uint32_t i = 0; i < n; i++) {
				uint32_t rel, len;

				nnb_dgram(g, j0 + i, &rel, &len);
				s->iov[2 * i] = (struct iovec){ s->hdrs +
					((size_t)k * g->dgrams + j0 + i) * NNB_HDR_LEN, NNB_HDR_LEN };
				s->iov[2 * i + 1] = (struct iovec){ s->buf + (size_t)k * g->group + rel, len };
				want += NNB_HDR_LEN + len;
			}
			if (u == 0 && k == 0 && j0 == 0 && nnb_fault == FAULT_SKIP_DGRAM) {
				/* Drop the first datagram of the run: GSO sends the rest. */
				want -= s->iov[0].iov_len + s->iov[1].iov_len;
				msg.msg_iov += 2, msg.msg_iovlen -= 2;
				if (!msg.msg_iovlen)
					continue;
			}
			do {
				r = sendmsg(s->sock, &msg, 0);
			} while (r < 0 && errno == EINTR);
			if (r != (ssize_t)want)
				return r < 0 ? -errno : -EIO;
			s->c.send_calls++, s->c.send_bytes += want, s->c.datagrams += n;
			if (u == 0 && k == 0 && j0 == 0 && nnb_fault == FAULT_DUP_DGRAM) {
				struct msghdr one = { .msg_iov = s->iov, .msg_iovlen = 2 };

				if (sendmsg(s->sock, &one, 0) < 0)
					return -errno;
			}
		}
	return 0;
}

/* Datagrams of one group through a pipe: header written, payload spliced. */
static int splice_unit(struct posix_slot *s, int fd, uint64_t dev_off, const struct nnb_trial *t,
		       uint64_t u)
{
	const struct nnb_geom *g = s->a->g;

	nnb_set_unit_gen(g, s->hdrs, nnb_unit_gen(t, g, u));
	for (uint32_t k = 0; k < g->groups_per_unit; k++)
		for (uint32_t j = 0; j < g->dgrams; j++) {
			uint32_t rel, len;
			loff_t off;
			size_t left;
			ssize_t r;

			nnb_dgram(g, j, &rel, &len);
			off = (loff_t)(dev_off + (uint64_t)k * g->group + rel);
			if (write(s->pipe[1], s->hdrs + ((size_t)k * g->dgrams + j) * NNB_HDR_LEN,
				  NNB_HDR_LEN) != NNB_HDR_LEN)
				return -EIO;
			for (left = len; left; left -= (size_t)r) {
				r = splice(fd, &off, s->pipe[1], NULL, left, SPLICE_F_MOVE);
				if (r < 0 && errno == EINTR) {
					r = 0;
					continue;
				}
				if (r <= 0)
					return r ? -errno : -EIO;
				s->c.splice_calls++;
			}
			/* One splice into the socket ends exactly one datagram. */
			r = splice(s->pipe[0], NULL, s->sock, NULL, NNB_HDR_LEN + len, SPLICE_F_MOVE);
			s->c.splice_calls++;
			if (r != (ssize_t)(NNB_HDR_LEN + len))
				return r < 0 ? -errno : -EIO;
			s->c.send_calls++, s->c.send_bytes += NNB_HDR_LEN + len, s->c.datagrams++;
			s->c.read_bytes += len;
		}
	s->c.read_ops++;
	return 0;
}

static void *posix_thread(void *arg)
{
	struct posix_slot *s = arg;
	struct posix_priv *p = s->a->priv;
	const struct nnb_cfg *c = s->a->c;
	const struct nnb_geom *g = s->a->g;

	/* Join no barrier before every thread exists: setup may resize them. */
	pthread_mutex_lock(&p->launch);
	pthread_mutex_unlock(&p->launch);
	for (;;) {
		pthread_barrier_wait(&p->start);
		if (p->stop)
			break;
		memset(&s->c, 0, sizeof(s->c));
		s->err = 0;
		for (uint64_t u = s->id; u < p->t->units && !s->err; u += s->nthreads) {
			uint64_t dev = c->slba * c->lba + nnb_unit_offset(s->a, p->t, u);

			nnb_stamp(p->t->lat_start, u, nnb_now());
			if (p->splice) {
				s->err = splice_unit(s, p->fd, dev, p->t, u);
			} else {
				s->err = full_pio(p->fd, s->buf, g->size, (off_t)dev, 0);
				s->c.read_ops++, s->c.read_bytes += g->size;
				if (u == 0 && nnb_fault == FAULT_CORRUPT)
					s->buf[17] ^= 1;
				if (!s->err)
					s->err = send_unit(s, p->t, u);
			}
			if (!s->err)
				nnb_stamp(p->t->lat_done, u, nnb_now());
		}
		pthread_barrier_wait(&p->done);
	}
	return NULL;
}

static int posix_common_setup(struct nnb_arm *a, int splice_arm)
{
	const struct nnb_cfg *c = a->c;
	const struct nnb_geom *g = a->g;
	struct posix_priv *p = calloc(1, sizeof(*p));
	unsigned n = c->reverse ? 1 : c->qd;
	int flags = c->reverse ? O_RDWR : O_RDONLY;

	if (!p)
		return -ENOMEM;
	a->priv = p;
	p->splice = splice_arm;
	p->nthreads = n;
	a->effective_qd = n;
	/* splice holds one datagram per thread in its pipe; posix reverse one unit. */
	a->inflight_bytes = splice_arm ? (uint64_t)n * g->seg : (uint64_t)n * g->size;
	/* splice reads the page cache by construction; it is labelled buffered. */
	p->fd = open(c->source, flags | O_CLOEXEC | (c->direct && !splice_arm ? O_DIRECT : 0));
	if (p->fd < 0) {
		nnb_diag(a, "open %s: %s", c->source, strerror(errno));
		return -errno;
	}
	for (unsigned i = 0; i < n; i++) {
		struct posix_slot *s = &p->slot[i];

		s->a = a, s->id = i, s->nthreads = n, s->pipe[0] = s->pipe[1] = -1;
		s->buf = splice_arm ? NULL : nnb_alloc(g->size);
		s->hdrs = nnb_alloc((size_t)g->dgrams_per_unit * NNB_HDR_LEN);
		s->iov = calloc(2 * (size_t)(c->reverse ? 64 : g->gso_dgrams), sizeof(*s->iov));
		s->msgs = c->reverse ? calloc(64, sizeof(*s->msgs)) : NULL;
		if ((!splice_arm && !s->buf) || !s->hdrs || !s->iov || (c->reverse && !s->msgs))
			return -ENOMEM;
		nnb_fill_headers(g, s->hdrs, a->wire_session);
		/* Distinct source ports keep each thread on its own socket lock. */
		s->sock = -1;
		{
			struct nnb_arm tmp = *a;

			tmp.port = (uint16_t)(a->port + (c->reverse ? 0 : i * NNB_MAX_ARMS));
			s->sock = nnb_udp_socket(&tmp, !c->reverse, !splice_arm);
		}
		if (s->sock < 0) {
			nnb_diag(a, "UDP socket: %s", strerror(-s->sock));
			return s->sock;
		}
		if (c->reverse) {
			/* Absorb one burst while the synchronous loop is inside pwrite. */
			int want = (int)((uint64_t)c->qd * g->size + (8U << 20) > (1U << 30) ?
					 (1U << 30) : (uint64_t)c->qd * g->size + (8U << 20));
			struct timeval tv = { .tv_sec = 5 };

			if (setsockopt(s->sock, SOL_SOCKET, SO_RCVBUFFORCE, &want, sizeof(want)))
				setsockopt(s->sock, SOL_SOCKET, SO_RCVBUF, &want, sizeof(want));
			setsockopt(s->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		}
		if (splice_arm && pipe2(s->pipe, O_CLOEXEC))
			return -errno;
	}
	if (c->reverse)
		return 0;
	if (pthread_mutex_init(&p->launch, NULL) ||
	    pthread_barrier_init(&p->start, NULL, n + 1) ||
	    pthread_barrier_init(&p->done, NULL, n + 1))
		return -ENOMEM;
	pthread_mutex_lock(&p->launch);
	for (unsigned i = 0; i < n; i++) {
		if ((nnb_fault == FAULT_THREAD_CREATE && i == n / 2) ||
		    pthread_create(&p->slot[i].thread, NULL, posix_thread, &p->slot[i])) {
			/*
			 * The started threads still wait on the launch lock: size the
			 * barriers for them so teardown's stop round completes.
			 */
			pthread_barrier_destroy(&p->start), pthread_barrier_destroy(&p->done);
			if (pthread_barrier_init(&p->start, NULL, (unsigned)p->started + 1) ||
			    pthread_barrier_init(&p->done, NULL, (unsigned)p->started + 1))
				abort();	/* no safe way to release them */
			p->stop = 1;
			p->nthreads = (unsigned)p->started;
			pthread_mutex_unlock(&p->launch);
			nnb_diag(a, "pthread_create of thread %u failed", i);
			return -EAGAIN;
		}
		p->started++;
	}
	pthread_mutex_unlock(&p->launch);
	return 0;
}

static int posix_setup(struct nnb_arm *a) { return posix_common_setup(a, 0); }
static int splice_setup(struct nnb_arm *a) { return posix_common_setup(a, 1); }

/* Receive unit @u of @t in order into s->buf; any other datagram fails. */
static int recv_unit(struct posix_slot *s, const struct nnb_trial *t, uint64_t u)
{
	const struct nnb_geom *g = s->a->g;
	uint64_t gen0 = nnb_unit_gen(t, g, u);
	uint32_t next = 0;

	while (next < g->dgrams_per_unit) {
		uint32_t n = g->dgrams_per_unit - next < 64 ? g->dgrams_per_unit - next : 64;
		int r;

		for (uint32_t i = 0; i < n; i++) {
			uint32_t k = (next + i) / g->dgrams, j = (next + i) % g->dgrams, rel, len;

			nnb_dgram(g, j, &rel, &len);
			s->iov[2 * i] = (struct iovec){ s->hdrs + (size_t)i * NNB_HDR_LEN, NNB_HDR_LEN };
			s->iov[2 * i + 1] = (struct iovec){ s->buf + (size_t)k * g->group + rel, len };
			s->msgs[i] = (struct mmsghdr){ .msg_hdr = { .msg_iov = &s->iov[2 * i],
							     .msg_iovlen = 2 } };
		}
		do {
			r = recvmmsg(s->sock, s->msgs, n, MSG_WAITFORONE, NULL);
		} while (r < 0 && errno == EINTR);
		if (r <= 0)
			return r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) ? -ETIMEDOUT :
			       r < 0 ? -errno : -EIO;
		if (!next)
			nnb_stamp(t->lat_start, u, nnb_now());	/* first datagram of the unit */
		s->c.recv_calls++;
		for (int i = 0; i < r; i++) {
			uint32_t k = (next + (uint32_t)i) / g->dgrams, j = (next + (uint32_t)i) % g->dgrams;
			struct nnb_seg seg;

			/* Parse the scratch header against the expected position. */
			if ((s->msgs[i].msg_hdr.msg_flags & MSG_TRUNC) ||
			    nnb_hdr_parse(s->hdrs + (size_t)i * NNB_HDR_LEN, s->msgs[i].msg_len, g, &seg) ||
			    seg.session != s->a->wire_session || seg.gen != (uint32_t)(gen0 + k) ||
			    seg.index != j)
				return -EPROTO;	/* loss, reorder or foreign datagram */
			s->c.datagrams++;
		}
		next += (uint32_t)r;
	}
	return 0;
}

static int posix_run(struct nnb_arm *a, struct nnb_trial *t)
{
	struct posix_priv *p = a->priv;
	const struct nnb_cfg *c = a->c;
	int err = 0;

	if (!c->reverse) {
		p->t = t;
		pthread_barrier_wait(&p->start);
		pthread_barrier_wait(&p->done);
		t->t_release = nnb_now();
		for (unsigned i = 0; i < p->nthreads; i++) {
			struct nnb_counts *s = &p->slot[i].c;

			if (p->slot[i].err && !err) {
				err = p->slot[i].err;
				nnb_diag(a, "thread %u: %s", i, strerror(-err));
			}
			t->counts.read_ops += s->read_ops, t->counts.read_bytes += s->read_bytes;
			t->counts.send_calls += s->send_calls, t->counts.send_bytes += s->send_bytes;
			t->counts.datagrams += s->datagrams, t->counts.splice_calls += s->splice_calls;
		}
		return err;
	}
	{
		struct posix_slot *s = &p->slot[0];

		memset(&s->c, 0, sizeof(s->c));
		for (uint32_t b = 0; b < t->bursts && !err; b++) {
			uint64_t u0 = (uint64_t)b * t->burst_units;

			err = nnb_rev_go(a, t, b);
			for (uint64_t u = u0; !err && u < u0 + t->burst_units && u < t->units; u++) {
				err = recv_unit(s, t, u);
				if (!err && !(u == 0 && nnb_fault == FAULT_SKIP_WRITE))
					err = full_pio(p->fd, s->buf, a->g->size,
						       (off_t)(c->slba * c->lba + nnb_unit_offset(a, t, u)), 1);
				if (!err)
					nnb_stamp(t->lat_done, u, nnb_now());
				s->c.write_ops++, s->c.write_bytes += a->g->size;
			}
			if (b + 1 == t->bursts && !err)
				t->t_release = nnb_now();
			if (!err)
				err = nnb_rev_sent(a, t, b);
		}
		if (err)
			nnb_diag(a, "reverse posix: %s", strerror(-err));
		t->counts.datagrams = s->c.datagrams, t->counts.recv_calls = s->c.recv_calls;
		t->counts.write_ops = s->c.write_ops, t->counts.write_bytes = s->c.write_bytes;
	}
	return err;
}

static void posix_teardown(struct nnb_arm *a)
{
	struct posix_priv *p = a->priv;

	if (!p)
		return;
	if (p->started) {
		p->stop = 1;
		pthread_barrier_wait(&p->start);
		for (int i = 0; i < p->started; i++)
			pthread_join(p->slot[i].thread, NULL);
	}
	for (unsigned i = 0; i < NNB_MAX_QD; i++) {
		struct posix_slot *s = &p->slot[i];

		if (!s->a)
			continue;
		if (s->sock >= 0)
			close(s->sock);
		if (s->pipe[0] >= 0)
			close(s->pipe[0]), close(s->pipe[1]);
		free(s->buf), free(s->hdrs), free(s->iov), free(s->msgs);
	}
	if (p->fd >= 0)
		close(p->fd);
	free(p);
	a->priv = NULL;
}

const struct nnb_arm_ops nnb_posix_ops = { "posix", posix_setup, posix_run, posix_teardown };
const struct nnb_arm_ops nnb_splice_ops = { "splice", splice_setup, posix_run, posix_teardown };

/* --- campaign ------------------------------------------------------------ */

static int window_io(const struct nnb_cfg *c, const struct nnb_geom *g, int poison,
		     int64_t *mismatch)
{
	unsigned char *buf = nnb_alloc(NNB_MAX_SIZE);
	int fd = open(c->source, (poison ? O_WRONLY : O_RDONLY) | O_CLOEXEC |
		      (c->direct ? O_DIRECT : 0));
	int ret = 0;

	*mismatch = -1;
	if (!buf || fd < 0) {
		ret = fd < 0 ? -errno : -ENOMEM;
		goto out;
	}
	if (poison)
		memset(buf, 0xee, NNB_MAX_SIZE);
	for (uint64_t off = 0; off < g->window_bytes && !ret && *mismatch < 0; off += NNB_MAX_SIZE) {
		ret = full_pio(fd, buf, NNB_MAX_SIZE, (off_t)(c->slba * c->lba + off), poison);
		if (!ret && !poison) {
			int64_t at = nnb_gen_check(c->seed, off, buf, NNB_MAX_SIZE);

			if (at >= 0)
				*mismatch = (int64_t)off + at;
		}
	}
	if (!ret && poison && fsync(fd))
		ret = -errno;
out:
	if (fd >= 0)
		close(fd);
	free(buf);
	return ret;
}

static int prepare_window(const struct nnb_cfg *c, const struct nnb_geom *g)
{
	unsigned char *buf = nnb_alloc(NNB_MAX_SIZE);
	int fd = open(c->source, O_WRONLY | O_CLOEXEC | (c->direct ? O_DIRECT : 0)), ret = 0;

	if (!buf || fd < 0) {
		ret = fd < 0 ? -errno : -ENOMEM;
		goto out;
	}
	for (uint64_t off = 0; off < g->window_bytes && !ret; off += NNB_MAX_SIZE) {
		nnb_gen_fill(c->seed, off, buf, NNB_MAX_SIZE);
		ret = full_pio(fd, buf, NNB_MAX_SIZE, (off_t)(c->slba * c->lba + off), 1);
	}
	if (!ret && fsync(fd))
		ret = -errno;
out:
	if (fd >= 0)
		close(fd);
	free(buf);
	return ret;
}

static const struct nnb_arm_ops *arm_ops(const char *name)
{
	static const struct nnb_arm_ops *const all[] = {
		&nnb_posix_ops, &nnb_uring_ops, &nnb_splice_ops, &nnb_session_ops,
	};

	for (unsigned i = 0; i < 4; i++)
		if (!strcmp(all[i]->name, name))
			return all[i];
	return NULL;
}

static uint64_t mix(uint64_t *x)
{
	uint64_t z = (*x += 0x9e3779b97f4a7c15ULL);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static double usec(const struct timeval *tv)
{
	return (double)tv->tv_sec * 1e6 + (double)tv->tv_usec;
}

static void print_counts(const struct nnb_counts *k)
{
	printf("\"read_ops\":%" PRIu64 ",\"read_bytes\":%" PRIu64 ",\"write_ops\":%" PRIu64
	       ",\"write_bytes\":%" PRIu64 ",\"send_calls\":%" PRIu64 ",\"send_bytes\":%" PRIu64
	       ",\"datagrams\":%" PRIu64 ",\"recv_calls\":%" PRIu64 ",\"cqes\":%" PRIu64
	       ",\"notifs\":%" PRIu64 ",\"zc_copied\":%" PRIu64 ",\"splice_calls\":%" PRIu64
	       ",\"batches\":%" PRIu64,
	       k->read_ops, k->read_bytes, k->write_ops, k->write_bytes, k->send_calls,
	       k->send_bytes, k->datagrams, k->recv_calls, k->cqes, k->notifs, k->zc_copied,
	       k->splice_calls, k->batches);
}

static int cmp_u64(const void *x, const void *y)
{
	uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;

	return a < b ? -1 : a > b;
}

/* Nearest-rank percentile num/den of @n sorted samples. */
static uint64_t rank(const uint64_t *v, uint64_t n, uint64_t num, uint64_t den)
{
	uint64_t r = (n * num + den - 1) / den;

	return v[r ? r - 1 : 0];
}

/*
 * Per-unit latencies of a finished trial into @lat (sorted, in place of the
 * start stamps).  Every unit must carry both stamps; a missing one is a defect
 * of the arm, never a sample to drop.
 */
static int unit_latencies(struct nnb_arm *a, uint64_t *start, const uint64_t *done, uint64_t units)
{
	for (uint64_t u = 0; u < units; u++) {
		if (!start[u] || done[u] < start[u]) {
			nnb_diag(a, "unit %" PRIu64 ": latency stamps missing", u);
			return -EPROTO;
		}
		start[u] = done[u] - start[u];
	}
	qsort(start, units, sizeof(*start), cmp_u64);
	return 0;
}

static int capability_errno(int err)
{
	/* Missing devices, kernel features or peer: refused, not a failure. */
	return err == -EOPNOTSUPP || err == -ENODEV || err == -ENOENT || err == -ECONNREFUSED;
}

static int run_trial(struct nnb_arm *a, uint64_t trial, uint64_t units, const char *kind,
		     int pair, int position)
{
	const struct nnb_cfg *c = a->c;
	const struct nnb_geom *g = a->g;
	struct nnb_trial t = { .trial = trial, .first_gen = a->next_gen, .units = units,
		.integrity = !strcmp(kind, "integrity") };
	struct rusage r0, r1;
	struct nnb_msg m;
	uint64_t f[8], t_receipt = 0, *lat = NULL;
	int64_t mismatch = -1;
	int stamps = strcmp(a->ops->name, "session") != 0;
	int ret = 0;

	t.groups = units * g->groups_per_unit;
	t.burst_units = c->reverse ? c->qd : 0;
	t.bursts = c->reverse ? (uint32_t)((units + c->qd - 1) / c->qd) : 0;
	if (t.first_gen + t.groups > 0xffffffffULL)
		return -EOVERFLOW;
	/* Untimed: one stamp pair per unit, allocated and zeroed before the trial. */
	if (stamps) {
		t.lat_start = calloc(units, sizeof(uint64_t));
		t.lat_done = calloc(units, sizeof(uint64_t));
		if (!t.lat_start || !t.lat_done) {
			ret = -ENOMEM;
			goto out;
		}
	}
	f[0] = trial, f[1] = a->wire_session, f[2] = t.first_gen, f[3] = t.groups;
	f[4] = (uint64_t)t.integrity, f[5] = a->port, f[6] = (uint64_t)t.burst_units * g->groups_per_unit;
	f[7] = c->rate_mbps;
	ret = nnb_msg_send(a->ctl, c->run_id, NNB_BEGIN, f, 8);
	if (!ret)
		ret = nnb_msg_expect(a->ctl, c->run_id, NNB_READY, &m, 20000);
	if (!ret && c->reverse && t.integrity)
		ret = window_io(c, g, 1, &mismatch);
	if (!ret && !c->reverse && !strcmp(a->ops->name, "splice")) {
		/*
		 * Untimed: the trial starts from storage, not the page cache.  A trial
		 * of more units than the window reads later passes from the page cache;
		 * window_passes in the record says how many passes there were.
		 */
		int fd = open(c->source, O_RDONLY | O_CLOEXEC);

		if (fd < 0 || posix_fadvise(fd, (off_t)(c->slba * c->lba), (off_t)g->window_bytes,
					    POSIX_FADV_DONTNEED))
			ret = -EIO;
		if (fd >= 0)
			close(fd);
	}
	if (ret) {
		nnb_diag(a, "trial %" PRIu64 " setup: %s", trial, strerror(-ret));
		goto out;
	}
	getrusage(RUSAGE_SELF, &r0);
	t.t_start = nnb_now();
	ret = a->ops->run(a, &t);
	getrusage(RUSAGE_SELF, &r1);
	if (ret)
		goto out;
	a->next_gen += t.groups;
	if (!c->reverse) {
		ret = nnb_msg_send(a->ctl, c->run_id, NNB_END, &trial, 1);
		if (!ret)
			ret = nnb_msg_expect(a->ctl, c->run_id, NNB_RECEIPT, &m, 30000);
		t_receipt = nnb_now();
		if (ret)
			goto out;
		/* f: trial, datagrams, bytes, duplicates, foreign, malformed, missing, compare, buffers */
		if (m.f[0] != trial || m.f[1] != t.groups * g->dgrams ||
		    m.f[2] != (uint64_t)units * (g->size + (uint64_t)g->dgrams_per_unit * NNB_HDR_LEN) ||
		    m.f[3] || m.f[5] || m.f[6] || (t.integrity && m.f[7] != 1) ||
		    !m.f[8] || m.f[8] > m.f[1]) {
			nnb_diag(a, "peer receipt: datagrams=%" PRIu64 " bytes=%" PRIu64 " dup=%" PRIu64
				 " malformed=%" PRIu64 " missing=%" PRIu64 " compare=%" PRId64
				 " buffers=%" PRIu64, m.f[1], m.f[2], m.f[3], m.f[5], m.f[6],
				 (int64_t)m.f[7], m.f[8]);
			ret = -EPROTO;
			goto out;
		}
	} else if (t.integrity) {
		ret = window_io(c, g, 0, &mismatch);
		if (ret || mismatch >= 0) {
			nnb_diag(a, "integrity readback: %s at window byte %" PRId64,
				 ret ? strerror(-ret) : "mismatch", mismatch);
			ret = ret ? ret : -EPROTO;
			goto out;
		}
	}
	/* Untimed: the stamp pairs become sorted per-unit latencies. */
	if (stamps) {
		ret = unit_latencies(a, t.lat_start, t.lat_done, units);
		if (ret)
			goto out;
		lat = t.lat_start;
	}
	printf("{\"record\":\"%s\",\"arm\":\"%s\",\"direction\":\"%s\",\"size\":%u,\"qd\":%u,"
	       "\"effective_qd\":%u,\"session_depth\":%u,\"inflight_bytes\":%" PRIu64
	       ",\"xsk_zerocopy\":%d,\"pair\":%d,"
	       "\"position\":%d,\"trial\":%" PRIu64 ",\"units\":%" PRIu64 ",\"groups\":%" PRIu64
	       ",\"group_bytes\":%u,\"seg\":%u,\"dgrams_per_group\":%u,\"payload_bytes\":%" PRIu64
	       ",\"bursts\":%u,\"wire_session\":%" PRIu64 ",\"first_gen\":%" PRIu64
	       ",\"window_passes\":%" PRIu64 ",\"lat_samples\":%" PRIu64 ",",
	       kind, a->ops->name, c->reverse ? "rev" : "fwd", c->size, c->qd, a->effective_qd,
	       a->session_depth, a->inflight_bytes, a->xsk_zerocopy, pair, position, trial, units,
	       t.groups, g->group, g->seg, g->dgrams, units * (uint64_t)g->size, t.bursts,
	       a->wire_session, t.first_gen, (units + g->window_units - 1) / g->window_units,
	       lat ? units : 0);
	print_counts(&t.counts);
	if (!c->reverse)
		printf(",\"peer_datagrams\":%" PRIu64 ",\"peer_bytes\":%" PRIu64 ",\"peer_foreign\":%" PRIu64
		       ",\"peer_buffers\":%" PRIu64 ",\"peer_compare\":%" PRId64, m.f[1], m.f[2], m.f[4],
		       m.f[8], (int64_t)m.f[7]);
	else
		printf(",\"readback_compare\":%d", t.integrity ? 1 : 0);
	/* Integrity trials and correctness runs carry no timing. */
	if (!c->correctness && !t.integrity) {
		printf(",\"%s_ns\":%" PRIu64 ",\"cpu_user_us\":%.0f,\"cpu_sys_us\":%.0f",
		       c->reverse ? "durable" : "local_release", t.t_release - t.t_start,
		       usec(&r1.ru_utime) - usec(&r0.ru_utime),
		       usec(&r1.ru_stime) - usec(&r0.ru_stime));
		if (!c->reverse)
			printf(",\"receipt_ns\":%" PRIu64, t_receipt - t.t_start);
		if (lat)
			printf(",\"lat_min_ns\":%" PRIu64 ",\"lat_p50_ns\":%" PRIu64 ",\"lat_p90_ns\":%" PRIu64
			       ",\"lat_p99_ns\":%" PRIu64 ",\"lat_p999_ns\":%" PRIu64 ",\"lat_max_ns\":%" PRIu64,
			       lat[0], rank(lat, units, 1, 2), rank(lat, units, 9, 10),
			       rank(lat, units, 99, 100), rank(lat, units, 999, 1000), lat[units - 1]);
	}
	puts("}");
	fflush(stdout);
out:
	free(t.lat_start), free(t.lat_done);
	return ret;
}

static int campaign(struct nnb_cfg *c, const struct nnb_geom *g)
{
	struct nnb_arm arms[NNB_MAX_ARMS];
	struct sockaddr_in ctl_addr = { .sin_family = AF_INET, .sin_port = htons(c->control_port) };
	struct in_addr local;
	struct nnb_msg m;
	uint64_t f[7], trial = 0, prng = c->order_seed, units = c->units;
	unsigned set = 0;
	int ctl = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0), ret = 0, capability = 1;
	int64_t mismatch;

	memset(arms, 0, sizeof(arms));
	if (ctl < 0 || ipv4(c->control_ip, &ctl_addr.sin_addr) || ipv4(c->local_ip, &local) ||
	    connect(ctl, (struct sockaddr *)&ctl_addr, sizeof(ctl_addr))) {
		fprintf(stderr, "nnb_producer: peer control %s:%u: %s\n", c->control_ip,
			c->control_port, strerror(errno));
		if (ctl >= 0)
			close(ctl);
		return NNB_CAPABILITY;
	}
	f[0] = (uint64_t)c->reverse, f[1] = c->seed, f[2] = c->mtu, f[3] = c->size;
	f[4] = g->window_bytes, f[5] = local.s_addr, f[6] = g->window_groups;
	ret = nnb_msg_send(ctl, c->run_id, NNB_HELLO, f, 7);
	if (!ret)
		ret = nnb_msg_expect(ctl, c->run_id, NNB_HELLO_ACK, &m, 20000);
	if (ret) {
		fprintf(stderr, "nnb_producer: peer HELLO: %s\n", strerror(-ret));
		close(ctl);
		return NNB_CAPABILITY;
	}
	/* Untimed admission: a forward window must hold the independent bytes. */
	if (!c->reverse) {
		ret = window_io(c, g, 0, &mismatch);
		if (ret || mismatch >= 0) {
			fprintf(stderr, "nnb_producer: source window is not the prepared reference "
				"(%s, first mismatch %" PRId64 "); run --prepare-window first\n",
				ret ? strerror(-ret) : "content", mismatch);
			nnb_msg_send(ctl, c->run_id, NNB_BYE, NULL, 0);
			close(ctl);
			return NNB_CAPABILITY;
		}
	}
	for (unsigned i = 0; i < c->nr_arms; i++, set++) {
		struct nnb_arm *a = &arms[i];

		a->ops = arm_ops(c->arms[i]);
		a->c = c, a->g = g, a->index = i, a->ctl = ctl, a->next_gen = 1;
		a->wire_session = c->session_base + i;
		a->xsk_zerocopy = -1;
		/* Reverse: a distinct port per arm keeps the session's XDP filter off the others. */
		a->port = (uint16_t)(c->local_port + (strcmp(c->arms[i], "session") ? 1 + i : 0));
		ret = a->ops->setup(a);
		printf("{\"record\":\"setup\",\"arm\":\"%s\",\"status\":\"%s\",\"registrations\":%d,"
		       "\"effective_qd\":%u,\"session_depth\":%u,\"inflight_bytes\":%" PRIu64
		       ",\"xsk_zerocopy\":%d,\"port\":%u,\"diagnostic\":\"%s\"}\n", a->ops->name,
		       ret ? "refused" : "ok", a->registrations, a->effective_qd, a->session_depth,
		       a->inflight_bytes, a->xsk_zerocopy, a->port, a->diag);
		fflush(stdout);
		if (ret) {
			set++;
			goto out;
		}
	}
	capability = 0;
	for (unsigned i = 0; i < c->nr_arms && !ret; i++)
		for (unsigned w = 0; w < c->warmup && !ret; w++)
			ret = run_trial(&arms[i], ++trial, units, "warmup", -1, (int)i);
	for (unsigned p = 0; p < c->pairs && !ret; p++) {
		unsigned order[NNB_MAX_ARMS];

		for (unsigned i = 0; i < c->nr_arms; i++)
			order[i] = i;
		for (unsigned i = c->nr_arms; i > 1; i--) {
			unsigned j = (unsigned)(mix(&prng) % i), tmp = order[i - 1];

			order[i - 1] = order[j], order[j] = tmp;
		}
		for (unsigned i = 0; i < c->nr_arms && !ret; i++)
			ret = run_trial(&arms[order[i]], ++trial, units, "trial", (int)p, (int)i);
	}
	/* One full byte compare per arm, after the timed campaign. */
	for (unsigned i = 0; i < c->nr_arms && !ret; i++)
		ret = run_trial(&arms[i], ++trial, g->window_units, "integrity", -1, (int)i);
out:
	if (ret) {
		for (unsigned i = 0; i < set && i < c->nr_arms; i++)
			if (arms[i].diag[0])
				fprintf(stderr, "nnb_producer: %s: %s\n", c->arms[i], arms[i].diag);
		fprintf(stderr, "nnb_producer: %s\n", strerror(ret < 0 ? -ret : ret));
	}
	/* A refused setup issued no trial: the peer may end cleanly too. */
	if (!ret || capability)
		nnb_msg_send(ctl, c->run_id, NNB_BYE, NULL, 0);
	for (unsigned i = 0; i < set && i < c->nr_arms; i++)
		if (arms[i].ops)
			arms[i].ops->teardown(&arms[i]);
	close(ctl);
	if (ret)
		return capability && capability_errno(ret) ? NNB_CAPABILITY : NNB_FAIL;
	return NNB_OK;
}

/* --- command line -------------------------------------------------------- */

static int parse_u64(const char *s, uint64_t *v)
{
	char *end;

	if (!s || *s < '0' || *s > '9')
		return -1;
	errno = 0;
	*v = strtoull(s, &end, 10);
	return errno || *end ? -1 : 0;
}

static void usage(FILE *f)
{
	fputs("usage: nnb_producer --direction fwd|rev --size N --qd N --arms A[,A...]\n"
	      "  --source BLOCK|FILE --slba N --nlb N [--lba N] [--ng NG] [--buffered]\n"
	      "  --mtu N [--ifname IF --queue N --local-mac MAC --peer-mac MAC --bpf-object F]\n"
	      "  --local-ip IP --peer-ip IP --local-port N --peer-port N --control IP:PORT\n"
	      "  [--units N] [--pairs N] [--warmup N] [--order-seed N] [--seed N]\n"
	      "  [--run-id N] [--session-base N] [--rate-mbps N] [--correctness]\n"
	      "  [--prepare-window] [--features]\n"
	      "  [--fault skip-datagram|duplicate-datagram|corrupt-payload|skip-write|thread-create]\n"
	      "  (--fault with --correctness only)\n"
	      "arms: posix uring splice session; splice is forward only\n", f);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "direction", 1, 0, 'd' }, { "size", 1, 0, 's' }, { "qd", 1, 0, 'q' },
		{ "arms", 1, 0, 'a' }, { "source", 1, 0, 'S' }, { "slba", 1, 0, 'L' },
		{ "nlb", 1, 0, 'N' }, { "lba", 1, 0, 'B' }, { "ng", 1, 0, 'G' },
		{ "buffered", 0, 0, 'b' }, { "mtu", 1, 0, 'm' }, { "ifname", 1, 0, 'i' },
		{ "queue", 1, 0, 'Q' }, { "local-mac", 1, 0, 'M' }, { "peer-mac", 1, 0, 'P' },
		{ "bpf-object", 1, 0, 'o' }, { "local-ip", 1, 0, 'l' }, { "peer-ip", 1, 0, 'p' },
		{ "local-port", 1, 0, 'x' }, { "peer-port", 1, 0, 'y' }, { "control", 1, 0, 'c' },
		{ "units", 1, 0, 'u' }, { "pairs", 1, 0, 'r' }, { "warmup", 1, 0, 'w' },
		{ "order-seed", 1, 0, 'O' }, { "seed", 1, 0, 'e' }, { "run-id", 1, 0, 'I' },
		{ "session-base", 1, 0, 'E' }, { "rate-mbps", 1, 0, 'R' },
		{ "correctness", 0, 0, 'C' }, { "prepare-window", 0, 0, 'W' }, { "help", 0, 0, 'h' },
		{ "fault", 1, 0, 'F' }, { "features", 0, 0, 'X' },
		{ 0, 0, 0, 0 },
	};
	struct nnb_cfg c = { .direct = 1, .lba = 0, .pairs = 5, .warmup = 1, .seed = 1,
		.run_id = 1, .session_base = 1, .order_seed = 1, .mtu = 1500 };
	char *arm_list = NULL, seen[128] = { 0 };
	int prepare = 0, opt, have_direction = 0;
	struct nnb_geom g;
	uint64_t v;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		if (opt == '?' || opt == 'h') {
			usage(opt == 'h' ? stdout : stderr);
			return opt == 'h' ? 0 : NNB_USAGE;
		}
		if (seen[opt]++) {
			fprintf(stderr, "nnb_producer: duplicate option\n");
			return NNB_USAGE;
		}
		switch (opt) {
		case 'd':
			if (strcmp(optarg, "fwd") && strcmp(optarg, "rev"))
				goto bad;
			c.reverse = !strcmp(optarg, "rev"), have_direction = 1;
			continue;
		case 'a': arm_list = optarg; continue;
		case 'S': c.source = optarg; continue;
		case 'G': c.ng = optarg; continue;
		case 'b': c.direct = 0; continue;
		case 'i': c.ifname = optarg; continue;
		case 'M': c.local_mac = optarg; continue;
		case 'P': c.peer_mac = optarg; continue;
		case 'o': c.bpf_object = optarg; continue;
		case 'l': c.local_ip = optarg; continue;
		case 'p': c.peer_ip = optarg; continue;
		case 'C': c.correctness = 1; continue;
		case 'W': prepare = 1; continue;
		case 'X':
			printf("{\"uring\":%s,\"session\":%s}\n",
#ifdef NNB_HAVE_URING
			       "true",
#else
			       "false",
#endif
#ifdef NNB_HAVE_SESSION
			       "true");
#else
			       "false");
#endif
			return NNB_OK;
		case 'F':
			for (nnb_fault = FAULT_COUNT - 1; nnb_fault > 0 && strcmp(optarg, fault_names[nnb_fault]);
			     nnb_fault--)
				;
			if (!nnb_fault)
				goto bad;
			continue;
		case 'c': {
			static char ip[64];
			const char *colon = strrchr(optarg, ':');

			if (!colon || colon == optarg || (size_t)(colon - optarg) >= sizeof(ip) ||
			    parse_u64(colon + 1, &v) || !v || v > 65535)
				goto bad;
			memcpy(ip, optarg, (size_t)(colon - optarg));
			ip[colon - optarg] = 0;
			c.control_ip = ip, c.control_port = (uint16_t)v;
			continue;
		}
		}
		if (parse_u64(optarg, &v))
			goto bad;
		switch (opt) {
		case 's': c.size = v > UINT32_MAX ? 0 : (uint32_t)v; break;
		case 'q': c.qd = v > NNB_MAX_QD ? 0 : (uint32_t)v; break;
		case 'L': c.slba = v; break;
		case 'N': c.nlb = v; break;
		case 'B': c.lba = v > 65536 ? 1 : (uint32_t)v; break;
		case 'm': c.mtu = v > 65535 ? 0 : (uint32_t)v; break;
		case 'Q': c.queue = v > UINT32_MAX ? UINT32_MAX : (uint32_t)v; break;
		case 'x': if (!v || v > 65535 - 2 * NNB_MAX_ARMS * NNB_MAX_QD) goto bad; c.local_port = (uint16_t)v; break;
		case 'y': if (!v || v > 65535) goto bad; c.peer_port = (uint16_t)v; break;
		case 'u': c.units = v > (1U << 20) ? 0 : (uint32_t)v; if (!c.units) goto bad; break;
		case 'r': if (v > 1000) goto bad; c.pairs = (uint32_t)v; break;
		case 'w': if (v > 100) goto bad; c.warmup = (uint32_t)v; break;
		case 'O': c.order_seed = v; break;
		case 'e': c.seed = v; break;
		case 'I': c.run_id = v; break;
		case 'E': if (!v || v > UINT64_MAX - NNB_MAX_ARMS) goto bad; c.session_base = v; break;
		case 'R': if (v > 1000000) goto bad; c.rate_mbps = (uint32_t)v; break;
		}
	}
	if (optind != argc || !have_direction || !c.qd || !c.source || !c.nlb ||
	    (nnb_fault && !c.correctness))
		goto bad;
	if (!c.lba) {
		struct stat st;
		int fd = open(c.source, O_RDONLY | O_CLOEXEC);
		unsigned sector = 0;

		if (fd < 0 || fstat(fd, &st))
			goto bad;
		if (S_ISBLK(st.st_mode) && !ioctl(fd, BLKSSZGET, &sector))
			c.lba = sector;
		else if (S_ISREG(st.st_mode))
			c.lba = 512;
		close(fd);
		if (!c.lba)
			goto bad;
	}
	if (c.lba < 512 || (c.lba & (c.lba - 1)) || c.nlb > UINT64_MAX / c.lba ||
	    nnb_geom_init(&g, c.mtu, c.size, c.nlb * c.lba)) {
		fprintf(stderr, "nnb_producer: geometry: size must be a power of two in 4KiB..4MiB "
			"and the window (nlb*lba) a multiple of 4MiB\n");
		return NNB_USAGE;
	}
	if (prepare) {
		int ret = c.reverse ? -EINVAL : prepare_window(&c, &g);

		if (ret)
			fprintf(stderr, "nnb_producer: prepare window: %s\n", strerror(-ret));
		else
			printf("{\"record\":\"prepared\",\"window_bytes\":%" PRIu64 ",\"seed\":%" PRIu64 "}\n",
			       g.window_bytes, c.seed);
		return ret ? NNB_FAIL : NNB_OK;
	}
	if (!arm_list || !c.local_ip || !c.peer_ip || !c.control_ip || !c.local_port || !c.peer_port)
		goto bad;
	for (char *save = NULL, *tok = strtok_r(arm_list, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		if (c.nr_arms == NNB_MAX_ARMS || !arm_ops(tok) ||
		    (c.reverse && !strcmp(tok, "splice")))
			goto bad;
		for (unsigned i = 0; i < c.nr_arms; i++)
			if (!strcmp(c.arms[i], tok))
				goto bad;
		c.arms[c.nr_arms++] = tok;
	}
	if (!c.nr_arms)
		goto bad;
	if (!c.units) {
		uint64_t want = (64ULL << 20) / c.size;

		c.units = (uint32_t)(want < c.qd ? c.qd : want);
	}
	/* Reverse bursts are whole: units round up to a multiple of qd. */
	if (c.reverse)
		c.units = (c.units + c.qd - 1) / c.qd * c.qd;
	return campaign(&c, &g);
bad:
	usage(stderr);
	return NNB_USAGE;
}
