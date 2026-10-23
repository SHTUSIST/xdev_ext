// SPDX-License-Identifier: GPL-2.0
/*
 * nnb_peer - remote end of the NVMe<->NIC eval (reviewer E3), in C so that no
 * interpreter sits on the measured path.
 *
 * Forward: receives every arm's NXP2 datagrams on --data-bind.  During a
 * timed trial it only parses the 40-byte header and sets one bit per
 * (generation, segment); duplicates, malformed and missing datagrams are
 * counted.  In the integrity trial it also places each payload at its window
 * offset and, after END, compares the whole window with the independent
 * generator once.  The receipt is sent after END, never per datagram.
 * The data socket has UDP_GRO, so one receive buffer carries a whole GSO run
 * of the producer (split here at the GRO segment size); the receiver is still
 * one thread, and loss beyond its capacity fails the trial (see README).
 * Reverse: holds the generator's window image and, per GO, sends the burst's
 * groups in order (GSO runs of header + payload iovecs, optional pacing),
 * then reports what it sent.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "nnb_wire.h"

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#define P_BATCH		64U
#define P_BUF		65536U	/* one GRO buffer: up to 64 KiB of datagrams */

struct peer {
	int data, reverse;
	uint64_t run_id, seed, max_window;
	struct nnb_geom g;
	struct sockaddr_in producer;
	unsigned char *image;		/* window bytes: reverse source, forward integrity */
	unsigned char *rx;		/* P_BATCH receive buffers */
	int gro;			/* UDP_GRO enabled on the data socket */
	uint8_t *bits;
	size_t bits_bytes;
	/* current trial */
	uint64_t trial, session, first_gen, groups, rate_mbps;
	int integrity;
};

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int endpoint(const char *s, struct sockaddr_in *a)
{
	char ip[64];
	const char *colon = strrchr(s, ':');
	unsigned long port;
	char *end;

	if (!colon || colon == s || (size_t)(colon - s) >= sizeof(ip))
		return -EINVAL;
	memcpy(ip, s, (size_t)(colon - s));
	ip[colon - s] = 0;
	port = strtoul(colon + 1, &end, 10);
	*a = (struct sockaddr_in){ .sin_family = AF_INET, .sin_port = htons((uint16_t)port) };
	if (*end || port > 65535 || inet_pton(AF_INET, ip, &a->sin_addr) != 1)
		return -EINVAL;
	return 0;
}

static void drain(struct peer *p)
{
	while (recv(p->data, p->rx, P_BUF, MSG_DONTWAIT) >= 0)
		;
}

static int hello(struct peer *p, int ctl, const struct nnb_msg *m)
{
	uint64_t ack = 0;
	struct sockaddr_in local;
	socklen_t len = sizeof(local);
	int size;

	p->reverse = (int)m->f[0], p->seed = m->f[1];
	free(p->image), free(p->bits);
	p->image = NULL, p->bits = NULL, p->bits_bytes = 0;
	if (m->f[0] > 1 || m->f[2] > 65535 || m->f[3] > NNB_MAX_SIZE ||
	    nnb_geom_init(&p->g, (uint32_t)m->f[2], (uint32_t)m->f[3], m->f[4]) ||
	    p->g.window_groups != m->f[6] || m->f[4] > p->max_window)
		return -EINVAL;
	p->producer = (struct sockaddr_in){ .sin_family = AF_INET, .sin_addr.s_addr = (uint32_t)m->f[5] };
	/* Untimed: the image is generated before READY of any trial. */
	if (posix_memalign((void **)&p->image, 4096, (size_t)p->g.window_bytes))
		return -ENOMEM;
	if (p->reverse) {
		nnb_gen_fill(p->seed, 0, p->image, (size_t)p->g.window_bytes);
		size = (int)(NNB_HDR_LEN + p->g.seg);
		if (p->g.gso_dgrams > 1 &&
		    setsockopt(p->data, IPPROTO_UDP, UDP_SEGMENT, &size, sizeof(size)))
			return -errno;
	}
	if (getsockname(p->data, (struct sockaddr *)&local, &len))
		return -errno;
	ack = ntohs(local.sin_port);
	return nnb_msg_send(ctl, p->run_id, NNB_HELLO_ACK, &ack, 1);
}

struct fwd_count {
	uint64_t count, bytes, dup, foreign, malformed;
};

/* One datagram of a forward trial: header-only accounting, payload placed for integrity. */
static void fwd_dgram(struct peer *p, struct fwd_count *k, const unsigned char *d, size_t len)
{
	struct nnb_seg s;
	uint64_t bit;
	int r = nnb_hdr_parse(d, len, &p->g, &s);

	if (r == -ENOMSG || (!r && s.session != p->session)) {
		k->foreign++;
		return;
	}
	if (r || s.gen < p->first_gen || s.gen - p->first_gen >= p->groups) {
		k->malformed++;
		return;
	}
	bit = (s.gen - p->first_gen) * p->g.dgrams + s.index;
	if (p->bits[bit / 8] & (1U << (bit % 8))) {
		k->dup++;
		return;
	}
	p->bits[bit / 8] |= (uint8_t)(1U << (bit % 8));
	k->count++;
	k->bytes += len;
	if (p->integrity)
		memcpy(p->image + nnb_gen_offset(&p->g, s.gen) + s.rel, d + NNB_HDR_LEN, s.len);
}

/* The GRO segment size of a received buffer, or 0 when it is one datagram. */
static size_t gro_size(struct msghdr *msg)
{
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(msg); cm; cm = CMSG_NXTHDR(msg, cm))
		if (cm->cmsg_level == IPPROTO_UDP && cm->cmsg_type == UDP_GRO) {
			int v;

			memcpy(&v, CMSG_DATA(cm), sizeof(v));
			return v > 0 ? (size_t)v : 0;
		}
	return 0;
}

/* Forward trial: header-only accounting, receipt after END. */
static int fwd_trial(struct peer *p, int ctl)
{
	struct mmsghdr msgs[P_BATCH];
	struct iovec iov[P_BATCH];
	static char cmsg[P_BATCH][CMSG_SPACE(sizeof(int))];
	struct fwd_count k = { 0 };
	uint64_t expected = p->groups * p->g.dgrams, buffers = 0, f[9];
	int64_t compare = 0;
	int ended = 0, ret;
	size_t need = (size_t)((expected + 7) / 8);

	if (need > p->bits_bytes) {
		free(p->bits);
		p->bits = malloc(need);
		p->bits_bytes = p->bits ? need : 0;
		if (!p->bits)
			return -ENOMEM;
	}
	memset(p->bits, 0, need);
	if (p->integrity)
		memset(p->image, 0xee, (size_t)p->g.window_bytes);
	drain(p);
	ret = nnb_msg_send(ctl, p->run_id, NNB_READY, &p->trial, 1);
	if (ret)
		return ret;
	for (unsigned i = 0; i < P_BATCH; i++)
		iov[i] = (struct iovec){ p->rx + (size_t)i * P_BUF, P_BUF };
	while (!ended || k.count < expected) {
		struct pollfd pfd[2] = { { .fd = p->data, .events = POLLIN },
					 { .fd = ctl, .events = POLLIN } };
		int n = poll(pfd, ended ? 1 : 2, ended ? 200 : 60000);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -errno;
		if (!n) {
			if (ended)
				break;	/* idle after END: the rest is missing */
			return -ETIMEDOUT;
		}
		if (!ended && (pfd[1].revents & POLLIN)) {
			struct nnb_msg m;

			ret = nnb_msg_expect(ctl, p->run_id, NNB_END, &m, 1000);
			if (ret || m.f[0] != p->trial)
				return ret ? ret : -EPROTO;
			ended = 1;
		}
		if (!(pfd[0].revents & POLLIN))
			continue;
		for (unsigned i = 0; i < P_BATCH; i++)
			msgs[i] = (struct mmsghdr){ .msg_hdr = { .msg_iov = &iov[i], .msg_iovlen = 1,
				.msg_control = cmsg[i], .msg_controllen = sizeof(cmsg[i]) } };
		n = recvmmsg(p->data, msgs, P_BATCH, MSG_DONTWAIT, NULL);
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (n < 0)
			return -errno;
		for (int i = 0; i < n; i++) {
			const unsigned char *d = p->rx + (size_t)i * P_BUF;
			size_t len = msgs[i].msg_len, seg = gro_size(&msgs[i].msg_hdr);

			buffers++;
			if (!len || (msgs[i].msg_hdr.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
				k.malformed++;
				continue;
			}
			/* A GRO buffer is consecutive datagrams of @seg bytes, the last shorter. */
			for (size_t off = 0; off < len; off += seg ? seg : len)
				fwd_dgram(p, &k, d + off, seg && len - off > seg ? seg : len - off);
		}
	}
	if (p->integrity) {
		int64_t at = k.count == expected && p->groups == p->g.window_groups ?
			     nnb_gen_check(p->seed, 0, p->image, (size_t)p->g.window_bytes) : 0;

		compare = at < 0 ? 1 : -1;
	}
	f[0] = p->trial, f[1] = k.count, f[2] = k.bytes, f[3] = k.dup, f[4] = k.foreign;
	f[5] = k.malformed, f[6] = expected - k.count, f[7] = (uint64_t)compare, f[8] = buffers;
	printf("{\"record\":\"receipt\",\"trial\":%" PRIu64 ",\"datagrams\":%" PRIu64 ",\"bytes\":%" PRIu64
	       ",\"duplicates\":%" PRIu64 ",\"foreign\":%" PRIu64 ",\"malformed\":%" PRIu64
	       ",\"missing\":%" PRIu64 ",\"compare\":%" PRId64 ",\"buffers\":%" PRIu64 "}\n",
	       p->trial, k.count, k.bytes, k.dup, k.foreign, k.malformed, expected - k.count, compare,
	       buffers);
	fflush(stdout);
	return nnb_msg_send(ctl, p->run_id, NNB_RECEIPT, f, 9);
}

/* Reverse: send @groups groups from @first_gen in order, then report. */
static int rev_burst(struct peer *p, int ctl, const struct nnb_msg *m)
{
	const struct nnb_geom *g = &p->g;
	unsigned char *hdrs = malloc((size_t)g->dgrams * NNB_HDR_LEN);
	struct iovec *iov = calloc(2 * (size_t)g->gso_dgrams, sizeof(*iov));
	struct sockaddr_in dst = p->producer;
	uint64_t sent = 0, bytes = 0, start = now_ns(), f[5];
	int ret = 0;

	if (!hdrs || !iov) {
		free(hdrs), free(iov);
		return -ENOMEM;
	}
	if (m->f[0] != p->trial || m->f[2] < p->first_gen ||
	    m->f[2] + m->f[3] > p->first_gen + p->groups) {
		free(hdrs), free(iov);
		return -EPROTO;
	}
	for (uint32_t j = 0; j < g->dgrams; j++)
		nnb_hdr_encode(hdrs + (size_t)j * NNB_HDR_LEN, g, p->session, 1, j);
	for (uint64_t gen = m->f[2]; gen < m->f[2] + m->f[3] && !ret; gen++) {
		const unsigned char *src = p->image + nnb_gen_offset(g, gen);

		for (uint32_t j = 0; j < g->dgrams; j++)
			nnb_hdr_set_gen(hdrs + (size_t)j * NNB_HDR_LEN, (uint32_t)gen);
		for (uint32_t j0 = 0; j0 < g->dgrams; j0 += g->gso_dgrams) {
			uint32_t n = g->dgrams - j0 < g->gso_dgrams ? g->dgrams - j0 : g->gso_dgrams;
			struct msghdr msg = { .msg_name = &dst, .msg_namelen = sizeof(dst),
					      .msg_iov = iov, .msg_iovlen = 2 * n };
			size_t want = 0;
			ssize_t r;

			for (uint32_t i = 0; i < n; i++) {
				uint32_t rel, len;

				nnb_dgram(g, j0 + i, &rel, &len);
				iov[2 * i] = (struct iovec){ hdrs + (size_t)(j0 + i) * NNB_HDR_LEN, NNB_HDR_LEN };
				iov[2 * i + 1] = (struct iovec){ (void *)(src + rel), len };
				want += NNB_HDR_LEN + len;
			}
			for (;;) {
				r = sendmsg(p->data, &msg, 0);
				if (r >= 0 || (errno != EINTR && errno != ENOBUFS && errno != EAGAIN))
					break;
			}
			if (r != (ssize_t)want) {
				ret = r < 0 ? -errno : -EIO;
				break;
			}
			sent += n, bytes += want;
			/* Optional pacing of the offered load; equal for every arm. */
			if (p->rate_mbps)
				while (now_ns() - start < bytes * 8000ULL / p->rate_mbps)
					;
		}
	}
	free(hdrs), free(iov);
	if (ret)
		return ret;
	f[0] = m->f[0], f[1] = m->f[1], f[2] = sent, f[3] = bytes, f[4] = 0;
	return nnb_msg_send(ctl, p->run_id, NNB_SENT, f, 5);
}

static int serve(struct peer *p, int ctl)
{
	for (;;) {
		struct nnb_msg m;
		int ret = nnb_io_full(ctl, &m, sizeof(m), 0, 600000);

		if (ret)
			return ret;
		if (m.magic != NNB_CTL_MAGIC)
			return -EPROTO;
		if (m.type == NNB_HELLO) {
			p->run_id = m.run_id;
			ret = hello(p, ctl, &m);
		} else if (m.run_id != p->run_id || !p->image) {
			ret = -EPROTO;
		} else if (m.type == NNB_BEGIN) {
			p->trial = m.f[0], p->session = m.f[1], p->first_gen = m.f[2];
			p->groups = m.f[3], p->integrity = (int)m.f[4], p->rate_mbps = m.f[7];
			p->producer.sin_port = htons((uint16_t)m.f[5]);
			if (!p->session || !p->first_gen || !p->groups || m.f[5] > 65535 ||
			    p->first_gen + p->groups > 0xffffffffULL ||
			    (p->integrity && p->groups != p->g.window_groups))
				ret = -EINVAL;
			else if (!p->reverse)
				ret = fwd_trial(p, ctl);
			else
				ret = nnb_msg_send(ctl, p->run_id, NNB_READY, &p->trial, 1);
		} else if (m.type == NNB_GO && p->reverse) {
			ret = rev_burst(p, ctl, &m);
		} else if (m.type == NNB_BYE) {
			return 0;
		} else {
			ret = -EPROTO;
		}
		if (ret) {
			uint64_t code = (uint64_t)-ret;

			nnb_msg_send(ctl, m.run_id, NNB_ERROR, &code, 1);
			return ret;
		}
	}
}

int main(int argc, char **argv)
{
	struct peer p = { .max_window = 1ULL << 30 };
	struct sockaddr_in cb, db;
	const char *control = NULL, *data = NULL;
	int once = 0, lfd, one = 1, rcvbuf = 256 << 20, status = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--control-bind") && i + 1 < argc)
			control = argv[++i];
		else if (!strcmp(argv[i], "--data-bind") && i + 1 < argc)
			data = argv[++i];
		else if (!strcmp(argv[i], "--max-window-bytes") && i + 1 < argc)
			p.max_window = strtoull(argv[++i], NULL, 10);
		else if (!strcmp(argv[i], "--once"))
			once = 1;
		else
			control = NULL, i = argc;
	}
	if (!control || !data || endpoint(control, &cb) || endpoint(data, &db) || !p.max_window) {
		fputs("usage: nnb_peer --control-bind IP:PORT --data-bind IP:PORT "
		      "[--max-window-bytes N] [--once]\n", stderr);
		return 2;
	}
	lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	p.data = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	p.rx = malloc((size_t)P_BATCH * P_BUF);
	if (lfd < 0 || p.data < 0 || !p.rx ||
	    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
	    bind(lfd, (struct sockaddr *)&cb, sizeof(cb)) || listen(lfd, 1) ||
	    bind(p.data, (struct sockaddr *)&db, sizeof(db))) {
		perror("nnb_peer: bind");
		return 4;
	}
	if (setsockopt(p.data, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)))
		setsockopt(p.data, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	/* Coalesced receive (Linux 5.0+); without it every datagram costs one buffer. */
	p.gro = !setsockopt(p.data, IPPROTO_UDP, UDP_GRO, &one, sizeof(one));
	{
		socklen_t len = sizeof(cb);

		getsockname(lfd, (struct sockaddr *)&cb, &len);
		len = sizeof(db);
		getsockname(p.data, (struct sockaddr *)&db, &len);
	}
	printf("{\"status\":\"ready\",\"control_port\":%u,\"data_port\":%u,\"udp_gro\":%d}\n",
	       ntohs(cb.sin_port), ntohs(db.sin_port), p.gro);
	fflush(stdout);
	do {
		int ctl = accept4(lfd, NULL, NULL, SOCK_CLOEXEC), ret;

		if (ctl < 0) {
			if (errno == EINTR)
				continue;
			perror("nnb_peer: accept");
			return 1;
		}
		ret = serve(&p, ctl);
		close(ctl);
		if (ret) {
			fprintf(stderr, "nnb_peer: %s\n", strerror(-ret));
			status = 1;
		}
	} while (!once);
	free(p.image), free(p.bits), free(p.rx);
	close(p.data), close(lfd);
	return status;
}
