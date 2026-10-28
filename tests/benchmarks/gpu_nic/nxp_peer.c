// SPDX-License-Identifier: GPL-2.0
/*
 * nxp_peer - the far end of every GPU<->NIC arm, on an ordinary UDP socket.
 *
 *   send  generations 1..groups of one NXP wire session to an ingest arm.
 *         Group g carries block g mod --window-groups of the shared payload.
 *   recv  the groups an egress arm sends, checking every segment's protocol
 *         CRC and its payload identity: --expect window:W (group g is block
 *         g mod W) or --expect slots:D (every segment of a group is the
 *         same one of blocks 0..D-1, as the session's slot-seeded egress
 *         sends them).  Segments must arrive complete and in order.
 *
 * The peer is measurement infrastructure.  It does no extra pass over the
 * payload: the sender takes the payload CRCs from a table built before the
 * campaign and the receiver derives the payload CRC from the protocol CRC it
 * computes anyway (gpu_nic_core.h, CRC linearity).  Its JSON record (stdout)
 * gives the stream time from the first to the last datagram.
 * Exit: 0 complete and verified, 1 failure or timeout, 2 usage, 4 network
 * capability unavailable.
 */
#define _GNU_SOURCE
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "gpu_nic_core.h"

#define NP_BATCH	64

struct np_opts {
	bool send;
	const char *expect;
	struct sockaddr_in local, remote;
	bool have_remote_port;
	uint64_t wire_session, size, messages, mtu, window_groups, slots, seed, timeout_ms,
		 gap_us;
};

static uint64_t np_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t np_cpu_us(void)
{
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru))
		return 0;
	return xg_cpu_us(ru.ru_utime.tv_sec, ru.ru_utime.tv_usec, ru.ru_stime.tv_sec,
			 ru.ru_stime.tv_usec);
}

static void np_usage(FILE *f)
{
	fprintf(f,
"usage: nxp_peer send --local-ip A --local-port P --peer-ip A --peer-port P\n"
"                 --wire-session N --size N --messages N --mtu N [--window-groups N]\n"
"                 [--seed N] [--gap-us N]\n"
"       nxp_peer recv --local-ip A --local-port P --wire-session N --size N\n"
"                 --messages N --mtu N --expect window:W|slots:D [--seed N]\n"
"                 [--timeout-ms N]\n");
}

static int np_parse(int argc, char **argv, struct np_opts *o)
{
	enum { O_LIP = 1, O_LPORT, O_PIP, O_PPORT, O_WIRE, O_SIZE, O_MSG, O_MTU, O_WIN,
	       O_EXPECT, O_SEED, O_TMO, O_GAP };
	static const struct option opts[] = {
		{ "local-ip", required_argument, NULL, O_LIP },
		{ "local-port", required_argument, NULL, O_LPORT },
		{ "peer-ip", required_argument, NULL, O_PIP },
		{ "peer-port", required_argument, NULL, O_PPORT },
		{ "wire-session", required_argument, NULL, O_WIRE },
		{ "size", required_argument, NULL, O_SIZE },
		{ "messages", required_argument, NULL, O_MSG },
		{ "mtu", required_argument, NULL, O_MTU },
		{ "window-groups", required_argument, NULL, O_WIN },
		{ "expect", required_argument, NULL, O_EXPECT },
		{ "seed", required_argument, NULL, O_SEED },
		{ "timeout-ms", required_argument, NULL, O_TMO },
		{ "gap-us", required_argument, NULL, O_GAP },
		{ NULL, 0, NULL, 0 },
	};
	bool have_lip = false, have_lport = false, have_pip = false;
	int c, bad = 0;

	memset(o, 0, sizeof(*o));
	o->seed = 1;
	o->timeout_ms = 60000;
	o->local.sin_family = o->remote.sin_family = AF_INET;
	if (argc < 2)
		return XG_EXIT_USAGE;
	if (!strcmp(argv[1], "send"))
		o->send = true;
	else if (strcmp(argv[1], "recv"))
		return XG_EXIT_USAGE;
	optind = 2;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case O_LIP: bad |= gn_parse_ip(optarg, &o->local.sin_addr.s_addr); have_lip = true; break;
		case O_LPORT: bad |= gn_parse_port(optarg, &o->local.sin_port); have_lport = true; break;
		case O_PIP: bad |= gn_parse_ip(optarg, &o->remote.sin_addr.s_addr); have_pip = true; break;
		case O_PPORT: bad |= gn_parse_port(optarg, &o->remote.sin_port); o->have_remote_port = true; break;
		case O_WIRE: bad |= xg_parse_u64(optarg, UINT64_MAX, &o->wire_session); break;
		case O_SIZE: bad |= xg_parse_u64(optarg, GN_MAX_SIZE, &o->size); break;
		case O_MSG: bad |= xg_parse_u64(optarg, GN_MAX_MESSAGES, &o->messages); break;
		case O_MTU: bad |= xg_parse_u64(optarg, 65535, &o->mtu); break;
		case O_WIN: bad |= xg_parse_u64(optarg, GN_MAX_MESSAGES, &o->window_groups); break;
		case O_EXPECT: o->expect = optarg; break;
		case O_SEED: bad |= xg_parse_u64(optarg, UINT32_MAX, &o->seed); break;
		case O_TMO: bad |= xg_parse_u64(optarg, 3600000, &o->timeout_ms); break;
		case O_GAP: bad |= xg_parse_u64(optarg, 1000000, &o->gap_us); break;
		default: bad = 1; break;
		}
	}
	if (o->expect && !o->send) {
		if (!strncmp(o->expect, "window:", 7))
			bad |= xg_parse_u64(o->expect + 7, GN_MAX_MESSAGES, &o->window_groups);
		else if (!strncmp(o->expect, "slots:", 6))
			bad |= xg_parse_u64(o->expect + 6, GN_MAX_DEPTH, &o->slots);
		else
			bad = 1;
	}
	if (o->send && !o->window_groups)
		o->window_groups = 1;
	if (bad || optind != argc || !have_lip || !have_lport || !o->wire_session ||
	    !o->size || !o->messages || !o->mtu || !o->timeout_ms ||
	    (o->send ? (!have_pip || !o->have_remote_port || o->expect) :
		       (!o->expect || (!o->window_groups && !o->slots) || o->gap_us)))
		return XG_EXIT_USAGE;
	return XG_EXIT_PASS;
}

/* Payload blocks, their per-segment payload CRCs and the CRC shifts. */
struct np_tables {
	struct gn_plan p;
	unsigned char *blocks;		/* nblocks * group_bytes */
	uint32_t *crc;			/* nblocks * frames */
	uint64_t nblocks;
	struct gn_crc_shift shift[2];	/* full and last segment length */
};

static int np_tables_init(struct np_tables *t, const struct np_opts *o, uint64_t nblocks)
{
	unsigned char *zeros;
	uint32_t i, off, len;
	uint64_t b;

	memset(t, 0, sizeof(*t));
	if (gn_plan_init(&t->p, o->size, o->messages, (uint32_t)o->mtu, 1,
			 nblocks ? nblocks : 1))
		return -EINVAL;
	t->nblocks = nblocks;
	t->blocks = malloc(nblocks * t->p.l.group_bytes);
	t->crc = calloc(nblocks * t->p.frames, sizeof(*t->crc));
	zeros = malloc(t->p.l.seg_len);
	if (!t->blocks || !t->crc || !zeros) {
		free(zeros);
		return -ENOMEM;
	}
	xg_fill(t->blocks, 0, nblocks * t->p.l.group_bytes, (uint32_t)o->seed);
	for (b = 0; b < nblocks; b++)
		for (i = 0; i < t->p.frames; i++) {
			gn_segment(&t->p, i, &off, &len);
			t->crc[b * t->p.frames + i] =
				gn_crc32c(0, t->blocks + b * t->p.l.group_bytes + off, len);
		}
	gn_segment(&t->p, 0, &off, &len);
	gn_crc_shift_init(&t->shift[0], len, zeros);
	gn_segment(&t->p, t->p.frames - 1, &off, &len);
	gn_crc_shift_init(&t->shift[1], len, zeros);
	free(zeros);
	return 0;
}

static const struct gn_crc_shift *np_shift(const struct np_tables *t, uint32_t len)
{
	return t->shift[0].len == len ? &t->shift[0] : &t->shift[1];
}

static int np_send(int fd, const struct np_opts *o, const struct np_tables *t)
{
	const struct gn_plan *p = &t->p;
	static unsigned char hdr[NP_BATCH][XDEV_EXT_MP_NXP_LEN];
	struct mmsghdr msg[NP_BATCH];
	struct iovec iov[NP_BATCH][2];
	uint64_t g = 0, first = 0, last = 0, cpu0 = np_cpu_us();
	uint32_t i = 0;

	while (g < p->groups) {
		unsigned int n = 0, sent = 0;

		for (; n < NP_BATCH && g < p->groups; n++) {
			uint64_t block = g % t->nblocks;
			uint32_t off, len, h;
			unsigned char prep[XDEV_EXT_MP_NXP_LEN];

			gn_segment(p, i, &off, &len);
			if (gn_nxp_header(hdr[n], p, o->wire_session, g, i))
				return -EINVAL;
			xdev_ext_mp_nxp_crc_prep(prep, hdr[n]);
			h = gn_crc32c(XDEV_EXT_MP_CRC32C_SEED, prep, sizeof(prep));
			xdev_ext_mp_nxp_crc_store(hdr[n], gn_crc_shift(np_shift(t, len), h) ^
					     t->crc[block * p->frames + i]);
			iov[n][0].iov_base = hdr[n];
			iov[n][0].iov_len = XDEV_EXT_MP_NXP_LEN;
			iov[n][1].iov_base = t->blocks + block * p->l.group_bytes + off;
			iov[n][1].iov_len = len;
			memset(&msg[n], 0, sizeof(msg[n]));
			msg[n].msg_hdr.msg_iov = iov[n];
			msg[n].msg_hdr.msg_iovlen = 2;
			if (++i == p->frames) {
				i = 0;
				g++;
			}
		}
		while (sent < n) {
			int k = sendmmsg(fd, msg + sent, n - sent, 0);

			if (k < 0 && (errno == EINTR || errno == ENOBUFS || errno == EAGAIN))
				continue;
			if (k <= 0)
				return k < 0 ? -errno : -EIO;
			if (!first)
				first = np_now_ns();
			sent += (unsigned int)k;
		}
		/* Optional pacing between batches, for a receiver that cannot keep up. */
		if (o->gap_us)
			usleep((useconds_t)o->gap_us);
	}
	last = np_now_ns();
	printf("{\"schema_version\":1,\"role\":\"send\",\"groups\":%llu,\"group_bytes\":%u,"
	       "\"io_bytes\":%llu,\"stream_ns\":%llu,\"cpu_us\":%llu,\"status\":\"pass\"}\n",
	       (unsigned long long)p->groups, p->l.group_bytes,
	       (unsigned long long)(p->groups * p->l.group_bytes),
	       (unsigned long long)(last > first ? last - first : 0),
	       (unsigned long long)(np_cpu_us() - cpu0));
	return 0;
}

static int np_recv(int fd, const struct np_opts *o, const struct np_tables *t)
{
	const struct gn_plan *p = &t->p;
	size_t cap = XDEV_EXT_MP_NXP_LEN + p->l.seg_len + 1;
	unsigned char *buf = malloc(NP_BATCH * cap);
	struct mmsghdr msg[NP_BATCH];
	struct iovec iov[NP_BATCH];
	uint64_t g = 0, first = 0, last = 0, block = 0, deadline, cpu0 = np_cpu_us();
	uint32_t i = 0;
	unsigned int k;

	if (!buf)
		return -ENOMEM;
	fprintf(stderr, "XDEV_EVAL_READY role=recv groups=%llu group_bytes=%u\n",
		(unsigned long long)p->groups, p->l.group_bytes);
	deadline = np_now_ns() + o->timeout_ms * 1000000ULL;
	while (g < p->groups) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		uint64_t now = np_now_ns();
		int n;

		if (now >= deadline) {
			fprintf(stderr, "timeout after %llu of %llu groups\n",
				(unsigned long long)g, (unsigned long long)p->groups);
			free(buf);
			return -ETIMEDOUT;
		}
		if (poll(&pfd, 1, (int)((deadline - now) / 1000000 + 1)) < 0 && errno != EINTR) {
			free(buf);
			return -errno;
		}
		for (k = 0; k < NP_BATCH; k++) {
			iov[k].iov_base = buf + k * cap;
			iov[k].iov_len = cap;
			memset(&msg[k], 0, sizeof(msg[k]));
			msg[k].msg_hdr.msg_iov = &iov[k];
			msg[k].msg_hdr.msg_iovlen = 1;
		}
		n = recvmmsg(fd, msg, NP_BATCH, MSG_DONTWAIT, NULL);
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (n < 0) {
			free(buf);
			return -errno;
		}
		if (n && !first)
			first = np_now_ns();
		for (k = 0; k < (unsigned int)n && g < p->groups; k++) {
			const unsigned char *nxp = buf + k * cap;
			struct xdev_ext_mp_segment s;
			uint32_t got, b;

			if (gn_nxp_parse(nxp, msg[k].msg_len, p, o->wire_session, &s) ||
			    s.generation != g + 1 || s.index != i ||
			    !gn_segment_check(nxp, nxp + XDEV_EXT_MP_NXP_LEN, np_shift(t, s.payload_len),
					      &got)) {
				fprintf(stderr, "segment %u of group %llu missing, reordered or corrupt\n",
					i, (unsigned long long)g);
				free(buf);
				return -EBADMSG;
			}
			if (!i) {
				/* window: the group's own block; slots: whichever block it is. */
				if (o->slots) {
					for (b = 0; b < t->nblocks && t->crc[b * p->frames] != got; b++)
						;
					block = b;
				} else {
					block = g % t->nblocks;
				}
			}
			if (block >= t->nblocks || t->crc[block * p->frames + i] != got) {
				fprintf(stderr, "group %llu segment %u has a foreign payload\n",
					(unsigned long long)g, i);
				free(buf);
				return -EBADMSG;
			}
			if (++i == p->frames) {
				i = 0;
				g++;
			}
		}
		last = np_now_ns();
	}
	free(buf);
	printf("{\"schema_version\":1,\"role\":\"recv\",\"groups\":%llu,\"group_bytes\":%u,"
	       "\"io_bytes\":%llu,\"verified_groups\":%llu,\"expect\":\"%s\",\"stream_ns\":%llu,"
	       "\"cpu_us\":%llu,\"status\":\"pass\"}\n",
	       (unsigned long long)p->groups, p->l.group_bytes,
	       (unsigned long long)(p->groups * p->l.group_bytes), (unsigned long long)g,
	       o->slots ? "slots" : "window", (unsigned long long)(last > first ? last - first : 0),
	       (unsigned long long)(np_cpu_us() - cpu0));
	return 0;
}

int main(int argc, char **argv)
{
	struct np_opts o;
	struct np_tables t;
	int fd, ret, one = 1;

	ret = np_parse(argc, argv, &o);
	if (ret) {
		np_usage(stderr);
		return ret;
	}
	ret = np_tables_init(&t, &o, o.slots ? o.slots : o.window_groups);
	if (ret) {
		fprintf(stderr, "message size %llu is not whole groups on MTU %llu\n",
			(unsigned long long)o.size, (unsigned long long)o.mtu);
		return ret == -ENOMEM ? XG_EXIT_FAIL : XG_EXIT_USAGE;
	}
	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd >= 0 && !o.send) {
		int bytes = 64 << 20;

		/* A deep receive queue; FORCE needs CAP_NET_ADMIN, else best effort. */
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &bytes, sizeof(bytes)))
			(void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes));
	}
	if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) ||
	    bind(fd, (struct sockaddr *)&o.local, sizeof(o.local)) ||
	    (o.send && connect(fd, (struct sockaddr *)&o.remote, sizeof(o.remote)))) {
		fprintf(stderr, "SKIP: UDP endpoint: %s\n", strerror(errno));
		ret = XG_EXIT_UNAVAILABLE;
		goto out;
	}
	ret = o.send ? np_send(fd, &o, &t) : np_recv(fd, &o, &t);
	if (ret)
		fprintf(stderr, "nxp_peer %s: %s\n", o.send ? "send" : "recv", strerror(-ret));
	ret = ret ? XG_EXIT_FAIL : (fflush(stdout) ? XG_EXIT_FAIL : XG_EXIT_PASS);
out:
	if (fd >= 0)
		close(fd);
	free(t.blocks);
	free(t.crc);
	return ret;
}
