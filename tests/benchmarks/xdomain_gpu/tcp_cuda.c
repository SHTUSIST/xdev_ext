// SPDX-License-Identifier: GPL-2.0
/*
 * tcp_cuda - E4 baseline 1: TCP over thunderbolt-net + cudaMemcpy, VRAM to VRAM.
 *
 *   rank 1: tcp_cuda --rank 1 --listen ADDR:PORT [options]
 *   rank 0: tcp_cuda --rank 0 --peer   ADDR:PORT [options]
 *
 * One TCP connection, kernel default sysctls and the interface's default
 * MTU; TCP_NODELAY is on (recorded) unless --no-nodelay.  The sender copies
 * the message from VRAM into a pinned host buffer (cuMemHostAlloc, i.e.
 * cudaHostAlloc) with a synchronous D2H copy and send()s it; the receiver
 * recv()s it completely and copies it to VRAM with a synchronous H2D copy.
 * No pipelining or tuning beyond that ordinary pattern (plan E4, baseline 1).
 *
 * pingpong: rank 0 sends a message from its VRAM, rank 1 receives it into
 *   VRAM, then sends one message of the same size from its VRAM (only after
 *   the received copy completed), rank 0 receives it into VRAM.  Rank 0
 *   times each round trip with CLOCK_MONOTONIC after --warmup rounds and
 *   reports median/p99 RTT and RTT/2 (a symmetric estimate, not a measured
 *   one-way latency).  The messages carry each rank's slot-0 image; both
 *   ranks check their received VRAM after the timed loop.
 * stream: rank 0 sends --stream-messages messages from a ring of --window
 *   VRAM slots, rank 1 receives them into its ring; rank 1 times from its
 *   READY to the last H2D copy on its own clock and reports Gb/s of unique
 *   bytes, counted only when every receive slot holds the sender's image of
 *   that slot afterwards.
 *
 * Both ranks must give the same options (checked at connect).  One JSON
 * line per size on stdout.  --fake-gpu replaces VRAM with host memory for
 * host checks (execution host-fake, performance_claim none).
 * Exit: 0 pass, 1 failure, 2 usage, 4 no CUDA driver.
 */
#define _GNU_SOURCE
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>

#include "xdg_core.h"
#include "xdg_net.h"
#include "xdg_gpu.h"

enum mode { MODE_PINGPONG, MODE_STREAM };

struct opts {
	int rank, gpu, window, timeout_s;
	enum mode mode;
	const char *peer, *listen, *sizes_arg;
	uint64_t sizes[XDG_MAX_SIZES], iters, warmup, messages, seed;
	int nsizes;
	bool nodelay, fake;
};

struct run {
	struct opts o;
	struct xdg_gpu g;
	int fd;
	uint64_t tx, rx;	/* device rings of window * size_max bytes */
	void *host, *scratch;
};

static void usage(void)
{
	fprintf(stderr,
		"usage: tcp_cuda --rank 0 --peer HOST:PORT | --rank 1 --listen HOST:PORT\n"
		"       [--mode pingpong|stream] [--sizes LIST] [--iters N] [--warmup N]\n"
		"       [--stream-messages N] [--window SLOTS] [--seed N] [--gpu N]\n"
		"       [--no-nodelay] [--fake-gpu] [--timeout-s S]\n");
}

static int parse(int argc, char **argv, struct opts *o)
{
	static const struct option lo[] = {
		{ "rank", required_argument, NULL, 'r' }, { "peer", required_argument, NULL, 'p' },
		{ "listen", required_argument, NULL, 'l' }, { "mode", required_argument, NULL, 'm' },
		{ "sizes", required_argument, NULL, 's' }, { "iters", required_argument, NULL, 'i' },
		{ "warmup", required_argument, NULL, 'w' },
		{ "stream-messages", required_argument, NULL, 'n' },
		{ "window", required_argument, NULL, 'W' }, { "seed", required_argument, NULL, 'S' },
		{ "gpu", required_argument, NULL, 'g' }, { "no-nodelay", no_argument, NULL, 'D' },
		{ "fake-gpu", no_argument, NULL, 'F' }, { "timeout-s", required_argument, NULL, 't' },
		{ 0 }
	};
	uint64_t v;
	int c;

	*o = (struct opts){ .rank = -1, .window = 32, .timeout_s = 60, .iters = 1000,
			    .warmup = 100, .seed = 1, .nodelay = true };
	while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
		const char *a = optarg;
		size_t n = a ? strlen(a) : 0;

		switch (c) {
		case 'r': if (xdg_parse_u64(a, n, 1, &v)) return -EINVAL; o->rank = (int)v; break;
		case 'p': o->peer = a; break;
		case 'l': o->listen = a; break;
		case 'm':
			if (!strcmp(a, "pingpong")) o->mode = MODE_PINGPONG;
			else if (!strcmp(a, "stream")) o->mode = MODE_STREAM;
			else return -EINVAL;
			break;
		case 's': o->sizes_arg = a; break;
		case 'i': if (xdg_parse_u64(a, n, 100000000, &o->iters) || !o->iters) return -EINVAL; break;
		case 'w': if (xdg_parse_u64(a, n, 100000000, &o->warmup)) return -EINVAL; break;
		case 'n': if (xdg_parse_u64(a, n, 1u << 24, &o->messages)) return -EINVAL; break;
		case 'W': if (xdg_parse_u64(a, n, 64, &v) || !v) return -EINVAL; o->window = (int)v; break;
		case 'S': if (xdg_parse_u64(a, n, UINT32_MAX, &o->seed)) return -EINVAL; break;
		case 'g': if (xdg_parse_u64(a, n, 64, &v)) return -EINVAL; o->gpu = (int)v; break;
		case 'D': o->nodelay = false; break;
		case 'F': o->fake = true; break;
		case 't': if (xdg_parse_u64(a, n, 3600, &v) || !v) return -EINVAL; o->timeout_s = (int)v; break;
		default: return -EINVAL;
		}
	}
	if (optind != argc || o->rank < 0 || (o->rank == 0) != !!o->peer ||
	    (o->rank == 1) != !!o->listen)
		return -EINVAL;
	o->nsizes = xdg_parse_sizes(o->sizes_arg, o->sizes);
	return o->nsizes < 0 ? -EINVAL : 0;
}

static uint64_t stream_messages(const struct opts *o, uint64_t size)
{
	uint64_t n = o->messages ? o->messages : (256ULL << 20) / size;

	return n < (uint64_t)o->window ? (uint64_t)o->window : n;
}

static void common_json(const struct run *r, uint64_t size, const char *role)
{
	printf("{\"tool\": \"tcp_cuda\", \"arm\": \"tcp-cudamemcpy\", \"rank\": %d, \"role\": \"%s\", "
	       "\"mode\": \"%s\", \"size\": %" PRIu64 ", \"tcp_nodelay\": %s, "
	       "\"execution\": \"%s\", \"performance_claim\": \"%s\", \"cuda_driver_version\": %d, "
	       "\"cuda_api\": \"driver: cuMemHostAlloc(0) + synchronous cuMemcpyDtoH/HtoD\"",
	       r->o.rank, role, r->o.mode == MODE_PINGPONG ? "pingpong" : "stream", size,
	       r->o.nodelay ? "true" : "false", xdg_gpu_execution(&r->g),
	       r->g.fake ? "none" : "e4-vram-to-vram", r->g.driver_version);
}

/* Received VRAM slot @slot holds the image @seed of the sender's slot @slot. */
static int verify_slot(struct run *r, uint64_t size, uint64_t seed, uint64_t slot, bool *ok)
{
	uint64_t bad;
	int ret = xdg_gpu_dtoh(&r->g, r->scratch, r->rx + slot * size, size);

	*ok = !ret && !xdg_check(r->scratch, size, seed, slot, &bad);
	return ret;
}

static int pingpong(struct run *r, uint64_t size)
{
	uint64_t total = r->o.warmup + r->o.iters, *rtt = NULL, mine = r->o.seed + (uint64_t)r->o.rank,
		 theirs = r->o.seed + (uint64_t)(1 - r->o.rank);
	uint8_t peer_ok = 0, my_ok;
	struct xdg_stats st = { 0 };
	bool ok = false;
	int ret;

	ret = xdg_gpu_seed(&r->g, r->tx, size, mine, 0, r->scratch);
	if (!ret && r->o.rank == 0 && !(rtt = calloc(r->o.iters, sizeof(*rtt))))
		ret = -ENOMEM;
	if (!ret)
		ret = xdg_barrier(r->fd, 'P');
	for (uint64_t i = 0; i < total && !ret; i++) {
		uint64_t t0 = xdg_now_ns();

		if (r->o.rank == 0) {
			ret = xdg_gpu_dtoh(&r->g, r->host, r->tx, size);
			if (!ret)
				ret = xdg_send_all(r->fd, r->host, size);
			if (!ret)
				ret = xdg_recv_all(r->fd, r->host, size);
			if (!ret)
				ret = xdg_gpu_htod(&r->g, r->rx, r->host, size);
			if (!ret && i >= r->o.warmup)
				rtt[i - r->o.warmup] = xdg_now_ns() - t0;
		} else {
			ret = xdg_recv_all(r->fd, r->host, size);
			if (!ret)
				ret = xdg_gpu_htod(&r->g, r->rx, r->host, size);
			if (!ret)
				ret = xdg_gpu_dtoh(&r->g, r->host, r->tx, size);
			if (!ret)
				ret = xdg_send_all(r->fd, r->host, size);
		}
	}
	if (!ret)
		ret = verify_slot(r, size, theirs, 0, &ok);
	my_ok = ok;
	if (!ret)
		ret = xdg_send_all(r->fd, &my_ok, 1);
	if (!ret)
		ret = xdg_recv_all(r->fd, &peer_ok, 1);
	if (!ret && r->o.rank == 0) {
		xdg_stats(rtt, r->o.iters, &st);
		common_json(r, size, "initiator");
		printf(", \"warmup\": %" PRIu64 ", \"clock\": \"CLOCK_MONOTONIC rank 0\", "
		       "\"rtt_ns\": {\"n\": %" PRIu64 ", \"min\": %" PRIu64 ", \"median\": %" PRIu64
		       ", \"p99\": %" PRIu64 ", \"max\": %" PRIu64 "}, \"half_rtt_ns_median\": %" PRIu64
		       ", \"verified\": %s, \"peer_verified\": %s}\n", r->o.warmup, st.n, st.min,
		       st.median, st.p99, st.max, st.median / 2, ok ? "true" : "false",
		       peer_ok ? "true" : "false");
	} else if (!ret) {
		common_json(r, size, "echo");
		printf(", \"verified\": %s, \"peer_verified\": %s}\n", ok ? "true" : "false",
		       peer_ok ? "true" : "false");
	}
	fflush(stdout);
	free(rtt);
	return ret ? ret : (ok && peer_ok) ? 0 : -EIO;
}

static int stream(struct run *r, uint64_t size)
{
	uint64_t n = stream_messages(&r->o, size), W = (uint64_t)r->o.window, t0 = 0, t1 = 0;
	uint8_t ready = 0;
	bool ok = true;
	int ret = 0;

	if (r->o.rank == 0)
		for (uint64_t s = 0; s < W && !ret; s++)
			ret = xdg_gpu_seed(&r->g, r->tx, size, r->o.seed, s, r->scratch);
	if (!ret)
		ret = xdg_barrier(r->fd, 'S');
	if (r->o.rank == 1) {
		if (!ret)
			ret = xdg_send_all(r->fd, "R", 1);
		t0 = xdg_now_ns();
		for (uint64_t k = 0; k < n && !ret; k++) {
			ret = xdg_recv_all(r->fd, r->host, size);
			if (!ret)
				ret = xdg_gpu_htod(&r->g, r->rx + (k % W) * size, r->host, size);
		}
		t1 = xdg_now_ns();
		for (uint64_t s = 0; s < W && s < n && !ret; s++) {
			bool slot_ok;

			ret = verify_slot(r, size, r->o.seed, s, &slot_ok);
			ok = ok && slot_ok;
		}
		if (!ret) {
			common_json(r, size, "receiver");
			printf(", \"messages\": %" PRIu64 ", \"window\": %" PRIu64 ", \"clock\": "
			       "\"CLOCK_MONOTONIC rank 1 (receiver)\", \"elapsed_ns\": %" PRIu64
			       ", \"verified\": %s, \"verified_bytes\": %" PRIu64 ", \"gbps\": %.6f}\n",
			       n, W, t1 - t0, ok ? "true" : "false", ok ? n * size : 0,
			       ok ? xdg_gbps(n * size, t1 - t0) : 0.0);
		}
	} else {
		if (!ret)
			ret = xdg_recv_all(r->fd, &ready, 1);
		if (!ret && ready != 'R')
			ret = -EPROTO;
		t0 = xdg_now_ns();
		for (uint64_t k = 0; k < n && !ret; k++) {
			ret = xdg_gpu_dtoh(&r->g, r->host, r->tx + (k % W) * size, size);
			if (!ret)
				ret = xdg_send_all(r->fd, r->host, size);
		}
		t1 = xdg_now_ns();
		if (!ret) {
			common_json(r, size, "sender");
			printf(", \"messages\": %" PRIu64 ", \"window\": %" PRIu64
			       ", \"sender_elapsed_ns\": %" PRIu64 "}\n", n, W, t1 - t0);
		}
	}
	fflush(stdout);
	/* The receiver's verdict ends the size on both ranks. */
	if (!ret) {
		uint8_t v = ok, peer = 1;

		ret = r->o.rank == 1 ? xdg_send_all(r->fd, &v, 1) : xdg_recv_all(r->fd, &peer, 1);
		ok = ok && peer;
	}
	return ret ? ret : ok ? 0 : -EIO;
}

int main(int argc, char **argv)
{
	struct run r = { .fd = -1 };
	char config[512];
	uint64_t max = 0;
	int ret, one = 1, i;

	if (parse(argc, argv, &r.o)) {
		usage();
		return XDG_EXIT_USAGE;
	}
	max = r.o.sizes[r.o.nsizes - 1];
	ret = xdg_gpu_open(&r.g, r.o.gpu, r.o.fake);
	if (ret == -ENOSYS) {
		fprintf(stderr, "tcp_cuda: no CUDA driver (libcuda.so.1)\n");
		return XDG_EXIT_UNAVAILABLE;
	}
	if (!ret)
		ret = xdg_gpu_alloc(&r.g, (uint64_t)r.o.window * max, &r.tx);
	if (!ret)
		ret = xdg_gpu_alloc(&r.g, (uint64_t)r.o.window * max, &r.rx);
	if (!ret)
		ret = xdg_gpu_host_alloc(&r.g, max, &r.host);
	if (!ret && !(r.scratch = malloc(max)))
		ret = -ENOMEM;
	if (ret) {
		fprintf(stderr, "tcp_cuda: GPU setup: %s\n", strerror(-ret));
		return XDG_EXIT_FAIL;
	}
	r.fd = xdg_tcp_open(r.o.rank ? r.o.listen : r.o.peer, r.o.rank, r.o.timeout_s);
	if (r.fd < 0) {
		fprintf(stderr, "tcp_cuda: connection: %s\n", strerror(-r.fd));
		return XDG_EXIT_FAIL;
	}
	if (r.o.nodelay && setsockopt(r.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one))) {
		perror("TCP_NODELAY");
		return XDG_EXIT_FAIL;
	}
	snprintf(config, sizeof(config), "tcp_cuda v1 mode=%d sizes=%s iters=%" PRIu64 " warmup=%"
		 PRIu64 " messages=%" PRIu64 " window=%d seed=%" PRIu64 " nodelay=%d fake=%d",
		 r.o.mode, r.o.sizes_arg ? r.o.sizes_arg : "default", r.o.iters, r.o.warmup,
		 r.o.messages, r.o.window, r.o.seed, r.o.nodelay, r.o.fake);
	ret = xdg_exchange_config(r.fd, config);
	for (i = 0; i < r.o.nsizes && !ret; i++)
		ret = r.o.mode == MODE_PINGPONG ? pingpong(&r, r.o.sizes[i]) : stream(&r, r.o.sizes[i]);
	if (ret)
		fprintf(stderr, "tcp_cuda: rank %d: %s\n", r.o.rank, strerror(-ret));
	close(r.fd);
	xdg_gpu_free(&r.g, r.tx);
	xdg_gpu_free(&r.g, r.rx);
	xdg_gpu_host_free(&r.g, r.host);
	free(r.scratch);
	xdg_gpu_close(&r.g);
	return ret ? XDG_EXIT_FAIL : XDG_EXIT_PASS;
}
