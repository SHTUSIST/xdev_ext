/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_XDG_NET_H
#define XDEV_EVAL_XDG_NET_H
/*
 * TCP helpers of the E4 tools: the control connection between the ranks
 * (configuration check and barriers; xdomain_gpu, nccl_pingpong) and the
 * data connection of the TCP+cudaMemcpy baseline.  Rank 1 listens, rank 0
 * connects.  Kernel default socket options apart from the ones a tool sets
 * and records (TCP_NODELAY).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static inline uint64_t xdg_now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static inline int xdg_split_addr(const char *spec, char *host, size_t hcap, char *port, size_t pcap)
{
	const char *colon = spec ? strrchr(spec, ':') : NULL;

	if (!colon || colon == spec || !colon[1] || (size_t)(colon - spec) >= hcap ||
	    strlen(colon + 1) >= pcap)
		return -EINVAL;
	memcpy(host, spec, (size_t)(colon - spec));
	host[colon - spec] = 0;
	strcpy(port, colon + 1);
	return 0;
}

/* Rank 1: listen on @spec and accept one peer.  Rank 0: connect, retrying for @timeout_s. */
static inline int xdg_tcp_open(const char *spec, int listen_side, int timeout_s)
{
	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *ai;
	char host[256], port[16];
	int fd = -1, one = 1, ret;
	uint64_t deadline = xdg_now_ns() + (uint64_t)timeout_s * 1000000000ULL;

	if (xdg_split_addr(spec, host, sizeof(host), port, sizeof(port)))
		return -EINVAL;
	if (listen_side)
		hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(host, port, &hints, &ai))
		return -EHOSTUNREACH;
	for (;;) {
		fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, 0);
		if (fd < 0)
			break;
		if (listen_side) {
			int c;

			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
			if (bind(fd, ai->ai_addr, ai->ai_addrlen) || listen(fd, 1)) {
				ret = -errno;
				close(fd);
				fd = ret;
				break;
			}
			c = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
			ret = c < 0 ? -errno : c;
			close(fd);
			fd = ret;
			break;
		}
		if (!connect(fd, ai->ai_addr, ai->ai_addrlen))
			break;
		ret = -errno;
		close(fd);
		fd = ret;
		if (xdg_now_ns() > deadline)
			break;
		usleep(100000);
	}
	freeaddrinfo(ai);
	return fd;
}

static inline int xdg_send_all(int fd, const void *buf, uint64_t n)
{
	const uint8_t *p = buf;

	while (n) {
		ssize_t k = send(fd, p, n, MSG_NOSIGNAL);

		if (k < 0 && errno == EINTR)
			continue;
		if (k <= 0)
			return k < 0 ? -errno : -EPIPE;
		p += k;
		n -= (uint64_t)k;
	}
	return 0;
}

static inline int xdg_recv_all(int fd, void *buf, uint64_t n)
{
	uint8_t *p = buf;

	while (n) {
		ssize_t k = recv(fd, p, n, 0);

		if (k < 0 && errno == EINTR)
			continue;
		if (k <= 0)
			return k < 0 ? -errno : -ECONNRESET;
		p += k;
		n -= (uint64_t)k;
	}
	return 0;
}

/* Both ranks send their configuration line; each refuses a different one. */
static inline int xdg_exchange_config(int fd, const char *mine)
{
	char theirs[512] = { 0 };
	uint32_t len = (uint32_t)strlen(mine), peer = 0;
	int ret;

	if (len >= sizeof(theirs))
		return -E2BIG;
	ret = xdg_send_all(fd, &len, sizeof(len));
	if (!ret)
		ret = xdg_send_all(fd, mine, len);
	if (!ret)
		ret = xdg_recv_all(fd, &peer, sizeof(peer));
	if (!ret && peer >= sizeof(theirs))
		ret = -E2BIG;
	if (!ret)
		ret = xdg_recv_all(fd, theirs, peer);
	if (!ret && (peer != len || memcmp(theirs, mine, len))) {
		fprintf(stderr, "the ranks disagree:\n  mine:   %s\n  theirs: %s\n", mine, theirs);
		ret = -EPROTO;
	}
	return ret;
}

/* One byte each way: both ranks have reached the same point. */
static inline int xdg_barrier(int fd, uint8_t tag)
{
	uint8_t got = 0;
	int ret = xdg_send_all(fd, &tag, 1);

	if (!ret)
		ret = xdg_recv_all(fd, &got, 1);
	return ret ? ret : got == tag ? 0 : -EPROTO;
}

#endif /* XDEV_EVAL_XDG_NET_H */
