// SPDX-License-Identifier: GPL-2.0
/* Bounded ordinary-libc compatibility shape; no device/performance evidence. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RECORD 48
#define GUARD 16
#define MAX_RECORDS 4096
#define DEADLINE_SECONDS 20

struct actor {
	int fd, sync_fd, file, status;
	unsigned int count;
	struct sockaddr_in destination;
	struct timespec deadline;
};

static uint64_t decode(const unsigned char *bytes)
{
	uint64_t value = 0;
	for (unsigned int i = 0; i < 8; i++)
		value |= (uint64_t)bytes[i] << (8 * i);
	return value;
}

static void encode(unsigned char *bytes, uint64_t value)
{
	for (unsigned int i = 0; i < 8; i++)
		bytes[i] = (unsigned char)(value >> (8 * i));
}

static uint64_t checksum(const unsigned char *bytes)
{
	uint64_t value = UINT64_C(14695981039346656037);
	for (unsigned int i = 0; i < 40; i++) {
		value ^= bytes[i];
		value *= UINT64_C(1099511628211);
	}
	return value;
}

/* One absolute deadline bounds retries, including repeated EINTR. */
static int ready(int fd, short events, const struct timespec *deadline)
{
	for (;;) {
		struct timespec now;
		struct pollfd pfd = { .fd = fd, .events = events };
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			return -1;
		int64_t remaining = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000 +
			(deadline->tv_nsec - now.tv_nsec) / 1000000;
		if (remaining <= 0) {
			errno = ETIMEDOUT;
			return -1;
		}
		int result = poll(&pfd, 1, remaining > INT_MAX ? INT_MAX : (int)remaining);
		if (result > 0) {
			if (pfd.revents & (events | POLLHUP))
				return 0;
			errno = EIO;
			return -1;
		}
		if (!result)
			errno = ETIMEDOUT;
		if (result >= 0 || errno != EINTR)
			return -1;
	}
}

static int stream_send(int fd, const unsigned char *bytes, size_t length,
		       const struct timespec *deadline)
{
	while (length) {
		if (ready(fd, POLLOUT, deadline))
			return -1;
		ssize_t sent = send(fd, bytes, length, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
			continue;
		if (sent <= 0)
			return -1;
		bytes += sent;
		length -= (size_t)sent;
	}
	return 0;
}

static int write_at(int fd, const unsigned char *bytes, size_t length, off_t offset)
{
	while (length) {
		ssize_t written = pwrite(fd, bytes, length, offset);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			return -1;
		bytes += written;
		length -= (size_t)written;
		offset += written;
	}
	return 0;
}

static int bind_loopback(int fd, struct sockaddr_in *address)
{
	*address = (struct sockaddr_in){ .sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = 0 };
	socklen_t length = sizeof(*address);
	return bind(fd, (struct sockaddr *)address, length) ||
		getsockname(fd, (struct sockaddr *)address, &length) ? -1 : 0;
}

static void *feed_ticks(void *argument)
{
	struct actor *actor = argument;
	for (uint64_t sequence = 1; sequence <= actor->count; sequence++) {
		unsigned char tick[RECORD], ack;
		uint64_t bid = 9900 + (37 * sequence) % 211;
		uint64_t fields[] = { sequence, bid, bid + 2 + sequence % 7,
			1 + (3 * sequence) % 97, 1 + (5 * sequence) % 89 };
		for (unsigned int i = 0; i < 5; i++)
			encode(tick + 8 * i, fields[i]);
		encode(tick + 40, checksum(tick));
		ssize_t sent;
		do {
			if (ready(actor->fd, POLLOUT, &actor->deadline))
				return NULL;
			sent = sendto(actor->fd, tick, sizeof(tick), MSG_DONTWAIT | MSG_NOSIGNAL,
				(struct sockaddr *)&actor->destination, sizeof(actor->destination));
		} while (sent < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
		if (sent != RECORD)
			return NULL;
		ssize_t received;
		do {
			if (ready(actor->sync_fd, POLLIN, &actor->deadline))
				return NULL;
			received = recv(actor->sync_fd, &ack, 1, MSG_DONTWAIT);
		} while (received < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
		if (received != 1 || ack != 1)
			return NULL;
	}
	actor->status = 0;
	return NULL;
}

static void *capture_stream(void *argument)
{
	struct actor *actor = argument;
	size_t offset = 0, expected = (size_t)actor->count * RECORD;
	for (;;) {
		unsigned char buffer[1024];
		if (ready(actor->fd, POLLIN, &actor->deadline))
			return NULL;
		ssize_t received = recv(actor->fd, buffer, sizeof(buffer), MSG_DONTWAIT);
		if (received < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
			continue;
		if (received < 0)
			return NULL;
		if (!received) {
			if (offset == expected)
				actor->status = 0;
			return NULL;
		}
		if ((size_t)received > expected - offset ||
		    write_at(actor->file, buffer, (size_t)received, (off_t)offset))
			return NULL;
		offset += (size_t)received;
	}
}

static int join_actor(pthread_t thread, const struct timespec *deadline)
{
	/* The realtime conversion is used only for pthread_timedjoin_np. The
	 * process alarm is a final bound if the system clock changes meanwhile. */
	struct timespec now, limit;
	if (clock_gettime(CLOCK_MONOTONIC, &now) || clock_gettime(CLOCK_REALTIME, &limit))
		return -1;
	limit.tv_sec += deadline->tv_sec - now.tv_sec;
	limit.tv_nsec += deadline->tv_nsec - now.tv_nsec;
	if (limit.tv_nsec < 0) {
		limit.tv_sec--;
		limit.tv_nsec += 1000000000;
	} else if (limit.tv_nsec >= 1000000000) {
		limit.tv_sec++;
		limit.tv_nsec -= 1000000000;
	}
	return pthread_timedjoin_np(thread, NULL, &limit);
}

int main(int argc, char **argv)
{
	unsigned int count = 65;
	if (argc != 3 && argc != 4)
		return 2;
	if (argc == 4) {
		char *end;
		errno = 0;
		unsigned long parsed = strtoul(argv[3], &end, 10);
		if (!argv[3][0] || argv[3][0] < '0' || argv[3][0] > '9' ||
		    errno || *end || parsed < 1 || parsed > MAX_RECORDS)
			return 2;
		count = (unsigned int)parsed;
	}
	/* Even filesystem stalls or a broken actor cannot outlive this cap. */
	alarm(DEADLINE_SECONDS + 5);
	int audit = -1, capture = -1, udp = -1, sender = -1;
	int listener = -1, tcp = -1, accepted = -1, sync[2] = { -1, -1 };
	int result = 1, feeder_started = 0, sink_started = 0;
	pthread_t feeder, sink;
	struct actor feed = { .status = 1, .count = count };
	struct actor receiver = { .status = 1, .count = count };
	if (clock_gettime(CLOCK_MONOTONIC, &feed.deadline))
		goto cleanup;
	feed.deadline.tv_sec += DEADLINE_SECONDS;
	receiver.deadline = feed.deadline;
	audit = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (audit < 0)
		goto cleanup;
	capture = open(argv[2], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (capture < 0)
		goto cleanup;
	unsigned char guard[GUARD];
	memset(guard, 0xa5, sizeof(guard));
	if (write_at(audit, guard, sizeof(guard), 0))
		goto cleanup;
	memset(guard, 0x5a, sizeof(guard));
	if (write_at(audit, guard, sizeof(guard), GUARD + (off_t)count * RECORD))
		goto cleanup;
	udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	tcp = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_in unused, tcp_address;
	if (udp < 0 || sender < 0 || listener < 0 || tcp < 0 ||
	    bind_loopback(udp, &feed.destination) || bind_loopback(sender, &unused) ||
	    bind_loopback(listener, &tcp_address) || bind_loopback(tcp, &unused) ||
	    socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sync) || listen(listener, 1) ||
	    connect(tcp, (struct sockaddr *)&tcp_address, sizeof(tcp_address)) ||
	    ready(listener, POLLIN, &feed.deadline))
		goto cleanup;
	accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (accepted < 0)
		goto cleanup;
	feed.fd = sender;
	feed.sync_fd = sync[1];
	receiver.fd = accepted;
	receiver.file = capture;
	if (pthread_create(&sink, NULL, capture_stream, &receiver))
		goto cleanup;
	sink_started = 1;
	if (pthread_create(&feeder, NULL, feed_ticks, &feed))
		goto cleanup;
	feeder_started = 1;
	uint64_t previous = 10000;
	for (uint64_t sequence = 1; sequence <= count; sequence++) {
		unsigned char tick[RECORD], record[RECORD], ack = 1;
		ssize_t received;
		do {
			if (ready(udp, POLLIN, &feed.deadline))
				goto cleanup;
			received = recvfrom(udp, tick, sizeof(tick), MSG_DONTWAIT | MSG_TRUNC, NULL, NULL);
		} while (received < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
		if (received != RECORD || decode(tick) != sequence ||
		    decode(tick + 40) != checksum(tick))
			goto cleanup;
		uint64_t bid = decode(tick + 8), ask = decode(tick + 16);
		/* Validate the complete deterministic tick, including both quantities. */
		if (bid != 9900 + (37 * sequence) % 211 || ask != bid + 2 + sequence % 7 ||
		    decode(tick + 24) != 1 + (3 * sequence) % 97 ||
		    decode(tick + 32) != 1 + (5 * sequence) % 89)
			goto cleanup;
		uint64_t mid = (bid + ask) / 2;
		previous = (95 * previous + 5 * mid) / 100;
		uint64_t action = (mid > previous ? mid - previous : previous - mid) > 1;
		uint64_t fields[] = { sequence, decode(tick + 40), mid, previous, action };
		for (unsigned int i = 0; i < 5; i++)
			encode(record + 8 * i, fields[i]);
		encode(record + 40, checksum(record));
		/* Causal order: complete buffered audit write, then complete TCP send.
		 * This is not an atomic commit, fsync, or a remote acknowledgement. */
		if (write_at(audit, record, sizeof(record), GUARD + (off_t)(sequence - 1) * RECORD) ||
		    stream_send(tcp, record, sizeof(record), &feed.deadline) ||
		    stream_send(sync[0], &ack, 1, &feed.deadline))
			goto cleanup;
	}
	if (shutdown(tcp, SHUT_WR))
		goto cleanup;
	result = 0;
cleanup:
	if (result) {
		if (sync[0] >= 0)
			shutdown(sync[0], SHUT_RDWR);
		if (tcp >= 0)
			shutdown(tcp, SHUT_RDWR);
		if (accepted >= 0)
			shutdown(accepted, SHUT_RDWR);
	}
	/* On join failure exit immediately: actor arguments are stack-owned and
	 * their fds must not be closed/reused while a thread may still use them. */
	if ((feeder_started && join_actor(feeder, &feed.deadline)) ||
	    (sink_started && join_actor(sink, &feed.deadline))) {
		fputs("mixed workload: actor join failed\n", stderr);
		_exit(1);
	}
	if (feed.status || receiver.status)
		result = 1;
	int fds[] = { audit, capture, udp, sender, listener, tcp, accepted, sync[0], sync[1] };
	for (unsigned int i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
		if (fds[i] >= 0 && close(fds[i]))
			result = 1;
	if (result) {
		fputs("mixed workload: incomplete pipeline or I/O failure\n", stderr);
		return 1;
	}
	printf("{\"evidence\":\"ordinary-libc-workload\",\"scope\":\"compatibility\","
	       "\"records\":%u,\"udp_records\":%u,\"audit_records\":%u,\"tcp_records\":%u,"
	       "\"record_bytes\":48,\"feeder_status\":0,\"sink_status\":0}\n", count, count, count, count);
	return 0;
}
