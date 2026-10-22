// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

/* Ordinary libc calls, without private headers or a hand-assembled request. */
#define FILE_BYTES 8192
#define MESSAGE_BYTES 257
#define ROUNDS 17

static unsigned char pattern(size_t position, unsigned seed)
{
	return (unsigned char)(position * 37U + (position >> 5) + seed * 19U);
}

static int fail(const char *why)
{
	fprintf(stderr, "XDEV_EXT_APP_FALLBACK=FAIL check=%s errno=%d\n", why, errno);
	return 1;
}

static int receive_all(int fd, unsigned char *bytes, size_t length)
{
	while (length) {
		ssize_t n = read(fd, bytes, length);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		bytes += n;
		length -= (size_t)n;
	}
	return 0;
}

static int transmit_all(int fd, unsigned char *bytes, size_t length, unsigned api)
{
	while (length) {
		struct iovec iov[2] = {{bytes, length / 2},
			{bytes + length / 2, length - length / 2}};
		ssize_t n = api == 0 ? send(fd, bytes, length, MSG_NOSIGNAL) :
			api == 1 ? write(fd, bytes, length) : writev(fd, iov, 2);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0 || (size_t)n > length)
			return -1;
		bytes += n;
		length -= (size_t)n;
	}
	return 0;
}

static int tcp_shapes(void)
{
	struct sockaddr_in address = {.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	socklen_t alen = sizeof(address);
	struct { unsigned char left[16], data[MESSAGE_BYTES], right[16]; } received;
	unsigned char expected[MESSAGE_BYTES], sent[MESSAGE_BYTES];
	int listener = -1, tx = -1, rx = -1, result = -1;

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0 || bind(listener, (void *)&address, sizeof(address)) ||
	    getsockname(listener, (void *)&address, &alen) || listen(listener, 1))
		goto out;
	tx = socket(AF_INET, SOCK_STREAM, 0);
	if (tx < 0 || connect(tx, (void *)&address, sizeof(address)) ||
	    (rx = accept(listener, NULL, NULL)) < 0)
		goto out;
	for (unsigned round = 0; round < ROUNDS; round++) {
		for (unsigned api = 0; api < 3; api++) {
			for (size_t j = 0; j < sizeof(sent); j++)
				sent[j] = pattern(j, round * 3U + api);
			memset(&received, 0xa5, sizeof(received));
			if (transmit_all(tx, sent, sizeof(sent), api) ||
			    receive_all(rx, received.data, sizeof(received.data)))
				goto out;
			for (size_t j = 0; j < sizeof(expected); j++)
				expected[j] = pattern(j, round * 3U + api);
			if (memcmp(received.data, expected, sizeof(expected)))
				goto out;
			for (size_t j = 0; j < sizeof(received.left); j++)
				if (received.left[j] != 0xa5 || received.right[j] != 0xa5)
					goto out;
		}
	}
	if (shutdown(tx, SHUT_WR) || read(rx, received.data, 1) != 0)
		goto out;
	result = 0;
out:
	if (rx >= 0) close(rx);
	if (tx >= 0) close(tx);
	if (listener >= 0) close(listener);
	return result;
}

int main(int argc, char **argv)
{
	unsigned char expected[FILE_BYTES], log_record[64];
	struct { unsigned char left[16], data[FILE_BYTES], right[16]; } received;
	struct stat st;
	ssize_t direct_result;
	int fd, direct_fd, direct_errno;

	if (argc != 2) {
		fprintf(stderr, "usage: %s existing-disposable-regular-file\n", argv[0]);
		return 2;
	}
	alarm(20);
	fd = open(argv[1], O_RDWR | O_NOFOLLOW);
	if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || ftruncate(fd, 0))
		return fail("regular-file");
	for (size_t j = 0; j < sizeof(expected); j++) expected[j] = pattern(j, 71);
	for (size_t j = 0; j < sizeof(log_record); j++) log_record[j] = pattern(j, 97);
	if (transmit_all(fd, expected, sizeof(expected), 1)) return fail("buffered-write");
	direct_fd = open(argv[1], O_RDWR | O_DIRECT | O_NOFOLLOW);
	if (direct_fd < 0) {
		if (errno == EINVAL || errno == EOPNOTSUPP) {
			fprintf(stderr, "SKIP: filesystem does not accept O_DIRECT\n");
			close(fd);
			return 4;
		}
		return fail("direct-open");
	}
	/* Offset 1 and length 64 are deliberately outside the admitted shape.
	 * Some filesystems ignore O_DIRECT. Compare their actual libc semantics. */
	errno = 0;
	direct_result = pwrite(direct_fd, log_record, sizeof(log_record), 1);
	direct_errno = errno;
	if (direct_result > (ssize_t)sizeof(log_record) || direct_result < -1)
		return fail("direct-result");
	if (direct_result > 0) memcpy(expected + 1, log_record, (size_t)direct_result);
	if (close(direct_fd) || lseek(fd, 0, SEEK_SET) != 0) return fail("file-seek");
	memset(&received, 0xa5, sizeof(received));
	if (receive_all(fd, received.data, sizeof(received.data)) ||
	    memcmp(received.data, expected, sizeof(expected)) ||
	    read(fd, log_record, 1) != 0 || fstat(fd, &st) || st.st_size != FILE_BYTES)
		return fail("whole-file");
	for (size_t j = 0; j < sizeof(received.left); j++)
		if (received.left[j] != 0xa5 || received.right[j] != 0xa5)
			return fail("file-guards");
	if (close(fd) || tcp_shapes()) return fail("tcp-full-payload");
	printf("XDEV_EXT_APP_FALLBACK=PASS file_bytes=%u tcp_messages=%u tcp_bytes=%u "
	       "direct64_result=%zd direct64_errno=%d full_compare=1 guards=1 tcp_eof=1\n",
	       FILE_BYTES, ROUNDS * 3, ROUNDS * 3 * MESSAGE_BYTES,
	       direct_result, direct_errno);
	return 0;
}
