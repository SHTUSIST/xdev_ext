// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static const char first_payload[] = "send";
static const char second_payload[] = "sendto-null";
static const char third_payload[] = "sendmsg";

static int receive_exact(int fd, const void *expected, size_t length)
{
	unsigned char buffer[128];
	ssize_t ret;

	memset(buffer, 0, sizeof(buffer));
	ret = recv(fd, buffer, sizeof(buffer), 0);
	if (ret != (ssize_t)length || memcmp(buffer, expected, length))
		return -1;
	return 0;
}

static int run_ipv4(void)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct iovec one = {
		.iov_base = (void *)third_payload,
		.iov_len = sizeof(third_payload),
	};
	struct msghdr message = {
		.msg_iov = &one,
		.msg_iovlen = 1,
	};
	socklen_t address_length = sizeof(address);
	int receiver = -1;
	int sender = -1;
	int ret = -1;

	receiver = socket(AF_INET, SOCK_DGRAM, 0);
	if (receiver < 0 || bind(receiver, (struct sockaddr *)&address,
				      sizeof(address)) ||
	    getsockname(receiver, (struct sockaddr *)&address, &address_length))
		goto out;
	sender = socket(AF_INET, SOCK_DGRAM, 0);
	if (sender < 0 || connect(sender, (struct sockaddr *)&address,
				       sizeof(address)))
		goto out;

	errno = EDOM;
	if (send(sender, first_payload, sizeof(first_payload), MSG_NOSIGNAL) !=
	    sizeof(first_payload) || errno != EDOM ||
	    receive_exact(receiver, first_payload, sizeof(first_payload)))
		goto out;
	errno = ERANGE;
	if (sendto(sender, second_payload, sizeof(second_payload), 0, NULL, 0) !=
	    sizeof(second_payload) || errno != ERANGE ||
	    receive_exact(receiver, second_payload, sizeof(second_payload)))
		goto out;
	errno = ENOTTY;
	if (sendmsg(sender, &message, 0) != sizeof(third_payload) ||
	    errno != ENOTTY ||
	    receive_exact(receiver, third_payload, sizeof(third_payload)))
		goto out;

	ret = 0;
out:
	if (sender >= 0)
		close(sender);
	if (receiver >= 0)
		close(receiver);
	return ret;
}

int main(void)
{
	if (run_ipv4()) {
		perror("connected UDP preload smoke");
		return EXIT_FAILURE;
	}
	printf("XDEV_EXT_TRANSPARENT_SOCKET_PAYLOAD=PASS sends=3 bytes=%zu\n",
	       sizeof(first_payload) + sizeof(second_payload) +
	       sizeof(third_payload));
	return EXIT_SUCCESS;
}
