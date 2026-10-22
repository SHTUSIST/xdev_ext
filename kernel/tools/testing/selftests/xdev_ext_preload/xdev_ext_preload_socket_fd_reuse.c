// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const char payload[] = "stable-open-file-description";

struct send_state {
	int fd;
	ssize_t result;
	int error;
};

static int bind_loopback_udp(struct sockaddr_in *address)
{
	socklen_t length = sizeof(*address);
	int fd;

	memset(address, 0, sizeof(*address));
	address->sin_family = AF_INET;
	address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0 || bind(fd, (struct sockaddr *)address, sizeof(*address)) ||
	    getsockname(fd, (struct sockaddr *)address, &length)) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	return fd;
}

static int connected_udp(const struct sockaddr_in *address)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0 || connect(fd, (const struct sockaddr *)address,
			      sizeof(*address))) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	return fd;
}

static void *send_one(void *opaque)
{
	struct send_state *state = opaque;

	errno = EDOM;
	state->result = send(state->fd, payload, sizeof(payload), 0);
	state->error = errno;
	return NULL;
}

int main(void)
{
	typedef int (*barrier_fn)(void);
	struct timeval timeout = { .tv_sec = 2 };
	struct sockaddr_in first_address;
	struct sockaddr_in second_address;
	struct send_state state;
	barrier_fn wait_until_blocked;
	barrier_fn release;
	unsigned char received[sizeof(payload)];
	pthread_t thread;
	int first_receiver = -1;
	int second_receiver = -1;
	int original_sender = -1;
	int replacement = -1;
	int thread_started = 0;
	int ret = EXIT_FAILURE;

	wait_until_blocked = (barrier_fn)dlsym(RTLD_DEFAULT,
					       "test_socket_barrier_wait_until_blocked");
	release = (barrier_fn)dlsym(RTLD_DEFAULT, "test_socket_barrier_release");
	if (!wait_until_blocked || !release)
		goto out;
	first_receiver = bind_loopback_udp(&first_address);
	second_receiver = bind_loopback_udp(&second_address);
	if (first_receiver < 0 || second_receiver < 0)
		goto out;
	if (setsockopt(first_receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)) ||
	    setsockopt(second_receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		       sizeof(timeout)))
		goto out;
	original_sender = connected_udp(&first_address);
	replacement = connected_udp(&second_address);
	if (original_sender < 0 || replacement < 0)
		goto out;
	state = (struct send_state) { .fd = original_sender, .result = -1 };
	if (pthread_create(&thread, NULL, send_one, &state))
		goto out;
	thread_started = 1;
	if (wait_until_blocked())
		goto release_and_out;
	if (close(original_sender))
		goto release_and_out;
	if (dup2(replacement, original_sender) != original_sender)
		goto release_and_out;
	if (release())
		goto out;
	if (pthread_join(thread, NULL))
		goto out;
	thread_started = 0;
	if (state.result != (ssize_t)sizeof(payload) || state.error != EDOM)
		goto out;
	if (recv(first_receiver, received, sizeof(received), 0) !=
		    (ssize_t)sizeof(received) ||
	    memcmp(received, payload, sizeof(payload)))
		goto out;
	errno = 0;
	if (recv(second_receiver, received, sizeof(received), MSG_DONTWAIT) >= 0 ||
	    (errno != EAGAIN && errno != EWOULDBLOCK))
		goto out;
	printf("XDEV_EXT_TRANSPARENT_SOCKET_FD_REUSE=PASS sends=1 bytes=%zu\n",
	       sizeof(payload));
	ret = EXIT_SUCCESS;
	goto out;

release_and_out:
	(void)release();
out:
	if (thread_started)
		pthread_join(thread, NULL);
	if (replacement >= 0)
		close(replacement);
	if (original_sender >= 0)
		close(original_sender);
	if (second_receiver >= 0)
		close(second_receiver);
	if (first_receiver >= 0)
		close(first_receiver);
	if (ret != EXIT_SUCCESS)
		fprintf(stderr, "connected UDP fd-reuse test failed\n");
	return ret;
}
