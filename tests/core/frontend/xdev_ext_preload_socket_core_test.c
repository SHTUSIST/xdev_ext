// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "../../../xdev_ext_preload_core.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_TRUE(expr) do {                                            \
	checks++;                                                           \
	if (!(expr)) {                                                      \
		fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n",        \
			__FILE__, __LINE__, #expr);                            \
		failures++;                                                \
	}                                                                   \
} while (0)

#define EXPECT_EQ(actual, expected) do {                                 \
	long long _actual = (long long)(actual);                           \
	long long _expected = (long long)(expected);                       \
	checks++;                                                           \
	if (_actual != _expected) {                                        \
		fprintf(stderr, "%s:%d: %s=%lld, expected %lld\n",        \
			__FILE__, __LINE__, #actual, _actual, _expected);       \
		failures++;                                                \
	}                                                                   \
} while (0)

struct fake_send {
	unsigned int submit_calls;
	unsigned int fallback_calls;
	bool published;
	int submit_ret;
	int cqe_res;
	ssize_t fallback_ret;
	int fallback_errno;
	int fallback_fd;
	const void *fallback_buffer;
	size_t fallback_count;
	uint32_t fallback_flags;
	struct io_uring_sqe observed;
};

static int fake_submit_and_wait(void *opaque, const struct io_uring_sqe *sqe,
				int *cqe_res, bool *published)
{
	struct fake_send *fake = opaque;

	fake->submit_calls++;
	fake->observed = *sqe;
	*published = fake->published;
	*cqe_res = fake->cqe_res;
	return fake->submit_ret;
}

static ssize_t fake_fallback(void *opaque, int fd, const void *buffer,
			     size_t count, uint32_t flags, int *error)
{
	struct fake_send *fake = opaque;

	fake->fallback_calls++;
	fake->fallback_fd = fd;
	fake->fallback_buffer = buffer;
	fake->fallback_count = count;
	fake->fallback_flags = flags;
	*error = fake->fallback_errno;
	return fake->fallback_ret;
}

static struct xdev_ext_preload_send_seam seam_for(struct fake_send *fake)
{
	return (struct xdev_ext_preload_send_seam) {
		.opaque = fake,
		.submit_and_wait = fake_submit_and_wait,
		.fallback = fake_fallback,
	};
}

static void test_supported_call_shapes(void)
{
	static const char payload[] = "connected-udp";
	struct sockaddr_storage destination = {};
	struct iovec iov = {
		.iov_base = (void *)payload,
		.iov_len = sizeof(payload),
	};
	struct iovec two_iov[2] = { iov, iov };
	struct msghdr message = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	const void *buffer = NULL;
	size_t count = 0;

	EXPECT_TRUE(xdev_ext_preload_send_buffer_supported(payload, sizeof(payload)));
	EXPECT_TRUE(xdev_ext_preload_send_buffer_supported(NULL, 0));
	EXPECT_TRUE(!xdev_ext_preload_send_buffer_supported(NULL, 1));
	EXPECT_TRUE(!xdev_ext_preload_send_buffer_supported(payload,
						  (size_t)UINT32_MAX + 1));

	EXPECT_TRUE(xdev_ext_preload_sendto_shape_supported(NULL, 0));
	EXPECT_TRUE(!xdev_ext_preload_sendto_shape_supported(NULL, 1));
	EXPECT_TRUE(!xdev_ext_preload_sendto_shape_supported(
		(const struct sockaddr *)&destination, sizeof(destination)));

	EXPECT_TRUE(xdev_ext_preload_sendmsg_shape_supported(&message, &buffer, &count));
	EXPECT_TRUE(buffer == payload);
	EXPECT_EQ(count, sizeof(payload));

	message.msg_name = &destination;
	message.msg_namelen = sizeof(destination);
	EXPECT_TRUE(!xdev_ext_preload_sendmsg_shape_supported(&message, &buffer, &count));
	message.msg_name = NULL;
	message.msg_namelen = 0;
	message.msg_control = &destination;
	message.msg_controllen = 1;
	EXPECT_TRUE(!xdev_ext_preload_sendmsg_shape_supported(&message, &buffer, &count));
	message.msg_control = NULL;
	message.msg_controllen = 0;
	message.msg_iov = two_iov;
	message.msg_iovlen = 2;
	EXPECT_TRUE(!xdev_ext_preload_sendmsg_shape_supported(&message, &buffer, &count));
	EXPECT_TRUE(!xdev_ext_preload_sendmsg_shape_supported(NULL, &buffer, &count));
}

static void test_flags_and_sqe_encoding(void)
{
	static const unsigned char payload[73] = {};
	struct io_uring_sqe sqe;
	uint32_t flags;

	EXPECT_TRUE(xdev_ext_preload_send_flags_supported(MSG_NOSIGNAL | MSG_MORE));
	EXPECT_TRUE(xdev_ext_preload_send_flags_supported(MSG_DONTWAIT));
	EXPECT_TRUE(!xdev_ext_preload_send_flags_supported(MSG_ZEROCOPY));
#ifdef MSG_FASTOPEN
	EXPECT_TRUE(!xdev_ext_preload_send_flags_supported(MSG_FASTOPEN));
#endif
	EXPECT_TRUE(!xdev_ext_preload_send_flags_supported(MSG_DONTROUTE));
	EXPECT_TRUE(!xdev_ext_preload_send_flags_supported(
		XDEV_EXT_PRELOAD_MSG_INTERNAL_SEND_FLAGS));
	flags = xdev_ext_preload_send_effective_flags(O_NONBLOCK, MSG_NOSIGNAL);
	EXPECT_TRUE(flags & MSG_DONTWAIT);
	EXPECT_TRUE(flags & MSG_NOSIGNAL);
	flags = xdev_ext_preload_send_effective_flags(0, MSG_MORE);
	EXPECT_EQ(flags, MSG_MORE);

	xdev_ext_preload_encode_send_sqe(&sqe, 17, payload, sizeof(payload),
				     MSG_NOSIGNAL, UINT64_C(0x12345000), 99);
	EXPECT_EQ(sqe.opcode, IORING_OP_UNIFIED_OPS);
	EXPECT_EQ(sqe.flags, 0);
	EXPECT_EQ(sqe.fd, 17);
	EXPECT_TRUE(sqe.addr == (uintptr_t)payload);
	EXPECT_EQ(sqe.len, IO_UNIFIED_OP_SEND);
	EXPECT_EQ(sqe.rw_flags, sizeof(payload));
	EXPECT_EQ(sqe.off, MSG_NOSIGNAL);
	EXPECT_EQ(sqe.addr3, UINT64_C(0x12345000));
	EXPECT_EQ(sqe.user_data, 99);

	xdev_ext_preload_encode_send_sqe(&sqe, 18, NULL, 0, 0,
				     UINT64_C(0x55550000), 100);
	EXPECT_TRUE(sqe.addr != 0);
	EXPECT_EQ(sqe.rw_flags, 0);
}

static void test_execute_and_fallback_boundaries(void)
{
	static const char payload[] = "payload";
	struct fake_send fake = {
		.published = true,
		.cqe_res = 3,
		.fallback_ret = 71,
	};
	struct xdev_ext_preload_send_seam seam = seam_for(&fake);
	int error = 0;
	ssize_t ret;

	ret = xdev_ext_preload_execute_send(true, 41, payload, sizeof(payload),
				       MSG_NOSIGNAL, UINT64_C(0x1000), 7,
				       &seam, &error);
	EXPECT_EQ(ret, 3);
	EXPECT_EQ(error, 0);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.fallback_calls, 0);
	EXPECT_EQ(fake.observed.fd, 41);

	/* A zero-length datagram still publishes once with a non-NULL sentinel. */
	memset(&fake, 0, sizeof(fake));
	fake.published = true;
	seam = seam_for(&fake);
	ret = xdev_ext_preload_execute_send(true, 46, NULL, 0, 0,
				       UINT64_C(0x1000), 12, &seam, &error);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(error, 0);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.fallback_calls, 0);
	EXPECT_TRUE(fake.observed.addr != 0);
	EXPECT_EQ(fake.observed.rw_flags, 0);

	/* Unproven flags must take the exact fallback before SQE publication. */
	memset(&fake, 0, sizeof(fake));
	fake.fallback_ret = 17;
	seam = seam_for(&fake);
	ret = xdev_ext_preload_execute_send(true, 47, payload, sizeof(payload),
				       MSG_ZEROCOPY, UINT64_C(0x1000), 13,
				       &seam, &error);
	EXPECT_EQ(ret, 17);
	EXPECT_EQ(fake.submit_calls, 0);
	EXPECT_EQ(fake.fallback_calls, 1);
	EXPECT_EQ(fake.fallback_flags, MSG_ZEROCOPY);

	memset(&fake, 0, sizeof(fake));
	fake.fallback_ret = 71;
	seam = seam_for(&fake);
	ret = xdev_ext_preload_execute_send(false, 42, payload, sizeof(payload), 0,
				       UINT64_C(0x1000), 8, &seam, &error);
	EXPECT_EQ(ret, 71);
	EXPECT_EQ(fake.submit_calls, 0);
	EXPECT_EQ(fake.fallback_calls, 1);
	EXPECT_EQ(fake.fallback_fd, 42);
	EXPECT_TRUE(fake.fallback_buffer == payload);
	EXPECT_EQ(fake.fallback_count, sizeof(payload));

	/* Failure before publication may fall back exactly once. */
	memset(&fake, 0, sizeof(fake));
	fake.submit_ret = -EIO;
	fake.fallback_ret = 19;
	seam = seam_for(&fake);
	ret = xdev_ext_preload_execute_send(true, 43, payload, sizeof(payload), 0,
				       UINT64_C(0x1000), 9, &seam, &error);
	EXPECT_EQ(ret, 19);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.fallback_calls, 1);

	/* Once published, an infrastructure error must never replay through libc. */
	memset(&fake, 0, sizeof(fake));
	fake.published = true;
	fake.submit_ret = -EINTR;
	fake.fallback_ret = 29;
	seam = seam_for(&fake);
	ret = xdev_ext_preload_execute_send(true, 44, payload, sizeof(payload), 0,
				       UINT64_C(0x1000), 10, &seam, &error);
	EXPECT_EQ(ret, -1);
	EXPECT_EQ(error, EINTR);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.fallback_calls, 0);

	memset(&fake, 0, sizeof(fake));
	fake.published = true;
	fake.cqe_res = -EAGAIN;
	seam = seam_for(&fake);
	ret = xdev_ext_preload_execute_send(true, 45, payload, sizeof(payload), 0,
				       UINT64_C(0x1000), 11, &seam, &error);
	EXPECT_EQ(ret, -1);
	EXPECT_EQ(error, EAGAIN);
	EXPECT_EQ(fake.fallback_calls, 0);

	memset(&fake, 0, sizeof(fake));
	fake.published = true;
	fake.cqe_res = sizeof(payload) + 1;
	seam = seam_for(&fake);
	ret = xdev_ext_preload_execute_send(true, 46, payload, sizeof(payload), 0,
				       UINT64_C(0x1000), 12, &seam, &error);
	EXPECT_EQ(ret, -1);
	EXPECT_EQ(error, EIO);
}

int main(void)
{
	test_supported_call_shapes();
	test_flags_and_sqe_encoding();
	test_execute_and_fallback_boundaries();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u socket preload checks\n",
			failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u socket preload checks\n", checks);
	return EXIT_SUCCESS;
}
