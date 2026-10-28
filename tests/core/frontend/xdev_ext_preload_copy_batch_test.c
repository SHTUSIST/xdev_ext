// SPDX-License-Identifier: GPL-2.0
/*
 * The vector gather/scatter of the positional front end must cost one
 * kernel-mediated copy per call, not one per iovec element, and must keep
 * the copied-prefix contract: a fault stops at the first inaccessible byte and
 * the bytes before it are reported, never retried or exceeded.
 *
 * Every copy is a real process_vm_readv/process_vm_writev on this process;
 * the syscall(3) seam only counts them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

static unsigned int copy_calls;

static long counting_syscall(long nr, ...)
{
	va_list ap;
	long a[6];
	int i;

	va_start(ap, nr);
	for (i = 0; i < 6; i++)
		a[i] = va_arg(ap, long);
	va_end(ap);
	if (nr == SYS_process_vm_readv || nr == SYS_process_vm_writev)
		copy_calls++;
	return syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
}

#define syscall counting_syscall
#include "xdev_ext_preload_core.h"
#undef syscall

static unsigned int checks;
static unsigned int failures;

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

static void fill(unsigned char *p, size_t n, unsigned int seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (unsigned char)(seed + i * 13U);
}

static void test_gather_is_one_copy(void)
{
	unsigned char a[512], b[1024], c[2560], staging[4096], expected[4096];
	struct iovec iov[4] = {
		{ a, sizeof(a) }, { b, sizeof(b) }, { NULL, 0 }, { c, sizeof(c) },
	};

	fill(a, sizeof(a), 1);
	fill(b, sizeof(b), 2);
	fill(c, sizeof(c), 3);
	memcpy(expected, a, sizeof(a));
	memcpy(expected + sizeof(a), b, sizeof(b));
	memcpy(expected + sizeof(a) + sizeof(b), c, sizeof(c));
	copy_calls = 0;
	EXPECT_EQ(xdev_ext_preload_iov_gather(staging, sizeof(staging), iov, 4,
					      sizeof(staging)), true);
	EXPECT_EQ(copy_calls, 1);
	EXPECT_EQ(memcmp(staging, expected, sizeof(staging)), 0);
}

static void test_full_scatter_is_one_copy(void)
{
	unsigned char a[512], b[1024], c[2560], staging[4096];
	struct iovec iov[4] = {
		{ a, sizeof(a) }, { NULL, 0 }, { b, sizeof(b) }, { c, sizeof(c) },
	};

	fill(staging, sizeof(staging), 9);
	memset(a, 0, sizeof(a));
	memset(b, 0, sizeof(b));
	memset(c, 0, sizeof(c));
	copy_calls = 0;
	EXPECT_EQ(xdev_ext_preload_iov_scatter_prefix(iov, 4, staging,
						      sizeof(staging)), 4096);
	EXPECT_EQ(copy_calls, 1);
	EXPECT_EQ(memcmp(a, staging, sizeof(a)), 0);
	EXPECT_EQ(memcmp(b, staging + 512, sizeof(b)), 0);
	EXPECT_EQ(memcmp(c, staging + 1536, sizeof(c)), 0);
}

/* A short completion fills a prefix and never writes past it. */
static void test_short_scatter_stops_at_the_prefix(void)
{
	unsigned char a[512], b[1024], c[2560], staging[4096];
	struct iovec iov[3] = { { a, sizeof(a) }, { b, sizeof(b) }, { c, sizeof(c) } };
	unsigned int i;

	fill(staging, sizeof(staging), 21);
	memset(a, 0xee, sizeof(a));
	memset(b, 0xee, sizeof(b));
	memset(c, 0xee, sizeof(c));
	copy_calls = 0;
	EXPECT_EQ(xdev_ext_preload_iov_scatter_prefix(iov, 3, staging, 1000), 1000);
	/* One copy for whole elements, one for the partial last element. */
	EXPECT_EQ(copy_calls <= 2, true);
	EXPECT_EQ(memcmp(a, staging, sizeof(a)), 0);
	EXPECT_EQ(memcmp(b, staging + 512, 488), 0);
	for (i = 488; i < sizeof(b); i++)
		EXPECT_EQ(b[i], 0xee);
	for (i = 0; i < sizeof(c); i++)
		if (c[i] != 0xee)
			break;
	EXPECT_EQ(i, sizeof(c));
}

/*
 * A destination page that becomes inaccessible stops the copy at that page:
 * the bytes before it are the result, as with one copy per element.
 */
static void test_scatter_fault_reports_the_copied_prefix(void)
{
	long page = sysconf(_SC_PAGESIZE);
	unsigned char a[512], staging[4096];
	unsigned char *mapping;
	struct iovec iov[2];

	mapping = mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	EXPECT_EQ(mapping == MAP_FAILED, false);
	if (mapping == MAP_FAILED)
		return;
	EXPECT_EQ(mprotect(mapping + page, (size_t)page, PROT_NONE), 0);
	iov[0] = (struct iovec){ a, sizeof(a) };
	iov[1] = (struct iovec){ mapping + page - 1024, 2048 };
	fill(staging, sizeof(staging), 33);
	copy_calls = 0;
	EXPECT_EQ(xdev_ext_preload_iov_scatter_prefix(iov, 2, staging, 2560),
		  512 + 1024);
	EXPECT_EQ(copy_calls, 1);
	EXPECT_EQ(memcmp(a, staging, sizeof(a)), 0);
	EXPECT_EQ(memcmp(mapping + page - 1024, staging + 512, 1024), 0);
	/* Nothing copied at all is a failure, not a zero-byte success. */
	iov[0] = (struct iovec){ mapping + page, 512 };
	EXPECT_EQ(xdev_ext_preload_iov_scatter_prefix(iov, 1, staging, 512), -1);
	munmap(mapping, 2 * (size_t)page);
}

static void test_gather_fault_is_a_failure(void)
{
	long page = sysconf(_SC_PAGESIZE);
	unsigned char a[512], staging[4096];
	unsigned char *mapping;
	struct iovec iov[2];

	mapping = mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	EXPECT_EQ(mapping == MAP_FAILED, false);
	if (mapping == MAP_FAILED)
		return;
	EXPECT_EQ(mprotect(mapping + page, (size_t)page, PROT_NONE), 0);
	fill(a, sizeof(a), 5);
	iov[0] = (struct iovec){ a, sizeof(a) };
	iov[1] = (struct iovec){ mapping + page - 512, 1024 };
	EXPECT_EQ(xdev_ext_preload_iov_gather(staging, sizeof(staging), iov, 2,
					      1536), false);
	munmap(mapping, 2 * (size_t)page);
}

int main(void)
{
	test_gather_is_one_copy();
	test_full_scatter_is_one_copy();
	test_short_scatter_stops_at_the_prefix();
	test_scatter_fault_reports_the_copied_prefix();
	test_gather_fault_is_a_failure();
	if (failures) {
		fprintf(stderr, "not ok - %u of %u copy-batch checks failed\n",
			failures, checks);
		return 1;
	}
	printf("ok - %u copy-batch checks: one copy per vector call, exact prefixes\n",
	       checks);
	return 0;
}
