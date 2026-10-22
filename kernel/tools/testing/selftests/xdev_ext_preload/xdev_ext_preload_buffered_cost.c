// SPDX-License-Identifier: GPL-2.0
/*
 * A descriptor without O_DIRECT on an allowlisted file is not eligible, so
 * every positional call on it falls back to libc.  That fallback must stay
 * cheap: after the first call, the front end may make at most one descriptor
 * call (fcntl, fstat, readlink or close) per positional call before it calls
 * libc.  Setting O_DIRECT later, through the interposed fcntl or a raw
 * syscall, must still make the descriptor eligible, and its taken-over calls
 * must cost no more than the full validation.
 *
 * Run under LD_PRELOAD=libio_uring_unified.so:libxdev_ext_preload_kernel_model.so
 * with XDEV_EXT_MODEL_UMEM=1, XDEV_EXT_MODEL_DIOALIGN, XDEV_EXT_PRELOAD_ENABLED=1 and
 * XDEV_EXT_PRELOAD_PATHS=<file>.
 */
#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#define COST_LENGTH 4096U
#define COST_CALLS 64U
/* Duplicate, fstat, F_GETFL and readlink of the duplicate, then its close. */
#define COST_TAKEOVER_CALLS 5U

typedef void (*begin_fn)(void);
typedef uint64_t (*count_fn)(void);

static begin_fn count_begin;
static count_fn count_end;
static count_fn read_requests;

static const char *const kinds[] = { "pread", "pwrite", "preadv" };

static int fail(const char *message)
{
	fprintf(stderr, "XDEV_EXT_PRELOAD_BUFFERED_COST=FAIL %s\n", message);
	return 1;
}

static ssize_t positional(int fd, unsigned char *buffer, int kind)
{
	struct iovec iov = { .iov_base = buffer, .iov_len = COST_LENGTH };

	if (kind == 0)
		return pread(fd, buffer, COST_LENGTH, 0);
	if (kind == 1)
		return pwrite(fd, buffer, COST_LENGTH, 0);
	return preadv(fd, &iov, 1, 0);
}

/*
 * One uncounted call, which may revalidate the descriptor in full, then
 * COST_CALLS counted calls of the same kind, each allowed per_call
 * descriptor calls.
 */
static int check_cost(int fd, unsigned char *buffer, int kind,
		      const char *when, unsigned int per_call)
{
	uint64_t calls;
	unsigned int i;

	if (positional(fd, buffer, kind) != (ssize_t)COST_LENGTH)
		return fail("a positional call failed");
	count_begin();
	for (i = 0; i < COST_CALLS; i++) {
		if (positional(fd, buffer, kind) != (ssize_t)COST_LENGTH) {
			count_end();
			return fail("a positional call failed");
		}
	}
	calls = count_end();
	fprintf(stderr, "%u %s calls %s made %llu descriptor calls\n",
		COST_CALLS, kinds[kind], when, (unsigned long long)calls);
	if (calls > (uint64_t)COST_CALLS * per_call)
		return fail("too many descriptor calls per positional call");
	return 0;
}

/* One aligned pread on fd must be one READ_COMPAT request. */
static int taken_over(int fd, unsigned char *buffer)
{
	uint64_t before = read_requests();

	if (pread(fd, buffer, COST_LENGTH, 0) != (ssize_t)COST_LENGTH)
		return 0;
	return read_requests() == before + 1;
}

int main(int argc, char **argv)
{
	unsigned char *buffer = NULL;
	int flags;
	int kind;
	int fd;

	if (argc != 2)
		return 2;
	count_begin = (begin_fn)dlsym(RTLD_DEFAULT,
				      "xdev_ext_model_count_calls_begin");
	count_end = (count_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_count_calls_end");
	read_requests = (count_fn)dlsym(RTLD_DEFAULT,
					"xdev_ext_model_read_requests");
	if (!count_begin || !count_end || !read_requests)
		return fail("kernel model hooks are not loaded");
	if (posix_memalign((void **)&buffer, COST_LENGTH, COST_LENGTH))
		return fail("posix_memalign");
	memset(buffer, 0x3c, COST_LENGTH);
	fd = open(argv[1], O_RDWR);
	if (fd < 0 ||
	    pwrite(fd, buffer, COST_LENGTH, 0) != (ssize_t)COST_LENGTH)
		return fail("buffered setup");
	for (kind = 0; kind < 3; kind++)
		if (check_cost(fd, buffer, kind, "on a buffered descriptor", 1))
			return 1;
	if (taken_over(fd, buffer))
		return fail("a buffered pread was taken over");

	flags = fcntl(fd, F_GETFL);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_DIRECT))
		return fail("F_SETFL O_DIRECT");
	if (!taken_over(fd, buffer))
		return fail("F_SETFL O_DIRECT did not make the descriptor "
			    "eligible");
	if (fcntl(fd, F_SETFL, flags))
		return fail("F_SETFL clearing O_DIRECT");
	if (check_cost(fd, buffer, 0, "after F_SETFL cleared O_DIRECT", 1))
		return 1;

	if (syscall(SYS_fcntl, fd, F_SETFL, flags | O_DIRECT))
		return fail("raw F_SETFL O_DIRECT");
	if (!taken_over(fd, buffer))
		return fail("a raw-syscall F_SETFL O_DIRECT did not make the "
			    "descriptor eligible");
	if (check_cost(fd, buffer, 0, "after a raw F_SETFL set O_DIRECT",
		       COST_TAKEOVER_CALLS))
		return 1;
	if (syscall(SYS_fcntl, fd, F_SETFL, flags))
		return fail("raw F_SETFL clearing O_DIRECT");
	if (taken_over(fd, buffer))
		return fail("a pread was taken over after a raw-syscall "
			    "F_SETFL cleared O_DIRECT");
	if (check_cost(fd, buffer, 0, "after a raw F_SETFL cleared O_DIRECT",
		       1))
		return 1;
	/* Calls made while O_DIRECT was clear did not retire the descriptor. */
	if (syscall(SYS_fcntl, fd, F_SETFL, flags | O_DIRECT))
		return fail("raw F_SETFL O_DIRECT");
	if (!taken_over(fd, buffer))
		return fail("the descriptor was retired while O_DIRECT was "
			    "clear");
	close(fd);
	free(buffer);
	printf("XDEV_EXT_PRELOAD_BUFFERED_COST=PASS calls_per_kind=%u\n",
	       COST_CALLS);
	return 0;
}
