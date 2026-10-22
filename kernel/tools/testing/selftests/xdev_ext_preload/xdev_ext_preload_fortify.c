// SPDX-License-Identifier: GPL-2.0
/*
 * A fortified build (-D_FORTIFY_SOURCE) turns pread/pread64 into a buffer of
 * known size with a run-time count into __pread_chk/__pread64_chk.  Those are
 * the entry points an unmodified, distribution-hardened application reaches,
 * so the front end must take them over exactly as it takes over pread and
 * pread64, and it must keep glibc's check: a count larger than the buffer
 * aborts the process.
 *
 * Built with -O2 -D_FORTIFY_SOURCE=2.  Run under the front end and
 * xdev_ext_preload_kernel_model with XDEV_EXT_MODEL_UMEM=1 to check takeover, or with
 * the model alone to check the libc behaviour.
 */
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define FORTIFY_HEADER_BYTES 4096U

/* A database file header read into a fixed buffer, as fortified code does. */
static unsigned char header[FORTIFY_HEADER_BYTES]
	__attribute__((aligned(FORTIFY_HEADER_BYTES)));
static unsigned char pattern[FORTIFY_HEADER_BYTES]
	__attribute__((aligned(FORTIFY_HEADER_BYTES)));

typedef uint64_t (*count_fn)(void);

static int fail(const char *message)
{
	fprintf(stderr, "XDEV_EXT_PRELOAD_FORTIFY=FAIL %s\n", message);
	return 1;
}

int main(int argc, char **argv)
{
	count_fn read_requests;
	volatile size_t length = FORTIFY_HEADER_BYTES;
	uint64_t before = 0;
	pid_t child;
	int status;
	int fd;

	if (argc != 3 || (strcmp(argv[2], "takeover") && strcmp(argv[2], "libc")))
		return 2;
	read_requests = (count_fn)dlsym(RTLD_DEFAULT, "xdev_ext_model_read_requests");
	fd = open(argv[1], O_RDWR | O_DIRECT);
	if (fd < 0)
		return fail("open");
	memset(pattern, 0x6b, sizeof(pattern));
	if (pwrite(fd, pattern, sizeof(pattern), 0) != (ssize_t)sizeof(pattern))
		return fail("setup pwrite");
	if (read_requests)
		before = read_requests();
	errno = EDOM;
	if (pread(fd, header, length, 0) != (ssize_t)length || errno != EDOM ||
	    memcmp(header, pattern, sizeof(header)))
		return fail("fortified pread");
	memset(header, 0, sizeof(header));
	if (pread64(fd, header, length, 0) != (ssize_t)length || errno != EDOM ||
	    memcmp(header, pattern, sizeof(header)))
		return fail("fortified pread64");
	if (!strcmp(argv[2], "takeover") &&
	    (!read_requests || read_requests() - before != 2))
		return fail("fortified reads were not taken over");

	/* glibc aborts a fortified read larger than its buffer. */
	fflush(NULL);
	child = fork();
	if (child < 0)
		return fail("fork");
	if (!child) {
		length = 2 * FORTIFY_HEADER_BYTES;
		(void)!pread(fd, header, length, 0);
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) ||
	    WTERMSIG(status) != SIGABRT)
		return fail("an oversized fortified read did not abort");
	close(fd);
	printf("XDEV_EXT_PRELOAD_FORTIFY=PASS mode=%s\n", argv[2]);
	return 0;
}
