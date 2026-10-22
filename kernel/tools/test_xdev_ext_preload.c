// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define BLOCK_SIZE 4096U

struct thread_read {
	int fd;
	off_t offset;
	unsigned char expected;
	int failed;
};

static void *read_block(void *opaque)
{
	struct thread_read *request = opaque;
	unsigned char *buffer = NULL;
	ssize_t ret;

	if (posix_memalign((void **)&buffer, BLOCK_SIZE, BLOCK_SIZE)) {
		request->failed = 1;
		return NULL;
	}
	ret = pread(request->fd, buffer, BLOCK_SIZE, request->offset);
	if (ret != BLOCK_SIZE || buffer[0] != request->expected ||
	    buffer[BLOCK_SIZE - 1] != request->expected)
		request->failed = 1;
	free(buffer);
	return NULL;
}

static int check_open_variants(const char *path)
{
	char *copy = strdup(path);
	char *slash;
	const char *base;
	int dirfd = -1;
	int fd = -1;
	int ret = -1;

	if (!copy)
		return -1;
	fd = open64(path, O_RDONLY | O_DIRECT);
	if (fd < 0)
		goto out;
	close(fd);
	fd = -1;
	slash = strrchr(copy, '/');
	if (!slash || slash == copy)
		goto out;
	*slash = '\0';
	base = slash + 1;
	dirfd = open(copy, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0)
		goto out;
	fd = openat(dirfd, base, O_RDONLY | O_DIRECT);
	if (fd < 0)
		goto out;
	close(fd);
	fd = openat64(dirfd, base, O_RDONLY | O_DIRECT);
	if (fd < 0)
		goto out;
	ret = 0;
out:
	if (fd >= 0)
		close(fd);
	if (dirfd >= 0)
		close(dirfd);
	free(copy);
	return ret;
}

int main(int argc, char **argv)
{
	struct thread_read reads[2] = {
		{ .offset = 0, .expected = 0x31 },
		{ .offset = BLOCK_SIZE, .expected = 0x62 },
	};
	unsigned char *first = NULL;
	unsigned char *second = NULL;
	unsigned char *input = NULL;
	pthread_t threads[2];
	int pipefd[2] = { -1, -1 };
	int duplicate = -1;
	int replace = -1;
	int scratch = -1;
	int fd = -1;
	pid_t child;
	ssize_t ret;
	int status;
	int status_flags;
	int i;
	struct iovec input_iov[2];
	struct iovec first_iov[2];
	struct iovec second_iov[2];

	if (argc != 2)
		return 2;
	if (posix_memalign((void **)&first, BLOCK_SIZE, BLOCK_SIZE) ||
	    posix_memalign((void **)&second, BLOCK_SIZE, BLOCK_SIZE) ||
	    posix_memalign((void **)&input, BLOCK_SIZE, BLOCK_SIZE))
		goto fail;
	memset(first, 0x31, BLOCK_SIZE);
	memset(second, 0x62, BLOCK_SIZE);
	fd = open(argv[1], O_RDWR | O_DIRECT);
	if (fd < 0)
		goto fail;
	if (pwrite(fd, first, BLOCK_SIZE, 0) != BLOCK_SIZE ||
	    pwrite64(fd, second, BLOCK_SIZE, BLOCK_SIZE) != BLOCK_SIZE)
		goto fail;
	memset(input, 0, BLOCK_SIZE);
	if (pread(fd, input, BLOCK_SIZE, 0) != BLOCK_SIZE ||
	    memcmp(input, first, BLOCK_SIZE))
		goto fail;
	memset(input, 0, BLOCK_SIZE);
	if (pread64(fd, input, BLOCK_SIZE, BLOCK_SIZE) != BLOCK_SIZE ||
	    memcmp(input, second, BLOCK_SIZE))
		goto fail;
	first_iov[0] = (struct iovec) {
		.iov_base = first,
		.iov_len = BLOCK_SIZE / 2,
	};
	first_iov[1] = (struct iovec) {
		.iov_base = first + BLOCK_SIZE / 2,
		.iov_len = BLOCK_SIZE / 2,
	};
	second_iov[0] = (struct iovec) {
		.iov_base = second,
		.iov_len = BLOCK_SIZE / 2,
	};
	second_iov[1] = (struct iovec) {
		.iov_base = second + BLOCK_SIZE / 2,
		.iov_len = BLOCK_SIZE / 2,
	};
	input_iov[0] = (struct iovec) {
		.iov_base = input,
		.iov_len = BLOCK_SIZE / 2,
	};
	input_iov[1] = (struct iovec) {
		.iov_base = input + BLOCK_SIZE / 2,
		.iov_len = BLOCK_SIZE / 2,
	};
	if (pwritev(fd, first_iov, 2, 2 * BLOCK_SIZE) != BLOCK_SIZE)
		goto fail;
	memset(input, 0, BLOCK_SIZE);
	if (preadv(fd, input_iov, 2, 2 * BLOCK_SIZE) != BLOCK_SIZE ||
	    memcmp(input, first, BLOCK_SIZE))
		goto fail;
	if (pwritev64(fd, second_iov, 2, 3 * BLOCK_SIZE) != BLOCK_SIZE)
		goto fail;
	memset(input, 0, BLOCK_SIZE);
	if (preadv64(fd, input_iov, 2, 3 * BLOCK_SIZE) != BLOCK_SIZE ||
	    memcmp(input, second, BLOCK_SIZE))
		goto fail;
	if (pwritev2(fd, second_iov, 2, 2 * BLOCK_SIZE, 0) != BLOCK_SIZE)
		goto fail;
	memset(input, 0, BLOCK_SIZE);
	if (preadv2(fd, input_iov, 2, 2 * BLOCK_SIZE, 0) != BLOCK_SIZE ||
	    memcmp(input, second, BLOCK_SIZE))
		goto fail;
	if (pwritev64v2(fd, first_iov, 2, 3 * BLOCK_SIZE, 0) != BLOCK_SIZE)
		goto fail;
	memset(input, 0, BLOCK_SIZE);
	if (preadv64v2(fd, input_iov, 2, 3 * BLOCK_SIZE, 0) != BLOCK_SIZE ||
	    memcmp(input, first, BLOCK_SIZE))
		goto fail;

	duplicate = dup(fd);
	if (duplicate < 0 || pread(duplicate, input, BLOCK_SIZE, 0) != BLOCK_SIZE)
		goto fail;
	close(duplicate);
	duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (duplicate < 0 || pread(duplicate, input, BLOCK_SIZE, 0) != BLOCK_SIZE)
		goto fail;
	close(duplicate);
	duplicate = -1;
	duplicate = fcntl(fd, F_DUPFD, 0);
	if (duplicate < 0 || pread(duplicate, input, BLOCK_SIZE, 0) != BLOCK_SIZE)
		goto fail;
	close(duplicate);
	duplicate = -1;
	duplicate = fcntl64(fd, F_DUPFD_CLOEXEC, 0);
	if (duplicate < 0 || !(fcntl(duplicate, F_GETFD) & FD_CLOEXEC) ||
	    pread(duplicate, input, BLOCK_SIZE, 0) != BLOCK_SIZE)
		goto fail;
	close(duplicate);
	duplicate = -1;
	status_flags = fcntl(fd, F_GETFL);
	if (status_flags < 0 || fcntl64(fd, F_SETFL, status_flags))
		goto fail;
	{
		struct flock lock = {
			.l_type = F_WRLCK,
			.l_whence = SEEK_SET,
			.l_start = 0,
			.l_len = 1,
		};

		if (fcntl(fd, F_GETLK, &lock))
			goto fail;
	}
	replace = open("/dev/null", O_RDONLY);
	if (replace < 0 || dup2(fd, replace) != replace ||
	    pread(replace, input, BLOCK_SIZE, 0) != BLOCK_SIZE)
		goto fail;
	close(replace);
	replace = -1;
	replace = open("/dev/null", O_RDONLY);
	if (replace < 0 || dup3(fd, replace, O_CLOEXEC) != replace ||
	    !(fcntl(replace, F_GETFD) & FD_CLOEXEC) ||
	    pread(replace, input, BLOCK_SIZE, 0) != BLOCK_SIZE)
		goto fail;
	close(replace);
	replace = -1;

	/* A closed tracked number reused for an untracked object must fallback. */
	duplicate = dup(fd);
	if (duplicate < 0)
		goto fail;
	status = duplicate;
	close(duplicate);
	duplicate = -1;
	scratch = open("/dev/null", O_RDONLY);
	if (scratch < 0)
		goto fail;
	if (scratch != status) {
		if (dup2(scratch, status) != status)
			goto fail;
		close(scratch);
		scratch = status;
	}
	if (pread(scratch, input, BLOCK_SIZE, 0) != 0)
		goto fail;
	close(scratch);
	scratch = -1;

	for (i = 0; i < 2; i++) {
		reads[i].fd = fd;
		if (pthread_create(&threads[i], NULL, read_block, &reads[i]))
			goto fail;
	}
	for (i = 0; i < 2; i++) {
		if (pthread_join(threads[i], NULL) || reads[i].failed)
			goto fail;
	}

	child = fork();
	if (child < 0)
		goto fail;
	if (!child) {
		memset(input, 0, BLOCK_SIZE);
		_exit(pread(fd, input, BLOCK_SIZE, 0) == BLOCK_SIZE &&
		      input[0] == 0x31 ? 0 : 1);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status))
		goto fail;

	if (ftruncate(fd, BLOCK_SIZE + 512))
		goto fail;
	memset(input, 0, BLOCK_SIZE);
	ret = pread(fd, input, BLOCK_SIZE, BLOCK_SIZE);
	if (ret != 512 || input[0] != 0x62 || input[511] != 0x62)
		goto fail;
	if (check_open_variants(argv[1]))
		goto fail;

	/* read/write remain explicit libc fallbacks. */
	if (pipe(pipefd) || write(pipefd[1], "x", 1) != 1 ||
	    read(pipefd[0], input, 1) != 1 || input[0] != 'x')
		goto fail;
	close(pipefd[0]);
	close(pipefd[1]);
	pipefd[0] = pipefd[1] = -1;
	errno = EDOM;
	if (pread(fd, input, 512, 0) != 512 || errno != EDOM)
		goto fail;
	errno = 0;
	if (pread(-1, input, BLOCK_SIZE, 0) != -1 || errno != EBADF)
		goto fail;

	close(fd);
	free(input);
	free(second);
	free(first);
	puts("PASS: transparent preload positional-I/O smoke");
	return 0;

fail:
	perror("transparent preload smoke");
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	if (pipefd[1] >= 0)
		close(pipefd[1]);
	if (duplicate >= 0)
		close(duplicate);
	if (replace >= 0)
		close(replace);
	if (scratch >= 0)
		close(scratch);
	if (fd >= 0)
		close(fd);
	free(input);
	free(second);
	free(first);
	return 1;
}
