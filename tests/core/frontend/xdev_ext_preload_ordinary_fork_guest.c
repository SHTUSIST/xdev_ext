// SPDX-License-Identifier: GPL-2.0
/*
 * Real-kernel ordinary preload ring fork regression. No syscall seams or model.
 * Run dynamically linked with the real preload, enabled, frame_size=4096,
 * PATHS naming the existing disposable ext4 file supplied as argv[1].
 * Main performs only raw file syscalls. Two live workers create real rings;
 * each child inspects inherited resources BEFORE its first eligible call.
 * --selftest checks this test's observers/oracle, never claims guest coverage.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define FRAME 4096U
#define PAGES 12U
#define WORKERS 2U
#define FORKS 3U
#define MAX_FDS 128U
#define MAX_MAPS 32U
#define PROC_BYTES (128U * 1024U)
#define RING_SQ 0ULL
#define RING_CQ 0x8000000ULL
#define RING_SQES 0x10000000ULL

struct fd_record {
	int fd;
	dev_t dev;
	ino_t ino;
	mode_t mode;
	int flags;
	bool ring;
	char target[256];
};
struct mapping {
	unsigned long lo, hi;
	unsigned long long offset, ino;
};
struct snapshot {
	unsigned int nfds, nrings, nmaps;
	struct fd_record fd[MAX_FDS];
	struct mapping map[MAX_MAPS];
};
struct linux_dirent64_local {
	uint64_t ino;
	int64_t off;
	unsigned short reclen;
	unsigned char type;
	char name[];
};
struct child_result {
	int error;
	unsigned int before_rings, after_rings, unmapped;
};
struct state {
	int fd;
	pthread_mutex_t lock;
	pthread_cond_t changed;
	unsigned int command, done[WORKERS];
	bool stop, failed;
};
struct worker {
	struct state *s;
	unsigned int id;
	unsigned char *allocation;
};

static char proc_buffer[PROC_BYTES]; /* No allocator in the child observer. */

static int raw_close(int fd)
{
	return (int)syscall(SYS_close, fd);
}

static void fd_path(char *out, const char *prefix, int fd)
{
	char digits[16];
	unsigned int n = 0;
	while (*prefix)
		*out++ = *prefix++;
	do {
		digits[n++] = '0' + fd % 10;
		fd /= 10;
	} while (fd);
	while (n)
		*out++ = digits[--n];
	*out = 0;
}

/* Reject truncation: an absent tail must never hide a ring or VMA. */
static int read_proc(const char *path)
{
	int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
	size_t used = 0;
	ssize_t n;
	if (fd < 0)
		return -1;
	while (used < sizeof(proc_buffer) - 1) {
		n = syscall(SYS_read, fd, proc_buffer + used,
			    sizeof(proc_buffer) - 1 - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			raw_close(fd);
			return -1;
		}
		if (!n) {
			raw_close(fd);
			proc_buffer[used] = 0;
			return 0;
		}
		used += (size_t)n;
	}
	raw_close(fd);
	return -1;
}

static bool ring_target(const char *s)
{
	return !strcmp(s, "anon_inode:[io_uring]");
}

static bool ring_info(const char *s)
{
	return strstr(s, "SqMask:\t0x1\n") && strstr(s, "CqMask:\t0x") &&
		strstr(s, "SqHead:\t") && strstr(s, "SqTail:\t") &&
		strstr(s, "CqHead:\t") && strstr(s, "CqTail:\t");
}

static int scan_fds(struct snapshot *s)
{
	_Alignas(uint64_t) char entries[4096];
	char path[64];
	int directory = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/fd",
				   O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
	ssize_t bytes, target_bytes;
	if (directory < 0)
		return -1;
	while ((bytes = syscall(SYS_getdents64, directory, entries, sizeof(entries))) != 0) {
		size_t position = 0;
		if (bytes < 0) {
			if (errno == EINTR)
				continue;
			goto fail;
		}
		while (position < (size_t)bytes) {
			struct linux_dirent64_local *entry = (void *)(entries + position);
			struct fd_record record = {0};
			struct stat st;
			const char *p;
			unsigned int insert;
			if (entry->reclen < offsetof(struct linux_dirent64_local, name) + 1 ||
			    entry->reclen > (size_t)bytes - position ||
			    !memchr(entry->name, 0, entry->reclen -
				    offsetof(struct linux_dirent64_local, name)))
				goto fail;
			position += entry->reclen;
			if (entry->name[0] == '.')
				continue;
			for (p = entry->name; *p; p++) {
				if (*p < '0' || *p > '9' || record.fd > 10000000)
					goto fail;
				record.fd = record.fd * 10 + *p - '0';
			}
			if (record.fd == directory)
				continue; /* The only observer FD excluded from the set. */
			if (s->nfds == MAX_FDS || syscall(SYS_fstat, record.fd, &st))
				goto fail;
			record.dev = st.st_dev;
			record.ino = st.st_ino;
			record.mode = st.st_mode;
			record.flags = (int)syscall(SYS_fcntl, record.fd, F_GETFD);
			if (record.flags < 0)
				goto fail;
			fd_path(path, "/proc/self/fd/", record.fd);
			target_bytes = syscall(SYS_readlinkat, AT_FDCWD, path,
					       record.target, sizeof(record.target) - 1);
			if (target_bytes < 0 || target_bytes == sizeof(record.target) - 1)
				goto fail;
			record.target[target_bytes] = 0;
			record.ring = ring_target(record.target);
			if (record.ring) {
				fd_path(path, "/proc/self/fdinfo/", record.fd);
				if (read_proc(path) || !ring_info(proc_buffer))
					goto fail;
				s->nrings++;
			}
			insert = s->nfds++;
			while (insert && s->fd[insert - 1].fd > record.fd) {
				s->fd[insert] = s->fd[insert - 1];
				insert--;
			}
			s->fd[insert] = record;
		}
	}
	raw_close(directory);
	return 0;
fail:
	raw_close(directory);
	return -1;
}

static bool overlap(const struct mapping *a, const struct mapping *b)
{
	return a->lo < b->hi && b->lo < a->hi;
}

static bool valid_layout(const struct snapshot *s)
{
	unsigned int i, sq = 0, cq = 0, sqes = 0;
	for (i = 0; i < s->nmaps; i++) {
		if (s->map[i].offset == RING_SQ)
			sq++;
		else if (s->map[i].offset == RING_CQ)
			cq++;
		else if (s->map[i].offset == RING_SQES)
			sqes++;
		else
			return false;
	}
	return sq == s->nrings && sqes == s->nrings && cq <= s->nrings;
}

static bool number(const char **cursor, unsigned int base, unsigned long long *value)
{
	const char *start = *cursor;
	*value = 0;
	for (;;) {
		unsigned int digit;
		char c = **cursor;
		if (c >= '0' && c <= '9')
			digit = c - '0';
		else if (c >= 'a' && c <= 'f')
			digit = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F')
			digit = c - 'A' + 10;
		else
			break;
		if (digit >= base)
			break;
		if (*value > (ULLONG_MAX - digit) / base)
			return false;
		*value = *value * base + digit;
		(*cursor)++;
	}
	return *cursor != start;
}

static bool space(const char **cursor)
{
	const char *start = *cursor;
	while (**cursor == ' ' || **cursor == '\t')
		(*cursor)++;
	return *cursor != start;
}

/* No stdio, allocation, or locale state in the post-fork proc observer. */
static int parse_map(const char *line, struct mapping *m)
{
	unsigned long long lo, hi, ignored;
	if (!number(&line, 16, &lo) || *line++ != '-' ||
	    !number(&line, 16, &hi) || lo >= hi || hi > ULONG_MAX ||
	    !space(&line))
		return -1;
	if ((*line != 'r' && *line != '-') || !*line++)
		return -1;
	if ((*line != 'w' && *line != '-') || !*line++)
		return -1;
	if ((*line != 'x' && *line != '-') || !*line++)
		return -1;
	if ((*line != 's' && *line != 'p') || !*line++)
		return -1;
	if (!space(&line) || !number(&line, 16, &m->offset) || !space(&line) ||
	    !number(&line, 16, &ignored) || *line++ != ':' ||
	    !number(&line, 16, &ignored) || !space(&line) ||
	    !number(&line, 10, &m->ino) || (*line && *line != ' ' && *line != '\t'))
		return -1;
	m->lo = (unsigned long)lo;
	m->hi = (unsigned long)hi;
	return 0;
}

static int scan_maps(struct snapshot *s, const struct snapshot *must_be_gone)
{
	char *line, *end;
	unsigned int i;
	if (read_proc("/proc/self/maps"))
		return -1;
	for (line = proc_buffer; *line; line = end + 1) {
		struct mapping m;
		end = strchr(line, '\n');
		if (!end)
			return -1;
		*end = 0;
		if (parse_map(line, &m))
			return -1;
		if (must_be_gone)
			for (i = 0; i < must_be_gone->nmaps; i++)
				if (overlap(&m, &must_be_gone->map[i]))
					return -1;
		if (!strstr(line, "[io_uring]"))
			continue;
		if (s->nmaps == MAX_MAPS)
			return -1;
		s->map[s->nmaps++] = m;
	}
	/* Observe the whole union, without assuming an anon-inode is unique to
	 * one descriptor. SQ/CQ may alias under SINGLE_MMAP; SQEs remain separate.
	 * This checkout's mini_liburing currently maps all three independently.
	 */
	return valid_layout(s) ? 0 : -1;
}

static int observe(struct snapshot *s, const struct snapshot *gone)
{
	memset(s, 0, sizeof(*s));
	return scan_fds(s) || scan_maps(s, gone) ? -1 : 0;
}

static bool same_fd(const struct fd_record *a, const struct fd_record *b)
{
	return a->fd == b->fd && a->dev == b->dev && a->ino == b->ino &&
		a->mode == b->mode && a->flags == b->flags &&
		!strcmp(a->target, b->target);
}

/* Exact allowed set = baseline, plus precisely the requested real rings. */
static bool allowed_fds(const struct snapshot *s, const struct snapshot *base,
			 unsigned int rings)
{
	unsigned int i, j = 0;
	if (s->nrings != rings || s->nfds != base->nfds + rings)
		return false;
	for (i = 0; i < s->nfds; i++) {
		if (s->fd[i].ring)
			continue;
		if (j == base->nfds || !same_fd(&s->fd[i], &base->fd[j++]))
			return false;
	}
	return j == base->nfds;
}

static bool same_rings(const struct snapshot *a, const struct snapshot *b)
{
	unsigned int i, j = 0;
	if (a->nrings != b->nrings || a->nmaps != b->nmaps)
		return false;
	for (i = 0; i < a->nfds; i++) {
		if (!a->fd[i].ring)
			continue;
		while (j < b->nfds && !b->fd[j].ring)
			j++;
		if (j == b->nfds || !same_fd(&a->fd[i], &b->fd[j++]))
			return false;
	}
	for (i = 0; i < a->nmaps; i++)
		if (a->map[i].lo != b->map[i].lo || a->map[i].hi != b->map[i].hi ||
		    a->map[i].ino != b->map[i].ino || a->map[i].offset != b->map[i].offset)
			return false;
	return true;
}

static unsigned char original(unsigned int page, unsigned int byte)
{
	return (unsigned char)((page * 53U + byte * 17U + (byte >> 7)) ^ 0xa7U);
}

static unsigned char written(unsigned int owner, unsigned int epoch, unsigned int byte)
{
	return (unsigned char)((owner * 61U + epoch * 37U + byte * 29U +
			       (byte >> 5)) ^ 0x5bU);
}

static bool guards(const unsigned char *a)
{
	unsigned int i;
	for (i = 0; i < FRAME; i++)
		if (a[i] != 0xcd || a[2 * FRAME + i] != 0xcd)
			return false;
	return true;
}

static bool io_epoch(int fd, unsigned char *allocation, unsigned int owner,
		     unsigned int epoch, unsigned int destination)
{
	unsigned char *data = allocation + FRAME;
	unsigned int i;
	memset(allocation, 0xcd, 3 * FRAME);
	if (pread(fd, data, FRAME, (off_t)(owner == 2 ? 1 : owner + 1) * FRAME) != FRAME ||
	    !guards(allocation))
		return false;
	for (i = 0; i < FRAME; i++)
		if (data[i] != original(owner == 2 ? 1 : owner + 1, i))
			return false;
	for (i = 0; i < FRAME; i++)
		data[i] = written(owner, epoch, i);
	if (pwrite(fd, data, FRAME, (off_t)destination * FRAME) != FRAME ||
	    !guards(allocation))
		return false;
	for (i = 0; i < FRAME; i++)
		if (data[i] != written(owner, epoch, i))
			return false;
	memset(data, 0xe1, FRAME);
	if (pread(fd, data, FRAME, (off_t)destination * FRAME) != FRAME ||
	    !guards(allocation))
		return false;
	for (i = 0; i < FRAME; i++)
		if (data[i] != written(owner, epoch, i))
			return false;
	return true;
}

static void *worker_main(void *opaque)
{
	struct worker *w = opaque;
	struct state *s = w->s;
	unsigned int epoch;
	for (epoch = 0; epoch <= FORKS; epoch++) {
		bool ok = io_epoch(s->fd, w->allocation, w->id, epoch, 4 + w->id);
		pthread_mutex_lock(&s->lock);
		s->failed |= !ok;
		s->done[w->id] = epoch + 1;
		pthread_cond_broadcast(&s->changed);
		while (!s->stop && s->command <= epoch)
			pthread_cond_wait(&s->changed, &s->lock);
		if (s->stop) {
			pthread_mutex_unlock(&s->lock);
			break;
		}
		pthread_mutex_unlock(&s->lock);
	}
	return NULL;
}

static bool await_workers(struct state *s, unsigned int epoch)
{
	bool ok;
	pthread_mutex_lock(&s->lock);
	while (s->done[0] <= epoch || s->done[1] <= epoch)
		pthread_cond_wait(&s->changed, &s->lock);
	ok = !s->failed;
	pthread_mutex_unlock(&s->lock);
	return ok;
}

static void run_child(int fd, int report, unsigned char *buffer, unsigned int round,
		      const struct snapshot *base, const struct snapshot *live)
{
	struct child_result result = {0};
	struct snapshot current;
	unsigned int i;
	/* Check before opening any observer FD, which could reuse a closed number. */
	for (i = 0; i < live->nfds; i++)
		if (live->fd[i].ring &&
		    (syscall(SYS_fcntl, live->fd[i].fd, F_GETFD) != -1 || errno != EBADF))
			result.error = 1;
	if (!result.error && (observe(&current, live) || !allowed_fds(&current, base, 0)))
		result.error = 2;
	result.before_rings = result.error ? UINT32_MAX : current.nrings;
	result.unmapped = result.error ? 0 : live->nmaps;
	/* This is deliberately the child's first eligible operation. */
	if (!result.error && !io_epoch(fd, buffer, 2, round, 6 + round))
		result.error = 3;
	if (!result.error && (observe(&current, NULL) || !allowed_fds(&current, base, 1)))
		result.error = 4;
	result.after_rings = result.error ? UINT32_MAX : current.nrings;
	if (syscall(SYS_write, report, &result, sizeof(result)) != sizeof(result))
		_exit(120);
	/* Exercise the real preload's process-exit reporting. No _exit on success. */
	exit(result.error ? 1 : 0);
}

static int selftest(void)
{
	struct mapping m, a = {.lo = 0x1000, .hi = 0x2000};
	struct snapshot base = {0}, observed = {0}, layout = {.nrings = 1, .nmaps = 2};
	unsigned char buffer[3 * FRAME];
	int pipefd[2];
	if (parse_map("1000-2000 rw-s 10000000 00:10 42 anon_inode:[io_uring]", &m) ||
	    m.offset != RING_SQES || m.ino != 42 || !overlap(&m, &a) ||
	    !parse_map("2000-1000 rw-s 0 00:10 42", &m) ||
	    !parse_map("bad", &m) || !ring_target("anon_inode:[io_uring]") ||
	    ring_target("anon_inode:[eventfd]") || ring_info("pos:\t0\n") ||
	    !ring_info("SqMask:\t0x1\nCqMask:\t0x3\nSqHead:\t0\nSqTail:\t0\nCqHead:\t0\nCqTail:\t0\n"))
		return 1;
	memset(buffer, 0xcd, sizeof(buffer));
	if (!guards(buffer))
		return 1;
	buffer[2 * FRAME + FRAME - 1] ^= 1;
	if (guards(buffer) || original(1, 0) == written(0, 0, 0))
		return 1;
	layout.map[0].offset = RING_SQ;
	layout.map[1].offset = RING_SQES;
	if (!valid_layout(&layout)) /* SINGLE_MMAP-compatible observer layout. */
		return 1;
	layout.map[layout.nmaps++].offset = RING_CQ;
	if (!valid_layout(&layout))
		return 1;
	layout.map[1].offset = RING_SQ;
	if (valid_layout(&layout))
		return 1;
	if (observe(&base, NULL) || base.nrings || pipe(pipefd) || observe(&observed, NULL) ||
	    allowed_fds(&observed, &base, 0))
		return 1;
	raw_close(pipefd[0]);
	raw_close(pipefd[1]);
	if (observe(&observed, NULL) || !allowed_fds(&observed, &base, 0) ||
	    allowed_fds(&observed, &base, 1))
		return 1;
	if (!observed.nfds)
		return 1;
	observed.fd[0].ino ^= 1;
	if (allowed_fds(&observed, &base, 0)) /* Same count, wrong actual FD identity. */
		return 1;
	puts("XDEV_EXT_ORDINARY_FORK_SELFTEST=PASS guest_coverage=none");
	return 0;
}

#define REQUIRE(condition, label) do { if (!(condition)) { \
	fprintf(stderr, "XDEV_EXT_ORDINARY_FORK=FAIL stage=%s errno=%d\n", label, errno); \
	return 1; } } while (0)

int main(int argc, char **argv)
{
	struct state s = {.lock = PTHREAD_MUTEX_INITIALIZER,
			  .changed = PTHREAD_COND_INITIALIZER};
	struct worker workers[WORKERS];
	pthread_t threads[WORKERS];
	struct snapshot base, live, current;
	unsigned char *image, *child_buffer;
	unsigned int i, page, round;
	int pipefd[2];
	struct stat st;
	if (argc == 2 && !strcmp(argv[1], "--selftest"))
		return selftest();
	if (argc != 2) {
		fprintf(stderr, "usage: %s existing-disposable-ext4-file | --selftest\n", argv[0]);
		return 2;
	}
	/* An external guest timeout also bounds atfork/deadlock failures. */
	alarm(120);
	REQUIRE(!posix_memalign((void **)&image, FRAME, PAGES * FRAME), "allocate-image");
	REQUIRE(!posix_memalign((void **)&child_buffer, FRAME, 3 * FRAME), "allocate-child");
	s.fd = open(argv[1], O_RDWR | O_DIRECT | O_CLOEXEC);
	REQUIRE(s.fd >= 0, "open-direct-no-skip");
	REQUIRE(!syscall(SYS_ftruncate, s.fd, PAGES * FRAME), "size-file");
	for (page = 0; page < PAGES; page++)
		for (i = 0; i < FRAME; i++)
			image[page * FRAME + i] = original(page, i);
	REQUIRE(syscall(SYS_pwrite64, s.fd, image, PAGES * FRAME, 0) == PAGES * FRAME,
		"raw-seed-file");
	REQUIRE(!pipe2(pipefd, O_CLOEXEC), "pipe");
	REQUIRE(!observe(&base, NULL) && !base.nrings, "main-no-ring-baseline");
	for (i = 0; i < WORKERS; i++) {
		workers[i] = (struct worker){.s = &s, .id = i};
		REQUIRE(!posix_memalign((void **)&workers[i].allocation, FRAME, 3 * FRAME),
			"allocate-worker");
		REQUIRE(!pthread_create(&threads[i], NULL, worker_main, &workers[i]), "create-worker");
	}
	REQUIRE(await_workers(&s, 0), "initial-worker-bytes");
	REQUIRE(!observe(&live, NULL) && allowed_fds(&live, &base, WORKERS),
		"two-real-live-rings-required-no-fallback");
	printf("XDEV_EXT_ORDINARY_FORK_LIVE workers=2 rings=%u maps=%u baseline_fds=%u allowed=baseline+2-rings\n",
	       live.nrings, live.nmaps, base.nfds);
	for (i = 0; i < base.nfds; i++)
		printf("XDEV_EXT_ORDINARY_FORK_ALLOWED fd=%d dev=%llu ino=%llu flags=%d target=%s\n",
		       base.fd[i].fd, (unsigned long long)base.fd[i].dev,
		       (unsigned long long)base.fd[i].ino, base.fd[i].flags, base.fd[i].target);
	for (i = 0; i < live.nfds; i++)
		if (live.fd[i].ring)
			printf("XDEV_EXT_ORDINARY_FORK_RING fd=%d ino=%llu target=%s fdinfo=SqMask:0x1,CqMask\n",
			       live.fd[i].fd, (unsigned long long)live.fd[i].ino, live.fd[i].target);
	for (i = 0; i < live.nmaps; i++)
		printf("XDEV_EXT_ORDINARY_FORK_MAP range=%lx-%lx ino=%llu offset=%llx\n",
		       live.map[i].lo, live.map[i].hi, live.map[i].ino, live.map[i].offset);
	for (round = 0; round < FORKS; round++) {
		struct child_result result;
		struct pollfd report_ready = {.fd = pipefd[0], .events = POLLIN};
		pid_t child, waited;
		int status;
		/* The child's exit() flushes inherited stdio: empty it before each fork. */
		fflush(NULL);
		child = fork();
		REQUIRE(child >= 0, "fork");
		if (!child)
			run_child(s.fd, pipefd[1], child_buffer, round, &base, &live);
		do {
			waited = waitpid(child, &status, 0);
		} while (waited < 0 && errno == EINTR);
		REQUIRE(waited == child, "wait-child");
		/* Do not block reading a report from a child killed before reporting. */
		REQUIRE(WIFEXITED(status), "child-signaled");
		REQUIRE(syscall(SYS_poll, &report_ready, 1, 0) == 1 &&
			(report_ready.revents & POLLIN), "child-report-readable");
		REQUIRE(syscall(SYS_read, pipefd[0], &result, sizeof(result)) == sizeof(result),
			"child-report-present");
		if (result.error)
			fprintf(stderr, "XDEV_EXT_ORDINARY_FORK_CHILD_ERROR round=%u error=%d before_rings=%u after_rings=%u\n",
				round, result.error, result.before_rings, result.after_rings);
		REQUIRE(!WEXITSTATUS(status) && !result.error && !result.before_rings && result.after_rings == 1 &&
			result.unmapped == live.nmaps, "child-first-call-observation");
		printf("XDEV_EXT_ORDINARY_FORK_CHILD round=%u before_rings=0 after_rings=1 inherited_maps_removed=%u allowed=exact-baseline\n",
		       round, result.unmapped);
		REQUIRE(!observe(&current, NULL) && allowed_fds(&current, &base, WORKERS) &&
			same_rings(&current, &live),
			"parent-rings-survive-child");
		pthread_mutex_lock(&s.lock);
		s.command = round + 1;
		pthread_cond_broadcast(&s.changed);
		pthread_mutex_unlock(&s.lock);
		REQUIRE(await_workers(&s, round + 1), "parent-io-after-child");
		REQUIRE(!observe(&current, NULL) && same_rings(&current, &live),
			"parent-original-rings-still-used");
	}
	/* Every byte of source, received destinations, and untouched file guards. */
	REQUIRE(syscall(SYS_pread64, s.fd, image, PAGES * FRAME, 0) == PAGES * FRAME,
		"raw-full-file-read");
	REQUIRE(!syscall(SYS_fstat, s.fd, &st) && st.st_size == PAGES * FRAME, "file-size");
	for (page = 0; page < PAGES; page++)
		for (i = 0; i < FRAME; i++) {
			unsigned char expected = original(page, i);
			if (page == 4 || page == 5)
				expected = written(page - 4, FORKS, i);
			if (page >= 6 && page < 6 + FORKS)
				expected = written(2, page - 6, i);
			REQUIRE(image[page * FRAME + i] == expected, "full-source-received-guards");
		}
	pthread_mutex_lock(&s.lock);
	s.stop = true;
	pthread_cond_broadcast(&s.changed);
	pthread_mutex_unlock(&s.lock);
	for (i = 0; i < WORKERS; i++)
		REQUIRE(!pthread_join(threads[i], NULL), "join-worker-normal-exit");
	REQUIRE(!observe(&current, &live) && allowed_fds(&current, &base, 0),
		"worker-destructors-release-exact-baseline");
	for (i = 0; i < WORKERS; i++)
		free(workers[i].allocation);
	free(image);
	free(child_buffer);
	close(s.fd);
	raw_close(pipefd[0]);
	raw_close(pipefd[1]);
	puts("XDEV_EXT_ORDINARY_FORK=PASS workers=2 forks=3 main_eligible=0 parent_reads=16 parent_writes=8 child_reads=6 child_writes=3 bytes=49152 source=unchanged received=complete guards=complete first_child_call=observed-real-proc exit=normal");
	return 0;
}
