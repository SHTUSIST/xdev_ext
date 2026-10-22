// SPDX-License-Identifier: GPL-2.0
/*
 * Registration table and private-descriptor set of the transparent front end.
 *
 * The injected real calls are counting wrappers around libc, so every check
 * runs against the kernel's own descriptor semantics.  close_range can be
 * switched to a recorder so that close_range(3, ~0U, 0) splits are observed
 * without closing the test's own descriptors.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../../../xdev_ext_preload_reg.h"

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

#define EXPECT_STR(actual, expected) do {                                \
	checks++;                                                           \
	if (strcmp((actual), (expected))) {                                \
		fprintf(stderr, "%s:%d: %s=\"%s\", expected \"%s\"\n",    \
			__FILE__, __LINE__, #actual, (actual), (expected));    \
		failures++;                                                \
	}                                                                   \
} while (0)

#define TEST_FLOOR 900

/* Injected real calls. */
struct real_calls {
	unsigned int close;
	unsigned int dup;
	unsigned int dup2;
	unsigned int dup3;
	unsigned int close_range;
	unsigned int dupfd;
	unsigned int fstat;
};

static struct real_calls calls;
static bool tracing;
static char trace[1024];
static bool record_close_range;
static struct xdev_ext_fd_span spans_seen[XDEV_EXT_PRIVFD_MAX_SPANS + 4];
static unsigned int nspans_seen;
static int dupfd_errno;
static int last_dupfd_cmd;
static int fstat_lie_fd = -1;

/*
 * The real close() is a cancellation point.  The injected one can block on
 * @block_close_fd before closing, standing for a close() that sleeps
 * (SO_LINGER, a slow flush); each nanosleep() is a cancellation point, as
 * glibc's close() is.
 */
static int block_close_fd = -1;
static int close_blocked;
static int close_unblock;
/* Runs right after a successful real dup or F_DUPFD: the window in which
 * another thread's close(oldfd) can land. */
static void (*after_dup_hook)(int oldfd);

static void count(unsigned int *counter)
{
	__atomic_fetch_add(counter, 1, __ATOMIC_RELAXED);
}

static void block_inside_close(void)
{
	const struct timespec tick = { .tv_nsec = 1000 * 1000 };

	__atomic_store_n(&close_blocked, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&close_unblock, __ATOMIC_ACQUIRE))
		nanosleep(&tick, NULL);
}

static void trace_add(const char *fmt, ...)
{
	size_t used = strlen(trace);
	va_list args;

	if (!tracing || used + 2 >= sizeof(trace))
		return;
	if (used)
		trace[used++] = ' ';
	va_start(args, fmt);
	vsnprintf(trace + used, sizeof(trace) - used, fmt, args);
	va_end(args);
}

static int t_close(int fd)
{
	count(&calls.close);
	trace_add("close(%d)", fd);
	if (fd >= 0 && fd == __atomic_load_n(&block_close_fd, __ATOMIC_ACQUIRE))
		block_inside_close();
	return close(fd);
}

static int t_dup(int fd)
{
	int ret;

	count(&calls.dup);
	trace_add("dup(%d)", fd);
	ret = dup(fd);
	if (ret >= 0 && after_dup_hook)
		after_dup_hook(fd);
	return ret;
}

static int t_dup2(int oldfd, int newfd)
{
	count(&calls.dup2);
	trace_add("dup2(%d,%d)", oldfd, newfd);
	return dup2(oldfd, newfd);
}

static int t_dup3(int oldfd, int newfd, int flags)
{
	count(&calls.dup3);
	trace_add("dup3(%d,%d,%d)", oldfd, newfd, flags);
	return dup3(oldfd, newfd, flags);
}

static int t_close_range(unsigned int first, unsigned int last, int flags)
{
	count(&calls.close_range);
	trace_add("close_range(%u,%u,%d)", first, last, flags);
	if (nspans_seen < sizeof(spans_seen) / sizeof(spans_seen[0]))
		spans_seen[nspans_seen++] =
			(struct xdev_ext_fd_span){ .first = first, .last = last };
	if (record_close_range)
		return 0;
	return (int)syscall(SYS_close_range, first, last, flags);
}

static int t_fcntl_dupfd(int fd, int cmd, int minfd)
{
	int ret;

	count(&calls.dupfd);
	trace_add("dupfd(%d,%d)", fd, minfd);
	last_dupfd_cmd = cmd;
	if (dupfd_errno) {
		errno = dupfd_errno;
		dupfd_errno = 0;
		return -1;
	}
	ret = fcntl(fd, cmd, minfd);
	if (ret >= 0 && after_dup_hook)
		after_dup_hook(fd);
	return ret;
}

static int t_fstat(int fd, struct stat *st)
{
	int ret;

	count(&calls.fstat);
	ret = fstat(fd, st);
	if (!ret && fd == fstat_lie_fd)
		st->st_ino ^= 1;
	return ret;
}

static const struct xdev_ext_fd_real_ops real_ops = {
	.close = t_close,
	.dup = t_dup,
	.dup2 = t_dup2,
	.dup3 = t_dup3,
	.close_range = t_close_range,
	.fcntl_dupfd = t_fcntl_dupfd,
	.fstat = t_fstat,
};

/* Backend hooks; the counters outlive the registration they belong to. */
struct fake_backend {
	unsigned int release;
	unsigned int retire;
	unsigned int sequester;
	unsigned int destroy;
	enum xdev_ext_release_reason why;
};

static void fb_release(struct xdev_ext_reg *r, enum xdev_ext_release_reason why)
{
	struct fake_backend *b = r->backend;

	count(&b->release);
	b->why = why;
}

static void fb_retire(struct xdev_ext_reg *r)
{
	count(&((struct fake_backend *)r->backend)->retire);
}

static void fb_sequester(struct xdev_ext_reg *r)
{
	count(&((struct fake_backend *)r->backend)->sequester);
}

static void fb_destroy(struct xdev_ext_reg *r)
{
	count(&((struct fake_backend *)r->backend)->destroy);
	/* A hook may clobber errno; lifecycle calls must restore it. */
	errno = ENOTRECOVERABLE;
}

static const struct xdev_ext_reg_backend_ops backend_ops = {
	.release = fb_release,
	.retire = fb_retire,
	.sequester = fb_sequester,
	.destroy = fb_destroy,
};

static const struct xdev_ext_reg_env env = {
	.real = &real_ops,
	.backend = &backend_ops,
};

/* Private-fd owner as a backend would keep it: relocated() runs under
 * xdev_ext_privfd_mu and records the new number (-1: the object is gone). */
struct owner {
	int fd;
	unsigned int relocations;
	int last_old;
	int last_new;
};

static void relocated(void *opaque, int oldfd, int newfd)
{
	struct owner *owner = opaque;

	owner->fd = newfd;
	owner->relocations++;
	owner->last_old = oldfd;
	owner->last_new = newfd;
	trace_add("reloc(%d,%d)", oldfd, newfd);
}

static void reset_calls(void)
{
	memset(&calls, 0, sizeof(calls));
	trace[0] = '\0';
	nspans_seen = 0;
	last_dupfd_cmd = -1;
}

static int open_file(void)
{
	char path[] = "/tmp/xdev_ext_preload_reg_test.XXXXXX";
	int fd = mkstemp(path);

	if (fd < 0) {
		perror("mkstemp");
		exit(EXIT_FAILURE);
	}
	unlink(path);
	return fd;
}

/* Test setup goes straight to libc and is never counted. */
static int place(int fd, int at)
{
	if (dup2(fd, at) != at) {
		perror("dup2");
		exit(EXIT_FAILURE);
	}
	if (fd != at)
		close(fd);
	return at;
}

static bool fd_open(int fd)
{
	return fcntl(fd, F_GETFD) >= 0;
}

static bool fd_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD);

	return flags >= 0 && (flags & FD_CLOEXEC);
}

static struct xdev_ext_fd_identity identity_of(int fd)
{
	struct xdev_ext_fd_identity id;
	struct stat st;

	memset(&id, 0, sizeof(id));
	if (!fstat(fd, &st))
		xdev_ext_fd_identity_from_stat(&st, &id);
	return id;
}

static bool same_file(int fd, const struct xdev_ext_fd_identity *id)
{
	struct xdev_ext_fd_identity now = identity_of(fd);

	return xdev_ext_fd_identity_equal(&now, id);
}

static struct xdev_ext_reg *reg_for(int fd, enum xdev_ext_reg_kind kind,
			       struct fake_backend *backend)
{
	struct xdev_ext_fd_identity id = identity_of(fd);
	struct xdev_ext_reg *r = xdev_ext_reg_new(kind, &id, getpid());

	if (!r) {
		fprintf(stderr, "xdev_ext_reg_new failed\n");
		exit(EXIT_FAILURE);
	}
	r->backend = backend;
	return r;
}

/* Install and drop the creator's reference: the slot holds the only one. */
static struct xdev_ext_reg *register_fd(int fd, struct fake_backend *backend)
{
	struct xdev_ext_reg *r = reg_for(fd, XDEV_EXT_REG_NS_PASSTHRU, backend);

	EXPECT_EQ(xdev_ext_reg_install(&env, fd, r), 0);
	xdev_ext_reg_put(&env, r);
	return r;
}

static unsigned int refs(struct xdev_ext_reg *r)
{
	return atomic_load(&r->refs);
}

/* White-box slot read without taking a reference (single-threaded use). */
static struct xdev_ext_reg *peek(int fd)
{
	struct xdev_ext_reg **chunk;

	if (fd < 0 || fd >= (int)XDEV_EXT_REG_FD_LIMIT)
		return NULL;
	chunk = atomic_load(&xdev_ext_reg_chunks[(unsigned int)fd >>
					    XDEV_EXT_REG_CHUNK_SHIFT]);
	return chunk ? chunk[fd & (XDEV_EXT_REG_CHUNK_SLOTS - 1)] : NULL;
}

static void test_identity_and_floor(void)
{
	struct xdev_ext_fd_identity a;
	struct xdev_ext_fd_identity b;
	struct stat st;

	memset(&st, 0, sizeof(st));
	st.st_dev = 7;
	st.st_ino = 11;
	st.st_rdev = 13;
	st.st_mode = S_IFBLK | 0640;
	xdev_ext_fd_identity_from_stat(&st, &a);
	EXPECT_EQ(a.dev, 7);
	EXPECT_EQ(a.ino, 11);
	EXPECT_EQ(a.rdev, 13);
	EXPECT_EQ(a.type, S_IFBLK);
	b = a;
	EXPECT_TRUE(xdev_ext_fd_identity_equal(&a, &b));
	b.rdev = 14;
	EXPECT_TRUE(!xdev_ext_fd_identity_equal(&a, &b));
	b = a;
	b.type = S_IFREG;
	EXPECT_TRUE(!xdev_ext_fd_identity_equal(&a, &b));

	/* max(64, min(soft RLIMIT_NOFILE - 64, 1000)) */
	EXPECT_EQ(xdev_ext_privfd_floor_for_nofile(1024), 960);
	EXPECT_EQ(xdev_ext_privfd_floor_for_nofile(4096), 1000);
	EXPECT_EQ(xdev_ext_privfd_floor_for_nofile(RLIM_INFINITY), 1000);
	EXPECT_EQ(xdev_ext_privfd_floor_for_nofile(100), 64);
	EXPECT_EQ(xdev_ext_privfd_floor_for_nofile(0), 64);
}

static void test_span_split(void)
{
	struct xdev_ext_fd_span s[8] = { { 0 } };
	const unsigned int mid[] = { 900, 901, 905 };
	const unsigned int edge_first[] = { 10 };
	const unsigned int edge_last[] = { 20 };
	const unsigned int all[] = { 10, 11, 12 };
	const unsigned int outside[] = { 5, 30 };
	unsigned int n;

	n = xdev_ext_fd_spans_split(3, UINT_MAX, mid, 3, s);
	EXPECT_EQ(n, 3);
	EXPECT_EQ(s[0].first, 3);
	EXPECT_EQ(s[0].last, 899);
	EXPECT_EQ(s[1].first, 902);
	EXPECT_EQ(s[1].last, 904);
	EXPECT_EQ(s[2].first, 906);
	EXPECT_EQ(s[2].last, UINT_MAX);
	n = xdev_ext_fd_spans_split(10, 20, edge_first, 1, s);
	EXPECT_EQ(n, 1);
	EXPECT_EQ(s[0].first, 11);
	EXPECT_EQ(s[0].last, 20);
	n = xdev_ext_fd_spans_split(10, 20, edge_last, 1, s);
	EXPECT_EQ(n, 1);
	EXPECT_EQ(s[0].first, 10);
	EXPECT_EQ(s[0].last, 19);
	EXPECT_EQ(xdev_ext_fd_spans_split(10, 12, all, 3, s), 0);
	n = xdev_ext_fd_spans_split(10, 20, outside, 2, s);
	EXPECT_EQ(n, 1);
	EXPECT_EQ(s[0].first, 10);
	EXPECT_EQ(s[0].last, 20);
	n = xdev_ext_fd_spans_split(7, 7, NULL, 0, s);
	EXPECT_EQ(n, 1);
	EXPECT_EQ(s[0].first, 7);
	EXPECT_EQ(s[0].last, 7);
}

static void test_dup_family_shares_one_object(void)
{
	struct fake_backend b = { 0 };
	int fd = place(open_file(), 300);
	struct xdev_ext_reg *r = register_fd(fd, &b);
	struct xdev_ext_reg *got;
	int d_dup, d_fdup, d_fdupc;

	EXPECT_EQ(refs(r), 1);
	reset_calls();
	d_dup = xdev_ext_reg_dup(&env, fd);
	EXPECT_TRUE(d_dup >= 0);
	EXPECT_EQ(calls.dup, 1);
	EXPECT_TRUE(peek(d_dup) == r);
	EXPECT_EQ(refs(r), 2);
	EXPECT_EQ(xdev_ext_reg_dup2(&env, fd, 301), 301);
	EXPECT_EQ(calls.dup2, 1);
	EXPECT_TRUE(peek(301) == r);
	EXPECT_EQ(refs(r), 3);
	EXPECT_EQ(xdev_ext_reg_dup3(&env, fd, 302, O_CLOEXEC), 302);
	EXPECT_EQ(calls.dup3, 1);
	EXPECT_TRUE(peek(302) == r);
	EXPECT_TRUE(fd_cloexec(302));
	EXPECT_EQ(refs(r), 4);
	d_fdup = xdev_ext_reg_dupfd(&env, fd, F_DUPFD, 310);
	EXPECT_TRUE(d_fdup >= 310);
	EXPECT_EQ(last_dupfd_cmd, F_DUPFD);
	EXPECT_TRUE(peek(d_fdup) == r);
	EXPECT_TRUE(!fd_cloexec(d_fdup));
	EXPECT_EQ(refs(r), 5);
	d_fdupc = xdev_ext_reg_dupfd(&env, fd, F_DUPFD_CLOEXEC, 320);
	EXPECT_TRUE(d_fdupc >= 320);
	EXPECT_EQ(last_dupfd_cmd, F_DUPFD_CLOEXEC);
	EXPECT_TRUE(peek(d_fdupc) == r);
	EXPECT_TRUE(fd_cloexec(d_fdupc));
	EXPECT_EQ(refs(r), 6);
	EXPECT_EQ(calls.dupfd, 2);
	/* Descriptors returned by an unlocked real call are identity-checked;
	 * dup2/dup3 run under both shard locks and need no fstat. */
	EXPECT_EQ(calls.fstat, 3);
	errno = EDOM;
	EXPECT_EQ(xdev_ext_reg_dupfd(&env, fd, F_GETFD, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(calls.dupfd, 2);

	got = xdev_ext_reg_get(301);
	EXPECT_TRUE(got == r);
	EXPECT_EQ(refs(r), 7);
	xdev_ext_reg_put(&env, got);
	EXPECT_EQ(refs(r), 6);

	reset_calls();
	errno = EDOM;
	EXPECT_EQ(xdev_ext_reg_close(&env, fd), 0);
	EXPECT_EQ(errno, EDOM);
	EXPECT_EQ(refs(r), 5);
	EXPECT_EQ(xdev_ext_reg_close(&env, d_dup), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, 301), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, 302), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, d_fdup), 0);
	EXPECT_EQ(refs(r), 1);
	EXPECT_EQ(b.destroy, 0);
	errno = EDOM;
	EXPECT_EQ(xdev_ext_reg_close(&env, d_fdupc), 0);
	EXPECT_EQ(errno, EDOM);
	EXPECT_EQ(b.destroy, 1);
	EXPECT_EQ(calls.close, 6);
	EXPECT_TRUE(!fd_open(fd) && !fd_open(d_dup) && !fd_open(301) &&
		    !fd_open(302) && !fd_open(d_fdup) && !fd_open(d_fdupc));
	EXPECT_TRUE(peek(fd) == NULL && peek(d_fdupc) == NULL);

	/* A failing close still forgets the slot. */
	reset_calls();
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_close(&env, 303), -1);
	EXPECT_EQ(errno, EBADF);
	EXPECT_EQ(calls.close, 1);
}

static void test_in_flight_reference_defers_destroy(void)
{
	struct fake_backend b = { 0 };
	int fd = place(open_file(), 330);
	struct xdev_ext_reg *r = register_fd(fd, &b);
	struct xdev_ext_reg *got;

	EXPECT_TRUE(xdev_ext_reg_maybe_registered(fd));
	got = xdev_ext_reg_get(fd);
	EXPECT_TRUE(got == r);
	EXPECT_EQ(refs(r), 2);
	EXPECT_EQ(xdev_ext_reg_close(&env, fd), 0);
	EXPECT_TRUE(peek(fd) == NULL);
	EXPECT_TRUE(!xdev_ext_reg_maybe_registered(fd));
	EXPECT_EQ(b.destroy, 0);
	EXPECT_EQ(refs(r), 1);
	xdev_ext_reg_put(&env, got);
	EXPECT_EQ(b.destroy, 1);

	EXPECT_TRUE(xdev_ext_reg_get(fd) == NULL);
	EXPECT_TRUE(xdev_ext_reg_get(-1) == NULL);
	EXPECT_TRUE(xdev_ext_reg_get(XDEV_EXT_REG_FD_LIMIT) == NULL);
	EXPECT_TRUE(!xdev_ext_reg_maybe_registered(-1));
	EXPECT_TRUE(!xdev_ext_reg_maybe_registered(XDEV_EXT_REG_FD_LIMIT));
}

static int fclose_stream(void *stream)
{
	return fclose(stream);
}

/* fclose/freopen close the descriptor inside libc; the wrapper runs them as
 * the real call and the slot is forgotten all the same. */
static void test_close_call_forgets_the_slot(void)
{
	struct fake_backend b = { 0 };
	int fd = place(open_file(), 335);
	FILE *stream;

	register_fd(fd, &b);
	stream = fdopen(fd, "r+");
	EXPECT_TRUE(stream != NULL);
	if (!stream)
		return;
	xdev_ext_epoll_seen_mark(fd);
	errno = EDOM;
	EXPECT_EQ(xdev_ext_reg_close_call(&env, fileno(stream), fclose_stream,
				     stream), 0);
	EXPECT_EQ(errno, EDOM);
	EXPECT_TRUE(peek(fd) == NULL);
	EXPECT_EQ(b.destroy, 1);
	EXPECT_TRUE(!fd_open(fd));
	EXPECT_TRUE(!xdev_ext_epoll_seen_test(fd));
}

/* A per-call identity check that fails drops only the slot that still
 * holds the stale registration. */
static void test_forget_drops_only_the_expected_registration(void)
{
	struct fake_backend b = { 0 }, other_b = { 0 };
	int fd = place(open_file(), 336);
	int other = place(open_file(), 337);
	struct xdev_ext_reg *r = register_fd(fd, &b);
	struct xdev_ext_reg *ro = register_fd(other, &other_b);
	struct xdev_ext_reg *got;

	EXPECT_EQ(xdev_ext_reg_dup2(&env, fd, 338), 338);
	got = xdev_ext_reg_get(fd);
	EXPECT_TRUE(got == r);
	EXPECT_EQ(refs(r), 3);
	EXPECT_TRUE(!xdev_ext_reg_forget(&env, fd, ro));
	EXPECT_TRUE(peek(fd) == r);
	EXPECT_TRUE(xdev_ext_reg_forget(&env, fd, got));
	EXPECT_TRUE(peek(fd) == NULL);
	EXPECT_TRUE(peek(338) == r);
	EXPECT_EQ(refs(r), 2);
	EXPECT_TRUE(!xdev_ext_reg_forget(&env, fd, got));
	EXPECT_TRUE(!xdev_ext_reg_forget(&env, -1, got));
	xdev_ext_reg_put(&env, got);
	EXPECT_EQ(b.destroy, 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, 338), 0);
	EXPECT_EQ(b.destroy, 1);
	EXPECT_EQ(xdev_ext_reg_close(&env, fd), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, other), 0);
	EXPECT_EQ(other_b.destroy, 1);
}

static void test_dup2_over_a_registered_target(void)
{
	struct fake_backend ba = { 0 }, bb = { 0 };
	int a = place(open_file(), 340);
	int b = place(open_file(), 341);
	int c = place(open_file(), 342);
	struct xdev_ext_reg *ra = register_fd(a, &ba);
	struct xdev_ext_reg *rb = register_fd(b, &bb);

	EXPECT_EQ(xdev_ext_reg_dup2(&env, a, b), b);
	EXPECT_EQ(bb.destroy, 1);
	EXPECT_TRUE(peek(b) == ra);
	EXPECT_EQ(refs(ra), 2);
	EXPECT_TRUE(same_file(b, &ra->id));
	(void)rb;

	/* dup2(fd, fd) is one real call and leaves the table alone. */
	reset_calls();
	EXPECT_EQ(xdev_ext_reg_dup2(&env, a, a), a);
	EXPECT_EQ(calls.dup2, 1);
	EXPECT_TRUE(peek(a) == ra);
	EXPECT_EQ(refs(ra), 2);

	/* An unregistered source clears the target. */
	EXPECT_EQ(xdev_ext_reg_dup2(&env, c, b), b);
	EXPECT_TRUE(peek(b) == NULL);
	EXPECT_EQ(refs(ra), 1);

	/* A failing real call leaves the table as it was. */
	reset_calls();
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dup2(&env, 345, a), -1);
	EXPECT_EQ(errno, EBADF);
	EXPECT_EQ(calls.dup2, 1);
	EXPECT_TRUE(peek(a) == ra);
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dup3(&env, a, b, 1), -1);
	EXPECT_EQ(errno, EINVAL);
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dup3(&env, a, a, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(calls.dup3, 2);
	EXPECT_TRUE(peek(a) == ra && peek(b) == NULL);
	EXPECT_EQ(refs(ra), 1);

	EXPECT_EQ(xdev_ext_reg_close(&env, a), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, b), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, c), 0);
	EXPECT_EQ(ba.destroy, 1);
}

static void test_install_checks_identity_under_the_lock(void)
{
	struct fake_backend b = { 0 };
	int a = place(open_file(), 350);
	int other = place(open_file(), 351);
	struct xdev_ext_reg *r = reg_for(a, XDEV_EXT_REG_NS_PASSTHRU, &b);
	struct rlimit lim;
	int high;

	EXPECT_EQ(xdev_ext_reg_install(&env, other, r), -ESTALE);
	EXPECT_TRUE(peek(other) == NULL);
	fstat_lie_fd = a;
	EXPECT_EQ(xdev_ext_reg_install(&env, a, r), -ESTALE);
	fstat_lie_fd = -1;
	EXPECT_TRUE(peek(a) == NULL);
	EXPECT_EQ(refs(r), 1);
	EXPECT_EQ(xdev_ext_reg_install(&env, 352, r), -EBADF);
	reset_calls();
	EXPECT_EQ(xdev_ext_reg_install(&env, XDEV_EXT_REG_FD_LIMIT, r), -ERANGE);
	EXPECT_EQ(xdev_ext_reg_install(&env, -1, r), -EBADF);
	EXPECT_EQ(calls.fstat, 0);
	EXPECT_EQ(b.destroy, 0);

	EXPECT_EQ(xdev_ext_reg_install(&env, a, r), 0);
	EXPECT_EQ(refs(r), 2);

	/* The number a dup returns is checked before it inherits the slot. */
	fstat_lie_fd = 360;
	EXPECT_EQ(xdev_ext_reg_dupfd(&env, a, F_DUPFD, 360), 360);
	fstat_lie_fd = -1;
	EXPECT_TRUE(peek(360) == NULL);
	EXPECT_EQ(refs(r), 2);
	EXPECT_EQ(xdev_ext_reg_close(&env, 360), 0);

	/* The last slot of the last chunk is usable when the limit allows. */
	if (!getrlimit(RLIMIT_NOFILE, &lim) &&
	    lim.rlim_cur > XDEV_EXT_REG_FD_LIMIT) {
		high = fcntl(a, F_DUPFD, XDEV_EXT_REG_FD_LIMIT - 1);
		EXPECT_EQ(high, XDEV_EXT_REG_FD_LIMIT - 1);
		if (high == (int)XDEV_EXT_REG_FD_LIMIT - 1) {
			EXPECT_EQ(xdev_ext_reg_install(&env, high, r), 0);
			EXPECT_TRUE(peek(high) == r);
			EXPECT_EQ(xdev_ext_reg_close(&env, high), 0);
			EXPECT_TRUE(peek(high) == NULL);
		}
	}

	xdev_ext_reg_put(&env, r);
	EXPECT_EQ(b.destroy, 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, a), 0);
	EXPECT_EQ(b.destroy, 1);
	EXPECT_EQ(xdev_ext_reg_close(&env, other), 0);

	/* A registration that never reached a slot is destroyed by its put. */
	memset(&b, 0, sizeof(b));
	a = place(open_file(), 353);
	r = reg_for(a, XDEV_EXT_REG_NS_PASSTHRU, &b);
	EXPECT_EQ(xdev_ext_reg_install(&env, 354, r), -EBADF);
	xdev_ext_reg_put(&env, r);
	EXPECT_EQ(b.destroy, 1);
	EXPECT_EQ(xdev_ext_reg_close(&env, a), 0);
}

static void close_source(int oldfd)
{
	EXPECT_EQ(xdev_ext_reg_close(&env, oldfd), 0);
}

static struct xdev_ext_reg *install_during_dup;

static void install_on_source(int oldfd)
{
	EXPECT_EQ(xdev_ext_reg_install(&env, oldfd, install_during_dup), 0);
}

/* dup() or F_DUPFD racing close() of the source on another thread: the new
 * number is still an alias of the registered file and keeps the
 * registration, which stays reachable through every alias. */
static void test_dup_racing_close_of_the_source(void)
{
	struct fake_backend b = { 0 }, b2 = { 0 };
	int fd = place(open_file(), 410);
	int unreg = place(open_file(), 411);
	int src = place(open_file(), 412);
	struct xdev_ext_reg *r = reg_for(fd, XDEV_EXT_REG_DGRAM_RX, &b);
	int d, d2, d3, d4;

	EXPECT_EQ(xdev_ext_reg_install(&env, fd, r), 0);
	xdev_ext_reg_put(&env, r);
	EXPECT_EQ(xdev_ext_reg_dup2(&env, fd, 440), 440);
	EXPECT_EQ(refs(r), 2);

	after_dup_hook = close_source;
	d = xdev_ext_reg_dup(&env, fd);
	after_dup_hook = NULL;
	EXPECT_TRUE(d >= 0 && fd_open(d) && same_file(d, &r->id));
	EXPECT_TRUE(!fd_open(fd) && peek(fd) == NULL);
	EXPECT_TRUE(peek(d) == r);
	EXPECT_EQ(refs(r), 2);

	EXPECT_EQ(xdev_ext_reg_dup2(&env, 440, fd), fd);
	after_dup_hook = close_source;
	d2 = xdev_ext_reg_dupfd(&env, fd, F_DUPFD_CLOEXEC, 450);
	after_dup_hook = NULL;
	EXPECT_TRUE(d2 >= 450 && fd_open(d2) && fd_cloexec(d2));
	EXPECT_TRUE(!fd_open(fd) && peek(fd) == NULL);
	EXPECT_TRUE(peek(d2) == r);
	EXPECT_EQ(refs(r), 3);
	EXPECT_EQ(xdev_ext_reg_state_of(r), XDEV_EXT_REG_ACTIVE);

	/* The source's epoll mark is not lost to the same race. */
	xdev_ext_epoll_seen_mark(unreg);
	after_dup_hook = close_source;
	d3 = xdev_ext_reg_dup(&env, unreg);
	after_dup_hook = NULL;
	EXPECT_TRUE(d3 >= 0 && !fd_open(unreg));
	EXPECT_TRUE(xdev_ext_epoll_seen_test(d3));
	EXPECT_TRUE(peek(d3) == NULL);

	/* A registration installed on the source during the call is inherited
	 * as well. */
	install_during_dup = reg_for(src, XDEV_EXT_REG_DGRAM_RX, &b2);
	after_dup_hook = install_on_source;
	d4 = xdev_ext_reg_dup(&env, src);
	after_dup_hook = NULL;
	EXPECT_TRUE(peek(src) == install_during_dup);
	EXPECT_TRUE(peek(d4) == install_during_dup);
	EXPECT_EQ(refs(install_during_dup), 3);
	xdev_ext_reg_put(&env, install_during_dup);
	EXPECT_EQ(xdev_ext_reg_close(&env, src), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, d4), 0);
	EXPECT_EQ(b2.destroy, 1);

	EXPECT_EQ(xdev_ext_reg_close(&env, 440), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, d), 0);
	EXPECT_EQ(b.destroy, 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, d2), 0);
	EXPECT_EQ(b.destroy, 1);
	EXPECT_EQ(xdev_ext_reg_close(&env, d3), 0);
}

#define HIGH_ALIAS_NOFILE 70100

/* An alias the table cannot hold reaches libc.  A receive registration then
 * hands new datagrams back to the kernel stack, as after fork or SCM_RIGHTS;
 * other kinds keep serving, since libc on the alias reaches the same file. */
static void test_alias_beyond_the_table(void)
{
	struct fake_backend b1 = { 0 }, b2 = { 0 }, bw = { 0 };
	struct xdev_ext_reg *r1, *r2, *w;
	struct rlimit saved, lim;
	int fd1, fd2, fdw, d, d2;

	if (getrlimit(RLIMIT_NOFILE, &saved)) {
		perror("getrlimit");
		exit(EXIT_FAILURE);
	}
	lim = saved;
	if (lim.rlim_cur < HIGH_ALIAS_NOFILE)
		lim.rlim_cur = HIGH_ALIAS_NOFILE;
	if (lim.rlim_max < lim.rlim_cur)
		lim.rlim_max = lim.rlim_cur;
	if (setrlimit(RLIMIT_NOFILE, &lim)) {
		printf("# SKIP alias beyond the table: RLIMIT_NOFILE %d: %s\n",
		       HIGH_ALIAS_NOFILE, strerror(errno));
		return;
	}

	fd1 = place(open_file(), 420);
	r1 = reg_for(fd1, XDEV_EXT_REG_DGRAM_RX, &b1);
	EXPECT_EQ(xdev_ext_reg_install(&env, fd1, r1), 0);
	xdev_ext_reg_put(&env, r1);
	errno = EDOM;
	EXPECT_EQ(xdev_ext_reg_dup2(&env, fd1, 70000), 70000);
	EXPECT_EQ(errno, EDOM);
	EXPECT_TRUE(same_file(70000, &r1->id));
	EXPECT_TRUE(xdev_ext_reg_get(70000) == NULL);
	EXPECT_EQ(b1.release, 1);
	EXPECT_EQ(b1.why, XDEV_EXT_RELEASE_ALIAS);
	EXPECT_EQ(xdev_ext_reg_state_of(r1), XDEV_EXT_REG_RELEASING);
	EXPECT_TRUE(peek(fd1) == r1);
	EXPECT_EQ(refs(r1), 1);
	EXPECT_EQ(xdev_ext_reg_close(&env, 70000), 0);

	fd2 = place(open_file(), 421);
	r2 = reg_for(fd2, XDEV_EXT_REG_DGRAM_RX, &b2);
	EXPECT_EQ(xdev_ext_reg_install(&env, fd2, r2), 0);
	xdev_ext_reg_put(&env, r2);
	errno = EDOM;
	d = xdev_ext_reg_dupfd(&env, fd2, F_DUPFD, 65600);
	EXPECT_EQ(errno, EDOM);
	EXPECT_TRUE(d >= 65600 && same_file(d, &r2->id));
	EXPECT_EQ(b2.release, 1);
	EXPECT_EQ(b2.why, XDEV_EXT_RELEASE_ALIAS);
	EXPECT_EQ(xdev_ext_reg_state_of(r2), XDEV_EXT_REG_RELEASING);
	EXPECT_EQ(refs(r2), 1);
	EXPECT_EQ(xdev_ext_reg_close(&env, d), 0);

	/* A write registration keeps serving through the aliases it has. */
	fdw = place(open_file(), 422);
	w = register_fd(fdw, &bw);
	EXPECT_EQ(xdev_ext_reg_dup3(&env, fdw, 70001, O_CLOEXEC), 70001);
	d2 = xdev_ext_reg_dupfd(&env, fdw, F_DUPFD_CLOEXEC, 65601);
	EXPECT_TRUE(d2 >= 65601);
	EXPECT_EQ(bw.release, 0);
	EXPECT_EQ(xdev_ext_reg_state_of(w), XDEV_EXT_REG_ACTIVE);
	EXPECT_EQ(refs(w), 1);
	EXPECT_EQ(xdev_ext_reg_close(&env, 70001), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, d2), 0);

	EXPECT_EQ(xdev_ext_reg_close(&env, fd1), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, fd2), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, fdw), 0);
	EXPECT_EQ(b1.destroy + b2.destroy + bw.destroy, 3);
	if (setrlimit(RLIMIT_NOFILE, &saved)) {
		perror("setrlimit");
		exit(EXIT_FAILURE);
	}
}

static void test_epoll_seen_follows_the_descriptor(void)
{
	int a = place(open_file(), 370);
	int b = place(open_file(), 371);
	int c = place(open_file(), 372);
	int d;

	EXPECT_TRUE(!xdev_ext_epoll_seen_test(a));
	xdev_ext_epoll_seen_mark(a);
	EXPECT_TRUE(xdev_ext_epoll_seen_test(a));
	EXPECT_EQ(xdev_ext_reg_dup2(&env, a, b), b);
	EXPECT_TRUE(xdev_ext_epoll_seen_test(b));
	d = xdev_ext_reg_dup(&env, a);
	EXPECT_TRUE(d >= 0 && xdev_ext_epoll_seen_test(d));
	EXPECT_EQ(xdev_ext_reg_close(&env, a), 0);
	EXPECT_TRUE(!xdev_ext_epoll_seen_test(a));
	EXPECT_TRUE(xdev_ext_epoll_seen_test(b));
	EXPECT_EQ(xdev_ext_reg_dup2(&env, c, b), b);
	EXPECT_TRUE(!xdev_ext_epoll_seen_test(b));
	/* Descriptors the table cannot hold are never activated. */
	EXPECT_TRUE(xdev_ext_epoll_seen_test(-1));
	EXPECT_TRUE(xdev_ext_epoll_seen_test(XDEV_EXT_REG_FD_LIMIT));
	xdev_ext_epoll_seen_mark(XDEV_EXT_REG_FD_LIMIT);
	xdev_ext_epoll_seen_mark(-1);
	EXPECT_EQ(xdev_ext_reg_close(&env, b), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, c), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, d), 0);
	EXPECT_TRUE(!xdev_ext_epoll_seen_test(d));
}

static void test_close_range_with_and_without_cloexec(void)
{
	struct fake_backend b = { 0 };
	int a = place(open_file(), 600);
	int plain = place(open_file(), 603);
	struct xdev_ext_reg *r = register_fd(a, &b);

	EXPECT_EQ(xdev_ext_reg_dup2(&env, a, 601), 601);
	EXPECT_EQ(xdev_ext_reg_dup2(&env, a, 602), 602);
	EXPECT_EQ(refs(r), 3);
	xdev_ext_epoll_seen_mark(601);

	reset_calls();
	errno = EDOM;
	EXPECT_EQ(xdev_ext_reg_close_range(&env, 600, 610, CLOSE_RANGE_CLOEXEC), 0);
	EXPECT_EQ(errno, EDOM);
	EXPECT_EQ(calls.close_range, 1);
	EXPECT_EQ(spans_seen[0].first, 600);
	EXPECT_EQ(spans_seen[0].last, 610);
	EXPECT_EQ(refs(r), 3);
	EXPECT_TRUE(peek(600) == r && peek(601) == r && peek(602) == r);
	EXPECT_TRUE(fd_cloexec(600) && fd_cloexec(602) && fd_cloexec(plain));
	EXPECT_TRUE(xdev_ext_epoll_seen_test(601));

	reset_calls();
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_close_range(&env, 600, 610, 1 << 9), -1);
	EXPECT_EQ(errno, EINVAL);
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_close_range(&env, 610, 600, 0), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(calls.close_range, 2);
	EXPECT_EQ(refs(r), 3);

	reset_calls();
	errno = EDOM;
	EXPECT_EQ(xdev_ext_reg_close_range(&env, 600, 610, 0), 0);
	EXPECT_EQ(errno, EDOM);
	EXPECT_EQ(calls.close_range, 1);
	EXPECT_TRUE(peek(600) == NULL && peek(601) == NULL &&
		    peek(602) == NULL);
	EXPECT_EQ(b.destroy, 1);
	EXPECT_TRUE(!fd_open(600) && !fd_open(601) && !fd_open(602) &&
		    !fd_open(plain));
	EXPECT_TRUE(!xdev_ext_epoll_seen_test(601));
}

static int adopt(int fd, enum xdev_ext_privfd_role role, struct owner *owner)
{
	owner->fd = fd;
	EXPECT_EQ(xdev_ext_privfd_adopt(&real_ops, &owner->fd, role, owner,
				   relocated), 0);
	return owner->fd;
}

static void test_adopt_and_front_end_close(void)
{
	struct fake_backend b = { 0 };
	struct owner owner = { 0 };
	struct owner many[XDEV_EXT_PRIVFD_MAX];
	struct xdev_ext_fd_identity id;
	struct xdev_ext_reg *r;
	int fd = open_file();
	int low = fd;
	int priv, saved, other, probe;
	unsigned int i;

	id = identity_of(fd);
	reset_calls();
	priv = adopt(fd, XDEV_EXT_PRIVFD_XSK, &owner);
	EXPECT_TRUE(priv >= TEST_FLOOR);
	EXPECT_EQ(last_dupfd_cmd, F_DUPFD_CLOEXEC);
	EXPECT_TRUE(fd_cloexec(priv));
	EXPECT_TRUE(same_file(priv, &id));
	EXPECT_TRUE(!fd_open(low));
	EXPECT_TRUE(xdev_ext_privfd_test(priv));
	EXPECT_TRUE(!xdev_ext_privfd_test(low));
	EXPECT_EQ(calls.close, 1);

	/* A private descriptor never enters the registration table. */
	r = reg_for(priv, XDEV_EXT_REG_DGRAM_RX, &b);
	EXPECT_EQ(xdev_ext_reg_install(&env, priv, r), -EBADF);
	xdev_ext_reg_put(&env, r);
	EXPECT_EQ(b.destroy, 1);

	saved = priv;
	reset_calls();
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &owner.fd), 0);
	EXPECT_EQ(owner.fd, -1);
	EXPECT_EQ(calls.close, 1);
	EXPECT_TRUE(!fd_open(saved));
	EXPECT_TRUE(!xdev_ext_privfd_test(saved));

	/* Only a member of the set is ever closed through this path. */
	other = open_file();
	probe = other;
	reset_calls();
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &probe), -EBADF);
	EXPECT_EQ(calls.close, 0);
	EXPECT_EQ(probe, other);
	EXPECT_TRUE(fd_open(other));
	close(other);

	/* The set is bounded; a refused adoption still consumes the fd. */
	for (i = 0; i < XDEV_EXT_PRIVFD_MAX; i++)
		adopt(open_file(), XDEV_EXT_PRIVFD_MIRROR, &many[i]);
	fd = open_file();
	owner.fd = fd;
	EXPECT_EQ(xdev_ext_privfd_adopt(&real_ops, &owner.fd, XDEV_EXT_PRIVFD_LINK,
				   &owner, relocated), -EMFILE);
	EXPECT_EQ(owner.fd, -1);
	EXPECT_TRUE(!fd_open(fd));
	for (i = 0; i < XDEV_EXT_PRIVFD_MAX; i++)
		EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &many[i].fd), 0);

	/* A failed placement consumes the fd and adds nothing. */
	fd = open_file();
	owner.fd = fd;
	dupfd_errno = EMFILE;
	EXPECT_EQ(xdev_ext_privfd_adopt(&real_ops, &owner.fd, XDEV_EXT_PRIVFD_LINK,
				   &owner, relocated), -EMFILE);
	EXPECT_EQ(owner.fd, -1);
	EXPECT_TRUE(!fd_open(fd));
}

static void test_private_fds_are_invisible_to_the_application(void)
{
	struct owner owner = { 0 };
	int priv = adopt(open_file(), XDEV_EXT_PRIVFD_LINK, &owner);
	int free_fd = 380;

	EXPECT_TRUE(!fd_open(free_fd));
	reset_calls();
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_close(&env, priv), -1);
	EXPECT_EQ(errno, EBADF);
	EXPECT_EQ(calls.close, 0);
	EXPECT_TRUE(fd_open(priv));

	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dup(&env, priv), -1);
	EXPECT_EQ(errno, EBADF);
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dupfd(&env, priv, F_DUPFD, 0), -1);
	EXPECT_EQ(errno, EBADF);
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dupfd(&env, priv, F_DUPFD_CLOEXEC, 0), -1);
	EXPECT_EQ(errno, EBADF);
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dup2(&env, priv, free_fd), -1);
	EXPECT_EQ(errno, EBADF);
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dup2(&env, priv, priv), -1);
	EXPECT_EQ(errno, EBADF);
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dup3(&env, priv, free_fd, 0), -1);
	EXPECT_EQ(errno, EBADF);
	EXPECT_EQ(calls.dup + calls.dupfd + calls.dup2 + calls.dup3, 0);
	EXPECT_TRUE(!fd_open(free_fd));
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &owner.fd), 0);
}

static void test_dup_onto_a_private_fd_migrates_it_first(bool use_dup3)
{
	struct fake_backend bx = { 0 };
	struct owner owner = { 0 };
	struct xdev_ext_fd_identity priv_id;
	char expected[256];
	struct xdev_ext_reg *rx;
	int pfile = open_file();
	int x = place(open_file(), 40);
	int priv, moved, ret;

	priv_id = identity_of(pfile);
	priv = adopt(pfile, XDEV_EXT_PRIVFD_XSK, &owner);
	rx = register_fd(x, &bx);

	reset_calls();
	tracing = true;
	ret = use_dup3 ? xdev_ext_reg_dup3(&env, x, priv, O_CLOEXEC) :
			 xdev_ext_reg_dup2(&env, x, priv);
	tracing = false;
	EXPECT_EQ(ret, priv);
	moved = owner.fd;
	if (use_dup3)
		snprintf(expected, sizeof(expected),
			 "dupfd(%d,%d) reloc(%d,%d) dup3(%d,%d,%d)", priv,
			 TEST_FLOOR, priv, moved, x, priv, O_CLOEXEC);
	else
		snprintf(expected, sizeof(expected),
			 "dupfd(%d,%d) reloc(%d,%d) dup2(%d,%d)", priv,
			 TEST_FLOOR, priv, moved, x, priv);
	EXPECT_STR(trace, expected);
	EXPECT_EQ(last_dupfd_cmd, F_DUPFD_CLOEXEC);
	EXPECT_EQ(owner.relocations, 1);
	EXPECT_EQ(owner.last_old, priv);
	EXPECT_EQ(owner.last_new, moved);
	EXPECT_TRUE(moved >= TEST_FLOOR && moved != priv);
	EXPECT_TRUE(xdev_ext_privfd_test(moved));
	EXPECT_TRUE(!xdev_ext_privfd_test(priv));
	EXPECT_TRUE(fd_cloexec(moved));
	EXPECT_TRUE(same_file(moved, &priv_id));
	EXPECT_TRUE(same_file(priv, &rx->id));
	EXPECT_TRUE(peek(priv) == rx);
	EXPECT_EQ(refs(rx), 2);

	EXPECT_EQ(xdev_ext_reg_close(&env, priv), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, x), 0);
	EXPECT_EQ(bx.destroy, 1);
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &owner.fd), 0);
	EXPECT_TRUE(!fd_open(moved));
}

static void test_dup_onto_a_private_fd_when_migration_fails(void)
{
	struct owner owner = { 0 };
	int x = place(open_file(), 41);
	int priv = adopt(open_file(), XDEV_EXT_PRIVFD_XSK, &owner);
	struct xdev_ext_fd_identity xid = identity_of(x);

	/* The application's call is honoured; the owner learns the object
	 * is gone and must stop using it. */
	dupfd_errno = EMFILE;
	EXPECT_EQ(xdev_ext_reg_dup2(&env, x, priv), priv);
	EXPECT_EQ(owner.fd, -1);
	EXPECT_EQ(owner.relocations, 1);
	EXPECT_EQ(owner.last_new, -1);
	EXPECT_TRUE(!xdev_ext_privfd_test(priv));
	EXPECT_TRUE(same_file(priv, &xid));
	EXPECT_EQ(xdev_ext_reg_close(&env, priv), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, x), 0);
}

static void test_dup_onto_a_private_fd_when_the_real_call_fails(void)
{
	struct owner owner = { 0 };
	char expected[256];
	int bad = 899;
	int priv = adopt(open_file(), XDEV_EXT_PRIVFD_XSK, &owner);
	int moved;

	EXPECT_TRUE(!fd_open(bad));
	reset_calls();
	tracing = true;
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_dup2(&env, bad, priv), -1);
	tracing = false;
	EXPECT_EQ(errno, EBADF);
	moved = owner.fd;
	snprintf(expected, sizeof(expected),
		 "dupfd(%d,%d) reloc(%d,%d) dup2(%d,%d) close(%d)", priv,
		 TEST_FLOOR, priv, moved, bad, priv, priv);
	EXPECT_STR(trace, expected);
	/* The application sees the number as unused, exactly as before. */
	EXPECT_TRUE(!fd_open(priv));
	EXPECT_TRUE(xdev_ext_privfd_test(moved));
	EXPECT_TRUE(fd_open(moved));
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &owner.fd), 0);
}

static void test_close_range_splits_around_private_fds(void)
{
	struct fake_backend ba = { 0 }, bb = { 0 };
	struct owner p[4] = { 0 };
	int fds[4];
	int a = place(open_file(), 850);
	int b;
	unsigned int i;

	for (i = 0; i < 4; i++)
		fds[i] = adopt(open_file(), XDEV_EXT_PRIVFD_MIRROR, &p[i]);
	/* Leave a hole so the spans include one between two private fds. */
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &p[1].fd), 0);
	EXPECT_EQ(fds[3], fds[2] + 1);
	b = place(open_file(), fds[3] + 10);
	register_fd(a, &ba);
	register_fd(b, &bb);

	record_close_range = true;
	reset_calls();
	errno = EDOM;
	EXPECT_EQ(xdev_ext_reg_close_range(&env, 3, ~0U, 0), 0);
	EXPECT_EQ(errno, EDOM);
	record_close_range = false;
	EXPECT_EQ(calls.close_range, 3);
	EXPECT_EQ(spans_seen[0].first, 3);
	EXPECT_EQ(spans_seen[0].last, fds[0] - 1);
	EXPECT_EQ(spans_seen[1].first, fds[0] + 1);
	EXPECT_EQ(spans_seen[1].last, fds[2] - 1);
	EXPECT_EQ(spans_seen[2].first, fds[3] + 1);
	EXPECT_EQ(spans_seen[2].last, UINT_MAX);
	EXPECT_TRUE(peek(a) == NULL && peek(b) == NULL);
	EXPECT_EQ(ba.destroy, 1);
	EXPECT_EQ(bb.destroy, 1);
	EXPECT_TRUE(xdev_ext_privfd_test(fds[0]) && xdev_ext_privfd_test(fds[2]) &&
		    xdev_ext_privfd_test(fds[3]));
	EXPECT_TRUE(fd_open(fds[0]) && fd_open(fds[2]) && fd_open(fds[3]));
	/* The recorder did not really close them. */
	close(a);
	close(b);

	/* No private fd in range: one real call with the caller's range. */
	reset_calls();
	EXPECT_EQ(xdev_ext_reg_close_range(&env, 3, fds[0] - 1, CLOSE_RANGE_CLOEXEC),
		  0);
	EXPECT_EQ(calls.close_range, 1);
	EXPECT_EQ(spans_seen[0].first, 3);
	EXPECT_EQ(spans_seen[0].last, fds[0] - 1);

	/* Only private fds in range: the application sees none open. */
	reset_calls();
	EXPECT_EQ(xdev_ext_reg_close_range(&env, fds[2], fds[3], 0), 0);
	EXPECT_EQ(calls.close_range, 0);
	EXPECT_TRUE(fd_open(fds[2]) && fd_open(fds[3]));
	errno = 0;
	EXPECT_EQ(xdev_ext_reg_close_range(&env, fds[2], fds[3], 1 << 9), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(calls.close_range, 0);

	/* A real close over the span really keeps the private fds. */
	a = place(open_file(), fds[0] + 1);
	reset_calls();
	EXPECT_EQ(xdev_ext_reg_close_range(&env, fds[0], fds[3] + 5, 0), 0);
	EXPECT_EQ(calls.close_range, 2);
	EXPECT_TRUE(!fd_open(a));
	EXPECT_TRUE(fd_open(fds[0]) && fd_open(fds[2]) && fd_open(fds[3]));

	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &p[0].fd), 0);
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &p[2].fd), 0);
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &p[3].fd), 0);
}

static void test_state_machine(void)
{
	struct fake_backend b = { 0 };
	int fd = place(open_file(), 390);
	struct xdev_ext_reg *r = reg_for(fd, XDEV_EXT_REG_DGRAM_RX, &b);
	struct xdev_ext_reg *w;
	pid_t self = getpid();

	EXPECT_EQ(xdev_ext_reg_state_of(r), XDEV_EXT_REG_ACTIVE);
	EXPECT_EQ(r->owner_pid, self);
	EXPECT_EQ(r->kind, XDEV_EXT_REG_DGRAM_RX);
	EXPECT_TRUE(xdev_ext_reg_serves(r, self));
	EXPECT_TRUE(!xdev_ext_reg_serves(r, self + 1));
	EXPECT_TRUE(!xdev_ext_reg_retire(&env, r));
	EXPECT_EQ(b.retire, 0);

	EXPECT_TRUE(xdev_ext_reg_release(&env, r, XDEV_EXT_RELEASE_SHUTDOWN));
	EXPECT_EQ(xdev_ext_reg_state_of(r), XDEV_EXT_REG_RELEASING);
	EXPECT_EQ(b.release, 1);
	EXPECT_EQ(b.why, XDEV_EXT_RELEASE_SHUTDOWN);
	EXPECT_EQ(r->release_reason, XDEV_EXT_RELEASE_SHUTDOWN);
	EXPECT_TRUE(xdev_ext_reg_serves(r, self));
	EXPECT_TRUE(!xdev_ext_reg_release(&env, r, XDEV_EXT_RELEASE_FORK));
	EXPECT_EQ(b.release, 1);
	EXPECT_EQ(r->release_reason, XDEV_EXT_RELEASE_SHUTDOWN);

	EXPECT_TRUE(xdev_ext_reg_retire(&env, r));
	EXPECT_EQ(xdev_ext_reg_state_of(r), XDEV_EXT_REG_RELEASED);
	EXPECT_EQ(b.retire, 1);
	EXPECT_TRUE(!xdev_ext_reg_serves(r, self));
	EXPECT_TRUE(!xdev_ext_reg_retire(&env, r));
	EXPECT_TRUE(!xdev_ext_reg_sequester(&env, r));
	EXPECT_EQ(b.retire, 1);
	EXPECT_EQ(b.sequester, 0);
	xdev_ext_reg_put(&env, r);
	EXPECT_EQ(b.destroy, 1);

	/* ACTIVE and RELEASING both sequester, exactly once. */
	memset(&b, 0, sizeof(b));
	r = reg_for(fd, XDEV_EXT_REG_DGRAM_RX, &b);
	EXPECT_TRUE(xdev_ext_reg_sequester(&env, r));
	EXPECT_EQ(xdev_ext_reg_state_of(r), XDEV_EXT_REG_SEQUESTERED);
	EXPECT_TRUE(!xdev_ext_reg_serves(r, self));
	EXPECT_TRUE(!xdev_ext_reg_sequester(&env, r));
	EXPECT_TRUE(!xdev_ext_reg_release(&env, r, XDEV_EXT_RELEASE_SOCKOPT));
	EXPECT_EQ(b.sequester, 1);
	EXPECT_EQ(b.release, 0);
	xdev_ext_reg_put(&env, r);
	memset(&b, 0, sizeof(b));
	r = reg_for(fd, XDEV_EXT_REG_DGRAM_RX, &b);
	EXPECT_TRUE(xdev_ext_reg_release(&env, r, XDEV_EXT_RELEASE_MIRROR));
	EXPECT_TRUE(xdev_ext_reg_sequester(&env, r));
	EXPECT_EQ(b.sequester, 1);
	EXPECT_EQ(r->release_reason, XDEV_EXT_RELEASE_MIRROR);
	xdev_ext_reg_put(&env, r);
	EXPECT_EQ(b.destroy, 1);

	/* Write registrations keep serving in a forked child. */
	memset(&b, 0, sizeof(b));
	w = reg_for(fd, XDEV_EXT_REG_NS_PASSTHRU, &b);
	EXPECT_TRUE(xdev_ext_reg_serves(w, self + 1));
	EXPECT_EQ(atomic_load(&w->status_flags), 0);
	EXPECT_EQ(xdev_ext_reg_install(&env, fd, w), 0);
	xdev_ext_reg_refresh_status_flags(fd, O_RDWR | O_DIRECT);
	EXPECT_EQ(atomic_load(&w->status_flags), O_RDWR | O_DIRECT);
	xdev_ext_reg_refresh_status_flags(fd + 1, O_RDONLY);
	xdev_ext_reg_put(&env, w);
	EXPECT_EQ(xdev_ext_reg_close(&env, fd), 0);
	EXPECT_EQ(b.destroy, 1);
}

static void test_atfork_lock_set(void)
{
	unsigned int i;

	xdev_ext_reg_lock_all();
	EXPECT_EQ(pthread_mutex_trylock(&xdev_ext_privfd_mu), EBUSY);
	for (i = 0; i < XDEV_EXT_REG_SHARDS; i++)
		EXPECT_EQ(pthread_mutex_trylock(&xdev_ext_reg_shard_mu[i]), EBUSY);
	xdev_ext_reg_unlock_all();
	EXPECT_EQ(pthread_mutex_trylock(&xdev_ext_privfd_mu), 0);
	EXPECT_EQ(pthread_mutex_unlock(&xdev_ext_privfd_mu), 0);
	for (i = 0; i < XDEV_EXT_REG_SHARDS; i++) {
		EXPECT_EQ(pthread_mutex_trylock(&xdev_ext_reg_shard_mu[i]), 0);
		EXPECT_EQ(pthread_mutex_unlock(&xdev_ext_reg_shard_mu[i]), 0);
	}
}

/* A mutex left locked by a cancelled thread can never be taken again. */
static bool mutex_free(pthread_mutex_t *mu, const char *what)
{
	int ret = pthread_mutex_trylock(mu);

	checks++;
	if (ret) {
		fprintf(stderr, "%s:%d: %s left locked by a cancelled thread (%s)\n",
			__FILE__, __LINE__, what, strerror(ret));
		failures++;
		return false;
	}
	(void)pthread_mutex_unlock(mu);
	return true;
}

struct cancel_body {
	void (*run)(void *arg);
	void *arg;
};

static void *cancel_thread(void *opaque)
{
	struct cancel_body *body = opaque;

	body->run(body->arg);
	return NULL;
}

/* Run @run on a thread, cancel the thread once it is blocked inside the real
 * close of @fd, and return whether the cancellation acted. */
static bool cancel_inside_close(int fd, void (*run)(void *), void *arg)
{
	struct cancel_body body = { .run = run, .arg = arg };
	void *ret = NULL;
	pthread_t thread;

	__atomic_store_n(&close_blocked, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&close_unblock, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&block_close_fd, fd, __ATOMIC_RELEASE);
	if (pthread_create(&thread, NULL, cancel_thread, &body)) {
		fprintf(stderr, "pthread_create failed\n");
		exit(EXIT_FAILURE);
	}
	while (!__atomic_load_n(&close_blocked, __ATOMIC_ACQUIRE))
		usleep(1000);
	EXPECT_EQ(pthread_cancel(thread), 0);
	__atomic_store_n(&close_unblock, 1, __ATOMIC_RELEASE);
	EXPECT_EQ(pthread_join(thread, &ret), 0);
	__atomic_store_n(&block_close_fd, -1, __ATOMIC_RELEASE);
	return ret == PTHREAD_CANCELED;
}

static void close_body(void *arg)
{
	(void)xdev_ext_reg_close(&env, *(int *)arg);
}

/* close() stays a cancellation point, but the request acts only once the
 * shard lock is released and the slot forgotten. */
static void test_cancel_inside_close(void)
{
	struct fake_backend b = { 0 };
	int fd = place(open_file(), 400);
	int same_shard = place(open_file(), 400 + XDEV_EXT_REG_SHARDS);

	register_fd(fd, &b);
	EXPECT_TRUE(cancel_inside_close(fd, close_body, &fd));
	if (!mutex_free(&xdev_ext_reg_shard_mu[xdev_ext_reg_shard(fd)], "shard mutex"))
		return;
	EXPECT_TRUE(!fd_open(fd));
	EXPECT_TRUE(peek(fd) == NULL);
	EXPECT_EQ(b.destroy, 1);
	EXPECT_EQ(xdev_ext_reg_close(&env, same_shard), 0);
}

static pthread_barrier_t pending_go;

static void *close_with_pending_cancel(void *arg)
{
	/* pthread_barrier_wait() is not a cancellation point. */
	pthread_barrier_wait(&pending_go);
	pthread_barrier_wait(&pending_go);
	(void)xdev_ext_reg_close(&env, *(int *)arg);
	return NULL;
}

/* A request pending when close() is called acts before anything is locked
 * or closed, as it does in libc. */
static void test_cancel_pending_at_close(void)
{
	struct fake_backend b = { 0 };
	int fd = place(open_file(), 401);
	struct xdev_ext_reg *r = register_fd(fd, &b);
	void *ret = NULL;
	pthread_t thread;

	EXPECT_EQ(pthread_barrier_init(&pending_go, NULL, 2), 0);
	EXPECT_EQ(pthread_create(&thread, NULL, close_with_pending_cancel, &fd),
		  0);
	pthread_barrier_wait(&pending_go);
	EXPECT_EQ(pthread_cancel(thread), 0);
	pthread_barrier_wait(&pending_go);
	EXPECT_EQ(pthread_join(thread, &ret), 0);
	EXPECT_TRUE(ret == PTHREAD_CANCELED);
	if (!mutex_free(&xdev_ext_reg_shard_mu[xdev_ext_reg_shard(fd)], "shard mutex"))
		return;
	EXPECT_TRUE(fd_open(fd));
	EXPECT_TRUE(peek(fd) == r);
	EXPECT_EQ(b.destroy, 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, fd), 0);
	EXPECT_EQ(b.destroy, 1);
}

static void private_close_body(void *arg)
{
	(void)xdev_ext_privfd_close(&real_ops, &((struct owner *)arg)->fd);
}

static void adopt_body(void *arg)
{
	struct owner *owner = arg;

	(void)xdev_ext_privfd_adopt(&real_ops, &owner->fd, XDEV_EXT_PRIVFD_LINK, owner,
			       relocated);
}

/* Front-end teardown and adoption are not cancellation points: they run to
 * completion and release xdev_ext_privfd_mu. */
static void test_cancel_inside_private_close(void)
{
	struct owner owner = { 0 };
	int priv = adopt(open_file(), XDEV_EXT_PRIVFD_XSK, &owner);
	int fd;

	EXPECT_TRUE(!cancel_inside_close(priv, private_close_body, &owner));
	if (!mutex_free(&xdev_ext_privfd_mu, "xdev_ext_privfd_mu"))
		return;
	EXPECT_EQ(owner.fd, -1);
	EXPECT_TRUE(!fd_open(priv));
	EXPECT_TRUE(!xdev_ext_privfd_test(priv));

	fd = open_file();
	owner = (struct owner){ .fd = fd };
	EXPECT_TRUE(!cancel_inside_close(fd, adopt_body, &owner));
	if (!mutex_free(&xdev_ext_privfd_mu, "xdev_ext_privfd_mu"))
		return;
	EXPECT_TRUE(!fd_open(fd));
	EXPECT_TRUE(owner.fd >= TEST_FLOOR && xdev_ext_privfd_test(owner.fd) &&
		    fd_open(owner.fd));
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &owner.fd), 0);
}

struct dup2_arg {
	int oldfd;
	int newfd;
	int ret;
};

static void dup2_body(void *arg)
{
	struct dup2_arg *a = arg;

	a->ret = xdev_ext_reg_dup2(&env, a->oldfd, a->newfd);
}

/* dup2() onto a private fd that fails closes the number again with
 * xdev_ext_privfd_mu and two shard locks held. */
static void test_cancel_inside_dup2_rollback(void)
{
	struct owner owner = { 0 };
	int priv = adopt(open_file(), XDEV_EXT_PRIVFD_XSK, &owner);
	struct dup2_arg a = { .oldfd = 898, .newfd = priv };

	EXPECT_TRUE(!fd_open(a.oldfd));
	EXPECT_TRUE(!cancel_inside_close(priv, dup2_body, &a));
	if (!mutex_free(&xdev_ext_privfd_mu, "xdev_ext_privfd_mu") ||
	    !mutex_free(&xdev_ext_reg_shard_mu[xdev_ext_reg_shard(a.oldfd)],
			"shard mutex") ||
	    !mutex_free(&xdev_ext_reg_shard_mu[xdev_ext_reg_shard(priv)], "shard mutex"))
		return;
	EXPECT_EQ(a.ret, -1);
	EXPECT_TRUE(!fd_open(priv));
	EXPECT_TRUE(owner.fd != priv && xdev_ext_privfd_test(owner.fd) &&
		    fd_open(owner.fd));
	EXPECT_EQ(xdev_ext_privfd_close(&real_ops, &owner.fd), 0);
}

/* A case that fails leaves a mutex locked by a dead thread, which would hang
 * every later case: each one runs in a child of its own. */
static void run_in_child(const char *name, void (*fn)(void))
{
	int status = 0;
	pid_t pid;

	fflush(stderr);
	pid = fork();
	if (pid == 0) {
		alarm(30);
		failures = 0;
		fn();
		_exit(failures ? EXIT_FAILURE : EXIT_SUCCESS);
	}
	checks++;
	if (pid < 0 || waitpid(pid, &status, 0) != pid ||
	    !WIFEXITED(status) || WEXITSTATUS(status)) {
		fprintf(stderr, "%s:%d: %s failed (status 0x%x)\n", __FILE__,
			__LINE__, name, status);
		failures++;
	}
}

#define CROSS_ITERATIONS 10000U

struct cross_arg {
	pthread_barrier_t *start;
	int from;
	int to;
	unsigned int errors;
};

static void *cross_dup2(void *opaque)
{
	struct cross_arg *arg = opaque;

	/* Both loops must overlap, or a lock-order bug never shows. */
	pthread_barrier_wait(arg->start);
	for (unsigned int i = 0; i < CROSS_ITERATIONS; i++)
		if (xdev_ext_reg_dup2(&env, arg->from, arg->to) != arg->to)
			arg->errors++;
	return NULL;
}

static bool join_by(pthread_t thread, const struct timespec *deadline)
{
	return pthread_timedjoin_np(thread, NULL, deadline) == 0;
}

static void test_cross_dup2_does_not_deadlock(int a_at, int b_at)
{
	struct fake_backend ba = { 0 }, bb = { 0 };
	int a = place(open_file(), a_at);
	int b = place(open_file(), b_at);
	struct xdev_ext_reg *ra = register_fd(a, &ba);
	struct xdev_ext_reg *rb = register_fd(b, &bb);
	pthread_barrier_t start;
	struct cross_arg ab = { .start = &start, .from = a, .to = b };
	struct cross_arg ba_arg = { .start = &start, .from = b, .to = a };
	struct xdev_ext_reg *survivor;
	struct timespec deadline;
	pthread_t t1, t2;

	EXPECT_EQ(pthread_barrier_init(&start, NULL, 2), 0);
	EXPECT_EQ(pthread_create(&t1, NULL, cross_dup2, &ab), 0);
	EXPECT_EQ(pthread_create(&t2, NULL, cross_dup2, &ba_arg), 0);
	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 60;
	if (!join_by(t1, &deadline) || !join_by(t2, &deadline)) {
		fprintf(stderr,
			"FAIL: cross dup2(%d,%d)/dup2(%d,%d) did not finish in 60 s (deadlock)\n",
			a, b, b, a);
		exit(EXIT_FAILURE);
	}
	EXPECT_EQ(pthread_barrier_destroy(&start), 0);
	EXPECT_EQ(ab.errors, 0);
	EXPECT_EQ(ba_arg.errors, 0);
	EXPECT_EQ(ba.destroy + bb.destroy, 1);
	survivor = ba.destroy ? rb : ra;
	EXPECT_TRUE(peek(a) == survivor && peek(b) == survivor);
	EXPECT_EQ(refs(survivor), 2);
	EXPECT_TRUE(same_file(a, &survivor->id));
	EXPECT_TRUE(same_file(b, &survivor->id));
	EXPECT_EQ(xdev_ext_reg_close(&env, a), 0);
	EXPECT_EQ(xdev_ext_reg_close(&env, b), 0);
	EXPECT_EQ(ba.destroy + bb.destroy, 2);
}

#define RACE_READS 20000U
#define RACE_INSTALLS 2000U

struct reader_arg {
	int fd;
	unsigned int hits;
	unsigned int wrong_kind;
};

static void *read_slots(void *opaque)
{
	struct reader_arg *arg = opaque;

	for (unsigned int i = 0; i < RACE_READS; i++) {
		struct xdev_ext_reg *r = xdev_ext_reg_get(arg->fd);

		if (!r)
			continue;
		arg->hits++;
		if (r->kind != XDEV_EXT_REG_NS_PASSTHRU)
			arg->wrong_kind++;
		xdev_ext_reg_put(&env, r);
	}
	return NULL;
}

/* Readers drop the last reference of replaced registrations; the sanitizer
 * build turns any use after free into a failure. */
static void test_get_put_race_destroys_each_object_once(void)
{
	static struct fake_backend shared;
	struct reader_arg readers[2];
	pthread_t threads[2];
	int fd = place(open_file(), 700);
	unsigned int install_errors = 0;
	unsigned int i;

	memset(&shared, 0, sizeof(shared));
	for (i = 0; i < 2; i++) {
		readers[i] = (struct reader_arg){ .fd = fd };
		EXPECT_EQ(pthread_create(&threads[i], NULL, read_slots,
					 &readers[i]), 0);
	}
	for (i = 0; i < RACE_INSTALLS; i++) {
		struct xdev_ext_reg *r = reg_for(fd, XDEV_EXT_REG_NS_PASSTHRU, &shared);

		if (xdev_ext_reg_install(&env, fd, r))
			install_errors++;
		xdev_ext_reg_put(&env, r);
	}
	EXPECT_EQ(install_errors, 0);
	for (i = 0; i < 2; i++) {
		EXPECT_EQ(pthread_join(threads[i], NULL), 0);
		EXPECT_EQ(readers[i].wrong_kind, 0);
	}
	EXPECT_EQ(xdev_ext_reg_close(&env, fd), 0);
	EXPECT_EQ(__atomic_load_n(&shared.destroy, __ATOMIC_ACQUIRE),
		  RACE_INSTALLS);
}

int main(void)
{
	xdev_ext_privfd_set_floor(TEST_FLOOR);
	test_identity_and_floor();
	test_span_split();
	test_dup_family_shares_one_object();
	test_in_flight_reference_defers_destroy();
	test_close_call_forgets_the_slot();
	test_forget_drops_only_the_expected_registration();
	test_dup2_over_a_registered_target();
	test_install_checks_identity_under_the_lock();
	test_dup_racing_close_of_the_source();
	test_alias_beyond_the_table();
	test_epoll_seen_follows_the_descriptor();
	test_close_range_with_and_without_cloexec();
	test_adopt_and_front_end_close();
	test_private_fds_are_invisible_to_the_application();
	test_dup_onto_a_private_fd_migrates_it_first(false);
	test_dup_onto_a_private_fd_migrates_it_first(true);
	test_dup_onto_a_private_fd_when_migration_fails();
	test_dup_onto_a_private_fd_when_the_real_call_fails();
	test_close_range_splits_around_private_fds();
	test_state_machine();
	test_atfork_lock_set();
	run_in_child("cancel inside close", test_cancel_inside_close);
	run_in_child("cancel pending at close", test_cancel_pending_at_close);
	run_in_child("cancel inside private close",
		     test_cancel_inside_private_close);
	run_in_child("cancel inside dup2 rollback",
		     test_cancel_inside_dup2_rollback);
	/* Targets below XDEV_EXT_PRIVFD_FLOOR_MIN are ordered by the shard locks
	 * alone: two shards is the deadlock case, one shard must not lock
	 * itself twice.  Higher targets also hold xdev_ext_privfd_mu. */
	test_cross_dup2_does_not_deadlock(50, 51);
	test_cross_dup2_does_not_deadlock(52, 52 + XDEV_EXT_REG_SHARDS);
	test_cross_dup2_does_not_deadlock(200, 265);
	test_get_put_race_destroys_each_object_once();

	if (failures) {
		fprintf(stderr,
			"FAIL: %u/%u registration and private-fd checks\n",
			failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u registration and private-fd checks\n", checks);
	return EXIT_SUCCESS;
}
