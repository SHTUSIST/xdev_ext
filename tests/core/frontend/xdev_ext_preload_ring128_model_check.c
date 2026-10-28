// SPDX-License-Identifier: GPL-2.0
/*
 * Checks the XDEV_EXT_MODEL_RING128 simulation of libxdev_ext_preload_kernel_model.so
 * against the Linux 6.16 io_uring ABI, and tools/xdev_ext_preload_ring128.h
 * through it.  Run without arguments, it re-executes itself once per
 * scenario with the model preloaded from its own directory:
 *
 *   fd-only, default (variable unset), fd-only-eintr (XDEV_EXT_MODEL_EINTR=1)
 *	NO_MMAP + REGISTERED_FD_ONLY rings, plain rings and RING_FDS all work.
 *   ring-fds
 *	NO_MMAP and REGISTERED_FD_ONLY are refused; plain setup + RING_FDS work.
 *   reject
 *	No 128-byte SQE ring at all.
 *   host
 *	No model: the running kernel answers.  On a kernel without these
 *	features (tokio runs 5.15) the header must end up unavailable without
 *	leaking a descriptor; on Linux 6.5+ the same raw checks that validate
 *	the model's layout run against the kernel itself.
 *
 * The expected offsets are struct io_rings of include/linux/io_uring_types.h
 * and rings_size() of io_uring/io_uring.c, written out by hand here.
 * XDEV_EXT_PRELOAD_TEST_LD_PREFIX, if set, is put in front of the model in
 * LD_PRELOAD (the sanitizer runtime must come first).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "xdev_ext_preload_ring128.h"

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

#define K_SQ_HEAD		0U
#define K_SQ_TAIL		4U
#define K_CQ_HEAD		8U
#define K_CQ_TAIL		12U
#define K_SQ_RING_MASK		16U
#define K_CQ_RING_MASK		20U
#define K_SQ_RING_ENTRIES	24U
#define K_CQ_RING_ENTRIES	28U
#define K_SQ_DROPPED		32U
#define K_SQ_FLAGS		36U
#define K_CQ_FLAGS		40U
#define K_CQ_OVERFLOW		44U
#define K_CQES			64U
#define K_SQ_ARRAY		384U	/* ALIGN((64 + 8 * 16) << 1, 64) */

struct scenario {
	const char *name;
	const char *ring128;	/* XDEV_EXT_MODEL_RING128, NULL = unset */
	bool model;
	bool eintr;
};

static const struct scenario scenarios[] = {
	{ "fd-only", "fd-only", true, false },
	{ "default", NULL, true, false },
	{ "fd-only-eintr", "fd-only", true, true },
	{ "ring-fds", "ring-fds", true, false },
	{ "reject", "reject", true, false },
	{ "host", NULL, false, false },
};

static long page_size;

static unsigned int count_fds(void)
{
	DIR *dir = opendir("/proc/self/fd");
	struct dirent *entry;
	unsigned int n = 0;

	if (!dir)
		return 0;
	while ((entry = readdir(dir)))
		n += entry->d_name[0] != '.';
	closedir(dir);
	return n - 1;	/* the directory stream itself */
}

static uint32_t *word(void *rings, unsigned int offset)
{
	return (uint32_t *)((unsigned char *)rings + offset);
}

static int raw_setup(unsigned int entries, struct io_uring_params *p)
{
	return (int)syscall(SYS_io_uring_setup, (long)entries, p);
}

static int raw_register(unsigned int fd, unsigned int opcode, void *arg,
			unsigned int nr)
{
	return (int)syscall(SYS_io_uring_register, (long)fd, (long)opcode, arg,
			    (long)nr);
}

static int raw_enter(unsigned int fd, unsigned int to_submit,
		     unsigned int min_complete, unsigned int flags)
{
	return (int)syscall(SYS_io_uring_enter, (long)fd, (long)to_submit,
			    (long)min_complete, (long)flags, NULL, 0L);
}

/*
 * Submit the entry at the SQ tail - 1 and wait for one CQE; EINTR resumes
 * without resubmitting.  Returns how many entries the kernel consumed, or -1.
 */
static int raw_submit_wait(void *rings, unsigned int fd, bool registered)
{
	unsigned int flags = IORING_ENTER_GETEVENTS |
			     (registered ? IORING_ENTER_REGISTERED_RING : 0);
	uint32_t head = __atomic_load_n(word(rings, K_SQ_HEAD), __ATOMIC_ACQUIRE);
	unsigned int tries;

	for (tries = 0; tries < 8; tries++) {
		unsigned int to_submit =
			__atomic_load_n(word(rings, K_SQ_HEAD),
					__ATOMIC_ACQUIRE) == head;

		if (raw_enter(fd, to_submit, 1, flags) >= 0)
			break;
		if (errno != EINTR)
			return -1;
	}
	return (int)(__atomic_load_n(word(rings, K_SQ_HEAD), __ATOMIC_ACQUIRE) -
		     head);
}

static void push_sqe(void *rings, void *sqes, const struct io_uring_sqe *sqe)
{
	uint32_t tail = *word(rings, K_SQ_TAIL);
	uint32_t index = tail & 3;

	memset((unsigned char *)sqes + index * 128, 0, 128);
	memcpy((unsigned char *)sqes + index * 128, sqe, sizeof(*sqe));
	word(rings, K_SQ_ARRAY)[index] = index;
	__atomic_store_n(word(rings, K_SQ_TAIL), tail + 1, __ATOMIC_RELEASE);
}

/* Take the CQE at the head; check the 32-byte slot and its zeroed tail. */
static bool pop_cqe(void *rings, uint64_t user_data, int32_t *res)
{
	uint32_t head = *word(rings, K_CQ_HEAD);
	const unsigned char *cqe;
	uint64_t big[2], seen;
	uint32_t flags;

	if (head == __atomic_load_n(word(rings, K_CQ_TAIL), __ATOMIC_ACQUIRE))
		return false;
	cqe = (unsigned char *)rings + K_CQES + (head & 7) * 32;
	memcpy(&seen, cqe, 8);
	memcpy(res, cqe + 8, 4);
	memcpy(&flags, cqe + 12, 4);
	memcpy(big, cqe + 16, 16);
	EXPECT_EQ(seen, user_data);
	EXPECT_EQ(flags, 0);
	EXPECT_EQ(big[0], 0);
	EXPECT_EQ(big[1], 0);
	__atomic_store_n(word(rings, K_CQ_HEAD), head + 1, __ATOMIC_RELEASE);
	return seen == user_data;
}

static void expect_kernel_offsets(const struct io_uring_params *p)
{
	EXPECT_EQ(p->sq_entries, 4);
	EXPECT_EQ(p->cq_entries, 8);
	EXPECT_EQ(p->sq_off.head, K_SQ_HEAD);
	EXPECT_EQ(p->sq_off.tail, K_SQ_TAIL);
	EXPECT_EQ(p->sq_off.ring_mask, K_SQ_RING_MASK);
	EXPECT_EQ(p->sq_off.ring_entries, K_SQ_RING_ENTRIES);
	EXPECT_EQ(p->sq_off.flags, K_SQ_FLAGS);
	EXPECT_EQ(p->sq_off.dropped, K_SQ_DROPPED);
	EXPECT_EQ(p->sq_off.array, K_SQ_ARRAY);
	EXPECT_EQ(p->cq_off.head, K_CQ_HEAD);
	EXPECT_EQ(p->cq_off.tail, K_CQ_TAIL);
	EXPECT_EQ(p->cq_off.ring_mask, K_CQ_RING_MASK);
	EXPECT_EQ(p->cq_off.ring_entries, K_CQ_RING_ENTRIES);
	EXPECT_EQ(p->cq_off.overflow, K_CQ_OVERFLOW);
	EXPECT_EQ(p->cq_off.cqes, K_CQES);
	EXPECT_EQ(p->cq_off.flags, K_CQ_FLAGS);
	EXPECT_EQ(p->features & (IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
				 IORING_FEAT_REG_REG_RING),
		  IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
		  IORING_FEAT_REG_REG_RING);
}

static void expect_ring_header(void *rings)
{
	EXPECT_EQ(*word(rings, K_SQ_RING_MASK), 3);
	EXPECT_EQ(*word(rings, K_CQ_RING_MASK), 7);
	EXPECT_EQ(*word(rings, K_SQ_RING_ENTRIES), 4);
	EXPECT_EQ(*word(rings, K_CQ_RING_ENTRIES), 8);
}

struct thread_probe {
	unsigned int index;
	int ret;
	int error;
};

static void *enter_from_other_thread(void *opaque)
{
	struct thread_probe *probe = opaque;

	probe->ret = raw_enter(probe->index, 0, 0,
			       IORING_ENTER_REGISTERED_RING);
	probe->error = errno;
	return NULL;
}

/* Fixed files, NOP, WRITE and URING_CMD on one registered ring. */
static void exercise_registered_ring(void *rings, void *sqes, int index)
{
	char path[] = "/tmp/xdev_ext-ring128-check-XXXXXX";
	unsigned char data[512], back[512];
	struct io_uring_rsrc_update update;
	struct io_uring_sqe sqe;
	struct thread_probe probe = { .index = (unsigned int)index };
	pthread_t thread;
	int32_t files[16], fd_value, res = 0;
	unsigned int i;
	pid_t child;
	int status, tmp;

	for (i = 0; i < 16; i++)
		files[i] = -1;
	EXPECT_EQ(raw_register((unsigned int)index, IORING_REGISTER_FILES |
			       IORING_REGISTER_USE_REGISTERED_RING, files, 16),
		  0);
	errno = 0;
	EXPECT_EQ(raw_register((unsigned int)index, IORING_REGISTER_FILES |
			       IORING_REGISTER_USE_REGISTERED_RING, files, 16),
		  -1);
	EXPECT_EQ(errno, EBUSY);

	tmp = mkstemp(path);
	EXPECT_TRUE(tmp >= 0);
	if (tmp < 0)
		return;
	unlink(path);
	fd_value = tmp;
	update = (struct io_uring_rsrc_update){
		.offset = 16, .data = (uintptr_t)&fd_value };
	errno = 0;
	EXPECT_EQ(raw_register((unsigned int)index, IORING_REGISTER_FILES_UPDATE |
			       IORING_REGISTER_USE_REGISTERED_RING, &update, 1),
		  -1);
	EXPECT_EQ(errno, EINVAL);
	update.offset = 3;
	EXPECT_EQ(raw_register((unsigned int)index, IORING_REGISTER_FILES_UPDATE |
			       IORING_REGISTER_USE_REGISTERED_RING, &update, 1),
		  1);

	/* A garbage 64-byte entry right after SQE 0 must never be read. */
	memset((unsigned char *)sqes + 64, 0xff, 64);
	memset((unsigned char *)rings + K_CQES, 0xa5, 8 * 32);

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_NOP;
	sqe.user_data = 0x1111;
	push_sqe(rings, sqes, &sqe);
	memset((unsigned char *)sqes + 64, 0xff, 64);
	EXPECT_EQ(raw_submit_wait(rings, (unsigned int)index, true), 1);
	EXPECT_EQ(*word(rings, K_SQ_HEAD), 1);
	EXPECT_EQ(*word(rings, K_CQ_TAIL), 1);
	EXPECT_TRUE(pop_cqe(rings, 0x1111, &res));
	EXPECT_EQ(res, 0);

	/* SQE 1 sits at byte 128, its CQE at cqes + 32. */
	for (i = 0; i < sizeof(data); i++)
		data[i] = (unsigned char)(i * 13 + 5);
	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_WRITE;
	sqe.flags = IOSQE_FIXED_FILE;
	sqe.fd = 3;
	sqe.addr = (uintptr_t)data;
	sqe.len = sizeof(data);
	sqe.off = 4096;
	sqe.user_data = 0x2222;
	push_sqe(rings, sqes, &sqe);
	EXPECT_EQ(raw_submit_wait(rings, (unsigned int)index, true), 1);
	EXPECT_TRUE(pop_cqe(rings, 0x2222, &res));
	EXPECT_EQ(res, (int)sizeof(data));
	EXPECT_EQ(pread(tmp, back, sizeof(back), 4096), (ssize_t)sizeof(back));
	EXPECT_TRUE(!memcmp(back, data, sizeof(data)));

	/* An empty slot fails the request, not the submission. */
	sqe.fd = 5;
	sqe.user_data = 0x3333;
	push_sqe(rings, sqes, &sqe);
	EXPECT_EQ(raw_submit_wait(rings, (unsigned int)index, true), 1);
	EXPECT_TRUE(pop_cqe(rings, 0x3333, &res));
	EXPECT_EQ(res, -EBADF);

	/* A regular file has no ->uring_cmd. */
	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = IORING_OP_URING_CMD;
	sqe.flags = IOSQE_FIXED_FILE;
	sqe.fd = 3;
	sqe.user_data = 0x4444;
	push_sqe(rings, sqes, &sqe);
	EXPECT_EQ(raw_submit_wait(rings, (unsigned int)index, true), 1);
	EXPECT_TRUE(pop_cqe(rings, 0x4444, &res));
	EXPECT_EQ(res, -EOPNOTSUPP);
	close(tmp);

	/* The registered-ring table belongs to one task. */
	EXPECT_EQ(pthread_create(&thread, NULL, enter_from_other_thread,
				 &probe), 0);
	EXPECT_EQ(pthread_join(thread, NULL), 0);
	EXPECT_EQ(probe.ret, -1);
	EXPECT_EQ(probe.error, EINVAL);
	child = fork();
	if (!child) {
		errno = 0;
		_exit(raw_enter((unsigned int)index, 0, 0,
				IORING_ENTER_REGISTERED_RING) == -1 &&
		      errno == EINVAL ? 0 : 1);
	}
	EXPECT_TRUE(child > 0);
	EXPECT_EQ(waitpid(child, &status, 0), child);
	EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* Unregistered: the same task now gets EBADF for the index. */
	update = (struct io_uring_rsrc_update){ .offset = (uint32_t)index };
	EXPECT_EQ(raw_register((unsigned int)index, IORING_UNREGISTER_RING_FDS |
			       IORING_REGISTER_USE_REGISTERED_RING, &update, 1),
		  1);
	errno = 0;
	EXPECT_EQ(raw_enter((unsigned int)index, 0, 0,
			    IORING_ENTER_REGISTERED_RING), -1);
	EXPECT_EQ(errno, EBADF);
}

static void check_raw_fd_only(void)
{
	struct io_uring_params p;
	void *rings, *sqes;
	unsigned int before;
	int index;

	rings = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	sqes = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	EXPECT_TRUE(rings != MAP_FAILED && sqes != MAP_FAILED);
	if (rings == MAP_FAILED || sqes == MAP_FAILED)
		return;
	EXPECT_EQ(madvise(rings, page_size, MADV_DONTFORK), 0);
	EXPECT_EQ(madvise(sqes, page_size, MADV_DONTFORK), 0);

	/* There is no way to mmap rings without a real fd. */
	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32 |
		  IORING_SETUP_REGISTERED_FD_ONLY;
	errno = 0;
	EXPECT_EQ(raw_setup(4, &p), -1);
	EXPECT_EQ(errno, EINVAL);

	/* user_addr is set iff the region is user memory, and page aligned. */
	memset(&p, 0, sizeof(p));
	p.flags = XDEV_EXT_RING128_FD_ONLY_FLAGS;
	p.sq_off.user_addr = (uintptr_t)sqes;
	errno = 0;
	EXPECT_EQ(raw_setup(4, &p), -1);
	EXPECT_EQ(errno, EFAULT);
	memset(&p, 0, sizeof(p));
	p.flags = XDEV_EXT_RING128_FD_ONLY_FLAGS;
	p.sq_off.user_addr = (uintptr_t)sqes;
	p.cq_off.user_addr = (uintptr_t)rings + 8;
	errno = 0;
	EXPECT_EQ(raw_setup(4, &p), -1);
	EXPECT_EQ(errno, EINVAL);

	memset(&p, 0, sizeof(p));
	p.flags = XDEV_EXT_RING128_FD_ONLY_FLAGS;
	p.sq_off.user_addr = (uintptr_t)sqes;
	p.cq_off.user_addr = (uintptr_t)rings;
	before = count_fds();
	index = raw_setup(4, &p);
	EXPECT_TRUE(index >= 0 && index < 16);
	EXPECT_EQ(count_fds(), before);
	if (index < 0)
		goto out;
	expect_kernel_offsets(&p);
	EXPECT_EQ(p.sq_off.user_addr, (uintptr_t)sqes);
	EXPECT_EQ(p.cq_off.user_addr, (uintptr_t)rings);
	expect_ring_header(rings);
	exercise_registered_ring(rings, sqes, index);
	EXPECT_EQ(count_fds(), before);
out:
	munmap(rings, page_size);
	munmap(sqes, page_size);
}

static void check_raw_ring_fds(bool fd_only_refused)
{
	struct io_uring_rsrc_update update;
	struct io_uring_params p;
	void *rings, *sqes;
	unsigned int before;
	int fd;

	if (fd_only_refused) {
		void *page = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		EXPECT_TRUE(page != MAP_FAILED);
		memset(&p, 0, sizeof(p));
		p.flags = XDEV_EXT_RING128_FD_ONLY_FLAGS;
		p.sq_off.user_addr = (uintptr_t)page;
		p.cq_off.user_addr = (uintptr_t)page + page_size;
		errno = 0;
		EXPECT_EQ(raw_setup(4, &p), -1);
		EXPECT_EQ(errno, EINVAL);
		munmap(page, 2 * page_size);
	}
	memset(&p, 0, sizeof(p));
	p.flags = XDEV_EXT_RING128_SETUP_FLAGS;
	before = count_fds();
	fd = raw_setup(4, &p);
	EXPECT_TRUE(fd >= 0);
	if (fd < 0)
		return;
	EXPECT_EQ(count_fds(), before + 1);
	expect_kernel_offsets(&p);
	rings = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	sqes = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	EXPECT_TRUE(rings != MAP_FAILED && sqes != MAP_FAILED);
	if (rings == MAP_FAILED || sqes == MAP_FAILED) {
		close(fd);
		return;
	}
	expect_ring_header(rings);
	update = (struct io_uring_rsrc_update){ .offset = ~0U, .data = fd };
	EXPECT_EQ(raw_register((unsigned int)fd, IORING_REGISTER_RING_FDS,
			       &update, 1), 1);
	EXPECT_TRUE(update.offset < 16);
	EXPECT_EQ(close(fd), 0);
	EXPECT_EQ(count_fds(), before);
	if (update.offset < 16)
		exercise_registered_ring(rings, sqes, (int)update.offset);
	munmap(rings, page_size);
	munmap(sqes, page_size);
	EXPECT_EQ(count_fds(), before);
}

static uint64_t (*model_counter(const char *name))(void)
{
	uint64_t (*fn)(void);

	*(void **)&fn = dlsym(RTLD_DEFAULT, name);
	return fn;
}

struct exiting_thread {
	void *rings;
	void *sqes;
	int index;
};

static void *setup_then_exit(void *opaque)
{
	struct exiting_thread *t = opaque;
	struct io_uring_params p;

	memset(&p, 0, sizeof(p));
	p.flags = XDEV_EXT_RING128_FD_ONLY_FLAGS;
	p.sq_off.user_addr = (uintptr_t)t->sqes;
	p.cq_off.user_addr = (uintptr_t)t->rings;
	t->index = raw_setup(4, &p);
	return NULL;
}

/* A thread's registered rings go away with the thread (task exit). */
static void check_thread_exit_releases_rings(void)
{
	uint64_t (*live)(void) = model_counter("xdev_ext_model_ring128_rings");
	struct exiting_thread t = { .index = -1 };
	pthread_t thread;
	uint64_t before;

	if (!live)
		return;
	t.rings = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	t.sqes = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	EXPECT_TRUE(t.rings != MAP_FAILED && t.sqes != MAP_FAILED);
	before = live();
	EXPECT_EQ(pthread_create(&thread, NULL, setup_then_exit, &t), 0);
	EXPECT_EQ(pthread_join(thread, NULL), 0);
	EXPECT_TRUE(t.index >= 0 && t.index < 16);
	EXPECT_EQ(live(), before);
	munmap(t.rings, page_size);
	munmap(t.sqes, page_size);
}

static void check_header(int expected_mode, bool eintr)
{
	const struct xdev_ext_ring128_ops *ops = xdev_ext_ring128_sys_ops();
	uint64_t (*sqes_seen)(void) = model_counter("xdev_ext_model_ring128_sqes");
	uint64_t (*setups)(void) = model_counter("xdev_ext_model_ring128_setups");
	uint64_t (*live)(void) = model_counter("xdev_ext_model_ring128_rings");
	unsigned char sqe[XDEV_EXT_RING128_SQE_SIZE], data[512];
	struct io_uring_sqe *head = (struct io_uring_sqe *)sqe;
	struct xdev_ext_ring128 r;
	struct stat st;
	unsigned int before;
	uint64_t seen = 0, tried = 0;
	uint32_t cflags = 1;
	bool published = false;
	int32_t res = -1;
	int anchor;

	memset(&r, 0, sizeof(r));
	before = count_fds();
	if (setups)
		tried = setups();
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, ops),
		  expected_mode == XDEV_EXT_R128_UNAVAILABLE ? -ENODEV : 0);
	EXPECT_EQ(r.mode, expected_mode);
	EXPECT_EQ(count_fds(), before);
	if (expected_mode == XDEV_EXT_R128_UNAVAILABLE) {
		EXPECT_EQ(r.fd_only_error, -EINVAL);
		EXPECT_EQ(r.ring_fds_error, -EINVAL);
		if (setups) {
			EXPECT_EQ(setups() - tried, 2);
			EXPECT_EQ(xdev_ext_ring128_ensure(&r, ops), -ENODEV);
			EXPECT_EQ(setups() - tried, 2);
		}
		return;
	}
	if (expected_mode == XDEV_EXT_R128_RING_FDS)
		EXPECT_EQ(r.fd_only_error, -EINVAL);

	anchor = open("/dev/null", O_WRONLY | O_CLOEXEC);
	EXPECT_TRUE(anchor >= 0 && !fstat(anchor, &st));
	EXPECT_EQ(xdev_ext_ring128_install(&r, ops, 3, 1, anchor, st.st_rdev,
				      st.st_ino + 1), -ESTALE);
	EXPECT_EQ(xdev_ext_ring128_install(&r, ops, 2, 1, anchor, st.st_rdev,
				      st.st_ino), 0);
	EXPECT_EQ(r.installed[2], 1);

	memset(data, 0x5a, sizeof(data));
	memset(sqe, 0, sizeof(sqe));
	head->opcode = IORING_OP_WRITE;
	head->flags = IOSQE_FIXED_FILE;
	head->fd = 2;
	head->addr = (uintptr_t)data;
	head->len = sizeof(data);
	head->user_data = 0x100000001ULL;
	if (sqes_seen)
		seen = sqes_seen();
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, ops, sqe, &res, &cflags,
					      &published), 0);
	EXPECT_TRUE(published);
	EXPECT_EQ(res, (int)sizeof(data));
	EXPECT_EQ(cflags, 0);
	/* Published once, also when the model interrupts the wait. */
	if (sqes_seen)
		EXPECT_EQ(sqes_seen() - seen, 1);

	/* The slot holds its own file: the anchor number may go. */
	close(anchor);
	head->user_data = 0x100000002ULL;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, ops, sqe, &res, &cflags,
					      &published), 0);
	EXPECT_EQ(res, (int)sizeof(data));

	memset(sqe, 0, sizeof(sqe));
	head->opcode = IORING_OP_NOP;
	head->user_data = 0x100000003ULL;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, ops, sqe, &res, &cflags,
					      &published), 0);
	EXPECT_EQ(res, 0);
	EXPECT_TRUE(!r.broken && !r.inflight);

	xdev_ext_ring128_destroy(&r, ops);
	EXPECT_EQ(r.mode, XDEV_EXT_R128_NONE);
	EXPECT_EQ(count_fds(), before);
	if (live)
		EXPECT_EQ(live(), 0);
	/* Three requests, three SQEs: an interrupted wait never republished. */
	if (sqes_seen)
		EXPECT_EQ(sqes_seen() - seen, 3);
	(void)eintr;
}

static int run_scenario(const char *name)
{
	const struct scenario *s = NULL;
	bool present = dlsym(RTLD_DEFAULT, "xdev_ext_model_ring128_present") != NULL;
	unsigned int i;
	int mode;

	for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++)
		if (!strcmp(scenarios[i].name, name))
			s = &scenarios[i];
	if (!s) {
		fprintf(stderr, "unknown scenario %s\n", name);
		return 2;
	}
	EXPECT_EQ(present, s->model);
	if (s->model && !present)
		goto out;
	if (!strcmp(name, "reject")) {
		check_header(XDEV_EXT_R128_UNAVAILABLE, false);
	} else if (!strcmp(name, "ring-fds")) {
		check_raw_ring_fds(true);
		check_header(XDEV_EXT_R128_RING_FDS, false);
	} else if (s->model) {
		check_raw_fd_only();
		check_raw_ring_fds(false);
		check_thread_exit_releases_rings();
		check_header(XDEV_EXT_R128_FD_ONLY, s->eintr);
	} else {
		/* host: find out what this kernel offers, then hold it to it. */
		struct xdev_ext_ring128 probe;

		memset(&probe, 0, sizeof(probe));
		(void)xdev_ext_ring128_ensure(&probe, xdev_ext_ring128_sys_ops());
		mode = probe.mode;
		xdev_ext_ring128_destroy(&probe, xdev_ext_ring128_sys_ops());
		printf("xdev_ext_preload_ring128_model_check[host]: kernel offers %s\n",
		       mode == XDEV_EXT_R128_FD_ONLY ? "registered-fd-only" :
		       mode == XDEV_EXT_R128_RING_FDS ? "ring-fds" : "nothing");
		if (mode == XDEV_EXT_R128_FD_ONLY) {
			check_raw_fd_only();
			check_raw_ring_fds(false);
		} else if (mode == XDEV_EXT_R128_RING_FDS) {
			check_raw_ring_fds(true);
		}
		check_header(mode, false);
	}
out:
	printf("xdev_ext_preload_ring128_model_check[%s]: %u checks, %u failures\n",
	       name, checks, failures);
	return failures ? 1 : 0;
}

static char **child_environment(const struct scenario *s, const char *model)
{
	extern char **environ;
	const char *prefix = getenv("XDEV_EXT_PRELOAD_TEST_LD_PREFIX");
	static char preload[PATH_MAX * 2 + 32];
	static char ring128[64];
	char **env;
	size_t n = 0, i;

	while (environ[n])
		n++;
	env = calloc(n + 4, sizeof(*env));
	if (!env)
		return NULL;
	n = 0;
	for (i = 0; environ[i]; i++)
		if (strncmp(environ[i], "LD_PRELOAD=", 11) &&
		    strncmp(environ[i], "XDEV_EXT_MODEL_", 10))
			env[n++] = environ[i];
	if (s->model) {
		snprintf(preload, sizeof(preload), "LD_PRELOAD=%s%s%s",
			 prefix && *prefix ? prefix : "",
			 prefix && *prefix ? ":" : "", model);
		env[n++] = preload;
	} else if (prefix && *prefix) {
		snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", prefix);
		env[n++] = preload;
	}
	if (s->ring128) {
		snprintf(ring128, sizeof(ring128), "XDEV_EXT_MODEL_RING128=%s",
			 s->ring128);
		env[n++] = ring128;
	}
	if (s->eintr)
		env[n++] = "XDEV_EXT_MODEL_EINTR=1";
	return env;
}

int main(int argc, char **argv)
{
	char self[PATH_MAX], model[PATH_MAX + 64];
	unsigned int i, failed = 0;
	ssize_t length;

	page_size = sysconf(_SC_PAGESIZE);
	if (argc == 3 && !strcmp(argv[1], "--scenario"))
		return run_scenario(argv[2]);

	length = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (length <= 0) {
		perror("readlink /proc/self/exe");
		return 1;
	}
	self[length] = '\0';
	snprintf(model, sizeof(model), "%.*s/libxdev_ext_preload_kernel_model.so",
		 (int)(strrchr(self, '/') - self), self);
	for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
		const struct scenario *s = &scenarios[i];
		char *child_argv[] = { self, "--scenario", (char *)s->name, NULL };
		char **env = child_environment(s, model);
		int status = 0;
		pid_t child;

		fflush(NULL);
		child = fork();
		if (!child) {
			execve(self, child_argv, env);
			_exit(127);
		}
		free(env);
		if (child < 0 || waitpid(child, &status, 0) != child ||
		    !WIFEXITED(status) || WEXITSTATUS(status)) {
			fprintf(stderr, "scenario %s failed (status 0x%x)\n",
				s->name, status);
			failed++;
		}
	}
	if (failed) {
		fprintf(stderr, "FAIL: %u/%zu ring128 model scenarios failed\n",
			failed, sizeof(scenarios) / sizeof(scenarios[0]));
		return 1;
	}
	printf("PASS: ring128 model checks in %zu scenarios\n",
	       sizeof(scenarios) / sizeof(scenarios[0]));
	return 0;
}
