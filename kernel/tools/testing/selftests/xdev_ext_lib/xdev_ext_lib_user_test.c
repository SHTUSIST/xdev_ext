// SPDX-License-Identifier: GPL-2.0
/*
 * Host tests of the libxdev_ext USER stage helpers (SPEC.md section 8):
 * the register request, mapping at the offsets the kernel returned, taking
 * ready entries, the sleep/wakeup and kick protocols, posting completions,
 * the stopped state and resource release.  The test plays the kernel: the
 * register call is replaced through the library's test hook and answers
 * with a memfd whose pages stand in for the shared region; the kick ioctl
 * is recorded.  No test here claims that a device run succeeds; that is
 * proven only by the guest test against the real kernel.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include "include/uapi/linux/io_uring.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext.h"
#include "tools/xdev_ext_mech/lib/libxdev_ext_internal.h"

static unsigned int checks, failures, tests, test_failures_before;

#define EXPECT_EQ(actual, expected) do { \
	long long a_ = (long long)(actual); \
	long long e_ = (long long)(expected); \
	checks++; \
	if (a_ != e_) { \
		fprintf(stderr, "# %s:%d: %s: got %lld, expected %lld\n", \
			__FILE__, __LINE__, #actual, a_, e_); \
		failures++; \
	} \
} while (0)
#define EXPECT_TRUE(v) EXPECT_EQ(!!(v), 1)

/* The fake kernel: unusual but valid offsets, so the library must use them. */
#define ENTRIES 4U
#define OFF_READY 512U
#define OFF_DONE 1024U
#define OFF_SLOTS 2048U
#define MAP_SIZE (OFF_SLOTS + ENTRIES * sizeof(struct xdev_ext_user_slot) + 4096U)

static struct xdev_ext_mech_user_stage seen;
static unsigned int registers, kicks;
static int kernel_ret, kernel_fd = -1, kick_fd = -1;
static void *kmap;	/* the kernel's view of the region */
static int kick_ret;

static int fake_register(int fd, unsigned int opcode, void *arg, unsigned int nr)
{
	struct io_uring_xdev_ext_mech *req = arg;
	struct xdev_ext_mech_user_stage *r;

	(void)fd;
	if (nr != 1 || opcode != IORING_REGISTER_XDEV_EXT_MECH || req->op != XDEV_EXT_MECH_OP_USER_STAGE)
		return -EINVAL;
	registers++;
	r = (void *)(uintptr_t)req->arg;
	seen = *r;
	if (kernel_ret)
		return kernel_ret;
	kernel_fd = memfd_create("user-stage-region", MFD_CLOEXEC);
	if (kernel_fd < 0 || ftruncate(kernel_fd, MAP_SIZE))
		return -ENOMEM;
	kmap = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, kernel_fd, 0);
	if (kmap == MAP_FAILED)
		return -ENOMEM;
	r->fd = kernel_fd;
	r->off = (struct xdev_ext_user_ring_offsets){ .mmap_size = MAP_SIZE, .hdr = 0,
		.ready = OFF_READY, .done = OFF_DONE, .slots = OFF_SLOTS };
	return 0;
}

static int fake_ioctl(int fd, unsigned long request, unsigned long arg)
{
	(void)arg;
	if (request == XDEV_EXT_USER_IOC_KICK) {
		kicks++;
		kick_fd = fd;
		return kick_ret;
	}
	return -ENOTTY;
}

static const struct xdev_ext_sys fake_sys = {
	.io_uring_register = fake_register,
	.ioctl = fake_ioctl,
};

static struct xdev_ext_user_ring_hdr *hdr(void) { return kmap; }
static struct xdev_ext_user_ready *ready(void) { return (void *)((char *)kmap + OFF_READY); }
static struct xdev_ext_user_done *done(void) { return (void *)((char *)kmap + OFF_DONE); }
static struct xdev_ext_user_slot *slots(void) { return (void *)((char *)kmap + OFF_SLOTS); }

static void reset(void)
{
	memset(&seen, 0, sizeof(seen));
	registers = kicks = 0;
	kernel_ret = kick_ret = 0;
	kernel_fd = kick_fd = -1;
	if (kmap && kmap != MAP_FAILED)
		munmap(kmap, MAP_SIZE);
	kmap = NULL;
}

static int open_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int n = 0;

	if (!d)
		return -1;
	while ((e = readdir(d)))
		n += e->d_name[0] != '.';
	closedir(d);
	return n - 1;
}

static unsigned char umem[8 * 4096];

static struct xdev_ext_user_stage *opened(void)
{
	struct xdev_ext_user_stage_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_user_stage_opts,
		.ring_fd = 3, .umem = umem, .entries = ENTRIES);
	struct xdev_ext_user_stage *u = NULL;

	EXPECT_EQ(xdev_ext_user_stage_open(&o, &u), 0);
	return u;
}

/* The kernel hands out batch @slot with @nr frames from chunk @chunk on. */
static void produce_at(__u32 slot, __u32 nr, __u64 ticket, __u32 chunk)
{
	struct xdev_ext_user_ready *r = &ready()[hdr()->ready_prod & (ENTRIES - 1)];
	struct xdev_ext_user_slot *s = &slots()[slot];
	__u32 i;

	s->ticket = ticket;
	s->nr_frames = nr;
	for (i = 0; i < nr; i++)
		s->f[i] = (struct xdev_ext_user_frame){ .umem_addr = (chunk + i) * 4096ULL,
			.data_off = 64, .data_len = 1000 + i, .capacity = 4096 - 64, .out_len = 1000 + i };
	*r = (struct xdev_ext_user_ready){ .slot = slot, .nr_frames = nr, .ticket = ticket,
		.batch_id = 40 + slot, .key = 9, .arg = 0xabc };
	__atomic_store_n(&hdr()->ready_prod, hdr()->ready_prod + 1, __ATOMIC_RELEASE);
}

static void produce(__u32 slot, __u32 nr, __u64 ticket)
{
	produce_at(slot, nr, ticket, slot * 2);
}

/* The kernel cancels the batch held in @slot (deadline or stop). */
static void cancel(__u32 slot)
{
	slots()[slot].ticket = 0;
}

static void test_open_request(void)
{
	struct xdev_ext_user_stage *u;
	int before = open_fds();

	u = opened();
	EXPECT_TRUE(u);
	if (!u)
		return;
	EXPECT_EQ(registers, 1);
	EXPECT_EQ(seen.size, sizeof(struct xdev_ext_mech_user_stage));
	EXPECT_EQ(seen.flags, 0);
	EXPECT_EQ(seen.entries, ENTRIES);
	EXPECT_TRUE(seen.eventfd >= 0);
	EXPECT_EQ(seen.fd, 0);
	EXPECT_EQ(seen.off.mmap_size, 0);
	EXPECT_EQ(xdev_ext_user_stage_fd(u), kernel_fd);
	EXPECT_EQ(open_fds(), before + 2);	/* the stage fd and the library's eventfd */
	EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
	EXPECT_EQ(open_fds(), before);
}

static void test_open_validation(void)
{
	struct xdev_ext_user_stage_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_user_stage_opts,
		.ring_fd = 3, .entries = 3);
	struct xdev_ext_user_stage *u = (void *)1;
	int before = open_fds();

	EXPECT_EQ(xdev_ext_user_stage_open(&o, &u), -EINVAL);
	o.entries = 512;
	EXPECT_EQ(xdev_ext_user_stage_open(&o, &u), -EINVAL);
	o.entries = 0;
	o.flags = 1;
	EXPECT_EQ(xdev_ext_user_stage_open(&o, &u), -EOPNOTSUPP);
	o.flags = 0;
	o.ring_fd = -1;
	EXPECT_EQ(xdev_ext_user_stage_open(&o, &u), -EINVAL);
	o.ring_fd = 3;
	EXPECT_EQ(xdev_ext_user_stage_open(&o, NULL), -EINVAL);
	EXPECT_EQ(xdev_ext_user_stage_open(NULL, &u), -EINVAL);
	EXPECT_EQ(registers, 0);
	kernel_ret = -EBADF;
	EXPECT_EQ(xdev_ext_user_stage_open(&o, &u), -EBADF);
	EXPECT_EQ(seen.entries, 64);	/* 0 asks for the default ring size */
	EXPECT_EQ(open_fds(), before);
	EXPECT_EQ(xdev_ext_user_stage_close(NULL), 0);
}

static void test_take(void)
{
	struct xdev_ext_user_stage *u = opened();
	struct xdev_ext_user_batch b;

	if (!u)
		return;
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), -EAGAIN);
	EXPECT_EQ(xdev_ext_user_stage_next(u, 20, &b), -ETIMEDOUT);
	produce(1, 2, 555);
	memset(&b, 0, sizeof(b));
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), 0);
	EXPECT_EQ(b.slot, 1);
	EXPECT_EQ(b.nr_frames, 2);
	EXPECT_EQ(b.ticket, 555);
	EXPECT_EQ(b.batch_id, 41);
	EXPECT_EQ(b.key, 9);
	EXPECT_EQ(b.arg, 0xabc);
	EXPECT_TRUE((void *)b.f != (void *)slots()[1].f);	/* the library's copy */
	EXPECT_EQ(b.f[1].data_len, 1001);
	EXPECT_TRUE(b.data[0] == umem + 2 * 4096 + 64);
	EXPECT_TRUE(b.data[1] == umem + 3 * 4096 + 64);
	EXPECT_EQ(hdr()->ready_cons, 1);
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), -EAGAIN);
	EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

static void test_complete_and_kick(void)
{
	struct xdev_ext_user_stage *u = opened();
	struct xdev_ext_user_batch b;

	if (!u)
		return;
	produce(0, 1, 77);
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), 0);
	b.f[0].out_len = 1004;
	hdr()->kernel_flags = 0;
	EXPECT_EQ(xdev_ext_user_stage_complete(u, &b, 0), 0);
	EXPECT_EQ(hdr()->done_prod, 1);
	EXPECT_EQ(done()[0].slot, 0);
	EXPECT_EQ(done()[0].ticket, 77);
	EXPECT_EQ(done()[0].status, 0);
	EXPECT_EQ(slots()[0].f[0].out_len, 1004);
	EXPECT_EQ(kicks, 0);	/* the kernel was reaping: no kick */
	produce(1, 1, 78);
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), 0);
	hdr()->kernel_flags = XDEV_EXT_USER_K_NEED_KICK;
	EXPECT_EQ(xdev_ext_user_stage_complete(u, &b, -EIO), 0);
	EXPECT_EQ(done()[1].status, -EIO);
	EXPECT_EQ(kicks, 1);
	EXPECT_EQ(kick_fd, kernel_fd);
	EXPECT_EQ(xdev_ext_user_stage_complete(u, &b, 5), -EINVAL);
	EXPECT_EQ(hdr()->done_prod, 2);
	kick_ret = -ENOTCONN;
	EXPECT_EQ(xdev_ext_user_stage_complete(u, &b, 0), -ENOTCONN);
	EXPECT_EQ(hdr()->done_prod, 3);	/* posted even when the kick found no stage */
	hdr()->done_cons = 0;
	hdr()->done_prod = ENTRIES;
	EXPECT_EQ(xdev_ext_user_stage_complete(u, &b, 0), -ENOSPC);
	EXPECT_EQ(hdr()->done_prod, ENTRIES);
	EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

static void test_bad_entry(void)
{
	struct xdev_ext_user_stage *u = opened();
	struct xdev_ext_user_batch b;

	if (!u)
		return;
	produce(0, 1, 1);
	ready()[0].slot = ENTRIES;
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), -EPROTO);
	produce(0, 1, 2);
	ready()[1].nr_frames = XDEV_EXT_MECH_MAX_FRAMES + 1;
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), -EPROTO);
	EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

static void test_stopped(void)
{
	struct xdev_ext_user_stage *u = opened();
	struct xdev_ext_user_batch b;

	if (!u)
		return;
	produce(0, 1, 9);
	hdr()->kernel_flags = XDEV_EXT_USER_K_STOPPED;
	EXPECT_EQ(xdev_ext_user_stage_next(u, -1, &b), 0);	/* entries first */
	EXPECT_EQ(xdev_ext_user_stage_next(u, -1, &b), -ESHUTDOWN);
	EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

/* The kernel side of a wakeup: wait for the sleeping flag, then hand out
 * a batch and signal the eventfd the library registered. */
static void *waker(void *arg)
{
	int efd = *(int *)arg, i;

	for (i = 0; i < 2000; i++) {
		if (__atomic_load_n(&hdr()->user_flags, __ATOMIC_ACQUIRE) & XDEV_EXT_USER_F_SLEEPING)
			break;
		usleep(1000);
	}
	if (i == 2000)
		return (void *)1;
	produce(2, 1, 31);
	__sync_synchronize();
	eventfd_write(efd, 1);
	return NULL;
}

static void test_sleep_wakeup(void)
{
	struct xdev_ext_user_stage *u = opened();
	struct xdev_ext_user_batch b;
	pthread_t t;
	void *res = (void *)2;
	int efd = seen.eventfd;

	if (!u)
		return;
	EXPECT_EQ(pthread_create(&t, NULL, waker, &efd), 0);
	EXPECT_EQ(xdev_ext_user_stage_next(u, 5000, &b), 0);
	pthread_join(t, &res);
	EXPECT_TRUE(res == NULL);
	EXPECT_EQ(b.ticket, 31);
	EXPECT_EQ(hdr()->user_flags & XDEV_EXT_USER_F_SLEEPING, 0);
	EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

/*
 * A batch cancelled at its deadline before the user thread read its ready
 * entry; the kernel reused the slot for the next batch.  The stale entry
 * must not hand out the new batch's frames under the old ticket: the
 * application would transform the new payload twice (once under each
 * ticket), and the second, accepted pass would reach the next stage.
 */
static void test_stale_entry_after_reuse(void)
{
	struct xdev_ext_user_stage *u = opened();
	struct xdev_ext_user_batch b;
	unsigned int handed_b = 0, handed_a = 0;
	int ret;

	if (!u)
		return;
	produce_at(0, 1, 100, 0);	/* batch A: chunk 0 */
	cancel(0);			/* A passes its deadline, unread */
	produce_at(0, 1, 101, 5);	/* batch B reuses slot 0: chunk 5 */
	while ((ret = xdev_ext_user_stage_next(u, 0, &b)) == 0) {
		if (b.data[0] == umem + 5 * 4096 + 64)
			handed_b++;
		if (b.ticket == 100)
			handed_a++;
	}
	EXPECT_EQ(ret, -EAGAIN);
	EXPECT_EQ(handed_b, 1);		/* B's payload is handed out exactly once */
	EXPECT_EQ(handed_a, 0);		/* the cancelled A is never handed out */
	EXPECT_EQ(hdr()->ready_cons, 2);	/* the stale entry was consumed */
	EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

/*
 * The batch object is the library's copy: a later rewrite of the slot by
 * the kernel (B cancelled, slot reused for C) changes neither B's frame
 * table nor, through a late completion of B, C's output lengths.
 */
static void test_batch_is_a_copy(void)
{
	struct xdev_ext_user_stage *u = opened();
	struct xdev_ext_user_batch b;

	if (!u)
		return;
	produce_at(0, 1, 200, 3);
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), 0);
	EXPECT_EQ(b.ticket, 200);
	cancel(0);
	produce_at(0, 1, 201, 6);	/* C in the same slot */
	EXPECT_EQ(b.f[0].umem_addr, 3 * 4096);
	EXPECT_EQ(b.f[0].out_len, 1000);	/* preset to the input length */
	b.f[0].out_len = 1234;
	hdr()->kernel_flags = 0;
	EXPECT_EQ(xdev_ext_user_stage_complete(u, &b, 0), 0);	/* posted; the kernel refuses it */
	EXPECT_EQ(hdr()->done_prod, 1);
	EXPECT_EQ(done()[0].ticket, 200);
	EXPECT_EQ(slots()[0].f[0].out_len, 1000);	/* C's preset is untouched */
	EXPECT_EQ(xdev_ext_user_stage_next(u, 0, &b), 0);
	EXPECT_EQ(b.ticket, 201);
	EXPECT_EQ(b.f[0].umem_addr, 6 * 4096);
	b.f[0].out_len = 999;
	EXPECT_EQ(xdev_ext_user_stage_complete(u, &b, 0), 0);
	EXPECT_EQ(slots()[0].f[0].out_len, 999);	/* the held batch's lengths reach its slot */
	EXPECT_EQ(xdev_ext_user_stage_close(u), 0);
}

#define RUN(fn) do { \
	reset(); \
	xdev_ext__set_sys(&fake_sys); \
	test_failures_before = failures; \
	fn(); \
	xdev_ext__set_sys(NULL); \
	printf("%s %u - %s\n", failures == test_failures_before ? "ok" : "not ok", \
	       ++tests, #fn); \
} while (0)

int main(void)
{
	printf("TAP version 13\n1..9\n");
	RUN(test_open_request);
	RUN(test_open_validation);
	RUN(test_take);
	RUN(test_complete_and_kick);
	RUN(test_bad_entry);
	RUN(test_stopped);
	RUN(test_sleep_wakeup);
	RUN(test_stale_entry_after_reuse);
	RUN(test_batch_is_a_copy);
	reset();
	printf("# checks=%u failures=%u\n", checks, failures);
	return failures ? 1 : 0;
}
