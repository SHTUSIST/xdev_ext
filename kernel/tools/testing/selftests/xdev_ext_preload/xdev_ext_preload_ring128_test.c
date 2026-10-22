// SPDX-License-Identifier: GPL-2.0
/*
 * Host test of tools/xdev_ext_preload_ring128.h against a fake kernel injected
 * through struct xdev_ext_ring128_ops.  The fake keeps its own copy of the Linux
 * 6.16 ring layout (struct io_rings in include/linux/io_uring_types.h and
 * rings_size() in io_uring/io_uring.c) so the header's layout is checked
 * against an independent statement of it, not against itself.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

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

/* Linux 6.16 struct io_rings, x86-64 (64-byte cache lines). */
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
/* rings_size(SQE128|CQE32, 4, 8): ALIGN((64 + 8 * 16) << 1, 64) = 384. */
#define K_SQ_ARRAY		384U
#define K_RINGS_BYTES		400U

enum fake_call {
	C_SETUP = 1,
	C_ENTER,
	C_REG,
	C_MAP,
	C_UNMAP,
	C_ADVISE,
	C_CLOSE,
	C_FSTAT,
	C_BACKOFF,
};

struct fake_event {
	enum fake_call call;
	unsigned long a, b, c, d;
	int ret;
};

struct fake_map {
	void *addr;
	size_t len;
	int fd;
	off_t off;
	bool anonymous;
	bool live;
};

struct fake_step {
	bool consume;		/* take the published SQE if to_submit > 0 */
	bool post;		/* post one CQE */
	bool foreign;		/* that CQE carries another token */
	int32_t res;
	int ret;		/* io_uring_enter() return value */
};

struct fake {
	/* configuration */
	int fd_only_errno;
	int plain_errno;
	int fd_only_index;
	int plain_fd;
	int ring_fds_index;
	unsigned int fail_event;	/* 1-based event that fails with EIO */
	bool bad_layout;
	bool bad_mask;
	pid_t pid;
	struct stat anchor;
	struct stat anchor_later;	/* fstat after the first one, if set */
	bool anchor_changes;
	struct fake_step steps[8];
	unsigned int nsteps;

	/* observation */
	struct fake_event log[128];
	unsigned int nlog;
	struct fake_map maps[16];
	unsigned int nmaps;
	bool fd_open[256];
	bool index_registered[16];
	int32_t files[16];
	bool files_registered;
	unsigned int fstats;
	unsigned int step;
	unsigned int consumed;
	unsigned char last_sqe[128];
	uint64_t last_token;
	int cancel_state_in_enter;
	unsigned int backoff_attempt[8];
	unsigned int backoffs;

	/* the fake kernel's view of the current ring */
	unsigned char *rings;
	unsigned char *sqes;
	unsigned char *plain_rings;
	unsigned char *plain_sqes;
	unsigned int sq_head;
	unsigned int cq_tail;
};

static uint32_t k_scratch[128];

/* A ring that was never set up reads as zeroes instead of crashing. */
static uint32_t *k_word(unsigned char *rings, unsigned int offset)
{
	if (!rings) {
		memset(k_scratch, 0, sizeof(k_scratch));
		return &k_scratch[offset / 4 < 64 ? offset / 4 : 0];
	}
	return (uint32_t *)(rings + offset);
}

static int fake_event(struct fake *f, enum fake_call call, unsigned long a,
		      unsigned long b, unsigned long c, unsigned long d)
{
	struct fake_event *e = &f->log[f->nlog < 128 ? f->nlog : 127];

	if (f->nlog < 128)
		f->nlog++;
	*e = (struct fake_event){ call, a, b, c, d, 0 };
	if (f->fail_event && f->nlog == f->fail_event && call != C_CLOSE &&
	    call != C_UNMAP && call != C_BACKOFF) {
		e->ret = -EIO;
		return -EIO;
	}
	return 0;
}

static void fake_fill_params(struct fake *f, struct io_uring_params *p)
{
	p->sq_entries = 4;
	p->cq_entries = 8;
	p->features = IORING_FEAT_SINGLE_MMAP | IORING_FEAT_NODROP |
		      IORING_FEAT_REG_REG_RING;
	p->sq_off.head = K_SQ_HEAD;
	p->sq_off.tail = K_SQ_TAIL;
	p->sq_off.ring_mask = K_SQ_RING_MASK;
	p->sq_off.ring_entries = K_SQ_RING_ENTRIES;
	p->sq_off.flags = K_SQ_FLAGS;
	p->sq_off.dropped = K_SQ_DROPPED;
	p->sq_off.array = f->bad_layout ? 8000 : K_SQ_ARRAY;
	p->cq_off.head = K_CQ_HEAD;
	p->cq_off.tail = K_CQ_TAIL;
	p->cq_off.ring_mask = K_CQ_RING_MASK;
	p->cq_off.ring_entries = K_CQ_RING_ENTRIES;
	p->cq_off.overflow = K_CQ_OVERFLOW;
	p->cq_off.cqes = K_CQES;
	p->cq_off.flags = K_CQ_FLAGS;
}

static void fake_init_rings(struct fake *f, unsigned char *rings,
			    unsigned char *sqes)
{
	unsigned int i;

	/* Every new ring starts with no fixed-file table. */
	f->files_registered = false;
	for (i = 0; i < 16; i++)
		f->files[i] = -2;
	f->rings = rings;
	f->sqes = sqes;
	f->sq_head = 0;
	f->cq_tail = 0;
	*k_word(rings, K_SQ_RING_MASK) = f->bad_mask ? 1 : 3;
	*k_word(rings, K_CQ_RING_MASK) = 7;
	*k_word(rings, K_SQ_RING_ENTRIES) = 4;
	*k_word(rings, K_CQ_RING_ENTRIES) = 8;
}

static int fake_setup(void *opaque, unsigned int entries,
		      struct io_uring_params *p)
{
	struct fake *f = opaque;

	if (fake_event(f, C_SETUP, entries, p->flags, p->sq_off.user_addr,
		       p->cq_off.user_addr))
		return -EIO;
	if (p->flags & IORING_SETUP_REGISTERED_FD_ONLY) {
		if (f->fd_only_errno)
			return -f->fd_only_errno;
		fake_fill_params(f, p);
		fake_init_rings(f, (unsigned char *)(uintptr_t)p->cq_off.user_addr,
				(unsigned char *)(uintptr_t)p->sq_off.user_addr);
		f->index_registered[f->fd_only_index] = true;
		return f->fd_only_index;
	}
	if (f->plain_errno)
		return -f->plain_errno;
	fake_fill_params(f, p);
	if (!f->plain_rings) {
		f->plain_rings = aligned_alloc(4096, 4096);
		f->plain_sqes = aligned_alloc(4096, 4096);
	}
	memset(f->plain_rings, 0, 4096);
	memset(f->plain_sqes, 0, 4096);
	fake_init_rings(f, f->plain_rings, f->plain_sqes);
	f->fd_open[f->plain_fd] = true;
	return f->plain_fd;
}

static int fake_map(void *opaque, void **addr, size_t length, int prot,
		    int flags, int fd, off_t offset)
{
	struct fake *f = opaque;
	struct fake_map *m;
	void *view;

	(void)prot;
	if (fake_event(f, C_MAP, length, (unsigned long)flags,
		       (unsigned long)fd, (unsigned long)offset))
		return -EIO;
	if (fd < 0) {
		view = mmap(NULL, length, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (view == MAP_FAILED)
			return -errno;
	} else if (fd == f->plain_fd && offset == (off_t)IORING_OFF_SQ_RING) {
		view = f->plain_rings;
	} else if (fd == f->plain_fd && offset == (off_t)IORING_OFF_SQES) {
		view = f->plain_sqes;
	} else {
		return -EINVAL;
	}
	m = &f->maps[f->nmaps++];
	*m = (struct fake_map){ view, length, fd, offset, fd < 0, true };
	*addr = view;
	return 0;
}

static int fake_unmap(void *opaque, void *addr, size_t length)
{
	struct fake *f = opaque;
	unsigned int i;

	fake_event(f, C_UNMAP, (unsigned long)(uintptr_t)addr, length, 0, 0);
	for (i = 0; i < f->nmaps; i++) {
		struct fake_map *m = &f->maps[i];

		if (m->live && m->addr == addr && m->len == length) {
			m->live = false;
			if (m->anonymous)
				munmap(addr, length);
			return 0;
		}
	}
	return -EINVAL;
}

static int fake_advise(void *opaque, void *addr, size_t length, int advice)
{
	struct fake *f = opaque;

	return fake_event(f, C_ADVISE, (unsigned long)(uintptr_t)addr, length,
			  (unsigned long)advice, 0);
}

static int fake_close(void *opaque, int fd)
{
	struct fake *f = opaque;

	fake_event(f, C_CLOSE, (unsigned long)fd, 0, 0, 0);
	if (fd < 0 || fd >= 256 || !f->fd_open[fd])
		return -EBADF;
	f->fd_open[fd] = false;
	return 0;
}

static int fake_fstat(void *opaque, int fd, struct stat *st)
{
	struct fake *f = opaque;

	if (fake_event(f, C_FSTAT, (unsigned long)fd, 0, 0, 0))
		return -EIO;
	*st = (f->fstats++ && f->anchor_changes) ? f->anchor_later : f->anchor;
	return 0;
}

static pid_t fake_getpid(void *opaque)
{
	return ((struct fake *)opaque)->pid;
}

static void fake_backoff(void *opaque, unsigned int attempt)
{
	struct fake *f = opaque;

	fake_event(f, C_BACKOFF, attempt, 0, 0, 0);
	if (f->backoffs < 8)
		f->backoff_attempt[f->backoffs] = attempt;
	f->backoffs++;
}

static int fake_reg(void *opaque, unsigned int fd, unsigned int opcode,
		    void *arg, unsigned int nr_args)
{
	struct fake *f = opaque;
	bool use_registered = opcode & IORING_REGISTER_USE_REGISTERED_RING;
	unsigned int op = opcode & ~(unsigned int)IORING_REGISTER_USE_REGISTERED_RING;
	struct io_uring_rsrc_update *update = arg;
	unsigned int i;

	if (fake_event(f, C_REG, fd, opcode, nr_args,
		       op == IORING_REGISTER_RING_FDS ||
		       op == IORING_UNREGISTER_RING_FDS ||
		       op == IORING_REGISTER_FILES_UPDATE ?
		       (unsigned long)update->data : 0))
		return -EIO;
	if (use_registered && (fd >= 16 || !f->index_registered[fd]))
		return -EBADF;
	switch (op) {
	case IORING_REGISTER_FILES:
		if (f->files_registered)
			return -EBUSY;
		if (nr_args != 16)
			return -EINVAL;
		memcpy(f->files, arg, sizeof(f->files));
		f->files_registered = true;
		return 0;
	case IORING_REGISTER_FILES_UPDATE:
		if (!f->files_registered || nr_args != 1 || update->offset >= 16)
			return -EINVAL;
		f->files[update->offset] =
			*(int32_t *)(uintptr_t)update->data;
		return 1;
	case IORING_REGISTER_RING_FDS:
		if (use_registered || (int)fd != f->plain_fd || nr_args != 1 ||
		    update->offset != ~0U || update->data != (uint64_t)fd)
			return -EINVAL;
		update->offset = (uint32_t)f->ring_fds_index;
		f->index_registered[f->ring_fds_index] = true;
		return 1;
	case IORING_UNREGISTER_RING_FDS:
		if (nr_args != 1 || update->data || update->offset >= 16)
			return -EINVAL;
		f->index_registered[update->offset] = false;
		for (i = 0; i < 16; i++)
			f->files[i] = -1;
		f->files_registered = false;
		return 1;
	}
	return -EINVAL;
}

static void fake_post(struct fake *f, uint64_t user_data, int32_t res)
{
	unsigned char *cqe = f->rings + K_CQES + (f->cq_tail & 7) * 32;
	uint64_t zero[2] = { 0, 0 };
	uint32_t flags = 0;

	if (!f->rings)
		return;
	memcpy(cqe, &user_data, 8);
	memcpy(cqe + 8, &res, 4);
	memcpy(cqe + 12, &flags, 4);
	memcpy(cqe + 16, zero, 16);
	f->cq_tail++;
	__atomic_store_n(k_word(f->rings, K_CQ_TAIL), f->cq_tail,
			 __ATOMIC_RELEASE);
}

static int fake_enter(void *opaque, unsigned int index,
		      unsigned int to_submit, unsigned int min_complete,
		      unsigned int flags)
{
	struct fake *f = opaque;
	struct fake_step step = { .consume = true, .post = true, .ret = 1 };
	int state;

	if (fake_event(f, C_ENTER, index, to_submit, min_complete, flags))
		return -EIO;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	pthread_setcancelstate(state, NULL);
	f->cancel_state_in_enter = state;
	if (f->step < f->nsteps)
		step = f->steps[f->step++];
	if (to_submit && step.consume &&
	    f->sq_head != __atomic_load_n(k_word(f->rings, K_SQ_TAIL),
					  __ATOMIC_ACQUIRE)) {
		uint32_t slot = k_word(f->rings, K_SQ_ARRAY)[f->sq_head & 3];

		memcpy(f->last_sqe, f->sqes + (slot & 3) * 128, 128);
		memcpy(&f->last_token, f->last_sqe + 32, 8);
		f->sq_head++;
		f->consumed++;
		__atomic_store_n(k_word(f->rings, K_SQ_HEAD), f->sq_head,
				 __ATOMIC_RELEASE);
	}
	if (step.post)
		fake_post(f, step.foreign ? f->last_token ^ 0x5a : f->last_token,
			  step.res);
	return step.ret;
}

static struct fake fake;
static struct xdev_ext_ring128_ops ops;

static void fake_reset(void)
{
	unsigned int i;

	for (i = 0; i < fake.nmaps; i++)
		if (fake.maps[i].live && fake.maps[i].anonymous)
			munmap(fake.maps[i].addr, fake.maps[i].len);
	free(fake.plain_rings);
	free(fake.plain_sqes);
	memset(&fake, 0, sizeof(fake));
	fake.fd_only_index = 5;
	fake.plain_fd = 42;
	fake.ring_fds_index = 7;
	fake.pid = 1000;
	fake.anchor.st_mode = S_IFCHR | 0600;
	fake.anchor.st_rdev = makedev(242, 1);
	fake.anchor.st_ino = 77;
	for (i = 0; i < 16; i++)
		fake.files[i] = -2;
	ops = (struct xdev_ext_ring128_ops){
		.opaque = &fake,
		.setup = fake_setup,
		.enter = fake_enter,
		.reg = fake_reg,
		.map = fake_map,
		.unmap = fake_unmap,
		.advise = fake_advise,
		.close = fake_close,
		.fstat = fake_fstat,
		.getpid = fake_getpid,
		.backoff = fake_backoff,
	};
}

static unsigned int count_calls(enum fake_call call, unsigned int from)
{
	unsigned int i, n = 0;

	for (i = from; i < fake.nlog; i++)
		n += fake.log[i].call == call;
	return n;
}

static const struct fake_event *nth_call(enum fake_call call, unsigned int nth)
{
	unsigned int i;

	for (i = 0; i < fake.nlog; i++)
		if (fake.log[i].call == call && !nth--)
			return &fake.log[i];
	return NULL;
}

static unsigned int live_maps(void)
{
	unsigned int i, n = 0;

	for (i = 0; i < fake.nmaps; i++)
		n += fake.maps[i].live;
	return n;
}

static unsigned int open_fds(void)
{
	unsigned int i, n = 0;

	for (i = 0; i < 256; i++)
		n += fake.fd_open[i];
	return n;
}

static unsigned int registered_indices(void)
{
	unsigned int i, n = 0;

	for (i = 0; i < 16; i++)
		n += fake.index_registered[i];
	return n;
}

static bool advised_dontfork(void *addr, size_t len)
{
	unsigned int i;

	for (i = 0; i < fake.nlog; i++)
		if (fake.log[i].call == C_ADVISE &&
		    fake.log[i].a == (unsigned long)(uintptr_t)addr &&
		    fake.log[i].b == len && fake.log[i].c == MADV_DONTFORK &&
		    !fake.log[i].ret)
			return true;
	return false;
}

static void test_layout_matches_the_kernel(void)
{
	size_t sq_array = 0;

	/* io_uring/io_uring.c rings_size(): CQE32 doubles the whole header. */
	EXPECT_EQ(xdev_ext_ring128_rings_size(4, 8, true, &sq_array), K_RINGS_BYTES);
	EXPECT_EQ(sq_array, K_SQ_ARRAY);
	EXPECT_EQ(xdev_ext_ring128_rings_size(4, 8, false, &sq_array), 208);
	EXPECT_EQ(sq_array, 192);
	EXPECT_EQ(XDEV_EXT_RING128_ENTRIES, 4);
	EXPECT_EQ(XDEV_EXT_RING128_SLOTS, 16);
	EXPECT_EQ(XDEV_EXT_RING128_SQE_SIZE, 2 * sizeof(struct io_uring_sqe));
}

static void test_fd_only_setup_uses_no_descriptor_number(void)
{
	struct xdev_ext_ring128 r;
	const struct fake_event *setup, *files;
	int32_t empty[16];
	unsigned int i;

	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	EXPECT_EQ(r.mode, XDEV_EXT_R128_FD_ONLY);
	EXPECT_TRUE(xdev_ext_ring128_usable(&r));
	EXPECT_EQ(r.ring_index, 5);
	EXPECT_EQ(r.owner_pid, 1000);
	EXPECT_TRUE(r.rings_mem && r.sqes_mem);

	/* Nothing that hands out a descriptor number ran. */
	EXPECT_EQ(count_calls(C_SETUP, 0), 1);
	setup = nth_call(C_SETUP, 0);
	EXPECT_TRUE(setup != NULL);
	if (setup) {
		EXPECT_EQ(setup->a, 4);
		EXPECT_EQ(setup->b, IORING_SETUP_SQE128 | IORING_SETUP_CQE32 |
				     IORING_SETUP_NO_MMAP |
				     IORING_SETUP_REGISTERED_FD_ONLY);
		EXPECT_EQ(setup->c, (uintptr_t)r.sqes_mem);
		EXPECT_EQ(setup->d, (uintptr_t)r.rings_mem);
	}
	EXPECT_EQ(count_calls(C_CLOSE, 0), 0);
	for (i = 0; i < fake.nmaps; i++)
		EXPECT_TRUE(fake.maps[i].anonymous);
	EXPECT_EQ(open_fds(), 0);

	/* Both pages are kept out of fork children. */
	EXPECT_TRUE(advised_dontfork(r.rings_mem, r.rings_len));
	EXPECT_TRUE(advised_dontfork(r.sqes_mem, r.sqes_len));
	EXPECT_EQ(r.rings_len % 4096, 0);
	EXPECT_TRUE(r.rings_len >= K_RINGS_BYTES);
	EXPECT_TRUE(r.sqes_len >= 4 * 128);
	EXPECT_EQ(live_maps(), 2);

	/* Sixteen empty fixed-file slots, through the registered ring. */
	files = nth_call(C_REG, 0);
	EXPECT_TRUE(files != NULL);
	if (files) {
		EXPECT_EQ(files->a, 5);
		EXPECT_EQ(files->b, IORING_REGISTER_FILES |
				     IORING_REGISTER_USE_REGISTERED_RING);
		EXPECT_EQ(files->c, 16);
	}
	for (i = 0; i < 16; i++)
		empty[i] = -1;
	EXPECT_TRUE(!memcmp(fake.files, empty, sizeof(empty)));
	for (i = 0; i < XDEV_EXT_RING128_SLOTS; i++)
		EXPECT_EQ(r.installed[i], 0);

	/* A second call costs nothing. */
	i = fake.nlog;
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	EXPECT_EQ(fake.nlog, i);
	xdev_ext_ring128_destroy(&r, &ops);
}

static void test_ring_fds_fallback_closes_the_number(void)
{
	struct xdev_ext_ring128 r;
	const struct fake_event *e;
	unsigned int i, ring_fds_at = 0, close_at = 0;

	fake_reset();
	fake.fd_only_errno = EINVAL;
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	EXPECT_EQ(r.mode, XDEV_EXT_R128_RING_FDS);
	EXPECT_EQ(r.ring_index, 7);
	EXPECT_EQ(r.fd_only_error, -EINVAL);
	EXPECT_EQ(count_calls(C_SETUP, 0), 2);
	e = nth_call(C_SETUP, 1);
	EXPECT_TRUE(e && e->b == (IORING_SETUP_SQE128 | IORING_SETUP_CQE32));

	/* The pages of the failed first attempt are gone. */
	EXPECT_EQ(live_maps(), 2);
	for (i = 0; i < fake.nmaps; i++)
		if (fake.maps[i].live)
			EXPECT_EQ(fake.maps[i].fd, 42);
	EXPECT_TRUE(r.rings_mem == fake.plain_rings);
	EXPECT_TRUE(r.sqes_mem == fake.plain_sqes);
	EXPECT_TRUE(advised_dontfork(r.rings_mem, r.rings_len));
	EXPECT_TRUE(advised_dontfork(r.sqes_mem, r.sqes_len));

	/* Registered first, then the number is closed. */
	for (i = 0; i < fake.nlog; i++) {
		e = &fake.log[i];
		if (e->call == C_REG && e->b == IORING_REGISTER_RING_FDS) {
			ring_fds_at = i + 1;
			EXPECT_EQ(e->a, 42);
			EXPECT_EQ(e->d, 42);
		}
		if (e->call == C_CLOSE) {
			close_at = i + 1;
			EXPECT_EQ(e->a, 42);
		}
	}
	EXPECT_TRUE(ring_fds_at && close_at > ring_fds_at);
	EXPECT_EQ(count_calls(C_CLOSE, 0), 1);
	EXPECT_EQ(open_fds(), 0);
	e = nth_call(C_REG, 1);
	EXPECT_TRUE(e && e->a == 7 &&
		    e->b == (IORING_REGISTER_FILES |
			     IORING_REGISTER_USE_REGISTERED_RING));
	xdev_ext_ring128_destroy(&r, &ops);
	EXPECT_EQ(live_maps(), 0);
	EXPECT_EQ(registered_indices(), 0);
}

static void test_both_failing_is_unavailable_without_leaks(void)
{
	struct xdev_ext_ring128 r;
	unsigned int before;

	fake_reset();
	fake.fd_only_errno = EINVAL;
	fake.plain_errno = EINVAL;
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), -ENODEV);
	EXPECT_EQ(r.mode, XDEV_EXT_R128_UNAVAILABLE);
	EXPECT_TRUE(!xdev_ext_ring128_usable(&r));
	EXPECT_EQ(r.fd_only_error, -EINVAL);
	EXPECT_EQ(r.ring_fds_error, -EINVAL);
	EXPECT_EQ(live_maps(), 0);
	EXPECT_EQ(open_fds(), 0);
	EXPECT_EQ(registered_indices(), 0);
	EXPECT_TRUE(!strcmp(xdev_ext_ring128_mode_name(&r), "unavailable"));

	/* Sticky for this thread: no further attempt. */
	before = fake.nlog;
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), -ENODEV);
	EXPECT_EQ(fake.nlog, before);
	xdev_ext_ring128_destroy(&r, &ops);
	EXPECT_EQ(r.mode, XDEV_EXT_R128_NONE);
}

/*
 * Fail every step of one mode in turn while the other mode is unavailable:
 * each failure must leave no mapping, descriptor or registered index behind.
 */
static void run_rollback(bool fd_only_path, unsigned int first,
			 const enum fake_call *kinds, unsigned int last)
{
	struct xdev_ext_ring128 r;
	unsigned int n;

	for (n = first; n <= last; n++) {
		/* close() and munmap() are never failed by the fake. */
		if (kinds[n - 1] == C_CLOSE || kinds[n - 1] == C_UNMAP)
			continue;
		fake_reset();
		if (fd_only_path)
			fake.plain_errno = EINVAL;
		else
			fake.fd_only_errno = EINVAL;
		fake.fail_event = n;
		memset(&r, 0, sizeof(r));
		EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), -ENODEV);
		EXPECT_EQ(r.mode, XDEV_EXT_R128_UNAVAILABLE);
		EXPECT_EQ(live_maps(), 0);
		EXPECT_EQ(open_fds(), 0);
		EXPECT_EQ(registered_indices(), 0);
	}
}

static void test_each_failure_rolls_back(void)
{
	enum fake_call kinds[128];
	const struct fake_event *second_setup;
	struct xdev_ext_ring128 r;
	unsigned int i, prefix;

	/* fd-only: map, map, advise, advise, setup, register files. */
	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	EXPECT_EQ(fake.nlog, 6);
	for (i = 0; i < fake.nlog; i++)
		kinds[i] = fake.log[i].call;
	xdev_ext_ring128_destroy(&r, &ops);
	run_rollback(true, 1, kinds, 6);

	/* ring-fds after a failed fd-only attempt and its two unmaps. */
	fake_reset();
	fake.fd_only_errno = EINVAL;
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	second_setup = nth_call(C_SETUP, 1);
	prefix = second_setup ? (unsigned int)(second_setup - fake.log) : 0;
	EXPECT_EQ(fake.nlog - prefix, 8);
	for (i = 0; i < fake.nlog; i++)
		kinds[i] = fake.log[i].call;
	i = fake.nlog;
	xdev_ext_ring128_destroy(&r, &ops);
	run_rollback(false, prefix + 1, kinds, i);

	/* A layout that does not fit the provided pages is refused, undone. */
	fake_reset();
	fake.bad_layout = true;
	fake.plain_errno = EINVAL;
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), -ENODEV);
	EXPECT_EQ(r.fd_only_error, -EPROTO);
	EXPECT_EQ(live_maps(), 0);
	EXPECT_EQ(open_fds(), 0);
	EXPECT_EQ(registered_indices(), 0);

	/* Ring masks that disagree with the entry counts: both modes refuse. */
	fake_reset();
	fake.bad_mask = true;
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), -ENODEV);
	EXPECT_EQ(r.fd_only_error, -EPROTO);
	EXPECT_EQ(r.ring_fds_error, -EPROTO);
	EXPECT_EQ(live_maps(), 0);
	EXPECT_EQ(open_fds(), 0);
	EXPECT_EQ(registered_indices(), 0);
}

static void test_install_checks_the_anchor_first(void)
{
	struct xdev_ext_ring128 r;
	const struct fake_event *e;
	unsigned int before;
	dev_t rdev = makedev(242, 1);

	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);

	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 16, 1, 9, rdev, 77), -EINVAL);
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 3, 0, 9, rdev, 77), -EINVAL);

	/* Wrong device, wrong inode, not a character device: no install. */
	before = fake.nlog;
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 3, 1, 9, makedev(242, 2), 77),
		  -ESTALE);
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 3, 1, 9, rdev, 78), -ESTALE);
	fake.anchor.st_mode = S_IFREG | 0600;
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 3, 1, 9, rdev, 77), -ESTALE);
	fake.anchor.st_mode = S_IFCHR | 0600;
	EXPECT_EQ(count_calls(C_FSTAT, before), 3);
	EXPECT_EQ(count_calls(C_REG, before), 0);
	EXPECT_EQ(r.installed[3], 0);
	EXPECT_EQ(fake.files[3], -1);

	/* A matching anchor goes into the slot through the registered ring. */
	before = fake.nlog;
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 3, 1, 9, rdev, 77), 0);
	EXPECT_EQ(r.installed[3], 1);
	EXPECT_EQ(fake.files[3], 9);
	EXPECT_EQ(count_calls(C_REG, before), 1);
	e = &fake.log[before];
	EXPECT_TRUE(e->call == C_FSTAT && e->a == 9);
	e = nth_call(C_REG, 1);
	EXPECT_TRUE(e && e->a == 5 &&
		    e->b == (IORING_REGISTER_FILES_UPDATE |
			     IORING_REGISTER_USE_REGISTERED_RING) &&
		    e->c == 1);

	/* Same generation: no call at all. */
	before = fake.nlog;
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 3, 1, 9, rdev, 77), 0);
	EXPECT_EQ(fake.nlog, before);

	/* A new generation for the slot reinstalls. */
	fake.files[3] = -1;
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 3, 2, 11, rdev, 77), 0);
	EXPECT_EQ(r.installed[3], 2);
	EXPECT_EQ(fake.files[3], 11);
	EXPECT_EQ(count_calls(C_REG, before), 1);

	/* The anchor changed under the install: the slot is emptied again. */
	fake.fstats = 0;
	fake.anchor_changes = true;
	fake.anchor_later = fake.anchor;
	fake.anchor_later.st_ino = 99;
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 4, 1, 12, rdev, 77), -ESTALE);
	EXPECT_EQ(r.installed[4], 0);
	EXPECT_EQ(fake.files[4], -1);
	fake.anchor_changes = false;

	/* Uninstall empties the slot. */
	EXPECT_EQ(xdev_ext_ring128_uninstall(&r, &ops, 3), 0);
	EXPECT_EQ(r.installed[3], 0);
	EXPECT_EQ(fake.files[3], -1);
	xdev_ext_ring128_destroy(&r, &ops);
}

static void test_fork_child_never_touches_the_inherited_ring(void)
{
	struct xdev_ext_ring128 r;
	void *parent_rings, *parent_sqes;
	unsigned int before, i;

	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 2, 1, 9, makedev(242, 1), 77),
		  0);
	parent_rings = r.rings_mem;
	parent_sqes = r.sqes_mem;

	/* In the child: the inherited context is dropped without any call. */
	fake.pid = 2000;
	fake.fd_only_index = 0;
	before = fake.nlog;
	xdev_ext_ring128_destroy(&r, &ops);
	EXPECT_EQ(fake.nlog, before);
	EXPECT_EQ(r.mode, XDEV_EXT_R128_NONE);

	/* A fresh context in the child is built anew, never from the old one. */
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	EXPECT_EQ(fake.nlog - before, 6);
	EXPECT_EQ(r.owner_pid, 2000);
	EXPECT_EQ(r.ring_index, 0);
	for (i = before; i < fake.nlog; i++) {
		EXPECT_TRUE(fake.log[i].call != C_UNMAP);
		EXPECT_TRUE(fake.log[i].call != C_ENTER);
		if (fake.log[i].call == C_REG)
			EXPECT_EQ(fake.log[i].a, 0);
	}
	EXPECT_TRUE(r.rings_mem != parent_rings);
	EXPECT_TRUE(r.sqes_mem != parent_sqes);
	xdev_ext_ring128_destroy(&r, &ops);

	/* An inherited, already set up context is replaced in ensure(). */
	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	EXPECT_EQ(xdev_ext_ring128_install(&r, &ops, 2, 1, 9, makedev(242, 1), 77),
		  0);
	EXPECT_EQ(r.installed[2], 1);
	fake.pid = 3000;
	fake.fd_only_index = 1;
	before = fake.nlog;
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	EXPECT_EQ(r.ring_index, 1);
	EXPECT_EQ(r.installed[2], 0);
	for (i = before; i < fake.nlog; i++) {
		EXPECT_TRUE(fake.log[i].call != C_UNMAP);
		EXPECT_TRUE(fake.log[i].call != C_ENTER);
		if (fake.log[i].call == C_REG)
			EXPECT_EQ(fake.log[i].a, 1);
	}
	xdev_ext_ring128_destroy(&r, &ops);
}

static void make_sqe(unsigned char sqe[128], uint64_t token)
{
	unsigned int i;

	for (i = 0; i < 128; i++)
		sqe[i] = (unsigned char)(i * 7 + 1);
	sqe[0] = IORING_OP_URING_CMD;
	memcpy(sqe + 32, &token, 8);
}

static void test_publish_once_and_eintr_never_republishes(void)
{
	struct xdev_ext_ring128 r;
	unsigned char sqe[128];
	const struct fake_event *e;
	uint32_t cflags = 7;
	bool published = false;
	int32_t res = 0;

	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	make_sqe(sqe, 0x100000001ULL);
	/* Accepted, then interrupted; the CQE arrives on the next enter. */
	fake.steps[0] = (struct fake_step){ .consume = true, .ret = -EINTR };
	fake.steps[1] = (struct fake_step){ .post = true, .res = 0, .ret = 0 };
	fake.nsteps = 2;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), 0);
	EXPECT_TRUE(published);
	EXPECT_EQ(res, 0);
	EXPECT_EQ(cflags, 0);
	EXPECT_EQ(fake.consumed, 1);
	EXPECT_TRUE(!memcmp(fake.last_sqe, sqe, 128));
	EXPECT_EQ(count_calls(C_ENTER, 0), 2);
	EXPECT_EQ(count_calls(C_BACKOFF, 0), 0);
	e = nth_call(C_ENTER, 0);
	EXPECT_TRUE(e && e->a == 5 && e->b == 1 && e->c == 1 &&
		    e->d == (IORING_ENTER_GETEVENTS |
			     IORING_ENTER_REGISTERED_RING));
	e = nth_call(C_ENTER, 1);
	EXPECT_TRUE(e && e->b == 0);
	EXPECT_EQ(*k_word(fake.rings, K_SQ_TAIL), 1);
	EXPECT_EQ(*k_word(fake.rings, K_CQ_HEAD), 1);
	EXPECT_TRUE(!r.inflight);
	EXPECT_EQ(fake.cancel_state_in_enter, PTHREAD_CANCEL_DISABLE);

	/* The second request uses SQ slot 1 (128-byte stride), CQE 1. */
	make_sqe(sqe, 0x100000002ULL);
	sqe[47] = 0xee;
	fake.steps[2] = (struct fake_step){ .consume = true, .post = true,
					    .res = -EPERM, .ret = 1 };
	fake.nsteps = 3;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), 0);
	EXPECT_EQ(res, -EPERM);
	EXPECT_EQ(k_word(fake.rings, K_SQ_ARRAY)[1], 1);
	EXPECT_TRUE(fake.sqes && !memcmp(fake.sqes + 128, sqe, 128));
	EXPECT_TRUE(!memcmp(fake.last_sqe, sqe, 128));
	EXPECT_EQ(fake.cq_tail, 2);

	/* Interrupted before the kernel took it: still only one submission. */
	make_sqe(sqe, 0x100000003ULL);
	fake.steps[3] = (struct fake_step){ .ret = -EINTR };
	fake.steps[4] = (struct fake_step){ .consume = true, .post = true,
					    .res = 4096, .ret = 1 };
	fake.nsteps = 5;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), 0);
	EXPECT_EQ(res, 4096);
	EXPECT_EQ(fake.consumed, 3);
	EXPECT_EQ(*k_word(fake.rings, K_SQ_TAIL), 3);
	e = nth_call(C_ENTER, 4);
	EXPECT_TRUE(e && e->b == 1);
	xdev_ext_ring128_destroy(&r, &ops);
}

static void test_wait_errors_back_off_until_the_cqe(void)
{
	struct xdev_ext_ring128 r;
	unsigned char sqe[128];
	uint32_t cflags;
	bool published = false;
	int32_t res = 0;

	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	make_sqe(sqe, 0x200000001ULL);
	fake.steps[0] = (struct fake_step){ .consume = true, .ret = -EAGAIN };
	fake.steps[1] = (struct fake_step){ .ret = -ENOMEM };
	fake.steps[2] = (struct fake_step){ .ret = -EBUSY };
	fake.steps[3] = (struct fake_step){ .post = true, .res = 512,
					    .ret = 0 };
	fake.nsteps = 4;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), 0);
	EXPECT_TRUE(published);
	EXPECT_EQ(res, 512);
	EXPECT_EQ(fake.consumed, 1);
	EXPECT_EQ(count_calls(C_ENTER, 0), 4);
	EXPECT_EQ(fake.backoffs, 3);
	EXPECT_EQ(fake.backoff_attempt[0], 0);
	EXPECT_EQ(fake.backoff_attempt[1], 1);
	EXPECT_EQ(fake.backoff_attempt[2], 2);
	EXPECT_TRUE(!r.broken);
	xdev_ext_ring128_destroy(&r, &ops);
}

static void test_foreign_cqe_marks_the_thread_broken(void)
{
	struct xdev_ext_ring128 r;
	unsigned char sqe[128];
	uint32_t cflags;
	bool published = false;
	int32_t res = 0;
	unsigned int before;

	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	make_sqe(sqe, 0x300000001ULL);
	fake.steps[0] = (struct fake_step){ .consume = true, .post = true,
					    .foreign = true, .ret = 1 };
	fake.nsteps = 1;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), -EIO);
	EXPECT_TRUE(published);
	EXPECT_TRUE(r.broken);
	EXPECT_TRUE(r.inflight);

	/* Broken: refused before publication, the caller may use libc. */
	published = true;
	before = fake.nlog;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), -EIO);
	EXPECT_TRUE(!published);
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), -EIO);
	EXPECT_EQ(fake.nlog, before);

	/* Its request may still be in flight: keep ring and pages. */
	xdev_ext_ring128_destroy(&r, &ops);
	EXPECT_EQ(fake.nlog, before);
	EXPECT_EQ(live_maps(), 2);
	EXPECT_EQ(registered_indices(), 1);
}

static void test_refuses_before_publishing(void)
{
	struct xdev_ext_ring128 r;
	unsigned char sqe[128];
	uint32_t cflags;
	bool published = true;
	int32_t res = 0;

	/* Not set up. */
	fake_reset();
	memset(&r, 0, sizeof(r));
	make_sqe(sqe, 0x400000001ULL);
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), -ENODEV);
	EXPECT_TRUE(!published);
	EXPECT_EQ(fake.nlog, 0);

	/* An unconsumed entry is already in the SQ. */
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	__atomic_store_n(k_word(fake.rings, K_SQ_TAIL), 1, __ATOMIC_RELEASE);
	published = true;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), -EBUSY);
	EXPECT_TRUE(!published);
	EXPECT_EQ(count_calls(C_ENTER, 0), 0);
	__atomic_store_n(k_word(fake.rings, K_SQ_TAIL), 0, __ATOMIC_RELEASE);

	/* A CQE nobody asked for is already there: broken, nothing published. */
	fake_post(&fake, 0xdeadULL, 0);
	published = true;
	EXPECT_EQ(xdev_ext_ring128_submit_and_wait(&r, &ops, sqe, &res, &cflags,
					      &published), -EIO);
	EXPECT_TRUE(!published);
	EXPECT_TRUE(r.broken);
	EXPECT_TRUE(!r.inflight);
	EXPECT_EQ(*k_word(fake.rings, K_SQ_TAIL), 0);
	EXPECT_EQ(count_calls(C_ENTER, 0), 0);

	/* Nothing in flight, so a broken ring is still torn down. */
	xdev_ext_ring128_destroy(&r, &ops);
	EXPECT_EQ(live_maps(), 0);
	EXPECT_EQ(registered_indices(), 0);
}

static void test_destroy_unregisters_then_unmaps(void)
{
	struct xdev_ext_ring128 r;
	const struct fake_event *e;
	unsigned int before, i;
	bool seen_unregister = false;

	fake_reset();
	memset(&r, 0, sizeof(r));
	EXPECT_EQ(xdev_ext_ring128_ensure(&r, &ops), 0);
	before = fake.nlog;
	xdev_ext_ring128_destroy(&r, &ops);
	EXPECT_EQ(fake.nlog - before, 3);
	for (i = before; i < fake.nlog; i++) {
		e = &fake.log[i];
		if (e->call == C_REG) {
			seen_unregister = true;
			EXPECT_EQ(e->a, 5);
			EXPECT_EQ(e->b, IORING_UNREGISTER_RING_FDS |
					IORING_REGISTER_USE_REGISTERED_RING);
			EXPECT_EQ(e->c, 1);
			EXPECT_EQ(e->d, 0);
		} else {
			EXPECT_EQ(e->call, C_UNMAP);
			EXPECT_TRUE(seen_unregister);
		}
	}
	EXPECT_EQ(live_maps(), 0);
	EXPECT_EQ(registered_indices(), 0);
	EXPECT_EQ(r.mode, XDEV_EXT_R128_NONE);
	EXPECT_TRUE(!strcmp(xdev_ext_ring128_mode_name(&r), "none"));
}

int main(void)
{
	test_layout_matches_the_kernel();
	test_fd_only_setup_uses_no_descriptor_number();
	test_ring_fds_fallback_closes_the_number();
	test_both_failing_is_unavailable_without_leaks();
	test_each_failure_rolls_back();
	test_install_checks_the_anchor_first();
	test_fork_child_never_touches_the_inherited_ring();
	test_publish_once_and_eintr_never_republishes();
	test_wait_errors_back_off_until_the_cqe();
	test_foreign_cqe_marks_the_thread_broken();
	test_refuses_before_publishing();
	test_destroy_unregisters_then_unmaps();
	fake_reset();
	if (failures) {
		fprintf(stderr, "FAIL: %u/%u ring128 checks failed\n", failures,
			checks);
		return 1;
	}
	printf("PASS: %u ring128 checks\n", checks);
	return 0;
}
