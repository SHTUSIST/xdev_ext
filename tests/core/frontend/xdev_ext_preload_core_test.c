// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include "xdev_ext_preload_core.h"
#include "../../../../io_uring/unified_ops_core.h"

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

struct fake_io {
	unsigned int submit_calls;
	unsigned int fallback_calls;
	bool published;
	int submit_ret;
	int cqe_res;
	ssize_t fallback_ret;
	int fallback_errno;
	struct io_uring_sqe observed;
};

struct fake_iov_io {
	struct fake_io io;
	int observed_flags;
};

static int fake_submit_and_wait(void *opaque, const struct io_uring_sqe *sqe,
				int *cqe_res, bool *published)
{
	struct fake_io *fake = opaque;

	fake->submit_calls++;
	fake->observed = *sqe;
	*published = fake->published;
	*cqe_res = fake->cqe_res;
	return fake->submit_ret;
}

static ssize_t fake_fallback(void *opaque, int fd, void *buf, size_t count,
			     int64_t offset, bool write, int *error)
{
	struct fake_io *fake = opaque;

	(void)fd;
	(void)buf;
	(void)count;
	(void)offset;
	(void)write;
	fake->fallback_calls++;
	*error = fake->fallback_errno;
	return fake->fallback_ret;
}

static ssize_t fake_iov_fallback(void *opaque, int fd,
				 const struct iovec *iov, int iovcnt,
				 int64_t offset, bool write, int flags, int *error)
{
	struct fake_iov_io *fake = opaque;

	(void)fd;
	(void)iov;
	(void)iovcnt;
	(void)offset;
	(void)write;
	fake->io.fallback_calls++;
	fake->observed_flags = flags;
	*error = fake->io.fallback_errno;
	return fake->io.fallback_ret;
}

static int fake_iov_submit_and_wait(void *opaque,
				    const struct io_uring_sqe *sqe,
				    int *cqe_res, bool *published)
{
	struct fake_iov_io *fake = opaque;

	return fake_submit_and_wait(&fake->io, sqe, cqe_res, published);
}

static struct xdev_ext_preload_fd_meta eligible_meta(void)
{
	return (struct xdev_ext_preload_fd_meta) {
		.tracked = true,
		.identity_matches = true,
		.direct = true,
		.frame_size = 4096,
		.dio_mem_align = 512,
		.dio_offset_align = 512,
	};
}

static void test_fcntl_argument_kinds_cover_linux_abi(void)
{
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(F_GETFD), XDEV_EXT_FCNTL_NO_ARG);
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(F_GETFL), XDEV_EXT_FCNTL_NO_ARG);
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(XDEV_EXT_F_CREATED_QUERY),
		  XDEV_EXT_FCNTL_NO_ARG);
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(F_DUPFD), XDEV_EXT_FCNTL_INT_ARG);
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(XDEV_EXT_F_DUPFD_QUERY),
		  XDEV_EXT_FCNTL_INT_ARG);
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(F_SETFL), XDEV_EXT_FCNTL_INT_ARG);
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(F_GETLK), XDEV_EXT_FCNTL_POINTER_ARG);
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(XDEV_EXT_F_GETOWNER_UIDS),
		  XDEV_EXT_FCNTL_POINTER_ARG);
	EXPECT_EQ(xdev_ext_preload_fcntl_arg_kind(F_GET_RW_HINT),
		  XDEV_EXT_FCNTL_POINTER_ARG);
}

static void test_duplicated_fd_identity_must_match_snapshot(void)
{
	struct xdev_ext_preload_fd_identity expected = {
		.dev = 11,
		.ino = 22,
		.mode = S_IFREG | 0600,
	};
	struct xdev_ext_preload_fd_identity observed = expected;

	EXPECT_TRUE(xdev_ext_preload_fd_identity_matches(&expected, &observed,
						     true, O_DIRECT));
	observed.ino++;
	EXPECT_TRUE(!xdev_ext_preload_fd_identity_matches(&expected, &observed,
						      true, O_DIRECT));
	observed = expected;
	observed.mode = S_IFBLK | 0600;
	EXPECT_TRUE(!xdev_ext_preload_fd_identity_matches(&expected, &observed,
						      true, O_DIRECT));
	observed = expected;
	EXPECT_TRUE(!xdev_ext_preload_fd_identity_matches(&expected, &observed,
						      false, O_DIRECT));
	EXPECT_TRUE(!xdev_ext_preload_fd_identity_matches(&expected, &observed,
						      true, O_RDONLY));
}

/*
 * A descriptor whose O_DIRECT flag is clear only makes the current call fall
 * back; F_SETFL can set the flag again, and the next call must be admitted.
 * Only a different object or a path outside the allowlist retires the record.
 */
static void test_clear_o_direct_keeps_the_descriptor_record(void)
{
	struct xdev_ext_preload_fd_identity expected = {
		.dev = 11,
		.ino = 22,
		.mode = S_IFREG | 0600,
	};
	struct xdev_ext_preload_fd_identity observed = expected;

	EXPECT_TRUE(!xdev_ext_preload_fd_identity_matches(&expected, &observed,
						      true, O_RDWR));
	EXPECT_TRUE(!xdev_ext_preload_fd_record_stale(&expected, &observed, true));
	observed.ino++;
	EXPECT_TRUE(xdev_ext_preload_fd_record_stale(&expected, &observed, true));
	observed = expected;
	observed.dev++;
	EXPECT_TRUE(xdev_ext_preload_fd_record_stale(&expected, &observed, true));
	observed = expected;
	observed.mode = S_IFBLK | 0600;
	EXPECT_TRUE(xdev_ext_preload_fd_record_stale(&expected, &observed, true));
	observed = expected;
	EXPECT_TRUE(xdev_ext_preload_fd_record_stale(&expected, &observed, false));
	EXPECT_TRUE(xdev_ext_preload_fd_record_stale(NULL, &observed, true));
}

static void test_eligible_encodes_real_unified_sqe(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	struct fake_io fake = {
		.published = true,
		.cqe_res = 4096,
	};
	struct xdev_ext_preload_seam seam = {
		.opaque = &fake,
		.submit_and_wait = fake_submit_and_wait,
		.fallback = fake_fallback,
	};
	void *user_buffer = NULL;
	unsigned char staging[4096] __attribute__((aligned(4096)));
	int error = 0;
	ssize_t ret;

	EXPECT_EQ(posix_memalign(&user_buffer, 4096, 4096), 0);
	memset(staging, 0x5a, sizeof(staging));
	ret = xdev_ext_preload_execute(&meta, 7, user_buffer, 4096, 8192, false,
				  staging, UINT64_C(0x12345678), &seam, &error);
	EXPECT_EQ(ret, 4096);
	EXPECT_EQ(error, 0);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.fallback_calls, 0);
	EXPECT_EQ(fake.observed.opcode, IORING_OP_UNIFIED_OPS);
	EXPECT_EQ(fake.observed.flags, IOSQE_XDEV_EXT_UMEM);
	EXPECT_EQ(fake.observed.fd, 7);
	EXPECT_EQ(fake.observed.addr, 0);
	EXPECT_EQ(fake.observed.len, IO_UNIFIED_OP_READ_COMPAT);
	EXPECT_EQ(fake.observed.rw_flags, 4096);
	EXPECT_EQ(fake.observed.off, 8192);
	EXPECT_EQ(fake.observed.user_data, UINT64_C(0x12345678));
	EXPECT_TRUE(!memcmp(user_buffer, staging, 4096));
	free(user_buffer);
}

static void test_write_copies_before_submit(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	struct fake_io fake = { .published = true, .cqe_res = 512 };
	struct xdev_ext_preload_seam seam = {
		.opaque = &fake,
		.submit_and_wait = fake_submit_and_wait,
		.fallback = fake_fallback,
	};
	unsigned char user[512] __attribute__((aligned(512)));
	unsigned char staging[4096] __attribute__((aligned(4096)));
	int error = 0;

	memset(user, 0xa5, sizeof(user));
	memset(staging, 0, sizeof(staging));
	EXPECT_EQ(xdev_ext_preload_execute(&meta, 9, user, sizeof(user), 0, true,
				      staging, 77, &seam, &error), 512);
	EXPECT_EQ(fake.observed.len, IO_UNIFIED_OP_WRITE_COMPAT);
	EXPECT_TRUE(!memcmp(user, staging, sizeof(user)));
}

static void test_ineligible_never_submits(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	struct fake_io fake = { .fallback_ret = 17 };
	struct xdev_ext_preload_seam seam = {
		.opaque = &fake,
		.submit_and_wait = fake_submit_and_wait,
		.fallback = fake_fallback,
	};
	unsigned char user[513] __attribute__((aligned(512)));
	unsigned char staging[4096] __attribute__((aligned(4096)));
	int error = 0;

	/* A DIO-incompatible byte count must stay on libc with zero SQEs. */
	EXPECT_EQ(xdev_ext_preload_execute(&meta, 4, user, sizeof(user), 0, false,
				      staging, 1, &seam, &error), 17);
	EXPECT_EQ(fake.submit_calls, 0);
	EXPECT_EQ(fake.fallback_calls, 1);

	meta.identity_matches = false;
	fake.submit_calls = fake.fallback_calls = 0;
	EXPECT_EQ(xdev_ext_preload_execute(&meta, 4, user, 512, 0, false,
				      staging, 2, &seam, &error), 17);
	EXPECT_EQ(fake.submit_calls, 0);
	EXPECT_EQ(fake.fallback_calls, 1);
}

static void test_published_request_is_never_replayed(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	struct fake_io fake = {
		.published = true,
		.submit_ret = -EINTR,
		.fallback_ret = 4096,
	};
	struct xdev_ext_preload_seam seam = {
		.opaque = &fake,
		.submit_and_wait = fake_submit_and_wait,
		.fallback = fake_fallback,
	};
	unsigned char user[4096] __attribute__((aligned(4096)));
	unsigned char staging[4096] __attribute__((aligned(4096)));
	int error = 0;

	EXPECT_EQ(xdev_ext_preload_execute(&meta, 5, user, sizeof(user), 0, false,
				      staging, 3, &seam, &error), -1);
	EXPECT_EQ(error, EINTR);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.fallback_calls, 0);

	/* A failure before publication is safe to hand back to libc once. */
	fake.published = false;
	fake.submit_calls = fake.fallback_calls = 0;
	fake.fallback_ret = 101;
	EXPECT_EQ(xdev_ext_preload_execute(&meta, 5, user, sizeof(user), 0, false,
				      staging, 4, &seam, &error), 101);
	EXPECT_EQ(fake.submit_calls, 1);
	EXPECT_EQ(fake.fallback_calls, 1);
}

struct fake_ring {
	unsigned int publish_calls;
	unsigned int enter_calls;
	unsigned int submit_counts[4];
	bool accepted;
	bool complete;
};

static int fake_ring_publish(void *opaque, const struct io_uring_sqe *sqe)
{
	struct fake_ring *ring = opaque;

	(void)sqe;
	ring->publish_calls++;
	return 0;
}

static int fake_ring_peek(void *opaque, uint64_t token, int *result)
{
	struct fake_ring *ring = opaque;

	(void)token;
	if (!ring->complete)
		return 0;
	*result = 73;
	return 1;
}

static bool fake_ring_accepted(void *opaque)
{
	return ((struct fake_ring *)opaque)->accepted;
}

static int fake_ring_enter(void *opaque, unsigned int to_submit)
{
	struct fake_ring *ring = opaque;

	ring->submit_counts[ring->enter_calls] = to_submit;
	ring->enter_calls++;
	if (ring->enter_calls == 1) {
		ring->accepted = true;
		return -EINTR;
	}
	ring->complete = true;
	return 0;
}

static void test_eintr_drains_without_republishing(void)
{
	struct fake_ring fake = {};
	struct xdev_ext_preload_ring_seam seam = {
		.opaque = &fake,
		.publish_once = fake_ring_publish,
		.peek_completion = fake_ring_peek,
		.request_accepted = fake_ring_accepted,
		.enter_and_wait = fake_ring_enter,
	};
	struct io_uring_sqe sqe = { .user_data = 88 };
	bool published = false;
	int result = 0;

	EXPECT_EQ(xdev_ext_preload_submit_and_drain(&seam, &sqe, &result,
					      &published), 0);
	EXPECT_TRUE(published);
	EXPECT_EQ(result, 73);
	EXPECT_EQ(fake.publish_calls, 1);
	EXPECT_EQ(fake.enter_calls, 2);
	EXPECT_EQ(fake.submit_counts[0], 1);
	EXPECT_EQ(fake.submit_counts[1], 0);
}

static void test_backing_release_requires_a_terminal_completion(void)
{
	/* A request that never reached the shared SQ may release immediately. */
	EXPECT_TRUE(xdev_ext_preload_can_release_backing(false, false));
	/* A CQE, including a negative CQE result, proves the terminal boundary. */
	EXPECT_TRUE(xdev_ext_preload_can_release_backing(true, true));
	/* Closing the ring alone does not prove that published DMA is quiescent. */
	EXPECT_TRUE(!xdev_ext_preload_can_release_backing(true, false));
}

struct offset_thread {
	int64_t offset;
	uint32_t tid;
	struct io_uring_sqe sqe;
	uint64_t token;
};

static void *encode_offset(void *opaque)
{
	struct offset_thread *thread = opaque;
	struct xdev_ext_preload_token_source source = {
		.owner_pid = 42,
		.owner_tid = thread->tid,
	};

	thread->token = xdev_ext_preload_next_token(&source, 42, thread->tid);
	xdev_ext_preload_encode_sqe(&thread->sqe, 11, 4096, thread->offset, false,
			       thread->token);
	return NULL;
}

static void test_thread_offsets_and_tokens_are_isolated(void)
{
	struct offset_thread a = { .offset = INT64_C(0x100000000), .tid = 101 };
	struct offset_thread b = { .offset = INT64_C(0x200000000), .tid = 202 };
	pthread_t ta, tb;

	EXPECT_EQ(pthread_create(&ta, NULL, encode_offset, &a), 0);
	EXPECT_EQ(pthread_create(&tb, NULL, encode_offset, &b), 0);
	EXPECT_EQ(pthread_join(ta, NULL), 0);
	EXPECT_EQ(pthread_join(tb, NULL), 0);
	EXPECT_EQ(a.sqe.off, a.offset);
	EXPECT_EQ(b.sqe.off, b.offset);
	EXPECT_TRUE(a.token != b.token);
}

static void test_fork_requires_lazy_context_rebuild(void)
{
	struct xdev_ext_preload_token_source source = {
		.owner_pid = 900,
		.owner_tid = 901,
		.sequence = 7,
	};
	uint64_t token;

	EXPECT_TRUE(!xdev_ext_preload_context_stale(source.owner_pid, 900));
	EXPECT_TRUE(xdev_ext_preload_context_stale(source.owner_pid, 1000));
	token = xdev_ext_preload_next_token(&source, 1000, 1001);
	EXPECT_EQ(source.owner_pid, 1000);
	EXPECT_EQ(source.owner_tid, 1001);
	EXPECT_EQ(source.sequence, 1);
	EXPECT_TRUE(token != 0);
}

static void test_read_compat_recycles_but_pipeline_read_publishes(void)
{
	struct xdev_ext_mech_life frame;
	struct xdev_ext_mech_life_pool pool;
	__u64 claim, consumer;

	/* Original pipeline-read assertions: publish the completed byte count.
	 * The new API carries the full producer claim, not just its generation. */
	xdev_ext_mech_life_pool_init(&pool, &frame, 1);
	EXPECT_EQ(xdev_ext_mech_life_claim(&frame, 0, &claim), 0);
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, claim, 4096, false), 0);
	EXPECT_EQ(xdev_ext_mech_life_phase(&frame), XDEV_EXT_MECH_L_READY);
	EXPECT_EQ(frame.valid_len, 4096);
	EXPECT_EQ(xdev_ext_mech_life_refs(&frame), 1);
	EXPECT_EQ(xdev_ext_mech_life_gen(&frame), 0);
	EXPECT_EQ(xdev_ext_mech_life_acquire(&frame, 0, 0, &consumer), 0);
	EXPECT_EQ(xdev_ext_mech_life_phase(&frame), XDEV_EXT_MECH_L_OUT_PENDING);
	EXPECT_EQ(xdev_ext_mech_life_gen(&frame), 0);
	EXPECT_EQ(xdev_ext_mech_life_put(&frame, consumer), XDEV_EXT_MECH_L_FREED);
	EXPECT_EQ(xdev_ext_mech_life_phase(&frame), XDEV_EXT_MECH_L_FREE);
	EXPECT_EQ(xdev_ext_mech_life_refs(&frame), 0);
	EXPECT_EQ(xdev_ext_mech_life_gen(&frame), 1);

	/* Original compat-read assertions: successful I/O recycles immediately. */
	xdev_ext_mech_life_pool_init(&pool, &frame, 1);
	EXPECT_EQ(xdev_ext_mech_life_claim(&frame, 0, &claim), 0);
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, claim, 4096, true), 0);
	EXPECT_EQ(xdev_ext_mech_life_phase(&frame), XDEV_EXT_MECH_L_FREE);
	EXPECT_EQ(xdev_ext_mech_life_refs(&frame), 0);
	EXPECT_EQ(xdev_ext_mech_life_gen(&frame), 1);

	/* Original producer-error assertions: never publish a failed read. */
	xdev_ext_mech_life_pool_init(&pool, &frame, 1);
	EXPECT_EQ(xdev_ext_mech_life_claim(&frame, 0, &claim), 0);
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, claim, -EIO, false), 0);
	EXPECT_EQ(xdev_ext_mech_life_phase(&frame), XDEV_EXT_MECH_L_FREE);
	EXPECT_EQ(xdev_ext_mech_life_refs(&frame), 0);
	EXPECT_EQ(xdev_ext_mech_life_gen(&frame), 1);
}

static void test_read_finish_rejects_stale_or_nonproducer_claims(void)
{
	struct xdev_ext_mech_life frame;
	struct xdev_ext_mech_life_pool pool;
	__u64 claim, consumer, next, word, wrong_owner;

	xdev_ext_mech_life_pool_init(&pool, &frame, 1);
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, 0, 4096, false), -ESTALE);
	EXPECT_EQ(frame.ctrl, 0);
	EXPECT_EQ(frame.valid_len, 0);
	EXPECT_EQ(xdev_ext_mech_life_claim(&frame, 0, &claim), 0);
	word = frame.ctrl;
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0,
		claim + (1ULL << XDEV_EXT_MECH_L_GEN_SHIFT), 4096, false), -ESTALE);
	EXPECT_EQ(frame.ctrl, word);
	EXPECT_EQ(frame.valid_len, 0);
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, claim, 512, false), 0);
	word = frame.ctrl;
	/* A duplicate producer completion cannot replace an already READY payload. */
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, claim, 4096, false), -ESTALE);
	EXPECT_EQ(frame.ctrl, word);
	EXPECT_EQ(frame.valid_len, 512);
	EXPECT_EQ(xdev_ext_mech_life_acquire(&frame, 0, 0, &consumer), 0);
	word = frame.ctrl;
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, consumer, 4096, false), -ESTALE);
	EXPECT_EQ(frame.ctrl, word);
	EXPECT_EQ(frame.valid_len, 512);
	EXPECT_EQ(xdev_ext_mech_life_put(&frame, consumer), XDEV_EXT_MECH_L_FREED);
	EXPECT_EQ(xdev_ext_mech_life_claim(&frame, 0, &next), 0);
	EXPECT_EQ(xdev_ext_mech_life_claim_gen(next), 1);
	word = frame.ctrl;
	/* Neither stale failure nor stale compat completion may free the next read. */
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, claim, -EIO, false), -ESTALE);
	EXPECT_EQ(frame.ctrl, word);
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, claim, 4096, true), -ESTALE);
	EXPECT_EQ(frame.ctrl, word);
	EXPECT_EQ(frame.valid_len, 512);
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, next, -EIO, false), 0);
	EXPECT_EQ(xdev_ext_mech_life_phase(&frame), XDEV_EXT_MECH_L_FREE);
	EXPECT_EQ(xdev_ext_mech_life_gen(&frame), 2);

	/* Owner 0 mirrors the UMEM read window above. A nonzero producer owner
	 * must also work, while a different owner in the same generation fails. */
	EXPECT_EQ(xdev_ext_mech_life_claim(&frame, XDEV_EXT_MECH_L_OWNER_START, &next), 0);
	word = frame.ctrl;
	wrong_owner = (next & ~XDEV_EXT_MECH_L_OWNER_MASK) |
		(1ULL << XDEV_EXT_MECH_L_OWNER_SHIFT); /* owner 0, same generation/kind */
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, wrong_owner, 1024, false), -ESTALE);
	EXPECT_EQ(frame.ctrl, word);
	EXPECT_EQ(frame.valid_len, 512);
	EXPECT_EQ(xdev_ext_unified_read_finish(&pool, 0, next, 1024, false), 0);
	EXPECT_EQ(xdev_ext_mech_life_phase(&frame), XDEV_EXT_MECH_L_READY);
	EXPECT_EQ(frame.valid_len, 1024);
	EXPECT_EQ(xdev_ext_mech_life_refs(&frame), 1);
	EXPECT_EQ(xdev_ext_mech_life_gen(&frame), 2);
	EXPECT_EQ(xdev_ext_mech_life_acquire(&frame, 0, 0, &consumer), 0);
	EXPECT_EQ(xdev_ext_mech_life_put(&frame, consumer), XDEV_EXT_MECH_L_FREED);
	EXPECT_EQ(xdev_ext_mech_life_phase(&frame), XDEV_EXT_MECH_L_FREE);
	EXPECT_EQ(xdev_ext_mech_life_gen(&frame), 3);
}

static void test_write_compat_preserves_fd_durability_flags(void)
{
	EXPECT_TRUE(xdev_ext_unified_write_force_dsync(IO_UNIFIED_OP_WRITE));
	EXPECT_TRUE(!xdev_ext_unified_write_force_dsync(IO_UNIFIED_OP_WRITE_COMPAT));
}

static void test_cqe_short_io_and_errno(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	struct fake_io fake = { .published = true, .cqe_res = 512 };
	struct xdev_ext_preload_seam seam = {
		.opaque = &fake,
		.submit_and_wait = fake_submit_and_wait,
		.fallback = fake_fallback,
	};
	unsigned char user[4096] __attribute__((aligned(4096)));
	unsigned char staging[4096] __attribute__((aligned(4096)));
	int error = 0;

	memset(staging, 0x6c, sizeof(staging));
	EXPECT_EQ(xdev_ext_preload_execute(&meta, 3, user, sizeof(user), 0, false,
				      staging, 8, &seam, &error), 512);
	EXPECT_TRUE(!memcmp(user, staging, 512));

	fake.cqe_res = -EIO;
	EXPECT_EQ(xdev_ext_preload_execute(&meta, 3, user, sizeof(user), 0, false,
				      staging, 9, &seam, &error), -1);
	EXPECT_EQ(error, EIO);
	EXPECT_EQ(fake.fallback_calls, 0);
}

static void test_vectored_eligibility_and_staging(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	unsigned char first[2048] __attribute__((aligned(512)));
	unsigned char second[2048] __attribute__((aligned(512)));
	unsigned char staging[4096] __attribute__((aligned(4096)));
	struct iovec iov[3] = {
		{ .iov_base = first, .iov_len = sizeof(first) },
		{ .iov_base = NULL, .iov_len = 0 },
		{ .iov_base = second, .iov_len = sizeof(second) },
	};
	size_t total = 0;

	memset(first, 0x31, sizeof(first));
	memset(second, 0x62, sizeof(second));
	memset(staging, 0, sizeof(staging));
	EXPECT_TRUE(xdev_ext_preload_iov_is_eligible(&meta, iov, 3, 4096,
						 &total));
	EXPECT_EQ(total, sizeof(staging));
	EXPECT_TRUE(xdev_ext_preload_iov_gather(staging, sizeof(staging), iov, 3,
					    total));
	EXPECT_TRUE(!memcmp(staging, first, sizeof(first)));
	EXPECT_TRUE(!memcmp(staging + sizeof(first), second, sizeof(second)));

	memset(first, 0, sizeof(first));
	memset(second, 0, sizeof(second));
	EXPECT_TRUE(xdev_ext_preload_iov_scatter(iov, 3, staging, 2560));
	EXPECT_TRUE(first[0] == 0x31 && first[sizeof(first) - 1] == 0x31);
	EXPECT_TRUE(second[0] == 0x62 && second[511] == 0x62);
	EXPECT_EQ(second[512], 0);
}

static void test_vectored_rejects_unsafe_geometry(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	unsigned char storage[4608] __attribute__((aligned(512)));
	struct iovec iov[2] = {
		{ .iov_base = storage, .iov_len = 2048 },
		{ .iov_base = storage + 2048, .iov_len = 2048 },
	};
	size_t total = 123;

	EXPECT_TRUE(!xdev_ext_preload_iov_is_eligible(&meta, NULL, 2, 0, &total));
	EXPECT_TRUE(!xdev_ext_preload_iov_is_eligible(&meta, iov, 0, 0, &total));
	EXPECT_TRUE(!xdev_ext_preload_iov_is_eligible(&meta, iov, -1, 0, &total));
	iov[1].iov_base = storage + 2049;
	EXPECT_TRUE(!xdev_ext_preload_iov_is_eligible(&meta, iov, 2, 0, &total));
	iov[1].iov_base = storage + 2048;
	iov[1].iov_len = 2049;
	EXPECT_TRUE(!xdev_ext_preload_iov_is_eligible(&meta, iov, 2, 0, &total));
	iov[1].iov_len = 2560;
	EXPECT_TRUE(!xdev_ext_preload_iov_is_eligible(&meta, iov, 2, 0, &total));
	iov[1].iov_len = 2048;
	EXPECT_TRUE(!xdev_ext_preload_iov_is_eligible(&meta, iov, 2, INT64_MAX - 511,
						  &total));
}

static void test_vectored_execute_uses_one_staged_request(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	struct fake_iov_io fake = { .io = { .published = true, .cqe_res = 4096 } };
	struct xdev_ext_preload_iov_seam seam = {
		.opaque = &fake,
		.submit_and_wait = fake_iov_submit_and_wait,
		.fallback = fake_iov_fallback,
	};
	unsigned char first[2048] __attribute__((aligned(512)));
	unsigned char second[2048] __attribute__((aligned(512)));
	unsigned char staging[4096] __attribute__((aligned(4096)));
	struct iovec iov[2] = {
		{ .iov_base = first, .iov_len = sizeof(first) },
		{ .iov_base = second, .iov_len = sizeof(second) },
	};
	int error = 0;

	memset(first, 0x11, sizeof(first));
	memset(second, 0x22, sizeof(second));
	EXPECT_EQ(xdev_ext_preload_execute_iov(&meta, 17, iov, 2, 8192, true, 0,
					   staging, 99, &seam, &error), 4096);
	EXPECT_EQ(fake.io.submit_calls, 1);
	EXPECT_EQ(fake.io.fallback_calls, 0);
	EXPECT_EQ(fake.io.observed.fd, 17);
	EXPECT_EQ(fake.io.observed.len, IO_UNIFIED_OP_WRITE_COMPAT);
	EXPECT_EQ(fake.io.observed.rw_flags, 4096);
	EXPECT_EQ(fake.io.observed.off, 8192);
	EXPECT_TRUE(!memcmp(staging, first, sizeof(first)));
	EXPECT_TRUE(!memcmp(staging + sizeof(first), second, sizeof(second)));

	/* v2 flags outside the exact flags=0 subset must stay in libc. */
	fake.io.submit_calls = fake.io.fallback_calls = 0;
	fake.io.fallback_ret = 123;
	EXPECT_EQ(xdev_ext_preload_execute_iov(&meta, 17, iov, 2, 0, true, 1,
					   staging, 100, &seam, &error), 123);
	EXPECT_EQ(fake.io.submit_calls, 0);
	EXPECT_EQ(fake.io.fallback_calls, 1);
	EXPECT_EQ(fake.observed_flags, 1);
}

static void test_vectored_short_read_scatters_returned_prefix(void)
{
	struct xdev_ext_preload_fd_meta meta = eligible_meta();
	struct fake_iov_io fake = { .io = { .published = true, .cqe_res = 2560 } };
	struct xdev_ext_preload_iov_seam seam = {
		.opaque = &fake,
		.submit_and_wait = fake_iov_submit_and_wait,
		.fallback = fake_iov_fallback,
	};
	unsigned char first[2048] __attribute__((aligned(512)));
	unsigned char second[2048] __attribute__((aligned(512)));
	unsigned char staging[4096] __attribute__((aligned(4096)));
	struct iovec iov[2] = {
		{ .iov_base = first, .iov_len = sizeof(first) },
		{ .iov_base = second, .iov_len = sizeof(second) },
	};
	int error = 0;

	memset(first, 0, sizeof(first));
	memset(second, 0, sizeof(second));
	memset(staging, 0x7c, sizeof(staging));
	EXPECT_EQ(xdev_ext_preload_execute_iov(&meta, 18, iov, 2, 0, false, 0,
					   staging, 101, &seam, &error), 2560);
	EXPECT_TRUE(first[0] == 0x7c && first[sizeof(first) - 1] == 0x7c);
	EXPECT_TRUE(second[0] == 0x7c && second[511] == 0x7c);
	EXPECT_EQ(second[512], 0);
}

static void test_report_snapshot_obeys_quiescence_boundary(void)
{
	struct io_uring_unified_shared shared = {
		.read_count = 3,
		.send_count = 4,
		.read_bytes = 12288,
		.send_bytes = 16384,
		.read_errors = 1,
		.send_errors = 2,
	};
	struct xdev_ext_preload_report_snapshot snapshot = {};
	struct io_uring_unified_shared *invalid =
		(struct io_uring_unified_shared *)(uintptr_t)1;

	/* These guards must run before any access to a potentially unsafe mapping. */
	EXPECT_TRUE(!xdev_ext_preload_snapshot_report(false, false, invalid, &snapshot));
	EXPECT_TRUE(!xdev_ext_preload_snapshot_report(true, true, invalid, &snapshot));
	EXPECT_TRUE(xdev_ext_preload_snapshot_report(true, false, &shared, &snapshot));
	EXPECT_EQ(snapshot.read_count, 3);
	EXPECT_EQ(snapshot.write_count, 4);
	EXPECT_EQ(snapshot.read_bytes, 12288);
	EXPECT_EQ(snapshot.write_bytes, 16384);
	EXPECT_EQ(snapshot.read_errors, 1);
	EXPECT_EQ(snapshot.write_errors, 2);
	EXPECT_EQ(shared.lock, 0);
	shared.lock = 1;
	EXPECT_TRUE(!xdev_ext_preload_snapshot_report(true, false, &shared, &snapshot));
}

int main(void)
{
	test_fcntl_argument_kinds_cover_linux_abi();
	test_duplicated_fd_identity_must_match_snapshot();
	test_clear_o_direct_keeps_the_descriptor_record();
	test_eligible_encodes_real_unified_sqe();
	test_write_copies_before_submit();
	test_ineligible_never_submits();
	test_published_request_is_never_replayed();
	test_eintr_drains_without_republishing();
	test_backing_release_requires_a_terminal_completion();
	test_thread_offsets_and_tokens_are_isolated();
	test_fork_requires_lazy_context_rebuild();
	test_read_compat_recycles_but_pipeline_read_publishes();
	test_read_finish_rejects_stale_or_nonproducer_claims();
	test_write_compat_preserves_fd_durability_flags();
	test_cqe_short_io_and_errno();
	test_vectored_eligibility_and_staging();
	test_vectored_rejects_unsafe_geometry();
	test_vectored_execute_uses_one_staged_request();
	test_vectored_short_read_scatters_returned_prefix();
	test_report_snapshot_obeys_quiescence_boundary();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u checks\n", checks);
	return EXIT_SUCCESS;
}
