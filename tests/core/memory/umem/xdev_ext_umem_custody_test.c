// SPDX-License-Identifier: GPL-2.0
/*
 * Custody between the two users of one io_uring UMEM.  Mechanism sessions
 * (XDEV_EXT_MECH_POOL_IOU_UMEM) move frames through per-frame ownership words
 * (K_FREE, HELD, INFLIGHT under a native command, SEQUESTERED while a device
 * may still write).  Legacy unified ops (IOSQE_XDEV_EXT_UMEM) address the
 * same frames by UMEM offset and never read those words, so a legacy READ
 * could DMA into an INFLIGHT or SEQUESTERED frame.  The registry therefore
 * keeps one UMEM in one custody domain: legacy acquisition is refused once a
 * session has bound the UMEM, and a session cannot bind a UMEM legacy ops
 * have used.  The actual registry and pool provider code is compiled with
 * kernel primitives shimmed.
 */
#include <stdio.h>

#define CONFIG_XDEV_EXT_MECH 1
#include "xdev_ext_umem_mech_shim.h"

#include "../../../../io_uring/xdev_ext_umem.c"

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

#define NR_FRAMES 4

static const struct xdev_ext_mech_layout layout = { .frame_size = PAGE_SIZE };

static struct io_uring_unified_shared stats = { .marker = 7 };

static struct io_uring_xdev_ext_umem_reg reg_at(u64 addr)
{
	return (struct io_uring_xdev_ext_umem_reg) {
		.addr = addr,
		.size = NR_FRAMES * PAGE_SIZE,
		.shared_addr = (uintptr_t)&stats,
		.frame_size = PAGE_SIZE,
	};
}

static void use_mm(struct task_struct *task, struct mm_struct *mm,
		   unsigned int id)
{
	memset(mm, 0, sizeof(*mm));
	atomic_init(&mm->mm_count, 1);
	mm->id = id;
	task->mm = mm;
	current = task;
}

/* The acquisition io_unified_ops_issue() performs for IOSQE_XDEV_EXT_UMEM. */
static struct io_xdev_ext_umem *legacy_get(struct io_ring_ctx *ctx)
{
	struct io_uring_unified_shared *shared = NULL;

	return io_xdev_ext_umem_get_ctx_with_stats(ctx, &shared);
}

static void test_legacy_op_refused_after_session_binds(void)
{
	struct io_uring_xdev_ext_umem_reg reg = reg_at(0x300000);
	struct xdev_ext_mech_frame f = {};
	struct xdev_ext_mech_pool pool;
	struct io_xdev_ext_umem *umem;
	struct io_ring_ctx ctx = {};
	struct task_struct task = {};
	struct mm_struct mm;

	use_mm(&task, &mm, 40);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &reg), 0);
	EXPECT_EQ(io_xdev_ext_umem_mech_pool_bind(&pool, &ctx, &layout), 0);

	/* START hands frame 1 to the session; the worker submits it. */
	EXPECT_EQ(xdev_ext_mech_frame_move(&pool.state[1], XDEV_EXT_MECH_F_USER,
					  XDEV_EXT_MECH_F_K_FREE), 0);
	f.index = 1;
	pool.ops->recycle(&pool, &f);
	EXPECT_EQ(pool.ops->alloc(&pool, &f, 1), 0);
	EXPECT_EQ(xdev_ext_mech_frame_move(&pool.state[1], XDEV_EXT_MECH_F_HELD,
					  XDEV_EXT_MECH_F_INFLIGHT), 0);

	/* A legacy op on the same ring would target that INFLIGHT frame. */
	umem = legacy_get(&ctx);
	EXPECT_TRUE(umem == NULL);
	if (umem)
		io_xdev_ext_umem_put(umem);

	/*
	 * Frames can stay SEQUESTERED after the session is gone, so the
	 * refusal outlives the session.
	 */
	EXPECT_EQ(xdev_ext_mech_frame_move(&pool.state[1], XDEV_EXT_MECH_F_INFLIGHT,
					  XDEV_EXT_MECH_F_SEQUESTERED), 0);
	pool.ops->release(&pool);
	umem = legacy_get(&ctx);
	EXPECT_TRUE(umem == NULL);
	if (umem)
		io_xdev_ext_umem_put(umem);

	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), 0);
	EXPECT_EQ(atomic_load(&mm.mm_count), 1);
}

static void test_shared_umem_refuses_legacy_on_other_ring(void)
{
	struct io_uring_xdev_ext_umem_reg reg = reg_at(0x400000);
	struct io_ring_ctx legacy_ctx = {}, mech_ctx = {};
	struct xdev_ext_mech_pool pool;
	struct io_xdev_ext_umem *umem;
	struct task_struct task = {};
	struct mm_struct mm;

	use_mm(&task, &mm, 41);
	EXPECT_EQ(io_xdev_ext_umem_register(&legacy_ctx, &reg), 0);
	EXPECT_EQ(io_xdev_ext_umem_register(&mech_ctx, &reg), 0);
	EXPECT_TRUE(legacy_ctx.xdev_ext_umem == mech_ctx.xdev_ext_umem);
	EXPECT_EQ(io_xdev_ext_umem_mech_pool_bind(&pool, &mech_ctx, &layout), 0);

	umem = legacy_get(&legacy_ctx);
	EXPECT_TRUE(umem == NULL);
	if (umem)
		io_xdev_ext_umem_put(umem);

	pool.ops->release(&pool);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&mech_ctx), 0);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&legacy_ctx), 0);
	EXPECT_EQ(atomic_load(&mm.mm_count), 1);
}

static void test_session_refused_on_legacy_umem(void)
{
	struct io_uring_xdev_ext_umem_reg reg = reg_at(0x500000);
	struct io_ring_ctx legacy_ctx = {}, mech_ctx = {};
	struct xdev_ext_mech_pool pool;
	struct io_xdev_ext_umem *umem;
	struct task_struct task = {};
	struct mm_struct mm;

	use_mm(&task, &mm, 42);
	EXPECT_EQ(io_xdev_ext_umem_register(&legacy_ctx, &reg), 0);
	umem = legacy_get(&legacy_ctx);
	EXPECT_TRUE(umem != NULL);

	/* Another ring shares those pins and tries to start a session. */
	EXPECT_EQ(io_xdev_ext_umem_register(&mech_ctx, &reg), 0);
	EXPECT_EQ(io_xdev_ext_umem_mech_pool_bind(&pool, &mech_ctx, &layout),
		  -EBUSY);
	if (umem)
		io_xdev_ext_umem_put(umem);
	/* The legacy op has completed; the UMEM stays in its domain. */
	EXPECT_EQ(io_xdev_ext_umem_mech_pool_bind(&pool, &legacy_ctx, &layout),
		  -EBUSY);
	umem = legacy_get(&legacy_ctx);
	EXPECT_TRUE(umem != NULL);
	if (umem)
		io_xdev_ext_umem_put(umem);

	/* The refused binds took no reference: both unregisters free it. */
	test_watched_umem = legacy_ctx.xdev_ext_umem;
	atomic_store(&test_watched_free_count, 0);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&mech_ctx), 0);
	EXPECT_EQ(atomic_load(&test_watched_free_count), 0);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&legacy_ctx), 0);
	EXPECT_EQ(atomic_load(&test_watched_free_count), 1);
	test_watched_umem = NULL;
	EXPECT_EQ(atomic_load(&mm.mm_count), 1);
}

static void test_separate_umems_keep_both_interfaces(void)
{
	struct io_uring_xdev_ext_umem_reg legacy_reg = reg_at(0x600000);
	struct io_uring_xdev_ext_umem_reg mech_reg = reg_at(0x700000);
	struct io_ring_ctx legacy_ctx = {}, mech_ctx = {}, mech_ctx2 = {};
	struct xdev_ext_mech_pool pool, pool2;
	struct io_xdev_ext_umem *umem;
	struct task_struct task = {};
	struct mm_struct mm;

	use_mm(&task, &mm, 43);
	/*
	 * The preload socket path gives its session its own ring and region;
	 * distinct pins are distinct UMEMs and keep both interfaces usable.
	 */
	atomic_store(&test_page_generation, 1);
	EXPECT_EQ(io_xdev_ext_umem_register(&legacy_ctx, &legacy_reg), 0);
	atomic_store(&test_page_generation, 2);
	EXPECT_EQ(io_xdev_ext_umem_register(&mech_ctx, &mech_reg), 0);
	EXPECT_EQ(io_xdev_ext_umem_register(&mech_ctx2, &mech_reg), 0);
	atomic_store(&test_page_generation, 0);
	EXPECT_TRUE(legacy_ctx.xdev_ext_umem != mech_ctx.xdev_ext_umem);

	umem = legacy_get(&legacy_ctx);
	EXPECT_TRUE(umem != NULL);
	EXPECT_EQ(io_xdev_ext_umem_mech_pool_bind(&pool, &mech_ctx, &layout), 0);
	/* Several sessions may share one session UMEM and its words. */
	EXPECT_EQ(io_xdev_ext_umem_mech_pool_bind(&pool2, &mech_ctx2, &layout), 0);
	EXPECT_TRUE(pool.state == pool2.state);
	if (umem)
		io_xdev_ext_umem_put(umem);
	umem = legacy_get(&legacy_ctx);
	EXPECT_TRUE(umem != NULL);
	if (umem)
		io_xdev_ext_umem_put(umem);

	pool.ops->release(&pool);
	pool2.ops->release(&pool2);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&mech_ctx2), 0);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&mech_ctx), 0);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&legacy_ctx), 0);
	EXPECT_EQ(atomic_load(&mm.mm_count), 1);
}

int main(void)
{
	test_legacy_op_refused_after_session_binds();
	test_shared_umem_refuses_legacy_on_other_ring();
	test_session_refused_on_legacy_umem();
	test_separate_umems_keep_both_interfaces();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u checks\n", checks);
	return EXIT_SUCCESS;
}
