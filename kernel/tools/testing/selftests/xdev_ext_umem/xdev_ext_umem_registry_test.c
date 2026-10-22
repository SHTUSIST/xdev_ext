// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <unistd.h>

#include "xdev_ext_umem_kernel_shim.h"

/* Exercise the actual registry implementation with kernel primitives shimmed. */
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

static struct io_uring_xdev_ext_umem_reg test_reg(u64 shared_addr)
{
	return (struct io_uring_xdev_ext_umem_reg) {
		.addr = UINT64_C(0x100000),
		.size = PAGE_SIZE,
		.shared_addr = shared_addr,
		.frame_size = PAGE_SIZE,
	};
}

static void init_mm(struct mm_struct *mm, unsigned int id)
{
	atomic_init(&mm->mm_count, 1);
	mm->id = id;
}

static void use_mm(struct task_struct *task, struct mm_struct *mm)
{
	task->mm = mm;
	current = task;
}

static void test_same_va_in_different_mm_does_not_alias(void)
{
	struct io_uring_unified_shared stats1 = { .marker = 1 };
	struct io_uring_unified_shared stats2 = { .marker = 2 };
	struct io_uring_xdev_ext_umem_reg reg1 = test_reg((uintptr_t)&stats1);
	struct io_uring_xdev_ext_umem_reg reg2 = test_reg((uintptr_t)&stats2);
	struct io_ring_ctx ctx1 = {};
	struct io_ring_ctx ctx2 = {};
	struct task_struct task = {};
	struct mm_struct mm1;
	struct mm_struct mm2;

	init_mm(&mm1, 1);
	init_mm(&mm2, 2);
	use_mm(&task, &mm1);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx1, &reg1), 0);
	use_mm(&task, &mm2);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx2, &reg2), 0);
	EXPECT_TRUE(ctx1.xdev_ext_umem != ctx2.xdev_ext_umem);
	EXPECT_TRUE(ctx1.xdev_ext_umem->mm == &mm1);
	EXPECT_TRUE(ctx2.xdev_ext_umem->mm == &mm2);
	EXPECT_EQ(atomic_load(&mm1.mm_count), 2);
	EXPECT_EQ(atomic_load(&mm2.mm_count), 2);

	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx2), 0);
	use_mm(&task, &mm1);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx1), 0);
	EXPECT_EQ(atomic_load(&mm1.mm_count), 1);
	EXPECT_EQ(atomic_load(&mm2.mm_count), 1);
}

static void test_same_mm_shares_pages_but_not_stats_pointer(void)
{
	struct io_uring_unified_shared stats1 = { .marker = 1 };
	struct io_uring_unified_shared stats2 = { .marker = 2 };
	struct io_uring_xdev_ext_umem_reg reg1 = test_reg((uintptr_t)&stats1);
	struct io_uring_xdev_ext_umem_reg reg2 = test_reg((uintptr_t)&stats2);
	struct io_ring_ctx ctx1 = {};
	struct io_ring_ctx ctx2 = {};
	struct io_uring_unified_shared *observed_stats;
	struct io_xdev_ext_umem *held;
	struct task_struct task = {};
	struct mm_struct mm;

	init_mm(&mm, 3);
	use_mm(&task, &mm);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx1, &reg1), 0);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx2, &reg2), 0);
	EXPECT_TRUE(ctx1.xdev_ext_umem == ctx2.xdev_ext_umem);
	EXPECT_TRUE(ctx1.xdev_ext_umem_shared == &stats1);
	EXPECT_TRUE(ctx2.xdev_ext_umem_shared == &stats2);
	EXPECT_EQ(atomic_load(&mm.mm_count), 2);
	held = io_xdev_ext_umem_get_ctx_with_stats(&ctx1, &observed_stats);
	EXPECT_TRUE(held == ctx1.xdev_ext_umem);
	EXPECT_TRUE(observed_stats == &stats1);
	io_xdev_ext_umem_put(held);
	held = io_xdev_ext_umem_get_ctx_with_stats(&ctx2, &observed_stats);
	EXPECT_TRUE(held == ctx2.xdev_ext_umem);
	EXPECT_TRUE(observed_stats == &stats2);
	io_xdev_ext_umem_put(held);

	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx1), 0);
	EXPECT_TRUE(ctx1.xdev_ext_umem_shared == NULL);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx2), 0);
	EXPECT_EQ(atomic_load(&mm.mm_count), 1);
}

static void test_same_mm_same_va_after_remap_does_not_alias(void)
{
	struct io_uring_xdev_ext_umem_reg reg1 = test_reg(0);
	struct io_uring_xdev_ext_umem_reg reg2 = test_reg(0);
	struct io_ring_ctx ctx1 = {};
	struct io_ring_ctx ctx2 = {};
	struct task_struct task = {};
	struct mm_struct mm;

	init_mm(&mm, 30);
	use_mm(&task, &mm);
	atomic_store(&test_page_generation, 1);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx1, &reg1), 0);

	/* The first long-term pin remains alive while the process replaces the
	 * mapping at the same numeric VA.  A later ring must pin and identify the
	 * new pages instead of inheriting the old ring's DMA target. */
	atomic_store(&test_page_generation, 2);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx2, &reg2), 0);
	EXPECT_TRUE(ctx1.xdev_ext_umem != ctx2.xdev_ext_umem);
	EXPECT_TRUE(ctx1.xdev_ext_umem->pages[0] != ctx2.xdev_ext_umem->pages[0]);
	EXPECT_EQ(atomic_load(&mm.mm_count), 3);

	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx1), 0);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx2), 0);
	EXPECT_EQ(atomic_load(&mm.mm_count), 1);
	atomic_store(&test_page_generation, 0);
}

struct unregister_args {
	struct io_ring_ctx *ctx;
	struct task_struct *task;
	int ret;
};

static void *unregister_thread(void *opaque)
{
	struct unregister_args *args = opaque;

	current = args->task;
	args->ret = io_xdev_ext_umem_unregister(args->ctx);
	return NULL;
}

struct register_args {
	struct io_ring_ctx *ctx;
	struct io_uring_xdev_ext_umem_reg *reg;
	struct task_struct *task;
	atomic_bool started;
	atomic_bool finished;
	int ret;
};

static void *register_thread(void *opaque)
{
	struct register_args *args = opaque;

	current = args->task;
	atomic_store(&args->started, true);
	args->ret = io_xdev_ext_umem_register(args->ctx, args->reg);
	atomic_store(&args->finished, true);
	return NULL;
}

static void wait_until(atomic_bool *value)
{
	while (!atomic_load(value))
		sched_yield();
}

static void test_final_put_cannot_be_resurrected_by_register(void)
{
	struct io_uring_unified_shared stats1 = { .marker = 1 };
	struct io_uring_unified_shared stats2 = { .marker = 2 };
	struct io_uring_xdev_ext_umem_reg reg1 = test_reg((uintptr_t)&stats1);
	struct io_uring_xdev_ext_umem_reg reg2 = test_reg((uintptr_t)&stats2);
	struct io_ring_ctx ctx1 = {};
	struct io_ring_ctx ctx2 = {};
	struct task_struct task1 = {};
	struct task_struct task2 = {};
	struct unregister_args put_args = { .ctx = &ctx1, .task = &task1 };
	struct register_args get_args = {
		.ctx = &ctx2,
		.reg = &reg2,
		.task = &task2,
	};
	struct io_xdev_ext_umem *retiring;
	struct mm_struct mm;
	pthread_t put_thread;
	pthread_t get_thread;

	init_mm(&mm, 4);
	use_mm(&task1, &mm);
	task2.mm = &mm;
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx1, &reg1), 0);
	retiring = ctx1.xdev_ext_umem;

	pthread_mutex_lock(&test_pause_lock);
	test_pause_enabled = true;
	test_put_paused = false;
	test_put_holds_registry_lock = false;
	test_continue_put = false;
	test_pause_ref = &retiring->refcount;
	pthread_mutex_unlock(&test_pause_lock);

	EXPECT_EQ(pthread_create(&put_thread, NULL, unregister_thread, &put_args), 0);
	pthread_mutex_lock(&test_pause_lock);
	while (!test_put_paused)
		pthread_cond_wait(&test_pause_cond, &test_pause_lock);
	pthread_mutex_unlock(&test_pause_lock);

	atomic_init(&get_args.started, false);
	atomic_init(&get_args.finished, false);
	EXPECT_EQ(pthread_create(&get_thread, NULL, register_thread, &get_args), 0);
	wait_until(&get_args.started);

	/* The old decrement-then-lock path lets this registration finish by
	 * incrementing zero.  The fixed path holds the registry lock here. */
	if (!test_put_holds_registry_lock)
		wait_until(&get_args.finished);

	pthread_mutex_lock(&test_pause_lock);
	test_continue_put = true;
	pthread_cond_broadcast(&test_pause_cond);
	pthread_mutex_unlock(&test_pause_lock);

	EXPECT_EQ(pthread_join(put_thread, NULL), 0);
	EXPECT_EQ(pthread_join(get_thread, NULL), 0);
	EXPECT_EQ(put_args.ret, 0);
	EXPECT_EQ(get_args.ret, 0);
	EXPECT_TRUE(ctx2.xdev_ext_umem != retiring);
	mutex_lock(&xdev_ext_umem_lock);
	EXPECT_TRUE(xdev_ext_umem_find_locked(&mm, reg2.addr, reg2.size,
					 PAGE_SIZE, ctx2.xdev_ext_umem->pages,
					 ctx2.xdev_ext_umem->nr_pages) == ctx2.xdev_ext_umem);
	mutex_unlock(&xdev_ext_umem_lock);

	test_pause_enabled = false;
	test_pause_ref = NULL;
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx2), 0);
}

struct inflight_args {
	struct io_ring_ctx *ctx;
	struct io_xdev_ext_umem *umem;
	struct io_uring_unified_shared *stats;
	atomic_bool acquired;
	atomic_bool release;
};

static void *inflight_thread(void *opaque)
{
	struct inflight_args *args = opaque;

	args->umem = io_xdev_ext_umem_get_ctx_with_stats(args->ctx, &args->stats);
	atomic_store(&args->acquired, true);
	while (!atomic_load(&args->release))
		sched_yield();
	if (args->umem)
		io_xdev_ext_umem_put(args->umem);
	return NULL;
}

static void test_unregister_and_inflight_release_once(void)
{
	struct io_uring_unified_shared stats = { .marker = 1 };
	struct io_uring_xdev_ext_umem_reg reg = test_reg((uintptr_t)&stats);
	struct io_ring_ctx ctx = {};
	struct task_struct task = {};
	struct inflight_args args = { .ctx = &ctx };
	struct mm_struct mm;
	pthread_t thread;

	init_mm(&mm, 5);
	use_mm(&task, &mm);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &reg), 0);
	test_watched_umem = ctx.xdev_ext_umem;
	atomic_store(&test_watched_free_count, 0);
	atomic_init(&args.acquired, false);
	atomic_init(&args.release, false);
	EXPECT_EQ(pthread_create(&thread, NULL, inflight_thread, &args), 0);
	wait_until(&args.acquired);
	EXPECT_TRUE(args.umem == test_watched_umem);
	EXPECT_TRUE(args.stats == &stats);

	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), 0);
	EXPECT_TRUE(ctx.xdev_ext_umem == NULL);
	EXPECT_TRUE(ctx.xdev_ext_umem_shared == NULL);
	EXPECT_EQ(atomic_load(&test_watched_free_count), 0);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), -EINVAL);
	atomic_store(&args.release, true);
	EXPECT_EQ(pthread_join(thread, NULL), 0);
	EXPECT_EQ(atomic_load(&test_watched_free_count), 1);
	EXPECT_EQ(atomic_load(&mm.mm_count), 1);

	test_watched_umem = NULL;
	free(args.umem);
}

int main(void)
{
	test_same_va_in_different_mm_does_not_alias();
	test_same_mm_shares_pages_but_not_stats_pointer();
	test_same_mm_same_va_after_remap_does_not_alias();
	test_final_put_cannot_be_resurrected_by_register();
	test_unregister_and_inflight_release_once();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u checks\n", checks);
	return EXIT_SUCCESS;
}
