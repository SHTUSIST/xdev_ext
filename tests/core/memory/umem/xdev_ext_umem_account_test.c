// SPDX-License-Identifier: GPL-2.0
/*
 * Locked-memory accounting of IORING_REGISTER_XDEV_EXT_UMEM.  The UMEM pins
 * its pages long term (FOLL_LONGTERM), so it must charge them the way
 * io_uring registered buffers do: user->locked_vm against RLIMIT_MEMLOCK
 * unless the ring creator had CAP_IPC_LOCK, plus mm->pinned_vm, and undo
 * exactly that charge when the pins are dropped.  The actual registry code
 * is compiled with kernel primitives shimmed.
 */
#include <stdio.h>

#include "xdev_ext_umem_kernel_shim.h"

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

#define NR_PAGES 4

struct fixture {
	struct io_uring_unified_shared stats;
	struct io_uring_xdev_ext_umem_reg reg;
	struct task_struct task;
	struct mm_struct mm;		/* registering task and ring creator */
	struct user_struct user;	/* ring creator without CAP_IPC_LOCK */
};

static void fixture_init(struct fixture *f, unsigned int id)
{
	memset(f, 0, sizeof(*f));
	f->reg = (struct io_uring_xdev_ext_umem_reg) {
		.addr = UINT64_C(0x200000),
		.size = NR_PAGES * PAGE_SIZE,
		.shared_addr = (uintptr_t)&f->stats,
		.frame_size = PAGE_SIZE,
	};
	atomic_init(&f->mm.mm_count, 1);
	f->mm.id = id;
	atomic_init(&f->user.__count, 1);
	f->task.mm = &f->mm;
	current = &f->task;
	test_memlock_limit = ~0UL;
	test_pin_short = -1;
	test_vmap_fail = false;
}

/* A ring as io_uring_create() leaves it: ctx->user unless CAP_IPC_LOCK. */
static void ring_init(struct io_ring_ctx *ctx, struct fixture *f, bool ipc_lock)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->user = ipc_lock ? NULL : &f->user;
	ctx->mm_account = &f->mm;
}

static long locked(struct fixture *f)
{
	return atomic_load(&f->user.locked_vm);
}

static long long pinned(struct fixture *f)
{
	return atomic64_read(&f->mm.pinned_vm);
}

static bool registry_empty(void)
{
	bool empty;

	mutex_lock(&xdev_ext_umem_lock);
	empty = xdev_ext_umem_list.next == &xdev_ext_umem_list;
	mutex_unlock(&xdev_ext_umem_lock);
	return empty;
}

static void test_register_charges_and_unregister_uncharges(void)
{
	struct io_ring_ctx ctx;
	struct fixture f;

	fixture_init(&f, 10);
	ring_init(&ctx, &f, false);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), 0);
	EXPECT_EQ(locked(&f), NR_PAGES);
	EXPECT_EQ(pinned(&f), NR_PAGES);
	/* The UMEM can outlive the ring, so it holds its own references. */
	EXPECT_EQ(atomic_load(&f.user.__count), 2);

	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), 0);
	EXPECT_EQ(locked(&f), 0);
	EXPECT_EQ(pinned(&f), 0);
	EXPECT_EQ(atomic_load(&f.user.__count), 1);
	EXPECT_EQ(atomic_load(&f.mm.mm_count), 1);
	EXPECT_TRUE(registry_empty());
}

static void test_memlock_limit_refuses_registration(void)
{
	struct io_ring_ctx ctx;
	struct fixture f;

	fixture_init(&f, 11);
	ring_init(&ctx, &f, false);
	test_memlock_limit = (NR_PAGES - 1) * PAGE_SIZE;
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), -ENOMEM);
	EXPECT_TRUE(ctx.xdev_ext_umem == NULL);
	EXPECT_EQ(locked(&f), 0);
	EXPECT_EQ(pinned(&f), 0);
	EXPECT_EQ(atomic_load(&f.user.__count), 1);
	EXPECT_EQ(atomic_load(&f.mm.mm_count), 1);
	EXPECT_TRUE(registry_empty());

	/* The budget is per user: pages it already locked elsewhere count. */
	test_memlock_limit = (NR_PAGES + 1) * PAGE_SIZE;
	atomic_store(&f.user.locked_vm, 2);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), -ENOMEM);
	EXPECT_EQ(locked(&f), 2);
	atomic_store(&f.user.locked_vm, 1);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), 0);
	EXPECT_EQ(locked(&f), 1 + NR_PAGES);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), 0);
	EXPECT_EQ(locked(&f), 1);
	EXPECT_EQ(pinned(&f), 0);
}

static void test_cap_ipc_lock_skips_memlock_but_counts_pinned(void)
{
	struct io_ring_ctx ctx;
	struct fixture f;

	fixture_init(&f, 12);
	ring_init(&ctx, &f, true);
	test_memlock_limit = 0;
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), 0);
	EXPECT_EQ(locked(&f), 0);
	EXPECT_EQ(pinned(&f), NR_PAGES);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), 0);
	EXPECT_EQ(pinned(&f), 0);
	EXPECT_EQ(atomic_load(&f.mm.mm_count), 1);
}

static void test_shared_registration_charges_once(void)
{
	struct io_ring_ctx ctx1, ctx2;
	struct fixture f;

	fixture_init(&f, 13);
	ring_init(&ctx1, &f, false);
	ring_init(&ctx2, &f, false);
	/*
	 * Exactly one UMEM's worth of budget: the second ring shares the
	 * first ring's pins and must not need a second (even transient) charge.
	 */
	test_memlock_limit = NR_PAGES * PAGE_SIZE;
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx1, &f.reg), 0);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx2, &f.reg), 0);
	EXPECT_TRUE(ctx1.xdev_ext_umem == ctx2.xdev_ext_umem);
	EXPECT_EQ(locked(&f), NR_PAGES);
	EXPECT_EQ(pinned(&f), NR_PAGES);

	/* The charge follows the pins, which live until the last reference. */
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx1), 0);
	EXPECT_EQ(locked(&f), NR_PAGES);
	EXPECT_EQ(pinned(&f), NR_PAGES);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx2), 0);
	EXPECT_EQ(locked(&f), 0);
	EXPECT_EQ(pinned(&f), 0);
	EXPECT_EQ(atomic_load(&f.user.__count), 1);
	EXPECT_EQ(atomic_load(&f.mm.mm_count), 1);
}

static void test_double_registration_does_not_charge_twice(void)
{
	struct io_ring_ctx ctx;
	struct fixture f;

	fixture_init(&f, 14);
	ring_init(&ctx, &f, false);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), 0);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), -EBUSY);
	EXPECT_EQ(locked(&f), NR_PAGES);
	EXPECT_EQ(pinned(&f), NR_PAGES);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), 0);
	EXPECT_EQ(locked(&f), 0);
	EXPECT_EQ(pinned(&f), 0);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), -EINVAL);
	EXPECT_EQ(locked(&f), 0);
}

static void test_pin_and_map_failures_leave_no_charge(void)
{
	struct io_ring_ctx ctx;
	struct fixture f;

	fixture_init(&f, 15);
	ring_init(&ctx, &f, false);
	test_pin_short = NR_PAGES - 1;
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), -EFAULT);
	test_pin_short = 0;
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), -EFAULT);
	test_pin_short = -1;
	test_vmap_fail = true;
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), -ENOMEM);
	test_vmap_fail = false;
	EXPECT_TRUE(ctx.xdev_ext_umem == NULL);
	EXPECT_EQ(locked(&f), 0);
	EXPECT_EQ(pinned(&f), 0);
	EXPECT_EQ(atomic_load(&f.user.__count), 1);
	EXPECT_EQ(atomic_load(&f.mm.mm_count), 1);
	EXPECT_TRUE(registry_empty());

	/* After the failures a normal registration charges exactly once. */
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), 0);
	EXPECT_EQ(locked(&f), NR_PAGES);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), 0);
	EXPECT_EQ(locked(&f), 0);
}

static void test_charge_lives_while_operation_holds_umem(void)
{
	struct io_xdev_ext_umem *held;
	struct io_ring_ctx ctx;
	struct fixture f;

	fixture_init(&f, 16);
	ring_init(&ctx, &f, false);
	EXPECT_EQ(io_xdev_ext_umem_register(&ctx, &f.reg), 0);
	held = io_xdev_ext_umem_get_ctx(&ctx);
	EXPECT_TRUE(held != NULL);
	EXPECT_EQ(io_xdev_ext_umem_unregister(&ctx), 0);
	/* Pages stay pinned for the in-flight holder; so does the charge. */
	EXPECT_EQ(locked(&f), NR_PAGES);
	EXPECT_EQ(pinned(&f), NR_PAGES);
	if (held)
		io_xdev_ext_umem_put(held);
	EXPECT_EQ(locked(&f), 0);
	EXPECT_EQ(pinned(&f), 0);
	EXPECT_EQ(atomic_load(&f.user.__count), 1);
	EXPECT_EQ(atomic_load(&f.mm.mm_count), 1);
}

int main(void)
{
	test_register_charges_and_unregister_uncharges();
	test_memlock_limit_refuses_registration();
	test_cap_ipc_lock_skips_memlock_but_counts_pinned();
	test_shared_registration_charges_once();
	test_double_registration_does_not_charge_twice();
	test_pin_and_map_failures_leave_no_charge();
	test_charge_lives_while_operation_holds_umem();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u checks\n", checks);
	return EXIT_SUCCESS;
}
