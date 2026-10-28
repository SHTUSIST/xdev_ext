// SPDX-License-Identifier: GPL-2.0
/*
 * The sharded admission gate.  The first four cases are ExitOS's contract:
 * quiesce closes the gate before it drains, does not return while an admitted
 * caller is inside, a drained gate can be opened again, and one thread may
 * nest.  The rest cover what this front end adds: XDEV_EXT_ADMISSION_SCOPE leaves
 * on every return path, quiesce from inside an admitted section does not wait
 * for itself, a forked child does not wait for threads it does not have, and
 * no caller is ever inside after quiesce returns.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "xdev_ext_preload_admission.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_TRUE(expr) do {                                           \
	checks++;                                                          \
	if (!(expr)) {                                                     \
		fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n",       \
			__FILE__, __LINE__, #expr);                           \
		failures++;                                               \
	}                                                                  \
} while (0)

#define EXPECT_EQ(actual, expected) do {                                \
	long long _actual = (long long)(actual);                          \
	long long _expected = (long long)(expected);                      \
	checks++;                                                          \
	if (_actual != _expected) {                                       \
		fprintf(stderr, "%s:%d: %s=%lld, expected %lld\n",       \
			__FILE__, __LINE__, #actual, _actual, _expected);      \
		failures++;                                               \
	}                                                                  \
} while (0)

static void pause_ms(long ms)
{
	struct timespec pause = {
		.tv_sec = ms / 1000,
		.tv_nsec = (ms % 1000) * 1000000L,
	};

	nanosleep(&pause, NULL);
}

/* Poll flag for up to two seconds. */
static bool wait_for(atomic_bool *flag)
{
	for (unsigned int i = 0; i < 2000; i++) {
		if (atomic_load(flag))
			return true;
		pause_ms(1);
	}
	return atomic_load(flag);
}

/* One admitted caller held inside the gate until released. */
struct holder {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	bool inside;
	bool release;
	bool admitted;
	unsigned int shard_plus_one;
};

static void *hold_admission(void *opaque)
{
	struct holder *h = opaque;
	bool admitted = xdev_ext_admission_enter();

	pthread_mutex_lock(&h->mu);
	h->admitted = admitted;
	h->shard_plus_one = xdev_ext_admission_shard_plus_one;
	h->inside = true;
	pthread_cond_broadcast(&h->cv);
	while (!h->release)
		pthread_cond_wait(&h->cv, &h->mu);
	pthread_mutex_unlock(&h->mu);
	if (admitted)
		xdev_ext_admission_leave();
	return NULL;
}

static void holder_start(struct holder *h, pthread_t *thread)
{
	pthread_mutex_init(&h->mu, NULL);
	pthread_cond_init(&h->cv, NULL);
	h->inside = false;
	h->release = false;
	h->admitted = false;
	if (pthread_create(thread, NULL, hold_admission, h))
		abort();
	pthread_mutex_lock(&h->mu);
	while (!h->inside)
		pthread_cond_wait(&h->cv, &h->mu);
	pthread_mutex_unlock(&h->mu);
}

static void holder_release(struct holder *h, pthread_t thread)
{
	pthread_mutex_lock(&h->mu);
	h->release = true;
	pthread_cond_broadcast(&h->cv);
	pthread_mutex_unlock(&h->mu);
	pthread_join(thread, NULL);
}

static atomic_bool quiesce_done;

static void *run_quiesce(void *unused)
{
	(void)unused;
	xdev_ext_admission_quiesce();
	atomic_store(&quiesce_done, true);
	return NULL;
}

/* ExitOS: closes before it drains, waits for the admitted caller. */
static void test_quiesce_waits_for_admitted_caller(void)
{
	struct holder h;
	pthread_t holder_thread;
	pthread_t quiescer;
	bool observed_closed = false;

	EXPECT_TRUE(!xdev_ext_admission_enter());
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);

	xdev_ext_admission_enable();
	holder_start(&h, &holder_thread);
	EXPECT_TRUE(h.admitted);
	EXPECT_EQ(xdev_ext_admission_inflight(), 1);

	atomic_store(&quiesce_done, false);
	if (pthread_create(&quiescer, NULL, run_quiesce, NULL))
		abort();
	for (unsigned int i = 0; i < 100000; i++) {
		if (!xdev_ext_admission_enter()) {
			observed_closed = true;
			break;
		}
		xdev_ext_admission_leave();
		sched_yield();
	}
	EXPECT_TRUE(observed_closed);
	pause_ms(50);
	EXPECT_TRUE(!atomic_load(&quiesce_done));

	holder_release(&h, holder_thread);
	pthread_join(quiescer, NULL);
	EXPECT_TRUE(atomic_load(&quiesce_done));
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
	EXPECT_TRUE(!xdev_ext_admission_enter());
}

/* ExitOS: a drained gate opens again; one thread may nest. */
static void test_reopen_and_nesting(void)
{
	xdev_ext_admission_enable();
	EXPECT_TRUE(xdev_ext_admission_enter());
	EXPECT_TRUE(xdev_ext_admission_enter());
	EXPECT_EQ(xdev_ext_admission_inflight(), 2);
	xdev_ext_admission_leave();
	EXPECT_EQ(xdev_ext_admission_inflight(), 1);
	xdev_ext_admission_leave();
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
	xdev_ext_admission_quiesce();
	EXPECT_TRUE(!xdev_ext_admission_enter());
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
}

static unsigned int seen_inside;
static bool seen_entered;

static int scope_return_in_if(int x)
{
	XDEV_EXT_ADMISSION_SCOPE(admission);

	seen_entered = admission.entered;
	seen_inside = xdev_ext_admission_inflight();
	if (x > 0)
		return 1;
	return 0;
}

static int scope_return_in_loop(int x)
{
	XDEV_EXT_ADMISSION_SCOPE(admission);

	seen_entered = admission.entered;
	for (int i = 0; i < 10; i++) {
		seen_inside = xdev_ext_admission_inflight();
		if (i == x)
			return i;
	}
	return -1;
}

static int scope_return_in_switch(int x)
{
	XDEV_EXT_ADMISSION_SCOPE(admission);

	seen_entered = admission.entered;
	seen_inside = xdev_ext_admission_inflight();
	switch (x) {
	case 0:
		return 10;
	case 1: {
		int nested = x + 1;

		return nested;
	}
	default:
		break;
	}
	return 0;
}

static int scope_return_through_goto(int x)
{
	XDEV_EXT_ADMISSION_SCOPE(admission);
	int ret = 0;

	seen_entered = admission.entered;
	seen_inside = xdev_ext_admission_inflight();
	if (x)
		goto out;
	ret = 1;
out:
	return ret;
}

static void scope_fall_off_end(void)
{
	XDEV_EXT_ADMISSION_SCOPE(admission);

	seen_entered = admission.entered;
	seen_inside = xdev_ext_admission_inflight();
}

/* An early exit before a blocking wait, and re-entry after it. */
static int scope_exit_and_reenter(int x)
{
	XDEV_EXT_ADMISSION_SCOPE(admission);

	seen_entered = admission.entered;
	xdev_ext_admission_scope_exit(&admission);
	seen_inside = xdev_ext_admission_inflight();
	if (x)
		return 0;
	if (!xdev_ext_admission_scope_reenter(&admission))
		return -1;
	return (int)xdev_ext_admission_inflight();
}

#define EXPECT_SCOPE(call, inside) do {                                 \
	seen_inside = 99;                                                  \
	seen_entered = false;                                              \
	(void)(call);                                                      \
	EXPECT_EQ(seen_inside, (inside));                                  \
	EXPECT_EQ(seen_entered, (inside) != 0);                            \
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);                            \
} while (0)

static void test_scope_leaves_on_every_return_path(void)
{
	xdev_ext_admission_enable();
	EXPECT_SCOPE(scope_return_in_if(1), 1);
	EXPECT_SCOPE(scope_return_in_if(0), 1);
	EXPECT_SCOPE(scope_return_in_loop(3), 1);
	EXPECT_SCOPE(scope_return_in_loop(20), 1);
	EXPECT_SCOPE(scope_return_in_switch(0), 1);
	EXPECT_SCOPE(scope_return_in_switch(1), 1);
	EXPECT_SCOPE(scope_return_in_switch(2), 1);
	EXPECT_SCOPE(scope_return_through_goto(1), 1);
	EXPECT_SCOPE(scope_return_through_goto(0), 1);
	EXPECT_SCOPE(scope_fall_off_end(), 1);

	seen_inside = 99;
	EXPECT_EQ(scope_exit_and_reenter(1), 0);
	EXPECT_EQ(seen_inside, 0);
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
	EXPECT_EQ(scope_exit_and_reenter(0), 1);
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
	xdev_ext_admission_quiesce();

	/* A closed gate admits nothing, and leaving does not underflow. */
	EXPECT_SCOPE(scope_return_in_if(1), 0);
	EXPECT_SCOPE(scope_return_in_loop(3), 0);
	EXPECT_SCOPE(scope_fall_off_end(), 0);
	EXPECT_EQ(scope_exit_and_reenter(0), -1);
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
}

static atomic_bool self_quiesce_done;

static void *quiesce_from_inside(void *unused)
{
	(void)unused;
	if (!xdev_ext_admission_enter() || !xdev_ext_admission_enter())
		return (void *)1;
	/* exit() from a wrapper or a signal handler reaches the destructor here. */
	xdev_ext_admission_quiesce();
	atomic_store(&self_quiesce_done, true);
	xdev_ext_admission_leave();
	xdev_ext_admission_leave();
	return NULL;
}

/* The caller's own admissions do not hold up its quiesce. */
static void test_quiesce_from_inside_does_not_wait_for_itself(void)
{
	pthread_t thread;
	void *result = (void *)1;

	xdev_ext_admission_enable();
	atomic_store(&self_quiesce_done, false);
	if (pthread_create(&thread, NULL, quiesce_from_inside, NULL))
		abort();
	EXPECT_TRUE(wait_for(&self_quiesce_done));
	if (!atomic_load(&self_quiesce_done)) {
		fprintf(stderr, "FAIL: quiesce waited for its own caller\n");
		exit(EXIT_FAILURE);
	}
	pthread_join(thread, &result);
	EXPECT_TRUE(result == NULL);
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
	EXPECT_TRUE(!xdev_ext_admission_enter());
}

struct same_shard {
	unsigned int want;
	atomic_uint got;
	struct holder *other;
	atomic_bool done;
	bool admitted;
};

static void *record_shard(void *opaque)
{
	struct same_shard *s = opaque;

	if (xdev_ext_admission_enter())
		xdev_ext_admission_leave();
	atomic_store(&s->got, xdev_ext_admission_shard_plus_one);
	return NULL;
}

static void *quiesce_beside_other(void *opaque)
{
	struct same_shard *s = opaque;

	s->admitted = xdev_ext_admission_enter();
	atomic_store(&s->got, xdev_ext_admission_shard_plus_one);
	if (atomic_load(&s->got) == s->want) {
		xdev_ext_admission_quiesce();
		atomic_store(&s->done, true);
	}
	if (s->admitted)
		xdev_ext_admission_leave();
	return NULL;
}

/*
 * Only the caller's own admissions are excused: another thread admitted on
 * the same shard is still waited for.
 */
static void test_quiesce_still_waits_for_shard_neighbours(void)
{
	struct same_shard s = { 0 };
	struct holder h;
	pthread_t holder_thread;
	pthread_t thread;
	bool found = false;

	xdev_ext_admission_enable();
	holder_start(&h, &holder_thread);
	EXPECT_TRUE(h.admitted);
	s.want = h.shard_plus_one;
	s.other = &h;
	for (unsigned int i = 0; i < 2 * XDEV_EXT_ADMISSION_SHARDS && !found; i++) {
		struct same_shard probe = { 0 };

		if (pthread_create(&thread, NULL, record_shard, &probe))
			abort();
		pthread_join(thread, NULL);
		/* The next new thread takes the shard after probe's. */
		found = atomic_load(&probe.got) % XDEV_EXT_ADMISSION_SHARDS + 1 ==
			s.want;
	}
	EXPECT_TRUE(found);
	atomic_store(&s.done, false);
	if (pthread_create(&thread, NULL, quiesce_beside_other, &s))
		abort();
	pause_ms(100);
	EXPECT_EQ(atomic_load(&s.got), s.want);
	EXPECT_TRUE(!atomic_load(&s.done));
	holder_release(&h, holder_thread);
	pthread_join(thread, NULL);
	EXPECT_TRUE(atomic_load(&s.done));
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
}

/* A forked child has only the forking thread; it must not wait for others. */
static void test_fork_child_forgets_other_threads(void)
{
	struct holder h;
	pthread_t holder_thread;
	int status = -1;
	pid_t child;

	if (pthread_atfork(NULL, NULL, xdev_ext_admission_after_fork_child))
		abort();
	xdev_ext_admission_enable();
	holder_start(&h, &holder_thread);
	EXPECT_EQ(xdev_ext_admission_inflight(), 1);
	EXPECT_TRUE(xdev_ext_admission_enter());
	child = fork();
	if (!child) {
		/* Only this thread's own admission survives in the child. */
		alarm(5);
		if (xdev_ext_admission_inflight() != 1)
			_exit(2);
		xdev_ext_admission_quiesce();
		xdev_ext_admission_leave();
		if (xdev_ext_admission_inflight() != 0 || xdev_ext_admission_enter())
			_exit(3);
		_exit(0);
	}
	EXPECT_TRUE(child > 0);
	xdev_ext_admission_leave();
	while (waitpid(child, &status, 0) < 0)
		;
	EXPECT_TRUE(WIFEXITED(status));
	EXPECT_EQ(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
	EXPECT_EQ(xdev_ext_admission_inflight(), 1);
	holder_release(&h, holder_thread);
	xdev_ext_admission_quiesce();
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
}

#define STRESS_THREADS (XDEV_EXT_ADMISSION_SHARDS + 8)

static atomic_bool stress_stop;
static atomic_bool stress_quiesced;
static atomic_uint stress_admitted;
static atomic_uint stress_violations;

static void *stress_worker(void *unused)
{
	(void)unused;
	while (!atomic_load(&stress_stop)) {
		if (!xdev_ext_admission_enter()) {
			sched_yield();
			continue;
		}
		atomic_fetch_add(&stress_admitted, 1);
		if (atomic_load(&stress_quiesced))
			atomic_fetch_add(&stress_violations, 1);
		for (volatile int spin = 0; spin < 100; spin++)
			;
		if (atomic_load(&stress_quiesced))
			atomic_fetch_add(&stress_violations, 1);
		xdev_ext_admission_leave();
	}
	return NULL;
}

/* No caller is ever inside after quiesce returns, with shared shards. */
static void test_no_caller_inside_after_quiesce(void)
{
	pthread_t threads[STRESS_THREADS];
	unsigned int before;

	xdev_ext_admission_enable();
	atomic_store(&stress_stop, false);
	atomic_store(&stress_quiesced, false);
	atomic_store(&stress_admitted, 0);
	atomic_store(&stress_violations, 0);
	for (unsigned int i = 0; i < STRESS_THREADS; i++) {
		if (pthread_create(&threads[i], NULL, stress_worker, NULL))
			abort();
	}
	pause_ms(50);
	xdev_ext_admission_quiesce();
	atomic_store(&stress_quiesced, true);
	before = atomic_load(&stress_admitted);
	pause_ms(50);
	atomic_store(&stress_stop, true);
	for (unsigned int i = 0; i < STRESS_THREADS; i++)
		pthread_join(threads[i], NULL);
	EXPECT_TRUE(before > 0);
	EXPECT_EQ(atomic_load(&stress_admitted), before);
	EXPECT_EQ(atomic_load(&stress_violations), 0);
	EXPECT_EQ(xdev_ext_admission_inflight(), 0);
}

int main(void)
{
	test_quiesce_waits_for_admitted_caller();
	test_reopen_and_nesting();
	test_scope_leaves_on_every_return_path();
	test_quiesce_from_inside_does_not_wait_for_itself();
	test_quiesce_still_waits_for_shard_neighbours();
	test_fork_child_forgets_other_threads();
	test_no_caller_inside_after_quiesce();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u admission checks failed\n",
			failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u admission checks\n", checks);
	return EXIT_SUCCESS;
}
