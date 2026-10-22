// SPDX-License-Identifier: GPL-2.0
/* Host tests of the notification contract; no device or io_uring required. */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "include/uapi/linux/xdev_ext_mech.h"
#include "io_uring/xdev_ext_mech_notify.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do { \
	long long a_ = (long long)(actual); \
	long long e_ = (long long)(expected); \
	checks++; \
	if (a_ != e_) { \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n", \
			__FILE__, __LINE__, #actual, a_, e_); \
		failures++; \
	} \
} while (0)
#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

_Static_assert(XDEV_EXT_MECH_OP_NOTIFY_ARM == 5, "new operation is append-only");
_Static_assert(sizeof(struct xdev_ext_mech_notify_arm) == 32, "notify arm size");
_Static_assert(offsetof(struct xdev_ext_mech_notify_arm, session_id) == 0,
	       "session offset");
_Static_assert(offsetof(struct xdev_ext_mech_notify_arm, batches_target) == 8,
	       "finished target offset");
_Static_assert(offsetof(struct xdev_ext_mech_notify_arm, published_target) == 16,
	       "published target offset");
_Static_assert(offsetof(struct xdev_ext_mech_notify_arm, flags) == 24,
	       "flags offset");
_Static_assert(offsetof(struct xdev_ext_mech_notify_arm, rsvd) == 28,
	       "reserved offset");

static void test_validate(void)
{
	struct xdev_ext_mech_notify_arm arm = { .session_id = 17 };
	struct xdev_ext_mech_notify_arm before;

	EXPECT_EQ(xdev_ext_mech_notify_validate(&arm), -EINVAL);
	arm.batches_target = 1;
	EXPECT_EQ(xdev_ext_mech_notify_validate(&arm), 0);
	arm.session_id = 0;
	EXPECT_EQ(xdev_ext_mech_notify_validate(&arm), -EINVAL);
	arm.session_id = 17;
	arm.batches_target = 0;
	arm.published_target = 1;
	EXPECT_EQ(xdev_ext_mech_notify_validate(&arm), 0);
	arm.batches_target = UINT64_MAX;
	arm.published_target = UINT64_MAX;
	before = arm;
	EXPECT_EQ(xdev_ext_mech_notify_validate(&arm), 0);
	EXPECT_EQ(memcmp(&arm, &before, sizeof(arm)), 0);
	for (unsigned int bit = 0; bit < 32; bit++) {
		arm = before;
		arm.flags = 1U << bit;
		EXPECT_EQ(xdev_ext_mech_notify_validate(&arm), -EINVAL);
		arm = before;
		arm.rsvd = 1U << bit;
		EXPECT_EQ(xdev_ext_mech_notify_validate(&arm), -EINVAL);
	}
}

static void test_absolute_targets(void)
{
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = 17, .batches_target = 8,
	};

	EXPECT_FALSE(xdev_ext_mech_notify_reached(&arm, 0, 0,
					   XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	EXPECT_FALSE(xdev_ext_mech_notify_reached(&arm, 7, UINT64_MAX,
					   XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	EXPECT_TRUE(xdev_ext_mech_notify_reached(&arm, 8, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	EXPECT_TRUE(xdev_ext_mech_notify_reached(&arm, 9, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	arm.batches_target = 0;
	arm.published_target = 12;
	EXPECT_FALSE(xdev_ext_mech_notify_reached(&arm, UINT64_MAX, 11,
					   XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	EXPECT_TRUE(xdev_ext_mech_notify_reached(&arm, 0, 12,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	EXPECT_TRUE(xdev_ext_mech_notify_reached(&arm, 0, 13,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	arm.batches_target = UINT64_MAX;
	arm.published_target = UINT64_MAX;
	EXPECT_FALSE(xdev_ext_mech_notify_reached(&arm, UINT64_MAX - 1, UINT64_MAX,
					   XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	EXPECT_TRUE(xdev_ext_mech_notify_reached(&arm, UINT64_MAX, UINT64_MAX,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0));
}

static void test_targets_are_anded(void)
{
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = 17, .batches_target = 8, .published_target = 12,
	};

	for (__u64 finished = 7; finished <= 9; finished++)
		for (__u64 published = 11; published <= 13; published++)
			EXPECT_EQ(xdev_ext_mech_notify_reached(&arm, finished, published,
						 XDEV_EXT_MECH_SESSION_ACTIVE, 0),
				  finished >= 8 && published >= 12);
}

static void test_early_failure_and_stop(void)
{
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = 17, .batches_target = 8, .published_target = 12,
	};
	const __u32 terminal[] = {
		XDEV_EXT_MECH_SESSION_ERROR, XDEV_EXT_MECH_SESSION_STOPPING,
		XDEV_EXT_MECH_SESSION_STOPPED, XDEV_EXT_MECH_SESSION_ZOMBIE,
	};

	EXPECT_TRUE(xdev_ext_mech_notify_reached(&arm, 0, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, -EIO));
	EXPECT_TRUE(xdev_ext_mech_notify_reached(&arm, 0, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, -ECANCELED));
	for (unsigned int i = 0; i < sizeof(terminal) / sizeof(terminal[0]); i++)
		EXPECT_TRUE(xdev_ext_mech_notify_reached(&arm, 0, 0, terminal[i], 0));
	/* No accepted batch is in flight before START or between RX arrivals.
	 * Neither an idle receiver nor a pre-START session has finished its run.
	 */
	EXPECT_FALSE(xdev_ext_mech_notify_reached(&arm, 0, 0,
					   XDEV_EXT_MECH_SESSION_NONE, 0));
	EXPECT_FALSE(xdev_ext_mech_notify_reached(&arm, 0, 0,
					   XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	EXPECT_FALSE(xdev_ext_mech_notify_reached(&arm, 7, 11,
					   XDEV_EXT_MECH_SESSION_ACTIVE, 0));
	EXPECT_FALSE(xdev_ext_mech_notify_reached(&arm, 0, 0, 99, 0));
}

/* These state helpers are used under the same external lock as the counters.
 * A true return means emit one eventfd signal after publishing the results.
 * legacy_event distinguishes a finished legacy batch from a status check.
 */
static void test_legacy_and_exactly_once_modes(void)
{
	struct xdev_ext_mech_notify_state notify;
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = 17, .batches_target = 8, .published_target = 12,
	};

	xdev_ext_mech_notify_init(&notify);
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 0, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0, false));
	/* Repeated legacy completion decisions must each emit their own count. */
	for (__u64 finished = 1; finished <= 3; finished++)
		EXPECT_TRUE(xdev_ext_mech_notify_signal(&notify, finished, 0,
						 XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &arm), 0);
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 7, 12,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 8, 11,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_TRUE(xdev_ext_mech_notify_signal(&notify, 8, 12,
					 XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	/* Firing consumes this arm, but coarse mode survives subsequent batches,
	 * status checks, and terminal transitions until an explicit re-arm.
	 */
	for (unsigned int i = 0; i < 8; i++)
		EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 9 + i, 13 + i,
						  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 16, 20,
					  XDEV_EXT_MECH_SESSION_STOPPED, -ECANCELED, true));
	arm.batches_target = 20;
	arm.published_target = 24;
	EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &arm), 0);
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 19, 24,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_TRUE(xdev_ext_mech_notify_signal(&notify, 20, 24,
					 XDEV_EXT_MECH_SESSION_ACTIVE, 0, false));
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 20, 24,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0, false));
}

static void test_invalid_rearm_preserves_pending_arm(void)
{
	struct xdev_ext_mech_notify_state notify;
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = 17, .batches_target = 8,
	};
	struct xdev_ext_mech_notify_arm invalid = {
		.session_id = 17, .batches_target = 1, .flags = 1,
	};

	xdev_ext_mech_notify_init(&notify);
	/* A refused first arm cannot accidentally enable coarse mode. */
	EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &invalid), -EINVAL);
	EXPECT_TRUE(xdev_ext_mech_notify_signal(&notify, 1, 0,
					 XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &arm), 0);
	EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &invalid), -EINVAL);
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 7, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_TRUE(xdev_ext_mech_notify_signal(&notify, 8, 0,
					 XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &invalid), -EINVAL);
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 9, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
}

static void test_arm_keeps_its_target_snapshot(void)
{
	struct xdev_ext_mech_notify_state notify;
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = 17, .batches_target = 8,
	};

	xdev_ext_mech_notify_init(&notify);
	EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &arm), 0);
	/* Registration takes a value; later caller edits are not a re-arm. */
	arm.batches_target = 1;
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 1, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	EXPECT_TRUE(xdev_ext_mech_notify_signal(&notify, 8, 0,
					 XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
}

static void test_early_terminal_signal_once(void)
{
	const __u32 terminal[] = {
		XDEV_EXT_MECH_SESSION_ERROR, XDEV_EXT_MECH_SESSION_STOPPING,
		XDEV_EXT_MECH_SESSION_STOPPED, XDEV_EXT_MECH_SESSION_ZOMBIE,
	};
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = 17, .batches_target = 8,
	};
	struct xdev_ext_mech_notify_state notify;

	for (unsigned int i = 0; i < sizeof(terminal) / sizeof(terminal[0]); i++) {
		xdev_ext_mech_notify_init(&notify);
		EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &arm), 0);
		EXPECT_TRUE(xdev_ext_mech_notify_signal(&notify, 0, 0, terminal[i],
						 0, false));
		EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 0, 0, terminal[i],
						  0, false));
		EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 1, 0,
						  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
	}
	xdev_ext_mech_notify_init(&notify);
	EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &arm), 0);
	EXPECT_TRUE(xdev_ext_mech_notify_signal(&notify, 0, 0,
					 XDEV_EXT_MECH_SESSION_ACTIVE, -EIO, false));
	EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, 0, 0,
					  XDEV_EXT_MECH_SESSION_ACTIVE, -EIO, false));
}

static void test_arm_completion_serialization_model(void)
{
	struct xdev_ext_mech_notify_arm arm = {
		.session_id = 17, .batches_target = 8, .published_target = 12,
	};

	/* Enumerate arm before, between, and after two serialized counter
	 * updates. Their order is also varied. Registration checks the same
	 * counters immediately after arming while holding the decision lock.
	 * Counting only the opt-in interval, every interleaving emits once.
	 */
	for (unsigned int arm_at = 0; arm_at <= 2; arm_at++) {
		for (unsigned int publish_first = 0; publish_first <= 1;
		     publish_first++) {
			struct xdev_ext_mech_notify_state notify;
			__u64 finished = 7, published = 11;
			unsigned int signals = 0;
			bool armed = false;

			xdev_ext_mech_notify_init(&notify);
			for (unsigned int pos = 0; pos <= 2; pos++) {
				if (pos == arm_at) {
					EXPECT_EQ(xdev_ext_mech_notify_arm(&notify, &arm), 0);
					armed = true;
					signals += xdev_ext_mech_notify_signal(&notify, finished,
						published, XDEV_EXT_MECH_SESSION_ACTIVE, 0, false);
				}
				if (pos == 2)
					break;
				if (pos == publish_first)
					finished++;
				else
					published++;
				if (armed)
					signals += xdev_ext_mech_notify_signal(&notify, finished,
						published, XDEV_EXT_MECH_SESSION_ACTIVE, 0, true);
			}
			EXPECT_EQ(signals, 1);
			EXPECT_FALSE(xdev_ext_mech_notify_signal(&notify, finished, published,
							  XDEV_EXT_MECH_SESSION_ACTIVE, 0, true));
		}
	}
}

int main(void)
{
	test_validate();
	test_absolute_targets();
	test_targets_are_anded();
	test_early_failure_and_stop();
	test_legacy_and_exactly_once_modes();
	test_invalid_rearm_preserves_pending_arm();
	test_arm_keeps_its_target_snapshot();
	test_early_terminal_signal_once();
	test_arm_completion_serialization_model();
	if (failures) {
		fprintf(stderr, "FAIL: %u of %u notification checks\n", failures,
			checks);
		return 1;
	}
	printf("PASS: %u notification checks\n", checks);
	return 0;
}
