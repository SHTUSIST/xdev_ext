// SPDX-License-Identifier: GPL-2.0
/*
 * Host test of the single-owner command state machine of the native SPDK
 * pipeline (spdk_owner.h).  No SPDK, device or DMA: it checks the rules that
 * decide when a command's memory may be reused or released.
 *
 *   cc -std=c11 -Wall -Wextra -Werror test_owner.c -o test_owner && ./test_owner
 */
#include <errno.h>
#include <stdio.h>

#include "spdk_owner.h"

static int failures, checks;

#define CHECK(cond) do {						\
	checks++;							\
	if (!(cond)) {							\
		failures++;						\
		fprintf(stderr, "not ok %d - %s:%d %s\n", checks, __func__,	\
			__LINE__, #cond);					\
	}								\
} while (0)

static void accepted_exactly_once(void)
{
	struct sp_owner o;

	sp_init(&o);
	CHECK(sp_submit(&o, 0) == 0);
	CHECK(o.state == SP_SUBMITTED);
	CHECK(o.accepted == 1);
	/* A second submission while one is accepted is refused, never replayed. */
	CHECK(sp_submit(&o, 0) == -EBUSY);
	CHECK(o.accepted == 1);
	CHECK(!sp_can_release(&o));
}

static void rejected_submission_is_not_accepted(void)
{
	struct sp_owner o;

	sp_init(&o);
	CHECK(sp_submit(&o, -ENOMEM) == -ENOMEM);
	CHECK(o.state == SP_IDLE);
	CHECK(o.accepted == 0);
	CHECK(sp_can_release(&o));
}

static void healthy_success_completes(void)
{
	struct sp_owner o;

	sp_init(&o);
	CHECK(!sp_submit(&o, 0));
	sp_on_callback(&o, false);
	CHECK(o.state == SP_SUBMITTED);	/* nothing decided inside the callback */
	sp_after_poll(&o, 1, true);
	CHECK(o.state == SP_COMPLETED_OK);
	CHECK(sp_can_release(&o));
	CHECK(sp_next(&o) == 0);
	CHECK(o.state == SP_IDLE);
	CHECK(!sp_submit(&o, 0));
	CHECK(o.accepted == 2);
}

static void healthy_error_is_final(void)
{
	struct sp_owner o;

	sp_init(&o);
	CHECK(!sp_submit(&o, 0));
	sp_on_callback(&o, true);
	sp_after_poll(&o, 1, true);
	CHECK(o.state == SP_COMPLETED_ERROR);
	CHECK(sp_can_release(&o));
	CHECK(sp_next(&o) == -EIO);
	CHECK(o.state == SP_COMPLETED_ERROR);
}

static void failed_poll_is_not_proof(void)
{
	struct sp_owner o;

	sp_init(&o);
	CHECK(!sp_submit(&o, 0));
	sp_after_poll(&o, -ENXIO, false);
	CHECK(o.state == SP_SUBMITTED);
	CHECK(o.transport_failed);
	CHECK(!sp_can_release(&o));
	sp_on_deadline(&o);
	CHECK(o.state == SP_UNKNOWN);
	CHECK(!sp_can_release(&o));
	CHECK(sp_submit(&o, 0) == -EBUSY);
}

static void manual_completion_on_failed_transport_is_unknown(void)
{
	struct sp_owner o;

	sp_init(&o);
	CHECK(!sp_submit(&o, 0));
	/* The library completes the request in software while failing the qpair. */
	sp_on_callback(&o, true);
	sp_after_poll(&o, -ENXIO, false);
	CHECK(o.state == SP_UNKNOWN);
	CHECK(!sp_can_release(&o));
	/* A failed transport stays unproven, whatever arrives later. */
	sp_on_callback(&o, false);
	sp_after_poll(&o, 1, true);
	CHECK(o.state == SP_UNKNOWN);
	CHECK(!sp_can_release(&o));
}

static void late_healthy_completion_proves_quiescence(void)
{
	struct sp_owner o;

	sp_init(&o);
	CHECK(!sp_submit(&o, 0));
	sp_after_poll(&o, 0, true);
	sp_on_deadline(&o);
	CHECK(o.state == SP_UNKNOWN);
	sp_on_callback(&o, true);	/* e.g. aborted by request */
	sp_after_poll(&o, 1, true);
	CHECK(o.state == SP_COMPLETED_ERROR);
	CHECK(o.late);
	CHECK(sp_can_release(&o));
	CHECK(sp_next(&o) == -EIO);
}

static void late_success_is_still_a_failed_run(void)
{
	struct sp_owner o;

	sp_init(&o);
	CHECK(!sp_submit(&o, 0));
	sp_on_deadline(&o);
	sp_on_callback(&o, false);
	sp_after_poll(&o, 1, true);
	CHECK(o.state == SP_COMPLETED_OK);
	CHECK(o.late);
	CHECK(sp_can_release(&o));
	CHECK(sp_next(&o) == -ETIMEDOUT);
}

static void spurious_callback_is_flagged(void)
{
	struct sp_owner o;

	sp_init(&o);
	sp_on_callback(&o, false);
	sp_after_poll(&o, 1, true);
	CHECK(o.spurious);
	CHECK(o.state == SP_IDLE);
	CHECK(sp_submit(&o, 0) == -EPROTO);
}

static void deadline_without_command_is_harmless(void)
{
	struct sp_owner o;

	sp_init(&o);
	sp_on_deadline(&o);
	CHECK(o.state == SP_IDLE);
	CHECK(sp_can_release(&o));
}

int main(void)
{
	accepted_exactly_once();
	rejected_submission_is_not_accepted();
	healthy_success_completes();
	healthy_error_is_final();
	failed_poll_is_not_proof();
	manual_completion_on_failed_transport_is_unknown();
	late_healthy_completion_proves_quiescence();
	late_success_is_still_a_failed_run();
	spurious_callback_is_flagged();
	deadline_without_command_is_harmless();
	printf("%s %d/%d owner checks\n", failures ? "FAIL" : "PASS", checks - failures, checks);
	return failures ? 1 : 0;
}
