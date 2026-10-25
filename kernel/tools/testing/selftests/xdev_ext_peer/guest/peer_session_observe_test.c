// SPDX-License-Identifier: GPL-2.0
/* Host-only regression for the guest driver's bounded STATS observation.
 * Only syscall/usleep boundaries are replaced; no device is opened or created.
 */
#define syscall observe_test_syscall
#define usleep observe_test_usleep
#define main peer_session_guest_main
#include "peer_session_e2e.c"
#undef main
#undef usleep
#undef syscall
#include <stdarg.h>

static unsigned int reads, sleeps, creates;
static int scenario;
static struct session reclaim = {.ring = 77};

long observe_test_syscall(long number, ...)
{
	struct io_uring_xdev_ext_mech *req;
	struct xdev_ext_mech_stats *st;

	va_list args;
	va_start(args, number);
	int ring = va_arg(args, int);
	(void)va_arg(args, int);
	req = va_arg(args, struct io_uring_xdev_ext_mech *);
	va_end(args);
	if (number != __NR_io_uring_register)
		abort();
	if (req->op == XDEV_EXT_MECH_OP_CREATE && scenario >= 10) {
		if (ring != reclaim.ring || req->arg != (uintptr_t)&reclaim.c)
			abort();
		creates++;
		if (scenario == 10 && creates == 3)
			return 0;
		errno = scenario == 12 ? EINVAL : EBUSY;
		return -1;
	}
	if (req->op != XDEV_EXT_MECH_OP_STATS)
		abort();
	st = (void *)(uintptr_t)req->arg;
	st->state = XDEV_EXT_MECH_SESSION_ACTIVE;
	reads++;
	if (scenario == 1 && reads >= 3) {
		st->inflight = 4;
		st->submitted[0] = 4;
	} else if (scenario == 2) {
		st->batches_done = STOPRUN.groups;
		st->submitted[0] = st->completed[0] = STOPRUN.groups;
		st->submitted[1] = st->completed[1] = STOPRUN.groups;
	} else if (scenario == 3) {
		st->inflight = 4;
		st->submitted[0] = 4;
		st->completed[0] = reads == 1 ? 5 : 3;
	} else if (scenario == 4) {
		st->inflight = 4;
		st->submitted[0] = st->completed[0] = 4;
		st->submitted[1] = 2;
		st->completed[1] = 1;
	}
	return 0;
}

int observe_test_usleep(useconds_t usec)
{
	(void)usec;
	sleeps++;
	return 0;
}

int main(void)
{
	struct xdev_ext_mech_stats st;
	int ret;

	scenario = 1;
	ret = wait_native_inflight(7, 99, &STOPRUN, &st);
	if (ret || reads != 3 || sleeps != 2 || st.submitted[0] != 4 || !st.inflight)
		return 1;
	puts("PASS zero native submissions are polled past before observing producer work");
	scenario = 2; reads = sleeps = 0;
	if (!wait_native_inflight(7, 99, &STOPRUN, &st) || reads != 1 || sleeps)
		return 2;
	puts("PASS already completed START is not teardown-inflight coverage");
	scenario = 3; reads = sleeps = 0;
	if (wait_native_inflight(7, 99, &STOPRUN, &st) || reads != 2 || sleeps != 1)
		return 3;
	puts("PASS inconsistent native counter snapshot is retried");
	scenario = 4; reads = sleeps = 0;
	if (wait_native_inflight(7, 99, &STOPRUN, &st) || reads != 1 || sleeps)
		return 4;
	puts("PASS consumer-only native work is accepted");
	scenario = 0; reads = sleeps = 0;
	if (!wait_native_inflight(7, 99, &STOPRUN, &st) || reads < 2 || reads > 6000 || sleeps > 6000)
		return 5;
	puts("PASS no native submission fails after bounded polling");
	scenario = 10; creates = sleeps = 0;
	if (retry_create_busy(&reclaim, -EBUSY) || creates != 3 || sleeps != 3)
		return 6;
	puts("PASS delayed claim release retries CREATE with the same ring and request");
	scenario = 11; creates = sleeps = 0;
	if (retry_create_busy(&reclaim, -EBUSY) != -EBUSY || creates != 6000 || sleeps != 6000)
		return 7;
	puts("PASS unreleased claim fails after bounded CREATE retries");
	scenario = 12; creates = sleeps = 0;
	if (retry_create_busy(&reclaim, -EBUSY) != -EINVAL || creates != 1 || sleeps != 1)
		return 8;
	puts("PASS a non-EBUSY CREATE error immediately ends retries");
	creates = sleeps = 0;
	if (retry_create_busy(&reclaim, 0) || creates || sleeps ||
	    retry_create_busy(&reclaim, -EINVAL) != -EINVAL || creates || sleeps)
		return 9;
	puts("PASS first CREATE success or non-EBUSY error is never retried");
	return 0;
}
