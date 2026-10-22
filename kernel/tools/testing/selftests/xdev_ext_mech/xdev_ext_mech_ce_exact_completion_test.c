// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"

static unsigned int checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; \
	fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void rejected_success(bool submitted, __u64 bytes)
{
	struct xdev_ext_mech_life frame;
	__u64 token;
	int status, err;
	__u32 outcome;
	bool quarantine;

	xdev_ext_mech_life_init(&frame);
	CHECK(xdev_ext_mech_life_begin_produce(&frame, false, &token) == 0);
	status = xdev_ext_ce_completion_status(0, submitted, bytes, 8192);
	CHECK(status == -EIO);
	outcome = xdev_ext_ce_classify(status, submitted);
	CHECK(outcome != XDEV_EXT_CE_OK);
	quarantine = xdev_ext_ce_disposition(outcome, status, &err);
	CHECK(quarantine == submitted);
	CHECK(err != 0);
	/* The success publication branch must never become reachable. */
	if (outcome == XDEV_EXT_CE_OK)
		CHECK(xdev_ext_mech_life_publish(&frame, token, 8192) == 0);
	CHECK(xdev_ext_mech_life_phase(&frame) == XDEV_EXT_MECH_L_IO_PENDING);
	CHECK(frame.valid_len == 0);
}

int main(void)
{
	static const int statuses[] = { -EIO, -ENODEV, -ETIMEDOUT, 7, 4096 };
	static const __u64 lengths[] = { 0, 1, 8191, 8192, 8193, UINT64_MAX };

	for (unsigned int i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++)
		for (unsigned int j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++)
			for (unsigned int hw = 0; hw < 2; hw++)
				CHECK(xdev_ext_ce_completion_status(statuses[i], hw,
					lengths[j], 8192) == statuses[i]);
	CHECK(xdev_ext_ce_completion_status(0, true, 8192, 8192) == 0);
	CHECK(xdev_ext_ce_completion_status(0, true, UINT64_MAX, UINT64_MAX) == 0);
	CHECK(xdev_ext_ce_completion_status(0, true, 0, 0) == 0);
	CHECK(xdev_ext_ce_completion_status(0, false, 0, 0) == -EIO);
	rejected_success(true, 0);
	rejected_success(true, 8191);
	rejected_success(true, 8193);
	rejected_success(true, UINT64_MAX);
	rejected_success(false, 8192);
	printf("CE exact completion: %u checks, %u failures\n", checks, failures);
	return !!failures;
}
