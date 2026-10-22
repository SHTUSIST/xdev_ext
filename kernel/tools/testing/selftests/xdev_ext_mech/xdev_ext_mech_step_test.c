// SPDX-License-Identifier: GPL-2.0
/*
 * User-space checks of the pure decisions the mechanism core takes in
 * io_uring/xdev_ext_mech_step.h: CREATE and START admission of a session
 * composition, class table sizes, and the worker's step after a build or
 * complete callback.  Build with -I <kernel tree>.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "io_uring/xdev_ext_mech_step.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                              \
	long long _expected = (long long)(expected);                          \
	checks++;                                                              \
	if (_actual != _expected) {                                            \
		fprintf(stderr, "%s:%d: got %lld, expected %lld\n",             \
			__FILE__, __LINE__, _actual, _expected);                    \
		failures++;                                                     \
	}                                                                       \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

/* S1: AF_XDP RX into an NVMe WRITE, NXP layout (six frames of 1432 bytes). */
static struct xdev_ext_mech_create s1(void)
{
	struct xdev_ext_mech_create c;

	memset(&c, 0, sizeof(c));
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = 2;
	c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	c.pool_fd = 5;
	c.layout.frame_size = 4096;
	c.layout.hdr_room = 360;
	c.layout.seg_len = 1432;
	c.layout.group_bytes = 8192;
	c.depth = 4;
	c.eventfd = -1;
	c.st[0].class_id = XDEV_EXT_MECH_CLASS_AFXDP;
	c.st[0].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	c.st[0].fd = 5;
	c.st[1].class_id = XDEV_EXT_MECH_CLASS_NVME;
	c.st[1].direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
	c.st[1].fd = 6;
	c.st[1].arg0 = 1024;
	c.st[1].arg1 = 2048;
	return c;
}

/* S3(d): user frames through CE H2D and D2H on the ring's UMEM. */
static struct xdev_ext_mech_create s3d(void)
{
	struct xdev_ext_mech_create c;

	memset(&c, 0, sizeof(c));
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = 2;
	c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	c.pool_fd = -1;
	c.layout.frame_size = 4096;
	c.layout.seg_len = 4096;
	c.layout.group_bytes = 65536;
	c.depth = 1;
	c.eventfd = 7;
	c.st[0].class_id = XDEV_EXT_MECH_CLASS_CE;
	c.st[0].direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
	c.st[0].fd = 8;
	c.st[1].class_id = XDEV_EXT_MECH_CLASS_CE;
	c.st[1].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	c.st[1].fd = 8;
	return c;
}

static void test_create_check(void)
{
	struct xdev_ext_mech_create c;
	__u32 frames = 0;

	c = s1();
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EXPECT_EQ(frames, 6);
	c = s3d();
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EXPECT_EQ(frames, 16);

	/* The out parameter carries no input. */
	c = s1();
	c.session_id = ~0ULL;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);

	c = s1();
	c.abi_version = 2;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.nr_stages = 0;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.nr_stages = XDEV_EXT_MECH_MAX_STAGES + 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);

	c = s1();
	c.pool_kind = 0;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.pool_kind = XDEV_EXT_MECH_POOL_PEER + 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.pool_fd = -1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EBADF);
	c = s3d();
	c.pool_fd = 3;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);

	c = s1();
	c.depth = 0;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.depth = XDEV_EXT_MECH_MAX_DEPTH;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	c = s1();
	c.depth = XDEV_EXT_MECH_MAX_DEPTH + 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.eventfd = -2;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);

	c = s1();
	c.layout.seg_len = 0;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.layout.hdr_room = 4096;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.layout.group_bytes = 1432 * 32 + 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -E2BIG);

	c = s1();
	c.st[1].class_id = XDEV_EXT_MECH_CLASS_MAX;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s3d();
	c.st[0].class_id = XDEV_EXT_MECH_CLASS_IAA;
	c.st[0].flags = XDEV_EXT_IAA_F_SOFTWARE;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	c.st[0].flags = XDEV_EXT_IAA_F_SOFTWARE << 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.st[1].direction = XDEV_EXT_BINDING_DIRECTION_INTERNAL;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.st[1].direction = 0;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.st[1].flags = 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.st[1].fd = -1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EBADF);

	/* AF_XDP stages need the socket's UMEM as the pool. */
	c = s3d();
	c.st[1].class_id = XDEV_EXT_MECH_CLASS_AFXDP;
	c.st[1].direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	/* RX feeds a chain: stage 0 only, and never alone. */
	c = s1();
	c.st[1] = c.st[0];
	c.st[0].class_id = XDEV_EXT_MECH_CLASS_NVME;
	c.st[0].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.nr_stages = 1;
	memset(&c.st[1], 0, sizeof(c.st[1]));
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	/* TX may be any stage, the first one included. */
	c = s1();
	c.st[0].direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);

	/* Slots past nr_stages stay zero. */
	c = s1();
	c.st[2].arg0 = 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = s1();
	c.st[3].fd = 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
}

static struct xdev_ext_mech_start start(__u64 nr, __u32 flags, __u32 nr_user)
{
	struct xdev_ext_mech_start st;

	memset(&st, 0, sizeof(st));
	st.session_id = 1;
	st.nr_batches = nr;
	st.first_seq = 100;
	st.flags = flags;
	st.nr_user_frames = nr_user;
	if (nr_user)
		st.user_frames = 0x1000;
	return st;
}

static void test_start_check(void)
{
	const __u32 umem = XDEV_EXT_MECH_POOL_IOU_UMEM, xsk = XDEV_EXT_MECH_POOL_XSK;
	const __u32 uf = XDEV_EXT_MECH_START_F_USER_FRAMES;
	struct xdev_ext_mech_start st;

	st = start(4, 0, 0);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, xsk, false, 6, 64), 0);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), 0);
	/* An RX-fed session is started by the wire, not by START. */
	EXPECT_EQ(xdev_ext_mech_start_check(&st, xsk, true, 6, 64), -EINVAL);

	st = start(0, 0, 0);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, xsk, false, 6, 64), -EINVAL);
	st = start(1, 1U << 1, 0);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, xsk, false, 6, 64), -EINVAL);
	st = start(1, 0, 6);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), -EINVAL);
	st = start(1, 0, 0);
	st.user_frames = 0x1000;
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), -EINVAL);

	/* User frames: the ring's UMEM only, exactly one span per batch. */
	st = start(2, uf, 12);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), 0);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, xsk, false, 6, 64), -EINVAL);
	st = start(2, uf, 11);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), -EINVAL);
	st = start(2, uf, 13);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), -EINVAL);
	st = start(2, uf, 12);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 11), -ENOSPC);
	st = start(2, uf, 12);
	st.user_frames = 0;
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), -EFAULT);
	st = start(1ULL << 40, uf, 12);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), -EINVAL);
	st = start(2, uf, 0);
	EXPECT_EQ(xdev_ext_mech_start_check(&st, umem, false, 6, 64), -EINVAL);
}

static void test_class_sizes(void)
{
	/* NVMe, AF_XDP and CE tables as the classes declare them. */
	EXPECT_TRUE(xdev_ext_mech_class_sizes_ok(568, 64, 1, 16, 1, 64));
	EXPECT_TRUE(xdev_ext_mech_class_sizes_ok(560, 16, 32, 8, 32, 0));
	EXPECT_TRUE(xdev_ext_mech_class_sizes_ok(552, 32, 32, 24, 1, 0));
	/* No completion copies at all is fine; half of a pair is not. */
	EXPECT_TRUE(xdev_ext_mech_class_sizes_ok(0, 16, 1, 0, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 16, 1, 8, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 16, 1, 0, 1, 0));

	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 0, 1, 0, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 16, 0, 0, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 16, XDEV_EXT_MECH_MAX_FRAMES + 1, 0,
					     0, 0));
	EXPECT_TRUE(xdev_ext_mech_class_sizes_ok(XDEV_EXT_MECH_CLASS_SIZE_MAX, 128, 32,
					    128, 32, XDEV_EXT_MECH_CLASS_SIZE_MAX));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(XDEV_EXT_MECH_CLASS_SIZE_MAX + 1, 16,
					     1, 0, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 129, 32, 0, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 16, 1, 129, 32, 0));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 16, 1, 0, 0,
					     XDEV_EXT_MECH_CLASS_SIZE_MAX + 1));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 0x80000000U, 32, 0, 0, 0));
	EXPECT_FALSE(xdev_ext_mech_class_sizes_ok(0, 16, 1, 0x80000000U, 32, 0));
}

static void test_build_step(void)
{
	int err = 1;

	EXPECT_EQ(xdev_ext_mech_build_step(XDEV_EXT_MECH_BUILD_SUBMIT, false, &err),
		  XDEV_EXT_MECH_STEP_SUBMIT);
	EXPECT_EQ(err, 0);
	EXPECT_EQ(xdev_ext_mech_build_step(XDEV_EXT_MECH_BUILD_DEFAULT, true, &err),
		  XDEV_EXT_MECH_STEP_DEFAULT);
	EXPECT_EQ(err, 0);
	/* No silent C path when the class has no default. */
	EXPECT_EQ(xdev_ext_mech_build_step(XDEV_EXT_MECH_BUILD_DEFAULT, false, &err),
		  XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EOPNOTSUPP);
	EXPECT_EQ(xdev_ext_mech_build_step(XDEV_EXT_MECH_BUILD_ABORT, true, &err),
		  XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -ECANCELED);
	EXPECT_EQ(xdev_ext_mech_build_step(3, true, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EPROTO);
	EXPECT_EQ(xdev_ext_mech_build_step(-1, true, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EPROTO);
}

static void test_complete_step(void)
{
	const __u32 nvme = XDEV_EXT_MECH_CLASS_NVME, afxdp = XDEV_EXT_MECH_CLASS_AFXDP;
	const __u32 ce = XDEV_EXT_MECH_CLASS_CE;
	const __s32 nvme_retryable = 0x0002;		/* SC set, DNR clear */
	const __s32 nvme_dnr = 0x4002;
	int err = 1;

	/* Success advances as the program says. */
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, XDEV_EXT_MECH_NEXT, 0, false, false,
					 0, &err), XDEV_EXT_MECH_STEP_NEXT);
	EXPECT_EQ(err, 0);
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, XDEV_EXT_MECH_DONE, 0, false, false,
					 0, &err), XDEV_EXT_MECH_STEP_DONE);
	EXPECT_EQ(err, 0);
	EXPECT_EQ(xdev_ext_mech_complete_step(ce, XDEV_EXT_MECH_ABORT, 0, false, false,
					 0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -ECANCELED);

	/* A failed native command never advances, whatever the program says. */
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, XDEV_EXT_MECH_NEXT, nvme_dnr, false,
					 false, 0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EIO);
	EXPECT_EQ(xdev_ext_mech_complete_step(afxdp, XDEV_EXT_MECH_DONE, -ENXIO, false,
					 false, 0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -ENXIO);
	EXPECT_EQ(xdev_ext_mech_complete_step(afxdp, XDEV_EXT_MECH_ABORT, -ENXIO, false,
					 false, 0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -ENXIO);
	/* An out-of-range negative status is not passed on as an errno. */
	EXPECT_EQ(xdev_ext_mech_complete_step(afxdp, XDEV_EXT_MECH_DONE, -5000, false,
					 false, 0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EIO);

	/* RETRY only for what the device did not consume, within the cap. */
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, XDEV_EXT_MECH_RETRY, nvme_retryable,
					 false, false, 0, &err),
		  XDEV_EXT_MECH_STEP_RETRY);
	EXPECT_EQ(err, 0);
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, XDEV_EXT_MECH_RETRY, nvme_retryable,
					 false, false, XDEV_EXT_MECH_RETRY_MAX_NVME,
					 &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EIO);
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, XDEV_EXT_MECH_RETRY, nvme_dnr, false,
					 false, 0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(xdev_ext_mech_complete_step(afxdp, XDEV_EXT_MECH_RETRY, -EAGAIN, false,
					 false, 3, &err), XDEV_EXT_MECH_STEP_RETRY);
	EXPECT_EQ(xdev_ext_mech_complete_step(afxdp, XDEV_EXT_MECH_RETRY, -EAGAIN, false,
					 false, 4, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EAGAIN);
	EXPECT_EQ(xdev_ext_mech_complete_step(ce, XDEV_EXT_MECH_RETRY,
					 XDEV_EXT_CE_PRE_SUBMIT_FAILED, false, false,
					 0, &err), XDEV_EXT_MECH_STEP_RETRY);
	/* Retrying a success is refused. */
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, XDEV_EXT_MECH_RETRY, 0, false, false,
					 0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -ECANCELED);

	/* A sequestered batch stays sequestered whatever the program says. */
	EXPECT_EQ(xdev_ext_mech_complete_step(ce, XDEV_EXT_MECH_DONE, XDEV_EXT_CE_AMBIGUOUS,
					 true, false, 0, &err),
		  XDEV_EXT_MECH_STEP_SEQUESTER);
	EXPECT_EQ(err, -EIO);
	EXPECT_EQ(xdev_ext_mech_complete_step(ce, XDEV_EXT_MECH_RETRY, -ETIMEDOUT, true,
					 false, 0, &err),
		  XDEV_EXT_MECH_STEP_SEQUESTER);
	EXPECT_EQ(err, -ETIMEDOUT);
	EXPECT_EQ(xdev_ext_mech_complete_step(ce, XDEV_EXT_MECH_NEXT, 0, true, false, 0,
					 &err), XDEV_EXT_MECH_STEP_SEQUESTER);
	EXPECT_EQ(err, -EIO);
	/* A completion after the drain timed out runs no program. */
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, XDEV_EXT_MECH_DONE, 0, false, true,
					 0, &err), XDEV_EXT_MECH_STEP_SEQUESTER);
	EXPECT_EQ(err, -ETIMEDOUT);

	/* Values the worker never accepts from a complete callback. */
	EXPECT_EQ(xdev_ext_mech_complete_step(afxdp, XDEV_EXT_MECH_HOLD, 0, false, false,
					 0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EPROTO);
	EXPECT_EQ(xdev_ext_mech_complete_step(nvme, -1, 0, false, false, 0, &err),
		  XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EPROTO);
}

/*
 * The status convention of xdev_ext_mech_batch_complete(b, status): 0 is
 * success; a negative errno is a local failure; a positive value is the
 * class's native status (the NVMe status word, a CE outcome such as
 * XDEV_EXT_CE_PRE_SUBMIT_FAILED).  A non-zero status never lets a batch go on:
 * NEXT and DONE become ABORT, and RETRY survives only where the class's
 * retry rule takes that status.  The rule is restated here per class, apart
 * from xdev_ext_mech_retry_ok(), and checked over every program verdict.
 */
static int convention_step(__u32 class_id, __s32 verdict, __s32 status,
			   __u32 retries, int *err)
{
	bool retry = false;

	*err = 0;
	if (!status) {
		if (verdict == XDEV_EXT_MECH_NEXT)
			return XDEV_EXT_MECH_STEP_NEXT;
		if (verdict == XDEV_EXT_MECH_DONE)
			return XDEV_EXT_MECH_STEP_DONE;
		*err = -ECANCELED;
		return XDEV_EXT_MECH_STEP_ABORT;
	}
	switch (class_id) {
	case XDEV_EXT_MECH_CLASS_NVME:	/* status word: SCT/SC set, DNR clear */
		retry = status > 0 && (status & 0x07ff) && !(status & 0x4000) &&
			retries < XDEV_EXT_MECH_RETRY_MAX_NVME;
		break;
	case XDEV_EXT_MECH_CLASS_AFXDP:	/* the socket's send errno */
		retry = status == -EAGAIN && retries < XDEV_EXT_MECH_RETRY_MAX_AFXDP;
		break;
	case XDEV_EXT_MECH_CLASS_CE:		/* the outcome code */
		retry = status == XDEV_EXT_CE_PRE_SUBMIT_FAILED &&
			retries < XDEV_EXT_MECH_RETRY_MAX_CE;
		break;
	}
	if (verdict == XDEV_EXT_MECH_RETRY && retry)
		return XDEV_EXT_MECH_STEP_RETRY;
	*err = status < 0 && status >= -4095 ? status : -EIO;
	return XDEV_EXT_MECH_STEP_ABORT;
}

static void test_status_convention(void)
{
	static const __u32 classes[] = {
		XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_CLASS_CE,
	};
	static const __s32 verdicts[] = {
		XDEV_EXT_MECH_NEXT, XDEV_EXT_MECH_DONE, XDEV_EXT_MECH_RETRY, XDEV_EXT_MECH_ABORT,
	};
	static const __s32 statuses[] = {
		0, -EIO, -EAGAIN, -EINTR, -ENODEV, -ENXIO, -ETIMEDOUT, -4095,
		-4096, -65531 /* 0xffff0005: SC bits, no DNR bit */,
		-2147483647 - 1, XDEV_EXT_CE_PRE_SUBMIT_FAILED,
		XDEV_EXT_CE_AMBIGUOUS, 0x0002, 0x0004, 0x0281, 0x4002, 0x07ff, 0x0800,
		0x2000, 0x7fff, 2147483647,
	};
	__u32 c, v, k, retries;
	int err, want_err;

	for (c = 0; c < 3; c++)
		for (v = 0; v < 4; v++)
			for (k = 0; k < sizeof(statuses) / sizeof(statuses[0]);
			     k++)
				for (retries = 0; retries <= 4; retries++) {
					err = 1;
					EXPECT_EQ(xdev_ext_mech_complete_step(
							classes[c], verdicts[v],
							statuses[k], false,
							false, retries, &err),
						  convention_step(classes[c],
								  verdicts[v],
								  statuses[k],
								  retries,
								  &want_err));
					EXPECT_EQ(err, want_err);
				}

	/* The statuses each class hands the core, as its code passes them. */
	EXPECT_EQ(convention_step(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_RETRY, -EINTR,
				  0, &err), XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(convention_step(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_RETRY,
				  XDEV_EXT_CE_PRE_SUBMIT_FAILED, 0, &err),
		  XDEV_EXT_MECH_STEP_RETRY);
	EXPECT_EQ(convention_step(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_NEXT,
				  XDEV_EXT_CE_PRE_SUBMIT_FAILED, 0, &err),
		  XDEV_EXT_MECH_STEP_ABORT);
	EXPECT_EQ(err, -EIO);
}

static void test_status_errno(void)
{
	EXPECT_EQ(xdev_ext_mech_status_errno(0), 0);
	EXPECT_EQ(xdev_ext_mech_status_errno(-ENXIO), -ENXIO);
	EXPECT_EQ(xdev_ext_mech_status_errno(-XDEV_EXT_MECH_ERRNO_MAX), -XDEV_EXT_MECH_ERRNO_MAX);
	EXPECT_EQ(xdev_ext_mech_status_errno(-XDEV_EXT_MECH_ERRNO_MAX - 1), -EIO);
	EXPECT_EQ(xdev_ext_mech_status_errno(0x4002), -EIO);
	EXPECT_EQ(xdev_ext_mech_status_errno(XDEV_EXT_CE_AMBIGUOUS), -EIO);
}

static struct xdev_ext_mech_bstate bstate_at(__u8 state, __u8 stage)
{
	struct xdev_ext_mech_bstate b = { .state = state, .stage = stage,
				     .nr_stages = 3 };

	return b;
}

/*
 * In-order submission at an ordered stage (stage 2 here): a live batch
 * with a smaller key holds a later one back until it is submitted there.
 */
static void test_order_holds(void)
{
	struct xdev_ext_mech_bstate o;

	/* A smaller key not yet at stage 2 holds key 7 back. */
	o = bstate_at(XDEV_EXT_MECH_B_OPEN, 0);
	EXPECT_TRUE(xdev_ext_mech_order_holds(7, 2, 6, &o));
	o = bstate_at(XDEV_EXT_MECH_B_READY, 1);
	EXPECT_TRUE(xdev_ext_mech_order_holds(7, 2, 3, &o));
	o = bstate_at(XDEV_EXT_MECH_B_IN_FLIGHT, 1);
	EXPECT_TRUE(xdev_ext_mech_order_holds(7, 2, 3, &o));
	/* READY at stage 2 itself, not submitted yet: still ahead in line. */
	o = bstate_at(XDEV_EXT_MECH_B_READY, 2);
	EXPECT_TRUE(xdev_ext_mech_order_holds(7, 2, 6, &o));
	/* A submitted batch still owns DMA frames; retries must not be overtaken. */
	o = bstate_at(XDEV_EXT_MECH_B_IN_FLIGHT, 2);
	EXPECT_TRUE(xdev_ext_mech_order_holds(7, 2, 6, &o));
	o = bstate_at(XDEV_EXT_MECH_B_READY, 3);
	EXPECT_FALSE(xdev_ext_mech_order_holds(7, 2, 6, &o));
	/* A larger or equal key never holds a smaller one back. */
	o = bstate_at(XDEV_EXT_MECH_B_READY, 1);
	EXPECT_FALSE(xdev_ext_mech_order_holds(7, 2, 8, &o));
	EXPECT_FALSE(xdev_ext_mech_order_holds(7, 2, 7, &o));
	/* A finished or free batch is not live. */
	o = bstate_at(XDEV_EXT_MECH_B_DONE, 1);
	EXPECT_FALSE(xdev_ext_mech_order_holds(7, 2, 3, &o));
	o = bstate_at(XDEV_EXT_MECH_B_ABORT, 1);
	EXPECT_FALSE(xdev_ext_mech_order_holds(7, 2, 3, &o));
	o = bstate_at(XDEV_EXT_MECH_B_SEQUESTERED, 1);
	EXPECT_FALSE(xdev_ext_mech_order_holds(7, 2, 3, &o));
	o = bstate_at(XDEV_EXT_MECH_B_FREE, 0);
	EXPECT_FALSE(xdev_ext_mech_order_holds(7, 2, 3, &o));
}

int main(void)
{
	test_create_check();
	test_start_check();
	test_class_sizes();
	test_build_step();
	test_complete_step();
	test_status_convention();
	test_status_errno();
	test_order_holds();

	if (failures) {
		printf("FAIL: %u/%u XDEV_EXT mechanism step checks failed\n", failures,
		       checks);
		return 1;
	}
	printf("PASS: %u XDEV_EXT mechanism step checks\n", checks);
	return 0;
}
