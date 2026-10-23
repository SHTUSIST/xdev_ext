// SPDX-License-Identifier: GPL-2.0
/*
 * Host check: does the mechanism core admit a copy-engine stage as the first
 * or the last stage of a one-way session?  The eval session arms need
 *
 *   gpu_nic ingest   [AF_XDP RX, CE H2D]      (XSK pool)
 *   gpu_nic egress   [CE D2H, AF_XDP TX]      (XSK pool)
 *   nvme_gpu load    [NVMe READ, CE H2D]      (ring XDEV_EXT UMEM)
 *   nvme_gpu save    [CE D2H, NVMe WRITE]     (ring XDEV_EXT UMEM)
 *
 * It compiles the kernel's own pure admission rules (CREATE and START in
 * io_uring/xdev_ext_mech_step.h, the AF_XDP stage rule in
 * net/xdp/xsk_xdev_ext_mech_core.h) unchanged, with -I <kernel tree>.  A
 * discriminating negative control accompanies every accepted shape.  This is
 * admission only: binding, BPF plans and completions need the guest run.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "io_uring/xdev_ext_mech_step.h"
#include "net/xdp/xsk_xdev_ext_mech_core.h"

static unsigned int checks, failures;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _a = (long long)(actual), _e = (long long)(expected);        \
	checks++;                                                              \
	if (_a != _e) {                                                        \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",         \
			__FILE__, __LINE__, #actual, _a, _e);                   \
		failures++;                                                     \
	}                                                                       \
} while (0)

/* 8 KiB groups of 4 KiB frames on the ring UMEM, eight batches deep. */
static struct xdev_ext_mech_create umem_session(__u32 c0, __u32 d0, __u32 c1,
					     __u32 d1)
{
	struct xdev_ext_mech_create c;

	memset(&c, 0, sizeof(c));
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = 2;
	c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	c.pool_fd = -1;
	c.layout.frame_size = 4096;
	c.layout.seg_len = 4096;
	c.layout.group_bytes = 8192;
	c.depth = 8;
	c.eventfd = 9;
	c.st[0] = (struct xdev_ext_mech_stage_uapi) { .class_id = c0,
		.direction = d0, .fd = 10, .arg0 = 4096, .arg1 = 65536 };
	c.st[1] = (struct xdev_ext_mech_stage_uapi) { .class_id = c1,
		.direction = d1, .fd = 11, .arg0 = 4096, .arg1 = 65536 };
	return c;
}

/* The NXP layout xdev_ext_mech_ctl gives an MTU 1500 link: six 1432-byte segments. */
static struct xdev_ext_mech_create xsk_session(__u32 c0, __u32 d0, __u32 c1,
					    __u32 d1)
{
	struct xdev_ext_mech_create c = umem_session(c0, d0, c1, d1);

	c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	c.pool_fd = 5;
	c.layout.hdr_room = 360;
	c.layout.seg_len = 1432;
	if (c0 == XDEV_EXT_MECH_CLASS_AFXDP)
		c.st[0].fd = 5;
	if (c1 == XDEV_EXT_MECH_CLASS_AFXDP)
		c.st[1].fd = 5;
	return c;
}

static int start(const struct xdev_ext_mech_create *c, __u32 frames, bool user,
		 bool rx_first)
{
	static __u32 user_frames[64];
	struct xdev_ext_mech_start st;

	memset(&st, 0, sizeof(st));
	st.nr_batches = 32;
	st.first_seq = 1;
	if (user) {
		/* What a source session hands over: one depth of frames, recycled. */
		st.flags = XDEV_EXT_MECH_START_F_USER_FRAMES | XDEV_EXT_MECH_START_F_RECYCLE;
		st.nr_user_frames = c->depth * frames;
		st.user_frames = (__u64)(uintptr_t)user_frames;
	}
	return xdev_ext_mech_start_check(&st, c->pool_kind, rx_first, frames,
				    4096);
}

static void test_nvme_gpu_load_and_save(void)
{
	struct xdev_ext_mech_create c;
	__u32 frames = 0;

	c = umem_session(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_FROM_DEVICE,
			 XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_TO_DEVICE);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EXPECT_EQ(frames, 2);
	EXPECT_EQ(start(&c, frames, true, false), 0);

	c = umem_session(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_FROM_DEVICE,
			 XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_TO_DEVICE);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EXPECT_EQ(start(&c, frames, true, false), 0);

	/* Control: the same shapes with a CE flag the class does not define. */
	c.st[0].flags = 1;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = umem_session(XDEV_EXT_MECH_CLASS_NVME, XDEV_EXT_MECH_DIR_FROM_DEVICE,
			 XDEV_EXT_MECH_CLASS_CE, 0);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	/* Control: AF_XDP needs the socket's pool, not the ring UMEM. */
	c = umem_session(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_FROM_DEVICE,
			 XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_DIR_TO_DEVICE);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
}

static void test_gpu_nic_ingest(void)
{
	struct xdev_ext_mech_create c;
	__u32 frames = 0;

	c = xsk_session(XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_DIR_FROM_DEVICE,
			XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_TO_DEVICE);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EXPECT_EQ(frames, 6);
	/* An RX-first session is driven by arrivals and is never STARTed. */
	EXPECT_EQ(start(&c, frames, false, true), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(XDEV_EXT_MECH_DIR_FROM_DEVICE, 0,
					   true, true, false), 0);

	/* Control: RX may not follow the CE stage, nor stand alone. */
	c = xsk_session(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_TO_DEVICE,
			XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_DIR_FROM_DEVICE);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(XDEV_EXT_MECH_DIR_FROM_DEVICE, 1,
					   true, true, false), -EINVAL);
	c = xsk_session(XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_DIR_FROM_DEVICE,
			XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_TO_DEVICE);
	c.nr_stages = 1;
	memset(&c.st[1], 0, sizeof(c.st[1]));
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
}

static void test_gpu_nic_egress(void)
{
	struct xdev_ext_mech_create c;
	__u32 frames = 0;

	c = xsk_session(XDEV_EXT_MECH_CLASS_CE, XDEV_EXT_MECH_DIR_FROM_DEVICE,
			XDEV_EXT_MECH_CLASS_AFXDP, XDEV_EXT_MECH_DIR_TO_DEVICE);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	/* A source on the socket pool: frames come from the pool, not user space. */
	EXPECT_EQ(start(&c, frames, false, false), 0);
	EXPECT_EQ(start(&c, frames, true, false), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(XDEV_EXT_MECH_DIR_TO_DEVICE, 1,
					   true, true, false), 0);
	/* Control: one TX stage per socket. */
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(XDEV_EXT_MECH_DIR_TO_DEVICE, 1,
					   true, true, true), -EBUSY);
}

int main(void)
{
	test_nvme_gpu_load_and_save();
	test_gpu_nic_ingest();
	test_gpu_nic_egress();
	printf("CE stage position admission: %u checks, %u failures\n", checks,
	       failures);
	return failures ? 1 : 0;
}
