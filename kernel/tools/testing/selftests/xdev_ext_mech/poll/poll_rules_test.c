// SPDX-License-Identifier: GPL-2.0
/*
 * Pure rules of stage polling (Documentation/userspace-api/xdev_ext-poll.rst):
 * CREATE admission of XDEV_EXT_MECH_STAGE_F_POLL in xdev_ext_mech_step.h,
 * the per-stage split in xdev_ext_mech_poll.h, and the worker's re-arm rule.
 * Build with -I <kernel tree>; prints TAP.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "io_uring/xdev_ext_mech_step.h"
#include "io_uring/xdev_ext_mech_poll.h"

static unsigned int checks, failures;

#define EXPECT_EQ(actual, expected, what) do {                                \
	long long _a = (long long)(actual), _e = (long long)(expected);       \
	checks++;                                                              \
	if (_a != _e) {                                                        \
		failures++;                                                     \
		printf("not ok %u - %s (got %lld, expected %lld, line %d)\n",   \
		       checks, what, _a, _e, __LINE__);                         \
	} else {                                                                \
		printf("ok %u - %s\n", checks, what);                          \
	}                                                                       \
} while (0)

#define POLL XDEV_EXT_MECH_STAGE_F_POLL

static struct xdev_ext_mech_create nvme_copy(void)
{
	struct xdev_ext_mech_create c;

	memset(&c, 0, sizeof(c));
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = 2;
	c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	c.pool_fd = -1;
	c.layout.frame_size = 4096;
	c.layout.seg_len = 4096;
	c.layout.group_bytes = 4096;
	c.depth = 8;
	c.eventfd = -1;
	c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 5, .arg0 = 0, .arg1 = 64 };
	c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 6, .arg0 = 0, .arg1 = 64 };
	return c;
}

/* AF_XDP RX into an NVMe WRITE, NXP layout. */
static struct xdev_ext_mech_create nic_nvme(void)
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
	c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 5 };
	c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 6, .arg0 = 1024, .arg1 = 2048 };
	return c;
}

static void flag_identity(void)
{
	EXPECT_EQ(POLL, 1U << 29, "POLL is stage flag bit 29");
	EXPECT_EQ(POLL & XDEV_EXT_MECH_STAGE_F_FANOUT, 0, "POLL differs from FANOUT");
	EXPECT_EQ(POLL & (XDEV_EXT_AFXDP_F_RELIABLE | XDEV_EXT_AFXDP_F_FINITE |
			  XDEV_EXT_AFXDP_F_POLICY | XDEV_EXT_SOCKET_F_NXP |
			  XDEV_EXT_IAA_F_SOFTWARE), 0, "POLL differs from every class flag");
}

static void create_admission(void)
{
	struct xdev_ext_mech_create c;
	__u32 frames = 0;

	c = nvme_copy();
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0, "NVMe copy without POLL unchanged");
	c.st[0].flags = POLL;
	c.st[1].flags = POLL;
	frames = 0;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0, "POLL accepted on NVMe READ and WRITE");
	EXPECT_EQ(frames, 1, "POLL does not change the frames per batch");
	c.st[1].flags = POLL | (1U << 28);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL, "unknown bit beside POLL still refused");

	c = nic_nvme();
	c.st[0].flags = POLL;
	c.st[1].flags = POLL;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0, "POLL accepted on AF_XDP RX and NVMe WRITE");
	c.st[0].flags = POLL | XDEV_EXT_AFXDP_F_RELIABLE;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0, "POLL keeps AF_XDP RELIABLE");
	c.st[0].flags = POLL | XDEV_EXT_AFXDP_F_FINITE;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL,
		  "AF_XDP FINITE without RELIABLE still refused beside POLL");
	c.st[0].flags = POLL | (1U << 3);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL, "unknown AF_XDP bit beside POLL refused");

	/* Class capability is decided at bind; CREATE's generic check admits it. */
	c = nvme_copy();
	c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_CPU,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = -1,
		.arg0 = XDEV_EXT_CPU_XFORM_CRC32C_CHECK, .flags = POLL };
	c.nr_stages = 2;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0, "POLL on a CPU stage reaches bind");

	c = nvme_copy();
	c.st[2].flags = POLL;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL, "POLL on an unused stage slot refused");

	c = nvme_copy();
	c.nr_stages = 3;
	c.st[2] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 7, .arg0 = 0, .arg1 = 64,
		.flags = POLL | XDEV_EXT_MECH_STAGE_F_FANOUT };
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0, "POLL with FANOUT on a consumer");
	c.st[1].flags = POLL;
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0, "POLL on the fanout leader");
}

static void split(void)
{
	struct xdev_ext_mech_stage_uapi u = { .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 9,
		.flags = POLL | XDEV_EXT_AFXDP_F_RELIABLE, .arg0 = 3, .arg1 = 4 };
	struct xdev_ext_mech_stage_uapi clean;
	bool poll = false;

	memset(&clean, 0xa5, sizeof(clean));
	EXPECT_EQ(xdev_ext_mech_poll_split(&u, true, &clean, &poll), 0, "split: POLL on a polling class");
	EXPECT_EQ(poll, 1, "split: stage polls");
	EXPECT_EQ(clean.flags, XDEV_EXT_AFXDP_F_RELIABLE, "split: class flags without POLL");
	EXPECT_EQ(clean.class_id == u.class_id && clean.direction == u.direction &&
		  clean.fd == u.fd && clean.arg0 == u.arg0 && clean.arg1 == u.arg1, 1,
		  "split: every other field copied");
	EXPECT_EQ(u.flags, POLL | XDEV_EXT_AFXDP_F_RELIABLE, "split: caller input untouched");

	poll = true;
	EXPECT_EQ(xdev_ext_mech_poll_split(&u, false, &clean, &poll), -EOPNOTSUPP,
		  "split: POLL on a class without poll is EOPNOTSUPP");
	EXPECT_EQ(poll, 0, "split: refused stage does not poll");

	u.flags = XDEV_EXT_AFXDP_F_RELIABLE;
	poll = true;
	EXPECT_EQ(xdev_ext_mech_poll_split(&u, false, &clean, &poll), 0,
		  "split: no POLL needs no class poll");
	EXPECT_EQ(poll, 0, "split: stage without POLL does not poll");
	EXPECT_EQ(clean.flags, XDEV_EXT_AFXDP_F_RELIABLE, "split: flags unchanged without POLL");

	/* FANOUT is the other generic stage bit; ->bind never sees it either. */
	u.flags = XDEV_EXT_MECH_STAGE_F_FANOUT | POLL | XDEV_EXT_AFXDP_F_RELIABLE;
	EXPECT_EQ(xdev_ext_mech_poll_split(&u, true, &clean, &poll), 0, "split: FANOUT and POLL");
	EXPECT_EQ(poll, 1, "split: fanout member polls");
	EXPECT_EQ(clean.flags, XDEV_EXT_AFXDP_F_RELIABLE, "split: class flags without FANOUT or POLL");
	u.flags = XDEV_EXT_MECH_STAGE_F_FANOUT;
	EXPECT_EQ(xdev_ext_mech_poll_split(&u, false, &clean, &poll), 0,
		  "split: FANOUT alone needs no class poll");
	EXPECT_EQ(clean.flags, 0, "split: FANOUT alone leaves no class flag");
}

static void rearm(void)
{
	static const __u32 states[] = { XDEV_EXT_MECH_SESSION_NONE, XDEV_EXT_MECH_SESSION_ACTIVE,
		XDEV_EXT_MECH_SESSION_ERROR, XDEV_EXT_MECH_SESSION_STOPPING,
		XDEV_EXT_MECH_SESSION_STOPPED, XDEV_EXT_MECH_SESSION_ZOMBIE };
	unsigned int i;
	bool all = true;

	for (i = 0; i < sizeof(states) / sizeof(states[0]); i++)
		all &= xdev_ext_mech_poll_next(states[i], 3, true, true) == -1;
	EXPECT_EQ(all, 1, "never re-arm after worker_gone");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_ACTIVE, 1, false, false), 0,
		  "ACTIVE with live batches: next pass immediately");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_ERROR, 1, false, false), 0,
		  "ERROR with live batches: next pass immediately");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_STOPPING, 2, false, false), 0,
		  "STOPPING with accepted commands: keep polling through the drain");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_ZOMBIE, 2, false, false), 1,
		  "ZOMBIE with live batches: one jiffy between passes");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_ACTIVE, 0, false, false), -1,
		  "ACTIVE without live batches: stop");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_ACTIVE, 0, true, false), 0,
		  "ACTIVE receive source keeps polling without batches");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_STOPPING, 0, true, false), -1,
		  "receive source stops polling once STOPPING and drained");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_ZOMBIE, 0, true, false), -1,
		  "ZOMBIE without live batches: stop");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_STOPPED, 0, true, false), -1,
		  "STOPPED: stop");
	EXPECT_EQ(xdev_ext_mech_poll_next(XDEV_EXT_MECH_SESSION_NONE, 0, true, false), -1,
		  "before activation: never poll");
}

int main(void)
{
	printf("TAP version 13\n");
	flag_identity();
	create_admission();
	split();
	rearm();
	printf("1..%u\n", checks);
	return failures ? 1 : 0;
}
