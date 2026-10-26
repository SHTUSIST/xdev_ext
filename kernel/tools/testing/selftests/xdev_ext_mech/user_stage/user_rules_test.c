// SPDX-License-Identifier: GPL-2.0
/*
 * Pure rules of the USER stage (Documentation/userspace-api/xdev_ext-user-stage.rst):
 * the UAPI layout, the register-op request check, the shared-region layout,
 * ring index arithmetic, completion status and length rules in
 * io_uring/xdev_ext_mech_user_core.h, and CREATE admission and role of a
 * USER stage in io_uring/xdev_ext_mech_step.h.  Build with -I <kernel tree>;
 * prints TAP.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "io_uring/xdev_ext_mech_step.h"
#include "io_uring/xdev_ext_mech_user_core.h"

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

#define FRAME 4096U
#define TO XDEV_EXT_MECH_DIR_TO_DEVICE
#define FROM XDEV_EXT_MECH_DIR_FROM_DEVICE
#define VARLEN XDEV_EXT_USER_F_VARLEN

static struct xdev_ext_mech_stage_uapi user_stage(__u32 flags, __u64 deadline, __s64 delta)
{
	return (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_USER,
		.direction = TO, .fd = 7, .flags = flags, .arg0 = deadline, .arg1 = (__u64)delta };
}

/* NVMe READ -> USER -> NVMe WRITE on the ring's UMEM. */
static struct xdev_ext_mech_create nvme_user_nvme(void)
{
	struct xdev_ext_mech_create c;

	memset(&c, 0, sizeof(c));
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = 3;
	c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	c.pool_fd = -1;
	c.layout.frame_size = FRAME;
	c.layout.seg_len = FRAME;
	c.layout.group_bytes = FRAME;
	c.depth = 8;
	c.eventfd = -1;
	c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = FROM, .fd = 5, .arg0 = 0, .arg1 = 64 };
	c.st[1] = user_stage(0, 100, 0);
	c.st[2] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = TO, .fd = 6, .arg0 = 0, .arg1 = 64 };
	return c;
}

/* NVMe READ -> USER as the last stage. */
static struct xdev_ext_mech_create nvme_user(__u32 flags, __u64 deadline, __s64 delta)
{
	struct xdev_ext_mech_create c = nvme_user_nvme();

	c.nr_stages = 2;
	memset(&c.st[2], 0, sizeof(c.st[2]));
	c.st[1] = user_stage(flags, deadline, delta);
	return c;
}

static int check(const struct xdev_ext_mech_create *c)
{
	__u32 frames = 0;

	return xdev_ext_mech_create_check(c, &frames);
}

static void test_uapi(void)
{
	EXPECT_EQ(XDEV_EXT_MECH_CLASS_USER, 10, "USER class id is 10");
	EXPECT_EQ(XDEV_EXT_MECH_CLASS_MAX, 12, "class maximum is 12");
	EXPECT_EQ(XDEV_EXT_MECH_CLASS_CPU, 9, "CPU class id unchanged");
	EXPECT_EQ(XDEV_EXT_MECH_OP_USER_STAGE, 7, "register sub-op 7");
	EXPECT_EQ(xdev_ext_mech_class_known(XDEV_EXT_MECH_CLASS_USER), 1, "USER is a known class");
	EXPECT_EQ(xdev_ext_mech_class_known(XDEV_EXT_MECH_CLASS_MAX), 0, "MAX is not a class");
	EXPECT_EQ(XDEV_EXT_USER_F_VARLEN, 1U << 0, "VARLEN is stage flag bit 0");
	EXPECT_EQ(XDEV_EXT_USER_DEADLINE_MAX_MS, 600000, "deadline bound 600 s");
	EXPECT_EQ(XDEV_EXT_USER_RING_MAX, 256, "ring bound 256");
	EXPECT_EQ(XDEV_EXT_USER_DESC_VERSION, 1, "descriptor version 1");
	EXPECT_EQ(XDEV_EXT_USER_F_SLEEPING, 1U << 0, "user flag SLEEPING");
	EXPECT_EQ(XDEV_EXT_USER_K_NEED_KICK, 1U << 0, "kernel flag NEED_KICK");
	EXPECT_EQ(XDEV_EXT_USER_K_STOPPED, 1U << 1, "kernel flag STOPPED");
	EXPECT_EQ(XDEV_EXT_USER_IOC_KICK, 0x58e8, "kick ioctl is _IO('X', 0xe8)");
	EXPECT_EQ(sizeof(struct xdev_ext_user_desc), 16, "build descriptor 16 bytes");
	EXPECT_EQ(sizeof(struct xdev_ext_user_ring_hdr), 384, "ring header six 64-byte lines");
	EXPECT_EQ(offsetof(struct xdev_ext_user_ring_hdr, ready_prod), 0, "ready_prod line 0");
	EXPECT_EQ(offsetof(struct xdev_ext_user_ring_hdr, ready_cons), 64, "ready_cons line 1");
	EXPECT_EQ(offsetof(struct xdev_ext_user_ring_hdr, done_prod), 128, "done_prod line 2");
	EXPECT_EQ(offsetof(struct xdev_ext_user_ring_hdr, done_cons), 192, "done_cons line 3");
	EXPECT_EQ(offsetof(struct xdev_ext_user_ring_hdr, user_flags), 256, "user_flags line 4");
	EXPECT_EQ(offsetof(struct xdev_ext_user_ring_hdr, kernel_flags), 320, "kernel_flags line 5");
	EXPECT_EQ(sizeof(struct xdev_ext_user_ready), 40, "ready entry 40 bytes");
	EXPECT_EQ(offsetof(struct xdev_ext_user_ready, ticket), 8, "ready ticket at 8");
	EXPECT_EQ(offsetof(struct xdev_ext_user_ready, arg), 32, "ready arg at 32");
	EXPECT_EQ(sizeof(struct xdev_ext_user_done), 16, "completion entry 16 bytes");
	EXPECT_EQ(offsetof(struct xdev_ext_user_done, slot), 8, "completion slot at 8");
	EXPECT_EQ(offsetof(struct xdev_ext_user_done, status), 12, "completion status at 12");
	EXPECT_EQ(sizeof(struct xdev_ext_user_frame), 24, "slot frame 24 bytes");
	EXPECT_EQ(offsetof(struct xdev_ext_user_frame, out_len), 20, "out_len last");
	EXPECT_EQ(sizeof(struct xdev_ext_user_slot), 16 + 24 * XDEV_EXT_MECH_MAX_FRAMES, "slot 784 bytes");
	EXPECT_EQ(sizeof(struct xdev_ext_user_ring_offsets), 40, "offsets 40 bytes");
	EXPECT_EQ(sizeof(struct xdev_ext_mech_user_stage), 64, "register request 64 bytes");
	EXPECT_EQ(offsetof(struct xdev_ext_mech_user_stage, off), 24, "offsets follow the fd");
}

static void test_request(void)
{
	struct xdev_ext_mech_user_stage r;

	memset(&r, 0, sizeof(r));
	r.size = sizeof(r);
	r.entries = 64;
	r.eventfd = -1;
	EXPECT_EQ(xdev_ext_user_request_check(&r), 0, "request: 64 entries, no eventfd");
	r.eventfd = 3;
	EXPECT_EQ(xdev_ext_user_request_check(&r), 0, "request: with eventfd");
	r.eventfd = -2;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EBADF, "request: eventfd below -1");
	r.eventfd = -1;
	r.size = sizeof(r) - 8;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: short size");
	r.size = sizeof(r) + 8;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: long size");
	r.size = sizeof(r);
	r.flags = 1;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: unknown flag");
	r.flags = 0;
	r.rsvd = 1;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: nonzero rsvd");
	r.rsvd = 0;
	r.fd = 4;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: output fd nonzero on input");
	r.fd = 0;
	r.off.slots = 1;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: output offsets nonzero on input");
	r.off.slots = 0;
	r.off.mmap_size = 4096;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: output size nonzero on input");
	r.off.mmap_size = 0;
	r.entries = 0;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: zero entries");
	r.entries = 3;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: entries not a power of two");
	r.entries = 512;
	EXPECT_EQ(xdev_ext_user_request_check(&r), -EINVAL, "request: entries above 256");
	r.entries = 1;
	EXPECT_EQ(xdev_ext_user_request_check(&r), 0, "request: one entry");
	r.entries = 256;
	EXPECT_EQ(xdev_ext_user_request_check(&r), 0, "request: 256 entries");
}

static void test_layout(void)
{
	struct xdev_ext_user_ring_offsets o;
	__u32 entries;

	memset(&o, 0xff, sizeof(o));
	EXPECT_EQ(xdev_ext_user_layout(1, 4096, &o), 0, "layout of one entry");
	EXPECT_EQ(o.hdr, 0, "header at 0");
	EXPECT_EQ(o.ready, 384, "ready ring after the header");
	EXPECT_EQ(o.done, 448, "completion ring 64-aligned after one ready entry");
	EXPECT_EQ(o.slots, 512, "slot table 64-aligned after one completion entry");
	EXPECT_EQ(o.mmap_size, 4096, "one page");
	EXPECT_EQ(xdev_ext_user_layout(64, 4096, &o), 0, "layout of 64 entries");
	EXPECT_EQ(o.ready, 384, "ready ring after the header");
	EXPECT_EQ(o.done, 384 + 64 * 40, "completion ring after 64 ready entries");
	EXPECT_EQ(o.slots, 384 + 64 * 40 + 64 * 16, "slot table after 64 completion entries");
	EXPECT_EQ(o.mmap_size, 57344, "64 entries map 14 pages");
	EXPECT_EQ(xdev_ext_user_layout(256, 4096, &o), 0, "layout of 256 entries");
	EXPECT_EQ(o.mmap_size, 4096 * ((384 + 256 * 40 + 256 * 16 + 256 * 784 + 4095) / 4096),
		  "256 entries rounded to pages");
	EXPECT_EQ(xdev_ext_user_layout(3, 4096, &o), -EINVAL, "layout refuses 3 entries");
	EXPECT_EQ(xdev_ext_user_layout(0, 4096, &o), -EINVAL, "layout refuses 0 entries");
	EXPECT_EQ(xdev_ext_user_layout(512, 4096, &o), -EINVAL, "layout refuses 512 entries");
	for (entries = 1; entries <= XDEV_EXT_USER_RING_MAX; entries <<= 1) {
		xdev_ext_user_layout(entries, 4096, &o);
		if (o.ready % 8 || o.done % 64 || o.slots % 64 ||
		    o.slots + (__u64)entries * sizeof(struct xdev_ext_user_slot) > o.mmap_size ||
		    o.done < o.ready + (__u64)entries * sizeof(struct xdev_ext_user_ready) ||
		    o.slots < o.done + (__u64)entries * sizeof(struct xdev_ext_user_done))
			break;
	}
	EXPECT_EQ(entries, XDEV_EXT_USER_RING_MAX << 1, "every size: aligned, disjoint, inside the map");
}

static void test_rings(void)
{
	EXPECT_EQ(xdev_ext_user_ring_count(5, 5, 8), 0, "empty ring");
	EXPECT_EQ(xdev_ext_user_ring_count(13, 5, 8), 8, "full ring");
	EXPECT_EQ(xdev_ext_user_ring_count(14, 5, 8), -EOVERFLOW, "producer more than entries ahead");
	EXPECT_EQ(xdev_ext_user_ring_count(4, 5, 8), -EOVERFLOW, "producer behind consumer");
	EXPECT_EQ(xdev_ext_user_ring_count(2, 0xfffffffeU, 8), 4, "count across index wrap");
	EXPECT_EQ(xdev_ext_user_ring_room(5, 5, 8), 8, "room in an empty ring");
	EXPECT_EQ(xdev_ext_user_ring_room(12, 5, 8), 1, "one place left");
	EXPECT_EQ(xdev_ext_user_ring_room(13, 5, 8), 0, "no room in a full ring");
	EXPECT_EQ(xdev_ext_user_ring_room(5, 6, 8), 0, "user consumer ahead of the producer: no room");
	EXPECT_EQ(xdev_ext_user_ring_room(5, 0xf0000000U, 8), 0, "garbage consumer: no room");
	EXPECT_EQ(xdev_ext_user_ring_room(1, 0xffffffffU, 8), 6, "room across index wrap");
}

/* ->submit with a full ready ring: retry, bounded by one deadline. */
static void test_full_wait(void)
{
	unsigned long since = 0;
	bool full = false;

	EXPECT_EQ(xdev_ext_user_full_wait(1, &full, &since, 1000, 50), 0, "room: hand out");
	EXPECT_EQ(full, 0, "room: not waiting");
	EXPECT_EQ(xdev_ext_user_full_wait(0, &full, &since, 1000, 50), -EAGAIN, "first refusal: retry");
	EXPECT_EQ(full && since == 1000, 1, "first refusal starts the wait");
	EXPECT_EQ(xdev_ext_user_full_wait(0, &full, &since, 1049, 50), -EAGAIN, "one jiffy before the deadline: retry");
	EXPECT_EQ(since, 1000, "a later refusal keeps the start");
	EXPECT_EQ(xdev_ext_user_full_wait(0, &full, &since, 1050, 50), -ETIMEDOUT, "full for one deadline: fail");
	EXPECT_EQ(xdev_ext_user_full_wait(0, &full, &since, 1051, 50), -ETIMEDOUT, "still full: the next batch fails too");
	EXPECT_EQ(xdev_ext_user_full_wait(2, &full, &since, 1052, 50), 0, "room again: hand out");
	EXPECT_EQ(full, 0, "room ends the wait");
	EXPECT_EQ(xdev_ext_user_full_wait(0, &full, &since, 1053, 50), -EAGAIN, "a new full period starts over");
	EXPECT_EQ(since, 1053, "new start");
	since = (unsigned long)-10;
	full = true;
	EXPECT_EQ(xdev_ext_user_full_wait(0, &full, &since, 30, 50), -EAGAIN, "across jiffies wrap: 40 < 50");
	EXPECT_EQ(xdev_ext_user_full_wait(0, &full, &since, 40, 50), -ETIMEDOUT, "across jiffies wrap: 50");
}

static void test_done_window(void)
{
	__u32 cons;
	bool bad;

	cons = 10;
	EXPECT_EQ(xdev_ext_user_done_window(13, &cons, 8, &bad), 3, "three completions to read");
	EXPECT_EQ(cons, 10, "consumer unchanged");
	EXPECT_EQ(bad, 0, "a normal window is no reject");
	EXPECT_EQ(xdev_ext_user_done_window(18, &cons, 8, &bad), 8, "a full window");
	EXPECT_EQ(bad, 0, "a full window is no reject");
	EXPECT_EQ(xdev_ext_user_done_window(1010, &cons, 8, &bad), 8, "runaway producer: newest entries only");
	EXPECT_EQ(cons, 1002, "consumer skips the overwritten entries");
	EXPECT_EQ(bad, 1, "runaway producer is one reject");
	cons = 50;
	EXPECT_EQ(xdev_ext_user_done_window(40, &cons, 8, &bad), 0, "producer behind the consumer: read nothing");
	EXPECT_EQ(cons, 40, "consumer resynchronized to the producer");
	EXPECT_EQ(bad, 1, "producer behind is one reject");
	cons = 0xfffffffcU;
	EXPECT_EQ(xdev_ext_user_done_window(3, &cons, 8, &bad), 7, "window across index wrap");
	EXPECT_EQ(bad, 0, "wrap is no reject");
}

static void test_status_and_length(void)
{
	bool bad;

	bad = true;
	EXPECT_EQ(xdev_ext_user_status_err(0, &bad), 0, "status 0 succeeds");
	EXPECT_EQ(bad, 0, "status 0 is no protocol error");
	EXPECT_EQ(xdev_ext_user_status_err(-EIO, &bad), -EIO, "a negative errno fails the batch with it");
	EXPECT_EQ(bad, 0, "a negative errno is no protocol error");
	EXPECT_EQ(xdev_ext_user_status_err(-4095, &bad), -4095, "-4095 is still an errno");
	EXPECT_EQ(xdev_ext_user_status_err(-4096, &bad), -EPROTO, "below -4095 is -EPROTO");
	EXPECT_EQ(bad, 1, "below -4095 is a protocol error");
	EXPECT_EQ(xdev_ext_user_status_err(5, &bad), -EPROTO, "a positive status is -EPROTO");
	EXPECT_EQ(bad, 1, "a positive status is a protocol error");

	EXPECT_EQ(xdev_ext_user_len_ok(4096, 4096, 4096, 0, false), 1, "length preserved");
	EXPECT_EQ(xdev_ext_user_len_ok(4092, 4096, 4096, 4, false), 1, "exact append of 4");
	EXPECT_EQ(xdev_ext_user_len_ok(4092, 4092, 4096, 4, false), 0, "append rule needs the 4 bytes");
	EXPECT_EQ(xdev_ext_user_len_ok(4096, 4100, 4096, 4, false), 0, "append beyond capacity");
	EXPECT_EQ(xdev_ext_user_len_ok(100, 96, 4096, -4, false), 1, "exact strip of 4");
	EXPECT_EQ(xdev_ext_user_len_ok(4, 0, 4096, -4, false), 0, "an output frame keeps at least one byte");
	EXPECT_EQ(xdev_ext_user_len_ok(100, 1, 4096, 0, true), 1, "variable: one byte");
	EXPECT_EQ(xdev_ext_user_len_ok(100, 4096, 4096, 0, true), 1, "variable: full capacity");
	EXPECT_EQ(xdev_ext_user_len_ok(100, 4097, 4096, 0, true), 0, "variable: past capacity");
	EXPECT_EQ(xdev_ext_user_len_ok(100, 0, 4096, 0, true), 0, "variable: empty output");
	EXPECT_EQ(xdev_ext_user_len_ok(100, 100, 0, 0, false), 0, "no capacity, no output");
}

static void test_stage(void)
{
	struct xdev_ext_mech_stage_uapi u = user_stage(0, 1, 0);
	__s64 delta = 99;
	bool varlen = true;

	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), 0, "stage: deadline 1 ms");
	EXPECT_EQ(delta, 0, "stage: delta 0");
	EXPECT_EQ(varlen, 0, "stage: exact length rule");
	u = user_stage(VARLEN, XDEV_EXT_USER_DEADLINE_MAX_MS, 0);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), 0, "stage: varlen, max deadline");
	EXPECT_EQ(varlen, 1, "stage: variable length rule");
	u = user_stage(VARLEN, 100, 4);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), -EINVAL, "stage: varlen with a delta");
	u = user_stage(0, 0, 0);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), -EINVAL, "stage: zero deadline");
	u = user_stage(0, XDEV_EXT_USER_DEADLINE_MAX_MS + 1, 0);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), -EINVAL, "stage: deadline too long");
	u = user_stage(0, 100, FRAME);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), 0, "stage: delta of one frame");
	u = user_stage(0, 100, -(__s64)FRAME);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), 0, "stage: delta of minus one frame");
	EXPECT_EQ(delta, -(__s64)FRAME, "stage: negative delta kept");
	u = user_stage(0, 100, FRAME + 1);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), -EINVAL, "stage: delta above a frame");
	u = user_stage(0, 100, -(__s64)FRAME - 1);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), -EINVAL, "stage: delta below a frame");
	u = user_stage(2, 100, 0);
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), -EINVAL, "stage: unknown flag");
	u = user_stage(0, 100, 0);
	u.direction = FROM;
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), -EINVAL, "stage: FROM_DEVICE");
	u = user_stage(0, 100, 0);
	u.fd = -1;
	EXPECT_EQ(xdev_ext_user_stage_check(&u, FRAME, &delta, &varlen), -EBADF, "stage: no fd");
}

static void test_create(void)
{
	struct xdev_ext_mech_create c = nvme_user_nvme();

	EXPECT_EQ(check(&c), 0, "CREATE NVMe -> USER(0) -> NVMe");
	c.st[1].flags = XDEV_EXT_MECH_STAGE_F_POLL;
	EXPECT_EQ(check(&c), 0, "POLL is stripped by the generic check; bind refuses it");
	c.st[1].flags = XDEV_EXT_MECH_STAGE_F_FANOUT;
	EXPECT_EQ(check(&c), -EINVAL, "FANOUT on USER");
	c = nvme_user_nvme();
	c.st[1].direction = FROM;
	EXPECT_EQ(check(&c), -EINVAL, "USER FROM_DEVICE");
	c = nvme_user_nvme();
	c.st[1].fd = -1;
	EXPECT_EQ(check(&c), -EBADF, "USER without fd");
	c = nvme_user_nvme();
	c.st[1].arg0 = 0;
	EXPECT_EQ(check(&c), -EINVAL, "USER without deadline");
	c = nvme_user_nvme();
	c.st[1].arg1 = 4;
	EXPECT_EQ(check(&c), -EOPNOTSUPP, "USER(+4) before NVMe WRITE");
	c = nvme_user_nvme();
	c.st[1].flags = VARLEN;
	EXPECT_EQ(check(&c), -EOPNOTSUPP, "USER(varlen) before NVMe WRITE");
	c = nvme_user_nvme();
	c.st[1].flags = 2;
	EXPECT_EQ(check(&c), -EINVAL, "USER unknown flag");
	c = nvme_user_nvme();
	c.st[2] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.direction = TO, .fd = 6 };
	c.st[1].arg1 = (__u64)-4;
	c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	c.pool_fd = 9;
	EXPECT_EQ(check(&c), -EOPNOTSUPP, "USER(-4) before AF_XDP TX");
	c = nvme_user(0, 100, 4);
	EXPECT_EQ(check(&c), 0, "USER(+4) as the last stage");
	c = nvme_user(VARLEN, 100, 0);
	EXPECT_EQ(check(&c), 0, "USER(varlen) as the last stage");
	c = nvme_user(0, 100, 4);
	c.nr_stages = 4;
	c.st[2] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_CPU,
		.direction = TO, .fd = -1, .arg0 = XDEV_EXT_CPU_XFORM_CRC32C_CHECK };
	c.st[3] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = TO, .fd = 6, .arg1 = 64 };
	EXPECT_EQ(check(&c), -EOPNOTSUPP, "USER(+4) -> CPU CHECK -> NVMe: no transform between");
	c.nr_stages = 3;
	memset(&c.st[3], 0, sizeof(c.st[3]));
	EXPECT_EQ(check(&c), 0, "NVMe -> USER(+4) -> CPU CHECK");
	c = nvme_user(0, 100, 4);
	c.nr_stages = 3;
	c.st[2] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_IAA,
		.direction = TO, .fd = 8, .arg0 = 4, .arg1 = FRAME };
	EXPECT_EQ(check(&c), 0, "USER(+4) -> IAA transform");
	c = nvme_user_nvme();
	c.pool_kind = XDEV_EXT_MECH_POOL_PEER;
	c.pool_fd = 9;
	EXPECT_EQ(check(&c), -EOPNOTSUPP, "USER over a device-memory pool");
	c = nvme_user_nvme();
	c.st[1].class_id = XDEV_EXT_MECH_CLASS_MAX;
	EXPECT_EQ(check(&c), -EINVAL, "class id 11 is unknown");
	c = nvme_user_nvme();
	c.nr_stages = 1;
	c.st[0] = user_stage(0, 100, 0);
	memset(&c.st[1], 0, sizeof(c.st[1]));
	memset(&c.st[2], 0, sizeof(c.st[2]));
	EXPECT_EQ(check(&c), 0, "a lone START-driven USER stage");
}

static void test_role(void)
{
	struct xdev_ext_mech_create c = nvme_user_nvme();
	struct xdev_ext_mech_stage_uapi u = user_stage(0, 100, 0);

	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_INPLACE, "USER is INPLACE");
	u.direction = FROM;
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), -EINVAL, "USER FROM_DEVICE has no role");
	EXPECT_EQ(xdev_ext_mech_chain_refs(c.st, 3, 1), 1, "the NVMe READ publication has one reference: USER");
	EXPECT_EQ(xdev_ext_mech_chain_refs(c.st, 3, 2), 1, "the USER republication has one reference: NVMe WRITE");
	EXPECT_EQ(xdev_ext_mech_chain_refs(c.st, 2, 2), 0, "a last USER stage republishes with none");
	EXPECT_EQ(xdev_ext_mech_peer_dirs(XDEV_EXT_MECH_CLASS_USER), 0, "USER has no peer capability");
	EXPECT_EQ(xdev_ext_mech_ret_legal(XDEV_EXT_MECH_CLASS_USER, XDEV_EXT_MECH_MEMBER_BUILD,
					  XDEV_EXT_MECH_SITE_WORKER, XDEV_EXT_MECH_BUILD_DEFAULT), 1,
		  "USER build may return DEFAULT");
	EXPECT_EQ(xdev_ext_mech_ret_legal(XDEV_EXT_MECH_CLASS_USER, XDEV_EXT_MECH_MEMBER_COMPLETE,
					  XDEV_EXT_MECH_SITE_WORKER, XDEV_EXT_MECH_NEXT), 1,
		  "USER complete may return NEXT");
}

static void test_desc(void)
{
	struct xdev_ext_user_desc d = { .version = XDEV_EXT_USER_DESC_VERSION, .arg = 77 };

	EXPECT_EQ(xdev_ext_user_desc_check(&d, 1), 0, "descriptor v1 accepted");
	EXPECT_EQ(xdev_ext_user_desc_check(&d, 2), -EINVAL, "exactly one slot");
	d.flags = 1;
	EXPECT_EQ(xdev_ext_user_desc_check(&d, 1), -EINVAL, "descriptor flags must be 0");
	d.flags = 0;
	d.version = 2;
	EXPECT_EQ(xdev_ext_user_desc_check(&d, 1), -EINVAL, "descriptor version 2 refused");
}

int main(void)
{
	test_uapi();
	test_request();
	test_layout();
	test_rings();
	test_full_wait();
	test_done_window();
	test_status_and_length();
	test_stage();
	test_create();
	test_role();
	test_desc();
	printf("1..%u\n", checks);
	return failures ? 1 : 0;
}
