// SPDX-License-Identifier: GPL-2.0
/* Frozen X1 §4.1/X1: adding one NETWORK row admits PEER XDOMAIN I/O.
 * 42-XDOMAIN-HOST (ASK.43 option b) extends the row to IOU_UMEM host-page
 * frames for both directions; an AF_XDP (XSK) pool stays refused.
 * Catch a missing/wrong row, broadened flags/pools/roles and ABI drift.
 * Pure rules only; no native-I/O, verifier or hardware claim.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "io_uring/xdev_ext_mech_step.h"
#include "include/linux/xdev_ext_family_core.h"

#ifndef XDEV_EXT_XDOMAIN_PROTO_VERSION
int main(void)
{
	puts("not ok 1 - no XDOMAIN protocol ABI");
	return 1;
}
#else
static unsigned checks, failures;
#define EQ(actual, expected) do { \
	long long got = (long long)(actual), want = (long long)(expected); \
	checks++; \
	if (got != want) { \
		fprintf(stderr, "line %d: %s got %lld expected %lld\n", \
			__LINE__, #actual, got, want); \
		failures++; \
	} \
} while (0)

static struct xdev_ext_mech_create request(void)
{
	return (struct xdev_ext_mech_create) {
		.abi_version = XDEV_EXT_MECH_ABI_VERSION, .nr_stages = 2,
		.pool_kind = XDEV_EXT_MECH_POOL_PEER, .pool_fd = 3,
		.layout = { .frame_size = 65536, .seg_len = 65536,
			    .group_bytes = 131072 }, .depth = 2, .eventfd = -1,
		.st = {
			{ .class_id = XDEV_EXT_MECH_CLASS_NVME,
			  .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 4, .arg1 = 256 },
			{ .class_id = XDEV_EXT_MECH_CLASS_XDOMAIN,
			  .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 5, .arg0 = 1 },
		},
	};
}

int main(void)
{
	struct xdev_ext_mech_create c = request();
	const struct xdev_ext_mech_class_desc *d = xdev_ext_mech_class_desc(11);
	__u32 frames = UINT32_MAX;

	EQ(XDEV_EXT_MECH_CLASS_XDOMAIN, 11);
	EQ(XDEV_EXT_MECH_CLASS_MAX, 13);
	EQ(XDEV_EXT_XDOMAIN_PROTO_VERSION, 1);
	EQ(XDEV_EXT_XDOMAIN_KNOWN_FLAGS, 3);
	EQ(XDEV_EXT_XDOMAIN_F_ALLOW_UNVERIFIED, 1);
	EQ(XDEV_EXT_XDOMAIN_F_EARLY, 2);
	EQ(XDEV_EXT_XDOMAIN_MAX_FRAME, 4096);
	EQ(XDEV_EXT_XDOMAIN_MAX_ELEMS, 64);
	EQ(XDEV_EXT_XDOMAIN_TAG_LEN, 24);
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EQ(frames, 2);
	c.st[1].flags = XDEV_EXT_XDOMAIN_F_ALLOW_UNVERIFIED;
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	c.st[1].flags = XDEV_EXT_XDOMAIN_F_EARLY;
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	c.st[1].flags |= XDEV_EXT_XDOMAIN_F_ALLOW_UNVERIFIED;
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	for (__u32 bit = 2; bit < 29; bit++) {
		c.st[1].flags = 1U << bit;
		EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	}
	/* Host pages: NVMe READ -> XDOMAIN TX at stage 1 on the ring's UMEM. */
	c = request(); c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM; c.pool_fd = -1;
	frames = UINT32_MAX;
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EQ(frames, 2);
	/* Host pages: XDOMAIN RX at stage 0 -> NVMe WRITE. */
	c.st[0] = request().st[1]; c.st[0].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	c.st[1] = request().st[0]; c.st[1].direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
	frames = UINT32_MAX;
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EQ(frames, 2);
	/* TODO.74, TP host frames, send side: the GPU copy engine moves a batch
	 * from its slot of the device window into the ring's UMEM frames (CE
	 * FROM_DEVICE, flags 0), then XDOMAIN transmits those frames. */
	c = request(); c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM; c.pool_fd = -1;
	c.st[0] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_CE,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = 6,
		.arg0 = 0x7f0000000000ULL, .arg1 = 262144 };
	frames = UINT32_MAX;
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EQ(frames, 2);
	EQ(xdev_ext_mech_stage_role(&c.st[0]), XDEV_EXT_MECH_ROLE_PRODUCER);
	EQ(xdev_ext_mech_stage_role(&c.st[1]), XDEV_EXT_MECH_ROLE_CONSUMER);
	/* A range target is not the send side: CE D2H with TARGET_RANGE still
	 * needs an NVMe WRITE after it. */
	c.st[0].flags = XDEV_EXT_CE_STAGE_F_TARGET_RANGE;
	EQ(xdev_ext_mech_create_check(&c, &frames), -EOPNOTSUPP);
	/* The send pair needs host frames: refused on a PEER or an XSK pool. */
	c.st[0].flags = 0; c.pool_kind = XDEV_EXT_MECH_POOL_PEER; c.pool_fd = 3;
	EQ(xdev_ext_mech_create_check(&c, &frames), -EOPNOTSUPP);
	c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	EQ(xdev_ext_mech_create_check(&c, &frames), -EOPNOTSUPP);
	/* TP host frames, receive side: XDOMAIN RX into UMEM frames, then the CE
	 * range target writes the whole group into the device window. */
	c = request(); c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM; c.pool_fd = -1;
	c.st[0] = request().st[1]; c.st[0].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	c.st[1] = (struct xdev_ext_mech_stage_uapi){ .class_id = XDEV_EXT_MECH_CLASS_CE,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = 6,
		.flags = XDEV_EXT_CE_STAGE_F_TARGET_RANGE,
		.arg0 = 0x7f0000000000ULL, .arg1 = 262144 };
	frames = UINT32_MAX;
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EQ(frames, 2);
	/* The generic UMEM rule still applies: the UMEM is not an fd. */
	c = request(); c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM; c.pool_fd = 3;
	EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = request(); c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	EQ(xdev_ext_mech_create_check(&c, &frames), -EOPNOTSUPP);
	/* An XSK pool is refused by the XDOMAIN row, after the generic flag rule. */
	c.st[1].flags = 1U << 24;
	EQ(xdev_ext_mech_create_check(&c, &frames), -EINVAL);
	c = request(); c.st[0] = c.st[1];
	c.st[0].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	c.st[1] = request().st[0]; c.st[1].direction = XDEV_EXT_MECH_DIR_TO_DEVICE;
	EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EQ(xdev_ext_mech_stage_role(&c.st[0]), XDEV_EXT_MECH_ROLE_PRODUCER);
	EQ(xdev_ext_mech_stage_role(&c.st[1]), XDEV_EXT_MECH_ROLE_CONSUMER);
	EQ(xdev_ext_mech_peer_dirs(11), 6);
	EQ(xdev_ext_mech_class_family(11), XDEV_EXT_FAMILY_NETWORK);
	EQ(d->family, 1); EQ(d->peer_dirs, 6); EQ(d->peer_only, 0);
	EQ(d->known_flags, 3); EQ(d->flags_later, 0);
	EQ(d->role_rule, 1); EQ(d->ctx_rule, 4); EQ(d->no_file, 0);
	EQ(d->flags_ok == NULL, 1);
	c.st[0].direction = 0;
	EQ(xdev_ext_mech_stage_role(&c.st[0]), -EINVAL);
	c.st[0].direction = 3;
	EQ(xdev_ext_mech_stage_role(&c.st[0]), -EINVAL);

	EQ(sizeof(struct xdev_ext_mech_stage_caps), 64);
	EQ(sizeof(struct xdev_ext_xdomain_desc), 64);
	EQ(offsetof(struct xdev_ext_xdomain_desc, group), 16);
	EQ(offsetof(struct xdev_ext_xdomain_desc, tag), 24);
	EQ(sizeof(struct xdev_ext_xdomain_mech_cqe), 64);
	EQ(offsetof(struct xdev_ext_xdomain_mech_cqe, tag), 40);
	EQ(sizeof(struct xdev_ext_xdomain_mech_info) <= 4096, 1);
	EQ(XDEV_EXT_MECH_SITE_WORKER_PROTOCOL, 7);
	EQ(XDEV_EXT_MECH_SITE_WORKER, 0); EQ(XDEV_EXT_MECH_SITE_RX_GENERIC, 1);
	EQ(XDEV_EXT_MECH_SITE_RX_NATIVE, 2); EQ(XDEV_EXT_MECH_SITE_URING_CMD, 3);
	EQ(XDEV_EXT_MECH_SITE_CREATE, 4); EQ(XDEV_EXT_MECH_SITE_RX_HOLD_RESULT, 5);
	EQ(XDEV_EXT_MECH_SITE_WORKER_SELECT, 6);
	EQ(sizeof(struct xdev_ext_xdomain_proto_info), 256);
	EQ(offsetof(struct xdev_ext_xdomain_proto_info, tag), 200);
	EQ(offsetof(struct xdev_ext_xdomain_proto_info, reserved), 224);
	EQ(sizeof(struct xdev_ext_xdomain_proto_verdict), 64);
	EQ(offsetof(struct xdev_ext_xdomain_proto_verdict, event_id), 16);
	EQ(offsetof(struct xdev_ext_xdomain_proto_verdict, status), 48);
	printf("%s 1 - XDOMAIN pure CREATE/class and pointer-free protocol ABI (%u checks, %u failures)\n",
	       failures ? "not ok" : "ok", checks, failures);
	return failures != 0;
}
#endif
