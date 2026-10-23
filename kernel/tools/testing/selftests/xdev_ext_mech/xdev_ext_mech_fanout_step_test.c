// SPDX-License-Identifier: GPL-2.0
/*
 * User-space checks of the CREATE rules and chain planning for fan-out
 * consumer groups and the in-frame CPU stage (io_uring/xdev_ext_mech_step.h):
 * which stages may run concurrently on one READY publication, how many
 * consumer references a publication installs, and which CPU transform
 * parameters a session may name.  Build with -I <kernel tree>.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

#if defined(XDEV_EXT_MECH_STAGE_F_FANOUT) && defined(XDEV_EXT_MECH_CPU_ABI_VERSION)

#define TO XDEV_EXT_MECH_DIR_TO_DEVICE
#define FROM XDEV_EXT_MECH_DIR_FROM_DEVICE
#define FANOUT XDEV_EXT_MECH_STAGE_F_FANOUT

static struct xdev_ext_mech_stage_uapi stage(__u32 class_id, __u32 dir, __s32 fd,
					     __u32 flags, __u64 arg0, __u64 arg1)
{
	struct xdev_ext_mech_stage_uapi u;

	memset(&u, 0, sizeof(u));
	u.class_id = class_id;
	u.direction = dir;
	u.fd = fd;
	u.flags = flags;
	u.arg0 = arg0;
	u.arg1 = arg1;
	return u;
}

#define NVME_R(fd) stage(XDEV_EXT_MECH_CLASS_NVME, FROM, fd, 0, 1024, 512)
#define NVME_W(fd, fl) stage(XDEV_EXT_MECH_CLASS_NVME, TO, fd, fl, 4096, 512)
#define AF_TX(fl) stage(XDEV_EXT_MECH_CLASS_AFXDP, TO, 5, fl, 0, 0)
#define AF_RX() stage(XDEV_EXT_MECH_CLASS_AFXDP, FROM, 5, 0, 0, 0)
#define CE_H2D(fl) stage(XDEV_EXT_MECH_CLASS_CE, TO, 8, fl, 0, 1 << 20)
#define CE_D2H(fl) stage(XDEV_EXT_MECH_CLASS_CE, FROM, 8, fl, 0, 1 << 20)
#define CPU(x, p) stage(XDEV_EXT_MECH_CLASS_CPU, TO, -1, 0, x, p)
#define IAA_C() stage(XDEV_EXT_MECH_CLASS_IAA, TO, 9, XDEV_EXT_IAA_F_SOFTWARE, 0, 8192)
#define SOCK() stage(XDEV_EXT_MECH_CLASS_SOCKET, TO, 10, 0, 0, 0)

/* A session over @pool with @n stages; 8 KiB groups in 4 KiB frames. */
static struct xdev_ext_mech_create chain(__u32 pool, __u32 n,
					 const struct xdev_ext_mech_stage_uapi *st)
{
	struct xdev_ext_mech_create c;

	memset(&c, 0, sizeof(c));
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = n;
	c.pool_kind = pool;
	c.pool_fd = pool == XDEV_EXT_MECH_POOL_IOU_UMEM ? -1 : 5;
	c.layout.frame_size = 4096;
	c.layout.hdr_room = pool == XDEV_EXT_MECH_POOL_XSK ? 360 : 0;
	c.layout.seg_len = pool == XDEV_EXT_MECH_POOL_XSK ? 1432 : 4096;
	c.layout.group_bytes = 8192;
	c.depth = 4;
	c.eventfd = -1;
	memcpy(c.st, st, n * sizeof(*st));
	return c;
}

static int check(const struct xdev_ext_mech_create *c)
{
	__u32 frames = 0;

	return xdev_ext_mech_create_check(c, &frames);
}

static void test_uapi_values(void)
{
	EXPECT_EQ(XDEV_EXT_MECH_STAGE_F_FANOUT, 1U << 31);
	EXPECT_EQ(XDEV_EXT_MECH_CLASS_CPU, 9);
	EXPECT_EQ(XDEV_EXT_MECH_CLASS_MAX, 10);
	EXPECT_EQ(xdev_ext_mech_class_known(XDEV_EXT_MECH_CLASS_CPU), 1);
	EXPECT_EQ(xdev_ext_mech_class_known(10), 0);
	EXPECT_EQ(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 1);
	EXPECT_EQ(XDEV_EXT_CPU_XFORM_INFLATE, 9);
	EXPECT_EQ(XDEV_EXT_CPU_XFORM_MAX, 10);
	EXPECT_EQ(sizeof(struct xdev_ext_cpu_desc), 16);
	/* The frozen layouts do not move. */
	EXPECT_EQ(sizeof(struct xdev_ext_mech_stage_uapi), 32);
	EXPECT_EQ(sizeof(struct xdev_ext_mech_stats), 168);
}

static void test_fanout_accepted(void)
{
	struct xdev_ext_mech_stage_uapi a[] = { NVME_R(6), NVME_W(7, 0), AF_TX(FANOUT) };
	struct xdev_ext_mech_stage_uapi b[] = { AF_RX(), NVME_W(6, 0), NVME_W(7, FANOUT) };
	struct xdev_ext_mech_stage_uapi d[] = { NVME_R(6), NVME_W(7, 0), NVME_W(11, FANOUT),
						AF_TX(FANOUT) };
	struct xdev_ext_mech_stage_uapi e[] = { CE_H2D(0), NVME_W(7, FANOUT) };
	struct xdev_ext_mech_create c;
	__u32 frames = 0;

	/* NVMe READ -> {NVMe WRITE, AF_XDP TX} on one publication. */
	c = chain(XDEV_EXT_MECH_POOL_XSK, 3, a);
	EXPECT_EQ(xdev_ext_mech_create_check(&c, &frames), 0);
	EXPECT_EQ(frames, 6);
	c = chain(XDEV_EXT_MECH_POOL_XSK, 3, b);
	EXPECT_EQ(check(&c), 0);
	c = chain(XDEV_EXT_MECH_POOL_XSK, 4, d);
	EXPECT_EQ(check(&c), 0);
	/* START user frames feed a group headed by stage 0. */
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 2, e);
	EXPECT_EQ(check(&c), 0);
}

static void test_fanout_rejected(void)
{
	struct xdev_ext_mech_stage_uapi first[] = { NVME_W(7, FANOUT), AF_TX(0) };
	struct xdev_ext_mech_stage_uapi after_producer[] = { NVME_R(6), NVME_W(7, FANOUT) };
	struct xdev_ext_mech_stage_uapi producer[] = { NVME_R(6), CE_H2D(0), CE_D2H(FANOUT),
						       NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi on_cpu[] = { NVME_R(6), NVME_W(7, 0),
		stage(XDEV_EXT_MECH_CLASS_CPU, TO, -1, FANOUT, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0) };
	struct xdev_ext_mech_stage_uapi after_cpu[] = { NVME_R(6),
		CPU(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0), NVME_W(7, FANOUT) };
	struct xdev_ext_mech_stage_uapi on_iaa[] = { NVME_R(6), NVME_W(7, 0),
		stage(XDEV_EXT_MECH_CLASS_IAA, TO, 9, XDEV_EXT_IAA_F_SOFTWARE | FANOUT, 0, 8192) };
	struct xdev_ext_mech_stage_uapi after_iaa[] = { NVME_R(6), IAA_C(), NVME_W(7, FANOUT) };
	struct xdev_ext_mech_stage_uapi other_bit[] = { NVME_R(6), NVME_W(7, 0),
							NVME_W(11, 1U << 30) };
	struct xdev_ext_mech_create c;

	c = chain(XDEV_EXT_MECH_POOL_XSK, 2, first);
	EXPECT_EQ(check(&c), -EINVAL);
	c = chain(XDEV_EXT_MECH_POOL_XSK, 2, after_producer);
	EXPECT_EQ(check(&c), -EINVAL);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 4, producer);
	EXPECT_EQ(check(&c), -EINVAL);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, on_cpu);
	EXPECT_EQ(check(&c), -EINVAL);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, after_cpu);
	EXPECT_EQ(check(&c), -EINVAL);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, on_iaa);
	EXPECT_EQ(check(&c), -EINVAL);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, after_iaa);
	EXPECT_EQ(check(&c), -EINVAL);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, other_bit);
	EXPECT_EQ(check(&c), -EINVAL);
	/* An unused stage slot stays all-zero, the flag included. */
	c = chain(XDEV_EXT_MECH_POOL_XSK, 2, after_producer);
	c.st[1].flags = 0;
	c.st[2].flags = FANOUT;
	EXPECT_EQ(check(&c), -EINVAL);
}

static void test_cpu_stage_rules(void)
{
	struct xdev_ext_mech_stage_uapi st[] = { NVME_R(6), CPU(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0),
						 NVME_W(7, 0) };
	struct xdev_ext_mech_create c, base = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, st);
	__u32 x;

	/* NVMe READ -> CPU -> NVMe WRITE through the ring's UMEM. */
	EXPECT_EQ(check(&base), 0);
	c = base; c.st[1].fd = 3;
	EXPECT_EQ(check(&c), -EINVAL);
	c = base; c.st[1].fd = -2;
	EXPECT_EQ(check(&c), -EINVAL);
	c = base; c.st[1].direction = FROM;
	EXPECT_EQ(check(&c), -EINVAL);
	c = base; c.st[1].flags = 1;
	EXPECT_EQ(check(&c), -EINVAL);
	c = base; c.st[1].arg0 = 0;
	EXPECT_EQ(check(&c), -EINVAL);
	c = base; c.st[1].arg0 = XDEV_EXT_CPU_XFORM_MAX;
	EXPECT_EQ(check(&c), -EINVAL);
	c = base; c.st[1].arg0 = (1ULL << 32) | XDEV_EXT_CPU_XFORM_CRC32C_SEAL;
	EXPECT_EQ(check(&c), -EINVAL);
	/* Parameters that are not used must be zero. */
	for (x = XDEV_EXT_CPU_XFORM_CRC32C_APPEND; x <= XDEV_EXT_CPU_XFORM_CRC32C_CHECK; x++) {
		c = base; c.st[1].arg0 = x; c.st[1].arg1 = 1;
		EXPECT_EQ(check(&c), -EINVAL);
	}
	c = base; c.st[1].arg0 = XDEV_EXT_CPU_XFORM_SHA256_APPEND; c.st[1].arg1 = 1;
	EXPECT_EQ(check(&c), -EINVAL);
	c = base; c.st[1].arg0 = XDEV_EXT_CPU_XFORM_CRC32C_CHECK;
	EXPECT_EQ(check(&c), 0);
	/* Parse header length is bounded. */
	c = base; c.st[2] = SOCK(); c.st[1].arg0 = XDEV_EXT_CPU_XFORM_PARSE_STRIP;
	c.st[1].arg1 = XDEV_EXT_CPU_PARSE_HDR_MIN - 1;
	EXPECT_EQ(check(&c), -EINVAL);
	c.st[1].arg1 = XDEV_EXT_CPU_PARSE_HDR_MIN;
	EXPECT_EQ(check(&c), 0);
	c.st[1].arg1 = XDEV_EXT_CPU_PARSE_HDR_MAX;
	EXPECT_EQ(check(&c), 0);
	c.st[1].arg1 = XDEV_EXT_CPU_PARSE_HDR_MAX + 1;
	EXPECT_EQ(check(&c), -EINVAL);
	/* Any 64-bit hash seed. */
	c = base; c.st[2] = SOCK(); c.st[1].arg0 = XDEV_EXT_CPU_XFORM_XXH64_APPEND;
	c.st[1].arg1 = ~0ULL;
	EXPECT_EQ(check(&c), 0);
	/* Variable output names a bounded destination capacity. */
	c = base; c.st[1].arg0 = XDEV_EXT_CPU_XFORM_DEFLATE; c.st[1].arg1 = 0;
	EXPECT_EQ(check(&c), -EINVAL);
	c.st[1].arg1 = XDEV_EXT_MECH_MAX_FRAMES * 4096ULL;
	EXPECT_EQ(check(&c), 0);
	c.st[1].arg1 = XDEV_EXT_MECH_MAX_FRAMES * 4096ULL + 1;
	EXPECT_EQ(check(&c), -EINVAL);
	c = base; c.st[1].arg0 = XDEV_EXT_CPU_XFORM_INFLATE; c.st[1].arg1 = 8192;
	EXPECT_EQ(check(&c), 0);
	/* No CPU mapping of a peer allocation. */
	c = base; c.pool_kind = XDEV_EXT_MECH_POOL_PEER; c.pool_fd = 5;
	c.layout.frame_size = 65536; c.layout.seg_len = 65536; c.layout.group_bytes = 65536;
	EXPECT_EQ(check(&c), -EOPNOTSUPP);
	/* A CPU stage may read START user frames directly. */
	c = base; c.nr_stages = 2; c.st[0] = c.st[1]; c.st[1] = c.st[2];
	memset(&c.st[2], 0, sizeof(c.st[2]));
	EXPECT_EQ(check(&c), 0);
}

static void test_cpu_length_rule(void)
{
	struct xdev_ext_mech_stage_uapi to_nvme[] = { NVME_R(6),
		CPU(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0), NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi to_afxdp[] = { NVME_R(6),
		CPU(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0), AF_TX(0) };
	struct xdev_ext_mech_stage_uapi strip_to_nvme[] = { NVME_R(6),
		CPU(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 16), NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi via_ce[] = { CPU(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0),
		CE_H2D(0), CE_D2H(0), NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi via_iaa[] = { NVME_R(6),
		CPU(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0), IAA_C(), NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi to_socket[] = { NVME_R(6),
		CPU(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0), SOCK() };
	struct xdev_ext_mech_stage_uapi seal_afxdp[] = { NVME_R(6),
		CPU(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0), AF_TX(0) };
	struct xdev_ext_mech_create c;

	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, to_nvme);
	EXPECT_EQ(check(&c), -EOPNOTSUPP);
	c = chain(XDEV_EXT_MECH_POOL_XSK, 3, to_afxdp);
	EXPECT_EQ(check(&c), -EOPNOTSUPP);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, strip_to_nvme);
	EXPECT_EQ(check(&c), -EOPNOTSUPP);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 4, via_ce);
	EXPECT_EQ(check(&c), -EOPNOTSUPP);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 4, via_iaa);
	EXPECT_EQ(check(&c), 0);
	c = chain(XDEV_EXT_MECH_POOL_IOU_UMEM, 3, to_socket);
	EXPECT_EQ(check(&c), 0);
	/* NVMe READ -> CPU -> AF_XDP TX with a length-preserving transform. */
	c = chain(XDEV_EXT_MECH_POOL_XSK, 3, seal_afxdp);
	EXPECT_EQ(check(&c), 0);
}

static void test_stage_roles(void)
{
	struct xdev_ext_mech_stage_uapi u;

	u = NVME_R(6);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_PRODUCER);
	u = NVME_W(6, 0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_CONSUMER);
	u = NVME_W(6, FANOUT);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_CONSUMER);
	u = AF_RX();
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_PRODUCER);
	u = AF_TX(0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_CONSUMER);
	u = CE_H2D(0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_CONSUMER);
	u = CE_D2H(0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_PRODUCER);
	u = stage(XDEV_EXT_MECH_CLASS_DMA, FROM, 3, 0, 0, 4096);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_PRODUCER);
	u = stage(XDEV_EXT_MECH_CLASS_DMA, TO, 3, 0, 0, 4096);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_CONSUMER);
	u = SOCK();
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_CONSUMER);
	u = stage(XDEV_EXT_MECH_CLASS_NET, TO, 3, 0, 0, 0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_CONSUMER);
	u = IAA_C();
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_TRANSFORM);
	u.direction = FROM;
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_TRANSFORM);
	u = CPU(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_INPLACE);
	u = CPU(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_INPLACE);
	u = CPU(XDEV_EXT_CPU_XFORM_DEFLATE, 8192);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_TRANSFORM);
	u = CPU(XDEV_EXT_CPU_XFORM_INFLATE, 8192);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), XDEV_EXT_MECH_ROLE_TRANSFORM);
	u = CPU(0, 0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), -EINVAL);
	u = stage(11, TO, 3, 0, 0, 0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), -EINVAL);
	u = stage(XDEV_EXT_MECH_CLASS_NVME, 0, 3, 0, 0, 0);
	EXPECT_EQ(xdev_ext_mech_stage_role(&u), -EINVAL);
}

static void test_chain_refs(void)
{
	struct xdev_ext_mech_stage_uapi fan[] = { NVME_R(6), NVME_W(7, 0), AF_TX(FANOUT) };
	struct xdev_ext_mech_stage_uapi a[] = { NVME_R(6), CE_H2D(0), CE_D2H(0), NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi d[] = { CE_H2D(0), CE_D2H(0) };
	struct xdev_ext_mech_stage_uapi cpu[] = { NVME_R(6), CPU(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0),
						  NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi mixed[] = { NVME_R(6), NVME_W(7, 0),
		CPU(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0), AF_TX(0) };
	struct xdev_ext_mech_stage_uapi iaa[] = { NVME_R(6), IAA_C(), NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi rx[] = { AF_RX(), NVME_W(7, 0) };
	struct xdev_ext_mech_stage_uapi wide[] = { NVME_R(6), NVME_W(7, 0), NVME_W(11, FANOUT),
						   AF_TX(FANOUT) };

	/* Both members of the fan-out group read the READ publication. */
	EXPECT_EQ(xdev_ext_mech_chain_refs(fan, 3, 1), 2);
	EXPECT_EQ(xdev_ext_mech_chain_refs(wide, 4, 1), 3);
	/* Chain a: CE D2H writes the frame again only after CE H2D's reference. */
	EXPECT_EQ(xdev_ext_mech_chain_refs(a, 4, 1), 1);
	EXPECT_EQ(xdev_ext_mech_chain_refs(a, 4, 3), 1);
	/* START publication of chain d; the last producer publishes to nobody. */
	EXPECT_EQ(xdev_ext_mech_chain_refs(d, 2, 0), 1);
	EXPECT_EQ(xdev_ext_mech_chain_refs(d, 2, 2), 0);
	/* The in-frame stage is the last reader of the old version ... */
	EXPECT_EQ(xdev_ext_mech_chain_refs(cpu, 3, 1), 1);
	/* ... and its republication feeds the next stage. */
	EXPECT_EQ(xdev_ext_mech_chain_refs(cpu, 3, 2), 1);
	EXPECT_EQ(xdev_ext_mech_chain_refs(mixed, 4, 1), 2);
	EXPECT_EQ(xdev_ext_mech_chain_refs(mixed, 4, 3), 1);
	/* A variable-output transform reads the source; its output is new frames. */
	EXPECT_EQ(xdev_ext_mech_chain_refs(iaa, 3, 1), 1);
	EXPECT_EQ(xdev_ext_mech_chain_refs(iaa, 3, 2), 1);
	EXPECT_EQ(xdev_ext_mech_chain_refs(rx, 2, 1), 1);
	EXPECT_EQ(xdev_ext_mech_chain_refs(rx, 2, 2), 0);
}

static void test_group_end(void)
{
	struct xdev_ext_mech_stage_uapi fan[] = { NVME_R(6), NVME_W(7, 0), AF_TX(FANOUT) };
	struct xdev_ext_mech_stage_uapi wide[] = { NVME_R(6), NVME_W(7, 0), NVME_W(11, FANOUT),
						   AF_TX(FANOUT) };
	struct xdev_ext_mech_stage_uapi serial[] = { NVME_R(6), NVME_W(7, 0), AF_TX(0) };
	struct xdev_ext_mech_stage_uapi split[] = { NVME_R(6), NVME_W(7, 0), NVME_W(11, FANOUT),
						    AF_TX(0) };

	EXPECT_EQ(xdev_ext_mech_stage_group_end(fan, 3, 0), 1);
	EXPECT_EQ(xdev_ext_mech_stage_group_end(fan, 3, 1), 3);
	EXPECT_EQ(xdev_ext_mech_stage_group_end(wide, 4, 1), 4);
	EXPECT_EQ(xdev_ext_mech_stage_group_end(serial, 3, 1), 2);
	EXPECT_EQ(xdev_ext_mech_stage_group_end(serial, 3, 2), 3);
	EXPECT_EQ(xdev_ext_mech_stage_group_end(split, 4, 1), 3);
	EXPECT_EQ(xdev_ext_mech_stage_group_end(split, 4, 3), 4);
	/* After the fan-out group the last stage depends on both members. */
	EXPECT_EQ(xdev_ext_mech_chain_refs(split, 4, 1), 3);
}

static const struct {
	const char *name;
	void (*run)(void);
} tests[] = {
	{ "L3/L7 UAPI values and frozen layouts", test_uapi_values },
	{ "L3 CREATE accepts fan-out consumer groups", test_fanout_accepted },
	{ "L3 CREATE rejects misplaced fan-out flags", test_fanout_rejected },
	{ "L7 CREATE rules of the CPU stage", test_cpu_stage_rules },
	{ "L7 length-changing transform before a fixed-group class", test_cpu_length_rule },
	{ "L2 stage roles", test_stage_roles },
	{ "L2 references installed per publication", test_chain_refs },
	{ "L3 concurrent group boundaries", test_group_end },
};
#define NR_TESTS (sizeof(tests) / sizeof(tests[0]))
#define HAVE_API 1
#else
static const char *const names[] = {
	"L3/L7 UAPI values and frozen layouts",
	"L3 CREATE accepts fan-out consumer groups",
	"L3 CREATE rejects misplaced fan-out flags",
	"L7 CREATE rules of the CPU stage",
	"L7 length-changing transform before a fixed-group class",
	"L2 stage roles",
	"L2 references installed per publication",
	"L3 concurrent group boundaries",
};
#define NR_TESTS (sizeof(names) / sizeof(names[0]))
#define HAVE_API 0
#endif

int main(void)
{
	unsigned int i, failed = 0;

	printf("TAP version 13\n1..%zu\n", NR_TESTS);
	for (i = 0; i < NR_TESTS; i++) {
#if HAVE_API
		unsigned int before = failures;

		tests[i].run();
		printf("%s %u - %s\n", failures == before ? "ok" : "not ok", i + 1, tests[i].name);
		failed += failures != before;
#else
		printf("not ok %u - %s # missing API: XDEV_EXT_MECH_STAGE_F_FANOUT / "
		       "XDEV_EXT_MECH_CPU_ABI_VERSION (fan-out and CPU stage contract)\n",
		       i + 1, names[i]);
		failed++;
#endif
	}
	(void)checks;
	(void)failures;
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
