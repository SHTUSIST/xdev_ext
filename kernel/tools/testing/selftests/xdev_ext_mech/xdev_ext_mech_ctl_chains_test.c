// SPDX-License-Identifier: GPL-2.0
/*
 * Host contract of the ctl helpers for the fan-out chain
 * (NVMe READ -> {NVMe WRITE, AF_XDP TX}) and the CPU chains
 * (NVMe READ -> CPU -> NVMe WRITE or AF_XDP TX): the stage arrays they
 * build pass the CREATE checker, and the user-space oracle the guest uses
 * to judge transformed bytes agrees with independent implementations
 * (xform_oracle.h).  Build with -I <kernel tree> -I <this directory>.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tools/xdev_ext_mech/xdev_ext_mech_ctl_core.h"
#include "io_uring/xdev_ext_mech_step.h"
#include "xform_oracle.h"

#define CHECK(expr) do {                                                     \
	if (!(expr)) {                                                        \
		fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr);        \
		return false;                                                  \
	}                                                                     \
} while (0)

#if defined(XDEV_EXT_MECH_CTL_CHAINS_V2) && defined(XDEV_EXT_MECH_STAGE_F_FANOUT)

struct guarded {
	struct xdev_ext_mech_stage_uapi st[XDEV_EXT_MECH_MAX_STAGES];
	uint64_t guard;
};

static void poison(struct guarded *g)
{
	memset(g, 0xa5, sizeof(*g));
	g->guard = 0x0123456789abcdefULL;
}

static bool untouched(const struct guarded *g)
{
	const unsigned char *p = (const unsigned char *)g->st;
	size_t i;

	for (i = 0; i < sizeof(g->st); i++)
		if (p[i] != 0xa5)
			return false;
	return g->guard == 0x0123456789abcdefULL;
}

static struct xdev_ext_mech_create create_of(const struct guarded *g, __u32 n, __u32 pool)
{
	struct xdev_ext_mech_create c;

	memset(&c, 0, sizeof(c));
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = n;
	c.pool_kind = pool;
	c.pool_fd = pool == XDEV_EXT_MECH_POOL_IOU_UMEM ? -1 : 100003;
	c.layout.frame_size = 4096;
	c.layout.hdr_room = pool == XDEV_EXT_MECH_POOL_XSK ? 360 : 0;
	c.layout.seg_len = pool == XDEV_EXT_MECH_POOL_XSK ? 1432 : 4096;
	c.layout.group_bytes = 8192;
	c.depth = 4;
	c.eventfd = -1;
	memcpy(c.st, g->st, sizeof(c.st));
	return c;
}

static bool test_xform_names(void)
{
	static const struct { const char *name; __u32 x; } names[] = {
		{ "crc32c-append", XDEV_EXT_CPU_XFORM_CRC32C_APPEND },
		{ "crc32c-strip", XDEV_EXT_CPU_XFORM_CRC32C_STRIP },
		{ "crc32c-seal", XDEV_EXT_CPU_XFORM_CRC32C_SEAL },
		{ "crc32c-check", XDEV_EXT_CPU_XFORM_CRC32C_CHECK },
		{ "parse-strip", XDEV_EXT_CPU_XFORM_PARSE_STRIP },
		{ "xxh64-append", XDEV_EXT_CPU_XFORM_XXH64_APPEND },
		{ "sha256-append", XDEV_EXT_CPU_XFORM_SHA256_APPEND },
		{ "deflate", XDEV_EXT_CPU_XFORM_DEFLATE },
		{ "inflate", XDEV_EXT_CPU_XFORM_INFLATE },
	};
	static const char *const bad[] = { "", "crc32c", "CRC32C-APPEND", "crc32c-append ",
					   "deflate-iaa", "none" };
	unsigned int i;
	__u32 x;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		x = 0;
		CHECK(!xdev_ext_mech_ctl_xform_parse(names[i].name, &x));
		CHECK(x == names[i].x);
	}
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		x = 77;
		CHECK(xdev_ext_mech_ctl_xform_parse(bad[i], &x) == -EINVAL);
		CHECK(x == 77);
	}
	return true;
}

static bool test_fanout_stages(void)
{
	struct guarded g;
	struct xdev_ext_mech_stage_uapi want[3] = {
		{ .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE,
		  .fd = 100001, .arg0 = 2048, .arg1 = 64 },
		{ .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
		  .fd = 100002, .arg0 = (1ULL << 33) + 9, .arg1 = 64 },
		{ .class_id = XDEV_EXT_MECH_CLASS_AFXDP, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
		  .fd = 100003, .flags = XDEV_EXT_MECH_STAGE_F_FANOUT },
	};
	struct xdev_ext_mech_stage_uapi zero;
	struct xdev_ext_mech_create c;
	__u32 frames;

	memset(&zero, 0, sizeof(zero));
	poison(&g);
	CHECK(xdev_ext_mech_ctl_fanout_stages(g.st, 100001, 2048, 64, 100002,
					      (1ULL << 33) + 9, 64, 100003) == 3);
	CHECK(!memcmp(g.st, want, sizeof(want)));
	CHECK(!memcmp(&g.st[3], &zero, sizeof(zero)));
	CHECK(g.guard == 0x0123456789abcdefULL);
	c = create_of(&g, 3, XDEV_EXT_MECH_POOL_XSK);
	CHECK(!xdev_ext_mech_create_check(&c, &frames));
	CHECK(xdev_ext_mech_chain_refs(c.st, 3, 1) == 2);
	CHECK(xdev_ext_mech_stage_group_end(c.st, 3, 1) == 3);
	poison(&g);
	CHECK(xdev_ext_mech_ctl_fanout_stages(g.st, -1, 2048, 64, 100002, 9, 64, 100003) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_fanout_stages(g.st, 100001, 2048, 64, -1, 9, 64, 100003) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_fanout_stages(g.st, 100001, 2048, 64, 100002, 9, 64, -1) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_fanout_stages(g.st, 100001, 2048, 0, 100002, 9, 64, 100003) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_fanout_stages(g.st, 100001, 2048, 64, 100002, 9, 0, 100003) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_fanout_stages(NULL, 100001, 2048, 64, 100002, 9, 64, 100003) == -EINVAL);
	CHECK(untouched(&g));
	return true;
}

static bool test_cpu_stages(void)
{
	struct guarded g;
	struct xdev_ext_mech_stage_uapi want[3] = {
		{ .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_FROM_DEVICE,
		  .fd = 100001, .arg0 = 2048, .arg1 = 64 },
		{ .class_id = XDEV_EXT_MECH_CLASS_CPU, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
		  .fd = -1, .arg0 = XDEV_EXT_CPU_XFORM_CRC32C_SEAL, .arg1 = 0 },
		{ .class_id = XDEV_EXT_MECH_CLASS_NVME, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
		  .fd = 100002, .arg0 = 8192, .arg1 = 64 },
	};
	struct xdev_ext_mech_stage_uapi zero;
	struct xdev_ext_mech_create c;
	__u32 frames;

	memset(&zero, 0, sizeof(zero));
	/* NVMe READ -> CPU -> NVMe WRITE. */
	poison(&g);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, 100001, 2048, 64, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0,
					   XDEV_EXT_MECH_CLASS_NVME, 100002, 8192, 64) == 3);
	CHECK(!memcmp(g.st, want, sizeof(want)));
	CHECK(!memcmp(&g.st[3], &zero, sizeof(zero)));
	CHECK(g.guard == 0x0123456789abcdefULL);
	c = create_of(&g, 3, XDEV_EXT_MECH_POOL_IOU_UMEM);
	CHECK(!xdev_ext_mech_create_check(&c, &frames));
	/* NVMe READ -> CPU -> AF_XDP TX. */
	poison(&g);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, 100001, 2048, 64, XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0,
					   XDEV_EXT_MECH_CLASS_AFXDP, 100003, 0, 0) == 3);
	CHECK(g.st[2].class_id == XDEV_EXT_MECH_CLASS_AFXDP &&
	      g.st[2].direction == XDEV_EXT_MECH_DIR_TO_DEVICE && g.st[2].fd == 100003 &&
	      !g.st[2].flags && !g.st[2].arg0 && !g.st[2].arg1);
	CHECK(g.st[1].arg0 == XDEV_EXT_CPU_XFORM_CRC32C_CHECK);
	c = create_of(&g, 3, XDEV_EXT_MECH_POOL_XSK);
	CHECK(!xdev_ext_mech_create_check(&c, &frames));
	/* The parameter is passed through. */
	poison(&g);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, 100001, 2048, 64, XDEV_EXT_CPU_XFORM_XXH64_APPEND,
					   ~0ULL, XDEV_EXT_MECH_CLASS_NVME, 100002, 8192, 64) == 3);
	CHECK(g.st[1].arg1 == ~0ULL);
	/* An appended digest cannot feed an NVMe WRITE of the fixed group. */
	c = create_of(&g, 3, XDEV_EXT_MECH_POOL_IOU_UMEM);
	CHECK(xdev_ext_mech_create_check(&c, &frames) == -EOPNOTSUPP);
	poison(&g);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, 100001, 2048, 64, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0,
					   XDEV_EXT_MECH_CLASS_SOCKET, 100002, 0, 0) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, 100001, 2048, 64, 0, 0,
					   XDEV_EXT_MECH_CLASS_NVME, 100002, 8192, 64) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, 100001, 2048, 64, XDEV_EXT_CPU_XFORM_MAX, 0,
					   XDEV_EXT_MECH_CLASS_NVME, 100002, 8192, 64) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, -1, 2048, 64, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0,
					   XDEV_EXT_MECH_CLASS_NVME, 100002, 8192, 64) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, 100001, 2048, 64, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0,
					   XDEV_EXT_MECH_CLASS_NVME, -1, 8192, 64) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_cpu_stages(g.st, 100001, 2048, 0, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0,
					   XDEV_EXT_MECH_CLASS_NVME, 100002, 8192, 64) == -EINVAL);
	CHECK(untouched(&g));
	return true;
}

static void fill(__u8 *p, __u32 n, unsigned int seed)
{
	__u32 i;

	for (i = 0; i < n; i++) {
		seed = seed * 1103515245U + 12345U;
		p[i] = (__u8)(seed >> 16);
	}
}

/* The oracle applied segment by segment, from xform_oracle.h only. */
static __u32 expect_independent(__u32 x, __u64 param, __u32 seg, const __u8 *src, __u32 len,
				__u8 *out)
{
	__u32 off, n, o = 0;

	for (off = 0; off < len; off += n) {
		n = len - off < seg ? len - off : seg;
		memcpy(out + o, src + off, n);
		switch (x) {
		case XDEV_EXT_CPU_XFORM_CRC32C_APPEND:
			oracle_put_le32(out + o + n, oracle_crc32c(src + off, n));
			o += n + 4;
			break;
		case XDEV_EXT_CPU_XFORM_CRC32C_SEAL:
			oracle_put_le32(out + o + n - 4, oracle_crc32c(src + off, n - 4));
			o += n;
			break;
		case XDEV_EXT_CPU_XFORM_XXH64_APPEND:
			oracle_put_be64(out + o + n, oracle_xxh64(src + off, n, param));
			o += n + 8;
			break;
		case XDEV_EXT_CPU_XFORM_SHA256_APPEND:
			oracle_sha256(src + off, n, out + o + n);
			o += n + 32;
			break;
		}
	}
	return o;
}

static bool test_oracle_agrees(void)
{
	static const __u32 xs[] = { XDEV_EXT_CPU_XFORM_CRC32C_APPEND, XDEV_EXT_CPU_XFORM_CRC32C_SEAL,
				    XDEV_EXT_CPU_XFORM_XXH64_APPEND, XDEV_EXT_CPU_XFORM_SHA256_APPEND };
	static const __u32 segs[] = { 1432, 4096, 7, 8192 };
	/* Seven-byte segments carry 1171 digests: room for every SHA-256 one. */
	static __u8 src[8192], want[8192 + 1171 * 32], got[8192 + 1171 * 32];
	unsigned int i, j;
	__u32 n, wn;

	CHECK(oracle_self_test());
	fill(src, sizeof(src), 1);
	for (i = 0; i < sizeof(xs) / sizeof(xs[0]); i++) {
		for (j = 0; j < sizeof(segs) / sizeof(segs[0]); j++) {
			if (xs[i] == XDEV_EXT_CPU_XFORM_CRC32C_SEAL && segs[j] < 8)
				continue;
			__u64 param = xs[i] == XDEV_EXT_CPU_XFORM_XXH64_APPEND ? 0x5eed : 0;

			wn = expect_independent(xs[i], param, segs[j], src, sizeof(src), want);
			n = 0;
			memset(got, 0, sizeof(got));
			CHECK(!xdev_ext_mech_ctl_xform_expect(xs[i], param, segs[j], src, sizeof(src),
							       got, sizeof(got), &n));
			CHECK(n == wn);
			CHECK(!memcmp(got, want, n));
		}
	}
	/* Parameters are checked as at CREATE. */
	CHECK(xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 1, 4096, src, 8192,
					      got, sizeof(got), &n) == -EINVAL);
	/* Exactly enough room, then one byte short. */
	wn = expect_independent(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 1432, src, 8192, want);
	CHECK(!xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 1432, src, 8192,
					       got, wn, &n));
	CHECK(n == wn);
	CHECK(xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 1432, src, 8192,
					      got, wn - 1, &n) == -EMSGSIZE);
	return true;
}

static bool test_oracle_verifies(void)
{
	__u8 src[4096 + 8], sealed[4096 + 8], out[4096 + 8];
	__u32 n = 0, i, want_len;

	fill(src, 4096, 9);
	/* Two sealed 2048-byte segments verify and strip; a damaged one fails. */
	CHECK(!xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, 2048, src, 4096,
					       sealed, sizeof(sealed), &n));
	CHECK(n == 4096);
	CHECK(!xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0, 2048, sealed, 4096,
					       out, sizeof(out), &n));
	CHECK(n == 4096 && !memcmp(out, sealed, 4096));
	CHECK(!xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0, 2048, sealed, 4096,
					       out, sizeof(out), &n));
	CHECK(n == 4088);
	CHECK(!memcmp(out, sealed, 2044) && !memcmp(out + 2044, sealed + 2048, 2044));
	sealed[3000] ^= 0x40;
	CHECK(xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0, 2048, sealed, 4096,
					      out, sizeof(out), &n) == -EBADMSG);
	/* Parse-strip per segment: LE32 payload length, header of h bytes. */
	for (i = 0; i < 2; i++)
		oracle_put_le32(src + i * 2048, 2048 - 32);
	CHECK(!xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 32, 2048, src, 4096,
					       out, sizeof(out), &n));
	want_len = 2 * (2048 - 32);
	CHECK(n == want_len);
	CHECK(!memcmp(out, src + 32, 2016) && !memcmp(out + 2016, src + 2048 + 32, 2016));
	oracle_put_le32(src + 2048, 7);
	CHECK(xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 32, 2048, src, 4096,
					      out, sizeof(out), &n) == -EBADMSG);
	/* Variable output is judged by a round trip, not by this oracle. */
	CHECK(xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_DEFLATE, 8192, 2048, src, 4096,
					      out, sizeof(out), &n) == -EINVAL);
	CHECK(xdev_ext_mech_ctl_xform_expect(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, 0, src, 4096,
					      out, sizeof(out), &n) == -EINVAL);
	return true;
}

#define FN(f) f
#else
#define FN(f) NULL
#endif

int main(void)
{
	static const struct {
		const char *name;
		bool (*run)(void);
	} tests[] = {
		{ "L7 ctl transform names", FN(test_xform_names) },
		{ "L3 ctl fan-out stages pass CREATE", FN(test_fanout_stages) },
		{ "L7 ctl CPU chain stages pass CREATE", FN(test_cpu_stages) },
		{ "L7 ctl oracle agrees with independent oracles", FN(test_oracle_agrees) },
		{ "L7 ctl oracle verification and parse", FN(test_oracle_verifies) },
	};
	unsigned int i, failed = 0;

	printf("TAP version 13\n1..%zu\n", sizeof(tests) / sizeof(tests[0]));
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		bool ok = tests[i].run && tests[i].run();

		printf("%s %u - %s%s\n", ok ? "ok" : "not ok", i + 1, tests[i].name,
		       tests[i].run ? "" :
		       " # missing API: XDEV_EXT_MECH_CTL_CHAINS_V2 (ctl fan-out and CPU chain contract)");
		failed += !ok;
	}
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
