// SPDX-License-Identifier: GPL-2.0
/*
 * Host tests of the fixed in-frame CPU transforms (io_uring/xdev_ext_mech_cpu_core.h):
 * output length and bounds, exact output bytes against independent oracles
 * (xform_oracle.h), verification failures that leave the frame unchanged,
 * nothing ever written past the frame boundary, the variable-output result
 * rule, and the bounded per-batch selection a program may make.
 * Build with -I <kernel tree>.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xform_oracle.h"

#if defined(__has_include)
#if __has_include("io_uring/xdev_ext_mech_cpu_core.h")
#include "io_uring/xdev_ext_mech_cpu_core.h"
#define HAVE_CPU_CORE 1
#endif
#endif

#define CHECK(expr) do {                                                     \
	if (!(expr)) {                                                        \
		fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr);        \
		return false;                                                  \
	}                                                                     \
} while (0)

static bool test_oracles(void)
{
	CHECK(oracle_self_test());
	return true;
}

#ifdef HAVE_CPU_CORE

#define GUARD 64
#define GUARD_BYTE 0xc5

static void prim_sha256(const void *p, size_t len, __u8 out[32])
{
	oracle_sha256(p, len, out);
}

static __u32 prim_crc32c(__u32 crc, const void *p, size_t len)
{
	return oracle_crc32c_update(crc, p, len);
}

static __u64 prim_xxh64(const void *p, size_t len, __u64 seed)
{
	return oracle_xxh64(p, len, seed);
}

static const struct xdev_ext_mech_cpu_prims prims = {
	.crc32c = prim_crc32c,
	.xxh64 = prim_xxh64,
	.sha256 = prim_sha256,
};

static __u8 *frame(__u32 cap)
{
	__u8 *f = malloc(cap + GUARD);

	if (f)
		memset(f + cap, GUARD_BYTE, GUARD);
	return f;
}

static bool guard_intact(const __u8 *f, __u32 cap)
{
	__u32 i;

	for (i = 0; i < GUARD; i++)
		if (f[cap + i] != GUARD_BYTE)
			return false;
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

static bool test_classes(void)
{
	__u32 x;

	for (x = XDEV_EXT_CPU_XFORM_CRC32C_APPEND; x <= XDEV_EXT_CPU_XFORM_SHA256_APPEND; x++)
		CHECK(xdev_ext_mech_cpu_xform_fixed(x) && !xdev_ext_mech_cpu_xform_variable(x));
	CHECK(xdev_ext_mech_cpu_xform_variable(XDEV_EXT_CPU_XFORM_DEFLATE));
	CHECK(xdev_ext_mech_cpu_xform_variable(XDEV_EXT_CPU_XFORM_INFLATE));
	CHECK(!xdev_ext_mech_cpu_xform_fixed(XDEV_EXT_CPU_XFORM_DEFLATE));
	CHECK(!xdev_ext_mech_cpu_xform_fixed(0) && !xdev_ext_mech_cpu_xform_variable(0));
	CHECK(!xdev_ext_mech_cpu_xform_fixed(XDEV_EXT_CPU_XFORM_MAX));
	CHECK(!xdev_ext_mech_cpu_xform_variable(XDEV_EXT_CPU_XFORM_MAX));
	return true;
}

static bool delta_is(__u32 x, __u64 param, long long want)
{
	__s64 d = 12345;

	return !xdev_ext_mech_cpu_len_delta(x, param, &d) && d == want;
}

static bool test_length_delta(void)
{
	__s64 d = 7;

	CHECK(delta_is(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 4));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0, -4));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, 0));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0, 0));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 40, -40));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_XXH64_APPEND, 99, 8));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, 32));
	CHECK(xdev_ext_mech_cpu_len_delta(XDEV_EXT_CPU_XFORM_DEFLATE, 4096, &d) == -EINVAL);
	CHECK(xdev_ext_mech_cpu_len_delta(0, 0, &d) == -EINVAL);
	CHECK(d == 7);
	return true;
}

static bool out_len_is(__u32 x, __u64 param, __u32 len, __u32 cap, int ret, __u32 want)
{
	__u32 out = 0xdeadbeef;
	int r = xdev_ext_mech_cpu_out_len(x, param, len, cap, &out);

	if (r != ret)
		return false;
	return ret ? out == 0xdeadbeef : out == want;
}

static bool test_out_len_bounds(void)
{
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 100, 104, 0, 104));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 100, 103, -EMSGSIZE, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 0, 4, 0, 4));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0, 4, 4, 0, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0, 3, 64, -EBADMSG, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, 4096, 4096, 0, 4096));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, 3, 4096, -EBADMSG, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0, 8, 8, 0, 8));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 16, 16, 16, 0, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 16, 15, 64, -EBADMSG, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 3, 64, 64, -EINVAL, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 257, 512, 512, -EINVAL, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_XXH64_APPEND, 1, 4088, 4096, 0, 4096));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_XXH64_APPEND, 1, 4089, 4096, -EMSGSIZE, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, 4064, 4096, 0, 4096));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, 4065, 4096, -EMSGSIZE, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 1, 64, 4096, -EINVAL, 0));
	/* The valid span itself must lie inside the frame. */
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, 4097, 4096, -EINVAL, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_DEFLATE, 8192, 100, 4096, -EINVAL, 0));
	CHECK(out_len_is(0, 0, 100, 4096, -EINVAL, 0));
	/* No 32-bit wrap of valid_len + digest. */
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, UINT32_MAX - 8, UINT32_MAX,
			 -EMSGSIZE, 0));
	return true;
}

/* Apply @x to a copy of @in and compare with @want (NULL: expect @err). */
static bool apply_is(__u32 x, __u64 param, const __u8 *in, __u32 len, __u32 cap,
		     int err, const __u8 *want, __u32 want_len)
{
	__u8 *f = frame(cap), *before = malloc(cap ? cap : 1);
	__u32 out = 0xdeadbeef;
	bool ok;
	int r;

	if (!f || !before) {
		free(f);
		free(before);
		return false;
	}
	fill(f, cap, 99);
	memcpy(f, in, len);
	memcpy(before, f, cap);
	r = xdev_ext_mech_cpu_apply(&prims, x, param, f, len, cap, &out);
	if (err)
		ok = r == err && out == 0xdeadbeef && !memcmp(f, before, cap);
	else
		ok = !r && out == want_len && !memcmp(f, want, want_len);
	ok = ok && guard_intact(f, cap);
	if (!ok)
		fprintf(stderr, "xform %u len %u cap %u: ret %d out %u\n", x, len, cap, r, out);
	free(f);
	free(before);
	return ok;
}

static bool test_crc32c_transforms(void)
{
	__u8 in[512], want[516];
	__u32 crc;

	memcpy(in, "123456789", 9);
	memcpy(want, in, 9);
	oracle_put_le32(want + 9, 0xE3069283U);
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, in, 9, 13, 0, want, 13));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, in, 9, 12, -EMSGSIZE, NULL, 0));
	/* Verify-and-strip of what APPEND produced; then a damaged trailer. */
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0, want, 13, 13, 0, in, 9));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0, want, 13, 64, 0, want, 13));
	want[11] ^= 0x10;
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0, want, 13, 13, -EBADMSG, NULL, 0));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0, want, 13, 13, -EBADMSG, NULL, 0));
	want[11] ^= 0x10;
	want[0] ^= 1;
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0, want, 13, 13, -EBADMSG, NULL, 0));
	/* SEAL: the checksum of [0, len - 4) replaces the last four bytes. */
	fill(in, sizeof(in), 3);
	memcpy(want, in, 512);
	crc = oracle_crc32c(in, 508);
	oracle_put_le32(want + 508, crc);
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, in, 512, 512, 0, want, 512));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0, want, 512, 512, 0, want, 512));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, in, 3, 512, -EBADMSG, NULL, 0));
	return true;
}

static bool test_parse_strip(void)
{
	__u8 in[300], want[300];
	__u32 h = 24, payload = 200;

	fill(in, sizeof(in), 5);
	oracle_put_le32(in, payload);
	memcpy(want, in + h, payload);
	/* The payload moves to the start of the span; the header is gone. */
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, h, in, h + payload, 300, 0, want, payload));
	oracle_put_le32(in, payload + 1);
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, h, in, h + payload, 300, -EBADMSG, NULL, 0));
	oracle_put_le32(in, payload - 1);
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, h, in, h + payload, 300, -EBADMSG, NULL, 0));
	oracle_put_le32(in, 0);
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, h, in, h, 300, 0, want, 0));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_PARSE_STRIP, XDEV_EXT_CPU_PARSE_HDR_MAX + 1, in, 300, 300,
		       -EINVAL, NULL, 0));
	return true;
}

static bool test_digest_appends(void)
{
	__u8 in[4096 + 32], want[4096 + 32];
	__u64 seed = 0x0123456789abcdefULL;

	fill(in, 4096, 11);
	memcpy(want, in, 4096);
	oracle_put_be64(want + 1000, oracle_xxh64(in, 1000, seed));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_XXH64_APPEND, seed, in, 1000, 1008, 0, want, 1008));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_XXH64_APPEND, seed, in, 1000, 1007, -EMSGSIZE, NULL, 0));
	memcpy(in, "abc", 3);
	memcpy(want, in, 3);
	oracle_sha256(in, 3, want + 3);
	CHECK(want[3] == 0xba && want[34] == 0xad);
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, in, 3, 35, 0, want, 35));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, in, 3, 34, -EMSGSIZE, NULL, 0));
	/* Multi-block digest of a full frame span. */
	fill(in, 4064, 13);
	memcpy(want, in, 4064);
	oracle_sha256(in, 4064, want + 4064);
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, in, 4064, 4096, 0, want, 4096));
	return true;
}

static bool test_never_past_frame(void)
{
	static const __u32 xs[] = {
		XDEV_EXT_CPU_XFORM_CRC32C_APPEND, XDEV_EXT_CPU_XFORM_CRC32C_STRIP,
		XDEV_EXT_CPU_XFORM_CRC32C_SEAL, XDEV_EXT_CPU_XFORM_CRC32C_CHECK,
		XDEV_EXT_CPU_XFORM_PARSE_STRIP, XDEV_EXT_CPU_XFORM_XXH64_APPEND,
		XDEV_EXT_CPU_XFORM_SHA256_APPEND, XDEV_EXT_CPU_XFORM_DEFLATE,
		XDEV_EXT_CPU_XFORM_INFLATE,
	};
	unsigned int i, len, cap;
	__u8 *f;
	__u8 before[72];
	__u32 out;
	int ret;

	for (i = 0; i < sizeof(xs) / sizeof(xs[0]); i++) {
		for (cap = 0; cap <= 72; cap++) {
			for (len = 0; len <= cap + 2; len++) {
				f = frame(cap);
				CHECK(f != NULL);
				fill(f, cap, len);
				if (cap >= 4)
					oracle_put_le32(f, len >= 16 ? len - 16 : 0);
				memcpy(before, f, cap);
				out = 0xdeadbeef;
				ret = xdev_ext_mech_cpu_apply(&prims, xs[i], xs[i] ==
						XDEV_EXT_CPU_XFORM_PARSE_STRIP ? 16 : 0,
						f, len, cap, &out);
				CHECK(guard_intact(f, cap));
				if (ret) {
					CHECK(out == 0xdeadbeef);
					CHECK(!memcmp(f, before, cap));
				} else {
					CHECK(out <= cap);
				}
				free(f);
			}
		}
	}
	return true;
}

/* Randomized lengths and contents, compared with the oracles. */
static bool test_random_against_oracle(void)
{
	__u8 in[2048 + 64], want[2048 + 64];
	unsigned int round, seed = 17;
	__u32 len, cap;

	for (round = 0; round < 3000; round++) {
		seed = seed * 1664525U + 1013904223U;
		len = 4 + seed % 2040;
		cap = len + 32 + (seed >> 20) % 16;
		fill(in, len, round);
		memcpy(want, in, len);
		switch (round % 4) {
		case 0:
			oracle_put_le32(want + len, oracle_crc32c(in, len));
			CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, in, len, cap, 0, want, len + 4));
			break;
		case 1:
			oracle_put_le32(want + len - 4, oracle_crc32c(in, len - 4));
			CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, in, len, cap, 0, want, len));
			CHECK(apply_is(XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0, want, len, cap, 0, want, len - 4));
			break;
		case 2:
			oracle_put_be64(want + len, oracle_xxh64(in, len, round));
			CHECK(apply_is(XDEV_EXT_CPU_XFORM_XXH64_APPEND, round, in, len, cap, 0, want, len + 8));
			break;
		default:
			oracle_sha256(in, len, want + len);
			CHECK(apply_is(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, in, len, cap, 0, want, len + 32));
			break;
		}
	}
	return true;
}

static bool var_is(int err, __u32 produced, __u32 cap, int ret, __u32 want)
{
	__u32 v = 0xdeadbeef;
	int r = xdev_ext_mech_cpu_var_result(err, produced, cap, &v);

	return r == ret && (ret ? v == 0xdeadbeef : v == want);
}

static bool test_variable_result(void)
{
	CHECK(var_is(0, 100, 8192, 0, 100));
	CHECK(var_is(0, 8192, 8192, 0, 8192));
	/* Output larger than the destination fails the operation. */
	CHECK(var_is(0, 8193, 8192, -ENOSPC, 0));
	CHECK(var_is(-ENOSPC, 0, 8192, -ENOSPC, 0));
	CHECK(var_is(-EOVERFLOW, 0, 8192, -ENOSPC, 0));
	CHECK(var_is(0, 0, 8192, -EPROTO, 0));
	CHECK(var_is(-EBADMSG, 0, 8192, -EBADMSG, 0));
	CHECK(var_is(-EINVAL, 5, 8192, -EINVAL, 0));
	return true;
}

static int desc(__u32 xform, __u32 flags, __u64 param, __u32 cx, __u64 cp)
{
	struct xdev_ext_cpu_desc d = { .xform = xform, .flags = flags, .param = param };

	return xdev_ext_mech_cpu_desc_check(&d, cx, cp);
}

static bool test_program_selection(void)
{
	/* A program may pick another fixed transform with the same length change. */
	CHECK(!desc(XDEV_EXT_CPU_XFORM_CRC32C_CHECK, 0, 0, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0));
	CHECK(!desc(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 0, XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0));
	CHECK(!desc(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 0, 4, XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0));
	CHECK(desc(XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0, 0, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 0, 8, XDEV_EXT_CPU_XFORM_CRC32C_STRIP, 0) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_PARSE_STRIP, 0, 3, XDEV_EXT_CPU_XFORM_PARSE_STRIP, 3) == -EINVAL);
	CHECK(!desc(XDEV_EXT_CPU_XFORM_XXH64_APPEND, 0, 42, XDEV_EXT_CPU_XFORM_XXH64_APPEND, 7));
	CHECK(desc(XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0, 1, XDEV_EXT_CPU_XFORM_SHA256_APPEND, 0) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 1, 0, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0) == -EINVAL);
	CHECK(desc(0, 0, 0, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_MAX, 0, 0, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0) == -EINVAL);
	/* No switch between fixed and variable output; capacity is CREATE's. */
	CHECK(desc(XDEV_EXT_CPU_XFORM_DEFLATE, 0, 8192, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, 0, XDEV_EXT_CPU_XFORM_DEFLATE, 8192) == -EINVAL);
	CHECK(!desc(XDEV_EXT_CPU_XFORM_DEFLATE, 0, 8192, XDEV_EXT_CPU_XFORM_DEFLATE, 8192));
	CHECK(desc(XDEV_EXT_CPU_XFORM_DEFLATE, 0, 8193, XDEV_EXT_CPU_XFORM_DEFLATE, 8192) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_INFLATE, 0, 8192, XDEV_EXT_CPU_XFORM_DEFLATE, 8192) == -EINVAL);
	return true;
}

/*
 * BPF compute transform (Documentation/userspace-api/xdev_ext-compute.rst):
 * id 10, an exact declared length change D in arg1, never applied by the
 * fixed-transform code, and the bounds the compute kfuncs enforce.
 */
#ifdef XDEV_EXT_CPU_BPF_DELTA_MAX
static bool test_bpf_class(void)
{
	CHECK(XDEV_EXT_CPU_XFORM_BPF == 10 && XDEV_EXT_CPU_XFORM_MAX == 11);
	CHECK(XDEV_EXT_CPU_BPF_DELTA_MAX == 256);
	CHECK(xdev_ext_mech_cpu_xform_bpf(XDEV_EXT_CPU_XFORM_BPF));
	CHECK(!xdev_ext_mech_cpu_xform_fixed(XDEV_EXT_CPU_XFORM_BPF));
	CHECK(!xdev_ext_mech_cpu_xform_variable(XDEV_EXT_CPU_XFORM_BPF));
	CHECK(!xdev_ext_mech_cpu_xform_bpf(0));
	CHECK(!xdev_ext_mech_cpu_xform_bpf(XDEV_EXT_CPU_XFORM_INFLATE));
	CHECK(!xdev_ext_mech_cpu_xform_bpf(XDEV_EXT_CPU_XFORM_MAX));
	return true;
}

static bool test_bpf_delta(void)
{
	__s64 d = 7;

	CHECK(delta_is(XDEV_EXT_CPU_XFORM_BPF, 0, 0));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_BPF, 4, 4));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_BPF, (__u64)-4LL, -4));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_BPF, XDEV_EXT_CPU_BPF_DELTA_MAX,
		       XDEV_EXT_CPU_BPF_DELTA_MAX));
	CHECK(delta_is(XDEV_EXT_CPU_XFORM_BPF, (__u64)-(__s64)XDEV_EXT_CPU_BPF_DELTA_MAX,
		       -(long long)XDEV_EXT_CPU_BPF_DELTA_MAX));
	CHECK(xdev_ext_mech_cpu_len_delta(XDEV_EXT_CPU_XFORM_BPF,
					  XDEV_EXT_CPU_BPF_DELTA_MAX + 1, &d) == -EINVAL);
	CHECK(xdev_ext_mech_cpu_len_delta(XDEV_EXT_CPU_XFORM_BPF,
		(__u64)-(__s64)(XDEV_EXT_CPU_BPF_DELTA_MAX + 1), &d) == -EINVAL);
	CHECK(xdev_ext_mech_cpu_len_delta(XDEV_EXT_CPU_XFORM_BPF, 1ULL << 32, &d) == -EINVAL);
	CHECK(xdev_ext_mech_cpu_len_delta(XDEV_EXT_CPU_XFORM_BPF, 1ULL << 63, &d) == -EINVAL);
	CHECK(d == 7);
	return true;
}

static bool test_bpf_out_len(void)
{
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, 0, 100, 4096, 0, 100));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, 0, 0, 4096, 0, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, 4, 4092, 4096, 0, 4096));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, 4, 4093, 4096, -EMSGSIZE, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, (__u64)-4LL, 4, 64, 0, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, (__u64)-4LL, 3, 64, -EBADMSG, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, 0, 4097, 4096, -EINVAL, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, 257, 100, 4096, -EINVAL, 0));
	CHECK(out_len_is(XDEV_EXT_CPU_XFORM_BPF, XDEV_EXT_CPU_BPF_DELTA_MAX,
			 UINT32_MAX - 8, UINT32_MAX, -EMSGSIZE, 0));
	return true;
}

/* The fixed-transform code never runs a BPF transform: nothing is written. */
static bool test_bpf_not_applied_by_kernel_code(void)
{
	__u8 in[64];

	fill(in, sizeof(in), 11);
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_BPF, 0, in, 60, 64, -EINVAL, NULL, 0));
	CHECK(apply_is(XDEV_EXT_CPU_XFORM_BPF, 4, in, 60, 64, -EINVAL, NULL, 0));
	return true;
}

static bool test_bpf_selection(void)
{
	/* The same length change, either way between fixed and BPF. */
	CHECK(!desc(XDEV_EXT_CPU_XFORM_BPF, 0, 0, XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0));
	CHECK(!desc(XDEV_EXT_CPU_XFORM_CRC32C_SEAL, 0, 0, XDEV_EXT_CPU_XFORM_BPF, 0));
	CHECK(!desc(XDEV_EXT_CPU_XFORM_BPF, 0, 4, XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0));
	CHECK(!desc(XDEV_EXT_CPU_XFORM_XXH64_APPEND, 0, 1, XDEV_EXT_CPU_XFORM_BPF, 8));
	CHECK(!desc(XDEV_EXT_CPU_XFORM_BPF, 0, (__u64)-16LL, XDEV_EXT_CPU_XFORM_PARSE_STRIP, 16));
	CHECK(!desc(XDEV_EXT_CPU_XFORM_BPF, 0, 4, XDEV_EXT_CPU_XFORM_BPF, 4));
	/* A different change, an out-of-range change or a flag is refused. */
	CHECK(desc(XDEV_EXT_CPU_XFORM_BPF, 0, 8, XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_BPF, 0, (__u64)-4LL, XDEV_EXT_CPU_XFORM_CRC32C_APPEND, 0) ==
	      -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_BPF, 0, 4, XDEV_EXT_CPU_XFORM_BPF, 0) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_BPF, 0, 257, XDEV_EXT_CPU_XFORM_BPF, 257) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_BPF, 1, 0, XDEV_EXT_CPU_XFORM_BPF, 0) == -EINVAL);
	/* No switch between BPF and variable output. */
	CHECK(desc(XDEV_EXT_CPU_XFORM_BPF, 0, 0, XDEV_EXT_CPU_XFORM_DEFLATE, 8192) == -EINVAL);
	CHECK(desc(XDEV_EXT_CPU_XFORM_DEFLATE, 0, 8192, XDEV_EXT_CPU_XFORM_BPF, 0) == -EINVAL);
	return true;
}

/* bpf_xdev_ext_frame_rw(): [off, off + size) inside [data_off, frame_size). */
static bool test_compute_view_rule(void)
{
	CHECK(xdev_ext_mech_compute_view_ok(360, 4096, 0, 1));
	CHECK(xdev_ext_mech_compute_view_ok(360, 4096, 3735, 1));
	CHECK(!xdev_ext_mech_compute_view_ok(360, 4096, 3736, 1));
	CHECK(xdev_ext_mech_compute_view_ok(360, 4096, 3732, 4));
	CHECK(!xdev_ext_mech_compute_view_ok(360, 4096, 3733, 4));
	CHECK(xdev_ext_mech_compute_view_ok(360, 4096, 0, 3736));
	CHECK(!xdev_ext_mech_compute_view_ok(360, 4096, 0, 3737));
	CHECK(xdev_ext_mech_compute_view_ok(0, 4096, 0, 4096));
	CHECK(!xdev_ext_mech_compute_view_ok(360, 4096, 0, 0));
	CHECK(!xdev_ext_mech_compute_view_ok(360, 4096, UINT32_MAX, 1));
	CHECK(!xdev_ext_mech_compute_view_ok(360, 4096, 8, UINT64_MAX));
	CHECK(!xdev_ext_mech_compute_view_ok(360, 4096, 8, 1ULL << 32));
	CHECK(!xdev_ext_mech_compute_view_ok(4096, 4096, 0, 1));
	CHECK(!xdev_ext_mech_compute_view_ok(4097, 4096, 0, 1));
	return true;
}

/* bpf_xdev_ext_frame_set_len(): exactly L + D, and within the capacity. */
static bool test_compute_len_rule(void)
{
	CHECK(xdev_ext_mech_compute_len_ok(100, 0, 4096, 100));
	CHECK(!xdev_ext_mech_compute_len_ok(100, 0, 4096, 101));
	CHECK(!xdev_ext_mech_compute_len_ok(100, 0, 4096, 99));
	CHECK(xdev_ext_mech_compute_len_ok(100, 4, 4096, 104));
	CHECK(!xdev_ext_mech_compute_len_ok(100, 4, 4096, 100));
	CHECK(xdev_ext_mech_compute_len_ok(100, -4, 4096, 96));
	CHECK(xdev_ext_mech_compute_len_ok(4092, 4, 4096, 4096));
	CHECK(!xdev_ext_mech_compute_len_ok(4093, 4, 4096, 4097));
	CHECK(!xdev_ext_mech_compute_len_ok(2, -4, 64, (__u32)-2));
	CHECK(!xdev_ext_mech_compute_len_ok(4097, 0, 4096, 4097));
	CHECK(xdev_ext_mech_compute_len_ok(0, 0, 0, 0));
	return true;
}
#define FB(f) f
#else
#define FB(f) NULL
#endif

#define FN(f) f
#else
#define FN(f) NULL
#define FB(f) NULL
#endif

int main(void)
{
	static const struct {
		const char *name;
		bool (*run)(void);
	} tests[] = {
		{ "L7 oracles match published vectors", test_oracles },
		{ "L7 fixed and variable transform classes", FN(test_classes) },
		{ "L7 output length change per transform", FN(test_length_delta) },
		{ "L7 output length and frame bounds", FN(test_out_len_bounds) },
		{ "L7 CRC32C append, strip, seal and check", FN(test_crc32c_transforms) },
		{ "L7 bounded header parse and strip", FN(test_parse_strip) },
		{ "L7 XXH64 and SHA-256 digest append", FN(test_digest_appends) },
		{ "L7 never writes past the frame boundary", FN(test_never_past_frame) },
		{ "L7 randomized spans against the oracles", FN(test_random_against_oracle) },
		{ "L7 variable output larger than destination fails", FN(test_variable_result) },
		{ "L7 bounded program selection of a fixed transform", FN(test_program_selection) },
		{ "L7 BPF compute transform id and class", FB(test_bpf_class) },
		{ "L7 BPF compute declared length change", FB(test_bpf_delta) },
		{ "L7 BPF compute output length bounds", FB(test_bpf_out_len) },
		{ "L7 BPF compute is never applied by kernel transform code", FB(test_bpf_not_applied_by_kernel_code) },
		{ "L7 BPF compute selection keeps the declared length change", FB(test_bpf_selection) },
		{ "L7 BPF compute writable view stays inside the frame capacity", FB(test_compute_view_rule) },
		{ "L7 BPF compute output length is exactly L + D", FB(test_compute_len_rule) },
	};
	unsigned int i, failed = 0;

	printf("TAP version 13\n1..%zu\n", sizeof(tests) / sizeof(tests[0]));
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		bool ok = tests[i].run && tests[i].run();

		printf("%s %u - %s%s\n", ok ? "ok" : "not ok", i + 1, tests[i].name,
		       tests[i].run ? "" :
		       " # missing API: io_uring/xdev_ext_mech_cpu_core.h (in-frame CPU transform or BPF compute contract)");
		failed += !ok;
	}
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
