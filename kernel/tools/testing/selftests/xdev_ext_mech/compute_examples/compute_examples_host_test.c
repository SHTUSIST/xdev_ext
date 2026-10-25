// SPDX-License-Identifier: GPL-2.0
/*
 * Host tests of the BPF compute examples (tools/xdev_ext_mech/examples/compute).
 * The examples keep their algorithm in headers that compile both as BPF and
 * as C; this file compiles those headers with the host compiler against a
 * mock of the three compute kfuncs (Documentation/userspace-api/xdev_ext-compute.rst)
 * built on the kernel's own bound rules, xdev_ext_mech_compute_view_ok() and
 * xdev_ext_mech_compute_len_ok() of io_uring/xdev_ext_mech_cpu_core.h. Every
 * output is compared with the independent oracles of xform_oracle.h and with
 * the kernel's fixed transform (xdev_ext_mech_cpu_apply() with oracle
 * primitives), byte for byte over the whole frame chunk and a guard.
 * Build once per CRC32C variant: -DEX_CRC32C_SLICE8=0 and -DEX_CRC32C_SLICE8=1,
 * with -I <kernel tree> -I <this directory's parent> -I <examples/compute>.
 * Correctness only; nothing is timed.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xform_oracle.h"
#include "io_uring/xdev_ext_mech_cpu_core.h"

#ifndef EX_CRC32C_SLICE8
#error "build with -DEX_CRC32C_SLICE8=0 or -DEX_CRC32C_SLICE8=1"
#endif

/* --- mock of the compute kfuncs, with the kernel's bound rules --------- */

struct ex_host_frame {
	__u8 *chunk;		/* frame_size bytes + GUARD */
	__u32 data_off, frame_size, len, out_len;
	bool set;
};

struct ex_host_ctx {
	__u32 nr_frames;
	struct ex_host_frame *f;
	__s64 delta;		/* the length change declared at CREATE */
	unsigned int bad_pos, bad_len, null_views;
};

typedef struct ex_host_ctx ex_ctx;

static inline __u32 ex_nr_frames(ex_ctx *c)
{
	return c->nr_frames;
}

static inline __u32 ex_frame_len(ex_ctx *c, __u32 pos)
{
	if (pos >= c->nr_frames) {
		c->bad_pos++;
		return 0;
	}
	return c->f[pos].len;
}

static inline __u8 *ex_frame_rw(ex_ctx *c, __u32 pos, __u32 off, size_t size)
{
	struct ex_host_frame *f;

	if (pos >= c->nr_frames) {
		c->null_views++;
		return NULL;
	}
	f = &c->f[pos];
	if (!xdev_ext_mech_compute_view_ok(f->data_off, f->frame_size, off, size)) {
		c->null_views++;
		return NULL;
	}
	return f->chunk + f->data_off + off;
}

static inline int ex_frame_set_len(ex_ctx *c, __u32 pos, __u32 len)
{
	struct ex_host_frame *f;

	if (pos >= c->nr_frames) {
		c->bad_pos++;
		return -EINVAL;
	}
	f = &c->f[pos];
	if (!xdev_ext_mech_compute_len_ok(f->len, c->delta, f->frame_size - f->data_off, len)) {
		c->bad_len++;
		return -EINVAL;
	}
	f->out_len = len;
	f->set = true;
	return 0;
}

#include "compute_example.h"
#include "crc32c.h"
#include "xxh64.h"
#include "parse.h"

/* --- helpers ------------------------------------------------------------ */

#define FRAME_SIZE 4096U
#define GUARD 64U
#define CHUNK_FILL 0xa5
#define GUARD_BYTE 0xc5
#define MAX_FRAMES 32U

static unsigned int checks, failures;

#define CHECK(expr) do {						\
	checks++;							\
	if (!(expr)) {							\
		failures++;						\
		fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #expr);	\
		return false;						\
	}								\
} while (0)

static __u32 prim_crc32c(__u32 crc, const void *p, size_t len)
{
	return oracle_crc32c_update(crc, p, len);
}

static __u64 prim_xxh64(const void *p, size_t len, __u64 seed)
{
	return oracle_xxh64(p, len, seed);
}

static void prim_sha256(const void *p, size_t len, __u8 out[32])
{
	oracle_sha256(p, len, out);
}

static const struct xdev_ext_mech_cpu_prims prims = {
	.crc32c = prim_crc32c,
	.xxh64 = prim_xxh64,
	.sha256 = prim_sha256,
};

static void fill(__u8 *p, __u32 n, __u32 seed)
{
	__u32 i;

	for (i = 0; i < n; i++) {
		seed = seed * 1103515245U + 12345U;
		p[i] = (__u8)(seed >> 16);
	}
}

/* A chunk with a recognisable fill, @data at @data_off, a guard behind it. */
static bool frame_init(struct ex_host_frame *f, __u32 data_off, const __u8 *data, __u32 len)
{
	memset(f, 0, sizeof(*f));
	f->chunk = malloc(FRAME_SIZE + GUARD);
	if (!f->chunk)
		return false;
	memset(f->chunk, CHUNK_FILL, FRAME_SIZE);
	memset(f->chunk + FRAME_SIZE, GUARD_BYTE, GUARD);
	f->data_off = data_off;
	f->frame_size = FRAME_SIZE;
	f->len = len;
	if (len)
		memcpy(f->chunk + data_off, data, len);
	return true;
}

static void frames_free(struct ex_host_frame *f, __u32 n)
{
	__u32 i;

	for (i = 0; i < n; i++)
		free(f[i].chunk);
}

/* The core's rule after compute returns 0: every frame leaves with L + D. */
static int kernel_lengths(ex_ctx *c)
{
	__u32 i;

	for (i = 0; i < c->nr_frames; i++) {
		struct ex_host_frame *f = &c->f[i];
		__u32 out = f->set ? f->out_len : f->len;

		if ((__s64)out != (__s64)f->len + c->delta)
			return -EPROTO;
		f->out_len = out;
	}
	return 0;
}

enum example {
	EX_CRC_CHECK,
	EX_CRC_STRIP,
	EX_CRC_APPEND,
	EX_XXH64_APPEND,
	EX_PARSE_CHECK,
};

static const char *const example_name[] = {
	"crc32c-check", "crc32c-strip", "crc32c-append", "xxh64-append", "parse-check",
};

/* The example's length change D and the fixed transform it matches. */
static __s64 example_delta(enum example e)
{
	switch (e) {
	case EX_CRC_STRIP: return -4;
	case EX_CRC_APPEND: return 4;
	case EX_XXH64_APPEND: return 8;
	default: return 0;
	}
}

static __u32 example_fixed(enum example e)
{
	switch (e) {
	case EX_CRC_CHECK: return XDEV_EXT_CPU_XFORM_CRC32C_CHECK;
	case EX_CRC_STRIP: return XDEV_EXT_CPU_XFORM_CRC32C_STRIP;
	case EX_CRC_APPEND: return XDEV_EXT_CPU_XFORM_CRC32C_APPEND;
	case EX_XXH64_APPEND: return XDEV_EXT_CPU_XFORM_XXH64_APPEND;
	default: return XDEV_EXT_CPU_XFORM_PARSE_STRIP;
	}
}

static int run_example(enum example e, ex_ctx *c, __u64 arg)
{
	int err;

	switch (e) {
	case EX_CRC_CHECK: err = ex_crc32c_check(c, 0); break;
	case EX_CRC_STRIP: err = ex_crc32c_check(c, 1); break;
	case EX_CRC_APPEND: err = ex_crc32c_append(c); break;
	case EX_XXH64_APPEND: err = ex_xxh64_append(c, arg); break;
	default: err = ex_parse_check(c, (__u32)arg); break;
	}
	return err ? err : kernel_lengths(c);
}

/*
 * Run example @e over frames of @lens (each at @data_off, from @data) and the
 * fixed transform over identical copies; both must agree on the result, on
 * every chunk byte and on the guard. On success the oracle decides the bytes:
 * @want_err 0 means the oracle accepts every frame.
 */
static bool compare_batch(enum example e, __u64 arg, const __u32 *lens, __u32 n,
			  const __u32 *data_off, const __u8 *const *data, int want_err)
{
	struct ex_host_frame ex[MAX_FRAMES], fx[MAX_FRAMES], ref[MAX_FRAMES];
	ex_ctx c = { .nr_frames = n, .f = ex, .delta = example_delta(e) };
	__u32 i, fixed_out[MAX_FRAMES];
	int ex_err, fixed_err = 0;
	bool ok = true;

	for (i = 0; i < n; i++)
		if (!frame_init(&ex[i], data_off[i], data[i], lens[i]) ||
		    !frame_init(&fx[i], data_off[i], data[i], lens[i]) ||
		    !frame_init(&ref[i], data_off[i], data[i], lens[i])) {
			frames_free(ex, i + 1);
			frames_free(fx, i + 1);
			frames_free(ref, i + 1);
			CHECK(false);
		}
	ex_err = run_example(e, &c, arg);
	/* The fixed transform stops at the first failing frame, as the CPU stage. */
	for (i = 0; i < n && !fixed_err; i++)
		fixed_err = xdev_ext_mech_cpu_apply(&prims, example_fixed(e),
						    e == EX_XXH64_APPEND || e == EX_PARSE_CHECK ? arg : 0,
						    fx[i].chunk + fx[i].data_off, lens[i],
						    FRAME_SIZE - fx[i].data_off, &fixed_out[i]);
	if (ex_err != want_err || fixed_err != want_err || c.bad_pos || c.bad_len ||
	    c.null_views) {
		fprintf(stderr, "%s arg %llu frames %u len0 %u: example %d fixed %d want %d "
			"bad_pos %u bad_len %u null_views %u\n", example_name[e],
			(unsigned long long)arg, n, lens[0], ex_err, fixed_err, want_err,
			c.bad_pos, c.bad_len, c.null_views);
		ok = false;
	}
	for (i = 0; ok && i < n; i++) {
		struct ex_host_frame *f = &ex[i];

		if (e == EX_PARSE_CHECK) {
			/*
			 * The example only checks and writes nothing; the fixed
			 * transform also strips, which stays a kernel operation.
			 */
			if (memcmp(f->chunk, ref[i].chunk, FRAME_SIZE + GUARD) ||
			    (!want_err && (fixed_out[i] != lens[i] - arg ||
					   memcmp(fx[i].chunk + fx[i].data_off,
						  data[i] + arg, fixed_out[i]))))
				ok = false;
			if (!ok)
				fprintf(stderr, "%s frame %u len %u hdr %llu: wrote bytes or "
					"disagrees with the fixed strip\n", example_name[e], i,
					lens[i], (unsigned long long)arg);
			continue;
		}
		if (memcmp(f->chunk, fx[i].chunk, FRAME_SIZE + GUARD))
			ok = false;
		/* A check writes nothing at all. */
		if ((e == EX_CRC_CHECK || e == EX_CRC_STRIP || want_err) &&
		    memcmp(f->chunk, ref[i].chunk, FRAME_SIZE + GUARD))
			ok = false;
		if (!want_err && f->out_len != fixed_out[i])
			ok = false;
		if (!ok)
			fprintf(stderr, "%s frame %u len %u data_off %u: bytes or length differ "
				"from the fixed transform (example %u fixed %u)\n", example_name[e],
				i, lens[i], data_off[i], f->out_len, fixed_out[i]);
	}
	/* The oracle, independent of both. */
	for (i = 0; ok && !want_err && i < n; i++) {
		const __u8 *out = ex[i].chunk + ex[i].data_off;
		__u8 want[32];

		switch (e) {
		case EX_CRC_CHECK:
		case EX_CRC_STRIP:
			oracle_put_le32(want, oracle_crc32c(data[i], lens[i] - 4));
			ok = lens[i] >= 4 && !memcmp(out, data[i], lens[i]) &&
			     !memcmp(want, data[i] + lens[i] - 4, 4);
			break;
		case EX_CRC_APPEND:
			oracle_put_le32(want, oracle_crc32c(data[i], lens[i]));
			ok = (!lens[i] || !memcmp(out, data[i], lens[i])) &&
			     !memcmp(out + lens[i], want, 4);
			break;
		case EX_XXH64_APPEND:
			oracle_put_be64(want, oracle_xxh64(data[i], lens[i], arg));
			ok = (!lens[i] || !memcmp(out, data[i], lens[i])) &&
			     !memcmp(out + lens[i], want, 8);
			break;
		default:
			ok = lens[i] >= arg && oracle_le32(data[i]) == lens[i] - arg;
			break;
		}
		if (!ok)
			fprintf(stderr, "%s frame %u len %u: differs from the oracle\n",
				example_name[e], i, lens[i]);
	}
	frames_free(ex, n);
	frames_free(fx, n);
	frames_free(ref, n);
	CHECK(ok);
	return true;
}

static bool compare_one(enum example e, __u64 arg, __u32 len, __u32 data_off,
			const __u8 *data, int want_err)
{
	return compare_batch(e, arg, &len, 1, &data_off, &data, want_err);
}

/* Lengths 0..300, then the frame-size and chunk-size edges. */
static const __u32 edges[] = {
	301, 383, 384, 385, 511, 512, 513, 767, 1023, 1024, 1025, 1431, 1432, 1433,
	2047, 2048, 2049, 3000, 3704, 3728, 3732, 3735, 3736, 4064, 4088, 4092, 4095, 4096,
};

static bool next_len(__u32 *len, unsigned int *edge)
{
	if (*len < 300) {
		(*len)++;
		return true;
	}
	if (*edge >= sizeof(edges) / sizeof(edges[0]))
		return false;
	*len = edges[(*edge)++];
	return true;
}

/* Two placements of each length: ample room, and a capacity of exactly L + D. */
static bool for_lengths(enum example e, __u64 arg, __u32 min_len,
			bool (*make)(__u8 *buf, __u32 len, __u64 arg, __u32 seed))
{
	__s64 d = example_delta(e);
	unsigned int edge = 0;
	__u32 len = 0;
	__u8 *buf = malloc(FRAME_SIZE);

	CHECK(buf);
	do {
		__u32 need = (__u32)((__s64)len + (d > 0 ? d : 0)), room;

		if (len < min_len || need > FRAME_SIZE)
			continue;
		if (!make(buf, len, arg, len * 2654435761U)) {
			free(buf);
			CHECK(false);
		}
		room = FRAME_SIZE - need >= 360 ? 360 : 0;
		if (!compare_one(e, arg, len, room, buf, 0) ||
		    !compare_one(e, arg, len, FRAME_SIZE - need, buf, 0)) {
			free(buf);
			return false;
		}
	} while (next_len(&len, &edge));
	free(buf);
	return true;
}

static bool make_random(__u8 *buf, __u32 len, __u64 arg, __u32 seed)
{
	(void)arg;
	fill(buf, len, seed);
	return true;
}

static bool make_sealed(__u8 *buf, __u32 len, __u64 arg, __u32 seed)
{
	(void)arg;
	if (len < 4)
		return false;
	fill(buf, len - 4, seed);
	oracle_put_le32(buf + len - 4, oracle_crc32c(buf, len - 4));
	return true;
}

static bool make_parse(__u8 *buf, __u32 len, __u64 arg, __u32 seed)
{
	if (len < arg)
		return false;
	fill(buf, len, seed);
	oracle_put_le32(buf, len - (__u32)arg);
	return true;
}

/* --- tests -------------------------------------------------------------- */

static bool test_oracles(void)
{
	CHECK(oracle_self_test());
	return true;
}

/* Row k of the table is the raw update of byte i followed by k zero bytes. */
static bool test_crc_table(void)
{
	__u8 b[8] = { 0 };
	__u32 k, i;

	CHECK(EX_CRC32C_ROWS == (EX_CRC32C_SLICE8 ? 8 : 1));
	CHECK(sizeof(ex_crc32c_tab) == EX_CRC32C_ROWS * 256 * sizeof(__u32));
	for (k = 0; k < EX_CRC32C_ROWS; k++)
		for (i = 0; i < 256; i++) {
			b[0] = (__u8)i;
			CHECK(ex_crc32c_tab[k][i] == oracle_crc32c_update(0, b, k + 1));
		}
	return true;
}

/* The raw update over any frame range, any offset, against the oracle. */
static bool test_crc_range(void)
{
	struct ex_host_frame f;
	ex_ctx c = { .nr_frames = 1, .f = &f };
	__u8 *buf = malloc(FRAME_SIZE);
	unsigned int edge = 0;
	__u32 len = 0, off, crc;

	CHECK(buf);
	fill(buf, FRAME_SIZE, 7);
	do {
		for (off = 0; off < 10 && off + len <= FRAME_SIZE; off++) {
			if (!frame_init(&f, 0, buf, FRAME_SIZE)) {
				free(buf);
				CHECK(false);
			}
			crc = ~0U;
			if (ex_crc32c_range(&c, 0, off, len, &crc) ||
			    crc != oracle_crc32c_update(~0U, buf + off, len) || c.null_views) {
				fprintf(stderr, "crc range off %u len %u: %08x\n", off, len, crc);
				free(f.chunk);
				free(buf);
				CHECK(false);
			}
			free(f.chunk);
		}
	} while (next_len(&len, &edge));
	/* A range past the frame capacity is refused, never read. */
	CHECK(frame_init(&f, 4000, buf, 96));
	crc = 0x12345678;
	CHECK(ex_crc32c_range(&c, 0, 0, 97, &crc) == -EX_EFAULT && crc == 0x12345678);
	free(f.chunk);
	free(buf);
	return true;
}

static bool test_crc_append(void)
{
	return for_lengths(EX_CRC_APPEND, 0, 0, make_random);
}

static bool test_crc_check(void)
{
	return for_lengths(EX_CRC_CHECK, 0, 4, make_sealed) &&
	       for_lengths(EX_CRC_STRIP, 0, 4, make_sealed);
}

/* Every corrupted byte of short frames, spread positions of longer ones. */
static bool test_crc_check_detects(void)
{
	static const enum example ex[] = { EX_CRC_CHECK, EX_CRC_STRIP };
	__u8 *buf = malloc(FRAME_SIZE);
	unsigned int edge = 0, k;
	__u32 len = 3, pos, step;

	CHECK(buf);
	/* Fewer than four bytes cannot carry the CRC. */
	for (len = 0; len < 4; len++) {
		fill(buf, len, len);
		for (k = 0; k < 2; k++)
			if (!compare_one(ex[k], 0, len, 360, buf, -EBADMSG)) {
				free(buf);
				return false;
			}
	}
	len = 3;
	while (next_len(&len, &edge)) {
		step = len <= 40 ? 1 : len / 13 + 1;
		for (pos = 0; pos < len; pos++) {
			/* Every byte of short frames; both ends and a spread otherwise. */
			if (pos >= 8 && pos + 8 < len && pos % step)
				continue;
			make_sealed(buf, len, 0, len);
			buf[pos] ^= (__u8)(1U << (pos % 8));
			for (k = 0; k < 2; k++)
				if (!compare_one(ex[k], 0, len, FRAME_SIZE - len, buf, -EBADMSG)) {
					fprintf(stderr, "corruption at %u of %u not detected\n", pos, len);
					free(buf);
					return false;
				}
		}
	}
	free(buf);
	return true;
}

static bool test_xxh64_append(void)
{
	static const __u64 seeds[] = { 0, 1, 0x5eed, 0x9E3779B185EBCA87ULL, ~0ULL };
	unsigned int i;

	for (i = 0; i < sizeof(seeds) / sizeof(seeds[0]); i++)
		if (!for_lengths(EX_XXH64_APPEND, seeds[i], 0, make_random))
			return false;
	/* The published vectors through the example itself. */
	{
		struct ex_host_frame f;
		ex_ctx c = { .nr_frames = 1, .f = &f, .delta = 8 };
		__u8 want[8];

		CHECK(frame_init(&f, 0, (const __u8 *)"abc", 3));
		CHECK(!ex_xxh64_append(&c, 0) && f.set && f.out_len == 11);
		oracle_put_be64(want, 0x44BC2CF5AD770999ULL);
		CHECK(!memcmp(f.chunk + 3, want, 8));
		free(f.chunk);
	}
	return true;
}

static bool test_parse_check(void)
{
	static const __u32 hdrs[] = { 4, 5, 16, 255, 256 };
	__u8 *buf = malloc(FRAME_SIZE);
	unsigned int i, edge;
	__u32 len;

	CHECK(buf);
	for (i = 0; i < sizeof(hdrs) / sizeof(hdrs[0]); i++) {
		if (!for_lengths(EX_PARSE_CHECK, hdrs[i], hdrs[i], make_parse)) {
			free(buf);
			return false;
		}
		/* A wrong length word, and a frame shorter than the header. */
		for (len = hdrs[i], edge = 0; ; ) {
			make_parse(buf, len, hdrs[i], len);
			oracle_put_le32(buf, len - hdrs[i] + 1);
			if (!compare_one(EX_PARSE_CHECK, hdrs[i], len, 0, buf, -EBADMSG)) {
				free(buf);
				return false;
			}
			if (!next_len(&len, &edge) || len > FRAME_SIZE)
				break;
		}
		fill(buf, hdrs[i], 3);
		if (!compare_one(EX_PARSE_CHECK, hdrs[i], hdrs[i] - 1, 0, buf, -EBADMSG)) {
			free(buf);
			return false;
		}
		/* Shorter than the header, with the word a wrapped L - hdr would match. */
		if (hdrs[i] - 1 >= 4) {
			oracle_put_le32(buf, (hdrs[i] - 1) - hdrs[i]);
			if (!compare_one(EX_PARSE_CHECK, hdrs[i], hdrs[i] - 1, 0, buf, -EBADMSG)) {
				free(buf);
				return false;
			}
		}
	}
	free(buf);
	/* A header length outside what the fixed transform accepts. */
	{
		struct ex_host_frame f;
		ex_ctx c = { .nr_frames = 1, .f = &f };
		__u8 data[64] = { 60 };

		CHECK(frame_init(&f, 0, data, 64));
		CHECK(ex_parse_check(&c, 3) == -EX_EINVAL);
		CHECK(ex_parse_check(&c, 257) == -EX_EINVAL);
		CHECK(ex_parse_check(&c, 4) == 0);
		free(f.chunk);
	}
	return true;
}

/* Session-shaped batches: seg_len frames, the last one shorter. */
static bool test_batches(void)
{
	static const struct { __u32 seg, group, hdr; } layouts[] = {
		{ 1432, 8192, 360 }, { 300, 8192, 360 }, { 7, 200, 0 }, { 4064, 8192, 0 },
		{ 16, 512, 0 }, { 1, 32, 0 },
	};
	static const enum example all[] = {
		EX_CRC_CHECK, EX_CRC_STRIP, EX_CRC_APPEND, EX_XXH64_APPEND, EX_PARSE_CHECK,
	};
	__u8 *store = malloc(MAX_FRAMES * FRAME_SIZE);
	const __u8 *data[MAX_FRAMES];
	__u32 lens[MAX_FRAMES], offs[MAX_FRAMES];
	unsigned int l, k;
	__u32 n, i;

	CHECK(store);
	for (l = 0; l < sizeof(layouts) / sizeof(layouts[0]); l++) {
		n = (layouts[l].group + layouts[l].seg - 1) / layouts[l].seg;
		CHECK(n <= MAX_FRAMES);
		for (k = 0; k < sizeof(all) / sizeof(all[0]); k++) {
			enum example e = all[k];
			__u64 arg = e == EX_XXH64_APPEND ? 0x5eed : e == EX_PARSE_CHECK ? 4 : 0;
			bool skip = false;

			for (i = 0; i < n; i++) {
				__u8 *b = store + i * FRAME_SIZE;

				lens[i] = i + 1 < n ? layouts[l].seg :
					  layouts[l].group - (n - 1) * layouts[l].seg;
				offs[i] = layouts[l].hdr;
				data[i] = b;
				if (e == EX_CRC_CHECK || e == EX_CRC_STRIP)
					skip |= !make_sealed(b, lens[i], 0, i + 31 * l);
				else if (e == EX_PARSE_CHECK)
					skip |= !make_parse(b, lens[i], arg, i + 31 * l);
				else
					make_random(b, lens[i], arg, i + 31 * l);
			}
			if (skip)
				continue;
			if (!compare_batch(e, arg, lens, n, offs, data, 0)) {
				free(store);
				return false;
			}
			/* One bad frame in the middle fails the whole batch. */
			if (e == EX_CRC_CHECK || e == EX_CRC_STRIP || e == EX_PARSE_CHECK) {
				store[(n / 2) * FRAME_SIZE] ^= 0x40;
				if (!compare_batch(e, arg, lens, n, offs, data, -EBADMSG)) {
					free(store);
					return false;
				}
			}
		}
	}
	free(store);
	return true;
}

int main(void)
{
	static const struct { const char *name; bool (*fn)(void); } tests[] = {
		{ "oracles", test_oracles },
		{ "crc_table", test_crc_table },
		{ "crc_range", test_crc_range },
		{ "crc_append", test_crc_append },
		{ "crc_check", test_crc_check },
		{ "crc_check_detects", test_crc_check_detects },
		{ "xxh64_append", test_xxh64_append },
		{ "parse_check", test_parse_check },
		{ "batches", test_batches },
	};
	unsigned int i, bad = 0;

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		bool ok = tests[i].fn();

		printf("%s %u - %s\n", ok ? "ok" : "not ok", i + 1, tests[i].name);
		bad += !ok;
	}
	printf("1..%u\n", i);
	printf("XDEV_EXT_COMPUTE_EXAMPLES_HOST=%s variant=%s tests=%u failed=%u checks=%u\n",
	       bad ? "FAIL" : "PASS", EX_CRC32C_SLICE8 ? "slice8" : "bytewise", i, bad, checks);
	return bad ? 1 : 0;
}
