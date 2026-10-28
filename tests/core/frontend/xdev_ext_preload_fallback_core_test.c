// SPDX-License-Identifier: GPL-2.0
/*
 * Pure admission helpers of the positional front end:
 *  - the fallback reason agrees with the eligibility predicates and names the
 *    first condition that keeps a call in libc;
 *  - the /proc/self/maps text scan over a positional reader keeps the
 *    fgets-based scan's semantics (gaps, permissions, long pathname
 *    continuations, the byte bound) for any read granularity;
 *  - the PROCMAP_QUERY walk follows VMAs across every destination.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include "xdev_ext_preload_core.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual, expected) do {                                 \
	long long _actual = (long long)(actual);                           \
	long long _expected = (long long)(expected);                       \
	checks++;                                                           \
	if (_actual != _expected) {                                        \
		fprintf(stderr, "%s:%d: %s=%lld, expected %lld\n",        \
			__FILE__, __LINE__, #actual, _actual, _expected);       \
		failures++;                                                \
	}                                                                   \
} while (0)

static const struct xdev_ext_preload_fd_meta good_meta = {
	.tracked = true,
	.identity_matches = true,
	.direct = true,
	.frame_size = 65536,
	.dio_mem_align = 512,
	.dio_offset_align = 4096,
};

static void test_positional_reasons(void)
{
	struct xdev_ext_preload_fd_meta meta = good_meta;
	char *buffer = (char *)(uintptr_t)0x100000;

	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 4096, 8192),
		  XDEV_EXT_PRELOAD_FALLBACK_NONE);
	EXPECT_EQ(xdev_ext_preload_fallback_reason(NULL, buffer, 4096, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_ALLOWLISTED);
	meta.tracked = false;
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 4096, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_ALLOWLISTED);
	meta = good_meta;
	meta.direct = false;
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 4096, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_DIRECT);
	meta = good_meta;
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer + 1, 4096, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED);
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 4096, 512),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED);
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 1024, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED);
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 131072, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE);
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 4096, -4096),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE);
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 4096,
						   INT64_MAX - 4095),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE);
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, NULL, 4096, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 0, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
	/* A kernel without STATX_DIOALIGN reports no alignment at all. */
	meta.dio_mem_align = 0;
	EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, 4096, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
}

/* NONE exactly when the existing predicate admits the call. */
static void test_positional_reason_matches_predicate(void)
{
	static const size_t counts[] = { 0, 512, 1024, 4096, 8192, 65536, 65537,
					 131072 };
	static const int64_t offsets[] = { -4096, 0, 512, 4096, 1 << 20,
					   INT64_MAX - 4095, INT64_MAX };
	static const uintptr_t buffers[] = { 0, 0x100000, 0x100001, 0x100200 };
	static const uint32_t aligns[] = { 0, 512, 4096 };
	unsigned int b, c, o, m, f;

	for (b = 0; b < sizeof(buffers) / sizeof(buffers[0]); b++)
	for (c = 0; c < sizeof(counts) / sizeof(counts[0]); c++)
	for (o = 0; o < sizeof(offsets) / sizeof(offsets[0]); o++)
	for (m = 0; m < 3; m++)
	for (f = 0; f < 3; f++) {
		struct xdev_ext_preload_fd_meta meta = good_meta;
		const void *buffer = (const void *)buffers[b];

		meta.dio_mem_align = aligns[m];
		meta.dio_offset_align = aligns[f];
		EXPECT_EQ(xdev_ext_preload_fallback_reason(&meta, buffer, counts[c],
							   offsets[o]) ==
			  XDEV_EXT_PRELOAD_FALLBACK_NONE,
			  xdev_ext_preload_is_eligible(&meta, buffer, counts[c],
						       offsets[o]));
	}
}

static void test_vector_reasons(void)
{
	struct xdev_ext_preload_fd_meta meta = good_meta;
	struct iovec iov[3] = {
		{ (void *)(uintptr_t)0x100000, 4096 },
		{ NULL, 0 },
		{ (void *)(uintptr_t)0x200000, 8192 },
	};
	size_t total;

	EXPECT_EQ(xdev_ext_preload_iov_fallback_reason(&meta, iov, 3, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_NONE);
	EXPECT_EQ(xdev_ext_preload_iov_is_eligible(&meta, iov, 3, 0, &total), true);
	iov[2].iov_base = (void *)(uintptr_t)0x200010;
	EXPECT_EQ(xdev_ext_preload_iov_fallback_reason(&meta, iov, 3, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED);
	iov[2].iov_base = (void *)(uintptr_t)0x200000;
	iov[2].iov_len = 65536;
	EXPECT_EQ(xdev_ext_preload_iov_fallback_reason(&meta, iov, 3, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE);
	iov[2].iov_len = 8192;
	EXPECT_EQ(xdev_ext_preload_iov_fallback_reason(&meta, iov, 3, 512),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED);
	EXPECT_EQ(xdev_ext_preload_iov_fallback_reason(&meta, iov, IOV_MAX + 1, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE);
	EXPECT_EQ(xdev_ext_preload_iov_fallback_reason(&meta, iov, 0, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
	iov[0].iov_len = 0;
	iov[2].iov_len = 0;
	EXPECT_EQ(xdev_ext_preload_iov_fallback_reason(&meta, iov, 3, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
	meta.direct = false;
	EXPECT_EQ(xdev_ext_preload_iov_fallback_reason(&meta, iov, 3, 0),
		  XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_DIRECT);
	EXPECT_EQ(strcmp(xdev_ext_preload_fallback_name(
				 XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_DIRECT),
			 "file_not_direct"), 0);
	EXPECT_EQ(strcmp(xdev_ext_preload_fallback_name(
				 XDEV_EXT_PRELOAD_FALLBACK_SOCKET_MECH_UNAVAILABLE),
			 "socket_mech_unavailable"), 0);
}

struct fake_maps {
	const char *text;
	size_t length;
	size_t granule;
	unsigned int reads;
	int fail_at;
};

static ssize_t fake_read_at(void *opaque, void *buffer, size_t length,
			    uint64_t offset)
{
	struct fake_maps *maps = opaque;

	if (maps->fail_at >= 0 && maps->reads == (unsigned int)maps->fail_at)
		return -EIO;
	maps->reads++;
	if (offset >= maps->length)
		return 0;
	if (length > maps->length - offset)
		length = maps->length - offset;
	if (length > maps->granule)
		length = maps->granule;
	memcpy(buffer, maps->text + offset, length);
	return (ssize_t)length;
}

static int scan(const char *text, size_t granule, const struct iovec *iov,
		int iovcnt)
{
	struct fake_maps maps = { text, strlen(text), granule, 0, -1 };
	char buffer[4096];
	struct xdev_ext_preload_maps_reader reader = {
		.read_at = fake_read_at, .opaque = &maps,
		.buffer = buffer, .capacity = sizeof(buffer),
	};
	uintptr_t cursor[4];

	return xdev_ext_preload_maps_text_writable(&reader, iov, iovcnt, cursor);
}

static void test_maps_text_scan(void)
{
	static const char maps[] =
		"00400000-00401000 r-xp 00000000 08:01 1 /bin/x\n"
		"00600000-00602000 rw-p 00000000 00:00 0 \n"
		"00602000-00603000 rw-p 00000000 00:00 0 [heap]\n"
		"00700000-00701000 r--p 00000000 00:00 0 \n"
		"00800000-00801000 rw-p 00000000 00:00 0 \n";
	static const size_t granules[] = { 1, 7, 64, 4096 };
	unsigned int g;

	for (g = 0; g < sizeof(granules) / sizeof(granules[0]); g++) {
		size_t gr = granules[g];
		struct iovec spans = { (void *)(uintptr_t)0x601000, 0x1800 };
		struct iovec ro = { (void *)(uintptr_t)0x700000, 0x100 };
		struct iovec gap = { (void *)(uintptr_t)0x602800, 0x1000 };
		struct iovec pair[2] = {
			{ (void *)(uintptr_t)0x600000, 0x100 },
			{ (void *)(uintptr_t)0x800000, 0x1000 },
		};
		struct iovec beyond = { (void *)(uintptr_t)0x800800, 0x1000 };
		struct iovec text = { (void *)(uintptr_t)0x400000, 0x10 };

		EXPECT_EQ(scan(maps, gr, &spans, 1), true);
		EXPECT_EQ(scan(maps, gr, &ro, 1), false);
		EXPECT_EQ(scan(maps, gr, &gap, 1), false);
		EXPECT_EQ(scan(maps, gr, pair, 2), true);
		EXPECT_EQ(scan(maps, gr, &beyond, 1), false);
		EXPECT_EQ(scan(maps, gr, &text, 1), false);
	}
}

/*
 * A pathname longer than one line piece is never read as a mapping: a
 * continuation piece that starts like a writable mapping header is skipped.
 * Pieces are XDEV_EXT_PRELOAD_MAPS_LINE - 1 bytes, as with fgets before.
 */
static void test_maps_long_pathname(void)
{
	static const char head[] = "00600000-00601000 r--p 00000000 08:01 1 /";
	static const char fake[] = "00900000-00901000 rw-p 00000000 00:00 0 ";
	static const char tail[] = "\n00700000-00701000 rw-p 00000000 00:00 0 \n";
	size_t piece = XDEV_EXT_PRELOAD_MAPS_LINE - 1;
	char *text = malloc(4 * piece + sizeof(tail));
	struct iovec writable = { (void *)(uintptr_t)0x700000, 0x100 };
	struct iovec continuation = { (void *)(uintptr_t)0x900000, 0x100 };
	size_t at;

	if (!text) {
		failures++;
		return;
	}
	memset(text, 'a', 4 * piece);
	memcpy(text, head, sizeof(head) - 1);
	/* Each later piece of the same line starts with a header lookalike. */
	for (at = piece; at + sizeof(fake) < 4 * piece; at += piece)
		memcpy(text + at, fake, sizeof(fake) - 1);
	memcpy(text + 4 * piece, tail, sizeof(tail));
	EXPECT_EQ(scan(text, 4096, &writable, 1), true);
	EXPECT_EQ(scan(text, 13, &writable, 1), true);
	EXPECT_EQ(scan(text, 4096, &continuation, 1), false);
	EXPECT_EQ(scan(text, 1, &continuation, 1), false);
	free(text);
}

static void test_maps_read_failure_keeps_libc(void)
{
	static const char maps[] = "00600000-00602000 rw-p 00000000 00:00 0 \n";
	struct fake_maps fake = { maps, strlen(maps), 8, 0, 1 };
	char buffer[64];
	struct xdev_ext_preload_maps_reader reader = {
		.read_at = fake_read_at, .opaque = &fake,
		.buffer = buffer, .capacity = sizeof(buffer),
	};
	struct iovec iov = { (void *)(uintptr_t)0x601000, 0x100 };
	uintptr_t cursor[1];

	EXPECT_EQ(xdev_ext_preload_maps_text_writable(&reader, &iov, 1, cursor),
		  false);
}

struct fake_vma {
	uint64_t start, end, flags;
};

struct fake_query {
	const struct fake_vma *vmas;
	unsigned int nr;
	unsigned int calls;
	int error;
};

static int fake_vma_query(void *opaque, uint64_t address, uint64_t *end,
			  uint64_t *flags)
{
	struct fake_query *q = opaque;
	unsigned int i;

	q->calls++;
	if (q->error)
		return q->error;
	for (i = 0; i < q->nr; i++) {
		if (address >= q->vmas[i].start && address < q->vmas[i].end) {
			*end = q->vmas[i].end;
			*flags = q->vmas[i].flags;
			return 0;
		}
	}
	return -ENOENT;
}

static void test_query_walk(void)
{
	static const struct fake_vma vmas[] = {
		{ 0x600000, 0x602000, XDEV_EXT_PRELOAD_VMA_WRITABLE | 1 },
		{ 0x602000, 0x603000, XDEV_EXT_PRELOAD_VMA_WRITABLE | 1 },
		{ 0x700000, 0x701000, 1 },
	};
	struct fake_query q = { vmas, 3, 0, 0 };
	struct iovec spans[2] = {
		{ (void *)(uintptr_t)0x601000, 0x1800 },
		{ NULL, 0 },
	};
	struct iovec ro = { (void *)(uintptr_t)0x700000, 0x10 };
	struct iovec gap = { (void *)(uintptr_t)0x602800, 0x1000 };

	EXPECT_EQ(xdev_ext_preload_maps_query_writable(fake_vma_query, &q, spans, 2), 1);
	/* One query per VMA the destination crosses. */
	EXPECT_EQ(q.calls, 2);
	EXPECT_EQ(xdev_ext_preload_maps_query_writable(fake_vma_query, &q, &ro, 1), 0);
	EXPECT_EQ(xdev_ext_preload_maps_query_writable(fake_vma_query, &q, &gap, 1), 0);
	q.error = -ENOTTY;
	EXPECT_EQ(xdev_ext_preload_maps_query_writable(fake_vma_query, &q, &ro, 1),
		  -ENOTTY);
}

/*
 * More non-empty destinations (or VMAs) than one call may query: the walk
 * hands the decision to the text scan (-E2BIG) instead of keeping a request
 * in libc that the text scan would admit.
 */
static void test_query_budget_defers_to_text(void)
{
	static const struct fake_vma vmas[] = {
		{ 0x600000, 0x800000, XDEV_EXT_PRELOAD_VMA_WRITABLE | 1 },
	};
	unsigned int count = XDEV_EXT_PRELOAD_MAPS_MAX_QUERIES + 1, i;
	struct fake_query q = { vmas, 1, 0, 0 };
	struct iovec *many = calloc(count, sizeof(*many));

	EXPECT_EQ(many != NULL, true);
	if (!many)
		return;
	for (i = 0; i < count; i++) {
		many[i].iov_base = (void *)(uintptr_t)(0x600000 + i * 0x100);
		many[i].iov_len = 0x100;
	}
	EXPECT_EQ(xdev_ext_preload_maps_query_writable(fake_vma_query, &q, many,
						       (int)count), -E2BIG);
	EXPECT_EQ(q.calls, XDEV_EXT_PRELOAD_MAPS_MAX_QUERIES);
	/* Exactly the budget still decides by itself. */
	q.calls = 0;
	EXPECT_EQ(xdev_ext_preload_maps_query_writable(fake_vma_query, &q, many,
						       (int)count - 1), 1);
	free(many);
}

int main(void)
{
	test_positional_reasons();
	test_positional_reason_matches_predicate();
	test_vector_reasons();
	test_maps_text_scan();
	test_maps_long_pathname();
	test_maps_read_failure_keeps_libc();
	test_query_walk();
	test_query_budget_defers_to_text();
	if (failures) {
		fprintf(stderr, "not ok - %u of %u fallback-core checks failed\n",
			failures, checks);
		return 1;
	}
	printf("ok - %u fallback-core checks\n", checks);
	return 0;
}
