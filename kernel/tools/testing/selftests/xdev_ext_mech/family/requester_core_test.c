// SPDX-License-Identifier: GPL-2.0
/* Requirement: after a provider-page refusal, try the longest proper prefix
 * ending at a naturally aligned power-of-two boundary, from 2 GiB to 4 KiB.
 * Catch skipped boundaries, a non-decreasing retry, and early exhaustion.
 * Build with -I <kernel tree>; this executes the production pure rule. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#if !__has_include("include/linux/xdev_ext_requester_core.h")
int main(void)
{
	puts("not ok 1 - lease split lives only in NVMe; no requester base");
	return 1;
}
#else
#include "include/linux/xdev_ext_requester_core.h"

static unsigned int checks, failures;
#define EQ(actual, expected) do { \
	uint64_t got = (uint64_t)(actual), want = (uint64_t)(expected); \
	checks++; \
	if (got != want) { \
		fprintf(stderr, "line %d: %s got %llu expected %llu\n", \
			__LINE__, #actual, (unsigned long long)got, \
			(unsigned long long)want); \
		failures++; \
	} \
} while (0)

/* Independent oracle: distance to the next aligned boundary by modulo,
 * without constructing off + len (which can wrap at the 64-bit limit).
 * An equal-length boundary is not a shorter retry. */
static uint32_t oracle(uint64_t off, uint32_t len, uint32_t *shift,
		       uint32_t min_shift)
{
	for (; *shift >= min_shift; (*shift)--) {
		uint64_t page = UINT64_C(1) << *shift;
		uint64_t distance = page - off % page;

		if (distance < len)
			return (uint32_t)distance;
	}
	return 0;
}

static void compare_chain(uint64_t off, uint32_t len, uint32_t min_shift)
{
	uint32_t actual_shift = 31, expected_shift = 31;
	uint32_t actual_len = len, expected_len = len;
	unsigned int step;

	for (step = 0; step < 24; step++) {
		uint32_t previous = actual_len;

		actual_len = xdev_ext_lease_shrink(off, actual_len,
						 &actual_shift, min_shift);
		expected_len = oracle(off, expected_len, &expected_shift, min_shift);
		EQ(actual_len, expected_len);
		EQ(actual_shift, expected_shift);
		if (!actual_len) {
			/* An exhausted cursor stays exhausted on repeated calls. */
			EQ(xdev_ext_lease_shrink(off, len, &actual_shift, min_shift), 0);
			EQ(actual_shift, min_shift - 1);
			return;
		}
		EQ(actual_len < previous, true);
	}
	EQ(step < 24, true);
}

int main(void)
{
	static const struct {
		uint64_t off;
		uint32_t len, shift, minimum, want_len, want_shift;
	} literal[] = {
		{ 0xf000, 0x3000, 31, 12, 0x1000, 16 },
		{ 0xf000, 0x1000, 16, 12, 0, 11 },
		{ 0, 0x2000, 31, 12, 0x1000, 12 },
		{ 0, 0x1000, 31, 12, 0, 11 },
		{ 1, 0x1000, 31, 12, 0xfff, 12 },
		{ 0xfff, 2, 31, 12, 1, 12 },
		{ 0x10000, 0x10000, 31, 12, 0x8000, 15 },
		{ 0, UINT32_MAX, 31, 12, 0x80000000U, 31 },
		{ 0, 0x80000000U, 31, 12, 0x40000000U, 30 },
		{ UINT64_MAX, 2, 31, 12, 1, 31 },
		{ UINT64_MAX - 0xfff, 0x1001, 31, 12, 0x1000, 31 },
		{ 0, 0x20000, 31, 16, 0x10000, 16 },
		{ 0, 0x10000, 31, 16, 0, 15 },
		{ 0, 0, 31, 12, 0, 11 },
		{ 0, UINT32_MAX, 11, 12, 0, 11 },
	};
	static const uint64_t large_offsets[] = {
		UINT64_C(0x7ffff000), UINT64_C(0x80000000),
		UINT64_C(0x123456789abcdef0), UINT64_MAX - 0x1000, UINT64_MAX,
	};
	static const uint32_t large_lengths[] = {
		0, 1, 2, 4095, 4096, 4097, 65536, 0x80000000U, UINT32_MAX,
	};
	uint64_t off;
	uint32_t len;
	unsigned int i, j;

	EQ(XDEV_EXT_LEASE_MIN_SHIFT, 12);
	for (i = 0; i < sizeof(literal) / sizeof(literal[0]); i++) {
		uint32_t shift = literal[i].shift;

		EQ(xdev_ext_lease_shrink(literal[i].off, literal[i].len,
					 &shift, literal[i].minimum), literal[i].want_len);
		EQ(shift, literal[i].want_shift);
	}
	for (off = 0; off < (1U << 18); off += 4096 - 512)
		for (len = 1; len <= (1U << 18); len = len * 3 + 7)
			compare_chain(off, len, 12);
	for (i = 0; i < sizeof(large_offsets) / sizeof(large_offsets[0]); i++)
		for (j = 0; j < sizeof(large_lengths) / sizeof(large_lengths[0]); j++) {
			compare_chain(large_offsets[i], large_lengths[j], 12);
			compare_chain(large_offsets[i], large_lengths[j], 16);
		}
	printf("%s 1 - lease shrink follows the aligned-page rule (%u checks, %u failures)\n",
	       failures ? "not ok" : "ok", checks, failures);
	return failures != 0;
}
#endif
