// SPDX-License-Identifier: GPL-2.0
/*
 * Checks of nv_ce_runtime_cases.h: the round-trip cases cover what the GPU
 * window must prove (4 KiB to 64 MiB, unaligned offsets, copies across
 * 64 KiB and 2 MiB GPU pages, a full batch), every case and its guards fit
 * the buffers, every error case is out of bounds by construction, and the
 * gate runs nothing without CUDA and the window flag.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nv_ce_runtime_cases.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	checks++;                                                           \
	if (actual_ != expected_) {                                         \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__FILE__, __LINE__, #actual_expr, actual_, expected_); \
		failures++;                                                   \
	}                                                                   \
} while (0)

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)

static bool crosses(uint64_t off, uint64_t size, uint64_t boundary)
{
	return off / boundary != (off + size - 1) / boundary;
}

static void test_coverage(void)
{
	bool pow2[27] = { false };
	bool unaligned_host = false, unaligned_gpu = false, unaligned_size = false;
	bool cross_64k = false, cross_2m = false, cross_2m_large = false;
	uint64_t largest = 0;
	size_t i;

	for (i = 0; i < NV_CE_NR_CASES; i++) {
		const struct nv_ce_case *c = &nv_ce_cases[i];

		EXPECT_TRUE(nv_ce_case_fits(c));
		EXPECT_TRUE(c->name && c->name[0]);
		if (!(c->size & (c->size - 1)) && !(c->host_off % 4096) &&
		    !(c->gpu_off % 4096)) {
			for (int b = 12; b <= 26; b++)
				if (c->size == 1ULL << b)
					pow2[b] = true;
		}
		unaligned_host |= c->host_off % 8 != 0;
		unaligned_gpu |= c->gpu_off % 8 != 0;
		unaligned_size |= c->size % 8 != 0;
		cross_64k |= crosses(c->gpu_off, c->size, 64 * NV_CE_KIB);
		cross_2m |= crosses(c->gpu_off, c->size, 2 * NV_CE_MIB);
		cross_2m_large |= crosses(c->gpu_off, c->size, 2 * NV_CE_MIB) &&
				  c->size > 2 * NV_CE_MIB;
		if (c->size > largest)
			largest = c->size;
	}
	for (int b = 12; b <= 26; b++) {
		if (!pow2[b])
			fprintf(stderr, "no aligned case of 2^%d bytes\n", b);
		EXPECT_TRUE(pow2[b]);
	}
	EXPECT_TRUE(unaligned_host);
	EXPECT_TRUE(unaligned_gpu);
	EXPECT_TRUE(unaligned_size);
	EXPECT_TRUE(cross_64k);
	EXPECT_TRUE(cross_2m);
	EXPECT_TRUE(cross_2m_large);
	EXPECT_EQ(largest, 64 * NV_CE_MIB);
	/* Names are unique, so a failing line names one case. */
	for (i = 0; i < NV_CE_NR_CASES; i++)
		for (size_t j = 0; j < i; j++)
			EXPECT_TRUE(strcmp(nv_ce_cases[i].name,
					   nv_ce_cases[j].name));
}

static void test_fits(void)
{
	struct nv_ce_case c = { "probe", 4096, 4096, 4096 };

	EXPECT_TRUE(nv_ce_case_fits(&c));
	c.size = 0;
	EXPECT_EQ(nv_ce_case_fits(&c), false);
	c.size = NV_CE_MAX_SIZE + 1;
	EXPECT_EQ(nv_ce_case_fits(&c), false);
	/* Room for the guard below and above, in both buffers. */
	c = (struct nv_ce_case) { "probe", 4096, NV_CE_GUARD - 1, 4096 };
	EXPECT_EQ(nv_ce_case_fits(&c), false);
	c = (struct nv_ce_case) { "probe", 4096, 4096, NV_CE_GUARD - 1 };
	EXPECT_EQ(nv_ce_case_fits(&c), false);
	c = (struct nv_ce_case) { "probe", 4096,
				  NV_CE_AREA - 4096 - NV_CE_GUARD + 1, 4096 };
	EXPECT_EQ(nv_ce_case_fits(&c), false);
	c = (struct nv_ce_case) { "probe", 4096, 4096,
				  NV_CE_AREA - 4096 - NV_CE_GUARD };
	EXPECT_TRUE(nv_ce_case_fits(&c));
	c.gpu_off = UINT64_MAX - 10;
	EXPECT_EQ(nv_ce_case_fits(&c), false);
	/* The geometry the tool pins and allocates. */
	EXPECT_EQ(NV_CE_HOST_BYTES % NV_CE_FRAME, 0);
	EXPECT_EQ(NV_CE_HOST_BYTES, 2 * NV_CE_AREA);
}

static void test_batch(void)
{
	uint64_t host = 0, gpu = 0;

	EXPECT_EQ(NV_CE_BATCH, 64);
	for (uint32_t i = 0; i < NV_CE_BATCH; i++) {
		struct nv_ce_case c;

		nv_ce_batch_entry(i, &c);
		EXPECT_TRUE(nv_ce_case_fits(&c));
		/* Back to back, unaligned, no overlap. */
		if (i) {
			EXPECT_EQ(c.host_off, host);
			EXPECT_EQ(c.gpu_off, gpu);
		}
		EXPECT_TRUE(c.size % 8 != 0);
		host = c.host_off + c.size;
		gpu = c.gpu_off + c.size;
	}
}

static void test_errors(void)
{
	bool seen[NV_CE_ERR_NR] = { false };

	for (size_t i = 0; i < NV_CE_NR_ERRORS; i++) {
		const struct nv_ce_error *e = &nv_ce_errors[i];

		seen[e->kind] = true;
		switch (e->kind) {
		case NV_CE_ERR_SIZE_ZERO:
			EXPECT_EQ(e->size, 0);
			break;
		case NV_CE_ERR_HOST_RANGE:
			EXPECT_TRUE(e->host_off <= NV_CE_HOST_BYTES &&
				    e->size > NV_CE_HOST_BYTES - e->host_off);
			break;
		case NV_CE_ERR_GPU_RANGE:
			EXPECT_TRUE(e->gpu_off <= NV_CE_AREA &&
				    e->size > NV_CE_AREA - e->gpu_off);
			break;
		case NV_CE_ERR_DIRECTION:
			EXPECT_TRUE(e->direction > 1);
			break;
		case NV_CE_ERR_BAD_HANDLE:
		case NV_CE_ERR_STALE_HANDLE:
			EXPECT_TRUE(e->handle_xor != 0);
			break;
		default:
			EXPECT_TRUE(false);
		}
		/* Only what it names is wrong: the rest is a valid request. */
		if (e->kind != NV_CE_ERR_SIZE_ZERO)
			EXPECT_TRUE(e->size != 0);
		if (e->kind != NV_CE_ERR_DIRECTION)
			EXPECT_TRUE(e->direction <= 1);
		if (e->kind != NV_CE_ERR_BAD_HANDLE &&
		    e->kind != NV_CE_ERR_STALE_HANDLE)
			EXPECT_EQ(e->handle_xor, 0);
	}
	for (int k = 0; k < NV_CE_ERR_NR; k++)
		EXPECT_TRUE(seen[k]);
	/* A stale handle differs only in its generation (bits 63..32). */
	for (size_t i = 0; i < NV_CE_NR_ERRORS; i++)
		if (nv_ce_errors[i].kind == NV_CE_ERR_STALE_HANDLE)
			EXPECT_EQ(nv_ce_errors[i].handle_xor & 0xffffffffULL, 0);
	/* The range error on the GPU runs last: a driver that let it reach
	 * the copy engine would quarantine the window's GPU path. */
	EXPECT_EQ(nv_ce_errors[NV_CE_NR_ERRORS - 1].kind, NV_CE_ERR_GPU_RANGE);
}

static void test_pattern(void)
{
	unsigned int same = 0;

	/* Different seeds and different pages differ. */
	for (uint64_t i = 0; i < 1 << 16; i++) {
		same += nv_ce_pattern(1, i) == nv_ce_pattern(2, i);
		same += nv_ce_pattern(1, i) == nv_ce_pattern(1, i + 4096);
	}
	EXPECT_TRUE(same < (1 << 16) / 64);
	EXPECT_TRUE(nv_ce_pattern(3, 0) == nv_ce_pattern(3, 0));
	EXPECT_TRUE(nv_ce_pattern(1, 0) != NV_CE_GUARD_BYTE ||
		    nv_ce_pattern(1, 1) != NV_CE_GUARD_BYTE);
}

static void test_gate(void)
{
	EXPECT_EQ(nv_ce_runtime_gate(false, false), NV_CE_GATE_HOST_BUILD);
	EXPECT_EQ(nv_ce_runtime_gate(true, false), NV_CE_GATE_HOST_BUILD);
	EXPECT_EQ(nv_ce_runtime_gate(false, true), NV_CE_GATE_NO_WINDOW);
	EXPECT_EQ(nv_ce_runtime_gate(true, true), NV_CE_GATE_RUN);
	EXPECT_TRUE(!strcmp(nv_ce_gate_reason(NV_CE_GATE_HOST_BUILD),
			    "host-build"));
	EXPECT_TRUE(!strcmp(nv_ce_gate_reason(NV_CE_GATE_NO_WINDOW),
			    "no-gpu-window-flag"));
}

int main(void)
{
	test_coverage();
	test_fits();
	test_batch();
	test_errors();
	test_pattern();
	test_gate();
	printf("nv_ce_runtime_cases: %u checks, %u failures\n", checks,
	       failures);
	return failures ? 1 : 0;
}
