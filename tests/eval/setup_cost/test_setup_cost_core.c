// SPDX-License-Identifier: GPL-2.0
/*
 * Host test of setup_cost_core.h: argument parsing, the summary of repeated
 * timings, the verifier statistics parser, iovec splitting, JSON string
 * escaping and the hypervisor check.  Nothing here opens a device.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "setup_cost_core.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)

static void test_sizes(void)
{
	uint64_t v[8];
	int n;

	CHECK(sc_parse_size("4096", &v[0]) == 0 && v[0] == 4096);
	CHECK(sc_parse_size("64K", &v[0]) == 0 && v[0] == 64ULL << 10);
	CHECK(sc_parse_size("1M", &v[0]) == 0 && v[0] == 1ULL << 20);
	CHECK(sc_parse_size("96G", &v[0]) == 0 && v[0] == 96ULL << 30);
	CHECK(sc_parse_size("", &v[0]) < 0);
	CHECK(sc_parse_size("1T", &v[0]) < 0);
	CHECK(sc_parse_size("0", &v[0]) < 0);
	CHECK(sc_parse_size("12x", &v[0]) < 0);
	CHECK(sc_parse_size("99999999999G", &v[0]) < 0);	/* overflow */
	n = sc_parse_sizes("1M,4M,1G", v, 8);
	CHECK(n == 3 && v[0] == 1ULL << 20 && v[2] == 1ULL << 30);
	CHECK(sc_parse_sizes("1M,,4M", v, 8) < 0);
	CHECK(sc_parse_sizes("1M,2M,3M", v, 2) < 0);
	CHECK(sc_parse_window("2048:4096", &v[0], &v[1]) == 0 && v[0] == 2048 && v[1] == 4096);
	CHECK(sc_parse_window("2048", &v[0], &v[1]) < 0);
	CHECK(sc_parse_window("1:0", &v[0], &v[1]) < 0);
}

static void test_summary(void)
{
	uint64_t ns[] = { 50, 10, 40, 20, 30 };
	uint64_t even[] = { 4, 1, 3, 2 };
	struct sc_summary s;

	CHECK(sc_summarize(ns, 5, &s) == 0);
	CHECK(s.n == 5 && s.min == 10 && s.median == 30 && s.max == 50);
	CHECK(ns[0] == 50);	/* input order is preserved */
	CHECK(sc_summarize(even, 4, &s) == 0 && s.median == 2);	/* lower median */
	CHECK(sc_summarize(ns, 0, &s) < 0);
}

static void test_verifier_log(void)
{
	const char *log =
		"func#0 @0\n0: R1=ctx() R10=fp0\n"
		"verification time 187 usec\n"
		"stack depth 16+0\n"
		"processed 421 insns (limit 1000000) max_states_per_insn 1 total_states 30 "
		"peak_states 30 mark_read 5\n";
	struct sc_verifier v;

	CHECK(sc_parse_verifier_log(log, &v) == 0);
	CHECK(v.have_time && v.verify_usec == 187);
	CHECK(v.have_processed && v.processed_insns == 421);
	CHECK(sc_parse_verifier_log("processed 7 insns (limit 1)\n", &v) == 0);
	CHECK(!v.have_time && v.have_processed && v.processed_insns == 7);
	CHECK(sc_parse_verifier_log("", &v) < 0);
	CHECK(sc_xlated_insns(8 * 33) == 33);
}

static void test_iovecs(void)
{
	struct iovec iov[4];
	char *base = (char *)0x100000;

	CHECK(sc_split_iovecs(base, 3ULL << 30, SC_IOVEC_MAX, iov, 4) == 3);
	CHECK(iov[0].iov_base == base && iov[0].iov_len == 1ULL << 30);
	CHECK(iov[2].iov_base == base + (2ULL << 30) && iov[2].iov_len == 1ULL << 30);
	CHECK(sc_split_iovecs(base, (1ULL << 30) + 4096, SC_IOVEC_MAX, iov, 4) == 2);
	CHECK(iov[1].iov_len == 4096);
	CHECK(sc_split_iovecs(base, 5ULL << 30, SC_IOVEC_MAX, iov, 4) < 0);
}

static void test_host_memory(void)
{
	const char *meminfo =
		"MemTotal:       263921344 kB\n"
		"MemFree:         1048576 kB\n"
		"MemAvailable:   67108864 kB\n"
		"Buffers:            4096 kB\n";
	uint64_t avail = 0;

	CHECK(sc_meminfo_available(meminfo, &avail) == 0 && avail == 64ULL << 30);
	CHECK(sc_meminfo_available("MemTotal: 1 kB\nMemFree: 1 kB\n", &avail) < 0);
	CHECK(sc_meminfo_available("MemAvailable: x kB\n", &avail) < 0);
	CHECK(sc_meminfo_available(NULL, &avail) < 0);
	/* Default margin: the larger of 4 GiB and 1/8 of MemAvailable. */
	CHECK(sc_mem_margin(64ULL << 30, 0) == 8ULL << 30);
	CHECK(sc_mem_margin(16ULL << 30, 0) == 4ULL << 30);
	CHECK(sc_mem_margin(64ULL << 30, 1ULL << 30) == 1ULL << 30);
	CHECK(sc_host_fits(56ULL << 30, 64ULL << 30, 8ULL << 30));
	CHECK(!sc_host_fits((56ULL << 30) + 4096, 64ULL << 30, 8ULL << 30));
	CHECK(!sc_host_fits(96ULL << 30, 64ULL << 30, 8ULL << 30));
	CHECK(!sc_host_fits(1ULL << 20, 2ULL << 30, 4ULL << 30));	/* margin > avail */
}

static void test_json_and_hypervisor(void)
{
	char out[64];

	CHECK(sc_json_escape("a\"b\\c\n\x01", out, sizeof(out)) == 0);
	CHECK(strcmp(out, "a\\\"b\\\\c\\n\\u0001") == 0);
	CHECK(sc_json_escape("0123456789", out, 8) < 0);
	CHECK(sc_cpuinfo_hypervisor("processor : 0\nflags : fpu vme hypervisor sse\n"));
	CHECK(!sc_cpuinfo_hypervisor("processor : 0\nflags : fpu vme sse\n"));
	CHECK(!sc_cpuinfo_hypervisor("model name : hypervisorless\nflags : fpu\n"));
}

int main(void)
{
	test_sizes();
	test_summary();
	test_verifier_log();
	test_iovecs();
	test_host_memory();
	test_json_and_hypervisor();
	if (failures) {
		fprintf(stderr, "test_setup_cost_core: %d failure(s)\n", failures);
		return 1;
	}
	printf("test_setup_cost_core: PASS\n");
	return 0;
}
