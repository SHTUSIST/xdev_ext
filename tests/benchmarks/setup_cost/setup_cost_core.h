/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SETUP_COST_CORE_H
#define SETUP_COST_CORE_H

/*
 * Pure part of setup_cost: argument parsing, the summary of repeated
 * timings, the BPF verifier statistics parser, iovec splitting and the
 * host memory check.  Nothing
 * here opens a device; test_setup_cost_core.c covers it on the host.
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#define SC_MAX_SIZES	32
#define SC_MAX_REPS	64
/* io_uring_register_buffers takes at most 1 GiB per iovec (io_uring/rsrc.c). */
#define SC_IOVEC_MAX	(1ULL << 30)

struct sc_summary {
	unsigned int n;
	uint64_t min, median, max;
};

/* Statistics the verifier prints at BPF_LOG_STATS (kernel/bpf/verifier.c). */
struct sc_verifier {
	bool have_time, have_processed;
	uint64_t verify_usec;
	uint64_t processed_insns;
};

/* "4096", "64K", "1M", "96G" (binary units) -> bytes; 0 is refused. */
static inline int sc_parse_size(const char *s, uint64_t *out)
{
	unsigned long long v;
	unsigned int shift = 0;
	char *end;

	if (!s || !isdigit((unsigned char)*s))
		return -EINVAL;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno)
		return -EINVAL;
	switch (*end) {
	case 'K': shift = 10; end++; break;
	case 'M': shift = 20; end++; break;
	case 'G': shift = 30; end++; break;
	case '\0': break;
	default: return -EINVAL;
	}
	if (*end || !v || v > (UINT64_MAX >> shift))
		return -EINVAL;
	*out = (uint64_t)v << shift;
	return 0;
}

/* Comma-separated sizes; returns the count or -EINVAL. */
static inline int sc_parse_sizes(const char *list, uint64_t *out, int max)
{
	char buf[512], *save = NULL, *tok;
	int n = 0;

	if (!list || strlen(list) >= sizeof(buf) || strstr(list, ",,") ||
	    *list == ',' || (*list && list[strlen(list) - 1] == ','))
		return -EINVAL;
	strcpy(buf, list);
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		if (n == max || sc_parse_size(tok, &out[n]))
			return -EINVAL;
		n++;
	}
	return n ? n : -EINVAL;
}

/* "SLBA:NLB" of the NVMe stage window; NLB must be nonzero. */
static inline int sc_parse_window(const char *s, uint64_t *slba, uint64_t *nlb)
{
	unsigned long long a, b;
	char *end;

	if (!s || !isdigit((unsigned char)*s))
		return -EINVAL;
	errno = 0;
	a = strtoull(s, &end, 10);
	if (errno || *end != ':' || !isdigit((unsigned char)end[1]))
		return -EINVAL;
	b = strtoull(end + 1, &end, 10);
	if (errno || *end || !b)
		return -EINVAL;
	*slba = a;
	*nlb = b;
	return 0;
}

static inline int sc_cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

/* min, lower median and max of @n values; @ns is not reordered. */
static inline int sc_summarize(const uint64_t *ns, unsigned int n, struct sc_summary *s)
{
	uint64_t sorted[SC_MAX_REPS];

	if (!n || n > SC_MAX_REPS)
		return -EINVAL;
	memcpy(sorted, ns, n * sizeof(*ns));
	qsort(sorted, n, sizeof(*sorted), sc_cmp_u64);
	s->n = n;
	s->min = sorted[0];
	s->median = sorted[(n - 1) / 2];
	s->max = sorted[n - 1];
	return 0;
}

static inline int sc_parse_verifier_log(const char *log, struct sc_verifier *v)
{
	const char *p;
	unsigned long long x;

	memset(v, 0, sizeof(*v));
	p = log ? strstr(log, "verification time ") : NULL;
	if (p && sscanf(p, "verification time %llu usec", &x) == 1) {
		v->have_time = true;
		v->verify_usec = x;
	}
	p = log ? strstr(log, "processed ") : NULL;
	if (p && sscanf(p, "processed %llu insns", &x) == 1) {
		v->have_processed = true;
		v->processed_insns = x;
	}
	return v->have_time || v->have_processed ? 0 : -ENOENT;
}

/* bpf_prog_info.xlated_prog_len counts bytes of struct bpf_insn (8 bytes). */
static inline uint32_t sc_xlated_insns(uint32_t xlated_prog_len)
{
	return xlated_prog_len / 8;
}

/* Split [base, base + size) into iovecs of at most @limit bytes. */
static inline int sc_split_iovecs(void *base, uint64_t size, uint64_t limit,
				  struct iovec *iov, int max)
{
	uint64_t off = 0;
	int n = 0;

	while (off < size) {
		uint64_t len = size - off < limit ? size - off : limit;

		if (n == max)
			return -E2BIG;
		iov[n].iov_base = (char *)base + off;
		iov[n].iov_len = (size_t)len;
		off += len;
		n++;
	}
	return n;
}

static inline int sc_json_escape(const char *in, char *out, size_t cap)
{
	size_t o = 0;

	for (; *in; in++) {
		unsigned char c = (unsigned char)*in;
		char tmp[8];
		const char *rep = tmp;

		if (c == '"' || c == '\\')
			snprintf(tmp, sizeof(tmp), "\\%c", c);
		else if (c == '\n')
			rep = "\\n";
		else if (c < 0x20)
			snprintf(tmp, sizeof(tmp), "\\u%04x", c);
		else
			snprintf(tmp, sizeof(tmp), "%c", c);
		if (o + strlen(rep) + 1 > cap)
			return -E2BIG;
		strcpy(out + o, rep);
		o += strlen(rep);
	}
	if (o + 1 > cap)
		return -E2BIG;
	out[o] = '\0';
	return 0;
}

/* "MemAvailable:   N kB" of /proc/meminfo -> bytes. */
static inline int sc_meminfo_available(const char *meminfo, uint64_t *bytes)
{
	const char *p = meminfo ? strstr(meminfo, "MemAvailable:") : NULL;
	unsigned long long kb;
	char unit[4];

	if (!p || sscanf(p, "MemAvailable: %llu %3s", &kb, unit) != 2 ||
	    strcmp(unit, "kB") || kb > (UINT64_MAX >> 10))
		return -EINVAL;
	*bytes = (uint64_t)kb << 10;
	return 0;
}

/*
 * Memory left untouched for the other jobs of a shared host: @requested,
 * or by default the larger of 4 GiB and an eighth of MemAvailable.
 */
static inline uint64_t sc_mem_margin(uint64_t avail, uint64_t requested)
{
	uint64_t eighth = avail / 8;

	if (requested)
		return requested;
	return eighth > (4ULL << 30) ? eighth : 4ULL << 30;
}

/* A populated region of @size leaves at least @margin of MemAvailable. */
static inline bool sc_host_fits(uint64_t size, uint64_t avail, uint64_t margin)
{
	return margin <= avail && size <= avail - margin;
}

/* The CPU flags line lists "hypervisor" under a hypervisor. */
static inline bool sc_cpuinfo_hypervisor(const char *cpuinfo)
{
	const char *line = cpuinfo;

	while (line && *line) {
		const char *end = strchr(line, '\n');
		size_t len = end ? (size_t)(end - line) : strlen(line);

		if (!strncmp(line, "flags", 5)) {
			const char *p = line;

			while ((p = strstr(p, "hypervisor")) && p < line + len) {
				bool left = p == line || p[-1] == ' ' || p[-1] == '\t';
				bool right = p + 10 == line + len || p[10] == ' ' || p[10] == '\n';

				if (left && right)
					return true;
				p += 10;
			}
		}
		line = end ? end + 1 : NULL;
	}
	return false;
}

#endif /* SETUP_COST_CORE_H */
