// SPDX-License-Identifier: GPL-2.0
/*
 * uring_tenant - one io_uring tenant of the E8 multi-tenant runner.
 *
 * Closed loop of --depth O_DIRECT reads of --io-bytes each, READ_FIXED into
 * registered host buffers (the shared io_uring baseline's I/O path, without a
 * GPU copy: the plan's host-destination control), no SQPOLL, no IOPOLL.
 * Offsets follow the shared random schedule of ../nvme_gpu/nvme_gpu_core.h
 * over the tenant's window [--offset, --offset + --bytes), which lies in the
 * prepared region starting at --region-offset.  Per request, CLOCK_MONOTONIC
 * from submission to the reaped completion goes into a log2-microsecond
 * histogram and an exact count of requests that took >= 1 ms.  With --verify
 * every read is compared with the position-encoding payload of the region and
 * only matching reads count in bytes_ok.
 *
 * Tenant contract (tenants.py): after setup print TENANT_READY {json}, wait
 * for "GO" on stdin, run --warmup seconds uncounted and --seconds counted,
 * print TENANT_RESULT {json}.  Exit 0 ok, 1 I/O or payload failure, 2 usage.
 *
 *   uring_tenant --write-pattern --device D --region-offset R --bytes B --seed S
 * writes the payload over [R, R + B) instead (overwrites it).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../chains/uring_min.h"
#include "../nvme_gpu/nvme_gpu_core.h"

#define HIST 32
#define MAX_DEPTH 256

struct opts {
	const char *device;
	uint64_t region, off, bytes, io, depth, seed;
	double seconds, warmup;
	bool verify, write_pattern;
};

struct counts {
	uint64_t ops, bytes_ok, verify_fail, errors, ge_1ms, max_ns, hist[HIST];
};

static uint64_t now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static int parse_u64(const char *s, uint64_t *v)
{
	char *end;

	if (!s || !*s || *s == '-')
		return -1;
	errno = 0;
	*v = strtoull(s, &end, 0);
	return errno || *end ? -1 : 0;
}

static int parse_secs(const char *s, double *v)
{
	char *end;

	if (!s || !*s)
		return -1;
	*v = strtod(s, &end);
	return *end || *v < 0 || *v > 86400 ? -1 : 0;
}

static unsigned bucket(uint64_t ns)
{
	uint64_t us = ns / 1000;
	unsigned b = 0;

	while (us >= 2 && b < HIST - 1) {
		us >>= 1;
		b++;
	}
	return b;
}

static int write_pattern(const struct opts *o)
{
	const uint64_t chunk = 1 << 20;
	unsigned char *buf;
	int fd = open(o->device, O_WRONLY | O_CLOEXEC | O_DIRECT), ret = 0;

	if (fd < 0)
		return -errno;
	if (posix_memalign((void **)&buf, 4096, chunk)) {
		close(fd);
		return -ENOMEM;
	}
	for (uint64_t at = 0; at < o->bytes && !ret; at += chunk) {
		uint64_t n = o->bytes - at < chunk ? o->bytes - at : chunk;

		xg_fill(buf, at, n, (uint32_t)o->seed);
		if (pwrite(fd, buf, n, (off_t)(o->region + at)) != (ssize_t)n)
			ret = -EIO;
	}
	if (!ret && fsync(fd))
		ret = -errno;
	free(buf);
	close(fd);
	return ret;
}

/* Position i of the tenant's schedule: a block of its window, pass by pass. */
static uint64_t next_offset(const struct xg_geometry *g, uint64_t *pass, uint64_t *i)
{
	uint64_t b = xg_block(g, *pass, *i);

	if (++*i == xg_blocks(g)) {
		*i = 0;
		++*pass;
	}
	return b * g->size;
}

static void print_cpus(void)
{
	cpu_set_t set;
	bool first = true;

	printf("[");
	if (!sched_getaffinity(0, sizeof(set), &set))
		for (int c = 0; c < CPU_SETSIZE; c++)
			if (CPU_ISSET(c, &set)) {
				printf("%s%d", first ? "" : ", ", c);
				first = false;
			}
	printf("]");
}

static int run(const struct opts *o)
{
	struct xg_geometry g = { .size = o->io, .qd = o->depth, .window = o->bytes, .passes = 1,
		.pattern = XG_RAND, .seed = (uint32_t)o->seed };
	struct iovec iov[MAX_DEPTH];
	uint64_t sub_ns[MAX_DEPTH], where[MAX_DEPTH], pass = 0, pos = 0, t_go, t_start, t_end;
	struct counts c = { 0 };
	unsigned char *bufs;
	char line[16];
	struct ur ur;
	int fd, ret;

	fd = open(o->device, O_RDONLY | O_CLOEXEC | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "uring_tenant: %s: %s\n", o->device, strerror(errno));
		return 1;
	}
	if (posix_memalign((void **)&bufs, 4096, o->depth * o->io)) {
		close(fd);
		return 1;
	}
	ret = ur_setup(&ur, (unsigned)o->depth, false, false);
	for (uint64_t k = 0; k < o->depth; k++)
		iov[k] = (struct iovec){ bufs + k * o->io, o->io };
	if (!ret)
		ret = ur_register(&ur, IORING_REGISTER_BUFFERS, iov, (unsigned)o->depth);
	if (ret) {
		fprintf(stderr, "uring_tenant: io_uring setup: %s\n", strerror(-ret));
		return 1;
	}
	printf("TENANT_READY {\"pid\": %d, \"ready_ns\": %" PRIu64 ", \"cpus\": ", getpid(), now_ns());
	print_cpus();
	printf(", \"depth\": %" PRIu64 ", \"io_bytes\": %" PRIu64 "}\n", o->depth, o->io);
	fflush(stdout);
	if (!fgets(line, sizeof(line), stdin) || strncmp(line, "GO", 2))
		return 1;
	t_go = now_ns();
	t_start = t_go + (uint64_t)(o->warmup * 1e9);
	t_end = t_start + (uint64_t)(o->seconds * 1e9);
	for (uint64_t k = 0; k < o->depth; k++) {
		struct io_uring_sqe *sqe = ur_sqe(&ur);

		where[k] = next_offset(&g, &pass, &pos);
		ur_prep_rw(sqe, IORING_OP_READ_FIXED, fd, iov[k].iov_base, (uint32_t)o->io,
			   o->off + where[k], k);
		sqe->buf_index = (uint16_t)k;
		sub_ns[k] = now_ns();
	}
	ret = ur_enter(&ur, 0);
	for (uint64_t inflight = o->depth; inflight && ret >= 0; ) {
		struct io_uring_cqe *cqe;

		ret = ur_enter(&ur, 1);
		while (ret >= 0 && (cqe = ur_peek(&ur))) {
			uint64_t k = cqe->user_data, t = now_ns(), lat = t - sub_ns[k];
			bool counted = sub_ns[k] >= t_start && t <= t_end;
			int res = cqe->res;

			ur_seen(&ur);
			inflight--;
			if (counted) {
				c.ops++;
				c.hist[bucket(lat)]++;
				c.ge_1ms += lat >= 1000000ULL;
				c.max_ns = lat > c.max_ns ? lat : c.max_ns;
				if (res != (int)o->io)
					c.errors++;
				else if (o->verify &&
					 xg_compare(iov[k].iov_base, o->off - o->region + where[k], o->io,
						    (uint32_t)o->seed) >= 0)
					c.verify_fail++;
				else
					c.bytes_ok += o->io;
			}
			if (t < t_end) {
				struct io_uring_sqe *sqe = ur_sqe(&ur);

				where[k] = next_offset(&g, &pass, &pos);
				ur_prep_rw(sqe, IORING_OP_READ_FIXED, fd, iov[k].iov_base,
					   (uint32_t)o->io, o->off + where[k], k);
				sqe->buf_index = (uint16_t)k;
				sub_ns[k] = now_ns();
				inflight++;
			}
		}
	}
	printf("TENANT_RESULT {\"ops\": %" PRIu64 ", \"bytes_ok\": %" PRIu64 ", \"verify_fail\": %"
	       PRIu64 ", \"errors\": %" PRIu64 ", \"ge_1ms\": %" PRIu64 ", \"max_ns\": %" PRIu64
	       ", \"go_ns\": %" PRIu64 ", \"t_start_ns\": %" PRIu64 ", \"t_end_ns\": %" PRIu64
	       ", \"measured_ns\": %" PRIu64 ", \"window_offset\": %" PRIu64 ", \"window_bytes\": %"
	       PRIu64 ", \"verify\": %s, \"io_error\": %d, \"hist_log2_us\": [",
	       c.ops, c.bytes_ok, c.verify_fail, c.errors, c.ge_1ms, c.max_ns, t_go, t_start, t_end,
	       t_end - t_start, o->off, o->bytes, o->verify ? "true" : "false", ret < 0 ? ret : 0);
	for (int b = 0; b < HIST; b++)
		printf("%s%" PRIu64, b ? ", " : "", c.hist[b]);
	printf("]}\n");
	fflush(stdout);
	ur_close(&ur);
	free(bufs);
	close(fd);
	return ret < 0 || c.errors || c.verify_fail ? 1 : 0;
}

int main(int argc, char **argv)
{
	static const struct option lo[] = {
		{ "device", 1, 0, 1 }, { "region-offset", 1, 0, 2 }, { "offset", 1, 0, 3 },
		{ "bytes", 1, 0, 4 }, { "io-bytes", 1, 0, 5 }, { "depth", 1, 0, 6 },
		{ "seconds", 1, 0, 7 }, { "warmup", 1, 0, 8 }, { "seed", 1, 0, 9 },
		{ "verify", 0, 0, 10 }, { "write-pattern", 0, 0, 11 }, { 0, 0, 0, 0 } };
	struct opts o = { .io = 4096, .depth = 32, .seconds = 30, .warmup = 5, .seed = 1 };
	int c, bad = 0;
	bool have_off = false;

	while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
		switch (c) {
		case 1: o.device = optarg; break;
		case 2: bad |= parse_u64(optarg, &o.region); break;
		case 3: bad |= parse_u64(optarg, &o.off); have_off = true; break;
		case 4: bad |= parse_u64(optarg, &o.bytes); break;
		case 5: bad |= parse_u64(optarg, &o.io); break;
		case 6: bad |= parse_u64(optarg, &o.depth); break;
		case 7: bad |= parse_secs(optarg, &o.seconds); break;
		case 8: bad |= parse_secs(optarg, &o.warmup); break;
		case 9: bad |= parse_u64(optarg, &o.seed); break;
		case 10: o.verify = true; break;
		case 11: o.write_pattern = true; break;
		default: bad = 1;
		}
	}
	if (bad || optind != argc || !o.device || !o.bytes || o.io % 4096 || !o.io ||
	    o.region % 4096 || o.bytes % o.io || o.seed > UINT32_MAX) {
		fprintf(stderr, "usage: uring_tenant --device D --region-offset R --offset O --bytes B "
			"[--io-bytes N] [--depth N] [--seconds S] [--warmup S] [--seed N] [--verify]\n"
			"       uring_tenant --write-pattern --device D --region-offset R --bytes B --seed N\n");
		return 2;
	}
	if (o.write_pattern) {
		int ret = write_pattern(&o);

		if (ret)
			fprintf(stderr, "uring_tenant: write pattern: %s\n", strerror(-ret));
		return ret ? 1 : 0;
	}
	if (!have_off || o.off < o.region || o.off % o.io || !o.depth || o.depth > MAX_DEPTH ||
	    o.bytes / o.io < o.depth || o.bytes / o.io > (1ULL << 24)) {
		fprintf(stderr, "uring_tenant: window must lie in the region, hold depth blocks "
			"and at most 2^24 blocks\n");
		return 2;
	}
	return run(&o);
}
