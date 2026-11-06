// SPDX-License-Identifier: GPL-2.0
/*
 * K-KV baseline "no new code" arm, host 2: the KV object's LBA range is read
 * from the NVMe-oF/TCP namespace that host 1's kernel target exports, chunk
 * by chunk with pread() into one host buffer, and each chunk is copied to GPU
 * memory with cuMemcpyHtoD; a final cuCtxSynchronize() makes the KV resident
 * before the clock stops (a copy from pageable memory may return before its
 * DMA completed).  Defaults are the untuned ones: buffered reads, pageable
 * memory, one thread, 1 MiB chunks.  No xdev_ext header is used.
 *
 *   nvmeof_worker --device /dev/nvmeXnY --lba-bytes N --frame-bytes N --pool-bytes N
 *       --gpu-bdf BDF [--chunk-bytes N] [--io buffered|direct] [--host-memory pageable|pinned]
 *   nvmeof_worker ... --test-host-destination     (host copy instead of the GPU;
 *                                                 protocol tests only)
 * Worker protocol as kv_restore (kv_protocol.py).  The CUDA driver API is
 * loaded with dlopen, as in the other arms; no SDK is needed to build.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "kv_pattern.h"

#define LINE_MAX_BYTES 1024

struct cuda {
	void *lib, *ctx;
	int device;
	int (*init)(unsigned int);
	int (*device_count)(int *);
	int (*device_get)(int *, int);
	int (*device_bdf)(char *, int, int);
	int (*ctx_retain)(void **, int);
	int (*ctx_release)(int);
	int (*ctx_set)(void *);
	int (*ctx_sync)(void);
	int (*mem_alloc)(uint64_t *, size_t);
	int (*mem_free)(uint64_t);
	int (*host_alloc)(void **, size_t, unsigned int);
	int (*host_free)(void *);
	int (*htod)(uint64_t, const void *, size_t);
	int (*dtoh)(void *, uint64_t, size_t);
};

struct opts {
	const char *device, *gpu_bdf;
	uint64_t lba_bytes, frame_bytes, pool_bytes, chunk_bytes;
	bool direct, pinned, test_host;
};

struct worker {
	struct opts o;
	struct cuda cu;
	int fd;
	uint8_t *buf, *host_dst;
	uint64_t dptr;
	uint64_t restores;
};

static uint64_t now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static uint64_t cpu_us(void)
{
	struct rusage r;

	getrusage(RUSAGE_SELF, &r);
	return (uint64_t)(r.ru_utime.tv_sec + r.ru_stime.tv_sec) * 1000000ULL +
	       (uint64_t)(r.ru_utime.tv_usec + r.ru_stime.tv_usec);
}

static void emit_error(const char *where, int err)
{
	printf("KV_ERROR {\"where\": \"%s\", \"error\": %d, \"strerror\": \"%s\"}\n", where, err,
	       strerror(err < 0 ? -err : err));
	fflush(stdout);
}

static int parse_u64(const char *s, uint64_t *v)
{
	unsigned long long n;
	char *end;

	if (!s || !*s || *s == '-')
		return -EINVAL;
	errno = 0;
	n = strtoull(s, &end, 0);
	if (errno || *end)
		return -EINVAL;
	*v = n;
	return 0;
}

static int cuda_open(struct worker *w)
{
	struct cuda *c = &w->cu;
	int count = 0, matches = 0;

	c->lib = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!c->lib)
		return -ENOENT;
#define LOAD(member, symbol) do { *(void **)&c->member = dlsym(c->lib, symbol); \
	if (!c->member) return -ENOSYS; } while (0)
	LOAD(init, "cuInit");
	LOAD(device_count, "cuDeviceGetCount");
	LOAD(device_get, "cuDeviceGet");
	LOAD(device_bdf, "cuDeviceGetPCIBusId");
	LOAD(ctx_retain, "cuDevicePrimaryCtxRetain");
	LOAD(ctx_release, "cuDevicePrimaryCtxRelease_v2");
	LOAD(ctx_set, "cuCtxSetCurrent");
	LOAD(ctx_sync, "cuCtxSynchronize");
	LOAD(mem_alloc, "cuMemAlloc_v2");
	LOAD(mem_free, "cuMemFree_v2");
	LOAD(host_alloc, "cuMemHostAlloc");
	LOAD(host_free, "cuMemFreeHost");
	LOAD(htod, "cuMemcpyHtoD_v2");
	LOAD(dtoh, "cuMemcpyDtoH_v2");
#undef LOAD
	if (c->init(0) || c->device_count(&count))
		return -EIO;
	for (int i = 0; i < count; i++) {
		char bdf[32] = { 0 };
		int dev;

		if (c->device_get(&dev, i) || c->device_bdf(bdf, sizeof(bdf), dev))
			return -EIO;
		if (!strcasecmp(bdf, w->o.gpu_bdf)) {
			c->device = dev;
			matches++;
		}
	}
	if (matches != 1)
		return -EXDEV;
	if (c->ctx_retain(&c->ctx, c->device) || c->ctx_set(c->ctx))
		return -EIO;
	return c->mem_alloc(&w->dptr, w->o.pool_bytes) ? -ENOMEM : 0;
}

static int setup(struct worker *w)
{
	int ret;

	w->fd = open(w->o.device, O_RDONLY | O_CLOEXEC | (w->o.direct ? O_DIRECT : 0));
	if (w->fd < 0)
		return -errno;
	if (w->o.test_host) {
		w->host_dst = calloc(1, w->o.pool_bytes);
		if (!w->host_dst)
			return -ENOMEM;
	} else {
		ret = cuda_open(w);
		if (ret)
			return ret;
	}
	if (w->o.pinned && !w->o.test_host)
		return w->cu.host_alloc((void **)&w->buf, w->o.chunk_bytes, 0) ? -ENOMEM : 0;
	w->buf = aligned_alloc(KV_BLOCK, (w->o.chunk_bytes + KV_BLOCK - 1) / KV_BLOCK * KV_BLOCK);
	return w->buf ? 0 : -ENOMEM;
}

static int read_full(int fd, uint8_t *buf, uint64_t len, uint64_t at)
{
	uint64_t done = 0;

	while (done < len) {
		ssize_t n = pread(fd, buf + done, len - done, (off_t)(at + done));

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return n < 0 ? -errno : -EIO;
		done += (uint64_t)n;
	}
	return 0;
}

static const char *get(char **keys, char **vals, unsigned n, const char *key)
{
	for (unsigned i = 0; i < n; i++)
		if (!strcmp(keys[i], key))
			return vals[i];
	return NULL;
}

static void handle_go(struct worker *w, char *line)
{
	char *keys[16], *vals[16], *save = NULL, *tok, run[65] = "";
	uint64_t slba, bytes, dst0, ordinal, seed = 0, verify = 0, t0 = 0, t1 = 0, c0 = 0, c1 = 0;
	uint64_t chunks = 0, first_bad = 0, digest = KV_FNV_OFFSET, base, dst;
	int ret = 0, check = 1;
	unsigned n = 0;
	bool started = false;
	const char *r;

	strtok_r(line, " \t\r\n", &save);
	while ((tok = strtok_r(NULL, " \t\r\n", &save)) && n < 16) {
		char *eq = strchr(tok, '=');

		if (!eq)
			break;
		*eq = 0;
		keys[n] = tok;
		vals[n++] = eq + 1;
	}
	r = get(keys, vals, n, "run");
	if (!r || strlen(r) > 64 || parse_u64(get(keys, vals, n, "ordinal"), &ordinal) || !ordinal ||
	    parse_u64(get(keys, vals, n, "object_slba"), &slba) ||
	    parse_u64(get(keys, vals, n, "bytes"), &bytes) || !bytes ||
	    parse_u64(get(keys, vals, n, "dst_frame0"), &dst0) ||
	    (get(keys, vals, n, "seed") && parse_u64(get(keys, vals, n, "seed"), &seed)) ||
	    (get(keys, vals, n, "verify") && (parse_u64(get(keys, vals, n, "verify"), &verify) ||
					      verify > 1))) {
		emit_error("GO arguments", -EINVAL);
		return;
	}
	snprintf(run, sizeof(run), "%s", r);
	base = slba * w->o.lba_bytes;
	dst = dst0 * w->o.frame_bytes;
	if (slba > UINT64_MAX / w->o.lba_bytes || dst0 > UINT64_MAX / w->o.frame_bytes ||
	    bytes > w->o.pool_bytes || dst > w->o.pool_bytes - bytes)
		ret = -ENOSPC;
	else if (w->o.direct && ((base | bytes) % KV_BLOCK))
		ret = -EINVAL;
	if (ret)
		goto report;
	c0 = cpu_us();
	t0 = now_ns();
	started = true;
	for (uint64_t off = 0; off < bytes && !ret; off += w->o.chunk_bytes) {
		uint64_t len = bytes - off < w->o.chunk_bytes ? bytes - off : w->o.chunk_bytes;

		ret = read_full(w->fd, w->buf, w->o.direct ? (len + KV_BLOCK - 1) / KV_BLOCK * KV_BLOCK
								  : len, base + off);
		if (ret)
			break;
		if (w->o.test_host)
			memcpy(w->host_dst + dst + off, w->buf, len);
		else if (w->cu.htod(w->dptr + dst + off, w->buf, len))
			ret = -EIO;
		chunks++;
	}
	if (!ret && !w->o.test_host && w->cu.ctx_sync())
		ret = -EIO;
	t1 = now_ns();
	c1 = cpu_us();
	if (!ret && verify) {
		check = 0;
		for (uint64_t off = 0; off < bytes && !ret && !check; off += w->o.chunk_bytes) {
			uint64_t len = bytes - off < w->o.chunk_bytes ? bytes - off : w->o.chunk_bytes;
			const uint8_t *src = w->buf;

			if (w->o.test_host)
				src = w->host_dst + dst + off;
			else if (w->cu.dtoh(w->buf, w->dptr + dst + off, len))
				ret = -EIO;
			if (!ret) {
				check = kv_pattern_check(seed, off, src, len, &first_bad);
				digest = kv_fnv1a(digest, src, len);
			}
		}
	}
report:
	w->restores++;
	printf("KV_RESULT {\"run\": \"%s\", \"role\": \"nvmeof\", \"ok\": %s, \"error\": %d, "
	       "\"bytes\": %" PRIu64 ", \"started\": %s, \"t0_ns\": %" PRIu64 ", \"t1_ns\": %" PRIu64
	       ", \"latency_ns\": %" PRIu64 ", \"worker_cpu_us\": %" PRIu64 ", \"chunks\": %" PRIu64,
	       run, !ret && (!verify || !check) ? "true" : "false", ret,
	       !ret && (!verify || !check) ? bytes : 0, started ? "true" : "false", t0, t1,
	       !ret && (!verify || !check) ? t1 - t0 : 0, started ? c1 - c0 : 0, chunks);
	if (verify && !ret)
		printf(", \"verified\": %s, \"first_bad\": %" PRId64 ", \"digest\": \"0x%016" PRIx64 "\"",
		       check ? "false" : "true", check ? (int64_t)first_bad : -1, digest);
	else
		printf(", \"verified\": null");
	printf("}\n");
	fflush(stdout);
}

static int parse(int argc, char **argv, struct opts *o)
{
	static const struct option lo[] = {
		{ "device", 1, 0, 1 }, { "lba-bytes", 1, 0, 2 }, { "frame-bytes", 1, 0, 3 },
		{ "pool-bytes", 1, 0, 4 }, { "chunk-bytes", 1, 0, 5 }, { "io", 1, 0, 6 },
		{ "host-memory", 1, 0, 7 }, { "gpu-bdf", 1, 0, 8 },
		{ "test-host-destination", 0, 0, 9 }, { 0, 0, 0, 0 } };
	int c, bad = 0;

	o->frame_bytes = 131072;
	o->chunk_bytes = 1 << 20;
	while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
		switch (c) {
		case 1: o->device = optarg; break;
		case 2: bad |= parse_u64(optarg, &o->lba_bytes); break;
		case 3: bad |= parse_u64(optarg, &o->frame_bytes); break;
		case 4: bad |= parse_u64(optarg, &o->pool_bytes); break;
		case 5: bad |= parse_u64(optarg, &o->chunk_bytes); break;
		case 6: o->direct = !strcmp(optarg, "direct"); bad |= !o->direct && strcmp(optarg, "buffered"); break;
		case 7: o->pinned = !strcmp(optarg, "pinned"); bad |= !o->pinned && strcmp(optarg, "pageable"); break;
		case 8: o->gpu_bdf = optarg; break;
		case 9: o->test_host = true; break;
		default: return -EINVAL;
		}
	}
	if (bad || optind != argc || !o->device || !o->lba_bytes || !o->frame_bytes ||
	    !o->pool_bytes || !o->chunk_bytes || o->chunk_bytes > (1ULL << 30) ||
	    (o->direct && o->chunk_bytes % KV_BLOCK) || (!o->test_host && !o->gpu_bdf))
		return -EINVAL;
	return 0;
}

int main(int argc, char **argv)
{
	struct worker w = { .fd = -1 };
	char line[LINE_MAX_BYTES];
	int ret;

	if (parse(argc, argv, &w.o)) {
		emit_error("arguments", -EINVAL);
		return 2;
	}
	ret = setup(&w);
	if (ret) {
		emit_error("setup", ret);
		return 1;
	}
	printf("KV_READY {\"role\": \"nvmeof\", \"device\": \"%s\", \"chunk_bytes\": %" PRIu64
	       ", \"io\": \"%s\", \"host_memory\": \"%s\", \"pool_bytes\": %" PRIu64
	       ", \"test_host_destination\": %s}\n", w.o.device, w.o.chunk_bytes,
	       w.o.direct ? "direct" : "buffered", w.o.pinned ? "pinned" : "pageable",
	       w.o.pool_bytes, w.o.test_host ? "true" : "false");
	fflush(stdout);
	while (fgets(line, sizeof(line), stdin)) {
		if (!strncmp(line, "QUIT", 4))
			break;
		if (strncmp(line, "GO ", 3)) {
			emit_error("unknown command", -EINVAL);
			continue;
		}
		handle_go(&w, line);
	}
	ret = 0;
	if (!w.o.test_host && w.cu.lib) {
		if (w.dptr && w.cu.mem_free(w.dptr))
			ret = -EIO;
		if (w.o.pinned && w.buf && w.cu.host_free(w.buf))
			ret = -EIO;
		if (w.cu.ctx && w.cu.ctx_release(w.cu.device))
			ret = -EIO;
	}
	if (!w.o.pinned || w.o.test_host)
		free(w.buf);
	free(w.host_dst);
	close(w.fd);
	printf("KV_BYE {\"error\": %d, \"retained\": false, \"restores\": %" PRIu64 "}\n", ret,
	       w.restores);
	fflush(stdout);
	return ret ? 1 : 0;
}
