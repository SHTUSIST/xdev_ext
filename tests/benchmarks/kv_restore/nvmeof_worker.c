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
 *   nvmeof_worker ... --engine uring --depth N --io direct --host-memory registered
 *       E5 level 1, the plan's shared io_uring baseline on the NVMe-oF namespace:
 *       O_DIRECT READ_FIXED of chunk-sized reads into N buffers registered once
 *       with io_uring and with cuMemHostRegister, N reads in flight, and per
 *       completed read one cuMemcpyHtoDAsync to its destination offset; a buffer
 *       is reused only after its copy completed.  No SQPOLL, no IOPOLL.  The
 *       io_uring system calls are raw (<linux/io_uring.h>), no liburing.
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
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
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
	/* --engine uring */
	int (*host_register)(void *, size_t, unsigned int);
	int (*host_unregister)(void *);
	int (*stream_create)(void **, unsigned int);
	int (*event_create)(void **, unsigned int);
	int (*event_record)(void *, void *);
	int (*event_query)(void *);
	int (*event_sync)(void *);
	int (*htod_async)(uint64_t, const void *, size_t, void *);
	void *stream;
};

#define MAX_DEPTH 256
#define CUDA_ERROR_NOT_READY 600

/* The few io_uring pieces the uring engine needs, on raw system calls. */
struct ring {
	int fd;
	unsigned entries, *sq_head, *sq_tail, *sq_mask, *sq_array, *cq_head, *cq_tail, *cq_mask;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	void *sq_map, *cq_map;
	size_t sq_len, cq_len, sqes_len;
	unsigned pending;
};

struct opts {
	const char *device, *gpu_bdf;
	uint64_t lba_bytes, frame_bytes, pool_bytes, chunk_bytes;
	bool direct, pinned, test_host, uring, registered;
	uint64_t depth;
};

struct worker {
	struct opts o;
	struct cuda cu;
	int fd;
	uint8_t *buf, *host_dst;
	uint64_t dptr;
	uint64_t restores;
	struct ring ring;
	uint8_t *slots;			/* --engine uring: depth chunk buffers */
	void *events[MAX_DEPTH];
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
	if (w->o.uring) {
		LOAD(host_register, "cuMemHostRegister_v2");
		LOAD(host_unregister, "cuMemHostUnregister");
		LOAD(stream_create, "cuStreamCreate");
		LOAD(event_create, "cuEventCreate");
		LOAD(event_record, "cuEventRecord");
		LOAD(event_query, "cuEventQuery");
		LOAD(event_sync, "cuEventSynchronize");
		LOAD(htod_async, "cuMemcpyHtoDAsync_v2");
	}
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

static int ring_setup(struct ring *r, unsigned entries)
{
	struct io_uring_params p;

	memset(r, 0, sizeof(*r));
	memset(&p, 0, sizeof(p));
	r->fd = (int)syscall(__NR_io_uring_setup, entries, &p);
	if (r->fd < 0)
		return -errno;
	r->entries = p.sq_entries;
	r->sq_len = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	r->cq_len = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	r->sqes_len = p.sq_entries * sizeof(struct io_uring_sqe);
	r->sq_map = mmap(NULL, r->sq_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
			 IORING_OFF_SQ_RING);
	r->cq_map = mmap(NULL, r->cq_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
			 IORING_OFF_CQ_RING);
	r->sqes = mmap(NULL, r->sqes_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
		       IORING_OFF_SQES);
	if (r->sq_map == MAP_FAILED || r->cq_map == MAP_FAILED || r->sqes == MAP_FAILED)
		return -ENOMEM;
	r->sq_head = (unsigned *)((char *)r->sq_map + p.sq_off.head);
	r->sq_tail = (unsigned *)((char *)r->sq_map + p.sq_off.tail);
	r->sq_mask = (unsigned *)((char *)r->sq_map + p.sq_off.ring_mask);
	r->sq_array = (unsigned *)((char *)r->sq_map + p.sq_off.array);
	r->cq_head = (unsigned *)((char *)r->cq_map + p.cq_off.head);
	r->cq_tail = (unsigned *)((char *)r->cq_map + p.cq_off.tail);
	r->cq_mask = (unsigned *)((char *)r->cq_map + p.cq_off.ring_mask);
	r->cqes = (struct io_uring_cqe *)((char *)r->cq_map + p.cq_off.cqes);
	return 0;
}

/* Queue READ_FIXED of len bytes at off into registered buffer idx. */
static void ring_read(struct ring *r, int fd, void *buf, unsigned len, uint64_t off, unsigned idx)
{
	unsigned tail = *r->sq_tail + r->pending, i = tail & *r->sq_mask;
	struct io_uring_sqe *sqe = &r->sqes[i];

	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_READ_FIXED;
	sqe->fd = fd;
	sqe->addr = (uintptr_t)buf;
	sqe->len = len;
	sqe->off = off;
	sqe->buf_index = (uint16_t)idx;
	sqe->user_data = idx;
	r->sq_array[i] = i;
	r->pending++;
}

/* Submit the queued reads and wait for @wait completions. */
static int ring_enter(struct ring *r, unsigned wait)
{
	unsigned n = r->pending;
	int ret;

	__atomic_store_n(r->sq_tail, *r->sq_tail + n, __ATOMIC_RELEASE);
	r->pending = 0;
	if (!n && !wait)
		return 0;
	do
		ret = (int)syscall(__NR_io_uring_enter, r->fd, n, wait,
				   wait ? IORING_ENTER_GETEVENTS : 0, NULL, 0);
	while (ret < 0 && errno == EINTR && !(n = 0));
	return ret < 0 ? -errno : 0;
}

static struct io_uring_cqe *ring_peek(struct ring *r)
{
	unsigned head = *r->cq_head;

	if (head == __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE))
		return NULL;
	return &r->cqes[head & *r->cq_mask];
}

static void ring_seen(struct ring *r)
{
	__atomic_store_n(r->cq_head, *r->cq_head + 1, __ATOMIC_RELEASE);
}

static void ring_close(struct ring *r)
{
	if (r->sqes && r->sqes != MAP_FAILED)
		munmap(r->sqes, r->sqes_len);
	if (r->cq_map && r->cq_map != MAP_FAILED)
		munmap(r->cq_map, r->cq_len);
	if (r->sq_map && r->sq_map != MAP_FAILED)
		munmap(r->sq_map, r->sq_len);
	if (r->fd > 0)
		close(r->fd);
}

/* --engine uring: depth buffers registered with io_uring and CUDA, one event each. */
static int uring_setup(struct worker *w)
{
	struct iovec iov[MAX_DEPTH];
	size_t bytes = w->o.depth * w->o.chunk_bytes;
	int ret = ring_setup(&w->ring, (unsigned)w->o.depth);

	if (ret)
		return ret;
	w->slots = aligned_alloc(KV_BLOCK, bytes);
	if (!w->slots)
		return -ENOMEM;
	for (uint64_t k = 0; k < w->o.depth; k++)
		iov[k] = (struct iovec){ w->slots + k * w->o.chunk_bytes, w->o.chunk_bytes };
	if (syscall(__NR_io_uring_register, w->ring.fd, IORING_REGISTER_BUFFERS, iov,
		    (unsigned)w->o.depth) < 0)
		return -errno;
	if (w->o.test_host)
		return 0;
	if (w->cu.host_register(w->slots, bytes, 0) || w->cu.stream_create(&w->cu.stream, 1))
		return -EIO;
	for (uint64_t k = 0; k < w->o.depth; k++)
		if (w->cu.event_create(&w->events[k], 3))	/* blocking sync, no timing */
			return -EIO;
	return 0;
}

enum { SLOT_FREE, SLOT_READ, SLOT_COPY };

/*
 * One restore with depth reads in flight: a completed read starts the copy of
 * its chunk to dst + off; a buffer returns to the free list once its copy
 * completed.  With --test-host-destination the copy is a memcpy at completion.
 */
static int uring_restore(struct worker *w, uint64_t base, uint64_t dst, uint64_t bytes,
			 uint64_t *chunks)
{
	uint64_t n = (bytes + w->o.chunk_bytes - 1) / w->o.chunk_bytes, next = 0, finished = 0;
	uint64_t chunk_of[MAX_DEPTH];
	unsigned state[MAX_DEPTH] = { 0 }, reads = 0, copies = 0;
	int ret = 0;

	while (finished < n) {
		struct io_uring_cqe *cqe;
		bool progressed = false;

		for (uint64_t k = 0; !ret && next < n && k < w->o.depth; k++) {
			uint64_t len;

			if (state[k] != SLOT_FREE)
				continue;
			len = bytes - next * w->o.chunk_bytes < w->o.chunk_bytes ?
			      bytes - next * w->o.chunk_bytes : w->o.chunk_bytes;
			ring_read(&w->ring, w->fd, w->slots + k * w->o.chunk_bytes,
				  (unsigned)((len + KV_BLOCK - 1) / KV_BLOCK * KV_BLOCK),
				  base + next * w->o.chunk_bytes, (unsigned)k);
			chunk_of[k] = next++;
			state[k] = SLOT_READ;
			reads++;
		}
		/* Sleep on io_uring only when no copy can be retired meanwhile. */
		ret = ring_enter(&w->ring, reads && !copies ? 1 : 0);
		while (!ret && (cqe = ring_peek(&w->ring))) {
			unsigned k = (unsigned)cqe->user_data;
			uint64_t off = chunk_of[k] * w->o.chunk_bytes;
			uint64_t len = bytes - off < w->o.chunk_bytes ? bytes - off : w->o.chunk_bytes;
			int res = cqe->res;

			ring_seen(&w->ring);
			reads--;
			progressed = true;
			if (res < 0 || (uint64_t)res < len) {
				ret = res < 0 ? res : -EIO;
				break;
			}
			if (w->o.test_host) {
				memcpy(w->host_dst + dst + off, w->slots + (uint64_t)k * w->o.chunk_bytes, len);
				state[k] = SLOT_FREE;
				finished++;
			} else if (w->cu.htod_async(w->dptr + dst + off,
						    w->slots + (uint64_t)k * w->o.chunk_bytes, len,
						    w->cu.stream) ||
				   w->cu.event_record(w->events[k], w->cu.stream)) {
				ret = -EIO;
			} else {
				state[k] = SLOT_COPY;
				copies++;
			}
			(*chunks)++;
		}
		for (uint64_t k = 0; !ret && k < w->o.depth; k++) {
			int q;

			if (state[k] != SLOT_COPY)
				continue;
			q = w->cu.event_query(w->events[k]);
			if (q == CUDA_ERROR_NOT_READY)
				continue;
			if (q) {
				ret = -EIO;
				break;
			}
			state[k] = SLOT_FREE;
			copies--;
			finished++;
			progressed = true;
		}
		/* Nothing finished: block on one copy instead of polling (reads that
		 * complete meanwhile wait in the completion ring). */
		if (!ret && !progressed && copies) {
			for (uint64_t k = 0; k < w->o.depth; k++)
				if (state[k] == SLOT_COPY) {
					ret = w->cu.event_sync(w->events[k]) ? -EIO : 0;
					break;
				}
		}
		if (ret)
			break;
	}
	/* On error: let reads and copies in flight finish before buffers are reused. */
	while (reads && !ring_enter(&w->ring, 1)) {
		struct io_uring_cqe *cqe;

		while ((cqe = ring_peek(&w->ring))) {
			ring_seen(&w->ring);
			reads--;
		}
	}
	if (copies && w->cu.ctx_sync())
		ret = ret ? ret : -EIO;
	return ret;
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
	if (w->o.uring)
		return uring_setup(w);
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
	if (w->o.uring)
		ret = uring_restore(w, base, dst, bytes, &chunks);
	for (uint64_t off = 0; !w->o.uring && off < bytes && !ret; off += w->o.chunk_bytes) {
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
			uint8_t *scratch = w->o.uring ? w->slots : w->buf;
			const uint8_t *src = scratch;

			if (w->o.test_host)
				src = w->host_dst + dst + off;
			else if (w->cu.dtoh(scratch, w->dptr + dst + off, len))
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
		{ "test-host-destination", 0, 0, 9 }, { "engine", 1, 0, 10 }, { "depth", 1, 0, 11 },
		{ 0, 0, 0, 0 } };
	int c, bad = 0;
	bool depth_given = false;

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
		case 7:
			o->pinned = !strcmp(optarg, "pinned");
			o->registered = !strcmp(optarg, "registered");
			bad |= !o->pinned && !o->registered && strcmp(optarg, "pageable");
			break;
		case 8: o->gpu_bdf = optarg; break;
		case 9: o->test_host = true; break;
		case 10: o->uring = !strcmp(optarg, "uring"); bad |= !o->uring && strcmp(optarg, "pread"); break;
		case 11: bad |= parse_u64(optarg, &o->depth); depth_given = true; break;
		default: return -EINVAL;
		}
	}
	if (bad || optind != argc || !o->device || !o->lba_bytes || !o->frame_bytes ||
	    !o->pool_bytes || !o->chunk_bytes || o->chunk_bytes > (1ULL << 30) ||
	    (o->direct && o->chunk_bytes % KV_BLOCK) || (!o->test_host && !o->gpu_bdf))
		return -EINVAL;
	/* The uring engine reads O_DIRECT into its registered buffers only. */
	if (o->uring ? !o->direct || !o->registered || !o->depth || o->depth > MAX_DEPTH :
		       depth_given || o->registered)
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
	       ", \"test_host_destination\": %s, \"engine\": \"%s\", \"depth\": %" PRIu64 "}\n",
	       w.o.device, w.o.chunk_bytes, w.o.direct ? "direct" : "buffered",
	       w.o.registered ? "registered" : w.o.pinned ? "pinned" : "pageable",
	       w.o.pool_bytes, w.o.test_host ? "true" : "false", w.o.uring ? "uring" : "pread",
	       w.o.uring ? w.o.depth : 1);
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
	if (w.o.uring) {
		if (!w.o.test_host && w.cu.host_unregister && w.slots)
			w.cu.host_unregister(w.slots);
		ring_close(&w.ring);
		free(w.slots);
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
