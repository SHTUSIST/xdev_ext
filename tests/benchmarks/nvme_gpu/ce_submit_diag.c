// SPDX-License-Identifier: GPL-2.0
/*
 * ce_submit_diag - internal diagnostic of the copy-engine submission path.
 *
 * For each transfer size it times, in one process on one GPU:
 *   ce-session   one XDEV_EXT session with one CE stage and N batches of one
 *                group of SIZE bytes (frame size chosen as session_nvme_ce.c
 *                does), START to terminal wake;
 *   cuda-sync    N x cuMemcpyHtoD_v2 (DtoH_v2) of SIZE bytes from pinned host
 *                memory (cuMemAllocHost), each call returning after its copy;
 *   cuda-stream  N x cuMemcpyHtoDAsync_v2 (DtoHAsync_v2) on one stream, then
 *                one cuStreamSynchronize.
 * The CUDA copies use the same VMM allocation the CE stage is bound to.
 *
 * Optional per phase: hit deltas of tracefs kprobe events (--kprobe-profile)
 * and the minimum/maximum PCIe link speed and width read from the GPU's Link
 * Status register while the phase runs (--link-bdf).
 *
 * Every result line carries diagnostic=internal: these numbers explain the
 * submission path and are never paper results.  A periodic-pattern check of
 * the window (h2d) or host frames (d2h) after each CE session catches a stage
 * that moved nothing; it is not the CE acceptance (ce_vmm_probe.c).
 * Exit: 0 every phase ran and checked, 1 failure, 2 usage, 4 unavailable.
 */
#define _GNU_SOURCE
#include <getopt.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include "../common/cpu_timer.h"
static struct cpu_timer endpoint_timer;
#include "eval_session.h"

#define CSD_MAX_SIZES 16U
#define CSD_MAX_EVENTS 16U

typedef int (*csd_alloc_host)(void **, size_t);
typedef int (*csd_free_host)(void *);
typedef int (*csd_stream_create)(void **, unsigned int);
typedef int (*csd_stream_sync)(void *);
typedef int (*csd_stream_destroy)(void *);
typedef int (*csd_htod_async)(uint64_t, const void *, size_t, void *);
typedef int (*csd_dtoh_async)(void *, uint64_t, size_t, void *);

struct csd_opts {
	const char *dev, *kprobe_profile, *link_bdf;
	uint64_t sizes[CSD_MAX_SIZES];
	unsigned int nr_sizes;
	uint64_t batches, depth, reps, timeout_ms, frame_bytes;
	bool d2h;
};

struct csd_cuda {
	csd_alloc_host alloc_host;
	csd_free_host free_host;
	csd_stream_create stream_create;
	csd_stream_sync stream_sync;
	csd_stream_destroy stream_destroy;
	csd_htod_async htod_async;
	csd_dtoh_async dtoh_async;
};

/* --- PCIe Link Status sampling ------------------------------------------ */
struct csd_link {
	int fd;
	off_t lnksta;
	pthread_t thread;
	atomic_int run, active;
	atomic_uint min_speed, max_speed, min_width, max_width, samples;
};

static void csd_link_reset(struct csd_link *l)
{
	atomic_store(&l->min_speed, 255);
	atomic_store(&l->max_speed, 0);
	atomic_store(&l->min_width, 255);
	atomic_store(&l->max_width, 0);
	atomic_store(&l->samples, 0);
}

static void *csd_link_main(void *arg)
{
	struct csd_link *l = arg;

	while (atomic_load(&l->run)) {
		uint16_t v;

		if (atomic_load(&l->active) &&
		    pread(l->fd, &v, sizeof(v), l->lnksta) == (ssize_t)sizeof(v)) {
			unsigned int speed = v & 0xf, width = (v >> 4) & 0x3f;

			if (speed < atomic_load(&l->min_speed))
				atomic_store(&l->min_speed, speed);
			if (speed > atomic_load(&l->max_speed))
				atomic_store(&l->max_speed, speed);
			if (width < atomic_load(&l->min_width))
				atomic_store(&l->min_width, width);
			if (width > atomic_load(&l->max_width))
				atomic_store(&l->max_width, width);
			atomic_fetch_add(&l->samples, 1);
		}
		usleep(200);
	}
	return NULL;
}

/* Finds the PCI Express capability; 0 or a negative errno. */
static int csd_link_open(struct csd_link *l, const char *bdf)
{
	unsigned char cfg[256];
	char path[128];
	unsigned int ptr, hops;

	memset(l, 0, sizeof(*l));
	l->fd = -1;
	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config", bdf);
	l->fd = open(path, O_RDONLY | O_CLOEXEC);
	if (l->fd < 0)
		return -errno;
	if (pread(l->fd, cfg, sizeof(cfg), 0) != (ssize_t)sizeof(cfg) || !(cfg[6] & 0x10))
		return -EIO;
	for (ptr = cfg[0x34] & 0xfc, hops = 0; ptr && hops < 48; hops++) {
		if (cfg[ptr] == 0x10) {
			l->lnksta = (off_t)ptr + 0x12;
			csd_link_reset(l);
			atomic_store(&l->run, 1);
			return pthread_create(&l->thread, NULL, csd_link_main, l) ? -EAGAIN : 0;
		}
		ptr = cfg[ptr + 1] & 0xfc;
	}
	return -ENOENT;
}

static const char *csd_gts(unsigned int code)
{
	static const char *const gts[] = { "?", "2.5", "5", "8", "16", "32", "64" };

	return code < sizeof(gts) / sizeof(gts[0]) ? gts[code] : "?";
}

static void csd_link_begin(struct csd_link *l)
{
	if (l->fd < 0)
		return;
	csd_link_reset(l);
	atomic_store(&l->active, 1);
}

static void csd_link_end(struct csd_link *l, const char *method, uint64_t size,
			 unsigned int rep)
{
	if (l->fd < 0)
		return;
	atomic_store(&l->active, 0);
	usleep(1000);
	printf("CE_SUBMIT_DIAG_LINK method=%s size=%llu rep=%u samples=%u "
	       "speed_min_gts=%s speed_max_gts=%s width_min=x%u width_max=x%u\n",
	       method, (unsigned long long)size, rep, atomic_load(&l->samples),
	       csd_gts(atomic_load(&l->min_speed)), csd_gts(atomic_load(&l->max_speed)),
	       atomic_load(&l->min_width), atomic_load(&l->max_width));
}

/* --- kprobe hit deltas -------------------------------------------------- */
struct csd_hits {
	char name[CSD_MAX_EVENTS][64];
	unsigned long long hits[CSD_MAX_EVENTS];
	unsigned int n;
};

static void csd_hits_read(const char *path, struct csd_hits *h)
{
	char line[256];
	FILE *f;

	h->n = 0;
	if (!path || !(f = fopen(path, "re")))
		return;
	while (h->n < CSD_MAX_EVENTS && fgets(line, sizeof(line), f)) {
		unsigned long long hit, miss;

		if (sscanf(line, "%63s %llu %llu", h->name[h->n], &hit, &miss) == 3)
			h->hits[h->n++] = hit;
	}
	fclose(f);
}

static void csd_hits_print(const struct csd_hits *a, const struct csd_hits *b,
			   const char *method, uint64_t size, unsigned int rep)
{
	unsigned int i, j;

	for (i = 0; i < b->n; i++)
		for (j = 0; j < a->n; j++)
			if (!strcmp(a->name[j], b->name[i]))
				printf("CE_SUBMIT_DIAG_KPROBE method=%s size=%llu rep=%u event=%s hits=%llu\n",
				       method, (unsigned long long)size, rep, b->name[i],
				       b->hits[i] - a->hits[j]);
}

/* --- helpers ------------------------------------------------------------ */
static unsigned char csd_pattern(uint64_t frame_off)
{
	return (unsigned char)(frame_off * 131U + 7U);
}

static uint64_t csd_frame(const struct csd_opts *o, uint64_t size)
{
	uint64_t f = o->frame_bytes ? o->frame_bytes : 4096;

	if (!o->frame_bytes)
		while (f * XDEV_EXT_MECH_MAX_FRAMES < size)
			f <<= 1;
	return f;
}

static void csd_result(const char *method, uint64_t size, uint64_t frame,
		       const struct csd_opts *o, unsigned int rep, uint64_t ns)
{
	double bytes = (double)size * (double)o->batches;

	printf("CE_SUBMIT_DIAG method=%s dir=%s size=%llu frame=%llu batches=%llu depth=%llu "
	       "rep=%u ns=%llu gbps=%.3f us_per_copy=%.3f diagnostic=internal\n",
	       method, o->d2h ? "d2h" : "h2d", (unsigned long long)size,
	       (unsigned long long)frame, (unsigned long long)o->batches,
	       (unsigned long long)o->depth, rep, (unsigned long long)ns,
	       ns ? bytes / (double)ns : 0.0,
	       (double)ns / 1000.0 / (double)o->batches);
}

/*
 * One CE session of o->batches groups of @size bytes; START to terminal wake.
 * Returns 0, or an exit code; *fatal means STOP was not proven and nothing
 * the session used may be released.
 */
static int csd_ce_session(const struct csd_opts *o, struct es_ce *ce, uint64_t size,
			  unsigned int rep, struct csd_link *link, bool *fatal)
{
	uint64_t frame = csd_frame(o, size), frames, i, t0, t1, deadline;
	struct io_uring_xdev_ext_umem_reg reg = { 0 };
	struct xdev_ext_mech_create c;
	struct xdev_ext_mech_stats s;
	struct es_run r = { .ring = -1, .efd = -1 };
	struct csd_hits before, after;
	unsigned char *umem = MAP_FAILED, *buf = NULL;
	__u32 *user = NULL;
	int ret, closed;

	*fatal = false;
	memset(&c, 0, sizeof(c));
	c.layout = (struct xdev_ext_mech_layout) {
		.frame_size = (__u32)frame, .hdr_room = 0,
		.seg_len = (__u32)frame, .group_bytes = (__u32)size,
	};
	ret = xdev_ext_mech_layout_frames(&c.layout);
	if (ret <= 0)
		return XG_EXIT_USAGE;
	frames = (uint64_t)ret;
	reg.frame_size = (__u32)frame;
	reg.size = o->depth * frames * frame;
	umem = mmap(NULL, reg.size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	user = calloc(o->depth * frames, sizeof(*user));
	buf = malloc(o->depth * size);
	if (umem == MAP_FAILED || !user || !buf) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	for (i = 0; i < reg.size; i++)
		umem[i] = o->d2h ? 0x5a : csd_pattern(i % frame);
	for (i = 0; i < o->depth * frames; i++)
		user[i] = (__u32)i;
	/* Window: poison (h2d) or the pattern every group slot must deliver (d2h). */
	for (i = 0; i < o->depth * size; i++)
		buf[i] = o->d2h ? csd_pattern(i % frame) : 0xa5;
	ret = es_ce_access(ce, true, 0, buf, o->depth * size);
	if (ret) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	reg.addr = (uintptr_t)umem;
	ret = es_ring_open(&r);
	if (!ret)
		ret = es_register(r.ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg);
	if (ret) {
		fprintf(stderr, "ring/UMEM: %s\n", strerror(-ret));
		ret = XG_EXIT_UNAVAILABLE;
		goto out;
	}
	c.nr_stages = 1;
	c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	c.pool_fd = -1;
	c.depth = (__u32)o->depth;
	c.st[0] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_CE,
		.direction = o->d2h ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE,
		.fd = ce->fd[0], .arg0 = ce->va, .arg1 = o->depth * size,
	};
	ret = es_create(&r, &c, o->batches);
	if (ret) {
		fprintf(stderr, "CREATE (attached ce_plan_ops, CE device): %s\n", strerror(-ret));
		ret = r.session ? XG_EXIT_FAIL : XG_EXIT_UNAVAILABLE;
		goto out;
	}
	csd_hits_read(o->kprobe_profile, &before);
	deadline = es_now_ns() + o->timeout_ms * 1000000ULL;
	csd_link_begin(link);
	t0 = es_now_ns();
	ret = es_start(&r, o->batches, user, (__u32)(o->depth * frames));
	if (!ret)
		ret = es_wait_terminal(&r, deadline);
	t1 = es_now_ns();
	csd_link_end(link, "ce-session", size, rep);
	csd_hits_read(o->kprobe_profile, &after);
	if (!ret)
		ret = es_settle(&r, o->batches, deadline, &s);
	else
		es_stats(&r, &s);
	es_print_stats(&s);
	if (ret || s.batches_done != o->batches || s.submitted[0] != o->batches ||
	    s.completed[0] != o->batches || s.inflight || !t0 || t1 <= t0) {
		fprintf(stderr, "CE session size=%llu: %s\n", (unsigned long long)size,
			ret ? strerror(-ret) : "counters do not cover the campaign");
		ret = XG_EXIT_FAIL;
		goto out;
	}
	csd_result("ce-session", size, frame, o, rep, t1 - t0);
	csd_hits_print(&before, &after, "ce-session", size, rep);
	ret = 0;
out:
	closed = es_close(&r);
	if (closed) {
		/* No proven drain: keep UMEM, buffers and the window as they are. */
		fprintf(stderr, "CE_SUBMIT_DIAG=FAIL size=%llu stop=%d release=withheld\n",
			(unsigned long long)size, closed);
		*fatal = true;
		return XG_EXIT_FAIL;
	}
	if (!ret) {
		/*
		 * h2d: every window slot holds the pattern.  d2h: every frame is
		 * either untouched or a whole pattern frame, and at least one
		 * group's frames were written (which frames a batch takes is
		 * the kernel's choice).
		 */
		if (o->d2h) {
			uint64_t f, written = 0;

			for (f = 0, i = 0; f < o->depth * frames && !ret; f++) {
				unsigned char *p = umem + f * frame;
				bool poison = p[0] == 0x5a;

				for (i = 0; i < frame; i++)
					if (p[i] != (poison ? 0x5a : csd_pattern(i)))
						break;
				if (i != frame)
					ret = XG_EXIT_FAIL;
				written += !poison;
			}
			if (!ret && written < frames)
				ret = XG_EXIT_FAIL;
		} else if (es_ce_access(ce, false, 0, buf, o->depth * size)) {
			ret = XG_EXIT_FAIL;
		} else {
			for (i = 0; i < o->depth * size && buf[i] == csd_pattern(i % frame); i++)
				;
			if (i != o->depth * size)
				ret = XG_EXIT_FAIL;
		}
		if (ret)
			fprintf(stderr, "CE_SUBMIT_DIAG=FAIL size=%llu data byte %llu differs\n",
				(unsigned long long)size, (unsigned long long)i);
	}
	free(user);
	free(buf);
	if (umem != MAP_FAILED)
		munmap(umem, reg.size);
	return ret;
}

/* N pinned copies, synchronous per call (@stream NULL) or on one stream. */
static int csd_cuda_copies(const struct csd_opts *o, struct es_ce *ce,
			   const struct csd_cuda *cu, uint64_t size, unsigned int rep,
			   bool stream, struct csd_link *link)
{
	const char *method = stream ? "cuda-stream" : "cuda-sync";
	struct csd_hits before, after;
	void *host = NULL, *st = NULL, *previous = NULL;
	uint64_t i, t0, t1;
	int ret, err = 0;

	ret = xdev_ext_mech_cuda_result(ce->cuda.ctx_get(&previous), "cuCtxGetCurrent");
	if (!ret)
		ret = xdev_ext_mech_cuda_result(ce->cuda.ctx_set(ce->cuda.ctx), "cuCtxSetCurrent");
	if (ret)
		return XG_EXIT_FAIL;
	if (cu->alloc_host(&host, size) || !host) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	memset(host, 0x3c, size);
	if (stream && cu->stream_create(&st, 0)) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	csd_hits_read(o->kprobe_profile, &before);
	csd_link_begin(link);
	t0 = es_now_ns();
	for (i = 0; i < o->batches && !err; i++) {
		uint64_t dev = ce->va + (i % o->depth) * size;

		if (stream)
			err = o->d2h ? cu->dtoh_async(host, dev, size, st) :
				       cu->htod_async(dev, host, size, st);
		else
			err = o->d2h ? ce->dtoh(host, dev, size) : ce->htod(dev, host, size);
	}
	if (!err && stream)
		err = cu->stream_sync(st);
	t1 = es_now_ns();
	csd_link_end(link, method, size, rep);
	csd_hits_read(o->kprobe_profile, &after);
	if (err || !t0 || t1 <= t0) {
		fprintf(stderr, "%s size=%llu: CUDA status %d\n", method,
			(unsigned long long)size, err);
		ret = XG_EXIT_FAIL;
		goto out;
	}
	csd_result(method, size, size, o, rep, t1 - t0);
	csd_hits_print(&before, &after, method, size, rep);
	ret = 0;
out:
	if (st && cu->stream_destroy(st))
		ret = XG_EXIT_FAIL;
	if (host && cu->free_host(host))
		ret = XG_EXIT_FAIL;
	if (xdev_ext_mech_cuda_result(ce->cuda.ctx_set(previous), "cuCtxSetCurrent(restore)"))
		ret = XG_EXIT_FAIL;
	return ret;
}

static int csd_resolve(struct es_ce *ce, struct csd_cuda *cu)
{
	void *lib = ce->cuda.lib;

	*(void **)&cu->alloc_host = dlsym(lib, "cuMemAllocHost_v2");
	*(void **)&cu->free_host = dlsym(lib, "cuMemFreeHost");
	*(void **)&cu->stream_create = dlsym(lib, "cuStreamCreate");
	*(void **)&cu->stream_sync = dlsym(lib, "cuStreamSynchronize");
	*(void **)&cu->stream_destroy = dlsym(lib, "cuStreamDestroy_v2");
	*(void **)&cu->htod_async = dlsym(lib, "cuMemcpyHtoDAsync_v2");
	*(void **)&cu->dtoh_async = dlsym(lib, "cuMemcpyDtoHAsync_v2");
	return cu->alloc_host && cu->free_host && cu->stream_create && cu->stream_sync &&
	       cu->stream_destroy && cu->htod_async && cu->dtoh_async ? 0 : -ENOSYS;
}

/* One size: a fresh VMM window of depth groups, then every method rep times. */
static int csd_size(const struct csd_opts *o, uint64_t size, struct csd_link *link)
{
	struct es_ce ce = { .fd = { -1, -1 }, .sim = true };
	struct csd_cuda cu;
	unsigned int rep;
	bool fatal = false;
	int ret;

	ret = es_ce_open(&ce, o->dev, 1, ES_CE_VMM, 0, o->depth * size);
	if (ret)
		goto out;
	if (!ce.cuda.vmm || !ce.cuda.mapped || ce.cuda.vmm_bytes < o->depth * size ||
	    csd_resolve(&ce, &cu)) {
		ret = XG_EXIT_UNAVAILABLE;
		goto out;
	}
	ce.len = ce.cuda.vmm_bytes;
	for (rep = 0; rep < o->reps && !ret; rep++) {
		ret = csd_ce_session(o, &ce, size, rep, link, &fatal);
		if (fatal) {
			fflush(stdout);
			fflush(stderr);
			_exit(XG_EXIT_FAIL);
		}
		if (!ret)
			ret = csd_cuda_copies(o, &ce, &cu, size, rep, false, link);
		if (!ret)
			ret = csd_cuda_copies(o, &ce, &cu, size, rep, true, link);
	}
out:
	if (es_ce_close(&ce))
		ret = XG_EXIT_FAIL;
	return ret;
}

static void csd_usage(FILE *f)
{
	fprintf(f, "usage: ce_submit_diag [--ce-dev /dev/nvidiaN] [--sizes 4096,...,4194304]\n"
		"       [--batches N] [--depth N] [--reps N] [--frame-bytes N] [--dir h2d|d2h]\n"
		"       [--timeout-ms N] [--kprobe-profile PATH] [--link-bdf DDDD:BB:DD.F]\n"
		"Internal diagnostic: CE session vs pinned cuMemcpy; never a paper result.\n");
}

static int csd_parse_sizes(const char *arg, struct csd_opts *o)
{
	char copy[512], *save = NULL, *tok;

	if (strlen(arg) >= sizeof(copy))
		return -1;
	strcpy(copy, arg);
	o->nr_sizes = 0;
	for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		uint64_t v;

		if (o->nr_sizes == CSD_MAX_SIZES || xg_parse_u64(tok, 1ULL << 26, &v) ||
		    v < 4096 || (v & (v - 1)))
			return -1;
		o->sizes[o->nr_sizes++] = v;
	}
	return o->nr_sizes ? 0 : -1;
}

static int csd_parse(int argc, char **argv, struct csd_opts *o)
{
	static const struct option opts[] = {
		{ "ce-dev", required_argument, NULL, 'd' },
		{ "sizes", required_argument, NULL, 's' },
		{ "batches", required_argument, NULL, 'n' },
		{ "depth", required_argument, NULL, 'q' },
		{ "reps", required_argument, NULL, 'r' },
		{ "frame-bytes", required_argument, NULL, 'f' },
		{ "dir", required_argument, NULL, 'D' },
		{ "timeout-ms", required_argument, NULL, 't' },
		{ "kprobe-profile", required_argument, NULL, 'k' },
		{ "link-bdf", required_argument, NULL, 'l' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int ch, bad = 0;

	*o = (struct csd_opts) { .dev = "/dev/nvidia0", .batches = 256, .depth = 8,
				 .reps = 3, .timeout_ms = 60000 };
	csd_parse_sizes("4096,16384,65536,262144,1048576,4194304", o);
	while ((ch = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (ch) {
		case 'd': o->dev = optarg; break;
		case 's': bad |= csd_parse_sizes(optarg, o); break;
		case 'n': bad |= xg_parse_u64(optarg, 1ULL << 20, &o->batches) || !o->batches; break;
		case 'q': bad |= xg_parse_u64(optarg, 64, &o->depth) || !o->depth; break;
		case 'r': bad |= xg_parse_u64(optarg, 100, &o->reps) || !o->reps; break;
		case 'f':
			bad |= xg_parse_u64(optarg, 1ULL << 22, &o->frame_bytes) ||
			       o->frame_bytes < 4096 || (o->frame_bytes & (o->frame_bytes - 1));
			break;
		case 'D':
			if (!strcmp(optarg, "h2d") || !strcmp(optarg, "d2h"))
				o->d2h = !strcmp(optarg, "d2h");
			else
				bad = 1;
			break;
		case 't': bad |= xg_parse_u64(optarg, 600000, &o->timeout_ms) || !o->timeout_ms; break;
		case 'k': o->kprobe_profile = optarg; break;
		case 'l': o->link_bdf = optarg; break;
		case 'h': csd_usage(stdout); return -1;
		default: return XG_EXIT_USAGE;
		}
	}
	if (bad || optind != argc || !*o->dev || es_ce_is_sim(o->dev) ||
	    o->batches < o->depth)
		return XG_EXIT_USAGE;
	return 0;
}

int main(int argc, char **argv)
{
	struct csd_link link = { .fd = -1 };
	struct csd_opts o;
	unsigned int i;
	int ret, fd_before;

	(void)endpoint_timer; /* eval include prerequisite; the timer is not used. */
	ret = csd_parse(argc, argv, &o);
	if (ret == -1)
		return XG_EXIT_PASS;
	if (ret) {
		csd_usage(stderr);
		return ret;
	}
	ret = es_ce_runtime_begin(o.dev, &fd_before);
	if (ret)
		return ret;
	if (o.link_bdf && csd_link_open(&link, o.link_bdf)) {
		fprintf(stderr, "PCIe Link Status of %s unavailable; not sampled\n", o.link_bdf);
		if (link.fd >= 0)
			close(link.fd);
		link.fd = -1;
	}
	for (i = 0; i < o.nr_sizes && !ret; i++)
		ret = csd_size(&o, o.sizes[i], &link);
	if (link.fd >= 0) {
		atomic_store(&link.run, 0);
		pthread_join(link.thread, NULL);
		close(link.fd);
	}
	if (!ret && eval_fd_check(fd_before))
		ret = XG_EXIT_FAIL;
	printf("CE_SUBMIT_DIAG_DONE result=%s sizes=%u diagnostic=internal performance_claim=none\n",
	       ret ? "FAIL" : "PASS", o.nr_sizes);
	if (fflush(stdout) && !ret)
		ret = XG_EXIT_FAIL;
	return ret;
}
