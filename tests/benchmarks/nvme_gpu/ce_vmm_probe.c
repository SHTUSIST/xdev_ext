// SPDX-License-Identifier: GPL-2.0
/*
 * Unmeasured VMM -> real CE session acceptance. CUDA copies only seed/read the
 * oracle; the tested transfers use START and the kernel's CE backend.
 *
 * The large cases move one 2 MiB group of 32 64 KiB frames with no head room,
 * so the frames are adjacent in the host pool and the window and one RM
 * transfer covers a whole stage; the CE then needs one command per run of
 * physically adjacent pages.  large-huge backs the pool with 2 MiB hugetlb
 * pages (multi-page commands), large-4k with ordinary 4 KiB pages scattered
 * on purpose (about one command per page against one long GPU run).  Optional kprobe hit deltas around
 * START..terminal and the host run count from /proc/self/pagemap are
 * diagnostics, never part of the PASS decision.
 */
#define _GNU_SOURCE
#include <getopt.h>
#include "../common/cpu_timer.h"
static struct cpu_timer endpoint_timer;
#include "eval_session.h"
#include "../../../kernel/include/uapi/linux/xdev_ext_policy.h"
#include "ce_vmm_probe_check.h"

#define CVP_FRAME 4096U
#define CVP_HEAD 1024U
#define CVP_SEG 2048U
#define CVP_FRAMES 2U
#define CVP_HOST_BYTES (4U * CVP_FRAME)
#define CVP_PAYLOAD (CVP_FRAMES * CVP_SEG)
#define CVP_A 4096U
#define CVP_B 16384U
#define CVP_BYTES 32768U
#define CVP_LARGE_FRAME (64U * 1024U)
#define CVP_LARGE_FRAMES 32U
#define CVP_LARGE_PAYLOAD (CVP_LARGE_FRAMES * CVP_LARGE_FRAME)	/* 2 MiB */
#define CVP_LARGE_HOST (4U << 20)	/* two 2 MiB pages */
#define CVP_LARGE_FIRST 16U		/* frames 16..47 straddle the two pages */
#define CVP_LARGE_B (5U << 19)		/* 2.5 MiB: crosses a 2 MiB boundary */
#define CVP_LARGE_BYTES (8U << 20)
#define CVP_MAX_EVENTS 16U

enum cvp_case { CVP_H2D, CVP_D2H, CVP_MULTI, CVP_CLOSE_EXPORT, CVP_PARTIAL,
		CVP_LARGE_HUGE, CVP_LARGE_4K };
static const char *const cvp_names[] = {
	"single-h2d", "single-d2h", "multi", "close-export", "partial-attach",
	"large-huge", "large-4k"
};

/* Frames first..first+frames-1 each carry seg bytes at head; windows A and B. */
struct cvp_geom {
	unsigned int frame, head, seg, frames, first;
	size_t host_bytes, payload;
	uint64_t a, b, bytes;
};
static const struct cvp_geom cvp_small = {
	CVP_FRAME, CVP_HEAD, CVP_SEG, CVP_FRAMES, 1, CVP_HOST_BYTES, CVP_PAYLOAD,
	CVP_A, CVP_B, CVP_BYTES
};
static const struct cvp_geom cvp_large = {
	CVP_LARGE_FRAME, 0, CVP_LARGE_FRAME, CVP_LARGE_FRAMES, CVP_LARGE_FIRST,
	CVP_LARGE_HOST, CVP_LARGE_PAYLOAD, 0, CVP_LARGE_B, CVP_LARGE_BYTES
};

struct cvp_options {
	const char *dev, *kprobe_profile;
	enum cvp_case which;
	uint64_t timeout_ms;
};

static void cvp_usage(FILE *f)
{
	fprintf(f, "usage: ce_vmm_probe [--ce-dev /dev/nvidiaN] [--timeout-ms 5000]\n"
		"       [--case single-h2d|single-d2h|multi|close-export|partial-attach|\n"
		"               large-huge|large-4k] [--kprobe-profile PATH]\n"
		"Default: multi. large-huge needs two reserved 2 MiB hugetlb pages.\n"
		"--kprobe-profile prints tracefs kprobe hit deltas around START..terminal\n"
		"(diagnostic only). Real CE session correctness only; no timing or performance result.\n");
}

static bool cvp_is_large(enum cvp_case which)
{
	return which == CVP_LARGE_HUGE || which == CVP_LARGE_4K;
}

/* tracefs kprobe_profile lines: "event hits misses". */
struct cvp_hits {
	char name[CVP_MAX_EVENTS][64];
	unsigned long long hits[CVP_MAX_EVENTS];
	unsigned int n;
};

static void cvp_hits_read(const char *path, struct cvp_hits *h)
{
	char line[256];
	FILE *f;

	h->n = 0;
	if (!path || !(f = fopen(path, "re")))
		return;
	while (h->n < CVP_MAX_EVENTS && fgets(line, sizeof(line), f)) {
		unsigned long long hit, miss;

		if (sscanf(line, "%63s %llu %llu", h->name[h->n], &hit, &miss) == 3)
			h->hits[h->n++] = hit;
	}
	fclose(f);
}

static void cvp_hits_print(const struct cvp_hits *a, const struct cvp_hits *b,
			   const char *name)
{
	unsigned int i, j;

	for (i = 0; i < b->n; i++)
		for (j = 0; j < a->n; j++)
			if (!strcmp(a->name[j], b->name[i]))
				printf("CE_VMM_KPROBE case=%s event=%s hits=%llu diagnostic=internal\n",
				       name, b->name[i], b->hits[i] - a->hits[j]);
}

/*
 * Keeps transparent huge pages out of [p, p + n).  A kernel built without
 * them rejects MADV_NOHUGEPAGE with EINVAL; its anonymous pages are 4 KiB
 * already.  0 or a negative errno.
 */
static int cvp_no_thp(void *p, size_t n)
{
	return madvise(p, n, MADV_NOHUGEPAGE) && errno != EINVAL ? -errno : 0;
}

/*
 * Faults the 4 KiB pages of @pool and @filler alternately, so whichever order
 * the page allocator hands out frames in, two neighbouring pool pages never
 * get consecutive ones from it.  On a freshly booted guest a pool touched in
 * order came out physically contiguous.
 */
static void cvp_scatter(unsigned char *pool, unsigned char *filler, size_t bytes)
{
	volatile unsigned char *p = pool, *f = filler;
	size_t off;

	for (off = 0; off < bytes; off += 4096U) {
		p[off] = 0;
		f[off] = 0;
	}
}

/* Physically adjacent runs of the pinned host bytes [off, off + len). */
static unsigned int cvp_host_runs(const unsigned char *host, size_t off, size_t len)
{
	uint64_t entry[CVP_LARGE_PAYLOAD / 4096U];
	size_t n = len / 4096U;
	off_t at = (off_t)(((uintptr_t)host + off) / 4096U * sizeof(entry[0]));
	ssize_t got;
	int fd;

	if (n > sizeof(entry) / sizeof(entry[0]) || (off | len) % 4096U)
		return 0;
	fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	got = pread(fd, entry, n * sizeof(entry[0]), at);
	close(fd);
	return got == (ssize_t)(n * sizeof(entry[0])) ? cvp_phys_runs(entry, n) : 0;
}

static int cvp_parse(int argc, char **argv, struct cvp_options *o)
{
	static const struct option opts[] = {
		{ "case", required_argument, NULL, 'c' },
		{ "ce-dev", required_argument, NULL, 'd' },
		{ "timeout-ms", required_argument, NULL, 't' },
		{ "kprobe-profile", required_argument, NULL, 'k' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	int ch;

	*o = (struct cvp_options) { .dev = "/dev/nvidia0", .which = CVP_MULTI,
				   .timeout_ms = 5000 };
	while ((ch = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		unsigned int i;

		switch (ch) {
		case 'c':
			for (i = 0; i < sizeof(cvp_names) / sizeof(cvp_names[0]); i++)
				if (!strcmp(optarg, cvp_names[i]))
					break;
			if (i == sizeof(cvp_names) / sizeof(cvp_names[0]))
				return XG_EXIT_USAGE;
			o->which = (enum cvp_case)i;
			break;
		case 'd': o->dev = optarg; break;
		case 'k': o->kprobe_profile = optarg; break;
		case 't':
			if (xg_parse_u64(optarg, 60000, &o->timeout_ms) || !o->timeout_ms)
				return XG_EXIT_USAGE;
			break;
		case 'h': cvp_usage(stdout); return -1;
		default: return XG_EXIT_USAGE;
		}
	}
	if (optind != argc || !*o->dev || es_ce_is_sim(o->dev))
		return XG_EXIT_USAGE;
	return 0;
}

static bool cvp_capability(int ret)
{
	return ret == -ENODEV || ret == -ENOENT || ret == -ENOSYS ||
	       ret == -EOPNOTSUPP || ret == -EPERM || ret == -EACCES;
}

/* After CREATE accepted a session, no error is an unavailable capability. */
static int cvp_exit_code(int ret, bool created)
{
	if (ret >= 0)
		return ret;
	return !created && cvp_capability(ret) ? XG_EXIT_UNAVAILABLE : XG_EXIT_FAIL;
}

static void cvp_pattern(unsigned char *p, size_t bytes, uint64_t seed)
{
	size_t i;

	for (i = 0; i < bytes; i++) {
		uint64_t x = (uint64_t)i + seed;

		x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
		x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
		p[i] = (unsigned char)(x ^ (x >> 31));
	}
}

static void cvp_host_payload(unsigned char *host, const unsigned char *payload,
			     const struct cvp_geom *g)
{
	unsigned int i;

	for (i = 0; i < g->frames; i++)
		memcpy(host + (size_t)(g->first + i) * g->frame + g->head,
		       payload + (size_t)i * g->seg, g->seg);
}

/* No fallback/retry CREATE: a missing report cannot authorize caller cleanup. */
static int cvp_create(struct es_run *r, struct xdev_ext_mech_create *c,
		      bool *released)
{
	struct xdev_ext_mech_create_with_report e = {
		.size = sizeof(e), .version = XDEV_EXT_MECH_CREATE_REPORT_VERSION,
	};
	struct xdev_ext_mech_notify_arm arm;
	int ret;

	c->abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c->eventfd = r->efd;
	e.create = *c;
	*released = false;
	ret = es_mech(r->ring, XDEV_EXT_MECH_OP_CREATE_REPORT, (uintptr_t)&e);
	if (ret)
		return ret;
	if (e.size != sizeof(e) || e.version != XDEV_EXT_MECH_CREATE_REPORT_VERSION ||
	    e.report.size != sizeof(e.report) ||
	    e.report.version != XDEV_EXT_MECH_CREATE_REPORT_VERSION)
		return -EPROTO;
	fprintf(stderr, "CE_VMM_CREATE result=%d phase=%u stage=%u cleanup=%u rollback=%d\n",
		e.report.result, e.report.phase, e.report.failed_stage,
		e.report.cleanup, e.report.rollback_errno);
	if (e.report.result) {
		if (e.report.result > 0 || e.report.session_id || e.create.session_id ||
		    e.report.cleanup > XDEV_EXT_MECH_CREATE_CLEANUP_RETAINED)
			return -EPROTO;
		*released = e.report.cleanup == XDEV_EXT_MECH_CREATE_CLEANUP_RELEASED ||
			(e.report.cleanup == XDEV_EXT_MECH_CREATE_CLEANUP_NONE &&
			 e.report.phase == XDEV_EXT_MECH_CREATE_CHECK);
		return e.report.result;
	}
	if (!e.report.session_id || e.create.session_id != e.report.session_id ||
	    e.report.cleanup != XDEV_EXT_MECH_CREATE_CLEANUP_NONE ||
	    e.report.rollback_errno || e.report.phase)
		return -EPROTO;
	r->session = e.report.session_id;
	ret = xdev_ext_mech_ctl_notify_request(&arm, r->session, 1);
	return ret ? ret : es_mech(r->ring, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
}

static int cvp_stop(struct es_run *r, unsigned int stages, unsigned int frames,
		    bool complete, bool *released)
{
	struct xdev_ext_mech_stop_report report = {
		.size = sizeof(report), .version = XDEV_EXT_MECH_STOP_REPORT_VERSION,
		.session_id = r->session,
	};
	uint64_t session = r->session;
	int ret;

	*released = false;
	ret = es_mech(r->ring, XDEV_EXT_MECH_OP_STOP_REPORT, (uintptr_t)&report);
	/* Never issue a second STOP or treat ENOENT as evidence of release. */
	r->session = 0;
	fprintf(stderr, "CE_VMM_STOP_REPORT result=%d\n", ret);
	if (ret)
		return ret;
	if (report.size != sizeof(report) ||
	    report.version != XDEV_EXT_MECH_STOP_REPORT_VERSION ||
	    report.session_id != session || report.stats.session_id != session ||
	    report.stats.state != XDEV_EXT_MECH_SESSION_STOPPED ||
	    report.stats.inflight || report.stats.sequestered)
		return -EPROTO;
	*released = true;
	es_print_stats(&report.stats);
	return complete ? cvp_check_stop(&report, session, stages, frames) : 0;
}

/* First attach is real; the second ioctl must reach and be refused by NVIDIA. */
static int cvp_partial_attach(const char *dev, int fd_before)
{
	struct es_ce ce = { .fd = { -1, -1 }, .sim = true };
	struct xdev_ext_nv_ce_attach_memory attach;
	int ret, bad, saved;

	ret = es_ce_open(&ce, dev, 1, ES_CE_VMM, 0, CVP_BYTES);
	if (ret)
		goto out;
	ce.fd[1] = open(dev, O_RDWR | O_CLOEXEC);
	if (ce.fd[1] < 0) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	bad = fcntl(ce.cuda.export_fd, F_DUPFD_CLOEXEC, 0);
	if (bad < 0) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	if (close(bad)) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	/* A negative fd is rejected by the user helper without an ioctl. */
	attach = (struct xdev_ext_nv_ce_attach_memory) {
		.mem_fd = bad, .gpu_va = ce.cuda.va, .size = ce.cuda.vmm_bytes,
		.status = UINT32_MAX,
	};
	ret = xdev_ext_nv_ce_attach_memory(ce.fd[1], &attach);
	saved = errno;
	if (ret != -1 || saved != EIO || !attach.status || attach.status == UINT32_MAX) {
		fprintf(stderr, "partial attach did not produce native rejection: ret=%d errno=%d status=0x%x\n",
			ret, saved, attach.status);
		ret = XG_EXIT_FAIL;
	} else {
		fprintf(stderr, "CE_VMM_PARTIAL_ATTACH=REJECTED native_status=0x%x create=0 start=0\n",
			attach.status);
		ret = XG_EXIT_PASS;
	}
out:
	if (es_ce_close(&ce))
		ret = XG_EXIT_FAIL;
	if (eval_fd_check(fd_before))
		ret = XG_EXIT_FAIL;
	return ret;
}

static int cvp_run(const struct cvp_options *o)
{
	const bool large = cvp_is_large(o->which), huge = o->which == CVP_LARGE_HUGE;
	const struct cvp_geom *g = large ? &cvp_large : &cvp_small;
	struct es_ce ce = { .fd = { -1, -1 }, .sim = true };
	struct es_run r = { .ring = -1, .efd = -1 };
	struct io_uring_xdev_ext_umem_reg reg = { .frame_size = g->frame,
						.size = g->host_bytes };
	struct xdev_ext_mech_create c = {
		.nr_stages = o->which <= CVP_D2H ? 1 : 2,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1, .depth = 1,
		.layout = { .frame_size = g->frame, .hdr_room = g->head,
			    .seg_len = g->seg, .group_bytes = (__u32)g->payload },
	};
	struct xdev_ext_mech_stats stats;
	struct cvp_hits before, after;
	unsigned char *payload = NULL, *expected_host = NULL;
	unsigned char *host = MAP_FAILED, *filler = MAP_FAILED, *gpu = NULL, *expected_gpu = NULL;
	__u32 frames[CVP_LARGE_FRAMES];
	const char *phase = "allocation/attach";
	bool released = true, complete = false, created = false;
	size_t mapped_bytes = 0;
	uint64_t now, deadline;
	int ret, stopped;
	unsigned int i;

	for (i = 0; i < g->frames; i++)
		frames[i] = g->first + i;
	ret = es_ce_open(&ce, o->dev, c.nr_stages, ES_CE_VMM, 0, g->bytes);
	if (ret)
		goto out;
	if (!ce.cuda.vmm || !ce.cuda.exported || !ce.cuda.mapped ||
	    ce.cuda.vmm_bytes < g->bytes || ce.cuda.vmm_bytes > SIZE_MAX) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	/* Oracle covers allocation rounding slack as well as payload/guards. */
	mapped_bytes = (size_t)ce.cuda.vmm_bytes;
	ce.len = ce.cuda.vmm_bytes;
	gpu = malloc(mapped_bytes);
	expected_gpu = malloc(mapped_bytes);
	payload = malloc(g->payload);
	expected_host = malloc(g->host_bytes);
	/* large-4k: no transparent huge pages, so the frames stay 4 KiB pages. */
	host = mmap(NULL, g->host_bytes, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS |
		    (huge ? MAP_HUGETLB | MAP_POPULATE : large ? 0 : MAP_POPULATE), -1, 0);
	if (host == MAP_FAILED && huge) {
		fprintf(stderr, "SKIP: hugetlb host pool of %zu bytes: %s (reserve vm.nr_hugepages)\n",
			g->host_bytes, strerror(errno));
		ret = XG_EXIT_UNAVAILABLE;
		goto out;
	}
	if (host != MAP_FAILED && large && !huge) {
		filler = mmap(NULL, g->host_bytes, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (filler == MAP_FAILED) {
			ret = XG_EXIT_FAIL;
			goto out;
		}
		ret = cvp_no_thp(host, g->host_bytes);
		if (!ret)
			ret = cvp_no_thp(filler, g->host_bytes);
		if (ret)
			goto out;
		cvp_scatter(host, filler, g->host_bytes);
	}
	if (!gpu || !expected_gpu || !payload || !expected_host || host == MAP_FAILED) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	cvp_pattern(payload, g->payload, UINT64_C(0x123456789));
	memset(host, 0x6b, g->host_bytes);
	memset(gpu, 0xa7, mapped_bytes);
	if (o->which == CVP_H2D)
		cvp_host_payload(host, payload, g);
	else
		memcpy(gpu + g->a, payload, g->payload);
	memcpy(expected_host, host, g->host_bytes);
	if (o->which != CVP_H2D)
		cvp_host_payload(expected_host, payload, g);
	memcpy(expected_gpu, gpu, mapped_bytes);
	if (o->which != CVP_D2H)
		memcpy(expected_gpu + g->b, payload, g->payload);
	phase = "CUDA seed";
	ret = es_ce_access(&ce, true, 0, gpu, mapped_bytes);
	if (ret)
		goto out;
	/* Readback must overwrite independent poison, never the expected buffer. */
	memset(gpu, 0x3c, mapped_bytes);
	if (o->which == CVP_CLOSE_EXPORT) {
		int fd = ce.cuda.export_fd;

		ret = close(fd);
		ce.cuda.exported = 0;
		ce.cuda.export_fd = -1;
		if (ret) {
			ret = -errno;
			goto out;
		}
		fprintf(stderr, "CE_VMM_USER_EXPORT=CLOSED before_create=1 dma_release_proven=0\n");
	}
	phase = "ring/UMEM";
	ret = es_ring_open(&r);
	reg.addr = (uintptr_t)host;
	if (!ret)
		ret = es_register(r.ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg);
	if (ret)
		goto out;
	if (large) {
		/* Pinned by the registration, so the frame numbers stay put. */
		unsigned int runs = cvp_host_runs(host, (size_t)g->first * g->frame, g->payload);
		char shown[16] = "unknown";

		if (runs)
			snprintf(shown, sizeof(shown), "%u", runs);
		printf("CE_VMM_HOST_LAYOUT case=%s backing=%s frames=%u-%u frame_bytes=%u "
		       "group_bytes=%zu host_pages=%zu host_runs=%s diagnostic=internal\n",
		       cvp_names[o->which], huge ? "huge2m" : "4k", g->first,
		       g->first + g->frames - 1, g->frame, g->payload, g->payload / 4096U, shown);
	}
	for (i = 0; i < c.nr_stages; i++) {
		bool h2d = o->which == CVP_H2D || i == 1;

		c.st[i] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_CE,
			.direction = h2d ? XDEV_EXT_MECH_DIR_TO_DEVICE :
					   XDEV_EXT_MECH_DIR_FROM_DEVICE,
			.fd = ce.fd[i], .arg0 = ce.va + (h2d ? g->b : g->a),
			.arg1 = g->payload,
		};
	}
	phase = "CREATE/NOTIFY_ARM";
	ret = cvp_create(&r, &c, &released);
	if (ret)
		goto out;
	created = true;
	now = es_now_ns();
	if (!now) {
		ret = -EIO;
		goto out;
	}
	deadline = now + o->timeout_ms * UINT64_C(1000000);
	phase = "START/eventfd/STATS";
	cvp_hits_read(o->kprobe_profile, &before);
	ret = es_start(&r, 1, frames, g->frames);
	if (!ret)
		ret = es_wait_terminal(&r, deadline);
	cvp_hits_read(o->kprobe_profile, &after);
	if (!ret)
		cvp_hits_print(&before, &after, cvp_names[o->which]);
	if (!ret)
		ret = es_settle(&r, 1, deadline, &stats);
	if (!ret) {
		es_print_stats(&stats);
		ret = cvp_check_stats(&stats, r.session, c.nr_stages,
				      XDEV_EXT_MECH_SESSION_ACTIVE, g->frames);
	}
	complete = !ret;
out:
	if (r.session) {
		stopped = cvp_stop(&r, c.nr_stages, g->frames, complete, &released);
		if (stopped) {
			ret = stopped;
			phase = "STOP_REPORT";
		}
	}
	/* es_close now only closes ring/eventfd; STOP_REPORT owns final release. */
	es_close(&r);
	if (!released) {
		fprintf(stderr, "CE_VMM_ACCEPTANCE=FAIL phase=%s error=%d release=unproven "
			"explicit_cuda_cleanup=withheld; fd-close is not DMA quiescence\n", phase, ret);
		/* Do not read/reuse host pages or explicitly destroy CUDA resources. */
		fflush(stderr);
		_exit(XG_EXIT_FAIL);
	}
	if (!ret && complete) {
		phase = "full-allocation/host oracle";
		ret = es_ce_access(&ce, false, 0, gpu, mapped_bytes);
		if (!ret)
			ret = cvp_check_memory(host, expected_host, g->host_bytes,
					       gpu, expected_gpu, mapped_bytes);
	}
	if (ret)
		fprintf(stderr, "CE_VMM_ACCEPTANCE=FAIL phase=%s error=%d\n", phase, ret);
	if (es_ce_close(&ce))
		ret = XG_EXIT_FAIL;
	if (host != MAP_FAILED && munmap(host, g->host_bytes))
		ret = XG_EXIT_FAIL;
	if (filler != MAP_FAILED && munmap(filler, g->host_bytes))
		ret = XG_EXIT_FAIL;
	free(gpu);
	free(expected_gpu);
	free(payload);
	free(expected_host);
	return cvp_exit_code(ret, created);
}

int main(int argc, char **argv)
{
	struct cvp_options o;
	int ret, fd_before;

	(void)endpoint_timer; /* eval include prerequisite; no timer starts. */
	ret = cvp_parse(argc, argv, &o);
	if (ret == -1)
		return XG_EXIT_PASS;
	if (ret) {
		cvp_usage(stderr);
		return ret;
	}
	ret = es_ce_runtime_begin(o.dev, &fd_before);
	if (ret)
		return ret;
	if (o.which == CVP_PARTIAL) {
		ret = cvp_partial_attach(o.dev, fd_before);
		if (ret)
			return ret;
		/* A fresh real multi-stage transfer must succeed after the refusal. */
	}
	ret = cvp_run(&o);
	if (eval_fd_check(fd_before))
		ret = XG_EXIT_FAIL;
	if (ret)
		return ret;
	printf("CE_VMM_ACCEPTANCE=PASS case=%s stages=%u batches=1 payload_bytes=%zu%s "
	       "data=verified guards=verified completion=exact stop_report=verified "
	       "execution=physical-gpu-ce performance_claim=none\n",
	       cvp_names[o.which], o.which <= CVP_D2H ? 1U : 2U,
	       cvp_is_large(o.which) ? cvp_large.payload : cvp_small.payload,
	       o.which == CVP_LARGE_HUGE ? " frames=32 host=huge2m" :
	       o.which == CVP_LARGE_4K ? " frames=32 host=4k" : "");
	return fflush(stdout) ? XG_EXIT_FAIL : XG_EXIT_PASS;
}
