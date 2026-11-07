// SPDX-License-Identifier: GPL-2.0
/*
 * Unmeasured VMM -> real CE session acceptance. CUDA copies only seed/read the
 * oracle; the tested transfers use START and the kernel's CE backend.
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

enum cvp_case { CVP_H2D, CVP_D2H, CVP_MULTI, CVP_CLOSE_EXPORT, CVP_PARTIAL };
static const char *const cvp_names[] = {
	"single-h2d", "single-d2h", "multi", "close-export", "partial-attach"
};

struct cvp_options {
	const char *dev;
	enum cvp_case which;
	uint64_t timeout_ms;
};

static void cvp_usage(FILE *f)
{
	fprintf(f, "usage: ce_vmm_probe [--ce-dev /dev/nvidiaN] [--timeout-ms 5000]\n"
		"       [--case single-h2d|single-d2h|multi|close-export|partial-attach]\n"
		"Default: multi. Real CE session correctness only; no timing or performance result.\n");
}

static int cvp_parse(int argc, char **argv, struct cvp_options *o)
{
	static const struct option opts[] = {
		{ "case", required_argument, NULL, 'c' },
		{ "ce-dev", required_argument, NULL, 'd' },
		{ "timeout-ms", required_argument, NULL, 't' },
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

static void cvp_host_payload(unsigned char *host, const unsigned char *payload)
{
	unsigned int i;

	for (i = 0; i < CVP_FRAMES; i++)
		memcpy(host + (i + 1) * CVP_FRAME + CVP_HEAD,
		       payload + i * CVP_SEG, CVP_SEG);
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

static int cvp_stop(struct es_run *r, unsigned int stages, bool complete, bool *released)
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
	return complete ? cvp_check_stop(&report, session, stages) : 0;
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
	struct es_ce ce = { .fd = { -1, -1 }, .sim = true };
	struct es_run r = { .ring = -1, .efd = -1 };
	struct io_uring_xdev_ext_umem_reg reg = { .frame_size = CVP_FRAME,
						.size = CVP_HOST_BYTES };
	struct xdev_ext_mech_create c = {
		.nr_stages = o->which <= CVP_D2H ? 1 : 2,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .pool_fd = -1, .depth = 1,
		.layout = { .frame_size = CVP_FRAME, .hdr_room = CVP_HEAD,
			    .seg_len = CVP_SEG, .group_bytes = CVP_PAYLOAD },
	};
	struct xdev_ext_mech_stats stats;
	unsigned char payload[CVP_PAYLOAD], expected_host[CVP_HOST_BYTES];
	unsigned char *host = MAP_FAILED, *gpu = NULL, *expected_gpu = NULL;
	const __u32 frames[CVP_FRAMES] = { 1, 2 };
	const char *phase = "allocation/attach";
	bool released = true, complete = false, created = false;
	size_t mapped_bytes = 0;
	uint64_t now, deadline;
	int ret, stopped;
	unsigned int i;

	ret = es_ce_open(&ce, o->dev, c.nr_stages, ES_CE_VMM, 0, CVP_BYTES);
	if (ret)
		goto out;
	if (!ce.cuda.vmm || !ce.cuda.exported || !ce.cuda.mapped ||
	    ce.cuda.vmm_bytes < CVP_BYTES || ce.cuda.vmm_bytes > SIZE_MAX) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	/* Oracle covers allocation rounding slack as well as payload/guards. */
	mapped_bytes = (size_t)ce.cuda.vmm_bytes;
	ce.len = ce.cuda.vmm_bytes;
	gpu = malloc(mapped_bytes);
	expected_gpu = malloc(mapped_bytes);
	host = mmap(NULL, CVP_HOST_BYTES, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (!gpu || !expected_gpu || host == MAP_FAILED) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	cvp_pattern(payload, sizeof(payload), UINT64_C(0x123456789));
	memset(host, 0x6b, CVP_HOST_BYTES);
	memset(gpu, 0xa7, mapped_bytes);
	if (o->which == CVP_H2D)
		cvp_host_payload(host, payload);
	else
		memcpy(gpu + CVP_A, payload, sizeof(payload));
	memcpy(expected_host, host, sizeof(expected_host));
	if (o->which != CVP_H2D)
		cvp_host_payload(expected_host, payload);
	memcpy(expected_gpu, gpu, mapped_bytes);
	if (o->which != CVP_D2H)
		memcpy(expected_gpu + CVP_B, payload, sizeof(payload));
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
	for (i = 0; i < c.nr_stages; i++) {
		bool h2d = o->which == CVP_H2D || i == 1;

		c.st[i] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_CE,
			.direction = h2d ? XDEV_EXT_MECH_DIR_TO_DEVICE :
					   XDEV_EXT_MECH_DIR_FROM_DEVICE,
			.fd = ce.fd[i], .arg0 = ce.va + (h2d ? CVP_B : CVP_A),
			.arg1 = CVP_PAYLOAD,
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
	ret = es_start(&r, 1, frames, CVP_FRAMES);
	if (!ret)
		ret = es_wait_terminal(&r, deadline);
	if (!ret)
		ret = es_settle(&r, 1, deadline, &stats);
	if (!ret) {
		es_print_stats(&stats);
		ret = cvp_check_stats(&stats, r.session, c.nr_stages,
				      XDEV_EXT_MECH_SESSION_ACTIVE);
	}
	complete = !ret;
out:
	if (r.session) {
		stopped = cvp_stop(&r, c.nr_stages, complete, &released);
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
			ret = cvp_check_memory(host, expected_host, CVP_HOST_BYTES,
					       gpu, expected_gpu, mapped_bytes);
	}
	if (ret)
		fprintf(stderr, "CE_VMM_ACCEPTANCE=FAIL phase=%s error=%d\n", phase, ret);
	if (es_ce_close(&ce))
		ret = XG_EXIT_FAIL;
	if (host != MAP_FAILED && munmap(host, CVP_HOST_BYTES))
		ret = XG_EXIT_FAIL;
	free(gpu);
	free(expected_gpu);
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
	printf("CE_VMM_ACCEPTANCE=PASS case=%s stages=%u batches=1 payload_bytes=%u "
	       "data=verified guards=verified completion=exact stop_report=verified "
	       "execution=physical-gpu-ce performance_claim=none\n",
	       cvp_names[o.which], o.which <= CVP_D2H ? 1U : 2U, CVP_PAYLOAD);
	return fflush(stdout) ? XG_EXIT_FAIL : XG_EXIT_PASS;
}
