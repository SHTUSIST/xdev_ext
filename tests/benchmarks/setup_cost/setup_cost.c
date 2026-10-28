// SPDX-License-Identifier: GPL-2.0
/*
 * setup_cost - one-time setup costs of the session path and its baselines.
 *
 *   setup_cost [--sizes 1M,64M,1G] [--reps N] [--frame-size N]
 *              [--measure umem,mech,xdp,iou,cuda,cufile]
 *              [--nvme-ng /dev/ngXnY --nvme-window SLBA:NLB] [--cuda-device N]
 *              [--bpf-obj F.bpf.o ...] [--counts-only]
 *   setup_cost --prog-stats [--prog-prefix NAME] -- WORKLOAD ARGV...
 *
 * For every region size each measure maps and populates a fresh anonymous
 * region (populate time is reported apart), then times registration and
 * release, --reps times:
 *   umem    IORING_REGISTER_XDEV_EXT_UMEM / IORING_UNREGISTER_XDEV_EXT_UMEM
 *   mech    session CREATE / STOP of a one-stage NVMe READ session over that
 *           UMEM; the stage binding includes the device's DMA mapping
 *           (needs --nvme-ng, --nvme-window and an attached NVMe plan)
 *   xdp     AF_XDP XDP_UMEM_REG / close of the socket
 *   iou     IORING_REGISTER_BUFFERS / IORING_UNREGISTER_BUFFERS (1 GiB iovecs)
 *   cuda    cudaHostRegister / cudaHostUnregister
 *   cufile  cuFileBufRegister / cuFileBufDeregister of a cudaMalloc buffer
 * cuda and cufile exist only when built with SETUP_COST_HAVE_CUDA.  A kernel
 * or device refusal (for example a size above a registration cap) is
 * recorded with its errno; nothing is retried at another size.  A size that
 * would leave less than --mem-margin (default max(4 GiB, MemAvailable/8)) of
 * MemAvailable is recorded as host_refused before any mmap, and with
 * --umem-cap the umem and mech measures above that cap are recorded as
 * not_run_above_cap without populating the region.
 *
 * Each --bpf-obj is opened and loaded with libbpf; every program's
 * bpf_prog_info gives verified_insns, translated instructions and JIT bytes,
 * and (libbpf >= 1.0) the BPF_LOG_STATS log gives the verification time.
 * --counts-only reports only these deterministic instruction counts and
 * runs no timed step, so it may run in a virtual machine; every timed mode
 * refuses a hypervisor with exit 4.
 *
 * --prog-stats enables BPF run-time statistics (BPF_ENABLE_STATS), runs the
 * workload and reports, per struct_ops program, the run count and run time
 * accumulated meanwhile: BPF time per operation including the statistics
 * overhead.  Keep the plan attached across the workload.
 *
 * Output is one JSON document on stdout.  Exit status: 0 at least one
 * result, 1 a failure (release or info query failed, workload failed),
 * 2 usage error, 4 not run (hypervisor, nothing measurable).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>

#include "../../../kernel/include/uapi/linux/io_uring.h"
#include "../../../kernel/include/uapi/linux/xdev_ext_mech.h"

#ifdef SETUP_COST_HAVE_CUDA
#include <cuda_runtime_api.h>
#include <cufile.h>
#endif

#include "setup_cost_core.h"

#ifndef AF_XDP
#define AF_XDP			44
#endif
#ifndef SOL_XDP
#define SOL_XDP			283
#endif

enum { SC_OK = 0, SC_FAIL = 1, SC_USAGE = 2, SC_NOT_RUN = 4 };
enum { M_UMEM, M_MECH, M_XDP, M_IOU, M_CUDA, M_CUFILE, M_NR };

#define SC_MAX_OBJS		32
#define SC_MAX_PROGS		1024
#define SC_LOG_SIZE		(64 * 1024)
#define SC_MECH_MAX_DEPTH	64	/* XDEV_EXT_MECH_MAX_DEPTH */
#define SC_MAX_IOV		128

static const char *const sc_names[M_NR] = {
	"umem", "mech", "xdp", "iou", "cuda", "cufile",
};

struct sc_opts {
	uint64_t sizes[SC_MAX_SIZES];
	int nr_sizes;
	unsigned int reps;
	uint32_t frame_size;
	bool measure[M_NR];
	const char *nvme_ng;
	uint64_t slba, nlb;
	int cuda_device;
	const char *objs[SC_MAX_OBJS];
	int nr_objs;
	bool counts_only, prog_stats;
	uint64_t umem_cap, mem_margin;	/* 0: no cap / default margin */
	const char *prog_prefix;
	char **cmd;
};

/* Why one repetition stopped: the step, and an errno or device error code. */
struct sc_err {
	const char *step;
	const char *kind;	/* kernel_refused, host_refused, device_refused, failed */
	int code;
	char text[160];
};

static int results_ok, failures;

static uint64_t sc_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sc_errno(struct sc_err *e, const char *kind, const char *step, int err)
{
	e->kind = kind;
	e->step = step;
	e->code = err;
	snprintf(e->text, sizeof(e->text), "%s", strerror(err));
}

static void sc_jstr(const char *key, const char *value, bool comma)
{
	char buf[1024];

	if (sc_json_escape(value ? value : "", buf, sizeof(buf)))
		strcpy(buf, "(unprintable)");
	printf("\"%s\":\"%s\"%s", key, buf, comma ? "," : "");
}

static void sc_jsummary(const char *key, const uint64_t *ns, unsigned int n)
{
	struct sc_summary s;

	if (sc_summarize(ns, n, &s)) {
		printf(",\"%s\":null", key);
		return;
	}
	printf(",\"%s\":{\"n\":%u,\"min\":%llu,\"median\":%llu,\"max\":%llu}", key, s.n,
	       (unsigned long long)s.min, (unsigned long long)s.median,
	       (unsigned long long)s.max);
}

static int sc_read_file(const char *path, char **out)
{
	size_t cap = 65536, len = 0;
	char *buf = malloc(cap);
	ssize_t r;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0 || !buf) {
		free(buf);
		if (fd >= 0)
			close(fd);
		return -1;
	}
	while ((r = read(fd, buf + len, cap - len - 1)) > 0) {
		len += (size_t)r;
		if (len + 1 == cap) {
			char *n = realloc(buf, cap * 2);

			if (!n)
				break;
			buf = n;
			cap *= 2;
		}
	}
	close(fd);
	buf[len] = '\0';
	*out = buf;
	return 0;
}

/* SETUP_COST_HOST_ROOT prefixes the /proc and /sys paths; the host tests use it. */
static bool sc_hypervisor(void)
{
	const char *root = getenv("SETUP_COST_HOST_ROOT");
	char path[4096], *cpuinfo = NULL;
	bool hv;

	snprintf(path, sizeof(path), "%s/sys/hypervisor/type", root ? root : "");
	hv = access(path, F_OK) == 0;
	snprintf(path, sizeof(path), "%s/proc/cpuinfo", root ? root : "");
	if (!hv && !sc_read_file(path, &cpuinfo))
		hv = sc_cpuinfo_hypervisor(cpuinfo);
	free(cpuinfo);
	return hv;
}

static int sc_mem_available(uint64_t *bytes)
{
	const char *root = getenv("SETUP_COST_HOST_ROOT");
	char path[4096], *meminfo = NULL;
	int ret;

	snprintf(path, sizeof(path), "%s/proc/meminfo", root ? root : "");
	if (sc_read_file(path, &meminfo))
		return -ENOENT;
	ret = sc_meminfo_available(meminfo, bytes);
	free(meminfo);
	return ret;
}

/* --- registration measures ------------------------------------------ */

static int sc_ring(void)
{
	struct io_uring_params p;
	int fd;

	memset(&p, 0, sizeof(p));
	fd = (int)syscall(__NR_io_uring_setup, 8, &p);
	return fd < 0 ? -errno : fd;
}

static int sc_register(int ring, unsigned int op, void *arg, unsigned int nr)
{
	int ret = (int)syscall(__NR_io_uring_register, ring, op, arg, nr);

	return ret < 0 ? -errno : ret;
}

static int sc_umem_reg(int ring, void *region, uint64_t size, uint32_t frame)
{
	struct io_uring_xdev_ext_umem_reg reg = {
		.addr = (uintptr_t)region, .size = size, .frame_size = frame,
	};

	return sc_register(ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1);
}

static int sc_measure_umem(const struct sc_opts *o, void *region, uint64_t size,
			   uint64_t *reg, uint64_t *unreg, struct sc_err *e)
{
	uint64_t t0;
	int ring = sc_ring(), ret;

	if (ring < 0) {
		sc_errno(e, "kernel_refused", "io_uring_setup", -ring);
		return -1;
	}
	t0 = sc_now();
	ret = sc_umem_reg(ring, region, size, o->frame_size);
	*reg = sc_now() - t0;
	if (ret) {
		sc_errno(e, "kernel_refused", "register", -ret);
		close(ring);
		return -1;
	}
	t0 = sc_now();
	ret = sc_register(ring, IORING_UNREGISTER_XDEV_EXT_UMEM, NULL, 0);
	*unreg = sc_now() - t0;
	close(ring);
	if (ret) {
		sc_errno(e, "failed", "unregister", -ret);
		return -1;
	}
	return 0;
}

static int sc_mech_op(int ring, uint32_t op, uint64_t arg)
{
	struct io_uring_xdev_ext_mech req = { .op = op, .arg = arg };

	return sc_register(ring, IORING_REGISTER_XDEV_EXT_MECH, &req, 1);
}

static int sc_measure_mech(const struct sc_opts *o, void *region, uint64_t size,
			   uint64_t *reg, uint64_t *unreg, struct sc_err *e)
{
	struct xdev_ext_mech_create c;
	uint64_t frames = size / o->frame_size, t0;
	int ring, ng, ret;

	ng = open(o->nvme_ng, O_RDWR | O_CLOEXEC);
	if (ng < 0) {
		sc_errno(e, "host_refused", "open_nvme_ng", errno);
		return -1;
	}
	ring = sc_ring();
	if (ring < 0) {
		sc_errno(e, "kernel_refused", "io_uring_setup", -ring);
		close(ng);
		return -1;
	}
	ret = sc_umem_reg(ring, region, size, o->frame_size);
	if (ret) {
		sc_errno(e, "kernel_refused", "umem_register", -ret);
		goto out;
	}
	memset(&c, 0, sizeof(c));
	c.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	c.nr_stages = 1;
	c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	c.pool_fd = -1;
	c.layout.frame_size = o->frame_size;
	c.layout.seg_len = o->frame_size;
	c.layout.group_bytes = o->frame_size;
	c.depth = (uint32_t)(frames < SC_MECH_MAX_DEPTH ? frames : SC_MECH_MAX_DEPTH);
	c.eventfd = -1;
	c.st[0].class_id = XDEV_EXT_MECH_CLASS_NVME;
	c.st[0].direction = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	c.st[0].fd = ng;
	c.st[0].arg0 = o->slba;
	c.st[0].arg1 = o->nlb;
	t0 = sc_now();
	ret = sc_mech_op(ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&c);
	*reg = sc_now() - t0;
	if (ret) {
		sc_errno(e, "kernel_refused", "create", -ret);
		goto out;
	}
	t0 = sc_now();
	ret = sc_mech_op(ring, XDEV_EXT_MECH_OP_STOP, c.session_id);
	*unreg = sc_now() - t0;
	if (ret)
		sc_errno(e, "failed", "stop", -ret);
out:
	close(ring);	/* releases the session's ring reference and the UMEM */
	close(ng);
	return ret ? -1 : 0;
}

static int sc_measure_xdp(const struct sc_opts *o, void *region, uint64_t size,
			  uint64_t *reg, uint64_t *unreg, struct sc_err *e)
{
	struct xdp_umem_reg r = {
		.addr = (uintptr_t)region, .len = size, .chunk_size = o->frame_size,
	};
	uint64_t t0;
	int fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0), ret;

	if (fd < 0) {
		sc_errno(e, "kernel_refused", "socket", errno);
		return -1;
	}
	t0 = sc_now();
	ret = setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &r, sizeof(r));
	*reg = sc_now() - t0;
	if (ret) {
		sc_errno(e, "kernel_refused", "register", errno);
		close(fd);
		return -1;
	}
	/* The UMEM is released with the socket; the kernel may defer the unpin. */
	t0 = sc_now();
	ret = close(fd);
	*unreg = sc_now() - t0;
	if (ret) {
		sc_errno(e, "failed", "close", errno);
		return -1;
	}
	return 0;
}

static int sc_measure_iou(const struct sc_opts *o, void *region, uint64_t size,
			  uint64_t *reg, uint64_t *unreg, struct sc_err *e)
{
	struct iovec iov[SC_MAX_IOV];
	uint64_t t0;
	int n, ring, ret;

	(void)o;
	n = sc_split_iovecs(region, size, SC_IOVEC_MAX, iov, SC_MAX_IOV);
	if (n < 0) {
		sc_errno(e, "host_refused", "iovecs", -n);
		return -1;
	}
	ring = sc_ring();
	if (ring < 0) {
		sc_errno(e, "kernel_refused", "io_uring_setup", -ring);
		return -1;
	}
	t0 = sc_now();
	ret = sc_register(ring, IORING_REGISTER_BUFFERS, iov, (unsigned int)n);
	*reg = sc_now() - t0;
	if (ret) {
		sc_errno(e, "kernel_refused", "register", -ret);
		close(ring);
		return -1;
	}
	t0 = sc_now();
	ret = sc_register(ring, IORING_UNREGISTER_BUFFERS, NULL, 0);
	*unreg = sc_now() - t0;
	close(ring);
	if (ret) {
		sc_errno(e, "failed", "unregister", -ret);
		return -1;
	}
	return 0;
}

#ifdef SETUP_COST_HAVE_CUDA
static void sc_cuda_err(struct sc_err *e, const char *step, cudaError_t err)
{
	e->kind = "device_refused";
	e->step = step;
	e->code = (int)err;
	snprintf(e->text, sizeof(e->text), "%s", cudaGetErrorString(err));
}

static int sc_measure_cuda(const struct sc_opts *o, void *region, uint64_t size,
			   uint64_t *reg, uint64_t *unreg, struct sc_err *e)
{
	uint64_t t0;
	cudaError_t err;

	(void)o;
	t0 = sc_now();
	err = cudaHostRegister(region, (size_t)size, cudaHostRegisterDefault);
	*reg = sc_now() - t0;
	if (err) {
		sc_cuda_err(e, "register", err);
		return -1;
	}
	t0 = sc_now();
	err = cudaHostUnregister(region);
	*unreg = sc_now() - t0;
	if (err) {
		sc_cuda_err(e, "unregister", err);
		e->kind = "failed";
		return -1;
	}
	return 0;
}

static int sc_measure_cufile(const struct sc_opts *o, void *region, uint64_t size,
			     uint64_t *reg, uint64_t *unreg, struct sc_err *e)
{
	CUfileError_t ferr;
	cudaError_t err;
	void *gpu = NULL;
	uint64_t t0;
	int ret = -1;

	(void)o;
	(void)region;
	err = cudaMalloc(&gpu, (size_t)size);
	if (err) {
		sc_cuda_err(e, "cuda_malloc", err);
		return -1;
	}
	t0 = sc_now();
	ferr = cuFileBufRegister(gpu, (size_t)size, 0);
	*reg = sc_now() - t0;
	if (ferr.err != CU_FILE_SUCCESS) {
		e->kind = "device_refused";
		e->step = "register";
		e->code = (int)ferr.err;
		snprintf(e->text, sizeof(e->text), "cuFile error %d", (int)ferr.err);
		goto out;
	}
	t0 = sc_now();
	ferr = cuFileBufDeregister(gpu);
	*unreg = sc_now() - t0;
	if (ferr.err != CU_FILE_SUCCESS) {
		e->kind = "failed";
		e->step = "deregister";
		e->code = (int)ferr.err;
		snprintf(e->text, sizeof(e->text), "cuFile error %d", (int)ferr.err);
		goto out;
	}
	ret = 0;
out:
	cudaFree(gpu);
	return ret;
}

/* CUDA context and cuFile driver are opened once, outside every timing. */
static const char *sc_cuda_prepare(const struct sc_opts *o)
{
	static char why[160];
	cudaError_t err = cudaSetDevice(o->cuda_device);

	if (!err)
		err = cudaFree(NULL);
	if (err) {
		snprintf(why, sizeof(why), "CUDA device %d unavailable: %s", o->cuda_device,
			 cudaGetErrorString(err));
		return why;
	}
	if (o->measure[M_CUFILE] && cuFileDriverOpen().err != CU_FILE_SUCCESS)
		return "cuFile driver unavailable";
	return NULL;
}
#endif

typedef int (*sc_measure_fn)(const struct sc_opts *, void *, uint64_t, uint64_t *,
			     uint64_t *, struct sc_err *);

static const sc_measure_fn sc_fns[M_NR] = {
	sc_measure_umem, sc_measure_mech, sc_measure_xdp, sc_measure_iou,
#ifdef SETUP_COST_HAVE_CUDA
	sc_measure_cuda, sc_measure_cufile,
#else
	NULL, NULL,
#endif
};

static void sc_result_head(int m, uint64_t size, bool *first)
{
	printf("%s{\"measure\":\"%s\",\"size\":%llu,", *first ? "" : ",", sc_names[m],
	       (unsigned long long)size);
	*first = false;
}

static void sc_not_run(int m, uint64_t size, const char *why, bool *first)
{
	sc_result_head(m, size, first);
	sc_jstr("status", "not_run_capability", true);
	sc_jstr("reason", why, false);
	printf("}");
}

/*
 * Every repetition populates the whole region, so a size that would leave
 * less than the margin of MemAvailable is refused before any mmap: on a
 * shared host the sweep must not push other jobs into reclaim or OOM.
 */
static bool sc_host_memory_ok(const struct sc_opts *o, uint64_t size, bool *first, int m)
{
	uint64_t avail = 0, margin;
	int ret = sc_mem_available(&avail);

	margin = sc_mem_margin(avail, o->mem_margin);
	if (!ret && sc_host_fits(size, avail, margin))
		return true;
	sc_result_head(m, size, first);
	sc_jstr("status", "host_refused", true);
	sc_jstr("step", "mem_available", true);
	printf("\"code\":%d,", ENOMEM);
	sc_jstr("error", ret ? "MemAvailable unreadable in /proc/meminfo" :
		"region does not fit MemAvailable minus the margin; not populated", false);
	if (!ret)
		printf(",\"mem_available\":%llu,\"mem_margin\":%llu",
		       (unsigned long long)avail, (unsigned long long)margin);
	printf(",\"completed_reps\":0}");
	return false;
}

/* Above --umem-cap: the UMEM registration cap the caller read from the kernel. */
static void sc_skip_cap(int m, uint64_t size, bool *first)
{
	sc_result_head(m, size, first);
	sc_jstr("status", "not_run_above_cap", true);
	sc_jstr("reason", "size above --umem-cap; not populated or registered", false);
	printf("}");
}

static void sc_run_measure(const struct sc_opts *o, int m, uint64_t size, bool *first)
{
	uint64_t pop[SC_MAX_REPS], reg[SC_MAX_REPS], unreg[SC_MAX_REPS];
	struct sc_err e = { 0 };
	unsigned int r, done = 0;
	bool host = m != M_CUFILE;

	if (host && !sc_host_memory_ok(o, size, first, m))
		return;
	for (r = 0; r < o->reps; r++) {
		void *region = NULL;
		uint64_t t0 = sc_now();
		int ret;

		if (host) {
			region = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE,
				      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
			if (region == MAP_FAILED) {
				sc_errno(&e, "host_refused", "mmap_populate", errno);
				break;
			}
		}
		pop[r] = sc_now() - t0;
		ret = sc_fns[m](o, region, size, &reg[r], &unreg[r], &e);
		if (region)
			munmap(region, (size_t)size);
		if (ret)
			break;
		done++;
	}
	sc_result_head(m, size, first);
	if (done == o->reps) {
		results_ok++;
		sc_jstr("status", "ok", false);
		if (host)
			sc_jsummary("populate_ns", pop, done);
		sc_jsummary("register_ns", reg, done);
		sc_jsummary("release_ns", unreg, done);
	} else {
		if (!strcmp(e.kind, "failed"))
			failures++;
		sc_jstr("status", e.kind, true);
		sc_jstr("step", e.step, true);
		printf("\"code\":%d,", e.code);
		sc_jstr("error", e.text, false);
		printf(",\"completed_reps\":%u", done);
	}
	printf("}");
}

static void sc_registration(const struct sc_opts *o)
{
	const char *cuda_why = "built without the CUDA/cuFile SDK (SETUP_COST_HAVE_CUDA)";
	bool first = true;
	int m, i;

#ifdef SETUP_COST_HAVE_CUDA
	cuda_why = (o->measure[M_CUDA] || o->measure[M_CUFILE]) ? sc_cuda_prepare(o) : NULL;
#endif
	printf("\"registration\":[");
	for (m = 0; m < M_NR; m++) {
		if (!o->measure[m])
			continue;
		for (i = 0; i < o->nr_sizes; i++) {
			if ((m == M_CUDA || m == M_CUFILE) && cuda_why)
				sc_not_run(m, o->sizes[i], cuda_why, &first);
			else if (m == M_MECH && !o->nvme_ng)
				sc_not_run(m, o->sizes[i], "--nvme-ng and --nvme-window required", &first);
			else if ((m == M_UMEM || m == M_MECH) && o->umem_cap &&
				 o->sizes[i] > o->umem_cap)
				sc_skip_cap(m, o->sizes[i], &first);
			else
				sc_run_measure(o, m, o->sizes[i], &first);
		}
	}
	printf("]");
}

/* --- BPF objects ------------------------------------------------------ */

static int sc_prog_info(int fd, struct bpf_prog_info *info)
{
	union bpf_attr attr;
	int ret;

	memset(info, 0, sizeof(*info));
	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = (uint32_t)fd;
	attr.info.info_len = sizeof(*info);
	attr.info.info = (uintptr_t)info;
	ret = (int)syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	return ret < 0 ? -errno : 0;
}

static void sc_bpf_object(const struct sc_opts *o, const char *path, bool comma)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	char *logs[SC_MAX_PROGS] = { NULL };
	uint64_t t0, load_ns;
	int nprog = 0, ret, i = 0;
	bool first = true;

	printf("%s{", comma ? "," : "");
	sc_jstr("object", path, true);
	/* libbpf 1.x returns NULL with errno, 0.x an error pointer. */
	obj = bpf_object__open_file(path, NULL);
	ret = !obj ? -errno : (uintptr_t)obj >= (uintptr_t)-4095 ? (int)(intptr_t)obj : 0;
	if (ret) {
		sc_jstr("status", "open_failed", true);
		sc_jstr("error", strerror(ret < 0 ? -ret : ret), false);
		printf("}");
		failures++;
		return;
	}
	bpf_object__for_each_program(prog, obj) {
		if (nprog == SC_MAX_PROGS)
			break;
#if defined(LIBBPF_MAJOR_VERSION) && LIBBPF_MAJOR_VERSION >= 1
		if (!o->counts_only) {
			logs[nprog] = calloc(1, SC_LOG_SIZE);
			if (logs[nprog]) {
				bpf_program__set_log_level(prog, 4);	/* BPF_LOG_STATS */
				bpf_program__set_log_buf(prog, logs[nprog], SC_LOG_SIZE);
			}
		}
#endif
		nprog++;
	}
	t0 = sc_now();
	ret = bpf_object__load(obj);
	load_ns = sc_now() - t0;
	if (ret) {
		sc_jstr("status", "load_refused", true);
		sc_jstr("error", strerror(-ret), false);
		printf("}");
		goto out;
	}
	results_ok++;
	sc_jstr("status", "ok", false);
	if (!o->counts_only)
		printf(",\"load_ns\":%llu", (unsigned long long)load_ns);
	printf(",\"programs\":[");
	bpf_object__for_each_program(prog, obj) {
		struct bpf_prog_info info;
		struct sc_verifier v;
		int fd = bpf_program__fd(prog);

		if (i == nprog)
			break;
		printf("%s{", first ? "" : ",");
		first = false;
		sc_jstr("name", bpf_program__name(prog), false);
		if (fd < 0 || sc_prog_info(fd, &info)) {
			printf(",\"status\":\"info_failed\"}");
			failures++;
			i++;
			continue;
		}
		printf(",\"type\":%u,\"verified_insns\":%u,\"xlated_insns\":%u,\"jited_bytes\":%u",
		       info.type, info.verified_insns, sc_xlated_insns(info.xlated_prog_len),
		       info.jited_prog_len);
		if (logs[i] && !sc_parse_verifier_log(logs[i], &v)) {
			if (v.have_time)
				printf(",\"verify_usec\":%llu", (unsigned long long)v.verify_usec);
			if (v.have_processed)
				printf(",\"processed_insns\":%llu",
				       (unsigned long long)v.processed_insns);
		}
		printf("}");
		i++;
	}
	printf("]}");
out:
	bpf_object__close(obj);
	for (i = 0; i < nprog; i++)
		free(logs[i]);
}

/* --- BPF run-time statistics around a workload ------------------------ */

struct sc_prog_stat {
	uint32_t id;
	char name[BPF_OBJ_NAME_LEN];
	uint64_t run_cnt, run_time_ns;
	uint32_t verified_insns;
};

static int sc_snapshot(const char *prefix, struct sc_prog_stat *out, int max)
{
	uint32_t id = 0, next;
	int n = 0;

	while (!bpf_prog_get_next_id(id, &next)) {
		struct bpf_prog_info info;
		int fd;

		id = next;
		fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0)
			continue;	/* unloaded meanwhile */
		if (!sc_prog_info(fd, &info) && info.type == BPF_PROG_TYPE_STRUCT_OPS &&
		    (!prefix || !strncmp(info.name, prefix, strlen(prefix)))) {
			if (n == max) {
				close(fd);
				return -E2BIG;
			}
			out[n].id = info.id;
			memcpy(out[n].name, info.name, sizeof(out[n].name));
			out[n].name[sizeof(out[n].name) - 1] = '\0';
			out[n].run_cnt = info.run_cnt;
			out[n].run_time_ns = info.run_time_ns;
			out[n].verified_insns = info.verified_insns;
			n++;
		}
		close(fd);
	}
	return n;
}

static int sc_prog_stats(const struct sc_opts *o)
{
	static struct sc_prog_stat before[SC_MAX_PROGS], after[SC_MAX_PROGS];
	union bpf_attr attr;
	int nb, na, i, j, stats_fd, status = 0;
	bool first = true;
	pid_t pid;

	memset(&attr, 0, sizeof(attr));
	attr.enable_stats.type = BPF_STATS_RUN_TIME;
	stats_fd = (int)syscall(__NR_bpf, BPF_ENABLE_STATS, &attr, sizeof(attr));
	if (stats_fd < 0) {
		fprintf(stderr, "setup_cost: BPF_ENABLE_STATS: %s\n", strerror(errno));
		return SC_NOT_RUN;
	}
	nb = sc_snapshot(o->prog_prefix, before, SC_MAX_PROGS);
	fflush(stdout);
	pid = fork();
	if (pid == 0) {
		/* The workload's output goes to stderr; stdout carries the JSON. */
		close(stats_fd);
		dup2(STDERR_FILENO, STDOUT_FILENO);
		execvp(o->cmd[0], o->cmd);
		_exit(127);
	}
	if (pid < 0 || waitpid(pid, &status, 0) < 0) {
		close(stats_fd);
		return SC_FAIL;
	}
	na = sc_snapshot(o->prog_prefix, after, SC_MAX_PROGS);
	close(stats_fd);
	if (nb < 0 || na < 0)
		return SC_FAIL;
	printf("{\"schema\":\"xdev-eval-setup-cost-v1\",\"mode\":\"prog-stats\",");
	printf("\"workload_status\":%d,\"programs\":[",
	       WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
	for (i = 0; i < na; i++) {
		uint64_t cnt = after[i].run_cnt, ns = after[i].run_time_ns;

		for (j = 0; j < nb; j++)
			if (before[j].id == after[i].id) {
				cnt -= before[j].run_cnt;
				ns -= before[j].run_time_ns;
			}
		printf("%s{\"id\":%u,", first ? "" : ",", after[i].id);
		first = false;
		sc_jstr("name", after[i].name, false);
		printf(",\"verified_insns\":%u,\"run_cnt\":%llu,\"run_time_ns\":%llu",
		       after[i].verified_insns, (unsigned long long)cnt, (unsigned long long)ns);
		if (cnt)
			printf(",\"ns_per_run\":%.1f", (double)ns / (double)cnt);
		printf("}");
	}
	printf("]}\n");
	return WIFEXITED(status) && !WEXITSTATUS(status) ? SC_OK : SC_FAIL;
}

/* --- command line ----------------------------------------------------- */

static int sc_parse_measures(const char *list, bool *measure)
{
	char buf[128], *save = NULL, *tok;
	int m;

	if (strlen(list) >= sizeof(buf))
		return -EINVAL;
	strcpy(buf, list);
	memset(measure, 0, sizeof(bool) * M_NR);
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		for (m = 0; m < M_NR && strcmp(tok, sc_names[m]); m++)
			;
		if (m == M_NR)
			return -EINVAL;
		measure[m] = true;
	}
	return 0;
}

static void sc_usage(void)
{
	fprintf(stderr,
		"usage: setup_cost [--sizes LIST] [--reps N] [--frame-size N]\n"
		"                  [--measure umem,mech,xdp,iou,cuda,cufile]\n"
		"                  [--nvme-ng DEV --nvme-window SLBA:NLB] [--cuda-device N]\n"
		"                  [--umem-cap SIZE] [--mem-margin SIZE]\n"
		"                  [--bpf-obj F ...] [--counts-only]\n"
		"       setup_cost --prog-stats [--prog-prefix NAME] -- CMD...\n");
}

static int sc_parse(int argc, char **argv, struct sc_opts *o)
{
	static const struct option longopts[] = {
		{ "sizes", required_argument, NULL, 's' },
		{ "reps", required_argument, NULL, 'r' },
		{ "frame-size", required_argument, NULL, 'f' },
		{ "measure", required_argument, NULL, 'm' },
		{ "nvme-ng", required_argument, NULL, 'n' },
		{ "nvme-window", required_argument, NULL, 'w' },
		{ "cuda-device", required_argument, NULL, 'g' },
		{ "bpf-obj", required_argument, NULL, 'b' },
		{ "counts-only", no_argument, NULL, 'c' },
		{ "prog-stats", no_argument, NULL, 'p' },
		{ "prog-prefix", required_argument, NULL, 'x' },
		{ "umem-cap", required_argument, NULL, 'u' },
		{ "mem-margin", required_argument, NULL, 'M' },
		{ NULL, 0, NULL, 0 },
	};
	bool window = false;
	uint64_t v;
	int c;

	memset(o, 0, sizeof(*o));
	o->reps = 5;
	o->frame_size = 4096;
	o->measure[M_UMEM] = o->measure[M_XDP] = o->measure[M_IOU] = true;
	o->sizes[0] = 1ULL << 20;
	o->nr_sizes = 1;
	while ((c = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (c) {
		case 's':
			o->nr_sizes = sc_parse_sizes(optarg, o->sizes, SC_MAX_SIZES);
			if (o->nr_sizes < 0)
				return -EINVAL;
			break;
		case 'r':
			if (sc_parse_size(optarg, &v) || v > SC_MAX_REPS)
				return -EINVAL;
			o->reps = (unsigned int)v;
			break;
		case 'f':
			if (sc_parse_size(optarg, &v) || v > (1U << 16) || (v & (v - 1)))
				return -EINVAL;
			o->frame_size = (uint32_t)v;
			break;
		case 'm':
			if (sc_parse_measures(optarg, o->measure))
				return -EINVAL;
			break;
		case 'n':
			o->nvme_ng = optarg;
			break;
		case 'w':
			if (sc_parse_window(optarg, &o->slba, &o->nlb))
				return -EINVAL;
			window = true;
			break;
		case 'g':
			o->cuda_device = atoi(optarg);
			break;
		case 'b':
			if (o->nr_objs == SC_MAX_OBJS)
				return -EINVAL;
			o->objs[o->nr_objs++] = optarg;
			break;
		case 'c':
			o->counts_only = true;
			break;
		case 'p':
			o->prog_stats = true;
			break;
		case 'x':
			o->prog_prefix = optarg;
			break;
		case 'u':
			if (sc_parse_size(optarg, &o->umem_cap))
				return -EINVAL;
			break;
		case 'M':
			if (sc_parse_size(optarg, &o->mem_margin))
				return -EINVAL;
			break;
		default:
			return -EINVAL;
		}
	}
	if (!!o->nvme_ng != window)
		return -EINVAL;
	for (c = 0; c < o->nr_sizes; c++)
		if (o->sizes[c] % o->frame_size)
			return -EINVAL;
	if (o->prog_stats) {
		if (optind >= argc)
			return -EINVAL;
		o->cmd = argv + optind;
	} else if (optind != argc) {
		return -EINVAL;
	}
	if (o->counts_only && (o->prog_stats || !o->nr_objs))
		return -EINVAL;
	return 0;
}

int main(int argc, char **argv)
{
	struct sc_opts o;
	int i;

	if (sc_parse(argc, argv, &o)) {
		sc_usage();
		return SC_USAGE;
	}
	if (!o.counts_only && sc_hypervisor()) {
		fprintf(stderr, "setup_cost: hypervisor detected; timed setup costs are measured "
			"on physical hosts only (use --counts-only for instruction counts)\n");
		return SC_NOT_RUN;
	}
	if (o.prog_stats)
		return sc_prog_stats(&o);
	printf("{\"schema\":\"xdev-eval-setup-cost-v1\",\"mode\":\"%s\",",
	       o.counts_only ? "counts" : "timing");
	printf("\"frame_size\":%u,\"reps\":%u,", o.frame_size, o.reps);
	if (!o.counts_only) {
		sc_registration(&o);
		printf(",");
	}
	printf("\"bpf\":[");
	for (i = 0; i < o.nr_objs; i++)
		sc_bpf_object(&o, o.objs[i], i > 0);
	printf("]}\n");
	if (failures)
		return SC_FAIL;
	return results_ok ? SC_OK : SC_NOT_RUN;
}
