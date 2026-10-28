// SPDX-License-Identifier: GPL-2.0
/*
 * session_nvme_ce - the xdev_ext session arm of the NVMe<->GPU comparison.
 *
 *   load: [NVMe READ, CE H2D]   one session, NVMe -> shared host frame -> VRAM
 *   save: [CE D2H, NVMe WRITE]  one session, VRAM -> shared host frame -> NVMe
 *
 * Both are one-way two-stage sessions on the ring's XDEV_EXT UMEM; the CE
 * stage is the last (load) or first (save) stage, which
 * ../gpu_nic/test_ce_stage_position.c shows the core admits.  The ctl chains
 * a/d always add the reverse copy; this arm does not.
 *
 * Ported idea: the NVMe -> UMEM -> GPU and GPU -> UMEM -> NVMe chain of
 * archive/conduit-legacy/eval/benchmark-code/bench_full_pipeline.c
 * (git blob 69e46d263a35d1d5b3825c401597700c8ea15978, sha256
 * 5fe24476abe1d90faead86c2e101338c4d1a0ce2e56af76065e9cab37d3eb0d6).  That
 * program drove pread/cuMemcpy/pwrite from user space per iteration and
 * computed on the CPU; here the kernel session owns every per-group step,
 * there is no compute and no CPU payload copy, and the oracle runs once after
 * each pass.
 *
 * Each pass is one session of window/size batches, START to terminal wake
 * timed.  Batch k reads or writes LBA slba + k*size/lba (the nxp_nvme_ops
 * plan of nxp_mech.bpf.o with nvme_mode=0 and key_base=1); its CE copy uses
 * window slot (batch object) s of depth slots (ce_plan_ops of ce_plan.bpf.o).
 * Both struct_ops programs must be attached.  The plan is linear, so only
 * --pattern seq runs; rand and qd > 64 (XDEV_EXT_MECH_MAX_DEPTH) exit 4.
 *
 * The device side is a ring of qd slots (destination slot-ring); the
 * baselines of run.py use the same layout.  ce_validate (kernel
 * io_uring/xdev_ext_mech_ce.c) refuses any copy outside the batch slot's
 * group_bytes, so a session cannot place a block by its LBA order.
 * Completion: the arm sleeps on the session eventfd (completion_wait block).
 *
 * Oracle, outside the timed region (window/size >= qd, so every slot is
 * used):
 *   load  every slot holds one whole, distinct block image of the window
 *         (all of the window's blocks when window/size == qd).
 *   save  every group of the file window is overwritten by an exact image
 *         of one device slot, and every slot's image appears; the slots
 *         were seeded with blocks 0..qd-1.
 * --file names the same blocks through a block device or a single-extent
 * file (run.py derives the LBA window); it is read and written with
 * O_DIRECT only.
 *
 * With /dev/xdev_ext_ce_sim the run is a KVM correctness record
 * (execution=kvm-ce-sim, performance_claim=none).  Exit: 0 verified, 1
 * failure, 2 usage, 4 unavailable capability (stdout empty unless 0).
 */
#define _GNU_SOURCE
#include "../common/cpu_timer.h"
static struct cpu_timer endpoint_timer;
static void endpoint_timer_cleanup(void) { cpu_timer_destroy(&endpoint_timer); }
#include "../common/fd_check.h"
#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "eval_session.h"

#define SN_MAX_SESSION_DEPTH	64ULL	/* XDEV_EXT_MECH_MAX_DEPTH */
#define SN_IO_ALIGN		4096ULL

struct sn_opts {
	uint32_t direction;
	const char *ng, *file, *ce_dev;
	uint64_t slba, lba_size, file_offset, frame_size, timeout_ms, ce_va;
	bool ce_alloc;
	struct xg_geometry g;
};

static void sn_usage(FILE *f)
{
	fprintf(f,
"usage: session_nvme_ce --direction load|save --ng /dev/ngXnY --slba N --lba-size N\n"
"         --file PATH [--file-offset N] --ce-dev DEV (--ce-va N | --ce-alloc)\n"
"         --size N --qd N --window-bytes N [--passes N] [--pattern seq]\n"
"         [--seed N] [--frame-size N] [--timeout-ms N]\n");
}

static int sn_parse(int argc, char **argv, struct sn_opts *o)
{
	enum { O_DIR = 1, O_NG, O_SLBA, O_LBA, O_FILE, O_FOFF, O_CE, O_VA, O_ALLOC,
	       O_SIZE, O_QD, O_WIN, O_PASS, O_PAT, O_SEED, O_FRAME, O_TMO, O_HELP };
	static const struct option opts[] = {
		{ "direction", required_argument, NULL, O_DIR },
		{ "ng", required_argument, NULL, O_NG },
		{ "slba", required_argument, NULL, O_SLBA },
		{ "lba-size", required_argument, NULL, O_LBA },
		{ "file", required_argument, NULL, O_FILE },
		{ "file-offset", required_argument, NULL, O_FOFF },
		{ "ce-dev", required_argument, NULL, O_CE },
		{ "ce-va", required_argument, NULL, O_VA },
		{ "ce-alloc", no_argument, NULL, O_ALLOC },
		{ "size", required_argument, NULL, O_SIZE },
		{ "qd", required_argument, NULL, O_QD },
		{ "window-bytes", required_argument, NULL, O_WIN },
		{ "passes", required_argument, NULL, O_PASS },
		{ "pattern", required_argument, NULL, O_PAT },
		{ "seed", required_argument, NULL, O_SEED },
		{ "frame-size", required_argument, NULL, O_FRAME },
		{ "timeout-ms", required_argument, NULL, O_TMO },
		{ "help", no_argument, NULL, O_HELP },
		{ NULL, 0, NULL, 0 },
	};
	bool have_dir = false, have_slba = false, have_va = false;
	uint64_t seed = 1;
	int c, bad = 0;

	memset(o, 0, sizeof(*o));
	o->g.passes = 1;
	o->timeout_ms = 60000;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case O_DIR: bad |= xg_parse_direction(optarg, &o->direction); have_dir = true; break;
		case O_NG: o->ng = optarg; break;
		case O_SLBA: bad |= xg_parse_u64(optarg, UINT64_MAX >> 1, &o->slba); have_slba = true; break;
		case O_LBA: bad |= xg_parse_u64(optarg, 65536, &o->lba_size); break;
		case O_FILE: o->file = optarg; break;
		case O_FOFF: bad |= xg_parse_u64(optarg, UINT64_MAX >> 2, &o->file_offset); break;
		case O_CE: o->ce_dev = optarg; break;
		case O_VA: bad |= xg_parse_u64(optarg, UINT64_MAX >> 2, &o->ce_va); have_va = true; break;
		case O_ALLOC: o->ce_alloc = true; break;
		case O_SIZE: bad |= xg_parse_u64(optarg, XG_MAX_SIZE, &o->g.size); break;
		case O_QD: bad |= xg_parse_u64(optarg, XG_MAX_QD, &o->g.qd); break;
		case O_WIN: bad |= xg_parse_u64(optarg, XG_MAX_WINDOW, &o->g.window); break;
		case O_PASS: bad |= xg_parse_u64(optarg, XG_MAX_PASSES, &o->g.passes); break;
		case O_PAT: bad |= xg_parse_pattern(optarg, &o->g.pattern); break;
		case O_SEED: bad |= xg_parse_u64(optarg, UINT32_MAX, &seed); break;
		case O_FRAME: bad |= xg_parse_u64(optarg, 1ULL << 22, &o->frame_size); break;
		case O_TMO: bad |= xg_parse_u64(optarg, 3600000, &o->timeout_ms); break;
		case O_HELP: sn_usage(stdout); exit(0);
		default: bad = 1; break;
		}
	}
	o->g.seed = (uint32_t)seed;
	if (bad || optind != argc || !have_dir || !o->ng || !have_slba || !o->file ||
	    !o->ce_dev || have_va == o->ce_alloc || !o->timeout_ms ||
	    !o->lba_size || (o->lba_size & (o->lba_size - 1)) || o->lba_size < 512 ||
	    o->file_offset % SN_IO_ALIGN || xg_geometry_check(&o->g) ||
	    o->g.size % o->lba_size ||
	    (o->frame_size && (o->frame_size < 4096 ||
			       (o->frame_size & (o->frame_size - 1)))))
		return XG_EXIT_USAGE;
	if (!o->frame_size) {
		/* Smallest power of two holding a group in at most 32 frames. */
		o->frame_size = 4096;
		while (o->frame_size * XDEV_EXT_MECH_MAX_FRAMES < o->g.size)
			o->frame_size <<= 1;
	}
	if ((o->g.size + o->frame_size - 1) / o->frame_size > XDEV_EXT_MECH_MAX_FRAMES)
		return XG_EXIT_USAGE;
	return XG_EXIT_PASS;
}

static int sn_unavailable(const char *what, int err)
{
	fprintf(stderr, "SKIP: %s: %s\n", what, strerror(-err));
	return XG_EXIT_UNAVAILABLE;
}

/* Setup errnos that mean "this kernel, program or device cannot do it". */
static bool sn_capability_errno(int err)
{
	return err == -EINVAL || err == -EOPNOTSUPP || err == -ENOSYS ||
	       err == -ENODEV || err == -ENXIO || err == -EPERM || err == -EACCES;
}

static int sn_direct_io(int fd, bool write, void *buf, uint64_t len, uint64_t off)
{
	uint64_t done = 0;

	while (done < len) {
		ssize_t k = write ? pwrite(fd, (char *)buf + done, len - done, (off_t)(off + done)) :
				    pread(fd, (char *)buf + done, len - done, (off_t)(off + done));

		if (k < 0 && errno == EINTR)
			continue;
		if (k <= 0)
			return k < 0 ? -errno : -EIO;
		done += (uint64_t)k;
	}
	return 0;
}

/* Window [0, window) of --file: payload of @seed, in size-sized chunks. */
static int sn_file_fill(int fd, const struct sn_opts *o, unsigned char *buf,
			uint32_t seed)
{
	uint64_t off;
	int ret;

	for (off = 0; off < o->g.window; off += o->g.size) {
		xg_fill(buf, off, o->g.size, seed);
		ret = sn_direct_io(fd, true, buf, o->g.size, o->file_offset + off);
		if (ret)
			return ret;
	}
	return fsync(fd) ? -errno : 0;
}

struct sn_pass {
	uint64_t io_ns, cpu_us, host_busy_us, verified_bytes, slots_used;
	struct xdev_ext_mech_stats stats;
};

/* One pass: a fresh ring, UMEM and session; START to terminal wake is timed. */
static int sn_session(const struct sn_opts *o, const struct es_ce *ce, int ng,
		      struct sn_pass *p)
{
	uint64_t n = xg_blocks(&o->g), depth = o->g.qd;
	uint64_t groups = n < depth ? n : depth, frames, i;
	struct io_uring_xdev_ext_umem_reg reg = { 0 };
	struct xdev_ext_mech_create c;
	struct es_run r = { .ring = -1, .efd = -1 };
	__u32 *user = NULL;
	void *umem = MAP_FAILED;
	__u64 t0, t1, cpu0, busy0, deadline;
	int ret, nvme = o->direction == XG_LOAD ? 0 : 1, cei = 1 - nvme, closed;

	memset(&c, 0, sizeof(c));
	c.layout = (struct xdev_ext_mech_layout) {
		.frame_size = (__u32)o->frame_size, .hdr_room = 0,
		.seg_len = (__u32)o->frame_size, .group_bytes = (__u32)o->g.size,
	};
	ret = xdev_ext_mech_layout_frames(&c.layout);
	if (ret < 0)
		return XG_EXIT_USAGE;
	frames = (uint64_t)ret;
	reg.frame_size = (__u32)o->frame_size;
	reg.size = groups * frames * o->frame_size;
	umem = mmap(NULL, reg.size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	user = calloc(groups * frames, sizeof(*user));
	if (umem == MAP_FAILED || !user) {
		ret = -ENOMEM;
		goto out;
	}
	reg.addr = (uintptr_t)umem;
	for (i = 0; i < groups * frames; i++)
		user[i] = (__u32)i;
	ret = es_ring_open(&r);
	if (!ret)
		ret = es_register(r.ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg);
	if (ret) {
		ret = sn_capability_errno(ret) ?
		      sn_unavailable("io_uring XDEV_EXT UMEM", ret) : XG_EXIT_FAIL;
		goto out;
	}
	c.nr_stages = 2;
	c.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	c.pool_fd = -1;
	c.depth = (__u32)depth;
	c.st[nvme] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = nvme ? XDEV_EXT_MECH_DIR_TO_DEVICE : XDEV_EXT_MECH_DIR_FROM_DEVICE,
		.fd = ng, .arg0 = o->slba, .arg1 = o->g.window / o->lba_size,
	};
	c.st[cei] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_CE,
		.direction = nvme ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE,
		.fd = ce->fd[0], .arg0 = ce->va, .arg1 = ce->len,
	};
	ret = es_create(&r, &c, n);
	if (ret) {
		ret = sn_capability_errno(ret) ?
		      sn_unavailable("CREATE (kernel, attached nxp_nvme_ops/ce_plan_ops, devices)", ret) :
		      XG_EXIT_FAIL;
		goto out;
	}
	deadline = es_now_ns() + o->timeout_ms * 1000000ULL;
	cpu0 = es_cpu_us();
	busy0 = xg_host_busy_us();
	t0 = es_now_ns();
	ret = es_start(&r, n, user, (__u32)(groups * frames));
	if (!ret)
		ret = es_wait_terminal(&r, deadline);
	/* A terminal notification alone does not prove the final drain. */
	if (!ret)
		ret = es_settle(&r, n, deadline, &p->stats);
	else
		es_stats(&r, &p->stats);
	t1 = es_now_ns();
	p->cpu_us = es_cpu_us() - cpu0;
	p->host_busy_us = xg_host_busy_us() - busy0;
	es_print_stats(&p->stats);
	if (ret) {
		fprintf(stderr, "session pass failed: %s\n", strerror(-ret));
		ret = XG_EXIT_FAIL;
		goto out;
	}
	if (p->stats.batches_done != n || p->stats.completed[0] != p->stats.submitted[0] ||
	    p->stats.completed[1] != p->stats.submitted[1] || !t0 || t1 <= t0) {
		fprintf(stderr, "session counters do not cover the campaign\n");
		ret = XG_EXIT_FAIL;
		goto out;
	}
	cpu_timer_store(&endpoint_timer, "io_ns", endpoint_timer.count, t0, t1);
	p->io_ns = t1 - t0;
	ret = XG_EXIT_PASS;
out:
	closed = es_close(&r);
	if (closed && ret == XG_EXIT_PASS) {
		fprintf(stderr, "STOP: %s\n", strerror(-closed));
		ret = XG_EXIT_FAIL;
	}
	free(user);
	if (umem != MAP_FAILED)
		munmap(umem, reg.size);
	return ret < 0 ? XG_EXIT_FAIL : ret;
}

/* load: every slot holds a distinct whole block; a sentinel slot was never used. */
static int sn_check_load(const struct sn_opts *o, struct es_ce *ce,
			 unsigned char *buf, unsigned char *seen, struct sn_pass *p)
{
	uint64_t n = xg_blocks(&o->g), s, used = 0;

	memset(seen, 0, n);
	for (s = 0; s < o->g.qd; s++) {
		uint64_t block;
		int ret = es_ce_access(ce, false, s * o->g.size, buf, o->g.size);

		if (ret)
			return ret;
		ret = xg_identify(buf, o->g.size, n, o->g.seed, &block);
		if (!ret) {
			if (seen[block]++)
				return -EEXIST;
			used++;
			continue;
		}
		if (xg_compare(buf, s * o->g.size, o->g.size, ~o->g.seed) >= 0)
			return -EBADMSG;
	}
	if (used != o->g.qd)
		return -ENODATA;
	p->slots_used = used;
	p->verified_bytes = o->g.qd * o->g.size;
	return 0;
}

/* save: every group of the window is an exact image of a seeded slot. */
static int sn_check_save(const struct sn_opts *o, int fd, unsigned char *buf,
			 unsigned char *seen, struct sn_pass *p)
{
	uint64_t n = xg_blocks(&o->g), k, used = 0;

	memset(seen, 0, o->g.qd);
	for (k = 0; k < n; k++) {
		uint64_t block;
		int ret = sn_direct_io(fd, false, buf, o->g.size, o->file_offset + k * o->g.size);

		if (ret)
			return ret;
		ret = xg_identify(buf, o->g.size, o->g.qd, o->g.seed, &block);
		if (ret)
			return ret;
		if (!seen[block]++)
			used++;
	}
	/* n >= qd batches: every batch slot carried at least one group. */
	if (used != o->g.qd)
		return -ENODATA;
	p->slots_used = used;
	p->verified_bytes = o->g.window;
	return 0;
}

static int sn_seed_slots(const struct sn_opts *o, struct es_ce *ce, unsigned char *buf)
{
	uint64_t s;
	int ret;

	/* load: sentinel in every slot; save: block s in slot s. */
	for (s = 0; s < o->g.qd; s++) {
		xg_fill(buf, s * o->g.size, o->g.size,
			o->direction == XG_LOAD ? ~o->g.seed : o->g.seed);
		ret = es_ce_access(ce, true, s * o->g.size, buf, o->g.size);
		if (ret)
			return ret;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int fd_before = eval_fd_count();
	struct sn_opts o;
	struct es_ce ce = { .fd = { -1, -1 }, .sim = true };
	struct sn_pass p, total = { 0 };
	unsigned char *buf = NULL, *seen = NULL;
	struct stat st;
	uint64_t pass, slots_used = 0;
	int ret, fd = -1, ng = -1, closed;

	setvbuf(stdout, NULL, _IOFBF, 1 << 16);
	ret = sn_parse(argc, argv, &o);
	if (ret) {
		sn_usage(stderr);
		return ret;
	}
	{
		int error = cpu_timer_init(&endpoint_timer, "CLOCK_MONOTONIC", o.g.passes);
		if (error)
			fprintf(stderr, "XDEV_EXT_CPU_TIMER_REFUSED phase=init code=%d\n", error);
	}
	atexit(endpoint_timer_cleanup);
	if (o.g.pattern != XG_SEQ) {
		fprintf(stderr, "SKIP: session NVMe plan is linear in the batch key; rand needs another plan program\n");
		return XG_EXIT_UNAVAILABLE;
	}
	if (o.g.qd > SN_MAX_SESSION_DEPTH) {
		fprintf(stderr, "SKIP: session depth is limited to %llu batches\n",
			(unsigned long long)SN_MAX_SESSION_DEPTH);
		return XG_EXIT_UNAVAILABLE;
	}
	fd = open(o.file, O_RDWR | O_DIRECT | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &st) || !(S_ISREG(st.st_mode) || S_ISBLK(st.st_mode))) {
		fprintf(stderr, "SKIP: %s: no O_DIRECT regular file or block device\n", o.file);
		ret = XG_EXIT_UNAVAILABLE;
		goto out;
	}
	if (S_ISREG(st.st_mode) && (uint64_t)st.st_size < o.file_offset + o.g.window) {
		fprintf(stderr, "%s is shorter than the window\n", o.file);
		ret = XG_EXIT_USAGE;
		goto out;
	}
	ng = open(o.ng, O_RDWR | O_CLOEXEC);
	if (ng < 0) {
		fprintf(stderr, "SKIP: %s: %s\n", o.ng, strerror(errno));
		ret = XG_EXIT_UNAVAILABLE;
		goto out;
	}
	ret = es_ce_open(&ce, o.ce_dev, 1, o.ce_alloc, o.ce_va, o.g.qd * o.g.size);
	if (ret)
		goto out;
	if (posix_memalign((void **)&buf, SN_IO_ALIGN, o.g.size) ||
	    !(seen = calloc(xg_blocks(&o.g) > o.g.qd ? xg_blocks(&o.g) : o.g.qd, 1))) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	for (pass = 0; pass < o.g.passes; pass++) {
		/* Seeding is outside the timed region and repeated per pass. */
		ret = sn_file_fill(fd, &o, buf, o.direction == XG_LOAD ? o.g.seed : ~o.g.seed);
		if (!ret)
			ret = sn_seed_slots(&o, &ce, buf);
		if (ret) {
			fprintf(stderr, "seeding: %s\n", strerror(-ret));
			ret = XG_EXIT_FAIL;
			goto out;
		}
		memset(&p, 0, sizeof(p));
		ret = sn_session(&o, &ce, ng, &p);
		if (ret)
			goto out;
		ret = o.direction == XG_LOAD ? sn_check_load(&o, &ce, buf, seen, &p) :
					       sn_check_save(&o, fd, buf, seen, &p);
		if (ret) {
			fprintf(stderr, "oracle failed in pass %llu: %s\n",
				(unsigned long long)pass, strerror(-ret));
			ret = XG_EXIT_FAIL;
			goto out;
		}
		total.io_ns += p.io_ns;
		total.cpu_us += p.cpu_us;
		total.host_busy_us += p.host_busy_us;
		total.verified_bytes += p.verified_bytes;
		slots_used = p.slots_used;
	}
	closed = es_ce_close(&ce);
	if (closed) {
		fprintf(stderr, "CE window cleanup: %s\n", strerror(-closed));
		ret = XG_EXIT_FAIL;
		goto out;
	}
	{
		int error = cpu_timer_publish(&endpoint_timer);
		if (error)
			fprintf(stderr, "XDEV_EXT_CPU_TIMER_REFUSED phase=publish code=%d\n", error);
	}
	printf("{\"schema_version\":1,\"arm\":\"session\",\"direction\":\"%s\","
	       "\"route\":\"%s\",\"execution\":\"%s\",\"performance_claim\":\"%s\","
	       "\"destination\":\"slot-ring\",\"completion_wait\":\"block\","
	       "\"size\":%llu,\"qd\":%llu,\"pattern\":\"seq\",\"window_bytes\":%llu,"
	       "\"passes\":%llu,\"operations\":%llu,\"io_bytes\":%llu,"
	       "\"verified_bytes\":%llu,\"slots_used\":%llu,\"oracle\":\"%s\","
	       "\"io_ns\":%llu,\"cpu_us\":%llu,\"host_busy_us\":%llu,\"status\":\"pass\"}\n",
	       o.direction == XG_LOAD ? "load" : "save",
	       o.direction == XG_LOAD ? "nvme-read>shared-host-frame>ce-h2d" :
					"ce-d2h>shared-host-frame>nvme-write",
	       ce.sim ? "kvm-ce-sim" : "physical-gpu-ce",
	       ce.sim ? "none" : "physical",
	       (unsigned long long)o.g.size, (unsigned long long)o.g.qd,
	       (unsigned long long)o.g.window, (unsigned long long)o.g.passes,
	       (unsigned long long)(xg_blocks(&o.g) * o.g.passes),
	       (unsigned long long)(o.g.window * o.g.passes),
	       (unsigned long long)total.verified_bytes, (unsigned long long)slots_used,
	       o.direction == XG_LOAD ? "device-slot-block-images" : "file-window-slot-images",
	       (unsigned long long)total.io_ns, (unsigned long long)total.cpu_us,
	       (unsigned long long)total.host_busy_us);
	ret = fflush(stdout) ? XG_EXIT_FAIL : XG_EXIT_PASS;
out:
	/* Idempotent: a closed window has no fd and no driver handle left. */
	if (es_ce_close(&ce) && ret == XG_EXIT_PASS)
		ret = XG_EXIT_FAIL;
	if (ng >= 0)
		close(ng);
	if (fd >= 0)
		close(fd);
	free(buf);
	free(seen);
	if (eval_fd_check(fd_before) && ret == XG_EXIT_PASS)
		ret = XG_EXIT_FAIL;
	return ret;
}
