// SPDX-License-Identifier: GPL-2.0
/*
 * xdomain_gpu - E4 xdev_ext arm: VRAM to VRAM over one Thunderbolt/USB4 cable
 * through our XDOMAIN session, with host frames and the GPU copy engine
 * (plan E4, TODO.75).  For a GPU without GPUDirect RDMA (RTX 5090).
 *
 *   rank 1: xdomain_gpu --rank 1 --listen ADDR:PORT  [link, GPU and size options]
 *   rank 0: xdomain_gpu --rank 0 --peer   ADDR:PORT  [same options]
 *
 * Each rank opens two sessions per message size on the ring's XDEV_EXT UMEM
 * (host frames):
 *   TX  [CE D2H, XDOMAIN TX]  the copy engine reads the batch's VRAM slot
 *                             into host frames, the NHI sends them;
 *   RX  [XDOMAIN RX, CE H2D]  the NHI receives into host frames, the copy
 *                             engine writes them to the batch's VRAM slot.
 * The CE stages are in slot mode (ce_plan.bpf.c): batch slot s of the
 * session's depth slots maps to VRAM [s * group, (s + 1) * group) of a CUDA
 * VMM allocation exported as a POSIX fd and attached to the CE device.  Each
 * direction has its own CE fd and allocation.  The CE class program
 * (ce_plan_ops) and the XDOMAIN class default program (xdomain_peer.bpf.c)
 * must be attached.  No CPU copies a payload byte.
 *
 * A message of SIZE bytes is SIZE/group groups of group = min(SIZE, 256 KiB)
 * bytes (XDOMAIN carries at most 64 NHI frames of 4 KiB per batch).
 *
 * pingpong: depth = window = groups per message.  Rank 0 posts its receive
 *   (RX START), takes t0, STARTs one message on TX and waits for the RX
 *   session's final notification (t1); rank 1 waits for its RX, then STARTs
 *   its reply on TX and posts the next receive.  The reply is application
 *   level (after the received copy completed), the same order as the TCP
 *   baseline's recv-then-send.  Rank 0 reports median/p99 RTT and RTT/2 (a
 *   symmetric estimate).  START to final wake is the timed span; the wait
 *   sleeps on the session eventfd.
 * stream: depth = window = --window groups (32 by default).  Rank 1 STARTs
 *   all receives, tells rank 0 over the control connection, and times until
 *   its RX session's final notification; rank 0 STARTs all sends.
 *
 * Oracle (outside the timed region, both modes): before the size, each TX
 * slot s holds the slot image of the sender (xdg_core.h) and each RX slot
 * is poisoned; afterwards every RX slot must hold a whole, distinct sender
 * slot image and every image must appear.  Slots are batch objects, so a
 * multi-group message lands in a permutation of the slots; the permutation
 * oracle accepts exactly that.  Counters must show every batch done with
 * no abort, sequestering or error.
 *
 * Both ranks must give the same options (checked over the control
 * connection, which carries only configuration, barriers and verdicts).
 * --dry-run opens no device and prints the per-size plan.  Nothing here has
 * run on two hosts; a run in a VM or on the lab-vfio self-loop is a
 * correctness record only.
 * Exit: 0 pass, 1 failure, 2 usage, 4 unavailable (device, CUDA, CREATE refused).
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/resource.h>

#include "../../../kernel/tools/xdev_ext_mech/lib/libxdev_ext.h"
#include "../../../kernel/tools/xdev_ext_mech/xdev_ext_mech_cuda.h"
#include "../../../kernel/tools/include/xdev_ext_nv_p2p_ioctl.h"
#include "xdg_core.h"
#include "xdg_net.h"

#define POISON		0xA5
#define FRAME		XDEV_EXT_FRAME_SIZE

enum mode { MODE_PINGPONG, MODE_STREAM };

struct opts {
	int rank, window, timeout_ms;
	enum mode mode;
	const char *peer, *listen, *sizes_arg, *gpu_bdf, *ce_dev, *service, *sysfs_root;
	uint64_t sizes[XDG_MAX_SIZES], iters, warmup, messages, seed, link_token;
	int nsizes;
	bool early, dry_run;
};

struct plan {
	uint64_t size, group, groups, depth, window, frames_per_group, ring_frames, win_bytes;
	uint64_t batches;	/* per START: pingpong one message, stream all of them */
	uint64_t messages;
};

struct dir {
	struct xdev_ext_mech_cuda cuda;
	struct xdev_ext_session *s;
	int ce_fd;
	uint64_t done;		/* batches_done seen so far */
};

struct run {
	struct opts o;
	struct dir tx, rx;
	int ctl, fd;
	uint64_t token, max_win;
	uint8_t *scratch;
};

static void usage(void)
{
	fprintf(stderr,
		"usage: xdomain_gpu --rank 0 --peer HOST:PORT | --rank 1 --listen HOST:PORT\n"
		"       --gpu-bdf BDF --ce-dev /dev/nvidiaN (--service NAME [--sysfs-root DIR] |\n"
		"       --link-token N) [--mode pingpong|stream] [--sizes LIST] [--iters N]\n"
		"       [--warmup N] [--stream-messages N] [--window W] [--seed N] [--early]\n"
		"       [--timeout-ms MS] [--dry-run]\n");
}

static int parse(int argc, char **argv, struct opts *o)
{
	static const struct option lo[] = {
		{ "rank", 1, 0, 'r' }, { "peer", 1, 0, 'p' }, { "listen", 1, 0, 'l' },
		{ "mode", 1, 0, 'm' }, { "sizes", 1, 0, 's' }, { "iters", 1, 0, 'i' },
		{ "warmup", 1, 0, 'w' }, { "stream-messages", 1, 0, 'n' }, { "window", 1, 0, 'W' },
		{ "seed", 1, 0, 'S' }, { "gpu-bdf", 1, 0, 'g' }, { "ce-dev", 1, 0, 'c' },
		{ "service", 1, 0, 'v' }, { "sysfs-root", 1, 0, 'y' }, { "link-token", 1, 0, 'k' },
		{ "early", 0, 0, 'e' }, { "timeout-ms", 1, 0, 't' }, { "dry-run", 0, 0, 'd' },
		{ 0, 0, 0, 0 }
	};
	uint64_t v;
	int c;

	*o = (struct opts){ .rank = -1, .window = 32, .timeout_ms = 30000, .iters = 1000,
			    .warmup = 100, .seed = 1, .sysfs_root = "/sys/bus/thunderbolt/devices" };
	while ((c = getopt_long(argc, argv, "", lo, NULL)) != -1) {
		const char *a = optarg;
		size_t n = a ? strlen(a) : 0;

		switch (c) {
		case 'r': if (xdg_parse_u64(a, n, 1, &v)) return -EINVAL; o->rank = (int)v; break;
		case 'p': o->peer = a; break;
		case 'l': o->listen = a; break;
		case 'm':
			if (!strcmp(a, "pingpong")) o->mode = MODE_PINGPONG;
			else if (!strcmp(a, "stream")) o->mode = MODE_STREAM;
			else return -EINVAL;
			break;
		case 's': o->sizes_arg = a; break;
		case 'i': if (xdg_parse_u64(a, n, 100000000, &o->iters) || !o->iters) return -EINVAL; break;
		case 'w': if (xdg_parse_u64(a, n, 100000000, &o->warmup)) return -EINVAL; break;
		case 'n': if (xdg_parse_u64(a, n, 1u << 24, &o->messages)) return -EINVAL; break;
		case 'W':
			if (xdg_parse_u64(a, n, XDEV_EXT_XDOMAIN_MAX_WINDOW, &v) || !v)
				return -EINVAL;
			o->window = (int)v;
			break;
		case 'S': if (xdg_parse_u64(a, n, UINT32_MAX, &o->seed)) return -EINVAL; break;
		case 'g': o->gpu_bdf = a; break;
		case 'c': o->ce_dev = a; break;
		case 'v': o->service = a; break;
		case 'y': o->sysfs_root = a; break;
		case 'k': if (xdg_parse_u64(a, n, UINT64_MAX, &o->link_token) || !o->link_token) return -EINVAL; break;
		case 'e': o->early = true; break;
		case 't': if (xdg_parse_u64(a, n, 3600000, &v) || !v) return -EINVAL; o->timeout_ms = (int)v; break;
		case 'd': o->dry_run = true; break;
		default: return -EINVAL;
		}
	}
	if (optind != argc || o->rank < 0 || (o->rank == 0) != !!o->peer ||
	    (o->rank == 1) != !!o->listen || !o->gpu_bdf || !o->ce_dev ||
	    !o->service == !o->link_token)
		return -EINVAL;
	o->nsizes = xdg_parse_sizes(o->sizes_arg, o->sizes);
	return o->nsizes < 0 ? -EINVAL : 0;
}

static int make_plan(const struct opts *o, uint64_t size, struct plan *p)
{
	int ret;

	memset(p, 0, sizeof(*p));
	p->size = size;
	ret = xdg_split(size, &p->group, &p->groups);
	if (ret)
		return ret;
	if (o->mode == MODE_PINGPONG) {
		p->depth = p->window = p->groups;
		p->messages = 1;
	} else {
		p->depth = p->window = (uint64_t)o->window;
		p->messages = o->messages ? o->messages : (256ULL << 20) / size;
		/* Every RX slot must be written for the oracle. */
		if (p->messages * p->groups < p->depth)
			p->messages = (p->depth + p->groups - 1) / p->groups;
	}
	if (p->window > XDEV_EXT_XDOMAIN_MAX_WINDOW || p->depth > 64)
		return -E2BIG;
	p->frames_per_group = (p->group + FRAME - 1) / FRAME;
	p->ring_frames = p->depth * p->frames_per_group;
	p->win_bytes = p->depth * p->group;
	p->batches = p->messages * p->groups;
	return 0;
}

static void plan_json(const struct plan *p)
{
	printf("\"group_bytes\": %" PRIu64 ", \"groups_per_message\": %" PRIu64 ", \"depth\": %"
	       PRIu64 ", \"window\": %" PRIu64 ", \"frames_per_group\": %" PRIu64
	       ", \"ring_frames\": %" PRIu64 ", \"vram_window_bytes\": %" PRIu64,
	       p->group, p->groups, p->depth, p->window, p->frames_per_group, p->ring_frames,
	       p->win_bytes);
}

/* --- CUDA (untimed seeding and checks) ------------------------------------ */

static int cuda_copy(struct dir *d, uint64_t off, void *buf, uint64_t n, bool to_device)
{
	int (*htod)(uint64_t, const void *, size_t);
	int (*dtoh)(void *, uint64_t, size_t);
	void *previous = NULL;
	int ret, r;

	*(void **)&htod = dlsym(d->cuda.lib, "cuMemcpyHtoD_v2");
	*(void **)&dtoh = dlsym(d->cuda.lib, "cuMemcpyDtoH_v2");
	if (!htod || !dtoh)
		return -ENOSYS;
	if (d->cuda.ctx_get(&previous) || d->cuda.ctx_set(d->cuda.ctx))
		return -EIO;
	ret = to_device ? htod(d->cuda.va + off, buf, n) : dtoh(buf, d->cuda.va + off, n);
	r = d->cuda.ctx_set(previous);
	return ret || r ? -EIO : 0;
}

static int seed_tx(struct run *r, const struct plan *p, uint64_t seed)
{
	int ret = 0;

	for (uint64_t s = 0; s < p->depth && !ret; s++) {
		xdg_fill(r->scratch, p->group, seed, s);
		ret = cuda_copy(&r->tx, s * p->group, r->scratch, p->group, true);
	}
	return ret;
}

/* Every RX slot holds a distinct whole image of a sender slot. */
static int check_rx(struct run *r, const struct plan *p, uint64_t seed, bool *ok)
{
	int ids[64], ret = 0;

	for (uint64_t s = 0; s < p->depth && !ret; s++) {
		ret = cuda_copy(&r->rx, s * p->group, r->scratch, p->group, false);
		ids[s] = ret ? -1 : xdg_identify(r->scratch, p->group, seed, (int)p->depth);
	}
	*ok = !ret && !xdg_slot_oracle(ids, (int)p->depth);
	return ret;
}

/* --- sessions -------------------------------------------------------------- */

static int open_dir(struct run *r, struct dir *d)
{
	struct xdev_ext_nv_ce_attach_memory attach = { 0 };
	int ret = xdev_ext_mech_cuda_open_vmm(&d->cuda, r->o.gpu_bdf, r->max_win);

	if (ret)
		return ret;
	ret = xdev_ext_mech_cuda_window(&d->cuda, NULL, POISON, d->cuda.vmm_bytes);
	if (ret)
		return ret;
	d->ce_fd = open(r->o.ce_dev, O_RDWR | O_CLOEXEC);
	if (d->ce_fd < 0)
		return -errno;
	attach = (struct xdev_ext_nv_ce_attach_memory){ .mem_fd = d->cuda.export_fd,
		.gpu_va = d->cuda.va, .size = d->cuda.vmm_bytes };
	if (xdev_ext_nv_ce_attach_memory(d->ce_fd, &attach)) {
		ret = errno ? -errno : -EIO;
		fprintf(stderr, "xdomain_gpu: CE attach status 0x%x\n", attach.status);
		return ret;
	}
	return 0;
}

static int create(struct run *r, struct dir *d, const struct plan *p, bool tx)
{
	struct xdev_ext_pool_opts umem = { .sz = sizeof(umem),
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM, .nr_frames = (__u32)p->ring_frames };
	struct xdev_ext_create_opts c = { .sz = sizeof(c) };
	struct xdev_ext_mech_create_report report;
	struct xdev_ext_mech_stage_uapi ce = { .class_id = XDEV_EXT_MECH_CLASS_CE,
		.direction = tx ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE,
		.fd = d->ce_fd, .arg0 = d->cuda.va, .arg1 = p->win_bytes };
	unsigned xi = tx ? 1 : 0;
	int fds[2] = { -1, -1 }, ret;

	d->done = 0;
	ret = xdev_ext_session_open(&umem, &d->s);
	if (ret)
		return ret;
	c.group_bytes = (__u32)p->group;
	c.depth = (__u32)p->depth;
	c.nr_stages = 2;
	c.layout = (struct xdev_ext_mech_layout){ .frame_size = FRAME, .hdr_room = 0,
		.seg_len = FRAME, .group_bytes = (__u32)p->group };
	ret = xdev_ext_stage_xdomain(&c.st[xi], r->ctl, r->token,
				     tx ? XDEV_EXT_MECH_DIR_TO_DEVICE : XDEV_EXT_MECH_DIR_FROM_DEVICE,
				     r->o.early ? XDEV_EXT_XDOMAIN_F_EARLY : 0);
	if (ret)
		return ret;
	c.st[xi].arg1 = p->window << XDEV_EXT_XDOMAIN_WINDOW_SHIFT;
	c.st[1 - xi] = ce;
	ret = xdev_ext_session_create_programs(d->s, &c, fds, 2, &report);
	if (ret && report.size == sizeof(report))
		fprintf(stderr, "xdomain_gpu: %s CREATE result=%d phase=%u failed_stage=%u\n",
			tx ? "TX" : "RX", report.result, report.phase, report.failed_stage);
	return ret;
}

static int close_dir_session(struct dir *d)
{
	int ret = 0, r;

	if (!d->s)
		return 0;
	r = xdev_ext_session_stop(d->s);
	ret = r;
	r = xdev_ext_session_close(d->s);
	if (r && !ret)
		ret = r;
	if (xdev_ext_session_retained(d->s))
		ret = ret ? ret : -EBUSY;
	d->s = NULL;
	return ret;
}

static int start(struct dir *d, const struct plan *p, uint64_t nr, uint64_t first_seq)
{
	static uint32_t idx[XDEV_EXT_MAX_FRAMES];
	struct xdev_ext_start_frames_opts so = { .sz = sizeof(so), .nr_batches = nr,
		.first_seq = first_seq, .indices = idx, .nr_indices = (__u32)p->ring_frames,
		.flags = XDEV_EXT_MECH_START_F_RECYCLE };

	for (uint32_t i = 0; i < p->ring_frames; i++)
		idx[i] = i;
	return xdev_ext_session_start_frames(d->s, &so);
}

/* Wait for the START's final notification; every batch done, nothing lost. */
static int wait_done(struct run *r, struct dir *d, uint64_t nr, struct xdev_ext_mech_stats *st)
{
	int ret = xdev_ext_session_wait(d->s, r->o.timeout_ms, st);

	if (ret)
		return ret;
	if (st->batches_done != d->done + nr || st->batches_abort || st->sequestered ||
	    st->inflight || st->last_err)
		return st->last_err ? st->last_err : -EIO;
	d->done = st->batches_done;
	return 0;
}

static void common_json(const struct run *r, const struct plan *p, const char *role)
{
	printf("{\"tool\": \"xdomain_gpu\", \"arm\": \"xdev-ext\", \"rank\": %d, \"role\": \"%s\", "
	       "\"mode\": \"%s\", \"size\": %" PRIu64 ", \"ce_mode\": \"slot\", "
	       "\"payload_path\": \"vram>ce-d2h>host-frame>xdomain>host-frame>ce-h2d>vram\", "
	       "\"cpu_copy_bytes\": 0, \"early\": %s, \"execution\": \"xdev-ext-session\", "
	       "\"performance_claim\": \"needs-bare-metal-two-host-qualification\", ",
	       r->o.rank, role, r->o.mode == MODE_PINGPONG ? "pingpong" : "stream", p->size,
	       r->o.early ? "true" : "false");
	plan_json(p);
}

static int exchange_ok(struct run *r, bool ok, bool *peer)
{
	uint8_t mine = ok, theirs = 0;
	int ret = xdg_send_all(r->fd, &mine, 1);

	if (!ret)
		ret = xdg_recv_all(r->fd, &theirs, 1);
	*peer = theirs;
	return ret;
}

static int pingpong(struct run *r, const struct plan *p)
{
	uint64_t total = r->o.warmup + r->o.iters, *rtt = NULL, g = p->groups;
	uint64_t mine = r->o.seed + (uint64_t)r->o.rank, theirs = r->o.seed + (uint64_t)(1 - r->o.rank);
	struct xdev_ext_mech_stats st_tx = { 0 }, st_rx = { 0 };
	struct xdg_stats st = { 0 };
	bool ok = false, peer = false;
	int ret;

	ret = seed_tx(r, p, mine);
	if (!ret && r->o.rank == 0 && !(rtt = calloc(r->o.iters, sizeof(*rtt))))
		ret = -ENOMEM;
	if (!ret && r->o.rank == 1)
		ret = start(&r->rx, p, g, 1);	/* first receive posted before the barrier */
	if (!ret)
		ret = xdg_barrier(r->fd, 'P');
	for (uint64_t i = 0; i < total && !ret; i++) {
		uint64_t seq = 1 + i * g, t0;

		if (r->o.rank == 0) {
			ret = start(&r->rx, p, g, seq);
			t0 = xdg_now_ns();
			if (!ret)
				ret = start(&r->tx, p, g, seq);
			if (!ret)
				ret = wait_done(r, &r->rx, g, &st_rx);
			if (!ret && i >= r->o.warmup)
				rtt[i - r->o.warmup] = xdg_now_ns() - t0;
			if (!ret)
				ret = wait_done(r, &r->tx, g, &st_tx);
		} else {
			ret = wait_done(r, &r->rx, g, &st_rx);
			if (!ret)
				ret = start(&r->tx, p, g, seq);
			if (!ret && i + 1 < total)
				ret = start(&r->rx, p, g, seq + g);
			if (!ret)
				ret = wait_done(r, &r->tx, g, &st_tx);
		}
	}
	if (!ret)
		ret = check_rx(r, p, theirs, &ok);
	if (!ret)
		ret = exchange_ok(r, ok, &peer);
	if (!ret) {
		common_json(r, p, r->o.rank ? "echo" : "initiator");
		if (r->o.rank == 0) {
			xdg_stats(rtt, r->o.iters, &st);
			printf(", \"warmup\": %" PRIu64 ", \"clock\": \"CLOCK_MONOTONIC rank 0\", "
			       "\"rtt_ns\": {\"n\": %" PRIu64 ", \"min\": %" PRIu64 ", \"median\": %"
			       PRIu64 ", \"p99\": %" PRIu64 ", \"max\": %" PRIu64
			       "}, \"half_rtt_ns_median\": %" PRIu64, r->o.warmup, st.n, st.min,
			       st.median, st.p99, st.max, st.median / 2);
		}
		printf(", \"tx_batches_done\": %" PRIu64 ", \"rx_batches_done\": %" PRIu64
		       ", \"verified\": %s, \"peer_verified\": %s}\n", (uint64_t)st_tx.batches_done,
		       (uint64_t)st_rx.batches_done, ok ? "true" : "false", peer ? "true" : "false");
		fflush(stdout);
	}
	free(rtt);
	return ret ? ret : ok && peer ? 0 : -EIO;
}

static int stream(struct run *r, const struct plan *p)
{
	struct xdev_ext_mech_stats st = { 0 };
	uint64_t t0 = 0, t1 = 0;
	uint8_t go = 0;
	bool ok = true, peer = true;
	int ret = r->o.rank == 0 ? seed_tx(r, p, r->o.seed) : 0;

	if (!ret)
		ret = xdg_barrier(r->fd, 'S');
	if (r->o.rank == 1) {
		if (!ret)
			ret = start(&r->rx, p, p->batches, 1);
		if (!ret)
			ret = xdg_send_all(r->fd, "G", 1);
		t0 = xdg_now_ns();
		if (!ret)
			ret = wait_done(r, &r->rx, p->batches, &st);
		t1 = xdg_now_ns();
		if (!ret)
			ret = check_rx(r, p, r->o.seed, &ok);
	} else {
		if (!ret)
			ret = xdg_recv_all(r->fd, &go, 1);
		if (!ret && go != 'G')
			ret = -EPROTO;
		t0 = xdg_now_ns();
		if (!ret)
			ret = start(&r->tx, p, p->batches, 1);
		if (!ret)
			ret = wait_done(r, &r->tx, p->batches, &st);
		t1 = xdg_now_ns();
	}
	if (!ret)
		ret = exchange_ok(r, ok, &peer);
	if (!ret) {
		uint64_t bytes = p->messages * p->size;

		common_json(r, p, r->o.rank ? "receiver" : "sender");
		printf(", \"messages\": %" PRIu64 ", \"batches_done\": %" PRIu64, p->messages,
		       (uint64_t)st.batches_done);
		if (r->o.rank == 1)
			printf(", \"clock\": \"CLOCK_MONOTONIC rank 1 (receiver)\", \"elapsed_ns\": %"
			       PRIu64 ", \"verified\": %s, \"verified_bytes\": %" PRIu64
			       ", \"gbps\": %.6f", t1 - t0, ok ? "true" : "false", ok ? bytes : 0,
			       ok ? xdg_gbps(bytes, t1 - t0) : 0.0);
		else
			printf(", \"sender_elapsed_ns\": %" PRIu64 ", \"peer_verified\": %s", t1 - t0,
			       peer ? "true" : "false");
		printf("}\n");
		fflush(stdout);
	}
	return ret ? ret : ok && peer ? 0 : -EIO;
}

static int link_token(struct run *r)
{
	struct xdev_ext_link_snapshot snap;
	int ret;

	if (r->o.link_token) {
		r->token = r->o.link_token;
	} else {
		ret = xdev_ext_link_read(r->o.sysfs_root, r->o.service, &snap);
		if (ret)
			return ret;
		r->token = snap.token;
	}
	return xdev_ext_link_discover(r->o.sysfs_root, r->token, &snap);
}

static bool capability(int err)
{
	return err == -ENOENT || err == -ENODEV || err == -ENXIO || err == -ENOSYS ||
	       err == -EOPNOTSUPP || err == -ENOLINK || err == -EACCES || err == -EPERM;
}

int main(int argc, char **argv)
{
	struct run r = { .ctl = -1, .fd = -1, .tx.ce_fd = -1, .rx.ce_fd = -1 };
	struct rlimit lim = { RLIM_INFINITY, RLIM_INFINITY };
	struct plan p;
	char config[512];
	const char *step = "options";
	int ret = 0, i, closed;

	if (parse(argc, argv, &r.o)) {
		usage();
		return XDG_EXIT_USAGE;
	}
	for (i = 0; i < r.o.nsizes; i++) {
		if (make_plan(&r.o, r.o.sizes[i], &p)) {
			usage();
			return XDG_EXIT_USAGE;
		}
		if (p.win_bytes > r.max_win)
			r.max_win = p.win_bytes;
		if (r.o.dry_run) {
			printf("{\"tool\": \"xdomain_gpu\", \"dry_run\": true, \"rank\": %d, \"mode\": "
			       "\"%s\", \"size\": %" PRIu64 ", \"messages\": %" PRIu64
			       ", \"batches_per_start\": %" PRIu64 ", ", r.o.rank,
			       r.o.mode == MODE_PINGPONG ? "pingpong" : "stream", p.size, p.messages,
			       p.batches);
			plan_json(&p);
			printf("}\n");
		}
	}
	if (r.o.dry_run)
		return XDG_EXIT_PASS;
	setrlimit(RLIMIT_MEMLOCK, &lim);
	r.scratch = malloc(XDG_MAX_GROUP);
	step = "open /dev/xdev_ext_peer";
	r.ctl = r.scratch ? open("/dev/xdev_ext_peer", O_RDWR | O_CLOEXEC) : -1;
	ret = r.ctl < 0 ? -errno : 0;
	if (!ret) {
		step = "XDOMAIN link";
		ret = link_token(&r);
	}
	if (!ret) {
		step = "TX CUDA VMM and CE attach";
		ret = open_dir(&r, &r.tx);
	}
	if (!ret) {
		step = "RX CUDA VMM and CE attach";
		ret = open_dir(&r, &r.rx);
	}
	if (ret) {
		fprintf(stderr, "xdomain_gpu: %s: %s\n", step, strerror(-ret));
		ret = capability(ret) ? XDG_EXIT_UNAVAILABLE : XDG_EXIT_FAIL;
		goto out;
	}
	step = "control connection";
	r.fd = xdg_tcp_open(r.o.rank ? r.o.listen : r.o.peer, r.o.rank, r.o.timeout_ms / 1000 + 1);
	ret = r.fd < 0 ? r.fd : 0;
	snprintf(config, sizeof(config), "xdomain_gpu v1 mode=%d sizes=%s iters=%" PRIu64
		 " warmup=%" PRIu64 " messages=%" PRIu64 " window=%d seed=%" PRIu64 " early=%d",
		 r.o.mode, r.o.sizes_arg ? r.o.sizes_arg : "default", r.o.iters, r.o.warmup,
		 r.o.messages, r.o.window, r.o.seed, r.o.early);
	if (!ret)
		ret = xdg_exchange_config(r.fd, config);
	for (i = 0; i < r.o.nsizes && !ret; i++) {
		make_plan(&r.o, r.o.sizes[i], &p);
		step = "CREATE";
		/* Receivers first, then a barrier, then senders. */
		ret = create(&r, &r.rx, &p, false);
		if (!ret)
			ret = xdg_barrier(r.fd, 'C');
		if (!ret)
			ret = create(&r, &r.tx, &p, true);
		if (!ret)
			ret = xdg_barrier(r.fd, 'T');
		if (ret) {
			fprintf(stderr, "xdomain_gpu: size %" PRIu64 ": %s: %s\n", p.size, step,
				strerror(-ret));
			ret = capability(ret) ? -ENOSYS : ret;
			break;
		}
		step = "run";
		ret = r.o.mode == MODE_PINGPONG ? pingpong(&r, &p) : stream(&r, &p);
		closed = close_dir_session(&r.tx);
		ret = ret ? ret : closed;
		closed = close_dir_session(&r.rx);
		ret = ret ? ret : closed;
		if (ret)
			fprintf(stderr, "xdomain_gpu: size %" PRIu64 ": %s\n", p.size, strerror(-ret));
	}
	ret = ret == -ENOSYS ? XDG_EXIT_UNAVAILABLE : ret ? XDG_EXIT_FAIL : XDG_EXIT_PASS;
out:
	closed = close_dir_session(&r.tx) | close_dir_session(&r.rx);
	if (closed && ret == XDG_EXIT_PASS)
		ret = XDG_EXIT_FAIL;
	if (r.fd >= 0)
		close(r.fd);
	for (i = 0; i < 2; i++) {
		struct dir *d = i ? &r.rx : &r.tx;

		if (d->ce_fd >= 0)
			close(d->ce_fd);
		if (d->cuda.lib && xdev_ext_mech_cuda_close(&d->cuda) && ret == XDG_EXIT_PASS)
			ret = XDG_EXIT_FAIL;
	}
	if (r.ctl >= 0)
		close(r.ctl);
	free(r.scratch);
	return ret;
}
