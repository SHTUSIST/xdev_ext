// SPDX-License-Identifier: GPL-2.0
/*
 * Guest driver of libxdev_ext over an IOU_UMEM pool (the ring's own UMEM),
 * against the real kernel.  It prints what the library reports; the
 * destination bytes are checked by the host validator from the raw image.
 * Correctness only, no timing is measured.
 *
 *   xdev_ext_lib_iou --kind single|threads|procs|retain|zombie --name N
 *	--nvme-obj nxp_mech.bpf.o --ce-obj ce_plan.bpf.o --ce-dev DEV
 *	--src-ng NG --dst-ng NG --groups G --depth D --group-bytes B
 *	--slba1 S --dst-slba1 S [--slba2 S --dst-slba2 S] --timeout-ms T
 *
 * single   NVMe READ -> NVMe WRITE, step API with xdev_ext_session_wait()
 * threads  two handles of one process, one per thread, started together
 * procs    two processes, one handle each, started together
 * retain   NVMe -> CE -> CE -> NVMe with the CE stand-in completing late
 *	    (its delay_us set by the caller beyond the kernel drain bound):
 *	    STOP must report -EBUSY, close must keep the handle while the
 *	    kernel holds the session and succeed once the kernel released it
 * zombie   the same chain with the CE stand-in reporting ambiguous
 *	    outcomes: the kernel keeps the session for good, so close must
 *	    keep refusing (a deliberate leak, SPEC section 5)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "libxdev_ext.h"

#define LBA 512U
#define CE_LEN 65536U
#define RETAIN_CE_VA 0U
#define ZOMBIE_CE_VA 1048576U

struct args {
	const char *kind, *name, *nvme_obj, *ce_obj, *ce_dev, *src_ng, *dst_ng;
	__u64 groups, slba[2], dst_slba[2];
	__u32 depth, group_bytes;
	int timeout_ms, windows;
};

struct run {
	const struct args *a;
	int idx, src, dst, ce[2];
	pthread_barrier_t *barrier;	/* threads: start together */
	int go_fd;			/* procs: read one byte, then START */
	int ret, wait_err, stop_err, close_err;
	bool retained;
	__u64 session;
	struct xdev_ext_mech_stats st;
};

static void print_stats(const char *tag, const struct run *r, const char *phase)
{
	const struct xdev_ext_mech_stats *s = &r->st;

	printf("XDEV_EXT_LIB_IOU_STATS name=%s idx=%d phase=%s tag=%s session=%llu state=%u last_err=%d batches_done=%llu batches_abort=%llu rejects=%llu sequestered=%llu timeouts=%llu inflight=%llu protocol_err=%llu submitted=%llu/%llu/%llu/%llu completed=%llu/%llu/%llu/%llu\n",
	       r->a->name, r->idx, phase, tag, (unsigned long long)r->session, s->state, s->last_err,
	       (unsigned long long)s->batches_done, (unsigned long long)s->batches_abort,
	       (unsigned long long)s->rejects, (unsigned long long)s->sequestered,
	       (unsigned long long)s->timeouts, (unsigned long long)s->inflight,
	       (unsigned long long)s->protocol_err,
	       (unsigned long long)s->submitted[0], (unsigned long long)s->submitted[1],
	       (unsigned long long)s->submitted[2], (unsigned long long)s->submitted[3],
	       (unsigned long long)s->completed[0], (unsigned long long)s->completed[1],
	       (unsigned long long)s->completed[2], (unsigned long long)s->completed[3]);
	fflush(stdout);
}

static void print_result(const struct run *r)
{
	printf("XDEV_EXT_LIB_IOU_RESULT name=%s idx=%d session=%llu ret=%d wait_err=%d stop_err=%d close_err=%d retained=%d\n",
	       r->a->name, r->idx, (unsigned long long)r->session, r->ret, r->wait_err,
	       r->stop_err, r->close_err, r->retained);
	fflush(stdout);
}

static __u64 now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000 + (__u64)ts.tv_nsec / 1000000;
}

static bool ce_chain(const struct args *a)
{
	return !strcmp(a->kind, "retain") || !strcmp(a->kind, "zombie");
}

static void stages(const struct run *r, struct xdev_ext_create_opts *c)
{
	const struct args *a = r->a;
	__u64 nlb = a->groups * a->group_bytes / LBA;
	__u32 n = 0, va = !strcmp(a->kind, "zombie") ? ZOMBIE_CE_VA : RETAIN_CE_VA;

	c->st[n++] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = r->src,
		.arg0 = a->slba[r->idx], .arg1 = nlb };
	if (ce_chain(a)) {
		c->st[n++] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_CE,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = r->ce[0],
			.arg0 = va, .arg1 = CE_LEN };
		c->st[n++] = (struct xdev_ext_mech_stage_uapi) {
			.class_id = XDEV_EXT_MECH_CLASS_CE,
			.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = r->ce[1],
			.arg0 = va, .arg1 = CE_LEN };
	}
	c->st[n++] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = r->dst,
		.arg0 = a->dst_slba[r->idx], .arg1 = nlb };
	c->nr_stages = n;
}

static int open_fds(struct run *r)
{
	r->src = open(r->a->src_ng, O_RDONLY | O_CLOEXEC);
	r->dst = open(r->a->dst_ng, O_RDWR | O_CLOEXEC);
	r->ce[0] = r->ce[1] = -1;
	if (ce_chain(r->a)) {
		r->ce[0] = open(r->a->ce_dev, O_RDWR | O_CLOEXEC);
		r->ce[1] = open(r->a->ce_dev, O_RDWR | O_CLOEXEC);
	}
	if (r->src < 0 || r->dst < 0 || (ce_chain(r->a) && (r->ce[0] < 0 || r->ce[1] < 0)))
		return -errno;
	return 0;
}

static void close_fds(struct run *r)
{
	int *fds[] = { &r->src, &r->dst, &r->ce[0], &r->ce[1] };
	unsigned int i;

	for (i = 0; i < 4; i++)
		if (*fds[i] >= 0) {
			close(*fds[i]);
			*fds[i] = -1;
		}
}

static int setup(struct run *r, struct xdev_ext_session **x)
{
	struct xdev_ext_pool_opts pool = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM);
	struct xdev_ext_create_opts c = XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
		.group_bytes = r->a->group_bytes, .depth = r->a->depth);
	int ret;

	ret = open_fds(r);
	if (ret)
		return ret;
	ret = xdev_ext_session_open(&pool, x);
	if (ret)
		return ret;
	stages(r, &c);
	ret = xdev_ext_session_create(*x, &c);
	if (ret)
		return ret;
	r->session = xdev_ext_session_id(*x);
	return xdev_ext_session_arm(*x, r->a->groups, 0);
}

static int start(struct run *r, struct xdev_ext_session *x)
{
	struct xdev_ext_start_opts st = XDEV_EXT_OPTS_INIT(xdev_ext_start_opts,
		.nr_batches = r->a->groups);

	return xdev_ext_session_start(x, &st);
}

/* single, threads, procs: the whole step sequence of one handle. */
static void *run_exact(void *arg)
{
	struct run *r = arg;
	struct xdev_ext_session *x = NULL;
	char go;

	r->ret = setup(r, &x);
	if (r->barrier)
		pthread_barrier_wait(r->barrier);	/* also on failure: never strand the peer */
	if (r->go_fd >= 0 && read(r->go_fd, &go, 1) != 1 && !r->ret)
		r->ret = -EPIPE;
	if (!r->ret)
		r->ret = start(r, x);
	if (!r->ret) {
		r->wait_err = xdev_ext_session_wait(x, r->a->timeout_ms, &r->st);
		r->ret = r->wait_err;
		print_stats("wait", r, "wait");
	}
	if (x && xdev_ext_session_id(x)) {
		r->stop_err = xdev_ext_session_stop(x);
		if (!r->ret)
			r->ret = r->stop_err;
	}
	r->retained = x && xdev_ext_session_retained(x);
	if (x) {
		r->close_err = xdev_ext_session_close(x);
		if (!r->ret)
			r->ret = r->close_err;
	}
	if (!r->close_err)
		close_fds(r);
	print_result(r);
	return NULL;
}

/* Poll STATS until the predicate holds or the deadline passes. */
static int stats_until(struct run *r, struct xdev_ext_session *x, int ms,
		       bool (*pred)(const struct xdev_ext_mech_stats *))
{
	__u64 deadline = now_ms() + (__u64)ms;
	int ret;

	for (;;) {
		ret = xdev_ext_session_stats(x, &r->st);
		if (ret || pred(&r->st))
			return ret;
		if (now_ms() >= deadline)
			return -ETIMEDOUT;
		usleep(10000);
	}
}

static bool ce_in_flight(const struct xdev_ext_mech_stats *s)
{
	return s->inflight && s->submitted[1] && s->submitted[1] > s->completed[1];
}

static bool not_active(const struct xdev_ext_mech_stats *s)
{
	return s->state != XDEV_EXT_MECH_SESSION_ACTIVE || s->sequestered;
}

/*
 * retain: STOP while the CE stand-in holds accepted transfers past the
 * kernel's drain bound.  The kernel keeps the session (STOP -EBUSY), and the
 * last late completion releases it; close must follow exactly that.
 */
static int run_retain(struct run *r)
{
	struct xdev_ext_session *x = NULL;
	__u64 deadline;
	int ret, tries = 0, held;

	ret = setup(r, &x);
	if (!ret)
		ret = start(r, x);
	if (!ret)
		ret = stats_until(r, x, r->a->timeout_ms, ce_in_flight);
	print_stats("before-stop", r, "before-stop");
	if (ret)
		goto out;
	r->stop_err = xdev_ext_session_stop(x);
	r->retained = xdev_ext_session_retained(x);
	printf("XDEV_EXT_LIB_RETAIN name=%s phase=stop stop=%d retained=%d\n",
	       r->a->name, r->stop_err, r->retained);
	ret = xdev_ext_session_stats(x, &r->st);
	printf("XDEV_EXT_LIB_RETAIN name=%s phase=stats-after-stop stats=%d\n", r->a->name, ret);
	if (!ret)
		print_stats("after-stop", r, "after-stop");
	held = xdev_ext_session_close(x);
	printf("XDEV_EXT_LIB_RETAIN name=%s phase=close-held close=%d\n", r->a->name, held);
	if (!held) {
		x = NULL;
		r->ret = -EPROTO;	/* released although accepted transfers were pending */
		goto out_print;
	}
	deadline = now_ms() + (__u64)r->a->timeout_ms;
	do {
		usleep(100000);
		tries++;
		r->close_err = xdev_ext_session_close(x);
	} while (r->close_err == -EBUSY && now_ms() < deadline);
	printf("XDEV_EXT_LIB_RETAIN name=%s phase=released close=%d tries=%d\n",
	       r->a->name, r->close_err, tries);
	if (!r->close_err)
		x = NULL;
	r->ret = r->stop_err == -EBUSY && r->retained && held == -EBUSY ? r->close_err : -EPROTO;
	goto out_print;
out:
	r->ret = ret;
	if (x) {
		r->stop_err = xdev_ext_session_stop(x);
		r->close_err = xdev_ext_session_close(x);
		if (!r->close_err)
			x = NULL;
	}
out_print:
	if (!x)
		close_fds(r);
	print_result(r);
	return r->ret;
}

/*
 * zombie: the CE stand-in reports every transfer as run-but-outcome-lost.
 * The kernel sequesters, STOP quarantines (-EBUSY), STATS shows ZOMBIE, and
 * close keeps every resource because a device may still use the frames.
 */
static int run_zombie(struct run *r)
{
	struct xdev_ext_session *x = NULL;
	int ret, stats_ret, close1, close2;

	ret = setup(r, &x);
	if (!ret)
		ret = start(r, x);
	if (ret)
		goto fail;
	r->wait_err = xdev_ext_session_wait(x, r->a->timeout_ms, &r->st);
	print_stats("wait", r, "wait");
	ret = stats_until(r, x, r->a->timeout_ms, not_active);
	print_stats("error", r, "error");
	if (ret)
		goto fail;
	r->stop_err = xdev_ext_session_stop(x);
	r->retained = xdev_ext_session_retained(x);
	stats_ret = xdev_ext_session_stats(x, &r->st);
	printf("XDEV_EXT_LIB_ZOMBIE name=%s phase=stop stop=%d retained=%d stats=%d\n",
	       r->a->name, r->stop_err, r->retained, stats_ret);
	if (!stats_ret)
		print_stats("after-stop", r, "after-stop");
	close1 = xdev_ext_session_close(x);
	usleep(2000000);	/* not a timing result: a later close sees the same */
	close2 = close1 ? xdev_ext_session_close(x) : 0;
	stats_ret = close2 ? xdev_ext_session_stats(x, &r->st) : -ENOTCONN;
	printf("XDEV_EXT_LIB_ZOMBIE name=%s phase=close close1=%d close2=%d stats=%d\n",
	       r->a->name, close1, close2, stats_ret);
	if (!stats_ret)
		print_stats("after-close", r, "after-close");
	r->close_err = close2;
	/* The retained handle, its fds and the borrowed stage fds are kept. */
	r->ret = r->wait_err && r->stop_err == -EBUSY && r->retained &&
		 close1 == -EBUSY && close2 == -EBUSY ? 0 : -EPROTO;
	print_result(r);
	return r->ret;
fail:
	r->ret = ret;
	print_result(r);
	return ret;
}

static int attach(const struct args *a, struct xdev_ext_prog *p[2])
{
	struct xdev_ext_prog_global g = { "nvme_mode", 0 };
	struct xdev_ext_prog_opts nvme = XDEV_EXT_OPTS_INIT(xdev_ext_prog_opts,
		.obj_path = a->nvme_obj, .map_name = "nxp_nvme_ops", .globals = &g,
		.nr_globals = 1);
	struct xdev_ext_prog_opts ce = XDEV_EXT_OPTS_INIT(xdev_ext_prog_opts,
		.obj_path = a->ce_obj, .map_name = "ce_plan_ops");
	int ret = xdev_ext_prog_attach(&nvme, &p[0]);

	if (!ret && ce_chain(a))
		ret = xdev_ext_prog_attach(&ce, &p[1]);
	return ret;
}

static int run_pair(const struct args *a)
{
	struct run r[2];
	pthread_barrier_t barrier;
	pthread_t t[2];
	int i, ret = 0;

	pthread_barrier_init(&barrier, NULL, 2);
	for (i = 0; i < 2; i++) {
		r[i] = (struct run){ .a = a, .idx = i, .barrier = &barrier, .go_fd = -1 };
		if (pthread_create(&t[i], NULL, run_exact, &r[i]))
			return -EAGAIN;
	}
	for (i = 0; i < 2; i++) {
		pthread_join(t[i], NULL);
		if (!ret)
			ret = r[i].ret;
	}
	pthread_barrier_destroy(&barrier);
	if (!ret && r[0].session == r[1].session)
		ret = -EPROTO;
	return ret;
}

static int run_procs(const struct args *a)
{
	int go[2], i, status, ret = 0;
	pid_t pid[2];

	if (pipe2(go, O_CLOEXEC))
		return -errno;
	fflush(stdout);
	for (i = 0; i < 2; i++) {
		pid[i] = fork();
		if (pid[i] < 0)
			return -errno;
		if (!pid[i]) {
			struct run r = { .a = a, .idx = i, .go_fd = go[0] };

			close(go[1]);
			run_exact(&r);
			fflush(stdout);
			_exit(r.ret ? 1 : 0);
		}
	}
	close(go[0]);
	/* Both children CREATE first; each START waits for its byte. */
	if (write(go[1], "gg", 2) != 2)
		ret = -EPIPE;
	close(go[1]);
	for (i = 0; i < 2; i++) {
		if (waitpid(pid[i], &status, 0) != pid[i])
			return -errno;
		printf("XDEV_EXT_LIB_IOU_CHILD name=%s idx=%d exit=%d\n", a->name, i,
		       WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
		if (!ret && !(WIFEXITED(status) && !WEXITSTATUS(status)))
			ret = -EIO;
	}
	return ret;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "kind", 1, 0, 'k' }, { "name", 1, 0, 'N' }, { "nvme-obj", 1, 0, 'o' },
		{ "ce-obj", 1, 0, 'O' }, { "ce-dev", 1, 0, 'c' }, { "src-ng", 1, 0, 's' },
		{ "dst-ng", 1, 0, 'd' }, { "groups", 1, 0, 'g' }, { "depth", 1, 0, 'D' },
		{ "group-bytes", 1, 0, 'b' }, { "slba1", 1, 0, '1' }, { "dst-slba1", 1, 0, '2' },
		{ "slba2", 1, 0, '3' }, { "dst-slba2", 1, 0, '4' }, { "timeout-ms", 1, 0, 't' },
		{ 0, 0, 0, 0 } };
	struct xdev_ext_prog *prog[2] = { NULL, NULL };
	struct args a = { .timeout_ms = 60000 };
	int c, ret, i;

	setvbuf(stdout, NULL, _IOLBF, 0);
	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case 'k': a.kind = optarg; break;
		case 'N': a.name = optarg; break;
		case 'o': a.nvme_obj = optarg; break;
		case 'O': a.ce_obj = optarg; break;
		case 'c': a.ce_dev = optarg; break;
		case 's': a.src_ng = optarg; break;
		case 'd': a.dst_ng = optarg; break;
		case 'g': a.groups = strtoull(optarg, NULL, 0); break;
		case 'D': a.depth = (__u32)strtoul(optarg, NULL, 0); break;
		case 'b': a.group_bytes = (__u32)strtoul(optarg, NULL, 0); break;
		case '1': a.slba[0] = strtoull(optarg, NULL, 0); a.windows |= 1; break;
		case '2': a.dst_slba[0] = strtoull(optarg, NULL, 0); a.windows |= 2; break;
		case '3': a.slba[1] = strtoull(optarg, NULL, 0); a.windows |= 4; break;
		case '4': a.dst_slba[1] = strtoull(optarg, NULL, 0); a.windows |= 8; break;
		case 't': a.timeout_ms = atoi(optarg); break;
		default: return 2;
		}
	}
	if (!a.kind || !a.name || !a.nvme_obj || !a.src_ng || !a.dst_ng || !a.groups ||
	    !a.depth || !a.group_bytes || a.group_bytes % LBA || (a.windows & 3) != 3 ||
	    (ce_chain(&a) && (!a.ce_obj || !a.ce_dev)))
		return 2;
	ret = attach(&a, prog);
	if (ret) {
		printf("XDEV_EXT_LIB_IOU_EXIT name=%s ret=%d (attach)\n", a.name, ret);
		return 1;
	}
	if (!strcmp(a.kind, "single")) {
		struct run r = { .a = &a, .go_fd = -1 };

		run_exact(&r);
		ret = r.ret;
	} else if (!strcmp(a.kind, "threads") && a.windows == 15) {
		ret = run_pair(&a);
	} else if (!strcmp(a.kind, "procs") && a.windows == 15) {
		ret = run_procs(&a);
	} else if (!strcmp(a.kind, "retain")) {
		struct run r = { .a = &a, .go_fd = -1 };

		ret = run_retain(&r);
	} else if (!strcmp(a.kind, "zombie")) {
		struct run r = { .a = &a, .go_fd = -1 };

		ret = run_zombie(&r);
	} else {
		return 2;
	}
	/* A retained zombie session owns its programs' class: keep them. */
	if (strcmp(a.kind, "zombie"))
		for (i = 2; i--;)
			if (prog[i])
				xdev_ext_prog_detach(prog[i]);
	printf("XDEV_EXT_LIB_IOU_EXIT name=%s ret=%d (%s)\n", a.name, ret, strerror(-ret));
	return ret ? 1 : 0;
}
