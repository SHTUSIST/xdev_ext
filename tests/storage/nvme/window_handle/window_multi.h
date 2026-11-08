/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GUEST TEST ONLY, included by window_guest.c: four tenants share one NVMe
 * namespace at once, each with its own program, and one of them fails.
 * Correctness only; nothing is timed beyond ordering timestamps.
 *
 * Requirement under test: several mechanism sessions, each running its own
 * program, share one namespace at the same time; each session's commands are
 * admitted only inside the LBA window of the handle the holder issued to it;
 * and one session's failure (its process killed, its program building
 * commands outside its window, an UNKNOWN command outcome, a command that
 * never completes) does not stop or corrupt the other sessions on the device.
 *
 * Devices: SRC (its own controller) holds the position-unique source. The
 * DST controller has two namespaces: ns1, the shared destination (writes
 * rate-limited by the runner), and ns2, a private source of the faulty tenant
 * (0x3c bytes; nothing from it may ever reach ns1). Fault injection is the
 * kernel's own, on ns2 only: nvme fault_inject (an error status on a command
 * QEMU completed) and fail_io_timeout (a swallowed completion). The runner
 * boots with nvme_core.io_timeout=600 so no command timeout fires on its own.
 *
 * Rounds r = 0..3 (kill, escape, unknown, timeout), four tenant processes
 * each, forked before any namespace node is opened. Tenant i of round r owns
 * ns1 window M(r, i) = 4r + i and reads SRC window M(r, i); tenant 0 is the
 * faulty one, tenants 1..3 are innocent. Each tenant loads its own BPF
 * object (own struct_ops maps, programs and links), sets up its ring as root,
 * receives a read and a write handle over SCM_RIGHTS, drops to uid 65534,
 * CREATEs, reports ready and STARTs when the holder says go:
 *
 *   kill    : tenant 0 is SIGKILLed after two batches completed, the rest of
 *             its batches still to run; its range is free once the kernel has
 *             released the session; each of its groups is exact or guard
 *   escape  : tenant 0's write stage runs escape_ops (odd keys into tenant 1's
 *             window, even keys across its own window end): every batch
 *             refused with -ERANGE, no write submitted, its window guard
 *   unknown : tenant 0 reads ns2 with an injected error status: its batches
 *             are sequestered, STOP quarantines it (-EBUSY) and its range
 *             stays reserved for good; its window guard
 *   timeout : tenant 0 reads ns2 with every completion swallowed: STOP passes
 *             the drain bound with commands in flight (-EBUSY) and its range
 *             stays reserved; after the round the holder resets the DST
 *             controller so the guest can power off (nothing else runs then)
 *
 * Innocents must complete 8/8 batches with no abort, reject, timeout or
 * sequester, STOP with 0 and be released, while the fault happens (each
 * round asserts that at least one innocent was still running at the fault),
 * and the whole-disk oracle requires every innocent window to be its exact
 * source window and every byte nobody owns to stay guard.
 */
#include <signal.h>
#include <time.h>
#include <bpf/bpf.h>

#define M_ROUNDS 4U
#define M_TENANTS 4U
#define M_AUX_FILL 0x3cU
#define M_KILL_AFTER 2U
#define M_STABLE_MS 1000

enum { R_KILL, R_ESCAPE, R_UNKNOWN, R_TIMEOUT };
static const char *const m_round_name[M_ROUNDS] = { "kill", "escape", "unknown", "timeout" };

static unsigned m_win(unsigned r, unsigned i) { return 4 * r + i; }

static __u64 now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return (__u64)t.tv_sec * 1000000000ULL + (__u64)t.tv_nsec;
}

enum { MSG_READY = 1, MSG_KILLPOINT, MSG_FINAL };
struct mmsg {
	__u32 kind;
	__u32 write_map_id, build_prog_id, write_link_id;
	__u64 t_start, t_end;
	__u64 done, abort_, rejects, sequestered, inflight, submitted0, submitted1;
	__s32 last_err, stop_ret;
	__u32 state, ok;
};

static void m_send(int sock, struct mmsg *m)
{
	if (write(sock, m, sizeof(*m)) != (ssize_t)sizeof(*m))
		_exit(5);
}

static bool m_recv(int sock, struct mmsg *m, __u32 kind)
{
	return read(sock, m, sizeof(*m)) == (ssize_t)sizeof(*m) && m->kind == kind;
}

static __u32 map_id(struct bpf_map *map)
{
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);

	return bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &len) ? 0 : info.id;
}

static __u32 prog_id(struct bpf_object *obj, const char *name)
{
	struct bpf_program *p = bpf_object__find_program_by_name(obj, name);
	struct bpf_prog_info info = {};
	__u32 len = sizeof(info);

	return !p || bpf_obj_get_info_by_fd(bpf_program__fd(p), &info, &len) ? 0 : info.id;
}

static __u32 link_id(struct bpf_link *l)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);

	return bpf_obj_get_info_by_fd(bpf_link__fd(l), &info, &len) ? 0 : info.id;
}

static void m_fill(struct mmsg *m, const struct xdev_ext_mech_stats *st)
{
	m->done = st->batches_done;
	m->abort_ = st->batches_abort;
	m->rejects = st->rejects;
	m->sequestered = st->sequestered;
	m->inflight = st->inflight;
	m->submitted0 = st->submitted[0];
	m->submitted1 = st->submitted[1];
	m->last_err = st->last_err;
	m->state = st->state;
}

/* Poll until nothing changes for M_STABLE_MS with nothing in flight, or 60 s. */
static struct xdev_ext_mech_stats wait_quiet(const struct session *s, bool need_idle)
{
	struct xdev_ext_mech_stats st, prev;
	int i, same = 0;

	memset(&prev, 0, sizeof(prev));
	for (i = 0; i < WAIT_MS / 5; i++) {
		quiet_stats(s, &st);
		if (!memcmp(&st, &prev, sizeof(st)) && (!need_idle || !st.inflight)) {
			if (++same * 5 >= M_STABLE_MS)
				break;
		} else {
			same = 0;
		}
		prev = st;
		usleep(5000);
	}
	print_stats(&st, "quiet");
	return st;
}

/* One tenant of one round; returns its exit code. */
static int m_tenant(int sock, unsigned r, unsigned i, const char *src_ng, const char *dst_ng,
		    const char *bpf_dir)
{
	bool faulty = i == 0;
	struct xdev_ext_mech_stats st;
	struct mmsg m = { .kind = MSG_READY };
	char name[32], go;
	struct session s;
	struct object o;
	int h[2];	/* read handle, write handle */
	int ret;

	snprintf(name, sizeof(name), "%s.t%u%s", m_round_name[r], i, faulty ? "-faulty" : "");
	who = name;
	if (!recv_fds(sock, h, 2)) {
		printf("# %s: no handles received\n", name);
		return 3;
	}
	object_open(bpf_dir, &o);
	ring_up(&s, o.window, faulty && r == R_ESCAPE ? o.escape : o.window);
	m.write_map_id = map_id(faulty && r == R_ESCAPE ? o.escape : o.window);
	m.build_prog_id = prog_id(o.obj, faulty && r == R_ESCAPE ? "escape_build" : "window_build");
	m.write_link_id = link_id(s.links[1]);
	drop_privileges(src_ng, dst_ng);
	CHECK_EQ(create(&s, (struct stage){ h[0], win(m_win(r, i)), WIN_NLB },
			(struct stage){ h[1], win(m_win(r, i)), WIN_NLB }), 0,
		 "CREATE inside its own handles on the shared namespace");
	CHECK(!close(h[0]) && !close(h[1]), "close its handle fds: the session holds the range");
	m_send(sock, &m);
	if (read(sock, &go, 1) != 1)
		return 3;
	memset(&m, 0, sizeof(m));
	m.t_start = now_ns();
	start(&s);

	if (!faulty) {
		st = wait_settled(&s);
		m.t_end = now_ns();
		check_exact_run(&st, "innocent: every batch completed exactly while another tenant failed");
		m_fill(&m, &st);
		stop_ok(&s, "innocent: STOP returns 0 and releases the session");
		m.ok = 1;
		goto final;
	}
	switch (r) {
	case R_KILL: {
		int k;

		for (k = 0; k < WAIT_MS; k++) {
			quiet_stats(&s, &st);
			if (st.batches_done >= M_KILL_AFTER)
				break;
			usleep(1000);
		}
		print_stats(&st, "at the kill point");
		m.kind = MSG_KILLPOINT;
		m.t_end = now_ns();
		m_fill(&m, &st);
		m_send(sock, &m);
		for (;;)
			pause();	/* the holder SIGKILLs this process */
	}
	case R_ESCAPE:
		st = wait_settled(&s);
		m.t_end = now_ns();
		CHECK(!st.batches_done && st.batches_abort == GROUPS && st.rejects == GROUPS &&
		      st.last_err == -ERANGE && !st.inflight && !st.sequestered &&
		      !st.submitted[1] && !st.completed[1] && st.state == XDEV_EXT_MECH_SESSION_ACTIVE,
		      "escape: every out-of-window WRITE refused with -ERANGE before submission");
		m_fill(&m, &st);
		stop_expect(&s, -ERANGE, "escape: STOP reports -ERANGE and releases the session");
		m.ok = 1;
		break;
	case R_UNKNOWN:
		st = wait_quiet(&s, true);
		m.t_end = now_ns();
		CHECK(st.sequestered > 0 && !st.batches_done && !st.submitted[1] && !st.inflight,
		      "unknown: the error-status READs are sequestered and no WRITE was issued");
		m_fill(&m, &st);
		ret = mech(s.ring, XDEV_EXT_MECH_OP_STOP, s.id);
		m.stop_ret = ret;
		CHECK_EQ(ret, -EBUSY, "unknown: STOP quarantines the session (-EBUSY)");
		m.ok = 1;
		break;
	case R_TIMEOUT:
		usleep(500000);
		quiet_stats(&s, &st);
		print_stats(&st, "with its completions swallowed");
		m.t_end = now_ns();
		CHECK(!st.batches_done && st.inflight > 0 && st.submitted[0] > 0 && !st.completed[0],
		      "timeout: its READs were accepted and never completed");
		m_fill(&m, &st);
		ret = mech(s.ring, XDEV_EXT_MECH_OP_STOP, s.id);
		m.stop_ret = ret;
		CHECK_EQ(ret, -EBUSY, "timeout: STOP passes the drain bound and defers the release (-EBUSY)");
		m.ok = 1;
		break;
	}
final:
	m.kind = MSG_FINAL;
	ring_down(&s);
	bpf_object__close(o.obj);
	fflush(stdout);
	m_send(sock, &m);
	return 0;
}

struct mchild { pid_t pid; int sock; };

static struct mchild m_fork(unsigned r, unsigned i, char **argv)
{
	struct mchild c;
	int sv[2];

	CHECK(!socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv), "tenant socket pair");
	fflush(stdout);
	c.pid = fork();
	if (!c.pid) {
		close(sv[0]);
		_exit(m_tenant(sv[1], r, i, argv[2], argv[4], argv[5]));
	}
	CHECK(c.pid > 0, "fork a tenant");
	close(sv[1]);
	c.sock = sv[0];
	return c;
}

static void write_file(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n = fd < 0 ? -1 : write(fd, value, strlen(value));

	if (fd >= 0)
		close(fd);
	if (n != (ssize_t)strlen(value))
		printf("# holder: write %s <- %s failed: %s\n", path, value, strerror(errno));
	CHECK(n == (ssize_t)strlen(value), path);
}

/* The fault of round @r on the faulty tenant's private namespace @disk. */
static void m_fault(unsigned r, const char *disk, bool on)
{
	char path[PATH_MAX];

	if (r == R_UNKNOWN) {
		snprintf(path, sizeof(path), "/sys/kernel/debug/%s/fault_inject/verbose", disk);
		write_file(path, "0");
		snprintf(path, sizeof(path), "/sys/kernel/debug/%s/fault_inject/times", disk);
		write_file(path, "-1");
		snprintf(path, sizeof(path), "/sys/kernel/debug/%s/fault_inject/probability", disk);
		write_file(path, on ? "100" : "0");
	} else if (r == R_TIMEOUT) {
		write_file("/sys/kernel/debug/fail_io_timeout/verbose", "0");
		write_file("/sys/kernel/debug/fail_io_timeout/times", "-1");
		write_file("/sys/kernel/debug/fail_io_timeout/probability", on ? "100" : "0");
		snprintf(path, sizeof(path), "/sys/block/%s/io-timeout-fail", disk);
		write_file(path, on ? "1" : "0");
	}
}

/* The DST controller of @disk ("nvmeXnY"): reset it and wait until live. */
static void m_reset_controller(const char *disk)
{
	char ctrl[64], path[PATH_MAX], state[32];
	int i, fd;
	ssize_t n = 0;

	snprintf(ctrl, sizeof(ctrl), "%s", disk);
	*strrchr(ctrl, 'n') = 0;
	snprintf(path, sizeof(path), "/sys/class/nvme/%s/reset_controller", ctrl);
	write_file(path, "1");
	snprintf(path, sizeof(path), "/sys/class/nvme/%s/state", ctrl);
	for (i = 0; i < 3000; i++) {
		fd = open(path, O_RDONLY | O_CLOEXEC);
		n = fd < 0 ? -1 : read(fd, state, sizeof(state) - 1);
		if (fd >= 0)
			close(fd);
		if (n > 0 && !strncmp(state, "live", 4))
			break;
		usleep(10000);
	}
	CHECK(n > 0 && !strncmp(state, "live", 4), "the DST controller is live again after the reset");
}

static bool group_is(const unsigned char *dest, const unsigned char *source, unsigned w, unsigned g)
{
	__u64 off = win(w) * LBA + (__u64)g * GROUP;

	return !memcmp(dest + off, source + off, GROUP);
}

static bool group_guard(const unsigned char *dest, unsigned w, unsigned g)
{
	__u64 off = win(w) * LBA + (__u64)g * GROUP, b;

	for (b = 0; b < GROUP; b++)
		if (dest[off + b] != GUARD)
			return false;
	return true;
}

static int multi_main(char **argv)
{
	struct mchild c[M_ROUNDS][M_TENANTS];
	struct mmsg ready[M_TENANTS], fin[M_TENANTS], kp;
	unsigned char *source, *dest, *aux;
	__u64 src_bytes, dst_bytes, aux_bytes, off, t_fault;
	int src, srcng, dst, dstng, aux_blk, auxng, status, fd, i;
	unsigned r, t, u, exact, guard, killed_done = 0, killed_exact = 0;
	const char *disk = strrchr(argv[7], '/') + 1;
	char go = 'g';

	CHECK(getenv("XDEV_EXT_WINDOW_GUEST") && !strcmp(getenv("XDEV_EXT_WINDOW_GUEST"), "1"),
	      "guest-only opt-in");
	puts("# multi: four tenants per round share the DST namespace; tenant 0 fails");
	for (r = 0; r < M_ROUNDS; r++)
		for (t = 0; t < M_TENANTS; t++)
			c[r][t] = m_fork(r, t, argv);

	src = open_ok(argv[1], O_RDONLY);
	srcng = open_ok(argv[2], O_RDWR);
	dst = open_ok(argv[3], O_RDWR);
	dstng = open_ok(argv[4], O_RDWR);
	aux_blk = open_ok(argv[7], O_RDONLY);
	auxng = open_ok(argv[8], O_RDWR);
	CHECK(!ioctl(src, BLKGETSIZE64, &src_bytes) && !ioctl(dst, BLKGETSIZE64, &dst_bytes) &&
	      !ioctl(aux_blk, BLKGETSIZE64, &aux_bytes), "disk capacities");
	CHECK(src_bytes == SPAN && dst_bytes == SPAN && aux_bytes == SPAN, "three 4 MiB namespaces");
	source = malloc(SPAN); dest = malloc(SPAN); aux = malloc(SPAN);
	CHECK(source && dest && aux, "verification buffers");
	read_disk(src, source, SPAN, "read the source disk");
	check_source(source, SPAN);
	read_disk(dst, dest, SPAN, "read the shared destination");
	for (off = 0; off < SPAN && dest[off] == GUARD; off++)
		;
	CHECK(off == SPAN, "the shared destination starts as guard bytes");

	for (r = 0; r < M_ROUNDS; r++) {
		int rh[M_TENANTS], wh[M_TENANTS];

		who = "holder";
		printf("# multi: round %s\n", m_round_name[r]);
		for (t = 0; t < M_TENANTS; t++) {
			bool private_src = t == 0 && (r == R_UNKNOWN || r == R_TIMEOUT);

			wh[t] = issue_ok(dstng, win(m_win(r, t)), WIN_NLB, RDWR,
					 "issue a tenant's write handle on the shared namespace");
			rh[t] = issue_ok(private_src ? auxng : srcng, win(m_win(r, t)), WIN_NLB, RD,
					 private_src ? "issue the faulty tenant's read handle on its own namespace"
						     : "issue a tenant's read handle on the source");
		}
		for (t = 0; t < M_TENANTS; t++) {
			int pass[2] = { rh[t], wh[t] };

			send_fds(c[r][t].sock, pass, 2, "pass a tenant its two handles");
			CHECK(!close(rh[t]) && !close(wh[t]), "the holder drops its copies");
		}
		for (t = 0; t < M_TENANTS; t++)
			CHECK(m_recv(c[r][t].sock, &ready[t], MSG_READY), "a tenant CREATEd and is ready");
		for (t = 0; t < M_TENANTS; t++) {
			printf("# multi: %s tenant %u write_map=%u build_prog=%u write_link=%u\n",
			       m_round_name[r], t, ready[t].write_map_id, ready[t].build_prog_id,
			       ready[t].write_link_id);
			for (u = 0; u < t; u++)
				CHECK(ready[t].write_map_id && ready[t].build_prog_id && ready[t].write_link_id &&
				      ready[t].write_map_id != ready[u].write_map_id &&
				      ready[t].build_prog_id != ready[u].build_prog_id &&
				      ready[t].write_link_id != ready[u].write_link_id,
				      "two tenants run distinct program instances (maps, programs, links)");
		}
		for (t = 0; t < M_TENANTS; t++)
			CHECK_EQ(issue(dstng, win(m_win(r, t)), WIN_NLB, RDWR, 0), -EBUSY,
				 "each live session reserves its range on the shared namespace");
		m_fault(r, disk, true);
		for (t = 0; t < M_TENANTS; t++)
			CHECK(write(c[r][t].sock, &go, 1) == 1, "go");

		t_fault = 0;
		if (r == R_KILL) {
			CHECK(m_recv(c[r][0].sock, &kp, MSG_KILLPOINT), "the faulty tenant reached its kill point");
			t_fault = now_ns();
			CHECK(!kill(c[r][0].pid, SIGKILL), "SIGKILL the faulty tenant");
			printf("# multi: kill point done=%llu inflight=%llu submitted_write=%llu\n",
			       (unsigned long long)kp.done, (unsigned long long)kp.inflight,
			       (unsigned long long)kp.submitted1);
			CHECK(kp.done >= M_KILL_AFTER && kp.done < GROUPS,
			      "the kill lands mid-run: some batches done, more still to run");
			killed_done = (unsigned)kp.done;
			CHECK(waitpid(c[r][0].pid, &status, 0) == c[r][0].pid && WIFSIGNALED(status) &&
			      WTERMSIG(status) == SIGKILL, "the faulty tenant died of SIGKILL");
		}
		for (t = r == R_KILL ? 1 : 0; t < M_TENANTS; t++) {
			CHECK(m_recv(c[r][t].sock, &fin[t], MSG_FINAL) && fin[t].ok, "a tenant finished its checks");
			CHECK(waitpid(c[r][t].pid, &status, 0) == c[r][t].pid && WIFEXITED(status) &&
			      !WEXITSTATUS(status), "a tenant exited 0");
		}
		m_fault(r, disk, false);
		if (r != R_KILL)
			t_fault = fin[0].t_start;	/* its faulty commands begin at its START */
		for (t = 1, u = 0; t < M_TENANTS; t++) {
			printf("# multi: overlap %s innocent %u start%+lld us end%+lld us from the fault\n",
			       m_round_name[r], t, ((long long)fin[t].t_start - (long long)t_fault) / 1000,
			       ((long long)fin[t].t_end - (long long)t_fault) / 1000);
			u += fin[t].t_end > t_fault;
		}
		CHECK(u > 0, "at least one innocent tenant was still running when the fault began");

		/* Ranges: innocents released; the faulty tenant per its fate. */
		for (t = 1; t < M_TENANTS; t++) {
			fd = issue_ok(dstng, win(m_win(r, t)), WIN_NLB, RDWR,
				      "an innocent's range is free once its session is released");
			CHECK(!close(fd), "close it");
		}
		if (r == R_KILL || r == R_ESCAPE) {
			for (i = 0; i < 3000 && (fd = issue(dstng, win(m_win(r, 0)), WIN_NLB, RDWR, 0)) == -EBUSY; i++)
				usleep(10000);
			printf("# multi: %s faulty range reserved for %d polls of 10 ms\n", m_round_name[r], i);
			CHECK(fd >= 0, "the faulty tenant's range is free once the kernel released its session");
			CHECK(!close(fd), "close it");
		} else {
			usleep(200000);
			CHECK_EQ(issue(dstng, win(m_win(r, 0)), WIN_NLB, RDWR, 0), -EBUSY,
				 "the unreleased faulty session keeps its range reserved");
		}
		if (r == R_TIMEOUT) {
			/* Its swallowed READs are still accepted; nothing else runs now.
			 * A reset cancels them so the guest can power off, and the
			 * deferred release then quarantines the session. */
			m_reset_controller(disk);
			usleep(500000);
			CHECK_EQ(issue(dstng, win(m_win(r, 0)), WIN_NLB, RDWR, 0), -EBUSY,
				 "after the reset the timed-out session still keeps its range");
		}
	}

	/* Whole-disk oracle over the shared namespace. */
	who = "holder";
	read_disk(dst, dest, SPAN, "read back the shared destination");
	for (r = 0; r < M_ROUNDS; r++) {
		for (t = 1; t < M_TENANTS; t++)
			CHECK(window_is(dest, source, m_win(r, t)),
			      "an innocent window holds exactly its own source window");
		for (u = 0, exact = 0, guard = 0; u < GROUPS; u++) {
			exact += group_is(dest, source, m_win(r, 0), u);
			guard += group_guard(dest, m_win(r, 0), u);
		}
		printf("# multi: %s faulty window: %u exact groups, %u guard groups\n",
		       m_round_name[r], exact, guard);
		if (r == R_KILL) {
			killed_exact = exact;
			CHECK(exact + guard == GROUPS && exact >= killed_done,
			      "kill: each faulty group is its own source group or guard, and every completed one landed");
		} else {
			CHECK(guard == GROUPS, "the faulty window is untouched");
		}
	}
	for (off = win(M_ROUNDS * M_TENANTS) * LBA; off < SPAN && dest[off] == GUARD; off++)
		;
	CHECK(off == SPAN, "every byte past the round windows is guard");
	read_disk(aux_blk, aux, SPAN, "read the faulty tenant's namespace");
	for (off = 0; off < SPAN && aux[off] == M_AUX_FILL; off++)
		;
	CHECK(off == SPAN, "the faulty tenant's namespace is unchanged");
	read_disk(src, aux, SPAN, "read the source again");
	CHECK(!memcmp(aux, source, SPAN), "the source is unchanged");
	printf("XDEV_EXT_WINDOW_MULTI_KILL done_at_kill=%u exact_groups=%u\n", killed_done, killed_exact);
	close(src); close(srcng); close(dst); close(dstng); close(aux_blk); close(auxng);
	free(source); free(dest); free(aux);
	printf("1..%u\n", checks);
	printf("XDEV_EXT_WINDOW_MULTI=PASS timing=none\n");
	return 0;
}
