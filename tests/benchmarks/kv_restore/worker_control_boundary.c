/* SPDX-License-Identifier: GPL-2.0 */
/* Runs the actual TCP control and restore orchestration. Only session START /
 * completion are CPU stand-ins; no storage, DMA or GPU work is performed. */
#define main kv_restore_worker_main
#include "kv_restore.c"
#undef main

static uint64_t groups_done;
static bool fail_send;
ssize_t __real_send(int fd, const void *buf, size_t len, int flags);
ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags)
{
	if (fail_send) { errno = EPIPE; return -1; }
	return __real_send(fd, buf, len, flags);
}
int __wrap_xdev_ext_session_start_frames(struct xdev_ext_session *s,
	const struct xdev_ext_start_frames_opts *o)
{
	(void)s;
	groups_done += o->nr_batches;
	return 0;
}
int __wrap_xdev_ext_session_wait(struct xdev_ext_session *s, int ms,
	struct xdev_ext_mech_stats *st)
{
	(void)s; (void)ms;
	memset(st, 0, sizeof(*st));
	st->batches_done = groups_done;
	return 0;
}
int main(int argc, char **argv)
{
	struct worker wk = { 0 };
	struct queued q = { 0 };
	struct kv_line l;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int rc;
	if (argc < 2) return 2;
	wk.o.w = (struct kv_window){ .slba = 2048, .nlb = 128, .lba_bytes = 512 };
	wk.o.g = (struct kv_geometry){ .group_bytes = 4096, .frame_bytes = 4096,
		.depth = 1, .window = 1, .early = true };
	wk.o.token = "5";
	wk.o.timeout_ms = argc == 3 && !strcmp(argv[1], "serve") ? atoi(argv[2]) : 180;
	wk.o.dst = DST_PEER;
	wk.pool_frames = 16;
	wk.sock = wk.lsock = -1;
	if (!strcmp(argv[1], "go")) {
		if (argc != 3) return 2;
		wk.o.role = ROLE_RESTORE;
		wk.sock = atoi(argv[2]);
		if (line_split(&l, "GO run=r ordinal=1 object_slba=2048 bytes=4096 dst_frame0=0"))
			return 3;
		handle_go(&wk, &l, &q, now_ns());
		printf("CONTROL_STATE dirty=%d\n", wk.dirty);
		close(wk.sock);
		return 0;
	}
	if (!strcmp(argv[1], "reply-failure")) {
		wk.o.role = ROLE_SERVE;
		fail_send = true;
		serve_request(&wk, "RESTORE token=5 run=r ordinal=1 object_slba=2048 bytes=4096 first_seq=16 groups=1");
		printf("CONTROL_STATE dirty=%d\n", wk.dirty);
		return 0;
	}
	if (strcmp(argv[1], "serve")) return 2;
	wk.o.role = ROLE_SERVE;
	wk.sock = -1;
	wk.lsock = tcp_open("127.0.0.1:0", true, wk.o.timeout_ms);
	if (wk.lsock < 0 || getsockname(wk.lsock, (struct sockaddr *)&addr, &len)) return 4;
	printf("CONTROL_READY %u\n", ntohs(addr.sin_port));
	fflush(stdout);
	rc = serve_loop(&wk);
	printf("CONTROL_RETURN %d\n", rc);
	if (wk.sock >= 0) close(wk.sock);
	close(wk.lsock);
	return rc ? 5 : 0;
}
