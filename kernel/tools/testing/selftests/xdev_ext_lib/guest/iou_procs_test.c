// SPDX-License-Identifier: GPL-2.0
/* Host regression of the real guest process coordinator, without devices.
 * Only library/device calls are substituted; fork, pipes, deadlines, logging
 * and reaping use the guest driver's actual implementation.
 */
#define main guest_driver_main
#include "xdev_ext_lib_iou.c"
#undef main
#include <sys/mman.h>

struct xdev_ext_session { unsigned int idx; __u64 id; };
struct shared_state { int live, peak, armed, started, early_start; };
static struct shared_state *shared;
static const char *mode;
static int closed0[2];

int xdev_ext_session_open(const struct xdev_ext_pool_opts *o, struct xdev_ext_session **s)
{
	(void)o;
	*s = calloc(1, sizeof(**s));
	return *s ? 0 : -ENOMEM;
}

int xdev_ext_session_create(struct xdev_ext_session *s, const struct xdev_ext_create_opts *o)
{
	char token;
	int live, peak;

	s->idx = (unsigned int)o->st[0].arg0 - 1;
	if (s->idx) {
		if (!strcmp(mode, "fail"))
			return -EIO;
		if (!strcmp(mode, "exit"))
			_exit(3);
		if (!strcmp(mode, "serial") || !strcmp(mode, "stall"))
			if (read(closed0[0], &token, 1) != 1)
				return -EPIPE;
	}
	s->id = 40 + (!strcmp(mode, "duplicate") ? 0 : s->idx);
	live = __atomic_add_fetch(&shared->live, 1, __ATOMIC_SEQ_CST);
	peak = __atomic_load_n(&shared->peak, __ATOMIC_SEQ_CST);
	while (live > peak && !__atomic_compare_exchange_n(&shared->peak, &peak, live,
							false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
		;
	return 0;
}

__u64 xdev_ext_session_id(const struct xdev_ext_session *s) { return s->id; }

int xdev_ext_session_arm(struct xdev_ext_session *s, __u64 n, __u64 p)
{
	(void)s; (void)n; (void)p;
	__atomic_add_fetch(&shared->armed, 1, __ATOMIC_SEQ_CST);
	return 0;
}

int xdev_ext_session_start(struct xdev_ext_session *s, const struct xdev_ext_start_opts *o)
{
	(void)s; (void)o;
	__atomic_add_fetch(&shared->started, 1, __ATOMIC_SEQ_CST);
	if (__atomic_load_n(&shared->armed, __ATOMIC_SEQ_CST) != 2)
		__atomic_store_n(&shared->early_start, 1, __ATOMIC_SEQ_CST);
	return 0;
}

int xdev_ext_session_wait(struct xdev_ext_session *s, int t, struct xdev_ext_mech_stats *out)
{
	(void)t;
	memset(out, 0, sizeof(*out));
	out->session_id = s->id;
	out->state = XDEV_EXT_MECH_SESSION_ACTIVE;
	out->batches_done = 24;
	out->submitted[0] = out->submitted[1] = 24;
	out->completed[0] = out->completed[1] = 24;
	return 0;
}

int xdev_ext_session_stop(struct xdev_ext_session *s) { (void)s; return 0; }
bool xdev_ext_session_retained(const struct xdev_ext_session *s) { (void)s; return false; }

int xdev_ext_session_close(struct xdev_ext_session *s)
{
	if (s->id) {
		__atomic_sub_fetch(&shared->live, 1, __ATOMIC_SEQ_CST);
		if (!s->idx && !strcmp(mode, "serial") && write(closed0[1], "c", 1) != 1)
			return -EPIPE;
	}
	free(s);
	return 0;
}

int main(int argc, char **argv)
{
	const struct args a = { .name = "iou-procs", .kind = "procs", .src_ng = "/dev/null",
		.dst_ng = "/dev/null", .groups = 24, .depth = 4, .group_bytes = 8192,
		.slba = {1, 2}, .dst_slba = {3, 4}, .timeout_ms = 100 };
	int ret, status;

	if (argc != 2)
		return 2;
	mode = argv[1];
	shared = mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED || pipe(closed0))
		return 2;
	/* Keep stdout fully buffered: the coordinator must explicitly flush GO. */
	ret = run_procs(&a);
	printf("CHECK mode=%s ret=%d peak=%d armed=%d started=%d early_start=%d\n",
	       mode, ret, shared->peak, shared->armed, shared->started, shared->early_start);
	if (waitpid(-1, &status, WNOHANG) != -1 || errno != ECHILD)
		return 1;
	if (!strcmp(mode, "ok"))
		return ret || shared->peak != 2 || shared->started != 2 || shared->early_start;
	return !ret || shared->started;
}
