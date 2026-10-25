// SPDX-License-Identifier: GPL-2.0
/*
 * Guest driver of libxdev_ext: NVMe READ -> AF_XDP TX through either the
 * one call (--api oneshot) or the step API (--api steps).  It prints the
 * library's own result; the payload bytes are checked independently by
 * xdev_ext_lib_rx on the receiving interface and by the host validator.
 *
 *   xdev_ext_lib_nvme_nic --api oneshot|steps --obj nxp_mech.bpf.o
 *	--ng /dev/ngXnY --slba N --nlb N --ifname IF [--copy]
 *	--peer-mac M --local-ip A --peer-ip A --local-port P --peer-port P
 *	--wire-session S --groups G --depth D --group-bytes B --timeout-ms T
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libxdev_ext.h"

struct args {
	const char *api, *obj, *ng, *ifname;
	__u64 slba, nlb, groups, wire_session;
	__u32 depth, group_bytes, xsk_mode;
	int timeout_ms;
	struct xdev_ext_mech_peer peer;
};

static int parse_mac(const char *s, __u8 mac[6])
{
	unsigned int b[6], i;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
		return -1;
	for (i = 0; i < 6; i++)
		mac[i] = (__u8)b[i];
	return 0;
}

static void print_result(const char *api, int ret, __u64 session, bool zc, int wait_err,
			 int nic_err, int stop_err, bool retained,
			 const struct xdev_ext_mech_stats *s,
			 const struct xdev_ext_mech_transport_stats_v3 *n)
{
	printf("XDEV_EXT_LIB_RESULT api=%s ret=%d session=%llu zero_copy=%d wait_err=%d nic_err=%d stop_err=%d retained=%d\n",
	       api, ret, (unsigned long long)session, zc, wait_err, nic_err, stop_err, retained);
	printf("XDEV_EXT_LIB_STATS api=%s state=%u last_err=%d batches_done=%llu batches_abort=%llu rejects=%llu sequestered=%llu timeouts=%llu inflight=%llu protocol_err=%llu submitted0=%llu completed0=%llu submitted1=%llu completed1=%llu\n",
	       api, s->state, s->last_err, (unsigned long long)s->batches_done,
	       (unsigned long long)s->batches_abort, (unsigned long long)s->rejects,
	       (unsigned long long)s->sequestered, (unsigned long long)s->timeouts,
	       (unsigned long long)s->inflight, (unsigned long long)s->protocol_err,
	       (unsigned long long)s->submitted[0], (unsigned long long)s->completed[0],
	       (unsigned long long)s->submitted[1], (unsigned long long)s->completed[1]);
	printf("XDEV_EXT_LIB_NIC api=%s nic_copy_ops=%llu nic_copy_bytes=%llu nic_zc_ops=%llu nic_zc_bytes=%llu\n",
	       api, (unsigned long long)n->nic_copy_ops, (unsigned long long)n->nic_copy_bytes,
	       (unsigned long long)n->nic_zc_ops, (unsigned long long)n->nic_zc_bytes);
	fflush(stdout);
}

static int nxp_progs(const struct args *a, struct xdev_ext_prog_opts p[2],
		     struct xdev_ext_prog_global g[2])
{
	g[0] = (struct xdev_ext_prog_global) { "nxp_session", a->wire_session };
	g[1] = (struct xdev_ext_prog_global) { "nvme_mode", 0 };
	p[0] = XDEV_EXT_OPTS_INIT(xdev_ext_prog_opts, .obj_path = a->obj,
		.map_name = "nxp_afxdp_ops", .globals = &g[0], .nr_globals = 1);
	p[1] = XDEV_EXT_OPTS_INIT(xdev_ext_prog_opts, .obj_path = a->obj,
		.map_name = "nxp_nvme_ops", .globals = &g[1], .nr_globals = 1);
	return 2;
}

static int run_oneshot(const struct args *a)
{
	struct xdev_ext_prog_global g[2];
	struct xdev_ext_prog_opts p[2];
	struct xdev_ext_nvme_nic_opts o = XDEV_EXT_OPTS_INIT(xdev_ext_nvme_nic_opts,
		.nvme_path = a->ng, .slba = a->slba, .nlb = a->nlb,
		.ifname = a->ifname, .xsk_mode = a->xsk_mode, .peer = a->peer,
		.group_bytes = a->group_bytes, .depth = a->depth,
		.nr_batches = a->groups, .timeout_ms = a->timeout_ms,
		.progs = p, .nr_progs = (__u32)nxp_progs(a, p, g));
	struct xdev_ext_run_result r = { .sz = sizeof(r) };
	int ret = xdev_ext_nvme_to_nic(&o, &r);

	print_result("oneshot", ret, r.session_id, r.zero_copy, r.wait_err, r.nic_err,
		     r.stop_err, r.retained, &r.stats, &r.nic);
	if (r.retained)
		printf("XDEV_EXT_LIB_RETAINED close=%d\n", xdev_ext_session_close(r.session));
	return ret;
}

/* The step API with the caller's own event loop on the session eventfd. */
static int run_steps(const struct args *a)
{
	struct xdev_ext_prog_global g[2];
	struct xdev_ext_prog_opts p[2];
	struct xdev_ext_prog *prog[2] = { NULL, NULL };
	struct xdev_ext_pool_opts pool = XDEV_EXT_OPTS_INIT(xdev_ext_pool_opts,
		.pool_kind = XDEV_EXT_MECH_POOL_XSK, .xsk_mode = a->xsk_mode,
		.ifname = a->ifname);
	struct xdev_ext_create_opts c = XDEV_EXT_OPTS_INIT(xdev_ext_create_opts,
		.group_bytes = a->group_bytes, .depth = a->depth, .nr_stages = 2,
		.peer = a->peer);
	struct xdev_ext_start_opts st = XDEV_EXT_OPTS_INIT(xdev_ext_start_opts,
		.nr_batches = a->groups);
	struct xdev_ext_mech_transport_stats_v3 nic = { 0 };
	struct xdev_ext_mech_stats s = { 0 };
	struct xdev_ext_session *x = NULL;
	int ret, i, n = nxp_progs(a, p, g), ng = -1, wait_err = 0, nic_err = 0, stop_err = 0;
	__u64 count;

	for (i = 0; i < n; i++) {
		ret = xdev_ext_prog_attach(&p[i], &prog[i]);
		if (ret)
			goto out;
	}
	ng = open(a->ng, O_RDONLY | O_CLOEXEC);
	if (ng < 0) {
		ret = -errno;
		goto out;
	}
	ret = xdev_ext_session_open(&pool, &x);
	if (ret)
		goto out;
	c.st[0] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_NVME,
		.direction = XDEV_EXT_MECH_DIR_FROM_DEVICE, .fd = ng,
		.arg0 = a->slba, .arg1 = a->nlb };
	c.st[1] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_AFXDP,
		.direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = -1 };
	if ((ret = xdev_ext_session_create(x, &c)) ||
	    (ret = xdev_ext_session_arm(x, a->groups, 0)) ||
	    (ret = xdev_ext_session_start(x, &st)))
		goto stop;
	{
		struct pollfd pfd = { .fd = xdev_ext_session_eventfd(x), .events = POLLIN };
		int ready = poll(&pfd, 1, a->timeout_ms);

		wait_err = ready < 0 ? -errno : !ready ? -ETIMEDOUT :
			read(pfd.fd, &count, sizeof(count)) == sizeof(count) ? 0 : -errno;
	}
	ret = xdev_ext_session_stats(x, &s);
	if (!ret)
		ret = wait_err;
	if (!ret && (s.last_err || s.state != XDEV_EXT_MECH_SESSION_ACTIVE ||
		     s.batches_done != a->groups || s.batches_abort || s.inflight ||
		     s.sequestered))
		ret = -EIO;
	nic_err = xdev_ext_session_nic_accounting(x, &nic);
	if (!ret)
		ret = nic_err;
stop:
	stop_err = xdev_ext_session_stop(x);
	if (!ret)
		ret = stop_err;
out:
	print_result("steps", ret, x ? xdev_ext_session_id(x) : 0,
		     xdev_ext_session_zero_copy(x), wait_err, nic_err, stop_err,
		     xdev_ext_session_retained(x), &s, &nic);
	if (x) {
		int closed = xdev_ext_session_close(x);

		if (closed) {
			/* Retained: keep the programs and the borrowed NVMe fd. */
			printf("XDEV_EXT_LIB_RETAINED close=%d\n", closed);
			return ret ? ret : closed;
		}
	}
	if (ng >= 0)
		close(ng);
	for (i = n; i--;)
		if (prog[i])
			xdev_ext_prog_detach(prog[i]);
	return ret;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "api", 1, 0, 'a' }, { "obj", 1, 0, 'o' }, { "ng", 1, 0, 'n' },
		{ "slba", 1, 0, 's' }, { "nlb", 1, 0, 'l' }, { "ifname", 1, 0, 'i' },
		{ "copy", 0, 0, 'c' }, { "peer-mac", 1, 0, 'm' },
		{ "local-ip", 1, 0, 'L' }, { "peer-ip", 1, 0, 'P' },
		{ "local-port", 1, 0, 'x' }, { "peer-port", 1, 0, 'y' },
		{ "wire-session", 1, 0, 'w' }, { "groups", 1, 0, 'g' },
		{ "depth", 1, 0, 'd' }, { "group-bytes", 1, 0, 'b' },
		{ "timeout-ms", 1, 0, 't' }, { 0, 0, 0, 0 } };
	struct args a = { .timeout_ms = 60000 };
	int c, ret;

	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case 'a': a.api = optarg; break;
		case 'o': a.obj = optarg; break;
		case 'n': a.ng = optarg; break;
		case 's': a.slba = strtoull(optarg, NULL, 0); break;
		case 'l': a.nlb = strtoull(optarg, NULL, 0); break;
		case 'i': a.ifname = optarg; break;
		case 'c': a.xsk_mode = XDEV_EXT_XSK_COPY; break;
		case 'm': if (parse_mac(optarg, a.peer.peer_mac)) return 2; break;
		case 'L': if (inet_pton(AF_INET, optarg, &a.peer.local_ip) != 1) return 2; break;
		case 'P': if (inet_pton(AF_INET, optarg, &a.peer.peer_ip) != 1) return 2; break;
		case 'x': a.peer.local_port = htons((__u16)atoi(optarg)); break;
		case 'y': a.peer.peer_port = htons((__u16)atoi(optarg)); break;
		case 'w': a.wire_session = strtoull(optarg, NULL, 0); break;
		case 'g': a.groups = strtoull(optarg, NULL, 0); break;
		case 'd': a.depth = (__u32)strtoul(optarg, NULL, 0); break;
		case 'b': a.group_bytes = (__u32)strtoul(optarg, NULL, 0); break;
		case 't': a.timeout_ms = atoi(optarg); break;
		default: return 2;
		}
	}
	if (!a.api || !a.obj || !a.ng || !a.ifname || !a.wire_session)
		return 2;
	if (!strcmp(a.api, "oneshot"))
		ret = run_oneshot(&a);
	else if (!strcmp(a.api, "steps"))
		ret = run_steps(&a);
	else
		return 2;
	printf("XDEV_EXT_LIB_EXIT api=%s ret=%d (%s)\n", a.api, ret, strerror(-ret));
	return ret ? 1 : 0;
}
