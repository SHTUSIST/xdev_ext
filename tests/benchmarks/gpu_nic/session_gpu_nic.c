// SPDX-License-Identifier: GPL-2.0
/*
 * session_gpu_nic - the xdev_ext session arm of the GPU<->NIC comparison.
 *
 *   ingest: [AF_XDP RX, CE H2D]  NIC -> shared host frame -> VRAM
 *   egress: [CE D2H, AF_XDP TX]  VRAM -> shared host frame -> NIC
 *
 * One one-way session on the AF_XDP socket's UMEM.  The CE stage is the last
 * (ingest) or the first (egress) stage; test_ce_stage_position.c shows the
 * core admits both.  The struct_ops programs nxp_afxdp_ops (nxp_mech.bpf.o,
 * nxp_session=--wire-session, key_base 1) and ce_plan_ops (ce_plan.bpf.o)
 * must be attached; CREATE without them exits 4.
 *
 * ingest  A peer (nxp_peer send, or any NXP sender) sends generations
 *         1..groups of --wire-session to --local-ip:--local-port.  The
 *         redirect program sends exactly that flow to the socket.  The
 *         timed region runs from READY (printed on stderr after CREATE,
 *         NOTIFY_ARM, fill ring and redirect) to the terminal wake, so it
 *         includes the sender's start; the peer's own record times the
 *         stream.  Oracle: every used CE window slot holds one whole,
 *         distinct group block (gpu_nic_core.h).
 * egress  START groups batches; slot s was seeded with block s, so the
 *         receiving peer (nxp_peer recv --expect slots:DEPTH) checks every
 *         group against a slot image.  START to terminal wake is timed.
 *
 * The CE window is a GPU allocation (--ce-alloc) or /dev/xdev_ext_ce_sim
 * (--ce-va), as in ../nvme_gpu/eval_session.h; with the stand-in the record
 * says execution=kvm-ce-sim and performance_claim=none.
 * Exit: 0 verified, 1 failure, 2 usage, 4 unavailable capability.
 */
#define _GNU_SOURCE
#include "../common/cpu_timer.h"
static struct cpu_timer endpoint_timer;
static void endpoint_timer_cleanup(void) { cpu_timer_destroy(&endpoint_timer); }
#include "../common/fd_check.h"
#include <getopt.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include "../../../kernel/tools/include/xdev_ext_xsk_redirect.h"
#include "../nvme_gpu/eval_session.h"
#include "xsk_port.h"

struct sg_opts {
	bool ingest, copy_mode, ce_alloc, have_va;
	const char *ifname, *ce_dev;
	uint64_t queue, size, messages, depth, window_groups, wire_session, timeout_ms,
		 seed, ce_va;
	struct xdev_ext_mech_peer peer;
};

static void sg_usage(FILE *f)
{
	fprintf(f,
"usage: session_gpu_nic --direction ingest|egress --ifname IF [--queue N] [--copy-mode]\n"
"         --ce-dev DEV (--ce-va N | --ce-alloc) --size N --messages N --depth N\n"
"         [--window-groups N] --wire-session N --local-ip A --peer-ip A\n"
"         --local-port P --peer-port P --peer-mac M [--local-mac M]\n"
"         [--seed N] [--timeout-ms N]\n");
}

static int sg_if_query(const char *ifname, unsigned long req, struct ifreq *ifr)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0), ret;

	if (fd < 0)
		return -errno;
	memset(ifr, 0, sizeof(*ifr));
	snprintf(ifr->ifr_name, sizeof(ifr->ifr_name), "%s", ifname);
	ret = ioctl(fd, req, ifr) ? -errno : 0;
	close(fd);
	return ret;
}

static int sg_parse(int argc, char **argv, struct sg_opts *o)
{
	enum { O_DIR = 1, O_IF, O_QUEUE, O_COPY, O_CE, O_VA, O_ALLOC, O_SIZE, O_MSG, O_DEPTH,
	       O_WIN, O_WIRE, O_LIP, O_PIP, O_LPORT, O_PPORT, O_PMAC, O_LMAC, O_SEED, O_TMO,
	       O_HELP };
	static const struct option opts[] = {
		{ "direction", required_argument, NULL, O_DIR },
		{ "ifname", required_argument, NULL, O_IF },
		{ "queue", required_argument, NULL, O_QUEUE },
		{ "copy-mode", no_argument, NULL, O_COPY },
		{ "ce-dev", required_argument, NULL, O_CE },
		{ "ce-va", required_argument, NULL, O_VA },
		{ "ce-alloc", no_argument, NULL, O_ALLOC },
		{ "size", required_argument, NULL, O_SIZE },
		{ "messages", required_argument, NULL, O_MSG },
		{ "depth", required_argument, NULL, O_DEPTH },
		{ "window-groups", required_argument, NULL, O_WIN },
		{ "wire-session", required_argument, NULL, O_WIRE },
		{ "local-ip", required_argument, NULL, O_LIP },
		{ "peer-ip", required_argument, NULL, O_PIP },
		{ "local-port", required_argument, NULL, O_LPORT },
		{ "peer-port", required_argument, NULL, O_PPORT },
		{ "peer-mac", required_argument, NULL, O_PMAC },
		{ "local-mac", required_argument, NULL, O_LMAC },
		{ "seed", required_argument, NULL, O_SEED },
		{ "timeout-ms", required_argument, NULL, O_TMO },
		{ "help", no_argument, NULL, O_HELP },
		{ NULL, 0, NULL, 0 },
	};
	unsigned int have = 0;
	bool have_dir = false, have_lmac = false;
	int c, bad = 0;

	memset(o, 0, sizeof(*o));
	o->timeout_ms = 60000;
	o->seed = 1;
	opterr = 0;
	while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (c) {
		case O_DIR:
			have_dir = true;
			if (!strcmp(optarg, "ingest"))
				o->ingest = true;
			else if (strcmp(optarg, "egress"))
				bad = 1;
			break;
		case O_IF: o->ifname = optarg; break;
		case O_QUEUE: bad |= xg_parse_u64(optarg, 4095, &o->queue); break;
		case O_COPY: o->copy_mode = true; break;
		case O_CE: o->ce_dev = optarg; break;
		case O_VA: bad |= xg_parse_u64(optarg, UINT64_MAX >> 2, &o->ce_va); o->have_va = true; break;
		case O_ALLOC: o->ce_alloc = true; break;
		case O_SIZE: bad |= xg_parse_u64(optarg, GN_MAX_SIZE, &o->size); break;
		case O_MSG: bad |= xg_parse_u64(optarg, GN_MAX_MESSAGES, &o->messages); break;
		case O_DEPTH: bad |= xg_parse_u64(optarg, GN_MAX_DEPTH, &o->depth); break;
		case O_WIN: bad |= xg_parse_u64(optarg, GN_MAX_MESSAGES, &o->window_groups); break;
		case O_WIRE: bad |= xg_parse_u64(optarg, UINT64_MAX, &o->wire_session); break;
		case O_LIP: bad |= gn_parse_ip(optarg, &o->peer.local_ip); have |= 1; break;
		case O_PIP: bad |= gn_parse_ip(optarg, &o->peer.peer_ip); have |= 2; break;
		case O_LPORT: bad |= gn_parse_port(optarg, &o->peer.local_port); have |= 4; break;
		case O_PPORT: bad |= gn_parse_port(optarg, &o->peer.peer_port); have |= 8; break;
		case O_PMAC: bad |= xdev_ext_mech_ctl_parse_mac(optarg, o->peer.peer_mac); have |= 16; break;
		case O_LMAC: bad |= xdev_ext_mech_ctl_parse_mac(optarg, o->peer.local_mac); have_lmac = true; break;
		case O_SEED: bad |= xg_parse_u64(optarg, UINT32_MAX, &o->seed); break;
		case O_TMO: bad |= xg_parse_u64(optarg, 3600000, &o->timeout_ms); break;
		case O_HELP: sg_usage(stdout); exit(0);
		default: bad = 1; break;
		}
	}
	if (!o->window_groups)
		o->window_groups = o->depth;
	if (bad || optind != argc || !have_dir || !o->ifname || !o->ce_dev ||
	    o->have_va == o->ce_alloc || !o->size || !o->messages || !o->depth ||
	    !o->wire_session || have != 31 || !o->timeout_ms ||
	    (!o->ingest && o->window_groups != o->depth))
		return XG_EXIT_USAGE;
	if (!have_lmac) {
		struct ifreq ifr;

		if (sg_if_query(o->ifname, SIOCGIFHWADDR, &ifr)) {
			fprintf(stderr, "SKIP: %s has no hardware address\n", o->ifname);
			return XG_EXIT_UNAVAILABLE;
		}
		memcpy(o->peer.local_mac, ifr.ifr_hwaddr.sa_data, 6);
	}
	return XG_EXIT_PASS;
}

static bool sg_capability_errno(int err)
{
	return err == -EINVAL || err == -EOPNOTSUPP || err == -ENOSYS || err == -ENODEV ||
	       err == -ENXIO || err == -EPERM || err == -EACCES || err == -EAFNOSUPPORT ||
	       err == -EPROTONOSUPPORT;
}

static int sg_slots(struct es_ce *ce, const struct gn_plan *p, unsigned char *buf,
		    bool sentinel, uint32_t seed)
{
	uint64_t s, g = p->l.group_bytes;
	int ret;

	for (s = 0; s < p->depth; s++) {
		xg_fill(buf, s * g, g, sentinel ? ~seed : seed);
		ret = es_ce_access(ce, true, s * g, buf, g);
		if (ret)
			return ret;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int fd_before = eval_fd_count();
	struct xdev_ext_xsk_redirect redirect = XDEV_EXT_XSK_REDIRECT_INIT;
	struct es_run r = { .ring = -1, .efd = -1 };
	struct es_ce ce = { .fd = { -1, -1 }, .sim = true };
	struct xp_sock x = { .fd = -1 };
	struct xdev_ext_mech_create c;
	struct xdev_ext_mech_stats st;
	struct sg_opts o;
	struct gn_plan p;
	struct ifreq ifr;
	unsigned char *slots = NULL, *seen = NULL;
	uint32_t headroom = 0, xsk = 0, cei = 1;
	uint64_t used = 0, t0 = 0, t1 = 0, cpu0, cpu = 0, busy0, busy = 0, deadline;
	int ret, err, closed;

	ret = sg_parse(argc, argv, &o);
	if (ret) {
		if (ret == XG_EXIT_USAGE)
			sg_usage(stderr);
		return ret;
	}
	{
		int error = cpu_timer_init(&endpoint_timer, "CLOCK_MONOTONIC", 1);
		if (error)
			fprintf(stderr, "XDEV_EXT_CPU_TIMER_REFUSED phase=init code=%d\n", error);
	}
	atexit(endpoint_timer_cleanup);
	err = sg_if_query(o.ifname, SIOCGIFMTU, &ifr);
	if (err) {
		fprintf(stderr, "SKIP: %s: %s\n", o.ifname, strerror(-err));
		return XG_EXIT_UNAVAILABLE;
	}
	if (gn_plan_init(&p, o.size, o.messages, (uint32_t)ifr.ifr_mtu, (uint32_t)o.depth,
			 o.window_groups)) {
		fprintf(stderr, "message size %llu is not whole groups on MTU %d\n",
			(unsigned long long)o.size, ifr.ifr_mtu);
		return XG_EXIT_USAGE;
	}
	if (o.ingest && xdev_ext_mech_ctl_rx_headroom(&p.l, &headroom))
		return XG_EXIT_USAGE;
	slots = malloc(p.depth * (uint64_t)p.l.group_bytes);
	seen = calloc(p.window_groups, 1);
	if (!slots || !seen) {
		ret = XG_EXIT_FAIL;
		goto out;
	}
	ret = es_ce_open(&ce, o.ce_dev, 1, o.ce_alloc, o.ce_va,
			 p.depth * (uint64_t)p.l.group_bytes);
	if (ret)
		goto out;
	/* ingest: sentinel slots; egress: slot s holds block s.  Before CREATE. */
	err = sg_slots(&ce, &p, slots, o.ingest, (uint32_t)o.seed);
	if (err) {
		fprintf(stderr, "seeding the CE window: %s\n", strerror(-err));
		ret = XG_EXIT_FAIL;
		goto out;
	}
	err = xp_open(&x, o.ifname, (uint32_t)o.queue, 4096, headroom, o.ingest, !o.ingest,
		      o.copy_mode);
	if (!err)
		err = es_ring_open(&r);
	if (err) {
		ret = sg_capability_errno(err) ? XG_EXIT_UNAVAILABLE : XG_EXIT_FAIL;
		fprintf(stderr, "%sAF_XDP socket/io_uring on %s: %s\n",
			ret == XG_EXIT_UNAVAILABLE ? "SKIP: " : "", o.ifname, strerror(-err));
		goto out;
	}
	memset(&c, 0, sizeof(c));
	if (!o.ingest) {
		xsk = 1;
		cei = 0;
	}
	c.nr_stages = 2;
	c.pool_kind = XDEV_EXT_MECH_POOL_XSK;
	c.pool_fd = x.fd;
	c.layout = p.l;
	c.depth = p.depth;
	c.peer = o.peer;
	c.st[xsk].class_id = XDEV_EXT_MECH_CLASS_AFXDP;
	c.st[xsk].direction = o.ingest ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE;
	c.st[xsk].fd = x.fd;
	c.st[cei].class_id = XDEV_EXT_MECH_CLASS_CE;
	c.st[cei].direction = o.ingest ? XDEV_EXT_MECH_DIR_TO_DEVICE : XDEV_EXT_MECH_DIR_FROM_DEVICE;
	c.st[cei].fd = ce.fd[0];
	c.st[cei].arg0 = ce.va;
	c.st[cei].arg1 = ce.len;
	err = es_create(&r, &c, p.groups);
	if (err) {
		ret = sg_capability_errno(err) ? XG_EXIT_UNAVAILABLE : XG_EXIT_FAIL;
		fprintf(stderr, "%sCREATE (kernel, nxp_afxdp_ops/ce_plan_ops, devices): %s\n",
			ret == XG_EXIT_UNAVAILABLE ? "SKIP: " : "", strerror(-err));
		goto out;
	}
	if (o.ingest || !x.zero_copy)
		err = xp_fq_fill(&x, 0, XP_RING_SIZE);
	if (!err && o.ingest) {
		struct xdev_ext_xsk_flow_filter filter;

		memset(&filter, 0, sizeof(filter));
		filter.flags = XDEV_EXT_XSK_FILTER_F_ALL;
		filter.src_ipv4 = ntohl(o.peer.peer_ip);
		filter.dst_ipv4 = ntohl(o.peer.local_ip);
		filter.payload_magic = XDEV_EXT_MP_NXP_MAGIC;
		filter.src_port = ntohs(o.peer.peer_port);
		filter.dst_port = ntohs(o.peer.local_port);
		err = xdev_ext_xsk_redirect_attach(&redirect, &filter,
					      (int)if_nametoindex(o.ifname), (uint32_t)o.queue,
					      x.fd, o.copy_mode ? XDP_FLAGS_SKB_MODE :
								  XDP_FLAGS_DRV_MODE);
	}
	if (err) {
		ret = sg_capability_errno(err) ? XG_EXIT_UNAVAILABLE : XG_EXIT_FAIL;
		fprintf(stderr, "%sfill ring / XDP redirect: %s\n",
			ret == XG_EXIT_UNAVAILABLE ? "SKIP: " : "", strerror(-err));
		goto out;
	}
	fprintf(stderr, "XDEV_EVAL_READY direction=%s session=%llu groups=%llu group_bytes=%u xsk=%s\n",
		o.ingest ? "ingest" : "egress", (unsigned long long)r.session,
		(unsigned long long)p.groups, p.l.group_bytes, x.zero_copy ? "zc" : "copy");
	deadline = es_now_ns() + o.timeout_ms * 1000000ULL;
	cpu0 = es_cpu_us();
	busy0 = xg_host_busy_us();
	t0 = es_now_ns();
	err = o.ingest ? 0 : es_start(&r, p.groups, NULL, 0);
	if (!err)
		err = es_wait_terminal(&r, deadline);
	t1 = es_now_ns();
	cpu_timer_store(&endpoint_timer, "io_ns", 0, t0, t1);
	cpu = es_cpu_us() - cpu0;
	busy = xg_host_busy_us() - busy0;
	if (!err)
		err = es_settle(&r, p.groups, deadline, &st);
	else
		es_stats(&r, &st);
	es_print_stats(&st);
	if (err || st.batches_done != p.groups || !t0 || t1 <= t0) {
		fprintf(stderr, "session campaign failed: %s\n", strerror(err ? -err : EIO));
		ret = XG_EXIT_FAIL;
		goto out;
	}
	if (xdev_ext_xsk_redirect_is_active(&redirect))
		xdev_ext_xsk_redirect_detach(&redirect);
	closed = es_close(&r);
	if (closed) {
		fprintf(stderr, "STOP: %s\n", strerror(-closed));
		ret = XG_EXIT_FAIL;
		goto out;
	}
	if (o.ingest) {
		err = es_ce_access(&ce, false, 0, slots, p.depth * (uint64_t)p.l.group_bytes);
		if (!err)
			err = gn_check_slots(slots, &p, (uint32_t)o.seed, seen, &used);
		if (err) {
			fprintf(stderr, "slot oracle failed: %s\n", strerror(-err));
			ret = XG_EXIT_FAIL;
			goto out;
		}
	}
	{
		int error = cpu_timer_publish(&endpoint_timer);
		if (error)
			fprintf(stderr, "XDEV_EXT_CPU_TIMER_REFUSED phase=publish code=%d\n", error);
	}
	printf("{\"schema_version\":1,\"arm\":\"session\",\"direction\":\"%s\",\"route\":\"%s\","
	       "\"execution\":\"%s\",\"performance_claim\":\"%s\",\"size\":%llu,\"messages\":%llu,"
	       "\"group_bytes\":%u,\"groups\":%llu,\"depth\":%u,\"mtu\":%u,\"xsk\":\"%s\","
	       "\"io_bytes\":%llu,\"slots_used\":%llu,\"oracle\":\"%s\",\"io_ns\":%llu,"
	       "\"cpu_us\":%llu,\"host_busy_us\":%llu,\"completion_wait\":\"block\","
	       "\"status\":\"pass\"}\n",
	       o.ingest ? "ingest" : "egress",
	       o.ingest ? "afxdp-rx>shared-host-frame>ce-h2d" : "ce-d2h>shared-host-frame>afxdp-tx",
	       ce.sim ? "kvm-ce-sim" : "physical-gpu-ce", ce.sim ? "none" : "physical",
	       (unsigned long long)p.size, (unsigned long long)p.messages, p.l.group_bytes,
	       (unsigned long long)p.groups, p.depth, p.mtu, x.zero_copy ? "zc" : "copy",
	       (unsigned long long)(p.groups * p.l.group_bytes), (unsigned long long)used,
	       o.ingest ? "device-slot-group-images" : "peer-receipt-required",
	       (unsigned long long)(t1 - t0), (unsigned long long)cpu, (unsigned long long)busy);
	ret = fflush(stdout) ? XG_EXIT_FAIL : XG_EXIT_PASS;
out:
	if (xdev_ext_xsk_redirect_is_active(&redirect))
		xdev_ext_xsk_redirect_detach(&redirect);
	if (es_close(&r) && ret == XG_EXIT_PASS)
		ret = XG_EXIT_FAIL;
	xp_close(&x);
	if (es_ce_close(&ce) && ret == XG_EXIT_PASS)
		ret = XG_EXIT_FAIL;
	free(slots);
	free(seen);
	if (eval_fd_check(fd_before) && ret == XG_EXIT_PASS)
		ret = XG_EXIT_FAIL;
	return ret;
}
