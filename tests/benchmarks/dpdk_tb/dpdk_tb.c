// SPDX-License-Identifier: GPL-2.0
/*
 * dpdk_tb: GPU-memory to GPU-memory messages over DPDK's net_af_xdp PMD.
 *
 * Baseline for E4 (Thunderbolt between two hosts).  thunderbolt-net has no
 * DPDK PMD, so the port is net_af_xdp on the kernel interface with every
 * PMD option at its default except one socket on queue 0
 * (--vdev net_af_xdp0,iface=IF,start_queue=0,queue_count=1).
 *
 * Send: cudaMemcpy device -> registered host staging buffer, then the
 * message is cut into MTU-sized frames copied into DPDK mbufs and sent.
 * Receive: frames land in mbufs, their payloads are reassembled in a
 * registered host staging buffer, then one cudaMemcpy host -> device.
 * The frame protocol (tb_wire.h) does not retransmit; any lost frame ends
 * the run with an error, so every reported number comes from a loss-free
 * run.
 *
 *   client --mode pingpong: one-way latency = (request + echo round trip)/2,
 *     timed from the first device->host copy to the end of the last
 *     host->device copy, so both GPUs' copies are inside the time.
 *   client --mode stream: bandwidth = bytes / time from the first
 *     device->host copy until the server reports the last message in its
 *     GPU memory.
 *   server: serves one client session and exits after BYE.
 *
 * Output: one JSON line per message size on stdout (client), one summary
 * line (server).  Built with tb_gpu_host.c the "GPU" is ordinary memory and
 * the records say gpu="none": correctness only.
 */
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include <bpf/libbpf.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_version.h>

#include "tb_gpu.h"
#include "tb_wire.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#define BURST 32
#define NB_MBUF 16383
#define MBUF_CACHE 250
#define HELLO_INTERVAL_NS 100000000ull

struct tb {
	struct tb_opts o;
	uint16_t port;
	struct rte_mempool *pool;
	struct rte_ether_addr self, peer;
	int have_peer;
	uint32_t mtu, dpdk_mtu, dpdk_max_mtu, netdev_mtu;
	size_t fp;
	uint32_t run_id;
	uint32_t peer_mode, peer_max;
	int session, bye, hello_acked;
	struct tb_tx_window tx;
	struct tb_rx_state rx;
	uint32_t tx_msg_id;      /* messages sent in our direction */
	uint32_t peer_completed; /* from the peer's ACKs */
	int msg_ready;           /* a message completed and is in GPU memory */
	uint64_t t_done;         /* when its host->device copy finished */
	uint8_t *tx_stage, *rx_stage, *check;
	void *gpu_src, *gpu_dst;
	char gpu_name[128];
	char iface[IF_NAMESIZE];
	char vdev[256];
	const char *attach_mode;
	int zerocopy;
	uint64_t frames_tx, frames_rx, ignored, verified;
	uint64_t last_progress;
};

static volatile sig_atomic_t force_quit;
static struct tb *G;

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void cleanup(void)
{
	if (G && G->pool) {
		rte_eth_dev_stop(G->port);
		rte_eth_dev_close(G->port);
	}
	rte_eal_cleanup();
}

static void __attribute__((noreturn, format(printf, 1, 2))) fatal(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "dpdk_tb: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	if (G)
		fprintf(stderr, "dpdk_tb: frames_tx=%" PRIu64 " frames_rx=%" PRIu64
			" tx_next_seq=%u tx_acked=%u rx_expected_seq=%u\n", G->frames_tx,
			G->frames_rx, G->tx.next_seq, G->tx.acked, G->rx.expected_seq);
	cleanup();
	exit(1);
}

static void on_signal(int sig)
{
	(void)sig;
	force_quit = 1;
}

static void progress(struct tb *t)
{
	t->last_progress = now_ns();
}

static void check_stall(struct tb *t, const char *what)
{
	if (force_quit)
		fatal("interrupted while %s", what);
	if (now_ns() - t->last_progress > (uint64_t)t->o.timeout_ms * 1000000ull)
		fatal("no progress for %u ms while %s (a frame was lost or the peer stopped)",
		      t->o.timeout_ms, what);
}

/* ---- frames ---- */

static struct rte_mbuf *frame(struct tb *t, const struct tb_hdr *h, const uint8_t *payload,
			      int broadcast)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(t->pool);
	struct rte_ether_hdr *eth;
	uint8_t *p;

	if (!m)
		fatal("mbuf pool empty");
	p = (uint8_t *)rte_pktmbuf_append(m, TB_ETH_HLEN + TB_HDR_LEN + h->payload_len);
	if (!p)
		fatal("mbuf too small for %u payload bytes", h->payload_len);
	eth = (struct rte_ether_hdr *)p;
	if (broadcast || !t->have_peer)
		memset(&eth->dst_addr, 0xff, RTE_ETHER_ADDR_LEN);
	else
		rte_ether_addr_copy(&t->peer, &eth->dst_addr);
	rte_ether_addr_copy(&t->self, &eth->src_addr);
	eth->ether_type = rte_cpu_to_be_16(TB_ETHERTYPE);
	tb_hdr_encode(p + TB_ETH_HLEN, h);
	if (h->payload_len)
		memcpy(p + TB_ETH_HLEN + TB_HDR_LEN, payload, h->payload_len);
	return m;
}

static void send_burst(struct tb *t, struct rte_mbuf **m, uint16_t n)
{
	uint16_t sent = 0;

	while (sent < n) {
		uint16_t k = rte_eth_tx_burst(t->port, 0, m + sent, (uint16_t)(n - sent));

		if (k) {
			sent = (uint16_t)(sent + k);
			progress(t);
		} else {
			check_stall(t, "transmitting");
		}
	}
	t->frames_tx += n;
}

static void send_ctrl(struct tb *t, uint8_t type, uint32_t seq, uint32_t msg_len, uint32_t aux,
		      int broadcast)
{
	struct tb_hdr h = { .magic = TB_MAGIC, .type = type, .seq = seq, .msg_len = msg_len,
			    .aux = aux, .run_id = t->run_id };
	struct rte_mbuf *m = frame(t, &h, NULL, broadcast);

	send_burst(t, &m, 1);
}

static void send_ack(struct tb *t)
{
	send_ctrl(t, TB_ACK, t->rx.expected_seq, 0, (uint32_t)t->rx.messages, 0);
	tb_rx_mark_acked(&t->rx);
}

/* The message just reassembled in rx_stage goes to GPU memory. */
static void message_done(struct tb *t)
{
	uint32_t len = t->rx.done_len;
	int r = tb_gpu_h2d(t->gpu_dst, t->rx_stage, len);

	if (r)
		fatal("host->device copy: %s", tb_gpu_error());
	t->t_done = now_ns();
	if (t->rx.done_flags & TB_F_VERIFY) {
		long bad;

		if (tb_gpu_d2h(t->check, t->gpu_dst, len))
			fatal("verify copy: %s", tb_gpu_error());
		bad = tb_pattern_check(t->check, len, t->rx.done_msg_id);
		if (bad >= 0)
			fatal("message %u (%u bytes): byte %ld differs after the GPU copy",
			      t->rx.done_msg_id, len, bad);
		t->verified++;
	}
	if (t->rx.done_flags & TB_F_ACKREQ || tb_rx_should_ack(&t->rx))
		send_ack(t);
	t->msg_ready = tb_holds_messages(t->o.role, t->o.role == TB_ROLE_SERVER ?
					 (int)t->peer_mode : t->o.mode);
}

static void session_reset(struct tb *t, uint32_t run_id)
{
	t->run_id = run_id;
	tb_tx_init(&t->tx, t->o.window_frames);
	tb_rx_init(&t->rx, t->o.max_size, t->o.ack_every);
	t->tx_msg_id = 0;
	t->peer_completed = 0;
	t->msg_ready = 0;
	t->bye = 0;
}

static void handle(struct tb *t, struct rte_mbuf *m)
{
	const uint8_t *p = rte_pktmbuf_mtod(m, const uint8_t *);
	const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)p;
	uint32_t len = rte_pktmbuf_data_len(m);
	struct tb_hdr h;
	int r;

	if (m->nb_segs != 1 || len < TB_ETH_HLEN ||
	    eth->ether_type != rte_cpu_to_be_16(TB_ETHERTYPE) ||
	    tb_hdr_decode(p + TB_ETH_HLEN, len - TB_ETH_HLEN, &h)) {
		t->ignored++; /* ARP, IPv6 ND and the like reach the socket too */
		return;
	}
	t->frames_rx++;
	if (t->o.role == TB_ROLE_SERVER && h.type == TB_HELLO) {
		if (!t->session || h.run_id != t->run_id) {
			session_reset(t, h.run_id);
			t->session = 1;
			t->peer_mode = h.aux;
		}
		rte_ether_addr_copy(&eth->src_addr, &t->peer);
		t->have_peer = 1;
		send_ctrl(t, TB_HELLO_ACK, 0, 0, t->o.max_size, 0);
		progress(t);
		return;
	}
	if (h.run_id != t->run_id || (t->o.role == TB_ROLE_SERVER && !t->session)) {
		t->ignored++;
		return;
	}
	progress(t);
	switch (h.type) {
	case TB_HELLO_ACK:
		if (t->o.role == TB_ROLE_CLIENT && !t->hello_acked) {
			rte_ether_addr_copy(&eth->src_addr, &t->peer);
			t->have_peer = 1;
			t->peer_max = h.aux;
			t->hello_acked = 1;
		}
		break;
	case TB_DATA:
		if (t->msg_ready)
			fatal("message %u arrived before the previous one was consumed", h.msg_id);
		r = tb_rx_data(&t->rx, &h, p + TB_ETH_HLEN + TB_HDR_LEN, t->rx_stage);
		if (r < 0)
			fatal("DATA seq %u (expected %u) msg %u off %u: %s", h.seq,
			      t->rx.expected_seq, h.msg_id, h.frag_off, strerror(-r));
		if (r == TB_RX_DONE)
			message_done(t);
		else if (tb_rx_should_ack(&t->rx))
			send_ack(t);
		break;
	case TB_ACK:
		if (tb_tx_on_ack(&t->tx, h.seq))
			fatal("ACK %u beyond the frames sent (next %u)", h.seq, t->tx.next_seq);
		if ((int32_t)(h.aux - t->peer_completed) > 0)
			t->peer_completed = h.aux;
		break;
	case TB_BYE:
		t->bye = 1;
		break;
	default:
		t->ignored++;
	}
}

static void poll_rx(struct tb *t)
{
	struct rte_mbuf *m[BURST];
	uint16_t n = rte_eth_rx_burst(t->port, 0, m, BURST);

	for (uint16_t i = 0; i < n; i++) {
		handle(t, m[i]);
		rte_pktmbuf_free(m[i]);
	}
}

/* Cut src[0..len) into frames and send them within the window. */
static void send_message(struct tb *t, const uint8_t *src, uint32_t len, uint8_t flags)
{
	uint32_t n = tb_frag_count(len, t->fp);
	struct rte_mbuf *batch[BURST];
	uint16_t k = 0;

	for (uint32_t i = 0; i < n; i++) {
		struct tb_hdr h = { .magic = TB_MAGIC, .type = TB_DATA, .msg_id = t->tx_msg_id,
				    .msg_len = len, .run_id = t->run_id };
		uint16_t plen = 0;
		int last = 0;

		while (!tb_tx_can_send(&t->tx)) {
			if (k) {
				send_burst(t, batch, k);
				k = 0;
			}
			poll_rx(t);
			check_stall(t, "waiting for window credit");
		}
		if (tb_frag_at(len, t->fp, i, &h.frag_off, &plen, &last))
			fatal("frame %u of a %u-byte message", i, len);
		h.payload_len = plen;
		h.seq = t->tx.next_seq;
		h.flags = (uint8_t)(flags & TB_F_VERIFY);
		if (last)
			h.flags |= (uint8_t)(TB_F_LAST | (flags & TB_F_ACKREQ));
		batch[k++] = frame(t, &h, src + h.frag_off, 0);
		tb_tx_sent(&t->tx);
		if (k == BURST) {
			send_burst(t, batch, k);
			k = 0;
		}
	}
	if (k)
		send_burst(t, batch, k);
	t->tx_msg_id++;
}

static void wait_message(struct tb *t, const char *what)
{
	progress(t);
	while (!t->msg_ready) {
		poll_rx(t);
		check_stall(t, what);
	}
	t->msg_ready = 0;
}

/* ---- setup ---- */

static const char *attach_mode_name(int ifindex)
{
	LIBBPF_OPTS(bpf_xdp_query_opts, q);

	if (bpf_xdp_query(ifindex, 0, &q))
		return "unknown";
	switch (q.attach_mode) {
	case XDP_ATTACHED_NONE: return "none";
	case XDP_ATTACHED_DRV: return "drv";
	case XDP_ATTACHED_SKB: return "skb";
	case XDP_ATTACHED_HW: return "hw";
	case XDP_ATTACHED_MULTI: return "multi";
	default: return "unknown";
	}
}

/* 1 zero-copy, 0 copy mode, -1 no AF_XDP socket found in this process. */
static int xsk_zerocopy(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int result = -1;

	if (!d)
		return -1;
	while ((e = readdir(d))) {
		int fd = atoi(e->d_name), dom = 0;
		socklen_t l = sizeof(dom);
		struct xdp_options opt;
		socklen_t ol = sizeof(opt);

		if (e->d_name[0] < '0' || e->d_name[0] > '9')
			continue;
		if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &dom, &l) || dom != AF_XDP)
			continue;
		if (!getsockopt(fd, SOL_XDP, XDP_OPTIONS, &opt, &ol)) {
			result = !!(opt.flags & XDP_OPTIONS_ZEROCOPY);
			break;
		}
	}
	closedir(d);
	return result;
}

static uint32_t netdev_mtu(const char *iface)
{
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	uint32_t mtu = 0;

	if (fd < 0)
		return 0;
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
	if (!ioctl(fd, SIOCGIFMTU, &ifr))
		mtu = (uint32_t)ifr.ifr_mtu;
	close(fd);
	return mtu;
}

static void port_init(struct tb *t)
{
	struct rte_eth_conf conf = { 0 };
	struct rte_eth_dev_info info;
	uint16_t mtu;
	int r;

	if (!rte_eth_dev_is_valid_port(t->port))
		fatal("no DPDK port %u (pass --vdev net_af_xdp0,iface=...)", t->port);
	t->pool = rte_pktmbuf_pool_create("tb_pool", NB_MBUF, MBUF_CACHE, 0,
					  RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (!t->pool)
		fatal("mbuf pool: %s (hugepages reserved?)", rte_strerror(rte_errno));
	if ((r = rte_eth_dev_info_get(t->port, &info)))
		fatal("dev_info: %s", strerror(-r));
	t->dpdk_max_mtu = info.max_mtu;
	if ((r = rte_eth_dev_configure(t->port, 1, 1, &conf)))
		fatal("configure: %s", strerror(-r));
	if ((r = rte_eth_rx_queue_setup(t->port, 0, 0, rte_eth_dev_socket_id(t->port), NULL,
					t->pool)))
		fatal("rx queue: %s", strerror(-r));
	if ((r = rte_eth_tx_queue_setup(t->port, 0, 0, rte_eth_dev_socket_id(t->port), NULL)))
		fatal("tx queue: %s", strerror(-r));
	if ((r = rte_eth_dev_start(t->port)))
		fatal("start: %s", strerror(-r));
	if ((r = rte_eth_macaddr_get(t->port, &t->self)))
		fatal("mac: %s", strerror(-r));
	if ((r = rte_eth_dev_get_mtu(t->port, &mtu)))
		fatal("mtu: %s", strerror(-r));
	t->dpdk_mtu = mtu;
	if (!info.if_index || !if_indextoname(info.if_index, t->iface))
		snprintf(t->iface, sizeof(t->iface), "?");
	t->netdev_mtu = netdev_mtu(t->iface);
	t->mtu = t->netdev_mtu && t->netdev_mtu < t->dpdk_mtu ? t->netdev_mtu : t->dpdk_mtu;
	t->fp = tb_frag_payload(t->mtu);
	if (!t->fp)
		fatal("MTU %u leaves no payload", t->mtu);
	t->attach_mode = info.if_index ? attach_mode_name((int)info.if_index) : "unknown";
	t->zerocopy = xsk_zerocopy();
}

static void buffers_init(struct tb *t)
{
	size_t n = t->o.max_size;

	if (tb_gpu_init(t->o.gpu, t->gpu_name, sizeof(t->gpu_name)))
		fatal("GPU init: %s", tb_gpu_error());
	if (posix_memalign((void **)&t->tx_stage, 4096, n) ||
	    posix_memalign((void **)&t->rx_stage, 4096, n) ||
	    posix_memalign((void **)&t->check, 4096, n))
		fatal("staging buffers: out of memory");
	if (tb_host_register(t->tx_stage, n) || tb_host_register(t->rx_stage, n) ||
	    tb_host_register(t->check, n))
		fatal("register staging buffers: %s", tb_gpu_error());
	if (tb_gpu_alloc(&t->gpu_src, n) || tb_gpu_alloc(&t->gpu_dst, n))
		fatal("device buffers: %s", tb_gpu_error());
	memset(t->rx_stage, 0, n);
	memset(t->check, 0, n);
	if (tb_gpu_h2d(t->gpu_src, t->check, n) || tb_gpu_h2d(t->gpu_dst, t->check, n))
		fatal("clear device buffers: %s", tb_gpu_error());
}

static void print_common(struct tb *t)
{
	printf("\"dpdk_version\":\"%s\",\"vdev\":\"%s\",\"iface\":\"%s\","
	       "\"xdp_attach_mode\":\"%s\",\"xsk_zerocopy\":%s,\"mtu\":%u,\"dpdk_mtu\":%u,"
	       "\"dpdk_max_mtu\":%u,\"netdev_mtu\":%u,\"frag_payload\":%zu,\"window_frames\":%u,\"ack_every\":%u,"
	       "\"gpu\":\"%s\",\"host_registered\":true",
	       rte_version(), t->vdev, t->iface, t->attach_mode,
	       t->zerocopy < 0 ? "null" : t->zerocopy ? "true" : "false", t->mtu, t->dpdk_mtu,
	       t->dpdk_max_mtu, t->netdev_mtu, t->fp, t->o.window_frames, t->o.ack_every, t->gpu_name);
}

/* ---- client ---- */

static void client_hello(struct tb *t)
{
	uint64_t start = now_ns(), last = 0;
	uint32_t largest = 0;

	for (int i = 0; i < t->o.nsizes; i++)
		if (t->o.sizes[i] > largest)
			largest = t->o.sizes[i];
	session_reset(t, (uint32_t)(now_ns() ^ ((uint64_t)getpid() << 16)) | 1u);
	while (!t->hello_acked) {
		if (now_ns() - last > HELLO_INTERVAL_NS) {
			send_ctrl(t, TB_HELLO, 0, largest, (uint32_t)t->o.mode, !t->have_peer);
			last = now_ns();
		}
		poll_rx(t);
		if (force_quit || now_ns() - start > 30000000000ull)
			fatal("no HELLO_ACK from a server within 30 s");
	}
	if (t->peer_max < largest)
		fatal("server buffer %u bytes is smaller than the largest size %u", t->peer_max,
		      largest);
}

/* Put the pattern of the next message id into gpu_src (untimed). */
static void load_pattern(struct tb *t, uint32_t size)
{
	tb_pattern_fill(t->check, size, t->tx_msg_id);
	if (tb_gpu_h2d(t->gpu_src, t->check, size))
		fatal("load pattern: %s", tb_gpu_error());
}

static void d2h_stage(struct tb *t, uint32_t size)
{
	if (tb_gpu_d2h(t->tx_stage, t->gpu_src, size))
		fatal("device->host copy: %s", tb_gpu_error());
}

static void client_pingpong(struct tb *t, uint32_t size)
{
	uint32_t total = t->o.warmup + t->o.iters;
	uint64_t *ns = calloc(t->o.iters, sizeof(*ns));
	uint64_t v0 = t->verified, f_tx = t->frames_tx, f_rx = t->frames_rx;
	struct tb_lat lat;

	if (!ns)
		fatal("out of memory");
	for (uint32_t i = 0; i < total; i++) {
		int verify = i < t->o.warmup || t->o.verify_all;
		uint64_t t0;

		if (verify)
			load_pattern(t, size);
		t0 = now_ns();
		d2h_stage(t, size);
		send_message(t, t->tx_stage, size, verify ? TB_F_VERIFY : 0);
		wait_message(t, "waiting for the echo");
		if (t->rx.done_len != size)
			fatal("echo of %u bytes for a %u-byte request", t->rx.done_len, size);
		if (i >= t->o.warmup)
			ns[i - t->o.warmup] = (t->t_done - t0) / 2;
	}
	tb_summarize(ns, t->o.iters, &lat);
	printf("{\"arm\":\"dpdk-af_xdp\",\"role\":\"client\",\"mode\":\"pingpong\","
	       "\"size\":%u,\"iters\":%u,\"warmup\":%u,\"frames_per_msg\":%u,", size,
	       t->o.iters, t->o.warmup, tb_frag_count(size, t->fp));
	print_common(t);
	printf(",\"one_way_ns\":{\"min\":%" PRIu64 ",\"p50\":%" PRIu64 ",\"p99\":%" PRIu64
	       ",\"mean\":%.1f,\"max\":%" PRIu64 "},\"verified_messages\":%" PRIu64
	       ",\"timed_includes_verify\":%s,\"frames_tx\":%" PRIu64 ",\"frames_rx\":%" PRIu64
	       "}\n", lat.min, lat.p50, lat.p99, lat.mean, lat.max, t->verified - v0,
	       t->o.verify_all ? "true" : "false", t->frames_tx - f_tx, t->frames_rx - f_rx);
	fflush(stdout);
	free(ns);
}

static void wait_completed(struct tb *t, const char *what)
{
	progress(t);
	while (t->peer_completed != t->tx_msg_id) {
		poll_rx(t);
		check_stall(t, what);
	}
}

static void client_stream(struct tb *t, uint32_t size)
{
	uint64_t msgs = tb_stream_messages(size, t->o.iters, t->o.stream_min_bytes);
	uint64_t f_tx = t->frames_tx, f_rx = t->frames_rx, t0, t1;
	uint64_t verified_sent = 0;
	double secs;

	/* warmup: each message verified by the server, one at a time */
	for (uint32_t i = 0; i < t->o.warmup; i++) {
		load_pattern(t, size);
		d2h_stage(t, size);
		send_message(t, t->tx_stage, size, TB_F_VERIFY | TB_F_ACKREQ);
		wait_completed(t, "waiting for a warmup message");
		verified_sent++;
	}
	t0 = now_ns();
	for (uint64_t m = 0; m < msgs; m++) {
		uint8_t flags = m == msgs - 1 ? TB_F_ACKREQ : 0;

		if (t->o.verify_all) {
			load_pattern(t, size);
			flags |= TB_F_VERIFY;
			verified_sent++;
		}
		d2h_stage(t, size);
		send_message(t, t->tx_stage, size, flags);
	}
	wait_completed(t, "waiting for the last streamed message");
	t1 = now_ns();
	secs = (double)(t1 - t0) / 1e9;
	printf("{\"arm\":\"dpdk-af_xdp\",\"role\":\"client\",\"mode\":\"stream\","
	       "\"size\":%u,\"messages\":%" PRIu64 ",\"warmup\":%u,\"frames_per_msg\":%u,", size,
	       msgs, t->o.warmup, tb_frag_count(size, t->fp));
	print_common(t);
	printf(",\"seconds\":%.6f,\"bytes_per_s\":%.1f,\"gbit_per_s\":%.4f,"
	       "\"verified_messages\":%" PRIu64 ",\"timed_includes_verify\":%s,"
	       "\"frames_tx\":%" PRIu64 ",\"frames_rx\":%" PRIu64 "}\n", secs,
	       (double)msgs * size / secs, (double)msgs * size * 8 / secs / 1e9,
	       verified_sent, t->o.verify_all ? "true" : "false", t->frames_tx - f_tx,
	       t->frames_rx - f_rx);
	fflush(stdout);
}

static int client(struct tb *t)
{
	client_hello(t);
	for (int i = 0; i < t->o.nsizes; i++) {
		if (t->o.mode == TB_MODE_PINGPONG)
			client_pingpong(t, t->o.sizes[i]);
		else
			client_stream(t, t->o.sizes[i]);
	}
	for (int i = 0; i < 3; i++)
		send_ctrl(t, TB_BYE, 0, 0, 0, 0);
	return 0;
}

/* ---- server ---- */

static int server(struct tb *t)
{
	uint64_t echoes = 0;

	fprintf(stderr, "dpdk_tb: server on %s (%02x:%02x:%02x:%02x:%02x:%02x), MTU %u, "
		"waiting for a client\n", t->iface, t->self.addr_bytes[0], t->self.addr_bytes[1],
		t->self.addr_bytes[2], t->self.addr_bytes[3], t->self.addr_bytes[4],
		t->self.addr_bytes[5], t->mtu);
	while (!t->bye) {
		if (force_quit)
			fatal("interrupted");
		poll_rx(t);
		if (t->rx.in_msg)
			check_stall(t, "reassembling a message");
		else
			progress(t);
		if (t->msg_ready) {
			t->msg_ready = 0;
			if (t->peer_mode == TB_MODE_PINGPONG) {
				uint32_t len = t->rx.done_len;

				if (tb_gpu_d2h(t->tx_stage, t->gpu_dst, len))
					fatal("device->host copy: %s", tb_gpu_error());
				send_message(t, t->tx_stage, len, t->rx.done_flags & TB_F_VERIFY);
				echoes++;
			}
		}
	}
	printf("{\"arm\":\"dpdk-af_xdp\",\"role\":\"server\",\"mode\":\"%s\",\"messages\":%"
	       PRIu64 ",\"echoes\":%" PRIu64 ",", t->peer_mode == TB_MODE_STREAM ? "stream" :
	       "pingpong", t->rx.messages, echoes);
	print_common(t);
	printf(",\"verified_messages\":%" PRIu64 ",\"frames_tx\":%" PRIu64 ",\"frames_rx\":%"
	       PRIu64 ",\"ignored_frames\":%" PRIu64 "}\n", t->verified, t->frames_tx,
	       t->frames_rx, t->ignored);
	fflush(stdout);
	return 0;
}

static void record_vdev(struct tb *t, int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		const char *v = NULL;

		if (!strcmp(argv[i], "--"))
			break;
		if (!strcmp(argv[i], "--vdev") && i + 1 < argc)
			v = argv[i + 1];
		else if (!strncmp(argv[i], "--vdev=", 7))
			v = argv[i] + 7;
		if (v) {
			for (size_t k = 0, j = 0; v[k] && j + 1 < sizeof(t->vdev); k++)
				if (v[k] != '"' && v[k] != '\\')
					t->vdev[j++] = v[k];
			return;
		}
	}
}

int main(int argc, char **argv)
{
	static struct tb t;
	char err[256] = "";
	int n, r;

	G = &t;
	record_vdev(&t, argc, argv);
	n = rte_eal_init(argc, argv);
	if (n < 0) {
		fprintf(stderr, "dpdk_tb: EAL init failed: %s\n", rte_strerror(rte_errno));
		return 1;
	}
	argv[n] = argv[0];
	r = tb_parse_opts(argc - n, argv + n, &t.o, err, sizeof(err));
	if (r) {
		fprintf(r > 0 ? stdout : stderr, "%s%s%s", r > 0 ? "" : "dpdk_tb: ", r > 0 ? "" : err,
			r > 0 ? TB_USAGE : "\n" TB_USAGE);
		rte_eal_cleanup();
		return r > 0 ? 0 : 2;
	}
	if (t.o.have_peer_mac) {
		memcpy(t.peer.addr_bytes, t.o.peer_mac, 6);
		t.have_peer = 1;
	}
	t.port = (uint16_t)t.o.port;
	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	port_init(&t);
	buffers_init(&t);
	progress(&t);
	r = t.o.role == TB_ROLE_CLIENT ? client(&t) : server(&t);
	cleanup();
	return r;
}
