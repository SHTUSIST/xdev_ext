// SPDX-License-Identifier: GPL-2.0
/*
 * Run-loop behaviour of the no-CUDA GPU/AF_XDP sample.
 *
 * The sample source is compiled into this test unchanged.  poll(), recvfrom()
 * and sendto() are redirected to a scripted model of one AF_XDP socket, and
 * the fill, completion, RX and TX rings are real libxdp rings over test
 * memory.  The sample's own run_loop(), process_packets() and frame lifecycle
 * therefore run against a model NIC that consumes the fill ring for ingress,
 * writes a complete frame into each received buffer, consumes the TX ring
 * and records the transmitted bytes, and posts exact TX completions a
 * configurable number of polls later.
 *
 * TX moves the way the kernel moves it.  Zero-copy (the default): the driver
 * takes the whole TX ring at every poll() entry, and also on sendto() when
 * the TX ring's need-wakeup flag is set.  Copy mode (the XDP_FLAGS_SKB_MODE
 * fallback): only the kernel's transmit pass moves TX.  sendto() runs one
 * pass, and poll() runs one on entry and, after a timeout, one more.  A pass
 * takes at most 32 descriptors, and a scripted -EAGAIN pass (socket send
 * buffer full, driver busy) takes none and leaves them for a retry.  A model
 * clock adds up the expired poll timeouts.
 *
 * Requirements checked:
 *  - with no traffic the loop blocks in poll() with a finite timeout and
 *    never returns early (no busy spin), even though a socket with TX ring
 *    space is always writable;
 *  - a fatal poll event (POLLERR, POLLHUP, POLLNVAL) stops the loop with an
 *    error and running == 0 before any ring, frame or wakeup is touched;
 *  - TX completions that land after ingress stops are still reaped and the
 *    frames return to the fill ring (no quiet-period stall), and one quiet
 *    poll reaps every completion present, not one RX batch;
 *  - at most one early POLLOUT wakeup follows each RX batch that did work;
 *  - the fill-ring wakeup follows the refill, and a maintenance failure is a
 *    fail-closed loop exit;
 *  - in copy mode the loop kicks TX while descriptors wait on the TX ring and
 *    the last reply leaves without a full poll timeout, however many passes
 *    hit -EAGAIN; once the TX ring is empty the loop is back to POLLIN-only
 *    full-timeout waits;
 *  - every poll entered while TX descriptors wait follows a kick, in copy
 *    mode and whenever the TX ring's need-wakeup flag is set;
 *  - a fixed-header IPv4/UDP frame is sent back with its Ethernet, IPv4 and
 *    UDP endpoints swapped and its checksums still valid, and every other
 *    frame is sent back unchanged.  Built with UBSan, the sample's header
 *    accesses are also checked against the packet layout, which puts the
 *    IPv4 header at an address that is 2 mod 4.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Every header the sample includes, before the redirection macros below, so
 * that the macros apply to the sample body only. */
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

static int model_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms);
static ssize_t model_recvfrom(int fd, void *buf, size_t len, int flags,
			      struct sockaddr *addr, socklen_t *addr_len);
static ssize_t model_sendto(int fd, const void *buf, size_t len, int flags,
			    const struct sockaddr *addr, socklen_t addr_len);
static unsigned int model_if_nametoindex(const char *ifname);

#define main gpu_xdp_nocuda_sample_main
#define if_nametoindex(ifname) model_if_nametoindex(ifname)
#define poll(fds, nfds, timeout) model_poll(fds, nfds, timeout)
#define recvfrom(fd, buf, len, flags, addr, addr_len) \
	model_recvfrom(fd, buf, len, flags, addr, addr_len)
#define sendto(fd, buf, len, flags, addr, addr_len) \
	model_sendto(fd, buf, len, flags, addr, addr_len)
#include "../../../../drivers/gpu/nvidia-p2p/samples/gpu_xdp_p2p_nocuda.c"
#undef sendto
#undef recvfrom
#undef poll
#undef if_nametoindex
#undef main

#define MODEL_FD		1000
#define MODEL_IFINDEX		7
#define MODEL_MAX_POLLS		80
#define MODEL_RX_HEADROOM	256
/* Unless a scenario scripts its own frames, every ingress frame is this long
 * and a complete Ethernet/IPv4/UDP frame, so each RX batch also goes through
 * the sample's packet rewrite. */
#define MODEL_PACKET_LEN	64
#define MODEL_FRAME_MAX		128
#define MODEL_WIRE_MAX		64	/* transmitted frames recorded */
#define MODEL_FATAL		(POLLERR | POLLHUP | POLLNVAL)
#define MODEL_TX_PASS_BUDGET	32	/* TX_BATCH_SIZE in net/xdp/xsk.c */
#define MODEL_FULL_TIMEOUT_MS	1000	/* the loop's idle poll timeout */
/* A TX retry may wait a short re-poll, never a full poll timeout. */
#define MODEL_RETRY_MS_MAX	10

static unsigned int checks;
static unsigned int failures;
static const char *scenario;

#define EXPECT_EQ(expected, actual) do {                                    \
	long long expected_ = (long long)(expected);                           \
	long long actual_ = (long long)(actual);                               \
	checks++;                                                              \
	if (expected_ != actual_) {                                            \
		fprintf(stderr, "%s:%d [%s] %s: expected %lld, got %lld\n",    \
			__FILE__, __LINE__, scenario, #actual, expected_,      \
			actual_);                                              \
		failures++;                                                    \
	}                                                                      \
} while (0)

#define EXPECT_TRUE(cond) EXPECT_EQ(1, !!(cond))

/* Observable state; a fatal poll event must leave all of it unchanged. */
struct model_snapshot {
	uint32_t fq_prod, fq_cons, cq_prod, cq_cons;
	uint32_t rx_prod, rx_cons, tx_prod, tx_cons;
	uint32_t rx_cached_cons, cq_cached_cons, fq_cached_prod, tx_cached_prod;
	uint32_t fill, rx, tx, free_frames, recycle;
	uint64_t rx_packets, tx_packets, errors;
	unsigned int fq_wakeups, tx_kicks;
};

struct model_completion {
	uint64_t addr;
	unsigned int due_poll;
};

struct model_frame {
	uint32_t len;
	uint8_t bytes[MODEL_FRAME_MAX];
};

/* What a test frame carries; model_build_frame() lays it out byte by byte. */
struct model_flow {
	const char *name;
	uint8_t dst_mac[ETH_ALEN], src_mac[ETH_ALEN];
	uint8_t version_ihl;		/* IPv4 byte 0: version << 4 | IHL */
	uint8_t protocol;
	uint32_t saddr, daddr;		/* host order */
	uint16_t sport, dport;
	bool l4_checksum;		/* false: 0, "no checksum" in IPv4 */
	uint32_t len;			/* whole frame */
	uint8_t seed;			/* identification and payload pattern */
};

static struct {
	/* Ring memory as the kernel would map it. */
	uint32_t fq_prod, fq_cons, fq_flags;
	uint32_t cq_prod, cq_cons, cq_flags;
	uint32_t rx_prod, rx_cons, rx_flags;
	uint32_t tx_prod, tx_cons, tx_flags;
	uint64_t fq_ring[FILL_RING_SIZE];
	uint64_t cq_ring[COMP_RING_SIZE];
	struct xdp_desc rx_ring[FILL_RING_SIZE];
	struct xdp_desc tx_ring[COMP_RING_SIZE];

	/* Script, indexed by 0-based poll number. */
	unsigned int poll_limit;
	unsigned int rx_at[MODEL_MAX_POLLS];
	bool empty_pollin_at[MODEL_MAX_POLLS];
	short fatal_at[MODEL_MAX_POLLS];
	unsigned int completion_delay;
	unsigned int completion_release_at; /* none posted before this poll */
	unsigned int foreign_completion_at;	/* 1-based; 0 = never */
	const struct model_frame *ingress;	/* cycled; none: default */
	unsigned int ingress_count, ingress_next;
	bool tx_copy;			/* copy-mode TX, see the top comment */
	unsigned int tx_eagain_left;	/* next passes that hit -EAGAIN */
	/* The sample's create_xsk() may run against a driver without
	 * zero-copy: a zero-copy bind is refused, a copy-mode bind works. */
	bool setup_allowed;
	unsigned int creates;
	uint32_t create_xdp_flags[2], create_bind_flags[2];
	uint32_t attach_xdp_flags;

	/* NIC-side TX completions not yet posted to the completion ring. */
	struct model_completion pending[COMP_RING_SIZE];
	unsigned int pending_head, pending_count;

	/* Observations. */
	unsigned int polls;
	unsigned int timeouts;		/* blocked until the timeout expired */
	unsigned int early_idle;	/* returned at once, no ingress */
	unsigned int zero_waits;	/* nothing ready, zero timeout */
	unsigned int unbounded_waits;	/* nothing ready, no timeout */
	unsigned int bad_poll_args;
	unsigned int foreign_calls;
	unsigned int rx_without_fill;
	unsigned int bad_tx_descs;	/* outside UMEM or too long to record */
	struct model_frame wire[MODEL_WIRE_MAX];	/* first frames sent */
	unsigned int wire_count;
	short events[MODEL_MAX_POLLS];
	int timeout_ms[MODEL_MAX_POLLS];
	bool timed_out[MODEL_MAX_POLLS];
	unsigned int clock_ms;		/* sum of the expired poll timeouts */
	unsigned int full_timeouts;	/* expired full-timeout waits */
	unsigned int tx_passes;		/* copy-mode passes that found TX */
	/* Model clock and full timeouts when the last TX descriptor left. */
	unsigned int tx_last_clock_ms, tx_last_full_timeouts;
	bool kicked;			/* sendto() since the last poll() */
	unsigned int unkicked_polls;	/* TX waiting, kick due, none made */
	unsigned int fq_wakeups, tx_kicks;
	uint32_t fq_queued_at_wakeup;	/* fill entries visible at last wakeup */
	unsigned int wakeups_before_refill; /* FREE frames not yet in FILL */
	struct model_snapshot at_last_poll;
} model;

static xsk_ctx_t test_ctx;
static gpu_p2p_ctx_t test_gpu;
static uint8_t test_umem[UMEM_SIZE] __attribute__((aligned(4096)));
static struct model_frame model_default_frame;

static void ring_prod_init(struct xsk_ring_prod *ring, uint32_t size,
			   uint32_t *producer, uint32_t *consumer,
			   void *entries, uint32_t *flags);
static void ring_cons_init(struct xsk_ring_cons *ring, uint32_t size,
			   uint32_t *producer, uint32_t *consumer,
			   void *entries, uint32_t *flags);

/*
 * libxdp entry points reached only from the sample's main() and setup code.
 * Outside a scenario that runs create_xsk() a call is a test failure.
 */
int xsk_umem__create(struct xsk_umem **umem, void *umem_area, __u64 size,
		     struct xsk_ring_prod *fill, struct xsk_ring_cons *comp,
		     const struct xsk_umem_config *config)
{
	(void)umem; (void)umem_area; (void)size; (void)fill; (void)comp;
	(void)config;
	model.foreign_calls++;
	return -ENOSYS;
}

int xsk_socket__create(struct xsk_socket **xsk, const char *ifname,
		       __u32 queue_id, struct xsk_umem *umem,
		       struct xsk_ring_cons *rx, struct xsk_ring_prod *tx,
		       const struct xsk_socket_config *config)
{
	(void)ifname; (void)queue_id; (void)umem;
	if (!model.setup_allowed || model.creates == 2) {
		model.foreign_calls++;
		return -ENOSYS;
	}
	model.create_xdp_flags[model.creates] = config->xdp_flags;
	model.create_bind_flags[model.creates] = config->bind_flags;
	model.creates++;
	if (config->bind_flags & XDP_ZEROCOPY)
		return -EOPNOTSUPP;	/* driver without zero-copy */
	ring_cons_init(rx, FILL_RING_SIZE, &model.rx_prod, &model.rx_cons,
		       model.rx_ring, &model.rx_flags);
	ring_prod_init(tx, COMP_RING_SIZE, &model.tx_prod, &model.tx_cons,
		       model.tx_ring, &model.tx_flags);
	*xsk = (struct xsk_socket *)&model;
	return 0;
}

int xsk_umem__delete(struct xsk_umem *umem)
{
	(void)umem;
	model.foreign_calls++;
	return -ENOSYS;
}

void xsk_socket__delete(struct xsk_socket *xsk)
{
	(void)xsk;
	model.foreign_calls++;
}

int xsk_socket__fd(const struct xsk_socket *xsk)
{
	(void)xsk;
	return MODEL_FD;
}

void xdev_ext_xsk_redirect_init(struct xdev_ext_xsk_redirect *redirect)
{
	memset(redirect, 0, sizeof(*redirect));
	if (!model.setup_allowed)
		model.foreign_calls++;
}

static unsigned int model_if_nametoindex(const char *ifname)
{
	(void)ifname;
	if (!model.setup_allowed) {
		model.foreign_calls++;
		return 0;
	}
	return MODEL_IFINDEX;
}

bool xdev_ext_xsk_redirect_is_active(const struct xdev_ext_xsk_redirect *redirect)
{
	(void)redirect;
	model.foreign_calls++;
	return false;
}

int xdev_ext_xsk_redirect_attach(struct xdev_ext_xsk_redirect *redirect,
			    const struct xdev_ext_xsk_flow_filter *filter, int ifindex,
			    uint32_t queue_id, int xsk_fd, uint32_t xdp_flags)
{
	(void)redirect; (void)filter; (void)queue_id;
	if (!model.setup_allowed || ifindex != MODEL_IFINDEX ||
	    xsk_fd != MODEL_FD) {
		model.foreign_calls++;
		return -ENOSYS;
	}
	model.attach_xdp_flags = xdp_flags;
	return 0;
}

int xdev_ext_xsk_redirect_detach(struct xdev_ext_xsk_redirect *redirect)
{
	(void)redirect;
	model.foreign_calls++;
	return -ENOSYS;
}

static void model_snapshot(struct model_snapshot *snap)
{
	const struct xdev_ext_xsk_frame_owner *owner = &test_ctx.frames.owner;

	memset(snap, 0, sizeof(*snap));
	snap->fq_prod = model.fq_prod;
	snap->fq_cons = model.fq_cons;
	snap->cq_prod = model.cq_prod;
	snap->cq_cons = model.cq_cons;
	snap->rx_prod = model.rx_prod;
	snap->rx_cons = model.rx_cons;
	snap->tx_prod = model.tx_prod;
	snap->tx_cons = model.tx_cons;
	snap->rx_cached_cons = test_ctx.rx.cached_cons;
	snap->cq_cached_cons = test_ctx.cq.cached_cons;
	snap->fq_cached_prod = test_ctx.fq.cached_prod;
	snap->tx_cached_prod = test_ctx.tx.cached_prod;
	snap->fill = xdev_ext_xsk_frame_count_state(owner, XDEV_EXT_XSK_FRAME_FILL);
	snap->rx = xdev_ext_xsk_frame_count_state(owner, XDEV_EXT_XSK_FRAME_RX);
	snap->tx = xdev_ext_xsk_frame_count_state(owner, XDEV_EXT_XSK_FRAME_TX);
	snap->free_frames = xdev_ext_xsk_frame_count_state(owner, XDEV_EXT_XSK_FRAME_FREE);
	snap->recycle = test_ctx.frames.recycle.count;
	snap->rx_packets = stats.rx_packets;
	snap->tx_packets = stats.tx_packets;
	snap->errors = stats.errors;
	snap->fq_wakeups = model.fq_wakeups;
	snap->tx_kicks = model.tx_kicks;
}

static void put_be16(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 8);
	p[1] = (uint8_t)value;
}

static void put_be32(uint8_t *p, uint32_t value)
{
	put_be16(p, value >> 16);
	put_be16(p + 2, value & 0xffff);
}

/* RFC 1071 one's-complement sum of big-endian 16-bit words. */
static uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t len)
{
	for (size_t i = 0; i + 1 < len; i += 2)
		sum += (uint32_t)p[i] << 8 | p[i + 1];
	if (len & 1)
		sum += (uint32_t)p[len - 1] << 8;
	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)sum;
}

/* IPv4 pseudo-header sum for an L4 checksum. */
static uint32_t pseudo_sum(const uint8_t *frame, uint8_t protocol,
			   uint32_t l4_len)
{
	return csum_add(0, frame + ETH_HLEN + 12, 8) + protocol + l4_len;
}

/* Lays the frame out byte by byte, independently of the header structs the
 * sample uses.  Bytes past the headers carry a pattern derived from @seed;
 * for a protocol other than UDP the four port bytes are filler too. */
static void model_build_frame(struct model_frame *frame,
			      const struct model_flow *flow)
{
	uint8_t *p = frame->bytes;
	uint8_t *ip = p + ETH_HLEN;
	uint32_t ip_len = (flow->version_ihl & 0xfu) * 4u;
	uint8_t *l4 = ip + ip_len;
	uint32_t l4_len = flow->len - ETH_HLEN - ip_len;
	uint16_t check;

	memset(frame, 0, sizeof(*frame));
	frame->len = flow->len;
	for (uint32_t i = 0; i < MODEL_FRAME_MAX; i++)
		p[i] = (uint8_t)(flow->seed + 7 * i);
	memcpy(p, flow->dst_mac, ETH_ALEN);
	memcpy(p + ETH_ALEN, flow->src_mac, ETH_ALEN);
	put_be16(p + 12, ETH_P_IP);
	ip[0] = flow->version_ihl;
	ip[1] = 0;					/* DSCP/ECN */
	put_be16(ip + 2, flow->len - ETH_HLEN);	/* total length */
	put_be16(ip + 4, 0x1200u + flow->seed);	/* identification */
	put_be16(ip + 6, 0x4000);			/* don't fragment */
	ip[8] = 64;					/* TTL */
	ip[9] = flow->protocol;
	put_be16(ip + 10, 0);
	put_be32(ip + 12, flow->saddr);
	put_be32(ip + 16, flow->daddr);
	memset(ip + 20, 1, ip_len - 20);		/* NOP options */
	put_be16(ip + 10, (uint16_t)~csum_fold(csum_add(0, ip, ip_len)));
	put_be16(l4, flow->sport);
	put_be16(l4 + 2, flow->dport);
	put_be16(l4 + 4, l4_len);
	put_be16(l4 + 6, 0);
	if (flow->l4_checksum) {
		check = (uint16_t)~csum_fold(csum_add(
			pseudo_sum(p, flow->protocol, l4_len), l4, l4_len));
		put_be16(l4 + 6, check ? check : 0xffff);
	}
}

/* The same frame with both endpoints exchanged at every layer. */
static struct model_flow model_reply_flow(const struct model_flow *flow)
{
	struct model_flow reply = *flow;

	memcpy(reply.dst_mac, flow->src_mac, ETH_ALEN);
	memcpy(reply.src_mac, flow->dst_mac, ETH_ALEN);
	reply.saddr = flow->daddr;
	reply.daddr = flow->saddr;
	reply.sport = flow->dport;
	reply.dport = flow->sport;
	return reply;
}

/* A receiver's checks on a fixed-header IPv4/UDP frame. */
static bool ipv4_checksum_valid(const uint8_t *frame)
{
	return csum_fold(csum_add(0, frame + ETH_HLEN, 20)) == 0xffff;
}

static bool udp_checksum_valid(const uint8_t *frame, uint32_t len)
{
	const uint8_t *udp = frame + ETH_HLEN + 20;
	uint32_t udp_len = len - ETH_HLEN - 20;

	if (!udp[6] && !udp[7])
		return true;	/* sent without a checksum, valid for IPv4 */
	return csum_fold(csum_add(pseudo_sum(frame, IPPROTO_UDP, udp_len),
				  udp, udp_len)) == 0xffff;
}

/* Offset of the first differing byte, or -1. */
static long first_difference(const uint8_t *want, const uint8_t *got,
			     uint32_t len)
{
	for (uint32_t i = 0; i < len; i++)
		if (want[i] != got[i])
			return (long)i;
	return -1;
}

/* Records the bytes a TX descriptor puts on the wire. */
static void model_record_tx(const struct xdp_desc *desc)
{
	struct model_frame *wire;

	if (desc->len > MODEL_FRAME_MAX || desc->addr > UMEM_SIZE ||
	    desc->len > UMEM_SIZE - desc->addr) {
		model.bad_tx_descs++;
		return;
	}
	if (model.wire_count == MODEL_WIRE_MAX)
		return;
	wire = &model.wire[model.wire_count++];
	wire->len = desc->len;
	memcpy(wire->bytes, test_umem + desc->addr, desc->len);
}

/* One TX descriptor leaves.  Its exact completion is posted at the first
 * poll from @poll + completion_delay on whose NIC step runs after this. */
static void model_take_tx(unsigned int poll)
{
	const struct xdp_desc *tx_desc =
		&model.tx_ring[model.tx_cons & (COMP_RING_SIZE - 1)];
	unsigned int slot = (model.pending_head + model.pending_count) %
			    COMP_RING_SIZE;

	model_record_tx(tx_desc);
	model.pending[slot].addr = tx_desc->addr;
	model.pending[slot].due_poll = poll + model.completion_delay;
	model.pending_count++;
	model.tx_cons++;
	model.tx_last_clock_ms = model.clock_ms;
	model.tx_last_full_timeouts = model.full_timeouts;
}

/* A zero-copy driver takes everything published on the TX ring. */
static void model_driver_takes_tx(unsigned int poll)
{
	while (model.tx_cons != model.tx_prod)
		model_take_tx(poll);
}

/* One copy-mode transmit pass (__xsk_generic_xmit()). */
static int model_copy_tx_pass(unsigned int poll)
{
	unsigned int budget = MODEL_TX_PASS_BUDGET;

	if (model.tx_cons == model.tx_prod)
		return 0;
	model.tx_passes++;
	if (model.tx_eagain_left) {
		model.tx_eagain_left--;
		return -EAGAIN;
	}
	while (budget-- && model.tx_cons != model.tx_prod)
		model_take_tx(poll);
	return model.tx_cons == model.tx_prod ? 0 : -EAGAIN;
}

/* The model NIC, run at the start of poll number @n. */
static void model_nic_step(unsigned int n)
{
	/* A zero-copy driver takes what the application published on the TX
	 * ring; in copy mode only a transmit pass does. */
	if (!model.tx_copy)
		model_driver_takes_tx(n);
	/* Post the exact TX completions that are due, unless the NIC still
	 * holds them back to post them together. */
	while (model.pending_count && n >= model.completion_release_at &&
	       model.pending[model.pending_head].due_poll <= n) {
		model.cq_ring[model.cq_prod & (COMP_RING_SIZE - 1)] =
			model.pending[model.pending_head].addr;
		model.cq_prod++;
		model.pending_head = (model.pending_head + 1) % COMP_RING_SIZE;
		model.pending_count--;
	}
	/* A completion for a frame that was never transmitted. */
	if (model.foreign_completion_at == n + 1) {
		model.cq_ring[model.cq_prod & (COMP_RING_SIZE - 1)] =
			MODEL_RX_HEADROOM;
		model.cq_prod++;
	}
	/* Ingress: each packet consumes one fill-ring entry and is written
	 * into that frame after the headroom. */
	for (unsigned int i = 0; i < model.rx_at[n]; i++) {
		const struct model_frame *packet = &model_default_frame;
		struct xdp_desc *desc;
		uint64_t frame;

		if (model.fq_cons == model.fq_prod) {
			model.rx_without_fill++;
			break;
		}
		if (model.ingress_count)
			packet = &model.ingress[model.ingress_next++ %
						model.ingress_count];
		frame = model.fq_ring[model.fq_cons & (FILL_RING_SIZE - 1)];
		model.fq_cons++;
		desc = &model.rx_ring[model.rx_prod & (FILL_RING_SIZE - 1)];
		desc->addr = frame + MODEL_RX_HEADROOM;
		desc->len = packet->len;
		desc->options = 0;
		memcpy(test_umem + desc->addr, packet->bytes, packet->len);
		model.rx_prod++;
	}
}

/* Whether the kernel needs a sendto() to move what waits on the TX ring. */
static bool model_tx_kick_due(void)
{
	return model.tx_copy || (model.tx_flags & XDP_RING_NEED_WAKEUP);
}

static short model_ready(unsigned int n)
{
	short ready = 0;

	if (model.rx_cons != model.rx_prod || model.empty_pollin_at[n])
		ready |= POLLIN;
	/* xsk_tx_writeable(): TX ring at most half full. */
	if (model.tx_prod - model.tx_cons <= COMP_RING_SIZE / 2)
		ready |= POLLOUT;
	return ready | model.fatal_at[n];
}

static int model_poll(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
	unsigned int n = model.polls;

	if (nfds != 1 || !fds || fds[0].fd != MODEL_FD) {
		/* drain_tx_completions() and detach use poll(NULL, 0, ms) as a
		 * sleep; the run loop must poll exactly the socket. */
		model.bad_poll_args++;
		running = 0;
		errno = EINVAL;
		return -1;
	}
	if (n >= model.poll_limit || n >= MODEL_MAX_POLLS) {
		/* End of the script: behave like SIGINT during poll(). */
		running = 0;
		errno = EINTR;
		return -1;
	}
	model.polls++;
	model.events[n] = fds[0].events;
	model.timeout_ms[n] = timeout_ms;
	if (model_tx_kick_due() && model.tx_cons != model.tx_prod &&
	    !model.kicked)
		model.unkicked_polls++;
	model.kicked = false;
	model_nic_step(n);
	if (model.tx_copy)
		(void)model_copy_tx_pass(n);	/* xsk_poll() on entry */

	fds[0].revents = model_ready(n) & (fds[0].events | MODEL_FATAL);
	if (fds[0].revents) {
		model_snapshot(&model.at_last_poll);
		if (!(fds[0].revents & (POLLIN | MODEL_FATAL)))
			model.early_idle++;
		return 1;
	}
	if (timeout_ms < 0) {
		/* Nothing will ever become ready: blocked forever. */
		model_snapshot(&model.at_last_poll);
		model.unbounded_waits++;
		running = 0;
		errno = EINTR;
		return -1;
	}
	if (timeout_ms == 0) {
		model.zero_waits++;
		model_snapshot(&model.at_last_poll);
		return 0;
	}
	/* Nothing ends the wait early: ingress arrives only at poll entry,
	 * and the model frees no send-buffer space while poll() sleeps. */
	model.timeouts++;
	model.timed_out[n] = true;
	model.clock_ms += (unsigned int)timeout_ms;
	if (timeout_ms >= MODEL_FULL_TIMEOUT_MS)
		model.full_timeouts++;
	/* do_poll() calls xsk_poll() once more when the timeout expires. */
	if (model.tx_copy) {
		(void)model_copy_tx_pass(n);
		fds[0].revents = model_ready(n) & fds[0].events;
	}
	model_snapshot(&model.at_last_poll);
	return fds[0].revents ? 1 : 0;
}

static ssize_t model_recvfrom(int fd, void *buf, size_t len, int flags,
			      struct sockaddr *addr, socklen_t *addr_len)
{
	(void)buf; (void)len; (void)flags; (void)addr; (void)addr_len;
	if (fd == MODEL_FD) {
		model.fq_wakeups++;
		model.fq_queued_at_wakeup = model.fq_prod - model.fq_cons;
		if (test_ctx.frames.recycle.count)
			model.wakeups_before_refill++;
	}
	return 0;
}

static ssize_t model_sendto(int fd, const void *buf, size_t len, int flags,
			    const struct sockaddr *addr, socklen_t addr_len)
{
	(void)buf; (void)len; (void)flags; (void)addr; (void)addr_len;
	if (fd != MODEL_FD)
		return 0;
	model.tx_kicks++;
	model.kicked = true;
	/* Work done now is visible at the next poll, number model.polls. */
	if (model.tx_copy) {
		if (model_copy_tx_pass(model.polls)) {
			errno = EAGAIN;
			return -1;
		}
	} else if (model.tx_flags & XDP_RING_NEED_WAKEUP) {
		model_driver_takes_tx(model.polls);
	}
	return 0;
}

static void ring_prod_init(struct xsk_ring_prod *ring, uint32_t size,
			   uint32_t *producer, uint32_t *consumer,
			   void *entries, uint32_t *flags)
{
	ring->cached_prod = 0;
	ring->cached_cons = size;
	ring->mask = size - 1;
	ring->size = size;
	ring->producer = producer;
	ring->consumer = consumer;
	ring->ring = entries;
	ring->flags = flags;
}

static void ring_cons_init(struct xsk_ring_cons *ring, uint32_t size,
			   uint32_t *producer, uint32_t *consumer,
			   void *entries, uint32_t *flags)
{
	ring->cached_prod = 0;
	ring->cached_cons = 0;
	ring->mask = size - 1;
	ring->size = size;
	ring->producer = producer;
	ring->consumer = consumer;
	ring->ring = entries;
	ring->flags = flags;
}

/* Fresh model, the fill and completion rings xsk_umem__create() would set
 * up, and the RX and TX rings, but no frame published yet. */
static void model_setup_rings(const char *name, unsigned int poll_limit)
{
	scenario = name;
	memset(&model, 0, sizeof(model));
	memset(&test_ctx, 0, sizeof(test_ctx));
	memset(&stats, 0, sizeof(stats));
	model.poll_limit = poll_limit;
	ring_prod_init(&test_ctx.fq, FILL_RING_SIZE, &model.fq_prod,
		       &model.fq_cons, model.fq_ring, &model.fq_flags);
	ring_cons_init(&test_ctx.cq, COMP_RING_SIZE, &model.cq_prod,
		       &model.cq_cons, model.cq_ring, &model.cq_flags);
	ring_cons_init(&test_ctx.rx, FILL_RING_SIZE, &model.rx_prod,
		       &model.rx_cons, model.rx_ring, &model.rx_flags);
	ring_prod_init(&test_ctx.tx, COMP_RING_SIZE, &model.tx_prod,
		       &model.tx_cons, model.tx_ring, &model.tx_flags);
	test_ctx.xsk = (struct xsk_socket *)&model;
	test_ctx.umem_buffer = test_umem;
	test_ctx.gpu_ctx = &test_gpu;
	running = 1;
}

/* The state create_xsk() leaves behind: every frame published to FILL. */
static void model_setup(const char *name, unsigned int poll_limit)
{
	unsigned int push_failures = 0;

	model_setup_rings(name, poll_limit);
	EXPECT_EQ(0, gpu_xdp_frame_runtime_init(&test_ctx.frames,
						test_ctx.frame_states,
						test_ctx.recycle_entries,
						test_ctx.expected_tx_addrs,
						NUM_FRAMES, FRAME_SIZE));
	for (uint32_t i = 0; i < NUM_FRAMES; i++)
		push_failures += !!xdev_ext_xsk_recycle_push(&test_ctx.frames.recycle,
							(uint64_t)i * FRAME_SIZE);
	EXPECT_EQ(0, push_failures);
	EXPECT_EQ(NUM_FRAMES, gpu_xdp_refill(&test_ctx.frames, &test_ctx.fq,
					     NUM_FRAMES));
}

static int saved_stdout = -1;

/* The sample's progress and statistics lines on stdout are not checked.
 * stderr stays connected, so its failure messages and any sanitizer report
 * remain visible. */
static void sample_output_off(void)
{
	int null_fd;

	fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (saved_stdout < 0 || null_fd < 0 ||
	    dup2(null_fd, STDOUT_FILENO) < 0) {
		perror("discard sample stdout");
		exit(2);
	}
	close(null_fd);
}

static void sample_output_on(void)
{
	fflush(stdout);
	if (dup2(saved_stdout, STDOUT_FILENO) < 0) {
		perror("restore stdout");
		exit(2);
	}
	close(saved_stdout);
}

static int run_sample_loop(void)
{
	int ret;

	sample_output_off();
	ret = run_loop(&test_ctx);
	sample_output_on();
	return ret;
}

static void expect_model_sane(void)
{
	EXPECT_EQ(0, model.bad_poll_args);
	EXPECT_EQ(0, model.foreign_calls);
	EXPECT_EQ(0, model.rx_without_fill);
	EXPECT_EQ(0, model.bad_tx_descs);
	EXPECT_EQ(0, model.unbounded_waits);
	EXPECT_EQ(0, model.zero_waits);
	for (unsigned int i = 0; i < model.polls; i++)
		EXPECT_TRUE(model.timeout_ms[i] > 0);
}

static void expect_all_frames_in_fill(void)
{
	const struct xdev_ext_xsk_frame_owner *owner = &test_ctx.frames.owner;

	EXPECT_EQ(0, xdev_ext_xsk_frame_count_state(owner, XDEV_EXT_XSK_FRAME_TX));
	EXPECT_EQ(0, xdev_ext_xsk_frame_count_state(owner, XDEV_EXT_XSK_FRAME_RX));
	EXPECT_EQ(NUM_FRAMES,
		  xdev_ext_xsk_frame_count_state(owner, XDEV_EXT_XSK_FRAME_FILL));
	EXPECT_EQ(0, test_ctx.frames.recycle.count);
	EXPECT_EQ(model.cq_prod, model.cq_cons);
	EXPECT_EQ(NUM_FRAMES, model.fq_prod - model.fq_cons);
}

/* With no traffic every poll asks for ingress only and blocks until its
 * timeout; an always-writable socket must not wake the loop. */
static void test_idle_loop_blocks_in_poll(void)
{
	int ret;

	model_setup("idle", 6);
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(6, model.polls);
	for (unsigned int i = 0; i < model.polls; i++) {
		EXPECT_EQ(POLLIN, model.events[i]);
		EXPECT_EQ(MODEL_FULL_TIMEOUT_MS, model.timeout_ms[i]);
	}
	EXPECT_EQ(6, model.timeouts);
	EXPECT_EQ(0, model.early_idle);
	EXPECT_EQ(0, stats.rx_packets);
	expect_model_sane();
	expect_all_frames_in_fill();
}

/* A fatal event is handled before any datapath or maintenance work, even
 * when ingress and TX completions are waiting in the same poll. */
static void test_fatal_event_stops_before_datapath(const char *name,
						   short event, int expected)
{
	struct model_snapshot after;
	int ret;

	model_setup(name, 8);
	model.rx_at[0] = 8;		/* one RX batch: frames go to TX */
	model.rx_at[1] = 4;		/* ingress waiting at the fatal poll */
	model.fatal_at[1] = event;	/* completions also land at poll 1 */
	ret = run_sample_loop();
	EXPECT_EQ(expected, ret);
	EXPECT_EQ(0, running);
	EXPECT_EQ(2, model.polls);
	EXPECT_EQ(8, stats.rx_packets);
	EXPECT_EQ(8, model.at_last_poll.tx);
	EXPECT_EQ(8, model.at_last_poll.cq_prod - model.at_last_poll.cq_cons);
	EXPECT_EQ(4, model.at_last_poll.rx_prod - model.at_last_poll.rx_cons);
	model_snapshot(&after);
	EXPECT_EQ(0, memcmp(&model.at_last_poll, &after, sizeof(after)));
	EXPECT_EQ(model.at_last_poll.rx_cons, after.rx_cons);
	EXPECT_EQ(model.at_last_poll.rx_cached_cons, after.rx_cached_cons);
	EXPECT_EQ(model.at_last_poll.cq_cons, after.cq_cons);
	EXPECT_EQ(model.at_last_poll.cq_cached_cons, after.cq_cached_cons);
	EXPECT_EQ(model.at_last_poll.fq_prod, after.fq_prod);
	EXPECT_EQ(model.at_last_poll.tx_prod, after.tx_prod);
	EXPECT_EQ(model.at_last_poll.fq_wakeups, after.fq_wakeups);
	EXPECT_EQ(model.at_last_poll.tx_kicks, after.tx_kicks);
	expect_model_sane();
}

/* A fatal event on a socket that never saw traffic. */
static void test_fatal_event_on_quiet_socket(const char *name, short event,
					     int expected)
{
	struct model_snapshot after;
	int ret;

	model_setup(name, 8);
	model.fatal_at[0] = event;
	ret = run_sample_loop();
	EXPECT_EQ(expected, ret);
	EXPECT_EQ(0, running);
	EXPECT_EQ(1, model.polls);
	model_snapshot(&after);
	EXPECT_EQ(0, memcmp(&model.at_last_poll, &after, sizeof(after)));
	EXPECT_EQ(0, stats.rx_packets);
	expect_model_sane();
}

/* RX work arms exactly one POLLOUT opportunity; the next poll consumes it
 * and the loop goes back to waiting for ingress only. */
static void test_rx_batch_arms_one_pollout(void)
{
	int ret;

	model_setup("arm-once", 5);
	model.rx_at[0] = 16;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(5, model.polls);
	EXPECT_EQ(POLLIN, model.events[0]);
	EXPECT_EQ(POLLIN | POLLOUT, model.events[1]);
	for (unsigned int i = 2; i < model.polls; i++)
		EXPECT_EQ(POLLIN, model.events[i]);
	EXPECT_EQ(1, model.early_idle);
	EXPECT_EQ(3, model.timeouts);
	EXPECT_EQ(16, stats.tx_packets);
	expect_model_sane();
	expect_all_frames_in_fill();
}

/* POLLIN with an empty RX ring is not RX work and arms nothing. */
static void test_empty_rx_pass_does_not_arm(void)
{
	int ret;

	model_setup("empty-rx-pass", 4);
	model.empty_pollin_at[0] = true;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(4, model.polls);
	for (unsigned int i = 0; i < model.polls; i++)
		EXPECT_EQ(POLLIN, model.events[i]);
	EXPECT_EQ(0, model.early_idle);
	EXPECT_EQ(3, model.timeouts);
	expect_model_sane();
}

/* Back-to-back RX batches, then ingress stops.  Completions for the last
 * batch land @delay polls after it, possibly after the armed POLLOUT was
 * spent; they must still be reaped, and the quiet polls must block. */
static void test_quiet_period_reaps_late_completions(const char *name,
						     unsigned int delay)
{
	unsigned int quiet_early = 0;
	int ret;

	model_setup(name, 12);
	model.completion_delay = delay;
	model.rx_at[0] = RX_BATCH_SIZE;
	model.rx_at[1] = RX_BATCH_SIZE;
	model.rx_at[2] = RX_BATCH_SIZE;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(12, model.polls);
	EXPECT_EQ(3 * RX_BATCH_SIZE, stats.rx_packets);
	EXPECT_EQ(3 * RX_BATCH_SIZE, stats.tx_packets);
	EXPECT_EQ(0, model.pending_count);
	expect_all_frames_in_fill();
	/* At most one early wakeup per RX batch, and none after the first
	 * quiet poll. */
	EXPECT_TRUE(model.early_idle <= 3);
	for (unsigned int i = 4; i < model.polls; i++)
		quiet_early += model.events[i] != POLLIN;
	EXPECT_EQ(0, quiet_early);
	EXPECT_TRUE(model.timeouts >= 8);
	EXPECT_EQ(0, model.fq_wakeups);
	EXPECT_EQ(0, stats.errors);
	expect_model_sane();
}

/* Maintenance wakes the kernel for the fill ring only after the refill, so
 * the kernel sees every recycled frame. */
static void test_fill_wakeup_follows_refill(void)
{
	int ret;

	model_setup("fill-wakeup", 6);
	model.fq_flags = XDP_RING_NEED_WAKEUP;
	model.completion_delay = 2;	/* completions land on a quiet poll */
	model.rx_at[0] = 32;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	expect_all_frames_in_fill();
	EXPECT_TRUE(model.fq_wakeups >= 1);
	EXPECT_EQ(0, model.wakeups_before_refill);
	EXPECT_EQ(NUM_FRAMES, model.fq_queued_at_wakeup);
	expect_model_sane();
}

/* Every frame of the UMEM is in TX when ingress stops, and all of their
 * completions land together on a quiet poll.  That one poll returns every
 * frame to FILL, so recovery is not paced at one RX batch per timeout. */
static void test_quiet_poll_reaps_every_completion(void)
{
	const unsigned int batches = NUM_FRAMES / RX_BATCH_SIZE;
	int ret;

	model_setup("quiet-reap-budget", batches + 2);
	model.completion_release_at = batches + 1;
	for (unsigned int i = 0; i < batches; i++)
		model.rx_at[i] = RX_BATCH_SIZE;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(batches + 2, model.polls);
	EXPECT_EQ(batches * RX_BATCH_SIZE, stats.tx_packets);
	EXPECT_TRUE(batches * RX_BATCH_SIZE > BATCH_SIZE);
	/* Every completion was first visible at the last poll, a timeout. */
	EXPECT_EQ(batches * RX_BATCH_SIZE,
		  model.at_last_poll.cq_prod - model.at_last_poll.cq_cons);
	EXPECT_EQ(batches * RX_BATCH_SIZE, model.at_last_poll.tx);
	EXPECT_EQ(POLLIN, model.events[batches + 1]);
	EXPECT_EQ(1, model.timeouts);
	expect_all_frames_in_fill();
	expect_model_sane();
}

#define REWRITE_FLOW(flow_name, vihl, proto, checksum, length, s) {	\
	.name = flow_name,						\
	.dst_mac = { 0x02, 0x10, 0x20, 0x30, 0x40, s },		\
	.src_mac = { 0x02, 0xa0, 0xb0, 0xc0, 0xd0, s },		\
	.version_ihl = vihl, .protocol = proto,				\
	.saddr = 0x0a000100u + (s), .daddr = 0xc0a80700u + (s),	\
	.sport = 40000 + (s), .dport = 4791 + (s),			\
	.l4_checksum = checksum, .len = length, .seed = s }

/* Complete frames go through the sample's own RX -> CPU staging -> rewrite
 * -> TX path.  A fixed-header IPv4/UDP frame leaves as the reply: MACs,
 * addresses and ports exchanged and every other byte, the checksums
 * included, as it arrived, which keeps both checksums valid.  Any other
 * frame leaves unchanged.  Frames sit at frame-aligned offsets in UMEM and
 * in staging, so the IPv4 header is at an address that is 2 mod 4. */
static void test_packet_rewrite(void)
{
	static const struct {
		struct model_flow flow;
		bool reply;
	} cases[] = {
		{ REWRITE_FLOW("udp", 0x45, IPPROTO_UDP, true, 64, 1), true },
		{ REWRITE_FLOW("udp-headers-only", 0x45, IPPROTO_UDP, true,
			       42, 2), true },
		{ REWRITE_FLOW("udp-odd-length", 0x45, IPPROTO_UDP, true,
			       99, 3), true },
		{ REWRITE_FLOW("udp-no-checksum", 0x45, IPPROTO_UDP, false,
			       64, 4), true },
		{ REWRITE_FLOW("tcp", 0x45, IPPROTO_TCP, false, 64, 5), false },
		{ REWRITE_FLOW("ihl-6", 0x46, IPPROTO_UDP, true, 68, 6),
		  false },
		{ REWRITE_FLOW("version-6", 0x65, IPPROTO_UDP, true, 64, 7),
		  false },
		{ REWRITE_FLOW("short", 0x45, IPPROTO_UDP, false, 41, 8),
		  false },
	};
	enum { CASES = sizeof(cases) / sizeof(cases[0]) };
	const uint32_t ip_check = ETH_HLEN + 10, udp_check = ETH_HLEN + 26;
	struct model_frame sent[CASES];
	int ret;

	model_setup("packet-rewrite", 3);
	for (unsigned int i = 0; i < CASES; i++)
		model_build_frame(&sent[i], &cases[i].flow);
	model.ingress = sent;
	model.ingress_count = CASES;
	model.rx_at[0] = CASES;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(CASES, stats.rx_packets);
	EXPECT_EQ(CASES, stats.tx_packets);
	EXPECT_EQ(CASES, model.wire_count);
	expect_model_sane();
	expect_all_frames_in_fill();
	for (unsigned int i = 0; i < CASES && i < model.wire_count; i++) {
		const struct model_frame *got = &model.wire[i];
		struct model_frame want = sent[i];

		scenario = cases[i].flow.name;
		if (cases[i].reply) {
			struct model_flow reply =
				model_reply_flow(&cases[i].flow);

			model_build_frame(&want, &reply);
			/* The vector must not be its own reply. */
			EXPECT_TRUE(first_difference(sent[i].bytes, want.bytes,
						     want.len) >= 0);
		}
		EXPECT_EQ(want.len, got->len);
		EXPECT_EQ(-1, first_difference(want.bytes, got->bytes,
					       want.len));
		if (!cases[i].reply)
			continue;
		EXPECT_EQ(0, memcmp(sent[i].bytes + ip_check,
				    got->bytes + ip_check, 2));
		EXPECT_EQ(0, memcmp(sent[i].bytes + udp_check,
				    got->bytes + udp_check, 2));
		EXPECT_TRUE(ipv4_checksum_valid(got->bytes));
		EXPECT_TRUE(udp_checksum_valid(got->bytes, got->len));
	}
	scenario = "packet-rewrite";
}

/* A completion for a frame that was never transmitted is an ownership
 * failure: the loop stops with an error at the poll that exposed it. */
static void test_quiet_maintenance_failure_fails_closed(void)
{
	int ret;

	model_setup("maintenance-failure", 8);
	model.foreign_completion_at = 2;
	ret = run_sample_loop();
	EXPECT_EQ(-EPROTO, ret);
	EXPECT_EQ(0, running);
	EXPECT_EQ(2, model.polls);
	expect_model_sane();
}

/* Every reply left, each poll entered while TX waited followed a kick, the
 * last reply did not wait for a full poll timeout, and the loop settled:
 * its last three polls asked for ingress only and slept the full timeout. */
static void expect_tx_retried_promptly(unsigned int frames,
				       unsigned int eagain)
{
	EXPECT_EQ(frames, stats.tx_packets);
	EXPECT_EQ(frames, model.tx_cons);
	EXPECT_EQ(0, model.tx_eagain_left);
	EXPECT_EQ(0, model.unkicked_polls);
	EXPECT_EQ(0, model.tx_last_full_timeouts);
	EXPECT_TRUE(model.tx_last_clock_ms <= eagain * MODEL_RETRY_MS_MAX);
	EXPECT_TRUE(model.polls >= 3);
	for (unsigned int i = model.polls - 3; i < model.polls; i++) {
		EXPECT_EQ(POLLIN, model.events[i]);
		EXPECT_EQ(MODEL_FULL_TIMEOUT_MS, model.timeout_ms[i]);
		EXPECT_TRUE(model.timed_out[i]);
	}
	EXPECT_EQ(0, stats.errors);
	expect_model_sane();
	expect_all_frames_in_fill();
}

/* Copy mode: replies to @batches back-to-back RX batches leave through
 * transmit passes of 32, and the first @eagain passes that find TX
 * descriptors hit -EAGAIN.  The kernel leaves the TX ring's need-wakeup
 * flag set in copy mode. */
static void test_copy_mode_tx_retry(const char *name, unsigned int batches,
				    unsigned int eagain)
{
	int ret;

	model_setup(name, 24);
	model.tx_copy = true;
	model.tx_flags = XDP_RING_NEED_WAKEUP;
	model.tx_eagain_left = eagain;
	for (unsigned int i = 0; i < batches; i++)
		model.rx_at[i] = RX_BATCH_SIZE;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(24, model.polls);
	expect_tx_retried_promptly(batches * RX_BATCH_SIZE, eagain);
	/* More than one pass per RX batch was needed. */
	EXPECT_TRUE(model.tx_passes > batches);
}

/* Zero-copy with the TX ring's need-wakeup flag set: the driver moves TX
 * only when sendto() or poll() wakes it, so a poll entered while
 * descriptors wait must follow a kick. */
static void test_zero_copy_need_wakeup_kicks(void)
{
	int ret;

	model_setup("zc-need-wakeup", 8);
	model.tx_flags = XDP_RING_NEED_WAKEUP;
	model.rx_at[0] = RX_BATCH_SIZE;
	model.rx_at[1] = RX_BATCH_SIZE;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(8, model.polls);
	EXPECT_TRUE(model.tx_kicks >= 2);
	expect_tx_retried_promptly(2 * RX_BATCH_SIZE, 0);
}

/* The sample's own create_xsk() on a driver without zero-copy falls back to
 * a copy-mode socket.  Copy mode moves TX only on sendto() or poll(), so
 * the loop kicks TX in copy mode even when the TX ring's need-wakeup flag
 * reads clear. */
static void test_copy_mode_fallback_kicks_without_ring_flag(void)
{
	const struct xdev_ext_xsk_flow_filter filter = {
		.flags = XDEV_EXT_XSK_FILTER_F_ALL,
	};
	int ret;

	model_setup_rings("copy-fallback-flag-clear", 24);
	model.setup_allowed = true;
	test_ctx.xsk = NULL;
	sample_output_off();
	ret = create_xsk(&test_ctx, "model0", 0, &filter);
	sample_output_on();
	model.setup_allowed = false;
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, model.creates);
	EXPECT_TRUE(model.create_bind_flags[0] & XDP_ZEROCOPY);
	EXPECT_EQ(0, model.create_bind_flags[1] & XDP_ZEROCOPY);
	EXPECT_EQ(XDP_FLAGS_SKB_MODE, model.create_xdp_flags[1]);
	EXPECT_EQ(XDP_FLAGS_SKB_MODE, model.attach_xdp_flags);
	EXPECT_TRUE(test_ctx.xsk == (struct xsk_socket *)&model);
	expect_all_frames_in_fill();

	model.tx_copy = true;
	model.tx_flags = 0;
	model.tx_eagain_left = 3;
	model.rx_at[0] = RX_BATCH_SIZE;
	ret = run_sample_loop();
	EXPECT_EQ(0, ret);
	EXPECT_EQ(24, model.polls);
	EXPECT_TRUE(model.tx_kicks >= 1);
	expect_tx_retried_promptly(RX_BATCH_SIZE, 3);
}

int main(void)
{
	static const struct model_flow default_flow =
		REWRITE_FLOW("default", 0x45, IPPROTO_UDP, true,
			     MODEL_PACKET_LEN, 0x5a);
	setvbuf(stdout, NULL, _IONBF, 0);
	int ret;

	scenario = "setup";
	model_build_frame(&model_default_frame, &default_flow);
	sample_output_off();
	ret = gpu_p2p_init(&test_gpu, test_umem, UMEM_SIZE, 0, -1);
	sample_output_on();
	EXPECT_EQ(0, ret);

	test_idle_loop_blocks_in_poll();
	test_packet_rewrite();
	test_fatal_event_stops_before_datapath("fatal-err", POLLERR, -EIO);
	test_fatal_event_stops_before_datapath("fatal-hup", POLLHUP,
					       -ENOTCONN);
	test_fatal_event_stops_before_datapath("fatal-nval", POLLNVAL,
					       -EBADF);
	test_fatal_event_on_quiet_socket("fatal-quiet-err", POLLERR, -EIO);
	test_fatal_event_on_quiet_socket("fatal-quiet-hup", POLLHUP,
					 -ENOTCONN);
	test_rx_batch_arms_one_pollout();
	test_empty_rx_pass_does_not_arm();
	test_quiet_period_reaps_late_completions("quiet-reap-now", 0);
	test_quiet_period_reaps_late_completions("quiet-reap-late", 4);
	test_quiet_poll_reaps_every_completion();
	test_fill_wakeup_follows_refill();
	test_quiet_maintenance_failure_fails_closed();
	test_copy_mode_tx_retry("copy-tx-eagain-0", 1, 0);
	test_copy_mode_tx_retry("copy-tx-eagain-1", 1, 1);
	test_copy_mode_tx_retry("copy-tx-eagain-2", 1, 2);
	test_copy_mode_tx_retry("copy-tx-eagain-3", 1, 3);
	test_copy_mode_tx_retry("copy-tx-eagain-4", 1, 4);
	test_copy_mode_tx_retry("copy-tx-eagain-5", 1, 5);
	test_copy_mode_tx_retry("copy-tx-eagain-6", 1, 6);
	test_copy_mode_tx_retry("copy-tx-burst-eagain-4", 3, 4);
	test_zero_copy_need_wakeup_kicks();
	test_copy_mode_fallback_kicks_without_ring_flag();

	gpu_p2p_cleanup(&test_gpu);
	printf("gpu_xdp_nocuda_loop: %u checks, %u failures\n", checks,
	       failures);
	return failures ? 1 : 0;
}
