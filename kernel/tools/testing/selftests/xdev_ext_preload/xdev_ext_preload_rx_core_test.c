// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for tools/xdev_ext_preload_rx_core.h: datagram validation, the
 * receive-ring cursor and frame states, recv semantics, and the poll and
 * select folding used while a taken-over UDP socket waits.
 *
 * A fake kernel drives the rings with the real AF_XDP UAPI layout
 * (struct xdp_desc, XDP_RING_NEED_WAKEUP) so a layout drift between the
 * generic core and the UAPI fails here.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "../../../../include/uapi/linux/if_xdp.h"
#include "../../../xdev_ext_preload_rx_core.h"

static unsigned int checks;
static unsigned int failures;

#define EXPECT_TRUE(expr) do {                                            \
	checks++;                                                           \
	if (!(expr)) {                                                      \
		fprintf(stderr, "%s:%d: EXPECT_TRUE(%s) failed\n",        \
			__FILE__, __LINE__, #expr);                            \
		failures++;                                                \
	}                                                                   \
} while (0)

#define EXPECT_EQ(actual, expected) do {                                 \
	long long _actual = (long long)(actual);                           \
	long long _expected = (long long)(expected);                       \
	checks++;                                                           \
	if (_actual != _expected) {                                        \
		fprintf(stderr, "%s:%d: %s=%lld, expected %lld\n",        \
			__FILE__, __LINE__, #actual, _actual, _expected);       \
		failures++;                                                \
	}                                                                   \
} while (0)

/* The generic descriptor must be the UAPI one, byte for byte. */
_Static_assert(sizeof(struct xdev_ext_rx_desc) == sizeof(struct xdp_desc),
	       "descriptor size");
_Static_assert(offsetof(struct xdev_ext_rx_desc, addr) ==
	       offsetof(struct xdp_desc, addr), "descriptor addr");
_Static_assert(offsetof(struct xdev_ext_rx_desc, len) ==
	       offsetof(struct xdp_desc, len), "descriptor len");
_Static_assert(offsetof(struct xdev_ext_rx_desc, options) ==
	       offsetof(struct xdp_desc, options), "descriptor options");

#define FK_MAX_FRAMES 64U
#define FK_HEADROOM 256U	/* XDP_PACKET_HEADROOM in aligned mode */

static const uint8_t flow_mac[6] = { 0x02, 0, 0, 0, 0, 0x02 };
static const uint8_t other_mac[6] = { 0x02, 0, 0, 0, 0, 0x09 };

static in_addr_t flow_dst(void) { return inet_addr("192.0.2.2"); }
static in_addr_t flow_src(void) { return inet_addr("192.0.2.1"); }
#define FLOW_DPORT 12345
#define FLOW_SPORT 40000

/* ------------------------------------------------------------------ */
/* Reference checksums: byte at a time, independent of the core.       */

static uint32_t ref_sum(uint32_t sum, const uint8_t *p, size_t len)
{
	for (size_t i = 0; i < len; i++)
		sum += (i & 1) ? p[i] : (uint32_t)p[i] << 8;
	return sum;
}

static uint16_t ref_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)sum;
}

enum csum_mode { CSUM_OK, CSUM_ZERO, CSUM_BAD };

struct frame_spec {
	uint16_t ethertype;	/* 0: IPv4 */
	bool vlan;
	uint8_t version;	/* 0: 4 */
	uint8_t ihl;		/* 0: 5 */
	uint16_t frag;		/* host-order frag_off */
	uint8_t proto;		/* 0: UDP */
	int tot_len_delta;
	int udp_len_delta;
	bool bad_ip_csum;
	enum csum_mode csum;
	in_addr_t src, dst;	/* 0: flow defaults */
	uint16_t sport, dport;	/* host order, 0: flow defaults */
	const uint8_t *dmac;
	size_t pad_to;
};

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

static size_t build_frame(uint8_t *out, const struct frame_spec *s,
			  const uint8_t *payload, size_t plen)
{
	in_addr_t src = s->src ? s->src : flow_src();
	in_addr_t dst = s->dst ? s->dst : flow_dst();
	uint8_t ihl = s->ihl ? s->ihl : 5;
	size_t l2 = s->vlan ? 18 : 14;
	uint8_t *ip = out + l2;
	uint8_t *udp = ip + ihl * 4;
	uint16_t ulen = (uint16_t)(8 + plen + s->udp_len_delta);
	uint16_t tot = (uint16_t)(ihl * 4 + 8 + plen + s->tot_len_delta);
	size_t len = l2 + ihl * 4 + 8 + plen;
	uint8_t pseudo[12];
	uint32_t sum;
	size_t covered;

	memset(out, 0, len > s->pad_to ? len : s->pad_to);
	memcpy(out, s->dmac ? s->dmac : flow_mac, 6);
	memcpy(out + 6, other_mac, 6);
	if (s->vlan) {
		put16(out + 12, 0x8100);
		put16(out + 14, 7);
		put16(out + 16, 0x0800);
	} else {
		put16(out + 12, s->ethertype ? s->ethertype : 0x0800);
	}
	ip[0] = (uint8_t)(((s->version ? s->version : 4) << 4) | (ihl & 0xf));
	put16(ip + 2, tot);
	put16(ip + 4, 0x1234);
	put16(ip + 6, s->frag);
	ip[8] = 64;
	ip[9] = s->proto ? s->proto : IPPROTO_UDP;
	memcpy(ip + 12, &src, 4);
	memcpy(ip + 16, &dst, 4);
	put16(ip + 10, (uint16_t)~ref_fold(ref_sum(0, ip, ihl * 4u)));
	if (s->bad_ip_csum)
		ip[10] ^= 0x40;

	put16(udp, s->sport ? s->sport : FLOW_SPORT);
	put16(udp + 2, s->dport ? s->dport : FLOW_DPORT);
	put16(udp + 4, ulen);
	memcpy(udp + 8, payload, plen);
	if (s->csum != CSUM_ZERO) {
		uint16_t c;

		memcpy(pseudo, &src, 4);
		memcpy(pseudo + 4, &dst, 4);
		pseudo[8] = 0;
		pseudo[9] = IPPROTO_UDP;
		put16(pseudo + 10, ulen);
		covered = ulen < 8 + plen ? ulen : 8 + plen;
		sum = ref_sum(ref_sum(0, pseudo, sizeof(pseudo)), udp, covered);
		c = (uint16_t)~ref_fold(sum);
		if (!c)
			c = 0xffff;
		/* Flip a bit, never to 0: 0 means "no checksum". */
		if (s->csum == CSUM_BAD)
			c = (c ^ 0x0100) ? (c ^ 0x0100) : (c ^ 0x0001);
		put16(udp + 6, c);
	}
	return len > s->pad_to ? len : s->pad_to;
}

static struct xdev_ext_flow_tuple flow_tuple(void)
{
	struct xdev_ext_flow_tuple t = {
		.dst_addr = flow_dst(),
		.dst_port = htons(FLOW_DPORT),
	};

	memcpy(t.dst_mac, flow_mac, sizeof(t.dst_mac));
	return t;
}

/* ------------------------------------------------------------------ */
/* A fake kernel: producer of the receive ring, consumer of the fill  */
/* ring, with the UAPI descriptor layout.                              */

struct fake_kernel {
	uint32_t nframes, frame_size;
	uint8_t *umem;
	uint8_t state[FK_MAX_FRAMES];
	struct {
		uint32_t producer, consumer, flags;
		struct xdp_desc descs[FK_MAX_FRAMES];
	} rx;
	struct {
		uint32_t producer, consumer, flags;
		uint64_t descs[FK_MAX_FRAMES];
	} fill;
	struct xdev_ext_rx_core core;
};

static struct xdev_ext_rx_layout fk_layout(struct fake_kernel *fk)
{
	return (struct xdev_ext_rx_layout) {
		.umem = fk->umem,
		.nframes = fk->nframes,
		.frame_size = fk->frame_size,
		.frame_state = fk->state,
		.rx = {
			.producer = &fk->rx.producer,
			.consumer = &fk->rx.consumer,
			.flags = &fk->rx.flags,
			.descs = fk->rx.descs,
			.mask = fk->nframes - 1,
			.size = fk->nframes,
		},
		.fill = {
			.producer = &fk->fill.producer,
			.consumer = &fk->fill.consumer,
			.flags = &fk->fill.flags,
			.descs = fk->fill.descs,
			.mask = fk->nframes - 1,
			.size = fk->nframes,
		},
		.wakeup_flag = XDP_RING_NEED_WAKEUP,
	};
}

static struct fake_kernel *fk_new_tuple(uint32_t nframes, uint32_t frame_size,
					const struct xdev_ext_flow_tuple *tuple)
{
	struct fake_kernel *fk = calloc(1, sizeof(*fk));
	struct xdev_ext_rx_layout layout;
	bool wake = false;

	if (!fk)
		abort();
	fk->nframes = nframes;
	fk->frame_size = frame_size;
	fk->umem = calloc(nframes, frame_size);
	if (!fk->umem)
		abort();
	/* Rings start at an arbitrary index, as after a long uptime. */
	fk->rx.producer = fk->rx.consumer = UINT32_MAX - 2;
	fk->fill.producer = fk->fill.consumer = UINT32_MAX - 1;
	layout = fk_layout(fk);
	EXPECT_EQ(xdev_ext_rx_core_init(&fk->core, &layout, tuple), 0);
	EXPECT_EQ(xdev_ext_rx_core_fill_all(&fk->core, &wake), 0);
	EXPECT_TRUE(!wake);
	return fk;
}

static struct fake_kernel *fk_new(uint32_t nframes)
{
	struct xdev_ext_flow_tuple t = flow_tuple();

	return fk_new_tuple(nframes, 2048, &t);
}

static void fk_free(struct fake_kernel *fk)
{
	free(fk->umem);
	free(fk);
}

/* Post one frame the way the kernel does: take a fill address, copy the
 * frame after the headroom, publish an RX descriptor. */
static bool fk_post(struct fake_kernel *fk, const uint8_t *frame, size_t len)
{
	uint32_t fprod = __atomic_load_n(&fk->fill.producer, __ATOMIC_ACQUIRE);
	uint32_t rcons = __atomic_load_n(&fk->rx.consumer, __ATOMIC_ACQUIRE);
	uint32_t mask = fk->nframes - 1;
	uint64_t addr;

	if (fk->fill.consumer == fprod)
		return false;
	if (fk->rx.producer - rcons >= fk->nframes)
		return false;
	addr = fk->fill.descs[fk->fill.consumer & mask];
	__atomic_store_n(&fk->fill.consumer, fk->fill.consumer + 1,
			 __ATOMIC_RELEASE);
	addr &= ~(uint64_t)(fk->frame_size - 1);
	memcpy(fk->umem + addr + FK_HEADROOM, frame, len);
	fk->rx.descs[fk->rx.producer & mask] = (struct xdp_desc) {
		.addr = addr + FK_HEADROOM,
		.len = (uint32_t)len,
	};
	__atomic_store_n(&fk->rx.producer, fk->rx.producer + 1,
			 __ATOMIC_RELEASE);
	return true;
}

/* Post a raw descriptor without touching the fill ring. */
static void fk_post_desc(struct fake_kernel *fk, uint64_t addr, uint32_t len,
			 uint32_t options)
{
	uint32_t mask = fk->nframes - 1;

	fk->rx.descs[fk->rx.producer & mask] = (struct xdp_desc) {
		.addr = addr, .len = len, .options = options,
	};
	__atomic_store_n(&fk->rx.producer, fk->rx.producer + 1,
			 __ATOMIC_RELEASE);
}

static bool fk_post_good(struct fake_kernel *fk, const char *text)
{
	struct frame_spec s = { 0 };
	uint8_t frame[2048];
	size_t len = build_frame(frame, &s, (const uint8_t *)text,
				 strlen(text));

	return fk_post(fk, frame, len);
}

static uint64_t ctr(const struct fake_kernel *fk, size_t offset)
{
	struct xdev_ext_rx_counters snap;

	xdev_ext_rx_counters_snapshot(&fk->core.ctr, &snap);
	return *(const uint64_t *)((const char *)&snap + offset);
}
#define CTR(fk, name) ctr((fk), offsetof(struct xdev_ext_rx_counters, name))

struct recv_out {
	int status;
	ssize_t ret;
	bool wake;
	int msg_flags;
	struct sockaddr_in from;
	socklen_t fromlen;
	size_t controllen;
};

static struct recv_out do_recv(struct fake_kernel *fk, void *buf, size_t n,
			       int flags)
{
	struct recv_out o = { .fromlen = sizeof(o.from) };
	struct iovec iov = { .iov_base = buf, .iov_len = n };
	char control[64];
	struct msghdr msg = {
		.msg_name = &o.from,
		.msg_namelen = sizeof(o.from),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
		.msg_flags = 0x7fff0000,
	};

	o.status = xdev_ext_rx_core_recv(&fk->core, &msg, flags, &o.ret, &o.wake);
	o.msg_flags = msg.msg_flags;
	o.fromlen = msg.msg_namelen;
	o.controllen = msg.msg_controllen;
	return o;
}

/* ------------------------------------------------------------------ */

static void test_init_and_fill(void)
{
	struct xdev_ext_flow_tuple t = flow_tuple();
	struct fake_kernel *fk = fk_new(8);
	struct xdev_ext_rx_layout layout;
	struct xdev_ext_rx_core c;
	bool wake = false;

	/* Every frame starts in the fill ring, as a frame-aligned address. */
	EXPECT_EQ(fk->fill.producer - fk->fill.consumer, 8);
	for (uint32_t i = 0; i < 8; i++) {
		uint64_t a = fk->fill.descs[(fk->fill.consumer + i) & 7];

		EXPECT_EQ(a % 2048, 0);
		EXPECT_EQ(fk->state[a / 2048], XDEV_EXT_FRAME_FILL);
	}
	EXPECT_EQ(fk->core.cons_pub, UINT32_MAX - 2);
	EXPECT_EQ(fk->core.fill_prod, fk->fill.producer);
	EXPECT_TRUE(!xdev_ext_rx_core_ready(&fk->core));
	EXPECT_EQ(xdev_ext_rx_core_pending(&fk->core), 0);

	/* Geometry that cannot hold the protocol is refused. */
	layout = fk_layout(fk);
	layout.fill.size = 4;
	layout.fill.mask = 3;
	EXPECT_EQ(xdev_ext_rx_core_init(&c, &layout, &t), -EINVAL);
	layout = fk_layout(fk);
	layout.rx.mask = 6;
	EXPECT_EQ(xdev_ext_rx_core_init(&c, &layout, &t), -EINVAL);
	layout = fk_layout(fk);
	layout.rx.size = 6;
	layout.rx.mask = 5;
	EXPECT_EQ(xdev_ext_rx_core_init(&c, &layout, &t), -EINVAL);
	layout = fk_layout(fk);
	layout.frame_size = 0;
	EXPECT_EQ(xdev_ext_rx_core_init(&c, &layout, &t), -EINVAL);
	layout = fk_layout(fk);
	layout.umem = NULL;
	EXPECT_EQ(xdev_ext_rx_core_init(&c, &layout, &t), -EINVAL);
	layout = fk_layout(fk);
	layout.fill.descs = NULL;
	EXPECT_EQ(xdev_ext_rx_core_init(&c, &layout, &t), -EINVAL);
	layout = fk_layout(fk);
	layout.wakeup_flag = 0;
	EXPECT_EQ(xdev_ext_rx_core_init(&c, &layout, &t), -EINVAL);
	fk_free(fk);

	/* A fill ring that asks for a wakeup is reported. */
	fk = calloc(1, sizeof(*fk));
	fk->nframes = 4;
	fk->frame_size = 4096;
	fk->umem = calloc(4, 4096);
	fk->fill.flags = XDP_RING_NEED_WAKEUP;
	layout = fk_layout(fk);
	EXPECT_EQ(xdev_ext_rx_core_init(&fk->core, &layout, &t), 0);
	EXPECT_EQ(xdev_ext_rx_core_fill_all(&fk->core, &wake), 0);
	EXPECT_TRUE(wake);
	EXPECT_EQ(fk->fill.producer, 4);
	/* A second fill would overflow: refused without touching the ring. */
	EXPECT_EQ(xdev_ext_rx_core_fill_all(&fk->core, &wake), -ENOSPC);
	EXPECT_EQ(fk->fill.producer, 4);
	fk_free(fk);
}

static void test_flags_and_shapes(void)
{
	struct iovec iov[2] = { { .iov_base = NULL, .iov_len = 0 } };
	struct sockaddr_in sin;
	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 1 };

	EXPECT_TRUE(xdev_ext_rx_flags_supported(0));
	EXPECT_TRUE(xdev_ext_rx_flags_supported(MSG_DONTWAIT | MSG_PEEK |
					   MSG_TRUNC | MSG_WAITALL |
					   MSG_CMSG_CLOEXEC | MSG_NOSIGNAL));
	EXPECT_TRUE(!xdev_ext_rx_flags_supported(MSG_ERRQUEUE));
	EXPECT_TRUE(!xdev_ext_rx_flags_supported(MSG_OOB));
	EXPECT_TRUE(!xdev_ext_rx_flags_supported(MSG_PEEK | MSG_ERRQUEUE));

	EXPECT_TRUE(xdev_ext_rx_msg_shape_ok(&msg));
	msg.msg_iovlen = 0;
	msg.msg_iov = NULL;
	EXPECT_TRUE(xdev_ext_rx_msg_shape_ok(&msg));
	msg.msg_iovlen = 1;
	EXPECT_TRUE(!xdev_ext_rx_msg_shape_ok(&msg));	/* kernel: EFAULT */
	msg.msg_iov = iov;
	msg.msg_iovlen = 1025;				/* kernel: EMSGSIZE */
	EXPECT_TRUE(!xdev_ext_rx_msg_shape_ok(&msg));
	msg.msg_iovlen = 1;
	iov[0].iov_len = (size_t)SSIZE_MAX + 1;		/* kernel: EINVAL */
	EXPECT_TRUE(!xdev_ext_rx_msg_shape_ok(&msg));
	iov[0].iov_len = 0;
	msg.msg_name = &sin;
	msg.msg_namelen = (socklen_t)INT_MAX + 1;	/* kernel: EINVAL */
	EXPECT_TRUE(!xdev_ext_rx_msg_shape_ok(&msg));
	msg.msg_name = NULL;				/* ignored without name */
	EXPECT_TRUE(xdev_ext_rx_msg_shape_ok(&msg));
}

struct parse_case {
	const char *what;
	struct frame_spec spec;
	size_t plen;
	int verdict;
	uint32_t len;
};

static void test_parse_matrix(void)
{
	static const uint8_t payload[200] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	const struct parse_case cases[] = {
		{ "valid", { .csum = CSUM_OK }, 100, XDEV_EXT_RX_FRAME_OK, 100 },
		{ "zero udp csum", { .csum = CSUM_ZERO }, 100,
		  XDEV_EXT_RX_FRAME_OK, 100 },
		{ "empty datagram", { 0 }, 0, XDEV_EXT_RX_FRAME_OK, 0 },
		{ "padded runt", { .pad_to = 60 }, 1, XDEV_EXT_RX_FRAME_OK, 1 },
		{ "vlan", { .vlan = true }, 10, XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "ipv6 ethertype", { .ethertype = 0x86dd }, 10,
		  XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "arp ethertype", { .ethertype = 0x0806 }, 10,
		  XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "ip options", { .ihl = 6 }, 10, XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "more fragments", { .frag = 0x2000 }, 10,
		  XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "fragment offset", { .frag = 0x0001 }, 10,
		  XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "dont fragment", { .frag = 0x4000 }, 10, XDEV_EXT_RX_FRAME_OK, 10 },
		{ "tcp", { .proto = IPPROTO_TCP }, 10,
		  XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "ip version 6", { .version = 6 }, 10,
		  XDEV_EXT_RX_FRAME_MALFORMED, 0 },
		{ "ihl 4", { .ihl = 4 }, 10, XDEV_EXT_RX_FRAME_MALFORMED, 0 },
		{ "ip total too long", { .tot_len_delta = 1 }, 10,
		  XDEV_EXT_RX_FRAME_MALFORMED, 0 },
		{ "ip total below headers", { .tot_len_delta = -11 }, 10,
		  XDEV_EXT_RX_FRAME_MALFORMED, 0 },
		{ "udp longer than ip", { .udp_len_delta = 1 }, 10,
		  XDEV_EXT_RX_FRAME_MALFORMED, 0 },
		{ "udp shorter than header", { .udp_len_delta = -11 }, 10,
		  XDEV_EXT_RX_FRAME_MALFORMED, 0 },
		/* The kernel trims an IP payload longer than the UDP length
		 * (net/ipv4/udp.c __udp4_lib_rcv: pskb_trim_rcsum(skb, ulen)). */
		{ "udp shorter than ip", { .udp_len_delta = -3 }, 10,
		  XDEV_EXT_RX_FRAME_OK, 7 },
		{ "ip header csum", { .bad_ip_csum = true }, 10,
		  XDEV_EXT_RX_FRAME_IP_CSUM, 0 },
		{ "dst port", { .dport = FLOW_DPORT + 1 }, 10,
		  XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "dst addr", { .dst = inet_addr("192.0.2.3") }, 10,
		  XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		{ "dst mac", { .dmac = other_mac }, 10,
		  XDEV_EXT_RX_FRAME_NOT_FLOW, 0 },
		/* A bad UDP checksum parses; it is caught while copying. */
		{ "udp csum", { .csum = CSUM_BAD }, 10, XDEV_EXT_RX_FRAME_OK, 10 },
	};
	struct xdev_ext_flow_tuple t = flow_tuple();
	struct xdev_ext_rx_datagram dg;
	uint8_t frame[512];

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const struct parse_case *pc = &cases[i];
		size_t len = build_frame(frame, &pc->spec, payload, pc->plen);
		int v = xdev_ext_rx_parse_frame(&t, frame, (uint32_t)len, &dg);

		if (v != pc->verdict)
			fprintf(stderr, "parse case '%s'\n", pc->what);
		EXPECT_EQ(v, pc->verdict);
		if (v == XDEV_EXT_RX_FRAME_OK && pc->verdict == XDEV_EXT_RX_FRAME_OK) {
			EXPECT_EQ(dg.len, pc->len);
			EXPECT_TRUE(dg.payload == frame + 42);
			EXPECT_EQ(dg.src_addr, flow_src());
			EXPECT_EQ(dg.src_port, htons(FLOW_SPORT));
			EXPECT_EQ(xdev_ext_rx_udp_csum_ok(&dg),
				  pc->spec.csum != CSUM_BAD);
		}
	}

	/* Every length below the end of the UDP header is malformed. */
	build_frame(frame, &(struct frame_spec){ 0 }, payload, 10);
	for (uint32_t len = 0; len < 42; len += 3)
		EXPECT_EQ(xdev_ext_rx_parse_frame(&t, frame, len, &dg),
			  XDEV_EXT_RX_FRAME_MALFORMED);

	/* Connected flows also match the source. */
	t.connected = true;
	t.src_addr = flow_src();
	t.src_port = htons(FLOW_SPORT);
	build_frame(frame, &(struct frame_spec){ 0 }, payload, 10);
	EXPECT_EQ(xdev_ext_rx_parse_frame(&t, frame, 52, &dg), XDEV_EXT_RX_FRAME_OK);
	build_frame(frame, &(struct frame_spec){ .sport = FLOW_SPORT + 1 },
		    payload, 10);
	EXPECT_EQ(xdev_ext_rx_parse_frame(&t, frame, 52, &dg),
		  XDEV_EXT_RX_FRAME_NOT_FLOW);
	build_frame(frame, &(struct frame_spec){ .src = inet_addr("192.0.2.9") },
		    payload, 10);
	EXPECT_EQ(xdev_ext_rx_parse_frame(&t, frame, 52, &dg),
		  XDEV_EXT_RX_FRAME_NOT_FLOW);

	/* Frames longer than the flow's bound are not ours. */
	t = flow_tuple();
	t.max_frame_len = 60;
	build_frame(frame, &(struct frame_spec){ 0 }, payload, 18);
	EXPECT_EQ(xdev_ext_rx_parse_frame(&t, frame, 60, &dg), XDEV_EXT_RX_FRAME_OK);
	build_frame(frame, &(struct frame_spec){ 0 }, payload, 19);
	EXPECT_EQ(xdev_ext_rx_parse_frame(&t, frame, 61, &dg),
		  XDEV_EXT_RX_FRAME_NOT_FLOW);
}

/* Checksums verified across iovec splits at odd offsets. */
static void test_csum_across_iovec_splits(void)
{
	static const size_t splits[][4] = {
		{ 1, 3, 7, 4096 }, { 0, 1, 0, 4096 }, { 2, 2, 2, 4096 },
		{ 4096, 0, 0, 0 }, { 5, 0, 1000, 4096 },
	};
	uint8_t payload[1001];
	uint8_t frame[2048];
	struct xdev_ext_flow_tuple t = flow_tuple();

	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(i * 7 + 3);

	for (size_t s = 0; s < sizeof(splits) / sizeof(splits[0]); s++) {
		for (int bad = 0; bad < 2; bad++) {
			struct fake_kernel *fk = fk_new_tuple(4, 2048, &t);
			struct frame_spec spec = {
				.csum = bad ? CSUM_BAD : CSUM_OK,
			};
			uint8_t out[4][4096];
			struct iovec iov[4];
			struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 4 };
			size_t len = build_frame(frame, &spec, payload,
						 sizeof(payload));
			size_t off = 0;
			ssize_t ret = 0;
			bool wake = false;
			int st;

			memset(out, 0, sizeof(out));
			for (int k = 0; k < 4; k++) {
				iov[k].iov_base = out[k];
				iov[k].iov_len = splits[s][k];
			}
			EXPECT_TRUE(fk_post(fk, frame, len));
			st = xdev_ext_rx_core_recv(&fk->core, &msg, 0, &ret, &wake);
			if (bad) {
				EXPECT_EQ(st, XDEV_EXT_RX_EMPTY);
				EXPECT_EQ(CTR(fk, dropped_udp_csum), 1);
				EXPECT_EQ(CTR(fk, delivered), 0);
			} else {
				EXPECT_EQ(st, XDEV_EXT_RX_DELIVERED);
				EXPECT_EQ(ret, sizeof(payload));
				for (int k = 0; k < 4 && off < sizeof(payload);
				     k++) {
					size_t n = splits[s][k];

					if (n > sizeof(payload) - off)
						n = sizeof(payload) - off;
					EXPECT_TRUE(!memcmp(out[k], payload + off,
							    n));
					off += n;
				}
				EXPECT_EQ(off, sizeof(payload));
				EXPECT_EQ(CTR(fk, dropped_udp_csum), 0);
			}
			EXPECT_EQ(CTR(fk, frames_outstanding), 0);
			fk_free(fk);
		}
	}

	/* A bad checksum on a truncating or peeking read is found before the
	 * copy, as udp_recvmsg does: the caller's buffer stays untouched. */
	for (int peek = 0; peek < 2; peek++) {
		struct fake_kernel *fk = fk_new(4);
		struct frame_spec spec = { .csum = CSUM_BAD };
		uint8_t out[16];
		size_t len = build_frame(frame, &spec, payload, 100);
		struct recv_out o;

		memset(out, 0xa5, sizeof(out));
		EXPECT_TRUE(fk_post(fk, frame, len));
		o = do_recv(fk, out, peek ? 200 : 16, peek ? MSG_PEEK : 0);
		EXPECT_EQ(o.status, XDEV_EXT_RX_EMPTY);
		EXPECT_EQ(out[0], 0xa5);
		EXPECT_EQ(CTR(fk, dropped_udp_csum), 1);
		EXPECT_TRUE(!xdev_ext_rx_core_ready(&fk->core));
		fk_free(fk);
	}
}

static void test_recv_semantics(void)
{
	struct fake_kernel *fk = fk_new(8);
	char buf[64] = { 0 };
	struct recv_out o;
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	struct msghdr msg;
	uint32_t cons0 = fk->rx.consumer;
	struct sockaddr_in small;
	ssize_t ret;
	bool wake;

	/* Peek twice: same datagram, consumer never published. */
	EXPECT_TRUE(fk_post_good(fk, "first-datagram"));
	EXPECT_TRUE(fk_post_good(fk, "second"));
	memset(buf, 0, sizeof(buf));
	o = do_recv(fk, buf, sizeof(buf), MSG_PEEK);
	EXPECT_EQ(o.status, XDEV_EXT_RX_DELIVERED);
	EXPECT_EQ(o.ret, 14);
	EXPECT_TRUE(!memcmp(buf, "first-datagram", 14));
	EXPECT_EQ(fk->rx.consumer, cons0);
	EXPECT_EQ(fk->core.peek_source, XDEV_EXT_PEEK_RING);
	EXPECT_EQ(o.msg_flags, 0);
	EXPECT_EQ(o.controllen, 0);
	EXPECT_EQ(o.fromlen, sizeof(struct sockaddr_in));
	EXPECT_EQ(o.from.sin_family, AF_INET);
	EXPECT_EQ(o.from.sin_port, htons(FLOW_SPORT));
	EXPECT_EQ(o.from.sin_addr.s_addr, flow_src());
	o = do_recv(fk, buf, 5, MSG_PEEK);
	EXPECT_EQ(o.ret, 5);
	EXPECT_EQ(o.msg_flags, MSG_TRUNC);
	EXPECT_EQ(fk->rx.consumer, cons0);
	EXPECT_EQ(CTR(fk, peeked), 2);
	EXPECT_EQ(CTR(fk, frames_received), 1);
	EXPECT_EQ(CTR(fk, frames_outstanding), 1);

	/* MSG_TRUNC as a flag returns the datagram's full length. */
	o = do_recv(fk, buf, 5, MSG_PEEK | MSG_TRUNC);
	EXPECT_EQ(o.ret, 14);
	EXPECT_EQ(o.msg_flags, MSG_TRUNC);

	/* The next ordinary read takes the peeked datagram and publishes. */
	memset(buf, 0, sizeof(buf));
	o = do_recv(fk, buf, 4, MSG_CMSG_CLOEXEC);
	EXPECT_EQ(o.status, XDEV_EXT_RX_DELIVERED);
	EXPECT_EQ(o.ret, 4);
	EXPECT_TRUE(!memcmp(buf, "firs", 4));
	EXPECT_EQ(buf[4], 0);
	/* recvmsg echoes MSG_CMSG_CLOEXEC (net/socket.c ____sys_recvmsg). */
	EXPECT_EQ(o.msg_flags, MSG_TRUNC | MSG_CMSG_CLOEXEC);
	EXPECT_EQ(fk->rx.consumer, cons0 + 1);
	EXPECT_EQ(fk->core.peek_source, XDEV_EXT_PEEK_NONE);
	EXPECT_EQ(CTR(fk, delivered), 1);
	EXPECT_EQ(CTR(fk, delivered_bytes), 4);
	EXPECT_EQ(CTR(fk, truncated), 1);

	/* A zero-length buffer consumes one datagram. */
	o = do_recv(fk, NULL, 0, 0);
	EXPECT_EQ(o.status, XDEV_EXT_RX_DELIVERED);
	EXPECT_EQ(o.ret, 0);
	EXPECT_EQ(o.msg_flags, MSG_TRUNC);
	EXPECT_EQ(fk->rx.consumer, cons0 + 2);
	EXPECT_TRUE(!xdev_ext_rx_core_ready(&fk->core));
	o = do_recv(fk, buf, sizeof(buf), 0);
	EXPECT_EQ(o.status, XDEV_EXT_RX_EMPTY);

	/* With MSG_TRUNC, a zero-length buffer returns the full length. */
	EXPECT_TRUE(fk_post_good(fk, "abcdef"));
	o = do_recv(fk, NULL, 0, MSG_TRUNC);
	EXPECT_EQ(o.ret, 6);
	EXPECT_EQ(o.msg_flags, MSG_TRUNC);

	/* A zero-length datagram is not truncated. */
	EXPECT_TRUE(fk_post_good(fk, ""));
	o = do_recv(fk, NULL, 0, 0);
	EXPECT_EQ(o.status, XDEV_EXT_RX_DELIVERED);
	EXPECT_EQ(o.ret, 0);
	EXPECT_EQ(o.msg_flags, 0);

	/* Source address: truncated copy, full length reported. */
	EXPECT_TRUE(fk_post_good(fk, "name"));
	memset(&small, 0xee, sizeof(small));
	msg = (struct msghdr) {
		.msg_name = &small, .msg_namelen = 4,
		.msg_iov = &iov, .msg_iovlen = 1,
	};
	EXPECT_EQ(xdev_ext_rx_core_recv(&fk->core, &msg, MSG_PEEK, &ret, &wake),
		  XDEV_EXT_RX_DELIVERED);
	EXPECT_EQ(msg.msg_namelen, sizeof(struct sockaddr_in));
	EXPECT_EQ(small.sin_family, AF_INET);
	EXPECT_EQ(small.sin_port, htons(FLOW_SPORT));
	EXPECT_EQ(small.sin_addr.s_addr, 0xeeeeeeee);
	msg.msg_namelen = 0;
	memset(&small, 0xee, sizeof(small));
	EXPECT_EQ(xdev_ext_rx_core_recv(&fk->core, &msg, MSG_PEEK, &ret, &wake),
		  XDEV_EXT_RX_DELIVERED);
	EXPECT_EQ(msg.msg_namelen, sizeof(struct sockaddr_in));
	EXPECT_EQ(small.sin_family, 0xeeee);
	/* Without a name buffer the length is left as the caller set it. */
	msg.msg_name = NULL;
	msg.msg_namelen = 77;
	EXPECT_EQ(xdev_ext_rx_core_recv(&fk->core, &msg, 0, &ret, &wake),
		  XDEV_EXT_RX_DELIVERED);
	EXPECT_EQ(msg.msg_namelen, 77);
	EXPECT_EQ(ret, 4);

	/* MSG_WAITALL and MSG_DONTWAIT still return one datagram. */
	EXPECT_TRUE(fk_post_good(fk, "one"));
	EXPECT_TRUE(fk_post_good(fk, "two"));
	o = do_recv(fk, buf, sizeof(buf), MSG_WAITALL | MSG_DONTWAIT);
	EXPECT_EQ(o.ret, 3);
	EXPECT_TRUE(xdev_ext_rx_core_ready(&fk->core));
	fk_free(fk);
}

static void test_ring_cursor_publishes_only_on_delivery(void)
{
	struct fake_kernel *fk = fk_new(8);
	uint32_t cons0 = fk->rx.consumer;
	uint32_t fill0 = fk->fill.producer;
	char buf[32] = { 0 };
	struct recv_out o;
	char text[8];

	for (int i = 0; i < 5; i++) {
		snprintf(text, sizeof(text), "dg%d", i);
		EXPECT_TRUE(fk_post_good(fk, text));
	}
	EXPECT_TRUE(xdev_ext_rx_core_ready(&fk->core));
	EXPECT_EQ(xdev_ext_rx_core_pending(&fk->core), 5);
	for (int i = 0; i < 5; i++) {
		o = do_recv(fk, buf, sizeof(buf), 0);
		EXPECT_EQ(o.status, XDEV_EXT_RX_DELIVERED);
		snprintf(text, sizeof(text), "dg%d", i);
		EXPECT_EQ(o.ret, 3);
		EXPECT_TRUE(!memcmp(buf, text, 3));
		/* One delivery publishes exactly one consumer step. */
		EXPECT_EQ(fk->rx.consumer, cons0 + i + 1);
		EXPECT_EQ(fk->fill.producer, fill0 + i + 1);
		/* Readable as the kernel sees it: consumer != producer. */
		EXPECT_EQ(fk->rx.consumer != fk->rx.producer, i < 4);
		EXPECT_EQ(xdev_ext_rx_core_ready(&fk->core), i < 4);
		EXPECT_EQ(CTR(fk, frames_outstanding), 0);
	}
	/* Returned frames are frame-aligned and back in FILL. */
	for (uint32_t i = 0; i < 5; i++) {
		uint64_t a = fk->fill.descs[(fill0 + i) & 7];

		EXPECT_EQ(a % 2048, 0);
		EXPECT_EQ(fk->state[a / 2048], XDEV_EXT_FRAME_FILL);
	}
	EXPECT_EQ(CTR(fk, frames_received), 5);
	EXPECT_EQ(CTR(fk, frames_returned), 5);

	/* A dropped frame also publishes one step, and only one. */
	{
		struct frame_spec bad = { .bad_ip_csum = true };
		uint8_t frame[128];
		size_t len = build_frame(frame, &bad, (const uint8_t *)"x", 1);

		EXPECT_TRUE(fk_post(fk, frame, len));
		EXPECT_TRUE(fk_post_good(fk, "kept"));
		o = do_recv(fk, buf, sizeof(buf), MSG_PEEK);
		EXPECT_EQ(o.ret, 4);
		EXPECT_EQ(fk->rx.consumer, cons0 + 6);
		EXPECT_EQ(CTR(fk, dropped_ip_csum), 1);
		EXPECT_TRUE(xdev_ext_rx_core_ready(&fk->core));
	}

	/* The wakeup request is reported when the fill ring carries it. */
	fk->fill.flags = XDP_RING_NEED_WAKEUP;
	o = do_recv(fk, buf, sizeof(buf), 0);
	EXPECT_EQ(o.status, XDEV_EXT_RX_DELIVERED);
	EXPECT_TRUE(o.wake);
	fk->fill.flags = 0;
	EXPECT_TRUE(fk_post_good(fk, "quiet"));
	o = do_recv(fk, buf, sizeof(buf), 0);
	EXPECT_TRUE(!o.wake);
	fk_free(fk);
}

static void expect_sequestered(struct fake_kernel *fk, uint32_t cons,
			       uint32_t fill)
{
	char buf[16] = { 0 };
	struct recv_out o = do_recv(fk, buf, sizeof(buf), 0);
	uint32_t len = 0;
	bool wake = false;

	EXPECT_EQ(o.status, XDEV_EXT_RX_SEQUESTER);
	EXPECT_TRUE(fk->core.sequestered);
	/* Nothing is published once sequestered. */
	EXPECT_EQ(fk->rx.consumer, cons);
	EXPECT_EQ(fk->fill.producer, fill);
	EXPECT_TRUE(!xdev_ext_rx_core_ready(&fk->core));
	EXPECT_EQ(xdev_ext_rx_core_next_len(&fk->core, &len, &wake),
		  XDEV_EXT_RX_SEQUESTER);
	o = do_recv(fk, buf, sizeof(buf), MSG_PEEK);
	EXPECT_EQ(o.status, XDEV_EXT_RX_SEQUESTER);
	EXPECT_EQ(fk->rx.consumer, cons);
}

static void test_frame_state_and_sequester(void)
{
	struct fake_kernel *fk;
	uint32_t cons, fill;
	char buf[16] = { 0 };
	struct recv_out o;

	/* Address outside the frame area. */
	fk = fk_new(8);
	cons = fk->rx.consumer;
	fill = fk->fill.producer;
	fk_post_desc(fk, 8ULL * 2048 + FK_HEADROOM, 60, 0);
	expect_sequestered(fk, cons, fill);
	EXPECT_EQ(CTR(fk, desc_invalid), 1);
	EXPECT_EQ(CTR(fk, frames_received), 0);
	fk_free(fk);

	/* Length running past the end of its frame. */
	fk = fk_new(8);
	cons = fk->rx.consumer;
	fill = fk->fill.producer;
	fk_post_desc(fk, 2048 + FK_HEADROOM, 2048 - FK_HEADROOM + 1, 0);
	expect_sequestered(fk, cons, fill);
	EXPECT_EQ(CTR(fk, desc_invalid), 1);
	fk_free(fk);

	/* A continuation option: this ring never carries multi-buffer
	 * packets, so a set option is an impossible descriptor. */
	fk = fk_new(8);
	cons = fk->rx.consumer;
	fill = fk->fill.producer;
	fk_post_desc(fk, 2048 + FK_HEADROOM, 60, XDP_PKT_CONTD);
	expect_sequestered(fk, cons, fill);
	EXPECT_EQ(CTR(fk, desc_invalid), 1);
	fk_free(fk);

	/* A descriptor naming a frame that is not in FILL is refused at
	 * first sight, even with room in the fill ring. */
	fk = fk_new(8);
	{
		struct frame_spec s = { 0 };
		uint8_t frame[128];
		size_t len = build_frame(frame, &s, (const uint8_t *)"dup", 3);

		/* The kernel took one fill entry; frame 3 is (wrongly) RX. */
		__atomic_store_n(&fk->fill.consumer, fk->fill.consumer + 1,
				 __ATOMIC_RELEASE);
		fk->state[3] = XDEV_EXT_FRAME_RX;
		memcpy(fk->umem + 3 * 2048 + FK_HEADROOM, frame, len);
		cons = fk->rx.consumer;
		fill = fk->fill.producer;
		fk_post_desc(fk, 3 * 2048 + FK_HEADROOM, (uint32_t)len, 0);
	}
	expect_sequestered(fk, cons, fill);
	EXPECT_EQ(CTR(fk, desc_invalid), 1);
	EXPECT_EQ(CTR(fk, frames_received), 0);
	fk_free(fk);

	/* Retiring a frame that is no longer RX is a double retire. */
	fk = fk_new(8);
	EXPECT_TRUE(fk_post_good(fk, "twice"));
	o = do_recv(fk, buf, sizeof(buf), MSG_PEEK);
	EXPECT_EQ(o.status, XDEV_EXT_RX_DELIVERED);
	cons = fk->rx.consumer;
	fill = fk->fill.producer;
	fk->state[fk->rx.descs[cons & 7].addr / 2048] = XDEV_EXT_FRAME_FILL;
	expect_sequestered(fk, cons, fill);
	EXPECT_EQ(CTR(fk, double_retire), 1);
	fk_free(fk);

	/* A producer more than a ring ahead of the consumer. */
	fk = fk_new(8);
	cons = fk->rx.consumer;
	fill = fk->fill.producer;
	__atomic_store_n(&fk->rx.producer, cons + 9, __ATOMIC_RELEASE);
	expect_sequestered(fk, cons, fill);
	EXPECT_EQ(CTR(fk, desc_invalid), 1);
	fk_free(fk);

	/* A fill ring with no room left cannot take a frame back. */
	fk = fk_new(8);
	EXPECT_TRUE(fk_post_good(fk, "full"));
	cons = fk->rx.consumer;
	fill = fk->fill.producer;
	fk->fill.consumer = fill - 8;	/* the kernel claims 8 are queued */
	expect_sequestered(fk, cons, fill);
	EXPECT_EQ(CTR(fk, desc_invalid), 1);
	fk_free(fk);

	/* An explicit sequester stops all ring access too. */
	fk = fk_new(8);
	EXPECT_TRUE(fk_post_good(fk, "residue"));
	cons = fk->rx.consumer;
	fill = fk->fill.producer;
	EXPECT_EQ(xdev_ext_rx_core_pending(&fk->core), 1);
	xdev_ext_rx_core_sequester(&fk->core);
	/* The residue is counted once, then the ring is never read again. */
	EXPECT_EQ(fk->core.sequester_residue, 1);
	expect_sequestered(fk, cons, fill);
	EXPECT_EQ(xdev_ext_rx_core_pending(&fk->core), 0);
	EXPECT_EQ(fk->core.sequester_residue, 1);
	fk_free(fk);
}

static void test_next_len(void)
{
	struct fake_kernel *fk = fk_new(8);
	struct frame_spec bad = { .csum = CSUM_BAD };
	uint8_t frame[128];
	size_t len = build_frame(frame, &bad, (const uint8_t *)"bad", 3);
	uint32_t n = 99;
	bool wake = false;
	char buf[16] = { 0 };
	struct recv_out o;

	EXPECT_EQ(xdev_ext_rx_core_next_len(&fk->core, &n, &wake), XDEV_EXT_RX_EMPTY);
	EXPECT_TRUE(fk_post(fk, frame, len));
	EXPECT_TRUE(fk_post_good(fk, "seven77"));
	/* As FIONREAD: the bad head is dropped first, nothing is consumed. */
	EXPECT_EQ(xdev_ext_rx_core_next_len(&fk->core, &n, &wake),
		  XDEV_EXT_RX_DELIVERED);
	EXPECT_EQ(n, 7);
	EXPECT_EQ(CTR(fk, dropped_udp_csum), 1);
	EXPECT_EQ(CTR(fk, peeked), 0);
	EXPECT_EQ(CTR(fk, delivered), 0);
	EXPECT_TRUE(xdev_ext_rx_core_ready(&fk->core));
	o = do_recv(fk, buf, sizeof(buf), 0);
	EXPECT_EQ(o.ret, 7);
	fk_free(fk);
}

static void test_kernel_queue_order(void)
{
	struct fake_kernel *fk = fk_new(8);
	struct xdev_ext_rx_core *c = &fk->core;
	char buf[8] = { 0 };

	/* Activation leaves datagrams queued in the socket: drain first. */
	c->drain_pending = true;
	EXPECT_TRUE(xdev_ext_rx_core_kernel_first(c));
	EXPECT_TRUE(xdev_ext_rx_core_kernel_done(c, 12, 0, 0));
	EXPECT_EQ(CTR(fk, kernel_path_datagrams), 1);
	EXPECT_TRUE(xdev_ext_rx_core_kernel_first(c));
	/* An error other than EAGAIN goes back to the caller. */
	EXPECT_TRUE(xdev_ext_rx_core_kernel_done(c, -1, ECONNREFUSED, 0));
	EXPECT_TRUE(xdev_ext_rx_core_kernel_first(c));
	EXPECT_TRUE(!xdev_ext_rx_core_kernel_done(c, -1, EAGAIN, 0));
	EXPECT_TRUE(!c->drain_pending);
	EXPECT_TRUE(!xdev_ext_rx_core_kernel_first(c));

	/* A kernel-queue peek pins the next read to the kernel queue. */
	EXPECT_TRUE(xdev_ext_rx_core_kernel_done(c, 5, 0, MSG_PEEK));
	EXPECT_EQ(c->peek_source, XDEV_EXT_PEEK_KERNEL);
	EXPECT_EQ(CTR(fk, kernel_path_datagrams), 1);
	EXPECT_TRUE(xdev_ext_rx_core_kernel_first(c));
	EXPECT_TRUE(xdev_ext_rx_core_kernel_done(c, 5, 0, 0));
	EXPECT_EQ(c->peek_source, XDEV_EXT_PEEK_NONE);
	EXPECT_EQ(CTR(fk, kernel_path_datagrams), 2);
	EXPECT_TRUE(!xdev_ext_rx_core_kernel_first(c));
	/* The peeked datagram vanished (another reader): back to the ring. */
	EXPECT_TRUE(xdev_ext_rx_core_kernel_done(c, 5, 0, MSG_PEEK));
	EXPECT_TRUE(!xdev_ext_rx_core_kernel_done(c, -1, EWOULDBLOCK, 0));
	EXPECT_EQ(c->peek_source, XDEV_EXT_PEEK_NONE);

	/* A ring peek pins the next read to the ring even if a kernel check
	 * is due. */
	EXPECT_TRUE(fk_post_good(fk, "ring"));
	EXPECT_EQ(do_recv(fk, buf, sizeof(buf), MSG_PEEK).status,
		  XDEV_EXT_RX_DELIVERED);
	c->drain_pending = true;
	EXPECT_TRUE(!xdev_ext_rx_core_kernel_first(c));
	EXPECT_EQ(do_recv(fk, buf, sizeof(buf), 0).status, XDEV_EXT_RX_DELIVERED);
	EXPECT_TRUE(xdev_ext_rx_core_kernel_first(c));
	EXPECT_TRUE(!xdev_ext_rx_core_kernel_done(c, -1, EAGAIN, 0));

	/* Every 64th ring delivery schedules one look at the kernel queue. */
	for (int i = 1; i < 64; i++) {
		EXPECT_TRUE(fk_post_good(fk, "x"));
		EXPECT_EQ(do_recv(fk, buf, sizeof(buf), 0).status,
			  XDEV_EXT_RX_DELIVERED);
		if (i < 63)
			EXPECT_TRUE(!xdev_ext_rx_core_kernel_first(c));
	}
	EXPECT_EQ(CTR(fk, delivered), 64);
	EXPECT_TRUE(c->kernel_check_due);
	EXPECT_TRUE(xdev_ext_rx_core_kernel_first(c));
	EXPECT_TRUE(!xdev_ext_rx_core_kernel_done(c, -1, EAGAIN, 0));
	EXPECT_TRUE(!c->kernel_check_due);
	fk_free(fk);
}

/* ------------------------------------------------------------------ */
/* Random interleavings: arrivals, deliveries, peeks, drops.            */

enum post_kind {
	KIND_GOOD, KIND_GOOD_NOCSUM, KIND_IP_CSUM, KIND_UDP_CSUM,
	KIND_MALFORMED, KIND_NOT_FLOW, KIND_COUNT,
};

struct posted {
	enum post_kind kind;
	size_t len;
	uint8_t data[300];
};

static uint32_t rng_state;

static uint32_t rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static bool kind_good(enum post_kind k)
{
	return k == KIND_GOOD || k == KIND_GOOD_NOCSUM;
}

static unsigned int frames_in_rx_state(const struct fake_kernel *fk)
{
	unsigned int n = 0;

	for (uint32_t i = 0; i < fk->nframes; i++)
		n += fk->state[i] == XDEV_EXT_FRAME_RX;
	return n;
}

static bool check_balance(const struct fake_kernel *fk)
{
	struct xdev_ext_rx_counters s;
	bool ok;

	xdev_ext_rx_counters_snapshot(&fk->core.ctr, &s);
	ok = xdev_ext_rx_counters_balanced(&s) &&
	     s.frames_outstanding == frames_in_rx_state(fk) &&
	     /* Every frame is in the fill ring or in the receive ring. */
	     (fk->fill.producer - fk->fill.consumer) +
	     (fk->rx.producer - fk->rx.consumer) == fk->nframes &&
	     s.double_retire == 0 && s.desc_invalid == 0;
	return ok;
}

static void run_random(uint32_t seed, uint32_t nframes, unsigned int steps)
{
	struct fake_kernel *fk = fk_new(nframes);
	struct posted queue[FK_MAX_FRAMES];
	unsigned int qhead = 0, qtail = 0;
	unsigned long long expect_drop[KIND_COUNT] = { 0 };
	unsigned long long expect_delivered = 0;
	unsigned int balance_failures = 0, content_failures = 0;
	uint8_t frame[2048];
	uint8_t buf[512] = { 0 };
	bool draining = false;

	rng_state = seed;
	for (unsigned int step = 0; step < steps || qhead != qtail; step++) {
		uint32_t r;

		/* After the random phase only plain reads, until empty. */
		if (step == steps)
			draining = true;
		r = draining ? 50 : rng() % 100;
		if (r < 40) {
			struct posted *p = &queue[qtail % FK_MAX_FRAMES];
			struct frame_spec s = { 0 };
			size_t len;

			p->kind = (enum post_kind)(rng() % KIND_COUNT);
			p->len = rng() % sizeof(p->data);
			for (size_t i = 0; i < p->len; i++)
				p->data[i] = (uint8_t)rng();
			switch (p->kind) {
			case KIND_GOOD_NOCSUM: s.csum = CSUM_ZERO; break;
			case KIND_IP_CSUM: s.bad_ip_csum = true; break;
			case KIND_UDP_CSUM: s.csum = CSUM_BAD; break;
			case KIND_MALFORMED: s.udp_len_delta = 2; break;
			case KIND_NOT_FLOW: s.dport = FLOW_DPORT + 7; break;
			default: break;
			}
			len = build_frame(frame, &s, p->data, p->len);
			if (fk_post(fk, frame, len))
				qtail++;
		} else {
			bool peek = r >= 70 && r < 85;
			bool trunc_flag = r >= 95;
			size_t n = (size_t[]){ 0, 5, 64, 512 }[rng() % 4];
			int flags = (peek ? MSG_PEEK : 0) |
				    (trunc_flag ? MSG_TRUNC : 0);
			uint32_t next = 0;
			bool wake = false;
			struct recv_out o = { 0 };
			int st;

			if (draining)
				n = sizeof(buf);
			if (r >= 85 && r < 95) {
				st = xdev_ext_rx_core_next_len(&fk->core, &next,
							  &wake);
				o.status = st;
				o.ret = next;
				peek = true;
				n = 0;
			} else {
				o = do_recv(fk, buf, n, flags);
			}
			/* Bad frames ahead of the first good one are dropped. */
			while (qhead != qtail &&
			       !kind_good(queue[qhead % FK_MAX_FRAMES].kind)) {
				expect_drop[queue[qhead % FK_MAX_FRAMES].kind]++;
				qhead++;
			}
			if (qhead == qtail) {
				if (o.status != XDEV_EXT_RX_EMPTY)
					content_failures++;
				continue;
			}
			{
				struct posted *p = &queue[qhead % FK_MAX_FRAMES];
				size_t copy = n < p->len ? n : p->len;
				ssize_t want = (flags & MSG_TRUNC) || r >= 85 ?
					       (ssize_t)p->len : (ssize_t)copy;

				if (o.status != XDEV_EXT_RX_DELIVERED ||
				    o.ret != want ||
				    (n && memcmp(buf, p->data, copy)))
					content_failures++;
				if (!peek) {
					expect_delivered++;
					qhead++;
				}
			}
		}
		if (!check_balance(fk))
			balance_failures++;
	}
	EXPECT_EQ(balance_failures, 0);
	EXPECT_EQ(content_failures, 0);
	EXPECT_EQ(CTR(fk, delivered), expect_delivered);
	EXPECT_EQ(CTR(fk, dropped_ip_csum), expect_drop[KIND_IP_CSUM]);
	EXPECT_EQ(CTR(fk, dropped_udp_csum), expect_drop[KIND_UDP_CSUM]);
	EXPECT_EQ(CTR(fk, dropped_malformed), expect_drop[KIND_MALFORMED]);
	EXPECT_EQ(CTR(fk, dropped_not_flow), expect_drop[KIND_NOT_FLOW]);
	/* After a full drain: nothing outstanding, nothing impossible. */
	EXPECT_EQ(CTR(fk, frames_outstanding), 0);
	EXPECT_EQ(CTR(fk, double_retire), 0);
	EXPECT_EQ(CTR(fk, desc_invalid), 0);
	EXPECT_EQ(CTR(fk, frames_returned), CTR(fk, frames_received));
	EXPECT_TRUE(!xdev_ext_rx_core_ready(&fk->core));
	EXPECT_TRUE(CTR(fk, frames_received) > nframes);
	fk_free(fk);
}

static void test_random_sequences_keep_the_identities(void)
{
	static const uint32_t seeds[] = { 1, 7, 42, 1234, 0x9e3779b9 };

	for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); i++) {
		run_random(seeds[i], 8, 3000);
		run_random(seeds[i] ^ 0x5555, 2, 1000);
	}
}

static void test_counter_identities_detect_imbalance(void)
{
	struct xdev_ext_rx_counters s = {
		.frames_received = 10, .frames_returned = 8,
		.frames_outstanding = 2, .delivered = 5,
		.dropped_ip_csum = 1, .dropped_udp_csum = 1,
		.dropped_malformed = 0, .dropped_not_flow = 1,
	};

	EXPECT_TRUE(xdev_ext_rx_counters_balanced(&s));
	s.delivered++;
	EXPECT_TRUE(!xdev_ext_rx_counters_balanced(&s));
	s.delivered--;
	s.frames_returned--;
	EXPECT_TRUE(!xdev_ext_rx_counters_balanced(&s));
}

/* ------------------------------------------------------------------ */
/* poll folding                                                         */

static void test_poll_fold(void)
{
	/* Two entries for registration 0 (same fd twice), one for
	 * registration 1, one plain fd, one negative fd. */
	struct pollfd fds[5] = {
		{ .fd = 10, .events = POLLIN | POLLOUT },
		{ .fd = 11, .events = POLLRDNORM },
		{ .fd = 10, .events = POLLIN },
		{ .fd = 12, .events = POLLIN },
		{ .fd = -3, .events = POLLIN },
	};
	const int group[5] = { 0, 1, 0, -1, -1 };
	const int wait_fds[2] = { 100, 101 };
	struct pollfd ext[7];
	bool ready[2] = { false, true };
	int n;

	xdev_ext_rx_poll_extend(ext, fds, 5, wait_fds, 2);
	for (int i = 0; i < 5; i++) {
		EXPECT_EQ(ext[i].fd, fds[i].fd);
		EXPECT_EQ(ext[i].events, fds[i].events);
	}
	EXPECT_EQ(ext[5].fd, 100);
	EXPECT_EQ(ext[5].events, POLLIN);
	EXPECT_EQ(ext[6].fd, 101);
	EXPECT_EQ(ext[6].events, POLLIN);

	/* The real poll reported: fd 10 writable, private 101 readable. */
	for (int i = 0; i < 7; i++)
		ext[i].revents = 0;
	ext[0].revents = POLLOUT;
	ext[2].revents = 0;
	ext[6].revents = POLLIN;
	n = xdev_ext_rx_poll_fold(fds, 5, ext, group, 2);
	EXPECT_EQ(fds[0].revents, POLLOUT);
	EXPECT_EQ(fds[1].revents, POLLRDNORM);	/* only the requested bit */
	EXPECT_EQ(fds[2].revents, 0);
	EXPECT_EQ(fds[3].revents, 0);
	EXPECT_EQ(fds[4].revents, 0);
	EXPECT_EQ(n, 2);

	/* Registration 0 readable: both of its entries get POLLIN. */
	for (int i = 0; i < 7; i++)
		ext[i].revents = 0;
	ext[5].revents = POLLIN;
	ext[3].revents = POLLIN;
	n = xdev_ext_rx_poll_fold(fds, 5, ext, group, 2);
	EXPECT_EQ(fds[0].revents, POLLIN);
	EXPECT_EQ(fds[2].revents, POLLIN);
	EXPECT_EQ(fds[3].revents, POLLIN);
	EXPECT_EQ(fds[1].revents, 0);
	EXPECT_EQ(n, 3);

	/* POLLNVAL on an application entry is kept as is. */
	for (int i = 0; i < 7; i++)
		ext[i].revents = 0;
	ext[0].revents = POLLNVAL;
	ext[5].revents = POLLIN;
	n = xdev_ext_rx_poll_fold(fds, 5, ext, group, 2);
	EXPECT_EQ(fds[0].revents, POLLNVAL);
	EXPECT_EQ(fds[2].revents, POLLIN);
	EXPECT_EQ(n, 2);

	/* Only a private entry fired: nothing the caller can see. */
	for (int i = 0; i < 7; i++)
		ext[i].revents = 0;
	ext[6].revents = POLLERR;
	n = xdev_ext_rx_poll_fold(fds, 5, ext, group, 2);
	EXPECT_EQ(n, 0);

	/* Ready registrations folded into a zero-timeout poll result. */
	for (int i = 0; i < 5; i++)
		fds[i].revents = 0;
	fds[3].revents = POLLIN;
	fds[0].revents = POLLOUT;
	n = xdev_ext_rx_poll_mark_ready(fds, 5, group, ready, 2);
	EXPECT_EQ(fds[1].revents, POLLRDNORM);
	EXPECT_EQ(fds[0].revents, POLLOUT);
	EXPECT_EQ(fds[2].revents, 0);
	EXPECT_EQ(n, 3);
	ready[0] = true;
	fds[2].revents = POLLNVAL;
	n = xdev_ext_rx_poll_mark_ready(fds, 5, group, ready, 2);
	EXPECT_EQ(fds[0].revents, POLLOUT | POLLIN);
	EXPECT_EQ(fds[2].revents, POLLNVAL);
	EXPECT_EQ(fds[4].revents, 0);
	EXPECT_EQ(n, 4);
}

/* ------------------------------------------------------------------ */
/* select <-> poll                                                      */

static void test_select_conversion(void)
{
	fd_set rd, wr, ex, rd0, wr0, ex0;
	struct pollfd p[8] = { 0 };
	int n;

	FD_ZERO(&rd);
	FD_ZERO(&wr);
	FD_ZERO(&ex);
	FD_SET(3, &rd);
	FD_SET(3, &wr);
	FD_SET(5, &ex);
	FD_SET(7, &wr);
	FD_SET(9, &rd);		/* beyond nfds: ignored */

	EXPECT_EQ(xdev_ext_rx_select_to_poll(-1, &rd, &wr, &ex, p, 8), -EINVAL);
	EXPECT_EQ(xdev_ext_rx_select_to_poll(9, &rd, &wr, &ex, NULL, 0), 3);
	EXPECT_EQ(xdev_ext_rx_select_to_poll(9, &rd, &wr, &ex, p, 2), -ENOMEM);
	n = xdev_ext_rx_select_to_poll(9, &rd, &wr, &ex, p, 8);
	EXPECT_EQ(n, 3);
	EXPECT_EQ(p[0].fd, 3);
	EXPECT_EQ(p[0].events, POLLIN | POLLRDNORM | POLLRDBAND | POLLOUT |
			       POLLWRNORM | POLLWRBAND);
	EXPECT_EQ(p[1].fd, 5);
	EXPECT_EQ(p[1].events, POLLPRI);
	EXPECT_EQ(p[2].fd, 7);
	EXPECT_EQ(p[2].events, POLLOUT | POLLWRNORM | POLLWRBAND);
	EXPECT_EQ(xdev_ext_rx_select_to_poll(0, &rd, &wr, &ex, p, 8), 0);
	EXPECT_EQ(xdev_ext_rx_select_to_poll(9, NULL, NULL, NULL, p, 8), 0);

	/* Fold back with the kernel's select sets (fs/select.c POLLIN_SET,
	 * POLLOUT_SET, POLLEX_SET): HUP and ERR read as readable, ERR as
	 * writable, PRI as exceptional. */
	p[0].revents = POLLHUP;
	p[1].revents = POLLPRI | POLLERR;
	p[2].revents = POLLERR;
	rd0 = rd;
	wr0 = wr;
	ex0 = ex;
	n = xdev_ext_rx_poll_to_select(p, 3, 9, &rd, &wr, &ex);
	EXPECT_EQ(n, 3);
	EXPECT_TRUE(FD_ISSET(3, &rd));
	EXPECT_TRUE(!FD_ISSET(3, &wr));	/* HUP alone is not writable */
	EXPECT_TRUE(FD_ISSET(5, &ex));
	EXPECT_TRUE(FD_ISSET(7, &wr));
	/* The kernel writes back whole words: bit 9 is cleared too. */
	EXPECT_TRUE(!FD_ISSET(9, &rd));

	/* Readable and writable count twice. */
	rd = rd0;
	wr = wr0;
	ex = ex0;
	p[0].revents = POLLIN | POLLOUT;
	p[1].revents = 0;
	p[2].revents = 0;
	EXPECT_EQ(xdev_ext_rx_poll_to_select(p, 3, 9, &rd, &wr, &ex), 2);
	EXPECT_TRUE(FD_ISSET(3, &rd) && FD_ISSET(3, &wr));
	EXPECT_TRUE(!FD_ISSET(5, &ex) && !FD_ISSET(7, &wr));

	/* Only a hangup on an fd watched for writing: nothing to report;
	 * the caller polls again with the time left. */
	rd = rd0;
	wr = wr0;
	ex = ex0;
	p[0].revents = 0;
	p[2].revents = POLLHUP;
	EXPECT_EQ(xdev_ext_rx_poll_to_select(p, 3, 9, &rd, &wr, &ex), 0);

	/* POLLNVAL anywhere: EBADF and the sets are left untouched. */
	rd = rd0;
	wr = wr0;
	ex = ex0;
	p[0].revents = POLLIN;
	p[2].revents = POLLNVAL;
	EXPECT_EQ(xdev_ext_rx_poll_to_select(p, 3, 9, &rd, &wr, &ex), -EBADF);
	EXPECT_TRUE(!memcmp(&rd, &rd0, sizeof(rd)));
	EXPECT_TRUE(!memcmp(&wr, &wr0, sizeof(wr)));
	EXPECT_TRUE(!memcmp(&ex, &ex0, sizeof(ex)));

	/* Descriptors past FD_SETSIZE in a caller-sized set are reached
	 * through the words, not through FD_ISSET. */
	{
		unsigned long big[2048 / (8 * sizeof(unsigned long))];
		int fd = 1500;
		unsigned int bits = 8 * sizeof(unsigned long);

		memset(big, 0, sizeof(big));
		big[fd / bits] |= 1UL << (fd % bits);
		n = xdev_ext_rx_select_to_poll(fd + 1, (fd_set *)(void *)big, NULL,
					  NULL, p, 8);
		EXPECT_EQ(n, 1);
		EXPECT_EQ(p[0].fd, fd);
		p[0].revents = POLLIN;
		EXPECT_EQ(xdev_ext_rx_poll_to_select(p, 1, fd + 1,
						(fd_set *)(void *)big, NULL,
						NULL), 1);
		EXPECT_TRUE(big[fd / bits] & (1UL << (fd % bits)));
	}
}

static void test_select_timeouts(void)
{
	struct timeval tv;
	struct timespec ts, now, deadline, left;

	tv = (struct timeval) { .tv_sec = 1, .tv_usec = 2500000 };
	EXPECT_EQ(xdev_ext_rx_select_timeout(&tv, &ts), 0);
	EXPECT_EQ(ts.tv_sec, 3);
	EXPECT_EQ(ts.tv_nsec, 500000000);
	tv = (struct timeval) { .tv_sec = -1, .tv_usec = 0 };
	EXPECT_EQ(xdev_ext_rx_select_timeout(&tv, &ts), -EINVAL);
	tv = (struct timeval) { .tv_sec = 1, .tv_usec = -1 };
	EXPECT_EQ(xdev_ext_rx_select_timeout(&tv, &ts), -EINVAL);

	now = (struct timespec) { .tv_sec = 100, .tv_nsec = 900000000 };
	ts = (struct timespec) { .tv_sec = 2, .tv_nsec = 200000000 };
	xdev_ext_rx_deadline(&now, &ts, &deadline);
	EXPECT_EQ(deadline.tv_sec, 103);
	EXPECT_EQ(deadline.tv_nsec, 100000000);

	/* Time left rounds down to microseconds and stops at zero. */
	now = (struct timespec) { .tv_sec = 101, .tv_nsec = 999999 };
	EXPECT_TRUE(xdev_ext_rx_select_remaining(&ts, &deadline, &now, &tv));
	EXPECT_EQ(tv.tv_sec, 2);
	EXPECT_EQ(tv.tv_usec, 99000);
	xdev_ext_rx_time_left(&deadline, &now, &left);
	EXPECT_EQ(left.tv_sec, 2);
	EXPECT_EQ(left.tv_nsec, 99000001);
	now = (struct timespec) { .tv_sec = 104, .tv_nsec = 0 };
	EXPECT_TRUE(xdev_ext_rx_select_remaining(&ts, &deadline, &now, &tv));
	EXPECT_EQ(tv.tv_sec, 0);
	EXPECT_EQ(tv.tv_usec, 0);
	/* A zero timeout is not written back (fs/select.c
	 * poll_select_finish). */
	ts = (struct timespec) { 0 };
	tv = (struct timeval) { .tv_sec = 9, .tv_usec = 9 };
	EXPECT_TRUE(!xdev_ext_rx_select_remaining(&ts, &deadline, &now, &tv));
	EXPECT_EQ(tv.tv_sec, 9);

	/* A deadline saturates instead of wrapping. */
	ts = (struct timespec) { .tv_sec = LLONG_MAX, .tv_nsec = 999999999 };
	xdev_ext_rx_deadline(&now, &ts, &deadline);
	EXPECT_TRUE(deadline.tv_sec == LLONG_MAX);
}

int main(void)
{
	test_init_and_fill();
	test_flags_and_shapes();
	test_parse_matrix();
	test_csum_across_iovec_splits();
	test_recv_semantics();
	test_ring_cursor_publishes_only_on_delivery();
	test_frame_state_and_sequester();
	test_next_len();
	test_kernel_queue_order();
	test_random_sequences_keep_the_identities();
	test_counter_identities_detect_imbalance();
	test_poll_fold();
	test_select_conversion();
	test_select_timeouts();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u rx core checks failed\n",
			failures, checks);
		return EXIT_FAILURE;
	}
	printf("PASS: %u rx core checks\n", checks);
	return EXIT_SUCCESS;
}
