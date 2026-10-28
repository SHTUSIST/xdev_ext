/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_RX_CORE_H
#define XDEV_EXT_PRELOAD_RX_CORE_H

/*
 * Pure receive core for a taken-over UDP socket whose datagrams the kernel
 * hands over through a shared receive ring instead of the socket queue.
 * The receive source owns the rings and fills struct xdev_ext_rx_layout from the
 * kernel's ring offsets; nothing here names a device or makes a system call.
 * The caller reads the socket's own queue, waits, kicks the fill ring when
 * asked to, and holds its per-registration lock around every
 * xdev_ext_rx_core_*() call except xdev_ext_rx_core_ready().
 *
 * Ring protocol (single producer, single consumer, free-running u32
 * indices): a consumer loads the producer index with acquire before reading
 * the descriptors behind it and publishes its consumer index with release
 * once it is done with them; a producer writes its entries, then publishes
 * its producer index with release.  The receive ring's consumer index moves
 * only when the head datagram is delivered or dropped, so "the kernel
 * reports the ring readable" stays equivalent to "a datagram is still
 * undelivered", and a peek publishes nothing.
 *
 * Every frame is in exactly one place: in the fill ring or with the kernel
 * (XDEV_EXT_FRAME_FILL), or seen at the head of the receive ring and not yet
 * returned (XDEV_EXT_FRAME_RX).  A state that contradicts this cannot come from
 * a correct kernel; the core then sequesters itself and never touches the
 * rings again, and the caller falls back to the socket's own queue.
 */
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>

/* One receive descriptor, laid out as the kernel's ring UAPI defines it. */
struct xdev_ext_rx_desc {
	uint64_t addr;		/* byte offset of the packet in the frame area */
	uint32_t len;
	uint32_t options;	/* continuation flags; never set for this ring */
};

/* A ring the kernel shares with us, as mapped by the receive source. */
struct xdev_ext_rx_ring {
	uint32_t *producer, *consumer, *flags;
	void *descs;		/* struct xdev_ext_rx_desc[] or uint64_t[] (fill) */
	uint32_t mask, size;
};

enum xdev_ext_frame_state { XDEV_EXT_FRAME_FILL = 0, XDEV_EXT_FRAME_RX = 1 };
enum xdev_ext_peek_source { XDEV_EXT_PEEK_NONE, XDEV_EXT_PEEK_RING, XDEV_EXT_PEEK_KERNEL };

/* The flow one ring serves.  Addresses and ports in network byte order. */
struct xdev_ext_flow_tuple {
	in_addr_t dst_addr;
	in_port_t dst_port;
	bool connected;		/* also match the peer below */
	in_addr_t src_addr;
	in_port_t src_port;
	uint8_t dst_mac[6];	/* the interface's own address */
	uint32_t max_frame_len;	/* 0: only the descriptor bound applies */
};

/* Counters in the order the receive REPORT line prints them.  Only atomic
 * accesses touch them, so a report can be taken without the ring lock. */
#define XDEV_EXT_RX_COUNTERS(X)						\
	X(frames_received) X(frames_returned) X(frames_outstanding)	\
	X(double_retire) X(desc_invalid) X(delivered) X(delivered_bytes)	\
	X(dropped_ip_csum) X(dropped_udp_csum) X(dropped_malformed)	\
	X(dropped_not_flow) X(peeked) X(truncated)			\
	X(kernel_path_datagrams) X(waits) X(identity_mismatch)

struct xdev_ext_rx_counters {
#define XDEV_EXT_RX_COUNTER_FIELD(name) uint64_t name;
	XDEV_EXT_RX_COUNTERS(XDEV_EXT_RX_COUNTER_FIELD)
#undef XDEV_EXT_RX_COUNTER_FIELD
};

/* What the receive source hands the core after mapping the rings. */
struct xdev_ext_rx_layout {
	void *umem;			/* nframes * frame_size bytes */
	uint32_t nframes, frame_size;
	uint8_t *frame_state;		/* nframes entries */
	struct xdev_ext_rx_ring rx, fill;
	uint32_t wakeup_flag;		/* bit in *fill.flags asking for a kick */
};

struct xdev_ext_rx_core {
	struct xdev_ext_rx_ring rx, fill;
	uint32_t wakeup_flag;
	uint8_t *umem;
	uint32_t nframes, frame_size;
	uint32_t cons_pub;		/* receive consumer index we published */
	uint32_t cons_seen;		/* cons_pub + 1 once the head is RX */
	uint32_t fill_prod;
	uint8_t *frame_state;
	enum xdev_ext_peek_source peek_source;
	bool drain_pending, kernel_check_due;
	bool sequestered;		/* atomic: read by xdev_ext_rx_core_ready() */
	bool head_csum_ok;		/* UDP checksum of the head verified */
	uint32_t sequester_residue;	/* descriptors left in the ring then */
	struct xdev_ext_rx_desc head;	/* private copy of the validated head */
	struct xdev_ext_flow_tuple tuple;
	struct xdev_ext_rx_counters ctr;
};

enum xdev_ext_rx_status {
	XDEV_EXT_RX_SEQUESTER = -1,	/* impossible ring state: use the socket */
	XDEV_EXT_RX_EMPTY = 0,	/* nothing deliverable left in the ring */
	XDEV_EXT_RX_DELIVERED = 1,
};

enum xdev_ext_rx_verdict {
	XDEV_EXT_RX_FRAME_OK = 0,
	XDEV_EXT_RX_FRAME_MALFORMED,
	XDEV_EXT_RX_FRAME_NOT_FLOW,	/* the kernel stack would have taken it */
	XDEV_EXT_RX_FRAME_IP_CSUM,
};

/* A parsed datagram; pointers into the frame, fields in network order. */
struct xdev_ext_rx_datagram {
	const uint8_t *udp, *payload;
	uint32_t len;		/* payload bytes, after trimming to the UDP length */
	in_addr_t src_addr, dst_addr;
	in_port_t src_port;
	uint16_t udp_csum;	/* 0: the sender sent no checksum */
};

#define XDEV_EXT_RX_ETH_HLEN 14U
#define XDEV_EXT_RX_IP_HLEN 20U
#define XDEV_EXT_RX_UDP_HLEN 8U
#define XDEV_EXT_RX_ETHERTYPE_IPV4 0x0800
/* UIO_MAXIOV: the kernel fails a longer vector with EMSGSIZE. */
#define XDEV_EXT_RX_MAX_IOV 1024U
#define XDEV_EXT_RX_SUPPORTED_FLAGS (MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC | \
				MSG_WAITALL | MSG_CMSG_CLOEXEC | MSG_NOSIGNAL)
/* One look at the socket's own queue per this many ring deliveries. */
#define XDEV_EXT_RX_KERNEL_CHECK_EVERY 64U

static inline uint32_t xdev_ext_rx_load_acquire(const uint32_t *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void xdev_ext_rx_store_release(uint32_t *p, uint32_t v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static inline void xdev_ext_rx_ctr_add(uint64_t *counter, uint64_t v)
{
	__atomic_fetch_add(counter, v, __ATOMIC_RELAXED);
}

static inline bool xdev_ext_rx_flags_supported(int flags)
{
	return !(flags & ~XDEV_EXT_RX_SUPPORTED_FLAGS);
}

/* Shapes the kernel rejects before reading the queue are left to libc, so
 * the caller sees the kernel's own errno. */
static inline bool xdev_ext_rx_msg_shape_ok(const struct msghdr *msg)
{
	if (msg->msg_name && (int)msg->msg_namelen < 0)
		return false;
	if (msg->msg_iovlen > XDEV_EXT_RX_MAX_IOV ||
	    (msg->msg_iovlen && !msg->msg_iov))
		return false;
	for (size_t i = 0; i < msg->msg_iovlen; i++)
		if ((ssize_t)msg->msg_iov[i].iov_len < 0)
			return false;
	return true;
}

/* ---- Internet checksum (RFC 1071) ---------------------------------- */

static inline uint32_t xdev_ext_rx_csum_fold(uint64_t sum)
{
	sum = (sum & 0xffffffffULL) + (sum >> 32);
	sum = (sum & 0xffffffffULL) + (sum >> 32);
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (uint32_t)sum;
}

/* Sum len bytes in host order as if they started at an even offset, and
 * copy them to dst on the way when dst is set. */
static inline uint32_t xdev_ext_rx_csum_block(uint8_t *dst, const uint8_t *src,
					 size_t len)
{
	uint64_t sum = 0;
	size_t i = 0;

	for (; i + 8 <= len; i += 8) {
		uint64_t v;

		memcpy(&v, src + i, sizeof(v));
		if (dst)
			memcpy(dst + i, &v, sizeof(v));
		sum += (v & 0xffffffffULL) + (v >> 32);
	}
	for (; i + 2 <= len; i += 2) {
		uint16_t w;

		memcpy(&w, src + i, sizeof(w));
		if (dst)
			memcpy(dst + i, &w, sizeof(w));
		sum += w;
	}
	if (i < len) {
		uint16_t w = 0;

		memcpy(&w, src + i, 1);
		if (dst)
			dst[i] = src[i];
		sum += w;
	}
	return xdev_ext_rx_csum_fold(sum);
}

struct xdev_ext_rx_csum {
	uint64_t sum;
	size_t len;
};

static inline void xdev_ext_rx_csum_add(struct xdev_ext_rx_csum *cs, uint8_t *dst,
				   const uint8_t *src, size_t len)
{
	uint32_t part = xdev_ext_rx_csum_block(dst, src, len);

	/* A block that starts at an odd offset sums byte-swapped. */
	if (cs->len & 1)
		part = ((part & 0xff) << 8) | (part >> 8);
	cs->sum += part;
	cs->len += len;
}

/* Pseudo-header and UDP header; the payload follows at an even offset. */
static inline void xdev_ext_rx_csum_start(struct xdev_ext_rx_csum *cs,
				     const struct xdev_ext_rx_datagram *dg)
{
	uint16_t udp_len = htons((uint16_t)(dg->len + XDEV_EXT_RX_UDP_HLEN));
	uint8_t pseudo[12];

	memcpy(pseudo, &dg->src_addr, 4);
	memcpy(pseudo + 4, &dg->dst_addr, 4);
	pseudo[8] = 0;
	pseudo[9] = IPPROTO_UDP;
	memcpy(pseudo + 10, &udp_len, 2);
	cs->sum = 0;
	cs->len = 0;
	xdev_ext_rx_csum_add(cs, NULL, pseudo, sizeof(pseudo));
	xdev_ext_rx_csum_add(cs, NULL, dg->udp, XDEV_EXT_RX_UDP_HLEN);
}

static inline bool xdev_ext_rx_csum_valid(const struct xdev_ext_rx_csum *cs)
{
	return xdev_ext_rx_csum_fold(cs->sum) == 0xffff;
}

static inline bool xdev_ext_rx_udp_csum_ok(const struct xdev_ext_rx_datagram *dg)
{
	struct xdev_ext_rx_csum cs;

	if (!dg->udp_csum)
		return true;
	xdev_ext_rx_csum_start(&cs, dg);
	xdev_ext_rx_csum_add(&cs, NULL, dg->payload, dg->len);
	return xdev_ext_rx_csum_valid(&cs);
}

/* ---- Frame parsing ------------------------------------------------- */

static inline uint16_t xdev_ext_rx_get16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

/*
 * Ethernet + IPv4 + UDP, judged the way ip_rcv_core() and __udp4_lib_rcv()
 * would, plus the flow match the redirect program already made.  Anything
 * the kernel stack would have taken (other protocols, IP options,
 * fragments, another flow) is NOT_FLOW; anything it would have dropped as
 * bad is MALFORMED or IP_CSUM.  The UDP checksum is checked while copying.
 */
static inline int xdev_ext_rx_parse_frame(const struct xdev_ext_flow_tuple *t,
				     const uint8_t *frame, uint32_t len,
				     struct xdev_ext_rx_datagram *dg)
{
	const uint8_t *ip = frame + XDEV_EXT_RX_ETH_HLEN;
	const uint8_t *udp = ip + XDEV_EXT_RX_IP_HLEN;
	in_addr_t saddr, daddr;
	in_port_t sport, dport;
	uint32_t ip_len, udp_len;

	if (len < XDEV_EXT_RX_ETH_HLEN)
		return XDEV_EXT_RX_FRAME_MALFORMED;
	if (memcmp(frame, t->dst_mac, sizeof(t->dst_mac)) ||
	    xdev_ext_rx_get16(frame + 12) != XDEV_EXT_RX_ETHERTYPE_IPV4 ||
	    (t->max_frame_len && len > t->max_frame_len))
		return XDEV_EXT_RX_FRAME_NOT_FLOW;
	if (len < XDEV_EXT_RX_ETH_HLEN + XDEV_EXT_RX_IP_HLEN ||
	    (ip[0] >> 4) != 4 || (ip[0] & 0xf) < 5)
		return XDEV_EXT_RX_FRAME_MALFORMED;
	if ((ip[0] & 0xf) != 5)
		return XDEV_EXT_RX_FRAME_NOT_FLOW;
	if (xdev_ext_rx_csum_block(NULL, ip, XDEV_EXT_RX_IP_HLEN) != 0xffff)
		return XDEV_EXT_RX_FRAME_IP_CSUM;
	ip_len = xdev_ext_rx_get16(ip + 2);
	if (ip_len > len - XDEV_EXT_RX_ETH_HLEN ||
	    ip_len < XDEV_EXT_RX_IP_HLEN + XDEV_EXT_RX_UDP_HLEN)
		return XDEV_EXT_RX_FRAME_MALFORMED;
	/* More-fragments or a fragment offset: the stack reassembles. */
	if ((xdev_ext_rx_get16(ip + 6) & 0x3fff) || ip[9] != IPPROTO_UDP)
		return XDEV_EXT_RX_FRAME_NOT_FLOW;
	memcpy(&saddr, ip + 12, sizeof(saddr));
	memcpy(&daddr, ip + 16, sizeof(daddr));
	memcpy(&sport, udp, sizeof(sport));
	memcpy(&dport, udp + 2, sizeof(dport));
	if (daddr != t->dst_addr || dport != t->dst_port ||
	    (t->connected && (saddr != t->src_addr || sport != t->src_port)))
		return XDEV_EXT_RX_FRAME_NOT_FLOW;
	/* Longer than the IP payload or shorter than its own header is a
	 * short packet; shorter than the IP payload is trimmed to it. */
	udp_len = xdev_ext_rx_get16(udp + 4);
	if (udp_len < XDEV_EXT_RX_UDP_HLEN || udp_len > ip_len - XDEV_EXT_RX_IP_HLEN)
		return XDEV_EXT_RX_FRAME_MALFORMED;

	dg->udp = udp;
	dg->payload = udp + XDEV_EXT_RX_UDP_HLEN;
	dg->len = udp_len - XDEV_EXT_RX_UDP_HLEN;
	dg->src_addr = saddr;
	dg->dst_addr = daddr;
	dg->src_port = sport;
	memcpy(&dg->udp_csum, udp + 6, sizeof(dg->udp_csum));
	return XDEV_EXT_RX_FRAME_OK;
}

/* ---- Copy out ------------------------------------------------------ */

static inline size_t xdev_ext_rx_iov_capacity(const struct msghdr *msg)
{
	size_t cap = 0;

	for (size_t i = 0; i < msg->msg_iovlen; i++) {
		if (msg->msg_iov[i].iov_len > SIZE_MAX - cap)
			return SIZE_MAX;
		cap += msg->msg_iov[i].iov_len;
	}
	return cap;
}

/* Scatter len bytes over the iovecs, summing them when cs is set. */
static inline void xdev_ext_rx_copy_to_iov(const struct msghdr *msg,
				      const uint8_t *src, size_t len,
				      struct xdev_ext_rx_csum *cs)
{
	for (size_t i = 0; len && i < msg->msg_iovlen; i++) {
		size_t n = msg->msg_iov[i].iov_len;

		if (n > len)
			n = len;
		if (!n)
			continue;
		if (cs)
			xdev_ext_rx_csum_add(cs, msg->msg_iov[i].iov_base, src, n);
		else
			memcpy(msg->msg_iov[i].iov_base, src, n);
		src += n;
		len -= n;
	}
}

/* As udp_recvmsg() and move_addr_to_user(): copy at most the caller's
 * length, report the full one; leave the length alone without a buffer. */
static inline void xdev_ext_rx_fill_name(struct msghdr *msg,
				    const struct xdev_ext_rx_datagram *dg)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_port = dg->src_port,
		.sin_addr.s_addr = dg->src_addr,
	};
	size_t n = sizeof(sin);

	if (!msg->msg_name)
		return;
	if (msg->msg_namelen < n)
		n = msg->msg_namelen;
	memcpy(msg->msg_name, &sin, n);
	msg->msg_namelen = sizeof(sin);
}

/* ---- Ring cursor and frame states ---------------------------------- */

static inline bool xdev_ext_rx_ring_ok(const struct xdev_ext_rx_ring *r)
{
	return r->producer && r->consumer && r->flags && r->descs &&
	       r->size && !(r->size & (r->size - 1)) && r->mask == r->size - 1;
}

static inline int xdev_ext_rx_core_init(struct xdev_ext_rx_core *c,
				   const struct xdev_ext_rx_layout *l,
				   const struct xdev_ext_flow_tuple *tuple)
{
	/* The fill ring must hold every frame so returning one never fails. */
	if (!l->umem || !l->frame_state || !l->nframes || !l->frame_size ||
	    !l->wakeup_flag || !xdev_ext_rx_ring_ok(&l->rx) ||
	    !xdev_ext_rx_ring_ok(&l->fill) || l->fill.size < l->nframes ||
	    (uint64_t)l->nframes * l->frame_size > SIZE_MAX)
		return -EINVAL;

	memset(c, 0, sizeof(*c));
	c->rx = l->rx;
	c->fill = l->fill;
	c->wakeup_flag = l->wakeup_flag;
	c->umem = l->umem;
	c->nframes = l->nframes;
	c->frame_size = l->frame_size;
	c->frame_state = l->frame_state;
	c->cons_pub = xdev_ext_rx_load_acquire(c->rx.consumer);
	c->cons_seen = c->cons_pub;
	c->fill_prod = xdev_ext_rx_load_acquire(c->fill.producer);
	c->peek_source = XDEV_EXT_PEEK_NONE;
	c->tuple = *tuple;
	return 0;
}

static inline bool xdev_ext_rx_fill_wants_kick(const struct xdev_ext_rx_core *c)
{
	return __atomic_load_n(c->fill.flags, __ATOMIC_RELAXED) &
	       c->wakeup_flag;
}

/* Hand every frame to the kernel once, before the socket is bound. */
static inline int xdev_ext_rx_core_fill_all(struct xdev_ext_rx_core *c, bool *wake)
{
	uint32_t queued = c->fill_prod - xdev_ext_rx_load_acquire(c->fill.consumer);
	uint64_t *ring = c->fill.descs;

	*wake = false;
	if (queued > c->fill.size || c->fill.size - queued < c->nframes)
		return -ENOSPC;
	for (uint32_t i = 0; i < c->nframes; i++) {
		c->frame_state[i] = XDEV_EXT_FRAME_FILL;
		ring[(c->fill_prod + i) & c->fill.mask] =
			(uint64_t)i * c->frame_size;
	}
	c->fill_prod += c->nframes;
	xdev_ext_rx_store_release(c->fill.producer, c->fill_prod);
	*wake = xdev_ext_rx_fill_wants_kick(c);
	return 0;
}

static inline bool xdev_ext_rx_core_is_sequestered(const struct xdev_ext_rx_core *c)
{
	return __atomic_load_n(&c->sequestered, __ATOMIC_ACQUIRE);
}

/* Stop touching the rings for good.  What is left in the receive ring is
 * counted here, by the last read of the producer index. */
static inline void xdev_ext_rx_core_sequester(struct xdev_ext_rx_core *c)
{
	if (xdev_ext_rx_core_is_sequestered(c))
		return;
	c->sequester_residue = xdev_ext_rx_load_acquire(c->rx.producer) -
			       c->cons_pub;
	__atomic_store_n(&c->sequestered, true, __ATOMIC_RELEASE);
}

static inline int xdev_ext_rx_core_fault(struct xdev_ext_rx_core *c, uint64_t *counter)
{
	xdev_ext_rx_ctr_add(counter, 1);
	xdev_ext_rx_core_sequester(c);
	return XDEV_EXT_RX_SEQUESTER;
}

/* Lock-free: the kernel's own readability test on the published indices. */
static inline bool xdev_ext_rx_core_ready(const struct xdev_ext_rx_core *c)
{
	return !xdev_ext_rx_core_is_sequestered(c) &&
	       xdev_ext_rx_load_acquire(c->rx.consumer) !=
	       xdev_ext_rx_load_acquire(c->rx.producer);
}

static inline uint32_t xdev_ext_rx_core_pending(const struct xdev_ext_rx_core *c)
{
	if (xdev_ext_rx_core_is_sequestered(c))
		return 0;
	return xdev_ext_rx_load_acquire(c->rx.producer) - c->cons_pub;
}

static inline uint32_t xdev_ext_rx_frame_of(const struct xdev_ext_rx_core *c,
				       uint64_t addr)
{
	return (uint32_t)(addr / c->frame_size);
}

/* Make the oldest undelivered descriptor the head: validate it and move
 * its frame FILL -> RX the first time it is seen.  Returns 1 with a head,
 * or XDEV_EXT_RX_EMPTY / XDEV_EXT_RX_SEQUESTER. */
static inline int xdev_ext_rx_core_take_head(struct xdev_ext_rx_core *c)
{
	uint64_t area = (uint64_t)c->nframes * c->frame_size;
	struct xdev_ext_rx_desc d;
	uint32_t prod, frame;

	if (xdev_ext_rx_core_is_sequestered(c))
		return XDEV_EXT_RX_SEQUESTER;
	if (c->cons_seen != c->cons_pub) {
		/* Seen by an earlier peek: the frame must still be ours. */
		if (c->frame_state[xdev_ext_rx_frame_of(c, c->head.addr)] !=
		    XDEV_EXT_FRAME_RX)
			return xdev_ext_rx_core_fault(c, &c->ctr.double_retire);
		return 1;
	}
	prod = xdev_ext_rx_load_acquire(c->rx.producer);
	if (prod == c->cons_pub)
		return XDEV_EXT_RX_EMPTY;
	if (prod - c->cons_pub > c->rx.size)
		return xdev_ext_rx_core_fault(c, &c->ctr.desc_invalid);
	memcpy(&d, (const struct xdev_ext_rx_desc *)c->rx.descs +
	       (c->cons_pub & c->rx.mask), sizeof(d));
	if (d.options || d.addr >= area ||
	    d.len > c->frame_size - d.addr % c->frame_size)
		return xdev_ext_rx_core_fault(c, &c->ctr.desc_invalid);
	frame = xdev_ext_rx_frame_of(c, d.addr);
	if (c->frame_state[frame] != XDEV_EXT_FRAME_FILL)
		return xdev_ext_rx_core_fault(c, &c->ctr.desc_invalid);
	c->frame_state[frame] = XDEV_EXT_FRAME_RX;
	c->head = d;
	c->head_csum_ok = false;
	c->cons_seen = c->cons_pub + 1;
	xdev_ext_rx_ctr_add(&c->ctr.frames_received, 1);
	xdev_ext_rx_ctr_add(&c->ctr.frames_outstanding, 1);
	return 1;
}

/* Deliver or drop the head: frame back to the fill ring, then one consumer
 * step.  Counts the outcome in *reason. */
static inline int xdev_ext_rx_core_retire(struct xdev_ext_rx_core *c, uint64_t *reason,
				     bool *wake)
{
	uint32_t frame = xdev_ext_rx_frame_of(c, c->head.addr);
	uint64_t *fill = c->fill.descs;

	if (c->cons_seen == c->cons_pub ||
	    c->frame_state[frame] != XDEV_EXT_FRAME_RX)
		return xdev_ext_rx_core_fault(c, &c->ctr.double_retire);
	/* The fill ring has room for every frame; full means it is broken. */
	if (c->fill_prod - xdev_ext_rx_load_acquire(c->fill.consumer) >=
	    c->fill.size)
		return xdev_ext_rx_core_fault(c, &c->ctr.desc_invalid);

	fill[c->fill_prod & c->fill.mask] = (uint64_t)frame * c->frame_size;
	xdev_ext_rx_store_release(c->fill.producer, ++c->fill_prod);
	c->frame_state[frame] = XDEV_EXT_FRAME_FILL;
	xdev_ext_rx_store_release(c->rx.consumer, ++c->cons_pub);
	xdev_ext_rx_ctr_add(&c->ctr.frames_returned, 1);
	__atomic_fetch_sub(&c->ctr.frames_outstanding, 1, __ATOMIC_RELAXED);
	xdev_ext_rx_ctr_add(reason, 1);
	if (xdev_ext_rx_fill_wants_kick(c))
		*wake = true;
	return 0;
}

/* The head as a datagram of this flow, dropping every frame ahead of it
 * that fails validation. */
static inline int xdev_ext_rx_core_head(struct xdev_ext_rx_core *c,
				   struct xdev_ext_rx_datagram *dg, bool *wake)
{
	for (;;) {
		int st = xdev_ext_rx_core_take_head(c);
		uint64_t *reason;

		if (st != 1)
			return st;
		switch (xdev_ext_rx_parse_frame(&c->tuple, c->umem + c->head.addr,
					   c->head.len, dg)) {
		case XDEV_EXT_RX_FRAME_OK:
			return XDEV_EXT_RX_DELIVERED;
		case XDEV_EXT_RX_FRAME_IP_CSUM:
			reason = &c->ctr.dropped_ip_csum;
			break;
		case XDEV_EXT_RX_FRAME_NOT_FLOW:
			reason = &c->ctr.dropped_not_flow;
			break;
		default:
			reason = &c->ctr.dropped_malformed;
			break;
		}
		if (xdev_ext_rx_core_retire(c, reason, wake))
			return XDEV_EXT_RX_SEQUESTER;
	}
}

/*
 * One recvmsg() served from the ring, with udp_recvmsg() semantics: copy
 * min(buffer, datagram), MSG_TRUNC in msg_flags when cut, the full length
 * returned for the MSG_TRUNC flag, the source in msg_name, no control
 * data.  MSG_PEEK copies and publishes nothing.  A bad UDP checksum drops
 * the datagram and goes on with the next one; it is verified before the
 * copy when the copy is partial or a peek, and while copying otherwise.
 * *wake asks the caller to kick the fill ring.  The caller has already
 * checked xdev_ext_rx_flags_supported() and xdev_ext_rx_msg_shape_ok().
 */
static inline int xdev_ext_rx_core_recv(struct xdev_ext_rx_core *c, struct msghdr *msg,
				   int flags, ssize_t *result, bool *wake)
{
	bool peek = flags & MSG_PEEK;

	*wake = false;
	for (;;) {
		struct xdev_ext_rx_datagram dg;
		size_t cap, copied;
		bool truncated;
		int st = xdev_ext_rx_core_head(c, &dg, wake);

		if (st != XDEV_EXT_RX_DELIVERED)
			return st;
		cap = xdev_ext_rx_iov_capacity(msg);
		copied = cap < dg.len ? cap : dg.len;
		truncated = copied < dg.len;
		if (dg.udp_csum && !c->head_csum_ok && (truncated || peek)) {
			if (!xdev_ext_rx_udp_csum_ok(&dg)) {
				if (xdev_ext_rx_core_retire(c,
						&c->ctr.dropped_udp_csum, wake))
					return XDEV_EXT_RX_SEQUESTER;
				continue;
			}
			c->head_csum_ok = true;
		}
		if (dg.udp_csum && !c->head_csum_ok) {
			struct xdev_ext_rx_csum cs;

			xdev_ext_rx_csum_start(&cs, &dg);
			xdev_ext_rx_copy_to_iov(msg, dg.payload, copied, &cs);
			if (!xdev_ext_rx_csum_valid(&cs)) {
				if (xdev_ext_rx_core_retire(c,
						&c->ctr.dropped_udp_csum, wake))
					return XDEV_EXT_RX_SEQUESTER;
				continue;
			}
		} else {
			xdev_ext_rx_copy_to_iov(msg, dg.payload, copied, NULL);
		}
		xdev_ext_rx_fill_name(msg, &dg);
		msg->msg_controllen = 0;
		/* ____sys_recvmsg() starts msg_flags from MSG_CMSG_CLOEXEC. */
		msg->msg_flags = (flags & MSG_CMSG_CLOEXEC) |
				 (truncated ? MSG_TRUNC : 0);
		*result = (flags & MSG_TRUNC) ? (ssize_t)dg.len :
						(ssize_t)copied;
		if (peek) {
			xdev_ext_rx_ctr_add(&c->ctr.peeked, 1);
			c->peek_source = XDEV_EXT_PEEK_RING;
			return XDEV_EXT_RX_DELIVERED;
		}
		if (xdev_ext_rx_core_retire(c, &c->ctr.delivered, wake))
			return XDEV_EXT_RX_SEQUESTER;
		xdev_ext_rx_ctr_add(&c->ctr.delivered_bytes, copied);
		if (truncated)
			xdev_ext_rx_ctr_add(&c->ctr.truncated, 1);
		c->peek_source = XDEV_EXT_PEEK_NONE;
		if (!(__atomic_load_n(&c->ctr.delivered, __ATOMIC_RELAXED) %
		      XDEV_EXT_RX_KERNEL_CHECK_EVERY))
			c->kernel_check_due = true;
		return XDEV_EXT_RX_DELIVERED;
	}
}

/* Length of the next deliverable datagram, for FIONREAD/SIOCINQ.  Bad
 * frames ahead of it are dropped as a read would; nothing is consumed. */
static inline int xdev_ext_rx_core_next_len(struct xdev_ext_rx_core *c, uint32_t *len,
				       bool *wake)
{
	*wake = false;
	for (;;) {
		struct xdev_ext_rx_datagram dg;
		int st = xdev_ext_rx_core_head(c, &dg, wake);

		if (st != XDEV_EXT_RX_DELIVERED)
			return st;
		if (dg.udp_csum && !c->head_csum_ok) {
			if (!xdev_ext_rx_udp_csum_ok(&dg)) {
				if (xdev_ext_rx_core_retire(c,
						&c->ctr.dropped_udp_csum, wake))
					return XDEV_EXT_RX_SEQUESTER;
				continue;
			}
			c->head_csum_ok = true;
		}
		*len = dg.len;
		return XDEV_EXT_RX_DELIVERED;
	}
}

/* ---- The socket's own queue ---------------------------------------- */

/* Read the socket's own queue before the ring: right after activation, at
 * the periodic check, and after a peek that came from that queue.  A peek
 * from the ring pins the next read to the ring. */
static inline bool xdev_ext_rx_core_kernel_first(const struct xdev_ext_rx_core *c)
{
	if (c->peek_source == XDEV_EXT_PEEK_RING)
		return false;
	return c->peek_source == XDEV_EXT_PEEK_KERNEL || c->drain_pending ||
	       c->kernel_check_due;
}

/* Account for one MSG_DONTWAIT read of the socket's own queue that
 * returned n (errno err).  True: return it to the application.  False: the
 * queue is empty, go on with the ring. */
static inline bool xdev_ext_rx_core_kernel_done(struct xdev_ext_rx_core *c, ssize_t n,
					   int err, int flags)
{
	if (n >= 0 || (err != EAGAIN && err != EWOULDBLOCK)) {
		if (n >= 0 && !(flags & MSG_PEEK))
			xdev_ext_rx_ctr_add(&c->ctr.kernel_path_datagrams, 1);
		c->peek_source = (flags & MSG_PEEK) ? XDEV_EXT_PEEK_KERNEL :
						      XDEV_EXT_PEEK_NONE;
		return true;
	}
	c->drain_pending = false;
	c->kernel_check_due = false;
	if (c->peek_source == XDEV_EXT_PEEK_KERNEL)
		c->peek_source = XDEV_EXT_PEEK_NONE;
	return false;
}

/* ---- Counters ------------------------------------------------------ */

static inline void xdev_ext_rx_counters_snapshot(const struct xdev_ext_rx_counters *src,
					    struct xdev_ext_rx_counters *dst)
{
#define XDEV_EXT_RX_COUNTER_LOAD(name) \
	dst->name = __atomic_load_n(&src->name, __ATOMIC_RELAXED);
	XDEV_EXT_RX_COUNTERS(XDEV_EXT_RX_COUNTER_LOAD)
#undef XDEV_EXT_RX_COUNTER_LOAD
}

/* Every frame seen is delivered, dropped once, or still outstanding. */
static inline bool xdev_ext_rx_counters_balanced(const struct xdev_ext_rx_counters *s)
{
	return s->frames_received ==
		       s->delivered + s->dropped_ip_csum + s->dropped_udp_csum +
		       s->dropped_malformed + s->dropped_not_flow +
		       s->frames_outstanding &&
	       s->frames_returned == s->frames_received - s->frames_outstanding;
}

/* ---- poll folding -------------------------------------------------- */

#define XDEV_EXT_RX_POLL_READ (POLLIN | POLLRDNORM)

/*
 * group[i] names the registration fds[i] refers to (0..n-1), or -1.  Give
 * a group only to entries of taken-over sockets; several entries may share
 * one.  ext holds nfds + nwait entries: the caller's, then one POLLIN entry
 * per registration's wait fd.
 */
static inline void xdev_ext_rx_poll_extend(struct pollfd *ext,
				      const struct pollfd *fds, nfds_t nfds,
				      const int *wait_fds, unsigned int nwait)
{
	if (nfds)
		memcpy(ext, fds, nfds * sizeof(*fds));
	for (unsigned int k = 0; k < nwait; k++)
		ext[nfds + k] = (struct pollfd) {
			.fd = wait_fds[k], .events = POLLIN,
		};
}

static inline int xdev_ext_rx_poll_count(const struct pollfd *fds, nfds_t nfds)
{
	int n = 0;

	for (nfds_t i = 0; i < nfds; i++)
		n += fds[i].revents != 0;
	return n;
}

/* Readable, on the read bits the entry asked for; POLLNVAL stays alone. */
static inline void xdev_ext_rx_poll_or_read(struct pollfd *p)
{
	if (p->fd >= 0 && !(p->revents & POLLNVAL))
		p->revents |= p->events & XDEV_EXT_RX_POLL_READ;
}

/* Fold the real poll over ext back into fds; returns the count poll()
 * returns.  0 with a positive real result means only wait entries fired
 * with nothing to report: poll again with the time left. */
static inline int xdev_ext_rx_poll_fold(struct pollfd *fds, nfds_t nfds,
				   const struct pollfd *ext, const int *group,
				   unsigned int nwait)
{
	for (nfds_t i = 0; i < nfds; i++) {
		int g = group[i];

		fds[i].revents = ext[i].revents;
		if (g >= 0 && (unsigned int)g < nwait &&
		    (ext[nfds + g].revents & POLLIN))
			xdev_ext_rx_poll_or_read(&fds[i]);
	}
	return xdev_ext_rx_poll_count(fds, nfds);
}

/* After a zero-timeout real poll on fds: mark entries of registrations the
 * ring already has data for, and recount. */
static inline int xdev_ext_rx_poll_mark_ready(struct pollfd *fds, nfds_t nfds,
					 const int *group, const bool *ready,
					 unsigned int ngroups)
{
	for (nfds_t i = 0; i < nfds; i++) {
		int g = group[i];

		if (g >= 0 && (unsigned int)g < ngroups && ready[g])
			xdev_ext_rx_poll_or_read(&fds[i]);
	}
	return xdev_ext_rx_poll_count(fds, nfds);
}

/* ---- select <-> poll ----------------------------------------------- */

/* fs/select.c: what each set asks for, and which poll bits satisfy it
 * (POLLIN_SET, POLLOUT_SET, POLLEX_SET). */
#define XDEV_EXT_RX_SELECT_IN (POLLIN | POLLRDNORM | POLLRDBAND)
#define XDEV_EXT_RX_SELECT_OUT (POLLOUT | POLLWRNORM | POLLWRBAND)
#define XDEV_EXT_RX_SELECT_EX POLLPRI
#define XDEV_EXT_RX_SELECT_IN_SET (XDEV_EXT_RX_SELECT_IN | POLLHUP | POLLERR)
#define XDEV_EXT_RX_SELECT_OUT_SET (XDEV_EXT_RX_SELECT_OUT | POLLERR)
#define XDEV_EXT_RX_SELECT_EX_SET POLLPRI
#define XDEV_EXT_RX_FD_WORD_BITS (8 * (int)sizeof(unsigned long))

/* Sets are reached as words, like the kernel does, so a caller-sized set
 * beyond FD_SETSIZE works and FD_ISSET's bound check never fires. */
static inline bool xdev_ext_rx_fd_isset(const fd_set *set, int fd)
{
	const unsigned long *w = (const unsigned long *)(const void *)set;

	return set && ((w[fd / XDEV_EXT_RX_FD_WORD_BITS] >>
			(fd % XDEV_EXT_RX_FD_WORD_BITS)) & 1);
}

static inline void xdev_ext_rx_fd_setbit(fd_set *set, int fd)
{
	unsigned long *w = (unsigned long *)(void *)set;

	w[fd / XDEV_EXT_RX_FD_WORD_BITS] |= 1UL << (fd % XDEV_EXT_RX_FD_WORD_BITS);
}

/* The kernel writes back whole words, clearing bits past nfds too. */
static inline void xdev_ext_rx_fd_zero(fd_set *set, int nfds)
{
	if (set && nfds > 0)
		memset(set, 0, (size_t)((nfds + XDEV_EXT_RX_FD_WORD_BITS - 1) /
					XDEV_EXT_RX_FD_WORD_BITS) *
			       sizeof(unsigned long));
}

/* One pollfd per descriptor below nfds that is in any set, in fd order.
 * With out == NULL only counts.  -EINVAL for nfds < 0, -ENOMEM past cap. */
static inline int xdev_ext_rx_select_to_poll(int nfds, const fd_set *rd,
					const fd_set *wr, const fd_set *ex,
					struct pollfd *out, unsigned int cap)
{
	unsigned int n = 0;

	if (nfds < 0)
		return -EINVAL;
	for (int fd = 0; fd < nfds; fd++) {
		short events = 0;

		if (xdev_ext_rx_fd_isset(rd, fd))
			events |= XDEV_EXT_RX_SELECT_IN;
		if (xdev_ext_rx_fd_isset(wr, fd))
			events |= XDEV_EXT_RX_SELECT_OUT;
		if (xdev_ext_rx_fd_isset(ex, fd))
			events |= XDEV_EXT_RX_SELECT_EX;
		if (!events)
			continue;
		if (out) {
			if (n >= cap)
				return -ENOMEM;
			out[n] = (struct pollfd) { .fd = fd, .events = events };
		}
		n++;
	}
	return (int)n;
}

/* Rewrite the sets from a finished poll; returns select()'s count (an fd
 * ready for reading and writing counts twice).  Any POLLNVAL is -EBADF
 * with the sets untouched.  0 while the poll returned more means no event
 * the sets can show (a hangup on a write-only fd): poll again. */
static inline int xdev_ext_rx_poll_to_select(const struct pollfd *p, unsigned int n,
					int nfds, fd_set *rd, fd_set *wr,
					fd_set *ex)
{
	int count = 0;

	for (unsigned int i = 0; i < n; i++)
		if (p[i].revents & POLLNVAL)
			return -EBADF;
	xdev_ext_rx_fd_zero(rd, nfds);
	xdev_ext_rx_fd_zero(wr, nfds);
	xdev_ext_rx_fd_zero(ex, nfds);
	for (unsigned int i = 0; i < n; i++) {
		short ev = p[i].events, re = p[i].revents;

		if (rd && (ev & POLLIN) && (re & XDEV_EXT_RX_SELECT_IN_SET)) {
			xdev_ext_rx_fd_setbit(rd, p[i].fd);
			count++;
		}
		if (wr && (ev & POLLOUT) && (re & XDEV_EXT_RX_SELECT_OUT_SET)) {
			xdev_ext_rx_fd_setbit(wr, p[i].fd);
			count++;
		}
		if (ex && (ev & POLLPRI) && (re & XDEV_EXT_RX_SELECT_EX_SET)) {
			xdev_ext_rx_fd_setbit(ex, p[i].fd);
			count++;
		}
	}
	return count;
}

/* ---- Timeouts ------------------------------------------------------ */

#define XDEV_EXT_RX_NSEC_PER_SEC 1000000000L
#define XDEV_EXT_RX_TIME_MAX \
	((time_t)((1ULL << (sizeof(time_t) * CHAR_BIT - 1)) - 1))

/* select()'s timeval as kern_select() normalises it; -EINVAL if negative. */
static inline int xdev_ext_rx_select_timeout(const struct timeval *tv,
					struct timespec *ts)
{
	long long nsec = (long long)(tv->tv_usec % 1000000) * 1000;
	long long sec;

	if (__builtin_add_overflow((long long)tv->tv_sec,
				   (long long)(tv->tv_usec / 1000000), &sec) ||
	    sec < 0 || nsec < 0)
		return -EINVAL;
	ts->tv_sec = (time_t)sec;
	ts->tv_nsec = (long)nsec;
	return 0;
}

/* now + timeout, saturating like timespec64_add_safe(). */
static inline void xdev_ext_rx_deadline(const struct timespec *now,
				   const struct timespec *timeout,
				   struct timespec *deadline)
{
	long nsec = now->tv_nsec + timeout->tv_nsec;
	time_t sec;

	if (__builtin_add_overflow(now->tv_sec, timeout->tv_sec, &sec))
		goto saturate;
	if (nsec >= XDEV_EXT_RX_NSEC_PER_SEC) {
		nsec -= XDEV_EXT_RX_NSEC_PER_SEC;
		if (__builtin_add_overflow(sec, 1, &sec))
			goto saturate;
	}
	deadline->tv_sec = sec;
	deadline->tv_nsec = nsec;
	return;
saturate:
	deadline->tv_sec = XDEV_EXT_RX_TIME_MAX;
	deadline->tv_nsec = 0;
}

static inline void xdev_ext_rx_time_left(const struct timespec *deadline,
				    const struct timespec *now,
				    struct timespec *left)
{
	long nsec = deadline->tv_nsec - now->tv_nsec;
	time_t sec;

	if (__builtin_sub_overflow(deadline->tv_sec, now->tv_sec, &sec))
		sec = now->tv_sec > 0 ? -1 : XDEV_EXT_RX_TIME_MAX;
	if (nsec < 0) {
		nsec += XDEV_EXT_RX_NSEC_PER_SEC;
		sec--;
	}
	if (sec < 0) {
		sec = 0;
		nsec = 0;
	}
	left->tv_sec = sec;
	left->tv_nsec = nsec;
}

/* What select() writes back into its timeval (poll_select_finish()):
 * the time left, rounded down to microseconds, never for a zero timeout. */
static inline bool xdev_ext_rx_select_remaining(const struct timespec *timeout,
					   const struct timespec *deadline,
					   const struct timespec *now,
					   struct timeval *out)
{
	struct timespec left;

	if (!timeout->tv_sec && !timeout->tv_nsec)
		return false;
	xdev_ext_rx_time_left(deadline, now, &left);
	out->tv_sec = left.tv_sec;
	out->tv_usec = left.tv_nsec / 1000;
	return true;
}

#endif /* XDEV_EXT_PRELOAD_RX_CORE_H */
