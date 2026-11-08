/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EVAL_DPDK_TB_WIRE_H
#define XDEV_EVAL_DPDK_TB_WIRE_H

/*
 * Pure logic of the DPDK net_af_xdp baseline (dpdk_tb.c), kept free of DPDK
 * and CUDA so test_wire.c can check it on any host.
 *
 * Frame: Ethernet header (14 bytes, EtherType TB_ETHERTYPE) followed by a
 * 32-byte tb_hdr (little-endian) and up to tb_frag_payload(mtu) payload
 * bytes, so every frame fits the port MTU.  A message of msg_len bytes is
 * cut into tb_frag_count() frames carrying consecutive per-direction
 * sequence numbers.  The link is one queue in each direction and the
 * protocol does not retransmit: the receiver accepts frames strictly in
 * order and reports any gap, duplicate or inconsistent frame as an error,
 * which ends the run.  A sender keeps at most window_frames frames
 * unacknowledged; the receiver returns a cumulative ACK every ack_every
 * frames and, when the last frame asks for it (TB_F_ACKREQ), once the
 * message is in GPU memory.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TB_ETHERTYPE 0x88B5u /* IEEE 802 Local Experimental EtherType 1 */
#define TB_ETH_HLEN 14
#define TB_HDR_LEN 32
#define TB_MAGIC 0x31425458u /* "XTB1" on the wire */
#define TB_MAX_SIZES 64
#define TB_SIZE_LIMIT (64u << 20)
/* The af_xdp PMD's RX and fill rings hold 2048 descriptors (24.11). */
#define TB_MAX_WINDOW 2048u

enum tb_type { TB_HELLO = 1, TB_HELLO_ACK = 2, TB_DATA = 3, TB_ACK = 4, TB_BYE = 5 };

#define TB_F_LAST 0x01   /* DATA: last frame of the message */
#define TB_F_VERIFY 0x02 /* DATA: the receiver checks this message's bytes */
#define TB_F_ACKREQ 0x04 /* DATA, last frame: ACK as soon as the message is in GPU memory */

struct tb_hdr {
	uint32_t magic;
	uint8_t type;
	uint8_t flags;
	uint16_t payload_len;
	uint32_t seq;      /* DATA: frame sequence; ACK: next expected sequence */
	uint32_t msg_id;
	uint32_t msg_len;
	uint32_t frag_off;
	uint32_t aux;      /* ACK: messages completed; HELLO: mode */
	uint32_t run_id;
};

static inline void tb_put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t tb_get32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

static inline void tb_hdr_encode(uint8_t *out, const struct tb_hdr *h)
{
	tb_put32(out, h->magic);
	out[4] = h->type;
	out[5] = h->flags;
	out[6] = (uint8_t)h->payload_len;
	out[7] = (uint8_t)(h->payload_len >> 8);
	tb_put32(out + 8, h->seq);
	tb_put32(out + 12, h->msg_id);
	tb_put32(out + 16, h->msg_len);
	tb_put32(out + 20, h->frag_off);
	tb_put32(out + 24, h->aux);
	tb_put32(out + 28, h->run_id);
}

/* len: bytes available after the Ethernet header. */
static inline int tb_hdr_decode(const uint8_t *in, size_t len, struct tb_hdr *h)
{
	if (len < TB_HDR_LEN)
		return -EMSGSIZE;
	memset(h, 0, sizeof(*h));
	h->magic = tb_get32(in);
	h->type = in[4];
	h->flags = in[5];
	h->payload_len = (uint16_t)(in[6] | in[7] << 8);
	h->seq = tb_get32(in + 8);
	h->msg_id = tb_get32(in + 12);
	h->msg_len = tb_get32(in + 16);
	h->frag_off = tb_get32(in + 20);
	h->aux = tb_get32(in + 24);
	h->run_id = tb_get32(in + 28);
	if (h->magic != TB_MAGIC || h->type < TB_HELLO || h->type > TB_BYE)
		return -EBADMSG;
	if (len < (size_t)TB_HDR_LEN + h->payload_len)
		return -EMSGSIZE;
	return 0;
}

/* Payload bytes per frame for a port MTU (the MTU excludes the Ethernet header). */
static inline size_t tb_frag_payload(uint32_t mtu)
{
	return mtu > TB_HDR_LEN ? mtu - TB_HDR_LEN : 0;
}

static inline uint32_t tb_frag_count(uint64_t msg_len, size_t frag_payload)
{
	if (!msg_len || !frag_payload)
		return 0;
	return (uint32_t)((msg_len + frag_payload - 1) / frag_payload);
}

static inline int tb_frag_at(uint32_t msg_len, size_t frag_payload, uint32_t idx,
			     uint32_t *off, uint16_t *len, int *last)
{
	uint32_t n = tb_frag_count(msg_len, frag_payload);
	uint64_t start;

	if (idx >= n || frag_payload > 0xffff)
		return -ERANGE;
	start = (uint64_t)idx * frag_payload;
	*off = (uint32_t)start;
	*len = (uint16_t)(msg_len - start < frag_payload ? msg_len - start : frag_payload);
	*last = idx == n - 1;
	return 0;
}

/* ---- receiver ---- */

struct tb_rx_state {
	uint32_t expected_seq;  /* next DATA sequence number */
	uint32_t last_ack_sent; /* expected_seq carried by the last ACK */
	uint32_t ack_every;
	uint32_t capacity;      /* reassembly buffer bytes */
	uint32_t next_msg_id;
	uint32_t msg_len;       /* message being reassembled */
	uint32_t got;
	uint8_t flags;
	int in_msg;
	/* the last completed message */
	uint32_t done_len;
	uint32_t done_msg_id;
	uint8_t done_flags;
	uint64_t messages;
};

enum { TB_RX_MORE = 0, TB_RX_DONE = 1 };

static inline void tb_rx_init(struct tb_rx_state *rx, uint32_t capacity, uint32_t ack_every)
{
	memset(rx, 0, sizeof(*rx));
	rx->capacity = capacity;
	rx->ack_every = ack_every;
}

/*
 * Place one DATA frame into buf.  Returns TB_RX_MORE, TB_RX_DONE when the
 * frame completed a message (done_* describe it), or a negative error:
 * -EPROTO a frame is missing, -EALREADY a frame repeated, -EMSGSIZE the
 * message exceeds the buffer, -EBADMSG the frame contradicts its message.
 */
static inline int tb_rx_data(struct tb_rx_state *rx, const struct tb_hdr *h,
			     const uint8_t *payload, uint8_t *buf)
{
	int32_t delta = (int32_t)(h->seq - rx->expected_seq);
	uint64_t end = (uint64_t)h->frag_off + h->payload_len;
	int last = !!(h->flags & TB_F_LAST);

	if (delta > 0)
		return -EPROTO;
	if (delta < 0)
		return -EALREADY;
	if (h->msg_id != rx->next_msg_id || !h->msg_len || !h->payload_len)
		return -EBADMSG;
	if (!rx->in_msg) {
		if (h->frag_off)
			return -EBADMSG;
		if (h->msg_len > rx->capacity)
			return -EMSGSIZE;
		rx->msg_len = h->msg_len;
		rx->got = 0;
		rx->flags = h->flags & TB_F_VERIFY;
	} else if (h->msg_len != rx->msg_len) {
		return -EBADMSG;
	}
	if (h->frag_off != rx->got || end > rx->msg_len || last != (end == rx->msg_len))
		return -EBADMSG;
	memcpy(buf + h->frag_off, payload, h->payload_len);
	rx->got = (uint32_t)end;
	rx->expected_seq++;
	if (!last) {
		rx->in_msg = 1;
		return TB_RX_MORE;
	}
	rx->in_msg = 0;
	rx->done_len = rx->msg_len;
	rx->done_msg_id = h->msg_id;
	rx->done_flags = (uint8_t)(rx->flags | (h->flags & TB_F_ACKREQ));
	rx->next_msg_id++;
	rx->messages++;
	return TB_RX_DONE;
}

static inline int tb_rx_should_ack(const struct tb_rx_state *rx)
{
	return rx->expected_seq - rx->last_ack_sent >= rx->ack_every;
}

static inline void tb_rx_mark_acked(struct tb_rx_state *rx)
{
	rx->last_ack_sent = rx->expected_seq;
}

/* ---- sender window ---- */

struct tb_tx_window {
	uint32_t next_seq; /* sequence of the next DATA frame */
	uint32_t acked;    /* every frame before this one is acknowledged */
	uint32_t window;
};

static inline void tb_tx_init(struct tb_tx_window *w, uint32_t window)
{
	w->next_seq = 0;
	w->acked = 0;
	w->window = window;
}

static inline uint32_t tb_tx_in_flight(const struct tb_tx_window *w)
{
	return w->next_seq - w->acked;
}

static inline int tb_tx_can_send(const struct tb_tx_window *w)
{
	return tb_tx_in_flight(w) < w->window;
}

static inline void tb_tx_sent(struct tb_tx_window *w)
{
	w->next_seq++;
}

/* ack: the receiver's next expected sequence (cumulative). */
static inline int tb_tx_on_ack(struct tb_tx_window *w, uint32_t ack)
{
	uint32_t advance = ack - w->acked;

	if ((int32_t)advance <= 0)
		return 0; /* stale or repeated */
	if (advance > tb_tx_in_flight(w))
		return -EPROTO;
	w->acked = ack;
	return 0;
}

/* ---- command line ---- */

static inline int tb_parse_u64(const char *s, uint64_t *out)
{
	char *end;
	unsigned long long v;

	if (!s || !*s || *s < '0' || *s > '9')
		return -EINVAL;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno || *end)
		return -EINVAL;
	*out = v;
	return 0;
}

/* "A..B" doubles from A to B (B must be A times a power of two); "a,b,c" lists. */
static inline int tb_parse_sizes(const char *spec, uint32_t *out, int max, uint32_t limit)
{
	char buf[512], *dots, *tok, *save;
	uint64_t a, b;
	int n = 0;

	if (!spec || !*spec || strlen(spec) >= sizeof(buf))
		return -EINVAL;
	snprintf(buf, sizeof(buf), "%s", spec);
	dots = strstr(buf, "..");
	if (dots) {
		*dots = 0;
		if (tb_parse_u64(buf, &a) || tb_parse_u64(dots + 2, &b) || !a || a > b ||
		    b > limit)
			return -EINVAL;
		for (uint64_t v = a; v <= b; v *= 2) {
			if (n >= max)
				return -EINVAL;
			out[n++] = (uint32_t)v;
			if (v == b)
				return n;
		}
		return -EINVAL; /* B is not A times a power of two */
	}
	if (buf[strlen(buf) - 1] == ',' || buf[0] == ',' || strstr(buf, ",,"))
		return -EINVAL;
	for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		if (tb_parse_u64(tok, &a) || !a || a > limit || n >= max)
			return -EINVAL;
		out[n++] = (uint32_t)a;
	}
	return n ? n : -EINVAL;
}

static inline int tb_hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static inline int tb_parse_mac(const char *s, uint8_t *mac)
{
	if (!s || strlen(s) != 17)
		return -EINVAL;
	for (int i = 0; i < 6; i++) {
		int hi = tb_hexval(s[3 * i]), lo = tb_hexval(s[3 * i + 1]);

		if (hi < 0 || lo < 0 || (i < 5 && s[3 * i + 2] != ':'))
			return -EINVAL;
		mac[i] = (uint8_t)(hi << 4 | lo);
	}
	return 0;
}

enum { TB_ROLE_CLIENT = 1, TB_ROLE_SERVER = 2 };
enum { TB_MODE_PINGPONG = 1, TB_MODE_STREAM = 2 };

struct tb_opts {
	int role;
	int mode;
	uint32_t sizes[TB_MAX_SIZES];
	int nsizes;
	uint32_t iters;
	uint32_t warmup;
	uint64_t stream_min_bytes;
	uint32_t window_frames;
	uint32_t ack_every;
	int have_peer_mac;
	uint8_t peer_mac[6];
	int gpu;
	int verify_all;
	uint32_t timeout_ms;
	uint32_t max_size;
	int port;
};

#define TB_DEFAULT_SIZES "64..4194304"

#define TB_USAGE \
"usage: dpdk_tb [EAL options] -- --role client|server [options]\n" \
"  --mode pingpong|stream     client: one-way latency or bandwidth (pingpong)\n" \
"  --sizes A..B|a,b,c         message bytes (" TB_DEFAULT_SIZES ")\n" \
"  --iters N                  timed messages per size (1000)\n" \
"  --warmup N                 verified untimed messages per size (10)\n" \
"  --stream-min-bytes N       stream: at least N bytes per size (268435456)\n" \
"  --window-frames N          unacknowledged frames, at most 2048 (1024)\n" \
"  --ack-every N              receiver ACK interval in frames (256)\n" \
"  --peer-mac XX:XX:XX:XX:XX:XX  skip the broadcast HELLO discovery\n" \
"  --gpu N                    CUDA device (0)\n" \
"  --verify warmup|all        which messages are checked byte for byte (warmup)\n" \
"  --timeout-ms N             no progress for N ms ends the run (2000)\n" \
"  --max-size N               largest message, buffer size (4194304)\n" \
"  --port N                   DPDK port id (0)\n"

static inline int tb_opt_u32(const char *v, uint32_t min, uint32_t max, uint32_t *out)
{
	uint64_t x;

	if (tb_parse_u64(v, &x) || x < min || x > max)
		return -EINVAL;
	*out = (uint32_t)x;
	return 0;
}

/* Returns 0, 1 for --help, or -EINVAL with a message in err. */
static inline int tb_parse_opts(int argc, char **argv, struct tb_opts *o, char *err,
				size_t errlen)
{
	const char *sizes = TB_DEFAULT_SIZES;
	uint32_t tmp;

	memset(o, 0, sizeof(*o));
	o->mode = TB_MODE_PINGPONG;
	o->iters = 1000;
	o->warmup = 10;
	o->stream_min_bytes = 268435456ull;
	o->window_frames = 1024;
	o->ack_every = 256;
	o->timeout_ms = 2000;
	o->max_size = 4194304;
	for (int i = 1; i < argc; i++) {
		char name[64];
		const char *arg = argv[i], *val, *eq;

		if (!strcmp(arg, "--help") || !strcmp(arg, "-h"))
			return 1;
		if (strncmp(arg, "--", 2)) {
			snprintf(err, errlen, "unexpected argument %s", arg);
			return -EINVAL;
		}
		eq = strchr(arg, '=');
		if (eq) {
			snprintf(name, sizeof(name), "%.*s", (int)(eq - arg), arg);
			val = eq + 1;
		} else {
			snprintf(name, sizeof(name), "%s", arg);
			if (i + 1 >= argc) {
				snprintf(err, errlen, "%s needs a value", arg);
				return -EINVAL;
			}
			val = argv[++i];
		}
#define TB_BAD() do { snprintf(err, errlen, "bad value for %s: %s", name, val); \
		return -EINVAL; } while (0)
		if (!strcmp(name, "--role")) {
			if (!strcmp(val, "client"))
				o->role = TB_ROLE_CLIENT;
			else if (!strcmp(val, "server"))
				o->role = TB_ROLE_SERVER;
			else
				TB_BAD();
		} else if (!strcmp(name, "--mode")) {
			if (!strcmp(val, "pingpong"))
				o->mode = TB_MODE_PINGPONG;
			else if (!strcmp(val, "stream"))
				o->mode = TB_MODE_STREAM;
			else
				TB_BAD();
		} else if (!strcmp(name, "--sizes")) {
			sizes = val;
		} else if (!strcmp(name, "--iters")) {
			if (tb_opt_u32(val, 1, 100000000, &o->iters))
				TB_BAD();
		} else if (!strcmp(name, "--warmup")) {
			if (tb_opt_u32(val, 0, 100000000, &o->warmup))
				TB_BAD();
		} else if (!strcmp(name, "--stream-min-bytes")) {
			if (tb_parse_u64(val, &o->stream_min_bytes))
				TB_BAD();
		} else if (!strcmp(name, "--window-frames")) {
			if (tb_opt_u32(val, 1, TB_MAX_WINDOW, &o->window_frames))
				TB_BAD();
		} else if (!strcmp(name, "--ack-every")) {
			if (tb_opt_u32(val, 1, TB_MAX_WINDOW, &o->ack_every))
				TB_BAD();
		} else if (!strcmp(name, "--peer-mac")) {
			if (tb_parse_mac(val, o->peer_mac))
				TB_BAD();
			o->have_peer_mac = 1;
		} else if (!strcmp(name, "--gpu")) {
			if (tb_opt_u32(val, 0, 255, &tmp))
				TB_BAD();
			o->gpu = (int)tmp;
		} else if (!strcmp(name, "--verify")) {
			if (!strcmp(val, "all"))
				o->verify_all = 1;
			else if (!strcmp(val, "warmup"))
				o->verify_all = 0;
			else
				TB_BAD();
		} else if (!strcmp(name, "--timeout-ms")) {
			if (tb_opt_u32(val, 1, 3600000, &o->timeout_ms))
				TB_BAD();
		} else if (!strcmp(name, "--max-size")) {
			if (tb_opt_u32(val, 1, TB_SIZE_LIMIT, &o->max_size))
				TB_BAD();
		} else if (!strcmp(name, "--port")) {
			if (tb_opt_u32(val, 0, 1023, &tmp))
				TB_BAD();
			o->port = (int)tmp;
		} else {
			snprintf(err, errlen, "unknown option %s", name);
			return -EINVAL;
		}
#undef TB_BAD
	}
	if (!o->role) {
		snprintf(err, errlen, "--role client|server is required");
		return -EINVAL;
	}
	if (o->ack_every > o->window_frames) {
		snprintf(err, errlen, "--ack-every must not exceed --window-frames");
		return -EINVAL;
	}
	if (o->role == TB_ROLE_SERVER)
		return 0; /* the server takes each message's length from its frames */
	o->nsizes = tb_parse_sizes(sizes, o->sizes, TB_MAX_SIZES, o->max_size);
	if (o->nsizes < 0) {
		snprintf(err, errlen, "bad --sizes %s (each 1..--max-size %u)", sizes,
			 o->max_size);
		return -EINVAL;
	}
	return 0;
}

/* ---- payload pattern and statistics ---- */

static inline uint8_t tb_pattern_byte(size_t i, uint32_t msg_id)
{
	return (uint8_t)((i * 131u + msg_id * 7u + (i >> 8)) ^ 0x5au);
}

static inline void tb_pattern_fill(uint8_t *buf, size_t n, uint32_t msg_id)
{
	for (size_t i = 0; i < n; i++)
		buf[i] = tb_pattern_byte(i, msg_id);
}

/* -1 when every byte matches, otherwise the first mismatching offset. */
static inline long tb_pattern_check(const uint8_t *buf, size_t n, uint32_t msg_id)
{
	for (size_t i = 0; i < n; i++)
		if (buf[i] != tb_pattern_byte(i, msg_id))
			return (long)i;
	return -1;
}

struct tb_lat {
	uint64_t min, max, p50, p99;
	double mean;
};

static inline int tb_cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

	return x < y ? -1 : x > y;
}

/* Nearest-rank percentiles; sorts v in place. */
static inline void tb_summarize(uint64_t *v, size_t n, struct tb_lat *lat)
{
	double sum = 0;

	memset(lat, 0, sizeof(*lat));
	if (!n)
		return;
	qsort(v, n, sizeof(*v), tb_cmp_u64);
	for (size_t i = 0; i < n; i++)
		sum += (double)v[i];
	lat->min = v[0];
	lat->max = v[n - 1];
	lat->p50 = v[(n * 50 + 99) / 100 - 1];
	lat->p99 = v[(n * 99 + 99) / 100 - 1];
	lat->mean = sum / (double)n;
}

/* Stream: at least iters messages and at least min_bytes per size. */
static inline uint64_t tb_stream_messages(uint32_t size, uint32_t iters, uint64_t min_bytes)
{
	uint64_t by_bytes = (min_bytes + size - 1) / size;

	return by_bytes > iters ? by_bytes : iters;
}

#endif
