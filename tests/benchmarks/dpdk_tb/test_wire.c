// SPDX-License-Identifier: GPL-2.0
/* Host checks of tb_wire.h: wire header, fragmentation, reassembly, the
 * frame window, size lists, argument handling, patterns and percentiles.
 * No DPDK, no CUDA, no network: these are the pure parts of dpdk_tb.c. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tb_wire.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
		failures++; \
	} \
} while (0)

static void test_header_roundtrip(void)
{
	uint8_t buf[TB_HDR_LEN + 8] = { 0 };
	struct tb_hdr h = { .magic = TB_MAGIC, .type = TB_DATA, .flags = TB_F_LAST,
			    .payload_len = 8, .seq = 0xfffffffeu, .msg_id = 7,
			    .msg_len = 4194304, .frag_off = 4193000, .aux = 3,
			    .run_id = 0xabcdef01u };
	struct tb_hdr d = { 0 };

	CHECK(TB_HDR_LEN == 32);
	tb_hdr_encode(buf, &h);
	/* little-endian on the wire whatever the host order */
	CHECK(buf[0] == 0x58 && buf[1] == 0x54 && buf[2] == 0x42 && buf[3] == 0x31);
	CHECK(tb_hdr_decode(buf, sizeof(buf), &d) == 0);
	CHECK(memcmp(&h, &d, sizeof(h)) == 0);
	/* truncated frame: header claims 8 payload bytes, only 7 present */
	CHECK(tb_hdr_decode(buf, sizeof(buf) - 1, &d) == -EMSGSIZE);
	CHECK(tb_hdr_decode(buf, TB_HDR_LEN - 1, &d) == -EMSGSIZE);
	buf[0] ^= 1;
	CHECK(tb_hdr_decode(buf, sizeof(buf), &d) == -EBADMSG);
	buf[0] ^= 1;
	buf[4] = 9; /* unknown type */
	CHECK(tb_hdr_decode(buf, sizeof(buf), &d) == -EBADMSG);
}

static void test_fragmentation(void)
{
	uint32_t off = 0;
	uint16_t len = 0;
	int last = 0;
	uint64_t sum = 0;

	/* MTU 1500 (thunderbolt-net default once DPDK configures the port) */
	CHECK(tb_frag_payload(1500) == 1468);
	CHECK(tb_frag_payload(TB_HDR_LEN) == 0);
	CHECK(tb_frag_payload(68) == 36);
	/* af_xdp PMD maximum MTU with 4 KiB pages */
	CHECK(tb_frag_payload(3520) == 3488);
	CHECK(tb_frag_count(64, 1468) == 1);
	CHECK(tb_frag_count(1468, 1468) == 1);
	CHECK(tb_frag_count(1469, 1468) == 2);
	CHECK(tb_frag_count(4194304, 1468) == 2858);
	CHECK(tb_frag_count(0, 1468) == 0);
	CHECK(tb_frag_count(10, 0) == 0);
	for (uint32_t i = 0; i < 2858; i++) {
		CHECK(tb_frag_at(4194304, 1468, i, &off, &len, &last) == 0);
		CHECK(off == i * 1468u);
		CHECK(last == (i == 2857));
		sum += len;
	}
	CHECK(sum == 4194304);
	CHECK(tb_frag_at(4194304, 1468, 2857, &off, &len, &last) == 0 && len == 4194304 - 2857 * 1468);
	CHECK(tb_frag_at(4194304, 1468, 2858, &off, &len, &last) == -ERANGE);
	CHECK(tb_frag_at(64, 1468, 0, &off, &len, &last) == 0 && off == 0 && len == 64 && last);
}

/* Build the frames of one message, as the sender does. */
static int build_frames(uint32_t msg_len, size_t fp, uint32_t first_seq, uint32_t msg_id,
			uint8_t flags, struct tb_hdr *hdrs)
{
	uint32_t n = tb_frag_count(msg_len, fp);

	for (uint32_t i = 0; i < n; i++) {
		uint32_t off;
		uint16_t len;
		int last;

		if (tb_frag_at(msg_len, fp, i, &off, &len, &last))
			return -1;
		hdrs[i] = (struct tb_hdr){ .magic = TB_MAGIC, .type = TB_DATA,
			.flags = (uint8_t)(flags | (last ? TB_F_LAST : 0)), .payload_len = len,
			.seq = first_seq + i, .msg_id = msg_id, .msg_len = msg_len,
			.frag_off = off };
	}
	return (int)n;
}

static void test_reassembly(void)
{
	const size_t fp = 1468;
	const uint32_t size = 100000;
	uint8_t *src = calloc(1, size), *dst = calloc(1, size);
	struct tb_hdr hdrs[80] = { 0 };
	struct tb_rx_state rx = { 0 };
	int n;

	tb_pattern_fill(src, size, 5);
	tb_rx_init(&rx, size, 16);
	n = build_frames(size, fp, 0, 0, TB_F_VERIFY, hdrs);
	CHECK(n == 69);
	for (int i = 0; i < n; i++) {
		int r = tb_rx_data(&rx, &hdrs[i], src + hdrs[i].frag_off, dst);

		CHECK(r == (i == n - 1 ? TB_RX_DONE : TB_RX_MORE));
		if (i == 15)
			CHECK(tb_rx_should_ack(&rx));
		if (i == 14)
			CHECK(!tb_rx_should_ack(&rx));
		if (tb_rx_should_ack(&rx))
			tb_rx_mark_acked(&rx);
	}
	CHECK(memcmp(src, dst, size) == 0);
	CHECK(rx.done_len == size && rx.done_msg_id == 0 && (rx.done_flags & TB_F_VERIFY));
	CHECK(rx.expected_seq == 69 && rx.next_msg_id == 1 && rx.messages == 1);

	/* next message continues the sequence; a lost frame is reported as a gap */
	n = build_frames(3000, fp, 69, 1, 0, hdrs);
	CHECK(n == 3);
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == TB_RX_MORE);
	CHECK(tb_rx_data(&rx, &hdrs[2], src + hdrs[2].frag_off, dst) == -EPROTO);

	/* duplicate frame */
	tb_rx_init(&rx, size, 16);
	n = build_frames(3000, fp, 0, 0, 0, hdrs);
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == TB_RX_MORE);
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == -EALREADY);

	/* message larger than the buffer */
	tb_rx_init(&rx, 1000, 16);
	n = build_frames(3000, fp, 0, 0, 0, hdrs);
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == -EMSGSIZE);

	/* wrong message id, inconsistent offset, length overrun, bad LAST flag */
	tb_rx_init(&rx, size, 16);
	n = build_frames(3000, fp, 0, 4, 0, hdrs);
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == -EBADMSG);
	tb_rx_init(&rx, size, 16);
	n = build_frames(3000, fp, 0, 0, 0, hdrs);
	hdrs[1].frag_off += 1;
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == TB_RX_MORE);
	CHECK(tb_rx_data(&rx, &hdrs[1], src, dst) == -EBADMSG);
	tb_rx_init(&rx, size, 16);
	n = build_frames(3000, fp, 0, 0, 0, hdrs);
	hdrs[0].flags |= TB_F_LAST;
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == -EBADMSG);
	tb_rx_init(&rx, size, 16);
	n = build_frames(3000, fp, 0, 0, 0, hdrs);
	hdrs[2].flags &= (uint8_t)~TB_F_LAST;
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == TB_RX_MORE);
	CHECK(tb_rx_data(&rx, &hdrs[1], src + hdrs[1].frag_off, dst) == TB_RX_MORE);
	CHECK(tb_rx_data(&rx, &hdrs[2], src + hdrs[2].frag_off, dst) == -EBADMSG);
	/* msg_len change in the middle of a message */
	tb_rx_init(&rx, size, 16);
	n = build_frames(3000, fp, 0, 0, 0, hdrs);
	hdrs[1].msg_len = 4000;
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == TB_RX_MORE);
	CHECK(tb_rx_data(&rx, &hdrs[1], src, dst) == -EBADMSG);
	/* zero-length message */
	tb_rx_init(&rx, size, 16);
	hdrs[0] = (struct tb_hdr){ .magic = TB_MAGIC, .type = TB_DATA, .flags = TB_F_LAST,
				   .payload_len = 0, .seq = 0, .msg_id = 0, .msg_len = 0 };
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == -EBADMSG);

	/* sequence numbers wrap */
	tb_rx_init(&rx, size, 4);
	rx.expected_seq = 0xfffffffeu;
	rx.last_ack_sent = 0xfffffffeu;
	n = build_frames(5000, fp, 0xfffffffeu, 0, 0, hdrs);
	for (int i = 0; i < n; i++)
		CHECK(tb_rx_data(&rx, &hdrs[i], src + hdrs[i].frag_off, dst) ==
		      (i == n - 1 ? TB_RX_DONE : TB_RX_MORE));
	CHECK(rx.expected_seq == 2 && tb_rx_should_ack(&rx));
	free(src);
	free(dst);
}

static void test_completion_ack_request(void)
{
	const size_t fp = 1468;
	uint8_t src[4000] = { 0 }, dst[4000] = { 0 };
	struct tb_hdr hdrs[4] = { 0 };
	struct tb_rx_state rx = { 0 };
	int n;

	/* the sender asks for a completion ACK on the last frame only */
	tb_rx_init(&rx, sizeof(dst), 256);
	n = build_frames(4000, fp, 0, 0, 0, hdrs);
	hdrs[n - 1].flags |= TB_F_ACKREQ;
	for (int i = 0; i < n; i++)
		tb_rx_data(&rx, &hdrs[i], src + hdrs[i].frag_off, dst);
	CHECK(rx.done_flags & TB_F_ACKREQ);
	CHECK(!(rx.done_flags & TB_F_VERIFY));
	/* the next message without the request does not inherit it */
	n = build_frames(100, fp, 3, 1, TB_F_VERIFY, hdrs);
	CHECK(tb_rx_data(&rx, &hdrs[0], src, dst) == TB_RX_DONE);
	CHECK(!(rx.done_flags & TB_F_ACKREQ) && (rx.done_flags & TB_F_VERIFY));
}

static void test_window(void)
{
	struct tb_tx_window w = { 0 };

	tb_tx_init(&w, 4);
	for (int i = 0; i < 4; i++) {
		CHECK(tb_tx_can_send(&w));
		tb_tx_sent(&w);
	}
	CHECK(!tb_tx_can_send(&w));
	CHECK(tb_tx_in_flight(&w) == 4);
	CHECK(tb_tx_on_ack(&w, 2) == 0);
	CHECK(tb_tx_in_flight(&w) == 2 && tb_tx_can_send(&w));
	/* a stale ACK is ignored, an ACK beyond what was sent is a protocol error */
	CHECK(tb_tx_on_ack(&w, 1) == 0 && tb_tx_in_flight(&w) == 2);
	CHECK(tb_tx_on_ack(&w, 5) == -EPROTO && tb_tx_in_flight(&w) == 2);
	CHECK(tb_tx_on_ack(&w, 4) == 0 && tb_tx_in_flight(&w) == 0);
	/* wrap */
	tb_tx_init(&w, 8);
	w.next_seq = w.acked = 0xfffffffdu;
	for (int i = 0; i < 6; i++)
		tb_tx_sent(&w);
	CHECK(w.next_seq == 3 && tb_tx_in_flight(&w) == 6);
	CHECK(tb_tx_on_ack(&w, 1) == 0 && tb_tx_in_flight(&w) == 2);
	CHECK(tb_tx_on_ack(&w, 0xffffffffu) == 0 && tb_tx_in_flight(&w) == 2);
	CHECK(tb_tx_on_ack(&w, 4) == -EPROTO);
}

static void test_sizes(void)
{
	uint32_t s[TB_MAX_SIZES] = { 0 };

	CHECK(tb_parse_sizes("64..4194304", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == 17);
	CHECK(s[0] == 64 && s[1] == 128 && s[16] == 4194304);
	CHECK(tb_parse_sizes("4096", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == 1 && s[0] == 4096);
	CHECK(tb_parse_sizes("64,1000,65536", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == 3 && s[1] == 1000);
	CHECK(tb_parse_sizes("64..64", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == 1);
	CHECK(tb_parse_sizes("64..100", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == -EINVAL);
	CHECK(tb_parse_sizes("128..64", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == -EINVAL);
	CHECK(tb_parse_sizes("0", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == -EINVAL);
	CHECK(tb_parse_sizes("", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == -EINVAL);
	CHECK(tb_parse_sizes("64,", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == -EINVAL);
	CHECK(tb_parse_sizes("64x", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == -EINVAL);
	CHECK(tb_parse_sizes("-64", s, TB_MAX_SIZES, TB_SIZE_LIMIT) == -EINVAL);
	CHECK(tb_parse_sizes("8388608", s, TB_MAX_SIZES, 4194304) == -EINVAL);
	CHECK(tb_parse_sizes("1,2,3", s, 2, TB_SIZE_LIMIT) == -EINVAL);
}

static int parse(struct tb_opts *o, const char *line)
{
	char copy[512], *argv[32], err[160];
	int argc = 0;

	snprintf(copy, sizeof(copy), "dpdk_tb %s", line);
	for (char *t = strtok(copy, " "); t && argc < 31; t = strtok(NULL, " "))
		argv[argc++] = t;
	argv[argc] = NULL;
	err[0] = 0;
	return tb_parse_opts(argc, argv, o, err, sizeof(err));
}

static void test_options(void)
{
	struct tb_opts o = { 0 };

	CHECK(parse(&o, "--role client") == 0);
	CHECK(o.role == TB_ROLE_CLIENT && o.mode == TB_MODE_PINGPONG);
	CHECK(o.nsizes == 17 && o.sizes[0] == 64 && o.sizes[16] == 4194304);
	CHECK(o.iters == 1000 && o.warmup == 10 && o.window_frames == 1024 && o.ack_every == 256);
	CHECK(o.stream_min_bytes == 268435456ull && o.gpu == 0 && o.verify_all == 0);
	CHECK(o.timeout_ms == 2000 && o.max_size == 4194304 && !o.have_peer_mac);
	CHECK(parse(&o, "--role server --max-size 65536") == 0 && o.role == TB_ROLE_SERVER &&
	      o.max_size == 65536);
	CHECK(parse(&o, "--role=client --mode=stream --sizes=4096,8192 --iters 5 --warmup=0 "
		  "--verify all --peer-mac 02:00:00:00:00:0a --gpu 1 --timeout-ms 50") == 0);
	CHECK(o.mode == TB_MODE_STREAM && o.nsizes == 2 && o.iters == 5 && o.warmup == 0);
	CHECK(o.verify_all == 1 && o.have_peer_mac && o.peer_mac[5] == 0x0a && o.gpu == 1);
	CHECK(o.timeout_ms == 50);
	CHECK(parse(&o, "--role client --window-frames 64 --ack-every 16") == 0 &&
	      o.window_frames == 64 && o.ack_every == 16);
	/* missing or unknown values */
	CHECK(parse(&o, "") == -EINVAL);
	CHECK(parse(&o, "--role peer") == -EINVAL);
	CHECK(parse(&o, "--role client --mode bulk") == -EINVAL);
	CHECK(parse(&o, "--role client --iters 0") == -EINVAL);
	CHECK(parse(&o, "--role client --iters") == -EINVAL);
	CHECK(parse(&o, "--role client --iters 12x") == -EINVAL);
	CHECK(parse(&o, "--role client --frobnicate 1") == -EINVAL);
	CHECK(parse(&o, "--role client --window-frames 4096") == -EINVAL);
	CHECK(parse(&o, "--role client --window-frames 64 --ack-every 65") == -EINVAL);
	CHECK(parse(&o, "--role client --ack-every 0") == -EINVAL);
	CHECK(parse(&o, "--role client --peer-mac 02:00:00:00:00") == -EINVAL);
	CHECK(parse(&o, "--role client --sizes 64..100") == -EINVAL);
	CHECK(parse(&o, "--role client --verify some") == -EINVAL);
	CHECK(parse(&o, "--role server --max-size 0") == -EINVAL);
	/* a client size above the server buffer limit is refused locally too */
	CHECK(parse(&o, "--role client --sizes 8388608") == -EINVAL);
	CHECK(parse(&o, "--role client --max-size 8388608 --sizes 8388608") == 0);
	CHECK(parse(&o, "--help") == 1);
}

static void test_pattern_and_stats(void)
{
	uint8_t a[5000] = { 0 }, b[5000] = { 0 };
	uint64_t ns[] = { 50, 10, 40, 30, 20, 60, 70, 80, 90, 100 };
	struct tb_lat lat = { 0 };

	tb_pattern_fill(a, sizeof(a), 3);
	tb_pattern_fill(b, sizeof(b), 4);
	CHECK(memcmp(a, b, sizeof(a)) != 0);
	CHECK(tb_pattern_check(a, sizeof(a), 3) == -1);
	a[4321] ^= 0x10;
	CHECK(tb_pattern_check(a, sizeof(a), 3) == 4321);
	/* nearest-rank percentiles */
	tb_summarize(ns, 10, &lat);
	CHECK(lat.min == 10 && lat.max == 100 && lat.p50 == 50 && lat.p99 == 100);
	CHECK(lat.mean == 55.0);
	{
		uint64_t one[] = { 7 };

		tb_summarize(one, 1, &lat);
		CHECK(lat.p50 == 7 && lat.p99 == 7);
	}
	{
		uint8_t m[6] = { 0 };

		CHECK(tb_parse_mac("aa:BB:0c:00:ff:01", m) == 0 && m[1] == 0xbb && m[5] == 1);
		CHECK(tb_parse_mac("aa:bb:cc:dd:ee", m) == -EINVAL);
		CHECK(tb_parse_mac("aa:bb:cc:dd:ee:fg", m) == -EINVAL);
		CHECK(tb_parse_mac("aa:bb:cc:dd:ee:ff:00", m) == -EINVAL);
	}
}

static void test_stream_message_count(void)
{
	/* at least --iters messages and at least --stream-min-bytes per size */
	CHECK(tb_stream_messages(4194304, 1000, 268435456ull) == 1000);
	CHECK(tb_stream_messages(64, 1000, 268435456ull) == 4194304);
	CHECK(tb_stream_messages(1000, 1, 2500) == 3);
}

int main(void)
{
	test_header_roundtrip();
	test_fragmentation();
	test_reassembly();
	test_completion_ack_request();
	test_window();
	test_sizes();
	test_options();
	test_pattern_and_stats();
	test_stream_message_count();
	if (failures) {
		fprintf(stderr, "dpdk_tb wire: %d failure(s)\n", failures);
		return 1;
	}
	printf("dpdk_tb wire: PASS\n");
	return 0;
}
