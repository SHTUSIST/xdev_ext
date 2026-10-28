// SPDX-License-Identifier: GPL-2.0
/*
 * Pure rules of the AF_XDP mechanism TX stage: the descriptor validator,
 * the C-only header fields and one submit attempt with its RETRY resume.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../../net/xdp/xsk_xdev_ext_mech_tx_core.h"

static unsigned int tests_run;
static unsigned int tests_failed;

#define EXPECT_EQ(actual_expr, expected_expr) do {                         \
	long long actual_ = (long long)(actual_expr);                       \
	long long expected_ = (long long)(expected_expr);                   \
	tests_run++;                                                        \
	if (actual_ != expected_) {                                         \
		fprintf(stderr, "%s:%d: %s: got %lld, expected %lld\n",     \
			__FILE__, __LINE__, #actual_expr, actual_, expected_); \
		tests_failed++;                                               \
	}                                                                   \
} while (0)

#define FRAME_SIZE	4096U
#define HDR_ROOM	360U
#define PKT_OFF		278U	/* Ethernet header; NXP header at 320, data at 360 */
#define FIRST_CHUNK	5U
#define NR_CHUNKS	48U
#define MAX_FRAMES	XDEV_EXT_MECH_MAX_FRAMES

/* A batch of TX frames in a fake UMEM, and the scratch a build filled. */
struct tx_case {
	uint8_t umem[NR_CHUNKS * FRAME_SIZE];
	struct xdev_ext_mech_frame_info f[MAX_FRAMES + 1];
	const uint8_t *chunk[MAX_FRAMES + 1];
	uint8_t scratch[(MAX_FRAMES + 1) * sizeof(struct xdp_desc)];
	struct xdp_desc out[MAX_FRAMES];
	struct xsk_xdev_ext_mech_tx_bounds bd;
	uint32_t nr;
};

static struct tx_case tc;

static void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

static uint16_t get16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static uint8_t *pkt(uint32_t i)
{
	return tc.umem + tc.f[i].umem_addr + PKT_OFF;
}

static struct xdp_desc *desc(uint32_t i)
{
	return (struct xdp_desc *)(tc.scratch + i * sizeof(struct xdp_desc));
}

/* What a correct TX build writes for frame i: headers and its descriptor. */
static void build_frame(uint32_t i)
{
	const struct xdev_ext_mech_peer *pe = &tc.bd.peer;
	uint32_t len = tc.f[i].data_off + tc.f[i].data_len - PKT_OFF;
	uint8_t *p = pkt(i);

	memcpy(p, pe->peer_mac, 6);
	memcpy(p + 6, pe->local_mac, 6);
	put16(p + 12, 0x0800);
	p[14] = 0x45;
	p[15] = 0;
	put16(p + 16, len - 14);
	put16(p + 18, 0x1234 + i);
	put16(p + 20, 0x4000);		/* DF only */
	p[22] = 64;
	p[23] = 17;
	put16(p + 24, 0);
	memcpy(p + 26, &pe->local_ip, 4);
	memcpy(p + 30, &pe->peer_ip, 4);
	memcpy(p + 34, &pe->local_port, 2);
	memcpy(p + 36, &pe->peer_port, 2);
	put16(p + 38, len - 34);
	put16(p + 40, 0);
	*desc(i) = (struct xdp_desc) {
		.addr = tc.f[i].umem_addr + PKT_OFF,
		.len = len,
	};
}

/* S2 shape: 8 KiB in six frames of 1432 bytes, the last one 1032. */
static void tx_case_init(uint32_t nr, uint32_t seg)
{
	uint32_t i;

	memset(&tc, 0, sizeof(tc));
	tc.nr = nr;
	tc.bd.hdr_room = HDR_ROOM;
	tc.bd.mtu = 1500;
	memcpy(tc.bd.peer.local_mac, "\x02\x00\x00\x00\x00\x01", 6);
	memcpy(tc.bd.peer.peer_mac, "\x02\x00\x00\x00\x00\x02", 6);
	memcpy(&tc.bd.peer.local_ip, "\x0a\x00\x00\x01", 4);
	memcpy(&tc.bd.peer.peer_ip, "\x0a\x00\x00\x02", 4);
	memcpy(&tc.bd.peer.local_port, "\x23\x28", 2);
	memcpy(&tc.bd.peer.peer_port, "\x23\x29", 2);
	for (i = 0; i < nr; i++) {
		tc.f[i].umem_addr = (uint64_t)(FIRST_CHUNK + i) * FRAME_SIZE;
		tc.f[i].data_off = HDR_ROOM;
		tc.f[i].data_len = i + 1 < nr ? seg : seg - 400;
		tc.chunk[i] = tc.umem + tc.f[i].umem_addr;
		build_frame(i);
	}
}

static int validate(uint32_t n)
{
	return xsk_xdev_ext_mech_tx_validate(tc.scratch, n, tc.f, tc.chunk, tc.nr,
					&tc.bd, tc.out);
}

/* One defect in slot 2 of an otherwise valid six-frame batch. */
static int validate_with(void (*defect)(void))
{
	tx_case_init(6, 1432);
	defect();
	return validate(6);
}

static void d_options(void)		{ desc(2)->options = 1; }
static void d_contd(void)		{ desc(2)->options = XDP_PKT_CONTD; }
static void d_below_frame(void)		{ desc(2)->addr = tc.f[2].umem_addr - 64; }
static void d_in_data(void)
{
	desc(2)->addr += HDR_ROOM - PKT_OFF;
	desc(2)->len -= HDR_ROOM - PKT_OFF;
}

static void d_other_frame(void)		{ *desc(2) = *desc(3); }
static void d_outside_batch(void)	{ desc(2)->addr = 40ULL * FRAME_SIZE + PKT_OFF; }
static void d_addr_max(void)		{ desc(2)->addr = UINT64_MAX; }
static void d_hdr_past_room(void)	{ desc(2)->addr += 70; desc(2)->len -= 70; }

/* A length change that keeps the IPv4 and UDP lengths consistent. */
static void resize(int delta)
{
	desc(2)->len += delta;
	put16(pkt(2) + 16, get16(pkt(2) + 16) + delta);
	put16(pkt(2) + 38, get16(pkt(2) + 38) + delta);
}

static void d_short(void)		{ resize(-1); }
static void d_into_next(void)		{ resize(8); }
static void d_wrap(void)
{
	/* frame 2 at UMEM offset 0: off + header length must not wrap */
	tc.f[2].umem_addr = 0;
	tc.chunk[2] = tc.umem;
	build_frame(2);
	desc(2)->addr = UINT64_MAX - 20;
}

static void d_len_max(void)		{ desc(2)->len = UINT32_MAX; }
static void d_dst_mac(void)		{ pkt(2)[5] ^= 1; }
static void d_src_mac(void)		{ pkt(2)[11] ^= 1; }
static void d_ethertype(void)		{ put16(pkt(2) + 12, 0x86dd); }
static void d_vlan(void)		{ put16(pkt(2) + 12, 0x8100); }
static void d_version(void)		{ pkt(2)[14] = 0x65; }
static void d_ihl(void)			{ pkt(2)[14] = 0x46; }
static void d_proto(void)		{ pkt(2)[23] = 6; }
static void d_more_frags(void)		{ put16(pkt(2) + 20, 0x2000); }
static void d_frag_off(void)		{ put16(pkt(2) + 20, 0x0001); }
static void d_saddr(void)		{ pkt(2)[29] ^= 1; }
static void d_daddr(void)		{ pkt(2)[33] ^= 1; }
static void d_tot_len(void)		{ put16(pkt(2) + 16, get16(pkt(2) + 16) - 1); }
static void d_sport(void)		{ pkt(2)[35] ^= 1; }
static void d_dport(void)		{ pkt(2)[37] ^= 1; }
static void d_udp_len(void)		{ put16(pkt(2) + 38, get16(pkt(2) + 38) + 1); }
static void d_overlap_layout(void)	{ tc.f[2].data_off = HDR_ROOM - 8; tc.f[2].data_len += 8; }
static void d_none(void)		{ }

static void test_validator_accepts_the_s2_batch(void)
{
	uint32_t i;

	tx_case_init(6, 1432);
	EXPECT_EQ(validate(6), 0);
	for (i = 0; i < 6; i++) {
		EXPECT_EQ(tc.out[i].addr, tc.f[i].umem_addr + PKT_OFF);
		EXPECT_EQ(tc.out[i].len, HDR_ROOM - PKT_OFF + tc.f[i].data_len);
		EXPECT_EQ(tc.out[i].options, 0);
	}
	EXPECT_EQ(tc.out[5].len, 82 + 1032);
	/* DF alone is not a fragment, and the IPv4 checksum is C's to fill. */
	EXPECT_EQ(validate_with(d_none), 0);
	tx_case_init(6, 1432);
	put16(pkt(1) + 20, 0);
	put16(pkt(1) + 24, 0xbeef);
	put16(pkt(1) + 40, 0xbeef);
	EXPECT_EQ(validate(6), 0);
}

static void test_validator_needs_one_descriptor_per_frame(void)
{
	tx_case_init(6, 1432);
	EXPECT_EQ(validate(0), -EINVAL);
	EXPECT_EQ(validate(5), -EINVAL);
	EXPECT_EQ(validate(7), -EINVAL);
	/* slot i describes frame i: swapping two valid descriptors fails */
	tx_case_init(6, 1432);
	{
		struct xdp_desc t = *desc(0);

		*desc(0) = *desc(1);
		*desc(1) = t;
	}
	EXPECT_EQ(validate(6), -ERANGE);
	/* a full batch of XDEV_EXT_MECH_MAX_FRAMES frames, and not one more */
	tx_case_init(MAX_FRAMES, 1000);
	EXPECT_EQ(validate(MAX_FRAMES), 0);
	tx_case_init(MAX_FRAMES + 1, 1000);
	EXPECT_EQ(validate(MAX_FRAMES + 1), -EINVAL);
}

static void test_validator_rejects_each_field(void)
{
	EXPECT_EQ(validate_with(d_options), -EINVAL);
	EXPECT_EQ(validate_with(d_contd), -EINVAL);
	EXPECT_EQ(validate_with(d_below_frame), -ERANGE);
	EXPECT_EQ(validate_with(d_in_data), -ERANGE);
	EXPECT_EQ(validate_with(d_other_frame), -ERANGE);
	EXPECT_EQ(validate_with(d_outside_batch), -ERANGE);
	EXPECT_EQ(validate_with(d_addr_max), -ERANGE);
	EXPECT_EQ(validate_with(d_wrap), -ERANGE);
	EXPECT_EQ(validate_with(d_hdr_past_room), -ERANGE);
	EXPECT_EQ(validate_with(d_short), -EMSGSIZE);
	EXPECT_EQ(validate_with(d_into_next), -EMSGSIZE);
	EXPECT_EQ(validate_with(d_len_max), -EMSGSIZE);
	EXPECT_EQ(validate_with(d_dst_mac), -EPERM);
	EXPECT_EQ(validate_with(d_src_mac), -EPERM);
	EXPECT_EQ(validate_with(d_ethertype), -EPROTO);
	EXPECT_EQ(validate_with(d_vlan), -EPROTO);
	EXPECT_EQ(validate_with(d_version), -EPROTO);
	EXPECT_EQ(validate_with(d_ihl), -EPROTO);
	EXPECT_EQ(validate_with(d_proto), -EPROTO);
	EXPECT_EQ(validate_with(d_more_frags), -EPROTO);
	EXPECT_EQ(validate_with(d_frag_off), -EPROTO);
	EXPECT_EQ(validate_with(d_saddr), -EPERM);
	EXPECT_EQ(validate_with(d_daddr), -EPERM);
	EXPECT_EQ(validate_with(d_tot_len), -EMSGSIZE);
	EXPECT_EQ(validate_with(d_sport), -EPERM);
	EXPECT_EQ(validate_with(d_dport), -EPERM);
	EXPECT_EQ(validate_with(d_udp_len), -EMSGSIZE);
	EXPECT_EQ(validate_with(d_overlap_layout), -EINVAL);
}

static void test_validator_bounds_the_mtu(void)
{
	/* 1432 bytes of data make an IPv4 packet of 1500: exactly the MTU */
	tx_case_init(6, 1432);
	tc.bd.mtu = 1500;
	EXPECT_EQ(validate(6), 0);
	tc.bd.mtu = 1499;
	EXPECT_EQ(validate(6), -EMSGSIZE);
	tc.bd.mtu = 0;
	EXPECT_EQ(validate(6), -EMSGSIZE);
}

/* RFC 1071 sum of a 20-byte header including its checksum field. */
static uint16_t ones_sum(const uint8_t *h)
{
	uint32_t sum = 0;
	int i;

	for (i = 0; i < 20; i += 2)
		sum += get16(h + i);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)sum;
}

static void test_ipv4_checksum(void)
{
	static const uint8_t ref[20] = {
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
		0xde, 0xad, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
	};
	uint8_t p[64], before[64];
	uint32_t seed = 12345;
	int n, i;

	/* the stored checksum field does not take part */
	EXPECT_EQ(xsk_xdev_ext_mech_ipv4_csum(ref), 0xb861);

	for (n = 0; n < 1000; n++) {
		for (i = 0; i < 64; i++) {
			seed = seed * 1103515245U + 12345U;
			p[i] = (uint8_t)(seed >> 16);
		}
		p[14] = 0x45;
		memcpy(before, p, sizeof(p));
		xsk_xdev_ext_mech_tx_finish(p);
		/* what the receiver checks: the header sums to 0xffff */
		if (ones_sum(p + 14) != 0xffff)
			EXPECT_EQ(ones_sum(p + 14), 0xffff);
		/* UDP checksum 0: the receiver checks only the IPv4 one */
		if (p[40] || p[41])
			EXPECT_EQ(get16(p + 40), 0);
		/* nothing else in the packet changes */
		for (i = 0; i < 64; i++) {
			if (i == 24 || i == 25 || i == 40 || i == 41)
				continue;
			if (p[i] != before[i])
				EXPECT_EQ(p[i], before[i]);
		}
	}
	tests_run++;
}

/* A fake xsk_kernel_xmit(): results per call, a log of the slots sent. */
struct fake_xmit {
	int result[MAX_FRAMES];
	uint32_t calls;
	uint32_t slot[4 * MAX_FRAMES];
};

static int fake_xmit(void *arg, uint32_t slot)
{
	struct fake_xmit *fx = arg;
	int ret = fx->result[slot];

	fx->slot[fx->calls++] = slot;
	fx->result[slot] = 1432;	/* the next try of this slot succeeds */
	return ret;
}

struct tx_run {
	__u64 tags[NR_CHUNKS];
	__u64 *sent[MAX_FRAMES];
	int32_t err[MAX_FRAMES];
	struct fake_xmit fx;
};

static void tx_run_init(struct tx_run *r, uint32_t n)
{
	uint32_t i;

	memset(r, 0, sizeof(*r));
	for (i = 0; i < n; i++) {
		r->sent[i] = &r->tags[FIRST_CHUNK + i];
		r->fx.result[i] = 1432;
	}
}

static int run(struct tx_run *r, uint64_t id, uint32_t n)
{
	memset(&r->fx.slot, 0, sizeof(r->fx.slot));
	r->fx.calls = 0;
	return xsk_xdev_ext_mech_tx_run(id, n, r->sent, r->err, fake_xmit, &r->fx);
}

static void test_run_sends_every_frame_once_in_slot_order(void)
{
	struct tx_run r;
	uint32_t i;

	tx_run_init(&r, 6);
	EXPECT_EQ(run(&r, 7, 6), 0);
	EXPECT_EQ(r.fx.calls, 6);
	for (i = 0; i < 6; i++) {
		EXPECT_EQ(r.fx.slot[i], i);
		EXPECT_EQ(r.err[i], 0);
		EXPECT_EQ(*r.sent[i], 7);
	}
	EXPECT_EQ(r.tags[FIRST_CHUNK - 1], 0);
	EXPECT_EQ(r.tags[FIRST_CHUNK + 6], 0);
}

static void test_retry_resumes_after_the_frames_on_the_wire(void)
{
	struct tx_run r;
	uint32_t i;
	int status;

	tx_run_init(&r, 6);
	r.fx.result[3] = -EAGAIN;
	status = run(&r, 9, 6);
	EXPECT_EQ(status, -EAGAIN);
	EXPECT_EQ(r.fx.calls, 4);
	EXPECT_EQ(r.err[0], 0);
	EXPECT_EQ(r.err[2], 0);
	EXPECT_EQ(r.err[3], -EAGAIN);
	EXPECT_EQ(r.err[4], -ECANCELED);
	EXPECT_EQ(r.err[5], -ECANCELED);
	EXPECT_EQ(*r.sent[2], 9);
	EXPECT_EQ(*r.sent[3], 0);
	/* C honours RETRY for this status only, and only within the limit */
	EXPECT_EQ(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP, 0, status), true);
	EXPECT_EQ(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP,
				    XDEV_EXT_MECH_RETRY_MAX_AFXDP, status), false);

	/* the retry of batch 9 sends frames 3, 4 and 5 only */
	EXPECT_EQ(run(&r, 9, 6), 0);
	EXPECT_EQ(r.fx.calls, 3);
	EXPECT_EQ(r.fx.slot[0], 3);
	EXPECT_EQ(r.fx.slot[1], 4);
	EXPECT_EQ(r.fx.slot[2], 5);
	for (i = 0; i < 6; i++) {
		EXPECT_EQ(r.err[i], 0);
		EXPECT_EQ(*r.sent[i], 9);
	}

	/* another batch on the same chunks sends all of them again */
	EXPECT_EQ(run(&r, 10, 6), 0);
	EXPECT_EQ(r.fx.calls, 6);
}

static void test_run_stops_at_the_first_failure(void)
{
	struct tx_run r;
	uint32_t i;
	int status;

	/* the device went away: nothing more is sent, and no RETRY */
	tx_run_init(&r, 6);
	r.fx.result[0] = -ENXIO;
	status = run(&r, 11, 6);
	EXPECT_EQ(status, -ENXIO);
	EXPECT_EQ(r.fx.calls, 1);
	EXPECT_EQ(r.err[0], -ENXIO);
	for (i = 1; i < 6; i++)
		EXPECT_EQ(r.err[i], -ECANCELED);
	for (i = 0; i < 6; i++)
		EXPECT_EQ(*r.sent[i], 0);
	EXPECT_EQ(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP, 0, status), false);

	/* a dropped frame (-EBUSY) is not retryable either */
	tx_run_init(&r, 6);
	r.fx.result[5] = -EBUSY;
	status = run(&r, 12, 6);
	EXPECT_EQ(status, -EBUSY);
	EXPECT_EQ(r.fx.calls, 6);
	EXPECT_EQ(xdev_ext_mech_retry_ok(XDEV_EXT_MECH_CLASS_AFXDP, 0, status), false);
}

static void test_run_without_a_batch_id_never_skips(void)
{
	struct tx_run r;

	tx_run_init(&r, 6);
	r.fx.result[2] = -EAGAIN;
	EXPECT_EQ(run(&r, 0, 6), -EAGAIN);
	EXPECT_EQ(r.fx.calls, 3);
	EXPECT_EQ(run(&r, 0, 6), 0);
	EXPECT_EQ(r.fx.calls, 6);
}

static void test_stage_admission(void)
{
	const uint32_t rx = XDEV_EXT_MECH_DIR_FROM_DEVICE;
	const uint32_t tx = XDEV_EXT_MECH_DIR_TO_DEVICE;

	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(rx, 0, true, true, false), 0);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(tx, 1, true, true, false), 0);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(tx, 0, true, true, false), 0);
	/* RX feeds the chain: stage 0 only */
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(rx, 1, true, true, false), -EINVAL);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(2, 1, true, true, false), -EINVAL);
	/* an unbound socket, or one without the stage's ring */
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(tx, 1, false, true, false), -ENXIO);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(tx, 1, true, false, false), -ENXIO);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(rx, 0, true, false, false), -ENXIO);
	/* one stage per direction and socket */
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(tx, 1, true, true, true), -EBUSY);
	EXPECT_EQ(xsk_xdev_ext_mech_stage_check(rx, 0, true, true, true), -EBUSY);
}

int main(void)
{
	test_validator_accepts_the_s2_batch();
	test_validator_needs_one_descriptor_per_frame();
	test_validator_rejects_each_field();
	test_validator_bounds_the_mtu();
	test_ipv4_checksum();
	test_run_sends_every_frame_once_in_slot_order();
	test_retry_resumes_after_the_frames_on_the_wire();
	test_run_stops_at_the_first_failure();
	test_run_without_a_batch_id_never_skips();
	test_stage_admission();

	if (tests_failed) {
		fprintf(stderr, "FAIL: %u of %u checks failed\n",
			tests_failed, tests_run);
		return 1;
	}
	printf("PASS: %u AF_XDP mechanism TX checks\n", tests_run);
	return 0;
}
