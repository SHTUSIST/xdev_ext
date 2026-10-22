// SPDX-License-Identifier: GPL-2.0
/*
 * Differential check: the send-path baseline must accept exactly the UDP
 * payloads that nvme_xdp_pipeline's RX-write path accepts.  This test compiles
 * the pipeline itself (as nvme_xdp_pipeline_adapter_test does), builds every
 * candidate into a full Ethernet/IPv4/UDP frame with the pipeline's
 * build_packet(), and compares the pipeline's verdict
 * (parse_wire_packet() + pipeline_validate_rx_packet()) with the baseline's
 * spb_payload_parse() on the same UDP payload.  Sender-side layouts use the
 * pipeline's own FRAME_SIZE / NXP_LAYOUT_DATA_OFFSET / NXP_VECTOR_ALIGNMENT.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define main nvme_xdp_pipeline_program_main
#include "../../../../nvme_xdp_pipeline.c"
#undef main

#include "../../../xdev_ext_sendpath_baseline_core.h"

#define TEST_SESSION UINT64_C(0x0123456789abcdef)
#define TEST_FRAME_BYTES 16384
#define TEST_PAYLOAD_MAX 10000

static unsigned int checks;
static unsigned int failures;
static unsigned int compared;
static unsigned int both_accepted;

#define EXPECT_EQ(actual, expected) do {                                      \
	long long _actual = (long long)(actual);                               \
	long long _expected = (long long)(expected);                           \
	checks++;                                                               \
	if (_actual != _expected) {                                             \
		fprintf(stderr, "%s:%d: got %lld, expected %lld\n",              \
			__func__, __LINE__, _actual, _expected);                       \
		failures++;                                                        \
	}                                                                        \
} while (0)

static uint8_t frame_storage[TEST_FRAME_BYTES] __attribute__((aligned(4096)));
static uint8_t payload_storage[TEST_PAYLOAD_MAX];
static uint8_t data_storage[65536];

static void test_ctx_init(struct pipeline_ctx *ctx, uint64_t session,
			  uint32_t mtu)
{
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->dst_mac, "\x02\x00\x00\x00\x00\x01", 6);
	memcpy(ctx->src_mac, "\x02\x00\x00\x00\x00\x02", 6);
	ctx->dst_ip = htonl(UINT32_C(0x0a000001));
	ctx->src_ip = htonl(UINT32_C(0x0a000002));
	ctx->dst_port = 12345;
	ctx->src_port = 54321;
	ctx->session_id = session;
	ctx->mtu = mtu;
}

/* Pipeline verdict for one UDP payload delivered as an ordinary frame. */
static int pipeline_verdict(struct pipeline_ctx *ctx, const uint8_t *payload,
			    size_t len, struct nxp_wire_segment *segment)
{
	struct pipeline_rx_packet packet;
	size_t packet_len;
	int ret;

	if (len > TEST_FRAME_BYTES - PKT_START_OFF - PKT_HDR_SIZE)
		return -E2BIG;
	memset(frame_storage, 0, sizeof(frame_storage));
	packet_len = build_packet(ctx, frame_storage, (void *)payload, len);
	ret = parse_wire_packet(ctx, frame_storage + PKT_START_OFF,
				(uint32_t)packet_len, &packet);
	if (ret)
		return ret;
	ret = pipeline_validate_rx_packet(ctx, &packet);
	if (ret)
		return ret;
	*segment = packet.segment;
	return 0;
}

static void compare_payload(struct pipeline_ctx *ctx,
			    const struct spb_config *config,
			    const uint8_t *payload, size_t len, int line)
{
	struct nxp_wire_segment pipeline_segment = { 0 }, baseline_segment = { 0 };
	enum spb_drop_reason reason;
	const uint8_t *data = NULL;
	int pipeline_ret, baseline_ret;

	g_block_size = config->bytes;
	pipeline_ret = pipeline_verdict(ctx, payload, len, &pipeline_segment);
	baseline_ret = spb_payload_parse(config, payload, len,
					 &baseline_segment, &data, &reason);
	compared++;
	checks++;
	if (!pipeline_ret != !baseline_ret) {
		fprintf(stderr,
			"line %d: verdict mismatch len=%zu pipeline=%d baseline=%d\n",
			line, len, pipeline_ret, baseline_ret);
		failures++;
		return;
	}
	if (pipeline_ret)
		return;
	both_accepted++;
	/* Field by field: the structure has padding after the enum. */
	EXPECT_EQ(pipeline_segment.direction, baseline_segment.direction);
	EXPECT_EQ(pipeline_segment.session_id, baseline_segment.session_id);
	EXPECT_EQ(pipeline_segment.generation, baseline_segment.generation);
	EXPECT_EQ(pipeline_segment.segment_index, baseline_segment.segment_index);
	EXPECT_EQ(pipeline_segment.segment_count, baseline_segment.segment_count);
	EXPECT_EQ(pipeline_segment.total_len, baseline_segment.total_len);
	EXPECT_EQ(pipeline_segment.relative_offset,
		  baseline_segment.relative_offset);
	EXPECT_EQ(pipeline_segment.payload_len, baseline_segment.payload_len);
	EXPECT_EQ(data == payload + NXP_WIRE_HEADER_LEN, 1);
}

static size_t encode(const struct nxp_wire_layout *layout,
		     enum nxp_io_direction direction, uint16_t index,
		     uint8_t *out)
{
	struct nxp_wire_segment segment;
	struct nxp_wire_span span;

	if (nxp_wire_segment_at(layout, direction, index, &segment))
		return 0;
	span.data = data_storage + segment.relative_offset;
	span.len = segment.payload_len;
	if (nxp_wire_header_encode(out, NXP_WIRE_HEADER_LEN, &segment, &span, 1))
		return 0;
	memcpy(out + NXP_WIRE_HEADER_LEN, span.data, span.len);
	return NXP_WIRE_HEADER_LEN + span.len;
}

static void test_mirrored_constants_equal_the_pipeline(void)
{
	EXPECT_EQ(SPB_PIPELINE_FRAME_SIZE, FRAME_SIZE);
	EXPECT_EQ(SPB_PIPELINE_RX_DATA_OFFSET, NXP_LAYOUT_DATA_OFFSET);
	EXPECT_EQ(SPB_PIPELINE_VECTOR_ALIGNMENT, NXP_VECTOR_ALIGNMENT);
	EXPECT_EQ(SPB_GROUP_TIMEOUT_NS, NXP_RX_GROUP_TIMEOUT_NS);
	EXPECT_EQ(SPB_IDLE_TIMEOUT_NS, NXP_RX_IDLE_TIMEOUT_NS);
	EXPECT_EQ(SPB_MAX_DEPTH, MAX_INFLIGHT);
}

/* Every segment the pipeline's sender would emit, for a sweep of sender MTUs,
 * request sizes, directions, sessions, and generations, against receivers
 * configured for two path MTUs. */
static void test_sender_layout_sweep(void)
{
	static const uint32_t sender_mtus[] = { 576, 1000, 1500, 2000, 4000, 9000 };
	static const uint32_t receiver_mtus[] = { 1500, 9000 };
	static const uint32_t sizes[] = { 4096, 8192, 12288 };
	static const uint32_t generations[] = { 1, 7 };
	static const uint64_t sessions[] = { TEST_SESSION, TEST_SESSION + 1 };
	static const enum nxp_io_direction directions[] = {
		NXP_IO_WRITE, NXP_IO_READ,
	};
	struct pipeline_ctx ctx;

	for (size_t r = 0; r < sizeof(receiver_mtus) / sizeof(receiver_mtus[0]); r++) {
		struct spb_config config = {
			.session_id = TEST_SESSION,
			.start_lba = 0,
			.capacity_lbas = UINT64_C(1) << 20,
			.lba_size = 512,
			.bytes = 8192,
			.mtu = receiver_mtus[r],
			.groups = 4,
			.depth = 1,
			.group_timeout_ns = SPB_GROUP_TIMEOUT_NS,
		};

		test_ctx_init(&ctx, TEST_SESSION, receiver_mtus[r]);
		for (size_t m = 0; m < sizeof(sender_mtus) / sizeof(sender_mtus[0]); m++)
		for (size_t z = 0; z < sizeof(sizes) / sizeof(sizes[0]); z++)
		for (size_t g = 0; g < sizeof(generations) / sizeof(generations[0]); g++)
		for (size_t s = 0; s < sizeof(sessions) / sizeof(sessions[0]); s++)
		for (size_t d = 0; d < sizeof(directions) / sizeof(directions[0]); d++) {
			struct nxp_wire_layout layout;

			if (nxp_wire_mtu_layout_plan(sessions[s], generations[g],
						     sizes[z], sender_mtus[m],
						     FRAME_SIZE,
						     NXP_LAYOUT_DATA_OFFSET,
						     NXP_VECTOR_ALIGNMENT,
						     &layout))
				continue;
			for (uint16_t i = 0; i < layout.segment_count; i++) {
				size_t len = encode(&layout, directions[d], i,
						    payload_storage);

				if (!len)
					continue;
				compare_payload(&ctx, &config, payload_storage,
						len, __LINE__);
			}
		}
	}
}

/* Single-byte header corruptions, with and without a recomputed CRC, and
 * truncations/extensions of one valid datagram. */
static void test_corruption_sweep(void)
{
	struct spb_config config = {
		.session_id = TEST_SESSION,
		.capacity_lbas = UINT64_C(1) << 20,
		.lba_size = 512,
		.bytes = 8192,
		.mtu = 1500,
		.groups = 4,
		.depth = 1,
		.group_timeout_ns = SPB_GROUP_TIMEOUT_NS,
	};
	static const uint8_t flips[] = { 0x01, 0x80, 0xff };
	struct nxp_wire_layout layout;
	struct pipeline_ctx ctx;
	uint8_t valid[TEST_PAYLOAD_MAX];
	size_t valid_len;

	test_ctx_init(&ctx, TEST_SESSION, config.mtu);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_SESSION, 3, config.bytes,
					   config.mtu, FRAME_SIZE,
					   NXP_LAYOUT_DATA_OFFSET,
					   NXP_VECTOR_ALIGNMENT, &layout), 0);
	for (uint16_t index = 0; index < layout.segment_count; index++) {
		valid_len = encode(&layout, NXP_IO_WRITE, index, valid);
		EXPECT_EQ(valid_len > 0, 1);
		if (!valid_len)
			return;
		for (size_t byte = 0; byte < NXP_WIRE_HEADER_LEN; byte++) {
			for (size_t f = 0; f < sizeof(flips); f++) {
				struct nxp_wire_span span;

				memcpy(payload_storage, valid, valid_len);
				payload_storage[byte] ^= flips[f];
				compare_payload(&ctx, &config, payload_storage,
						valid_len, __LINE__);
				if (byte >= 36)
					continue;
				span.data = payload_storage + NXP_WIRE_HEADER_LEN;
				span.len = (uint32_t)(valid_len - NXP_WIRE_HEADER_LEN);
				nxp_wire_put_be32(payload_storage + 36,
						  nxp_wire_checksum(payload_storage,
								    &span, 1));
				compare_payload(&ctx, &config, payload_storage,
						valid_len, __LINE__);
			}
		}
		for (size_t len = 0; len <= valid_len + 2; len++) {
			memcpy(payload_storage, valid, valid_len);
			payload_storage[valid_len] = 0;
			payload_storage[valid_len + 1] = 0;
			compare_payload(&ctx, &config, payload_storage, len,
					__LINE__);
		}
	}
}

int main(void)
{
	for (size_t i = 0; i < sizeof(data_storage); i++)
		data_storage[i] = (uint8_t)(i * 131u + 7u);
	test_mirrored_constants_equal_the_pipeline();
	test_sender_layout_sweep();
	test_corruption_sweep();
	EXPECT_EQ(compared > 1000, 1);
	EXPECT_EQ(both_accepted > 10, 1);

	if (failures) {
		fprintf(stderr, "FAIL: %u of %u checks (%u payloads compared)\n",
			failures, checks, compared);
		return 1;
	}
	printf("PASS: %u checks (%u payloads compared, %u accepted by both)\n",
	       checks, compared, both_accepted);
	return 0;
}
