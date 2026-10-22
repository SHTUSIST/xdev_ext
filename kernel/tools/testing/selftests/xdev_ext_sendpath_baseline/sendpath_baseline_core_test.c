// SPDX-License-Identifier: GPL-2.0
/*
 * Pure-core tests for the traditional send-path baseline (UDP recv() ->
 * O_DIRECT write).  Every datagram payload below is produced with the
 * nvme_xdp_pipeline core's own wire helpers (nxp_wire_mtu_layout_plan,
 * nxp_wire_segment_at, nxp_wire_header_encode), so a passing run shows that
 * the baseline accepts the same wire v2 format as the XDEV_EXT sender and rejects
 * the same malformed, stale, duplicate, and out-of-order inputs.
 *
 * The tier-defining properties are also checked here, without a device:
 * the O_DIRECT requirement on the target's open flags, the io_uring write
 * opcode each tier prepares, that up to depth writes stay outstanding while
 * completions are withheld (and no more), and that a partition is refused
 * as a target by the same sysfs placement test as nvme_xdp_pipeline (against
 * a fake sysfs tree below a temporary directory, never the real /sys).
 */
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "../../../xdev_ext_sendpath_baseline_core.h"

#define TEST_SESSION UINT64_C(0x1122334455667788)
#define TEST_BYTES UINT32_C(8192)
#define TEST_MTU UINT32_C(1500)
#define TEST_MAX_SEGMENTS 16
#define TEST_MAX_DEPTH 8
#define TEST_DATAGRAM_MAX 4096

static unsigned int checks;
static unsigned int failures;

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

#define EXPECT_TRUE(value) EXPECT_EQ(!!(value), 1)
#define EXPECT_FALSE(value) EXPECT_EQ(!!(value), 0)

struct test_datagram {
	uint8_t bytes[TEST_DATAGRAM_MAX];
	size_t len;
	uint16_t index;
};

struct test_group {
	uint8_t data[TEST_BYTES];
	struct nxp_wire_layout layout;
	struct test_datagram datagrams[TEST_MAX_SEGMENTS];
	uint16_t count;
};

struct test_rx {
	struct spb_receiver rx;
	struct spb_group groups[TEST_MAX_DEPTH];
	uint8_t storage[TEST_MAX_DEPTH][TEST_BYTES];
	uint8_t *buffers[TEST_MAX_DEPTH];
};

static void fill_pattern(uint8_t *data, size_t len, uint32_t seed)
{
	uint32_t state = seed * UINT32_C(2654435761) + 1;

	for (size_t i = 0; i < len; i++) {
		state = state * UINT32_C(1103515245) + UINT32_C(12345);
		data[i] = (uint8_t)(state >> 16);
	}
}

/* Encode one ordinary datagram payload exactly as the XDEV_EXT sender does. */
static int encode_datagram(const struct nxp_wire_layout *layout,
			   enum nxp_io_direction direction, uint16_t index,
			   const uint8_t *data, struct test_datagram *out)
{
	struct nxp_wire_segment segment;
	struct nxp_wire_span span;
	int ret;

	ret = nxp_wire_segment_at(layout, direction, index, &segment);
	if (ret)
		return ret;
	if (NXP_WIRE_HEADER_LEN + (size_t)segment.payload_len > sizeof(out->bytes))
		return -E2BIG;
	span.data = data + segment.relative_offset;
	span.len = segment.payload_len;
	ret = nxp_wire_header_encode(out->bytes, sizeof(out->bytes), &segment,
				     &span, 1);
	if (ret)
		return ret;
	memcpy(out->bytes + NXP_WIRE_HEADER_LEN, span.data, span.len);
	out->len = NXP_WIRE_HEADER_LEN + span.len;
	out->index = index;
	return 0;
}

static int build_group_mtu(struct test_group *group, uint64_t session,
			   uint32_t generation, uint32_t mtu, uint32_t bytes,
			   uint32_t seed, enum nxp_io_direction direction)
{
	int ret;

	memset(group, 0, sizeof(*group));
	fill_pattern(group->data, sizeof(group->data), seed);
	ret = nxp_wire_mtu_layout_plan(session, generation, bytes, mtu,
				       SPB_PIPELINE_FRAME_SIZE,
				       SPB_PIPELINE_RX_DATA_OFFSET,
				       SPB_PIPELINE_VECTOR_ALIGNMENT,
				       &group->layout);
	if (ret)
		return ret;
	if (group->layout.segment_count > TEST_MAX_SEGMENTS)
		return -E2BIG;
	for (uint16_t i = 0; i < group->layout.segment_count; i++) {
		ret = encode_datagram(&group->layout, direction, i, group->data,
				      &group->datagrams[i]);
		if (ret)
			return ret;
	}
	group->count = group->layout.segment_count;
	return 0;
}

static int build_group(struct test_group *group, uint32_t generation,
		       uint32_t seed)
{
	return build_group_mtu(group, TEST_SESSION, generation, TEST_MTU,
			       TEST_BYTES, seed, NXP_IO_WRITE);
}

/* Rewrite selected header fields and recompute the CRC, producing a datagram
 * that is checksum-valid but semantically wrong. */
static void rewrite_header(struct test_datagram *datagram, uint16_t index,
			   uint16_t count, uint32_t offset)
{
	struct nxp_wire_span span = {
		.data = datagram->bytes + NXP_WIRE_HEADER_LEN,
		.len = (uint32_t)(datagram->len - NXP_WIRE_HEADER_LEN),
	};
	uint32_t checksum;

	nxp_wire_put_be16(datagram->bytes + 20, index);
	nxp_wire_put_be16(datagram->bytes + 22, count);
	nxp_wire_put_be32(datagram->bytes + 28, offset);
	checksum = nxp_wire_checksum(datagram->bytes, &span, 1);
	nxp_wire_put_be32(datagram->bytes + 36, checksum);
}

static struct spb_config base_config(void)
{
	return (struct spb_config) {
		.session_id = TEST_SESSION,
		.start_lba = 1000,
		.capacity_lbas = UINT64_C(1) << 20,
		.lba_size = 512,
		.bytes = TEST_BYTES,
		.mtu = TEST_MTU,
		.groups = 8,
		.depth = 2,
		.group_timeout_ns = SPB_GROUP_TIMEOUT_NS,
	};
}

static int rx_init(struct test_rx *t, const struct spb_config *config)
{
	memset(t, 0, sizeof(*t));
	for (int i = 0; i < TEST_MAX_DEPTH; i++)
		t->buffers[i] = t->storage[i];
	return spb_receiver_init(&t->rx, config, t->groups, t->buffers);
}

static int feed(struct test_rx *t, const struct test_datagram *datagram,
		uint64_t now_ns, struct spb_feed_result *result)
{
	return spb_receiver_feed(&t->rx, datagram->bytes, datagram->len, now_ns,
				 result);
}

static uint64_t total_dropped(const struct spb_counters *counters)
{
	uint64_t sum = 0;

	for (int i = 0; i < SPB_DROP_REASON_COUNT; i++)
		sum += counters->dropped[i];
	return sum;
}

static void expect_counter_identity(const struct spb_counters *counters)
{
	EXPECT_EQ(counters->packets_dropped, total_dropped(counters));
	EXPECT_EQ(counters->datagrams,
		  counters->packets_accepted + counters->packets_dropped);
}

/* The reassembled write buffer must equal the sent logical request. */
static void expect_group_bytes(const struct spb_group *group,
			       const uint8_t *expected)
{
	EXPECT_TRUE(group->buffer != NULL);
	if (group->buffer)
		EXPECT_EQ(memcmp(group->buffer, expected, TEST_BYTES), 0);
}

static void test_pipeline_layout_mirror(void)
{
	struct nxp_wire_layout layout = { 0 };

	/* nvme_xdp_pipeline.c documents the default 8 KiB transfer at MTU 1500
	 * as six frames; the derived RX data offset is 360 bytes. */
	EXPECT_EQ(SPB_PIPELINE_FRAME_SIZE, 4096);
	EXPECT_EQ(SPB_PIPELINE_RX_DATA_OFFSET, 360);
	EXPECT_EQ(SPB_PIPELINE_VECTOR_ALIGNMENT, 8);
	EXPECT_EQ(SPB_GROUP_TIMEOUT_NS, UINT64_C(1000000000));
	EXPECT_EQ(SPB_IDLE_TIMEOUT_NS, UINT64_C(5000000000));
	EXPECT_EQ(SPB_MAX_DEPTH, 2048);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_SESSION, 1, TEST_BYTES, TEST_MTU,
					   SPB_PIPELINE_FRAME_SIZE,
					   SPB_PIPELINE_RX_DATA_OFFSET,
					   SPB_PIPELINE_VECTOR_ALIGNMENT,
					   &layout), 0);
	EXPECT_EQ(layout.segment_count, 6);
	EXPECT_EQ(layout.segment_data_limit, 1432);
}

static void test_config_validation_mirrors_pipeline_geometry(void)
{
	struct spb_config config = base_config();
	struct spb_config bad;
	struct nxp_wire_layout layout = { 0 };

	EXPECT_EQ(spb_config_validate(&config, &layout), 0);
	EXPECT_EQ(layout.segment_count, 6);
	EXPECT_EQ(spb_config_validate(NULL, &layout), -EINVAL);

	bad = config;
	bad.session_id = 0;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.lba_size = 256;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.lba_size = 1536;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.bytes = 8192 + 512 / 2;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.bytes = 0;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.lba_size = 16384;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.groups = 0;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.depth = 0;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.depth = SPB_MAX_DEPTH + 1;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.group_timeout_ns = 0;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EINVAL);
	bad = config;
	bad.mtu = NXP_WIRE_IPV4_UDP_LEN + NXP_WIRE_HEADER_LEN;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EMSGSIZE);
	/* The window [start_lba, start_lba + groups * 16) must fit. */
	bad = config;
	bad.capacity_lbas = config.start_lba + config.groups * 16 - 1;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -ERANGE);
	bad.capacity_lbas++;
	EXPECT_EQ(spb_config_validate(&bad, &layout), 0);
	bad = config;
	bad.start_lba = UINT64_MAX - 8;
	bad.capacity_lbas = UINT64_MAX;
	EXPECT_EQ(spb_config_validate(&bad, &layout), -EOVERFLOW);
}

static void test_local_window_is_the_only_lba_source(void)
{
	struct spb_config config = base_config();
	uint64_t lba = 0, offset = 0;

	EXPECT_EQ(spb_local_lba(&config, 0, &lba, &offset), 0);
	EXPECT_EQ(lba, 1000);
	EXPECT_EQ(offset, UINT64_C(1000) * 512);
	EXPECT_EQ(spb_local_lba(&config, 7, &lba, &offset), 0);
	EXPECT_EQ(lba, 1000 + 7 * 16);
	EXPECT_EQ(offset, (uint64_t)(1000 + 7 * 16) * 512);
	EXPECT_EQ(spb_local_lba(&config, 8, &lba, &offset), -EACCES);

	config.lba_size = 4096;
	config.start_lba = 7;
	EXPECT_EQ(spb_local_lba(&config, 3, &lba, &offset), 0);
	EXPECT_EQ(lba, 7 + 3 * 2);
	EXPECT_EQ(offset, (uint64_t)(7 + 3 * 2) * 4096);
}

static void test_in_order_group_completes_with_local_lba(void)
{
	static struct test_group group;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };

	EXPECT_EQ(build_group(&group, 1, 11), 0);
	EXPECT_EQ(group.count, 6);
	EXPECT_EQ(rx_init(&t, &config), 0);
	EXPECT_TRUE(spb_receiver_can_accept(&t.rx));
	for (uint16_t i = 0; i < group.count; i++) {
		EXPECT_EQ(feed(&t, &group.datagrams[i], 100 + i, &result), 0);
		EXPECT_EQ(result.outcome, i + 1 == group.count ?
			  SPB_FEED_COMPLETED : SPB_FEED_ACCEPTED);
	}
	EXPECT_TRUE(result.group >= 0 && result.group < (int)config.depth);
	if (result.group < 0 || result.group >= (int)config.depth)
		return;
	EXPECT_EQ(t.groups[result.group].state, SPB_GROUP_READY);
	EXPECT_EQ(t.groups[result.group].request_index, 0);
	EXPECT_EQ(t.groups[result.group].lba, config.start_lba);
	EXPECT_EQ(t.groups[result.group].byte_offset, config.start_lba * 512);
	EXPECT_EQ(t.groups[result.group].first_accept_ns, 100);
	expect_group_bytes(&t.groups[result.group], group.data);
	EXPECT_EQ(t.rx.counters.packets_accepted, 6);
	EXPECT_EQ(t.rx.counters.packets_dropped, 0);
	EXPECT_EQ(t.rx.counters.groups_completed, 1);
	expect_counter_identity(&t.rx.counters);
}

static void test_reordered_group_is_never_ready_until_ordered_retry(void)
{
	static const uint16_t shuffled[] = { 1, 0, 2, 3, 4, 5 };
	static struct test_group group;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	int ready = -1;

	EXPECT_EQ(build_group(&group, 1, 12), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	/* Segment 1 begins the group but is a future segment; 0 is accepted;
	 * 2..5 are then future segments again because 1 is still missing. */
	for (size_t i = 0; i < sizeof(shuffled) / sizeof(shuffled[0]); i++) {
		EXPECT_EQ(feed(&t, &group.datagrams[shuffled[i]], 10, &result), 0);
		EXPECT_TRUE(result.outcome != SPB_FEED_COMPLETED);
		if (shuffled[i] == 0) {
			EXPECT_EQ(result.outcome, SPB_FEED_ACCEPTED);
		} else {
			EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
			EXPECT_EQ(result.reason, SPB_DROP_OUT_OF_ORDER);
			EXPECT_EQ(result.error, -EPIPE);
		}
	}
	EXPECT_EQ(t.rx.counters.groups_completed, 0);
	EXPECT_EQ(t.rx.counters.packets_accepted, 1);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_OUT_OF_ORDER], 5);

	/* Same-generation ordered retry: 0 is a duplicate, 1..5 complete it. */
	for (uint16_t i = 0; i < group.count; i++) {
		EXPECT_EQ(feed(&t, &group.datagrams[i], 20, &result), 0);
		if (i == 0) {
			EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
			EXPECT_EQ(result.reason, SPB_DROP_DUPLICATE);
		}
		if (result.outcome == SPB_FEED_COMPLETED)
			ready = result.group;
	}
	EXPECT_TRUE(ready >= 0);
	if (ready < 0)
		return;
	expect_group_bytes(&t.groups[ready], group.data);
	EXPECT_EQ(t.groups[ready].first_accept_ns, 10);
	EXPECT_EQ(t.rx.counters.packets_accepted, 6);
	EXPECT_EQ(t.rx.counters.packets_dropped, 6);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_DUPLICATE], 1);
	expect_counter_identity(&t.rx.counters);
}

static void test_duplicates_are_dropped_without_corrupting_the_group(void)
{
	static struct test_group group;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	int ready = -1;

	EXPECT_EQ(build_group(&group, 1, 13), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	for (uint16_t i = 0; i < group.count; i++) {
		EXPECT_EQ(feed(&t, &group.datagrams[i], 1, &result), 0);
		if (result.outcome == SPB_FEED_COMPLETED)
			ready = result.group;
		if (i == 2) {
			EXPECT_EQ(feed(&t, &group.datagrams[2], 1, &result), 0);
			EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
			EXPECT_EQ(result.reason, SPB_DROP_DUPLICATE);
			EXPECT_EQ(result.error, -EALREADY);
		}
	}
	EXPECT_TRUE(ready >= 0);
	if (ready >= 0)
		expect_group_bytes(&t.groups[ready], group.data);
	/* A datagram of the already committed generation is a duplicate. */
	EXPECT_EQ(feed(&t, &group.datagrams[5], 2, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
	EXPECT_EQ(result.reason, SPB_DROP_DUPLICATE);
	EXPECT_EQ(t.rx.counters.packets_accepted, 6);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_DUPLICATE], 2);
	EXPECT_EQ(t.rx.counters.packets_dropped, 2);
	expect_counter_identity(&t.rx.counters);
}

static void test_truncated_and_malformed_payloads_are_dropped(void)
{
	static struct test_group group;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	struct test_datagram datagram;

	EXPECT_EQ(build_group(&group, 1, 14), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);

	/* Shorter than the 40-byte NXP2 header. */
	datagram = group.datagrams[0];
	datagram.len = NXP_WIRE_HEADER_LEN - 1;
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
	EXPECT_EQ(result.reason, SPB_DROP_TRUNCATED);
	/* Header only: no payload bytes. */
	datagram.len = NXP_WIRE_HEADER_LEN;
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_TRUNCATED);
	/* Payload shorter than the header's payload_len field. */
	datagram = group.datagrams[0];
	datagram.len -= 100;
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
	EXPECT_EQ(result.reason, SPB_DROP_TRUNCATED);
	EXPECT_EQ(result.error, -EMSGSIZE);
	/* Wrong magic. */
	datagram = group.datagrams[0];
	datagram.bytes[0] ^= 0xff;
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_MALFORMED);
	EXPECT_EQ(result.error, -EPROTO);
	/* Wrong version. */
	datagram = group.datagrams[0];
	datagram.bytes[4] = NXP_WIRE_VERSION + 1;
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_MALFORMED);
	EXPECT_EQ(result.error, -EPROTONOSUPPORT);
	/* Out-of-range segment index (index == count), CRC recomputed. */
	datagram = group.datagrams[5];
	rewrite_header(&datagram, 6, 6, 5 * 1432);
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_MALFORMED);
	/* Offset that runs past total_len, CRC recomputed. */
	datagram = group.datagrams[1];
	rewrite_header(&datagram, 1, 6, TEST_BYTES - 10);
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_MALFORMED);

	EXPECT_EQ(t.rx.counters.packets_accepted, 0);
	EXPECT_EQ(t.rx.counters.packets_dropped, 7);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_TRUNCATED], 3);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_MALFORMED], 4);
	EXPECT_EQ(t.rx.counters.groups_completed, 0);
	expect_counter_identity(&t.rx.counters);
}

static void test_crc_mismatch_is_dropped(void)
{
	static struct test_group group;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	struct test_datagram datagram;

	EXPECT_EQ(build_group(&group, 1, 15), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	datagram = group.datagrams[0];
	datagram.bytes[NXP_WIRE_HEADER_LEN + 17] ^= 0x01;
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
	EXPECT_EQ(result.reason, SPB_DROP_CHECKSUM);
	EXPECT_EQ(result.error, -EBADMSG);
	datagram = group.datagrams[0];
	datagram.bytes[36] ^= 0x80;
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_CHECKSUM);
	/* Header field changed without recomputing the CRC. */
	datagram = group.datagrams[0];
	datagram.bytes[17] ^= 0x01;
	EXPECT_EQ(feed(&t, &datagram, 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_CHECKSUM);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_CHECKSUM], 3);
	EXPECT_EQ(t.rx.counters.packets_accepted, 0);
	expect_counter_identity(&t.rx.counters);
}

static void test_session_direction_and_layout_are_checked(void)
{
	static struct test_group foreign, read_group, wide, narrow, short_total;
	static struct test_group group;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };

	EXPECT_EQ(build_group(&group, 1, 16), 0);
	EXPECT_EQ(build_group_mtu(&foreign, TEST_SESSION + 1, 1, TEST_MTU,
				  TEST_BYTES, 16, NXP_IO_WRITE), 0);
	EXPECT_EQ(build_group_mtu(&read_group, TEST_SESSION, 1, TEST_MTU,
				  TEST_BYTES, 16, NXP_IO_READ), 0);
	EXPECT_EQ(build_group_mtu(&wide, TEST_SESSION, 1, 9000, TEST_BYTES, 16,
				  NXP_IO_WRITE), 0);
	EXPECT_EQ(build_group_mtu(&narrow, TEST_SESSION, 1, 1000, TEST_BYTES, 16,
				  NXP_IO_WRITE), 0);
	EXPECT_EQ(build_group_mtu(&short_total, TEST_SESSION, 1, TEST_MTU, 4096,
				  16, NXP_IO_WRITE), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);

	EXPECT_EQ(feed(&t, &foreign.datagrams[0], 1, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
	EXPECT_EQ(result.reason, SPB_DROP_SESSION);
	EXPECT_EQ(result.error, -ESTALE);
	EXPECT_EQ(feed(&t, &read_group.datagrams[0], 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_DIRECTION);
	EXPECT_EQ(result.error, -EACCES);
	/* A 9000-MTU segment is larger than the configured 1500-byte path. */
	EXPECT_EQ(feed(&t, &wide.datagrams[0], 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_OVERSIZE);
	/* Boundary: payload + IPv4/UDP headers one byte over the path MTU. */
	{
		struct test_datagram over = group.datagrams[0];

		EXPECT_EQ(over.len + NXP_WIRE_IPV4_UDP_LEN, TEST_MTU);
		over.bytes[over.len++] = 0;
		EXPECT_EQ(feed(&t, &over, 1, &result), 0);
		EXPECT_EQ(result.reason, SPB_DROP_OVERSIZE);
	}
	/* A 1000-MTU segmentation is not the shape the pipeline expects. */
	EXPECT_EQ(feed(&t, &narrow.datagrams[0], 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_LAYOUT);
	/* total_len must equal the configured -B bytes. */
	EXPECT_EQ(feed(&t, &short_total.datagrams[0], 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_LAYOUT);

	/* None of these began a group: a clean group still completes. */
	for (uint16_t i = 0; i < group.count; i++)
		EXPECT_EQ(feed(&t, &group.datagrams[i], 2, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_COMPLETED);
	EXPECT_EQ(t.rx.counters.packets_accepted, 6);
	EXPECT_EQ(t.rx.counters.packets_dropped, 6);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_SESSION], 1);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_DIRECTION], 1);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_OVERSIZE], 2);
	EXPECT_EQ(t.rx.counters.dropped[SPB_DROP_LAYOUT], 2);
	expect_counter_identity(&t.rx.counters);
}

static void complete_group(struct test_rx *t, const struct test_group *group,
			   uint64_t now_ns, int *ready)
{
	struct spb_feed_result result = { 0 };

	*ready = -1;
	for (uint16_t i = 0; i < group->count; i++) {
		EXPECT_EQ(feed(t, &group->datagrams[i], now_ns, &result), 0);
		if (result.outcome == SPB_FEED_COMPLETED)
			*ready = result.group;
	}
	EXPECT_TRUE(*ready >= 0);
}

static void test_generation_rules_mirror_the_pipeline(void)
{
	static struct test_group g1, g2, g3, g4;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	int ready;

	config.depth = 4;
	EXPECT_EQ(build_group(&g1, 1, 21), 0);
	EXPECT_EQ(build_group(&g2, 2, 22), 0);
	EXPECT_EQ(build_group(&g3, 3, 23), 0);
	EXPECT_EQ(build_group(&g4, 4, 24), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);

	/* Generation 2 before generation 1 is a gap. */
	EXPECT_EQ(feed(&t, &g2.datagrams[0], 1, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_OUT_OF_ORDER);
	EXPECT_EQ(result.error, -EPIPE);
	complete_group(&t, &g1, 2, &ready);
	if (ready >= 0)
		EXPECT_EQ(t.groups[ready].lba, config.start_lba);
	complete_group(&t, &g2, 3, &ready);
	if (ready >= 0)
		EXPECT_EQ(t.groups[ready].lba, config.start_lba + 16);
	/* Older committed generation is stale; latest committed is duplicate. */
	EXPECT_EQ(feed(&t, &g1.datagrams[0], 4, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_STALE);
	EXPECT_EQ(result.error, -ESTALE);
	EXPECT_EQ(feed(&t, &g2.datagrams[0], 4, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_DUPLICATE);
	/* While generation 3 collects, a generation-4 datagram is stale for the
	 * active group (nxp_wire_group_accept compares the active generation). */
	EXPECT_EQ(feed(&t, &g3.datagrams[0], 5, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_ACCEPTED);
	EXPECT_EQ(feed(&t, &g4.datagrams[0], 5, &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_STALE);
	for (uint16_t i = 1; i < g3.count; i++)
		EXPECT_EQ(feed(&t, &g3.datagrams[i], 6, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_COMPLETED);
	if (result.outcome == SPB_FEED_COMPLETED)
		EXPECT_EQ(t.groups[result.group].lba, config.start_lba + 32);
	EXPECT_EQ(t.rx.counters.groups_completed, 3);
	EXPECT_EQ(t.rx.counters.packets_accepted, 18);
	EXPECT_EQ(t.rx.counters.packets_dropped, 4);
	expect_counter_identity(&t.rx.counters);
}

static void test_depth_bounds_outstanding_groups(void)
{
	static struct test_group g1, g2, g3;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	uint64_t datagrams_before;
	int first, second, third;

	config.depth = 2;
	EXPECT_EQ(build_group(&g1, 1, 31), 0);
	EXPECT_EQ(build_group(&g2, 2, 32), 0);
	EXPECT_EQ(build_group(&g3, 3, 33), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	complete_group(&t, &g1, 1, &first);
	complete_group(&t, &g2, 2, &second);
	if (first < 0 || second < 0)
		return;
	EXPECT_TRUE(first != second);
	EXPECT_FALSE(spb_receiver_can_accept(&t.rx));
	datagrams_before = t.rx.counters.datagrams;
	EXPECT_EQ(feed(&t, &g3.datagrams[0], 3, &result), -EBUSY);
	EXPECT_EQ(t.rx.counters.datagrams, datagrams_before);

	/* READY -> WRITING -> FREE; any other transition fails closed. */
	EXPECT_EQ(spb_receiver_complete(&t.rx, first), -EPROTO);
	EXPECT_EQ(spb_receiver_submit(&t.rx, first), 0);
	EXPECT_EQ(spb_receiver_submit(&t.rx, first), -EPROTO);
	EXPECT_FALSE(spb_receiver_can_accept(&t.rx));
	EXPECT_EQ(spb_receiver_complete(&t.rx, first), 0);
	EXPECT_EQ(spb_receiver_complete(&t.rx, first), -EPROTO);
	EXPECT_EQ(spb_receiver_submit(&t.rx, -1), -EINVAL);
	EXPECT_EQ(spb_receiver_submit(&t.rx, 2), -EINVAL);
	EXPECT_TRUE(spb_receiver_can_accept(&t.rx));
	complete_group(&t, &g3, 4, &third);
	EXPECT_EQ(third, first);
	if (third >= 0) {
		EXPECT_EQ(t.groups[third].request_index, 2);
		EXPECT_EQ(t.groups[third].lba, config.start_lba + 32);
		expect_group_bytes(&t.groups[third], g3.data);
	}
}

static void test_group_count_stops_acceptance(void)
{
	static struct test_group g1, g2;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	int ready;

	config.groups = 1;
	config.depth = 2;
	EXPECT_EQ(build_group(&g1, 1, 41), 0);
	EXPECT_EQ(build_group(&g2, 2, 42), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	complete_group(&t, &g1, 1, &ready);
	EXPECT_FALSE(spb_receiver_can_accept(&t.rx));
	EXPECT_EQ(feed(&t, &g2.datagrams[0], 2, &result), -EBUSY);
	if (ready >= 0) {
		EXPECT_EQ(spb_receiver_submit(&t.rx, ready), 0);
		EXPECT_EQ(spb_receiver_complete(&t.rx, ready), 0);
	}
	EXPECT_FALSE(spb_receiver_can_accept(&t.rx));
}

static void test_incomplete_group_expires_and_same_generation_retries(void)
{
	static struct test_group g1, g2;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	uint64_t t0 = UINT64_C(5000000000);
	int ready = -1;

	EXPECT_EQ(build_group(&g1, 1, 51), 0);
	EXPECT_EQ(build_group(&g2, 2, 52), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	EXPECT_EQ(spb_receiver_expire(&t.rx, t0), 0);
	EXPECT_EQ(feed(&t, &g1.datagrams[0], t0, &result), 0);
	EXPECT_EQ(feed(&t, &g1.datagrams[1], t0 + 10, &result), 0);
	EXPECT_EQ(spb_receiver_expire(&t.rx, t0 + SPB_GROUP_TIMEOUT_NS - 1), 0);
	EXPECT_EQ(spb_receiver_expire(&t.rx, t0 + SPB_GROUP_TIMEOUT_NS), 1);
	EXPECT_EQ(t.rx.counters.groups_expired, 1);
	EXPECT_EQ(spb_receiver_expire(&t.rx, t0 + 2 * SPB_GROUP_TIMEOUT_NS), 0);
	/* Generation was not committed: generation 2 is still a gap. */
	EXPECT_EQ(feed(&t, &g2.datagrams[0], t0 + SPB_GROUP_TIMEOUT_NS + 1,
		       &result), 0);
	EXPECT_EQ(result.reason, SPB_DROP_OUT_OF_ORDER);
	/* Retrying generation 1 from segment 0 completes request index 0. */
	for (uint16_t i = 0; i < g1.count; i++) {
		EXPECT_EQ(feed(&t, &g1.datagrams[i],
			       t0 + SPB_GROUP_TIMEOUT_NS + 100 + i, &result), 0);
		if (result.outcome == SPB_FEED_COMPLETED)
			ready = result.group;
	}
	EXPECT_TRUE(ready >= 0);
	if (ready >= 0) {
		EXPECT_EQ(t.groups[ready].request_index, 0);
		EXPECT_EQ(t.groups[ready].lba, config.start_lba);
		EXPECT_EQ(t.groups[ready].first_accept_ns,
			  t0 + SPB_GROUP_TIMEOUT_NS + 100);
		expect_group_bytes(&t.groups[ready], g1.data);
	}
	EXPECT_EQ(t.rx.counters.packets_accepted, 2 + 6);
	EXPECT_EQ(t.rx.counters.packets_dropped, 1);
	EXPECT_EQ(t.rx.counters.groups_completed, 1);
	expect_counter_identity(&t.rx.counters);
}

/* A group arrives with the datagram that completes it: that datagram's time
 * becomes the group's last_arrival_ns, where its post-arrival time starts,
 * and the receiver's last_arrival_ns, where rx_span_us ends.  The earlier
 * datagrams of the group, a duplicate dropped after it completed, and a
 * group that expired incomplete move neither. */
static void test_group_arrives_with_its_completing_datagram(void)
{
	static struct test_group g1, g2;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	uint64_t retry = UINT64_C(3000000000);
	int ready = -1;

	EXPECT_EQ(build_group(&g1, 1, 61), 0);
	EXPECT_EQ(build_group(&g2, 2, 62), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	EXPECT_EQ(t.rx.last_arrival_ns, 0);
	for (uint16_t i = 0; i + 1 < g1.count; i++) {
		EXPECT_EQ(feed(&t, &g1.datagrams[i], 100 + i, &result), 0);
		EXPECT_EQ(result.outcome, SPB_FEED_ACCEPTED);
		EXPECT_EQ(t.groups[result.group].last_arrival_ns, 0);
	}
	EXPECT_EQ(t.rx.last_arrival_ns, 0);
	EXPECT_EQ(feed(&t, &g1.datagrams[g1.count - 1], 900, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_COMPLETED);
	ready = result.group;
	EXPECT_TRUE(ready >= 0);
	if (ready < 0)
		return;
	EXPECT_EQ(t.groups[ready].first_accept_ns, 100);
	EXPECT_EQ(t.groups[ready].last_arrival_ns, 900);
	EXPECT_EQ(t.rx.last_arrival_ns, 900);
	EXPECT_EQ(feed(&t, &g1.datagrams[g1.count - 1], 950, &result), 0);
	EXPECT_EQ(result.outcome, SPB_FEED_DROPPED);
	EXPECT_EQ(result.reason, SPB_DROP_DUPLICATE);
	EXPECT_EQ(t.groups[ready].last_arrival_ns, 900);
	EXPECT_EQ(t.rx.last_arrival_ns, 900);

	/* Group 2 expires after two datagrams, then is retried whole. */
	EXPECT_EQ(feed(&t, &g2.datagrams[0], 1000, &result), 0);
	EXPECT_EQ(feed(&t, &g2.datagrams[1], 1010, &result), 0);
	EXPECT_EQ(spb_receiver_expire(&t.rx, 1000 + SPB_GROUP_TIMEOUT_NS), 1);
	EXPECT_EQ(t.rx.last_arrival_ns, 900);
	ready = -1;
	for (uint16_t i = 0; i < g2.count; i++) {
		EXPECT_EQ(feed(&t, &g2.datagrams[i], retry + i, &result), 0);
		if (result.outcome == SPB_FEED_COMPLETED)
			ready = result.group;
	}
	EXPECT_TRUE(ready >= 0);
	if (ready < 0)
		return;
	EXPECT_EQ(t.groups[ready].first_accept_ns, retry);
	EXPECT_EQ(t.groups[ready].last_arrival_ns, retry + g2.count - 1);
	EXPECT_EQ(t.rx.last_arrival_ns, retry + g2.count - 1);
	/* Completing the write frees the slot and clears its arrival; the
	 * receiver's last arrival stays. */
	EXPECT_EQ(spb_receiver_submit(&t.rx, ready), 0);
	EXPECT_EQ(spb_receiver_complete(&t.rx, ready), 0);
	EXPECT_EQ(t.groups[ready].last_arrival_ns, 0);
	EXPECT_EQ(t.rx.last_arrival_ns, retry + g2.count - 1);
}

/* The arrival fields of SENDPATH_BASELINE_SUMMARY on known times: the span
 * from the first datagram to the last group's arrival, the tail from there
 * to the end of wall_us, and nearest-rank post-arrival percentiles.  A time
 * of 0 has not been seen. */
static void test_arrival_report_on_known_times(void)
{
	struct spb_arrival_report report;
	uint64_t post[2] = { 700000, 250999 };
	uint64_t many[100];

	spb_arrival_report(1000000, 2000000, 2250999, post, 2, &report);
	EXPECT_EQ(report.rx_span_us, 1000);
	EXPECT_EQ(report.tail_us, 250);
	EXPECT_EQ(report.post_arrival_us_p50, 250);
	EXPECT_EQ(report.post_arrival_us_p99, 700);
	/* No group arrived: neither span nor tail. */
	spb_arrival_report(1000000, 0, 5000000, NULL, 0, &report);
	EXPECT_EQ(report.rx_span_us, 0);
	EXPECT_EQ(report.tail_us, 0);
	EXPECT_EQ(report.post_arrival_us_p50, 0);
	EXPECT_EQ(report.post_arrival_us_p99, 0);
	/* The end of wall_us is not after the arrival: no tail. */
	spb_arrival_report(1000000, 2000000, 2000000, NULL, 0, &report);
	EXPECT_EQ(report.rx_span_us, 1000);
	EXPECT_EQ(report.tail_us, 0);
	/* No first datagram: no span. */
	spb_arrival_report(0, 2000000, 3000000, NULL, 0, &report);
	EXPECT_EQ(report.rx_span_us, 0);
	EXPECT_EQ(report.tail_us, 1000);
	/* 100 samples of 1..100 us in descending order. */
	for (int i = 0; i < 100; i++)
		many[i] = (uint64_t)(100 - i) * UINT64_C(1000);
	spb_arrival_report(1, 2, 3, many, 100, &report);
	EXPECT_EQ(report.post_arrival_us_p50, 50);
	EXPECT_EQ(report.post_arrival_us_p99, 99);
}

static void test_target_must_be_open_o_direct(void)
{
	/* fcntl(F_GETFL) of the opened target: buffered I/O is refused. */
	EXPECT_EQ(spb_target_flags_check(O_RDWR | O_DIRECT), 0);
	EXPECT_EQ(spb_target_flags_check(O_RDWR | O_DIRECT | O_LARGEFILE), 0);
	EXPECT_EQ(spb_target_flags_check(O_RDWR), -EOPNOTSUPP);
	EXPECT_EQ(spb_target_flags_check(O_RDWR | O_DSYNC), -EOPNOTSUPP);
	EXPECT_EQ(spb_target_flags_check(-1), -EINVAL);
}

/* Tier 1 (uring) prepares IORING_OP_WRITE from the request buffer; tier 2
 * prepares IORING_OP_WRITE_FIXED on registered buffer index == slot.  The
 * operation the program counts is classified from the prepared SQE itself. */
static void test_uring_write_prep_matches_the_tier(void)
{
	static struct test_group group, group2, group3;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct io_uring_sqe sqe;
	enum spb_write_op op = SPB_WRITE_OP_COUNT;
	int ready, other;

	EXPECT_EQ(build_group(&group, 1, 71), 0);
	EXPECT_EQ(build_group(&group2, 2, 72), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	complete_group(&t, &group, 1, &ready);
	if (ready < 0)
		return;

	memset(&sqe, 0xa5, sizeof(sqe));
	EXPECT_EQ(spb_prep_uring_write(&t.rx, ready, 17, false, &sqe, &op), 0);
	EXPECT_EQ(sqe.opcode, IORING_OP_WRITE);
	EXPECT_EQ(op, SPB_WRITE_OP_WRITE);
	EXPECT_EQ(sqe.fd, 17);
	EXPECT_EQ(sqe.addr, (uint64_t)(uintptr_t)t.groups[ready].buffer);
	EXPECT_EQ(sqe.len, TEST_BYTES);
	EXPECT_EQ(sqe.off, t.groups[ready].byte_offset);
	EXPECT_EQ(sqe.off, config.start_lba * 512);
	EXPECT_EQ(sqe.flags, 0);
	EXPECT_EQ(sqe.user_data,
		  (t.groups[ready].request_index << 32) | (uint32_t)ready);

	memset(&sqe, 0xa5, sizeof(sqe));
	op = SPB_WRITE_OP_COUNT;
	EXPECT_EQ(spb_prep_uring_write(&t.rx, ready, 17, true, &sqe, &op), 0);
	EXPECT_EQ(sqe.opcode, IORING_OP_WRITE_FIXED);
	EXPECT_EQ(op, SPB_WRITE_OP_WRITE_FIXED);
	EXPECT_EQ(sqe.buf_index, ready);
	EXPECT_EQ(sqe.addr, (uint64_t)(uintptr_t)t.groups[ready].buffer);
	EXPECT_EQ(sqe.len, TEST_BYTES);
	EXPECT_EQ(sqe.off, t.groups[ready].byte_offset);

	/* Only the two write opcodes are counted; anything else fails closed. */
	EXPECT_EQ(spb_uring_write_op(IORING_OP_WRITE, &op), 0);
	EXPECT_EQ(op, SPB_WRITE_OP_WRITE);
	EXPECT_EQ(spb_uring_write_op(IORING_OP_WRITE_FIXED, &op), 0);
	EXPECT_EQ(op, SPB_WRITE_OP_WRITE_FIXED);
	EXPECT_EQ(spb_uring_write_op(IORING_OP_WRITEV, &op), -EPROTO);
	EXPECT_EQ(spb_uring_write_op(IORING_OP_READ_FIXED, &op), -EPROTO);
	EXPECT_EQ(spb_uring_write_op(IORING_OP_NOP, &op), -EPROTO);

	/* The count comes from the submitted SQE's own opcode. */
	sqe.opcode = IORING_OP_NOP;
	EXPECT_EQ(spb_receiver_issue_sqe(&t.rx, ready, &sqe), -EPROTO);
	EXPECT_EQ(t.groups[ready].state, SPB_GROUP_READY);
	EXPECT_EQ(spb_receiver_issue_sqe(&t.rx, ready, NULL), -EINVAL);
	sqe.opcode = IORING_OP_WRITE_FIXED;
	EXPECT_EQ(spb_receiver_issue_sqe(&t.rx, ready, &sqe), 0);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_WRITE_FIXED], 1);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_WRITE], 0);
	EXPECT_EQ(t.rx.writes.inflight, 1);
	EXPECT_EQ(spb_receiver_retire(&t.rx, ready), 0);
	complete_group(&t, &group2, 2, &ready);
	if (ready < 0)
		return;
	sqe.opcode = IORING_OP_WRITE;
	EXPECT_EQ(spb_receiver_issue_sqe(&t.rx, ready, &sqe), 0);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_WRITE], 1);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_WRITE_FIXED], 1);

	/* A second request completed while slot 0 is still being written
	 * lands in slot 1.  Its SQE must name slot 1: registered buffer index
	 * 1, slot 1's buffer, and 1 in the low half of the token. */
	EXPECT_EQ(ready, 0);
	EXPECT_EQ(build_group(&group3, 3, 73), 0);
	complete_group(&t, &group3, 3, &other);
	EXPECT_EQ(other, 1);
	if (other != 1)
		return;
	EXPECT_TRUE(t.groups[1].buffer != t.groups[0].buffer);
	memset(&sqe, 0xa5, sizeof(sqe));
	EXPECT_EQ(spb_prep_uring_write(&t.rx, other, 17, true, &sqe, &op), 0);
	EXPECT_EQ(sqe.opcode, IORING_OP_WRITE_FIXED);
	EXPECT_EQ(sqe.buf_index, 1);
	EXPECT_EQ(sqe.addr, (uint64_t)(uintptr_t)t.groups[1].buffer);
	EXPECT_EQ((uint32_t)sqe.user_data, 1);
	EXPECT_EQ(sqe.user_data >> 32, t.groups[1].request_index);
	memset(&sqe, 0xa5, sizeof(sqe));
	EXPECT_EQ(spb_prep_uring_write(&t.rx, other, 17, false, &sqe, &op), 0);
	EXPECT_EQ(sqe.opcode, IORING_OP_WRITE);
	EXPECT_EQ(sqe.addr, (uint64_t)(uintptr_t)t.groups[1].buffer);
	EXPECT_EQ((uint32_t)sqe.user_data, 1);
	EXPECT_EQ(sqe.user_data >> 32, t.groups[1].request_index);

	/* A request that is not READY is never prepared. */
	EXPECT_EQ(spb_prep_uring_write(&t.rx, ready, 17, false, &sqe, &op),
		  -EPROTO);
	EXPECT_EQ(spb_prep_uring_write(&t.rx, -1, 17, false, &sqe, &op),
		  -EINVAL);
	EXPECT_EQ(spb_prep_uring_write(&t.rx, (int)config.depth, 17, false,
				       &sqe, &op), -EINVAL);
}

/* A fake completion source that withholds every completion.  The pump below
 * runs the same sequence as spb_run(): consult spb_loop_may_receive(), take
 * one datagram, and issue the write of every group the datagram completes.
 * The datagram source never runs dry, so only the guard can stop the pump.
 * It must stop after exactly depth writes are outstanding, keep receiving
 * while fewer are outstanding, and resume after one completion. */
static void drive_withheld_completions(uint32_t depth)
{
	static struct test_group group;
	static struct test_rx t;
	struct spb_config config = base_config();
	struct spb_feed_result result = { 0 };
	int slots[TEST_MAX_DEPTH + 1];
	const unsigned int step_limit = (depth + 2) * 6 * 4;
	uint32_t issued = 0, generation = 1;
	uint64_t datagrams_before;
	unsigned int steps = 0;
	uint16_t segment = 0;

	config.depth = depth;
	config.groups = depth + 1;
	EXPECT_EQ(rx_init(&t, &config), 0);
	EXPECT_EQ(build_group(&group, generation, 60 + generation), 0);
	while (spb_loop_may_receive(&t.rx, false) && steps++ < step_limit) {
		EXPECT_EQ(feed(&t, &group.datagrams[segment], steps, &result), 0);
		if (result.outcome == SPB_FEED_DROPPED)
			break;
		if (result.outcome != SPB_FEED_COMPLETED) {
			segment++;
			continue;
		}
		EXPECT_EQ(spb_receiver_issue(&t.rx, result.group,
					     SPB_WRITE_OP_WRITE), 0);
		if (issued < TEST_MAX_DEPTH + 1)
			slots[issued] = result.group;
		issued++;
		EXPECT_EQ(t.rx.writes.inflight, issued);
		/* Fewer than depth outstanding: the guard stays open. */
		if (issued < depth)
			EXPECT_TRUE(spb_loop_may_receive(&t.rx, false));
		generation++;
		segment = 0;
		EXPECT_EQ(build_group(&group, generation, 60 + generation), 0);
	}
	EXPECT_EQ(issued, depth);
	EXPECT_EQ(t.rx.writes.inflight, depth);
	EXPECT_EQ(t.rx.writes.max_inflight, depth);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_WRITE], depth);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_WRITE_FIXED], 0);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_PWRITE], 0);
	EXPECT_EQ(t.rx.outstanding, depth);
	EXPECT_EQ(t.rx.counters.groups_completed, depth);
	EXPECT_EQ(t.rx.counters.packets_dropped, 0);
	EXPECT_FALSE(spb_loop_may_receive(&t.rx, false));
	/* The next datagram is left in the socket buffer, not consumed. */
	datagrams_before = t.rx.counters.datagrams;
	EXPECT_EQ(feed(&t, &group.datagrams[0], steps, &result), -EBUSY);
	EXPECT_EQ(t.rx.counters.datagrams, datagrams_before);
	if (issued != depth)
		return;

	/* Deliver one completion: exactly one more group may be written. */
	EXPECT_EQ(spb_receiver_retire(&t.rx, slots[0]), 0);
	EXPECT_EQ(t.rx.writes.inflight, depth - 1);
	EXPECT_TRUE(spb_loop_may_receive(&t.rx, false));
	EXPECT_FALSE(spb_loop_may_receive(&t.rx, true));
	for (uint16_t i = 0; i < group.count; i++) {
		EXPECT_TRUE(spb_loop_may_receive(&t.rx, false));
		EXPECT_EQ(feed(&t, &group.datagrams[i], steps + 1 + i, &result), 0);
	}
	EXPECT_EQ(result.outcome, SPB_FEED_COMPLETED);
	if (result.outcome == SPB_FEED_COMPLETED) {
		EXPECT_EQ(result.group, slots[0]);
		EXPECT_EQ(spb_receiver_issue(&t.rx, result.group,
					     SPB_WRITE_OP_WRITE), 0);
	}
	EXPECT_EQ(t.rx.writes.inflight, depth);
	EXPECT_EQ(t.rx.writes.max_inflight, depth);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_WRITE], depth + 1);
	/* All -n groups reassembled: the guard is closed for good. */
	EXPECT_FALSE(spb_loop_may_receive(&t.rx, false));
}

static void test_withheld_completions_fill_exactly_depth(void)
{
	static const uint32_t depths[] = { 1, 2, 4, 7 };

	for (size_t i = 0; i < sizeof(depths) / sizeof(depths[0]); i++)
		drive_withheld_completions(depths[i]);
}

static void test_issue_and_retire_fail_closed(void)
{
	static struct test_group g1, g2;
	static struct test_rx t;
	struct spb_config config = base_config();
	int first, second;

	config.depth = 2;
	EXPECT_EQ(build_group(&g1, 1, 81), 0);
	EXPECT_EQ(build_group(&g2, 2, 82), 0);
	EXPECT_EQ(rx_init(&t, &config), 0);
	complete_group(&t, &g1, 1, &first);
	complete_group(&t, &g2, 2, &second);
	if (first < 0 || second < 0)
		return;
	/* Nothing in flight: a completion cannot be retired. */
	EXPECT_EQ(spb_receiver_retire(&t.rx, first), -EPROTO);
	EXPECT_EQ(spb_receiver_issue(&t.rx, first, SPB_WRITE_OP_COUNT), -EINVAL);
	EXPECT_EQ(spb_receiver_issue(NULL, first, SPB_WRITE_OP_WRITE), -EINVAL);
	EXPECT_EQ(spb_receiver_issue(&t.rx, first, SPB_WRITE_OP_PWRITE), 0);
	EXPECT_EQ(spb_receiver_issue(&t.rx, first, SPB_WRITE_OP_PWRITE), -EPROTO);
	EXPECT_EQ(t.rx.writes.ops[SPB_WRITE_OP_PWRITE], 1);
	EXPECT_EQ(t.rx.writes.inflight, 1);
	/* More than depth writes in flight is refused before any state change. */
	t.rx.writes.inflight = config.depth;
	EXPECT_EQ(spb_receiver_issue(&t.rx, second, SPB_WRITE_OP_PWRITE),
		  -EOVERFLOW);
	EXPECT_EQ(t.groups[second].state, SPB_GROUP_READY);
	t.rx.writes.inflight = 1;
	/* Retiring a request that is not being written fails closed. */
	EXPECT_EQ(spb_receiver_retire(&t.rx, second), -EPROTO);
	EXPECT_EQ(t.rx.writes.inflight, 1);
	EXPECT_EQ(spb_receiver_retire(&t.rx, first), 0);
	EXPECT_EQ(t.rx.writes.inflight, 0);
	EXPECT_EQ(t.rx.writes.max_inflight, 1);
	EXPECT_EQ(spb_receiver_retire(&t.rx, first), -EPROTO);
}

/* Fake sysfs tree below a temporary directory. */
static char fake_root[PATH_MAX];

static int fake_mkdirs(const char *relative)
{
	char path[PATH_MAX];

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", fake_root, relative) >=
	    sizeof(path))
		return -ENAMETOOLONG;
	for (char *p = path + strlen(fake_root) + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(path, 0755) && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	if (mkdir(path, 0755) && errno != EEXIST)
		return -errno;
	return 0;
}

static int fake_file(const char *dir, const char *name, const char *text)
{
	char path[PATH_MAX];
	FILE *file;
	int ret = fake_mkdirs(dir);

	if (ret)
		return ret;
	if ((size_t)snprintf(path, sizeof(path), "%s/%s/%s", fake_root, dir,
			     name) >= sizeof(path))
		return -ENAMETOOLONG;
	file = fopen(path, "w");
	if (!file)
		return -errno;
	fputs(text, file);
	return fclose(file) ? -errno : 0;
}

/* <root>/dev/block/<number> -> ../../<node>, as the kernel links it. */
static int fake_dev_link(const char *number, const char *node)
{
	char path[PATH_MAX], target[PATH_MAX];
	int ret = fake_mkdirs("dev/block");

	if (ret)
		return ret;
	if ((size_t)snprintf(path, sizeof(path), "%s/dev/block/%s", fake_root,
			     number) >= sizeof(path) ||
	    (size_t)snprintf(target, sizeof(target), "../../%s", node) >=
		    sizeof(target))
		return -ENAMETOOLONG;
	return symlink(target, path) ? -errno : 0;
}

static int fake_remove(const char *path, const struct stat *st, int type,
		       struct FTW *ftw)
{
	(void)st;
	(void)type;
	(void)ftw;
	return remove(path);
}

#define FAKE_NVME_CTRL "devices/pci0000:00/0000:00:04.0/nvme/nvme0"
#define FAKE_NVME_NS FAKE_NVME_CTRL "/nvme0n1"
#define FAKE_NVME_PART FAKE_NVME_NS "/nvme0n1p1"
#define FAKE_SCSI_DISK "devices/pci0000:00/0000:00:1f.2/ata1/host0/block/sda"
#define FAKE_SCSI_PART FAKE_SCSI_DISK "/sda4"
#define FAKE_LOOP "devices/virtual/block/loop0"
#define FAKE_LOOP_NESTED FAKE_LOOP "/loop0p1"
#define FAKE_MARKED "devices/virtual/block/marked0"
#define FAKE_GARBLED "devices/virtual/garbled0"
#define FAKE_GARBLED_CHILD FAKE_GARBLED "/child0"

static int build_fake_sysfs(void)
{
	const char *tmp = getenv("TMPDIR");
	int ret = 0;

	if (!tmp || !tmp[0])
		tmp = "/tmp";
	if ((size_t)snprintf(fake_root, sizeof(fake_root), "%s/spb-sysfs-XXXXXX",
			     tmp) >= sizeof(fake_root) ||
	    !mkdtemp(fake_root))
		return -errno ? -errno : -ENAMETOOLONG;
	/* NVMe: the whole namespace sits beside the generic character node
	 * below its controller, whose own "dev" is a character device number;
	 * the partition sits below the namespace and carries "partition". */
	ret = ret ? ret : fake_file(FAKE_NVME_CTRL, "dev", "241:0\n");
	ret = ret ? ret : fake_file(FAKE_NVME_CTRL "/ng0n1", "dev", "240:0\n");
	ret = ret ? ret : fake_file(FAKE_NVME_NS, "dev", "259:0\n");
	ret = ret ? ret : fake_file(FAKE_NVME_PART, "dev", "259:1\n");
	ret = ret ? ret : fake_file(FAKE_NVME_PART, "partition", "1\n");
	ret = ret ? ret : fake_dev_link("259:0", FAKE_NVME_NS);
	ret = ret ? ret : fake_dev_link("259:1", FAKE_NVME_PART);
	/* A block device that happens to share the controller's char number:
	 * the parent test must compare nodes, not just find a "dev" file. */
	ret = ret ? ret : fake_dev_link("241:0", FAKE_LOOP);
	/* SCSI disk and partition, the layout of the real /sys on this host. */
	ret = ret ? ret : fake_file(FAKE_SCSI_DISK, "dev", "8:0\n");
	ret = ret ? ret : fake_file(FAKE_SCSI_PART, "dev", "8:4\n");
	ret = ret ? ret : fake_file(FAKE_SCSI_PART, "partition", "4\n");
	ret = ret ? ret : fake_dev_link("8:0", FAKE_SCSI_DISK);
	ret = ret ? ret : fake_dev_link("8:4", FAKE_SCSI_PART);
	/* Placement only: below another block device, no "partition" file. */
	ret = ret ? ret : fake_file(FAKE_LOOP, "dev", "7:0\n");
	ret = ret ? ret : fake_file(FAKE_LOOP_NESTED, "dev", "7:1\n");
	ret = ret ? ret : fake_dev_link("7:0", FAKE_LOOP);
	ret = ret ? ret : fake_dev_link("7:1", FAKE_LOOP_NESTED);
	/* Attribute only: a "partition" file at top-level placement. */
	ret = ret ? ret : fake_file(FAKE_MARKED, "dev", "7:9\n");
	ret = ret ? ret : fake_file(FAKE_MARKED, "partition", "1\n");
	ret = ret ? ret : fake_dev_link("7:9", FAKE_MARKED);
	/* A parent whose dev attribute is not a device number cannot be shown
	 * to be a non-device: fail closed. */
	ret = ret ? ret : fake_file(FAKE_GARBLED, "dev", "garbled\n");
	ret = ret ? ret : fake_file(FAKE_GARBLED_CHILD, "dev", "7:21\n");
	ret = ret ? ret : fake_dev_link("7:21", FAKE_GARBLED_CHILD);
	return ret;
}

static void test_partition_targets_are_refused(void)
{
	struct stat st;
	const char *kind = NULL;
	int ret = build_fake_sysfs();

	EXPECT_EQ(ret, 0);
	if (ret) {
		if (fake_root[0])
			nftw(fake_root, fake_remove, 16, FTW_DEPTH | FTW_PHYS);
		return;
	}
	/* Whole devices are accepted. */
	EXPECT_EQ(spb_block_partition_check(fake_root, 259, 0), 0);
	EXPECT_EQ(spb_block_partition_check(fake_root, 8, 0), 0);
	EXPECT_EQ(spb_block_partition_check(fake_root, 7, 0), 0);
	/* Partitions: both markers, placement only, attribute only. */
	EXPECT_EQ(spb_block_partition_check(fake_root, 259, 1), -EXDEV);
	EXPECT_EQ(spb_block_partition_check(fake_root, 8, 4), -EXDEV);
	EXPECT_EQ(spb_block_partition_check(fake_root, 7, 1), -EXDEV);
	EXPECT_EQ(spb_block_partition_check(fake_root, 7, 9), -EXDEV);
	/* A device sysfs does not know cannot be shown whole: fail closed. */
	EXPECT_EQ(spb_block_partition_check(fake_root, 8, 16), -ENOENT);
	EXPECT_EQ(spb_block_partition_check(fake_root, 7, 21), -EPROTO);
	EXPECT_EQ(spb_block_partition_check(NULL, 259, 0), -EINVAL);
	EXPECT_EQ(spb_block_partition_check("", 259, 0), -EINVAL);

	/* The target classification the program uses. */
	memset(&st, 0, sizeof(st));
	st.st_mode = S_IFBLK | 0600;
	st.st_rdev = makedev(259, 0);
	EXPECT_EQ(spb_target_classify(&st, fake_root, &kind), 0);
	EXPECT_TRUE(kind && !strcmp(kind, "block"));
	kind = NULL;
	st.st_rdev = makedev(259, 1);
	EXPECT_EQ(spb_target_classify(&st, fake_root, &kind), -EXDEV);
	EXPECT_TRUE(kind == NULL);
	st.st_rdev = makedev(8, 4);
	EXPECT_EQ(spb_target_classify(&st, fake_root, &kind), -EXDEV);
	st.st_rdev = makedev(8, 16);
	EXPECT_EQ(spb_target_classify(&st, fake_root, &kind), -ENOENT);
	st.st_mode = S_IFREG | 0600;
	EXPECT_EQ(spb_target_classify(&st, fake_root, &kind), 0);
	EXPECT_TRUE(kind && !strcmp(kind, "file"));
	kind = NULL;
	st.st_mode = S_IFCHR | 0600;
	EXPECT_EQ(spb_target_classify(&st, fake_root, &kind), -ENOTBLK);
	EXPECT_TRUE(kind == NULL);
	EXPECT_EQ(spb_target_classify(NULL, fake_root, &kind), -EINVAL);

	EXPECT_EQ(nftw(fake_root, fake_remove, 16, FTW_DEPTH | FTW_PHYS), 0);
	EXPECT_TRUE(access(fake_root, F_OK) != 0);
}

static void test_receiver_init_rejects_missing_storage(void)
{
	static struct test_rx t;
	struct spb_config config = base_config();

	EXPECT_EQ(rx_init(&t, &config), 0);
	t.buffers[1] = NULL;
	EXPECT_EQ(spb_receiver_init(&t.rx, &config, t.groups, t.buffers),
		  -EINVAL);
	EXPECT_EQ(spb_receiver_init(&t.rx, &config, NULL, t.buffers), -EINVAL);
	config.session_id = 0;
	t.buffers[1] = t.storage[1];
	EXPECT_EQ(spb_receiver_init(&t.rx, &config, t.groups, t.buffers),
		  -EINVAL);
}

static void test_percentiles_use_nearest_rank(void)
{
	uint64_t values[] = { 50, 10, 40, 20, 30 };
	uint64_t many[100];

	spb_sort_u64(values, 5);
	EXPECT_EQ(values[0], 10);
	EXPECT_EQ(values[4], 50);
	EXPECT_EQ(spb_nearest_rank(values, 5, 50), 30);
	EXPECT_EQ(spb_nearest_rank(values, 5, 99), 50);
	EXPECT_EQ(spb_nearest_rank(values, 5, 100), 50);
	EXPECT_EQ(spb_nearest_rank(values, 5, 0), 10);
	EXPECT_EQ(spb_nearest_rank(values, 0, 50), 0);
	for (int i = 0; i < 100; i++)
		many[i] = (uint64_t)(100 - i);
	spb_sort_u64(many, 100);
	EXPECT_EQ(spb_nearest_rank(many, 100, 50), 50);
	EXPECT_EQ(spb_nearest_rank(many, 100, 99), 99);
}

static void test_drop_reason_names_are_distinct(void)
{
	for (int i = 0; i < SPB_DROP_REASON_COUNT; i++) {
		const char *name = spb_drop_reason_name((enum spb_drop_reason)i);

		EXPECT_TRUE(name != NULL && name[0] != '\0');
		for (int j = 0; j < i && name; j++)
			EXPECT_TRUE(strcmp(name, spb_drop_reason_name(
					(enum spb_drop_reason)j)) != 0);
	}
	EXPECT_TRUE(spb_drop_reason_name(SPB_DROP_REASON_COUNT) == NULL);
}

int main(void)
{
	test_pipeline_layout_mirror();
	test_config_validation_mirrors_pipeline_geometry();
	test_local_window_is_the_only_lba_source();
	test_in_order_group_completes_with_local_lba();
	test_reordered_group_is_never_ready_until_ordered_retry();
	test_duplicates_are_dropped_without_corrupting_the_group();
	test_truncated_and_malformed_payloads_are_dropped();
	test_crc_mismatch_is_dropped();
	test_session_direction_and_layout_are_checked();
	test_generation_rules_mirror_the_pipeline();
	test_depth_bounds_outstanding_groups();
	test_group_count_stops_acceptance();
	test_incomplete_group_expires_and_same_generation_retries();
	test_group_arrives_with_its_completing_datagram();
	test_arrival_report_on_known_times();
	test_receiver_init_rejects_missing_storage();
	test_target_must_be_open_o_direct();
	test_uring_write_prep_matches_the_tier();
	test_withheld_completions_fill_exactly_depth();
	test_issue_and_retire_fail_closed();
	test_partition_targets_are_refused();
	test_percentiles_use_nearest_rank();
	test_drop_reason_names_are_distinct();

	if (failures) {
		fprintf(stderr, "FAIL: %u of %u checks\n", failures, checks);
		return 1;
	}
	printf("PASS: %u checks\n", checks);
	return 0;
}
