// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "nvme_xdp_pipeline_core.h"
/* Read-only: the traditional receiver's definitions, so the pipeline's
 * PIPELINE_RX_SUMMARY helpers can be checked against them directly. */
#include "tools/xdev_ext_sendpath_baseline_core.h"

#define TEST_WIRE_SESSION UINT64_C(0x1122334455667788)

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

static struct nxp_namespace good_namespace(void)
{
	struct nxp_namespace ns = {
		.nsid = 7,
		.lba_size = 512,
		.capacity_lbas = UINT64_C(1000000),
		.metadata_size = 0,
		.pi_type = 0,
		.char_is_namespace = true,
		.block_is_whole_namespace = true,
		.same_namespace = true,
		.stable_id_present = true,
		.char_rdev = UINT64_C(0x1234),
		.block_rdev = UINT64_C(0x5678),
		.diskseq = 19,
		.controller_serial_present = true,
		.pci_bdf_present = true,
	};

	memcpy(ns.stable_id, "nvme.test-namespace", 19);
	ns.stable_id_len = 19;
	memcpy(ns.controller_serial, "SERIAL-TEST", 11);
	ns.controller_serial_len = 11;
	memcpy(ns.pci_bdf, "0000:65:00.0", 12);
	ns.pci_bdf_len = 12;
	return ns;
}

static void test_namespace_is_fail_closed(void)
{
	struct nxp_namespace ns = good_namespace();
	struct nxp_namespace snapshot = ns;

	EXPECT_TRUE(NXP_STABLE_ID_MAX >= 192);
	EXPECT_EQ(nxp_namespace_validate(&ns), 0);
	ns.nsid = 0;
	EXPECT_EQ(nxp_namespace_validate(&ns), -ENODEV);
	ns = snapshot;
	ns.lba_size = 0;
	EXPECT_EQ(nxp_namespace_validate(&ns), -EINVAL);
	ns = snapshot;
	ns.lba_size = 256; /* NVMe LBADS must be at least 9 (512 bytes). */
	EXPECT_EQ(nxp_namespace_validate(&ns), -EINVAL);
	ns = snapshot;
	ns.capacity_lbas = 0;
	EXPECT_EQ(nxp_namespace_validate(&ns), -ENOSPC);
	ns = snapshot;
	ns.metadata_size = 8;
	EXPECT_EQ(nxp_namespace_validate(&ns), -EOPNOTSUPP);
	ns = snapshot;
	ns.pi_type = 1;
	EXPECT_EQ(nxp_namespace_validate(&ns), -EOPNOTSUPP);
	ns = snapshot;
	ns.char_is_namespace = false;
	EXPECT_EQ(nxp_namespace_validate(&ns), -ENOTTY);
	ns = snapshot;
	ns.block_is_whole_namespace = false;
	EXPECT_EQ(nxp_namespace_validate(&ns), -ENOTBLK);
	ns = snapshot;
	ns.same_namespace = false;
	EXPECT_EQ(nxp_namespace_validate(&ns), -EXDEV);
	ns = snapshot;
	ns.stable_id_present = false;
	EXPECT_EQ(nxp_namespace_validate(&ns), -ENODATA);

	EXPECT_EQ(nxp_namespace_same_generation(&snapshot, &snapshot), 0);
	ns = snapshot;
	ns.diskseq++;
	EXPECT_EQ(nxp_namespace_same_generation(&snapshot, &ns), -ESTALE);
	ns = snapshot;
	ns.lba_size = 4096;
	EXPECT_EQ(nxp_namespace_same_generation(&snapshot, &ns), -ESTALE);
	ns = snapshot;
	ns.capacity_lbas--;
	EXPECT_EQ(nxp_namespace_same_generation(&snapshot, &ns), -ESTALE);
	ns = snapshot;
	ns.block_rdev++;
	EXPECT_EQ(nxp_namespace_same_generation(&snapshot, &ns), -ESTALE);
	ns = snapshot;
	ns.stable_id[0] ^= 1;
	EXPECT_EQ(nxp_namespace_same_generation(&snapshot, &ns), -ESTALE);
	ns = snapshot;
	ns.controller_serial[0] ^= 1;
	EXPECT_EQ(nxp_namespace_same_generation(&snapshot, &ns), -ESTALE);
	ns = snapshot;
	ns.pci_bdf[0] ^= 1;
	EXPECT_EQ(nxp_namespace_same_generation(&snapshot, &ns), -ESTALE);
	ns = snapshot;
	ns.controller_serial_present = false;
	EXPECT_EQ(nxp_namespace_validate(&ns), -ENODATA);
	ns = snapshot;
	ns.pci_bdf_present = false;
	EXPECT_EQ(nxp_namespace_validate(&ns), -ENODATA);
}

static void test_namespace_epoch_is_cheap_and_fail_closed(void)
{
	struct nxp_namespace ns = good_namespace();
	struct nxp_namespace_epoch frozen;
	struct nxp_namespace_epoch current;

	EXPECT_EQ(nxp_namespace_epoch_from_snapshot(&ns, &frozen), 0);
	current = frozen;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), 0);

	current = frozen;
	current.nsid++;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ESTALE);
	current = frozen;
	current.char_rdev++;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ESTALE);
	current = frozen;
	current.block_rdev++;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ESTALE);
	current = frozen;
	current.diskseq++;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ESTALE);
	current = frozen;
	current.char_is_namespace = false;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ENOTTY);
	current = frozen;
	current.block_is_whole_namespace = false;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ENOTBLK);

	current = frozen;
	current.nsid = 0;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ENODEV);
	current = frozen;
	current.char_rdev = 0;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ENODEV);
	current = frozen;
	current.block_rdev = 0;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ENODEV);
	current = frozen;
	current.diskseq = 0;
	EXPECT_EQ(nxp_namespace_epoch_validate(&frozen, &current), -ENODATA);

	ns.nsid = 0;
	EXPECT_EQ(nxp_namespace_epoch_from_snapshot(&ns, &current), -ENODEV);
	EXPECT_EQ(nxp_namespace_epoch_from_snapshot(NULL, &current), -EINVAL);
	EXPECT_EQ(nxp_namespace_epoch_from_snapshot(&ns, NULL), -EINVAL);
}

static void test_standard_nvme_sysfs_nodes_are_controller_siblings(void)
{
	const char *ng = "/sys/devices/pci0000:40/0000:40:01.0/nvme/nvme3/ng3n7";
	const char *block =
		"/sys/devices/pci0000:40/0000:40:01.0/nvme/nvme3/nvme3n7";
	const char *other =
		"/sys/devices/pci0000:40/0000:40:02.0/nvme/nvme4/nvme4n7";

	EXPECT_TRUE(nxp_paths_share_parent(ng, block));
	EXPECT_FALSE(nxp_paths_share_parent(ng,
		"/sys/devices/pci0000:40/0000:40:01.0/nvme/nvme3"));
	EXPECT_FALSE(nxp_paths_share_parent(ng, other));
	EXPECT_FALSE(nxp_paths_share_parent("ng3n7", "nvme3n7"));
	EXPECT_FALSE(nxp_paths_share_parent("/ng3n7", "/nvme3n7"));
}

static void test_controller_address_requires_unique_pci_bdf(void)
{
	EXPECT_TRUE(nxp_is_pci_bdf("0000:65:00.0"));
	EXPECT_TRUE(nxp_is_pci_bdf("ABCD:0a:1F.7"));
	EXPECT_FALSE(nxp_is_pci_bdf("65:00.0"));
	EXPECT_FALSE(nxp_is_pci_bdf("0000:65:00.8"));
	EXPECT_FALSE(nxp_is_pci_bdf("traddr=10.0.0.1,trsvcid=4420"));
	EXPECT_FALSE(nxp_is_pci_bdf("(ef57)"));
	EXPECT_FALSE(nxp_is_pci_bdf("0000:65:00.0\n"));
}

static void test_nvme_encoder_checks_every_boundary(void)
{
	struct nxp_namespace ns = good_namespace();
	struct nxp_io_limits limits = {
		.authorized_first_lba = 100,
		.authorized_lbas = 900000,
		.frame_size = 4096,
		.payload_offset = 64,
		.packet_header_len = 42,
		.l2_header_len = 14,
		.mtu = 1500,
	};
	struct nxp_nvme_read cmd;

	EXPECT_EQ(nxp_encode_read(&ns, &limits, 100, 0, 1024, &cmd), 0);
	EXPECT_EQ(cmd.slba, 100);
	EXPECT_EQ(cmd.blocks, 2);
	EXPECT_EQ(cmd.nlb, 1);
	EXPECT_EQ(cmd.cdw10, 100);
	EXPECT_EQ(cmd.cdw11, 0);
	EXPECT_EQ(cmd.cdw12, 1);

	ns.lba_size = 4096;
	limits.frame_size = UINT64_MAX;
	limits.payload_offset = 0;
	limits.packet_header_len = 0;
	limits.l2_header_len = 0;
	limits.mtu = UINT32_MAX;
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 100, 0, 4096, &cmd), 0);
	EXPECT_EQ(cmd.blocks, 1);
	EXPECT_EQ(cmd.nlb, 0);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 100, 0, 8192, &cmd), 0);
	EXPECT_EQ(cmd.nlb, 1);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 100, 0, 4095, &cmd), -EINVAL);
	ns = good_namespace();
	limits = (struct nxp_io_limits) {
		.authorized_first_lba = 100,
		.authorized_lbas = 900000,
		.frame_size = 4096,
		.payload_offset = 64,
		.packet_header_len = 42,
		.l2_header_len = 14,
		.mtu = 1500,
	};

	EXPECT_EQ(nxp_encode_read(&ns, &limits, UINT64_C(0x100000000), 0,
				  512, &cmd), -ERANGE);
	limits.authorized_first_lba = 0;
	limits.authorized_lbas = UINT64_MAX;
	ns.capacity_lbas = UINT64_MAX;
	EXPECT_EQ(nxp_encode_read(&ns, &limits, UINT64_C(0x100000000), 0,
				  512, &cmd), 0);
	EXPECT_EQ(cmd.cdw10, 0);
	EXPECT_EQ(cmd.cdw11, 1);

	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0, 0, &cmd), -EINVAL);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0, 513, &cmd), -EINVAL);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0,
				  UINT64_C(65536) * 512, &cmd), -ENOBUFS);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0,
				  UINT64_C(65537) * 512, &cmd), -E2BIG);

	/* Isolate the NVMe 65536-block upper bound from packet limits. */
	limits.frame_size = UINT64_MAX;
	limits.payload_offset = 0;
	limits.packet_header_len = 0;
	limits.l2_header_len = 0;
	limits.mtu = UINT32_MAX;
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0,
				  UINT64_C(65536) * 512, &cmd), 0);
	EXPECT_EQ(cmd.nlb, UINT16_MAX);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0,
				  UINT64_C(65537) * 512, &cmd), -E2BIG);

	EXPECT_EQ(nxp_encode_read(&ns, &limits, UINT64_MAX - 1, 1,
				  1024, &cmd), -EOVERFLOW);
	ns.capacity_lbas = 1000;
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 999, 0, 1024, &cmd), -ERANGE);
	limits.authorized_first_lba = 10;
	limits.authorized_lbas = 10;
	ns.capacity_lbas = 1000;
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 9, 0, 512, &cmd), -EACCES);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 19, 0, 1024, &cmd), -EACCES);

	limits = (struct nxp_io_limits) {
		.authorized_first_lba = 0,
		.authorized_lbas = 1000,
		.frame_size = 4096,
		.payload_offset = 64,
		.packet_header_len = 42,
		.l2_header_len = 14,
		.mtu = 1500,
	};
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0, 4032, &cmd), -EINVAL);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0, 1536, &cmd), -EMSGSIZE);
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0, 1024, &cmd), 0);
	limits.mtu = 9000;
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0, 4096, &cmd), -ENOBUFS);
	limits.payload_offset = 40;
	EXPECT_EQ(nxp_encode_read(&ns, &limits, 0, 0, 512, &cmd), -EINVAL);
}

static void test_direction_neutral_nvme_plan_uses_only_local_window(void)
{
	struct nxp_namespace ns = good_namespace();
	struct nxp_io_limits limits = {
		.authorized_first_lba = 100,
		.authorized_lbas = 64,
		/* Logical I/O may be segmented across several network frames. */
		.frame_size = 1,
		.payload_offset = 1,
		.packet_header_len = 1,
		.l2_header_len = 1,
		.mtu = 1,
	};
	struct nxp_local_io_position position = {
		.request_index = 1,
		.block_offset = 2,
	};
	struct nxp_nvme_io_plan read_plan = { 0 };
	struct nxp_nvme_io_plan write_plan = { 0 };

	EXPECT_EQ(nxp_plan_nvme_io(&ns, &limits, NXP_IO_READ, &position,
				    4096, &read_plan), 0);
	EXPECT_EQ(read_plan.direction, NXP_IO_READ);
	EXPECT_EQ(read_plan.opcode, NXP_NVME_OP_READ);
	EXPECT_EQ(read_plan.slba, 110);
	EXPECT_EQ(read_plan.blocks, 8);
	EXPECT_EQ(read_plan.nlb, 7);
	EXPECT_EQ(read_plan.data_len, 4096);
	EXPECT_EQ(read_plan.cdw10, 110);
	EXPECT_EQ(read_plan.cdw11, 0);
	EXPECT_EQ(read_plan.cdw12, 7);

	EXPECT_EQ(nxp_plan_nvme_io(&ns, &limits, NXP_IO_WRITE, &position,
				    4096, &write_plan), 0);
	EXPECT_EQ(write_plan.direction, NXP_IO_WRITE);
	EXPECT_EQ(write_plan.opcode, NXP_NVME_OP_WRITE);
	EXPECT_EQ(write_plan.slba, read_plan.slba);
	EXPECT_EQ(write_plan.blocks, read_plan.blocks);

	/* 8 KiB is a legal logical command even though one 4 KiB frame cannot
	 * carry it; the wire layout below decides how it is packetized. */
	ns.lba_size = 4096;
	limits.authorized_first_lba = 20;
	limits.authorized_lbas = 32;
	position.request_index = 3;
	position.block_offset = 1;
	EXPECT_EQ(nxp_plan_nvme_io(&ns, &limits, NXP_IO_WRITE, &position,
				    8192, &write_plan), 0);
	EXPECT_EQ(write_plan.slba, 27);
	EXPECT_EQ(write_plan.blocks, 2);
	EXPECT_EQ(write_plan.nlb, 1);

	EXPECT_EQ(nxp_plan_nvme_io(&ns, &limits,
				    (enum nxp_io_direction)99, &position,
				    8192, &write_plan), -EINVAL);
	EXPECT_EQ(nxp_plan_nvme_io(&ns, &limits, NXP_IO_WRITE, &position,
				    4097, &write_plan), -EINVAL);
	position.request_index = UINT64_MAX;
	EXPECT_EQ(nxp_plan_nvme_io(&ns, &limits, NXP_IO_WRITE, &position,
				    8192, &write_plan), -EOVERFLOW);
	position.request_index = 15;
	position.block_offset = 1;
	EXPECT_EQ(nxp_plan_nvme_io(&ns, &limits, NXP_IO_WRITE, &position,
				    8192, &write_plan), -EACCES);
	limits.authorized_first_lba = UINT64_MAX - 1;
	limits.authorized_lbas = 2;
	position.request_index = 0;
	position.block_offset = 1;
	ns.capacity_lbas = UINT64_MAX;
	EXPECT_EQ(nxp_plan_nvme_io(&ns, &limits, NXP_IO_READ, &position,
				    8192, &read_plan), -EOVERFLOW);
}

static void test_wire_layout_uses_only_ordinary_mtu_packets(void)
{
	struct nxp_wire_layout standard;
	struct nxp_wire_segment segment;

	/* MTU 1460 leaves 1392 bytes after IPv4, UDP, and the 40-byte
	 * wire header.  Every segment is a separate ordinary datagram. */
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 7, 4096, 1460, 4096, 64, 1,
					   &standard), 0);
	EXPECT_EQ(standard.segment_count, 3);
	EXPECT_EQ(standard.segment_data_limit, 1392);
	EXPECT_EQ(nxp_wire_segment_at(&standard, NXP_IO_READ, 0, &segment), 0);
	EXPECT_EQ(segment.generation, 7);
	EXPECT_EQ(segment.segment_index, 0);
	EXPECT_EQ(segment.segment_count, 3);
	EXPECT_EQ(segment.total_len, 4096);
	EXPECT_EQ(segment.relative_offset, 0);
	EXPECT_EQ(segment.payload_len, 1392);
	EXPECT_EQ(nxp_wire_segment_at(&standard, NXP_IO_READ, 2, &segment), 0);
	EXPECT_EQ(segment.relative_offset, 2784);
	EXPECT_EQ(segment.payload_len, 1312);

	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 8, 8192, 1460, 4096, 64, 1,
					   &standard), 0);
	EXPECT_EQ(standard.segment_count, 6);
	EXPECT_EQ(nxp_wire_segment_at(&standard, NXP_IO_WRITE, 5, &segment), 0);
	EXPECT_EQ(segment.relative_offset, 6960);
	EXPECT_EQ(segment.payload_len, 1232);

	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 0, 8192, 1460, 4096, 64, 1,
					   &standard),
		  -EINVAL);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(0, 1, 8192, 1460, 4096, 64, 1,
					   &standard),
		  -EINVAL);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 1, 0, 1460, 4096, 64, 1,
					   &standard),
		  -EINVAL);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 1, NXP_WIRE_MAX_SEGMENTS + 1,
					   NXP_WIRE_IPV4_UDP_LEN +
					   NXP_WIRE_HEADER_LEN + 1,
					   65, 64, 1, &standard),
		  -E2BIG);
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 1, 8192,
					   NXP_WIRE_IPV4_UDP_LEN +
					   NXP_WIRE_HEADER_LEN,
					   4096, 64, 1, &standard),
		  -EMSGSIZE);
	EXPECT_EQ(nxp_wire_segment_at(&standard, NXP_IO_READ,
				      standard.segment_count, &segment), -ERANGE);
}

static void test_wire_header_is_bounded_and_checksummed(void)
{
	struct nxp_wire_layout layout;
	struct nxp_wire_segment source;
	struct nxp_wire_segment parsed;
	uint8_t header[NXP_WIRE_HEADER_LEN];
	uint8_t payload_a[512];
	uint8_t payload_b[512];
	uint8_t payload_c[376];
	struct nxp_wire_span spans[] = {
		{ .data = payload_a, .len = sizeof(payload_a) },
		{ .data = payload_b, .len = sizeof(payload_b) },
		{ .data = payload_c, .len = sizeof(payload_c) },
	};

	memset(payload_a, 0x5a, sizeof(payload_a));
	memset(payload_b, 0xa5, sizeof(payload_b));
	memset(payload_c, 0x3c, sizeof(payload_c));
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 1234, 1400, 1468, 4096, 64, 1,
					   &layout), 0);
	EXPECT_EQ(nxp_wire_segment_at(&layout, NXP_IO_WRITE, 0, &source), 0);
	EXPECT_EQ(source.session_id, UINT64_C(0x1122334455667788));
	EXPECT_EQ(nxp_wire_header_encode(header, sizeof(header), &source,
					 spans, 3), 0);
	EXPECT_EQ(nxp_wire_header_parse(header, sizeof(header), spans, 3,
					 &parsed), 0);
	EXPECT_EQ(parsed.direction, NXP_IO_WRITE);
	EXPECT_EQ(parsed.session_id, UINT64_C(0x1122334455667788));
	EXPECT_EQ(parsed.generation, 1234);
	EXPECT_EQ(parsed.segment_index, 0);
	EXPECT_EQ(parsed.segment_count, 1);
	EXPECT_EQ(parsed.total_len, 1400);
	EXPECT_EQ(parsed.relative_offset, 0);
	EXPECT_EQ(parsed.payload_len, 1400);

	/* The session identity is covered by CRC and parsed as wire state.  It is
	 * intentionally not authentication; the receiver's configured session is
	 * what rejects a valid old-session packet below. */
	header[15] ^= 1;
	nxp_wire_put_be32(header + 36, nxp_wire_checksum(header, spans, 3));
	EXPECT_EQ(nxp_wire_header_parse(header, sizeof(header), spans, 3,
					 &parsed), 0);
	EXPECT_TRUE(parsed.session_id != source.session_id);
	EXPECT_EQ(nxp_wire_header_encode(header, sizeof(header), &source,
					 spans, 3), 0);

	header[0] ^= 1;
	EXPECT_EQ(nxp_wire_header_parse(header, sizeof(header), spans, 3,
					 &parsed), -EPROTO);
	header[0] ^= 1;
	header[4]++;
	EXPECT_EQ(nxp_wire_header_parse(header, sizeof(header), spans, 3,
					 &parsed), -EPROTONOSUPPORT);
	header[4]--;
	payload_b[17] ^= 1;
	EXPECT_EQ(nxp_wire_header_parse(header, sizeof(header), spans, 3,
					 &parsed), -EBADMSG);
	payload_b[17] ^= 1;
	header[6] = 3; /* unknown destination action, with a valid CRC */
	nxp_wire_put_be32(header + 36,
			  nxp_wire_checksum(header, spans, 3));
	EXPECT_EQ(nxp_wire_header_parse(header, sizeof(header), spans, 3,
					 &parsed), -EPROTO);
	header[6] = NXP_IO_WRITE;
	nxp_wire_put_be32(header + 36,
			  nxp_wire_checksum(header, spans, 3));
	EXPECT_EQ(nxp_wire_header_parse(header, sizeof(header) - 1, spans, 3,
					 &parsed), -EMSGSIZE);
	spans[2].len--;
	EXPECT_EQ(nxp_wire_header_parse(header, sizeof(header), spans, 3,
					 &parsed), -EMSGSIZE);
	spans[2].len++;

	source.segment_count = 0;
	EXPECT_EQ(nxp_wire_header_encode(header, sizeof(header), &source,
					 spans, 3), -EINVAL);
	source.segment_count = 1;
	source.relative_offset = 1;
	EXPECT_EQ(nxp_wire_header_encode(header, sizeof(header), &source,
					 spans, 3), -ERANGE);
}

static void test_wire_group_rejects_duplicates_gaps_and_generation_reuse(void)
{
	struct nxp_wire_layout layout;
	struct nxp_wire_layout next_layout;
	struct nxp_wire_segment segment[3];
	struct nxp_wire_segment next_segment;
	struct nxp_wire_group_rx rx = { 0 };

	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 1, 4096, 1460, 4096, 64, 1,
					   &layout), 0);
	for (uint16_t i = 0; i < layout.segment_count; i++)
		EXPECT_EQ(nxp_wire_segment_at(&layout, NXP_IO_WRITE, i,
					      &segment[i]), 0);
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 0, NXP_IO_WRITE, 4096, 3),
		  -EINVAL);
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 2, NXP_IO_WRITE, 4096, 3),
		  -EPIPE); /* first session group must be generation 1 */
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 1, NXP_IO_WRITE, 4096, 3), 0);
	{
		struct nxp_wire_segment stale_session = segment[0];

		stale_session.session_id ^= 1;
		EXPECT_EQ(nxp_wire_group_accept(&rx, &stale_session), -ESTALE);
	}
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[1]), -EPIPE);
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[0]), 0);
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[0]), -EALREADY);
	EXPECT_EQ(nxp_wire_group_finish(&rx), -ENODATA);
	/* Segment 2 exposes the missing segment 1 but does not destroy the
	 * group, so the caller may accept a later in-order delivery. */
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[2]), -EPIPE);
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[1]), 0);
	EXPECT_EQ(nxp_wire_group_finish(&rx), -ENODATA);
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[2]), 0);
	EXPECT_EQ(nxp_wire_group_finish(&rx), 0);
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[2]), -EALREADY);
	{
		struct nxp_wire_segment stale_session = segment[2];

		stale_session.session_id ^= 1;
		EXPECT_EQ(nxp_wire_group_accept(&rx, &stale_session), -ESTALE);
	}
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 1, NXP_IO_WRITE, 4096, 3),
		  -EALREADY);
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 3, NXP_IO_WRITE, 4096, 3),
		  -EPIPE); /* a missing generation requires session restart */

	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 2, 4096, 4164, 8192, 64, 1,
					   &next_layout), 0);
	EXPECT_EQ(nxp_wire_segment_at(&next_layout, NXP_IO_WRITE, 0,
				      &next_segment), 0);
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 2, NXP_IO_WRITE, 4096, 1), 0);
	/* A delayed segment from the completed generation cannot be mistaken
	 * for data belonging to the reused receiver object. */
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[2]), -ESTALE);
	EXPECT_EQ(nxp_wire_group_accept(&rx, &next_segment), 0);
	EXPECT_EQ(nxp_wire_group_finish(&rx), 0);
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 1, NXP_IO_WRITE, 4096, 1),
		  -ESTALE);
	rx.last_generation = UINT32_MAX;
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 1, NXP_IO_WRITE, 4096, 1),
		  -EOVERFLOW);

	memset(&rx, 0, sizeof(rx));
	EXPECT_EQ(nxp_wire_group_begin(&rx, TEST_WIRE_SESSION, 1, NXP_IO_READ, 4096, 3), 0);
	segment[0].generation = 1;
	segment[0].direction = NXP_IO_WRITE;
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[0]), -EPROTO);
	segment[0].direction = NXP_IO_READ;
	segment[0].segment_count = 2;
	EXPECT_EQ(nxp_wire_group_accept(&rx, &segment[0]), -EPROTO);
}

static void test_8k_group_depth_is_bounded_by_frames_and_every_xsk_ring(void)
{
	/* MTU1500 yields six ordinary packets.  341 groups need 2046 frames,
	 * fitting all 2048-entry XSK rings; 342 need 2052 and are rejected. */
	EXPECT_EQ(nxp_group_capacity_validate(341, 6, 4096,
				      2048, 2048, 2048, 2048), 0);
	EXPECT_EQ(nxp_group_capacity_validate(342, 6, 4096,
				      2048, 2048, 2048, 2048), -E2BIG);
	EXPECT_EQ(nxp_group_capacity_validate(683, 6, 4096,
				      8192, 8192, 8192, 8192), -E2BIG);
	EXPECT_EQ(nxp_group_capacity_validate(1, 0, 4096,
				      2048, 2048, 2048, 2048), -EINVAL);
}

static void test_8k_mtu_layout_keeps_one_lba_aligned_logical_io(void)
{
	struct nxp_wire_layout layout;
	struct nxp_wire_segment segment;
	uint64_t total = 0;

	/* MTU excludes Ethernet.  IPv4+UDP+NXP leave 1432 data bytes, so an
	 * 8 KiB logical command is six ordinary packets but remains one NVMe
	 * command.  Segment offsets are contiguous and vector-aligned; the start
	 * SLBA and total logical command length are independently LBA-aligned by
	 * nxp_plan_nvme_io(). */
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 7, 8192, 1500, 4096, 104,
					 sizeof(uint64_t), &layout), 0);
	EXPECT_EQ(layout.segment_data_limit, 1432);
	EXPECT_EQ(layout.segment_count, 6);
	for (uint16_t i = 0; i < layout.segment_count; i++) {
		EXPECT_EQ(nxp_wire_segment_at(&layout, NXP_IO_READ, i,
					      &segment), 0);
		EXPECT_EQ(segment.relative_offset, total);
		EXPECT_EQ(segment.payload_len % sizeof(uint64_t), 0);
		total += segment.payload_len;
	}
	EXPECT_EQ(total, 8192);

	/* The packetizer must reject a layout that cannot hold even one aligned
	 * data unit, and the NVMe planner rejects a non-LBA-aligned total. */
	EXPECT_EQ(nxp_wire_mtu_layout_plan(TEST_WIRE_SESSION, 7, 8192, 67, 4096, 104,
					 sizeof(uint64_t), &layout), -EMSGSIZE);
}

static void test_rx_frames_have_exactly_one_fill_io_recycle_lifetime(void)
{
	enum nxp_rx_frame_state state = NXP_RX_FRAME_FREE;

	EXPECT_EQ(nxp_rx_frame_to_fill(&state), 0);
	EXPECT_EQ(nxp_rx_frame_to_fill(&state), -EALREADY);
	EXPECT_EQ(nxp_rx_frame_to_received(&state), 0);
	EXPECT_EQ(nxp_rx_frame_hold_for_io(&state), 0);
	EXPECT_EQ(nxp_rx_frame_recycle_after_io(&state), 0);
	EXPECT_EQ(nxp_rx_frame_recycle_after_io(&state), -EALREADY);
	EXPECT_EQ(nxp_rx_frame_to_fill(&state), 0);
	EXPECT_EQ(nxp_rx_frame_to_received(&state), 0);
	EXPECT_EQ(nxp_rx_frame_drop(&state), 0);
	EXPECT_EQ(nxp_rx_frame_drop(&state), -EALREADY);
}

/* The census taken when the rx-write loop ends counts frames by state.
 * RECEIVED and IO frames are still owned by the program and not released; a
 * value outside the enum is counted as outstanding too, so a corrupted state
 * fails closed instead of disappearing from the count. */
static void test_rx_frame_census_counts_every_state(void)
{
	enum nxp_rx_frame_state states[9] = {
		NXP_RX_FRAME_FREE, NXP_RX_FRAME_FILL, NXP_RX_FRAME_FILL,
		NXP_RX_FRAME_RECEIVED, NXP_RX_FRAME_IO, NXP_RX_FRAME_IO,
		NXP_RX_FRAME_IO, NXP_RX_FRAME_FREE, (enum nxp_rx_frame_state)7,
	};
	struct nxp_rx_frame_census census;

	EXPECT_EQ(nxp_rx_frame_census_take(states, 9, &census), 0);
	EXPECT_EQ(census.free, 2);
	EXPECT_EQ(census.fill, 2);
	EXPECT_EQ(census.received, 1);
	EXPECT_EQ(census.io, 3);
	EXPECT_EQ(census.invalid, 1);
	EXPECT_EQ(nxp_rx_frame_census_outstanding(&census), 5);

	/* FREE and FILL frames are not the program's to release. */
	EXPECT_EQ(nxp_rx_frame_census_take(states, 3, &census), 0);
	EXPECT_EQ(census.free, 1);
	EXPECT_EQ(census.fill, 2);
	EXPECT_EQ(nxp_rx_frame_census_outstanding(&census), 0);

	/* A frame that went FILL -> RECEIVED -> IO is outstanding until its
	 * recycle, and one that went FILL -> RECEIVED until its drop. */
	states[0] = NXP_RX_FRAME_FREE;
	EXPECT_EQ(nxp_rx_frame_to_fill(&states[0]), 0);
	EXPECT_EQ(nxp_rx_frame_to_received(&states[0]), 0);
	EXPECT_EQ(nxp_rx_frame_census_take(states, 1, &census), 0);
	EXPECT_EQ(nxp_rx_frame_census_outstanding(&census), 1);
	EXPECT_EQ(nxp_rx_frame_hold_for_io(&states[0]), 0);
	EXPECT_EQ(nxp_rx_frame_census_take(states, 1, &census), 0);
	EXPECT_EQ(nxp_rx_frame_census_outstanding(&census), 1);
	EXPECT_EQ(nxp_rx_frame_recycle_after_io(&states[0]), 0);
	EXPECT_EQ(nxp_rx_frame_census_take(states, 1, &census), 0);
	EXPECT_EQ(nxp_rx_frame_census_outstanding(&census), 0);
	EXPECT_EQ(nxp_rx_frame_to_fill(&states[0]), 0);
	EXPECT_EQ(nxp_rx_frame_to_received(&states[0]), 0);
	EXPECT_EQ(nxp_rx_frame_drop(&states[0]), 0);
	EXPECT_EQ(nxp_rx_frame_census_take(states, 1, &census), 0);
	EXPECT_EQ(nxp_rx_frame_census_outstanding(&census), 0);

	EXPECT_EQ(nxp_rx_frame_census_take(states, 0, &census), 0);
	EXPECT_EQ(census.free + census.fill + census.received + census.io +
		  census.invalid, 0);
	EXPECT_EQ(nxp_rx_frame_census_take(NULL, 1, &census), -EINVAL);
	EXPECT_EQ(nxp_rx_frame_census_take(states, 1, NULL), -EINVAL);
	EXPECT_TRUE(nxp_rx_frame_census_outstanding(NULL) != 0);
}

static void test_submit_state_machine(void)
{
	struct nxp_request req[3] = { 0 };
	struct nxp_submit_result sr;
	uint32_t generation = 0;

	for (uint32_t i = 0; i < 3; i++) {
		EXPECT_EQ(nxp_request_prepare(&req[i], i, &generation), 0);
		EXPECT_EQ(req[i].state, NXP_REQ_PREPARED);
		EXPECT_TRUE(req[i].owns_backing);
		EXPECT_EQ(nxp_request_publish(&req[i]), 0);
	}

	sr = nxp_submit_classify(3, 3, 10, 13);
	EXPECT_EQ(sr.accepted, 3);
	EXPECT_FALSE(sr.invalidate);
	for (uint32_t i = 0; i < 3; i++)
		EXPECT_EQ(nxp_request_accept(&req[i]), 0);

	EXPECT_EQ(nxp_request_complete(&req[1], req[1].token), 0);
	EXPECT_EQ(req[1].state, NXP_REQ_COMPLETED);
	EXPECT_FALSE(req[1].owns_backing);
	EXPECT_EQ(nxp_request_complete(&req[1], req[1].token), -EALREADY);
	EXPECT_EQ(nxp_request_complete(&req[0], req[0].token + (UINT64_C(1) << 32)),
		  -ESTALE);
	EXPECT_EQ(req[0].state, NXP_REQ_ACCEPTED);
	EXPECT_TRUE(req[0].owns_backing);
	EXPECT_EQ(nxp_request_wait_failed(&req[0], -EIO), -EIO);
	EXPECT_EQ(req[0].state, NXP_REQ_ACCEPTED);
	EXPECT_TRUE(req[0].owns_backing);

	sr = nxp_submit_classify(0, 3, 10, 10);
	EXPECT_EQ(sr.accepted, 0);
	EXPECT_FALSE(sr.invalidate);
	sr = nxp_submit_classify(0, 3, 10, 11);
	EXPECT_EQ(sr.accepted, 1);
	EXPECT_FALSE(sr.invalidate);
	sr = nxp_submit_classify(1, 3, 10, 11);
	EXPECT_EQ(sr.accepted, 1);
	EXPECT_FALSE(sr.invalidate);
	sr = nxp_submit_classify(-EIO, 3, 10, 10);
	EXPECT_EQ(sr.accepted, 0);
	EXPECT_TRUE(sr.invalidate);
	sr = nxp_submit_classify(-EIO, 3, 10, 11);
	EXPECT_EQ(sr.accepted, 1);
	EXPECT_TRUE(sr.invalidate);
	sr = nxp_submit_classify(-EINTR, 3, 10, 10);
	EXPECT_EQ(sr.accepted, 0);
	EXPECT_FALSE(sr.invalidate);

	EXPECT_EQ(nxp_request_release_unaccepted(&req[2], false), -EBUSY);
	/* req[2] is accepted, so even rebuilding cannot release it. */
	EXPECT_EQ(nxp_request_release_unaccepted(&req[2], true), -EBUSY);

	memset(&req[2], 0, sizeof(req[2]));
	EXPECT_EQ(nxp_request_prepare(&req[2], 2, &generation), 0);
	EXPECT_EQ(nxp_request_publish(&req[2]), 0);
	EXPECT_EQ(nxp_request_release_unaccepted(&req[2], false), -EBUSY);
	EXPECT_EQ(nxp_request_release_unaccepted(&req[2], true), 0);
	EXPECT_FALSE(req[2].owns_backing);
}

static void test_generation_token_survives_slot_reuse(void)
{
	struct nxp_request req = { 0 };
	uint32_t generation = UINT32_MAX;
	uint64_t old_token;

	EXPECT_EQ(nxp_request_prepare(&req, 9, &generation), 0);
	EXPECT_EQ(generation, 1);
	old_token = req.token;
	EXPECT_EQ(nxp_request_publish(&req), 0);
	EXPECT_EQ(nxp_request_accept(&req), 0);
	EXPECT_EQ(nxp_request_complete(&req, req.token), 0);
	EXPECT_EQ(nxp_request_prepare(&req, 9, &generation), 0);
	EXPECT_TRUE(req.token != old_token);
	EXPECT_EQ(nxp_request_publish(&req), 0);
	EXPECT_EQ(nxp_request_accept(&req), 0);
	EXPECT_EQ(nxp_request_complete(&req, old_token), -ESTALE);
	EXPECT_TRUE(req.owns_backing);
	EXPECT_EQ(req.state, NXP_REQ_ACCEPTED);
	/* An extra stale CQE must not consume the later exact completion. */
	EXPECT_EQ(nxp_request_complete(&req, req.token), 0);
	EXPECT_FALSE(req.owns_backing);
}

static void test_latched_errors_and_quiescence(void)
{
	struct nxp_request req = { 0 };
	uint32_t generation = 0;
	unsigned int retries = 3;
	int first_error = 0;

	EXPECT_EQ(nxp_nvme_result_errno(0), 0);
	EXPECT_EQ(nxp_nvme_result_errno(-ENXIO), -ENXIO);
	EXPECT_EQ(nxp_nvme_result_errno(0x182), -EIO);
	nxp_latch_error(&first_error, -ENXIO);
	nxp_latch_error(&first_error, -EIO);
	EXPECT_EQ(first_error, -ENXIO);

	EXPECT_EQ(nxp_retry_consume(-EINTR, false, &retries), 0);
	EXPECT_EQ(nxp_retry_consume(-EAGAIN, false, &retries), 0);
	EXPECT_EQ(nxp_retry_consume(-EBUSY, false, &retries), 0);
	EXPECT_EQ(nxp_retry_consume(-EINTR, false, &retries), -ETIMEDOUT);
	retries = 1;
	EXPECT_EQ(nxp_retry_consume(-ETIME, true, &retries), 0);
	EXPECT_EQ(nxp_retry_consume(-ETIME, true, &retries), -ETIMEDOUT);
	retries = 1;
	EXPECT_EQ(nxp_retry_consume(-ETIME, false, &retries), -ETIME);

	EXPECT_EQ(nxp_request_prepare(&req, 4, &generation), 0);
	EXPECT_EQ(nxp_request_publish(&req), 0);
	EXPECT_EQ(nxp_request_accept(&req), 0);
	EXPECT_EQ(nxp_request_complete(&req, req.token + (UINT64_C(1) << 32)),
		  -ESTALE);
	/* A stale token never transfers backing ownership.  Production tests
	 * separately prove that an asynchronous ring close cannot do so either. */
	EXPECT_TRUE(req.owns_backing);
	EXPECT_EQ(req.state, NXP_REQ_ACCEPTED);
}

static void test_ready_ordering_and_statistics(void)
{
	struct nxp_data_progress p;
	struct nxp_stats stats = { 0 };

	nxp_data_begin(&p, true);
	EXPECT_EQ(nxp_data_publish(&p), -EAGAIN);
	EXPECT_EQ(nxp_data_dma_done(&p), 0);
	EXPECT_EQ(nxp_data_process(&p), -EAGAIN);
	EXPECT_EQ(nxp_data_copy(&p), 0);
	EXPECT_EQ(nxp_data_process(&p), 0);
	EXPECT_EQ(nxp_data_headers(&p), 0);
	EXPECT_EQ(nxp_data_publish(&p), 0);
	EXPECT_EQ(p.stage, NXP_DATA_READY);

	nxp_data_begin(&p, false);
	EXPECT_EQ(nxp_data_dma_done(&p), 0);
	EXPECT_EQ(nxp_data_process(&p), 0);
	EXPECT_EQ(nxp_data_headers(&p), 0);
	EXPECT_EQ(nxp_data_publish(&p), 0);

	nxp_stats_note(&stats, NXP_STAT_READ_ISSUED);
	nxp_stats_note(&stats, NXP_STAT_READ_OK);
	nxp_stats_note(&stats, NXP_STAT_READ_FAILED);
	nxp_stats_note(&stats, NXP_STAT_SUBMIT_ERROR);
	nxp_stats_note(&stats, NXP_STAT_WAIT_ERROR);
	nxp_stats_note(&stats, NXP_STAT_TX_SUBMITTED);
	nxp_stats_note(&stats, NXP_STAT_TX_RECLAIMED);
	nxp_stats_note(&stats, NXP_STAT_KICK_ERROR);
	nxp_stats_note(&stats, NXP_STAT_DROP);
	nxp_stats_note(&stats, NXP_STAT_PROTOCOL_ERROR);
	EXPECT_EQ(stats.read_issued, 1);
	EXPECT_EQ(stats.read_ok, 1);
	EXPECT_EQ(stats.read_failed, 1);
	EXPECT_EQ(stats.submit_errors, 1);
	EXPECT_EQ(stats.wait_errors, 1);
	EXPECT_EQ(stats.tx_submitted, 1);
	EXPECT_EQ(stats.tx_reclaimed, 1);
	EXPECT_EQ(stats.kick_errors, 1);
	EXPECT_EQ(stats.drops, 1);
	EXPECT_EQ(stats.protocol_errors, 1);
}

static void test_cleanup_is_reverse_initialization(void)
{
	uint32_t live = NXP_RESOURCE_CHAR_FD | NXP_RESOURCE_BLOCK_FD |
		NXP_RESOURCE_RING | NXP_RESOURCE_FIXED_FILE |
		NXP_RESOURCE_UMEM_MAP | NXP_RESOURCE_FIXED_BUFFER |
		NXP_RESOURCE_UMEM | NXP_RESOURCE_XSK;
	const uint32_t expected[] = {
		NXP_RESOURCE_FIXED_BUFFER,
		NXP_RESOURCE_XSK,
		NXP_RESOURCE_UMEM,
		NXP_RESOURCE_UMEM_MAP,
		NXP_RESOURCE_FIXED_FILE,
		NXP_RESOURCE_RING,
		NXP_RESOURCE_BLOCK_FD,
		NXP_RESOURCE_CHAR_FD,
	};

	for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
		uint32_t next = nxp_cleanup_next(live);

		EXPECT_EQ(next, expected[i]);
		live &= ~next;
	}
	EXPECT_EQ(nxp_cleanup_next(live), 0);
}

static void test_iopoll_requires_both_proofs(void)
{
	EXPECT_FALSE(nxp_iopoll_proven(0, 0));
	EXPECT_FALSE(nxp_iopoll_proven(8, 0));
	EXPECT_FALSE(nxp_iopoll_proven(0, 1));
	EXPECT_FALSE(nxp_iopoll_proven(8, 2));
	EXPECT_TRUE(nxp_iopoll_proven(8, 1));
}

static void test_integer_arguments_never_wrap(void)
{
	uint64_t u64 = 0;
	uint32_t u32 = 0;
	int positive = 0;

	EXPECT_EQ(nxp_parse_u64("0", &u64), 0);
	EXPECT_EQ(u64, 0);
	EXPECT_EQ(nxp_parse_u64("0x100000000", &u64), 0);
	EXPECT_EQ(u64, UINT64_C(0x100000000));
	EXPECT_EQ(nxp_parse_u64("18446744073709551615", &u64), 0);
	EXPECT_EQ(u64, UINT64_MAX);
	EXPECT_EQ(nxp_parse_u64("18446744073709551616", &u64), -ERANGE);
	EXPECT_EQ(nxp_parse_u64("-1", &u64), -EINVAL);
	EXPECT_EQ(nxp_parse_u64("1x", &u64), -EINVAL);
	EXPECT_EQ(nxp_parse_u64("", &u64), -EINVAL);

	EXPECT_EQ(nxp_parse_u32("4294967295", &u32), 0);
	EXPECT_EQ(u32, UINT32_MAX);
	EXPECT_EQ(nxp_parse_u32("4294967296", &u32), -ERANGE);
	EXPECT_EQ(nxp_parse_positive_int("1", 2048, &positive), 0);
	EXPECT_EQ(positive, 1);
	EXPECT_EQ(nxp_parse_positive_int("0", 2048, &positive), -ERANGE);
	EXPECT_EQ(nxp_parse_positive_int("2049", 2048, &positive), -ERANGE);
}

static void test_rx_empty_poll_wakeups_have_an_absolute_deadline(void)
{
	const uint64_t deadline = UINT64_C(5000000100);

	EXPECT_EQ(nxp_rx_idle_poll_result(1, POLLERR, deadline - 1, deadline),
		  -EIO);
	EXPECT_EQ(nxp_rx_idle_poll_result(1, POLLHUP, deadline - 1, deadline),
		  -EPIPE);
	EXPECT_EQ(nxp_rx_idle_poll_result(1, POLLNVAL, deadline - 1, deadline),
		  -EBADF);
	EXPECT_EQ(nxp_rx_idle_poll_result(1, POLLIN, deadline - 1, deadline),
		  -EAGAIN);
	EXPECT_EQ(nxp_rx_idle_poll_result(0, 0, deadline - 1, deadline),
		  -EAGAIN);
	EXPECT_EQ(nxp_rx_idle_poll_result(1, POLLIN, deadline, deadline),
		  -ETIMEDOUT);
	EXPECT_EQ(nxp_rx_idle_poll_result(0, 0, deadline + 1, deadline),
		  -ETIMEDOUT);
}

/* ---- PIPELINE_RX_SUMMARY: the rx-write receiver's A/B measurement ---- */

static uint64_t test_lcg_next(uint64_t *state)
{
	*state = *state * UINT64_C(6364136223846793005) +
		 UINT64_C(1442695040888963407);
	return *state >> 11;
}

/* Sort a copy with each side's sort and compare every percentile 0..100,
 * plus out-of-range percents, between nxp_nearest_rank and the baseline's
 * spb_nearest_rank. */
static void expect_rank_identity(const uint64_t *input, size_t count)
{
	static const unsigned int beyond[] = { 101, 150, 1000, UINT_MAX };
	uint64_t *ours = NULL;
	uint64_t *theirs = NULL;
	bool ascending = true;

	if (count) {
		ours = malloc(count * sizeof(*ours));
		theirs = malloc(count * sizeof(*theirs));
		EXPECT_TRUE(ours != NULL && theirs != NULL);
		if (!ours || !theirs) {
			free(ours);
			free(theirs);
			return;
		}
		memcpy(ours, input, count * sizeof(*ours));
		memcpy(theirs, input, count * sizeof(*theirs));
	}
	nxp_sort_u64(ours, count);
	spb_sort_u64(theirs, count);
	EXPECT_EQ(count ? memcmp(ours, theirs, count * sizeof(*ours)) : 0, 0);
	for (size_t i = 1; i < count; i++)
		ascending = ascending && ours[i - 1] <= ours[i];
	EXPECT_TRUE(ascending);
	for (unsigned int p = 0; p <= 100; p++)
		EXPECT_EQ(nxp_nearest_rank(ours, count, p),
			  spb_nearest_rank(theirs, count, p));
	for (size_t i = 0; i < sizeof(beyond) / sizeof(beyond[0]); i++)
		EXPECT_EQ(nxp_nearest_rank(ours, count, beyond[i]),
			  spb_nearest_rank(theirs, count, beyond[i]));
	free(ours);
	free(theirs);
}

static void test_rx_summary_nearest_rank_is_the_baseline_definition(void)
{
	static const uint64_t one[] = { 42 };
	static const uint64_t two[] = { 7, 3 };
	static const uint64_t odd[] = { 9, 1, 5, 3, 7 };
	static const uint64_t even[] = { 8, 2, 6, 4 };
	static const uint64_t duplicates[] = { 5, 5, 5, 1, 1, 9, 9, 9, 9 };
	static const uint64_t equal[] = { 3, 3, 3, 3, 3, 3 };
	static const uint64_t unsorted[] = {
		UINT64_MAX - 1, 0, UINT64_C(1) << 40, 17, UINT64_MAX,
		UINT64_C(12345678901), 2, 17, 999999, 1,
	};
	static const size_t large_sizes[] = { 99, 100, 101, 199, 1000, 10007 };
	uint64_t descending[100];
	uint64_t ascending[100];
	uint64_t seed = UINT64_C(0x5eed);

	expect_rank_identity(NULL, 0);
	expect_rank_identity(one, 1);
	expect_rank_identity(two, 2);
	expect_rank_identity(odd, 5);
	expect_rank_identity(even, 4);
	expect_rank_identity(duplicates, 9);
	expect_rank_identity(equal, 6);
	expect_rank_identity(unsorted, 10);
	for (size_t i = 0; i < 100; i++)
		descending[i] = 100 - i;
	expect_rank_identity(descending, 100);
	for (size_t s = 0; s < sizeof(large_sizes) / sizeof(large_sizes[0]);
	     s++) {
		uint64_t *values = malloc(large_sizes[s] * sizeof(*values));

		EXPECT_TRUE(values != NULL);
		if (!values)
			continue;
		for (size_t i = 0; i < large_sizes[s]; i++)
			values[i] = test_lcg_next(&seed) %
				    (i % 3 ? UINT64_C(1000) :
					     UINT64_C(1) << 50);
		expect_rank_identity(values, large_sizes[s]);
		free(values);
	}
	/* NULL with a nonzero count is "no samples" on both sides. */
	EXPECT_EQ(nxp_nearest_rank(NULL, 5, 50), spb_nearest_rank(NULL, 5, 50));
	EXPECT_EQ(nxp_nearest_rank(NULL, 5, 50), 0);

	/* Nearest rank, rank = ceil(p * n / 100), on known inputs. */
	for (size_t i = 0; i < 100; i++)
		ascending[i] = i + 1;
	EXPECT_EQ(nxp_nearest_rank(ascending, 100, 0), 1);
	EXPECT_EQ(nxp_nearest_rank(ascending, 100, 50), 50);
	EXPECT_EQ(nxp_nearest_rank(ascending, 100, 99), 99);
	EXPECT_EQ(nxp_nearest_rank(ascending, 100, 100), 100);
	EXPECT_EQ(nxp_nearest_rank(ascending, 10, 99), 10);
	EXPECT_EQ(nxp_nearest_rank(ascending, 10, 50), 5);
	EXPECT_EQ(nxp_nearest_rank(ascending, 2, 50), 1);
	EXPECT_EQ(nxp_nearest_rank(ascending, 2, 99), 2);
	EXPECT_EQ(nxp_nearest_rank(ascending, 1, 99), 1);
}

/* One completed group whose first accepted packet was seen at accept_ns and
 * whose NVMe WRITE CQE was reaped at done_ns. */
static void complete_one_group(struct nxp_rx_summary *s, uint32_t slot,
			       uint64_t accept_ns, uint64_t done_ns)
{
	EXPECT_EQ(nxp_rx_summary_arm_group(s, slot, accept_ns), 0);
	nxp_rx_summary_note_submitted(s, 1);
	EXPECT_EQ(nxp_rx_summary_note_completion(s, slot, true, 8192,
						 &done_ns), 0);
}

static void test_rx_summary_report_percentiles_match_the_baseline(void)
{
	static const uint64_t service_ns[] = {
		900000, 1500, 250000, 1500, 7999, 3000000, 12345, 1000, 999,
		64000001,
	};
	const size_t count = sizeof(service_ns) / sizeof(service_ns[0]);
	struct nxp_rx_group_clock clocks[2];
	struct nxp_rx_summary_report report;
	struct nxp_rx_summary s;
	uint64_t recorded[16];
	uint64_t sorted[16];

	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 16, clocks, 2), 0);
	nxp_rx_summary_note_rx(&s, 1000);
	for (size_t i = 0; i < count; i++)
		complete_one_group(&s, (uint32_t)(i % 2),
				   UINT64_C(5000) + i * UINT64_C(100000000),
				   UINT64_C(5000) + i * UINT64_C(100000000) +
				   service_ns[i]);
	EXPECT_EQ(s.service_count, count);
	memcpy(sorted, service_ns, sizeof(service_ns));
	spb_sort_u64(sorted, count);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	/* The baseline's spb_print_summary(): nearest rank in ns, then /1000. */
	EXPECT_EQ(report.group_service_us_p50,
		  spb_nearest_rank(sorted, count, 50) / UINT64_C(1000));
	EXPECT_EQ(report.group_service_us_p99,
		  spb_nearest_rank(sorted, count, 99) / UINT64_C(1000));
	EXPECT_EQ(report.group_service_us_p50, 7);     /* 7999 ns */
	EXPECT_EQ(report.group_service_us_p99, 64000); /* 64000001 ns */
	EXPECT_EQ(report.groups, count);
	EXPECT_EQ(report.bytes_written, count * 8192);

	/* 100 groups of 1..100 us, completed in descending order: p50 and p99
	 * are the 50th and 99th smallest, distinct from p95. */
	{
		struct nxp_rx_group_clock many_clocks[1];
		uint64_t many[100];
		uint64_t many_sorted[100];

		EXPECT_EQ(nxp_rx_summary_init(&s, many, 100, many_clocks, 1), 0);
		for (uint64_t i = 0; i < 100; i++)
			complete_one_group(&s, 0, i * UINT64_C(1000000),
					   i * UINT64_C(1000000) +
					   (100 - i) * UINT64_C(1000));
		memcpy(many_sorted, many, sizeof(many));
		spb_sort_u64(many_sorted, 100);
		EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
		EXPECT_EQ(report.group_service_us_p50, 50);
		EXPECT_EQ(report.group_service_us_p99, 99);
		EXPECT_EQ(report.group_service_us_p50,
			  spb_nearest_rank(many_sorted, 100, 50) / 1000);
		EXPECT_EQ(report.group_service_us_p99,
			  spb_nearest_rank(many_sorted, 100, 99) / 1000);
	}
}

static void test_rx_summary_line_is_exact_and_ordered(void)
{
	static const char *const keys[] = {
		"groups", "packets_accepted", "packets_dropped",
		"bytes_written", "write_errors", "cpu_user_us", "cpu_sys_us",
		"wall_us", "group_service_us_p50", "group_service_us_p99",
		"nvme_cmds", "max_inflight", "frames_received",
		"frames_returned", "frames_outstanding", "rx_span_us",
		"tail_us", "group_post_arrival_us_p50",
		"group_post_arrival_us_p99",
	};
	const size_t nkeys = sizeof(keys) / sizeof(keys[0]);
	/* The first twelve fields keep their original order; the frame
	 * census is appended after them, and the receive span, the tail and
	 * the post-arrival percentiles after the census. */
	const char *expected =
		"PIPELINE_RX_SUMMARY groups=1 packets_accepted=2 "
		"packets_dropped=3 bytes_written=4 write_errors=5 "
		"cpu_user_us=6 cpu_sys_us=7 wall_us=8 "
		"group_service_us_p50=9 group_service_us_p99=10 nvme_cmds=11 "
		"max_inflight=12 frames_received=13 frames_returned=14 "
		"frames_outstanding=15 rx_span_us=16 tail_us=17 "
		"group_post_arrival_us_p50=18 group_post_arrival_us_p99=19";
	struct nxp_rx_summary_report report = {
		.groups = 1, .packets_accepted = 2, .packets_dropped = 3,
		.bytes_written = 4, .write_errors = 5, .cpu_user_us = 6,
		.cpu_sys_us = 7, .wall_us = 8, .group_service_us_p50 = 9,
		.group_service_us_p99 = 10, .nvme_cmds = 11,
		.max_inflight = 12, .frames_received = 13,
		.frames_returned = 14, .frames_outstanding = 15,
		.rx_span_us = 16, .tail_us = 17,
		.group_post_arrival_us_p50 = 18,
		.group_post_arrival_us_p99 = 19,
	};
	char line[NXP_RX_SUMMARY_LINE_MAX];
	char copy[NXP_RX_SUMMARY_LINE_MAX];
	char *save = NULL;
	char *token;
	size_t index = 0;

	EXPECT_EQ(nxp_rx_summary_format(&report, line, sizeof(line)),
		  strlen(expected));
	EXPECT_EQ(strcmp(line, expected), 0);
	EXPECT_TRUE(strchr(line, '\n') == NULL);

	/* Field order is fixed: the tag, then exactly these nineteen keys. */
	memcpy(copy, line, sizeof(copy));
	for (token = strtok_r(copy, " ", &save); token;
	     token = strtok_r(NULL, " ", &save), index++) {
		size_t key_len;

		if (!index) {
			EXPECT_EQ(strcmp(token, "PIPELINE_RX_SUMMARY"), 0);
			continue;
		}
		EXPECT_TRUE(index <= nkeys);
		if (index > nkeys)
			break;
		key_len = strlen(keys[index - 1]);
		EXPECT_EQ(strncmp(token, keys[index - 1], key_len), 0);
		EXPECT_EQ(token[key_len], '=');
	}
	EXPECT_EQ(index, 1 + nkeys);

	/* The largest values still fit the fixed line buffer. */
	report = (struct nxp_rx_summary_report) {
		.groups = UINT64_MAX, .packets_accepted = UINT64_MAX,
		.packets_dropped = UINT64_MAX, .bytes_written = UINT64_MAX,
		.write_errors = UINT64_MAX, .cpu_user_us = UINT64_MAX,
		.cpu_sys_us = UINT64_MAX, .wall_us = UINT64_MAX,
		.group_service_us_p50 = UINT64_MAX,
		.group_service_us_p99 = UINT64_MAX, .nvme_cmds = UINT64_MAX,
		.max_inflight = UINT64_MAX, .frames_received = UINT64_MAX,
		.frames_returned = UINT64_MAX,
		.frames_outstanding = UINT64_MAX, .rx_span_us = UINT64_MAX,
		.tail_us = UINT64_MAX,
		.group_post_arrival_us_p50 = UINT64_MAX,
		.group_post_arrival_us_p99 = UINT64_MAX,
	};
	EXPECT_TRUE(nxp_rx_summary_format(&report, line, sizeof(line)) > 0);
	EXPECT_TRUE(strstr(line, " max_inflight=18446744073709551615 ") !=
		    NULL);
	EXPECT_TRUE(strstr(line, " frames_outstanding=18446744073709551615 ") !=
		    NULL);
	{
		const char *tail =
			" group_post_arrival_us_p99=18446744073709551615";
		size_t len = strlen(line), tail_len = strlen(tail);

		EXPECT_TRUE(len > tail_len &&
			    strcmp(line + len - tail_len, tail) == 0);
	}
	EXPECT_EQ(nxp_rx_summary_format(&report, line, 16), -ENOSPC);
	EXPECT_EQ(nxp_rx_summary_format(NULL, line, sizeof(line)), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_format(&report, NULL, sizeof(line)), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_format(&report, line, 0), -EINVAL);
}

/* The receive span runs from the first packet examined (the start of
 * wall_us) to the arrival of the packet that completed the last group to
 * complete; the tail from that arrival to the end of wall_us, so the two add
 * up to wall_us to within the truncation to whole microseconds.  Each group
 * whose write succeeds is sampled once more, from the arrival of its own last
 * packet to its write completion: unlike the service time, that sample does
 * not include the time the group's packets took to arrive. */
static void test_rx_summary_receive_span_tail_and_post_arrival(void)
{
	struct nxp_rx_group_clock clocks[2];
	struct nxp_rx_summary_report report;
	struct nxp_rx_summary s;
	uint64_t service[4];
	uint64_t post[4];
	uint64_t now;

	EXPECT_EQ(nxp_rx_summary_init(&s, service, 4, clocks, 2), 0);
	EXPECT_EQ(nxp_rx_summary_track_post_arrival(&s, post, 4), 0);
	EXPECT_EQ(s.post_arrival_count, 0);
	nxp_rx_summary_note_rx(&s, 1000000);
	/* Group A in slot 0: first accepted packet at 1.0 ms, last at 1.5 ms;
	 * group B in slot 1: 1.6 ms and 2.0 ms. */
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 0, 1000000), 0);
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 0, 1500000), 0);
	EXPECT_EQ(s.last_arrival_ns, 1500000);
	nxp_rx_summary_note_submitted(&s, 1);
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 1, 1600000), 0);
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 1, 2000000), 0);
	EXPECT_EQ(s.last_arrival_ns, 2000000);
	nxp_rx_summary_note_submitted(&s, 1);
	/* A is written at 2.2 ms, B at 2.25 ms. */
	now = 2200000;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, true, 8192, &now), 0);
	now = 2250999;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 1, true, 8192, &now), 0);
	EXPECT_EQ(s.post_arrival_count, 2);
	EXPECT_EQ(post[0], 700000);
	EXPECT_EQ(post[1], 250999);
	EXPECT_FALSE(clocks[0].arrived);
	EXPECT_FALSE(clocks[1].arrived);
	nxp_rx_summary_note_loop_end(&s, 9000000);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.wall_us, 1250);
	EXPECT_EQ(report.rx_span_us, 1000);
	EXPECT_EQ(report.tail_us, 250);
	EXPECT_EQ(report.group_service_us_p50, 650);
	EXPECT_EQ(report.group_service_us_p99, 1200);
	EXPECT_EQ(report.group_post_arrival_us_p50, 250);
	EXPECT_EQ(report.group_post_arrival_us_p99, 700);

	/* A failed write is not sampled; its arrival still ends the span. */
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 0, 3000000), 0);
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 0, 3100000), 0);
	nxp_rx_summary_note_submitted(&s, 1);
	now = 3300000;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, false, 8192, &now), 0);
	EXPECT_EQ(s.post_arrival_count, 2);
	EXPECT_FALSE(clocks[0].arrived);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.rx_span_us, 2100);
	EXPECT_EQ(report.tail_us, 200);
	EXPECT_EQ(report.wall_us, 2300);

	/* The next group in a slot clears an arrival its predecessor left (a
	 * complete group whose write was never submitted), so a write is
	 * sampled only from its own group's last packet. */
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 1, 3400000), 0);
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 1, 3500000), 0);
	EXPECT_FALSE(clocks[1].arrived);
	nxp_rx_summary_note_submitted(&s, 1);
	now = 3600000;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 1, true, 8192, &now), 0);
	EXPECT_EQ(s.post_arrival_count, 2);
	EXPECT_EQ(s.service_count, 3);

	/* No completion time: written, not sampled.  A clock behind the
	 * arrival samples zero.  The sample buffer never overflows. */
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 0, 4000000), 0);
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 0, 4100000), 0);
	nxp_rx_summary_note_submitted(&s, 1);
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, true, 8192, NULL), 0);
	EXPECT_EQ(s.post_arrival_count, 2);
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 0, 5000000), 0);
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 0, 5100000), 0);
	nxp_rx_summary_note_submitted(&s, 1);
	now = 5050000;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, true, 8192, &now), 0);
	EXPECT_EQ(s.post_arrival_count, 3);
	EXPECT_EQ(post[2], 0);
	for (uint64_t i = 0; i < 3; i++) {
		EXPECT_EQ(nxp_rx_summary_arm_group(&s, 0, 6000000 + i), 0);
		EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 0,
							    6100000 + i), 0);
		nxp_rx_summary_note_submitted(&s, 1);
		now = 6200000 + i;
		EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, true, 8192,
							 &now), 0);
	}
	EXPECT_EQ(s.post_arrival_count, 4);
	EXPECT_EQ(post[3], 100000);

	/* A last arrival at or after the end of wall_us leaves no tail. */
	EXPECT_EQ(nxp_rx_summary_init(&s, service, 4, clocks, 2), 0);
	nxp_rx_summary_note_rx(&s, 1000000);
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 0, 1000000), 0);
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 0, 2000000), 0);
	nxp_rx_summary_note_loop_end(&s, 2000000);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.wall_us, 1000);
	EXPECT_EQ(report.rx_span_us, 1000);
	EXPECT_EQ(report.tail_us, 0);
	/* Not tracked: the post-arrival percentiles stay zero. */
	EXPECT_EQ(report.group_post_arrival_us_p50, 0);
	EXPECT_EQ(report.group_post_arrival_us_p99, 0);

	/* No group arrived: no span and no tail, whatever wall_us is. */
	EXPECT_EQ(nxp_rx_summary_init(&s, service, 4, clocks, 2), 0);
	nxp_rx_summary_note_rx(&s, 1000000);
	nxp_rx_summary_note_loop_end(&s, 5000000);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.wall_us, 4000);
	EXPECT_EQ(report.rx_span_us, 0);
	EXPECT_EQ(report.tail_us, 0);

	/* Argument checks, without side effects. */
	EXPECT_EQ(nxp_rx_summary_track_post_arrival(NULL, post, 4), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_track_post_arrival(&s, NULL, 4), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_track_post_arrival(&s, post, 0), 0);
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(NULL, 0, 1), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 2, 7000000), -ERANGE);
	EXPECT_FALSE(s.last_arrival_seen);
}

/* The same run timed by both receivers' definitions: the pipeline's
 * nxp_rx_summary and the baseline's spb_arrival_report() give the same
 * receive span, tail and post-arrival percentiles. */
static void test_rx_summary_arrival_fields_match_the_baseline(void)
{
	static const uint64_t accept_ns[] = { 1000000, 1700000, 2950000 };
	static const uint64_t arrival_ns[] = { 1500000, 2600000, 3300001 };
	static const uint64_t done_ns[] = { 2100000, 2800999, 9100000 };
	const size_t count = sizeof(done_ns) / sizeof(done_ns[0]);
	struct nxp_rx_group_clock clocks[1];
	struct nxp_rx_summary_report report;
	struct spb_arrival_report baseline;
	struct nxp_rx_summary s;
	uint64_t service[3], post[3], baseline_post[3];

	EXPECT_EQ(nxp_rx_summary_init(&s, service, 3, clocks, 1), 0);
	EXPECT_EQ(nxp_rx_summary_track_post_arrival(&s, post, 3), 0);
	nxp_rx_summary_note_rx(&s, 999999);
	for (size_t i = 0; i < count; i++) {
		EXPECT_EQ(nxp_rx_summary_arm_group(&s, 0, accept_ns[i]), 0);
		EXPECT_EQ(nxp_rx_summary_note_group_arrived(&s, 0,
							    arrival_ns[i]), 0);
		nxp_rx_summary_note_submitted(&s, 1);
		EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, true, 8192,
							 &done_ns[i]), 0);
		baseline_post[i] = done_ns[i] - arrival_ns[i];
	}
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	spb_arrival_report(999999, arrival_ns[count - 1], done_ns[count - 1],
			   baseline_post, count, &baseline);
	EXPECT_EQ(report.rx_span_us, baseline.rx_span_us);
	EXPECT_EQ(report.tail_us, baseline.tail_us);
	EXPECT_EQ(report.group_post_arrival_us_p50,
		  baseline.post_arrival_us_p50);
	EXPECT_EQ(report.group_post_arrival_us_p99,
		  baseline.post_arrival_us_p99);
	EXPECT_EQ(report.rx_span_us, 2300);
	EXPECT_EQ(report.tail_us, 5799);
	EXPECT_EQ(report.group_post_arrival_us_p50, 600);
	EXPECT_EQ(report.group_post_arrival_us_p99, 5799);
	EXPECT_EQ(report.wall_us, 8100);
}

static void test_rx_summary_samples_once_per_completed_group(void)
{
	struct nxp_rx_group_clock clocks[2];
	struct nxp_rx_summary s;
	uint64_t recorded[3];
	uint64_t now;

	EXPECT_EQ(nxp_rx_summary_init(NULL, recorded, 3, clocks, 2), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_init(&s, NULL, 3, clocks, 2), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 3, NULL, 2), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 3, clocks, 0), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 3, clocks, 2), 0);
	EXPECT_EQ(s.service_count, 0);
	EXPECT_EQ(s.inflight, 0);

	/* Completed group: first accepted packet -> successful CQE. */
	complete_one_group(&s, 0, 1000, 2500);
	EXPECT_EQ(s.groups, 1);
	EXPECT_EQ(s.bytes_written, 8192);
	EXPECT_EQ(s.service_count, 1);
	EXPECT_EQ(recorded[0], 1500);
	EXPECT_FALSE(clocks[0].armed);

	/* A CQE with nothing in flight is an accounting fault, not a sample. */
	now = 2600;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, true, 8192, &now),
		  -EPROTO);
	EXPECT_EQ(s.groups, 1);
	EXPECT_EQ(s.service_count, 1);

	/* The clock is consumed by its completion: a second write from the same
	 * slot that was never re-armed is counted as written but not sampled. */
	nxp_rx_summary_note_submitted(&s, 1);
	now = 2700;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, true, 8192, &now), 0);
	EXPECT_EQ(s.groups, 2);
	EXPECT_EQ(s.service_count, 1);

	/* A failed group is never sampled and counts as a write error. */
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 1, 3000), 0);
	nxp_rx_summary_note_submitted(&s, 1);
	now = 3900;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 1, false, 8192, &now), 0);
	EXPECT_EQ(s.write_errors, 1);
	EXPECT_EQ(s.groups, 2);
	EXPECT_EQ(s.bytes_written, 2 * 8192);
	EXPECT_EQ(s.service_count, 1);
	EXPECT_FALSE(clocks[1].armed);
	EXPECT_EQ(s.end_ns, 3900);

	/* An expired group never completes: the slot's next group re-arms the
	 * clock with its own first accepted packet, so the sample runs from the
	 * retry, not from the expired group. */
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 0, 4000), 0);
	complete_one_group(&s, 0, 9000, 9500);
	EXPECT_EQ(s.service_count, 2);
	EXPECT_EQ(recorded[1], 500);
	EXPECT_EQ(s.groups, 3);

	/* No completion time (clock failure): written, end time untouched, no
	 * sample. */
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 1, 9600), 0);
	nxp_rx_summary_note_submitted(&s, 1);
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 1, true, 8192, NULL), 0);
	EXPECT_EQ(s.groups, 4);
	EXPECT_EQ(s.service_count, 2);
	EXPECT_EQ(s.end_ns, 9500);
	EXPECT_FALSE(clocks[1].armed);

	/* A clock that went backwards records zero, as the baseline does. */
	complete_one_group(&s, 1, 20000, 10000);
	EXPECT_EQ(s.service_count, 3);
	EXPECT_EQ(recorded[2], 0);

	/* The sample buffer never overflows; groups are still counted. */
	complete_one_group(&s, 0, 30000, 31000);
	EXPECT_EQ(s.service_count, 3);
	EXPECT_EQ(s.groups, 6);

	/* Slots outside the clock table are refused without side effects. */
	EXPECT_EQ(nxp_rx_summary_arm_group(&s, 2, 1), -ERANGE);
	nxp_rx_summary_note_submitted(&s, 1);
	now = 40000;
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 2, true, 8192, &now),
		  -ERANGE);
	EXPECT_EQ(s.inflight, 1);
	EXPECT_EQ(s.groups, 6);
	EXPECT_EQ(s.end_ns, 31000);
	EXPECT_EQ(nxp_rx_summary_arm_group(NULL, 0, 1), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_note_completion(NULL, 0, true, 8192, &now),
		  -EINVAL);
}

static void test_rx_summary_counts_packets_commands_and_depth(void)
{
	struct nxp_rx_group_clock clocks[4];
	struct nxp_rx_summary s;
	uint64_t recorded[4];
	uint64_t now = 100;

	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 4, clocks, 4), 0);
	for (int i = 0; i < 9; i++)
		nxp_rx_summary_note_packet(&s, true);
	for (int i = 0; i < 4; i++)
		nxp_rx_summary_note_packet(&s, false);
	EXPECT_EQ(s.packets_accepted, 9);
	EXPECT_EQ(s.packets_dropped, 4);
	EXPECT_EQ(s.packets_accepted + s.packets_dropped, 13);

	/* nvme_cmds counts WRITEs the kernel accepted; max_inflight is the most
	 * accepted and not yet reaped at once. */
	nxp_rx_summary_note_submitted(&s, 2);
	EXPECT_EQ(s.nvme_cmds, 2);
	EXPECT_EQ(s.inflight, 2);
	EXPECT_EQ(s.max_inflight, 2);
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 0, true, 8192, &now), 0);
	nxp_rx_summary_note_submitted(&s, 1);
	EXPECT_EQ(s.nvme_cmds, 3);
	EXPECT_EQ(s.inflight, 2);
	EXPECT_EQ(s.max_inflight, 2);
	nxp_rx_summary_note_submitted(&s, 0);
	EXPECT_EQ(s.nvme_cmds, 3);
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 1, true, 8192, &now), 0);
	EXPECT_EQ(nxp_rx_summary_note_completion(&s, 2, true, 8192, &now), 0);
	EXPECT_EQ(s.inflight, 0);
	EXPECT_EQ(s.max_inflight, 2);

	/* Groups whose WRITE was never accepted are write errors. */
	nxp_rx_summary_note_submit_failed(&s, 3);
	EXPECT_EQ(s.write_errors, 3);
	EXPECT_EQ(s.nvme_cmds, 3);
	EXPECT_EQ(s.inflight, 0);

	/* NULL is ignored by the counters. */
	nxp_rx_summary_note_packet(NULL, true);
	nxp_rx_summary_note_submitted(NULL, 1);
	nxp_rx_summary_note_submit_failed(NULL, 1);
	nxp_rx_summary_note_rx(NULL, 1);
	nxp_rx_summary_note_loop_end(NULL, 1);
}

/* frames_received and frames_returned count the frame transitions of the run;
 * frames_outstanding is the census at loop exit.  Every frame received must
 * have been returned exactly once: anything outstanding, or counters that do
 * not add up to the census, fails the run with -EPROTO. */
static void test_rx_summary_frame_census_fails_closed(void)
{
	struct nxp_rx_group_clock clocks[1];
	struct nxp_rx_summary_report report;
	struct nxp_rx_frame_census census;
	struct nxp_rx_summary s;
	uint64_t recorded[1];

	/* Six received, six returned, none outstanding. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 1, clocks, 1), 0);
	EXPECT_EQ(s.frames_received, 0);
	EXPECT_EQ(s.frames_returned, 0);
	for (int i = 0; i < 6; i++)
		nxp_rx_summary_note_frame_received(&s);
	for (int i = 0; i < 6; i++)
		nxp_rx_summary_note_frame_returned(&s);
	census = (struct nxp_rx_frame_census) { .free = 10, .fill = 54 };
	EXPECT_EQ(nxp_rx_summary_note_census(&s, &census), 0);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.frames_received, 6);
	EXPECT_EQ(report.frames_returned, 6);
	EXPECT_EQ(report.frames_outstanding, 0);

	/* One frame still held for a WRITE that was never retired. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 1, clocks, 1), 0);
	for (int i = 0; i < 6; i++)
		nxp_rx_summary_note_frame_received(&s);
	for (int i = 0; i < 5; i++)
		nxp_rx_summary_note_frame_returned(&s);
	census = (struct nxp_rx_frame_census) { .free = 63, .io = 1 };
	EXPECT_EQ(nxp_rx_summary_note_census(&s, &census), -EPROTO);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.frames_received, 6);
	EXPECT_EQ(report.frames_returned, 5);
	EXPECT_EQ(report.frames_outstanding, 1);

	/* One frame examined and then neither held nor dropped. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 1, clocks, 1), 0);
	nxp_rx_summary_note_frame_received(&s);
	census = (struct nxp_rx_frame_census) { .received = 1 };
	EXPECT_EQ(nxp_rx_summary_note_census(&s, &census), -EPROTO);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.frames_outstanding, 1);

	/* A state outside the enum is outstanding. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 1, clocks, 1), 0);
	nxp_rx_summary_note_frame_received(&s);
	census = (struct nxp_rx_frame_census) { .invalid = 1 };
	EXPECT_EQ(nxp_rx_summary_note_census(&s, &census), -EPROTO);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.frames_outstanding, 1);

	/* Counters that do not add up to the census: a frame returned twice,
	 * or one released without passing through the counted transitions. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 1, clocks, 1), 0);
	for (int i = 0; i < 6; i++)
		nxp_rx_summary_note_frame_received(&s);
	for (int i = 0; i < 7; i++)
		nxp_rx_summary_note_frame_returned(&s);
	census = (struct nxp_rx_frame_census) { .free = 64 };
	EXPECT_EQ(nxp_rx_summary_note_census(&s, &census), -EPROTO);
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 1, clocks, 1), 0);
	for (int i = 0; i < 6; i++)
		nxp_rx_summary_note_frame_received(&s);
	for (int i = 0; i < 5; i++)
		nxp_rx_summary_note_frame_returned(&s);
	EXPECT_EQ(nxp_rx_summary_note_census(&s, &census), -EPROTO);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.frames_received, 6);
	EXPECT_EQ(report.frames_returned, 5);
	EXPECT_EQ(report.frames_outstanding, 0);

	EXPECT_EQ(nxp_rx_summary_note_census(NULL, &census), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_note_census(&s, NULL), -EINVAL);
	nxp_rx_summary_note_frame_received(NULL);
	nxp_rx_summary_note_frame_returned(NULL);
}

/* A SIGTERM/SIGINT stop is not a success: rx-write fails with -EINTR when
 * the stop left requested groups unwritten, and not when every group was
 * already written before the loop saw it. */
static void test_rx_stop_fails_only_an_unfinished_run(void)
{
	EXPECT_EQ(nxp_rx_stop_result(0, 0, 4), 0);
	EXPECT_EQ(nxp_rx_stop_result(0, 4, 4), 0);
	EXPECT_EQ(nxp_rx_stop_result(15, 0, 4), -EINTR);
	EXPECT_EQ(nxp_rx_stop_result(15, 3, 4), -EINTR);
	EXPECT_EQ(nxp_rx_stop_result(2, 3, 4), -EINTR);
	EXPECT_EQ(nxp_rx_stop_result(15, 4, 4), 0);
}

/* The exit status of a failed run: 128 + the signal number when the run's
 * only failure is that stop (what a shell reports for a process the signal
 * ended), 1 for every other failure, including a teardown failure after the
 * stop or any error latched before it. */
static void test_stopped_run_exit_status(void)
{
	EXPECT_EQ(nxp_stop_exit_status(-EINTR, 0, 15), 143);
	EXPECT_EQ(nxp_stop_exit_status(-EINTR, 0, 2), 130);
	EXPECT_EQ(nxp_stop_exit_status(-EINTR, -EBUSY, 15), 1);
	EXPECT_EQ(nxp_stop_exit_status(-EINTR, 0, 0), 1);
	EXPECT_EQ(nxp_stop_exit_status(-EPROTO, 0, 15), 1);
	EXPECT_EQ(nxp_stop_exit_status(-EIO, 0, 15), 1);
	EXPECT_EQ(nxp_stop_exit_status(-EINTR, 0, 128), 1);
	EXPECT_EQ(nxp_stop_exit_status(-EINTR, 0, -1), 1);
}

static void test_rx_summary_wall_and_cpu_follow_the_baseline(void)
{
	struct nxp_rx_group_clock clocks[1];
	struct nxp_rx_summary_report report;
	struct nxp_rx_summary s;
	struct timeval tv = { .tv_sec = 2, .tv_usec = 345678 };
	uint64_t recorded[2];

	/* Nothing received, nothing completed: every derived value is zero. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 2, clocks, 1), 0);
	nxp_rx_summary_note_loop_end(&s, 7000000);
	EXPECT_EQ(nxp_rx_summary_report(&s, 11, 22, &report), 0);
	EXPECT_EQ(report.wall_us, 0);
	EXPECT_EQ(report.group_service_us_p50, 0);
	EXPECT_EQ(report.group_service_us_p99, 0);
	EXPECT_EQ(report.cpu_user_us, 11);
	EXPECT_EQ(report.cpu_sys_us, 22);
	EXPECT_EQ(report.max_inflight, 0);

	/* Received but nothing completed: wall runs to the end of the loop. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 2, clocks, 1), 0);
	nxp_rx_summary_note_rx(&s, 1000000);
	nxp_rx_summary_note_rx(&s, 1500000); /* only the first counts */
	nxp_rx_summary_note_packet(&s, false);
	nxp_rx_summary_note_loop_end(&s, 4000999);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.wall_us, 3000);
	EXPECT_EQ(report.packets_dropped, 1);

	/* With a completion, wall ends at the last completion, not at the end
	 * of the loop. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 2, clocks, 1), 0);
	nxp_rx_summary_note_rx(&s, 1000000);
	complete_one_group(&s, 0, 1000000, 1250000);
	complete_one_group(&s, 0, 1300000, 1501999);
	nxp_rx_summary_note_loop_end(&s, 9000000);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.wall_us, 501);
	EXPECT_EQ(report.group_service_us_p50, 201);
	EXPECT_EQ(report.group_service_us_p99, 250);
	EXPECT_EQ(report.groups, 2);
	EXPECT_EQ(report.nvme_cmds, 2);
	EXPECT_EQ(report.max_inflight, 1);

	/* A completion clock behind the first RX gives zero, not a wrap. */
	EXPECT_EQ(nxp_rx_summary_init(&s, recorded, 2, clocks, 1), 0);
	nxp_rx_summary_note_rx(&s, 5000000);
	complete_one_group(&s, 0, 5000000, 4000000);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, &report), 0);
	EXPECT_EQ(report.wall_us, 0);
	EXPECT_EQ(nxp_rx_summary_report(NULL, 0, 0, &report), -EINVAL);
	EXPECT_EQ(nxp_rx_summary_report(&s, 0, 0, NULL), -EINVAL);

	/* getrusage() deltas, as the baseline's spb_timeval_us() difference. */
	EXPECT_EQ(nxp_timeval_us(&tv), 2345678);
	EXPECT_EQ(nxp_timeval_us(NULL), 0);
	EXPECT_EQ(nxp_cpu_delta_us(1000, 4500), 3500);
	EXPECT_EQ(nxp_cpu_delta_us(4500, 1000), 0);
}

int main(void)
{
	test_namespace_is_fail_closed();
	test_namespace_epoch_is_cheap_and_fail_closed();
	test_standard_nvme_sysfs_nodes_are_controller_siblings();
	test_controller_address_requires_unique_pci_bdf();
	test_nvme_encoder_checks_every_boundary();
	test_direction_neutral_nvme_plan_uses_only_local_window();
	test_wire_layout_uses_only_ordinary_mtu_packets();
	test_wire_header_is_bounded_and_checksummed();
	test_wire_group_rejects_duplicates_gaps_and_generation_reuse();
	test_8k_mtu_layout_keeps_one_lba_aligned_logical_io();
	test_8k_group_depth_is_bounded_by_frames_and_every_xsk_ring();
	test_rx_frames_have_exactly_one_fill_io_recycle_lifetime();
	test_rx_frame_census_counts_every_state();
	test_submit_state_machine();
	test_generation_token_survives_slot_reuse();
	test_latched_errors_and_quiescence();
	test_ready_ordering_and_statistics();
	test_cleanup_is_reverse_initialization();
	test_iopoll_requires_both_proofs();
	test_integer_arguments_never_wrap();
	test_rx_empty_poll_wakeups_have_an_absolute_deadline();
	test_rx_summary_nearest_rank_is_the_baseline_definition();
	test_rx_summary_report_percentiles_match_the_baseline();
	test_rx_summary_line_is_exact_and_ordered();
	test_rx_summary_samples_once_per_completed_group();
	test_rx_summary_receive_span_tail_and_post_arrival();
	test_rx_summary_arrival_fields_match_the_baseline();
	test_rx_summary_counts_packets_commands_and_depth();
	test_rx_summary_wall_and_cpu_follow_the_baseline();
	test_rx_summary_frame_census_fails_closed();
	test_rx_stop_fails_only_an_unfinished_run();
	test_stopped_run_exit_status();

	if (failures) {
		fprintf(stderr, "FAIL: %u/%u checks failed\n", failures, checks);
		return 1;
	}
	printf("PASS: %u checks\n", checks);
	return 0;
}
