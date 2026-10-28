/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_TP_WIRE_H
#define XDEV_TP_WIRE_H
#include <stdint.h>
#define XDEV_TP_WIRE_MAGIC UINT64_C(0x3150545645445858)
#define XDEV_TP_WIRE_VERSION 1U
#define XDEV_TP_WIRE_HEADER_BYTES 64U
/* Fixed little-endian header; serialized into the actual PEER payload. Local
 * slot, CUDA VA, ticket and native authority generation never cross the wire. */
struct xdev_tp_wire_header {
	uint64_t magic;
	uint64_t communicator_id;
	uint64_t epoch;
	uint64_t sequence;
	uint64_t rows;
	uint64_t local_width;
	uint32_t payload_bytes;
	uint16_t version;
	uint16_t header_bytes;
	uint8_t operation;
	uint8_t dtype;
	uint8_t rank;
	uint8_t world_size;
	uint32_t reserved;
};
#ifdef __cplusplus
static_assert(sizeof(xdev_tp_wire_header) == XDEV_TP_WIRE_HEADER_BYTES, "wire header ABI");
#else
_Static_assert(sizeof(struct xdev_tp_wire_header) == XDEV_TP_WIRE_HEADER_BYTES, "wire header ABI");
#endif
#endif
