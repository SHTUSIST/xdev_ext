/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_NVME_CE_REQUEST_H
#define XDEV_EXT_NVME_CE_REQUEST_H
/* Native endian, example-local immutable requests, not a kernel ABI.
 * Offsets are relative to the respective C-authorized device windows. */
struct nvme_ce_request_key {
	__u64 session_id;
	__u64 request_key;
};
struct nvme_ce_request_value {
	__u64 nvme_byte_offset;
	__u64 gpu_byte_offset;
	__u32 byte_length;
	__u32 reserved;
};
#endif
