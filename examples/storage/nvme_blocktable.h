/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_NVME_BLOCKTABLE_H
#define XDEV_EXT_NVME_BLOCKTABLE_H
/* All fields are native endian. Offset is relative to the admitted window. */
struct blocktable_key { __u64 session_id; __u64 logical_key; };
struct blocktable_value { __u64 byte_offset; __u32 byte_length; __u32 reserved; };
#endif
