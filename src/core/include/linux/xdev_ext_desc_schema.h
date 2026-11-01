/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_XDEV_EXT_DESC_SCHEMA_H
#define _LINUX_XDEV_EXT_DESC_SCHEMA_H

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif
#include <linux/types.h>

/* A trusted declaration for exactly sixteen little-endian dwords. */
struct xdev_ext_desc_schema16 {
	__u32 writable[16];
};

static inline int xdev_ext_desc_schema16_check(const __u8 sqe[64],
		const struct xdev_ext_desc_schema16 *schema, __u8 required_opcode)
{
	unsigned int dw;

	if (!sqe || !schema)
		return -EINVAL;
	if (sqe[0] != required_opcode)
		return -EOPNOTSUPP;
	for (dw = 0; dw < 16; dw++) {
		const __u8 *p = sqe + 4 * dw;
		__u32 value = (__u32)p[0] | (__u32)p[1] << 8 |
			      (__u32)p[2] << 16 | (__u32)p[3] << 24;

		if (value & ~schema->writable[dw])
			return -EPERM;
	}
	return 0;
}

#endif
