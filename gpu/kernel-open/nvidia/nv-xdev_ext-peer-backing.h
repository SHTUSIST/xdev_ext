/* SPDX-License-Identifier: MIT */
#ifndef _NV_XDEV_EXT_PEER_BACKING_H
#define _NV_XDEV_EXT_PEER_BACKING_H

/* Same values as XDEV_EXT_PEER_BACKING_*; the provider asserts equality. */
#define NV_XDEV_EXT_BACKING_MMIO_BAR	(1U << 0)
#define NV_XDEV_EXT_BACKING_STRUCT_PAGE	(1U << 1)
#define NV_XDEV_EXT_BACKING_COHERENT_C2C	(1U << 2)
#define NV_XDEV_EXT_BACKING_EXTERNAL	(1U << 3)
#define NV_XDEV_EXT_BACKING_RAW_BUS_ADDR	(1U << 4)

static inline unsigned int nv_xdev_ext_peer_backing_flags(bool mem_has_struct_page,
							bool coherent, bool external,
							bool raw_bus_addr)
{
	unsigned int f = mem_has_struct_page ? NV_XDEV_EXT_BACKING_STRUCT_PAGE :
			 coherent ? NV_XDEV_EXT_BACKING_COHERENT_C2C :
				    NV_XDEV_EXT_BACKING_MMIO_BAR;

	if (external)
		f |= NV_XDEV_EXT_BACKING_EXTERNAL;
	if (raw_bus_addr && (f & NV_XDEV_EXT_BACKING_MMIO_BAR))
		f |= NV_XDEV_EXT_BACKING_RAW_BUS_ADDR;
	return f;
}
#endif
