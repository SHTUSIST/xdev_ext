/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBXDEV_EXT_CUDA_DEVICE_H
#define LIBXDEV_EXT_CUDA_DEVICE_H
#include "libxdev_ext_cuda.h"
struct xdev_cuda_ring {
	struct xdev_ext_user_ring_hdr *hdr;
	struct xdev_ext_user_ready *ready;
	struct xdev_ext_user_done *done;
	struct xdev_ext_user_slot *slots;
	unsigned long long allocation_va, allocation_bytes;
	unsigned int entries, frame_size;
};
#endif
