/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TOOLS_XDEV_EXT_NV_P2P_IOCTL_H
#define __TOOLS_XDEV_EXT_NV_P2P_IOCTL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>

#ifdef __cplusplus
#define XDEV_EXT_NV_STATIC_ASSERT static_assert
#else
#define XDEV_EXT_NV_STATIC_ASSERT _Static_assert
#endif

/*
 * Userspace view of the NVIDIA P2P UMEM extension.  Keep these layouts
 * byte-for-byte compatible with nv_ioctl_p2p_* in nv-ioctl.h.  This header
 * deliberately uses fixed-width C types so tools do not depend on private
 * NVIDIA build headers.
 */
#define XDEV_EXT_NV_IOCTL_MAGIC		'F'
#define XDEV_EXT_NV_IOCTL_BASE		200U
#define XDEV_EXT_NV_ESC_IOCTL_XFER_CMD	(XDEV_EXT_NV_IOCTL_BASE + 11U)
#define XDEV_EXT_NV_ESC_P2P_PIN_UMEM		(XDEV_EXT_NV_IOCTL_BASE + 19U)
#define XDEV_EXT_NV_ESC_P2P_UNPIN_UMEM	(XDEV_EXT_NV_IOCTL_BASE + 20U)
#define XDEV_EXT_NV_ESC_P2P_DMA_XFER		(XDEV_EXT_NV_IOCTL_BASE + 21U)
#define XDEV_EXT_NV_ESC_P2P_DMA_XFER_BATCH	(XDEV_EXT_NV_IOCTL_BASE + 22U)

/* Explicit raw host registration for non-AF_XDP endpoints (for example NVMe). */
#define XDEV_EXT_NV_P2P_PIN_F_HOST_REGION	(1U << 0)

#define XDEV_EXT_NV_OK	0U
#define XDEV_EXT_NV_P2P_MAX_BATCH	64U

enum xdev_ext_nv_p2p_direction {
	XDEV_EXT_NV_P2P_GPU_TO_UMEM = 0,
	XDEV_EXT_NV_P2P_UMEM_TO_GPU = 1,
};

struct xdev_ext_nv_ioctl_xfer {
	uint32_t cmd;
	uint32_t size;
	uint64_t ptr __attribute__((aligned(8)));
};

struct xdev_ext_nv_p2p_pin_umem {
	uint64_t umem_addr __attribute__((aligned(8)));
	uint64_t size __attribute__((aligned(8)));
	uint32_t frame_size;
	uint32_t status;
	uint64_t handle __attribute__((aligned(8)));
	int32_t xsk_fd;
	uint32_t flags;
};

struct xdev_ext_nv_p2p_unpin_umem {
	uint64_t handle __attribute__((aligned(8)));
	uint32_t status;
};

struct xdev_ext_nv_p2p_dma_xfer {
	uint64_t handle __attribute__((aligned(8)));
	uint64_t gpu_offset __attribute__((aligned(8)));
	uint64_t umem_offset __attribute__((aligned(8)));
	uint64_t size __attribute__((aligned(8)));
	uint32_t direction;
	uint32_t status;
};

struct xdev_ext_nv_p2p_dma_batch_entry {
	uint64_t gpu_offset __attribute__((aligned(8)));
	uint64_t umem_offset __attribute__((aligned(8)));
	uint64_t size __attribute__((aligned(8)));
	uint32_t direction;
	uint32_t status;
};

struct xdev_ext_nv_p2p_dma_batch {
	uint64_t handle __attribute__((aligned(8)));
	uint32_t count;
	uint32_t completed;
	uint32_t failed_index;
	uint32_t status;
	uint32_t flags;
	uint32_t reserved;
	struct xdev_ext_nv_p2p_dma_batch_entry entries[XDEV_EXT_NV_P2P_MAX_BATCH];
};

#define XDEV_EXT_NV_IOCTL_XFER_CMD \
	_IOWR(XDEV_EXT_NV_IOCTL_MAGIC, XDEV_EXT_NV_ESC_IOCTL_XFER_CMD, \
	      struct xdev_ext_nv_ioctl_xfer)

XDEV_EXT_NV_STATIC_ASSERT(sizeof(struct xdev_ext_nv_ioctl_xfer) == 16,
	       "NVIDIA xfer ABI size changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_ioctl_xfer, ptr) == 8,
	       "NVIDIA xfer pointer offset changed");
XDEV_EXT_NV_STATIC_ASSERT(sizeof(struct xdev_ext_nv_p2p_pin_umem) == 40,
	       "NVIDIA P2P pin ABI size changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_pin_umem, status) == 20,
	       "NVIDIA P2P pin status offset changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_pin_umem, handle) == 24,
	       "NVIDIA P2P pin handle offset changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_pin_umem, xsk_fd) == 32,
		       "NVIDIA P2P pin XSK fd offset changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_pin_umem, flags) == 36,
		       "NVIDIA P2P pin flags offset changed");
XDEV_EXT_NV_STATIC_ASSERT(sizeof(struct xdev_ext_nv_p2p_unpin_umem) == 16,
	       "NVIDIA P2P unpin ABI size changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_unpin_umem, status) == 8,
	       "NVIDIA P2P unpin status offset changed");
XDEV_EXT_NV_STATIC_ASSERT(sizeof(struct xdev_ext_nv_p2p_dma_xfer) == 40,
	       "NVIDIA P2P DMA ABI size changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_dma_xfer, direction) == 32,
	       "NVIDIA P2P DMA direction offset changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_dma_xfer, status) == 36,
	       "NVIDIA P2P DMA status offset changed");
XDEV_EXT_NV_STATIC_ASSERT(sizeof(struct xdev_ext_nv_p2p_dma_batch_entry) == 32,
	       "NVIDIA P2P DMA batch entry ABI size changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_dma_batch_entry, direction) == 24,
	       "NVIDIA P2P DMA batch direction offset changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_dma_batch_entry, status) == 28,
	       "NVIDIA P2P DMA batch entry status offset changed");
XDEV_EXT_NV_STATIC_ASSERT(sizeof(struct xdev_ext_nv_p2p_dma_batch) == 2080,
	       "NVIDIA P2P DMA batch ABI size changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_dma_batch, failed_index) == 16,
	       "NVIDIA P2P DMA batch failure index offset changed");
XDEV_EXT_NV_STATIC_ASSERT(offsetof(struct xdev_ext_nv_p2p_dma_batch, entries) == 32,
	       "NVIDIA P2P DMA batch entries offset changed");

typedef int (*xdev_ext_nv_ioctl_fn)(int fd, unsigned long request, void *argument);

static inline int xdev_ext_nv_ioctl_syscall(int fd, unsigned long request,
				       void *argument)
{
	return ioctl(fd, request, argument);
}

static inline int xdev_ext_nv_p2p_xfer_with(int fd, uint32_t command, void *params,
				       uint32_t size, xdev_ext_nv_ioctl_fn fn)
{
	struct xdev_ext_nv_ioctl_xfer xfer = {
		.cmd = command,
		.size = size,
		.ptr = (uint64_t)(uintptr_t)params,
	};
	int ret;

	if (!fn) {
		errno = EINVAL;
		return -1;
	}
	ret = fn(fd, XDEV_EXT_NV_IOCTL_XFER_CMD, &xfer);
	if (ret > 0) {
		errno = EIO;
		return -1;
	}
	return ret;
}

static inline int xdev_ext_nv_p2p_native_result(uint32_t status)
{
	if (status == XDEV_EXT_NV_OK)
		return 0;
	errno = EIO;
	return -1;
}

static inline int
xdev_ext_nv_p2p_pin_umem_with(int fd, struct xdev_ext_nv_p2p_pin_umem *params,
			 xdev_ext_nv_ioctl_fn fn)
{
	int ret;

	if (!params ||
	    !((params->flags == 0 && params->xsk_fd >= 0) ||
	      (params->flags == XDEV_EXT_NV_P2P_PIN_F_HOST_REGION &&
	       params->xsk_fd == -1))) {
		errno = EINVAL;
		return -1;
	}
	params->status = UINT32_MAX;
	params->handle = 0;
	ret = xdev_ext_nv_p2p_xfer_with(fd, XDEV_EXT_NV_ESC_P2P_PIN_UMEM, params,
				    sizeof(*params), fn);
	if (ret)
		return ret;
	if (xdev_ext_nv_p2p_native_result(params->status)) {
		params->handle = 0;
		return -1;
	}
	if (!params->handle) {
		errno = EPROTO;
		return -1;
	}
	return 0;
}

static inline int
xdev_ext_nv_p2p_unpin_umem_with(int fd, struct xdev_ext_nv_p2p_unpin_umem *params,
			   xdev_ext_nv_ioctl_fn fn)
{
	int ret;

	if (!params || !params->handle) {
		errno = EINVAL;
		return -1;
	}
	params->status = UINT32_MAX;
	ret = xdev_ext_nv_p2p_xfer_with(fd, XDEV_EXT_NV_ESC_P2P_UNPIN_UMEM, params,
				    sizeof(*params), fn);
	if (ret)
		return ret;
	return xdev_ext_nv_p2p_native_result(params->status);
}

static inline int
xdev_ext_nv_p2p_dma_xfer_with(int fd, struct xdev_ext_nv_p2p_dma_xfer *params,
			 xdev_ext_nv_ioctl_fn fn)
{
	int ret;

	if (!params || !params->handle) {
		errno = EINVAL;
		return -1;
	}
	params->status = UINT32_MAX;
	ret = xdev_ext_nv_p2p_xfer_with(fd, XDEV_EXT_NV_ESC_P2P_DMA_XFER, params,
				    sizeof(*params), fn);
	if (ret)
		return ret;
	return xdev_ext_nv_p2p_native_result(params->status);
}

static inline int
xdev_ext_nv_p2p_dma_batch_with(int fd, struct xdev_ext_nv_p2p_dma_batch *params,
			  xdev_ext_nv_ioctl_fn fn)
{
	uint32_t i;
	int ret;

	if (!params || !params->handle || !params->count ||
	    params->count > XDEV_EXT_NV_P2P_MAX_BATCH || params->flags ||
	    params->reserved) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < params->count; i++) {
		if (!params->entries[i].size ||
		    params->entries[i].direction > XDEV_EXT_NV_P2P_UMEM_TO_GPU) {
			errno = EINVAL;
			return -1;
		}
		params->entries[i].status = UINT32_MAX;
	}
	params->completed = 0;
	params->failed_index = UINT32_MAX;
	params->status = UINT32_MAX;
	ret = xdev_ext_nv_p2p_xfer_with(fd, XDEV_EXT_NV_ESC_P2P_DMA_XFER_BATCH,
				    params, sizeof(*params), fn);
	if (ret)
		return ret;
	if (params->completed > params->count) {
		errno = EPROTO;
		return -1;
	}
	for (i = 0; i < params->completed; i++) {
		if (params->entries[i].status != XDEV_EXT_NV_OK) {
			errno = EPROTO;
			return -1;
		}
	}
	if (params->status == XDEV_EXT_NV_OK) {
		if (params->failed_index != UINT32_MAX ||
		    params->completed != params->count) {
			errno = EPROTO;
			return -1;
		}
		return 0;
	}

	/*
	 * On failure, completed is the strict successful prefix and failed_index
	 * names the first non-successful item.  The failed item may have reached
	 * hardware before its native error was observed; callers must not replay
	 * either the prefix or the failed item automatically.
	 */
	if (params->failed_index != params->completed ||
	    params->failed_index >= params->count ||
	    params->entries[params->failed_index].status != params->status) {
		errno = EPROTO;
		return -1;
	}
	errno = EIO;
	return -1;
}

static inline int xdev_ext_nv_p2p_pin_umem(int fd,
				      struct xdev_ext_nv_p2p_pin_umem *params)
{
	return xdev_ext_nv_p2p_pin_umem_with(fd, params, xdev_ext_nv_ioctl_syscall);
}

static inline int xdev_ext_nv_p2p_unpin_umem(int fd,
					struct xdev_ext_nv_p2p_unpin_umem *params)
{
	return xdev_ext_nv_p2p_unpin_umem_with(fd, params, xdev_ext_nv_ioctl_syscall);
}

static inline int xdev_ext_nv_p2p_dma_xfer(int fd,
				      struct xdev_ext_nv_p2p_dma_xfer *params)
{
	return xdev_ext_nv_p2p_dma_xfer_with(fd, params, xdev_ext_nv_ioctl_syscall);
}

static inline int xdev_ext_nv_p2p_dma_batch(int fd,
				       struct xdev_ext_nv_p2p_dma_batch *params)
{
	return xdev_ext_nv_p2p_dma_batch_with(fd, params, xdev_ext_nv_ioctl_syscall);
}

#undef XDEV_EXT_NV_STATIC_ASSERT

#endif /* __TOOLS_XDEV_EXT_NV_P2P_IOCTL_H */
