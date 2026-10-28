/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TOOLS_XDEV_EXT_GPU_IDENTITY_H
#define __TOOLS_XDEV_EXT_GPU_IDENTITY_H

#include <limits.h>
#include <stddef.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XDEV_EXT_GPU_PCI_BDF_SIZE 32U
#define XDEV_EXT_GPU_IDENTITY_ANY_MINOR UINT_MAX
#define XDEV_EXT_GPU_IDENTITY_MAX_CANDIDATES 256U

struct xdev_ext_gpu_identity_candidate {
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE];
	unsigned int minor;
};

/* All callbacks return zero or a negative errno value. */
struct xdev_ext_gpu_identity_ops {
	int (*fstat_fd)(void *opaque, int fd, struct stat *st);
	int (*realpath_path)(void *opaque, const char *path, char *resolved,
			     size_t resolved_size);
	int (*stat_path)(void *opaque, const char *path, struct stat *st);
	int (*load_candidates)(void *opaque,
			       struct xdev_ext_gpu_identity_candidate *candidates,
			       size_t capacity, size_t *count);
};

int xdev_ext_gpu_identity_is_pci_bdf(const char *text);

int xdev_ext_gpu_identity_from_opened_with(
	const struct xdev_ext_gpu_identity_ops *ops, void *opaque, int fd,
	const char *requested, unsigned int expected_minor,
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE]);

int xdev_ext_gpu_identity_from_opened(int fd, const char *requested,
				 unsigned int expected_minor,
				 char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* __TOOLS_XDEV_EXT_GPU_IDENTITY_H */
