// SPDX-License-Identifier: GPL-2.0
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "include/xdev_ext_gpu_identity.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static int hex_value(unsigned char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	return -1;
}

int xdev_ext_gpu_identity_is_pci_bdf(const char *text)
{
	static const unsigned int hex_positions[] = {
		0, 1, 2, 3, 5, 6, 8, 9, 11,
	};
	unsigned int i;
	int slot;
	int function;

	if (!text || strnlen(text, 13) != 12 || text[4] != ':' ||
	    text[7] != ':' || text[10] != '.')
		return 0;
	for (i = 0; i < sizeof(hex_positions) / sizeof(hex_positions[0]); i++) {
		if (hex_value((unsigned char)text[hex_positions[i]]) < 0)
			return 0;
	}
	slot = (hex_value((unsigned char)text[8]) << 4) |
		hex_value((unsigned char)text[9]);
	function = hex_value((unsigned char)text[11]);
	return slot <= 0x1f && function <= 7;
}

static int production_fstat(void *opaque, int fd, struct stat *st)
{
	(void)opaque;
	return fstat(fd, st) ? (errno ? -errno : -EIO) : 0;
}

static int production_realpath(void *opaque, const char *path, char *resolved,
			       size_t resolved_size)
{
	char canonical[PATH_MAX];
	size_t length;

	(void)opaque;
	errno = 0;
	if (!realpath(path, canonical))
		return errno ? -errno : -ENOENT;
	length = strlen(canonical);
	if (length >= resolved_size)
		return -ENAMETOOLONG;
	memcpy(resolved, canonical, length + 1);
	return 0;
}

static int production_stat(void *opaque, const char *path, struct stat *st)
{
	(void)opaque;
	return stat(path, st) ? (errno ? -errno : -EIO) : 0;
}

static int information_minor(const char *path, unsigned int *minor_out)
{
	char line[256];
	FILE *information;
	int ret = -ENODEV;

	information = fopen(path, "re");
	if (!information)
		return errno ? -errno : -ENOENT;
	while (fgets(line, sizeof(line), information)) {
		static const char label[] = "Device Minor:";
		unsigned long parsed;
		char *value;
		char *end;

		if (strncmp(line, label, sizeof(label) - 1))
			continue;
		value = line + sizeof(label) - 1;
		while (isspace((unsigned char)*value))
			value++;
		errno = 0;
		parsed = strtoul(value, &end, 10);
		if (errno || end == value || parsed > UINT_MAX) {
			ret = -EPROTO;
			break;
		}
		while (isspace((unsigned char)*end))
			end++;
		if (*end) {
			ret = -EPROTO;
			break;
		}
		*minor_out = (unsigned int)parsed;
		ret = 0;
		break;
	}
	if (fclose(information) && !ret)
		ret = errno ? -errno : -EIO;
	return ret;
}

static int production_load_candidates(
	void *opaque, struct xdev_ext_gpu_identity_candidate *candidates,
	size_t capacity, size_t *count)
{
	static const char driver_path[] = "/sys/bus/pci/drivers/nvidia";
	struct dirent *entry;
	DIR *directory;
	size_t found = 0;
	int result = 0;

	(void)opaque;
	directory = opendir(driver_path);
	if (!directory)
		return errno ? -errno : -ENODEV;
	for (;;) {
		char candidate_link[PATH_MAX];
		char candidate_path[PATH_MAX];
		char information_path[PATH_MAX];
		const char *component;
		unsigned int device_minor = 0;
		size_t bdf_length;
		int ret;

		errno = 0;
		entry = readdir(directory);
		if (!entry) {
			if (errno)
				result = -errno;
			break;
		}
		bdf_length = strnlen(entry->d_name, XDEV_EXT_GPU_PCI_BDF_SIZE);
		if (bdf_length == XDEV_EXT_GPU_PCI_BDF_SIZE ||
		    !xdev_ext_gpu_identity_is_pci_bdf(entry->d_name))
			continue;
		if (snprintf(candidate_link, sizeof(candidate_link), "%s/%s",
			     driver_path, entry->d_name) >=
		    (int)sizeof(candidate_link)) {
			result = -ENAMETOOLONG;
			break;
		}
		ret = production_realpath(NULL, candidate_link, candidate_path,
					  sizeof(candidate_path));
		if (ret)
			continue;
		component = strrchr(candidate_path, '/');
		if (!component ||
		    !xdev_ext_gpu_identity_is_pci_bdf(component + 1) ||
		    strcasecmp(component + 1, entry->d_name))
			continue;
		if (snprintf(information_path, sizeof(information_path),
			     "/proc/driver/nvidia/gpus/%s/information",
			     entry->d_name) >= (int)sizeof(information_path)) {
			result = -ENAMETOOLONG;
			break;
		}
		ret = information_minor(information_path, &device_minor);
		if (ret)
			continue;
		if (found == capacity) {
			result = -E2BIG;
			break;
		}
		memcpy(candidates[found].bdf, entry->d_name, bdf_length + 1);
		candidates[found].minor = device_minor;
		found++;
	}
	if (closedir(directory) && !result)
		result = errno ? -errno : -EIO;
	if (result)
		return result;
	*count = found;
	return 0;
}

static const struct xdev_ext_gpu_identity_ops production_ops = {
	.fstat_fd = production_fstat,
	.realpath_path = production_realpath,
	.stat_path = production_stat,
	.load_candidates = production_load_candidates,
};

static int valid_ops(const struct xdev_ext_gpu_identity_ops *ops)
{
	return ops && ops->fstat_fd && ops->realpath_path && ops->stat_path &&
		ops->load_candidates;
}

int xdev_ext_gpu_identity_from_opened_with(
	const struct xdev_ext_gpu_identity_ops *ops, void *opaque, int fd,
	const char *requested, unsigned int expected_minor,
	char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE])
{
	struct xdev_ext_gpu_identity_candidate
		candidates[XDEV_EXT_GPU_IDENTITY_MAX_CANDIDATES];
	struct stat opened_stat;
	struct stat expected_stat;
	char expected[PATH_MAX];
	char opened_path[PATH_MAX];
	char expected_path[PATH_MAX];
	char sysfs_link[PATH_MAX];
	char sysfs_path[PATH_MAX];
	char selected[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };
	const char *component;
	unsigned int opened_minor;
	unsigned int matches = 0;
	size_t candidate_count = 0;
	size_t length;
	int ret;

	if (!valid_ops(ops) || fd < 0 || !requested || !*requested || !bdf)
		return -EINVAL;
	bdf[0] = '\0';
	ret = ops->fstat_fd(opaque, fd, &opened_stat);
	if (ret)
		return ret;
	if (!S_ISCHR(opened_stat.st_mode))
		return -ENOTTY;
	opened_minor = minor(opened_stat.st_rdev);
	if (expected_minor != XDEV_EXT_GPU_IDENTITY_ANY_MINOR &&
	    opened_minor != expected_minor)
		return -EXDEV;
	if (snprintf(expected, sizeof(expected), "/dev/nvidia%u",
		     opened_minor) >= (int)sizeof(expected))
		return -ENAMETOOLONG;
	ret = ops->realpath_path(opaque, requested, opened_path,
				 sizeof(opened_path));
	if (ret)
		return ret;
	ret = ops->realpath_path(opaque, expected, expected_path,
				 sizeof(expected_path));
	if (ret)
		return ret;
	ret = ops->stat_path(opaque, expected_path, &expected_stat);
	if (ret)
		return ret;
	if (strcmp(opened_path, expected_path) ||
	    !S_ISCHR(expected_stat.st_mode) ||
	    opened_stat.st_rdev != expected_stat.st_rdev)
		return -EXDEV;
	if (snprintf(sysfs_link, sizeof(sysfs_link),
		     "/sys/dev/char/%u:%u/device", major(opened_stat.st_rdev),
		     opened_minor) >= (int)sizeof(sysfs_link))
		return -ENAMETOOLONG;
	ret = ops->realpath_path(opaque, sysfs_link, sysfs_path,
				 sizeof(sysfs_path));
	if (!ret) {
		component = strrchr(sysfs_path, '/');
		if (!component || !xdev_ext_gpu_identity_is_pci_bdf(component + 1))
			return -EPROTO;
		length = strlen(component + 1);
		if (length >= XDEV_EXT_GPU_PCI_BDF_SIZE)
			return -ENAMETOOLONG;
		memcpy(bdf, component + 1, length + 1);
		return 0;
	} else if (ret != -ENOENT && ret != -ENOTDIR) {
		return ret;
	}
	ret = ops->load_candidates(opaque, candidates,
				   XDEV_EXT_GPU_IDENTITY_MAX_CANDIDATES,
				   &candidate_count);
	if (ret)
		return ret;
	if (candidate_count > XDEV_EXT_GPU_IDENTITY_MAX_CANDIDATES)
		return -E2BIG;
	for (size_t i = 0; i < candidate_count; i++) {
		size_t candidate_length;

		if (candidates[i].minor != opened_minor)
			continue;
		candidate_length = strnlen(candidates[i].bdf,
					     XDEV_EXT_GPU_PCI_BDF_SIZE);
		if (candidate_length == XDEV_EXT_GPU_PCI_BDF_SIZE)
			return -EPROTO;
		if (!xdev_ext_gpu_identity_is_pci_bdf(candidates[i].bdf))
			return -EPROTO;
		matches++;
		if (matches == 1)
			memcpy(selected, candidates[i].bdf,
			       candidate_length + 1);
	}
	if (matches != 1)
		return matches ? -EEXIST : -ENODEV;
	memcpy(bdf, selected, sizeof(selected));
	return 0;
}

int xdev_ext_gpu_identity_from_opened(int fd, const char *requested,
				 unsigned int expected_minor,
				 char bdf[XDEV_EXT_GPU_PCI_BDF_SIZE])
{
	return xdev_ext_gpu_identity_from_opened_with(&production_ops, NULL, fd,
					 requested, expected_minor, bdf);
}
