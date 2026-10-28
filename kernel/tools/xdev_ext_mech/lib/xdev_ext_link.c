// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "libxdev_ext.h"

/* Sysfs attributes are small records. A larger record is rejected, never cut. */
static int read_record(int directory, const char *name, char *buf, size_t cap)
{
	int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	size_t used = 0;
	int ret = 0;
	if (fd < 0)
		return -errno;
	for (;;) {
		ssize_t n = read(fd, buf + used, cap - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) { ret = -errno; break; }
		if (!n)
			break;
		used += (size_t)n;
		if (used == cap) { ret = -EOVERFLOW; break; }
	}
	close(fd);
	if (!ret) {
		if (memchr(buf, 0, used))
			return -EPROTO;
		buf[used] = 0;
	}
	return ret;
}

static int scalar(const char *text, __u64 *out)
{
	__u64 value = 0;
	const unsigned char *p = (const unsigned char *)text;
	if (!*p)
		return -EPROTO;
	for (; *p; p++) {
		if (*p < '0' || *p > '9')
			return -EPROTO;
		if (value > (UINT64_MAX - (*p - '0')) / 10)
			return -EOVERFLOW;
		value = value * 10 + *p - '0';
	}
	*out = value;
	return 0;
}

int xdev_ext_link_read(const char *root, const char *service,
	struct xdev_ext_link_snapshot *out)
{
	static const char *const names[] = {
		"version", "token", "local_inc", "remote_inc", "up", "closing",
		"nhi_gone", "channels",
	};
	struct xdev_ext_link_snapshot s = { 0 };
	__u64 values[8] = { 0 }, token;
	char record[1024], identity[128], *item, *save = NULL;
	unsigned int seen = 0, i;
	int rootfd, servicefd, ret;
	if (!root || !service || !out || !*service || strchr(service, '/') ||
	    !strcmp(service, ".") || !strcmp(service, "..") ||
	    strlen(service) >= sizeof(s.service))
		return -EINVAL;
	rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (rootfd < 0)
		return -errno;
	/* Real sysfs device entries are symlinks into /sys/devices. */
	servicefd = openat(rootfd, service, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	close(rootfd);
	if (servicefd < 0)
		return -errno;
	ret = read_record(servicefd, "xdev_ext_link", identity, sizeof(identity));
	if (!ret)
		ret = read_record(servicefd, "xdev_ext_link_state", record, sizeof(record));
	close(servicefd);
	if (ret)
		return ret;
	identity[strcspn(identity, "\n")] = 0;
	ret = scalar(identity, &token);
	if (ret || !token)
		return ret ? ret : -EPROTO;
	for (item = strtok_r(record, " \t\r\n", &save); item;
	     item = strtok_r(NULL, " \t\r\n", &save)) {
		char *equals = strchr(item, '=');
		if (!equals)
			return -EPROTO;
		*equals++ = 0;
		for (i = 0; i < 8 && strcmp(item, names[i]); i++)
			;
		if (i == 8 || (seen & (1U << i)))
			return -EPROTO;
		ret = scalar(equals, &values[i]);
		if (ret)
			return ret;
		seen |= 1U << i;
	}
	if (seen != 255 || values[0] != 1 || values[1] != token ||
	    values[4] > 1 || values[5] > 1 || values[6] > 1 || values[7] > UINT32_MAX)
		return -EPROTO;
	s.token = token;
	s.local_inc = values[2]; s.remote_inc = values[3];
	s.up = values[4]; s.closing = values[5]; s.nhi_gone = values[6];
	s.channels = values[7];
	memcpy(s.service, service, strlen(service) + 1);
	*out = s;
	return 0;
}

int xdev_ext_link_discover(const char *root, __u64 token,
	struct xdev_ext_link_snapshot *out)
{
	struct xdev_ext_link_snapshot s, found = { 0 };
	struct dirent *entry;
	unsigned int matches = 0;
	DIR *dir;
	int ret = 0;
	if (!root || !token || !out)
		return -EINVAL;
	dir = opendir(root);
	if (!dir)
		return -errno;
	while ((entry = readdir(dir))) {
		if (entry->d_name[0] == '.')
			continue;
		ret = xdev_ext_link_read(root, entry->d_name, &s);
		if (ret == -ENOENT || ret == -ENOTDIR)
			continue;
		/* A malformed service cannot be used as evidence for another link. */
		if (ret)
			break;
		if (s.token == token) { found = s; matches++; }
	}
	closedir(dir);
	if (ret && ret != -ENOENT && ret != -ENOTDIR)
		return ret;
	if (matches != 1)
		return matches ? -EEXIST : -ENOENT;
	if (!found.up || found.closing || found.nhi_gone || !found.local_inc ||
	    !found.remote_inc || !found.channels)
		return -ENOLINK;
	*out = found;
	return 0;
}
