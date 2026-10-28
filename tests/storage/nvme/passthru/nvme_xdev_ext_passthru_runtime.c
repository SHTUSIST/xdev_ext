// SPDX-License-Identifier: GPL-2.0

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "../../../../include/linux/nvme_xdev_ext_passthru.h"
#include "nvme_xdev_ext_passthru_runtime.h"

#define KSFT_SKIP 4
#define RING_ENTRIES 8U
#define READ_BUFFER_COUNT 4U
#define TEST_SLBA 8U
#define COMMAND_TIMEOUT_MS 30000
#define POLL_SLICE_MS 100

#define RUNTIME_PATH_MAX 128U

/* sysfs and device paths of one namespace: ng<C>n<N>, nvme<C>, nvme<C>n<N>. */
struct runtime_paths {
	char generic_dev[RUNTIME_PATH_MAX];
	char generic_parent[RUNTIME_PATH_MAX];
	char controller[RUNTIME_PATH_MAX];
	char model[RUNTIME_PATH_MAX];
	char serial[RUNTIME_PATH_MAX];
	char block[RUNTIME_PATH_MAX];
	char block_parent[RUNTIME_PATH_MAX];
	char block_dev[RUNTIME_PATH_MAX];
	char block_nsid[RUNTIME_PATH_MAX];
	char block_size[RUNTIME_PATH_MAX];
	char block_sectors[RUNTIME_PATH_MAX];
	char holders[RUNTIME_PATH_MAX];
	char block_device[RUNTIME_PATH_MAX];
	char partition_prefix[RUNTIME_PATH_MAX];
};

struct raw_ring {
	int fd;
	void *sq_ring;
	void *cq_ring;
	void *sqes;
	size_t sq_ring_size;
	size_t cq_ring_size;
	size_t sqes_size;
	uint32_t *sq_head;
	uint32_t *sq_tail;
	uint32_t *sq_mask;
	uint32_t *sq_entries;
	uint32_t *sq_array;
	uint32_t *cq_head;
	uint32_t *cq_tail;
	uint32_t *cq_mask;
	uint32_t *cq_entries;
	enum nvme_xdev_ext_runtime_backing_ownership backing_ownership;
	struct io_uring_params params;
};

struct command_completion {
	uint64_t user_data;
	int32_t res;
	uint32_t flags;
	uint64_t extra1;
	uint64_t extra2;
};

struct observed_device {
	struct nvme_xdev_ext_runtime_safety safety;
	char canonical_device[PATH_MAX];
	char model[128];
	char serial[128];
	dev_t character_rdev;
};

static unsigned int checks;
static unsigned int failures;
static uint64_t next_user_data = UINT64_C(0x5542524e564d4500);

#define RUNTIME_PATH(field, ...)					\
	((size_t)snprintf(paths->field, sizeof(paths->field), __VA_ARGS__) >= \
	 sizeof(paths->field))

static int runtime_paths_init(struct runtime_paths *paths,
			      const char *generic, const char *controller,
			      const char *block)
{
	bool truncated = false;

	truncated |= RUNTIME_PATH(generic_dev, "/sys/class/nvme-generic/%s/dev",
				  generic);
	truncated |= RUNTIME_PATH(generic_parent,
				  "/sys/class/nvme-generic/%s/device", generic);
	truncated |= RUNTIME_PATH(controller, "/sys/class/nvme/%s", controller);
	truncated |= RUNTIME_PATH(model, "/sys/class/nvme/%s/model", controller);
	truncated |= RUNTIME_PATH(serial, "/sys/class/nvme/%s/serial",
				  controller);
	truncated |= RUNTIME_PATH(block, "/sys/class/block/%s", block);
	truncated |= RUNTIME_PATH(block_parent, "/sys/class/block/%s/device",
				  block);
	truncated |= RUNTIME_PATH(block_dev, "/sys/class/block/%s/dev", block);
	truncated |= RUNTIME_PATH(block_nsid, "/sys/class/block/%s/nsid", block);
	truncated |= RUNTIME_PATH(block_size,
				  "/sys/class/block/%s/queue/logical_block_size",
				  block);
	truncated |= RUNTIME_PATH(block_sectors, "/sys/class/block/%s/size",
				  block);
	truncated |= RUNTIME_PATH(holders, "/sys/class/block/%s/holders", block);
	truncated |= RUNTIME_PATH(block_device, "/dev/%s", block);
	truncated |= RUNTIME_PATH(partition_prefix, "%sp", block);
	return truncated ? -ENAMETOOLONG : 0;
}

static void report_check(const char *name, bool ok)
{
	checks++;
	printf("%s %u - %s\n", ok ? "ok" : "not ok", checks, name);
	if (!ok)
		failures++;
}

static int read_text_file(const char *path, char *buffer, size_t size)
{
	ssize_t bytes;
	size_t first = 0;
	int fd;

	if (!size)
		return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	bytes = read(fd, buffer, size - 1);
	if (bytes < 0) {
		int error = -errno;

		close(fd);
		return error;
	}
	close(fd);
	buffer[bytes] = '\0';
	while (bytes > 0 && (buffer[bytes - 1] == '\n' ||
			     buffer[bytes - 1] == '\r' ||
			     buffer[bytes - 1] == ' ' ||
			     buffer[bytes - 1] == '\t'))
		buffer[--bytes] = '\0';
	while (buffer[first] == ' ' || buffer[first] == '\t')
		first++;
	if (first)
		memmove(buffer, buffer + first, (size_t)bytes - first + 1);
	return 0;
}

static int read_u64_file(const char *path, uint64_t *value)
{
	char buffer[64];
	char *end;
	unsigned long long parsed;
	int ret;

	ret = read_text_file(path, buffer, sizeof(buffer));
	if (ret)
		return ret;
	errno = 0;
	parsed = strtoull(buffer, &end, 10);
	if (errno || !buffer[0] || *end)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int parse_device_number(const char *path, unsigned int *major_number,
			       unsigned int *minor_number)
{
	char buffer[64];
	char trailing;
	int ret;

	ret = read_text_file(path, buffer, sizeof(buffer));
	if (ret)
		return ret;
	if (sscanf(buffer, "%u:%u%c", major_number, minor_number,
		   &trailing) != 2)
		return -EINVAL;
	return 0;
}

static bool running_under_hypervisor(void)
{
	char line[4096];
	FILE *file;
	bool found = false;

	file = fopen("/proc/cpuinfo", "re");
	if (!file)
		return false;
	while (fgets(line, sizeof(line), file)) {
		if (strstr(line, "hypervisor")) {
			found = true;
			break;
		}
	}
	fclose(file);
	return found;
}

static bool directory_has_entries(const char *path)
{
	struct dirent *entry;
	DIR *directory;
	bool found = false;

	directory = opendir(path);
	if (!directory)
		return true;
	errno = 0;
	while ((entry = readdir(directory))) {
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
			found = true;
			break;
		}
	}
	if (!entry && errno)
		found = true;
	closedir(directory);
	return found;
}

static bool namespace_has_partitions(const struct runtime_paths *paths)
{
	const char *prefix = paths->partition_prefix;
	size_t length = strlen(prefix);
	struct dirent *entry;
	DIR *directory;
	bool found = false;

	directory = opendir(paths->block);
	if (!directory)
		return true;
	errno = 0;
	while ((entry = readdir(directory))) {
		if (!strncmp(entry->d_name, prefix, length) &&
		    entry->d_name[length] >= '0' &&
		    entry->d_name[length] <= '9') {
			found = true;
			break;
		}
	}
	if (!entry && errno)
		found = true;
	closedir(directory);
	return found;
}

static bool namespace_is_mounted(const struct runtime_paths *paths)
{
	unsigned int block_major, block_minor;
	unsigned int line_major, line_minor;
	char line[8192];
	FILE *mountinfo;
	bool mounted = false;

	if (parse_device_number(paths->block_dev, &block_major, &block_minor))
		return true;
	mountinfo = fopen("/proc/self/mountinfo", "re");
	if (!mountinfo)
		return true;
	while (fgets(line, sizeof(line), mountinfo)) {
		if (sscanf(line, "%*u %*u %u:%u", &line_major,
			   &line_minor) == 2 && line_major == block_major &&
		    line_minor == block_minor) {
			mounted = true;
			break;
		}
	}
	if (ferror(mountinfo))
		mounted = true;
	fclose(mountinfo);
	return mounted;
}

static bool namespace_is_swap(const struct runtime_paths *paths)
{
	unsigned int block_major, block_minor;
	char line[PATH_MAX + 256];
	FILE *swaps;
	bool active = false;

	if (parse_device_number(paths->block_dev, &block_major, &block_minor))
		return true;
	swaps = fopen("/proc/swaps", "re");
	if (!swaps)
		return true;
	while (fgets(line, sizeof(line), swaps)) {
		char *separator = strpbrk(line, " \t\n");
		struct stat swap_stat;

		if (!separator) {
			active = true;
			break;
		}
		*separator = '\0';
		if (!strcmp(line, "Filename"))
			continue;
		if (!strcmp(line, paths->block_device)) {
			active = true;
			break;
		}
		if (!stat(line, &swap_stat) && S_ISBLK(swap_stat.st_mode) &&
		    major(swap_stat.st_rdev) == block_major &&
		    minor(swap_stat.st_rdev) == block_minor) {
			active = true;
			break;
		}
	}
	if (ferror(swaps))
		active = true;
	fclose(swaps);
	return active;
}

static bool block_guard_fd_matches(const struct runtime_paths *paths, int fd)
{
	unsigned int sysfs_major, sysfs_minor;
	struct stat block_stat;
	bool block_device = false;
	bool sysfs_matches = false;

	if (fd >= 0 && !fstat(fd, &block_stat)) {
		block_device = S_ISBLK(block_stat.st_mode);
		if (!parse_device_number(paths->block_dev, &sysfs_major,
					 &sysfs_minor))
			sysfs_matches = major(block_stat.st_rdev) == sysfs_major &&
				minor(block_stat.st_rdev) == sysfs_minor;
	}
	return nvme_xdev_ext_runtime_block_guard_valid(fd >= 0, block_device,
						  sysfs_matches);
}

static int open_block_guard(const struct runtime_paths *paths)
{
	int fd;

	fd = open(paths->block_device,
		  O_RDONLY | O_CLOEXEC | O_EXCL | O_NOFOLLOW);
	if (fd < 0)
		return -errno;
	if (!block_guard_fd_matches(paths, fd)) {
		close(fd);
		return -ENODEV;
	}
	return fd;
}

static bool sysfs_matches_character_device(const struct runtime_paths *paths,
					   const struct stat *device_stat)
{
	unsigned int sysfs_major, sysfs_minor;
	char generic_parent[PATH_MAX];
	char controller[PATH_MAX];
	struct stat block_stat;

	if (parse_device_number(paths->generic_dev, &sysfs_major,
				&sysfs_minor))
		return false;
	if (major(device_stat->st_rdev) != sysfs_major ||
	    minor(device_stat->st_rdev) != sysfs_minor)
		return false;
	if (!realpath(paths->generic_parent, generic_parent) ||
	    !realpath(paths->controller, controller) ||
	    strcmp(generic_parent, controller))
		return false;
	if (stat(paths->block, &block_stat) || !S_ISDIR(block_stat.st_mode))
		return false;
	return true;
}

static bool sibling_topology_matches(const struct runtime_paths *paths)
{
	char block_parent[PATH_MAX];
	char generic_parent[PATH_MAX];
	char controller[PATH_MAX];

	if (!realpath(paths->block_parent, block_parent) ||
	    !realpath(paths->generic_parent, generic_parent) ||
	    !realpath(paths->controller, controller))
		return false;
	return !strcmp(block_parent, generic_parent) &&
	       !strcmp(block_parent, controller);
}

static void collect_observed_device(const struct runtime_paths *paths,
				    const char *device, bool allow_write,
				    struct observed_device *observed)
{
	struct stat device_lstat;
	struct stat device_stat;

	memset(observed, 0, sizeof(*observed));
	observed->safety.device = device;
	observed->safety.allow_file_backed_write = allow_write;
	if (realpath(device, observed->canonical_device))
		observed->safety.canonical_device = observed->canonical_device;
	if (!read_text_file(paths->model, observed->model,
			    sizeof(observed->model)))
		observed->safety.model = observed->model;
	if (!read_text_file(paths->serial, observed->serial,
			    sizeof(observed->serial)))
		observed->safety.serial = observed->serial;
	observed->safety.virtual_machine = running_under_hypervisor();
	if (!lstat(device, &device_lstat) && !S_ISLNK(device_lstat.st_mode) &&
	    !stat(device, &device_stat) && S_ISCHR(device_stat.st_mode)) {
		observed->safety.character_device = 1;
		observed->character_rdev = device_stat.st_rdev;
		observed->safety.sysfs_device_matches =
			sysfs_matches_character_device(paths, &device_stat);
	}
	observed->safety.sibling_topology_matches =
		sibling_topology_matches(paths);
	observed->safety.mounted = namespace_is_mounted(paths);
	observed->safety.has_holders = directory_has_entries(paths->holders);
	observed->safety.has_partitions = namespace_has_partitions(paths);
	observed->safety.in_swap = namespace_is_swap(paths);
}

/* The namespace a run may touch, opened only after the safety gate. */
struct gated_namespace {
	struct runtime_paths paths;
	struct observed_device before_open;
	struct observed_device after_open;
	const char *device;
	const char *serial;		/* expected controller serial */
	bool allow_write;
	int fd;
	int block_fd;
	int nsid;
	uint32_t lba_size;
	uint64_t capacity_lbas;
};

static enum nvme_xdev_ext_runtime_safety_result
observed_safety_result(const struct gated_namespace *target,
		       const struct observed_device *observed)
{
	return nvme_xdev_ext_runtime_check_safety_for(&observed->safety,
						 target->allow_write,
						 target->device,
						 target->serial);
}

static const char *safety_result_name(enum nvme_xdev_ext_runtime_safety_result result)
{
	switch (result) {
	case NVME_XDEV_EXT_RUNTIME_SAFE:
		return "safe";
	case NVME_XDEV_EXT_RUNTIME_SKIP_NO_DEVICE:
		return "no explicit device";
	case NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE:
		return "device is not exactly the requested generic namespace";
	case NVME_XDEV_EXT_RUNTIME_REJECT_IDENTITY:
		return "QEMU model or serial mismatch";
	case NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE_TYPE:
		return "device is not a direct character-device node";
	case NVME_XDEV_EXT_RUNTIME_REJECT_SYSFS_MISMATCH:
		return "device and NVMe sysfs topology mismatch";
	case NVME_XDEV_EXT_RUNTIME_REJECT_SIBLING_TOPOLOGY:
		return "generic and block namespaces are not controller siblings";
	case NVME_XDEV_EXT_RUNTIME_REJECT_NOT_VM:
		return "CPU does not report a hypervisor";
	case NVME_XDEV_EXT_RUNTIME_REJECT_MOUNTED:
		return "namespace is mounted";
	case NVME_XDEV_EXT_RUNTIME_REJECT_HOLDERS:
		return "namespace has holders";
	case NVME_XDEV_EXT_RUNTIME_REJECT_PARTITIONS:
		return "namespace has partitions";
	case NVME_XDEV_EXT_RUNTIME_REJECT_SWAP:
		return "namespace is active swap";
	case NVME_XDEV_EXT_RUNTIME_REJECT_WRITE_NOT_ALLOWED:
		return "write flag was not supplied";
	}
	return "unknown safety result";
}

static void close_gated_namespace(struct gated_namespace *target)
{
	if (target->fd >= 0)
		close(target->fd);
	if (target->block_fd >= 0)
		close(target->block_fd);
	target->fd = -1;
	target->block_fd = -1;
}

/*
 * Safety gate, exclusive hold of the block sibling, open, gate again, then
 * the namespace geometry from sysfs.  Prints REFUSE and returns -errno on
 * any mismatch, with nothing left open.
 */
static int open_gated_namespace(struct gated_namespace *target)
{
	enum nvme_xdev_ext_runtime_safety_result safety_result;
	uint64_t block_sectors, capacity_bytes;
	uint64_t lba_size_u64, nsid_u64;
	struct stat fd_stat;

	target->fd = -1;
	target->block_fd = -1;
	collect_observed_device(&target->paths, target->device,
				target->allow_write, &target->before_open);
	safety_result = observed_safety_result(target, &target->before_open);
	if (safety_result != NVME_XDEV_EXT_RUNTIME_SAFE) {
		fprintf(stderr, "REFUSE: %s\n", safety_result_name(safety_result));
		return -EPERM;
	}
	if (geteuid()) {
		fprintf(stderr, "REFUSE: runtime harness must run as root in KVM\n");
		return -EPERM;
	}
	target->block_fd = open_block_guard(&target->paths);
	if (target->block_fd < 0) {
		fprintf(stderr, "REFUSE: cannot exclusively hold %s: %s\n",
			target->paths.block_device, strerror(-target->block_fd));
		target->block_fd = -1;
		return -EBUSY;
	}

	target->fd = open(target->device,
			  (target->allow_write ? O_RDWR : O_RDONLY) |
			  O_CLOEXEC | O_NOFOLLOW);
	if (target->fd < 0) {
		perror("open NVMe generic namespace");
		close_gated_namespace(target);
		return -ENODEV;
	}
	collect_observed_device(&target->paths, target->device,
				target->allow_write, &target->after_open);
	safety_result = observed_safety_result(target, &target->after_open);
	if (safety_result != NVME_XDEV_EXT_RUNTIME_SAFE ||
	    fstat(target->fd, &fd_stat) || !S_ISCHR(fd_stat.st_mode) ||
	    fd_stat.st_rdev != target->before_open.character_rdev ||
	    fd_stat.st_rdev != target->after_open.character_rdev ||
	    !block_guard_fd_matches(&target->paths, target->block_fd)) {
		fprintf(stderr, "REFUSE: device changed while applying safety gate\n");
		close_gated_namespace(target);
		return -ESTALE;
	}

	target->nsid = ioctl(target->fd, NVME_IOCTL_ID);
	if (target->nsid <= 0 ||
	    read_u64_file(target->paths.block_nsid, &nsid_u64) ||
	    nsid_u64 != (uint32_t)target->nsid) {
		fprintf(stderr, "REFUSE: namespace ID does not match sysfs\n");
		close_gated_namespace(target);
		return -EXDEV;
	}
	if (read_u64_file(target->paths.block_size, &lba_size_u64) ||
	    lba_size_u64 < 512 || lba_size_u64 > 65536 ||
	    (lba_size_u64 & (lba_size_u64 - 1)) ||
	    read_u64_file(target->paths.block_sectors, &block_sectors) ||
	    block_sectors > UINT64_MAX / 512) {
		fprintf(stderr, "REFUSE: invalid namespace geometry in sysfs\n");
		close_gated_namespace(target);
		return -EINVAL;
	}
	target->lba_size = (uint32_t)lba_size_u64;
	capacity_bytes = block_sectors * 512;
	if (!capacity_bytes || capacity_bytes % target->lba_size) {
		fprintf(stderr, "REFUSE: namespace capacity is not LBA aligned\n");
		close_gated_namespace(target);
		return -EINVAL;
	}
	target->capacity_lbas = capacity_bytes / target->lba_size;
	return 0;
}

static void raw_ring_destroy(struct raw_ring *ring)
{
	if (ring->sqes && ring->sqes != MAP_FAILED)
		munmap(ring->sqes, ring->sqes_size);
	if (ring->cq_ring && ring->cq_ring != MAP_FAILED &&
	    ring->cq_ring != ring->sq_ring)
		munmap(ring->cq_ring, ring->cq_ring_size);
	if (ring->sq_ring && ring->sq_ring != MAP_FAILED)
		munmap(ring->sq_ring, ring->sq_ring_size);
	if (ring->fd >= 0)
		close(ring->fd);
	memset(ring, 0, sizeof(*ring));
	ring->fd = -1;
}

static int raw_ring_init(struct raw_ring *ring)
{
	struct io_uring_params *params = &ring->params;
	size_t single_size;

	memset(ring, 0, sizeof(*ring));
	ring->fd = -1;
	params->flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	ring->fd = syscall(SYS_io_uring_setup, RING_ENTRIES, params);
	if (ring->fd < 0)
		return -errno;
	if (!(params->flags & IORING_SETUP_SQE128) ||
	    !(params->flags & IORING_SETUP_CQE32)) {
		raw_ring_destroy(ring);
		return -EPROTO;
	}

	ring->sq_ring_size = params->sq_off.array +
		params->sq_entries * sizeof(uint32_t);
	ring->cq_ring_size = params->cq_off.cqes +
		params->cq_entries * NVME_XDEV_EXT_RUNTIME_CQE_SIZE;
	ring->sqes_size = params->sq_entries * NVME_XDEV_EXT_RUNTIME_SQE_SIZE;
	if (params->features & IORING_FEAT_SINGLE_MMAP) {
		single_size = ring->sq_ring_size > ring->cq_ring_size ?
			ring->sq_ring_size : ring->cq_ring_size;
		ring->sq_ring_size = single_size;
		ring->cq_ring_size = single_size;
	}
	ring->sq_ring = mmap(NULL, ring->sq_ring_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, ring->fd, IORING_OFF_SQ_RING);
	if (ring->sq_ring == MAP_FAILED) {
		int error = -errno;

		raw_ring_destroy(ring);
		return error;
	}
	if (params->features & IORING_FEAT_SINGLE_MMAP) {
		ring->cq_ring = ring->sq_ring;
	} else {
		ring->cq_ring = mmap(NULL, ring->cq_ring_size,
				     PROT_READ | PROT_WRITE, MAP_SHARED,
				     ring->fd, IORING_OFF_CQ_RING);
		if (ring->cq_ring == MAP_FAILED) {
			int error = -errno;

			raw_ring_destroy(ring);
			return error;
		}
	}
	ring->sqes = mmap(NULL, ring->sqes_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, ring->fd, IORING_OFF_SQES);
	if (ring->sqes == MAP_FAILED) {
		int error = -errno;

		raw_ring_destroy(ring);
		return error;
	}

	ring->sq_head = ring->sq_ring + params->sq_off.head;
	ring->sq_tail = ring->sq_ring + params->sq_off.tail;
	ring->sq_mask = ring->sq_ring + params->sq_off.ring_mask;
	ring->sq_entries = ring->sq_ring + params->sq_off.ring_entries;
	ring->sq_array = ring->sq_ring + params->sq_off.array;
	ring->cq_head = ring->cq_ring + params->cq_off.head;
	ring->cq_tail = ring->cq_ring + params->cq_off.tail;
	ring->cq_mask = ring->cq_ring + params->cq_off.ring_mask;
	ring->cq_entries = ring->cq_ring + params->cq_off.ring_entries;
	if (!*ring->sq_entries || !*ring->cq_entries) {
		raw_ring_destroy(ring);
		return -EPROTO;
	}
	return 0;
}

static int raw_ring_register_buffers(struct raw_ring *ring, void **buffers,
				     unsigned int count, size_t buffer_size)
{
	struct iovec *iovecs;
	unsigned int index;
	int ret;

	if (!ring || ring->fd < 0 || !buffers || !count || !buffer_size)
		return -EINVAL;
	iovecs = calloc(count, sizeof(*iovecs));
	if (!iovecs)
		return -ENOMEM;
	for (index = 0; index < count; index++) {
		if (!buffers[index]) {
			free(iovecs);
			return -EINVAL;
		}
		iovecs[index].iov_base = buffers[index];
		iovecs[index].iov_len = buffer_size;
	}
	ret = syscall(SYS_io_uring_register, ring->fd,
		      IORING_REGISTER_BUFFERS, iovecs, count);
	free(iovecs);
	return ret < 0 ? -errno : 0;
}

static int raw_ring_enter(struct raw_ring *ring, unsigned int submit,
			  unsigned int minimum)
{
	int ret;

	ret = syscall(SYS_io_uring_enter, ring->fd, submit, minimum,
		      minimum ? IORING_ENTER_GETEVENTS : 0, NULL, 0);
	return ret < 0 ? -errno : ret;
}

static int64_t monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int raw_ring_wait_for_cqe(struct raw_ring *ring, int64_t deadline)
{
	struct pollfd pollfd = {
		.fd = ring->fd,
		.events = POLLIN,
	};
	int64_t now;
	int timeout;
	int ret;

	for (;;) {
		if (__atomic_load_n(ring->cq_head, __ATOMIC_RELAXED) !=
		    __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE))
			return 0;
		now = monotonic_milliseconds();
		if (now < 0)
			return -EIO;
		if (now >= deadline)
			return -ETIMEDOUT;
		timeout = deadline - now > POLL_SLICE_MS ?
			POLL_SLICE_MS : (int)(deadline - now);
		ret = poll(&pollfd, 1, timeout);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (ret && (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
			return -EIO;
		/* A syscall boundary also gives lazy io_uring task work a turn. */
		ret = raw_ring_enter(ring, 0, 0);
		if (ret < 0 && ret != -EINTR)
			return ret;
	}
}

static int raw_ring_execute(struct raw_ring *ring,
			    const struct nvme_xdev_ext_runtime_command *input,
			    struct command_completion *completion)
{
	struct nvme_xdev_ext_runtime_command command = *input;
	enum nvme_xdev_ext_runtime_backing_ownership ownership;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	uint32_t cq_head, cq_tail;
	uint32_t sq_head, sq_tail;
	uint32_t sq_index;
	uint32_t pending;
	int64_t deadline;
	int matches;
	int ret;

	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS ||
	    ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_PUBLISHED ||
	    ring->backing_ownership ==
		NVME_XDEV_EXT_RUNTIME_BACKING_RETAINED_FAILURE)
		return -ESHUTDOWN;
	deadline = monotonic_milliseconds();
	if (deadline < 0)
		return -EIO;
	deadline += COMMAND_TIMEOUT_MS;
	sq_head = __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE);
	sq_tail = __atomic_load_n(ring->sq_tail, __ATOMIC_RELAXED);
	if (sq_tail - sq_head >= *ring->sq_entries)
		return -EBUSY;
	sq_index = sq_tail & *ring->sq_mask;
	sqe = nvme_xdev_ext_runtime_sqe_at(ring->sqes, sq_index);
	command.user_data = ++next_user_data;
	ret = nvme_xdev_ext_runtime_encode(sqe, &command);
	if (ret)
		return ret;
	ring->sq_array[sq_tail & *ring->sq_mask] = sq_index;
	__atomic_store_n(ring->sq_tail, sq_tail + 1, __ATOMIC_RELEASE);
	ring->backing_ownership = NVME_XDEV_EXT_RUNTIME_BACKING_PUBLISHED;

	for (;;) {
		ret = raw_ring_enter(ring, 1, 0);
		if (ret > 0 ||
		    __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE) != sq_head)
			break;
		if (ret < 0 && ret != -EINTR)
			break;
		{
			int64_t now = monotonic_milliseconds();

			if (now >= 0 && now < deadline)
				continue;
			ret = -ETIMEDOUT;
			break;
		}
	}
	if (ret < 0 && ret != -EINTR) {
		ring->backing_ownership = nvme_xdev_ext_runtime_wait_result(0);
		return ret;
	}
	ret = raw_ring_wait_for_cqe(ring, deadline);
	if (ret) {
		ring->backing_ownership = nvme_xdev_ext_runtime_wait_result(0);
		return ret;
	}
	cq_head = __atomic_load_n(ring->cq_head, __ATOMIC_RELAXED);
	cq_tail = __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE);
	if (cq_head == cq_tail) {
		ring->backing_ownership = nvme_xdev_ext_runtime_wait_result(0);
		return -EPROTO;
	}
	cqe = nvme_xdev_ext_runtime_cqe_at(ring->cq_ring + ring->params.cq_off.cqes,
				      cq_head & *ring->cq_mask);
	completion->user_data = cqe->user_data;
	completion->res = cqe->res;
	completion->flags = cqe->flags;
	completion->extra1 = cqe->big_cqe[0];
	completion->extra2 = cqe->big_cqe[1];
	__atomic_store_n(ring->cq_head, cq_head + 1, __ATOMIC_RELEASE);
	matches = completion->user_data == command.user_data;
	pending = cq_tail - cq_head;
	ownership = nvme_xdev_ext_runtime_cqe_ownership(completion->flags, matches,
						   pending);
	ring->backing_ownership = ownership;
	if (ring->backing_ownership != NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED)
		return -EPROTO;
	return 0;
}

static struct nvme_xdev_ext_runtime_command
read_command(int fd, uint32_t nsid, uint64_t slba, uint32_t lba_size,
	     void *buffer, uint32_t flags)
{
	struct nvme_xdev_ext_runtime_command command = {
		.fd = fd,
		.cmd_op = NVME_URING_CMD_IO,
		.buffer = (uintptr_t)buffer,
		.slba = slba,
		.data_len = lba_size,
		.nsid = nsid,
		.nlb = 1,
		.xdev_ext_flags = flags,
		.opcode = NVME_XDEV_EXT_NVM_READ,
	};

	return command;
}

static bool run_expected(struct raw_ring *ring, const char *name,
			 const struct nvme_xdev_ext_runtime_command *command,
			 int expected, struct command_completion *completion)
{
	struct command_completion local = {};
	int ret;
	bool ok;

	ret = raw_ring_execute(ring, command, &local);
	ok = !ret && local.res == expected;
	if (!ok) {
		fprintf(stderr,
			"%s: transport=%d cqe.res=%d expected=%d flags=%#x\n",
			name, ret, local.res, expected, local.flags);
		fprintf(stderr, "completion extra1=%llu extra2=%llu\n",
			(unsigned long long)local.extra1,
			(unsigned long long)local.extra2);
	}
	report_check(name, ok);
	if (completion)
		*completion = local;
	return ok;
}

static void run_preflight_cases(struct raw_ring *ring,
				const struct nvme_xdev_ext_runtime_command *valid,
				uint64_t capacity_lbas, struct iovec *vector)
{
	struct nvme_xdev_ext_runtime_command command;

	command = *valid;
	/* The lowest bit above the contiguous known mask. */
	command.xdev_ext_flags = NVME_URING_CMD_F_XDEV_EXT |
			    (NVME_URING_CMD_F_KNOWN_MASK + 1U);
	run_expected(ring, "unknown rsvd2 bits fail with -EINVAL", &command,
		     -EINVAL, NULL);
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return;

	command = *valid;
	command.cmd_op = NVME_URING_CMD_IO_VEC;
	command.buffer = (uintptr_t)vector;
	command.data_len = 1;
	run_expected(ring, "opted-in non-fixed vector fails with -EOPNOTSUPP",
		     &command, -EOPNOTSUPP, NULL);
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return;

	command = *valid;
	command.data_len++;
	run_expected(ring, "length/NLB mismatch fails with -EMSGSIZE",
		     &command, -EMSGSIZE, NULL);
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return;

	command = *valid;
	command.data_len = 0;
	run_expected(ring, "zero data length fails with -EINVAL", &command,
		     -EINVAL, NULL);
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return;

	command = *valid;
	command.nsid++;
	if (!command.nsid)
		command.nsid = 1;
	run_expected(ring, "wrong namespace ID fails with -EINVAL", &command,
		     -EINVAL, NULL);
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return;

	command = *valid;
	command.slba = capacity_lbas;
	run_expected(ring, "LBA at capacity fails with -ERANGE", &command,
		     -ERANGE, NULL);
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return;

	command = *valid;
	command.slba = UINT64_MAX;
	run_expected(ring, "overflowing LBA fails with -EOVERFLOW", &command,
		     -EOVERFLOW, NULL);
}

static bool run_fixed_buffer_cases(struct raw_ring *ring,
				   const struct nvme_xdev_ext_runtime_command *valid,
				   void **buffers, uint32_t lba_size)
{
	struct nvme_xdev_ext_runtime_command command;
	struct iovec vector[2];
	bool all_ok = true;

	command = *valid;
	command.buffer = (uintptr_t)buffers[1];
	command.uring_cmd_flags = IORING_URING_CMD_FIXED;
	command.buf_index = 1;
	memset(buffers[1], 0, lba_size);
	all_ok &= run_expected(ring, "opted-in fixed-buffer READ succeeds",
			       &command, 0, NULL);
	all_ok &= !memcmp(buffers[0], buffers[1], lba_size);
	report_check("fixed-buffer READ matches native bytes",
		     !memcmp(buffers[0], buffers[1], lba_size));
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return false;

	vector[0].iov_base = buffers[1];
	vector[0].iov_len = lba_size / 2;
	vector[1].iov_base = (unsigned char *)buffers[1] + lba_size / 2;
	vector[1].iov_len = lba_size - vector[0].iov_len;

	command = *valid;
	command.cmd_op = NVME_URING_CMD_IO_VEC;
	command.buffer = (uintptr_t)vector;
	command.data_len = 2;
	command.xdev_ext_flags = 0;
	memset(buffers[1], 0, lba_size);
	all_ok &= run_expected(ring, "native non-fixed vector READ succeeds",
			       &command, 0, NULL);
	all_ok &= !memcmp(buffers[0], buffers[1], lba_size);
	report_check("native vector READ matches scalar bytes",
		     !memcmp(buffers[0], buffers[1], lba_size));
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return false;

	command.xdev_ext_flags = NVME_URING_CMD_F_XDEV_EXT;
	run_expected(ring, "opted-in non-fixed vector remains rejected",
		     &command, -EOPNOTSUPP, NULL);
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return false;

	command.uring_cmd_flags = IORING_URING_CMD_FIXED;
	command.buf_index = 1;
	memset(buffers[1], 0, lba_size);
	all_ok &= run_expected(ring, "opted-in fixed-vector READ succeeds",
			       &command, 0, NULL);
	all_ok &= !memcmp(buffers[0], buffers[1], lba_size);
	report_check("fixed-vector READ matches scalar bytes",
		     !memcmp(buffers[0], buffers[1], lba_size));
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return false;

	vector[1].iov_len++;
	run_expected(ring, "fixed-vector total/NLB mismatch fails with -EMSGSIZE",
		     &command, -EMSGSIZE, NULL);
	vector[1].iov_len--;
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return false;

	vector[1].iov_base = (unsigned char *)buffers[1] + 2U * lba_size - 1;
	vector[1].iov_len = 2;
	vector[0].iov_len = lba_size - 2;
	run_expected(ring, "fixed-vector range outside registered buffer fails",
		     &command, -EFAULT, NULL);
	return all_ok &&
		ring->backing_ownership != NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS;
}

static bool run_fixed_vector_write_round_trip(
		struct raw_ring *ring,
		const struct nvme_xdev_ext_runtime_command *valid,
		void **buffers, uint32_t lba_size,
		enum nvme_xdev_ext_runtime_media_state *media_state)
{
	struct nvme_xdev_ext_runtime_command command = *valid;
	struct iovec original[2], pattern[2], readback[2];
	unsigned int half = lba_size / 2;
	bool written = false;
	bool restored;
	bool all_ok = true;

	original[0] = (struct iovec) { buffers[0], half };
	original[1] = (struct iovec) {
		(unsigned char *)buffers[0] + half, lba_size - half
	};
	pattern[0] = (struct iovec) { buffers[2], half };
	pattern[1] = (struct iovec) {
		(unsigned char *)buffers[2] + half, lba_size - half
	};
	readback[0] = (struct iovec) { buffers[3], half };
	readback[1] = (struct iovec) {
		(unsigned char *)buffers[3] + half, lba_size - half
	};

	command.cmd_op = NVME_URING_CMD_IO_VEC;
	command.data_len = 2;
	command.uring_cmd_flags = IORING_URING_CMD_FIXED;
	command.opcode = NVME_XDEV_EXT_NVM_WRITE;
	command.buffer = (uintptr_t)pattern;
	command.buf_index = 2;
	*media_state = NVME_XDEV_EXT_RUNTIME_MEDIA_WRITE_PUBLISHED;
	if (run_expected(ring, "opted-in fixed-vector WRITE succeeds",
			 &command, 0, NULL)) {
		written = true;
		*media_state = nvme_xdev_ext_runtime_media_write_result(1);
	} else {
		*media_state = nvme_xdev_ext_runtime_media_write_result(0);
		ring->backing_ownership =
			nvme_xdev_ext_runtime_restore_failed(ring->backing_ownership);
		return false;
	}

	memset(buffers[3], 0, lba_size);
	command.opcode = NVME_XDEV_EXT_NVM_READ;
	command.buffer = (uintptr_t)readback;
	command.buf_index = 3;
	all_ok &= run_expected(ring, "fixed-vector READ after WRITE succeeds",
			       &command, 0, NULL);
	all_ok &= !memcmp(buffers[2], buffers[3], lba_size);
	report_check("fixed-vector WRITE data is read back exactly",
		     !memcmp(buffers[2], buffers[3], lba_size));
	if (ring->backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS) {
		*media_state = NVME_XDEV_EXT_RUNTIME_MEDIA_TAINTED;
		return false;
	}

	if (!written)
		return false;
	command.opcode = NVME_XDEV_EXT_NVM_WRITE;
	command.buffer = (uintptr_t)original;
	command.buf_index = 0;
	restored = run_expected(ring, "fixed-vector restore WRITE succeeds",
				&command, 0, NULL);
	if (!restored) {
		*media_state = NVME_XDEV_EXT_RUNTIME_MEDIA_TAINTED;
		ring->backing_ownership =
			nvme_xdev_ext_runtime_restore_failed(ring->backing_ownership);
		return false;
	}

	memset(buffers[3], 0, lba_size);
	command.opcode = NVME_XDEV_EXT_NVM_READ;
	command.buffer = (uintptr_t)readback;
	command.buf_index = 3;
	restored = run_expected(ring, "fixed-vector restored LBA can be read",
				&command, 0, NULL) &&
		   !memcmp(buffers[0], buffers[3], lba_size);
	report_check("fixed-vector restore matches original bytes", restored);
	*media_state = nvme_xdev_ext_runtime_media_restore_result(restored);
	if (!restored)
		ring->backing_ownership =
			nvme_xdev_ext_runtime_restore_failed(ring->backing_ownership);
	return all_ok && restored;
}

static bool run_write_round_trip(struct raw_ring *ring,
				 struct nvme_xdev_ext_runtime_command *command,
				 void *original, void *pattern, void *readback,
				 uint32_t lba_size,
				 enum nvme_xdev_ext_runtime_media_state *media_state)
{
	struct command_completion completion;
	bool pattern_written = false;
	bool all_ok = true;
	bool restored;

	command->opcode = NVME_XDEV_EXT_NVM_WRITE;
	command->buffer = (uintptr_t)pattern;
	*media_state = NVME_XDEV_EXT_RUNTIME_MEDIA_WRITE_PUBLISHED;
	if (run_expected(ring, "opted-in WRITE completes with native CQE res=0",
			 command, 0, &completion)) {
		pattern_written = true;
		*media_state = nvme_xdev_ext_runtime_media_write_result(1);
		all_ok &= completion.flags == 0 && completion.extra2 == 0;
		report_check("WRITE preserves native CQE flags/extra2", all_ok);
	} else {
		*media_state = nvme_xdev_ext_runtime_media_write_result(0);
		ring->backing_ownership =
			nvme_xdev_ext_runtime_restore_failed(ring->backing_ownership);
		all_ok = false;
	}

	if (pattern_written) {
		memset(readback, 0, lba_size);
		command->opcode = NVME_XDEV_EXT_NVM_READ;
		command->buffer = (uintptr_t)readback;
		all_ok &= run_expected(ring, "opted-in READ after WRITE succeeds",
				       command, 0, NULL);
		if (ring->backing_ownership ==
		    NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS) {
			*media_state = NVME_XDEV_EXT_RUNTIME_MEDIA_TAINTED;
			return false;
		}
		report_check("opted-in WRITE data is read back exactly",
			     !memcmp(pattern, readback, lba_size));
		all_ok &= !memcmp(pattern, readback, lba_size);
	}

	if (!pattern_written)
		return false;
	command->opcode = NVME_XDEV_EXT_NVM_WRITE;
	command->buffer = (uintptr_t)original;
	restored = run_expected(ring, "original file-backed LBA is restored",
				command, 0, NULL);
	if (!restored) {
		fprintf(stderr, "FATAL: failed to restore the test LBA\n");
		*media_state = nvme_xdev_ext_runtime_media_restore_result(0);
		ring->backing_ownership =
			nvme_xdev_ext_runtime_restore_failed(ring->backing_ownership);
		return false;
	}
	memset(readback, 0, lba_size);
	command->opcode = NVME_XDEV_EXT_NVM_READ;
	command->buffer = (uintptr_t)readback;
	restored = run_expected(ring, "restored LBA can be read", command, 0,
				NULL) && !memcmp(original, readback, lba_size);
	report_check("restored LBA matches its original bytes", restored);
	if (!restored) {
		fprintf(stderr, "FATAL: restored test LBA could not be verified\n");
		*media_state = nvme_xdev_ext_runtime_media_restore_result(0);
		ring->backing_ownership =
			nvme_xdev_ext_runtime_restore_failed(ring->backing_ownership);
	} else {
		*media_state = nvme_xdev_ext_runtime_media_restore_result(1);
	}
	return all_ok && restored;
}

/*
 * --mech-s0: plan section 4.2 (S0).  The harness attaches
 * tools/xdev_ext_mech/nvme_s0.bpf.c with xdev_ext_mech_ctl (global mode 0, 1 or 2) or
 * attaches nothing, then runs one case.  The runtime creates its own ring and
 * a one-stage NVMe WRITE session whose LBA window lies on the destination
 * controller UBRDST0001, zeroes and verifies the window, and issues one
 * NVME_URING_CMD_IO with F_XDEV_EXT | F_XDEV_EXT_BUILD and cdw10..cdw12 zero.  The
 * window is all zero again when a case passes.
 */
#define MECH_UMEM_FRAME 4096U
#define MECH_UMEM_FRAMES 4U

struct mech_options {
	enum nvme_xdev_ext_runtime_mech_case mech_case;
	uint64_t window_slba;
	uint64_t window_nlb;
	bool window_slba_set;
	bool window_nlb_set;
};

static const char *errno_name(int value, char *buffer, size_t size)
{
	switch (value) {
	case 0:
		return "0";
	case -EINVAL:
		return "-EINVAL";
	case -EPERM:
		return "-EPERM";
	case -ERANGE:
		return "-ERANGE";
	case -EMSGSIZE:
		return "-EMSGSIZE";
	case -EOPNOTSUPP:
		return "-EOPNOTSUPP";
	case -EPROTO:
		return "-EPROTO";
	case -ECANCELED:
		return "-ECANCELED";
	case -ESHUTDOWN:
		return "-ESHUTDOWN";
	}
	snprintf(buffer, size, "%d", value);
	return buffer;
}

/* Byte @offset of the payload a built WRITE carries. */
static uint8_t mech_pattern_byte(uint32_t offset)
{
	return (uint8_t)(offset * 131U + (offset >> 9) * 7U + 0x6dU);
}

static int mech_register(struct raw_ring *ring, unsigned int opcode,
			 void *argument)
{
	int ret;

	ret = syscall(SYS_io_uring_register, ring->fd, opcode, argument, 1);
	return ret < 0 ? -errno : ret;
}

static int mech_session_op(struct raw_ring *ring, uint32_t op, uint64_t arg)
{
	struct io_uring_xdev_ext_mech request = {
		.op = op,
		.arg = arg,
	};

	return mech_register(ring, IORING_REGISTER_XDEV_EXT_MECH, &request);
}

/* The ring's XDEV_EXT UMEM is the session pool; S0 starts no batch from it. */
static int mech_create(struct raw_ring *ring, int fd, void *umem,
		       const struct mech_options *mech, uint64_t *session_id)
{
	struct io_uring_xdev_ext_umem_reg umem_reg = {
		.addr = (uintptr_t)umem,
		.size = MECH_UMEM_FRAMES * MECH_UMEM_FRAME,
		.frame_size = MECH_UMEM_FRAME,
	};
	struct xdev_ext_mech_create create = {
		.abi_version = XDEV_EXT_MECH_ABI_VERSION,
		.nr_stages = 1,
		.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM,
		.pool_fd = -1,
		.layout = {
			.frame_size = MECH_UMEM_FRAME,
			.seg_len = MECH_UMEM_FRAME,
			.group_bytes = MECH_UMEM_FRAME,
		},
		.depth = 1,
		.eventfd = -1,
		.st[0] = {
			.class_id = XDEV_EXT_MECH_CLASS_NVME,
			.direction = XDEV_EXT_MECH_DIR_TO_DEVICE,
			.fd = fd,
			.arg0 = mech->window_slba,
			.arg1 = mech->window_nlb,
		},
	};
	int ret;

	ret = mech_register(ring, IORING_REGISTER_XDEV_EXT_UMEM, &umem_reg);
	if (ret < 0) {
		fprintf(stderr, "IORING_REGISTER_XDEV_EXT_UMEM: %s\n",
			strerror(-ret));
		return ret;
	}
	ret = mech_session_op(ring, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&create);
	if (ret < 0)
		return ret;
	*session_id = create.session_id;
	return 0;
}

/* Native WRITE or READ of LBAs [slba, slba + count) from or into @buffer. */
static bool mech_native_io(struct raw_ring *ring,
			   const struct gated_namespace *target,
			   uint8_t opcode, uint64_t slba, uint64_t count,
			   uint8_t *buffer)
{
	uint32_t chunk = NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES / target->lba_size;
	uint64_t done = 0;

	while (done < count) {
		uint32_t nlb = count - done < chunk ? (uint32_t)(count - done) :
						      chunk;
		struct nvme_xdev_ext_runtime_command command = {
			.fd = target->fd,
			.cmd_op = NVME_URING_CMD_IO,
			.buffer = (uintptr_t)(buffer + done * target->lba_size),
			.slba = slba + done,
			.data_len = nlb * target->lba_size,
			.nsid = (uint32_t)target->nsid,
			.nlb = nlb,
			.opcode = opcode,
		};
		struct command_completion completion = {};
		int ret;

		ret = raw_ring_execute(ring, &command, &completion);
		if (ret || completion.res) {
			fprintf(stderr, "native %s at LBA %llu: transport=%d res=%d\n",
				opcode == NVME_XDEV_EXT_NVM_WRITE ? "WRITE" : "READ",
				(unsigned long long)command.slba, ret,
				completion.res);
			return false;
		}
		done += nlb;
	}
	return true;
}

/* Bytes [from, to) of @buffer are zero. */
static bool mech_zero(const uint8_t *buffer, uint64_t from, uint64_t to)
{
	for (; from < to; from++)
		if (buffer[from])
			return false;
	return true;
}

/*
 * One built WRITE of the pattern; cdw10..cdw12 zero unless @user_slba.
 * completion->user_data is the request id the program saw.
 */
static int mech_built_write(struct raw_ring *ring,
			    const struct gated_namespace *target,
			    uint8_t *io, uint32_t flags, uint64_t user_slba,
			    struct command_completion *completion)
{
	struct nvme_xdev_ext_runtime_command command = {
		.fd = target->fd,
		.cmd_op = NVME_URING_CMD_IO,
		.buffer = (uintptr_t)io,
		.slba = user_slba,
		.data_len = NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES,
		.nsid = (uint32_t)target->nsid,
		.nlb = 1,	/* cdw12 = 0 */
		.xdev_ext_flags = flags,
		.opcode = NVME_XDEV_EXT_NVM_WRITE,
	};

	*completion = (struct command_completion) {};
	return raw_ring_execute(ring, &command, completion);
}

static bool mech_expect(struct raw_ring *ring,
			const struct gated_namespace *target, uint8_t *io,
			uint32_t flags, uint64_t user_slba, int expected,
			const char *name)
{
	struct command_completion completion;
	char buffer[16];
	bool ok;
	int ret;

	ret = mech_built_write(ring, target, io, flags, user_slba, &completion);
	ok = !ret && completion.res == expected;
	if (!ok)
		fprintf(stderr, "%s: transport=%d res=%s\n", name, ret,
			errno_name(completion.res, buffer, sizeof(buffer)));
	report_check(name, ok);
	return ok;
}

static int run_mech_s0(const char *device, const struct mech_options *mech)
{
	enum nvme_xdev_ext_runtime_mech_case mech_case = mech->mech_case;
	const char *name = nvme_xdev_ext_runtime_mech_case_name(mech_case);
	int expected = nvme_xdev_ext_runtime_mech_case_expected(mech_case);
	const uint32_t flags = NVME_URING_CMD_F_XDEV_EXT | NVME_URING_CMD_F_XDEV_EXT_BUILD;
	char generic[32], controller[32], block[32];
	char res_buffer[16], create_buffer[16];
	const char *res_name, *create_name;
	struct gated_namespace target = {
		.device = device,
		.serial = NVME_XDEV_EXT_RUNTIME_MECH_SERIAL,
		.allow_write = true,
	};
	struct command_completion completion = {};
	struct xdev_ext_mech_stats stats = {};
	uint8_t *io = NULL, *window = NULL;
	uint64_t window_bytes, offset, slba = 0;
	bool session = false, admit_plain = false, data_ok = false;
	bool ring_ready = false, release = true;
	uint32_t io_nlb = 0;
	uint64_t session_id = 0;
	void *umem = NULL;
	struct raw_ring ring;
	int create = -EINVAL, res = -EINVAL;
	int ret;

	/* Reject anything but /dev/ng<C>n<N> before any lookup on the path. */
	if (nvme_xdev_ext_runtime_mech_names(device, generic, controller, block,
					sizeof(generic)) ||
	    runtime_paths_init(&target.paths, generic, controller, block)) {
		fprintf(stderr, "REFUSE: --mech-s0 needs /dev/ng<C>n<N>\n");
		return 1;
	}
	if (open_gated_namespace(&target))
		return 1;
	ret = nvme_xdev_ext_runtime_mech_window_valid(mech->window_slba,
						 mech->window_nlb,
						 target.capacity_lbas,
						 target.lba_size);
	if (ret) {
		fprintf(stderr, "REFUSE: window %llu+%llu: %s\n",
			(unsigned long long)mech->window_slba,
			(unsigned long long)mech->window_nlb, strerror(-ret));
		close_gated_namespace(&target);
		return 1;
	}
	io_nlb = NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES / target.lba_size;
	window_bytes = mech->window_nlb * target.lba_size;
	if (posix_memalign((void **)&io, 4096, NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES) ||
	    posix_memalign((void **)&window, 4096, window_bytes) ||
	    posix_memalign(&umem, 4096, MECH_UMEM_FRAMES * MECH_UMEM_FRAME)) {
		fprintf(stderr, "posix_memalign failed\n");
		ret = -ENOMEM;
		goto out;
	}
	memset(umem, 0, MECH_UMEM_FRAMES * MECH_UMEM_FRAME);
	for (offset = 0; offset < NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES; offset++)
		io[offset] = mech_pattern_byte((uint32_t)offset);
	ret = raw_ring_init(&ring);
	if (ret) {
		fprintf(stderr, "io_uring SQE128/CQE32 setup failed: %s\n",
			strerror(-ret));
		goto out;
	}
	ring_ready = true;

	printf("TAP version 13\n");
	printf("# mech-s0 case=%s device=%s serial=%s nsid=%d lba=%u window=%llu+%llu\n",
	       name, device, target.after_open.serial, target.nsid,
	       target.lba_size, (unsigned long long)mech->window_slba,
	       (unsigned long long)mech->window_nlb);

	create = mech_create(&ring, target.fd, umem, mech, &session_id);
	session = !create;
	if (mech_case == NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG)
		report_check("CREATE without an NVMe program fails with -EOPNOTSUPP",
			     create == -EOPNOTSUPP);
	else
		report_check("one-stage NVMe WRITE session is created", session);
	if (mech_case != NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG && !session)
		goto done;

	/* Zero the window and read it back before any built write. */
	memset(window, 0, window_bytes);
	if (!mech_native_io(&ring, &target, NVME_XDEV_EXT_NVM_WRITE,
			    mech->window_slba, mech->window_nlb, window)) {
		report_check("window is zeroed", false);
		goto done;
	}
	memset(window, 0xa5, window_bytes);
	report_check("window reads back zero before the built write",
		     mech_native_io(&ring, &target, NVME_XDEV_EXT_NVM_READ,
				    mech->window_slba, mech->window_nlb,
				    window) &&
		     mech_zero(window, 0, window_bytes));
	if (failures)
		goto done;

	if (mech_case == NVME_XDEV_EXT_RUNTIME_MECH_LBA) {
		struct nvme_xdev_ext_runtime_command plain = {
			.fd = target.fd,
			.cmd_op = NVME_URING_CMD_IO,
			.buffer = (uintptr_t)io,
			.data_len = NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES,
			.nsid = (uint32_t)target.nsid,
			.nlb = 1,
			.xdev_ext_flags = NVME_URING_CMD_F_XDEV_EXT,
			.opcode = NVME_XDEV_EXT_NVM_READ,
		};

		/*
		 * The same cdw10..cdw12 and length that a built command passes
		 * with: a plain opted-in command decodes NLB 1 at initial
		 * admission and never reaches the device.
		 */
		admit_plain = run_expected(&ring,
					   "plain F_XDEV_EXT command with cdw12 0 fails initial admission with -EMSGSIZE",
					   &plain, -EMSGSIZE, NULL);
		mech_expect(&ring, &target, io, NVME_URING_CMD_F_XDEV_EXT_BUILD, 0,
			    -EINVAL, "F_XDEV_EXT_BUILD without F_XDEV_EXT fails with -EINVAL");
		mech_expect(&ring, &target, io, flags, mech->window_slba,
			    -EINVAL, "built command with a user cdw10 fails with -EINVAL");
		if (ring.backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
			goto done;
	}

	ret = mech_built_write(&ring, &target, io, flags, 0, &completion);
	res = ret ? ret : completion.res;
	report_check("built WRITE completes with the case's result",
		     !ret && res == expected);
	if (ret)
		goto done;

	memset(window, 0xa5, window_bytes);
	if (!mech_native_io(&ring, &target, NVME_XDEV_EXT_NVM_READ,
			    mech->window_slba, mech->window_nlb, window)) {
		report_check("window reads back after the built write", false);
		goto done;
	}
	if (mech_case != NVME_XDEV_EXT_RUNTIME_MECH_LBA) {
		report_check("rejected built write left the window unchanged",
			     mech_zero(window, 0, window_bytes));
		goto done;
	}

	/* Data only at the LBA the program chose from the request id. */
	if (nvme_xdev_ext_runtime_mech_s0_slba(completion.user_data,
					  mech->window_slba, mech->window_nlb,
					  io_nlb, &slba)) {
		report_check("program-chosen LBA is in the window", false);
		goto done;
	}
	offset = (slba - mech->window_slba) * target.lba_size;
	data_ok = !memcmp(window + offset, io, NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES);
	report_check("built WRITE data is at the program-chosen LBA", data_ok);
	report_check("the rest of the window is still zero",
		     mech_zero(window, 0, offset) &&
		     mech_zero(window, offset + NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES,
			       window_bytes));

	memset(window, 0, window_bytes);
	report_check("program-chosen LBAs are zeroed again",
		     mech_native_io(&ring, &target, NVME_XDEV_EXT_NVM_WRITE, slba,
				    io_nlb, window));
	memset(window, 0xa5, window_bytes);
	report_check("window reads back zero after the restore",
		     mech_native_io(&ring, &target, NVME_XDEV_EXT_NVM_READ,
				    mech->window_slba, mech->window_nlb,
				    window) &&
		     mech_zero(window, 0, window_bytes));

done:
	if (session) {
		stats.session_id = session_id;
		if (!mech_session_op(&ring, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&stats))
			printf("# mech stats rejects=%llu protocol_err=%llu state=%u last_err=%d\n",
			       (unsigned long long)stats.rejects,
			       (unsigned long long)stats.protocol_err,
			       stats.state, stats.last_err);
		report_check("session STOP succeeds",
			     !mech_session_op(&ring, XDEV_EXT_MECH_OP_STOP,
					      session_id));
	}
	printf("1..%u\n", checks);
	res_name = errno_name(res, res_buffer, sizeof(res_buffer));
	create_name = errno_name(create, create_buffer, sizeof(create_buffer));
	switch (mech_case) {
	case NVME_XDEV_EXT_RUNTIME_MECH_LBA:
		printf("XDEV_EXT_MECH_NVME_S0=%s case=%s %s=%d res=%s slba=%llu nlb=%u window=%llu+%llu restored=%d\n",
		       failures ? "FAIL" : "PASS", name,
		       nvme_xdev_ext_runtime_mech_case_key(mech_case), !failures,
		       res_name, (unsigned long long)slba, io_nlb,
		       (unsigned long long)mech->window_slba,
		       (unsigned long long)mech->window_nlb, !failures);
		printf("XDEV_EXT_MECH_NVME_ADMIT_ORDER=%s plain=-EMSGSIZE build=%s\n",
		       admit_plain && data_ok && !res ? "PASS" : "FAIL",
		       res_name);
		break;
	case NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG:
		printf("XDEV_EXT_MECH_NVME_S0=%s case=%s %s=%s create=%s dst_unchanged=%d\n",
		       failures ? "FAIL" : "PASS", name,
		       nvme_xdev_ext_runtime_mech_case_key(mech_case), res_name,
		       create_name, !failures);
		break;
	default:
		printf("XDEV_EXT_MECH_NVME_S0=%s case=%s %s=%d res=%s dst_unchanged=%d\n",
		       failures ? "FAIL" : "PASS", name,
		       nvme_xdev_ext_runtime_mech_case_key(mech_case), !failures,
		       res_name, !failures);
		break;
	}
	ret = failures ? 1 : 0;
	release = nvme_xdev_ext_runtime_may_release(ring.backing_ownership);
	raw_ring_destroy(&ring);
	ring_ready = false;
out:
	if (ring_ready) {
		release = nvme_xdev_ext_runtime_may_release(ring.backing_ownership);
		raw_ring_destroy(&ring);
		ret = 1;
	}
	if (release) {
		free(io);
		free(window);
		free(umem);
	} else {
		fprintf(stderr, "retaining command backing until process exit: ");
		fprintf(stderr, "ownership is ambiguous\n");
	}
	close_gated_namespace(&target);
	return ret ? 1 : 0;
}

static int parse_u64(const char *text, uint64_t *value)
{
	unsigned long long parsed;
	char *end;

	if (!text[0] || text[0] < '0' || text[0] > '9')
		return -EINVAL;
	errno = 0;
	parsed = strtoull(text, &end, 10);
	if (errno || *end)
		return -EINVAL;
	*value = parsed;
	return 0;
}

static int parse_arguments(int argc, char **argv, const char **device,
			   bool *allow_write, struct mech_options *mech)
{
	int index;

	*device = NULL;
	*allow_write = false;
	for (index = 1; index < argc; index++) {
		if (!strcmp(argv[index], "--device")) {
			if (*device || index + 1 == argc)
				return -EINVAL;
			*device = argv[++index];
		} else if (!strcmp(argv[index], "--allow-file-backed-write")) {
			if (*allow_write)
				return -EINVAL;
			*allow_write = true;
		} else if (!strcmp(argv[index], "--mech-s0")) {
			if (mech->mech_case || index + 1 == argc)
				return -EINVAL;
			mech->mech_case =
				nvme_xdev_ext_runtime_mech_case_parse(argv[++index]);
			if (!mech->mech_case)
				return -EINVAL;
		} else if (!strcmp(argv[index], "--window-slba")) {
			if (mech->window_slba_set || index + 1 == argc ||
			    parse_u64(argv[++index], &mech->window_slba))
				return -EINVAL;
			mech->window_slba_set = true;
		} else if (!strcmp(argv[index], "--window-nlb")) {
			if (mech->window_nlb_set || index + 1 == argc ||
			    parse_u64(argv[++index], &mech->window_nlb))
				return -EINVAL;
			mech->window_nlb_set = true;
		} else {
			return -EINVAL;
		}
	}
	if (*allow_write && !*device)
		return -EINVAL;
	/* The mechanism cases write: every option is explicit. */
	if (mech->mech_case && (!*device || !*allow_write ||
				!mech->window_slba_set ||
				!mech->window_nlb_set))
		return -EINVAL;
	if (!mech->mech_case && (mech->window_slba_set || mech->window_nlb_set))
		return -EINVAL;
	return 0;
}

int main(int argc, char **argv)
{
	struct nvme_xdev_ext_runtime_command native_command, opted_command;
	struct command_completion native_completion, opted_completion;
	struct nvme_xdev_ext_runtime_baseline baseline = {};
	enum nvme_xdev_ext_runtime_safety_result safety_result;
	enum nvme_xdev_ext_runtime_media_state media_state =
		NVME_XDEV_EXT_RUNTIME_MEDIA_ORIGINAL;
	struct gated_namespace target = {};
	struct observed_device before_write;
	struct mech_options mech = {};
	void *buffers[READ_BUFFER_COUNT] = {};
	uint64_t capacity_lbas;
	const char *device;
	struct raw_ring ring;
	bool allow_write;
	bool release_backing = true;
	bool ring_ready = false;
	uint32_t lba_size;
	uint64_t slba;
	struct stat fd_stat;
	struct iovec vector;
	int nsid;
	int block_fd;
	int fd;
	int ret;
	unsigned int index;

	ret = parse_arguments(argc, argv, &device, &allow_write, &mech);
	if (ret) {
		fprintf(stderr, "usage: %s [--device /dev/ng0n1]",
			argv[0]);
		fprintf(stderr, " [--allow-file-backed-write]\n");
		fprintf(stderr, "       %s --device /dev/ngCnN", argv[0]);
		fprintf(stderr, " --allow-file-backed-write");
		fprintf(stderr, " --mech-s0 lba|window|reserved|no-prog");
		fprintf(stderr, " --window-slba SLBA --window-nlb NLB\n");
		return 1;
	}
	if (mech.mech_case)
		return run_mech_s0(device, &mech);
	if (!device) {
		printf("SKIP: runtime access requires explicit --device /dev/ng0n1\n");
		return KSFT_SKIP;
	}
	/* Reject arbitrary paths before performing any lookup on the path. */
	if (strcmp(device, NVME_XDEV_EXT_RUNTIME_EXPECTED_DEVICE)) {
		fprintf(stderr, "REFUSE: device must be exactly %s\n",
			NVME_XDEV_EXT_RUNTIME_EXPECTED_DEVICE);
		return 1;
	}

	target.device = device;
	target.serial = NVME_XDEV_EXT_RUNTIME_EXPECTED_SERIAL;
	target.allow_write = allow_write;
	if (runtime_paths_init(&target.paths, "ng0n1", "nvme0", "nvme0n1") ||
	    open_gated_namespace(&target))
		return 1;
	fd = target.fd;
	block_fd = target.block_fd;
	nsid = target.nsid;
	lba_size = target.lba_size;
	capacity_lbas = target.capacity_lbas;
	if (capacity_lbas <= TEST_SLBA) {
		fprintf(stderr, "REFUSE: namespace is too small for test LBA\n");
		close_gated_namespace(&target);
		return 1;
	}
	slba = TEST_SLBA;

	for (index = 0; index < READ_BUFFER_COUNT; index++) {
		ret = posix_memalign(&buffers[index], 4096, 2U * lba_size);
		if (ret) {
			fprintf(stderr, "posix_memalign: %s\n", strerror(ret));
			goto out;
		}
		memset(buffers[index], 0, 2U * lba_size);
	}
	ret = raw_ring_init(&ring);
	if (ret) {
		fprintf(stderr, "io_uring SQE128/CQE32 setup failed: %s\n",
			strerror(-ret));
		goto out;
	}
	ring_ready = true;
	ret = raw_ring_register_buffers(&ring, buffers, READ_BUFFER_COUNT,
					2U * lba_size);
	if (ret) {
		fprintf(stderr, "io_uring buffer registration failed: %s\n",
			strerror(-ret));
		goto out;
	}

	printf("TAP version 13\n");
	printf("# device=%s model=%s serial=%s nsid=%d lba=%u\n", device,
	       target.after_open.model, target.after_open.serial, nsid,
	       lba_size);
	printf("# capacity_lbas=%llu mode=%s\n",
	       (unsigned long long)capacity_lbas,
	       allow_write ? "file-backed-write" : "read-only");

	native_command = read_command(fd, nsid, slba, lba_size, buffers[0], 0);
	baseline.native_read_ok =
		run_expected(&ring, "non-opt-in READ succeeds", &native_command,
			     0, &native_completion);
	if (ring.backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		goto tests_done;
	baseline.native_cqe_ok = native_completion.flags == 0 &&
		native_completion.extra2 == 0;
	report_check("non-opt-in READ has native CQE flags/extra2",
		     baseline.native_cqe_ok);

	opted_command = read_command(fd, nsid, slba, lba_size, buffers[1],
				     NVME_URING_CMD_F_XDEV_EXT);
	baseline.opted_read_ok =
		run_expected(&ring, "opted-in READ succeeds", &opted_command, 0,
			     &opted_completion);
	if (ring.backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		goto tests_done;
	baseline.bytes_match = !memcmp(buffers[0], buffers[1], lba_size);
	report_check("opted-in and native READ return identical bytes",
		     baseline.bytes_match);
	baseline.cqe_match = native_completion.res == opted_completion.res &&
		native_completion.flags == opted_completion.flags &&
		native_completion.extra1 == opted_completion.extra1 &&
		native_completion.extra2 == opted_completion.extra2;
	report_check("opted-in READ preserves native CQE semantics",
		     baseline.cqe_match);
	run_fixed_buffer_cases(&ring, &opted_command, buffers, lba_size);
	if (ring.backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		goto tests_done;

	vector.iov_base = buffers[1];
	vector.iov_len = lba_size;
	run_preflight_cases(&ring, &opted_command, capacity_lbas, &vector);
	if (ring.backing_ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		goto tests_done;
	baseline.preflight_ok = failures == 0;

	if (allow_write) {
		collect_observed_device(&target.paths, device, allow_write,
					&before_write);
		safety_result = observed_safety_result(&target, &before_write);
		baseline.block_guard_ok = block_guard_fd_matches(&target.paths,
								  block_fd);
		baseline.safety_rechecked = safety_result == NVME_XDEV_EXT_RUNTIME_SAFE &&
			!fstat(fd, &fd_stat) && S_ISCHR(fd_stat.st_mode) &&
			fd_stat.st_rdev == target.before_open.character_rdev &&
			fd_stat.st_rdev == before_write.character_rdev;
		report_check("block sibling remains exclusively held",
			     baseline.block_guard_ok);
		report_check("write safety gate remains valid",
			     baseline.safety_rechecked);
	}

	if (allow_write && nvme_xdev_ext_runtime_write_allowed(&baseline)) {
		for (index = 0; index < lba_size; index++)
			((unsigned char *)buffers[2])[index] =
				(unsigned char)(index * 131U + 0x5aU);
		if (run_write_round_trip(&ring, &opted_command, buffers[0],
					 buffers[2], buffers[3], lba_size,
					 &media_state) &&
		    nvme_xdev_ext_runtime_media_reusable(media_state))
			run_fixed_vector_write_round_trip(&ring, &opted_command,
						  buffers, lba_size,
						  &media_state);
	} else if (allow_write) {
		printf("ok %u - write round trip # SKIP", ++checks);
		printf(" baseline or preflight was not trustworthy\n");
	} else {
		printf("ok %u - write round trip # SKIP", ++checks);
		printf(" requires --allow-file-backed-write\n");
	}

tests_done:
	if (media_state != NVME_XDEV_EXT_RUNTIME_MEDIA_ORIGINAL) {
		bool reusable = nvme_xdev_ext_runtime_media_reusable(media_state);

		report_check("file-backed image is restored and reusable",
			     reusable);
		if (!reusable)
			fprintf(stderr, "FATAL: file-backed NVMe image may be ");
		if (!reusable)
			fprintf(stderr, "modified; discard/recreate before reuse\n");
	}
	printf("1..%u\n", checks);
	release_backing = nvme_xdev_ext_runtime_may_release(ring.backing_ownership);
	raw_ring_destroy(&ring);
	ring_ready = false;
	ret = failures ? 1 : 0;
out:
	if (ring_ready) {
		release_backing =
			nvme_xdev_ext_runtime_may_release(ring.backing_ownership);
		raw_ring_destroy(&ring);
	}
	if (release_backing) {
		for (index = 0; index < READ_BUFFER_COUNT; index++)
			free(buffers[index]);
	} else {
		fprintf(stderr, "retaining command backing until process exit: ");
		fprintf(stderr, "ownership is ambiguous or restore failed\n");
	}
	close_gated_namespace(&target);
	return ret ? 1 : 0;
}
