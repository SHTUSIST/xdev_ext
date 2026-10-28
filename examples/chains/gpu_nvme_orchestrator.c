// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe <-> GPU staged host-UMEM pipeline.
 *
 * NVMe uses native io_uring URING_CMD, SQE128/CQE32, one registered host
 * region, and fixed IO_VEC commands.  The NVIDIA ioctl synchronously moves
 * data between that same region and a CUDA allocation and requires the Copy
 * Engine in the kernel implementation.  This is a staged host-memory path,
 * not a claim of direct NVMe-to-GPU DMA.
 *
 * The default mode only reads storage.  Every mode that can issue NVMe WRITE
 * requires --allow-write, an explicit local LBA window, a retained matching
 * whole-namespace block fd, and O_RDWR on the namespace character fd.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <linux/fs.h>

#include "../include/uapi/linux/io_uring.h"
#include "../include/uapi/linux/nvme_ioctl.h"
#include "gpu_nvme_orchestrator_core.h"
#include "include/xdev_ext_gpu_identity.h"

#ifdef XDEV_EXT_GPU_NVME_WITH_CUDA
#include <cuda.h>
#endif

#define GNO_SQE_SIZE 128U
#define GNO_CQE_SIZE 32U
#define GNO_DEFAULT_DEPTH 16U
#define GNO_DEFAULT_BYTES UINT64_C(8192)
#define GNO_DEFAULT_VECTOR_BYTES UINT64_C(4096)
#define GNO_DEFAULT_TIMEOUT_MS UINT64_C(30000)
#define GNO_MAX_TRANSIENT_RETRIES 64U
#define GNO_NVME_IDENTIFY 0x06U

_Static_assert(sizeof(struct io_uring_sqe) == 64,
	       "SQE128 requires a 64-byte base SQE");
_Static_assert(sizeof(struct io_uring_cqe) == 16,
	       "CQE32 requires a 16-byte base CQE");
_Static_assert(offsetof(struct io_uring_sqe, cmd) == 48,
	       "unexpected io_uring command offset");
_Static_assert(sizeof(struct nvme_uring_cmd) <=
	       GNO_SQE_SIZE - offsetof(struct io_uring_sqe, cmd),
	       "NVMe command does not fit SQE128");

struct gno_raw_ring {
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
	struct io_uring_params params;
	uint32_t private_tail;
	uint32_t prepared;
	bool initialized;
	bool buffer_registered;
	bool iopoll;
};

struct gno_cli {
	const char *nvme_device;
	const char *block_device;
	const char *gpu_device;
	enum gno_mode mode;
	uint64_t window_first;
	uint64_t window_lbas;
	uint64_t request_index;
	uint64_t transfer_bytes;
	uint64_t vector_bytes;
	uint64_t user_max_io_bytes;
	uint64_t timeout_ms;
	uint32_t count;
	int gpu_index;
	unsigned int fill_byte;
	bool window_first_set;
	bool window_lbas_set;
	bool fill_byte_set;
	bool allow_write;
	bool iopoll;
};

struct gno_namespace_epoch {
	uint32_t nsid;
	dev_t char_rdev;
	dev_t block_rdev;
	uint64_t diskseq;
};

struct gno_runtime {
	struct gno_cli cli;
	struct gno_raw_ring ring;
	struct gno_namespace_epoch frozen_epoch;
	struct nxp_namespace ns;
	char char_sysfs[PATH_MAX];
	char block_sysfs[PATH_MAX];
	char controller_sysfs[PATH_MAX];
	int nvme_fd;
	int block_fd;
	int gpu_fd;
	void *umem;
	size_t umem_size;
	bool umem_locked;
	uint64_t p2p_handle;
	uint64_t gpu_base;
	uint64_t gpu_bytes;
	uint64_t timeout_ms;
	uint64_t gpu_batch_syscalls;
	uint64_t gpu_items_completed;
	uint32_t prepared_count;
	char gpu_pci_bdf[NXP_PCI_BDF_MAX + 1];
	bool cleanup_attempted;
	bool backing_retained;
#ifdef XDEV_EXT_GPU_NVME_WITH_CUDA
	CUdevice cuda_device;
	CUcontext cuda_context;
	CUdeviceptr cuda_allocation;
	bool cuda_primary_retained;
#endif
};

static int parse_u64(const char *text, uint64_t *value)
{
	unsigned long long parsed;
	char *end;

	if (!text || !value || text[0] < '0' || text[0] > '9')
		return -EINVAL;
	errno = 0;
	parsed = strtoull(text, &end, 0);
	if (errno == ERANGE)
		return -ERANGE;
	if (!*text || *end)
		return -EINVAL;
	*value = (uint64_t)parsed;
	return 0;
}

static int parse_u32(const char *text, uint32_t *value)
{
	uint64_t parsed;
	int ret = parse_u64(text, &parsed);

	if (ret)
		return ret;
	if (parsed > UINT32_MAX)
		return -ERANGE;
	*value = (uint32_t)parsed;
	return 0;
}

static int path_join(char *out, size_t out_size, const char *left,
		     const char *right)
{
	int written;

	if (!out || !out_size || !left || !right)
		return -EINVAL;
	written = snprintf(out, out_size, "%s/%s", left, right);
	return written < 0 || (size_t)written >= out_size ? -ENAMETOOLONG : 0;
}

static int read_text_file(const char *path, char *buffer, size_t size)
{
	ssize_t bytes;
	size_t first = 0;
	int fd;

	if (!path || !buffer || size < 2)
		return -EINVAL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	bytes = read(fd, buffer, size - 1);
	if (bytes < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}
	if (close(fd))
		return -errno;
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
	char text[64] = { 0 };
	int ret = read_text_file(path, text, sizeof(text));

	return ret ? ret : parse_u64(text, value);
}

static uint16_t load_le16(const unsigned char *data)
{
	return (uint16_t)data[0] | (uint16_t)data[1] << 8;
}

static uint64_t load_le64(const unsigned char *data)
{
	uint64_t value = 0;

	for (unsigned int i = 0; i < 8; i++)
		value |= (uint64_t)data[i] << (i * 8);
	return value;
}

static int identify_namespace(int fd, uint32_t nsid, uint32_t *lba_size,
			      uint64_t *capacity_lbas,
			      uint16_t *metadata_size, uint8_t *pi_type)
{
	struct nvme_admin_cmd command = { 0 };
	unsigned char *identify = NULL;
	unsigned int lbaf;
	int ret;

	if (posix_memalign((void **)&identify, 4096, 4096))
		return -ENOMEM;
	memset(identify, 0, 4096);
	command.opcode = GNO_NVME_IDENTIFY;
	command.nsid = nsid;
	command.addr = (uint64_t)(uintptr_t)identify;
	command.data_len = 4096;
	command.cdw10 = 0;
	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &command);
	if (ret) {
		ret = ret < 0 ? -errno : -EIO;
		goto out;
	}
	lbaf = (identify[26] & 0x0f) | ((identify[26] & 0x60) >> 1);
	if (lbaf >= 64 || identify[128 + lbaf * 4 + 2] >= 32) {
		ret = -EOPNOTSUPP;
		goto out;
	}
	*capacity_lbas = load_le64(identify);
	*metadata_size = load_le16(identify + 128 + lbaf * 4);
	*lba_size = UINT32_C(1) << identify[128 + lbaf * 4 + 2];
	*pi_type = identify[29] & 0x7;
	ret = 0;
out:
	free(identify);
	return ret;
}

static uint64_t encoded_rdev(dev_t device)
{
	return (uint64_t)major(device) << 32 | minor(device);
}

static int resolve_sysfs(struct gno_runtime *runtime)
{
	struct stat char_stat, block_stat;
	char link[PATH_MAX];
	char *slash;

	if (fstat(runtime->nvme_fd, &char_stat) ||
	    fstat(runtime->block_fd, &block_stat))
		return -errno;
	if (!S_ISCHR(char_stat.st_mode))
		return -ENOTTY;
	if (!S_ISBLK(block_stat.st_mode))
		return -ENOTBLK;
	if (snprintf(link, sizeof(link), "/sys/dev/char/%u:%u",
		     major(char_stat.st_rdev), minor(char_stat.st_rdev)) >=
	    (int)sizeof(link) || !realpath(link, runtime->char_sysfs))
		return errno ? -errno : -ENODEV;
	if (snprintf(link, sizeof(link), "/sys/dev/block/%u:%u",
		     major(block_stat.st_rdev), minor(block_stat.st_rdev)) >=
	    (int)sizeof(link) || !realpath(link, runtime->block_sysfs))
		return errno ? -errno : -ENODEV;
	if (snprintf(runtime->controller_sysfs,
		     sizeof(runtime->controller_sysfs), "%s",
		     runtime->char_sysfs) >=
	    (int)sizeof(runtime->controller_sysfs))
		return -ENAMETOOLONG;
	slash = strrchr(runtime->controller_sysfs, '/');
	if (!slash || slash == runtime->controller_sysfs)
		return -EXDEV;
	*slash = '\0';
	if (!nxp_paths_share_parent(runtime->char_sysfs,
				    runtime->block_sysfs) ||
	    strncmp(runtime->block_sysfs, runtime->controller_sysfs,
		    strlen(runtime->controller_sysfs)) ||
	    runtime->block_sysfs[strlen(runtime->controller_sysfs)] != '/')
		return -EXDEV;
	return 0;
}

static int collect_namespace(struct gno_runtime *runtime)
{
	struct nxp_namespace *ns = &runtime->ns;
	struct stat char_stat, block_stat;
	uint64_t capacity_bytes, diskseq, sysfs_nsid, csi;
	uint64_t identify_capacity = 0;
	uint32_t identify_lba = 0, block_lba;
	char path[PATH_MAX];
	char stable_id[NXP_STABLE_ID_MAX + 2] = { 0 };
	char serial[NXP_CONTROLLER_SERIAL_MAX + 2] = { 0 };
	char bdf[NXP_PCI_BDF_MAX + 2] = { 0 };
	char transport[32] = { 0 };
	char pci_link[PATH_MAX], pci_path[PATH_MAX];
	int ioctl_nsid;
	int ret;

	memset(ns, 0, sizeof(*ns));
	if (fstat(runtime->nvme_fd, &char_stat) ||
	    fstat(runtime->block_fd, &block_stat))
		return -errno;
	ns->char_is_namespace = S_ISCHR(char_stat.st_mode);
	ns->block_is_whole_namespace = S_ISBLK(block_stat.st_mode);
	ns->same_namespace = ns->char_is_namespace &&
		ns->block_is_whole_namespace;
	ns->char_rdev = encoded_rdev(char_stat.st_rdev);
	ns->block_rdev = encoded_rdev(block_stat.st_rdev);
	ioctl_nsid = ioctl(runtime->nvme_fd, NVME_IOCTL_ID);
	if (ioctl_nsid <= 0)
		return ioctl_nsid < 0 ? -errno : -ENODEV;
	ns->nsid = (uint32_t)ioctl_nsid;
	if (ioctl(runtime->block_fd, BLKSSZGET, &block_lba) < 0)
		return -errno;
	if (!block_lba)
		return -EUCLEAN;
	if (ioctl(runtime->block_fd, BLKGETSIZE64, &capacity_bytes) < 0)
		return -errno;
	if (capacity_bytes % block_lba)
		return -EUCLEAN;
	ns->lba_size = block_lba;
	ns->capacity_lbas = capacity_bytes / block_lba;
	if (ioctl(runtime->block_fd, BLKGETDISKSEQ, &diskseq) < 0)
		return -errno;
	if (!diskseq)
		return -ENODATA;
	ns->diskseq = diskseq;

	ret = path_join(path, sizeof(path), runtime->block_sysfs, "nsid");
	if (ret)
		return ret;
	ret = read_u64_file(path, &sysfs_nsid);
	if (ret)
		return ret;
	if (sysfs_nsid != ns->nsid)
		return -EXDEV;
	ret = path_join(path, sizeof(path), runtime->block_sysfs, "csi");
	if (ret)
		return ret;
	ret = read_u64_file(path, &csi);
	if (ret)
		return ret;
	if (csi != 0)
		return -EOPNOTSUPP;
	ret = path_join(path, sizeof(path), runtime->block_sysfs, "wwid");
	if (ret)
		return ret;
	ret = read_text_file(path, stable_id, sizeof(stable_id));
	if (ret)
		return ret;
	ns->stable_id_len = (uint8_t)strlen(stable_id);
	if (!ns->stable_id_len || ns->stable_id_len > NXP_STABLE_ID_MAX)
		return -ENODATA;
	memcpy(ns->stable_id, stable_id, ns->stable_id_len);
	ns->stable_id_present = true;

	ret = path_join(path, sizeof(path), runtime->controller_sysfs,
			"serial");
	if (ret)
		return ret;
	ret = read_text_file(path, serial, sizeof(serial));
	if (ret)
		return ret;
	ns->controller_serial_len = (uint8_t)strlen(serial);
	if (!ns->controller_serial_len ||
	    ns->controller_serial_len > NXP_CONTROLLER_SERIAL_MAX)
		return -ENODATA;
	memcpy(ns->controller_serial, serial, ns->controller_serial_len);
	ns->controller_serial_present = true;

	ret = path_join(path, sizeof(path), runtime->controller_sysfs,
			"transport");
	if (ret)
		return ret;
	ret = read_text_file(path, transport, sizeof(transport));
	if (ret)
		return ret;
	if (strcmp(transport, "pcie"))
		return -EOPNOTSUPP;
	ret = path_join(path, sizeof(path), runtime->controller_sysfs,
			"address");
	if (ret)
		return ret;
	ret = read_text_file(path, bdf, sizeof(bdf));
	if (ret)
		return ret;
	ns->pci_bdf_len = (uint8_t)strlen(bdf);
	if (!nxp_is_pci_bdf(bdf) || ns->pci_bdf_len > NXP_PCI_BDF_MAX)
		return -ENODATA;
	if (snprintf(pci_link, sizeof(pci_link), "/sys/bus/pci/devices/%s",
		     bdf) >= (int)sizeof(pci_link) ||
	    !realpath(pci_link, pci_path))
		return errno ? -errno : -ENODEV;
	if (strncmp(runtime->controller_sysfs, pci_path, strlen(pci_path)) ||
	    runtime->controller_sysfs[strlen(pci_path)] != '/')
		return -EXDEV;
	memcpy(ns->pci_bdf, bdf, ns->pci_bdf_len);
	ns->pci_bdf_present = true;

	ret = identify_namespace(runtime->nvme_fd, ns->nsid, &identify_lba,
				 &identify_capacity, &ns->metadata_size,
				 &ns->pi_type);
	if (ret)
		return ret;
	if (identify_lba != ns->lba_size ||
	    identify_capacity != ns->capacity_lbas)
		return -EUCLEAN;
	ret = nxp_namespace_validate(ns);
	if (ret)
		return ret;
	runtime->frozen_epoch = (struct gno_namespace_epoch) {
		.nsid = ns->nsid,
		.char_rdev = char_stat.st_rdev,
		.block_rdev = block_stat.st_rdev,
		.diskseq = diskseq,
	};
	return 0;
}

static int revalidate_namespace(struct gno_runtime *runtime)
{
	struct stat char_stat, block_stat;
	uint64_t diskseq;
	int nsid;

	if (fstat(runtime->nvme_fd, &char_stat) ||
	    fstat(runtime->block_fd, &block_stat))
		return -errno;
	if (!S_ISCHR(char_stat.st_mode) || !S_ISBLK(block_stat.st_mode))
		return -ESTALE;
	nsid = ioctl(runtime->nvme_fd, NVME_IOCTL_ID);
	if (nsid <= 0)
		return nsid < 0 ? -errno : -ENODEV;
	if (ioctl(runtime->block_fd, BLKGETDISKSEQ, &diskseq) < 0)
		return -errno;
	if ((uint32_t)nsid != runtime->frozen_epoch.nsid ||
	    char_stat.st_rdev != runtime->frozen_epoch.char_rdev ||
	    block_stat.st_rdev != runtime->frozen_epoch.block_rdev ||
	    diskseq != runtime->frozen_epoch.diskseq)
		return -ESTALE;
	return 0;
}

static int effective_max_io_bytes(struct gno_runtime *runtime,
				  uint64_t *max_bytes)
{
	char path[PATH_MAX];
	uint64_t max_kib;
	int ret;

	ret = path_join(path, sizeof(path), runtime->block_sysfs,
			"queue/max_hw_sectors_kb");
	if (ret)
		return ret;
	ret = read_u64_file(path, &max_kib);
	if (ret)
		return ret;
	if (!max_kib || max_kib > UINT64_MAX / 1024)
		return -EOVERFLOW;
	*max_bytes = max_kib * 1024;
	/* This is the effective Linux hardware cap derived from the controller
	 * limit (including MDTS), possibly reduced by the block layer. */
	if (runtime->cli.user_max_io_bytes) {
		if (runtime->cli.user_max_io_bytes > *max_bytes)
			return -ERANGE;
		*max_bytes = runtime->cli.user_max_io_bytes;
	}
	if (*max_bytes < runtime->ns.lba_size ||
	    *max_bytes % runtime->ns.lba_size)
		return -EUCLEAN;
	return 0;
}

static int prove_iopoll(struct gno_runtime *runtime)
{
	char path[PATH_MAX];
	uint64_t poll_queues, io_poll;
	int ret;

	ret = read_u64_file("/sys/module/nvme/parameters/poll_queues",
			    &poll_queues);
	if (ret || !poll_queues)
		return -EOPNOTSUPP;
	ret = path_join(path, sizeof(path), runtime->block_sysfs,
			"queue/io_poll");
	if (ret || read_u64_file(path, &io_poll) || !io_poll)
		return -EOPNOTSUPP;
	return 0;
}

static struct io_uring_sqe *ring_sqe(struct gno_raw_ring *ring,
				     uint32_t tail)
{
	uint32_t index = tail & *ring->sq_mask;

	return (struct io_uring_sqe *)((unsigned char *)ring->sqes +
		(size_t)index * GNO_SQE_SIZE);
}

static struct io_uring_cqe *ring_cqe(struct gno_raw_ring *ring,
				     uint32_t head)
{
	uint32_t index = head & *ring->cq_mask;

	return (struct io_uring_cqe *)((unsigned char *)ring->cq_ring +
		ring->params.cq_off.cqes + (size_t)index * GNO_CQE_SIZE);
}

static void raw_ring_destroy(struct gno_raw_ring *ring)
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

static int raw_ring_init(struct gno_raw_ring *ring, uint32_t entries,
			 bool iopoll)
{
	struct io_uring_params *params;
	size_t single_size;

	memset(ring, 0, sizeof(*ring));
	ring->fd = -1;
	params = &ring->params;
	params->flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	if (iopoll)
		params->flags |= IORING_SETUP_IOPOLL;
	ring->fd = syscall(SYS_io_uring_setup, entries, params);
	if (ring->fd < 0)
		return -errno;
	if (!(params->flags & IORING_SETUP_SQE128) ||
	    !(params->flags & IORING_SETUP_CQE32) ||
	    (iopoll && !(params->flags & IORING_SETUP_IOPOLL)))
		goto protocol_error;
	ring->sq_ring_size = params->sq_off.array +
		params->sq_entries * sizeof(uint32_t);
	ring->cq_ring_size = params->cq_off.cqes +
		params->cq_entries * GNO_CQE_SIZE;
	ring->sqes_size = params->sq_entries * GNO_SQE_SIZE;
	if (params->features & IORING_FEAT_SINGLE_MMAP) {
		single_size = ring->sq_ring_size > ring->cq_ring_size ?
			ring->sq_ring_size : ring->cq_ring_size;
		ring->sq_ring_size = single_size;
		ring->cq_ring_size = single_size;
	}
	ring->sq_ring = mmap(NULL, ring->sq_ring_size,
			     PROT_READ | PROT_WRITE, MAP_SHARED, ring->fd,
			     IORING_OFF_SQ_RING);
	if (ring->sq_ring == MAP_FAILED)
		goto map_error;
	if (params->features & IORING_FEAT_SINGLE_MMAP) {
		ring->cq_ring = ring->sq_ring;
	} else {
		ring->cq_ring = mmap(NULL, ring->cq_ring_size,
				     PROT_READ | PROT_WRITE, MAP_SHARED,
				     ring->fd, IORING_OFF_CQ_RING);
		if (ring->cq_ring == MAP_FAILED)
			goto map_error;
	}
	ring->sqes = mmap(NULL, ring->sqes_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, ring->fd, IORING_OFF_SQES);
	if (ring->sqes == MAP_FAILED)
		goto map_error;
	ring->sq_head = (uint32_t *)((unsigned char *)ring->sq_ring +
		params->sq_off.head);
	ring->sq_tail = (uint32_t *)((unsigned char *)ring->sq_ring +
		params->sq_off.tail);
	ring->sq_mask = (uint32_t *)((unsigned char *)ring->sq_ring +
		params->sq_off.ring_mask);
	ring->sq_entries = (uint32_t *)((unsigned char *)ring->sq_ring +
		params->sq_off.ring_entries);
	ring->sq_array = (uint32_t *)((unsigned char *)ring->sq_ring +
		params->sq_off.array);
	ring->cq_head = (uint32_t *)((unsigned char *)ring->cq_ring +
		params->cq_off.head);
	ring->cq_tail = (uint32_t *)((unsigned char *)ring->cq_ring +
		params->cq_off.tail);
	ring->cq_mask = (uint32_t *)((unsigned char *)ring->cq_ring +
		params->cq_off.ring_mask);
	ring->cq_entries = (uint32_t *)((unsigned char *)ring->cq_ring +
		params->cq_off.ring_entries);
	if (!*ring->sq_entries || !*ring->cq_entries)
		goto protocol_error;
	ring->private_tail = __atomic_load_n(ring->sq_tail, __ATOMIC_ACQUIRE);
	ring->iopoll = iopoll;
	ring->initialized = true;
	return 0;

map_error: {
	int ret = -errno;

	raw_ring_destroy(ring);
	return ret;
}
protocol_error:
	raw_ring_destroy(ring);
	return -EPROTO;
}

static int raw_ring_register_umem(struct gno_raw_ring *ring, void *umem,
				  size_t size)
{
	struct iovec iovec = { .iov_base = umem, .iov_len = size };
	int ret = syscall(SYS_io_uring_register, ring->fd,
			  IORING_REGISTER_BUFFERS, &iovec, 1);

	if (ret < 0)
		return -errno;
	ring->buffer_registered = true;
	return 0;
}

static int raw_ring_unregister_umem(struct gno_raw_ring *ring)
{
	int ret;

	if (!ring->buffer_registered)
		return 0;
	ret = syscall(SYS_io_uring_register, ring->fd,
		      IORING_UNREGISTER_BUFFERS, NULL, 0);
	if (ret < 0)
		return -errno;
	ring->buffer_registered = false;
	return 0;
}

static int64_t monotonic_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int wait_for_cqe(struct gno_runtime *runtime)
{
	struct gno_raw_ring *ring = &runtime->ring;
	int64_t start = monotonic_ms();
	int64_t deadline;

	if (start < 0 || runtime->timeout_ms > (uint64_t)(INT64_MAX - start))
		return -EOVERFLOW;
	deadline = start + (int64_t)runtime->timeout_ms;
	for (;;) {
		int64_t now;
		int ret;

		if (__atomic_load_n(ring->cq_head, __ATOMIC_RELAXED) !=
		    __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE))
			return 0;
		now = monotonic_ms();
		if (now < 0)
			return -EIO;
		if (now >= deadline)
			return -ETIMEDOUT;
		if (ring->iopoll) {
			ret = syscall(SYS_io_uring_enter, ring->fd, 0, 0,
				      IORING_ENTER_GETEVENTS, NULL, 0);
			if (ret < 0 && errno != EINTR && errno != EAGAIN &&
			    errno != EBUSY)
				return -errno;
			sched_yield();
		} else {
			struct pollfd poll_fd = { .fd = ring->fd, .events = POLLIN };
			int timeout = deadline - now > 100 ? 100 :
				(int)(deadline - now);

			ret = poll(&poll_fd, 1, timeout);
			if (ret < 0 && errno != EINTR)
				return -errno;
			if (ret > 0 && (poll_fd.revents &
					(POLLERR | POLLHUP | POLLNVAL)))
				return -EIO;
			ret = syscall(SYS_io_uring_enter, ring->fd, 0, 0, 0,
				      NULL, 0);
			if (ret < 0 && errno != EINTR)
				return -errno;
		}
	}
}

static int backend_prepare_nvme(void *opaque, uint32_t slot_index,
				const struct nxp_nvme_io_plan *plan,
				const struct iovec *vector,
				uint32_t vector_count, uint64_t token)
{
	struct gno_runtime *runtime = opaque;
	struct gno_raw_ring *ring = &runtime->ring;
	struct nvme_uring_cmd *command;
	struct io_uring_sqe *sqe;
	uint32_t head, tail;

	(void)slot_index;
	if (!plan || !vector || !vector_count || !token ||
	    !ring->buffer_registered)
		return -EINVAL;
	head = __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE);
	tail = ring->private_tail + ring->prepared;
	if (tail - head >= *ring->sq_entries)
		return -EBUSY;
	sqe = ring_sqe(ring, tail);
	memset(sqe, 0, GNO_SQE_SIZE);
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = runtime->nvme_fd;
	sqe->cmd_op = NVME_URING_CMD_IO_VEC;
	sqe->user_data = token;
	sqe->uring_cmd_flags = IORING_URING_CMD_FIXED;
	sqe->buf_index = 0;
	command = (struct nvme_uring_cmd *)sqe->cmd;
	command->opcode = plan->opcode;
	command->nsid = runtime->ns.nsid;
	command->addr = (uint64_t)(uintptr_t)vector;
	command->data_len = vector_count;
	command->cdw10 = plan->cdw10;
	command->cdw11 = plan->cdw11;
	command->cdw12 = plan->cdw12;
	command->rsvd2 = NVME_URING_CMD_F_XDEV_EXT;
	ring->sq_array[tail & *ring->sq_mask] = tail & *ring->sq_mask;
	ring->prepared++;
	runtime->prepared_count++;
	return 0;
}

static int backend_abort_private(void *opaque)
{
	struct gno_runtime *runtime = opaque;
	struct gno_raw_ring *ring = &runtime->ring;

	if (__atomic_load_n(ring->sq_tail, __ATOMIC_ACQUIRE) !=
	    ring->private_tail)
		return -EBUSY;
	ring->prepared = 0;
	runtime->prepared_count = 0;
	return 0;
}

static int backend_submit_nvme(void *opaque, uint32_t wanted,
			       uint32_t *accepted_out, bool *ambiguous)
{
	struct gno_runtime *runtime = opaque;
	struct gno_raw_ring *ring = &runtime->ring;
	uint32_t head_start, accepted = 0;
	unsigned int retries = GNO_MAX_TRANSIENT_RETRIES;
	int64_t start, deadline;
	int first_error = 0;
	int ret;

	*accepted_out = 0;
	*ambiguous = false;
	if (!wanted || wanted != ring->prepared ||
	    wanted != runtime->prepared_count)
		return -EINVAL;
	ret = revalidate_namespace(runtime);
	if (ret) {
		(void)backend_abort_private(runtime);
		return ret;
	}
	head_start = __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE);
	__atomic_store_n(ring->sq_tail, ring->private_tail + wanted,
			 __ATOMIC_RELEASE);
	start = monotonic_ms();
	if (start < 0 || runtime->timeout_ms > (uint64_t)(INT64_MAX - start)) {
		*ambiguous = true;
		return -EOVERFLOW;
	}
	deadline = start + (int64_t)runtime->timeout_ms;
	while (accepted < wanted) {
		uint32_t head_after, consumed, returned;

		ret = syscall(SYS_io_uring_enter, ring->fd, wanted - accepted, 0,
			      0, NULL, 0);
		if (ret < 0)
			ret = -errno;
		head_after = __atomic_load_n(ring->sq_head, __ATOMIC_ACQUIRE);
		consumed = head_after - head_start;
		returned = ret > 0 ? (uint32_t)ret : 0;
		if (consumed > wanted || returned > wanted - accepted) {
			first_error = -EPROTO;
			break;
		}
		if (consumed > accepted)
			accepted = consumed;
		else if (returned)
			accepted += returned;
		if (accepted == wanted)
			break;
		if (ret < 0 && ret != -EINTR && ret != -EAGAIN &&
		    ret != -EBUSY) {
			first_error = ret;
			break;
		}
		if (!retries-- || monotonic_ms() >= deadline) {
			first_error = -ETIMEDOUT;
			break;
		}
	}
	*accepted_out = accepted;
	ring->private_tail += wanted;
	ring->prepared = 0;
	runtime->prepared_count = 0;
	if (accepted != wanted) {
		*ambiguous = true;
		return first_error ? first_error : -EPROTO;
	}
	return 0;
}

static int backend_next_cqe(void *opaque, uint64_t *token, int *result)
{
	struct gno_runtime *runtime = opaque;
	struct gno_raw_ring *ring = &runtime->ring;
	struct io_uring_cqe *cqe;
	uint32_t head, tail;
	int ret = wait_for_cqe(runtime);

	if (ret)
		return ret;
	head = __atomic_load_n(ring->cq_head, __ATOMIC_RELAXED);
	tail = __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE);
	if (head == tail)
		return -EPROTO;
	cqe = ring_cqe(ring, head);
	if (cqe->flags || cqe->big_cqe[0] || cqe->big_cqe[1])
		return -EPROTO;
	*token = cqe->user_data;
	*result = cqe->res;
	__atomic_store_n(ring->cq_head, head + 1, __ATOMIC_RELEASE);
	return 0;
}

static int backend_gpu_batch(void *opaque,
			     const struct gno_gpu_transfer *transfers,
			     uint32_t count, uint32_t *completed,
			     bool *ambiguous)
{
	struct gno_runtime *runtime = opaque;
	struct xdev_ext_nv_p2p_dma_batch batch = {
		.handle = runtime->p2p_handle,
		.count = count,
	};
	int saved_errno;
	int ret;

	if (!transfers || !completed || !ambiguous ||
	    !runtime->p2p_handle || !count || count > XDEV_EXT_NV_P2P_MAX_BATCH)
		return -EINVAL;
	*completed = 0;
	*ambiguous = false;
	for (uint32_t i = 0; i < count; i++) {
		const struct gno_gpu_transfer *transfer = &transfers[i];
		uint64_t gpu_address;

		if (!transfer->length ||
		    transfer->direction > XDEV_EXT_NV_P2P_UMEM_TO_GPU ||
		    transfer->gpu_offset > runtime->gpu_bytes ||
		    transfer->length >
			runtime->gpu_bytes - transfer->gpu_offset ||
		    transfer->umem_offset > runtime->umem_size ||
		    transfer->length >
			runtime->umem_size - transfer->umem_offset)
			return -ERANGE;
		gpu_address = runtime->gpu_base + transfer->gpu_offset;
		if (gpu_address < runtime->gpu_base)
			return -EOVERFLOW;
		batch.entries[i] = (struct xdev_ext_nv_p2p_dma_batch_entry) {
			.gpu_offset = gpu_address,
			.umem_offset = transfer->umem_offset,
			.size = transfer->length,
			.direction = transfer->direction,
		};
	}
	runtime->gpu_batch_syscalls++;
	ret = xdev_ext_nv_p2p_dma_batch(runtime->gpu_fd, &batch);
	saved_errno = errno;
	if (batch.completed > count) {
		*ambiguous = true;
		return -EPROTO;
	}
	*completed = batch.completed;
	runtime->gpu_items_completed += batch.completed;
	for (uint32_t i = 0; i < batch.completed; i++) {
		if (batch.entries[i].status != XDEV_EXT_NV_OK) {
			*ambiguous = true;
			return -EPROTO;
		}
	}
	if (!ret)
		return 0;
	/* The ABI proves the successful prefix.  Even a structurally valid native
	 * failure may follow a partially issued failed CE item, so it does not
	 * prove DMA quiescence for that item. */
	*ambiguous = true;
	return saved_errno ? -saved_errno : -EIO;
}

static int backend_compare_umem(void *opaque, uint32_t slot,
				uint64_t left_offset,
				uint64_t right_offset, uint64_t length)
{
	struct gno_runtime *runtime = opaque;

	(void)slot;
	if (left_offset > runtime->umem_size ||
	    right_offset > runtime->umem_size ||
	    length > runtime->umem_size - left_offset ||
	    length > runtime->umem_size - right_offset)
		return -ERANGE;
	return memcmp((unsigned char *)runtime->umem + left_offset,
		      (unsigned char *)runtime->umem + right_offset,
		      (size_t)length) ? -EILSEQ : 0;
}

static const struct gno_backend_ops production_ops = {
	.prepare_nvme = backend_prepare_nvme,
	.abort_private_nvme = backend_abort_private,
	.submit_nvme = backend_submit_nvme,
	.next_nvme_cqe = backend_next_cqe,
	.gpu_batch_sync = backend_gpu_batch,
	.compare_umem = backend_compare_umem,
};

static uint64_t local_identity(void)
{
	uint64_t identity = 0;
	ssize_t bytes;

	do {
		bytes = getrandom(&identity, sizeof(identity), 0);
	} while (bytes < 0 && errno == EINTR);
	if (bytes != (ssize_t)sizeof(identity) || !identity) {
		struct timespec now = { 0 };

		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		identity = ((uint64_t)getpid() << 32) ^ (uint64_t)now.tv_sec ^
			(uint64_t)now.tv_nsec;
		if (!identity)
			identity = 1;
	}
	return identity;
}

#ifdef XDEV_EXT_GPU_NVME_WITH_CUDA
static int cuda_result(CUresult result, const char *operation)
{
	const char *name = NULL;
	const char *description = NULL;

	if (result == CUDA_SUCCESS)
		return 0;
	(void)cuGetErrorName(result, &name);
	(void)cuGetErrorString(result, &description);
	fprintf(stderr, "%s failed: %s (%s)\n", operation,
		name ? name : "CUDA_ERROR", description ? description :
		"no description");
	return -EIO;
}

static int cuda_setup(struct gno_runtime *runtime)
{
	CUcontext context;
	CUdevice selected_device = 0;
	int matched_ordinal = -1;
	unsigned int matches = 0;
	int device_count = 0;
	int ret;

	ret = cuda_result(cuInit(0), "cuInit");
	if (ret)
		return ret;
	ret = cuda_result(cuDeviceGetCount(&device_count), "cuDeviceGetCount");
	if (ret)
		return ret;
	for (int ordinal = 0; ordinal < device_count; ordinal++) {
		char cuda_pci_bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };
		CUdevice device;

		ret = cuda_result(cuDeviceGet(&device, ordinal), "cuDeviceGet");
		if (ret)
			return ret;
		ret = cuda_result(cuDeviceGetPCIBusId(cuda_pci_bdf,
						     sizeof(cuda_pci_bdf), device),
				  "cuDeviceGetPCIBusId");
		if (ret)
			return ret;
		if (!xdev_ext_gpu_identity_is_pci_bdf(cuda_pci_bdf)) {
			fprintf(stderr,
				"CUDA ordinal %d returned invalid PCI BDF '%s'\n",
				ordinal, cuda_pci_bdf);
			return -EPROTO;
		}
		if (!strcasecmp(cuda_pci_bdf, runtime->gpu_pci_bdf)) {
			matches++;
			matched_ordinal = ordinal;
			selected_device = device;
		}
	}
	if (matches != 1 || matched_ordinal != runtime->cli.gpu_index) {
		fprintf(stderr,
			"CUDA ordinal %d does not uniquely match opened GPU PCI %s "
			"(matches=%u, matched ordinal=%d)\n",
			runtime->cli.gpu_index, runtime->gpu_pci_bdf, matches,
			matched_ordinal);
		return -EXDEV;
	}
	runtime->cuda_device = selected_device;
	ret = cuda_result(cuDevicePrimaryCtxRetain(&context,
					   runtime->cuda_device),
			  "cuDevicePrimaryCtxRetain");
	if (ret)
		return ret;
	runtime->cuda_context = context;
	runtime->cuda_primary_retained = true;
	ret = cuda_result(cuCtxSetCurrent(context), "cuCtxSetCurrent");
	if (ret)
		return ret;
	ret = cuda_result(cuMemAlloc(&runtime->cuda_allocation,
				     (size_t)runtime->gpu_bytes), "cuMemAlloc");
	if (ret)
		return ret;
	runtime->gpu_base = (uint64_t)runtime->cuda_allocation;
	if (runtime->cli.mode == GNO_GPU_TO_NVME) {
		ret = cuda_result(cuMemsetD8(runtime->cuda_allocation,
					     (unsigned char)runtime->cli.fill_byte,
					     (size_t)runtime->gpu_bytes),
				  "cuMemsetD8");
		if (ret)
			return ret;
		ret = cuda_result(cuCtxSynchronize(), "cuCtxSynchronize");
		if (ret)
			return ret;
	}
	return 0;
}

static int cuda_cleanup(struct gno_runtime *runtime)
{
	int first_error = 0;
	int ret;

	if (runtime->cuda_allocation) {
		ret = cuda_result(cuCtxSetCurrent(runtime->cuda_context),
				  "cuCtxSetCurrent(cleanup)");
		if (ret) {
			first_error = ret;
		} else {
			ret = cuda_result(cuMemFree(runtime->cuda_allocation),
					  "cuMemFree");
			if (!ret)
				runtime->cuda_allocation = 0;
			else
				first_error = ret;
		}
	}
	if (runtime->cuda_primary_retained) {
		ret = cuda_result(cuDevicePrimaryCtxRelease(runtime->cuda_device),
				  "cuDevicePrimaryCtxRelease");
		if (!ret)
			runtime->cuda_primary_retained = false;
		else if (!first_error)
			first_error = ret;
	}
	return first_error;
}
#else
static int cuda_setup(struct gno_runtime *runtime)
{
	(void)runtime;
	fprintf(stderr,
		"this host build has no CUDA support; rebuild the cuda target\n");
	return -EOPNOTSUPP;
}

static int cuda_cleanup(struct gno_runtime *runtime)
{
	(void)runtime;
	return 0;
}
#endif

static int allocate_backing(struct gno_runtime *runtime)
{
	struct xdev_ext_nv_p2p_pin_umem pin;
	int ret;

	runtime->umem = mmap(NULL, runtime->umem_size,
			     PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (runtime->umem == MAP_FAILED) {
		runtime->umem = NULL;
		return -errno;
	}
	if (!mlock(runtime->umem, runtime->umem_size))
		runtime->umem_locked = true;
	ret = raw_ring_register_umem(&runtime->ring, runtime->umem,
				     runtime->umem_size);
	if (ret)
		return ret;
	pin = (struct xdev_ext_nv_p2p_pin_umem) {
		.umem_addr = (uint64_t)(uintptr_t)runtime->umem,
		.size = runtime->umem_size,
		.frame_size = (uint32_t)GNO_HOST_FRAME_SIZE,
		.xsk_fd = -1,
		.flags = XDEV_EXT_NV_P2P_PIN_F_HOST_REGION,
	};
	if (xdev_ext_nv_p2p_pin_umem(runtime->gpu_fd, &pin))
		return -errno;
	runtime->p2p_handle = pin.handle;
	return 0;
}

static int safe_cleanup(struct gno_runtime *runtime)
{
	int first_error = 0;

	if (runtime->backing_retained)
		return -EBUSY;
	if (runtime->cleanup_attempted)
		return -EALREADY;
	runtime->cleanup_attempted = true;
	if (runtime->ring.buffer_registered) {
		int ret = raw_ring_unregister_umem(&runtime->ring);

		if (ret) {
			runtime->backing_retained = true;
			return ret;
		}
	}
	if (runtime->p2p_handle) {
		struct xdev_ext_nv_p2p_unpin_umem unpin = {
			.handle = runtime->p2p_handle,
		};

		if (xdev_ext_nv_p2p_unpin_umem(runtime->gpu_fd, &unpin)) {
			runtime->backing_retained = true;
			return -errno;
		}
		runtime->p2p_handle = 0;
	}
	raw_ring_destroy(&runtime->ring);
	{
		int ret = cuda_cleanup(runtime);

		if (ret && !first_error)
			first_error = ret;
	}
	if (runtime->umem_locked && munlock(runtime->umem, runtime->umem_size) &&
	    !first_error)
		first_error = -errno;
	if (runtime->umem && munmap(runtime->umem, runtime->umem_size) &&
	    !first_error)
		first_error = -errno;
	runtime->umem = NULL;
	return first_error;
}

static void close_plain_fds(struct gno_runtime *runtime)
{
	if (runtime->gpu_fd >= 0)
		close(runtime->gpu_fd);
	if (runtime->block_fd >= 0)
		close(runtime->block_fd);
	if (runtime->nvme_fd >= 0)
		close(runtime->nvme_fd);
	runtime->gpu_fd = -1;
	runtime->block_fd = -1;
	runtime->nvme_fd = -1;
}

static void sequester_backing(void) __attribute__((noreturn));

static void sequester_backing(void)
{
	const int ignored_signals[] = { SIGHUP, SIGINT, SIGQUIT, SIGTERM };

	for (size_t i = 0; i < sizeof(ignored_signals) /
				      sizeof(ignored_signals[0]); i++)
		(void)signal(ignored_signals[i], SIG_IGN);
	fprintf(stderr,
		"process %ld is sequestered to keep DMA backing alive; verify "
		"device quiescence or reset it before SIGKILL\n",
		(long)getpid());
	fflush(NULL);
	for (;;)
		(void)pause();
}

static const char *mode_name(enum gno_mode mode)
{
	switch (mode) {
	case GNO_NVME_TO_GPU:
		return "nvme-to-gpu";
	case GNO_GPU_TO_NVME:
		return "gpu-to-nvme";
	case GNO_ROUNDTRIP_SAFE:
		return "roundtrip-safe";
	}
	return "invalid";
}

static int parse_mode(const char *text, enum gno_mode *mode)
{
	if (!strcmp(text, "nvme-to-gpu"))
		*mode = GNO_NVME_TO_GPU;
	else if (!strcmp(text, "gpu-to-nvme"))
		*mode = GNO_GPU_TO_NVME;
	else if (!strcmp(text, "roundtrip-safe"))
		*mode = GNO_ROUNDTRIP_SAFE;
	else
		return -EINVAL;
	return 0;
}

static void usage(FILE *file, const char *program)
{
	fprintf(file,
		"Usage: %s --nvme DEV --block DEV --gpu DEV --window-first LBA "
		"--window-lbas N [options]\n"
		"  --mode MODE          nvme-to-gpu (default), gpu-to-nvme, or "
		"roundtrip-safe\n"
		"  --bytes N            bytes per logical command (default 8192)\n"
		"  --vector-bytes N     bytes per fixed iovec (default 4096)\n"
		"  --count N            batched commands, max %u (default %u)\n"
		"  --request-index N    relative command index in local window\n"
		"  --max-io-bytes N     lower cap; cannot raise the sysfs cap\n"
		"  --gpu-index N        CUDA device ordinal (default 0)\n"
		"  --fill-byte N        required 0..255 pattern for gpu-to-nvme\n"
		"  --allow-write        required for either WRITE-capable mode\n"
		"  --iopoll             use true io_uring IOPOLL after proof\n"
		"  --timeout-ms N       bounded wait (default 30000)\n"
		"\nThe GPU ioctl is synchronous, CE-required, and has no CPU fallback.\n"
		"An ambiguous DMA failure sequesters the process and backing. "
		"Reset or verify device quiescence before SIGKILL.\n",
		program, GNO_MAX_BATCH, GNO_DEFAULT_DEPTH);
}

static int parse_options(int argc, char **argv, struct gno_cli *cli)
{
	enum {
		OPT_NVME = 1000, OPT_BLOCK, OPT_GPU, OPT_MODE,
		OPT_WINDOW_FIRST, OPT_WINDOW_LBAS, OPT_REQUEST_INDEX,
		OPT_BYTES, OPT_VECTOR_BYTES, OPT_COUNT, OPT_MAX_IO_BYTES,
		OPT_GPU_INDEX, OPT_FILL_BYTE, OPT_ALLOW_WRITE, OPT_IOPOLL,
		OPT_TIMEOUT_MS,
	};
	static const struct option options[] = {
		{ "nvme", required_argument, NULL, OPT_NVME },
		{ "block", required_argument, NULL, OPT_BLOCK },
		{ "gpu", required_argument, NULL, OPT_GPU },
		{ "mode", required_argument, NULL, OPT_MODE },
		{ "window-first", required_argument, NULL, OPT_WINDOW_FIRST },
		{ "window-lbas", required_argument, NULL, OPT_WINDOW_LBAS },
		{ "request-index", required_argument, NULL, OPT_REQUEST_INDEX },
		{ "bytes", required_argument, NULL, OPT_BYTES },
		{ "vector-bytes", required_argument, NULL, OPT_VECTOR_BYTES },
		{ "count", required_argument, NULL, OPT_COUNT },
		{ "max-io-bytes", required_argument, NULL, OPT_MAX_IO_BYTES },
		{ "gpu-index", required_argument, NULL, OPT_GPU_INDEX },
		{ "fill-byte", required_argument, NULL, OPT_FILL_BYTE },
		{ "allow-write", no_argument, NULL, OPT_ALLOW_WRITE },
		{ "iopoll", no_argument, NULL, OPT_IOPOLL },
		{ "timeout-ms", required_argument, NULL, OPT_TIMEOUT_MS },
		{ "help", no_argument, NULL, 'h' },
		{ 0, 0, 0, 0 },
	};
	int option;

	*cli = (struct gno_cli) {
		.mode = GNO_NVME_TO_GPU,
		.transfer_bytes = GNO_DEFAULT_BYTES,
		.vector_bytes = GNO_DEFAULT_VECTOR_BYTES,
		.count = GNO_DEFAULT_DEPTH,
		.timeout_ms = GNO_DEFAULT_TIMEOUT_MS,
	};
	while ((option = getopt_long(argc, argv, "h", options, NULL)) != -1) {
		uint64_t value;
		uint32_t value32;

		switch (option) {
		case OPT_NVME:
			cli->nvme_device = optarg;
			break;
		case OPT_BLOCK:
			cli->block_device = optarg;
			break;
		case OPT_GPU:
			cli->gpu_device = optarg;
			break;
		case OPT_MODE:
			if (parse_mode(optarg, &cli->mode))
				return -EINVAL;
			break;
		case OPT_WINDOW_FIRST:
			if (parse_u64(optarg, &cli->window_first))
				return -EINVAL;
			cli->window_first_set = true;
			break;
		case OPT_WINDOW_LBAS:
			if (parse_u64(optarg, &cli->window_lbas))
				return -EINVAL;
			cli->window_lbas_set = true;
			break;
		case OPT_REQUEST_INDEX:
			if (parse_u64(optarg, &cli->request_index))
				return -EINVAL;
			break;
		case OPT_BYTES:
			if (parse_u64(optarg, &cli->transfer_bytes))
				return -EINVAL;
			break;
		case OPT_VECTOR_BYTES:
			if (parse_u64(optarg, &cli->vector_bytes))
				return -EINVAL;
			break;
		case OPT_COUNT:
			if (parse_u32(optarg, &cli->count))
				return -EINVAL;
			break;
		case OPT_MAX_IO_BYTES:
			if (parse_u64(optarg, &cli->user_max_io_bytes))
				return -EINVAL;
			break;
		case OPT_GPU_INDEX:
			if (parse_u64(optarg, &value) || value > INT_MAX)
				return -EINVAL;
			cli->gpu_index = (int)value;
			break;
		case OPT_FILL_BYTE:
			if (parse_u32(optarg, &value32) || value32 > UCHAR_MAX)
				return -EINVAL;
			cli->fill_byte = value32;
			cli->fill_byte_set = true;
			break;
		case OPT_ALLOW_WRITE:
			cli->allow_write = true;
			break;
		case OPT_IOPOLL:
			cli->iopoll = true;
			break;
		case OPT_TIMEOUT_MS:
			if (parse_u64(optarg, &cli->timeout_ms))
				return -EINVAL;
			break;
		case 'h':
			usage(stdout, argv[0]);
			exit(EXIT_SUCCESS);
		default:
			return -EINVAL;
		}
	}
	if (optind != argc || !cli->nvme_device || !cli->block_device ||
	    !cli->gpu_device || !cli->window_first_set ||
	    !cli->window_lbas_set || !cli->window_lbas || !cli->count ||
	    cli->count > GNO_MAX_BATCH || !cli->transfer_bytes ||
	    !cli->vector_bytes || !cli->timeout_ms)
		return -EINVAL;
	if ((cli->mode == GNO_GPU_TO_NVME ||
	     cli->mode == GNO_ROUNDTRIP_SAFE) && !cli->allow_write)
		return -EPERM;
	if (cli->mode == GNO_GPU_TO_NVME && !cli->fill_byte_set)
		return -EINVAL;
	return 0;
}

static int open_devices(struct gno_runtime *runtime)
{
	bool writes = runtime->cli.mode != GNO_NVME_TO_GPU;
	int block_flags = O_RDONLY | O_CLOEXEC;

	if (writes)
		block_flags |= O_EXCL;
	runtime->nvme_fd = open(runtime->cli.nvme_device,
		writes ? O_RDWR | O_CLOEXEC : O_RDONLY | O_CLOEXEC);
	if (runtime->nvme_fd < 0)
		return -errno;
	runtime->block_fd = open(runtime->cli.block_device, block_flags);
	if (runtime->block_fd < 0)
		return -errno;
	runtime->gpu_fd = open(runtime->cli.gpu_device, O_RDWR | O_CLOEXEC);
	if (runtime->gpu_fd < 0)
		return -errno;
	return 0;
}

int main(int argc, char **argv)
{
	struct gno_runtime runtime = {
		.ring.fd = -1, .nvme_fd = -1, .block_fd = -1, .gpu_fd = -1,
	};
	struct gno_config config = { 0 };
	struct gno_batch batch = { 0 };
	struct gno_slot *slots = NULL;
	struct iovec *vectors = NULL;
	uint64_t max_io_bytes, batch_bytes, required_umem;
	uint64_t vector_count, vector_total;
	int cleanup_ret, required_error, ret;

	ret = parse_options(argc, argv, &runtime.cli);
	if (ret) {
		fprintf(stderr, "invalid arguments: %s\n", strerror(-ret));
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
#ifndef XDEV_EXT_GPU_NVME_WITH_CUDA
	ret = cuda_setup(&runtime);
	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
#endif
	ret = open_devices(&runtime);
	if (ret)
		goto fail;
	{
		char gpu_bdf[XDEV_EXT_GPU_PCI_BDF_SIZE] = { 0 };
		size_t gpu_bdf_len;

		ret = xdev_ext_gpu_identity_from_opened(
			runtime.gpu_fd, runtime.cli.gpu_device,
			XDEV_EXT_GPU_IDENTITY_ANY_MINOR, gpu_bdf);
		if (ret)
			goto fail;
		gpu_bdf_len = strlen(gpu_bdf);
		if (gpu_bdf_len >= sizeof(runtime.gpu_pci_bdf)) {
			ret = -ENAMETOOLONG;
			goto fail;
		}
		memcpy(runtime.gpu_pci_bdf, gpu_bdf, gpu_bdf_len + 1);
	}
	ret = resolve_sysfs(&runtime);
	if (ret)
		goto fail;
	ret = collect_namespace(&runtime);
	if (ret)
		goto fail;
	ret = effective_max_io_bytes(&runtime, &max_io_bytes);
	if (ret)
		goto fail;
	if (runtime.cli.iopoll) {
		ret = prove_iopoll(&runtime);
		if (ret)
			goto fail;
	}
	if (gno_u64_mul_overflow(runtime.cli.count,
				 runtime.cli.transfer_bytes, &batch_bytes)) {
		ret = -EOVERFLOW;
		goto fail;
	}
	runtime.gpu_bytes = batch_bytes;
	config = (struct gno_config) {
		.mode = runtime.cli.mode,
		.ns = runtime.ns,
		.limits = {
			.authorized_first_lba = runtime.cli.window_first,
			.authorized_lbas = runtime.cli.window_lbas,
		},
		.transfer_bytes = runtime.cli.transfer_bytes,
		.max_transfer_bytes = max_io_bytes,
		.vector_bytes = runtime.cli.vector_bytes,
		.request_index = runtime.cli.request_index,
		.request_count = runtime.cli.count,
		.gpu_bytes = runtime.gpu_bytes,
		.allow_write = runtime.cli.allow_write,
		.local_chain_id = local_identity(),
		.local_nvme_endpoint_id = local_identity(),
		.local_gpu_endpoint_id = local_identity(),
		.local_host_buffer_id = local_identity(),
	};
	required_umem = gno_required_registered_umem(&config, &required_error);
	if (required_error || required_umem > SIZE_MAX) {
		ret = required_error ? required_error : -EOVERFLOW;
		goto fail;
	}
	config.umem_bytes = required_umem;
	runtime.umem_size = (size_t)required_umem;
	ret = gno_config_validate(&config);
	if (ret)
		goto fail;
	ret = raw_ring_init(&runtime.ring, runtime.cli.count,
			    runtime.cli.iopoll);
	if (ret)
		goto fail;
	runtime.timeout_ms = runtime.cli.timeout_ms;
	ret = cuda_setup(&runtime);
	if (ret)
		goto fail;
	ret = allocate_backing(&runtime);
	if (ret)
		goto fail;

	vector_count = 1 + (config.transfer_bytes - 1) /
		config.vector_bytes;
	if (gno_u64_mul_overflow(vector_count, config.request_count,
				 &vector_total) ||
	    vector_total > UINT32_MAX ||
	    vector_total > SIZE_MAX / sizeof(*vectors)) {
		ret = -EOVERFLOW;
		goto fail;
	}
	slots = calloc(config.request_count, sizeof(*slots));
	vectors = calloc((size_t)vector_total, sizeof(*vectors));
	if (!slots || !vectors) {
		ret = -ENOMEM;
		goto fail;
	}
	batch.slots = slots;
	batch.slot_capacity = config.request_count;
	batch.vectors = vectors;
	batch.vector_capacity = (uint32_t)vector_total;
	ret = gno_batch_prepare(&batch, &config, runtime.umem,
				config.umem_bytes);
	if (ret)
		goto fail;

	printf("mode=%s count=%u bytes=%" PRIu64 " vectors/request=%" PRIu64
	       " lba=%u effective-max=%" PRIu64 " iopoll=%s\n",
	       mode_name(config.mode), config.request_count,
	       config.transfer_bytes, vector_count, config.ns.lba_size,
	       config.max_transfer_bytes, runtime.cli.iopoll ? "yes" : "no");
	printf("local correlation chain=%" PRIu64 " nvme-endpoint=%" PRIu64
	       " gpu-endpoint=%" PRIu64 " host-buffer=%" PRIu64 "\n",
	       config.local_chain_id, config.local_nvme_endpoint_id,
	       config.local_gpu_endpoint_id, config.local_host_buffer_id);
	printf("kernel BPF identities are independently trusted per backend; "
	       "GPU CE ioctl is synchronous\n");
	ret = gno_execute(&batch, &production_ops, &runtime);
	if (ret)
		goto fail;
	if (!gno_batch_may_destroy_backing(&batch)) {
		ret = -EBUSY;
		goto fail;
	}
	cleanup_ret = safe_cleanup(&runtime);
	if (cleanup_ret) {
		ret = cleanup_ret;
		goto fail;
	}
	close_plain_fds(&runtime);
	free(vectors);
	free(slots);
	printf("completed: %s (%u logical commands)\n",
	       mode_name(config.mode), config.request_count);
	printf("GPU batching: %" PRIu64 " ioctl(s), %" PRIu64
	       " completed item(s)\n", runtime.gpu_batch_syscalls,
	       runtime.gpu_items_completed);
	return EXIT_SUCCESS;

fail:
	if (batch.retain_backing ||
	    (batch.count && !gno_batch_may_destroy_backing(&batch)))
		runtime.backing_retained = true;
	if (!runtime.backing_retained && !runtime.cleanup_attempted) {
		cleanup_ret = safe_cleanup(&runtime);
		if (!ret && cleanup_ret)
			ret = cleanup_ret;
	}
	if (runtime.backing_retained)
		fprintf(stderr,
			"retaining ring, GPU handle, CUDA allocation, and UMEM: "
			"DMA quiescence was not proven\n");
	if (runtime.gpu_batch_syscalls)
		fprintf(stderr, "GPU batching before failure: %" PRIu64
			" ioctl(s), %" PRIu64 " completed item(s)\n",
			runtime.gpu_batch_syscalls,
			runtime.gpu_items_completed);
	fprintf(stderr, "gpu_nvme_orchestrator failed: %s (%d)\n",
		strerror(ret < 0 ? -ret : EIO), ret);
	if (runtime.backing_retained)
		sequester_backing();
	if (!runtime.backing_retained)
		close_plain_fds(&runtime);
	free(vectors);
	free(slots);
	return EXIT_FAILURE;
}
