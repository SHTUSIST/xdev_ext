// SPDX-License-Identifier: GPL-2.0
/*
 * Guest runtime test for the NVMe SGL virt-boundary backport.
 *
 * It runs only inside the disposable KVM guest, on the dedicated QEMU NVMe
 * controller with serial UBRSGL0001, and writes only the LBA regions listed
 * in sgl_regions[] (the host recomputes the same bytes and compares the whole
 * image after QEMU exits).  It checks:
 *
 *  - queue: the controller's SGL support (Identify Controller SGLS) and the
 *    I/O queue's virt_boundary_mask (0 is expected when SGL is supported);
 *  - pipeline: the pipeline's 8 KiB opted-in fixed IO_VEC WRITE (six
 *    segments at byte 104 of separate 4 KiB frames, 5 x 1432 + 1032) and the
 *    same-layout READ are DMA'd from the registered buffer: no kernel bounce
 *    copy and no -EAGAIN retry from io-wq, and the bytes match;
 *  - control: a fixed IO_VEC with more segments than max_segments must still
 *    be bounced and retried from io-wq, which shows the counters are live;
 *  - odirect: O_DIRECT pwritev/preadv with gapped, 4-byte aligned vectors
 *    (including one split by max_segments) keep their data, with the block
 *    split count the queue limits predict;
 *  - admin: Identify through a gapped vector on the admin queue is still
 *    bounced (the admin queue keeps the 4 KiB boundary) and matches the
 *    contiguous Identify.
 *
 * The bounce copy is bio_copy_user_iov() in block/blk-map.c, which the
 * compiler may inline into blk_rq_map_user_iov().  It is therefore counted
 * by its two out-of-line calls into block/bio.c: bio_kmalloc(), which
 * allocates every bounce bio (the fixed-buffer direct map allocates from the
 * REQ_ALLOC_CACHE bio set instead), and bio_free_pages(), which frees the
 * kernel bounce pages on unmap.  Both are counted kernel-wide during each
 * step, so zero bio_kmalloc() calls prove that the step had no bounce.  When
 * a bio_copy_user_iov symbol exists it is probed as well and must agree.
 * Every event carries a stack trace, printed for diagnosis.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
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

#include "../../../../include/uapi/linux/io_uring.h"
#include "../../../../include/uapi/linux/nvme_ioctl.h"

#define KSFT_SKIP 4
#define EXPECTED_MODEL "QEMU NVMe Ctrl"
#define EXPECTED_SERIAL "UBRSGL0001"
#define LBA_SIZE 512U
#define FRAME_SIZE 4096U
#define SQE_SIZE 128U
#define CQE_SIZE 32U
#define RING_ENTRIES 8U
#define COMMAND_TIMEOUT_MS 30000
#define POLL_SLICE_MS 100
#define NVME_OP_WRITE 0x01U
#define NVME_OP_READ 0x02U
#define NVME_ADMIN_IDENTIFY 0x06U
#define NVME_ID_CNS_CTRL 0x01U
#define IDENTIFY_BYTES 4096U
#define IDENTIFY_SERIAL_OFFSET 4U
#define IDENTIFY_SERIAL_BYTES 20U
#define IDENTIFY_SGLS_OFFSET 536U
#define XDEV_EXT_FLAG_OPT_IN 1U	/* NVME_URING_CMD_F_XDEV_EXT */

/* The pipeline layout: six frames, data at byte 104, 5 x 1432 + 1032. */
#define PIPELINE_SEGMENTS 6U
#define PIPELINE_OFFSET 104U
#define PIPELINE_SEGMENT 1432U
#define PIPELINE_LAST 1032U
#define PIPELINE_BYTES 8192U
#define PIPELINE_BUFFER_FRAMES 16U
/* More segments than QEMU's max_segments (128) and at most BIO_MAX_VECS. */
#define WIDE_SEGMENTS 160U

#define GUARD_WRITE 0xc3U
#define GUARD_READ 0x3cU

#define TRACE_INSTANCE "xdev_ext_sgl_gap"
#define TRACE_GROUP "xdev_ext_sgl"
#define MAX_COPY_SYMBOLS 4
#define TRACEFS_ROOT_MAX 512

/* Byte o of the namespace in a region written with @seed. */
static uint8_t pattern_byte(uint64_t offset, uint8_t seed)
{
	return (uint8_t)(offset * 131U + (offset >> 9) * 7U + seed);
}

struct region {
	const char *name;
	uint64_t lba;
	uint32_t sectors;
	uint8_t seed;
};

/* Mirrored by the harness, which recomputes the expected image. */
static const struct region sgl_regions[] = {
	{ "pipeline", 2048, PIPELINE_BYTES / LBA_SIZE, 0x11 },
	{ "control", 4096, WIDE_SEGMENTS, 0x22 },
	{ "odirect-l1", 8192, 12, 0x33 },
	{ "odirect-l2", 9216, 16, 0x44 },
	{ "odirect-l3", 10240, WIDE_SEGMENTS, 0x55 },
};

enum {
	REGION_PIPELINE,
	REGION_CONTROL,
	REGION_L1,
	REGION_L2,
	REGION_L3,
};

struct segment {
	unsigned int page;
	unsigned int offset;
	unsigned int length;
};

/* Gaps inside pages, one vector crossing a page boundary. */
static const struct segment layout_l1[] = {
	{ 0, 4, 1024 }, { 1, 1028, 512 }, { 2, 2052, 1536 },
	{ 3, 516, 1024 }, { 4, 3076, 2048 },
};

/* PRP-shaped except for one segment that starts inside its page. */
static const struct segment layout_l2[] = {
	{ 0, 0, 4096 }, { 2, 512, 3584 }, { 4, 0, 512 },
};

struct options {
	const char *controller;
	const char *block;
	const char *generic;
	const char *tracefs;
	bool allow_write;
};

struct ring {
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
	struct io_uring_params params;
	bool poisoned;
};

struct command {
	int fd;
	uint32_t cmd_op;
	uint8_t opcode;
	uint32_t nsid;
	uint64_t addr;
	uint32_t data_len;
	uint32_t cdw10;
	uint32_t cdw11;
	uint32_t cdw12;
	uint32_t rsvd2;
	bool fixed;
	uint16_t buf_index;
};

struct counts {
	long long copy_alloc;	/* diagnosis: bio_kmalloc() under blk_rq_map_user*() */
	long long copy_free;	/* diagnosis: bio_free_pages() under blk_rq_unmap_user() */
	long long copy_direct;	/* bio_copy_user_iov() hits, -1 if inlined */
	long long map_eagain;	/* blk_rq_map_user_iov() returned -EAGAIN */
	long long iowq;		/* io_uring_queue_async_work events */
	long long splits;	/* block_split events on this namespace */
	long long kmalloc_all;	/* every bio_kmalloc() hit */
	long long freepages_all;	/* every bio_free_pages() hit */
};

struct tracer {
	char root[TRACEFS_ROOT_MAX];
	char instance[TRACEFS_ROOT_MAX + 64];
	char copy_symbols[MAX_COPY_SYMBOLS][256];
	unsigned int copy_symbol_count;
	bool kprobes_added;
	bool instance_made;
	unsigned long long profile_before;
};

static unsigned int checks;
static unsigned int failures;
static uint64_t next_user_data = UINT64_C(0x55425253474c0000);

static void check(bool ok, const char *format, ...)
{
	va_list args;

	checks++;
	printf("%s %u - ", ok ? "ok" : "not ok", checks);
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
	fflush(stdout);
	if (!ok)
		failures++;
}

static int64_t now_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* ---- small file helpers ------------------------------------------------ */

static int write_text(const char *path, const char *text, bool append)
{
	size_t length = strlen(text);
	ssize_t written;
	int fd;

	fd = open(path, O_WRONLY | O_CLOEXEC | (append ? O_APPEND : O_TRUNC));
	if (fd < 0)
		return -errno;
	written = write(fd, text, length);
	if (written < 0) {
		int error = -errno;

		close(fd);
		return error;
	}
	close(fd);
	return (size_t)written == length ? 0 : -EIO;
}

static int writef(const char *text, bool append, const char *format, ...)
{
	char path[PATH_MAX];
	va_list args;

	va_start(args, format);
	vsnprintf(path, sizeof(path), format, args);
	va_end(args);
	return write_text(path, text, append);
}

static char *read_all(const char *path, size_t *length_out)
{
	size_t capacity = 65536, length = 0;
	char *buffer = malloc(capacity + 1);
	int fd;

	if (!buffer)
		return NULL;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		free(buffer);
		return NULL;
	}
	for (;;) {
		ssize_t got;

		if (length == capacity) {
			char *bigger;

			capacity *= 2;
			bigger = realloc(buffer, capacity + 1);
			if (!bigger) {
				free(buffer);
				close(fd);
				return NULL;
			}
			buffer = bigger;
		}
		got = read(fd, buffer + length, capacity - length);
		if (got < 0) {
			if (errno == EINTR)
				continue;
			free(buffer);
			close(fd);
			return NULL;
		}
		if (!got)
			break;
		length += (size_t)got;
	}
	close(fd);
	buffer[length] = '\0';
	if (length_out)
		*length_out = length;
	return buffer;
}

static int read_trimmed(const char *path, char *out, size_t size)
{
	char *text = read_all(path, NULL);
	size_t start = 0, end;

	if (!text)
		return -errno ? -errno : -EIO;
	end = strlen(text);
	while (end && (text[end - 1] == '\n' || text[end - 1] == ' ' ||
		       text[end - 1] == '\t'))
		end--;
	while (start < end && (text[start] == ' ' || text[start] == '\t'))
		start++;
	if (end - start >= size) {
		free(text);
		return -ENAMETOOLONG;
	}
	memcpy(out, text + start, end - start);
	out[end - start] = '\0';
	free(text);
	return 0;
}

static int read_u64(const char *path, uint64_t *value)
{
	char text[64], *end;

	if (read_trimmed(path, text, sizeof(text)))
		return -EIO;
	errno = 0;
	*value = strtoull(text, &end, 0);
	return errno || end == text || *end ? -EINVAL : 0;
}

/* ---- safety gate ------------------------------------------------------- */

static bool valid_name(const char *name, const char *prefix)
{
	size_t length = strlen(prefix);
	const char *cursor;

	if (strncmp(name, prefix, length) || !name[length])
		return false;
	for (cursor = name + length; *cursor; cursor++)
		if (!((*cursor >= '0' && *cursor <= '9') || *cursor == 'n'))
			return false;
	return true;
}

static bool under_hypervisor(void)
{
	char *cpuinfo = read_all("/proc/cpuinfo", NULL);
	bool found;

	if (!cpuinfo)
		return false;
	found = strstr(cpuinfo, " hypervisor") != NULL;
	free(cpuinfo);
	return found;
}

static bool same_realpath(const char *left, const char *right)
{
	char a[PATH_MAX], b[PATH_MAX];

	return realpath(left, a) && realpath(right, b) && !strcmp(a, b);
}

static bool node_matches(const char *node, const char *sysfs_dev, bool block)
{
	unsigned int major_number, minor_number;
	char text[64], extra;
	struct stat st;

	if (lstat(node, &st) || S_ISLNK(st.st_mode))
		return false;
	if (block ? !S_ISBLK(st.st_mode) : !S_ISCHR(st.st_mode))
		return false;
	if (read_trimmed(sysfs_dev, text, sizeof(text)) ||
	    sscanf(text, "%u:%u%c", &major_number, &minor_number, &extra) != 2)
		return false;
	return major(st.st_rdev) == major_number &&
	       minor(st.st_rdev) == minor_number;
}

static bool namespace_in_use(const char *block, dev_t rdev)
{
	char path[PATH_MAX], line[4096];
	unsigned int major_number, minor_number;
	struct dirent *entry;
	bool busy = false;
	DIR *directory;
	FILE *file;

	snprintf(path, sizeof(path), "/sys/class/block/%s/holders", block);
	directory = opendir(path);
	if (!directory)
		return true;
	while ((entry = readdir(directory)))
		if (entry->d_name[0] != '.')
			busy = true;
	closedir(directory);
	snprintf(path, sizeof(path), "/sys/class/block/%s", block);
	directory = opendir(path);
	if (!directory)
		return true;
	while ((entry = readdir(directory)))
		if (!strncmp(entry->d_name, block, strlen(block)) &&
		    entry->d_name[strlen(block)] == 'p')
			busy = true;
	closedir(directory);
	file = fopen("/proc/self/mountinfo", "re");
	if (!file)
		return true;
	while (fgets(line, sizeof(line), file))
		if (sscanf(line, "%*u %*u %u:%u", &major_number,
			   &minor_number) == 2 &&
		    major_number == major(rdev) && minor_number == minor(rdev))
			busy = true;
	fclose(file);
	file = fopen("/proc/swaps", "re");
	if (file) {
		snprintf(path, sizeof(path), "/dev/%s ", block);
		while (fgets(line, sizeof(line), file))
			if (!strncmp(line, path, strlen(path)))
				busy = true;
		fclose(file);
	}
	return busy;
}

/* Refuse anything that is not the private QEMU controller UBRSGL0001. */
static int safety_gate(const struct options *options)
{
	char path[PATH_MAX], other[PATH_MAX], text[256];
	struct stat st;

	if (!valid_name(options->controller, "nvme") ||
	    !valid_name(options->block, "nvme") ||
	    !valid_name(options->generic, "ng")) {
		fprintf(stderr, "REFUSE: device names must be nvmeN, nvmeNnM, ngNnM\n");
		return -EINVAL;
	}
	if (!under_hypervisor()) {
		fprintf(stderr, "REFUSE: CPU does not report a hypervisor\n");
		return -EPERM;
	}
	if (geteuid()) {
		fprintf(stderr, "REFUSE: must run as root inside the KVM guest\n");
		return -EPERM;
	}
	snprintf(path, sizeof(path), "/sys/class/nvme/%s/model",
		 options->controller);
	if (read_trimmed(path, text, sizeof(text)) ||
	    strcmp(text, EXPECTED_MODEL)) {
		fprintf(stderr, "REFUSE: controller model is not %s\n",
			EXPECTED_MODEL);
		return -EPERM;
	}
	snprintf(path, sizeof(path), "/sys/class/nvme/%s/serial",
		 options->controller);
	if (read_trimmed(path, text, sizeof(text)) ||
	    strcmp(text, EXPECTED_SERIAL)) {
		fprintf(stderr, "REFUSE: controller serial is not %s\n",
			EXPECTED_SERIAL);
		return -EPERM;
	}
	snprintf(path, sizeof(path), "/sys/class/nvme/%s", options->controller);
	snprintf(other, sizeof(other), "/sys/class/block/%s/device",
		 options->block);
	if (!same_realpath(path, other)) {
		fprintf(stderr, "REFUSE: %s is not a namespace of %s\n",
			options->block, options->controller);
		return -EPERM;
	}
	snprintf(other, sizeof(other), "/sys/class/nvme-generic/%s/device",
		 options->generic);
	if (!same_realpath(path, other)) {
		fprintf(stderr, "REFUSE: %s is not a namespace of %s\n",
			options->generic, options->controller);
		return -EPERM;
	}
	snprintf(path, sizeof(path), "/dev/%s", options->controller);
	snprintf(other, sizeof(other), "/sys/class/nvme/%s/dev",
		 options->controller);
	if (!node_matches(path, other, false))
		return -ENODEV;
	snprintf(path, sizeof(path), "/dev/%s", options->generic);
	snprintf(other, sizeof(other), "/sys/class/nvme-generic/%s/dev",
		 options->generic);
	if (!node_matches(path, other, false))
		return -ENODEV;
	snprintf(path, sizeof(path), "/dev/%s", options->block);
	snprintf(other, sizeof(other), "/sys/class/block/%s/dev",
		 options->block);
	if (!node_matches(path, other, true) || stat(path, &st))
		return -ENODEV;
	if (namespace_in_use(options->block, st.st_rdev)) {
		fprintf(stderr, "REFUSE: %s is mounted, held, partitioned or swap\n",
			options->block);
		return -EBUSY;
	}
	return 0;
}

/* ---- raw io_uring ------------------------------------------------------ */

static void ring_destroy(struct ring *ring)
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
	ring->fd = -1;
}

static int ring_init(struct ring *ring)
{
	struct io_uring_params *p = &ring->params;

	memset(ring, 0, sizeof(*ring));
	p->flags = IORING_SETUP_SQE128 | IORING_SETUP_CQE32;
	ring->fd = syscall(SYS_io_uring_setup, RING_ENTRIES, p);
	if (ring->fd < 0)
		return -errno;
	ring->sq_ring_size = p->sq_off.array + p->sq_entries * sizeof(uint32_t);
	ring->cq_ring_size = p->cq_off.cqes + p->cq_entries * CQE_SIZE;
	ring->sqes_size = p->sq_entries * SQE_SIZE;
	if (p->features & IORING_FEAT_SINGLE_MMAP) {
		if (ring->cq_ring_size > ring->sq_ring_size)
			ring->sq_ring_size = ring->cq_ring_size;
		ring->cq_ring_size = ring->sq_ring_size;
	}
	ring->sq_ring = mmap(NULL, ring->sq_ring_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED | MAP_POPULATE, ring->fd,
			     IORING_OFF_SQ_RING);
	if (ring->sq_ring == MAP_FAILED)
		goto fail;
	if (p->features & IORING_FEAT_SINGLE_MMAP)
		ring->cq_ring = ring->sq_ring;
	else
		ring->cq_ring = mmap(NULL, ring->cq_ring_size,
				     PROT_READ | PROT_WRITE,
				     MAP_SHARED | MAP_POPULATE, ring->fd,
				     IORING_OFF_CQ_RING);
	if (ring->cq_ring == MAP_FAILED)
		goto fail;
	ring->sqes = mmap(NULL, ring->sqes_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_POPULATE, ring->fd, IORING_OFF_SQES);
	if (ring->sqes == MAP_FAILED)
		goto fail;
	ring->sq_head = (uint32_t *)((char *)ring->sq_ring + p->sq_off.head);
	ring->sq_tail = (uint32_t *)((char *)ring->sq_ring + p->sq_off.tail);
	ring->sq_mask = (uint32_t *)((char *)ring->sq_ring + p->sq_off.ring_mask);
	ring->sq_entries = (uint32_t *)((char *)ring->sq_ring +
					p->sq_off.ring_entries);
	ring->sq_array = (uint32_t *)((char *)ring->sq_ring + p->sq_off.array);
	ring->cq_head = (uint32_t *)((char *)ring->cq_ring + p->cq_off.head);
	ring->cq_tail = (uint32_t *)((char *)ring->cq_ring + p->cq_off.tail);
	ring->cq_mask = (uint32_t *)((char *)ring->cq_ring + p->cq_off.ring_mask);
	return 0;
fail:
	{
		int error = -errno;

		ring_destroy(ring);
		return error;
	}
}

static int ring_register(struct ring *ring, struct iovec *buffers,
			 unsigned int count)
{
	int ret = syscall(SYS_io_uring_register, ring->fd,
			  IORING_REGISTER_BUFFERS, buffers, count);

	return ret < 0 ? -errno : 0;
}

/*
 * Submit one command and wait for its CQE.  A timeout poisons the ring: the
 * command may still own its buffers, so the caller stops issuing commands
 * and never frees them before exit.
 */
static int ring_execute(struct ring *ring, const struct command *command,
			int32_t *result)
{
	struct io_uring_sqe *sqe;
	struct nvme_uring_cmd *cmd;
	struct io_uring_cqe *cqe;
	uint32_t tail, index, head;
	uint64_t user_data;
	int64_t deadline;
	int ret;

	if (ring->poisoned)
		return -ESHUTDOWN;
	deadline = now_ms() + COMMAND_TIMEOUT_MS;
	tail = __atomic_load_n(ring->sq_tail, __ATOMIC_RELAXED);
	index = tail & *ring->sq_mask;
	sqe = (struct io_uring_sqe *)((char *)ring->sqes + index * SQE_SIZE);
	memset(sqe, 0, SQE_SIZE);
	user_data = ++next_user_data;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = command->fd;
	sqe->cmd_op = command->cmd_op;
	sqe->user_data = user_data;
	if (command->fixed) {
		sqe->uring_cmd_flags = IORING_URING_CMD_FIXED;
		sqe->buf_index = command->buf_index;
	}
	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	cmd->opcode = command->opcode;
	cmd->nsid = command->nsid;
	cmd->addr = command->addr;
	cmd->data_len = command->data_len;
	cmd->cdw10 = command->cdw10;
	cmd->cdw11 = command->cdw11;
	cmd->cdw12 = command->cdw12;
	cmd->rsvd2 = command->rsvd2;
	ring->sq_array[index] = index;
	__atomic_store_n(ring->sq_tail, tail + 1, __ATOMIC_RELEASE);

	for (;;) {
		ret = syscall(SYS_io_uring_enter, ring->fd, 1, 0, 0, NULL, 0);
		if (ret == 1)
			break;
		if (ret < 0 && errno != EINTR && errno != EAGAIN &&
		    errno != EBUSY) {
			ring->poisoned = true;
			return -errno;
		}
		if (now_ms() >= deadline) {
			ring->poisoned = true;
			return -ETIMEDOUT;
		}
	}
	for (;;) {
		struct pollfd pollfd = { .fd = ring->fd, .events = POLLIN };
		int64_t left;

		head = __atomic_load_n(ring->cq_head, __ATOMIC_RELAXED);
		if (head != __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE))
			break;
		left = deadline - now_ms();
		if (left <= 0) {
			ring->poisoned = true;
			return -ETIMEDOUT;
		}
		ret = poll(&pollfd, 1, left > POLL_SLICE_MS ? POLL_SLICE_MS :
			   (int)left);
		if (ret < 0 && errno != EINTR) {
			ring->poisoned = true;
			return -errno;
		}
		/* A syscall boundary also runs pending io_uring task work. */
		syscall(SYS_io_uring_enter, ring->fd, 0, 0,
			IORING_ENTER_GETEVENTS, NULL, 0);
	}
	cqe = (struct io_uring_cqe *)((char *)ring->cq_ring +
				      ring->params.cq_off.cqes +
				      (head & *ring->cq_mask) * CQE_SIZE);
	if (cqe->user_data != user_data) {
		ring->poisoned = true;
		return -EPROTO;
	}
	*result = cqe->res;
	__atomic_store_n(ring->cq_head, head + 1, __ATOMIC_RELEASE);
	return 0;
}

/* ---- tracefs counters -------------------------------------------------- */

static int tracer_find_copy_symbols(struct tracer *tracer)
{
	char line[512], name[256], type;
	unsigned long long address;
	FILE *kallsyms = fopen("/proc/kallsyms", "re");

	if (!kallsyms)
		return -errno;
	while (fgets(line, sizeof(line), kallsyms)) {
		if (sscanf(line, "%llx %c %255s", &address, &type, name) != 3)
			continue;
		if (strcmp(name, "bio_copy_user_iov") &&
		    strncmp(name, "bio_copy_user_iov.", 18))
			continue;
		if (tracer->copy_symbol_count == MAX_COPY_SYMBOLS)
			break;
		snprintf(tracer->copy_symbols[tracer->copy_symbol_count++],
			 sizeof(tracer->copy_symbols[0]), "%s", name);
	}
	fclose(kallsyms);
	return 0;
}

static void tracer_teardown(struct tracer *tracer)
{
	static const char *const enables[] = {
		"events/" TRACE_GROUP "/enable",
		"events/io_uring/io_uring_queue_async_work/enable",
		"events/block/block_split/enable",
	};
	char text[128];
	unsigned int index;

	if (tracer->instance_made) {
		for (index = 0; index < sizeof(enables) / sizeof(enables[0]);
		     index++)
			writef("0", false, "%s/%s", tracer->instance,
			       enables[index]);
		if (rmdir(tracer->instance))
			fprintf(stderr, "warning: rmdir %s: %s\n",
				tracer->instance, strerror(errno));
		tracer->instance_made = false;
	}
	if (tracer->kprobes_added) {
		static const char *const events[] = {
			"xdev_ext_sgl_kmalloc", "xdev_ext_sgl_freepages", "xdev_ext_sgl_mapret",
		};

		for (index = 0; index < 3; index++) {
			snprintf(text, sizeof(text), "-:%s/%s\n", TRACE_GROUP,
				 events[index]);
			writef(text, true, "%s/kprobe_events", tracer->root);
		}
		for (index = 0; index < tracer->copy_symbol_count; index++) {
			snprintf(text, sizeof(text), "-:%s/xdev_ext_sgl_copy%u\n",
				 TRACE_GROUP, index);
			writef(text, true, "%s/kprobe_events", tracer->root);
		}
		tracer->kprobes_added = false;
	}
}

static int tracer_setup(struct tracer *tracer, const char *root, dev_t rdev)
{
	char text[512];
	unsigned int index;
	int ret;

	memset(tracer, 0, sizeof(*tracer));
	if (strlen(root) >= sizeof(tracer->root))
		return -ENAMETOOLONG;
	snprintf(tracer->root, sizeof(tracer->root), "%s", root);
	snprintf(tracer->instance, sizeof(tracer->instance), "%s/instances/%s",
		 root, TRACE_INSTANCE);
	ret = tracer_find_copy_symbols(tracer);
	if (ret)
		return ret;
	/* A previous failed run may have left the instance behind. */
	tracer->instance_made = access(tracer->instance, F_OK) == 0;
	tracer->kprobes_added = true;
	tracer_teardown(tracer);

	tracer->kprobes_added = true;
	ret = writef("p:" TRACE_GROUP "/xdev_ext_sgl_kmalloc bio_kmalloc\n", true,
		     "%s/kprobe_events", root);
	if (!ret)
		ret = writef("p:" TRACE_GROUP "/xdev_ext_sgl_freepages bio_free_pages\n",
			     true, "%s/kprobe_events", root);
	if (!ret)
		ret = writef("r:" TRACE_GROUP "/xdev_ext_sgl_mapret blk_rq_map_user_iov ret=$retval:s32\n",
			     true, "%s/kprobe_events", root);
	for (index = 0; !ret && index < tracer->copy_symbol_count; index++) {
		snprintf(text, sizeof(text), "p:%s/xdev_ext_sgl_copy%u %s\n",
			 TRACE_GROUP, index, tracer->copy_symbols[index]);
		ret = writef(text, true, "%s/kprobe_events", root);
	}
	if (ret) {
		fprintf(stderr, "kprobe_events: %s\n", strerror(-ret));
		return ret;
	}
	if (mkdir(tracer->instance, 0700))
		return -errno;
	tracer->instance_made = true;
	ret = writef("1", false, "%s/options/stacktrace", tracer->instance);
	if (!ret)
		ret = writef("4096", false, "%s/buffer_size_kb", tracer->instance);
	if (!ret)
		ret = writef("ret == -11", false,
			     "%s/events/" TRACE_GROUP "/xdev_ext_sgl_mapret/filter",
			     tracer->instance);
	if (!ret) {
		/* The tracepoint stores the kernel dev_t: major << 20 | minor. */
		snprintf(text, sizeof(text), "dev == %u",
			 (major(rdev) << 20) | minor(rdev));
		ret = writef(text, false, "%s/events/block/block_split/filter",
			     tracer->instance);
	}
	if (!ret)
		ret = writef("1", false, "%s/events/" TRACE_GROUP "/enable",
			     tracer->instance);
	if (!ret)
		ret = writef("1", false,
			     "%s/events/io_uring/io_uring_queue_async_work/enable",
			     tracer->instance);
	if (!ret)
		ret = writef("1", false, "%s/events/block/block_split/enable",
			     tracer->instance);
	if (!ret)
		ret = writef("1", false, "%s/tracing_on", tracer->instance);
	if (ret)
		fprintf(stderr, "trace instance setup: %s\n", strerror(-ret));
	return ret;
}

/* Sum the kprobe_profile hit and miss counts of the bio_copy_user_iov probes. */
static int profile_copy_hits(struct tracer *tracer, unsigned long long *hits,
			     unsigned long long *missed)
{
	char path[PATH_MAX], *text, *line, *save = NULL;
	unsigned long long hit, miss;
	char name[128];

	*hits = 0;
	*missed = 0;
	snprintf(path, sizeof(path), "%s/kprobe_profile", tracer->root);
	text = read_all(path, NULL);
	if (!text)
		return -EIO;
	for (line = strtok_r(text, "\n", &save); line;
	     line = strtok_r(NULL, "\n", &save)) {
		if (sscanf(line, "%127s %llu %llu", name, &hit, &miss) != 3)
			continue;
		if (strncmp(name, "xdev_ext_sgl_", 7))
			continue;
		*missed += miss;
		if (!strncmp(name, "xdev_ext_sgl_copy", 11))
			*hits += hit;
	}
	free(text);
	return 0;
}

static int tracer_begin(struct tracer *tracer)
{
	unsigned long long missed;
	int ret;

	ret = writef("", false, "%s/trace", tracer->instance);
	if (ret)
		return ret;
	return profile_copy_hits(tracer, &tracer->profile_before, &missed);
}

/* Print the step's events with their stacks, for diagnosis. */
static void dump_trace(struct tracer *tracer)
{
	char path[PATH_MAX], *text, *line, *save = NULL;
	unsigned int printed = 0;

	snprintf(path, sizeof(path), "%s/trace", tracer->instance);
	text = read_all(path, NULL);
	if (!text)
		return;
	for (line = strtok_r(text, "\n", &save); line && printed < 120;
	     line = strtok_r(NULL, "\n", &save)) {
		if (line[0] == '#')
			continue;
		printf("# trace| %s\n", line);
		printed++;
	}
	free(text);
}

enum pending_event {
	PENDING_NONE,
	PENDING_KMALLOC,
	PENDING_FREEPAGES,
};

static bool starts_with(const char *text, const char *prefix)
{
	return !strncmp(text, prefix, strlen(prefix));
}

/*
 * Count the events in the instance buffer since tracer_begin().  With the
 * stacktrace option every event line is followed by a "<stack trace>" entry
 * and " => function" lines; a bio_kmalloc()/bio_free_pages() hit counts as
 * part of the bounce copy only if its stack holds the bounce caller.
 */
static int tracer_end(struct tracer *tracer, struct counts *counts)
{
	enum pending_event pending = PENDING_NONE;
	char path[PATH_MAX], *text, *line, *save = NULL;
	unsigned long long hits, missed;
	bool matched = false;
	int ret;

	memset(counts, 0, sizeof(*counts));
	snprintf(path, sizeof(path), "%s/trace", tracer->instance);
	text = read_all(path, NULL);
	if (!text)
		return -EIO;
	for (line = strtok_r(text, "\n", &save); ; line = strtok_r(NULL, "\n", &save)) {
		const char *frame = line ? line + strspn(line, " ") : NULL;

		if (line && (line[0] == '#' || strstr(line, "<stack trace>")))
			continue;
		if (frame && starts_with(frame, "=> ")) {
			frame += 3;
			if ((pending == PENDING_KMALLOC &&
			     starts_with(frame, "blk_rq_map_user")) ||
			    (pending == PENDING_FREEPAGES &&
			     starts_with(frame, "blk_rq_unmap_user")))
				matched = true;
			continue;
		}
		/* A new event (or the end) closes the previous event's stack. */
		if (pending == PENDING_KMALLOC && matched)
			counts->copy_alloc++;
		if (pending == PENDING_FREEPAGES && matched)
			counts->copy_free++;
		pending = PENDING_NONE;
		matched = false;
		if (!line)
			break;
		if (strstr(line, "xdev_ext_sgl_kmalloc:")) {
			counts->kmalloc_all++;
			pending = PENDING_KMALLOC;
		} else if (strstr(line, "xdev_ext_sgl_freepages:")) {
			counts->freepages_all++;
			pending = PENDING_FREEPAGES;
		} else if (strstr(line, "xdev_ext_sgl_mapret:")) {
			counts->map_eagain++;
		} else if (strstr(line, "io_uring_queue_async_work:")) {
			counts->iowq++;
		} else if (strstr(line, "block_split:")) {
			counts->splits++;
		}
	}
	if (counts->kmalloc_all || counts->freepages_all || counts->map_eagain ||
	    counts->iowq)
		dump_trace(tracer);
	free(text);
	ret = profile_copy_hits(tracer, &hits, &missed);
	if (ret)
		return ret;
	if (missed) {
		fprintf(stderr, "kprobe_profile reports %llu missed hits\n",
			missed);
		return -EOVERFLOW;
	}
	counts->copy_direct = tracer->copy_symbol_count ?
		(long long)(hits - tracer->profile_before) : -1;
	return 0;
}

static void print_counts(const char *label, const struct counts *counts)
{
	printf("# %s: copy_alloc=%lld copy_free=%lld copy_direct=%lld map_eagain=%lld iowq=%lld splits=%lld kmalloc_all=%lld freepages_all=%lld\n",
	       label, counts->copy_alloc, counts->copy_free,
	       counts->copy_direct, counts->map_eagain, counts->iowq,
	       counts->splits, counts->kmalloc_all, counts->freepages_all);
}

/*
 * The bounce count of one step.  bio_copy_user_iov() always allocates its
 * bio with bio_kmalloc() and its pages are freed with bio_free_pages() when
 * the request is unmapped, so a step with no bio_kmalloc() call anywhere in
 * the kernel had no bounce copy, and a step with bounces makes one call of
 * each per bounced bio.  The two counts must agree, and so must a direct
 * bio_copy_user_iov probe when that symbol exists; otherwise -1.  The
 * stack-attributed counts are printed for diagnosis only.
 */
static long long bounce_count(const struct counts *counts)
{
	if (counts->kmalloc_all != counts->freepages_all)
		return -1;
	if (counts->copy_direct >= 0 &&
	    counts->copy_direct != counts->kmalloc_all)
		return -1;
	return counts->kmalloc_all;
}

/* ---- data helpers ------------------------------------------------------ */

static void *map_pages(size_t pages, uint8_t fill)
{
	void *area = mmap(NULL, pages * FRAME_SIZE, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (area == MAP_FAILED)
		return NULL;
	/* Order-0 pages, faulted in by the fill below, before any pinning. */
	madvise(area, pages * FRAME_SIZE, MADV_NOHUGEPAGE);
	memset(area, fill, pages * FRAME_SIZE);
	return area;
}

static void fill_expected(uint8_t *buffer, const struct region *region)
{
	uint64_t base = region->lba * LBA_SIZE;
	uint64_t index;

	for (index = 0; index < (uint64_t)region->sectors * LBA_SIZE; index++)
		buffer[index] = pattern_byte(base + index, region->seed);
}

/* Scatter @expected into @area along @segments; returns the vector. */
static void build_vector(uint8_t *area, const struct segment *segments,
			 unsigned int count, const uint8_t *expected,
			 struct iovec *vector)
{
	size_t done = 0;
	unsigned int index;

	for (index = 0; index < count; index++) {
		uint8_t *base = area + (size_t)segments[index].page * FRAME_SIZE +
			segments[index].offset;

		if (expected)
			memcpy(base, expected + done, segments[index].length);
		vector[index].iov_base = base;
		vector[index].iov_len = segments[index].length;
		done += segments[index].length;
	}
}

/* Segment bytes equal @expected and every other byte still holds @guard. */
static bool gathered_matches(const uint8_t *area, size_t pages,
			     const struct segment *segments, unsigned int count,
			     const uint8_t *expected, uint8_t guard,
			     bool *guard_ok)
{
	uint8_t *covered = calloc(pages, FRAME_SIZE);
	size_t done = 0, index;
	bool data_ok = true;
	unsigned int segment;

	*guard_ok = covered != NULL;
	if (!covered)
		return false;
	for (segment = 0; segment < count; segment++) {
		size_t start = (size_t)segments[segment].page * FRAME_SIZE +
			segments[segment].offset;

		if (memcmp(area + start, expected + done,
			   segments[segment].length))
			data_ok = false;
		memset(covered + start, 1, segments[segment].length);
		done += segments[segment].length;
	}
	for (index = 0; index < pages * FRAME_SIZE; index++)
		if (!covered[index] && area[index] != guard)
			*guard_ok = false;
	free(covered);
	return data_ok;
}

static bool odirect_read_matches(int fd, const struct region *region,
				 const uint8_t *expected)
{
	size_t bytes = (size_t)region->sectors * LBA_SIZE;
	void *buffer = NULL;
	bool ok;

	if (posix_memalign(&buffer, FRAME_SIZE, bytes))
		return false;
	memset(buffer, 0, bytes);
	ok = pread(fd, buffer, bytes, (off_t)(region->lba * LBA_SIZE)) ==
		(ssize_t)bytes && !memcmp(buffer, expected, bytes);
	free(buffer);
	return ok;
}

/* ---- the checks -------------------------------------------------------- */

struct context {
	struct options options;
	struct ring ring;
	struct tracer tracer;
	int controller_fd;
	int generic_fd;
	int block_fd;
	uint32_t nsid;
	uint64_t virt_boundary_mask;
	uint64_t max_segments;
	uint32_t sgls;
	uint8_t *pipeline_area;
	uint8_t *readback_area;
	uint8_t *control_area;
};

static bool run_traced(struct context *context, const struct command *command,
		       int32_t *result, struct counts *counts, const char *label)
{
	int ret = tracer_begin(&context->tracer);

	if (!ret)
		ret = ring_execute(&context->ring, command, result);
	if (!ret)
		ret = tracer_end(&context->tracer, counts);
	if (ret) {
		fprintf(stderr, "%s: transport error %s\n", label, strerror(-ret));
		return false;
	}
	print_counts(label, counts);
	return true;
}

static void check_queue(struct context *context)
{
	struct command identify = {
		.fd = context->controller_fd,
		.cmd_op = NVME_URING_CMD_ADMIN,
		.opcode = NVME_ADMIN_IDENTIFY,
		.cdw10 = NVME_ID_CNS_CTRL,
		.data_len = IDENTIFY_BYTES,
	};
	char path[PATH_MAX], serial[IDENTIFY_SERIAL_BYTES + 1];
	uint8_t *data = NULL;
	int32_t result = -1;
	bool sgl_supported;
	size_t length;
	int ret;

	if (posix_memalign((void **)&data, FRAME_SIZE, IDENTIFY_BYTES))
		data = NULL;
	identify.addr = (uintptr_t)data;
	ret = data ? ring_execute(&context->ring, &identify, &result) : -ENOMEM;
	check(!ret && result == 0, "Identify Controller completes (res=%d)",
	      ret ? ret : result);
	if (!data || ret || result) {
		free(data);
		return;
	}
	memcpy(serial, data + IDENTIFY_SERIAL_OFFSET, IDENTIFY_SERIAL_BYTES);
	serial[IDENTIFY_SERIAL_BYTES] = '\0';
	for (length = IDENTIFY_SERIAL_BYTES; length && serial[length - 1] == ' ';
	     length--)
		serial[length - 1] = '\0';
	check(!strcmp(serial, EXPECTED_SERIAL),
	      "Identify serial '%s' is the dedicated controller", serial);
	memcpy(&context->sgls, data + IDENTIFY_SGLS_OFFSET, sizeof(context->sgls));
	free(data);
	sgl_supported = context->sgls & 0x3U;
	snprintf(path, sizeof(path), "/sys/class/block/%s/queue/virt_boundary_mask",
		 context->options.block);
	ret = read_u64(path, &context->virt_boundary_mask);
	if (!ret) {
		snprintf(path, sizeof(path),
			 "/sys/class/block/%s/queue/max_segments",
			 context->options.block);
		ret = read_u64(path, &context->max_segments);
	}
	check(!ret, "queue limits readable (virt_boundary_mask=%" PRIu64
	      " max_segments=%" PRIu64 ")", context->virt_boundary_mask,
	      context->max_segments);
	printf("XDEV_EXT_NVME_SGL_QUEUE controller=%s block=%s serial=%s sgls=0x%08x sgl_supported=%d virt_boundary_mask=%" PRIu64 " max_segments=%" PRIu64 "\n",
	       context->options.controller, context->options.block, serial,
	       context->sgls, sgl_supported, context->virt_boundary_mask,
	       context->max_segments);
	check(sgl_supported, "controller reports SGL support (sgls=0x%08x)",
	      context->sgls);
	check(!sgl_supported || context->virt_boundary_mask == 0,
	      "SGL-capable I/O queue reports virt_boundary_mask 0 (got %" PRIu64 ")",
	      context->virt_boundary_mask);
	check(context->max_segments > 0 && context->max_segments < WIDE_SEGMENTS,
	      "max_segments %" PRIu64 " is below the %u-segment control",
	      context->max_segments, WIDE_SEGMENTS);
}

static void pipeline_segments(struct segment *segments)
{
	/* Frames out of order, as AF_XDP RX hands them back. */
	static const unsigned int frames[PIPELINE_SEGMENTS] = { 3, 0, 7, 2, 9, 5 };
	unsigned int index;

	for (index = 0; index < PIPELINE_SEGMENTS; index++) {
		segments[index].page = frames[index];
		segments[index].offset = PIPELINE_OFFSET;
		segments[index].length = index + 1 < PIPELINE_SEGMENTS ?
			PIPELINE_SEGMENT : PIPELINE_LAST;
	}
}

static void check_pipeline(struct context *context)
{
	const struct region *region = &sgl_regions[REGION_PIPELINE];
	struct segment segments[PIPELINE_SEGMENTS];
	struct iovec vector[PIPELINE_SEGMENTS];
	uint8_t expected[PIPELINE_BYTES];
	struct command command = {
		.fd = context->generic_fd,
		.cmd_op = NVME_URING_CMD_IO_VEC,
		.nsid = context->nsid,
		.data_len = PIPELINE_SEGMENTS,
		.cdw10 = (uint32_t)region->lba,
		.cdw11 = (uint32_t)(region->lba >> 32),
		.cdw12 = region->sectors - 1,
		.rsvd2 = XDEV_EXT_FLAG_OPT_IN,
		.fixed = true,
	};
	struct counts counts;
	int32_t result = -1;
	long long bounce;
	bool guard_ok, ok;

	pipeline_segments(segments);
	fill_expected(expected, region);
	build_vector(context->pipeline_area, segments, PIPELINE_SEGMENTS,
		     expected, vector);
	command.opcode = NVME_OP_WRITE;
	command.addr = (uintptr_t)vector;
	command.buf_index = 0;
	ok = run_traced(context, &command, &result, &counts, "pipeline-write");
	bounce = bounce_count(&counts);
	check(ok && result == 0, "pipeline fixed IO_VEC WRITE completes (res=%d)",
	      result);
	check(ok && bounce == 0,
	      "pipeline WRITE is not bounce-copied (bounce=%lld)", bounce);
	check(ok && counts.map_eagain == 0,
	      "pipeline WRITE mapping never returns -EAGAIN (count=%lld)",
	      counts.map_eagain);
	check(ok && counts.iowq == 0,
	      "pipeline WRITE is not retried from io-wq (count=%lld)", counts.iowq);
	check(odirect_read_matches(context->block_fd, region, expected),
	      "pipeline WRITE bytes read back exactly (O_DIRECT)");
	printf("XDEV_EXT_NVME_SGL_PIPELINE_WRITE res=%d bounce=%lld map_eagain=%lld iowq=%lld segments=%u bytes=%u\n",
	       result, bounce, counts.map_eagain, counts.iowq,
	       PIPELINE_SEGMENTS, PIPELINE_BYTES);
	if (context->ring.poisoned)
		return;

	build_vector(context->readback_area, segments, PIPELINE_SEGMENTS, NULL,
		     vector);
	command.opcode = NVME_OP_READ;
	command.buf_index = 1;
	result = -1;
	ok = run_traced(context, &command, &result, &counts, "pipeline-read");
	bounce = bounce_count(&counts);
	check(ok && result == 0, "pipeline fixed IO_VEC READ completes (res=%d)",
	      result);
	check(ok && bounce == 0,
	      "pipeline READ is not bounce-copied (bounce=%lld)", bounce);
	check(ok && counts.map_eagain == 0 && counts.iowq == 0,
	      "pipeline READ needs no -EAGAIN/io-wq retry (eagain=%lld iowq=%lld)",
	      counts.map_eagain, counts.iowq);
	ok = gathered_matches(context->readback_area, PIPELINE_BUFFER_FRAMES,
			      segments, PIPELINE_SEGMENTS, expected, GUARD_READ,
			      &guard_ok);
	check(ok, "pipeline READ segments hold the written bytes");
	check(guard_ok, "pipeline READ wrote nothing outside its segments");
	printf("XDEV_EXT_NVME_SGL_PIPELINE_READ res=%d bounce=%lld map_eagain=%lld iowq=%lld data=%s guard=%s\n",
	       result, bounce, counts.map_eagain, counts.iowq,
	       ok ? "PASS" : "FAIL", guard_ok ? "PASS" : "FAIL");
}

static void check_control(struct context *context)
{
	const struct region *region = &sgl_regions[REGION_CONTROL];
	struct segment *segments = calloc(WIDE_SEGMENTS, sizeof(*segments));
	struct iovec *vector = calloc(WIDE_SEGMENTS, sizeof(*vector));
	uint8_t *expected = malloc((size_t)region->sectors * LBA_SIZE);
	struct command command = {
		.fd = context->generic_fd,
		.cmd_op = NVME_URING_CMD_IO_VEC,
		.opcode = NVME_OP_WRITE,
		.nsid = context->nsid,
		.data_len = WIDE_SEGMENTS,
		.cdw10 = (uint32_t)region->lba,
		.cdw11 = (uint32_t)(region->lba >> 32),
		.cdw12 = region->sectors - 1,
		.fixed = true,
		.buf_index = 2,
	};
	struct counts counts;
	int32_t result = -1;
	unsigned int index;
	long long bounce;
	bool ok;

	if (!segments || !vector || !expected) {
		check(false, "control allocation");
		goto out;
	}
	for (index = 0; index < WIDE_SEGMENTS; index++)
		segments[index] = (struct segment){ index, 0, LBA_SIZE };
	fill_expected(expected, region);
	build_vector(context->control_area, segments, WIDE_SEGMENTS, expected,
		     vector);
	command.addr = (uintptr_t)vector;
	ok = run_traced(context, &command, &result, &counts, "control-write");
	bounce = bounce_count(&counts);
	check(ok && result == 0,
	      "control: %u-segment fixed IO_VEC WRITE completes (res=%d)",
	      WIDE_SEGMENTS, result);
	check(ok && bounce == 1,
	      "control: a vector above max_segments is still bounced once (bounce=%lld)",
	      bounce);
	check(ok && counts.map_eagain >= 1 && counts.iowq >= 1,
	      "control: its nonblocking issue returns -EAGAIN and io-wq retries (eagain=%lld iowq=%lld)",
	      counts.map_eagain, counts.iowq);
	check(odirect_read_matches(context->block_fd, region, expected),
	      "control WRITE bytes read back exactly (O_DIRECT)");
	printf("XDEV_EXT_NVME_SGL_BOUNCE_CONTROL segments=%u res=%d bounce=%lld map_eagain=%lld iowq=%lld\n",
	       WIDE_SEGMENTS, result, bounce, counts.map_eagain, counts.iowq);
out:
	free(segments);
	free(vector);
	free(expected);
}

static unsigned int layout_pages(const struct segment *segments,
				 unsigned int count)
{
	unsigned int pages = 0, index;

	for (index = 0; index < count; index++) {
		unsigned int end = segments[index].page +
			(segments[index].offset + segments[index].length +
			 FRAME_SIZE - 1) / FRAME_SIZE;

		if (end > pages)
			pages = end;
	}
	return pages + 1;
}

static bool splits_as_predicted(const struct context *context,
				unsigned int vectors_pages, long long splits)
{
	if (context->virt_boundary_mask == 0)
		return splits == (long long)((vectors_pages - 1) /
					     context->max_segments);
	return splits >= 1;
}

/* Write, verify contiguously, then read back through the same gapped vector. */
static void check_odirect_layout(struct context *context, const char *name,
				 const struct region *region,
				 const struct segment *segments,
				 unsigned int count, unsigned int bvecs)
{
	size_t bytes = (size_t)region->sectors * LBA_SIZE;
	unsigned int pages = layout_pages(segments, count);
	struct iovec *vector = calloc(count, sizeof(*vector));
	uint8_t *expected = malloc(bytes);
	uint8_t *area = map_pages(pages, GUARD_WRITE);
	long long write_splits = -1, read_splits = -1;
	bool data_ok = false, guard_ok = false;
	bool verify_ok = false;
	struct counts counts;
	ssize_t done = -1;
	size_t total = 0;
	unsigned int index;
	int io_errno = 0;

	if (!vector || !expected || !area) {
		check(false, "%s allocation", name);
		goto out;
	}
	for (index = 0; index < count; index++)
		total += segments[index].length;
	if (total != bytes) {
		check(false, "%s layout covers %zu bytes, region %zu", name,
		      total, bytes);
		goto out;
	}
	fill_expected(expected, region);
	build_vector(area, segments, count, expected, vector);
	if (!tracer_begin(&context->tracer)) {
		done = pwritev(context->block_fd, vector, (int)count,
			       (off_t)(region->lba * LBA_SIZE));
		io_errno = done < 0 ? errno : 0;
		if (!tracer_end(&context->tracer, &counts)) {
			write_splits = counts.splits;
			print_counts(name, &counts);
		}
	}
	check(done == (ssize_t)bytes, "%s O_DIRECT pwritev of %u gapped vectors (ret=%zd errno=%d)",
	      name, count, done, io_errno);
	verify_ok = done == (ssize_t)bytes &&
		odirect_read_matches(context->block_fd, region, expected);
	check(verify_ok, "%s written bytes read back exactly (contiguous O_DIRECT)",
	      name);
	check(splits_as_predicted(context, bvecs, write_splits),
	      "%s write splits=%lld as virt_boundary_mask=%" PRIu64 " max_segments=%" PRIu64 " predict",
	      name, write_splits, context->virt_boundary_mask,
	      context->max_segments);
	/*
	 * Read back through the gapped vector only after the data verified:
	 * a gapped request misrouted to PRP would also DMA reads to the wrong
	 * pages.
	 */
	if (verify_ok) {
		munmap(area, (size_t)pages * FRAME_SIZE);
		area = map_pages(pages, GUARD_READ);
		if (!area) {
			check(false, "%s read allocation", name);
			goto out;
		}
		build_vector(area, segments, count, NULL, vector);
		done = -1;
		if (!tracer_begin(&context->tracer)) {
			done = preadv(context->block_fd, vector, (int)count,
				      (off_t)(region->lba * LBA_SIZE));
			io_errno = done < 0 ? errno : 0;
			if (!tracer_end(&context->tracer, &counts)) {
				read_splits = counts.splits;
				print_counts(name, &counts);
			}
		}
		check(done == (ssize_t)bytes,
		      "%s O_DIRECT preadv of the gapped vectors (ret=%zd errno=%d)",
		      name, done, io_errno);
		data_ok = done == (ssize_t)bytes &&
			gathered_matches(area, pages, segments, count, expected,
					 GUARD_READ, &guard_ok);
		check(data_ok, "%s gapped read returns the written bytes", name);
		check(guard_ok, "%s gapped read wrote nothing outside its vectors",
		      name);
		check(splits_as_predicted(context, bvecs, read_splits),
		      "%s read splits=%lld as the queue limits predict", name,
		      read_splits);
	}
	printf("XDEV_EXT_NVME_SGL_ODIRECT layout=%s vectors=%u bytes=%zu write_splits=%lld read_splits=%lld write_data=%s read_data=%s guard=%s\n",
	       name, count, bytes, write_splits, read_splits,
	       verify_ok ? "PASS" : "FAIL", data_ok ? "PASS" : "FAIL",
	       guard_ok ? "PASS" : "FAIL");
out:
	if (area)
		munmap(area, (size_t)pages * FRAME_SIZE);
	free(vector);
	free(expected);
}

static void check_odirect(struct context *context)
{
	struct segment *wide = calloc(WIDE_SEGMENTS, sizeof(*wide));
	unsigned int index;

	/* L1: five vectors, the last crossing a page: six bvecs. */
	check_odirect_layout(context, "odirect-l1", &sgl_regions[REGION_L1],
			     layout_l1, sizeof(layout_l1) / sizeof(layout_l1[0]),
			     6);
	check_odirect_layout(context, "odirect-l2", &sgl_regions[REGION_L2],
			     layout_l2, sizeof(layout_l2) / sizeof(layout_l2[0]),
			     3);
	if (!wide) {
		check(false, "odirect-l3 allocation");
		return;
	}
	/* L3: more gapped vectors than max_segments, so the bio is split. */
	for (index = 0; index < WIDE_SEGMENTS; index++)
		wide[index] = (struct segment){ index, 1024, LBA_SIZE };
	check_odirect_layout(context, "odirect-l3", &sgl_regions[REGION_L3],
			     wide, WIDE_SEGMENTS, WIDE_SEGMENTS);
	free(wide);
}

static void check_admin(struct context *context)
{
	struct command command = {
		.fd = context->controller_fd,
		.opcode = NVME_ADMIN_IDENTIFY,
		.cdw10 = NVME_ID_CNS_CTRL,
	};
	uint8_t *reference = NULL, *area = map_pages(4, GUARD_READ);
	uint8_t gathered[IDENTIFY_BYTES];
	struct iovec vector[2];
	struct counts counts;
	int32_t result = -1;
	long long bounce;
	bool ok;

	if (!area || posix_memalign((void **)&reference, FRAME_SIZE,
				    IDENTIFY_BYTES)) {
		check(false, "admin allocation");
		goto out;
	}
	memset(reference, 0, IDENTIFY_BYTES);
	command.cmd_op = NVME_URING_CMD_ADMIN;
	command.addr = (uintptr_t)reference;
	command.data_len = IDENTIFY_BYTES;
	ok = run_traced(context, &command, &result, &counts, "admin-contiguous");
	check(ok && result == 0, "admin Identify into a contiguous buffer (res=%d)",
	      result);
	vector[0].iov_base = area + 4;
	vector[0].iov_len = IDENTIFY_BYTES / 2;
	vector[1].iov_base = area + 2 * FRAME_SIZE + 1028;
	vector[1].iov_len = IDENTIFY_BYTES / 2;
	command.cmd_op = NVME_URING_CMD_ADMIN_VEC;
	command.addr = (uintptr_t)vector;
	command.data_len = 2;
	result = -1;
	ok = run_traced(context, &command, &result, &counts, "admin-gapped");
	bounce = bounce_count(&counts);
	check(ok && result == 0, "admin Identify into a gapped vector (res=%d)",
	      result);
	check(ok && bounce == 1,
	      "admin queue keeps its 4 KiB boundary: gapped vector bounced once (bounce=%lld)",
	      bounce);
	memcpy(gathered, vector[0].iov_base, IDENTIFY_BYTES / 2);
	memcpy(gathered + IDENTIFY_BYTES / 2, vector[1].iov_base,
	       IDENTIFY_BYTES / 2);
	ok = ok && result == 0 && !memcmp(gathered, reference, IDENTIFY_BYTES);
	check(ok, "gapped admin Identify equals the contiguous Identify");
	printf("XDEV_EXT_NVME_SGL_ADMIN res=%d gapped_bounce=%lld data=%s\n", result,
	       bounce, ok ? "PASS" : "FAIL");
out:
	if (area)
		munmap(area, 4 * FRAME_SIZE);
	free(reference);
}

/* ---- main -------------------------------------------------------------- */

static int parse(int argc, char **argv, struct options *options)
{
	int index;

	memset(options, 0, sizeof(*options));
	for (index = 1; index < argc; index++) {
		const char **slot = NULL;

		if (!strcmp(argv[index], "--controller"))
			slot = &options->controller;
		else if (!strcmp(argv[index], "--block"))
			slot = &options->block;
		else if (!strcmp(argv[index], "--generic"))
			slot = &options->generic;
		else if (!strcmp(argv[index], "--tracefs"))
			slot = &options->tracefs;
		else if (!strcmp(argv[index], "--allow-write")) {
			if (options->allow_write)
				return -EINVAL;
			options->allow_write = true;
			continue;
		} else {
			return -EINVAL;
		}
		if (*slot || index + 1 == argc)
			return -EINVAL;
		*slot = argv[++index];
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct context context = {
		.controller_fd = -1, .generic_fd = -1, .block_fd = -1,
	};
	struct iovec buffers[3];
	char path[PATH_MAX];
	uint64_t lba_size, sectors;
	struct stat block_stat;
	bool tracing = false;
	unsigned int index;
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (parse(argc, argv, &context.options)) {
		fprintf(stderr, "usage: %s --controller nvmeN --block nvmeNnM --generic ngNnM --tracefs DIR --allow-write\n",
			argv[0]);
		return 1;
	}
	if (!context.options.controller && !context.options.block &&
	    !context.options.generic) {
		printf("ok 1 # SKIP needs the dedicated KVM guest controller (--controller)\n");
		return KSFT_SKIP;
	}
	if (!context.options.controller || !context.options.block ||
	    !context.options.generic || !context.options.tracefs ||
	    !context.options.allow_write) {
		fprintf(stderr, "REFUSE: --controller, --block, --generic, --tracefs and --allow-write are all required\n");
		return 1;
	}
	if (safety_gate(&context.options))
		return 1;

	snprintf(path, sizeof(path), "/sys/class/block/%s/queue/logical_block_size",
		 context.options.block);
	if (read_u64(path, &lba_size) || lba_size != LBA_SIZE) {
		fprintf(stderr, "REFUSE: logical block size is not %u\n", LBA_SIZE);
		return 1;
	}
	snprintf(path, sizeof(path), "/sys/class/block/%s/size",
		 context.options.block);
	for (index = 0; index < sizeof(sgl_regions) / sizeof(sgl_regions[0]);
	     index++)
		if (read_u64(path, &sectors) ||
		    sgl_regions[index].lba + sgl_regions[index].sectors > sectors) {
			fprintf(stderr, "REFUSE: namespace too small for %s\n",
				sgl_regions[index].name);
			return 1;
		}
	snprintf(path, sizeof(path), "/dev/%s", context.options.block);
	/* O_EXCL holds the namespace against mounts for the whole run. */
	context.block_fd = open(path, O_RDWR | O_DIRECT | O_EXCL | O_CLOEXEC);
	if (context.block_fd < 0 || fstat(context.block_fd, &block_stat)) {
		fprintf(stderr, "REFUSE: cannot exclusively open %s: %s\n", path,
			strerror(errno));
		return 1;
	}
	snprintf(path, sizeof(path), "/dev/%s", context.options.generic);
	context.generic_fd = open(path, O_RDWR | O_CLOEXEC);
	snprintf(path, sizeof(path), "/dev/%s", context.options.controller);
	context.controller_fd = open(path, O_RDWR | O_CLOEXEC);
	if (context.generic_fd < 0 || context.controller_fd < 0) {
		perror("open NVMe character devices");
		return 1;
	}
	ret = ioctl(context.generic_fd, NVME_IOCTL_ID);
	if (ret <= 0) {
		fprintf(stderr, "REFUSE: NVME_IOCTL_ID failed\n");
		return 1;
	}
	context.nsid = (uint32_t)ret;

	context.pipeline_area = map_pages(PIPELINE_BUFFER_FRAMES, GUARD_WRITE);
	context.readback_area = map_pages(PIPELINE_BUFFER_FRAMES, GUARD_READ);
	context.control_area = map_pages(WIDE_SEGMENTS, GUARD_WRITE);
	if (!context.pipeline_area || !context.readback_area ||
	    !context.control_area) {
		perror("mmap");
		return 1;
	}
	ret = ring_init(&context.ring);
	if (ret) {
		fprintf(stderr, "io_uring SQE128/CQE32 setup: %s\n", strerror(-ret));
		return 1;
	}
	buffers[0] = (struct iovec){ context.pipeline_area,
				     PIPELINE_BUFFER_FRAMES * FRAME_SIZE };
	buffers[1] = (struct iovec){ context.readback_area,
				     PIPELINE_BUFFER_FRAMES * FRAME_SIZE };
	buffers[2] = (struct iovec){ context.control_area,
				     WIDE_SEGMENTS * FRAME_SIZE };
	ret = ring_register(&context.ring, buffers, 3);
	if (ret) {
		fprintf(stderr, "io_uring buffer registration: %s\n", strerror(-ret));
		return 1;
	}

	printf("TAP version 13\n");
	for (index = 0; index < sizeof(sgl_regions) / sizeof(sgl_regions[0]);
	     index++)
		printf("XDEV_EXT_NVME_SGL_REGION name=%s lba=%" PRIu64 " sectors=%u seed=%u\n",
		       sgl_regions[index].name, sgl_regions[index].lba,
		       sgl_regions[index].sectors, sgl_regions[index].seed);

	check_queue(&context);
	ret = tracer_setup(&context.tracer, context.options.tracefs,
			   block_stat.st_rdev);
	check(!ret, "tracefs counters ready (bio_copy_user_iov symbols=%u)",
	      context.tracer.copy_symbol_count);
	printf("# bio_copy_user_iov %s\n", context.tracer.copy_symbol_count ?
	       "is an out-of-line symbol and is probed directly" :
	       "is inlined; counting its bio_kmalloc/bio_free_pages calls");
	tracing = !ret;
	if (tracing && !context.ring.poisoned)
		check_pipeline(&context);
	if (tracing && !context.ring.poisoned)
		check_control(&context);
	if (tracing && !context.ring.poisoned)
		check_odirect(&context);
	if (tracing && !context.ring.poisoned)
		check_admin(&context);
	if (context.ring.poisoned)
		check(false, "a command timed out or the ring failed; buffers retained");
	tracer_teardown(&context.tracer);

	printf("1..%u\n", checks);
	printf("XDEV_EXT_NVME_SGL_GAP_RESULT=%s checks=%u failures=%u virt_boundary_mask=%" PRIu64 " sgls=0x%08x\n",
	       failures ? "FAIL" : "PASS", checks, failures,
	       context.virt_boundary_mask, context.sgls);
	if (context.ring.poisoned) {
		/* In-flight commands may still own the buffers: exit only. */
		_exit(1);
	}
	ring_destroy(&context.ring);
	close(context.block_fd);
	close(context.generic_fd);
	close(context.controller_fd);
	return failures ? 1 : 0;
}
