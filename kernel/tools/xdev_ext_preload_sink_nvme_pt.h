/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_SINK_NVME_PT_H
#define XDEV_EXT_PRELOAD_SINK_NVME_PT_H

/*
 * NVMe passthrough write sink for the transparent fast path.
 *
 * An O_DIRECT pwrite on a whole NVMe namespace block device is served as one
 * NVMe Write on the namespace's generic character device (/dev/ngXnY),
 * submitted as a 128-byte IORING_OP_URING_CMD that carries
 * NVME_URING_CMD_F_XDEV_EXT, so the kernel runs its namespace admission and the
 * policy dispatch for the write (nvme_uring_cmd_io() in
 * drivers/nvme/host/ioctl.c).  The DMA source is the caller's own buffer: the
 * request is not vectored and not fixed, so the kernel pins the user pages
 * instead of bouncing them.
 *
 * Nothing here calls into libc for I/O.  The namespace probe reads sysfs and
 * /dev under configurable roots and issues every open, ioctl, fstat and cache
 * call through struct xdev_ext_nvme_pt_env; the write path publishes through
 * struct xdev_ext_nvme_pt_ring.  The export layer binds both to its real entry
 * points and its per-thread ring, and the unit test binds them to a fake tree.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

/* Always consume the ABI from this source tree. */
#include "../include/uapi/linux/io_uring.h"
#include "../include/uapi/linux/nvme_ioctl.h"
#include "xdev_ext_preload_sink.h"

/* Like xdev_ext_preload_core.h, this needs the GNU <fcntl.h> names. */
#ifndef O_DIRECT
#error "build with _GNU_SOURCE: O_DIRECT is required"
#endif

#define XDEV_EXT_NVME_PT_NAME		"nvme-pt"
/* Fixed-file slots registered in each thread's ring. */
#define XDEV_EXT_NVME_PT_SLOTS		16U
#define XDEV_EXT_NVME_PT_IDENTIFY_LEN	4096U
#define XDEV_EXT_NVME_PT_REPORT_MAX		512U

#define XDEV_EXT_NVME_PT_OPC_WRITE		0x01U
#define XDEV_EXT_NVME_PT_OPC_IDENTIFY	0x06U
#define XDEV_EXT_NVME_PT_CNS_NS		0x00U
/* NLB is a 0-based 16-bit field; the admission decodes cdw12 & 0xffff. */
#define XDEV_EXT_NVME_PT_NLB_MAX		65536U
/* The kernel admission accepts 512-byte and larger blocks only. */
#define XDEV_EXT_NVME_PT_MIN_LBA_SHIFT	9U
#define XDEV_EXT_NVME_PT_MAX_LBA_SHIFT	31U

/*
 * Identify Namespace byte offsets (struct nvme_id_ns in
 * include/linux/nvme.h, which user space cannot include).
 */
#define XDEV_EXT_NVME_ID_NS_NSZE		0
#define XDEV_EXT_NVME_ID_NS_NCAP		8
#define XDEV_EXT_NVME_ID_NS_NLBAF		25
#define XDEV_EXT_NVME_ID_NS_FLBAS		26
#define XDEV_EXT_NVME_ID_NS_DPS		29
#define XDEV_EXT_NVME_ID_NS_LBAF		128
#define XDEV_EXT_NVME_ID_NS_DPS_PI_MASK	0x07U

/* capget() v3, from include/uapi/linux/capability.h, which uses __user. */
#define XDEV_EXT_NVME_PT_CAP_VERSION_3	0x20080522U
#define XDEV_EXT_NVME_PT_CAP_SYS_ADMIN	21

/* Write back dirty page-cache pages over the range and wait for them. */
#define XDEV_EXT_NVME_PT_PRESYNC_FLAGS					\
	(SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE |		\
	 SYNC_FILE_RANGE_WAIT_AFTER)

/* Which probe check refused a descriptor; OK when it was taken over. */
enum xdev_ext_nvme_pt_stage {
	XDEV_EXT_NVME_PT_STAGE_OK = 0,
	XDEV_EXT_NVME_PT_STAGE_ARGS,		/* bad arguments, not a block device */
	XDEV_EXT_NVME_PT_STAGE_ACCESS,	/* not open for writing */
	XDEV_EXT_NVME_PT_STAGE_SYSFS,	/* no sysfs entry for the device */
	XDEV_EXT_NVME_PT_STAGE_PARTITION,
	XDEV_EXT_NVME_PT_STAGE_MULTIPATH,	/* native multipath head */
	XDEV_EXT_NVME_PT_STAGE_LAYOUT,	/* not .../nvme/nvmeC/nvmeSnH */
	XDEV_EXT_NVME_PT_STAGE_ATTRS,	/* not the NVM command set, read-only */
	XDEV_EXT_NVME_PT_STAGE_ANCHOR,	/* no matching generic node */
	XDEV_EXT_NVME_PT_STAGE_NSID,
	XDEV_EXT_NVME_PT_STAGE_IDENTIFY,
	XDEV_EXT_NVME_PT_STAGE_FORMAT,	/* metadata, PI, block size, unused */
	XDEV_EXT_NVME_PT_STAGE_CAPACITY,
	XDEV_EXT_NVME_PT_STAGE_LIMITS,
	XDEV_EXT_NVME_PT_STAGE_PRIVILEGE,
	XDEV_EXT_NVME_PT_STAGE_CACHE,	/* exclusive-mode write-back failed */
	XDEV_EXT_NVME_PT_STAGE_PRIVATE,	/* anchor stayed in the app's view */
	XDEV_EXT_NVME_PT_STAGE_NOMEM,
};

/*
 * System calls the sink makes, injected.  Every operation returns a
 * non-negative value on success or a negative errno; the export layer wraps
 * its real libc entry points (never the interposed ones) to that convention.
 * The table must outlive every namespace probed through it.
 */
struct xdev_ext_nvme_pt_env {
	const char *sysfs_root;		/* "/sys" */
	const char *dev_root;		/* "/dev" */
	bool exclusive;			/* XDEV_EXT_PRELOAD_BDEV_CACHE=exclusive */
	size_t page_size;		/* 0: sysconf(_SC_PAGESIZE) */
	void *opaque;
	int (*open)(void *opaque, const char *path, int flags);
	int (*close)(void *opaque, int fd);
	ssize_t (*read)(void *opaque, int fd, void *buf, size_t count);
	int (*fstat)(void *opaque, int fd, struct stat *st);
	/* fcntl(fd, F_GETFL) */
	int (*getfl)(void *opaque, int fd);
	int (*ioctl)(void *opaque, int fd, unsigned long request, void *arg);
	int (*sync_range)(void *opaque, int fd, int64_t offset, int64_t count,
			  unsigned int flags);
	/* posix_fadvise(), with its error number negated */
	int (*fadvise)(void *opaque, int fd, int64_t offset, int64_t count,
		       int advice);
	bool (*has_sys_admin)(void *opaque);
	/*
	 * Optional.  Move a front-end descriptor out of the application's
	 * view; returns the number now holding it.  On failure fd stays open.
	 */
	int (*make_private)(void *opaque, int fd);
};

/*
 * Updated with relaxed atomics by every thread writing through the
 * registration.  takeover counts published requests; takeover_bytes counts
 * the bytes of those that completed successfully; errors counts published
 * requests that returned an error, policy_denied and device_status_errors
 * being two kinds of them.  The fallback_* counters count calls handed to
 * libc and why.
 */
struct xdev_ext_nvme_pt_counters {
	uint64_t takeover;
	uint64_t takeover_bytes;
	uint64_t errors;
	uint64_t policy_denied;
	uint64_t device_status_errors;
	uint64_t fallback_ineligible;
	uint64_t fallback_vector;
	uint64_t fallback_sync_flags;
	uint64_t fallback_identity;
	uint64_t fallback_presync;
	uint64_t invalidate_errors;
};

/* Backend of one XDEV_EXT_REG_NS_PASSTHRU registration. */
struct xdev_ext_nvme_pt_ns {
	int anchor_fd;			/* /dev/ngXnY, private */
	dev_t ng_rdev;
	ino_t ng_ino;
	uint32_t nsid;
	uint8_t lba_shift;
	uint64_t capacity_lbas;
	uint32_t max_bytes;
	uint32_t dma_align_mask;
	dev_t bdev_rdev;
	char name[32];			/* nvmeSnH, as in /dev */
	bool exclusive;			/* XDEV_EXT_PRELOAD_BDEV_CACHE */
	uint64_t written_lo;		/* exclusive: [lo, hi) written */
	uint64_t written_hi;
	struct xdev_ext_nvme_pt_counters ctr;
	/* Identity of the application's node at registration (with rdev). */
	dev_t bdev_dev;
	ino_t bdev_ino;
	mode_t bdev_type;		/* st_mode & S_IFMT */
	uint32_t page_mask;		/* coherent: whole pages only */
	const struct xdev_ext_nvme_pt_env *env;
	uint8_t torn_down;
	uint8_t report_emitted;
};

/* The three trailing components of a namespace's resolved sysfs path. */
struct xdev_ext_nvme_pt_layout {
	uint32_t ctrl_instance;		/* nvmeC */
	uint32_t disk_instance;		/* nvmeS... */
	uint32_t head_instance;		/* ...nH */
	size_t ctrl_dir_len;		/* prefix up to and including nvmeC */
};

struct xdev_ext_nvme_pt_id_ns {
	uint64_t nsze;
	uint64_t ncap;
	uint16_t ms;
	uint8_t lba_shift;
	uint8_t pi_type;
	uint8_t lbaf_index;
};

enum xdev_ext_nvme_pt_verdict {
	XDEV_EXT_NVME_PT_ELIGIBLE = 0,
	XDEV_EXT_NVME_PT_INELIGIBLE,
	XDEV_EXT_NVME_PT_SYNC_FLAGS,		/* O_DSYNC, O_SYNC or O_APPEND */
};

enum xdev_ext_nvme_pt_cqe_class {
	XDEV_EXT_NVME_PT_CQE_OK = 0,
	XDEV_EXT_NVME_PT_CQE_ERRNO,
	XDEV_EXT_NVME_PT_CQE_POLICY_DENIED,
	XDEV_EXT_NVME_PT_CQE_DEVICE_STATUS,
};

/* One IORING_SETUP_SQE128 entry: struct io_uring_sqe plus its cmd[] area. */
struct xdev_ext_nvme_pt_sqe {
	union {
		struct io_uring_sqe sqe;
		uint8_t bytes[128];
	};
};

_Static_assert(sizeof(struct io_uring_sqe) == 64, "io_uring_sqe size");
_Static_assert(offsetof(struct io_uring_sqe, cmd) == 48, "sqe cmd offset");
_Static_assert(sizeof(struct xdev_ext_nvme_pt_sqe) == 128, "SQE128 size");
_Static_assert(sizeof(struct nvme_uring_cmd) <= 128 - 48,
	       "nvme_uring_cmd fits the SQE128 command area");

/* One call as the export layer hands it over. */
struct xdev_ext_nvme_pt_call {
	const struct xdev_ext_io *io;
	int status_flags;		/* the registration's cached F_GETFL */
	uint32_t slot;			/* fixed-file slot of the anchor */
	uint64_t user_data;		/* completion token */
};

/*
 * This thread's ring.  ready() returns 0 when the ring exists and the slot
 * holds the anchor (installing it if needed), else a negative errno; nothing
 * is published then.  submit_and_wait() publishes the entry once and waits
 * for its terminal completion; *published reports whether the entry reached
 * the ring, also when it returns an error.
 */
struct xdev_ext_nvme_pt_ring {
	void *opaque;
	int (*ready)(void *opaque, uint32_t slot);
	int (*submit_and_wait)(void *opaque, const struct xdev_ext_nvme_pt_sqe *sqe,
			       int *cqe_res, bool *published);
};

static inline const char *xdev_ext_nvme_pt_stage_name(enum xdev_ext_nvme_pt_stage stage)
{
	switch (stage) {
	case XDEV_EXT_NVME_PT_STAGE_OK:		return "ok";
	case XDEV_EXT_NVME_PT_STAGE_ARGS:		return "args";
	case XDEV_EXT_NVME_PT_STAGE_ACCESS:		return "access";
	case XDEV_EXT_NVME_PT_STAGE_SYSFS:		return "sysfs";
	case XDEV_EXT_NVME_PT_STAGE_PARTITION:	return "partition";
	case XDEV_EXT_NVME_PT_STAGE_MULTIPATH:	return "multipath";
	case XDEV_EXT_NVME_PT_STAGE_LAYOUT:		return "layout";
	case XDEV_EXT_NVME_PT_STAGE_ATTRS:		return "attrs";
	case XDEV_EXT_NVME_PT_STAGE_ANCHOR:		return "anchor";
	case XDEV_EXT_NVME_PT_STAGE_NSID:		return "nsid";
	case XDEV_EXT_NVME_PT_STAGE_IDENTIFY:	return "identify";
	case XDEV_EXT_NVME_PT_STAGE_FORMAT:		return "format";
	case XDEV_EXT_NVME_PT_STAGE_CAPACITY:	return "capacity";
	case XDEV_EXT_NVME_PT_STAGE_LIMITS:		return "limits";
	case XDEV_EXT_NVME_PT_STAGE_PRIVILEGE:	return "privilege";
	case XDEV_EXT_NVME_PT_STAGE_CACHE:		return "cache";
	case XDEV_EXT_NVME_PT_STAGE_PRIVATE:		return "private";
	case XDEV_EXT_NVME_PT_STAGE_NOMEM:		return "nomem";
	}
	return "unknown";
}

static inline void xdev_ext_nvme_pt_count(uint64_t *counter, uint64_t value)
{
	__atomic_add_fetch(counter, value, __ATOMIC_RELAXED);
}

static inline uint64_t xdev_ext_nvme_pt_le(const uint8_t *bytes, unsigned int width)
{
	uint64_t value = 0;

	while (width--)
		value = (value << 8) | bytes[width];
	return value;
}

/* Parse "<digits>" up to end; no sign, no leading zero, fits in 32 bits. */
static inline bool xdev_ext_nvme_pt_parse_u32(const char *text, size_t length,
					 uint32_t *value)
{
	uint64_t parsed = 0;

	if (!length || (text[0] == '0' && length > 1))
		return false;
	for (size_t i = 0; i < length; i++) {
		if (text[i] < '0' || text[i] > '9')
			return false;
		parsed = parsed * 10 + (uint64_t)(text[i] - '0');
		if (parsed > UINT32_MAX)
			return false;
	}
	*value = (uint32_t)parsed;
	return true;
}

static inline const char *xdev_ext_nvme_pt_last_slash(const char *start,
						 const char *end)
{
	while (end > start)
		if (*--end == '/')
			return end;
	return NULL;
}

/*
 * A whole namespace resolves to .../nvme/nvmeC/nvmeSnH: the disk's parent is
 * its controller (device_add_disk(ctrl->device, ...), core.c).  Without
 * multipath S equals C; with nvme_core.multipath=Y a private namespace is
 * named after the subsystem instance instead, so S and C may differ.  A
 * native multipath head lives under .../nvme-subsystem/nvme-subsysN/ and
 * per-path disks are named nvmeScCnH; partitions add one more level.
 */
static inline enum xdev_ext_nvme_pt_stage
xdev_ext_nvme_pt_parse_layout(const char *resolved,
			 struct xdev_ext_nvme_pt_layout *layout)
{
	const char *leaf, *parent, *grand, *end, *sep;
	size_t length;

	if (!resolved || !layout)
		return XDEV_EXT_NVME_PT_STAGE_ARGS;
	memset(layout, 0, sizeof(*layout));
	end = resolved + strlen(resolved);
	leaf = xdev_ext_nvme_pt_last_slash(resolved, end);
	if (!leaf || leaf == resolved)
		return XDEV_EXT_NVME_PT_STAGE_LAYOUT;
	parent = xdev_ext_nvme_pt_last_slash(resolved, leaf);
	if (!parent)
		return XDEV_EXT_NVME_PT_STAGE_LAYOUT;
	grand = xdev_ext_nvme_pt_last_slash(resolved, parent);
	if (!grand)
		return XDEV_EXT_NVME_PT_STAGE_LAYOUT;
	leaf++;
	parent++;
	grand++;

	length = (size_t)(leaf - 1 - parent);
	if (length >= 11 && !strncmp(parent, "nvme-subsys", 11))
		return XDEV_EXT_NVME_PT_STAGE_MULTIPATH;
	if ((size_t)(parent - 1 - grand) != 4 || strncmp(grand, "nvme", 4))
		return XDEV_EXT_NVME_PT_STAGE_LAYOUT;
	if (length <= 4 || strncmp(parent, "nvme", 4) ||
	    !xdev_ext_nvme_pt_parse_u32(parent + 4, length - 4,
				   &layout->ctrl_instance))
		return XDEV_EXT_NVME_PT_STAGE_LAYOUT;

	length = (size_t)(end - leaf);
	if (length <= 4 || strncmp(leaf, "nvme", 4))
		return XDEV_EXT_NVME_PT_STAGE_LAYOUT;
	sep = memchr(leaf + 4, 'n', length - 4);
	if (!sep ||
	    !xdev_ext_nvme_pt_parse_u32(leaf + 4, (size_t)(sep - leaf - 4),
				   &layout->disk_instance) ||
	    !xdev_ext_nvme_pt_parse_u32(sep + 1, (size_t)(end - sep - 1),
				   &layout->head_instance))
		return XDEV_EXT_NVME_PT_STAGE_LAYOUT;
	layout->ctrl_dir_len = (size_t)(leaf - 1 - resolved);
	return XDEV_EXT_NVME_PT_STAGE_OK;
}

/*
 * Decode the fields of Identify Namespace (CNS 0) that the kernel admission
 * checks: a namespace with metadata or protection information is refused
 * there with -EOPNOTSUPP, and blocks below 512 bytes with -EINVAL
 * (nvme_xdev_ext_admit(), include/linux/nvme_xdev_ext_passthru.h).
 */
static inline int
xdev_ext_nvme_pt_decode_identify(const uint8_t *page, size_t length,
			    struct xdev_ext_nvme_pt_id_ns *id)
{
	const uint8_t *lbaf;
	uint8_t flbas;

	if (!page || !id || length < XDEV_EXT_NVME_PT_IDENTIFY_LEN)
		return -EINVAL;
	memset(id, 0, sizeof(*id));
	id->nsze = xdev_ext_nvme_pt_le(page + XDEV_EXT_NVME_ID_NS_NSZE, 8);
	id->ncap = xdev_ext_nvme_pt_le(page + XDEV_EXT_NVME_ID_NS_NCAP, 8);
	flbas = page[XDEV_EXT_NVME_ID_NS_FLBAS];
	/* nvme_lbaf_index(): bits 3:0, extended by bits 6:5. */
	id->lbaf_index = (uint8_t)((flbas & 0x0fU) | ((flbas & 0x60U) >> 1));
	/* NLBAF is 0-based. */
	if (id->lbaf_index > page[XDEV_EXT_NVME_ID_NS_NLBAF])
		return -EINVAL;
	lbaf = page + XDEV_EXT_NVME_ID_NS_LBAF + 4U * id->lbaf_index;
	id->ms = (uint16_t)xdev_ext_nvme_pt_le(lbaf, 2);
	id->lba_shift = lbaf[2];
	id->pi_type = page[XDEV_EXT_NVME_ID_NS_DPS] & XDEV_EXT_NVME_ID_NS_DPS_PI_MASK;

	/* NCAP 0: not allocated or not attached. */
	if (!id->nsze || !id->ncap)
		return -ENXIO;
	if (id->ms || id->pi_type)
		return -EOPNOTSUPP;
	if (id->lba_shift < XDEV_EXT_NVME_PT_MIN_LBA_SHIFT)
		return -EINVAL;
	if (id->lba_shift > XDEV_EXT_NVME_PT_MAX_LBA_SHIFT ||
	    id->nsze > (UINT64_MAX >> id->lba_shift))
		return -EOVERFLOW;
	return 0;
}

/*
 * Largest request that never needs a split, rounded down to whole blocks.
 * A passthrough request is mapped as one request: a bio that would need a
 * split fails with -EINVAL instead of being split (blk_rq_append_bio() and
 * blk_rq_map_user_iov(), block/blk-map.c).  The limits are max_hw_sectors,
 * the 16-bit NLB field, the 32-bit data_len and max_segments, counted as one
 * segment per page: a buffer of (max_segments - 1) pages at any page offset
 * spans at most max_segments pages.
 */
static inline uint32_t xdev_ext_nvme_pt_max_bytes(uint8_t lba_shift,
					     uint64_t max_hw_sectors_kb,
					     uint64_t max_segments,
					     uint64_t page_size)
{
	uint64_t limit = UINT32_MAX;

	if (lba_shift < XDEV_EXT_NVME_PT_MIN_LBA_SHIFT ||
	    lba_shift > XDEV_EXT_NVME_PT_MAX_LBA_SHIFT || !max_hw_sectors_kb ||
	    max_segments < 2 || !page_size)
		return 0;
	if (max_hw_sectors_kb < limit / 1024)
		limit = max_hw_sectors_kb * 1024;
	if (((uint64_t)XDEV_EXT_NVME_PT_NLB_MAX << lba_shift) < limit)
		limit = (uint64_t)XDEV_EXT_NVME_PT_NLB_MAX << lba_shift;
	if (max_segments - 1 < limit / page_size)
		limit = (max_segments - 1) * page_size;
	return (uint32_t)(limit & ~((1ULL << lba_shift) - 1));
}

/* CAP_SYS_ADMIN in the effective set, through the raw capget system call. */
static inline bool xdev_ext_nvme_pt_capable_sys_admin(void)
{
	struct {
		uint32_t version;
		int pid;
	} header = { XDEV_EXT_NVME_PT_CAP_VERSION_3, 0 };
	struct {
		uint32_t effective;
		uint32_t permitted;
		uint32_t inheritable;
	} data[2];

	memset(data, 0, sizeof(data));
	if (syscall(SYS_capget, &header, data))
		return false;
	return data[XDEV_EXT_NVME_PT_CAP_SYS_ADMIN / 32].effective &
	       (1U << (XDEV_EXT_NVME_PT_CAP_SYS_ADMIN % 32));
}

/* Read one sysfs attribute into text, without its trailing newline. */
static inline int xdev_ext_nvme_pt_read_attr(const struct xdev_ext_nvme_pt_env *env,
					const char *dir, const char *name,
					char *text, size_t size)
{
	char path[PATH_MAX];
	ssize_t length;
	int fd;
	int n;

	n = snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (n < 0 || (size_t)n >= sizeof(path))
		return -ENAMETOOLONG;
	fd = env->open(env->opaque, path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return fd;
	length = env->read(env->opaque, fd, text, size - 1);
	(void)env->close(env->opaque, fd);
	if (length < 0)
		return (int)length;
	text[length] = '\0';
	if (length && text[length - 1] == '\n')
		text[--length] = '\0';
	return 0;
}

static inline int xdev_ext_nvme_pt_read_u64(const struct xdev_ext_nvme_pt_env *env,
				       const char *dir, const char *name,
				       uint64_t *value)
{
	char text[32];
	char *end;
	int ret;

	ret = xdev_ext_nvme_pt_read_attr(env, dir, name, text, sizeof(text));
	if (ret)
		return ret;
	if (text[0] < '0' || text[0] > '9')
		return -EINVAL;
	errno = 0;
	*value = strtoull(text, &end, 10);
	if (errno || *end)
		return -EINVAL;
	return 0;
}

/* 1 when the attribute exists, 0 when it does not, else a negative errno. */
static inline int xdev_ext_nvme_pt_attr_exists(const struct xdev_ext_nvme_pt_env *env,
					  const char *dir, const char *name)
{
	char text[8];
	int ret;

	ret = xdev_ext_nvme_pt_read_attr(env, dir, name, text, sizeof(text));
	if (!ret)
		return 1;
	return ret == -ENOENT ? 0 : ret;
}

/*
 * The descriptor's page-cache coherence follows XDEV_EXT_PRELOAD_BDEV_CACHE:
 * coherent writes back the range before publishing and drops it after a
 * successful write, the pages the block layer's O_DIRECT write path
 * invalidates; exclusive does both once over the whole device at
 * registration and drops the written range once at teardown.
 *
 * posix_fadvise(POSIX_FADV_DONTNEED) keeps a page the range covers only in
 * part, where the block layer invalidates every page the write touches, so
 * coherent mode serves only writes whose offset and length are whole pages
 * and hands the rest to libc.  Unlike the block layer it does not wait for
 * a page locked by a concurrent buffered reader, and it does not unmap
 * pages; either can leave stale bytes in the page cache.
 */
static inline bool xdev_ext_nvme_pt_presync_required(const struct xdev_ext_nvme_pt_ns *ns)
{
	return !ns->exclusive;
}

static inline bool xdev_ext_nvme_pt_invalidate_after(const struct xdev_ext_nvme_pt_ns *ns,
						ssize_t result)
{
	return !ns->exclusive && result > 0;
}

static inline void xdev_ext_nvme_pt_note_written(struct xdev_ext_nvme_pt_ns *ns,
					    uint64_t offset, uint64_t length)
{
	uint64_t end = offset + length;
	uint64_t seen;

	if (!ns->exclusive || !length)
		return;
	seen = __atomic_load_n(&ns->written_lo, __ATOMIC_RELAXED);
	while (offset < seen &&
	       !__atomic_compare_exchange_n(&ns->written_lo, &seen, offset,
					    true, __ATOMIC_RELAXED,
					    __ATOMIC_RELAXED))
		;
	seen = __atomic_load_n(&ns->written_hi, __ATOMIC_RELAXED);
	while (end > seen &&
	       !__atomic_compare_exchange_n(&ns->written_hi, &seen, end,
					    true, __ATOMIC_RELAXED,
					    __ATOMIC_RELAXED))
		;
}

/* The range teardown must drop from the page cache, if any. */
static inline bool xdev_ext_nvme_pt_teardown_range(const struct xdev_ext_nvme_pt_ns *ns,
					      uint64_t *offset,
					      uint64_t *length)
{
	uint64_t lo = __atomic_load_n(&ns->written_lo, __ATOMIC_RELAXED);
	uint64_t hi = __atomic_load_n(&ns->written_hi, __ATOMIC_RELAXED);

	if (!ns->exclusive || hi <= lo)
		return false;
	*offset = lo;
	*length = hi - lo;
	return true;
}

/*
 * Register a whole NVMe namespace block device, or refuse it.  Returns 0 and
 * *out on success, else a negative errno with *stage naming the check.  Any
 * descriptor opened here is closed again on refusal.
 */
static inline int xdev_ext_nvme_pt_probe(const struct xdev_ext_nvme_pt_env *env,
				    int app_fd, const struct stat *st,
				    const char *path,
				    struct xdev_ext_nvme_pt_ns **out,
				    enum xdev_ext_nvme_pt_stage *stage)
{
	struct xdev_ext_nvme_pt_scratch {
		char link[PATH_MAX];
		char dir[PATH_MAX];
		char path[PATH_MAX];
		uint8_t page[XDEV_EXT_NVME_PT_IDENTIFY_LEN];
	} *s = NULL;
	enum xdev_ext_nvme_pt_stage failed = XDEV_EXT_NVME_PT_STAGE_ARGS;
	struct nvme_passthru_cmd identify;
	struct xdev_ext_nvme_pt_layout layout;
	struct xdev_ext_nvme_pt_id_ns id;
	struct xdev_ext_nvme_pt_ns *ns;
	uint64_t value, max_hw_kb, max_segments, bytes, page_size;
	uint32_t ng_major, ng_minor, dma_mask;
	struct stat ng;
	char text[32];
	char *colon;
	int anchor = -1;
	int nsid, ng_nsid;
	int ret = -EINVAL;
	int flags, n;

	(void)path;
	if (stage)
		*stage = XDEV_EXT_NVME_PT_STAGE_ARGS;
	if (!out)
		return -EINVAL;
	*out = NULL;
	if (!env || !st || !stage || app_fd < 0 || !env->sysfs_root ||
	    !env->dev_root || !env->open || !env->close || !env->read ||
	    !env->fstat || !env->getfl || !env->ioctl || !env->sync_range ||
	    !env->fadvise || !env->has_sys_admin)
		return -EINVAL;

	/* 1. A block device open for writing. */
	if (!S_ISBLK(st->st_mode))
		return -ENOTBLK;
	flags = env->getfl(env->opaque, app_fd);
	if (flags < 0 || (flags & O_ACCMODE) == O_RDONLY) {
		*stage = XDEV_EXT_NVME_PT_STAGE_ACCESS;
		return flags < 0 ? flags : -EBADF;
	}

	s = malloc(sizeof(*s));
	if (!s) {
		*stage = XDEV_EXT_NVME_PT_STAGE_NOMEM;
		return -ENOMEM;
	}

	/* 2. A whole namespace on a controller: not a partition or head. */
	failed = XDEV_EXT_NVME_PT_STAGE_SYSFS;
	n = snprintf(s->link, sizeof(s->link), "%s/dev/block/%u:%u",
		     env->sysfs_root, major(st->st_rdev), minor(st->st_rdev));
	if (n < 0 || (size_t)n >= sizeof(s->link)) {
		ret = -ENAMETOOLONG;
		goto fail;
	}
	if (!realpath(s->link, s->dir)) {
		ret = -errno;
		goto fail;
	}
	ret = xdev_ext_nvme_pt_attr_exists(env, s->dir, "partition");
	if (ret) {
		failed = ret > 0 ? XDEV_EXT_NVME_PT_STAGE_PARTITION : failed;
		ret = ret > 0 ? -EINVAL : ret;
		goto fail;
	}
	failed = xdev_ext_nvme_pt_parse_layout(s->dir, &layout);
	if (failed != XDEV_EXT_NVME_PT_STAGE_OK) {
		ret = failed == XDEV_EXT_NVME_PT_STAGE_MULTIPATH ? -EOPNOTSUPP :
							      -ENODEV;
		goto fail;
	}
	/* The admission refuses other command sets; libc would not. */
	failed = XDEV_EXT_NVME_PT_STAGE_ATTRS;
	ret = xdev_ext_nvme_pt_read_u64(env, s->dir, "csi", &value);
	if (ret || value) {
		ret = ret ? ret : -EOPNOTSUPP;
		goto fail;
	}
	ret = xdev_ext_nvme_pt_read_u64(env, s->dir, "ro", &value);
	if (ret || value) {
		ret = ret ? ret : -EROFS;
		goto fail;
	}

	/*
	 * 3. The generic node of the same namespace.  It sits next to the
	 * disk under the controller and is named ng<C>n<H> after the
	 * controller instance and the head instance (nvme_add_ns_cdev(),
	 * core.c); /dev must hold the device sysfs names.
	 */
	failed = XDEV_EXT_NVME_PT_STAGE_ANCHOR;
	n = snprintf(s->path, sizeof(s->path), "%.*s/ng%un%u",
		     (int)layout.ctrl_dir_len, s->dir, layout.ctrl_instance,
		     layout.head_instance);
	if (n < 0 || (size_t)n >= sizeof(s->path)) {
		ret = -ENAMETOOLONG;
		goto fail;
	}
	ret = xdev_ext_nvme_pt_read_attr(env, s->path, "dev", text, sizeof(text));
	if (ret)
		goto fail;
	colon = strchr(text, ':');
	if (!colon ||
	    !xdev_ext_nvme_pt_parse_u32(text, (size_t)(colon - text), &ng_major) ||
	    !xdev_ext_nvme_pt_parse_u32(colon + 1, strlen(colon + 1), &ng_minor)) {
		ret = -EINVAL;
		goto fail;
	}
	n = snprintf(s->path, sizeof(s->path), "%s/ng%un%u", env->dev_root,
		     layout.ctrl_instance, layout.head_instance);
	if (n < 0 || (size_t)n >= sizeof(s->path)) {
		ret = -ENAMETOOLONG;
		goto fail;
	}
	anchor = env->open(env->opaque, s->path, O_RDWR | O_CLOEXEC);
	if (anchor < 0) {
		ret = anchor;
		goto fail;
	}
	ret = env->fstat(env->opaque, anchor, &ng);
	if (ret)
		goto fail;
	if (!S_ISCHR(ng.st_mode) || ng.st_rdev != makedev(ng_major, ng_minor)) {
		ret = -ENODEV;
		goto fail;
	}

	/* 4. Both nodes name the same namespace. */
	failed = XDEV_EXT_NVME_PT_STAGE_NSID;
	nsid = env->ioctl(env->opaque, app_fd, NVME_IOCTL_ID, NULL);
	ng_nsid = env->ioctl(env->opaque, anchor, NVME_IOCTL_ID, NULL);
	if (nsid <= 0 || nsid != ng_nsid) {
		ret = nsid < 0 ? nsid : -EXDEV;
		goto fail;
	}

	/* 5. Identify Namespace, which an unprivileged caller may send. */
	failed = XDEV_EXT_NVME_PT_STAGE_IDENTIFY;
	memset(&identify, 0, sizeof(identify));
	identify.opcode = XDEV_EXT_NVME_PT_OPC_IDENTIFY;
	identify.nsid = (uint32_t)nsid;
	identify.addr = (uint64_t)(uintptr_t)s->page;
	identify.data_len = XDEV_EXT_NVME_PT_IDENTIFY_LEN;
	identify.cdw10 = XDEV_EXT_NVME_PT_CNS_NS;
	ret = env->ioctl(env->opaque, anchor, NVME_IOCTL_ADMIN_CMD, &identify);
	if (ret) {
		/* A positive value is an NVMe status. */
		ret = ret > 0 ? -EIO : ret;
		goto fail;
	}
	failed = XDEV_EXT_NVME_PT_STAGE_FORMAT;
	ret = xdev_ext_nvme_pt_decode_identify(s->page, sizeof(s->page), &id);
	if (ret)
		goto fail;

	/* 6. The block layer sees the same capacity and block size. */
	failed = XDEV_EXT_NVME_PT_STAGE_CAPACITY;
	bytes = 0;
	ret = env->ioctl(env->opaque, app_fd, BLKGETSIZE64, &bytes);
	if (ret)
		goto fail;
	if (bytes != id.nsze << id.lba_shift) {
		ret = -ERANGE;
		goto fail;
	}
	ret = xdev_ext_nvme_pt_read_u64(env, s->dir, "queue/logical_block_size",
				   &value);
	if (ret || value != 1ULL << id.lba_shift) {
		ret = ret ? ret : -ERANGE;
		goto fail;
	}

	/* 7. Request size and buffer alignment limits. */
	failed = XDEV_EXT_NVME_PT_STAGE_LIMITS;
	ret = xdev_ext_nvme_pt_read_u64(env, s->dir, "queue/max_hw_sectors_kb",
				   &max_hw_kb);
	if (ret)
		goto fail;
	ret = xdev_ext_nvme_pt_read_u64(env, s->dir, "queue/max_segments",
				   &max_segments);
	if (ret)
		goto fail;
	page_size = env->page_size;
	if (!page_size) {
		long system_page = sysconf(_SC_PAGESIZE);

		page_size = system_page > 0 ? (uint64_t)system_page : 0;
	}
	value = xdev_ext_nvme_pt_max_bytes(id.lba_shift, max_hw_kb, max_segments,
				      page_size);
	/* coherent mode masks with the page size; it is a power of two. */
	if (value < 1ULL << id.lba_shift || page_size > UINT32_MAX ||
	    (page_size & (page_size - 1))) {
		ret = -EINVAL;
		goto fail;
	}
	/* queue/dma_alignment is a mask; fall back to the block size. */
	dma_mask = (uint32_t)((1ULL << id.lba_shift) - 1);
	if (!xdev_ext_nvme_pt_read_u64(env, s->dir, "queue/dma_alignment", &bytes) &&
	    bytes <= UINT32_MAX)
		dma_mask = (uint32_t)bytes;

	/*
	 * 8. Write permission.  Without CAP_SYS_ADMIN the kernel allows the
	 * write only when the controller's Commands Supported and Effects
	 * log marks it supported (nvme_cmd_allowed(), ioctl.c); reading that
	 * log itself needs CAP_SYS_ADMIN, so it cannot be confirmed.
	 */
	failed = XDEV_EXT_NVME_PT_STAGE_PRIVILEGE;
	if (!env->has_sys_admin(env->opaque)) {
		ret = -EPERM;
		goto fail;
	}

	/* 9. exclusive: write back and drop the whole device once. */
	failed = XDEV_EXT_NVME_PT_STAGE_CACHE;
	if (env->exclusive) {
		ret = env->sync_range(env->opaque, app_fd, 0, 0,
				      XDEV_EXT_NVME_PT_PRESYNC_FLAGS);
		if (!ret)
			ret = env->fadvise(env->opaque, app_fd, 0, 0,
					   POSIX_FADV_DONTNEED);
		if (ret)
			goto fail;
	}

	failed = XDEV_EXT_NVME_PT_STAGE_NOMEM;
	ns = calloc(1, sizeof(*ns));
	if (!ns) {
		ret = -ENOMEM;
		goto fail;
	}
	failed = XDEV_EXT_NVME_PT_STAGE_PRIVATE;
	if (env->make_private) {
		ret = env->make_private(env->opaque, anchor);
		if (ret < 0) {
			free(ns);
			goto fail;
		}
		anchor = ret;
	}

	ns->anchor_fd = anchor;
	ns->ng_rdev = ng.st_rdev;
	ns->ng_ino = ng.st_ino;
	ns->nsid = (uint32_t)nsid;
	ns->lba_shift = id.lba_shift;
	ns->capacity_lbas = id.nsze;
	ns->max_bytes = (uint32_t)value;
	ns->dma_align_mask = dma_mask;
	ns->page_mask = (uint32_t)(page_size - 1);
	ns->bdev_rdev = st->st_rdev;
	ns->bdev_dev = st->st_dev;
	ns->bdev_ino = st->st_ino;
	ns->bdev_type = st->st_mode & S_IFMT;
	n = snprintf(ns->name, sizeof(ns->name), "%s",
		     s->dir + layout.ctrl_dir_len + 1);
	(void)n;
	ns->exclusive = env->exclusive;
	ns->written_lo = UINT64_MAX;
	ns->written_hi = 0;
	ns->env = env;
	free(s);
	*stage = XDEV_EXT_NVME_PT_STAGE_OK;
	*out = ns;
	return 0;

fail:
	if (anchor >= 0)
		(void)env->close(env->opaque, anchor);
	free(s);
	*stage = failed;
	return ret < 0 ? ret : -EINVAL;
}

/*
 * Per-call checks with no system call.  O_SYNC includes the O_DSYNC bit;
 * O_APPEND makes pwrite append on Linux.
 */
static inline enum xdev_ext_nvme_pt_verdict
xdev_ext_nvme_pt_classify(const struct xdev_ext_nvme_pt_ns *ns, int status_flags,
		     const struct xdev_ext_io *io)
{
	uint64_t block_mask, capacity;

	if (!ns || !io || !io->write)
		return XDEV_EXT_NVME_PT_INELIGIBLE;
	if (!(status_flags & O_DIRECT))
		return XDEV_EXT_NVME_PT_INELIGIBLE;
	if (status_flags & (O_DSYNC | O_SYNC | O_APPEND))
		return XDEV_EXT_NVME_PT_SYNC_FLAGS;
	block_mask = (1ULL << ns->lba_shift) - 1;
	capacity = ns->capacity_lbas << ns->lba_shift;
	if (!io->count || io->count > ns->max_bytes || io->offset < 0 ||
	    (((uint64_t)io->offset | io->count) & block_mask) ||
	    io->count > capacity || (uint64_t)io->offset > capacity - io->count)
		return XDEV_EXT_NVME_PT_INELIGIBLE;
	if (!io->buf || ((uintptr_t)io->buf & ns->dma_align_mask))
		return XDEV_EXT_NVME_PT_INELIGIBLE;
	if (!ns->exclusive &&
	    (((uint64_t)io->offset | io->count) & ns->page_mask))
		return XDEV_EXT_NVME_PT_INELIGIBLE;
	return XDEV_EXT_NVME_PT_ELIGIBLE;
}

/*
 * The application's descriptor still names the registered node: same
 * (st_dev, st_ino, file type, st_rdev).  The probe registers block devices
 * only; the type is compared as recorded so a test mapping keeps working.
 */
static inline bool xdev_ext_nvme_pt_identity_matches(const struct xdev_ext_nvme_pt_ns *ns,
						const struct stat *st)
{
	return ns && st && ns->bdev_type &&
	       (st->st_mode & S_IFMT) == ns->bdev_type &&
	       st->st_rdev == ns->bdev_rdev && st->st_ino == ns->bdev_ino &&
	       st->st_dev == ns->bdev_dev;
}

/*
 * One NVM Write of count bytes at offset from buf, on the fixed file in
 * slot: not vectored and not IORING_URING_CMD_FIXED, so cmd.data_len is the
 * byte count the policy sees.  No FUA: the application's fsync goes to libc
 * and flushes the whole device.
 */
static inline int xdev_ext_nvme_pt_encode_sqe(struct xdev_ext_nvme_pt_sqe *out,
					 const struct xdev_ext_nvme_pt_ns *ns,
					 uint32_t slot, const void *buf,
					 size_t count, int64_t offset,
					 uint64_t user_data)
{
	struct nvme_uring_cmd cmd;
	uint64_t block_mask, slba;

	if (!out || !ns || !buf || slot >= XDEV_EXT_NVME_PT_SLOTS)
		return -EINVAL;
	block_mask = (1ULL << ns->lba_shift) - 1;
	if (!count || offset < 0 ||
	    (((uint64_t)offset | count) & block_mask) ||
	    (count >> ns->lba_shift) > XDEV_EXT_NVME_PT_NLB_MAX ||
	    count > UINT32_MAX)
		return -EINVAL;
	slba = (uint64_t)offset >> ns->lba_shift;

	memset(out, 0, sizeof(*out));
	out->sqe.opcode = IORING_OP_URING_CMD;
	out->sqe.flags = IOSQE_FIXED_FILE;
	out->sqe.fd = (int32_t)slot;
	out->sqe.cmd_op = NVME_URING_CMD_IO;
	out->sqe.uring_cmd_flags = 0;
	out->sqe.user_data = user_data;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = XDEV_EXT_NVME_PT_OPC_WRITE;
	cmd.nsid = ns->nsid;
	cmd.addr = (uint64_t)(uintptr_t)buf;
	cmd.data_len = (uint32_t)count;
	cmd.cdw10 = (uint32_t)slba;
	cmd.cdw11 = (uint32_t)(slba >> 32);
	cmd.cdw12 = (uint32_t)(count >> ns->lba_shift) - 1;
	cmd.rsvd2 = NVME_URING_CMD_F_XDEV_EXT;
	memcpy(out->bytes + offsetof(struct io_uring_sqe, cmd), &cmd,
	       sizeof(cmd));
	return 0;
}

/*
 * An NVMe write completes whole or not at all: 0 is the full count, a
 * negative value an errno (-EPERM when policy denied it), and a positive
 * value an NVMe status, reported as EIO.
 */
static inline ssize_t xdev_ext_nvme_pt_map_cqe(int res, size_t count,
					  enum xdev_ext_nvme_pt_cqe_class *cls)
{
	enum xdev_ext_nvme_pt_cqe_class unused;

	if (!cls)
		cls = &unused;
	if (!res) {
		*cls = XDEV_EXT_NVME_PT_CQE_OK;
		return (ssize_t)count;
	}
	if (res > 0) {
		*cls = XDEV_EXT_NVME_PT_CQE_DEVICE_STATUS;
		return -EIO;
	}
	*cls = res == -EPERM ? XDEV_EXT_NVME_PT_CQE_POLICY_DENIED :
			       XDEV_EXT_NVME_PT_CQE_ERRNO;
	return res;
}

/*
 * Serve one write or hand it back.  Before publication every failure is a
 * fallback, so the caller runs libc with the original arguments.  Once the
 * entry is published only its terminal completion decides the result, and
 * libc is never called.  The order is identity, ring, write-back, publish,
 * invalidate.
 */
static inline int xdev_ext_nvme_pt_execute(struct xdev_ext_nvme_pt_ns *ns,
				      const struct xdev_ext_nvme_pt_call *call,
				      const struct xdev_ext_nvme_pt_ring *ring,
				      ssize_t *result, bool *published)
{
	const struct xdev_ext_nvme_pt_env *env;
	enum xdev_ext_nvme_pt_cqe_class cls;
	struct xdev_ext_nvme_pt_sqe sqe;
	const struct xdev_ext_io *io;
	struct stat st;
	int cqe_res = 0;
	int ret;

	if (!result || !published)
		return XDEV_EXT_SINK_FALLBACK;
	*published = false;
	*result = 0;
	if (!ns || !ns->env || !call || !call->io || !ring || !ring->ready ||
	    !ring->submit_and_wait)
		return XDEV_EXT_SINK_FALLBACK;
	env = ns->env;
	io = call->io;

	switch (xdev_ext_nvme_pt_classify(ns, call->status_flags, io)) {
	case XDEV_EXT_NVME_PT_ELIGIBLE:
		break;
	case XDEV_EXT_NVME_PT_SYNC_FLAGS:
		xdev_ext_nvme_pt_count(&ns->ctr.fallback_sync_flags, 1);
		return XDEV_EXT_SINK_FALLBACK;
	default:
		xdev_ext_nvme_pt_count(&ns->ctr.fallback_ineligible, 1);
		return XDEV_EXT_SINK_FALLBACK;
	}
	/* The number may have been closed and reused behind libc's back. */
	if (env->fstat(env->opaque, io->app_fd, &st) ||
	    !xdev_ext_nvme_pt_identity_matches(ns, &st)) {
		xdev_ext_nvme_pt_count(&ns->ctr.fallback_identity, 1);
		return XDEV_EXT_SINK_FALLBACK;
	}
	if (ring->ready(ring->opaque, call->slot) ||
	    xdev_ext_nvme_pt_encode_sqe(&sqe, ns, call->slot, io->buf, io->count,
				   io->offset, call->user_data)) {
		xdev_ext_nvme_pt_count(&ns->ctr.fallback_ineligible, 1);
		return XDEV_EXT_SINK_FALLBACK;
	}
	if (xdev_ext_nvme_pt_presync_required(ns) &&
	    env->sync_range(env->opaque, io->app_fd, io->offset,
			    (int64_t)io->count, XDEV_EXT_NVME_PT_PRESYNC_FLAGS)) {
		xdev_ext_nvme_pt_count(&ns->ctr.fallback_presync, 1);
		return XDEV_EXT_SINK_FALLBACK;
	}

	ret = ring->submit_and_wait(ring->opaque, &sqe, &cqe_res, published);
	if (ret < 0 && !*published) {
		xdev_ext_nvme_pt_count(&ns->ctr.fallback_ineligible, 1);
		return XDEV_EXT_SINK_FALLBACK;
	}
	*published = true;
	xdev_ext_nvme_pt_count(&ns->ctr.takeover, 1);
	if (ret < 0) {
		*result = ret;
		xdev_ext_nvme_pt_count(&ns->ctr.errors, 1);
		return XDEV_EXT_SINK_SERVED;
	}
	*result = xdev_ext_nvme_pt_map_cqe(cqe_res, io->count, &cls);
	switch (cls) {
	case XDEV_EXT_NVME_PT_CQE_OK:
		xdev_ext_nvme_pt_count(&ns->ctr.takeover_bytes, io->count);
		xdev_ext_nvme_pt_note_written(ns, (uint64_t)io->offset, io->count);
		break;
	case XDEV_EXT_NVME_PT_CQE_POLICY_DENIED:
		xdev_ext_nvme_pt_count(&ns->ctr.policy_denied, 1);
		xdev_ext_nvme_pt_count(&ns->ctr.errors, 1);
		break;
	case XDEV_EXT_NVME_PT_CQE_DEVICE_STATUS:
		xdev_ext_nvme_pt_count(&ns->ctr.device_status_errors, 1);
		xdev_ext_nvme_pt_count(&ns->ctr.errors, 1);
		break;
	case XDEV_EXT_NVME_PT_CQE_ERRNO:
		xdev_ext_nvme_pt_count(&ns->ctr.errors, 1);
		break;
	}
	if (xdev_ext_nvme_pt_invalidate_after(ns, *result) &&
	    env->fadvise(env->opaque, io->app_fd, io->offset,
			 (int64_t)io->count, POSIX_FADV_DONTNEED))
		xdev_ext_nvme_pt_count(&ns->ctr.invalidate_errors, 1);
	return XDEV_EXT_SINK_SERVED;
}

static inline int xdev_ext_nvme_pt_format_report(const struct xdev_ext_nvme_pt_ns *ns,
					    int pid, char *buf, size_t size)
{
	const struct xdev_ext_nvme_pt_counters *c;
	int n;

	if (!ns || !buf || !size)
		return -EINVAL;
	c = &ns->ctr;
#define XDEV_EXT_NVME_PT_LOAD(field) \
	((unsigned long long)__atomic_load_n(&c->field, __ATOMIC_RELAXED))
	n = snprintf(buf, size,
		     "XDEV_EXT_PRELOAD_WRITE_REPORT pid=%d sink=%s device=%s "
		     "nsid=%u lba_bytes=%u takeover=%llu takeover_bytes=%llu "
		     "errors=%llu policy_denied=%llu "
		     "device_status_errors=%llu fallback_ineligible=%llu "
		     "fallback_vector=%llu fallback_sync_flags=%llu "
		     "fallback_identity=%llu fallback_presync=%llu "
		     "invalidate_errors=%llu cache=%s\n",
		     pid, XDEV_EXT_NVME_PT_NAME, ns->name, ns->nsid,
		     1U << ns->lba_shift, XDEV_EXT_NVME_PT_LOAD(takeover),
		     XDEV_EXT_NVME_PT_LOAD(takeover_bytes), XDEV_EXT_NVME_PT_LOAD(errors),
		     XDEV_EXT_NVME_PT_LOAD(policy_denied),
		     XDEV_EXT_NVME_PT_LOAD(device_status_errors),
		     XDEV_EXT_NVME_PT_LOAD(fallback_ineligible),
		     XDEV_EXT_NVME_PT_LOAD(fallback_vector),
		     XDEV_EXT_NVME_PT_LOAD(fallback_sync_flags),
		     XDEV_EXT_NVME_PT_LOAD(fallback_identity),
		     XDEV_EXT_NVME_PT_LOAD(fallback_presync),
		     XDEV_EXT_NVME_PT_LOAD(invalidate_errors),
		     ns->exclusive ? "exclusive" : "coherent");
#undef XDEV_EXT_NVME_PT_LOAD
	if (n < 0)
		return -EINVAL;
	if ((size_t)n >= size)
		return -ENOSPC;
	return n;
}

/*
 * exclusive mode: drop the written range from the page cache, once.  The
 * application's descriptors may all be closed by now, so the block device is
 * opened again by name and checked against the registered device number;
 * any block-device descriptor reaches the same page cache.
 */
static inline void xdev_ext_nvme_pt_teardown(struct xdev_ext_nvme_pt_ns *ns)
{
	const struct xdev_ext_nvme_pt_env *env;
	char path[PATH_MAX];
	uint64_t offset, length;
	struct stat st;
	int fd, n;

	if (!ns || !ns->env ||
	    __atomic_exchange_n(&ns->torn_down, 1, __ATOMIC_ACQ_REL))
		return;
	if (!xdev_ext_nvme_pt_teardown_range(ns, &offset, &length))
		return;
	env = ns->env;
	n = snprintf(path, sizeof(path), "%s/%s", env->dev_root, ns->name);
	fd = n < 0 || (size_t)n >= sizeof(path) ? -ENAMETOOLONG :
		env->open(env->opaque, path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		xdev_ext_nvme_pt_count(&ns->ctr.invalidate_errors, 1);
		return;
	}
	if (env->fstat(env->opaque, fd, &st) || !S_ISBLK(st.st_mode) ||
	    st.st_rdev != ns->bdev_rdev ||
	    env->fadvise(env->opaque, fd, (int64_t)offset, (int64_t)length,
			 POSIX_FADV_DONTNEED))
		xdev_ext_nvme_pt_count(&ns->ctr.invalidate_errors, 1);
	(void)env->close(env->opaque, fd);
}

/* Last reference gone: tear down, close the anchor, free. */
static inline void xdev_ext_nvme_pt_destroy(struct xdev_ext_nvme_pt_ns *ns)
{
	if (!ns)
		return;
	xdev_ext_nvme_pt_teardown(ns);
	if (ns->env && ns->anchor_fd >= 0)
		(void)ns->env->close(ns->env->opaque, ns->anchor_fd);
	free(ns);
}

/*
 * struct xdev_ext_sink_ops adaptors that need neither the registration nor the
 * thread.  eligible and execute read the registration's status flags and
 * slot and this thread's ring, so the export layer builds them on top of
 * xdev_ext_nvme_pt_classify() and xdev_ext_nvme_pt_execute().
 */
static const struct xdev_ext_nvme_pt_env *xdev_ext_nvme_pt_active_env
	__attribute__((unused));

/* Set before admission opens; the table must stay valid while in use. */
static inline void xdev_ext_nvme_pt_use_env(const struct xdev_ext_nvme_pt_env *env)
{
	__atomic_store_n(&xdev_ext_nvme_pt_active_env, env, __ATOMIC_RELEASE);
}

static inline int xdev_ext_nvme_pt_sink_probe(int app_fd, const struct stat *st,
					 const char *path, void **backend)
{
	const struct xdev_ext_nvme_pt_env *env;
	enum xdev_ext_nvme_pt_stage stage;
	struct xdev_ext_nvme_pt_ns *ns = NULL;
	int ret;

	if (!backend)
		return -EINVAL;
	*backend = NULL;
	env = __atomic_load_n(&xdev_ext_nvme_pt_active_env, __ATOMIC_ACQUIRE);
	if (!env)
		return -ENODEV;
	ret = xdev_ext_nvme_pt_probe(env, app_fd, st, path, &ns, &stage);
	if (!ret)
		*backend = ns;
	return ret;
}

static inline void xdev_ext_nvme_pt_sink_destroy(void *backend)
{
	xdev_ext_nvme_pt_destroy(backend);
}

/* Exactly one line per registration, however often this is called. */
static inline void xdev_ext_nvme_pt_sink_report(const void *backend, int out_fd)
{
	/* The once flag is the only state a report changes. */
	struct xdev_ext_nvme_pt_ns *ns = (struct xdev_ext_nvme_pt_ns *)backend;
	char line[XDEV_EXT_NVME_PT_REPORT_MAX];
	int length;

	if (!ns || __atomic_exchange_n(&ns->report_emitted, 1,
				       __ATOMIC_ACQ_REL))
		return;
	length = xdev_ext_nvme_pt_format_report(ns, (int)getpid(), line,
					   sizeof(line));
	if (length > 0)
		(void)syscall(SYS_write, out_fd, line, (size_t)length);
}

#endif /* XDEV_EXT_PRELOAD_SINK_NVME_PT_H */
