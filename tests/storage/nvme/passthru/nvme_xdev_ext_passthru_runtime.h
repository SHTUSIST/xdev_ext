/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NVME_XDEV_EXT_PASSTHRU_RUNTIME_H
#define NVME_XDEV_EXT_PASSTHRU_RUNTIME_H

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../../include/uapi/linux/io_uring.h"
#include "../../../../include/uapi/linux/nvme_ioctl.h"
#include "../../../../include/uapi/linux/xdev_ext_mech.h"

#define NVME_XDEV_EXT_RUNTIME_SQE_SIZE 128U
#define NVME_XDEV_EXT_RUNTIME_CQE_SIZE 32U
#define NVME_XDEV_EXT_RUNTIME_EXPECTED_DEVICE "/dev/ng0n1"
#define NVME_XDEV_EXT_RUNTIME_EXPECTED_MODEL "QEMU NVMe Ctrl"
#define NVME_XDEV_EXT_RUNTIME_EXPECTED_SERIAL "UBRTEST0001"
/* --mech-s0 writes only windows of the destination controller. */
#define NVME_XDEV_EXT_RUNTIME_MECH_SERIAL "UBRDST0001"
/* One built WRITE; the runtime reads the whole window back. */
#define NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES 8192U
#define NVME_XDEV_EXT_RUNTIME_MECH_MAX_WINDOW_BYTES (1U << 20)
#define NVME_XDEV_EXT_RUNTIME_MECH_MAX_DIGITS 6U

struct nvme_xdev_ext_runtime_command {
	int fd;
	uint32_t cmd_op;
	uint64_t user_data;
	uint64_t buffer;
	uint64_t slba;
	uint32_t data_len;
	uint32_t nsid;
	uint32_t nlb;
	uint32_t xdev_ext_flags;
	uint32_t uring_cmd_flags;
	uint16_t buf_index;
	uint8_t opcode;
};

enum nvme_xdev_ext_runtime_safety_result {
	NVME_XDEV_EXT_RUNTIME_SAFE = 0,
	NVME_XDEV_EXT_RUNTIME_SKIP_NO_DEVICE,
	NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE,
	NVME_XDEV_EXT_RUNTIME_REJECT_IDENTITY,
	NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE_TYPE,
	NVME_XDEV_EXT_RUNTIME_REJECT_SYSFS_MISMATCH,
	NVME_XDEV_EXT_RUNTIME_REJECT_SIBLING_TOPOLOGY,
	NVME_XDEV_EXT_RUNTIME_REJECT_NOT_VM,
	NVME_XDEV_EXT_RUNTIME_REJECT_MOUNTED,
	NVME_XDEV_EXT_RUNTIME_REJECT_HOLDERS,
	NVME_XDEV_EXT_RUNTIME_REJECT_PARTITIONS,
	NVME_XDEV_EXT_RUNTIME_REJECT_SWAP,
	NVME_XDEV_EXT_RUNTIME_REJECT_WRITE_NOT_ALLOWED,
};

struct nvme_xdev_ext_runtime_safety {
	const char *device;
	const char *canonical_device;
	const char *model;
	const char *serial;
	int character_device;
	int sysfs_device_matches;
	int sibling_topology_matches;
	int virtual_machine;
	int mounted;
	int has_holders;
	int has_partitions;
	int in_swap;
	int allow_file_backed_write;
};

struct nvme_xdev_ext_runtime_baseline {
	int native_read_ok;
	int native_cqe_ok;
	int opted_read_ok;
	int bytes_match;
	int cqe_match;
	int preflight_ok;
	int block_guard_ok;
	int safety_rechecked;
};

enum nvme_xdev_ext_runtime_backing_ownership {
	NVME_XDEV_EXT_RUNTIME_BACKING_LOCAL,
	NVME_XDEV_EXT_RUNTIME_BACKING_PUBLISHED,
	NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED,
	NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS,
	NVME_XDEV_EXT_RUNTIME_BACKING_RETAINED_FAILURE,
};

enum nvme_xdev_ext_runtime_media_state {
	NVME_XDEV_EXT_RUNTIME_MEDIA_ORIGINAL,
	NVME_XDEV_EXT_RUNTIME_MEDIA_WRITE_PUBLISHED,
	NVME_XDEV_EXT_RUNTIME_MEDIA_PATTERN_PRESENT,
	NVME_XDEV_EXT_RUNTIME_MEDIA_RESTORED,
	NVME_XDEV_EXT_RUNTIME_MEDIA_TAINTED,
};

static_assert(sizeof(struct io_uring_sqe) == 64,
	      "io_uring base SQE layout changed");
static_assert(offsetof(struct io_uring_sqe, cmd) == 48,
	      "io_uring command offset changed");
static_assert(sizeof(struct nvme_uring_cmd) <=
	      NVME_XDEV_EXT_RUNTIME_SQE_SIZE - offsetof(struct io_uring_sqe, cmd),
	      "NVMe command no longer fits an SQE128 command area");
static_assert(sizeof(struct io_uring_cqe) == 16,
	      "io_uring base CQE layout changed");

static inline struct io_uring_sqe *
nvme_xdev_ext_runtime_sqe_at(void *base, uint32_t index)
{
	return (struct io_uring_sqe *)((unsigned char *)base +
		index * NVME_XDEV_EXT_RUNTIME_SQE_SIZE);
}

static inline struct io_uring_cqe *
nvme_xdev_ext_runtime_cqe_at(void *base, uint32_t index)
{
	return (struct io_uring_cqe *)((unsigned char *)base +
		index * NVME_XDEV_EXT_RUNTIME_CQE_SIZE);
}

static inline int
nvme_xdev_ext_runtime_encode(struct io_uring_sqe *sqe,
			const struct nvme_xdev_ext_runtime_command *command)
{
	struct nvme_uring_cmd *cmd;

	if (!sqe || !command)
		return -EINVAL;
	if (!command->nlb)
		return -EINVAL;
	if (command->nlb > 65536U)
		return -EOVERFLOW;

	memset(sqe, 0, NVME_XDEV_EXT_RUNTIME_SQE_SIZE);
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->fd = command->fd;
	sqe->cmd_op = command->cmd_op;
	sqe->user_data = command->user_data;
	sqe->uring_cmd_flags = command->uring_cmd_flags;
	sqe->buf_index = command->buf_index;

	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	cmd->opcode = command->opcode;
	cmd->nsid = command->nsid;
	cmd->addr = command->buffer;
	cmd->data_len = command->data_len;
	cmd->cdw10 = (uint32_t)command->slba;
	cmd->cdw11 = (uint32_t)(command->slba >> 32);
	cmd->cdw12 = command->nlb - 1;
	cmd->rsvd2 = command->xdev_ext_flags;
	return 0;
}

static inline int
nvme_xdev_ext_runtime_may_release(enum nvme_xdev_ext_runtime_backing_ownership ownership)
{
	return ownership == NVME_XDEV_EXT_RUNTIME_BACKING_LOCAL ||
	       ownership == NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED;
}

static inline enum nvme_xdev_ext_runtime_backing_ownership
nvme_xdev_ext_runtime_wait_result(int completion_observed)
{
	return completion_observed ? NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED :
		NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS;
}

static inline enum nvme_xdev_ext_runtime_backing_ownership
nvme_xdev_ext_runtime_cqe_ownership(uint32_t flags, int user_data_matches,
			       uint32_t pending_cqes)
{
	if (flags || !user_data_matches || pending_cqes != 1)
		return NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS;
	return NVME_XDEV_EXT_RUNTIME_BACKING_COMPLETED;
}

static inline enum nvme_xdev_ext_runtime_backing_ownership
nvme_xdev_ext_runtime_restore_failed(enum nvme_xdev_ext_runtime_backing_ownership ownership)
{
	if (ownership == NVME_XDEV_EXT_RUNTIME_BACKING_AMBIGUOUS)
		return ownership;
	return NVME_XDEV_EXT_RUNTIME_BACKING_RETAINED_FAILURE;
}

static inline int
nvme_xdev_ext_runtime_write_allowed(const struct nvme_xdev_ext_runtime_baseline *baseline)
{
	return baseline && baseline->native_read_ok && baseline->native_cqe_ok &&
	       baseline->opted_read_ok && baseline->bytes_match &&
	       baseline->cqe_match && baseline->preflight_ok &&
	       baseline->block_guard_ok && baseline->safety_rechecked;
}

static inline int
nvme_xdev_ext_runtime_block_guard_valid(int opened_exclusive, int block_device,
				   int sysfs_device_matches)
{
	return opened_exclusive && block_device && sysfs_device_matches;
}

static inline int
nvme_xdev_ext_runtime_media_reusable(enum nvme_xdev_ext_runtime_media_state state)
{
	return state == NVME_XDEV_EXT_RUNTIME_MEDIA_ORIGINAL ||
	       state == NVME_XDEV_EXT_RUNTIME_MEDIA_RESTORED;
}

static inline enum nvme_xdev_ext_runtime_media_state
nvme_xdev_ext_runtime_media_write_result(int completed_successfully)
{
	return completed_successfully ?
		NVME_XDEV_EXT_RUNTIME_MEDIA_PATTERN_PRESENT :
		NVME_XDEV_EXT_RUNTIME_MEDIA_TAINTED;
}

static inline enum nvme_xdev_ext_runtime_media_state
nvme_xdev_ext_runtime_media_restore_result(int verified)
{
	return verified ? NVME_XDEV_EXT_RUNTIME_MEDIA_RESTORED :
		NVME_XDEV_EXT_RUNTIME_MEDIA_TAINTED;
}

static inline enum nvme_xdev_ext_runtime_safety_result
nvme_xdev_ext_runtime_check_safety_for(const struct nvme_xdev_ext_runtime_safety *safety,
				  int wants_write, const char *expected_device,
				  const char *expected_serial)
{
	if (!safety || !safety->device)
		return NVME_XDEV_EXT_RUNTIME_SKIP_NO_DEVICE;
	if (!expected_device || !safety->canonical_device ||
	    strcmp(safety->device, expected_device) ||
	    strcmp(safety->canonical_device, expected_device))
		return NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE;
	if (!safety->model || !safety->serial || !expected_serial ||
	    strcmp(safety->model, NVME_XDEV_EXT_RUNTIME_EXPECTED_MODEL) ||
	    strcmp(safety->serial, expected_serial))
		return NVME_XDEV_EXT_RUNTIME_REJECT_IDENTITY;
	if (!safety->character_device)
		return NVME_XDEV_EXT_RUNTIME_REJECT_DEVICE_TYPE;
	if (!safety->sysfs_device_matches)
		return NVME_XDEV_EXT_RUNTIME_REJECT_SYSFS_MISMATCH;
	if (!safety->sibling_topology_matches)
		return NVME_XDEV_EXT_RUNTIME_REJECT_SIBLING_TOPOLOGY;
	if (!safety->virtual_machine)
		return NVME_XDEV_EXT_RUNTIME_REJECT_NOT_VM;
	if (safety->mounted)
		return NVME_XDEV_EXT_RUNTIME_REJECT_MOUNTED;
	if (safety->has_holders)
		return NVME_XDEV_EXT_RUNTIME_REJECT_HOLDERS;
	if (safety->has_partitions)
		return NVME_XDEV_EXT_RUNTIME_REJECT_PARTITIONS;
	if (safety->in_swap)
		return NVME_XDEV_EXT_RUNTIME_REJECT_SWAP;
	if (wants_write && !safety->allow_file_backed_write)
		return NVME_XDEV_EXT_RUNTIME_REJECT_WRITE_NOT_ALLOWED;
	return NVME_XDEV_EXT_RUNTIME_SAFE;
}

static inline enum nvme_xdev_ext_runtime_safety_result
nvme_xdev_ext_runtime_check_safety(const struct nvme_xdev_ext_runtime_safety *safety,
			      int wants_write)
{
	return nvme_xdev_ext_runtime_check_safety_for(safety, wants_write,
						 NVME_XDEV_EXT_RUNTIME_EXPECTED_DEVICE,
						 NVME_XDEV_EXT_RUNTIME_EXPECTED_SERIAL);
}

/*
 * --mech-s0 cases.  The harness attaches tools/xdev_ext_mech/nvme_s0.bpf.c with
 * global mode 0, 1 or 2 (or nothing) before each run; the runtime issues one
 * NVME_URING_CMD_F_XDEV_EXT_BUILD WRITE with cdw10..cdw12 zero and expects the
 * case's result.
 */
enum nvme_xdev_ext_runtime_mech_case {
	NVME_XDEV_EXT_RUNTIME_MECH_NONE = 0,
	NVME_XDEV_EXT_RUNTIME_MECH_LBA,	/* mode 0: in-window LBA from the request id */
	NVME_XDEV_EXT_RUNTIME_MECH_WINDOW,	/* mode 1: SLBA just past the window */
	NVME_XDEV_EXT_RUNTIME_MECH_RESERVED,	/* mode 2: a nonzero reserved dword */
	NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG,	/* no program attached */
};

static const char *const nvme_xdev_ext_runtime_mech_names_table[][2] = {
	[NVME_XDEV_EXT_RUNTIME_MECH_NONE] = { "", "" },
	[NVME_XDEV_EXT_RUNTIME_MECH_LBA] = { "lba", "lba_from_prog" },
	[NVME_XDEV_EXT_RUNTIME_MECH_WINDOW] = { "window", "window_reject" },
	[NVME_XDEV_EXT_RUNTIME_MECH_RESERVED] = { "reserved", "reserved_reject" },
	[NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG] = { "no-prog", "no_prog" },
};

static inline enum nvme_xdev_ext_runtime_mech_case
nvme_xdev_ext_runtime_mech_case_parse(const char *name)
{
	unsigned int c;

	if (!name || !name[0])
		return NVME_XDEV_EXT_RUNTIME_MECH_NONE;
	for (c = NVME_XDEV_EXT_RUNTIME_MECH_LBA; c <= NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG;
	     c++)
		if (!strcmp(name, nvme_xdev_ext_runtime_mech_names_table[c][0]))
			return (enum nvme_xdev_ext_runtime_mech_case)c;
	return NVME_XDEV_EXT_RUNTIME_MECH_NONE;
}

static inline const char *
nvme_xdev_ext_runtime_mech_case_name(enum nvme_xdev_ext_runtime_mech_case c)
{
	return c <= NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG ?
		nvme_xdev_ext_runtime_mech_names_table[c][0] : "";
}

/* Marker key the harness folds into XDEV_EXT_MECH_NVME_BUILD=PASS. */
static inline const char *
nvme_xdev_ext_runtime_mech_case_key(enum nvme_xdev_ext_runtime_mech_case c)
{
	return c <= NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG ?
		nvme_xdev_ext_runtime_mech_names_table[c][1] : "";
}

/* CQE res of the built WRITE: C validation rejects modes 1 and 2. */
static inline int
nvme_xdev_ext_runtime_mech_case_expected(enum nvme_xdev_ext_runtime_mech_case c)
{
	switch (c) {
	case NVME_XDEV_EXT_RUNTIME_MECH_LBA:
		return 0;
	case NVME_XDEV_EXT_RUNTIME_MECH_WINDOW:
		return -ERANGE;
	case NVME_XDEV_EXT_RUNTIME_MECH_RESERVED:
		return -EPERM;
	case NVME_XDEV_EXT_RUNTIME_MECH_NO_PROG:
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
}

/*
 * The SLBA tools/xdev_ext_mech/nvme_s0.bpf.c builds in mode 0: the request id
 * (the command's io_uring user_data) picks one of the window's whole
 * nlb-sized slots.
 */
static inline int nvme_xdev_ext_runtime_mech_s0_slba(uint64_t request_id,
						uint64_t window_slba,
						uint64_t window_nlb,
						uint64_t nlb, uint64_t *slba)
{
	if (!nlb || window_nlb < nlb)
		return -EINVAL;
	*slba = window_slba + request_id % (window_nlb / nlb) * nlb;
	return 0;
}

/* A window that holds one built WRITE, inside the namespace, read back whole. */
static inline int nvme_xdev_ext_runtime_mech_window_valid(uint64_t window_slba,
						     uint64_t window_nlb,
						     uint64_t capacity_lbas,
						     uint32_t lba_size)
{
	if (!lba_size || NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES % lba_size ||
	    window_nlb < NVME_XDEV_EXT_RUNTIME_MECH_IO_BYTES / lba_size)
		return -EINVAL;
	if (window_slba > capacity_lbas ||
	    window_nlb > capacity_lbas - window_slba)
		return -ERANGE;
	if (window_nlb > NVME_XDEV_EXT_RUNTIME_MECH_MAX_WINDOW_BYTES / lba_size)
		return -E2BIG;
	return 0;
}

/* Digits of a device number: 1..MAX_DIGITS, no leading zero. */
static inline unsigned int nvme_xdev_ext_runtime_mech_digits(const char *p)
{
	unsigned int n = 0;

	while (p[n] >= '0' && p[n] <= '9')
		n++;
	if (!n || n > NVME_XDEV_EXT_RUNTIME_MECH_MAX_DIGITS || (n > 1 && p[0] == '0'))
		return 0;
	return n;
}

/*
 * /dev/ng<C>n<N> to its nvme-generic, controller and block names
 * (ng<C>n<N>, nvme<C>, nvme<C>n<N>).  sysfs still has to show they are
 * siblings of one controller before anything is opened.
 */
static inline int nvme_xdev_ext_runtime_mech_names(const char *device,
					      char *generic, char *controller,
					      char *block, size_t size)
{
	static const char prefix[] = "/dev/ng";
	unsigned int c, n;
	const char *p;

	if (!device || strncmp(device, prefix, sizeof(prefix) - 1))
		return -EINVAL;
	p = device + sizeof(prefix) - 1;
	c = nvme_xdev_ext_runtime_mech_digits(p);
	if (!c || p[c] != 'n')
		return -EINVAL;
	n = nvme_xdev_ext_runtime_mech_digits(p + c + 1);
	if (!n || p[c + 1 + n])
		return -EINVAL;
	if ((size_t)snprintf(generic, size, "ng%s", p) >= size ||
	    (size_t)snprintf(controller, size, "nvme%.*s", (int)c, p) >= size ||
	    (size_t)snprintf(block, size, "nvme%s", p) >= size)
		return -ENAMETOOLONG;
	return 0;
}

#endif /* NVME_XDEV_EXT_PASSTHRU_RUNTIME_H */
