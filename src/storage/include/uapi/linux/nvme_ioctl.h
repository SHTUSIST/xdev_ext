/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Definitions for the NVM Express ioctl interface
 * Copyright (c) 2011-2014, Intel Corporation.
 */

#ifndef _UAPI_LINUX_NVME_IOCTL_H
#define _UAPI_LINUX_NVME_IOCTL_H

#include <linux/types.h>

struct nvme_user_io {
	__u8	opcode;
	__u8	flags;
	__u16	control;
	__u16	nblocks;
	__u16	rsvd;
	__u64	metadata;
	__u64	addr;
	__u64	slba;
	__u32	dsmgmt;
	__u32	reftag;
	__u16	apptag;
	__u16	appmask;
};

struct nvme_passthru_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32	result;
};

struct nvme_passthru_cmd64 {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	union {
		__u32	data_len; /* for non-vectored io */
		__u32	vec_cnt; /* for vectored io */
	};
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32   rsvd2;
	__u64	result;
};

/* same as struct nvme_passthru_cmd64, minus the 8b result field */
struct nvme_uring_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32   rsvd2;
};

/* Namespace io_uring passthrough policy flags carried in rsvd2. */
#define NVME_URING_CMD_F_XDEV_EXT		(1U << 0)
/*
 * With F_XDEV_EXT: the NVMe mechanism program of the ring's session builds SLBA
 * and NLB after the data is mapped; cdw2, cdw3 and cdw10..cdw15 must be 0.
 */
#define NVME_URING_CMD_F_XDEV_EXT_BUILD	(1U << 1)
#define NVME_URING_CMD_F_KNOWN_MASK	\
	(NVME_URING_CMD_F_XDEV_EXT | NVME_URING_CMD_F_XDEV_EXT_BUILD)

/*
 * XDEV_EXT LBA window handle.  NVME_IOCTL_XDEV_EXT_WINDOW on a /dev/ngXnY of a
 * live namespace returns a new O_CLOEXEC fd that names exactly
 * [slba, slba + nlb) of that namespace and the access in flags.  The caller's
 * fd and the native command policy must allow each granted access, and write
 * for any handle, because a handle reserves its range: while a handle, or a
 * session created from it, lives, issuing another handle of the same
 * namespace that shares an LBA with it fails with -EBUSY unless both are
 * read-only.  The handle has no other operation.  Passed (for example over
 * SCM_RIGHTS) as an NVMe mechanism stage fd in place of /dev/ngXnY, it bounds
 * the stage: CREATE fails with -EBADF for an ungranted direction and with
 * -EACCES unless the stage window lies inside the handle, and every command
 * the stage's program builds is admitted only inside that window.  Tenants are
 * isolated from each other only when they receive handles, never the
 * namespace node, which keeps whole-namespace passthrough.
 */
#define NVME_XDEV_EXT_WINDOW_F_READ	(1U << 0)
#define NVME_XDEV_EXT_WINDOW_F_WRITE	(1U << 1)

struct nvme_xdev_ext_window {
	__u64	slba;
	__u64	nlb;
	__u32	flags;		/* NVME_XDEV_EXT_WINDOW_F_* */
	__u32	rsvd;		/* zero */
};

#define nvme_admin_cmd nvme_passthru_cmd

#define NVME_IOCTL_ID		_IO('N', 0x40)
#define NVME_IOCTL_ADMIN_CMD	_IOWR('N', 0x41, struct nvme_admin_cmd)
#define NVME_IOCTL_SUBMIT_IO	_IOW('N', 0x42, struct nvme_user_io)
#define NVME_IOCTL_IO_CMD	_IOWR('N', 0x43, struct nvme_passthru_cmd)
#define NVME_IOCTL_RESET	_IO('N', 0x44)
#define NVME_IOCTL_SUBSYS_RESET	_IO('N', 0x45)
#define NVME_IOCTL_RESCAN	_IO('N', 0x46)
#define NVME_IOCTL_ADMIN64_CMD	_IOWR('N', 0x47, struct nvme_passthru_cmd64)
#define NVME_IOCTL_IO64_CMD	_IOWR('N', 0x48, struct nvme_passthru_cmd64)
#define NVME_IOCTL_IO64_CMD_VEC	_IOWR('N', 0x49, struct nvme_passthru_cmd64)

/* io_uring async commands: */
#define NVME_URING_CMD_IO	_IOWR('N', 0x80, struct nvme_uring_cmd)
#define NVME_URING_CMD_IO_VEC	_IOWR('N', 0x81, struct nvme_uring_cmd)
#define NVME_URING_CMD_ADMIN	_IOWR('N', 0x82, struct nvme_uring_cmd)
#define NVME_URING_CMD_ADMIN_VEC _IOWR('N', 0x83, struct nvme_uring_cmd)

/*
 * XDEV_EXT, outside the registered upstream 'N' ranges; 0xe0 and 0xe1 are the
 * XDEV_EXT_PEER_NVME_* commands of <linux/xdev_ext_peer.h>.
 */
#define NVME_IOCTL_XDEV_EXT_WINDOW	_IOW('N', 0xe2, struct nvme_xdev_ext_window)

#endif /* _UAPI_LINUX_NVME_IOCTL_H */
