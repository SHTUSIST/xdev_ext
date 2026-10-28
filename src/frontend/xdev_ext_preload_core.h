/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_CORE_H
#define XDEV_EXT_PRELOAD_CORE_H

/*
 * Policy, fault-reporting host copies and request encoding for the frontend.
 * Keep this
 * header independent of liburing so host tests can exercise every fallback
 * and completion decision with a fake submit seam.
 */
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/uio.h>

/* Always consume the ABI from this source tree. */
#include "../include/uapi/linux/io_uring.h"

/* Keep the fcntl vararg ABI complete even when this preload library is built
 * against libc headers older than the kernel UAPI shipped in this tree. */
#define XDEV_EXT_F_GETOWNER_UIDS 17
#define XDEV_EXT_F_DUPFD_QUERY 1027
#define XDEV_EXT_F_CREATED_QUERY 1028
#define XDEV_EXT_F_CANCELLK 1029

enum xdev_ext_fcntl_arg_kind {
	XDEV_EXT_FCNTL_NO_ARG,
	XDEV_EXT_FCNTL_INT_ARG,
	XDEV_EXT_FCNTL_POINTER_ARG,
};

static inline enum xdev_ext_fcntl_arg_kind
xdev_ext_preload_fcntl_arg_kind(int command)
{
	switch (command) {
	case F_GETFD:
	case F_GETFL:
#ifdef F_GETOWN
	case F_GETOWN:
#endif
#ifdef F_GETSIG
	case F_GETSIG:
#endif
#ifdef F_GETLEASE
	case F_GETLEASE:
#endif
#ifdef F_GETPIPE_SZ
	case F_GETPIPE_SZ:
#endif
#ifdef F_GET_SEALS
	case F_GET_SEALS:
#endif
	case XDEV_EXT_F_CREATED_QUERY:
		return XDEV_EXT_FCNTL_NO_ARG;
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
#if defined(F_GETLK64) && F_GETLK64 != F_GETLK
	case F_GETLK64:
	case F_SETLK64:
	case F_SETLKW64:
#endif
#ifdef F_OFD_GETLK
	case F_OFD_GETLK:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
#endif
#ifdef F_GETOWN_EX
	case F_GETOWN_EX:
	case F_SETOWN_EX:
#endif
#ifdef F_GET_RW_HINT
	case F_GET_RW_HINT:
	case F_SET_RW_HINT:
	case F_GET_FILE_RW_HINT:
	case F_SET_FILE_RW_HINT:
#endif
	case XDEV_EXT_F_GETOWNER_UIDS:
	case XDEV_EXT_F_CANCELLK:
		return XDEV_EXT_FCNTL_POINTER_ARG;
	/* Every remaining command in the current Linux UAPI takes an integer:
	 * DUPFD[_CLOEXEC|_QUERY], SETFD/SETFL/SETOWN/SETSIG, leases,
	 * directory notification, pipe sizing, and seals. */
	default:
		return XDEV_EXT_FCNTL_INT_ARG;
	}
}

/*
 * Why one call stayed in libc.  The front end counts these per process and
 * reports them next to the taken-over calls, so that the fraction of an
 * application's calls that qualified can be computed.  "other" covers a null
 * or empty buffer, unknown DIO alignment, an unwritable read destination,
 * unreadable vector metadata and preadv2/pwritev2 flags.
 */
enum xdev_ext_preload_fallback_reason {
	XDEV_EXT_PRELOAD_FALLBACK_NONE,
	XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_ALLOWLISTED,
	XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_DIRECT,
	XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED,
	XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE,
	XDEV_EXT_PRELOAD_FALLBACK_FILE_RUNTIME_ABSENT,
	XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER,
	/* read()/write() on a tracked file: only positional calls qualify. */
	XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_POSITIONAL,
	/* Not a connected AF_INET/AF_INET6 UDP socket. */
	XDEV_EXT_PRELOAD_FALLBACK_SOCKET_INELIGIBLE,
	XDEV_EXT_PRELOAD_FALLBACK_SOCKET_RUNTIME_ABSENT,
	/* The socket's mechanism session could not be stopped, or none is free. */
	XDEV_EXT_PRELOAD_FALLBACK_SOCKET_MECH_UNAVAILABLE,
	XDEV_EXT_PRELOAD_FALLBACK_SOCKET_OTHER,
	XDEV_EXT_PRELOAD_FALLBACK_NR,
};

static inline const char *
xdev_ext_preload_fallback_name(enum xdev_ext_preload_fallback_reason reason)
{
	static const char *const names[XDEV_EXT_PRELOAD_FALLBACK_NR] = {
		[XDEV_EXT_PRELOAD_FALLBACK_NONE] = "none",
		[XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_ALLOWLISTED] = "file_not_allowlisted",
		[XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_DIRECT] = "file_not_direct",
		[XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED] = "file_misaligned",
		[XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE] = "file_size",
		[XDEV_EXT_PRELOAD_FALLBACK_FILE_RUNTIME_ABSENT] = "file_runtime_absent",
		[XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER] = "file_other",
		[XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_POSITIONAL] = "file_not_positional",
		[XDEV_EXT_PRELOAD_FALLBACK_SOCKET_INELIGIBLE] = "socket_ineligible",
		[XDEV_EXT_PRELOAD_FALLBACK_SOCKET_RUNTIME_ABSENT] = "socket_runtime_absent",
		[XDEV_EXT_PRELOAD_FALLBACK_SOCKET_MECH_UNAVAILABLE] =
			"socket_mech_unavailable",
		[XDEV_EXT_PRELOAD_FALLBACK_SOCKET_OTHER] = "socket_other",
	};

	return (unsigned int)reason < XDEV_EXT_PRELOAD_FALLBACK_NR ?
	       names[reason] : "invalid";
}

struct xdev_ext_preload_fd_meta {
	bool tracked;
	bool identity_matches;
	bool direct;
	size_t frame_size;
	uint32_t dio_mem_align;
	uint32_t dio_offset_align;
	/* Why the descriptor was refused, when its validation failed. */
	enum xdev_ext_preload_fallback_reason refused;
};

struct xdev_ext_preload_fd_identity {
	dev_t dev;
	ino_t ino;
	mode_t mode;
};

struct xdev_ext_preload_report_snapshot {
	uint64_t read_count;
	uint64_t write_count;
	uint64_t read_bytes;
	uint64_t write_bytes;
	uint32_t read_errors;
	uint32_t write_errors;
};

static inline bool
xdev_ext_preload_fd_identity_matches(const struct xdev_ext_preload_fd_identity *expected,
				const struct xdev_ext_preload_fd_identity *observed,
				bool path_allowed, int status_flags)
{
	bool same_type;

	if (!expected || !observed || !path_allowed || !(status_flags & O_DIRECT))
		return false;
	same_type = (S_ISREG(expected->mode) && S_ISREG(observed->mode)) ||
		    (S_ISBLK(expected->mode) && S_ISBLK(observed->mode));
	return expected->dev == observed->dev && expected->ino == observed->ino &&
	       same_type;
}

/*
 * A descriptor record names one object at one allowlisted path.  A clear
 * O_DIRECT flag only makes the current call ineligible, because F_SETFL can
 * set it again; a different object, file type or path means the descriptor
 * number now refers to something else and the record must be retired.
 */
static inline bool
xdev_ext_preload_fd_record_stale(const struct xdev_ext_preload_fd_identity *expected,
			    const struct xdev_ext_preload_fd_identity *observed,
			    bool path_allowed)
{
	return !xdev_ext_preload_fd_identity_matches(expected, observed, path_allowed,
						O_DIRECT);
}

struct xdev_ext_preload_token_source {
	uint32_t owner_pid;
	uint32_t owner_tid;
	uint32_t sequence;
};

struct xdev_ext_preload_seam {
	void *opaque;
	int (*submit_and_wait)(void *opaque, const struct io_uring_sqe *sqe,
			       int *cqe_res, bool *published);
	ssize_t (*fallback)(void *opaque, int fd, void *buf, size_t count,
			    int64_t offset, bool write, int *error);
	/* This process's ID when the caller already knows it; 0 looks it up. */
	pid_t self_pid;
};

struct xdev_ext_preload_iov_seam {
	void *opaque;
	int (*submit_and_wait)(void *opaque, const struct io_uring_sqe *sqe,
			       int *cqe_res, bool *published);
	ssize_t (*fallback)(void *opaque, int fd, const struct iovec *iov,
			    int iovcnt, int64_t offset, bool write, int flags,
			    int *error);
	/* This process's ID when the caller already knows it; 0 looks it up. */
	pid_t self_pid;
};

struct xdev_ext_preload_send_seam {
	void *opaque;
	int (*submit_and_wait)(void *opaque, const struct io_uring_sqe *sqe,
			       int *cqe_res, bool *published);
	ssize_t (*fallback)(void *opaque, int fd, const void *buffer,
			    size_t count, uint32_t flags, int *error);
};

struct xdev_ext_preload_ring_seam {
	void *opaque;
	int (*publish_once)(void *opaque, const struct io_uring_sqe *sqe);
	/* Return 1 with result, 0 when absent, or a negative errno. */
	int (*peek_completion)(void *opaque, uint64_t token, int *result);
	bool (*request_accepted)(void *opaque);
	/* to_submit is one until the published entry is accepted, then zero. */
	int (*enter_and_wait)(void *opaque, unsigned int to_submit);
};

/*
 * A published request may already be owned by the kernel or device.  Only a
 * matching CQE proves that the backing can be unregistered and freed.  Ring
 * close by itself is deliberately not treated as a DMA-quiescence barrier.
 */
static inline bool
xdev_ext_preload_can_release_backing(bool published, bool terminal_completion)
{
	return !published || terminal_completion;
}

static inline int
xdev_ext_preload_submit_and_drain(const struct xdev_ext_preload_ring_seam *seam,
			     const struct io_uring_sqe *sqe, int *result,
			     bool *published)
{
	int ret;

	if (!seam || !seam->publish_once || !seam->peek_completion ||
	    !seam->request_accepted || !seam->enter_and_wait || !sqe ||
	    !result || !published)
		return -EINVAL;
	*published = false;
	ret = seam->publish_once(seam->opaque, sqe);
	if (ret < 0)
		return ret;
	*published = true;
	for (;;) {
		ret = seam->peek_completion(seam->opaque, sqe->user_data, result);
		if (ret > 0)
			return 0;
		if (ret < 0)
			return ret;
		ret = seam->enter_and_wait(seam->opaque,
					   seam->request_accepted(seam->opaque) ? 0 : 1);
		if (ret < 0 && ret != -EINTR)
			return ret;
	}
}

static inline bool xdev_ext_preload_context_stale(uint32_t owner_pid,
					     uint32_t current_pid)
{
	return owner_pid && owner_pid != current_pid;
}

static inline uint64_t
xdev_ext_preload_next_token(struct xdev_ext_preload_token_source *source,
		       uint32_t current_pid, uint32_t current_tid)
{
	uint64_t token;

	if (!source)
		return 0;
	if (source->owner_pid != current_pid ||
	    source->owner_tid != current_tid) {
		source->owner_pid = current_pid;
		source->owner_tid = current_tid;
		source->sequence = 0;
	}
	do {
		source->sequence++;
		token = ((uint64_t)current_tid << 32) | source->sequence;
	} while (!token);
	return token;
}

static inline bool
xdev_ext_preload_is_eligible(const struct xdev_ext_preload_fd_meta *meta,
			const void *buffer, size_t count, int64_t offset)
{
	uint64_t end;

	if (!meta || !meta->tracked || !meta->identity_matches || !meta->direct)
		return false;
	if (!buffer || !count || !meta->frame_size ||
	    !meta->dio_mem_align || !meta->dio_offset_align)
		return false;
	if (count > meta->frame_size || count > UINT32_MAX || offset < 0)
		return false;
	if ((uintptr_t)buffer % meta->dio_mem_align ||
	    count % meta->dio_mem_align ||
	    (uint64_t)offset % meta->dio_offset_align ||
	    count % meta->dio_offset_align)
		return false;
	end = (uint64_t)offset + count;
	if (end < (uint64_t)offset || end > INT64_MAX)
		return false;
	return true;
}

/* These bits are stripped by Linux's send/sendto/sendmsg syscall entry before
 * a protocol sees them.  The unified SEND UAPI deliberately rejects them, so
 * the transparent front end falls back before publishing an SQE. */
#define XDEV_EXT_PRELOAD_MSG_INTERNAL_SEND_FLAGS UINT32_C(0x08110000)
#define XDEV_EXT_PRELOAD_MSG_ALLOWED_SEND_FLAGS \
	((uint32_t)(MSG_DONTWAIT | MSG_NOSIGNAL | MSG_MORE))

static inline bool
xdev_ext_preload_send_buffer_supported(const void *buffer, size_t count)
{
	return (!count || buffer) && count <= UINT32_MAX &&
	       count <= (size_t)SSIZE_MAX;
}

static inline bool xdev_ext_preload_send_flags_supported(uint32_t flags)
{
	/* Keep the first transparent scope narrow.  In particular, zerocopy and
	 * fast-open carry completion or connection semantics that this synchronous
	 * connected-datagram wrapper does not reproduce. */
	return !(flags & ~XDEV_EXT_PRELOAD_MSG_ALLOWED_SEND_FLAGS);
}

static inline uint32_t
xdev_ext_preload_send_effective_flags(int status_flags, int call_flags)
{
	uint32_t flags = (uint32_t)call_flags;

	if (status_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	return flags;
}

static inline bool
xdev_ext_preload_sendto_shape_supported(const struct sockaddr *destination,
				   socklen_t destination_length)
{
	return !destination && !destination_length;
}

static inline bool
xdev_ext_preload_sendmsg_shape_supported(const struct msghdr *message,
				    const void **buffer_out,
				    size_t *count_out)
{
	const struct iovec *iov;

	if (buffer_out)
		*buffer_out = NULL;
	if (count_out)
		*count_out = 0;
	if (!message || !buffer_out || !count_out || message->msg_name ||
	    message->msg_namelen || message->msg_control ||
	    message->msg_controllen || !message->msg_iov ||
	    message->msg_iovlen != 1)
		return false;
	iov = message->msg_iov;
	if (!xdev_ext_preload_send_buffer_supported(iov->iov_base, iov->iov_len))
		return false;
	*buffer_out = iov->iov_base;
	*count_out = iov->iov_len;
	return true;
}

static inline bool
xdev_ext_preload_iov_is_eligible(const struct xdev_ext_preload_fd_meta *meta,
			    const struct iovec *iov, int iovcnt, int64_t offset,
			    size_t *total_out)
{
	size_t total = 0;
	int i;

	if (total_out)
		*total_out = 0;
	if (!meta || !meta->tracked || !meta->identity_matches || !meta->direct ||
	    !meta->frame_size || !meta->dio_mem_align ||
	    !meta->dio_offset_align || !iov || iovcnt <= 0 ||
	    iovcnt > IOV_MAX || offset < 0)
		return false;
	for (i = 0; i < iovcnt; i++) {
		size_t length = iov[i].iov_len;

		if (!length)
			continue;
		if (!iov[i].iov_base ||
		    (uintptr_t)iov[i].iov_base % meta->dio_mem_align ||
		    length % meta->dio_mem_align ||
		    length % meta->dio_offset_align ||
		    length > meta->frame_size - total)
			return false;
		total += length;
	}
	if (!total || total > UINT32_MAX || total > (size_t)SSIZE_MAX ||
	    (uint64_t)offset % meta->dio_offset_align ||
	    (uint64_t)offset + total < (uint64_t)offset ||
	    (uint64_t)offset + total > INT64_MAX)
		return false;
	if (total_out)
		*total_out = total;
	return true;
}

/* Kernel-mediated self copies report inaccessible caller memory without a
 * process-wide signal handler. Never probe and then memcpy the caller pointer.
 * A short copy is a real prefix, not permission to retry an accepted request.
 * pid must be this process: a cached value is valid only while the caller
 * knows that no fork happened since it was read (0 looks it up).
 */
static inline ssize_t
xdev_ext_preload_user_copy_vec(pid_t pid, void *local_buffer, size_t bytes,
			       const struct iovec *remote, unsigned long count,
			       bool to_user)
{
	struct iovec local = { .iov_base = local_buffer, .iov_len = bytes };

	if (!bytes)
		return 0;
	if (!pid)
		pid = getpid();
	/* syscall() consumes machine words; in particular its stack-passed flags
	 * must not leave the upper half of an argument slot uninitialized. */
	return syscall(to_user ? SYS_process_vm_writev : SYS_process_vm_readv,
		       (long)pid, &local, 1UL, remote, count, 0UL);
}

static inline ssize_t
xdev_ext_preload_user_copy_pid(pid_t pid, void *local_buffer, void *user_buffer,
			       size_t bytes, bool to_user)
{
	struct iovec remote = { .iov_base = user_buffer, .iov_len = bytes };

	return xdev_ext_preload_user_copy_vec(pid, local_buffer, bytes, &remote,
					      1UL, to_user);
}

static inline ssize_t
xdev_ext_preload_user_copy(void *local_buffer, void *user_buffer, size_t bytes,
                          bool to_user)
{
	return xdev_ext_preload_user_copy_pid(0, local_buffer, user_buffer, bytes,
					      to_user);
}

/* One copy for the whole vector: the remote side may hold IOV_MAX elements. */
static inline bool
xdev_ext_preload_iov_gather_pid(pid_t pid, void *staging, size_t staging_size,
				const struct iovec *iov, int iovcnt, size_t total)
{
	size_t capacity = 0;
	int i;

	if (!staging || !iov || iovcnt <= 0 || iovcnt > IOV_MAX ||
	    !total || total > staging_size)
		return false;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > SIZE_MAX - capacity)
			return false;
		capacity += iov[i].iov_len;
	}
	if (capacity != total)
		return false;
	return xdev_ext_preload_user_copy_vec(pid, staging, total, iov,
					      (unsigned long)iovcnt, false) ==
	       (ssize_t)total;
}

static inline bool
xdev_ext_preload_iov_gather(void *staging, size_t staging_size,
		       const struct iovec *iov, int iovcnt, size_t total)
{
	return xdev_ext_preload_iov_gather_pid(0, staging, staging_size, iov,
					       iovcnt, total);
}

/*
 * Copy the first bytes of staging out to the vector.  Whole elements go in
 * one copy; a prefix that ends inside an element copies that element's part
 * with a second one, so no byte past the prefix is written.  The kernel copies
 * in order, so a fault reports exactly the bytes before it.
 */
static inline ssize_t
xdev_ext_preload_iov_scatter_prefix_pid(pid_t pid, const struct iovec *iov,
					int iovcnt, const void *staging,
					size_t bytes)
{
	size_t capacity = 0;
	size_t whole = 0;
	ssize_t ret;
	int i, n;

	if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX || (!staging && bytes))
		return -1;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > SIZE_MAX - capacity)
			return -1;
		capacity += iov[i].iov_len;
	}
	if (bytes > capacity)
		return -1;
	if (!bytes)
		return 0;
	for (n = 0; n < iovcnt && iov[n].iov_len <= bytes - whole; n++)
		whole += iov[n].iov_len;
	if (whole) {
		ret = xdev_ext_preload_user_copy_vec(pid, (void *)staging, whole,
						     iov, (unsigned long)n, true);
		if (ret != (ssize_t)whole)
			return ret > 0 ? ret : -1;
	}
	if (whole == bytes)
		return (ssize_t)whole;
	/* iov[n] holds the rest of the prefix and more. */
	ret = xdev_ext_preload_user_copy_pid(
		pid, (void *)((const unsigned char *)staging + whole),
		iov[n].iov_base, bytes - whole, true);
	if (ret > 0)
		whole += (size_t)ret;
	return whole ? (ssize_t)whole : -1;
}

static inline ssize_t
xdev_ext_preload_iov_scatter_prefix(const struct iovec *iov, int iovcnt,
			const void *staging, size_t bytes)
{
	return xdev_ext_preload_iov_scatter_prefix_pid(0, iov, iovcnt, staging,
						       bytes);
}

static inline bool
xdev_ext_preload_iov_scatter(const struct iovec *iov, int iovcnt,
			const void *staging, size_t bytes)
{
	return xdev_ext_preload_iov_scatter_prefix(iov, iovcnt, staging, bytes) ==
	       (ssize_t)bytes;
}

/*
 * A report is advisory evidence, never a reason to relax the backing-lifetime
 * rule.  The quiescence guard deliberately precedes every shared-memory access.
 * A busy statistics lock makes this snapshot unavailable instead of racing the
 * kernel's multi-field update.
 */
static inline bool
xdev_ext_preload_snapshot_report(bool report_enabled, bool quiescence_unknown,
			    struct io_uring_unified_shared *shared,
			    struct xdev_ext_preload_report_snapshot *snapshot)
{
	uint32_t expected = 0;

	if (!report_enabled || quiescence_unknown || !shared || !snapshot)
		return false;
	if (!__atomic_compare_exchange_n(&shared->lock, &expected, 1, false,
					 __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return false;
	snapshot->read_count = __atomic_load_n(&shared->read_count,
						__ATOMIC_RELAXED);
	snapshot->write_count = __atomic_load_n(&shared->send_count,
						 __ATOMIC_RELAXED);
	snapshot->read_bytes = __atomic_load_n(&shared->read_bytes,
						__ATOMIC_RELAXED);
	snapshot->write_bytes = __atomic_load_n(&shared->send_bytes,
						 __ATOMIC_RELAXED);
	snapshot->read_errors = __atomic_load_n(&shared->read_errors,
						 __ATOMIC_RELAXED);
	snapshot->write_errors = __atomic_load_n(&shared->send_errors,
						  __ATOMIC_RELAXED);
	__atomic_store_n(&shared->lock, 0, __ATOMIC_RELEASE);
	return true;
}

static inline void
xdev_ext_preload_encode_sqe(struct io_uring_sqe *sqe, int fd, uint32_t count,
		       int64_t offset, bool write, uint64_t user_data)
{
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_UNIFIED_OPS;
	sqe->flags = IOSQE_XDEV_EXT_UMEM;
	sqe->fd = fd;
	sqe->addr = 0;
	sqe->len = write ? IO_UNIFIED_OP_WRITE_COMPAT :
			   IO_UNIFIED_OP_READ_COMPAT;
	sqe->rw_flags = count;
	sqe->off = (uint64_t)offset;
	sqe->user_data = user_data;
}

static inline void
xdev_ext_preload_encode_send_sqe(struct io_uring_sqe *sqe, int fd,
			    const void *buffer, uint32_t count,
			    uint32_t send_flags, uint64_t shared_addr,
			    uint64_t user_data)
{
	static const unsigned char zero_length_buffer;

	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_UNIFIED_OPS;
	sqe->fd = fd;
	/* The kernel rejects addr == 0 before it knows that len is zero. */
	sqe->addr = (uintptr_t)(buffer ? buffer : &zero_length_buffer);
	sqe->len = IO_UNIFIED_OP_SEND;
	sqe->rw_flags = count;
	sqe->off = send_flags;
	sqe->addr3 = shared_addr;
	sqe->user_data = user_data;
}

/* Execute one synchronous connected-datagram SEND.  A pre-publication failure
 * may use libc once; an accepted request is always drained and never replayed. */
static inline ssize_t
xdev_ext_preload_execute_send(bool socket_eligible, int fd, const void *buffer,
			 size_t count, uint32_t send_flags, uint64_t shared_addr,
			 uint64_t user_data,
			 const struct xdev_ext_preload_send_seam *seam, int *error)
{
	struct io_uring_sqe sqe;
	bool published = false;
	int cqe_res = 0;
	int ret;

	if (!error || !seam || !seam->fallback || !seam->submit_and_wait)
		return -1;
	*error = 0;
	if (!socket_eligible || !shared_addr ||
	    !xdev_ext_preload_send_buffer_supported(buffer, count) ||
	    !xdev_ext_preload_send_flags_supported(send_flags))
		return seam->fallback(seam->opaque, fd, buffer, count, send_flags,
				      error);

	xdev_ext_preload_encode_send_sqe(&sqe, fd, buffer, (uint32_t)count,
				     send_flags, shared_addr, user_data);
	ret = seam->submit_and_wait(seam->opaque, &sqe, &cqe_res, &published);
	if (ret < 0) {
		if (!published)
			return seam->fallback(seam->opaque, fd, buffer, count,
					      send_flags, error);
		*error = -ret;
		return -1;
	}
	if (cqe_res < 0) {
		*error = -cqe_res;
		return -1;
	}
	if ((size_t)cqe_res > count) {
		*error = EIO;
		return -1;
	}
	return cqe_res;
}

/*
 * Execute exactly one synchronous positional request.  Once the SQE has been
 * published to the ring, an infrastructure error is returned to the caller;
 * libc is never called because the kernel may already own the request.
 */
static inline ssize_t
xdev_ext_preload_execute(const struct xdev_ext_preload_fd_meta *meta, int fd,
		    void *user_buffer, size_t count, int64_t offset, bool write,
		    void *staging, uint64_t user_data,
		    const struct xdev_ext_preload_seam *seam, int *error)
{
	struct io_uring_sqe sqe;
	bool published = false;
	int cqe_res = 0;
	int ret;

	if (!error || !seam || !seam->fallback || !seam->submit_and_wait)
		return -1;
	*error = 0;
	if (!xdev_ext_preload_is_eligible(meta, user_buffer, count, offset) ||
	    !staging)
		return seam->fallback(seam->opaque, fd, user_buffer, count,
				      offset, write, error);

	if (write && xdev_ext_preload_user_copy_pid(seam->self_pid, staging,
						    user_buffer, count, false) !=
	    (ssize_t)count)
		return seam->fallback(seam->opaque, fd, user_buffer, count,
				      offset, write, error);
	xdev_ext_preload_encode_sqe(&sqe, fd, (uint32_t)count, offset, write,
			       user_data);
	ret = seam->submit_and_wait(seam->opaque, &sqe, &cqe_res, &published);
	if (ret < 0) {
		if (!published)
			return seam->fallback(seam->opaque, fd, user_buffer, count,
					      offset, write, error);
		*error = -ret;
		return -1;
	}
	if (cqe_res < 0) {
		*error = -cqe_res;
		return -1;
	}
	if ((size_t)cqe_res > count) {
		*error = EIO;
		return -1;
	}
	if (!write && cqe_res) {
		ssize_t copied = xdev_ext_preload_user_copy_pid(seam->self_pid,
							staging, user_buffer,
							(size_t)cqe_res, true);

		if (copied <= 0) {
			*error = EFAULT;
			return -1;
		}
		return copied;
	}
	return cqe_res;
}

static inline ssize_t
xdev_ext_preload_execute_iov(const struct xdev_ext_preload_fd_meta *meta, int fd,
			const struct iovec *iov, int iovcnt, int64_t offset,
			bool write, int flags, void *staging, uint64_t user_data,
			const struct xdev_ext_preload_iov_seam *seam, int *error)
{
	struct io_uring_sqe sqe;
	bool published = false;
	size_t total = 0;
	int cqe_res = 0;
	int ret;

	if (!error || !seam || !seam->fallback || !seam->submit_and_wait)
		return -1;
	*error = 0;
	if (flags || !staging ||
	    !xdev_ext_preload_iov_is_eligible(meta, iov, iovcnt, offset, &total))
		return seam->fallback(seam->opaque, fd, iov, iovcnt, offset,
				      write, flags, error);
	if (write && !xdev_ext_preload_iov_gather_pid(seam->self_pid, staging,
						      meta->frame_size, iov,
						      iovcnt, total))
		return seam->fallback(seam->opaque, fd, iov, iovcnt, offset,
				      write, flags, error);
	xdev_ext_preload_encode_sqe(&sqe, fd, (uint32_t)total, offset, write,
			       user_data);
	ret = seam->submit_and_wait(seam->opaque, &sqe, &cqe_res, &published);
	if (ret < 0) {
		if (!published)
			return seam->fallback(seam->opaque, fd, iov, iovcnt,
					      offset, write, flags, error);
		*error = -ret;
		return -1;
	}
	if (cqe_res < 0) {
		*error = -cqe_res;
		return -1;
	}
	if ((size_t)cqe_res > total) {
		*error = EIO;
		return -1;
	}
	if (!write && cqe_res) {
		ssize_t copied = xdev_ext_preload_iov_scatter_prefix_pid(
			seam->self_pid, iov, iovcnt, staging, (size_t)cqe_res);

		if (copied < 0)
			*error = EFAULT;
		return copied;
	}
	return cqe_res;
}

static inline enum xdev_ext_preload_fallback_reason
xdev_ext_preload_meta_fallback_reason(const struct xdev_ext_preload_fd_meta *meta)
{
	if (!meta || !meta->tracked || !meta->identity_matches)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_ALLOWLISTED;
	if (!meta->direct)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_DIRECT;
	if (!meta->frame_size || !meta->dio_mem_align || !meta->dio_offset_align)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER;
	return XDEV_EXT_PRELOAD_FALLBACK_NONE;
}

/* NONE exactly when xdev_ext_preload_is_eligible() admits the call. */
static inline enum xdev_ext_preload_fallback_reason
xdev_ext_preload_fallback_reason(const struct xdev_ext_preload_fd_meta *meta,
				 const void *buffer, size_t count, int64_t offset)
{
	enum xdev_ext_preload_fallback_reason reason;
	uint64_t end;

	reason = xdev_ext_preload_meta_fallback_reason(meta);
	if (reason != XDEV_EXT_PRELOAD_FALLBACK_NONE)
		return reason;
	if (!buffer || !count)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER;
	if (count > meta->frame_size || count > UINT32_MAX || offset < 0)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE;
	if ((uintptr_t)buffer % meta->dio_mem_align ||
	    count % meta->dio_mem_align ||
	    (uint64_t)offset % meta->dio_offset_align ||
	    count % meta->dio_offset_align)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED;
	end = (uint64_t)offset + count;
	if (end < (uint64_t)offset || end > INT64_MAX)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE;
	return XDEV_EXT_PRELOAD_FALLBACK_NONE;
}

/* NONE exactly when xdev_ext_preload_iov_is_eligible() admits the call. */
static inline enum xdev_ext_preload_fallback_reason
xdev_ext_preload_iov_fallback_reason(const struct xdev_ext_preload_fd_meta *meta,
				     const struct iovec *iov, int iovcnt,
				     int64_t offset)
{
	enum xdev_ext_preload_fallback_reason reason;
	size_t total = 0;
	int i;

	reason = xdev_ext_preload_meta_fallback_reason(meta);
	if (reason != XDEV_EXT_PRELOAD_FALLBACK_NONE)
		return reason;
	if (!iov || iovcnt <= 0)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER;
	if (iovcnt > IOV_MAX || offset < 0)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE;
	for (i = 0; i < iovcnt; i++) {
		size_t length = iov[i].iov_len;

		if (!length)
			continue;
		if (!iov[i].iov_base)
			return XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER;
		if ((uintptr_t)iov[i].iov_base % meta->dio_mem_align ||
		    length % meta->dio_mem_align ||
		    length % meta->dio_offset_align)
			return XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED;
		if (length > meta->frame_size - total)
			return XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE;
		total += length;
	}
	if (!total)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER;
	if (total > UINT32_MAX || total > (size_t)SSIZE_MAX)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE;
	if ((uint64_t)offset % meta->dio_offset_align)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_MISALIGNED;
	if ((uint64_t)offset + total < (uint64_t)offset ||
	    (uint64_t)offset + total > INT64_MAX)
		return XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE;
	return XDEV_EXT_PRELOAD_FALLBACK_NONE;
}

/*
 * Advisory check that every read destination is mapped writable, from the
 * text of /proc/self/maps read through a positional reader with no FILE
 * buffer.  It reads the same pieces as the
 * fgets() scan it replaces: lines of at most XDEV_EXT_PRELOAD_MAPS_LINE - 1
 * bytes, where only the first piece of a line can be a mapping header, and no
 * more than XDEV_EXT_PRELOAD_MAPS_SCAN_LIMIT bytes per call.
 */
#define XDEV_EXT_PRELOAD_MAPS_LINE 512U
#define XDEV_EXT_PRELOAD_MAPS_SCAN_LIMIT (1024U * 1024U)

struct xdev_ext_preload_maps_reader {
	/* Bytes read at offset, 0 at the end, or a negative errno. */
	ssize_t (*read_at)(void *opaque, void *buffer, size_t length,
			   uint64_t offset);
	void *opaque;
	/* The caller's read buffer; capacity bytes, at least one. */
	char *buffer;
	size_t capacity;
	uint64_t offset;
	size_t start, end;
	bool failed;
};

/* fgets() over read_at: NULL at the end, or after a read error. */
static inline char *
xdev_ext_preload_maps_gets(struct xdev_ext_preload_maps_reader *r, char *line,
			   size_t size)
{
	size_t used = 0;

	if (!size || !r->buffer || !r->capacity)
		return NULL;
	while (used + 1 < size) {
		char c;

		if (r->start == r->end) {
			ssize_t got;

			if (r->failed)
				return NULL;
			got = r->read_at(r->opaque, r->buffer, r->capacity,
					 r->offset);
			if (got < 0 || (size_t)got > r->capacity) {
				r->failed = true;
				return NULL;
			}
			if (!got)
				break;
			r->offset += (uint64_t)got;
			r->start = 0;
			r->end = (size_t)got;
		}
		c = r->buffer[r->start++];
		line[used++] = c;
		if (c == '\n')
			break;
	}
	if (!used)
		return NULL;
	line[used] = '\0';
	return line;
}

/* cursor holds iovcnt entries of scratch space. */
static inline bool
xdev_ext_preload_maps_text_writable(struct xdev_ext_preload_maps_reader *r,
				    const struct iovec *iov, int iovcnt,
				    uintptr_t *cursor)
{
	unsigned long low, high;
	char permissions[5], line[XDEV_EXT_PRELOAD_MAPS_LINE];
	size_t scanned = 0;
	bool line_start = true;
	int i;

	if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX || !cursor)
		return false;
	for (i = 0; i < iovcnt; i++) {
		cursor[i] = (uintptr_t)iov[i].iov_base;
		if (iov[i].iov_len > UINTPTR_MAX - cursor[i])
			return false;
	}
	while (scanned < XDEV_EXT_PRELOAD_MAPS_SCAN_LIMIT &&
	       xdev_ext_preload_maps_gets(r, line,
			XDEV_EXT_PRELOAD_MAPS_SCAN_LIMIT - scanned < sizeof(line) ?
			XDEV_EXT_PRELOAD_MAPS_SCAN_LIMIT - scanned + 1 : sizeof(line))) {
		size_t length = strlen(line);
		bool header = line_start;
		bool complete = true;

		scanned += length;
		line_start = length && line[length - 1] == '\n';
		if (!header || sscanf(line, "%lx-%lx %4s", &low, &high,
				      permissions) != 3)
			continue;
		for (i = 0; i < iovcnt; i++) {
			uintptr_t end = (uintptr_t)iov[i].iov_base + iov[i].iov_len;

			if (cursor[i] == end)
				continue;
			if (low > cursor[i])
				return false;
			if (high > cursor[i]) {
				if (permissions[1] != 'w')
					return false;
				cursor[i] = high < end ? high : end;
			}
			if (cursor[i] != end)
				complete = false;
		}
		if (complete)
			return true;
	}
	return false;
}

/* PROCMAP_QUERY's PROCMAP_QUERY_VMA_WRITABLE. */
#define XDEV_EXT_PRELOAD_VMA_WRITABLE UINT64_C(0x02)
/* Queries one call may make before it leaves the check to the text scan. */
#define XDEV_EXT_PRELOAD_MAPS_MAX_QUERIES 256U

/*
 * The same check through a VMA query (PROCMAP_QUERY on /proc/self/maps): 1
 * when every destination is mapped writable, 0 when not, -E2BIG when the
 * destinations need more than XDEV_EXT_PRELOAD_MAPS_MAX_QUERIES queries (the
 * text scan then decides), or the query's negative errno when the query
 * itself cannot be used.
 * query() returns 0 with the covering VMA's end and permission flags, or
 * -ENOENT when no VMA covers address.
 */
static inline int
xdev_ext_preload_maps_query_writable(int (*query)(void *opaque, uint64_t address,
						  uint64_t *end, uint64_t *flags),
				     void *opaque, const struct iovec *iov,
				     int iovcnt)
{
	unsigned int queries = 0;
	int i;

	if (!query || !iov || iovcnt <= 0 || iovcnt > IOV_MAX)
		return 0;
	for (i = 0; i < iovcnt; i++) {
		uint64_t cursor = (uintptr_t)iov[i].iov_base;
		uint64_t end;

		if (iov[i].iov_len > UINTPTR_MAX - cursor)
			return 0;
		end = cursor + iov[i].iov_len;
		while (cursor < end) {
			uint64_t vma_end = 0, flags = 0;
			int ret;

			if (queries++ == XDEV_EXT_PRELOAD_MAPS_MAX_QUERIES)
				return -E2BIG;
			ret = query(opaque, cursor, &vma_end, &flags);
			if (ret == -ENOENT)
				return 0;
			if (ret < 0)
				return ret;
			if (!(flags & XDEV_EXT_PRELOAD_VMA_WRITABLE) ||
			    vma_end <= cursor)
				return 0;
			cursor = vma_end;
		}
	}
	return 1;
}

/* Mechanism sessions one thread keeps, one per connected socket. */
#define XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS 4

#endif /* XDEV_EXT_PRELOAD_CORE_H */
