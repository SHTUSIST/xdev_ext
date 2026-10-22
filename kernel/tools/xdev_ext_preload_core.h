/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_CORE_H
#define XDEV_EXT_PRELOAD_CORE_H

/*
 * Pure policy and request encoding for io_uring_unified_preload.c.  Keep this
 * header independent of liburing so host tests can exercise every fallback
 * and completion decision with a fake submit seam.
 */
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
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

struct xdev_ext_preload_fd_meta {
	bool tracked;
	bool identity_matches;
	bool direct;
	size_t frame_size;
	uint32_t dio_mem_align;
	uint32_t dio_offset_align;
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
};

struct xdev_ext_preload_iov_seam {
	void *opaque;
	int (*submit_and_wait)(void *opaque, const struct io_uring_sqe *sqe,
			       int *cqe_res, bool *published);
	ssize_t (*fallback)(void *opaque, int fd, const struct iovec *iov,
			    int iovcnt, int64_t offset, bool write, int flags,
			    int *error);
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

static inline bool
xdev_ext_preload_iov_gather(void *staging, size_t staging_size,
		       const struct iovec *iov, int iovcnt, size_t total)
{
	size_t capacity = 0;
	size_t copied = 0;
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
	for (i = 0; i < iovcnt; i++) {
		if (!iov[i].iov_len)
			continue;
		memcpy((unsigned char *)staging + copied, iov[i].iov_base,
		       iov[i].iov_len);
		copied += iov[i].iov_len;
	}
	return true;
}

static inline bool
xdev_ext_preload_iov_scatter(const struct iovec *iov, int iovcnt,
			const void *staging, size_t bytes)
{
	size_t capacity = 0;
	size_t copied = 0;
	int i;

	if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX || (!staging && bytes))
		return false;
	for (i = 0; i < iovcnt; i++) {
		if (iov[i].iov_len > SIZE_MAX - capacity)
			return false;
		capacity += iov[i].iov_len;
	}
	if (bytes > capacity)
		return false;
	for (i = 0; i < iovcnt && copied < bytes; i++) {
		size_t length = iov[i].iov_len;

		if (length > bytes - copied)
			length = bytes - copied;
		if (!length)
			continue;
		memcpy(iov[i].iov_base, (const unsigned char *)staging + copied,
		       length);
		copied += length;
	}
	return copied == bytes;
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

	if (write)
		memcpy(staging, user_buffer, count);
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
	if (!write && cqe_res)
		memcpy(user_buffer, staging, (size_t)cqe_res);
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
	if (write && !xdev_ext_preload_iov_gather(staging, meta->frame_size, iov,
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
	if (!write && cqe_res &&
	    !xdev_ext_preload_iov_scatter(iov, iovcnt, staging, (size_t)cqe_res)) {
		*error = EFAULT;
		return -1;
	}
	return cqe_res;
}

#endif /* XDEV_EXT_PRELOAD_CORE_H */
