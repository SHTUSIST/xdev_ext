/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_SOCKET_MECH_H
#define XDEV_EXT_PRELOAD_SOCKET_MECH_H

/* Dedicated, bounded mechanism sessions for one thread's connected UDP calls,
 * one per socket in a small per-thread table (see
 * xdev_ext_socket_mech_select()).  The app buffer is copied once into a
 * private registered frame. A socket stage performs native compatibility
 * copying; this is not zero-copy.
 */
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "../include/uapi/linux/xdev_ext_mech.h"

struct xdev_ext_socket_mech_config {
	bool enabled;
	int error;
	const char *ce_device;
	uint64_t ce_addr, ce_len;
};

struct xdev_ext_socket_mech_runtime {
	int ring, event, ce_fd;
	pid_t owner;
	void *frame;
	size_t capacity;
	uint64_t session, cookie;
	struct sockaddr_storage peer;
	socklen_t peer_len;
	uint64_t finished, published, creates, calls, bytes, errors, stops, stop_errors;
	uint64_t submitted[XDEV_EXT_MECH_MAX_STAGES];
	uint64_t completed[XDEV_EXT_MECH_MAX_STAGES];
	/* Recency within the owning thread's table; only that thread uses it. */
	uint64_t last_use;
	unsigned nr_stages;
	bool unknown;
};

static inline int xdev_ext_socket_mech_u64(const char *s, uint64_t *out)
{
	char *end;
	unsigned long long n;
	if (!s || !*s || *s == '-' || *s == '+' || *s == ' ')
		return -EINVAL;
	errno = 0;
	n = strtoull(s, &end, 0);
	if (errno || *end)
		return -EINVAL;
	*out = n;
	return 0;
}

static inline void xdev_ext_socket_mech_configure(struct xdev_ext_socket_mech_config *c,
						bool socket_enabled)
{
	const char *mode, *addr, *len;
	if (!socket_enabled)
		return;
	mode = getenv("XDEV_EXT_PRELOAD_SOCKET_MECH");
	if (!mode || !*mode || !strcmp(mode, "0"))
		return;
	c->enabled = true;
	if (strcmp(mode, "1")) {
		c->error = -EINVAL;
		return;
	}
	c->ce_device = getenv("XDEV_EXT_PRELOAD_SOCKET_CE_DEVICE");
	addr = getenv("XDEV_EXT_PRELOAD_SOCKET_CE_ADDR");
	len = getenv("XDEV_EXT_PRELOAD_SOCKET_CE_LEN");
	if (!c->ce_device && !addr && !len)
		return;
	if (!c->ce_device || c->ce_device[0] != '/' ||
	    xdev_ext_socket_mech_u64(addr, &c->ce_addr) ||
	    xdev_ext_socket_mech_u64(len, &c->ce_len) || !c->ce_len ||
	    c->ce_addr > UINT64_MAX - c->ce_len)
		c->error = -EINVAL;
	else {
		c->ce_device = strdup(c->ce_device);
		if (!c->ce_device) c->error = -ENOMEM;
	}
}

static inline int xdev_ext_socket_mech_control(struct xdev_ext_socket_mech_runtime *m,
					      unsigned op, uint64_t arg)
{
	struct io_uring_xdev_ext_mech request = {.op = op, .arg = arg};
	int ret = syscall(SYS_io_uring_register, m->ring,
			  IORING_REGISTER_XDEV_EXT_MECH, &request, 1);
	return ret < 0 ? -errno : 0;
}

/* In a fork child the inherited registration belongs to the parent's mm.
 * Close only the inherited handles; never STOP or unregister its session.
 */
static inline void xdev_ext_socket_mech_forget_child(struct xdev_ext_socket_mech_runtime *m)
{
	if (m->owner && m->owner != getpid()) {
		if (m->ring >= 0) syscall(SYS_close, m->ring);
		if (m->event >= 0) syscall(SYS_close, m->event);
		if (m->ce_fd >= 0) syscall(SYS_close, m->ce_fd);
		if (m->frame) munmap(m->frame, m->capacity);
		memset(m, 0, sizeof(*m));
	}
}

/* STOP(0) is the final DMA barrier. Unknown resources remain in this one
 * bounded context; later calls fail rather than allocating another context.
 */
static inline int xdev_ext_socket_mech_release(struct xdev_ext_socket_mech_runtime *m)
{
	int ret = 0;
	if (!m->owner)
		return 0;
	if (m->owner != getpid()) {
		xdev_ext_socket_mech_forget_child(m);
		return 0;
	}
	if (m->unknown)
		return -EBUSY;
	if (m->session) {
		ret = xdev_ext_socket_mech_control(m, XDEV_EXT_MECH_OP_STOP, m->session);
		if (ret) {
			__atomic_add_fetch(&m->stop_errors, 1, __ATOMIC_RELAXED);
			m->unknown = true;
			return ret;
		}
		m->session = 0;
		__atomic_add_fetch(&m->stops, 1, __ATOMIC_RELAXED);
	}
	if (m->ring >= 0) syscall(SYS_close, m->ring);
	if (m->event >= 0) syscall(SYS_close, m->event);
	if (m->ce_fd >= 0) syscall(SYS_close, m->ce_fd);
	if (m->frame) munmap(m->frame, m->capacity);
	m->ring = m->event = m->ce_fd = -1;
	m->frame = NULL;
	m->owner = 0;
	return ret;
}

/* The socket's identity: its cookie, and the peer it is connected to now. */
static inline int xdev_ext_socket_mech_identity(int fd, uint64_t *cookie,
		struct sockaddr_storage *peer, socklen_t *peer_len)
{
	socklen_t cookie_len = sizeof(*cookie);

	memset(peer, 0, sizeof(*peer));
	*peer_len = sizeof(*peer);
	if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_COOKIE, cookie, &cookie_len)) return -errno;
	if (cookie_len != sizeof(*cookie)) return -EPROTO;
	if (syscall(SYS_getpeername, fd, peer, peer_len)) return -errno;
	if (*peer_len > sizeof(*peer)) return -EPROTO;
	return 0;
}

/* The caller already dropped fork-inherited state and refused an unknown
 * runtime; cookie and peer are fd's current identity.
 */
static inline int xdev_ext_socket_mech_prepare_identity(struct xdev_ext_socket_mech_runtime *m,
		const struct xdev_ext_socket_mech_config *cfg, int fd, size_t capacity,
		uint64_t cookie, const struct sockaddr_storage *peer, socklen_t peer_len)
{
	struct io_uring_params params = {};
	struct io_uring_xdev_ext_umem_reg reg = {};
	struct xdev_ext_mech_create create = {};
	size_t group_capacity = capacity < 65507 ? capacity : 65507;
	unsigned i;
	int ret;

	if (cfg->error) return cfg->error;
	if (m->session && m->cookie == cookie && m->peer_len == peer_len &&
	    !memcmp(&m->peer, peer, peer_len)) return 0;
	ret = xdev_ext_socket_mech_release(m);
	if (m->unknown) return ret;
	m->ring = m->event = m->ce_fd = -1;
	m->owner = getpid();
	m->capacity = capacity;
	m->finished = m->published = 0;
	m->frame = mmap(NULL, capacity, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (m->frame == MAP_FAILED) {m->frame = NULL; ret = -errno; goto fail;}
	m->ring = syscall(SYS_io_uring_setup, 2, &params);
	if (m->ring < 0) {ret = -errno; goto fail;}
	reg.addr = (uintptr_t)m->frame;
	reg.size = capacity;
	reg.frame_size = capacity;
	if (syscall(SYS_io_uring_register, m->ring, IORING_REGISTER_XDEV_EXT_UMEM, &reg, 1) < 0) {
		ret = -errno; goto fail;
	}
	m->event = syscall(SYS_eventfd2, 0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (m->event < 0) {ret = -errno; goto fail;}
	create.abi_version = XDEV_EXT_MECH_ABI_VERSION;
	create.pool_kind = XDEV_EXT_MECH_POOL_IOU_UMEM;
	create.pool_fd = -1;
	create.layout.frame_size = capacity;
	create.layout.seg_len = create.layout.group_bytes = group_capacity;
	create.depth = 1;
	create.eventfd = m->event;
	if (cfg->ce_device) {
		if (cfg->ce_len < group_capacity) {ret = -EINVAL; goto fail;}
		m->ce_fd = syscall(SYS_openat, AT_FDCWD, cfg->ce_device, O_RDWR | O_CLOEXEC, 0);
		if (m->ce_fd < 0) {ret = -errno; goto fail;}
		for (i = 0; i < 2; i++)
			create.st[i] = (struct xdev_ext_mech_stage_uapi) {
				.class_id = XDEV_EXT_MECH_CLASS_CE,
				.direction = i ? XDEV_EXT_MECH_DIR_FROM_DEVICE : XDEV_EXT_MECH_DIR_TO_DEVICE,
				.fd = m->ce_fd, .arg0 = cfg->ce_addr, .arg1 = cfg->ce_len,
			};
		create.nr_stages = 2;
	}
	create.st[create.nr_stages++] = (struct xdev_ext_mech_stage_uapi) {
		.class_id = XDEV_EXT_MECH_CLASS_SOCKET, .direction = XDEV_EXT_MECH_DIR_TO_DEVICE, .fd = fd,
	};
	ret = xdev_ext_socket_mech_control(m, XDEV_EXT_MECH_OP_CREATE, (uintptr_t)&create);
	if (ret) goto fail;
	m->session = create.session_id;
	m->cookie = cookie;
	m->peer = *peer;
	m->peer_len = peer_len;
	m->nr_stages = create.nr_stages;
	__atomic_add_fetch(&m->creates, 1, __ATOMIC_RELAXED);
	return 0;
fail:
	xdev_ext_socket_mech_release(m);
	return ret;
}

static inline int xdev_ext_socket_mech_prepare(struct xdev_ext_socket_mech_runtime *m,
		const struct xdev_ext_socket_mech_config *cfg, int fd, size_t capacity)
{
	struct sockaddr_storage peer;
	socklen_t peer_len;
	uint64_t cookie;
	int ret;

	xdev_ext_socket_mech_forget_child(m);
	if (m->unknown) return -EBUSY;
	if (cfg->error) return cfg->error;
	ret = xdev_ext_socket_mech_identity(fd, &cookie, &peer, &peer_len);
	if (ret) return ret;
	return xdev_ext_socket_mech_prepare_identity(m, cfg, fd, capacity, cookie,
						     &peer, peer_len);
}

/*
 * Pick cookie's session among one thread's nr slots: the slot bound to that
 * socket, else a free slot, else the least recently used slot, stopped first.
 * NULL means that this call goes to libc: the socket's own session, or the
 * one to evict, could not be stopped, or every slot is in that state.  Such a
 * slot keeps its resources (STOP is the DMA barrier) and is never reused; the
 * caller has dropped fork-inherited slots already.
 */
static inline struct xdev_ext_socket_mech_runtime *
xdev_ext_socket_mech_select(struct xdev_ext_socket_mech_runtime *const *slots,
			    unsigned int nr, uint64_t cookie)
{
	struct xdev_ext_socket_mech_runtime *free_slot = NULL, *oldest = NULL;
	unsigned int i;

	for (i = 0; i < nr; i++) {
		struct xdev_ext_socket_mech_runtime *m = slots[i];

		if (m->owner && m->cookie == cookie)
			return m->unknown ? NULL : m;
		if (!m->owner) {
			if (!free_slot) free_slot = m;
		} else if (!m->unknown && (!oldest || m->last_use < oldest->last_use)) {
			oldest = m;
		}
	}
	if (free_slot)
		return free_slot;
	if (!oldest || xdev_ext_socket_mech_release(oldest))
		return NULL;
	return oldest;
}

/* Caller has already excluded zero, oversized, nonblocking and unsupported
 * calls and prepared m for fd. Cancellation stays disabled until this
 * synchronous call is terminal.  Once START was attempted, no fallback or
 * second START is allowed, even if its syscall was interrupted: a failing
 * handoff can have lent frame custody.  pid is this process.
 */
static inline ssize_t xdev_ext_socket_mech_transfer(struct xdev_ext_socket_mech_runtime *m,
		const void *buf, size_t len, pid_t pid)
{
	struct xdev_ext_mech_user_span span = {.index = 0, .len = len};
	struct xdev_ext_mech_notify_arm arm;
	struct xdev_ext_mech_start start;
	struct xdev_ext_mech_stats stats;
	struct iovec local, remote;
	struct pollfd pfd;
	uint64_t notifications;
	unsigned i;
	int ret;
	local = (struct iovec){.iov_base = m->frame, .iov_len = len};
	remote = (struct iovec){.iov_base = (void *)buf, .iov_len = len};
	if (syscall(SYS_process_vm_readv, pid, &local, 1, &remote, 1, 0) != (ssize_t)len)
		return -EFAULT;
	/* A preceding terminal/stop wake must not consume the new arm. */
	while (syscall(SYS_read, m->event, &notifications, sizeof(notifications)) == sizeof(notifications)) {}
	arm = (struct xdev_ext_mech_notify_arm) {
		.session_id = m->session, .batches_target = m->finished + 1,
		.published_target = m->published + 1,
	};
	ret = xdev_ext_socket_mech_control(m, XDEV_EXT_MECH_OP_NOTIFY_ARM, (uintptr_t)&arm);
	if (ret) goto failed;
	start = (struct xdev_ext_mech_start) {
		.session_id = m->session, .nr_batches = 1, .first_seq = m->finished,
		.flags = XDEV_EXT_MECH_START_F_USER_FRAMES | XDEV_EXT_MECH_START_F_USER_SPANS,
		.nr_user_frames = 1, .user_frames = (uintptr_t)&span,
	};
	ret = xdev_ext_socket_mech_control(m, XDEV_EXT_MECH_OP_START, (uintptr_t)&start);
	if (ret) goto failed;
	pfd = (struct pollfd){.fd = m->event, .events = POLLIN};
	do {ret = poll(&pfd, 1, 30000);} while (ret < 0 && errno == EINTR);
	if (ret <= 0) {ret = ret < 0 ? -errno : -ETIMEDOUT; goto failed;}
	if (syscall(SYS_read, m->event, &notifications, sizeof(notifications)) != sizeof(notifications)) {
		ret = -EIO; goto failed;
	}
	stats = (struct xdev_ext_mech_stats){.session_id = m->session};
	ret = xdev_ext_socket_mech_control(m, XDEV_EXT_MECH_OP_STATS, (uintptr_t)&stats);
	if (ret) goto failed;
	if (stats.last_err || stats.batches_abort || stats.inflight || stats.sequestered ||
	    stats.state != XDEV_EXT_MECH_SESSION_ACTIVE || stats.batches_done != arm.batches_target ||
	    stats.published != arm.published_target) {
		ret = stats.last_err ? stats.last_err : -EIO; goto failed;
	}
	for (i = 0; i < m->nr_stages; i++) {
		if (stats.submitted[i] != arm.batches_target || stats.completed[i] != arm.batches_target) {
			ret = -EIO; goto failed;
		}
		__atomic_add_fetch(&m->submitted[i], 1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&m->completed[i], 1, __ATOMIC_RELAXED);
	}
	m->finished = stats.batches_done;
	m->published = stats.published;
	__atomic_add_fetch(&m->calls, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&m->bytes, len, __ATOMIC_RELAXED);
	return len;
failed:
	__atomic_add_fetch(&m->errors, 1, __ATOMIC_RELAXED);
	xdev_ext_socket_mech_release(m);
	return ret;
}

/* One synchronous send on m's single session, prepared for fd as needed. */
static inline ssize_t xdev_ext_socket_mech_send(struct xdev_ext_socket_mech_runtime *m,
		const struct xdev_ext_socket_mech_config *cfg, int fd, const void *buf,
		size_t len, size_t capacity)
{
	int ret;

	if (!len || len > capacity || len > 65507) return -EMSGSIZE;
	ret = xdev_ext_socket_mech_prepare(m, cfg, fd, capacity);
	if (ret) return ret;
	return xdev_ext_socket_mech_transfer(m, buf, len, getpid());
}

#endif
