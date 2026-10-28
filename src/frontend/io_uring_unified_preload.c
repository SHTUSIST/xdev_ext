// SPDX-License-Identifier: GPL-2.0
/*
 * Opt-in LD_PRELOAD front end for positional O_DIRECT file I/O through the
 * XDEV_EXT registered-UMEM unified operation. The default is a libc pass-through.
 */
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

/* Consume this checkout's UAPI even when the host liburing is older. */
#include "xdev_ext_preload_core.h"
#include "xdev_ext_preload_admission.h"
#include "xdev_ext_preload_config.h"
#include "xdev_ext_preload_fd_shard.h"
#define statx_timestamp xdev_ext_kernel_statx_timestamp
#define statx xdev_ext_kernel_statx
#include "../include/uapi/linux/stat.h"
#undef statx
#undef statx_timestamp
#include "include/io_uring/mini_liburing.h"
#include "xdev_ext_preload_socket_mech.h"

struct xdev_ext_real_functions {
	int (*open_fn)(const char *, int, ...);
	int (*open64_fn)(const char *, int, ...);
	int (*openat_fn)(int, const char *, int, ...);
	int (*openat64_fn)(int, const char *, int, ...);
	int (*open2_fn)(const char *, int);
	int (*open64_2_fn)(const char *, int);
	int (*openat2_fn)(int, const char *, int);
	int (*openat64_2_fn)(int, const char *, int);
	int (*close_fn)(int);
	int (*dup_fn)(int);
	int (*dup2_fn)(int, int);
	int (*dup3_fn)(int, int, int);
	int (*fcntl_fn)(int, int, ...);
	int (*fcntl64_fn)(int, int, ...);
	ssize_t (*read_fn)(int, void *, size_t);
	ssize_t (*write_fn)(int, const void *, size_t);
	ssize_t (*pread_fn)(int, void *, size_t, off_t);
	ssize_t (*pread64_fn)(int, void *, size_t, off64_t);
	ssize_t (*pread_chk_fn)(int, void *, size_t, off_t, size_t);
	ssize_t (*pread64_chk_fn)(int, void *, size_t, off64_t, size_t);
	ssize_t (*pwrite_fn)(int, const void *, size_t, off_t);
	ssize_t (*pwrite64_fn)(int, const void *, size_t, off64_t);
	ssize_t (*preadv_fn)(int, const struct iovec *, int, off_t);
	ssize_t (*preadv64_fn)(int, const struct iovec *, int, off64_t);
	ssize_t (*pwritev_fn)(int, const struct iovec *, int, off_t);
	ssize_t (*pwritev64_fn)(int, const struct iovec *, int, off64_t);
	ssize_t (*preadv2_fn)(int, const struct iovec *, int, off_t, int);
	ssize_t (*preadv64v2_fn)(int, const struct iovec *, int, off64_t, int);
	ssize_t (*pwritev2_fn)(int, const struct iovec *, int, off_t, int);
	ssize_t (*pwritev64v2_fn)(int, const struct iovec *, int, off64_t, int);
	ssize_t (*send_fn)(int, const void *, size_t, int);
	ssize_t (*sendto_fn)(int, const void *, size_t, int,
			     const struct sockaddr *, socklen_t);
	ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
	int (*getsockopt_fn)(int, int, int, void *, socklen_t *);
	int (*getpeername_fn)(int, struct sockaddr *, socklen_t *);
};

struct xdev_ext_fd_record {
	int fd;
	dev_t dev;
	ino_t ino;
	mode_t mode;
	int status_flags;
	uint32_t dio_mem_align;
	uint32_t dio_offset_align;
	/* Inode change time when the path was last found allowlisted. */
	struct timespec path_ctime;
	uint64_t generation;
	struct xdev_ext_fd_record *next;
};

struct xdev_ext_thread_ctx {
	struct io_uring ring;
	void *umem;
	struct io_uring_unified_shared *shared;
	size_t frame_size;
	pid_t owner_pid;
	bool ring_ready;
	bool umem_registered;
	bool broken;
	bool quiescence_unknown;
	bool report_emitted;
	pid_t owner_tid;
	uint64_t custom_send_count;
	uint64_t custom_send_bytes;
	uint32_t custom_send_errors;
	struct xdev_ext_preload_token_source tokens;
	struct xdev_ext_socket_mech_runtime socket_mech;
	/* The thread's further sessions, one per connected socket. */
	struct xdev_ext_socket_mech_runtime
		socket_mech_more[XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS - 1];
	uint64_t socket_mech_clock;
	pthread_mutex_t socket_mech_lock;
	/* Read buffer for the /proc/self/maps text of read admission. */
	char *maps_buffer;
	/* Calls this thread took over; folded into the fallback report. */
	uint64_t file_qualified;
	uint64_t socket_qualified;
	struct xdev_ext_thread_ctx *next;
};

struct xdev_ext_call_ctx {
	struct xdev_ext_thread_ctx *thread;
	bool use_64;
	bool use_v2;
	/* The call went to libc after all (set by the fallback seams). */
	bool fell_back;
	const struct iovec *original_iov;
};

enum xdev_ext_socket_call_kind {
	XDEV_EXT_SOCKET_CALL_SEND,
	XDEV_EXT_SOCKET_CALL_SENDTO,
	XDEV_EXT_SOCKET_CALL_SENDMSG,
};

struct xdev_ext_socket_call_ctx {
	struct xdev_ext_call_ctx ring_call;
	enum xdev_ext_socket_call_kind kind;
	const struct sockaddr *destination;
	socklen_t destination_length;
	const struct msghdr *message;
	bool custom_completed;
	bool fell_back;
	int custom_cqe_res;
	int cancel_state;
};

struct xdev_ext_ring_driver {
	struct xdev_ext_thread_ctx *thread;
	unsigned int initial_head;
};

static struct xdev_ext_real_functions xdev_ext_real;
static struct xdev_ext_config xdev_ext_cfg;
static struct xdev_ext_socket_mech_config xdev_ext_socket_mech_cfg;
static pthread_once_t xdev_ext_real_once = PTHREAD_ONCE_INIT;
static pthread_once_t xdev_ext_config_once = PTHREAD_ONCE_INIT;
static pthread_once_t xdev_ext_tls_once = PTHREAD_ONCE_INIT;
static pthread_key_t xdev_ext_tls_key;
static int xdev_ext_tls_key_error;
static struct xdev_ext_preload_fd_lockset xdev_ext_fd_locks =
	XDEV_EXT_PRELOAD_FD_LOCKSET_INITIALIZER;
static pthread_mutex_t xdev_ext_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static struct xdev_ext_fd_record *xdev_ext_fds[XDEV_EXT_PRELOAD_FD_SHARDS];
static struct xdev_ext_thread_ctx *xdev_ext_threads;
static uint64_t xdev_ext_fd_generation;
/*
 * With XDEV_EXT_PRELOAD_REPORT=1: calls that stayed in libc, per reason, and
 * the taken-over calls of threads already folded in by their report.  Each
 * thread counts its own taken-over calls without a shared cache line.
 */
static uint64_t xdev_ext_fallbacks[XDEV_EXT_PRELOAD_FALLBACK_NR];
static uint64_t xdev_ext_file_qualified;
static uint64_t xdev_ext_socket_qualified;
/* PROCMAP_QUERY is absent before Linux 6.11 (ENOTTY); then the text is read. */
static int xdev_ext_procmap_query_absent;
/*
 * initial-exec: a general-dynamic access can allocate on a thread's first use,
 * and the allocation's own calls would reach these wrappers before the guard
 * is readable.  This only holds for a library loaded at start-up, which is
 * how LD_PRELOAD loads it.
 *
 * xdev_ext_in_hook: this thread is inside a wrapper; a nested call goes straight
 * to libc without taking a lock or changing state.
 * xdev_ext_ctl_depth: this thread is running the front end's own control code
 * (configuration, and later ring, socket and program setup), so a nested call
 * is the front end's by construction, not the application's.
 */
static __thread unsigned int __attribute__((tls_model("initial-exec")))
	xdev_ext_in_hook;
static __thread unsigned int __attribute__((tls_model("initial-exec")))
	xdev_ext_ctl_depth;

/*
 * Per-thread cache of socket type, domain and protocol by SO_COOKIE.  A
 * cookie names one socket for the life of the boot and these three never
 * change, so a hit replaces three getsockopt calls with the cookie's one.  It
 * holds no resource, so threads and forks need no cleanup.
 */
#define XDEV_EXT_SOCKET_KIND_CACHE 8
struct xdev_ext_socket_kind {
	uint64_t cookie;
	int type;
	int domain;
	int protocol;
};
static __thread struct xdev_ext_socket_kind
	__attribute__((tls_model("initial-exec")))
	xdev_ext_socket_kinds[XDEV_EXT_SOCKET_KIND_CACHE];
static __thread unsigned int __attribute__((tls_model("initial-exec")))
	xdev_ext_socket_kind_next;

static void xdev_ext_report_all_threads(void);

static void xdev_ext_count_fallback(enum xdev_ext_preload_fallback_reason reason)
{
	if (xdev_ext_cfg.report && reason > XDEV_EXT_PRELOAD_FALLBACK_NONE &&
	    reason < XDEV_EXT_PRELOAD_FALLBACK_NR)
		__atomic_add_fetch(&xdev_ext_fallbacks[reason], 1, __ATOMIC_RELAXED);
}

/*
 * Only the owning thread adds, but the exit report may exchange the counter
 * from another thread while this one is still in a call: an atomic add keeps
 * that increment in exactly one of the two totals.  It is uncontended.
 */
static void xdev_ext_count_qualified(uint64_t *counter)
{
	__atomic_add_fetch(counter, 1, __ATOMIC_RELAXED);
}

/* The call went to libc inside the request executor, before publication. */
static void xdev_ext_count_executed(struct xdev_ext_thread_ctx *thread,
				    bool fell_back, uint64_t *qualified,
				    enum xdev_ext_preload_fallback_reason absent,
				    enum xdev_ext_preload_fallback_reason other)
{
	if (!fell_back)
		xdev_ext_count_qualified(qualified);
	else
		xdev_ext_count_fallback(thread->broken ? absent : other);
}

/* A child reports its own calls only. */
static void xdev_ext_fallback_counts_child(void)
{
	unsigned int i;

	for (i = 0; i < XDEV_EXT_PRELOAD_FALLBACK_NR; i++)
		__atomic_store_n(&xdev_ext_fallbacks[i], 0, __ATOMIC_RELAXED);
	__atomic_store_n(&xdev_ext_file_qualified, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&xdev_ext_socket_qualified, 0, __ATOMIC_RELAXED);
}

static void xdev_ext_atfork_prepare(void)
{
	struct xdev_ext_thread_ctx *thread;

	xdev_ext_preload_fd_lock_all(&xdev_ext_fd_locks);
	pthread_mutex_lock(&xdev_ext_thread_lock);
	/* Freeze runtime publication/teardown too: a fork between an fd's
	 * creation and its assignment into the context would orphan that fd.
	 * Registry -> runtime is also the close/report lock order.
	 */
	for (thread = xdev_ext_threads; thread; thread = thread->next)
		pthread_mutex_lock(&thread->socket_mech_lock);
}

static void xdev_ext_atfork_parent(void)
{
	struct xdev_ext_thread_ctx *thread;

	for (thread = xdev_ext_threads; thread; thread = thread->next)
		pthread_mutex_unlock(&thread->socket_mech_lock);
	pthread_mutex_unlock(&xdev_ext_thread_lock);
	xdev_ext_preload_fd_unlock_all(&xdev_ext_fd_locks);
}

static void xdev_ext_forget_child_ring(struct xdev_ext_thread_ctx *thread)
{
	struct io_uring_sq *sq = &thread->ring.sq;
	struct io_uring_cq *cq = &thread->ring.cq;

	if (!thread->ring_ready)
		return;
	/* Match mini_liburing's queue_exit mappings, but bypass interposed
	 * close: it can take locks and is a cancellation point after fork.
	 * Drop inherited references only, without unregistering parent UMEM.
	 */
	(void)munmap(sq->sqes,
		     *sq->kring_entries * sizeof(struct io_uring_sqe));
	(void)munmap(sq->ring_ptr, sq->ring_sz);
	if (cq->ring_ptr != sq->ring_ptr)
		(void)munmap(cq->ring_ptr, cq->ring_sz);
	(void)syscall(SYS_close, thread->ring.ring_fd);
	thread->ring_ready = false;
	thread->umem_registered = false;
}

static void xdev_ext_atfork_child(void)
{
	struct xdev_ext_thread_ctx *thread;

	/* Other threads vanished. Their contexts cannot be found through this
	 * thread's TLS, so discard every inherited handle/mapping now.
	 * This closes child references only; it never STOPs or unregisters the
	 * parent's live sessions. Keep metadata allocated here: allocator locks
	 * can belong to vanished threads. The surviving TLS context frees its
	 * metadata at lazy refresh; ring_ready prevents a duplicate close.
	 */
	for (thread = xdev_ext_threads; thread; thread = thread->next) {
		unsigned int i;

		xdev_ext_socket_mech_forget_child(&thread->socket_mech);
		for (i = 0; i < XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS - 1; i++)
			xdev_ext_socket_mech_forget_child(&thread->socket_mech_more[i]);
		xdev_ext_forget_child_ring(thread);
		pthread_mutex_unlock(&thread->socket_mech_lock);
	}
	pthread_mutex_unlock(&xdev_ext_thread_lock);
	xdev_ext_preload_fd_unlock_all(&xdev_ext_fd_locks);
	xdev_ext_admission_after_fork_child();
}

static void xdev_ext_resolve_symbol(void *slot, const char *name)
{
	*(void **)slot = dlsym(RTLD_NEXT, name);
}

static void xdev_ext_resolve_real_functions(void)
{
	xdev_ext_resolve_symbol(&xdev_ext_real.open_fn, "open");
	xdev_ext_resolve_symbol(&xdev_ext_real.open64_fn, "open64");
	xdev_ext_resolve_symbol(&xdev_ext_real.openat_fn, "openat");
	xdev_ext_resolve_symbol(&xdev_ext_real.openat64_fn, "openat64");
	xdev_ext_resolve_symbol(&xdev_ext_real.open2_fn, "__open_2");
	xdev_ext_resolve_symbol(&xdev_ext_real.open64_2_fn, "__open64_2");
	xdev_ext_resolve_symbol(&xdev_ext_real.openat2_fn, "__openat_2");
	xdev_ext_resolve_symbol(&xdev_ext_real.openat64_2_fn, "__openat64_2");
	xdev_ext_resolve_symbol(&xdev_ext_real.close_fn, "close");
	xdev_ext_resolve_symbol(&xdev_ext_real.dup_fn, "dup");
	xdev_ext_resolve_symbol(&xdev_ext_real.dup2_fn, "dup2");
	xdev_ext_resolve_symbol(&xdev_ext_real.dup3_fn, "dup3");
	xdev_ext_resolve_symbol(&xdev_ext_real.fcntl_fn, "fcntl");
	xdev_ext_resolve_symbol(&xdev_ext_real.fcntl64_fn, "fcntl64");
	xdev_ext_resolve_symbol(&xdev_ext_real.read_fn, "read");
	xdev_ext_resolve_symbol(&xdev_ext_real.write_fn, "write");
	xdev_ext_resolve_symbol(&xdev_ext_real.pread_fn, "pread");
	xdev_ext_resolve_symbol(&xdev_ext_real.pread64_fn, "pread64");
	xdev_ext_resolve_symbol(&xdev_ext_real.pread_chk_fn, "__pread_chk");
	xdev_ext_resolve_symbol(&xdev_ext_real.pread64_chk_fn, "__pread64_chk");
	xdev_ext_resolve_symbol(&xdev_ext_real.pwrite_fn, "pwrite");
	xdev_ext_resolve_symbol(&xdev_ext_real.pwrite64_fn, "pwrite64");
	xdev_ext_resolve_symbol(&xdev_ext_real.preadv_fn, "preadv");
	xdev_ext_resolve_symbol(&xdev_ext_real.preadv64_fn, "preadv64");
	xdev_ext_resolve_symbol(&xdev_ext_real.pwritev_fn, "pwritev");
	xdev_ext_resolve_symbol(&xdev_ext_real.pwritev64_fn, "pwritev64");
	xdev_ext_resolve_symbol(&xdev_ext_real.preadv2_fn, "preadv2");
	xdev_ext_resolve_symbol(&xdev_ext_real.preadv64v2_fn, "preadv64v2");
	xdev_ext_resolve_symbol(&xdev_ext_real.pwritev2_fn, "pwritev2");
	xdev_ext_resolve_symbol(&xdev_ext_real.pwritev64v2_fn, "pwritev64v2");
	xdev_ext_resolve_symbol(&xdev_ext_real.send_fn, "send");
	xdev_ext_resolve_symbol(&xdev_ext_real.sendto_fn, "sendto");
	xdev_ext_resolve_symbol(&xdev_ext_real.sendmsg_fn, "sendmsg");
	xdev_ext_resolve_symbol(&xdev_ext_real.getsockopt_fn, "getsockopt");
	xdev_ext_resolve_symbol(&xdev_ext_real.getpeername_fn, "getpeername");
	if (!xdev_ext_real.open64_fn)
		xdev_ext_real.open64_fn = xdev_ext_real.open_fn;
	if (!xdev_ext_real.openat64_fn)
		xdev_ext_real.openat64_fn = xdev_ext_real.openat_fn;
	if (!xdev_ext_real.fcntl64_fn)
		xdev_ext_real.fcntl64_fn = xdev_ext_real.fcntl_fn;
	if (!xdev_ext_real.pread64_fn)
		xdev_ext_real.pread64_fn = (void *)xdev_ext_real.pread_fn;
	if (!xdev_ext_real.pwrite64_fn)
		xdev_ext_real.pwrite64_fn = (void *)xdev_ext_real.pwrite_fn;
	if (!xdev_ext_real.preadv64_fn)
		xdev_ext_real.preadv64_fn = (void *)xdev_ext_real.preadv_fn;
	if (!xdev_ext_real.pwritev64_fn)
		xdev_ext_real.pwritev64_fn = (void *)xdev_ext_real.pwritev_fn;
}

static const char *xdev_ext_env_get(const struct xdev_ext_env_view *view,
			       const char *name)
{
	(void)view;
	return getenv(name);
}

/*
 * Resolve the XDEV_EXT_PRELOAD_PATHS snapshot into canonical paths and identities.
 * An entry that cannot be used is skipped as before; the first such entry is
 * noted for the XDEV_EXT_PRELOAD_CONFIG line.
 */
static void xdev_ext_resolve_allowlist(void)
{
	char *copy;
	char *cursor;
	char *token;

	copy = strdup(xdev_ext_cfg.paths);
	if (!copy) {
		xdev_ext_cfg.enabled = false;
		xdev_ext_preload_config_note(&xdev_ext_cfg, -ENOMEM, "XDEV_EXT_PRELOAD_PATHS");
		return;
	}
	cursor = copy;
	while ((token = strsep(&cursor, ":")) != NULL) {
		struct xdev_ext_allow_entry *grown;
		struct stat st;
		char *canonical;

		if (!*token)
			continue;
		if (token[0] != '/') {
			xdev_ext_preload_config_note(&xdev_ext_cfg, -EINVAL,
						"XDEV_EXT_PRELOAD_PATHS");
			continue;
		}
		canonical = realpath(token, NULL);
		if (!canonical || stat(canonical, &st)) {
			free(canonical);
			xdev_ext_preload_config_note(&xdev_ext_cfg, -ENOENT,
						"XDEV_EXT_PRELOAD_PATHS");
			continue;
		}
		grown = realloc(xdev_ext_cfg.allow,
				sizeof(*grown) * (xdev_ext_cfg.nr_allow + 1));
		if (!grown) {
			free(canonical);
			xdev_ext_preload_config_note(&xdev_ext_cfg, -ENOMEM,
						"XDEV_EXT_PRELOAD_PATHS");
			break;
		}
		xdev_ext_cfg.allow = grown;
		xdev_ext_cfg.allow[xdev_ext_cfg.nr_allow++] = (struct xdev_ext_allow_entry) {
			.path = canonical,
			.dev = st.st_dev,
			.ino = st.st_ino,
		};
	}
	free(copy);
	if (!xdev_ext_cfg.nr_allow)
		xdev_ext_cfg.enabled = false;
}

/* The one configuration snapshot; see xdev_ext_preload_init() for when it runs. */
static void xdev_ext_load_config(void)
{
	struct xdev_ext_env_view env = {
		.get = xdev_ext_env_get,
		.page_size = sysconf(_SC_PAGESIZE),
	};
	int ret;

	xdev_ext_ctl_depth++;
	(void)xdev_ext_preload_config_parse(&env, &xdev_ext_cfg);
	xdev_ext_socket_mech_configure(&xdev_ext_socket_mech_cfg, xdev_ext_cfg.socket_enabled);
	if (xdev_ext_cfg.report && atexit(xdev_ext_report_all_threads))
		xdev_ext_cfg.report = false;
	if (!xdev_ext_cfg.armed)
		goto out;
	ret = pthread_atfork(xdev_ext_atfork_prepare, xdev_ext_atfork_parent,
			     xdev_ext_atfork_child);
	if (ret) {
		xdev_ext_preload_config_disarm(&xdev_ext_cfg, -ret, NULL);
		goto out;
	}
	if (xdev_ext_cfg.report)
		(void)pthread_atfork(NULL, NULL, xdev_ext_fallback_counts_child);
	if (xdev_ext_cfg.enabled)
		xdev_ext_resolve_allowlist();
	xdev_ext_preload_config_update_armed(&xdev_ext_cfg);
out:
	xdev_ext_ctl_depth--;
}

/*
 * Runs before the application's constructors: resolve libc, close the gate
 * (a white-box test constructs more than once), take the snapshot, and open
 * the gate only after everything a gated path reads is published.  The
 * snapshot is taken here once; pthread_once only covers a wrapper that
 * another library's constructor reaches first, which then takes the same
 * single snapshot while the gate is still closed.
 */
__attribute__((constructor(101))) static void xdev_ext_preload_init(void)
{
	char line[160];
	int saved_errno = errno;
	int length;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	xdev_ext_in_hook++;
	xdev_ext_ctl_depth++;
	xdev_ext_admission_quiesce();
	pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
	/* A measurement that asked for takeover must not silently run libc. */
	if (xdev_ext_cfg.report || xdev_ext_cfg.verbose ||
	    xdev_ext_preload_config_must_abort(&xdev_ext_cfg)) {
		length = xdev_ext_preload_config_format(&xdev_ext_cfg, line, sizeof(line));
		if (length > 0)
			(void)syscall(SYS_write, STDERR_FILENO, line,
				      (size_t)length);
	}
	if (xdev_ext_preload_config_must_abort(&xdev_ext_cfg))
		abort();
	/* armed: xdev_ext_load_config() registered the child's gate reset. */
	if (xdev_ext_cfg.armed)
		xdev_ext_admission_enable();
	xdev_ext_ctl_depth--;
	xdev_ext_in_hook--;
	errno = saved_errno;
}

/*
 * Close the gate and wait for the bounded sections already admitted; waits
 * on the application happen outside the gate, so this never waits on it.
 * Nothing is freed: a caller arriving later only sees the closed gate, and
 * the existing paths keep the snapshot they read.
 */
__attribute__((destructor(101))) static void xdev_ext_preload_fini(void)
{
	int saved_errno = errno;

	xdev_ext_in_hook++;
	xdev_ext_ctl_depth++;
	xdev_ext_admission_quiesce();
	xdev_ext_ctl_depth--;
	xdev_ext_in_hook--;
	errno = saved_errno;
}

static bool xdev_ext_open_needs_mode(int flags)
{
	if (flags & O_CREAT)
		return true;
#ifdef O_TMPFILE
	if ((flags & O_TMPFILE) == O_TMPFILE)
		return true;
#endif
	return false;
}

static struct xdev_ext_fd_record *
xdev_ext_find_fd_locked(struct xdev_ext_fd_record *head, int fd)
{
	struct xdev_ext_fd_record *record;

	for (record = head; record; record = record->next) {
		if (record->fd == fd)
			return record;
	}
	return NULL;
}

static void xdev_ext_remove_fd_locked(struct xdev_ext_fd_record **head, int fd)
{
	struct xdev_ext_fd_record **cursor = head;

	while (*cursor) {
		if ((*cursor)->fd == fd) {
			struct xdev_ext_fd_record *old = *cursor;

			*cursor = old->next;
			free(old);
			return;
		}
		cursor = &(*cursor)->next;
	}
}

static void xdev_ext_forget_fd(int fd)
{
	unsigned int shard = xdev_ext_preload_fd_shard(fd);

	xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, fd);
	xdev_ext_remove_fd_locked(&xdev_ext_fds[shard], fd);
	xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, fd);
}

static bool xdev_ext_path_is_allowed(int fd, const struct stat *st)
{
	char proc_path[64];
	char fd_path[PATH_MAX + 1];
	ssize_t length;
	size_t i;

	if (snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd) < 0)
		return false;
	length = readlink(proc_path, fd_path, PATH_MAX);
	if (length <= 0 || length > PATH_MAX)
		return false;
	fd_path[length] = '\0';
	for (i = 0; i < xdev_ext_cfg.nr_allow; i++) {
		const struct xdev_ext_allow_entry *entry = &xdev_ext_cfg.allow[i];

		if (entry->dev == st->st_dev && entry->ino == st->st_ino &&
		    !strcmp(entry->path, fd_path))
			return true;
	}
	return false;
}

static void xdev_ext_query_dio_alignment(int fd, uint32_t *memory,
				    uint32_t *offset)
{
	struct xdev_ext_kernel_statx stx;
	int ret;

	*memory = 0;
	*offset = 0;
	memset(&stx, 0, sizeof(stx));
	ret = syscall(SYS_statx, fd, "", AT_EMPTY_PATH | AT_STATX_DONT_SYNC,
		      STATX_DIOALIGN, &stx);
	if (!ret && (stx.stx_mask & STATX_DIOALIGN)) {
		*memory = stx.stx_dio_mem_align;
		*offset = stx.stx_dio_offset_align;
	}
}

static void xdev_ext_track_open_fd(int fd)
{
	struct xdev_ext_fd_record *record = NULL;
	struct stat st;
	unsigned int shard;
	int flags;

	if (fd < 0 || !xdev_ext_cfg.enabled)
		return;
	if (fstat(fd, &st) || (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode)) ||
	    !xdev_ext_path_is_allowed(fd, &st))
		goto replace;
	flags = xdev_ext_real.fcntl_fn(fd, F_GETFL);
	if (flags < 0)
		goto replace;
	record = calloc(1, sizeof(*record));
	if (!record)
		goto replace;
	record->fd = fd;
	record->dev = st.st_dev;
	record->ino = st.st_ino;
	record->mode = st.st_mode;
	record->status_flags = flags;
	record->path_ctime = st.st_ctim;
	xdev_ext_query_dio_alignment(fd, &record->dio_mem_align,
				&record->dio_offset_align);

replace:
	shard = xdev_ext_preload_fd_shard(fd);
	xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, fd);
	xdev_ext_remove_fd_locked(&xdev_ext_fds[shard], fd);
	if (record) {
		record->generation = __atomic_add_fetch(&xdev_ext_fd_generation, 1,
							 __ATOMIC_RELAXED);
		record->next = xdev_ext_fds[shard];
		xdev_ext_fds[shard] = record;
	}
	xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, fd);
}

static int xdev_ext_finish_open(int fd)
{
	int saved_errno = errno;

	if (!xdev_ext_in_hook) {
		xdev_ext_in_hook++;
		pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
		xdev_ext_track_open_fd(fd);
		xdev_ext_in_hook--;
	}
	errno = saved_errno;
	return fd;
}

static bool xdev_ext_same_ctime(const struct timespec *a, const struct timespec *b)
{
	return a->tv_sec == b->tv_sec && a->tv_nsec == b->tv_nsec;
}

/*
 * On failure meta->refused says why: no record for this descriptor (never
 * opened at an allowlisted path, or retired), a buffered descriptor, or the
 * duplicate itself failed.
 */
static int xdev_ext_duplicate_validated_fd(int fd, struct xdev_ext_preload_fd_meta *meta)
{
	struct xdev_ext_fd_record snapshot;
	struct xdev_ext_fd_record *record;
	struct xdev_ext_preload_fd_identity expected;
	struct xdev_ext_preload_fd_identity observed;
	struct stat st;
	unsigned int shard;
	int duplicate = -1;
	int flags;
	bool path_allowed;
	bool path_known;
	bool buffered = false;
	bool tracked;
	bool matches;

	memset(meta, 0, sizeof(*meta));
	shard = xdev_ext_preload_fd_shard(fd);
	xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, fd);
	record = xdev_ext_find_fd_locked(xdev_ext_fds[shard], fd);
	if (record && !(record->status_flags & O_DIRECT)) {
		/*
		 * A buffered descriptor stays tracked because F_SETFL,
		 * interposed or raw, can set O_DIRECT later.  One F_GETFL
		 * keeps its calls from paying for the full validation below.
		 */
		flags = xdev_ext_real.fcntl_fn(fd, F_GETFL);
		if (flags < 0 || !(flags & O_DIRECT)) {
			buffered = flags >= 0;
			record = NULL;
		} else {
			record->status_flags = flags;
		}
	}
	tracked = record != NULL;
	if (record) {
		snapshot = *record;
		/*
		 * Interposed close/dup operations use this same lock.  Duplicate the
		 * open-file description before releasing it, then independently
		 * validate the duplicate to catch raw-syscall close/reuse races.
		 */
#ifdef F_DUPFD_CLOEXEC
		duplicate = xdev_ext_real.fcntl_fn(fd, F_DUPFD_CLOEXEC, 3);
#else
		duplicate = xdev_ext_real.dup_fn(fd);
#endif
	}
	xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, fd);
	if (!tracked || duplicate < 0) {
		meta->refused = buffered ? XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_DIRECT :
			tracked ? XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER :
			XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_ALLOWLISTED;
		return -1;
	}
	meta->tracked = true;
	meta->frame_size = xdev_ext_cfg.frame_size;
	meta->dio_mem_align = snapshot.dio_mem_align;
	meta->dio_offset_align = snapshot.dio_offset_align;
	meta->refused = XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER;
	if (fstat(duplicate, &st))
		goto invalid;
	flags = xdev_ext_real.fcntl_fn(duplicate, F_GETFL);
	if (flags < 0)
		goto invalid;
	expected = (struct xdev_ext_preload_fd_identity) {
		.dev = snapshot.dev,
		.ino = snapshot.ino,
		.mode = snapshot.mode,
	};
	observed = (struct xdev_ext_preload_fd_identity) {
		.dev = st.st_dev,
		.ino = st.st_ino,
		.mode = st.st_mode,
	};
	/*
	 * The record's path was allowlisted for this object at its last
	 * validation.  Renaming, linking or unlinking the file changes its
	 * ctime, and so does writing it; only then is the path read again.
	 * This is advisory: a change within one ctime tick of the last one can
	 * go unseen, and the request still names this same object.  Renaming a
	 * directory above the file leaves the file's ctime unchanged, so the
	 * exact-path allowlist then keeps passing for a path that no longer
	 * names it; only the allowlisted inode is ever admitted.
	 */
	path_known = xdev_ext_preload_fd_identity_matches(&expected, &observed,
							  true, O_DIRECT) &&
		     xdev_ext_same_ctime(&st.st_ctim, &snapshot.path_ctime);
	path_allowed = path_known || xdev_ext_path_is_allowed(duplicate, &st);
	matches = xdev_ext_preload_fd_identity_matches(&expected, &observed,
						  path_allowed, flags);
	meta->identity_matches = matches;
	meta->direct = matches;
	if (matches && !path_known) {
		xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, fd);
		record = xdev_ext_find_fd_locked(xdev_ext_fds[shard], fd);
		if (record && record->generation == snapshot.generation)
			record->path_ctime = st.st_ctim;
		xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, fd);
	}
	if (!matches) {
		/*
		 * A clear O_DIRECT flag alone falls back but keeps the record,
		 * with the observed flags so that the next call is cheap.
		 */
		bool stale = xdev_ext_preload_fd_record_stale(&expected, &observed,
							 path_allowed);

		meta->refused = stale ? XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_ALLOWLISTED :
			XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_DIRECT;
		xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, fd);
		record = xdev_ext_find_fd_locked(xdev_ext_fds[shard], fd);
		if (record && record->generation == snapshot.generation) {
			if (stale)
				xdev_ext_remove_fd_locked(&xdev_ext_fds[shard], fd);
			else
				record->status_flags = flags;
		}
		xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, fd);
		goto invalid;
	}
	meta->refused = XDEV_EXT_PRELOAD_FALLBACK_NONE;
	return duplicate;

invalid:
	(void)xdev_ext_real.close_fn(duplicate);
	return -1;
}

/* What a socket call learned about its duplicate. */
struct xdev_ext_socket_identity {
	uint64_t cookie;
	bool has_cookie;
	struct sockaddr_storage peer;
	socklen_t peer_len;
};

static bool xdev_ext_socket_option(int fd, int option, int *value)
{
	socklen_t length = sizeof(*value);

	return !xdev_ext_real.getsockopt_fn(fd, SOL_SOCKET, option, value, &length) &&
	       length == sizeof(*value);
}

/* The socket's type, domain and protocol, through the cookie cache. */
static bool xdev_ext_socket_kind(int fd, struct xdev_ext_socket_identity *id,
				 struct xdev_ext_socket_kind *kind)
{
	socklen_t length = sizeof(id->cookie);
	unsigned int i;
	int ret;

	ret = xdev_ext_real.getsockopt_fn(fd, SOL_SOCKET, SO_COOKIE, &id->cookie,
					  &length);
	if (!ret && length == sizeof(id->cookie) && id->cookie) {
		id->has_cookie = true;
		for (i = 0; i < XDEV_EXT_SOCKET_KIND_CACHE; i++) {
			if (xdev_ext_socket_kinds[i].cookie == id->cookie) {
				*kind = xdev_ext_socket_kinds[i];
				return true;
			}
		}
	} else if (ret && errno == ENOTSOCK) {
		return false;
	}
	if (!xdev_ext_socket_option(fd, SO_TYPE, &kind->type) ||
	    !xdev_ext_socket_option(fd, SO_DOMAIN, &kind->domain) ||
	    !xdev_ext_socket_option(fd, SO_PROTOCOL, &kind->protocol))
		return false;
	if (id->has_cookie) {
		kind->cookie = id->cookie;
		xdev_ext_socket_kinds[xdev_ext_socket_kind_next++ %
				      XDEV_EXT_SOCKET_KIND_CACHE] = *kind;
	}
	return true;
}

/* Keep an independent reference to the open-file-description for the whole
 * synchronous request.  Validation failures still return the duplicate so
 * the exact libc fallback cannot be redirected by a concurrent close/reuse. */
static int xdev_ext_duplicate_connected_udp(int fd, int *status_flags,
				       bool *eligible,
				       struct xdev_ext_socket_identity *id)
{
	struct xdev_ext_socket_kind kind;
	int duplicate;
	int flags;

	if (!status_flags || !eligible || !id)
		return -1;
	*status_flags = 0;
	*eligible = false;
	memset(id, 0, sizeof(*id));
#ifdef F_DUPFD_CLOEXEC
	duplicate = xdev_ext_real.fcntl_fn(fd, F_DUPFD_CLOEXEC, 3);
#else
	duplicate = xdev_ext_real.dup_fn(fd);
#endif
	if (duplicate < 0)
		return -1;
	if (!xdev_ext_real.getsockopt_fn || !xdev_ext_real.getpeername_fn)
		return duplicate;
	flags = xdev_ext_real.fcntl_fn(duplicate, F_GETFL);
	if (flags < 0)
		return duplicate;
	if (!xdev_ext_socket_kind(duplicate, id, &kind) ||
	    kind.type != SOCK_DGRAM ||
	    (kind.domain != AF_INET && kind.domain != AF_INET6) ||
	    kind.protocol != IPPROTO_UDP)
		return duplicate;
	/* The peer can change with every connect(), so it is read each call. */
	id->peer_len = sizeof(id->peer);
	if (xdev_ext_real.getpeername_fn(duplicate, (struct sockaddr *)&id->peer,
					 &id->peer_len) ||
	    id->peer_len < sizeof(id->peer.ss_family) ||
	    id->peer_len > sizeof(id->peer) || id->peer.ss_family != kind.domain)
		return duplicate;
	*status_flags = flags;
	*eligible = true;
	return duplicate;
}

static void xdev_ext_copy_fd_record(int oldfd, int newfd)
{
	struct xdev_ext_fd_record *copy = NULL;
	struct xdev_ext_fd_record *source;
	struct stat st;
	unsigned int old_shard;
	unsigned int new_shard;

	if (newfd < 0 || !xdev_ext_cfg.enabled)
		return;
	old_shard = xdev_ext_preload_fd_shard(oldfd);
	xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, oldfd);
	source = xdev_ext_find_fd_locked(xdev_ext_fds[old_shard], oldfd);
	if (source) {
		copy = malloc(sizeof(*copy));
		if (copy)
			*copy = *source;
	}
	xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, oldfd);
	if (copy && (fstat(newfd, &st) || st.st_dev != copy->dev ||
		     st.st_ino != copy->ino || !xdev_ext_path_is_allowed(newfd, &st))) {
		free(copy);
		copy = NULL;
	}
	if (copy)
		copy->path_ctime = st.st_ctim;
	new_shard = xdev_ext_preload_fd_shard(newfd);
	xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, newfd);
	xdev_ext_remove_fd_locked(&xdev_ext_fds[new_shard], newfd);
	if (copy) {
		copy->fd = newfd;
		copy->generation = __atomic_add_fetch(&xdev_ext_fd_generation, 1,
							 __ATOMIC_RELAXED);
		copy->next = xdev_ext_fds[new_shard];
		xdev_ext_fds[new_shard] = copy;
	}
	xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, newfd);
}

static void xdev_ext_refresh_fd_flags(int fd)
{
	struct xdev_ext_fd_record *record;
	unsigned int shard = xdev_ext_preload_fd_shard(fd);
	int flags = xdev_ext_real.fcntl_fn(fd, F_GETFL);

	if (flags < 0)
		return;
	xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, fd);
	record = xdev_ext_find_fd_locked(xdev_ext_fds[shard], fd);
	if (record)
		record->status_flags = flags;
	xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, fd);
}

static void xdev_ext_register_thread(struct xdev_ext_thread_ctx *thread)
{
	/* The initializer holds the registry lock from before ring creation. */
	thread->next = xdev_ext_threads;
	xdev_ext_threads = thread;
}

static void xdev_ext_remove_thread_locked(struct xdev_ext_thread_ctx *thread)
{
	struct xdev_ext_thread_ctx **cursor = &xdev_ext_threads;

	while (*cursor) {
		if (*cursor == thread) {
			*cursor = thread->next;
			thread->next = NULL;
			return;
		}
		cursor = &(*cursor)->next;
	}
}

/* Move a thread's taken-over counts into the process totals, once. */
static void xdev_ext_fold_qualified(struct xdev_ext_thread_ctx *thread)
{
	__atomic_add_fetch(&xdev_ext_file_qualified,
			   __atomic_exchange_n(&thread->file_qualified, 0,
					       __ATOMIC_RELAXED),
			   __ATOMIC_RELAXED);
	__atomic_add_fetch(&xdev_ext_socket_qualified,
			   __atomic_exchange_n(&thread->socket_qualified, 0,
					       __ATOMIC_RELAXED),
			   __ATOMIC_RELAXED);
}

static void xdev_ext_report_thread_locked(struct xdev_ext_thread_ctx *thread)
{
	struct xdev_ext_socket_mech_runtime *slots[XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS];
	struct xdev_ext_preload_report_snapshot snapshot;
	uint64_t mech[6 + 2 * 3] = { 0 };
	uint64_t custom_send_count;
	uint64_t custom_send_bytes;
	uint32_t custom_send_errors;
	unsigned int i, j;
	char line[480];
	int length;

	if (thread->owner_pid == getpid())
		xdev_ext_fold_qualified(thread);
	if (thread->report_emitted || thread->owner_pid != getpid() ||
	    !xdev_ext_preload_snapshot_report(
		    xdev_ext_cfg.report,
		    __atomic_load_n(&thread->quiescence_unknown, __ATOMIC_ACQUIRE),
		    thread->shared, &snapshot))
		return;
	slots[0] = &thread->socket_mech;
	for (i = 1; i < XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS; i++)
		slots[i] = &thread->socket_mech_more[i - 1];
	/* At exit/destruction this thread has no application call in progress.
	 * Drain its own sessions before reporting; never stop another live thread.
	 */
	if (xdev_ext_socket_mech_cfg.enabled &&
	    thread->owner_tid == (pid_t)syscall(SYS_gettid)) {
		pthread_mutex_lock(&thread->socket_mech_lock);
		for (i = 0; i < XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS; i++)
			(void)xdev_ext_socket_mech_release(slots[i]);
		pthread_mutex_unlock(&thread->socket_mech_lock);
	}
	custom_send_count = __atomic_load_n(&thread->custom_send_count,
					    __ATOMIC_RELAXED);
	custom_send_bytes = __atomic_load_n(&thread->custom_send_bytes,
					    __ATOMIC_RELAXED);
	custom_send_errors = __atomic_load_n(&thread->custom_send_errors,
					     __ATOMIC_RELAXED);
	length = snprintf(line, sizeof(line),
			  "XDEV_EXT_PRELOAD_REPORT pid=%ld tid=%ld "
			  "read_count=%" PRIu64 " read_bytes=%" PRIu64 " "
			  "read_errors=%" PRIu32 " write_count=%" PRIu64 " "
			  "write_bytes=%" PRIu64 " write_errors=%" PRIu32 " "
			  "custom_send_count=%" PRIu64 " "
			  "custom_send_bytes=%" PRIu64 " "
			  "custom_send_errors=%" PRIu32 "\n",
			  (long)thread->owner_pid, (long)thread->owner_tid,
			  snapshot.read_count, snapshot.read_bytes,
			  snapshot.read_errors, snapshot.write_count,
			  snapshot.write_bytes, snapshot.write_errors,
			  custom_send_count, custom_send_bytes,
			  custom_send_errors);
	if (length <= 0 || (size_t)length >= sizeof(line))
		return;
	thread->report_emitted = true;
	(void)syscall(SYS_write, STDERR_FILENO, line, (size_t)length);
	if (!xdev_ext_socket_mech_cfg.enabled)
		return;
	/* One line per thread: the sum over its sessions. */
	for (i = 0; i < XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS; i++) {
		struct xdev_ext_socket_mech_runtime *m = slots[i];
#define XDEV_EXT_SM_COUNT(field) __atomic_load_n(&m->field, __ATOMIC_RELAXED)
		mech[0] += XDEV_EXT_SM_COUNT(creates);
		mech[1] += XDEV_EXT_SM_COUNT(calls);
		mech[2] += XDEV_EXT_SM_COUNT(bytes);
		mech[3] += XDEV_EXT_SM_COUNT(errors);
		mech[4] += XDEV_EXT_SM_COUNT(stops);
		mech[5] += XDEV_EXT_SM_COUNT(stop_errors);
		for (j = 0; j < 3; j++) {
			mech[6 + j] += XDEV_EXT_SM_COUNT(submitted[j]);
			mech[9 + j] += XDEV_EXT_SM_COUNT(completed[j]);
		}
#undef XDEV_EXT_SM_COUNT
	}
	length = snprintf(line, sizeof(line),
		"XDEV_EXT_PRELOAD_MECH_REPORT pid=%ld tid=%ld creates=%" PRIu64
		" calls=%" PRIu64 " bytes=%" PRIu64 " errors=%" PRIu64
		" stops=%" PRIu64 " stop_errors=%" PRIu64
		" submitted0=%" PRIu64 " submitted1=%" PRIu64 " submitted2=%" PRIu64
		" completed0=%" PRIu64 " completed1=%" PRIu64 " completed2=%" PRIu64 "\n",
		(long)thread->owner_pid, (long)thread->owner_tid,
		mech[0], mech[1], mech[2], mech[3], mech[4], mech[5],
		mech[6], mech[7], mech[8], mech[9], mech[10], mech[11]);
	if (length > 0 && (size_t)length < sizeof(line))
		(void)syscall(SYS_write, STDERR_FILENO, line, (size_t)length);
}

/*
 * One line per process at exit: taken-over calls and, per reason, the calls
 * that stayed in libc, for the qualified fraction of an application's I/O.
 * The denominator is the calls the front end interposes: the positional
 * read/write families, send/sendto/sendmsg, and read()/write() on tracked
 * descriptors; readv()/writev() and memory-mapped I/O are not in it.
 * A process whose calls never reached the front end prints none.
 */
static void xdev_ext_report_fallbacks(void)
{
	uint64_t seen;
	char line[640];
	size_t used;
	int length;
	unsigned int i;

	seen = __atomic_load_n(&xdev_ext_file_qualified, __ATOMIC_RELAXED) |
	       __atomic_load_n(&xdev_ext_socket_qualified, __ATOMIC_RELAXED);
	for (i = 0; i < XDEV_EXT_PRELOAD_FALLBACK_NR; i++)
		seen |= __atomic_load_n(&xdev_ext_fallbacks[i], __ATOMIC_RELAXED);
	if (!seen)
		return;
	length = snprintf(line, sizeof(line),
			  "XDEV_EXT_PRELOAD_FALLBACK_REPORT pid=%ld "
			  "file_qualified=%" PRIu64 " socket_qualified=%" PRIu64,
			  (long)getpid(),
			  __atomic_load_n(&xdev_ext_file_qualified, __ATOMIC_RELAXED),
			  __atomic_load_n(&xdev_ext_socket_qualified, __ATOMIC_RELAXED));
	if (length <= 0 || (size_t)length >= sizeof(line))
		return;
	used = (size_t)length;
	for (i = XDEV_EXT_PRELOAD_FALLBACK_NONE + 1; i < XDEV_EXT_PRELOAD_FALLBACK_NR; i++) {
		length = snprintf(line + used, sizeof(line) - used, " %s=%" PRIu64,
				  xdev_ext_preload_fallback_name(i),
				  __atomic_load_n(&xdev_ext_fallbacks[i],
						  __ATOMIC_RELAXED));
		if (length <= 0 || (size_t)length >= sizeof(line) - used)
			return;
		used += (size_t)length;
	}
	if (used + 1 >= sizeof(line))
		return;
	line[used++] = '\n';
	(void)syscall(SYS_write, STDERR_FILENO, line, used);
}

static void xdev_ext_report_all_threads(void)
{
	struct xdev_ext_thread_ctx *thread;

	pthread_mutex_lock(&xdev_ext_thread_lock);
	for (thread = xdev_ext_threads; thread; thread = thread->next)
		xdev_ext_report_thread_locked(thread);
	pthread_mutex_unlock(&xdev_ext_thread_lock);
	if (xdev_ext_cfg.armed)
		xdev_ext_report_fallbacks();
}

static void xdev_ext_thread_destroy(void *opaque)
{
	struct xdev_ext_thread_ctx *thread = opaque;
	int cancel_state, ret;
	unsigned int i;

	if (!thread)
		return;
	/*
	 * An unmatched published request can still own this ring, its registered
	 * pages, and the file reference used by its SQE.  Intentionally retain all
	 * of them until process teardown; closing the ring is not proof that DMA
	 * has quiesced.
	 */
	if (__atomic_load_n(&thread->quiescence_unknown, __ATOMIC_ACQUIRE))
		return;
	/*
	 * When a thread returns from its start routine, glibc (seen on 2.35)
	 * runs this destructor with the thread's own cancellation state and
	 * before it marks the thread as exiting.  A request still pending then
	 * would act at the close() in io_uring_queue_exit(): the unwind
	 * abandons the teardown with the ring descriptor open and this context
	 * leaked, and pthread_join() reports PTHREAD_CANCELED instead of the
	 * returned value.  Restoring a deferred state afterwards does not act
	 * on the request.
	 */
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	pthread_mutex_lock(&xdev_ext_thread_lock);
	xdev_ext_report_thread_locked(thread);
	/* Keep the runtime discoverable by atfork until every inherited handle
	 * and mapping is gone. Unknown resources remain on the registry too.
	 */
	pthread_mutex_lock(&thread->socket_mech_lock);
	ret = xdev_ext_socket_mech_release(&thread->socket_mech);
	for (i = 0; i < XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS - 1; i++)
		if (xdev_ext_socket_mech_release(&thread->socket_mech_more[i]))
			ret = -EBUSY;
	pthread_mutex_unlock(&thread->socket_mech_lock);
	if (ret) {
		pthread_mutex_unlock(&xdev_ext_thread_lock);
		(void)pthread_setcancelstate(cancel_state, NULL);
		return;
	}
	xdev_ext_remove_thread_locked(thread);
	xdev_ext_in_hook++;
	if (thread->umem_registered && thread->owner_pid == getpid())
		syscall(SYS_io_uring_register, thread->ring.ring_fd,
			IORING_UNREGISTER_XDEV_EXT_UMEM, NULL, 0);
	if (thread->ring_ready)
		io_uring_queue_exit(&thread->ring);
	free(thread->shared);
	free(thread->umem);
	free(thread->maps_buffer);
	xdev_ext_in_hook--;
	/* Fork must not inherit a ring removed from the registry but still
	 * open. Keep the registry locked through ordinary-ring teardown too.
	 */
	pthread_mutex_unlock(&xdev_ext_thread_lock);
	(void)pthread_mutex_destroy(&thread->socket_mech_lock);
	free(thread);
	(void)pthread_setcancelstate(cancel_state, NULL);
}

static void xdev_ext_make_tls_key(void)
{
	xdev_ext_tls_key_error = pthread_key_create(&xdev_ext_tls_key, xdev_ext_thread_destroy);
}

/*
 * Only xdev_ext_get_thread() calls this, and its callers run with cancellation
 * disabled.  That is what makes it safe: io_uring_queue_exit() closes the
 * ring, and a request acting in that close() would leave this context half
 * torn down in the thread's key slot.
 */
static void xdev_ext_discard_inherited_thread(struct xdev_ext_thread_ctx *thread)
{
	unsigned int i;

	xdev_ext_socket_mech_forget_child(&thread->socket_mech);
	for (i = 0; i < XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS - 1; i++)
		xdev_ext_socket_mech_forget_child(&thread->socket_mech_more[i]);
	/* Unregistering here would mutate the parent's live, inherited ring. */
	pthread_mutex_lock(&xdev_ext_thread_lock);
	xdev_ext_remove_thread_locked(thread);
	pthread_mutex_unlock(&xdev_ext_thread_lock);
	if (thread->ring_ready)
		io_uring_queue_exit(&thread->ring);
	free(thread->shared);
	free(thread->umem);
	free(thread->maps_buffer);
	memset(thread, 0, sizeof(*thread));
}

static int xdev_ext_thread_init(struct xdev_ext_thread_ctx *thread)
{
	struct io_uring_xdev_ext_umem_reg registration;
	int ret;

	/* Also cover queue_init's partial failure cleanup: even before it
	 * returns, its descriptor and mappings are inheritable resources.
	 */
	pthread_mutex_lock(&xdev_ext_thread_lock);
	if (posix_memalign(&thread->umem, xdev_ext_cfg.frame_size,
			   xdev_ext_cfg.frame_size)) {
		pthread_mutex_unlock(&xdev_ext_thread_lock);
		return -ENOMEM;
	}
	memset(thread->umem, 0, xdev_ext_cfg.frame_size);
	thread->shared = calloc(1, sizeof(*thread->shared));
	if (!thread->shared) {
		ret = -ENOMEM;
		goto fail;
	}
	ret = io_uring_queue_init(2, &thread->ring, 0);
	if (ret < 0)
		goto fail;
	thread->ring_ready = true;
	registration = (struct io_uring_xdev_ext_umem_reg) {
		.addr = (uintptr_t)thread->umem,
		.size = xdev_ext_cfg.frame_size,
		.shared_addr = (uintptr_t)thread->shared,
		.frame_size = xdev_ext_cfg.frame_size,
	};
	ret = syscall(SYS_io_uring_register, thread->ring.ring_fd,
		      IORING_REGISTER_XDEV_EXT_UMEM, &registration, 1);
	if (ret < 0) {
		ret = -errno;
		goto fail;
	}
	thread->umem_registered = true;
	thread->frame_size = xdev_ext_cfg.frame_size;
	thread->owner_pid = getpid();
	thread->owner_tid = (pid_t)syscall(SYS_gettid);
	thread->socket_mech_lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	xdev_ext_register_thread(thread);
	pthread_mutex_unlock(&xdev_ext_thread_lock);
	return 0;

fail:
	if (thread->ring_ready)
		io_uring_queue_exit(&thread->ring);
	free(thread->shared);
	free(thread->umem);
	memset(thread, 0, sizeof(*thread));
	pthread_mutex_unlock(&xdev_ext_thread_lock);
	return ret;
}

/*
 * Callers run this with cancellation disabled.  Ring setup and its failure
 * path contain cancellation points (close); a request acting there would
 * leave a half torn-down ring for xdev_ext_thread_destroy().
 */
static struct xdev_ext_thread_ctx *xdev_ext_get_thread(void)
{
	struct xdev_ext_thread_ctx *thread;

	pthread_once(&xdev_ext_tls_once, xdev_ext_make_tls_key);
	if (xdev_ext_tls_key_error)
		return NULL;
	thread = pthread_getspecific(xdev_ext_tls_key);
	if (!thread) {
		thread = calloc(1, sizeof(*thread));
		if (!thread)
			return NULL;
		if (pthread_setspecific(xdev_ext_tls_key, thread)) {
			free(thread);
			return NULL;
		}
	}
	if (thread->owner_pid && thread->owner_pid != getpid())
		xdev_ext_discard_inherited_thread(thread);
	if (!thread->ring_ready && xdev_ext_thread_init(thread))
		return NULL;
	if (thread->broken)
		return NULL;
	return thread;
}

static int xdev_ext_ring_peek(void *opaque, uint64_t token, int *result)
{
	struct xdev_ext_ring_driver *driver = opaque;
	struct xdev_ext_thread_ctx *thread = driver->thread;
	struct io_uring_cq *cq = &thread->ring.cq;
	unsigned int head = __atomic_load_n(cq->khead, __ATOMIC_RELAXED);
	unsigned int tail = __atomic_load_n(cq->ktail, __ATOMIC_ACQUIRE);
	struct io_uring_cqe *cqe;

	if (head == tail)
		return 0;
	cqe = &cq->cqes[head & *cq->kring_mask];
	if (cqe->user_data != token) {
		thread->broken = true;
		return -EIO;
	}
	*result = cqe->res;
	__atomic_store_n(cq->khead, head + 1, __ATOMIC_RELEASE);
	return 1;
}

static int xdev_ext_ring_publish(void *opaque, const struct io_uring_sqe *request)
{
	struct xdev_ext_ring_driver *driver = opaque;
	struct xdev_ext_thread_ctx *thread = driver->thread;
	struct io_uring_sq *sq = &thread->ring.sq;
	unsigned int kernel_tail;
	unsigned int index;

	if (thread->broken)
		return -EIO;
	if (__atomic_load_n(sq->khead, __ATOMIC_ACQUIRE) !=
	    __atomic_load_n(sq->ktail, __ATOMIC_ACQUIRE))
		return -EBUSY;
	driver->initial_head = __atomic_load_n(sq->khead, __ATOMIC_ACQUIRE);
	kernel_tail = __atomic_load_n(sq->ktail, __ATOMIC_RELAXED);
	index = kernel_tail & *sq->kring_mask;
	sq->sqes[index] = *request;
	sq->array[index] = index;
	__atomic_store_n(sq->ktail, kernel_tail + 1, __ATOMIC_RELEASE);
	return 0;
}

static bool xdev_ext_ring_accepted(void *opaque)
{
	struct xdev_ext_ring_driver *driver = opaque;
	struct io_uring_sq *sq = &driver->thread->ring.sq;

	return __atomic_load_n(sq->khead, __ATOMIC_ACQUIRE) !=
	       driver->initial_head;
}

static int xdev_ext_ring_enter(void *opaque, unsigned int to_submit)
{
	struct xdev_ext_ring_driver *driver = opaque;
	int ret;

	ret = syscall(SYS_io_uring_enter, driver->thread->ring.ring_fd,
		      to_submit, 1, IORING_ENTER_GETEVENTS, NULL, 0);
	return ret < 0 ? -errno : ret;
}

/* Publish once, then drain the unique token. EINTR never causes a replay. */
static int xdev_ext_submit_and_wait(void *opaque, const struct io_uring_sqe *request,
			       int *cqe_res, bool *published)
{
	struct xdev_ext_call_ctx *call = opaque;
	struct xdev_ext_ring_driver driver = { .thread = call->thread };
	struct xdev_ext_preload_ring_seam seam = {
		.opaque = &driver,
		.publish_once = xdev_ext_ring_publish,
		.peek_completion = xdev_ext_ring_peek,
		.request_accepted = xdev_ext_ring_accepted,
		.enter_and_wait = xdev_ext_ring_enter,
	};
	int ret;

	ret = xdev_ext_preload_submit_and_drain(&seam, request, cqe_res, published);
	if (!xdev_ext_preload_can_release_backing(*published, ret == 0)) {
		call->thread->broken = true;
		__atomic_store_n(&call->thread->quiescence_unknown, true,
				 __ATOMIC_RELEASE);
	}
	return ret;
}

static int
xdev_ext_socket_submit_and_wait(void *opaque, const struct io_uring_sqe *request,
			   int *cqe_res, bool *published)
{
	struct xdev_ext_socket_call_ctx *call = opaque;
	int ret;

	ret = xdev_ext_submit_and_wait(&call->ring_call, request, cqe_res, published);
	if (!ret) {
		call->custom_completed = true;
		call->custom_cqe_res = *cqe_res;
	}
	return ret;
}

static ssize_t xdev_ext_socket_libc_send(const struct xdev_ext_socket_call_ctx *call,
				    int fd, const void *buffer, size_t count,
				    uint32_t flags, int *error)
{
	ssize_t ret;

	switch (call->kind) {
	case XDEV_EXT_SOCKET_CALL_SEND:
		ret = xdev_ext_real.send_fn(fd, buffer, count, (int)flags);
		break;
	case XDEV_EXT_SOCKET_CALL_SENDTO:
		ret = xdev_ext_real.sendto_fn(fd, buffer, count, (int)flags,
					 call->destination,
					 call->destination_length);
		break;
	case XDEV_EXT_SOCKET_CALL_SENDMSG:
		ret = xdev_ext_real.sendmsg_fn(fd, call->message, (int)flags);
		break;
	default:
		*error = EINVAL;
		return -1;
	}
	*error = ret < 0 ? errno : 0;
	return ret;
}

static void xdev_ext_close_duplicate(void *opaque)
{
	(void)xdev_ext_real.close_fn(*(const int *)opaque);
}

/*
 * The libc send on the front end's duplicate, entered with cancellation
 * disabled.  It runs with the caller's own cancellation state, as the caller's
 * call would; if a cancellation request acts inside it, fd is closed on the
 * way out, so fd must be the front end's own duplicate, never the caller's
 * descriptor.  Cancellation is disabled again before returning.
 */
static ssize_t xdev_ext_socket_duplicate_send(void *opaque, int fd,
					 const void *buffer, size_t count,
					 uint32_t flags, int *error)
{
	struct xdev_ext_socket_call_ctx *call = opaque;
	ssize_t ret;

	call->fell_back = true;
	pthread_cleanup_push(xdev_ext_close_duplicate, &fd);
	(void)pthread_setcancelstate(call->cancel_state, NULL);
	ret = xdev_ext_socket_libc_send(call, fd, buffer, count, flags, error);
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	pthread_cleanup_pop(0);
	return ret;
}

/*
 * One send through this thread's session for the socket.  *unavailable asks
 * for libc instead, with nothing started: the socket's own session, or the
 * one its slot needed stopped, is in an unknown state after a failed STOP,
 * and that slot keeps its resources.  Any other error is the call's result.
 */
static ssize_t xdev_ext_socket_mech_dispatch(struct xdev_ext_thread_ctx *thread,
					    int fd,
					    const struct xdev_ext_socket_identity *id,
					    const void *buffer, size_t count,
					    bool *unavailable)
{
	struct xdev_ext_socket_mech_runtime *slots[XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS];
	struct xdev_ext_socket_mech_runtime *m;
	unsigned int i;
	int ret;

	*unavailable = false;
	if (!id->has_cookie)
		return -ENOPROTOOPT;
	slots[0] = &thread->socket_mech;
	for (i = 1; i < XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS; i++)
		slots[i] = &thread->socket_mech_more[i - 1];
	m = xdev_ext_socket_mech_select(slots, XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS,
					id->cookie);
	if (!m) {
		*unavailable = true;
		return 0;
	}
	ret = xdev_ext_socket_mech_prepare_identity(m, &xdev_ext_socket_mech_cfg, fd,
						    thread->frame_size, id->cookie,
						    &id->peer, id->peer_len);
	if (ret) {
		/* Stopping the session of the socket's previous peer failed. */
		if (m->unknown) {
			*unavailable = true;
			return 0;
		}
		return ret;
	}
	m->last_use = ++thread->socket_mech_clock;
	xdev_ext_count_qualified(&thread->socket_qualified);
	return xdev_ext_socket_mech_transfer(m, buffer, count, thread->owner_pid);
}

static ssize_t
xdev_ext_socket_send(enum xdev_ext_socket_call_kind kind, int fd, const void *buffer,
		size_t count, int flags, const struct sockaddr *destination,
		socklen_t destination_length, const struct msghdr *message,
		int saved_errno)
{
	struct xdev_ext_socket_call_ctx call = {
		.kind = kind,
		.destination = destination,
		.destination_length = destination_length,
		.message = message,
	};
	struct xdev_ext_socket_identity identity;
	struct xdev_ext_preload_send_seam seam;
	struct xdev_ext_thread_ctx *thread = NULL;
	uint32_t effective_flags;
	uint64_t token;
	ssize_t ret;
	int request_fd = -1;
	int status_flags = 0;
	int error = 0;
	bool socket_eligible = false;
	bool unavailable;

	pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
	if (!xdev_ext_cfg.socket_enabled)
		goto fallback;
	if (!xdev_ext_preload_send_buffer_supported(buffer, count) ||
	    !xdev_ext_preload_send_flags_supported((uint32_t)flags)) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_SOCKET_OTHER);
		goto fallback;
	}
	/*
	 * Entry already acted on a pending cancellation.  While the front end
	 * holds its duplicate, a new request must not act inside the front end:
	 * a published SQE runs to its terminal CQE and the duplicate is closed.
	 * The request acts at the caller's next cancellation point, or inside
	 * the libc send on the duplicate, which then closes the duplicate.
	 */
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
				     &call.cancel_state);
	request_fd = xdev_ext_duplicate_connected_udp(fd, &status_flags,
						 &socket_eligible, &identity);
	if (request_fd < 0) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_SOCKET_OTHER);
		goto restore_and_fallback;
	}
	if (!socket_eligible) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_SOCKET_INELIGIBLE);
		goto duplicate_fallback;
	}
	if (xdev_ext_socket_mech_cfg.enabled &&
	    (!count || count > xdev_ext_cfg.frame_size || count > 65507 ||
	     (flags & ~MSG_NOSIGNAL) || (status_flags & O_NONBLOCK))) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_SOCKET_OTHER);
		goto duplicate_fallback;
	}
	thread = xdev_ext_get_thread();
	if (!thread) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_SOCKET_RUNTIME_ABSENT);
		goto duplicate_fallback;
	}
	if (xdev_ext_socket_mech_cfg.enabled) {
		pthread_mutex_lock(&thread->socket_mech_lock);
		ret = xdev_ext_socket_mech_dispatch(thread, request_fd, &identity,
						    buffer, count, &unavailable);
		pthread_mutex_unlock(&thread->socket_mech_lock);
		if (unavailable) {
			xdev_ext_count_fallback(
				XDEV_EXT_PRELOAD_FALLBACK_SOCKET_MECH_UNAVAILABLE);
			goto duplicate_fallback;
		}
		if (ret < 0) {error = -ret; ret = -1;}
		goto completed;
	}
	call.ring_call.thread = thread;
	effective_flags = xdev_ext_preload_send_effective_flags(status_flags, flags);
	seam = (struct xdev_ext_preload_send_seam) {
		.opaque = &call,
		.submit_and_wait = xdev_ext_socket_submit_and_wait,
		.fallback = xdev_ext_socket_duplicate_send,
	};
	token = xdev_ext_preload_next_token(&thread->tokens, (uint32_t)thread->owner_pid,
				       (uint32_t)thread->owner_tid);
	ret = xdev_ext_preload_execute_send(true, request_fd, buffer, count,
				       effective_flags,
				       (uintptr_t)thread->shared, token, &seam,
				       &error);
	xdev_ext_count_executed(thread, call.fell_back, &thread->socket_qualified,
				XDEV_EXT_PRELOAD_FALLBACK_SOCKET_RUNTIME_ABSENT,
				XDEV_EXT_PRELOAD_FALLBACK_SOCKET_OTHER);
completed:
	if (call.custom_completed) {
		if (call.custom_cqe_res < 0 ||
		    (size_t)call.custom_cqe_res > count) {
			__atomic_add_fetch(&thread->custom_send_errors, 1,
					   __ATOMIC_RELAXED);
		} else {
			__atomic_add_fetch(&thread->custom_send_count, 1,
					   __ATOMIC_RELAXED);
			__atomic_add_fetch(&thread->custom_send_bytes,
					   (uint64_t)call.custom_cqe_res,
					   __ATOMIC_RELAXED);
		}
	}
	if (!__atomic_load_n(&thread->quiescence_unknown, __ATOMIC_ACQUIRE))
		(void)xdev_ext_real.close_fn(request_fd);
	(void)pthread_setcancelstate(call.cancel_state, NULL);
	if (ret < 0)
		errno = error ? error : EIO;
	else
		errno = saved_errno;
	return ret;

duplicate_fallback:
	ret = xdev_ext_socket_duplicate_send(&call, request_fd, buffer, count,
					(uint32_t)flags, &error);
	(void)xdev_ext_real.close_fn(request_fd);
	(void)pthread_setcancelstate(call.cancel_state, NULL);
	goto out;

restore_and_fallback:
	(void)pthread_setcancelstate(call.cancel_state, NULL);
fallback:
	ret = xdev_ext_socket_libc_send(&call, fd, buffer, count, (uint32_t)flags,
				   &error);
out:
	if (ret < 0)
		errno = error;
	else
		errno = saved_errno;
	return ret;
}

static ssize_t xdev_ext_fallback(void *opaque, int fd, void *buffer, size_t count,
			    int64_t offset, bool write, int *error)
{
	struct xdev_ext_call_ctx *call = opaque;
	ssize_t ret;

	call->fell_back = true;
	if (write) {
		if (call->use_64)
			ret = xdev_ext_real.pwrite64_fn(fd, buffer, count, (off64_t)offset);
		else
			ret = xdev_ext_real.pwrite_fn(fd, buffer, count, (off_t)offset);
	} else {
		if (call->use_64)
			ret = xdev_ext_real.pread64_fn(fd, buffer, count, (off64_t)offset);
		else
			ret = xdev_ext_real.pread_fn(fd, buffer, count, (off_t)offset);
	}
	*error = ret < 0 ? errno : 0;
	return ret;
}

static ssize_t xdev_ext_iov_fallback(void *opaque, int fd,
				const struct iovec *iov, int iovcnt,
				int64_t offset, bool write, int flags, int *error)
{
	struct xdev_ext_call_ctx *call = opaque;
	ssize_t ret;

	call->fell_back = true;
	/* Admission and execution inspect only the owned snapshot. A delegation
	 * still passes the caller's original metadata to libc exactly once. */
	if (call->original_iov)
		iov = call->original_iov;

	if (write) {
		if (call->use_v2) {
			if (call->use_64 && xdev_ext_real.pwritev64v2_fn)
				ret = xdev_ext_real.pwritev64v2_fn(fd, iov, iovcnt,
							 (off64_t)offset, flags);
			else if (!call->use_64 && xdev_ext_real.pwritev2_fn)
				ret = xdev_ext_real.pwritev2_fn(fd, iov, iovcnt,
						       (off_t)offset, flags);
			else
				goto unavailable;
		} else if (call->use_64 && xdev_ext_real.pwritev64_fn) {
			ret = xdev_ext_real.pwritev64_fn(fd, iov, iovcnt,
						 (off64_t)offset);
		} else if (!call->use_64 && xdev_ext_real.pwritev_fn) {
			ret = xdev_ext_real.pwritev_fn(fd, iov, iovcnt, (off_t)offset);
		} else {
			goto unavailable;
		}
	} else {
		if (call->use_v2) {
			if (call->use_64 && xdev_ext_real.preadv64v2_fn)
				ret = xdev_ext_real.preadv64v2_fn(fd, iov, iovcnt,
							(off64_t)offset, flags);
			else if (!call->use_64 && xdev_ext_real.preadv2_fn)
				ret = xdev_ext_real.preadv2_fn(fd, iov, iovcnt,
						      (off_t)offset, flags);
			else
				goto unavailable;
		} else if (call->use_64 && xdev_ext_real.preadv64_fn) {
			ret = xdev_ext_real.preadv64_fn(fd, iov, iovcnt,
						(off64_t)offset);
		} else if (!call->use_64 && xdev_ext_real.preadv_fn) {
			ret = xdev_ext_real.preadv_fn(fd, iov, iovcnt, (off_t)offset);
		} else {
			goto unavailable;
		}
	}
	*error = ret < 0 ? errno : 0;
	return ret;

unavailable:
	*error = ENOSYS;
	return -1;
}

/* Reentrant calls must preserve libc semantics without dereferencing an
 * optional *v2 symbol that dlsym did not find.  Reuse the same exact fallback
 * selector as the ordinary ineligible path and surface ENOSYS when the host
 * libc truly has no matching entry point. */
static ssize_t xdev_ext_recursive_iov_v2(int fd, const struct iovec *iov,
				    int iovcnt, int64_t offset,
				    bool write, bool use_64, int flags)
{
	struct xdev_ext_call_ctx call = {
		.use_64 = use_64,
		.use_v2 = true,
	};
	int error = 0;
	ssize_t ret;

	ret = xdev_ext_iov_fallback(&call, fd, iov, iovcnt, offset, write, flags,
			       &error);
	if (ret < 0)
		errno = error;
	return ret;
}

/* O_DIRECT may reject the entire destination before transferring any bytes.
 * This is advisory admission only: mappings can change immediately afterwards,
 * so accepted reads must still use fault-reporting copyout and never replay.
 * Failure to inspect mappings simply keeps the original request in libc.
 * /proc/self/maps is opened and closed inside each check, so that the only
 * descriptor a thread keeps is its ring (the set the ordinary-fork oracle
 * allows) and an application's close_range() or dup2() can never leave the
 * check reading another file.  PROCMAP_QUERY asks for the VMAs covering the
 * destinations directly; without it (or past its query budget) the text is
 * read from offset 0 with pread, with no FILE buffer.  As with the fopen()
 * this replaces, a fork by another thread during the check inherits the
 * descriptor.
 */
#define XDEV_EXT_MAPS_BUFFER_SIZE (16U * 1024U)
#define XDEV_EXT_MAPS_LOCAL_CURSORS 4

/* struct procmap_query of the UAPI <linux/fs.h>, which libc headers lack. */
struct xdev_ext_procmap_query {
	uint64_t size;
	uint64_t query_flags;
	uint64_t query_addr;
	uint64_t vma_start;
	uint64_t vma_end;
	uint64_t vma_flags;
	uint64_t vma_page_size;
	uint64_t vma_offset;
	uint64_t inode;
	uint32_t dev_major;
	uint32_t dev_minor;
	uint32_t vma_name_size;
	uint32_t build_id_size;
	uint64_t vma_name_addr;
	uint64_t build_id_addr;
};
_Static_assert(sizeof(struct xdev_ext_procmap_query) == 104, "struct procmap_query");
#define XDEV_EXT_PROCMAP_QUERY _IOWR('f', 17, struct xdev_ext_procmap_query)

static int xdev_ext_procmap_query(void *opaque, uint64_t address, uint64_t *end,
				  uint64_t *flags)
{
	struct xdev_ext_procmap_query query = {
		.size = sizeof(query),
		.query_addr = address,
	};

	if (ioctl(*(const int *)opaque, XDEV_EXT_PROCMAP_QUERY, &query))
		return -errno;
	*end = query.vma_end;
	*flags = query.vma_flags;
	return 0;
}

/* A raw read: an interposer after the front end sees only the caller's I/O. */
static ssize_t xdev_ext_maps_read_at(void *opaque, void *buffer, size_t length,
				     uint64_t offset)
{
	const int *fd = opaque;
	ssize_t ret;

	do {
		ret = syscall(SYS_pread64, *fd, buffer, length, (off64_t)offset);
	} while (ret < 0 && errno == EINTR);
	return ret < 0 ? -errno : ret;
}

static bool xdev_ext_read_destinations_writable(struct xdev_ext_thread_ctx *thread,
					       const struct iovec *iov, int iovcnt)
{
	struct xdev_ext_preload_maps_reader reader = {
		.read_at = xdev_ext_maps_read_at,
	};
	uintptr_t local_cursor[XDEV_EXT_MAPS_LOCAL_CURSORS];
	uintptr_t *cursor = local_cursor;
	bool writable = false;
	int fd;
	int ret;

	if (!iov || iovcnt <= 0 || iovcnt > IOV_MAX)
		return false;
	if (!thread->maps_buffer) {
		thread->maps_buffer = malloc(XDEV_EXT_MAPS_BUFFER_SIZE);
		if (!thread->maps_buffer)
			return false;
	}
	do {
		fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps",
				  O_RDONLY | O_CLOEXEC);
	} while (fd < 0 && errno == EINTR);
	if (fd < 0)
		return false;
	if (!__atomic_load_n(&xdev_ext_procmap_query_absent, __ATOMIC_RELAXED)) {
		ret = xdev_ext_preload_maps_query_writable(xdev_ext_procmap_query,
							   &fd, iov, iovcnt);
		if (ret >= 0) {
			writable = ret;
			goto out;
		}
		/* Only a kernel without the ioctl stops later queries; any
		 * other error, or the query budget, sends this call to the text.
		 */
		if (ret == -ENOTTY || ret == -EINVAL)
			__atomic_store_n(&xdev_ext_procmap_query_absent, 1,
					 __ATOMIC_RELAXED);
	}
	if (iovcnt > XDEV_EXT_MAPS_LOCAL_CURSORS) {
		cursor = malloc((size_t)iovcnt * sizeof(*cursor));
		if (!cursor)
			goto out;
	}
	reader.opaque = &fd;
	reader.buffer = thread->maps_buffer;
	reader.capacity = XDEV_EXT_MAPS_BUFFER_SIZE;
	writable = xdev_ext_preload_maps_text_writable(&reader, iov, iovcnt, cursor);
	if (cursor != local_cursor)
		free(cursor);
out:
	(void)syscall(SYS_close, fd);
	return writable;
}

static ssize_t xdev_ext_positional_io(int fd, void *buffer, size_t count,
				 int64_t offset, bool write, bool use_64)
{
	enum xdev_ext_preload_fallback_reason reason;
	struct xdev_ext_preload_fd_meta meta;
	struct xdev_ext_preload_seam seam;
	struct xdev_ext_call_ctx call = { .use_64 = use_64 };
	struct xdev_ext_thread_ctx *thread;
	struct iovec destination = { .iov_base = buffer, .iov_len = count };
	uint64_t token;
	ssize_t ret;
	int request_fd = -1;
	int saved_errno = errno;
	int cancel_state;
	int error = 0;

	pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
	if (!xdev_ext_cfg.enabled)
		goto fallback;
	/*
	 * Entry already acted on a pending cancellation.  Until the result is
	 * known, a new request must not act inside the front end: a published
	 * SQE runs to its terminal CQE and the duplicate is closed.  The request
	 * acts at the caller's next cancellation point, and a libc fallback call
	 * runs with the caller's own cancellation state.
	 */
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	request_fd = xdev_ext_duplicate_validated_fd(fd, &meta);
	if (request_fd < 0) {
		xdev_ext_count_fallback(meta.refused);
		goto restore_and_fallback;
	}
	reason = xdev_ext_preload_fallback_reason(&meta, buffer, count, offset);
	if (reason != XDEV_EXT_PRELOAD_FALLBACK_NONE) {
		xdev_ext_count_fallback(reason);
		(void)xdev_ext_real.close_fn(request_fd);
		request_fd = -1;
		goto restore_and_fallback;
	}
	/* The context's cached pid and tid are this call's from here on. */
	thread = xdev_ext_get_thread();
	if (!thread) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_FILE_RUNTIME_ABSENT);
		(void)xdev_ext_real.close_fn(request_fd);
		request_fd = -1;
		goto restore_and_fallback;
	}
	if (!write && !xdev_ext_read_destinations_writable(thread, &destination, 1)) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
		(void)xdev_ext_real.close_fn(request_fd);
		request_fd = -1;
		goto restore_and_fallback;
	}
	/* The validated duplicate holds this exact object until its terminal CQE. */
	call.thread = thread;
	seam = (struct xdev_ext_preload_seam) {
		.opaque = &call,
		.submit_and_wait = xdev_ext_submit_and_wait,
		.fallback = xdev_ext_fallback,
		.self_pid = thread->owner_pid,
	};
	token = xdev_ext_preload_next_token(&thread->tokens, (uint32_t)thread->owner_pid,
				       (uint32_t)thread->owner_tid);
	ret = xdev_ext_preload_execute(&meta, request_fd, buffer, count, offset, write,
				  thread->umem, token, &seam, &error);
	xdev_ext_count_executed(thread, call.fell_back, &thread->file_qualified,
				XDEV_EXT_PRELOAD_FALLBACK_FILE_RUNTIME_ABSENT,
				XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
	if (!__atomic_load_n(&thread->quiescence_unknown, __ATOMIC_ACQUIRE))
		(void)xdev_ext_real.close_fn(request_fd);
	(void)pthread_setcancelstate(cancel_state, NULL);
	if (ret < 0)
		errno = error ? error : EIO;
	else
		errno = saved_errno;
	return ret;

restore_and_fallback:
	(void)pthread_setcancelstate(cancel_state, NULL);
fallback:
	ret = xdev_ext_fallback(&call, fd, buffer, count, offset, write, &error);
	if (ret < 0)
		errno = error;
	else
		errno = saved_errno;
	return ret;
}

static ssize_t xdev_ext_positional_iov(int fd, const struct iovec *iov, int iovcnt,
				  int64_t offset, bool write, bool use_64,
				  bool use_v2, int flags)
{
	enum xdev_ext_preload_fallback_reason reason;
	struct xdev_ext_preload_fd_meta meta;
	struct xdev_ext_preload_iov_seam seam;
	struct xdev_ext_call_ctx call = {
		.use_64 = use_64,
		.use_v2 = use_v2,
		.original_iov = iov,
	};
	struct xdev_ext_thread_ctx *thread;
	struct iovec *snapshot = NULL;
	size_t total;
	uint64_t token;
	ssize_t ret;
	int request_fd = -1;
	int saved_errno = errno;
	int cancel_state;
	int error = 0;

	pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
	/* Only the exact positional flags=0 ABI maps to READ/WRITE_COMPAT. */
	if (!xdev_ext_cfg.enabled)
		goto fallback;
	if (flags) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
		goto fallback;
	}
	/*
	 * Entry already acted on a pending cancellation.  Until the result is
	 * known, a new request must not act inside the front end: a published
	 * SQE runs to its terminal CQE and the duplicate is closed.  The request
	 * acts at the caller's next cancellation point, and a libc fallback call
	 * runs with the caller's own cancellation state.
	 */
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	request_fd = xdev_ext_duplicate_validated_fd(fd, &meta);
	if (request_fd < 0) {
		xdev_ext_count_fallback(meta.refused);
		goto restore_and_fallback;
	}
	/* Do not touch user metadata for descriptors that cannot be admitted. */
	reason = xdev_ext_preload_meta_fallback_reason(&meta);
	if (reason == XDEV_EXT_PRELOAD_FALLBACK_NONE &&
	    (!iov || iovcnt <= 0 || iovcnt > IOV_MAX || offset < 0))
		reason = iovcnt > IOV_MAX || offset < 0 ?
			XDEV_EXT_PRELOAD_FALLBACK_FILE_SIZE :
			XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER;
	if (reason != XDEV_EXT_PRELOAD_FALLBACK_NONE) {
		xdev_ext_count_fallback(reason);
		goto close_and_fallback;
	}
	/* The context's cached pid and tid are this call's from here on. */
	thread = xdev_ext_get_thread();
	if (!thread) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_FILE_RUNTIME_ABSENT);
		goto close_and_fallback;
	}
	snapshot = malloc((size_t)iovcnt * sizeof(*snapshot));
	if (!snapshot || xdev_ext_preload_user_copy_pid(thread->owner_pid, snapshot,
			(void *)iov, (size_t)iovcnt * sizeof(*snapshot), false) !=
	    (ssize_t)((size_t)iovcnt * sizeof(*snapshot))) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
		goto close_and_fallback;
	}
	reason = xdev_ext_preload_iov_fallback_reason(&meta, snapshot, iovcnt, offset);
	if (reason != XDEV_EXT_PRELOAD_FALLBACK_NONE ||
	    !xdev_ext_preload_iov_is_eligible(&meta, snapshot, iovcnt, offset, &total)) {
		xdev_ext_count_fallback(reason);
		(void)xdev_ext_real.close_fn(request_fd);
		request_fd = -1;
		goto restore_and_fallback;
	}
	if (!write && !xdev_ext_read_destinations_writable(thread, snapshot, iovcnt)) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
		goto close_and_fallback;
	}

	call.thread = thread;
	seam = (struct xdev_ext_preload_iov_seam) {
		.opaque = &call,
		.submit_and_wait = xdev_ext_submit_and_wait,
		.fallback = xdev_ext_iov_fallback,
		.self_pid = thread->owner_pid,
	};
	token = xdev_ext_preload_next_token(&thread->tokens, (uint32_t)thread->owner_pid,
				       (uint32_t)thread->owner_tid);
	ret = xdev_ext_preload_execute_iov(&meta, request_fd, snapshot, iovcnt, offset,
				      write, flags, thread->umem, token, &seam,
				      &error);
	xdev_ext_count_executed(thread, call.fell_back, &thread->file_qualified,
				XDEV_EXT_PRELOAD_FALLBACK_FILE_RUNTIME_ABSENT,
				XDEV_EXT_PRELOAD_FALLBACK_FILE_OTHER);
	if (!__atomic_load_n(&thread->quiescence_unknown, __ATOMIC_ACQUIRE))
		(void)xdev_ext_real.close_fn(request_fd);
	free(snapshot);
	(void)pthread_setcancelstate(cancel_state, NULL);
	if (ret < 0)
		errno = error ? error : EIO;
	else
		errno = saved_errno;
	return ret;

close_and_fallback:
	(void)xdev_ext_real.close_fn(request_fd);
restore_and_fallback:
	free(snapshot);
	(void)pthread_setcancelstate(cancel_state, NULL);
fallback:
	ret = xdev_ext_iov_fallback(&call, fd, iov, iovcnt, offset, write, flags,
			       &error);
	if (ret < 0)
		errno = error;
	else
		errno = saved_errno;
	return ret;
}

int open(const char *path, int flags, ...)
{
	mode_t mode = 0;
	int fd;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_open_needs_mode(flags)) {
		va_list args;
		va_start(args, flags);
		mode = (mode_t)va_arg(args, int);
		va_end(args);
		fd = xdev_ext_real.open_fn(path, flags, mode);
	} else {
		fd = xdev_ext_real.open_fn(path, flags);
	}
	return xdev_ext_finish_open(fd);
}

int open64(const char *path, int flags, ...)
{
	mode_t mode = 0;
	int fd;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_open_needs_mode(flags)) {
		va_list args;
		va_start(args, flags);
		mode = (mode_t)va_arg(args, int);
		va_end(args);
		fd = xdev_ext_real.open64_fn(path, flags, mode);
	} else {
		fd = xdev_ext_real.open64_fn(path, flags);
	}
	return xdev_ext_finish_open(fd);
}

int openat(int dirfd, const char *path, int flags, ...)
{
	mode_t mode = 0;
	int fd;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_open_needs_mode(flags)) {
		va_list args;
		va_start(args, flags);
		mode = (mode_t)va_arg(args, int);
		va_end(args);
		fd = xdev_ext_real.openat_fn(dirfd, path, flags, mode);
	} else {
		fd = xdev_ext_real.openat_fn(dirfd, path, flags);
	}
	return xdev_ext_finish_open(fd);
}

int openat64(int dirfd, const char *path, int flags, ...)
{
	mode_t mode = 0;
	int fd;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_open_needs_mode(flags)) {
		va_list args;
		va_start(args, flags);
		mode = (mode_t)va_arg(args, int);
		va_end(args);
		fd = xdev_ext_real.openat64_fn(dirfd, path, flags, mode);
	} else {
		fd = xdev_ext_real.openat64_fn(dirfd, path, flags);
	}
	return xdev_ext_finish_open(fd);
}

int __open_2(const char *path, int flags)
{
	int fd;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	fd = xdev_ext_real.open2_fn ? xdev_ext_real.open2_fn(path, flags) :
				xdev_ext_real.open_fn(path, flags);
	return xdev_ext_finish_open(fd);
}

int __open64_2(const char *path, int flags)
{
	int fd;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	fd = xdev_ext_real.open64_2_fn ? xdev_ext_real.open64_2_fn(path, flags) :
				  xdev_ext_real.open64_fn(path, flags);
	return xdev_ext_finish_open(fd);
}

int __openat_2(int dirfd, const char *path, int flags)
{
	int fd;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	fd = xdev_ext_real.openat2_fn ? xdev_ext_real.openat2_fn(dirfd, path, flags) :
				 xdev_ext_real.openat_fn(dirfd, path, flags);
	return xdev_ext_finish_open(fd);
}

int __openat64_2(int dirfd, const char *path, int flags)
{
	int fd;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	fd = xdev_ext_real.openat64_2_fn ?
		xdev_ext_real.openat64_2_fn(dirfd, path, flags) :
		xdev_ext_real.openat64_fn(dirfd, path, flags);
	return xdev_ext_finish_open(fd);
}

/* Explicitly interposed close/dup replacement retires every cached session
 * on this socket. The registry pins contexts while the per-context mutex
 * waits for any accepted call to become terminal before retiring its cache.
 * Raw syscalls bypass the compatibility library, as with positional I/O.
 */
static void xdev_ext_socket_mech_forget_fd(int fd)
{
	struct xdev_ext_thread_ctx *thread;
	uint64_t cookie;
	socklen_t size = sizeof(cookie);
	int cancel_state, saved_errno = errno;
	unsigned int i;

	if (!xdev_ext_socket_mech_cfg.enabled ||
	    syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_COOKIE, &cookie, &size) ||
	    size != sizeof(cookie))
		goto out;
	(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	pthread_mutex_lock(&xdev_ext_thread_lock);
	for (thread = xdev_ext_threads; thread; thread = thread->next) {
		if (thread->owner_pid != getpid()) continue;
		pthread_mutex_lock(&thread->socket_mech_lock);
		for (i = 0; i < XDEV_EXT_PRELOAD_SOCKET_MECH_SLOTS; i++) {
			struct xdev_ext_socket_mech_runtime *m = i ?
				&thread->socket_mech_more[i - 1] : &thread->socket_mech;

			if (m->session && m->cookie == cookie)
				(void)xdev_ext_socket_mech_release(m);
		}
		pthread_mutex_unlock(&thread->socket_mech_lock);
	}
	pthread_mutex_unlock(&xdev_ext_thread_lock);
	(void)pthread_setcancelstate(cancel_state, NULL);
out:
	errno = saved_errno;
}

int close(int fd)
{
	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (!xdev_ext_in_hook) {
		xdev_ext_in_hook++;
		pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
		if (xdev_ext_cfg.enabled)
			xdev_ext_forget_fd(fd);
		xdev_ext_socket_mech_forget_fd(fd);
		xdev_ext_in_hook--;
	}
	return xdev_ext_real.close_fn(fd);
}

int dup(int oldfd)
{
	int ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	ret = xdev_ext_real.dup_fn(oldfd);
	if (!xdev_ext_in_hook && ret >= 0) {
		xdev_ext_in_hook++;
		pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
		xdev_ext_copy_fd_record(oldfd, ret);
		xdev_ext_in_hook--;
	}
	return ret;
}

int dup2(int oldfd, int newfd)
{
	int ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (!xdev_ext_in_hook && oldfd != newfd) {
		xdev_ext_in_hook++;
		pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
		xdev_ext_socket_mech_forget_fd(newfd);
		xdev_ext_in_hook--;
	}
	ret = xdev_ext_real.dup2_fn(oldfd, newfd);
	if (!xdev_ext_in_hook && ret >= 0 && oldfd != newfd) {
		xdev_ext_in_hook++;
		pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
		xdev_ext_copy_fd_record(oldfd, ret);
		xdev_ext_in_hook--;
	}
	return ret;
}

int dup3(int oldfd, int newfd, int flags)
{
	int ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (!xdev_ext_in_hook && oldfd != newfd) {
		xdev_ext_in_hook++;
		pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
		xdev_ext_socket_mech_forget_fd(newfd);
		xdev_ext_in_hook--;
	}
	ret = xdev_ext_real.dup3_fn(oldfd, newfd, flags);
	if (!xdev_ext_in_hook && ret >= 0) {
		xdev_ext_in_hook++;
		pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
		xdev_ext_copy_fd_record(oldfd, ret);
		xdev_ext_in_hook--;
	}
	return ret;
}

static int xdev_ext_fcntl_dispatch(int (*function)(int, int, ...), int fd,
			      int command, va_list *args)
{
	enum xdev_ext_fcntl_arg_kind kind;
	int ret;

	kind = xdev_ext_preload_fcntl_arg_kind(command);
	if (kind == XDEV_EXT_FCNTL_POINTER_ARG) {
		void *argument;

		argument = va_arg(*args, void *);
		ret = function(fd, command, argument);
	} else if (kind == XDEV_EXT_FCNTL_INT_ARG) {
		int argument;

		argument = va_arg(*args, int);
		ret = function(fd, command, argument);
	} else {
		ret = function(fd, command);
	}
	if (!xdev_ext_in_hook && ret >= 0) {
		xdev_ext_in_hook++;
		pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
		if (command == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
		    || command == F_DUPFD_CLOEXEC
#endif
		)
			xdev_ext_copy_fd_record(fd, ret);
		else if (command == F_SETFL)
			xdev_ext_refresh_fd_flags(fd);
		xdev_ext_in_hook--;
	}
	return ret;
}

int fcntl(int fd, int command, ...)
{
	va_list args;
	int ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	va_start(args, command);
	ret = xdev_ext_fcntl_dispatch(xdev_ext_real.fcntl_fn, fd, command, &args);
	va_end(args);
	return ret;
}

int fcntl64(int fd, int command, ...)
{
	va_list args;
	int ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	va_start(args, command);
	ret = xdev_ext_fcntl_dispatch(xdev_ext_real.fcntl64_fn, fd, command, &args);
	va_end(args);
	return ret;
}

/*
 * read() and write() always stay in libc.  With XDEV_EXT_PRELOAD_REPORT=1 a
 * call on a descriptor the front end tracks counts as file_not_positional, so
 * that the qualified fraction does not leave out an allowlisted file's
 * non-positional I/O; other descriptors are not counted.
 */
static void xdev_ext_count_not_positional(int fd)
{
	bool tracked;

	if (xdev_ext_in_hook || fd < 0)
		return;
	xdev_ext_in_hook++;
	pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
	if (xdev_ext_cfg.enabled && xdev_ext_cfg.report) {
		xdev_ext_preload_fd_lock(&xdev_ext_fd_locks, fd);
		tracked = xdev_ext_find_fd_locked(
			xdev_ext_fds[xdev_ext_preload_fd_shard(fd)], fd) != NULL;
		xdev_ext_preload_fd_unlock(&xdev_ext_fd_locks, fd);
		if (tracked)
			xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_FILE_NOT_POSITIONAL);
	}
	xdev_ext_in_hook--;
}

ssize_t read(int fd, void *buffer, size_t count)
{
	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	xdev_ext_count_not_positional(fd);
	return xdev_ext_real.read_fn(fd, buffer, count);
}

ssize_t write(int fd, const void *buffer, size_t count)
{
	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	xdev_ext_count_not_positional(fd);
	return xdev_ext_real.write_fn(fd, buffer, count);
}

/*
 * send, sendto, sendmsg and the positional read/write families are POSIX
 * cancellation points.  Act on a pending deferred cancellation before the
 * front end duplicates a descriptor or publishes an SQE, where the libc entry
 * point would act on it.  The test must come before xdev_ext_in_hook is raised, so
 * that a cancellation acting at entry leaves the hook depth unchanged and the
 * exiting thread's cleanup handlers are still served by the front end.
 *
 * The wrapper's matching xdev_ext_in_hook-- runs only when the call returns.  A
 * cancellation that acts inside a libc call made with the caller's own state
 * (the fallback on the caller's descriptor, or the libc send on the front
 * end's duplicate) unwinds past it, so the exiting thread's cleanup handlers
 * and thread-specific-data destructors run with xdev_ext_in_hook raised: their
 * calls go straight to libc, and their close() skips xdev_ext_forget_fd().  A
 * record left that way is discarded by the identity validation of the next
 * call that finds a different file at that descriptor number, or replaced
 * when an open() through the front end returns that number again.
 */
static void xdev_ext_cancel_point_enter(void)
{
	pthread_testcancel();
	xdev_ext_in_hook++;
}

ssize_t send(int fd, const void *buffer, size_t count, int flags)
{
	int saved_errno = errno;
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook) {
		ret = xdev_ext_real.send_fn(fd, buffer, count, flags);
		if (ret >= 0)
			errno = saved_errno;
		return ret;
	}
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_socket_send(XDEV_EXT_SOCKET_CALL_SEND, fd, buffer, count, flags,
			      NULL, 0, NULL, saved_errno);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t sendto(int fd, const void *buffer, size_t count, int flags,
	       const struct sockaddr *destination, socklen_t destination_length)
{
	int saved_errno = errno;
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (!xdev_ext_in_hook && xdev_ext_cfg.socket_enabled &&
	    !xdev_ext_preload_sendto_shape_supported(destination,
						destination_length))
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_SOCKET_OTHER);
	if (xdev_ext_in_hook ||
	    !xdev_ext_preload_sendto_shape_supported(destination,
						destination_length)) {
		ret = xdev_ext_real.sendto_fn(fd, buffer, count, flags, destination,
					 destination_length);
		if (ret >= 0)
			errno = saved_errno;
		return ret;
	}
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_socket_send(XDEV_EXT_SOCKET_CALL_SENDTO, fd, buffer, count, flags,
			      destination, destination_length, NULL,
			      saved_errno);
	xdev_ext_in_hook--;
	return ret;
}

/* Inspect only bounded local metadata. A fault, short copy or unsupported
 * shape must reach libc with the original message before any publication;
 * libc/kernel retain responsibility for descriptor/error precedence.
 */
static bool xdev_ext_sendmsg_snapshot(const struct msghdr *message,
				 const void **buffer, size_t *count)
{
	struct msghdr header;
	struct iovec iov, local, remote;
	pid_t pid = getpid();

	local = (struct iovec){ .iov_base = &header, .iov_len = sizeof(header) };
	remote = (struct iovec){ .iov_base = (void *)message,
				 .iov_len = sizeof(header) };
	if (syscall(SYS_process_vm_readv, (long)pid, &local, 1UL, &remote, 1UL, 0UL) !=
	    (ssize_t)sizeof(header))
		return false;
	if (header.msg_name || header.msg_namelen || header.msg_control ||
	    header.msg_controllen || !header.msg_iov || header.msg_iovlen != 1)
		return false;
	local = (struct iovec){ .iov_base = &iov, .iov_len = sizeof(iov) };
	remote = (struct iovec){ .iov_base = header.msg_iov,
				 .iov_len = sizeof(iov) };
	if (syscall(SYS_process_vm_readv, (long)pid, &local, 1UL, &remote, 1UL, 0UL) !=
	    (ssize_t)sizeof(iov))
		return false;
	header.msg_iov = &iov;
	return xdev_ext_preload_sendmsg_shape_supported(&header, buffer, count);
}

ssize_t sendmsg(int fd, const struct msghdr *message, int flags)
{
	const void *buffer = NULL;
	size_t count = 0;
	int saved_errno = errno;
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		goto fallback;
	pthread_once(&xdev_ext_config_once, xdev_ext_load_config);
	if (!xdev_ext_cfg.socket_enabled)
		goto fallback;
	if (!xdev_ext_preload_send_flags_supported((uint32_t)flags) ||
	    !xdev_ext_sendmsg_snapshot(message, &buffer, &count)) {
		xdev_ext_count_fallback(XDEV_EXT_PRELOAD_FALLBACK_SOCKET_OTHER);
		goto fallback;
	}
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_socket_send(XDEV_EXT_SOCKET_CALL_SENDMSG, fd, buffer, count, flags,
			      NULL, 0, message, saved_errno);
	xdev_ext_in_hook--;
	return ret;

fallback:
	ret = xdev_ext_real.sendmsg_fn(fd, message, flags);
	if (ret >= 0)
		errno = saved_errno;
	return ret;
}

ssize_t pread(int fd, void *buffer, size_t count, off_t offset)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_real.pread_fn(fd, buffer, count, offset);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_io(fd, buffer, count, offset, false, false);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t pread64(int fd, void *buffer, size_t count, off64_t offset)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_real.pread64_fn(fd, buffer, count, offset);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_io(fd, buffer, count, offset, false, true);
	xdev_ext_in_hook--;
	return ret;
}

/*
 * -D_FORTIFY_SOURCE turns pread/pread64 into a buffer of known size and a
 * run-time count into these entry points.  An oversized count keeps glibc's
 * check, which aborts; every other call is handled exactly like pread/pread64.
 */
static ssize_t xdev_ext_pread_chk(int fd, void *buffer, size_t count, int64_t offset,
			     size_t buffer_length, bool use_64)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (count > buffer_length || xdev_ext_in_hook) {
		if (use_64 && xdev_ext_real.pread64_chk_fn)
			return xdev_ext_real.pread64_chk_fn(fd, buffer, count,
						       (off64_t)offset,
						       buffer_length);
		if (!use_64 && xdev_ext_real.pread_chk_fn)
			return xdev_ext_real.pread_chk_fn(fd, buffer, count,
						     (off_t)offset, buffer_length);
		if (count > buffer_length)
			abort();
		return use_64 ? xdev_ext_real.pread64_fn(fd, buffer, count,
						    (off64_t)offset) :
				xdev_ext_real.pread_fn(fd, buffer, count, (off_t)offset);
	}
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_io(fd, buffer, count, offset, false, use_64);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t __pread_chk(int fd, void *buffer, size_t count, off_t offset,
		    size_t buffer_length)
{
	return xdev_ext_pread_chk(fd, buffer, count, offset, buffer_length, false);
}

ssize_t __pread64_chk(int fd, void *buffer, size_t count, off64_t offset,
		      size_t buffer_length)
{
	return xdev_ext_pread_chk(fd, buffer, count, offset, buffer_length, true);
}

ssize_t pwrite(int fd, const void *buffer, size_t count, off_t offset)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_real.pwrite_fn(fd, buffer, count, offset);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_io(fd, (void *)buffer, count, offset, true, false);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t pwrite64(int fd, const void *buffer, size_t count, off64_t offset)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_real.pwrite64_fn(fd, buffer, count, offset);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_io(fd, (void *)buffer, count, offset, true, true);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_real.preadv_fn(fd, iov, iovcnt, offset);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_iov(fd, iov, iovcnt, offset, false, false, false, 0);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t preadv64(int fd, const struct iovec *iov, int iovcnt, off64_t offset)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_real.preadv64_fn(fd, iov, iovcnt, offset);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_iov(fd, iov, iovcnt, offset, false, true, false, 0);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_real.pwritev_fn(fd, iov, iovcnt, offset);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_iov(fd, iov, iovcnt, offset, true, false, false, 0);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t pwritev64(int fd, const struct iovec *iov, int iovcnt, off64_t offset)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_real.pwritev64_fn(fd, iov, iovcnt, offset);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_iov(fd, iov, iovcnt, offset, true, true, false, 0);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset,
		int flags)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_recursive_iov_v2(fd, iov, iovcnt, offset, false,
					    false, flags);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_iov(fd, iov, iovcnt, offset, false, false, true,
				 flags);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t preadv64v2(int fd, const struct iovec *iov, int iovcnt, off64_t offset,
		   int flags)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_recursive_iov_v2(fd, iov, iovcnt, offset, false,
					    true, flags);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_iov(fd, iov, iovcnt, offset, false, true, true,
				 flags);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset,
		 int flags)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_recursive_iov_v2(fd, iov, iovcnt, offset, true,
					    false, flags);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_iov(fd, iov, iovcnt, offset, true, false, true,
				 flags);
	xdev_ext_in_hook--;
	return ret;
}

ssize_t pwritev64v2(int fd, const struct iovec *iov, int iovcnt,
		    off64_t offset, int flags)
{
	ssize_t ret;

	pthread_once(&xdev_ext_real_once, xdev_ext_resolve_real_functions);
	if (xdev_ext_in_hook)
		return xdev_ext_recursive_iov_v2(fd, iov, iovcnt, offset, true,
					    true, flags);
	xdev_ext_cancel_point_enter();
	ret = xdev_ext_positional_iov(fd, iov, iovcnt, offset, true, true, true,
				 flags);
	xdev_ext_in_hook--;
	return ret;
}
