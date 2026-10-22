/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDEV_EXT_PRELOAD_SINK_H
#define XDEV_EXT_PRELOAD_SINK_H

/*
 * Device-independent interface between the export layer of the transparent
 * fast path and the back ends that serve a registered descriptor.  A sink
 * takes over positional writes; a source takes over datagram receive.  The
 * export layer owns registration, admission and the per-thread ring; a back
 * end owns only its private state behind the registration's backend pointer.
 *
 * Keep this header free of device names: every back end plugs in through the
 * operation tables below, and the export layer names them only in its
 * backend registry.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Defined by the registration table, the flow configuration and the export
 * layer; back ends only pass pointers to them through. */
struct xdev_ext_reg;
struct xdev_ext_flow;
struct xdev_ext_thread_ctx;
enum xdev_ext_release_reason;

/* One positional transfer as the application asked for it. */
struct xdev_ext_io {
	const void *buf;
	size_t count;
	int64_t offset;
	int app_fd;
	bool write;
};

/*
 * Return values of xdev_ext_sink_ops.execute.  FALLBACK means nothing reached the
 * ring: the caller runs libc with the original arguments.  SERVED means the
 * request was published and reached its terminal completion; *result then
 * holds the byte count or a negative errno, and libc is never called, since
 * the kernel may already have acted on the request.
 */
enum xdev_ext_sink_verdict {
	XDEV_EXT_SINK_FALLBACK = 0,
	XDEV_EXT_SINK_SERVED = 1,
};

struct xdev_ext_sink_ops {
	const char *name;
	/* 0 and *backend set when the descriptor is taken over, else -errno. */
	int  (*probe)(int app_fd, const struct stat *st, const char *path,
		      void **backend);
	/* Pure checks on the call; no system calls. */
	bool (*eligible)(const void *backend, const struct xdev_ext_reg *r,
			 const struct xdev_ext_io *io);
	/* Returns an enum xdev_ext_sink_verdict. */
	int  (*execute)(void *backend, struct xdev_ext_reg *r,
			struct xdev_ext_thread_ctx *t, const struct xdev_ext_io *io,
			ssize_t *result, bool *published);
	void (*destroy)(void *backend);
	/* Writes this registration's report line once. */
	void (*report)(const void *backend, int out_fd);
};

struct xdev_ext_source_ops {
	const char *name;
	int  (*activate)(int app_fd, const struct xdev_ext_flow *flow,
			 void **backend);
	int  (*refilter)(void *backend, const struct xdev_ext_flow *flow);
	int  (*recv)(void *backend, struct xdev_ext_reg *r, int app_fd,
		     struct msghdr *msg, int flags, ssize_t *result);
	/* 1 while an undelivered datagram remains. */
	int  (*ready)(void *backend);
	int  (*wait_fd)(const void *backend);
	int  (*mirror_add)(void *backend, int epfd, int app_fd,
			   const struct epoll_event *ev);
	int  (*mirror_mod)(void *backend, int epfd, int app_fd,
			   const struct epoll_event *ev);
	int  (*mirror_del)(void *backend, int epfd, int app_fd);
	void (*release)(void *backend, enum xdev_ext_release_reason why);
	void (*sequester)(void *backend);
	void (*after_fork_child)(void *backend);
	void (*destroy)(void *backend);
	void (*report)(const void *backend, int out_fd);
};

#endif /* XDEV_EXT_PRELOAD_SINK_H */
