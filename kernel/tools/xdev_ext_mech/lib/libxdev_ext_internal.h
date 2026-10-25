/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LIBXDEV_EXT_INTERNAL_H
#define LIBXDEV_EXT_INTERNAL_H

/*
 * Not public API.  Host unit tests replace these calls to observe the
 * requests the library builds and to inject kernel error returns
 * (SPEC.md section 7).  NULL members fall back to the real system call.
 */

#include <stddef.h>

struct io_uring_params;

struct xdev_ext_sys {
	int (*io_uring_setup)(unsigned int entries, struct io_uring_params *p);
	/* Returns 0/positive or -errno, like the library's own wrapper. */
	int (*io_uring_register)(int fd, unsigned int opcode, void *arg,
				 unsigned int nr_args);
	void (*usleep)(unsigned int usec);
	/* Returns 0/positive or -errno. */
	int (*ioctl)(int fd, unsigned long request, unsigned long arg);
};

/* Replace the system calls; NULL restores all of them. */
void xdev_ext__set_sys(const struct xdev_ext_sys *sys);

struct xdev_ext_session;
struct xdev_ext_prog;

/* Shared between the library's units; not for applications. */
int xdev_ext__opts_check(const void *o, size_t sz, size_t known);
/* The replaceable system calls, for the library's other units. */
int xdev_ext__uring_register(int fd, unsigned int opcode, void *arg);
int xdev_ext__ioctl(int fd, unsigned long request, unsigned long arg);
int xdev_ext__session_own_fd(struct xdev_ext_session *s, int fd);
int xdev_ext__session_adopt_prog(struct xdev_ext_session *s, struct xdev_ext_prog *p,
				 int (*detach)(struct xdev_ext_prog *p));

#endif /* LIBXDEV_EXT_INTERNAL_H */
