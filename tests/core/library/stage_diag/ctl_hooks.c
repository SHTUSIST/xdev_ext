/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include "include/uapi/linux/io_uring.h"
#include "include/uapi/linux/xdev_ext_mech.h"

long __wrap_syscall(long nr, ...)
{
 va_list ap; va_start(ap, nr);
 if (nr != __NR_io_uring_register) {
  va_end(ap); errno = ENOSYS; return -1;
 }
 int fd = va_arg(ap, int);
 unsigned opcode = va_arg(ap, unsigned);
 void *arg = va_arg(ap, void *);
 unsigned count = va_arg(ap, unsigned);
 va_end(ap);
 if (opcode != IORING_REGISTER_XDEV_EXT_MECH || count != 1) {
  errno = EINVAL; return -1;
 }
 struct io_uring_xdev_ext_mech *m = arg;
 fprintf(stderr, "HOOK fd=%d op=%u\n", fd, m->op);
 if (fcntl(fd, F_GETFD) < 0) { errno = EBADF; return -1; }
 if (m->op != XDEV_EXT_MECH_OP_STAGE_DIAG || m->rsvd) {
  errno = EINVAL; return -1;
 }
 struct xdev_ext_mech_stage_diag *d = (void *)(uintptr_t)m->arg;
 fprintf(stderr, "HOOK id=%llu stage=%u\n", (unsigned long long)d->session_id, d->stage);
 if (getenv("DIAG_UNSUPPORTED")) { errno = EOPNOTSUPP; return -1; }
 d->class_id = XDEV_EXT_MECH_CLASS_XDOMAIN;
 d->valid = XDEV_EXT_MECH_DIAG_IDENTITY | XDEV_EXT_MECH_DIAG_NATIVE |
  XDEV_EXT_MECH_DIAG_PROTOCOL;
 d->readiness = XDEV_EXT_MECH_DIAG_CLOSING;
 d->token = 51; d->local_inc = 52; d->remote_inc = 53;
 d->capture_begin_ns = 100; d->capture_end_ns = 200;
 d->native_inflight = 7; d->software_pending = 8; d->ack_owed = 9;
 if (getenv("DIAG_BAD_SCHEMA")) d->rsvd = 1;
 return 0;
}
