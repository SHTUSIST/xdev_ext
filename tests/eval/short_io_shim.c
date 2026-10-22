/* SPDX-License-Identifier: GPL-2.0-only
 * Test-only interposer: real syscalls with forced EINTR and partial progress.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static _Thread_local unsigned calls;
static int interrupt_call(void)
{
    if (++calls % 11 == 1) { errno = EINTR; return 1; }
    return 0;
}

ssize_t pread(int fd, void *buffer, size_t count, off_t offset)
{
    ssize_t (*real_call)(int, void *, size_t, off_t) = dlsym(RTLD_NEXT, "pread");
    if (interrupt_call()) return -1;
    return real_call(fd, buffer, count > 127 ? 127 : count, offset);
}

/* _FILE_OFFSET_BITS=64 maps the benchmark's pread symbol to pread64. */
ssize_t pread64(int fd, void *buffer, size_t count, off64_t offset)
{
    ssize_t (*real_call)(int, void *, size_t, off64_t) = dlsym(RTLD_NEXT, "pread64");
    if (interrupt_call()) return -1;
    return real_call(fd, buffer, count > 127 ? 127 : count, offset);
}

ssize_t send(int fd, const void *buffer, size_t count, int flags)
{
    ssize_t (*real_call)(int, const void *, size_t, int) = dlsym(RTLD_NEXT, "send");
    if (interrupt_call()) return -1;
    return real_call(fd, buffer, count > 113 ? 113 : count, flags);
}
