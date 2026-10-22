/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XDEV_EVAL_COMMON_H
#define XDEV_EVAL_COMMON_H
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Deliberately bounded disposable-file experiments, not raw-device writers. */
#define EVAL_MAX_CHUNK (16U * 1024U * 1024U)
#define EVAL_MAX_BYTES (UINT64_C(1) << 40)

static inline uint64_t eval_number(const char *text, uint64_t max, const char *name)
{
    char *end;
    unsigned long long n;
    errno = 0;
    if (!text[0] || strspn(text, "0123456789") != strlen(text)) {
        fprintf(stderr, "invalid %s\n", name);
        exit(2);
    }
    n = strtoull(text, &end, 10);
    if (errno || *end || n > max) {
        fprintf(stderr, "invalid %s\n", name);
        exit(2);
    }
    return (uint64_t)n;
}

static inline uint64_t eval_now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static inline int eval_pread(int fd, void *buf, size_t size, uint64_t offset)
{
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(fd, (char *)buf + done, size - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (!n) errno = ENODATA;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

static inline int eval_pwrite(int fd, const void *buf, size_t size, uint64_t offset)
{
    size_t done = 0;
    while (done < size) {
        ssize_t n = pwrite(fd, (const char *)buf + done, size - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            if (!n) errno = EIO;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}
#endif
