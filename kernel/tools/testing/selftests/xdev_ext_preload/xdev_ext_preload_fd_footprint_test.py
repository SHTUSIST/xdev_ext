#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Descriptors the preload front end keeps open across taken-over file calls.

The only descriptor a thread's file path may keep after its calls return is
its own io_uring ring; the ordinary-fork guest oracle
(xdev_ext_preload_ordinary_fork_guest.c, allowed_fds()) requires exactly the
baseline set plus one ring per eligible thread.  The fixture lists
/proc/self/fd (number and link target) before any call, after taken-over
pread/preadv/pwrite calls on the main thread, after sixteen more, while a
second thread that also made taken-over calls is alive, and after that thread
has exited.  It also makes one pread into a read-only destination, so the
read-destination check is known to have run.  Every returned byte is compared
with independently generated expected bytes.

The existing kernel model completes the taken-over requests on a real host
io_uring; this is host evidence of the front end's descriptor footprint, not
evidence of the kernel path or of a device.
"""
from pathlib import Path
import os
import re
import shlex
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get("XDEV_EXT_PRELOAD_TEST_DIR", str(HERE))).resolve()
RING = "anon_inode:[io_uring]"
FIXTURE = r"""
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#define BLOCK 4096

static int allowed;
static pthread_barrier_t barrier;

static void pattern(unsigned char *out, size_t len, unsigned int seed)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (unsigned char)(seed * 131u + i * 7u + 1u);
}

static int fail(const char *what)
{
    printf("XDEV_EXT_FD_FIXTURE=FAIL %s errno=%d\n", what, errno);
    return 1;
}

/* Every open descriptor except the listing's own directory. */
static int snapshot(const char *stage)
{
    char link[64], target[PATH_MAX];
    struct dirent *entry;
    DIR *directory = opendir("/proc/self/fd");
    ssize_t length;

    if (!directory)
        return 1;
    while ((entry = readdir(directory))) {
        int fd;

        if (entry->d_name[0] == '.')
            continue;
        fd = atoi(entry->d_name);
        if (fd == dirfd(directory))
            continue;
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        length = readlink(link, target, sizeof(target) - 1);
        if (length < 0)
            continue;
        target[length] = '\0';
        printf("XDEV_EXT_FD_SNAPSHOT stage=%s fd=%d target=%s\n", stage, fd, target);
    }
    closedir(directory);
    return 0;
}

/* One pread, one two-element preadv and one pwrite of the same bytes. */
static int calls(unsigned char *buffer)
{
    unsigned char expected[4 * BLOCK];
    struct iovec iov[2] = {
        { buffer, BLOCK }, { buffer + 2 * BLOCK, BLOCK },
    };

    pattern(expected, sizeof(expected), 5);
    memset(buffer, 0, 4 * BLOCK);
    if (pread(allowed, buffer, BLOCK, BLOCK) != BLOCK ||
        memcmp(buffer, expected + BLOCK, BLOCK))
        return 1;
    memset(buffer, 0, 4 * BLOCK);
    if (preadv(allowed, iov, 2, 2 * BLOCK) != 2 * BLOCK ||
        memcmp(buffer, expected + 2 * BLOCK, BLOCK) ||
        memcmp(buffer + 2 * BLOCK, expected + 3 * BLOCK, BLOCK))
        return 1;
    memcpy(buffer, expected, BLOCK);
    if (pwrite(allowed, buffer, BLOCK, 0) != BLOCK)
        return 1;
    return 0;
}

static void *worker(void *opaque)
{
    unsigned char *buffer = opaque;
    long failed = calls(buffer);

    pthread_barrier_wait(&barrier);
    pthread_barrier_wait(&barrier);
    return (void *)failed;
}

int main(int argc, char **argv)
{
    unsigned char *buffer, *other, *readonly;
    pthread_t thread;
    void *result;
    int i;

    if (argc != 2)
        return 2;
    if (posix_memalign((void **)&buffer, BLOCK, 4 * BLOCK) ||
        posix_memalign((void **)&other, BLOCK, 4 * BLOCK))
        return fail("allocation");
    readonly = mmap(NULL, BLOCK, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (readonly == MAP_FAILED)
        return fail("mmap");
    allowed = open(argv[1], O_RDWR | O_DIRECT);
    if (allowed < 0)
        return fail("open");
    if (pthread_barrier_init(&barrier, NULL, 2))
        return fail("barrier");
    fflush(stdout);
    if (snapshot("base"))
        return fail("snapshot base");
    if (calls(buffer))
        return fail("first calls");
    errno = 0;
    if (pread(allowed, readonly, BLOCK, 0) != -1 || errno != EFAULT)
        return fail("read-only destination");
    if (snapshot("first"))
        return fail("snapshot first");
    for (i = 0; i < 16; i++)
        if (calls(buffer))
            return fail("repeated calls");
    if (snapshot("repeated"))
        return fail("snapshot repeated");
    if (pthread_create(&thread, NULL, worker, other))
        return fail("thread");
    pthread_barrier_wait(&barrier);
    if (snapshot("worker-live"))
        return fail("snapshot worker-live");
    pthread_barrier_wait(&barrier);
    if (pthread_join(thread, &result) || result)
        return fail("worker calls");
    if (snapshot("worker-exited"))
        return fail("snapshot worker-exited");
    puts("XDEV_EXT_FD_FIXTURE=PASS");
    return 0;
}
"""


class FdFootprint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frontend = OUT / "libio_uring_unified.so"
        cls.model = OUT / "libxdev_ext_preload_kernel_model.so"
        for library in (cls.frontend, cls.model):
            if not library.is_file():
                raise RuntimeError(f"missing build artifact: {library}; build the selftests first")
        cls.work = tempfile.TemporaryDirectory(prefix="xdev-fd-footprint-", dir=OUT)
        cls.addClassCleanup(cls.work.cleanup)
        directory = Path(cls.work.name)
        cls.clean_env = {key: value for key, value in os.environ.items()
                         if not key.startswith("XDEV") and key != "LD_PRELOAD"}
        source = directory / "fixture.c"
        source.write_text(FIXTURE)
        cls.binary = directory / "fixture"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread",
            str(source), "-o", str(cls.binary)], env=cls.clean_env,
            check=True, capture_output=True, text=True, timeout=30)
        cls.allowed = directory / "allowed"
        cls.allowed.write_bytes(bytes((5 * 131 + i * 7 + 1) & 0xff
                                      for i in range(4 * 4096)))
        try:
            os.close(os.open(cls.allowed, os.O_RDWR | os.O_DIRECT))
        except OSError:
            raise unittest.SkipTest(f"{directory} does not accept O_DIRECT")

    def test_only_rings_stay_open(self):
        env = dict(self.clean_env)
        env.update(LD_PRELOAD=f"{self.frontend}:{self.model}",
                   XDEV_EXT_MODEL_DIOALIGN="4096:4096", XDEV_EXT_MODEL_UMEM="1",
                   XDEV_EXT_PRELOAD_ENABLED="1", XDEV_EXT_PRELOAD_PATHS=str(self.allowed),
                   XDEV_EXT_PRELOAD_REPORT="1", XDEV_EXT_PRELOAD_FRAME_SIZE="8192")
        completed = subprocess.run([str(self.binary), str(self.allowed)], env=env,
                                   capture_output=True, text=True, timeout=60)
        text = completed.stdout + completed.stderr
        for line in text.splitlines():
            print("# " + line)
        self.assertEqual(completed.returncode, 0, text)
        self.assertIn("XDEV_EXT_FD_FIXTURE=PASS", completed.stdout, text)
        # 18 rounds of three calls per thread on two threads, all taken over.
        report = [dict(re.findall(r"(\w+)=(\S+)", line)) for line in completed.stderr.splitlines()
                  if line.startswith("XDEV_EXT_PRELOAD_FALLBACK_REPORT ")]
        self.assertEqual(len(report), 1, text)
        self.assertEqual(int(report[0]["file_qualified"]), 17 * 3 + 3, text)

        stages = {}
        for line in completed.stdout.splitlines():
            match = re.fullmatch(r"XDEV_EXT_FD_SNAPSHOT stage=(\S+) fd=(\d+) target=(.*)", line)
            if match:
                stages.setdefault(match[1], {})[int(match[2])] = match[3]
        base = stages["base"]
        expected_rings = {"first": 1, "repeated": 1, "worker-live": 2, "worker-exited": 1}
        for stage, rings in expected_rings.items():
            current = stages[stage]
            with self.subTest(stage=stage):
                for fd, target in base.items():
                    self.assertEqual(current.get(fd), target, f"baseline fd {fd} changed")
                extra = {fd: target for fd, target in current.items() if fd not in base}
                undeclared = {fd: target for fd, target in extra.items() if target != RING}
                self.assertEqual(undeclared, {}, f"undeclared descriptors at {stage}")
                self.assertEqual(len(extra), rings, f"ring count at {stage}: {extra}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
