#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Per-reason fallback counters of the preload front end.

With XDEV_EXT_PRELOAD_REPORT=1 an armed front end prints one
XDEV_EXT_PRELOAD_FALLBACK_REPORT line per process at exit.  It counts the
calls that were taken over (file_qualified, socket_qualified) and, per reason,
the calls that stayed in libc, so that an evaluation can report the fraction
of an application's I/O calls that qualified.  The denominator is the calls
the front end interposes: the positional read/write families, send, sendto
and sendmsg, and read()/write() on a descriptor it tracks (an allowlisted
file opened through it), which are counted as file_not_positional.
readv()/writev() and memory-mapped I/O are not in it.  The fixture makes a
known number of calls for every reason and compares each returned byte with
independently generated expected bytes.

The existing kernel model completes the taken-over requests; this is host API
evidence of the accounting, not evidence of the kernel path or of a device.
"""
from pathlib import Path
import os
import re
import shlex
import socket
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get("XDEV_EXT_PRELOAD_TEST_DIR", str(HERE))).resolve()
KSFT_SKIP = 4
FIXTURE = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define BLOCK 4096

static void pattern(unsigned char *out, size_t len, unsigned int seed)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (unsigned char)(seed * 131u + i * 7u + 1u);
}

static int fail(const char *what)
{
    printf("XDEV_EXT_FALLBACK_FIXTURE=FAIL %s errno=%d\n", what, errno);
    return 1;
}

/* pread into buffer and compare with the file's independent pattern. */
static int checked_pread(int fd, unsigned char *buffer, size_t len, off_t offset)
{
    unsigned char expected[4 * BLOCK];

    memset(buffer, 0, len);
    pattern(expected, sizeof(expected), 5);
    if (pread(fd, buffer, len, offset) != (ssize_t)len ||
        memcmp(buffer, expected + offset, len))
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    unsigned char *aligned, *seed, *readonly;
    int allowed, buffered, other, i;

    if (argc != 5)
        return 2;
    if (posix_memalign((void **)&aligned, BLOCK, 4 * BLOCK) ||
        posix_memalign((void **)&seed, BLOCK, 4 * BLOCK))
        return fail("allocation");
    pattern(seed, 4 * BLOCK, 5);
    allowed = open(argv[1], O_RDWR | O_DIRECT);
    buffered = open(argv[1], O_RDONLY);
    other = open(argv[2], O_RDWR | O_DIRECT);
    if (allowed < 0 || buffered < 0 || other < 0)
        return fail("open");
    if (pwrite(other, seed, 4 * BLOCK, 0) != 4 * BLOCK)
        return fail("seed other");
    for (i = 0; i < atoi(argv[3]); i++)
        if (checked_pread(allowed, aligned, BLOCK, BLOCK))
            return fail("qualified pread");
    for (i = 0; i < 2; i++)
        if (checked_pread(other, aligned, BLOCK, 0))
            return fail("not-allowlisted pread");
    for (i = 0; i < 2; i++)
        if (checked_pread(buffered, aligned, BLOCK, 0))
            return fail("buffered pread");
    for (i = 0; i < 2; i++)
        if (checked_pread(allowed, aligned + 512, 512, 0))
            return fail("misaligned pread");
    if (checked_pread(allowed, aligned, 2 * BLOCK, 0))
        return fail("oversized pread");
    /* read()/write() on the allowlisted file, and a read() of a pipe. */
    if (lseek(allowed, 0, SEEK_SET) != 0)
        return fail("lseek");
    for (i = 0; i < 2; i++) {
        memset(aligned, 0, BLOCK);
        if (read(allowed, aligned, BLOCK) != BLOCK ||
            memcmp(aligned, seed + i * BLOCK, BLOCK))
            return fail("read");
    }
    memcpy(aligned, seed + 2 * BLOCK, BLOCK);
    if (write(allowed, aligned, BLOCK) != BLOCK)
        return fail("write");
    {
        int pipefd[2];
        char byte = 'x';

        if (pipe(pipefd) || write(pipefd[1], &byte, 1) != 1 ||
            read(pipefd[0], &byte, 1) != 1 || byte != 'x')
            return fail("pipe");
        close(pipefd[0]);
        close(pipefd[1]);
    }
    readonly = mmap(NULL, BLOCK, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (readonly == MAP_FAILED)
        return fail("mmap");
    errno = 0;
    if (pread(allowed, readonly, BLOCK, 0) != -1 || errno != EFAULT)
        return fail("read-only destination");
    {
        struct iovec iov = { aligned, BLOCK };

        if (preadv2(allowed, &iov, 1, 0, RWF_HIPRI) != BLOCK ||
            memcmp(aligned, seed, BLOCK))
            return fail("preadv2 with flags");
    }
    if (strcmp(argv[4], "-")) {
        int udp = atoi(argv[4]), pair[2];
        unsigned char payload[64];

        pattern(payload, sizeof(payload), 9);
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) ||
            send(pair[0], payload, sizeof(payload), 0) != sizeof(payload) ||
            send(udp, payload, sizeof(payload), 0) != sizeof(payload) ||
            send(udp, payload, sizeof(payload), MSG_CONFIRM) != sizeof(payload))
            return fail("sends");
    }
    puts("XDEV_EXT_FALLBACK_FIXTURE=PASS");
    return 0;
}
"""


def records(text, prefix):
    return [dict(re.findall(r"(\w+)=(\S+)", line)) for line in text.splitlines()
            if line.startswith(prefix + " ")]


class FallbackReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frontend = OUT / "libio_uring_unified.so"
        cls.model = OUT / "libxdev_ext_preload_kernel_model.so"
        for library in (cls.frontend, cls.model):
            if not library.is_file():
                raise RuntimeError(f"missing build artifact: {library}; build the selftests first")
        cls.work = tempfile.TemporaryDirectory(prefix="xdev-fallback-", dir=OUT)
        cls.addClassCleanup(cls.work.cleanup)
        directory = Path(cls.work.name)
        cls.clean_env = {key: value for key, value in os.environ.items()
                         if not key.startswith("XDEV") and key != "LD_PRELOAD"}
        source = directory / "fixture.c"
        source.write_text(FIXTURE)
        cls.binary = directory / "fixture"
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
            str(source), "-o", str(cls.binary)], env=cls.clean_env,
            check=True, capture_output=True, text=True, timeout=30)
        expected = bytes((5 * 131 + i * 7 + 1) & 0xff for i in range(4 * 4096))
        cls.allowed = directory / "allowed"
        cls.other = directory / "other"
        cls.allowed.write_bytes(expected)
        cls.other.write_bytes(b"\0" * 4 * 4096)
        try:
            os.close(os.open(cls.allowed, os.O_RDWR | os.O_DIRECT))
        except OSError:
            raise unittest.SkipTest(f"{directory} does not accept O_DIRECT")

    def run_fixture(self, qualified, umem, with_socket):
        env = dict(self.clean_env)
        env.update(LD_PRELOAD=f"{self.frontend}:{self.model}",
                   XDEV_EXT_MODEL_DIOALIGN="4096:4096",
                   XDEV_EXT_PRELOAD_ENABLED="1", XDEV_EXT_PRELOAD_PATHS=str(self.allowed),
                   XDEV_EXT_PRELOAD_REPORT="1", XDEV_EXT_PRELOAD_FRAME_SIZE="4096")
        env["XDEV_EXT_MODEL_UMEM" if umem else "XDEV_EXT_MODEL_REJECT_UMEM"] = "1"
        rx = tx = None
        argument, pass_fds = "-", ()
        if with_socket:
            env["XDEV_EXT_PRELOAD_SOCKET_ENABLED"] = "1"
            rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rx.bind(("127.0.0.1", 0))
            tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tx.connect(rx.getsockname())
            argument, pass_fds = str(tx.fileno()), (tx.fileno(),)
        try:
            completed = subprocess.run(
                [str(self.binary), str(self.allowed), str(self.other), str(qualified),
                 argument], env=env, pass_fds=pass_fds, capture_output=True,
                text=True, timeout=30)
            if rx is not None:
                rx.settimeout(3)
                expected = bytes((9 * 131 + i * 7 + 1) & 0xff for i in range(64))
                self.assertEqual([rx.recv(4096), rx.recv(4096)], [expected, expected])
        finally:
            for item in (rx, tx):
                if item is not None:
                    item.close()
        text = completed.stdout + completed.stderr
        print(f"# qualified={qualified} umem={umem} socket={with_socket}")
        for line in text.splitlines():
            print("# " + line)
        self.assertEqual(completed.returncode, 0, text)
        self.assertIn("XDEV_EXT_FALLBACK_FIXTURE=PASS", completed.stdout, text)
        rows = records(completed.stderr, "XDEV_EXT_PRELOAD_FALLBACK_REPORT")
        self.assertEqual(len(rows), 1, text)
        return {key: int(value) for key, value in rows[0].items() if key != "pid"}, text

    def test_0_every_reason_is_counted(self):
        counts, text = self.run_fixture(3, True, True)
        # The pwrite that seeds the other file is one of the three.
        expected = dict(file_qualified=3, file_not_allowlisted=3, file_not_direct=2,
                        file_misaligned=2, file_size=1, file_runtime_absent=0,
                        file_other=2, file_not_positional=3,
                        socket_qualified=1, socket_ineligible=1,
                        socket_runtime_absent=0, socket_mech_unavailable=0,
                        socket_other=1)
        self.assertEqual(counts, expected, text)

    def test_1_rejected_registration_counts_runtime_absent(self):
        counts, text = self.run_fixture(2, False, False)
        self.assertEqual(counts["file_qualified"], 0, text)
        # The qualifying preads plus the read-only destination, which only a
        # running front end inspects, find no runtime.
        self.assertEqual(counts["file_runtime_absent"], 3, text)
        self.assertEqual(counts["file_not_allowlisted"], 3, text)
        self.assertEqual(counts["file_misaligned"], 2, text)
        # Counted without a runtime too: the call shape alone decides.
        self.assertEqual(counts["file_not_positional"], 3, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
