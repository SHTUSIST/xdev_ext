#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Unreadable sendmsg metadata must retain Linux EFAULT and socket effects.

Each call runs in a separate process: a preload fault remains an observed
signal, and the parent still inspects the peer for unwanted datagrams.  The
armed configuration uses the existing test-only kernel model; this is a host
API regression check, not evidence of physical DMA or kernel execution.
"""
from pathlib import Path
import errno
import json
import os
import shlex
import socket
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get("XDEV_EXT_PRELOAD_TEST_DIR", str(HERE))).resolve()
CONTROL = b"efault-control"
FIXTURE = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct rlimit no_core = {0, 0};
    char payload[] = "efault-control";
    struct iovec iov = {.iov_base = payload, .iov_len = sizeof(payload) - 1};
    struct msghdr header = {.msg_iov = &iov, .msg_iovlen = 1};
    const struct msghdr *message = &header;
    long page_size = sysconf(_SC_PAGESIZE);
    void *mapping;
    volatile uintptr_t unreadable;
    ssize_t result;
    int saved_errno, fd;

    if (argc != 4 || page_size <= 0 || setrlimit(RLIMIT_CORE, &no_core))
        return 2;
    fd = atoi(argv[1]);
    mapping = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED || mprotect(mapping, (size_t)page_size, PROT_NONE))
        return 3;
    /* A runtime mapping, rather than an invented constant invalid pointer,
     * keeps the fixture well-defined for compiler diagnostics and optimizers.
     * Only the kernel or the API under test should inspect the protected page.
     */
    unreadable = (uintptr_t)mapping;
    if (!strcmp(argv[2], "msghdr"))
        message = (const struct msghdr *)unreadable;
    else if (!strcmp(argv[2], "iov"))
        header.msg_iov = (struct iovec *)unreadable;
    else if (strcmp(argv[2], "control"))
        return 4;

    errno = 0;
    if (!strcmp(argv[3], "syscall"))
        result = syscall(SYS_sendmsg, fd, message, MSG_NOSIGNAL);
    else if (!strcmp(argv[3], "libc"))
        result = sendmsg(fd, message, MSG_NOSIGNAL);
    else
        return 5;
    saved_errno = errno;
    printf("{\"result\":%zd,\"errno\":%d}\n", result, saved_errno);
    if (munmap(mapping, (size_t)page_size))
        return 6;
    return 0;
}
"""


class SendmsgMetadataEFAULT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frontend = OUT / "libio_uring_unified.so"
        cls.model = OUT / "libxdev_ext_preload_kernel_model.so"
        for library in (cls.frontend, cls.model):
            if not library.is_file():
                raise RuntimeError(f"missing build artifact: {library}; build the selftests first")
        cls.work = tempfile.TemporaryDirectory(prefix="xdev-efault-", dir=OUT)
        cls.addClassCleanup(cls.work.cleanup)
        directory = Path(cls.work.name)
        source = directory / "fixture.c"
        source.write_text(FIXTURE)
        cls.binary = directory / "fixture"
        cls.clean_env = {key: value for key, value in os.environ.items()
                         if not key.startswith("XDEV") and key != "LD_PRELOAD"}
        subprocess.run(shlex.split(os.environ.get("CC", "cc")) + [
            "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
            str(source), "-o", str(cls.binary)], env=cls.clean_env,
            check=True, capture_output=True, text=True, timeout=30)

    def check_case(self, case, mode, api):
        env = dict(self.clean_env)
        if mode == "inert":
            env["LD_PRELOAD"] = str(self.frontend)
        elif mode == "armed-model":
            env.update(LD_PRELOAD=f"{self.frontend}:{self.model}",
                       XDEV_EXT_PRELOAD_SOCKET_ENABLED="1",
                       XDEV_EXT_MODEL_UMEM="1", XDEV_EXT_MODEL_SUMMARY="1")
        tx, rx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with tx, rx:
            completed = subprocess.run([
                str(self.binary), str(tx.fileno()), case, api], env=env,
                pass_fds=(tx.fileno(),), capture_output=True, text=True, timeout=10)
            rx.setblocking(False)
            datagrams = []
            while True:
                try:
                    datagrams.append(rx.recv(65536))
                except BlockingIOError:
                    break
        observed = dict(case=case, mode=mode, api=api,
                        returncode=completed.returncode,
                        datagrams=[value.hex() for value in datagrams],
                        stdout=completed.stdout.strip(), stderr=completed.stderr.strip())
        print("XDEV_EXT_SENDMSG_EFAULT " + json.dumps(observed, sort_keys=True), flush=True)
        # Check socket effects even when a child died by signal. A signal is
        # never translated into an EFAULT success by the runner or fixture.
        self.assertEqual(datagrams, [CONTROL] if case == "control" else [], observed)
        self.assertEqual(completed.returncode, 0, observed)
        expected = {"result": len(CONTROL), "errno": 0} if case == "control" else {
            "result": -1, "errno": errno.EFAULT}
        self.assertEqual(json.loads(completed.stdout), expected, observed)
        if mode == "armed-model":
            summaries = [line for line in completed.stderr.splitlines()
                         if line.startswith("XDEV_EXT_MODEL_SUMMARY ")]
            self.assertEqual(len(summaries), 1, observed)
            fields = dict(field.split("=", 1) for field in summaries[0].split()[1:])
            if case != "control":
                for key in ("read_sqes", "write_sqes", "other_sqes", "send_sqes"):
                    self.assertEqual(int(fields[key]), 0, observed)
        else:
            self.assertEqual(completed.stderr, "", observed)

    def matrix(self, case):
        for mode in ("libc", "inert", "armed-model"):
            for api in ("syscall", "libc"):
                with self.subTest(case=case, mode=mode, api=api):
                    self.check_case(case, mode, api)

    def test_0_valid_metadata_sends_exactly_one_datagram(self):
        self.matrix("control")

    def test_1_unreadable_msghdr_returns_efault_without_datagram(self):
        self.matrix("msghdr")

    def test_2_unreadable_iov_returns_efault_without_datagram(self):
        self.matrix("iov")


if __name__ == "__main__":
    unittest.main(verbosity=2)
