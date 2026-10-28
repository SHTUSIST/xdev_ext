#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Syscalls the preload front end itself makes per taken-over call.

Each fixture runs under strace -f -k.  getppid(2), which neither the front
end nor a model calls, marks the boundaries of a window of N identical calls;
the syscalls inside a window are attributed through their stack to the front
end, a model or the application, counted by name and divided by N.  Every call
is followed, outside the windows, by a full byte comparison with independently
generated expected bytes.

File windows (pread, preadv and pwritev over four iovecs) run with the
existing kernel model, which completes each READ_COMPAT/WRITE_COMPAT request
with one pread64/pwrite64 in place of the io_uring_enter of a matching kernel;
that substitute counts once and the model's other syscalls are left out.  The
socket window alternates send(2) between two connected UDP sockets with
XDEV_EXT_PRELOAD_SOCKET_MECH=1 and the XDEV_EXT_MECH control model; the model's
own syscalls are left out and the io_uring_register control calls it answered
are added back, so each number is what the front end issues against a
matching kernel.

These are syscall counts on a stock host, not latency or throughput, and not
evidence of the kernel mechanism, a device or DMA.  Exit status 4 (kselftest
skip) without strace or an O_DIRECT-capable directory.
"""
from collections import Counter
from pathlib import Path
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get("XDEV_EXT_PRELOAD_TEST_DIR", str(HERE))).resolve()
CALLS = 32
KSFT_SKIP = 4
FIXTURE = r"""
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#define CALLS @CALLS@
#define BLOCK 4096

struct model_counts {
    uint64_t creates, starts, stops, stop_failures, modelled_ops, own_syscalls;
};

static void pattern(unsigned char *out, size_t len, unsigned int seed)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (unsigned char)(seed * 131u + i * 7u + 1u);
}

static int fail(const char *what)
{
    printf("XDEV_EXT_COST_FIXTURE=FAIL %s errno=%d\n", what, errno);
    return 1;
}

static int file_mode(const char *path)
{
    unsigned char *buffer, *expected;
    struct iovec iov[4];
    int fd, i, k;

    if (posix_memalign((void **)&buffer, BLOCK, 4 * BLOCK) ||
        !(expected = malloc(4 * BLOCK)))
        return fail("allocation");
    fd = open(path, O_RDWR | O_DIRECT);
    if (fd < 0)
        return fail("open");
    for (k = 0; k < 4; k++)
        iov[k] = (struct iovec){ buffer + k * BLOCK, BLOCK };
    pattern(buffer, 4 * BLOCK, 7);
    pattern(expected, 4 * BLOCK, 7);
    if (pwrite(fd, buffer, 4 * BLOCK, 0) != 4 * BLOCK)
        return fail("seed pwrite");
    /* Warm calls: lazy per-thread setup is not part of a window. */
    memset(buffer, 0, 4 * BLOCK);
    if (pread(fd, buffer, BLOCK, 0) != BLOCK || memcmp(buffer, expected, BLOCK) ||
        preadv(fd, iov, 4, 0) != 4 * BLOCK ||
        memcmp(buffer, expected, 4 * BLOCK) ||
        pwritev(fd, iov, 4, 0) != 4 * BLOCK)
        return fail("warm calls");
    /* A write changes the file's ctime: the next call reads its path once. */
    if (pread(fd, buffer, BLOCK, 0) != BLOCK)
        return fail("revalidating pread");
    getppid();
    for (i = 0; i < CALLS; i++)
        if (pread(fd, buffer, BLOCK, 0) != BLOCK)
            return fail("pread");
    getppid();
    if (memcmp(buffer, expected, BLOCK))
        return fail("pread bytes");
    memset(buffer, 0, 4 * BLOCK);
    getppid();
    for (i = 0; i < CALLS; i++)
        if (preadv(fd, iov, 4, 0) != 4 * BLOCK)
            return fail("preadv");
    getppid();
    if (memcmp(buffer, expected, 4 * BLOCK))
        return fail("preadv bytes");
    pattern(buffer, 4 * BLOCK, 11);
    pattern(expected, 4 * BLOCK, 11);
    getppid();
    for (i = 0; i < CALLS; i++)
        if (pwritev(fd, iov, 4, 0) != 4 * BLOCK)
            return fail("pwritev");
    getppid();
    memset(buffer, 0, 4 * BLOCK);
    if (pread(fd, buffer, 4 * BLOCK, 0) != 4 * BLOCK ||
        memcmp(buffer, expected, 4 * BLOCK))
        return fail("pwritev bytes");
    close(fd);
    puts("XDEV_EXT_COST_FIXTURE=PASS mode=file");
    return 0;
}

static int socket_mode(void)
{
    void (*counts)(struct model_counts *) =
        (void (*)(struct model_counts *))dlsym(RTLD_DEFAULT, "xdev_ext_mech_model_counts");
    struct sockaddr_in addr = {.sin_family = AF_INET,
                               .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct timeval timeout = {.tv_sec = 3};
    unsigned char payload[512], expected[512], received[1024];
    struct model_counts before, after;
    int rx[2], tx[2], i;

    if (!counts)
        return fail("mechanism model not loaded");
    for (i = 0; i < 2; i++) {
        socklen_t len = sizeof(addr);

        addr.sin_port = 0;
        rx[i] = socket(AF_INET, SOCK_DGRAM, 0);
        tx[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (rx[i] < 0 || tx[i] < 0 ||
            setsockopt(rx[i], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
            bind(rx[i], (void *)&addr, sizeof(addr)) ||
            getsockname(rx[i], (void *)&addr, &len) ||
            connect(tx[i], (void *)&addr, len))
            return fail("socket setup");
        pattern(payload, sizeof(payload), 99);
        if (send(tx[i], payload, sizeof(payload), MSG_NOSIGNAL) != sizeof(payload) ||
            recv(rx[i], received, sizeof(received), 0) != sizeof(payload) ||
            memcmp(received, payload, sizeof(payload)))
            return fail("warm send");
    }
    counts(&before);
    getppid();
    for (i = 0; i < CALLS; i++) {
        pattern(payload, sizeof(payload), (unsigned int)i);
        if (send(tx[i % 2], payload, sizeof(payload), MSG_NOSIGNAL) != sizeof(payload))
            return fail("send");
    }
    getppid();
    counts(&after);
    for (i = 0; i < CALLS; i++) {
        pattern(expected, sizeof(expected), (unsigned int)i);
        if (recv(rx[i % 2], received, sizeof(received), 0) != sizeof(expected) ||
            memcmp(received, expected, sizeof(expected)))
            return fail("received bytes");
    }
    printf("XDEV_EXT_COST_FIXTURE=PASS mode=socket creates=%llu modelled_ops=%llu "
           "own_syscalls=%llu\n",
           (unsigned long long)(after.creates - before.creates),
           (unsigned long long)(after.modelled_ops - before.modelled_ops),
           (unsigned long long)(after.own_syscalls - before.own_syscalls));
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "file"))
        return file_mode(argv[2]);
    if (argc == 2 && !strcmp(argv[1], "socket"))
        return socket_mode();
    return 2;
}
"""
LINE = re.compile(r"^(\d+)\s+(\w+)\((.*)$")
FRAME = re.compile(r"^ > (\S+?)\(([^+)]*)")
SYSTEM = ("/libc.so", "/ld-linux", "/libpthread.so", "/libdl.so")
# What a model issues in place of the one io_uring_enter of a matching kernel.
SUBSTITUTES = ("pread64", "pwrite64")


def owner_of(path):
    name = Path(path).name
    if any(system in path for system in SYSTEM):
        return "system"
    if "model" in name:
        return "model"
    if "libio_uring_unified" in name:
        return "frontend"
    return "application"


def attribute(frames):
    """Who issued a syscall: the first object outside the C library.

    A model frame with the same name as the C library function beneath it
    (syscall, fcntl, close, ...) is a pass-through interposer, so the call
    belongs to the next object up the stack.  The second value says whether
    the call passed through a model's syscall(3): the front end never asks
    syscall(3) for pread64/pwrite64, so those are the model's substitutes for
    io_uring_enter.
    """
    below, via_syscall = None, False
    for path, symbol in frames:
        owner = owner_of(path)
        if owner == "system":
            below = symbol
            continue
        if owner == "model" and symbol and symbol == below:
            via_syscall |= symbol == "syscall"
            below = None
            continue
        return owner, via_syscall
    return "application", via_syscall


def events(trace):
    """(name, rest, owner, via_syscall) for every traced syscall, from strace -f -k output."""
    result, pending = [], None
    for line in trace.splitlines():
        frame = FRAME.match(line)
        if frame and pending is not None:
            pending[2].append((frame.group(1), frame.group(2)))
            continue
        match = LINE.match(line)
        if not match:
            continue
        if pending is not None:
            result.append((pending[0], pending[1]) + attribute(pending[2]))
        pending = (match.group(2), match.group(3), [])
    if pending is not None:
        result.append((pending[0], pending[1]) + attribute(pending[2]))
    return result


def windows(trace):
    """Per-window Counters of front-end syscalls, between getppid markers.

    A syscall issued by a model is left out; a model's pread64/pwrite64 in
    place of io_uring_enter counts once as "io_uring_enter (modelled)".
    """
    maps_fds, result, current = set(), [], None
    for name, rest, owner, via_syscall in events(trace):
        if name in ("openat", "open") and '"/proc/self/maps"' in rest:
            ret = rest.rsplit("=", 1)[-1].split()[0]
            if ret.lstrip("-").isdigit() and int(ret) >= 0:
                maps_fds.add(int(ret))
        # A closed number may next name another file.
        closed = re.match(r"(\d+)\)", rest) if name == "close" else None
        if closed and int(closed[1]) in maps_fds:
            maps_fds.discard(int(closed[1]))
            if current is not None and owner != "model":
                current["maps_close"] += 1
        if name == "getppid" and owner == "application":
            if current is None:
                current = Counter()
            else:
                result.append(current)
                current = None
            continue
        if current is None:
            continue
        if owner == "model":
            current["model_issued"] += 1
            continue
        if owner == "application":
            current["application"] += 1
            continue
        fd = rest.split(",", 1)[0]
        if name in ("read", "pread64") and fd.isdigit() and int(fd) in maps_fds:
            current[name] += 1
            current["maps_read"] += 1
            continue
        if via_syscall and name in SUBSTITUTES:
            current["io_uring_enter (modelled)"] += 1
            continue
        current[name] += 1
        if name in ("openat", "open") and '"/proc/self/maps"' in rest:
            current["maps_open"] += 1
    return result


NOT_SYSCALLS = ("maps_read", "maps_open", "maps_close", "model_issued", "application")


def per_call(counter, names):
    return sum(counter[name] for name in names) / CALLS


def summary(label, counter, extra=0):
    real = sum(value for key, value in counter.items() if key not in NOT_SYSCALLS)
    data = dict(window=label, calls=CALLS,
                syscalls_per_call=(real + extra) / CALLS,
                maps_reads_per_call=per_call(counter, ["maps_read"]),
                maps_opens_per_call=per_call(counter, ["maps_open"]),
                maps_closes_per_call=per_call(counter, ["maps_close"]),
                readlink_per_call=per_call(counter, ["readlink", "readlinkat"]),
                getpid_per_call=per_call(counter, ["getpid"]),
                gettid_per_call=per_call(counter, ["gettid"]),
                process_vm_readv_per_call=per_call(counter, ["process_vm_readv"]),
                process_vm_writev_per_call=per_call(counter, ["process_vm_writev"]),
                application_syscalls=counter["application"],
                names={key: value for key, value in sorted(counter.items())})
    print("XDEV_EXT_PRELOAD_SYSCALL_COST " + json.dumps(data, sort_keys=True), flush=True)
    return data


def run(command, env, trace):
    completed = subprocess.run(["strace", "-f", "-qq", "-k", "-o", str(trace)] + command,
                               env=env, capture_output=True, text=True, timeout=120)
    if completed.returncode:
        print(completed.stdout + completed.stderr, end="")
        raise SystemExit(f"FAIL: fixture exited {completed.returncode}")
    return completed.stdout, trace.read_text()


def main():
    if not shutil.which("strace"):
        print("SKIP: strace is not installed")
        return KSFT_SKIP
    frontend = OUT / "libio_uring_unified.so"
    kernel_model = OUT / "libxdev_ext_preload_kernel_model.so"
    for artifact in (frontend, kernel_model):
        if not artifact.is_file():
            raise SystemExit(f"FAIL: missing build artifact: {artifact}; build the selftests first")
    clean = {key: value for key, value in os.environ.items()
             if not key.startswith("XDEV") and key != "LD_PRELOAD"}
    cc = shlex.split(os.environ.get("CC", "cc"))
    flags = ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"]
    failures = []
    with tempfile.TemporaryDirectory(prefix="xdev-syscall-cost-", dir=OUT) as tmp:
        work = Path(tmp)
        (work / "fixture.c").write_text(FIXTURE.replace("@CALLS@", str(CALLS)))
        fixture = work / "fixture"
        mech_model = work / "libxdev_ext_preload_mech_model.so"
        for command in (cc + flags + [str(work / "fixture.c"), "-o", str(fixture), "-ldl"],
                        cc + flags + ["-shared", "-fPIC", "-pthread",
                                      str(HERE / "xdev_ext_preload_mech_model.c"),
                                      "-o", str(mech_model), "-ldl"]):
            subprocess.run(command, env=clean, check=True, capture_output=True,
                           text=True, timeout=60)
        data = work / "data"
        data.write_bytes(b"\0" * 4 * 4096)
        try:
            os.close(os.open(data, os.O_RDWR | os.O_DIRECT))
        except OSError:
            print(f"SKIP: {work} does not accept O_DIRECT")
            return KSFT_SKIP

        env = dict(clean, LD_PRELOAD=f"{frontend}:{kernel_model}",
                   XDEV_EXT_MODEL_UMEM="1", XDEV_EXT_MODEL_DIOALIGN="4096:4096",
                   XDEV_EXT_PRELOAD_ENABLED="1", XDEV_EXT_PRELOAD_PATHS=str(data),
                   XDEV_EXT_PRELOAD_FRAME_SIZE="16384")
        stdout, trace = run([str(fixture), "file", str(data)], env, work / "file.trace")
        if "XDEV_EXT_COST_FIXTURE=PASS mode=file" not in stdout:
            raise SystemExit("FAIL: file fixture did not pass: " + stdout)
        found = windows(trace)
        if len(found) != 3:
            raise SystemExit(f"FAIL: expected 3 file windows, found {len(found)}")
        pread, preadv, pwritev = (summary(label, counter) for label, counter in
                                  zip(("pread", "preadv4", "pwritev4"), found))

        env = dict(clean, LD_PRELOAD=f"{frontend}:{mech_model}",
                   XDEV_EXT_PRELOAD_SOCKET_ENABLED="1", XDEV_EXT_PRELOAD_SOCKET_MECH="1")
        stdout, trace = run([str(fixture), "socket"], env, work / "socket.trace")
        result = re.search(r"XDEV_EXT_COST_FIXTURE=PASS mode=socket creates=(\d+) "
                           r"modelled_ops=(\d+) own_syscalls=(\d+)", stdout)
        if not result:
            raise SystemExit("FAIL: socket fixture did not pass: " + stdout)
        creates, modelled, own = (int(value) for value in result.groups())
        found = windows(trace)
        if len(found) != 1:
            raise SystemExit(f"FAIL: expected 1 socket window, found {len(found)}")
        send = summary("send-mech-alternating", found[0], modelled)
        send["creates_in_window"] = creates
        print("XDEV_EXT_PRELOAD_SYSCALL_COST " + json.dumps(
            dict(window="send-mech-alternating-sessions", creates_in_window=creates,
                 modelled_control_ops=modelled, model_own_syscalls=own)), flush=True)

    def check(condition, message):
        print(("ok - " if condition else "not ok - ") + message, flush=True)
        if not condition:
            failures.append(message)

    # The mapping list is opened and closed inside each read: a descriptor
    # kept open would add to the set the ordinary-fork guest oracle allows.
    check(pread["maps_opens_per_call"] == 1 and pread["maps_closes_per_call"] == 1,
          "pread opens and closes /proc/self/maps once per call")
    check(pread["readlink_per_call"] == 0, "pread of an unchanged file does not readlink its path")
    check(pread["getpid_per_call"] <= 1, "pread makes at most one getpid")
    check(pread["gettid_per_call"] == 0, "pread makes no gettid")
    check(pread["process_vm_writev_per_call"] == 1, "pread copies out once")
    check(pread["syscalls_per_call"] - pread["maps_reads_per_call"] <= 10,
          "pread makes at most 10 syscalls besides reading the mapping list")
    check(preadv["process_vm_writev_per_call"] == 1, "preadv(4) scatters with one copy")
    check(preadv["process_vm_readv_per_call"] == 1, "preadv(4) snapshots its iovec once")
    check(preadv["maps_opens_per_call"] == 1 and preadv["maps_closes_per_call"] == 1,
          "preadv opens and closes /proc/self/maps once per call")
    check(preadv["getpid_per_call"] <= 1, "preadv makes at most one getpid")
    # Each write may change the file's ctime, after which the next call reads
    # the path again; how often depends on the timestamp granularity.
    check(pwritev["readlink_per_call"] <= 1, "pwritev reads its path at most once per call")
    check(pwritev["process_vm_readv_per_call"] == 2,
          "pwritev(4) snapshots its iovec and gathers with one copy each")
    check(pwritev["getpid_per_call"] <= 1, "pwritev makes at most one getpid")
    check(creates == 0, "alternating two sockets creates no session inside the window")
    check(send["getpid_per_call"] <= 1, "socket send makes at most one getpid")
    check(send["syscalls_per_call"] <= 13, "socket mechanism send makes at most 13 syscalls")
    if failures:
        print(f"not ok - {len(failures)} syscall-cost checks failed")
        return 1
    print("ok - preload syscall cost bounds hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
