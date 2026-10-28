#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Public positional wrappers versus same-host libc and Linux syscalls.

Build the public frontend and existing kernel model first; point
XDEV_EXT_PRELOAD_TEST_DIR at their directory. Every tested call has its own
bounded child. Shared file-backed payload pages let the parent inspect all
bytes even if a buggy wrapper dies. The model is host API evidence only.
No device/provider is added and no throughput or latency is measured.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import os
import shlex
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
APIS = ("pread", "pread64", "pwrite", "pwrite64", "preadv", "preadv64",
        "pwritev", "pwritev64", "preadv2", "preadv64v2", "pwritev2", "pwritev64v2")
FIXTURE = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static unsigned char *payload;
static size_t page;
static int (*wait_blocked)(void), (*release_request)(void);
static const char *fault;
static int protect_payload(void)
{
    unsigned char *where = payload + page;
    int prot = PROT_NONE;
    if (strstr(fault, "readonly")) prot = PROT_READ;
    if (strstr(fault, "cross")) where += page;
    return mprotect(where, page, prot);
}
static void *late_fault(void *unused)
{
    (void)unused;
    if (wait_blocked() || protect_payload() || release_request()) _exit(22);
    return NULL;
}
static uint64_t counter(const char *name)
{
    uint64_t (*fn)(void) = dlsym(RTLD_DEFAULT, name);
    return fn ? fn() : 0;
}
int main(int argc, char **argv)
{
    struct rlimit no_core = {0, 0};
    struct iovec local[2], *iov = local;
    const char *api, *backend;
    unsigned char *metadata;
    int fd, pfd, n = 2, flags = 0, vector, write_op, saved;
    size_t count;
    ssize_t result;
    void *symbol;
    pthread_t thread;
    int late;
    if (argc != 7 || setrlimit(RLIMIT_CORE, &no_core)) return 2;
    api = argv[1]; fault = argv[2]; backend = argv[3];
    page = (size_t)sysconf(_SC_PAGESIZE); count = 2 * page;
    vector = strchr(api, 'v') != NULL;
    write_op = !strncmp(api, "pwrite", 6);
    late = !strncmp(fault, "late-", 5);
    pfd = open(argv[5], O_RDWR);
    if (pfd < 0) return 3;
    payload = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE, MAP_SHARED, pfd, 0);
    metadata = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (payload == MAP_FAILED || metadata == MAP_FAILED) return 4;
    fd = open(argv[4], O_RDWR | (strcmp(argv[6], "buffered") ? O_DIRECT : 0));
    if (fd < 0) { fprintf(stderr, "O_DIRECT open failed errno=%d\n", errno); return 5; }
    local[0] = (struct iovec){payload + page, page};
    local[1] = (struct iovec){payload + 2 * page, page};
    if (strstr(fault, "one")) { local[0].iov_len = count; n = 1; }
    if (!strcmp(fault, "metadata-none")) {
        iov = (struct iovec *)(metadata + page);
    } else if (!strcmp(fault, "metadata-partial")) {
        iov = (struct iovec *)(metadata + page - sizeof(struct iovec) - sizeof(void *));
        memcpy(iov, local, sizeof(local));
    } else if (!strcmp(fault, "metadata-partial-one")) {
        iov = (struct iovec *)(metadata + page - sizeof(void *));
        memcpy(iov, local, sizeof(struct iovec)); n = 1;
    }
    if (mprotect(metadata + page, page, PROT_NONE)) return 6;
    if (strcmp(fault, "valid") && strncmp(fault, "metadata-", 9) && !late &&
        protect_payload()) return 7;
    if (!strcmp(argv[6], "badfd")) { close(fd); fd = -1; }
    if (!strcmp(argv[6], "unsupported")) flags = 0x40000000;
    symbol = dlsym(RTLD_DEFAULT, api);
    if (!symbol) return 8;
    if (late) {
        int (*arm)(void) = dlsym(RTLD_DEFAULT, "xdev_ext_model_block_next_request");
        wait_blocked = dlsym(RTLD_DEFAULT, "xdev_ext_model_wait_until_blocked");
        release_request = dlsym(RTLD_DEFAULT, "xdev_ext_model_release_request");
        if (!arm || !wait_blocked || !release_request || arm() ||
            pthread_create(&thread, NULL, late_fault, NULL)) return 9;
    }
    errno = 117; /* Successful calls must preserve the caller's errno. */
    if (!strcmp(backend, "syscall")) {
        if (!vector)
            result = syscall(write_op ? SYS_pwrite64 : SYS_pread64,
                             fd, payload + page, count, page);
        else if (strstr(api, "v2"))
            result = syscall(write_op ? SYS_pwritev2 : SYS_preadv2,
                             fd, iov, n, page, 0, flags);
        else
            result = syscall(write_op ? SYS_pwritev : SYS_preadv,
                             fd, iov, n, page, 0);
    } else if (!vector) {
        ssize_t (*fn)(int, void *, size_t, off64_t) = symbol;
        result = fn(fd, payload + page, count, (off64_t)page);
    } else if (strstr(api, "v2")) {
        ssize_t (*fn)(int, const struct iovec *, int, off64_t, int) = symbol;
        result = fn(fd, iov, n, (off64_t)page, flags);
    } else {
        ssize_t (*fn)(int, const struct iovec *, int, off64_t) = symbol;
        result = fn(fd, iov, n, (off64_t)page);
    }
    saved = errno;
    if (late && pthread_join(thread, NULL)) return 10;
    printf("{\"result\":%zd,\"errno\":%d,\"read_sqes\":%" PRIu64
           ",\"write_sqes\":%" PRIu64 ",\"fallbacks\":%" PRIu64 "}\n",
           result, saved, counter("xdev_ext_model_read_requests"),
           counter("xdev_ext_model_write_requests"), counter("fault_observer_calls"));
    return 0;
}
'''

# This observer sits after the actual frontend. It counts libc delegation,
# including a forbidden replay after acceptance; it does not change results.
OBSERVER = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>
static uint64_t calls;
uint64_t fault_observer_calls(void) { return calls; }
#define SCALAR(name, offset_type) \
ssize_t name(int fd, void *buffer, size_t length, offset_type offset) { \
    ssize_t (*fn)(int, void *, size_t, offset_type) = dlsym(RTLD_NEXT, #name); \
    int saved = errno; calls++; errno = saved; return fn(fd, buffer, length, offset); }
#define WRITE(name, offset_type) \
ssize_t name(int fd, const void *buffer, size_t length, offset_type offset) { \
    ssize_t (*fn)(int, const void *, size_t, offset_type) = dlsym(RTLD_NEXT, #name); \
    int saved = errno; calls++; errno = saved; return fn(fd, buffer, length, offset); }
#define VECTOR(name, offset_type) \
ssize_t name(int fd, const struct iovec *iov, int n, offset_type offset) { \
    ssize_t (*fn)(int, const struct iovec *, int, offset_type) = dlsym(RTLD_NEXT, #name); \
    int saved = errno; calls++; errno = saved; return fn(fd, iov, n, offset); }
#define VECTOR2(name, offset_type) \
ssize_t name(int fd, const struct iovec *iov, int n, offset_type offset, int flags) { \
    ssize_t (*fn)(int, const struct iovec *, int, offset_type, int) = dlsym(RTLD_NEXT, #name); \
    int saved = errno; calls++; errno = saved; return fn(fd, iov, n, offset, flags); }
SCALAR(pread, off_t) SCALAR(pread64, off64_t)
WRITE(pwrite, off_t) WRITE(pwrite64, off64_t)
VECTOR(preadv, off_t) VECTOR(preadv64, off64_t)
VECTOR(pwritev, off_t) VECTOR(pwritev64, off64_t)
VECTOR2(preadv2, off_t) VECTOR2(preadv64v2, off64_t)
VECTOR2(pwritev2, off_t) VECTOR2(pwritev64v2, off64_t)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path(os.environ.get(
        "XDEV_EXT_PRELOAD_TEST_DIR", str(HERE))))
    parser.add_argument("--results", type=Path)
    parser.add_argument("--timeout", type=float, default=12)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    frontend = build / "libio_uring_unified.so"
    model = build / "libxdev_ext_preload_kernel_model.so"
    for library in (frontend, model):
        if not library.is_file():
            parser.error(f"missing {library}; build the public frontend and existing model first")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    env = {k: v for k, v in os.environ.items() if not k.startswith("XDEV") and k != "LD_PRELOAD"}
    page = os.sysconf("SC_PAGE_SIZE")
    if page != 4096:
        parser.error("fixture requires this contract's 4096-byte Linux page host")
    records, failures = [], []
    with tempfile.TemporaryDirectory(prefix="positional-fault-", dir=build) as work:
        work = Path(work)
        cc = shlex.split(os.environ.get("CC", "cc"))
        for name, source, extra in (("fixture", FIXTURE, []),
                                    ("observer.so", OBSERVER, ["-shared", "-fPIC"])):
            src = work / (name + ".c")
            src.write_text(source)
            subprocess.run(cc + ["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"] +
                           extra + [str(src), "-o", str(work / name), "-ldl", "-pthread"],
                           env=env, check=True, capture_output=True, text=True, timeout=30)
        fixture, observer = work / "fixture", work / "observer.so"
        target, payload, untracked = work / "selected", work / "payload", work / "other"
        target_bytes = bytes((i * 29 + i // page * 7) % 251 for i in range(4 * page))
        payload_bytes = bytes((i * 17 + i // page * 13 + 71) % 253 for i in range(4 * page))

        def run(api, fault, mode, backend="libc", control="direct"):
            target.write_bytes(target_bytes)
            payload.write_bytes(payload_bytes)
            untracked.write_bytes(target_bytes)
            child_env = dict(env)
            if mode != "plain":
                child_env["LD_PRELOAD"] = f"{frontend}:{observer}:{model}"
                child_env.update(XDEV_EXT_MODEL_UMEM="1", XDEV_EXT_MODEL_SUMMARY="1",
                                 XDEV_EXT_MODEL_DIOALIGN="4096:4096")
                if mode != "inert":
                    child_env.update(XDEV_EXT_PRELOAD_ENABLED="0" if mode == "disabled" else "1",
                                     XDEV_EXT_PRELOAD_PATHS=str(untracked if mode == "untracked" else target),
                                     XDEV_EXT_PRELOAD_FRAME_SIZE="16384")
                if mode == "armed-eintr":
                    child_env["XDEV_EXT_MODEL_EINTR"] = "1"
            command = [str(fixture), api, fault, backend, str(target), str(payload), control]
            record = dict(api=api, fault=fault, mode=mode, backend=backend, control=control)
            try:
                proc = subprocess.run(command, env=child_env, capture_output=True,
                                      text=True, timeout=args.timeout)
                record.update(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
                if proc.returncode == 0:
                    record["value"] = json.loads(proc.stdout)
            except subprocess.TimeoutExpired as exc:
                record.update(timeout=True, stdout=str(exc.stdout), stderr=str(exc.stderr))
            # Save all bytes in the result JSON, including guards and effects
            # after signals; comparison is exact, not merely hash equality.
            record["file_hex"] = target.read_bytes().hex()
            record["payload_hex"] = payload.read_bytes().hex()
            records.append(record)
            return record

        def compare(reference, observed, expected_publication=None):
            label = "/".join(str(observed[x]) for x in ("api", "fault", "mode", "control"))
            problems = []
            if observed.get("returncode") != 0 or "value" not in observed:
                problems.append(f"child return={observed.get('returncode')} timeout={observed.get('timeout', False)}")
            else:
                for key in ("result", "errno"):
                    if observed["value"][key] != reference["value"][key]:
                        problems.append(f"{key} {observed['value'][key]} != {reference['value'][key]}")
                value = observed["value"]
                submitted = value["read_sqes"] + value["write_sqes"]
                fallbacks = value["fallbacks"]
                if observed["mode"] != "plain":
                    if submitted > 1 or fallbacks > 1 or submitted + fallbacks != 1:
                        problems.append(f"publication/fallback={submitted}/{fallbacks}; must total exactly one")
                    if expected_publication is not None and submitted != expected_publication:
                        problems.append(f"published={submitted}, expected={expected_publication}")
            for key in ("file_hex", "payload_hex"):
                if observed[key] != reference[key]:
                    a, b = bytes.fromhex(observed[key]), bytes.fromhex(reference[key])
                    differences = [i for i, pair in enumerate(zip(a, b)) if pair[0] != pair[1]]
                    problems.append(f"{key} differs at {len(differences)} bytes; first={differences[:8]}")
            observed["problems"] = problems
            print(("not ok" if problems else "ok") + f" - {label}" +
                  (" : " + "; ".join(problems) if problems else ""), flush=True)
            if problems:
                failures.append(dict(label=label, problems=problems))

        # Prove DIO and actual armed takeover before running faults. Missing
        # capability is an explicit failure, never an all-skip successful run.
        reference = run("pread", "valid", "plain")
        if reference.get("returncode") != 0 or reference.get("value", {}).get("result") != 2 * page:
            failures.append(dict(label="required-host-O_DIRECT", observed=reference))
        else:
            compare(reference, run("pread", "valid", "armed"), 1)
        if not failures:
            for api in APIS:
                vector = "v" in api
                faults = ["valid", "none", "readonly", "cross-none", "cross-readonly"]
                if vector:
                    faults += ["cross-one-none", "cross-one-readonly", "metadata-none",
                               "metadata-partial", "metadata-partial-one"]
                for fault in faults:
                    reference = run(api, fault, "plain")
                    direct = run(api, fault, "plain", "syscall")
                    if reference.get("returncode") != 0 or "value" not in reference:
                        failures.append(dict(label=f"libc-oracle/{api}/{fault}", observed=reference))
                        continue
                    compare(reference, direct)
                    for mode in ("inert", "disabled", "untracked", "armed", "armed-eintr"):
                        expected = 0 if mode in ("inert", "disabled", "untracked") or fault.startswith("metadata-") else None
                        if mode.startswith("armed") and fault == "valid":
                            expected = 1
                        compare(reference, run(api, fault, mode), expected)
                for control in ("badfd", "buffered") + (("unsupported",) if "v2" in api else ()):
                    for fault in (("metadata-none", "none") if vector else ("none",)):
                        reference = run(api, fault, "plain", control=control)
                        if reference.get("returncode") != 0 or "value" not in reference:
                            failures.append(dict(label=f"control-oracle/{api}/{fault}/{control}", observed=reference))
                            continue
                        compare(reference, run(api, fault, "plain", "syscall", control))
                        compare(reference, run(api, fault, "armed", control=control), 0)
                # Change protection after the existing model has consumed the
                # accepted SQE. Static-fault libc is the no-copy EFAULT oracle.
                # This deliberately defeats pre-admission page probing.
                if api.startswith("pread"):
                    for fault in ("none", "readonly"):
                        reference = run(api, fault, "plain")
                        for mode in ("armed", "armed-eintr"):
                            compare(reference, run(api, "late-" + fault, mode), 1)
        report = dict(schema=1, evidence="host public LD_PRELOAD API with existing test-only model; not kernel/GPU/performance",
                      libraries={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (frontend, model)},
                      records=records, failures=failures,
                      counts=dict(children=len(records), failed_comparisons=len(failures)))
        if args.results:
            args.results.resolve().write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report["counts"], sort_keys=True), flush=True)
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
