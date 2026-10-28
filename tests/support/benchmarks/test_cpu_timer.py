#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent scalar journal contracts. No device, SDK or payload operations.

A missing header is SETUP-blocked, not behavioral RED. Arm runner tests also
import RunnerContract from this file; it has no test methods of its own.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
CPU_ENV_PREFIX = "XDEV_EXT_EVAL_CPU_"
DRY_RUN_GUARD = r"""
import runpy, sys, threading
from pathlib import Path
entry, *arguments = sys.argv[1:]
def forbidden_thread(*args, **kwargs):
    raise RuntimeError("dry-run started a thread")
threading.Thread.start = forbidden_thread
def audit(event, arguments):
    if event in ("subprocess.Popen", "os.posix_spawn", "os.fork", "socket.connect", "socket.bind", "fcntl.ioctl"):
        raise RuntimeError("dry-run attempted external execution/device/network: " + event)
    if event == "open" and isinstance(arguments[0], str) and arguments[0].startswith("/dev/"):
        raise RuntimeError("dry-run opened a device: " + arguments[0])
sys.addaudithook(audit)
sys.path.insert(0, str(Path(entry).parent))
sys.argv = [entry, *arguments]
runpy.run_path(entry, run_name="__main__")
"""


# These wrappers catch operations made by the real header, not a fake journal.
# The inaccessible page is never passed to the API: timer rows contain scalars.
FIXTURE = r'''
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "native_process.h"
#include "cpu_timer.h"
static int guarded, violations;
#ifdef __cplusplus
extern "C" {
#endif
void *__real_malloc(size_t n);
void *__real_calloc(size_t n, size_t s);
void *__real_realloc(void *p, size_t n);
void __real_free(void *p);
ssize_t __real_read(int fd, void *p, size_t n);
ssize_t __real_write(int fd, const void *p, size_t n);
int __real_clock_gettime(clockid_t id, struct timespec *p);
int __real_open(const char *p, int f, ...);
FILE *__real_fopen(const char *p, const char *m);
int __real_fflush(FILE *f);
int __real_fsync(int fd);
void *__wrap_malloc(size_t n) { if (guarded) violations++; return __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t s) { if (guarded) violations++; return __real_calloc(n,s); }
void *__wrap_realloc(void *p, size_t n) { if (guarded) violations++; return __real_realloc(p,n); }
void __wrap_free(void *p) { if (guarded) violations++; __real_free(p); }
ssize_t __wrap_read(int fd, void *p, size_t n) { if (guarded) violations++; return __real_read(fd,p,n); }
ssize_t __wrap_write(int fd, const void *p, size_t n) { if (guarded) violations++; return __real_write(fd,p,n); }
int __wrap_clock_gettime(clockid_t id, struct timespec *p) { if (guarded) violations++; return __real_clock_gettime(id,p); }
int __wrap_open(const char *p, int f, ...) {
    mode_t mode = 0;
    if (f & O_CREAT) { va_list ap; va_start(ap,f); mode=(mode_t)va_arg(ap,int); va_end(ap); }
    if (guarded) violations++;
    return (f & O_CREAT) ? __real_open(p,f,mode) : __real_open(p,f);
}
FILE *__wrap_fopen(const char *p, const char *m) { if (guarded) violations++; return __real_fopen(p,m); }
int __wrap_fflush(FILE *f) { if (guarded) violations++; return __real_fflush(f); }
int __wrap_fsync(int fd) { if (guarded) violations++; return __real_fsync(fd); }
#ifdef __cplusplus
}
#endif
int main(int argc, char **argv) {
    struct cpu_timer timer;
    uint64_t ticks=0;
    int rc=0, disabled, again=0;
    size_t cap=4;
    const char *mode=argc>1 ? argv[1] : "valid";
    const char *clock=argc>2 ? argv[2] : "CLOCK_MONOTONIC_RAW";
    void *payload=mmap(NULL,4096,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (payload==MAP_FAILED || native_process_start_ticks(&ticks)) return 90;
    memset(&timer,0,sizeof(timer));
    disabled=!strcmp(mode,"disabled");
    if (!strcmp(mode,"zero")) cap=0;
    if (!strcmp(mode,"excess")) cap=1048577;
    if (!strcmp(mode,"overflow")) cap=SIZE_MAX;
    if (disabled) guarded=1;
    rc=cpu_timer_init(&timer,clock,cap);
    if (!rc) {
        guarded=1;
        rc=cpu_timer_store(&timer,"io_ns",7,1000,1020);
        if (!rc) rc=cpu_timer_store(&timer,"io_ns",8,1100,1140);
        if (!rc && !strcmp(mode,"duplicate")) rc=cpu_timer_store(&timer,"io_ns",7,1200,1220);
        if (!rc && !strcmp(mode,"zero-span")) rc=cpu_timer_store(&timer,"io_ns",9,1200,1200);
        if (!rc && !strcmp(mode,"reverse-span")) rc=cpu_timer_store(&timer,"io_ns",9,1300,1200);
        if (!rc && !strcmp(mode,"full")) {
            rc=cpu_timer_store(&timer,"io_ns",9,1200,1220);
            if (!rc) rc=cpu_timer_store(&timer,"io_ns",10,1300,1320);
            if (!rc) rc=cpu_timer_store(&timer,"io_ns",11,1400,1420);
        }
        guarded=disabled;
        if (!strcmp(mode,"publish-failure")) {
            struct rlimit limit={0,0};
            signal(SIGXFSZ,SIG_IGN);
            if (setrlimit(RLIMIT_FSIZE,&limit)) return 92;
        }
        if (!rc) rc=cpu_timer_publish(&timer);
        if (!rc && !strcmp(mode,"again")) again=cpu_timer_publish(&timer);
    }
    cpu_timer_destroy(&timer);
    guarded=0;
    munmap(payload,4096);
    if (violations) { fprintf(stderr,"guarded operations: %d\n",violations); return 91; }
    fprintf(stderr,"identity %ld %llu\n",(long)getpid(),(unsigned long long)ticks);
    if (rc || again) return 3;
    fputs("{\"status\":\"pass\",\"io_ns\":60,\"oracle\":\"pass\"}\n",stdout);
    return 0;
}
'''


class CpuTimerJournal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (HERE / "cpu_timer.h").is_file():
            raise unittest.SkipTest("SETUP: cpu_timer.h not implemented; no behavioral RED claimed")
        cls.work = tempfile.TemporaryDirectory(prefix="cpu-timer-c-contract-")
        cls.binaries = {}
        for compiler, standard, suffix in (("gcc", "gnu11", "c"), ("g++", "c++17", "cc")):
            if not shutil.which(compiler):
                raise RuntimeError("SETUP: required GCC compiler absent: " + compiler)
            source = Path(cls.work.name) / ("fixture." + suffix)
            source.write_text(FIXTURE)
            binary = source.with_suffix(".bin")
            command = [compiler, "-std=" + standard, "-O0", "-Wall", "-Wextra", "-Werror",
                       "-I", str(HERE), str(source), "-o", str(binary)]
            command += ["-Wl,--wrap=" + name for name in
                        ("malloc", "calloc", "realloc", "free", "read", "write", "open",
                         "fopen", "clock_gettime", "fflush", "fsync")]
            built = subprocess.run(command, text=True, capture_output=True)
            if built.returncode:
                raise RuntimeError("SETUP: fixture compilation failed:\n" + built.stderr)
            cls.binaries[compiler] = binary

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "work"):
            cls.work.cleanup()

    def invoke(self, compiler, mode="valid", clock="CLOCK_MONOTONIC_RAW", changes=None):
        temporary = tempfile.TemporaryDirectory(prefix="cpu-timer-journal-contract-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        journal = root / "journal"
        journal.mkdir(mode=0o700)
        owner = root / "owner.json"
        owner.write_text(json.dumps({"schema": 1, "token": "independent-token", "run_id": "run-7",
            "clock_domain": "boot:run-7", "cpu_scope": {"schema": 1}, "tick_hz": 100,
            "primary_clock": clock, "extra_clocks": [], "samples_path": str(root / "samples.jsonl"),
            "journal_dir": str(journal)}))
        env = {k: v for k, v in os.environ.items() if not k.startswith(CPU_ENV_PREFIX)}
        if mode != "disabled":
            env.update({CPU_ENV_PREFIX + "OWNER": str(owner),
                        CPU_ENV_PREFIX + "JOURNAL_DIR": str(journal),
                        CPU_ENV_PREFIX + "TOKEN": "independent-token", CPU_ENV_PREFIX + "RUN_ID": "run-7",
                        CPU_ENV_PREFIX + "CLOCK_DOMAIN": "boot:run-7"})
        for key, value in (changes or {}).items():
            if value is None:
                env.pop(CPU_ENV_PREFIX + key, None)
            else:
                env[CPU_ENV_PREFIX + key] = value
        result = subprocess.run([str(self.binaries[compiler]), mode, clock], env=env,
                                capture_output=True, text=True, timeout=10)
        files = [p for p in journal.iterdir() if p.is_file()]
        rows = []
        for path in files:
            for line in path.read_text().splitlines():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # Refusal artifacts may be partial; never accepted as complete.
        return result, files, rows

    def test_original_scalar_endpoints_and_real_process_identity(self):
        for compiler in self.binaries:
            for clock in ("CLOCK_MONOTONIC_RAW", "CLOCK_MONOTONIC"):
                with self.subTest(compiler=compiler, clock=clock):
                    result, files, rows = self.invoke(compiler, clock=clock)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, '{"status":"pass","io_ns":60,"oracle":"pass"}\n')
                    self.assertEqual(len(files), 1)
                    self.assertEqual(len(rows), 3)
                    meta = rows[0]
                    pid, ticks = map(int, result.stderr.strip().split()[-2:])
                    self.assertEqual({k: meta[k] for k in
                        ("kind", "schema", "token", "run_id", "pid", "process_start_ticks", "clock",
                         "clock_domain", "rows", "complete")},
                        {"kind": "cpu-timer-metadata", "schema": 1, "token": "independent-token",
                         "run_id": "run-7", "pid": pid, "process_start_ticks": ticks, "clock": clock,
                         "clock_domain": "boot:run-7", "rows": 2, "complete": True})
                    self.assertEqual(rows[1:], [
                        {"kind": "cpu-timer-span", "metric": "io_ns", "key": 7,
                         "start_ns": 1000, "end_ns": 1020},
                        {"kind": "cpu-timer-span", "metric": "io_ns", "key": 8,
                         "start_ns": 1100, "end_ns": 1140}])

    def test_absent_owner_has_no_heap_clock_file_or_output_side_effect(self):
        for compiler in self.binaries:
            result, files, _ = self.invoke(compiler, "disabled")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(files, [])
            self.assertEqual(result.stdout, '{"status":"pass","io_ns":60,"oracle":"pass"}\n')

    def test_refusal_never_publishes_a_complete_invalid_journal(self):
        for compiler in self.binaries:
            for mode in ("zero", "excess", "overflow", "full", "duplicate", "zero-span", "reverse-span"):
                with self.subTest(compiler=compiler, mode=mode):
                    result, _, rows = self.invoke(compiler, mode)
                    self.assertEqual(result.returncode, 3, result.stderr)
                    self.assertFalse(any(r.get("complete") is True for r in rows))

    def test_required_scalar_identity_and_clock_are_validated(self):
        for changes in ({"TOKEN": None}, {"RUN_ID": None}, {"CLOCK_DOMAIN": None},
                        {"TOKEN": ""}, {"TOKEN": "x" * 65536}, {"JOURNAL_DIR": "/nonexistent/cpu-journal"}):
            with self.subTest(changes={k: len(v) if v else v for k,v in changes.items()}):
                result, _, rows = self.invoke("gcc", changes=changes)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertFalse(any(r.get("complete") is True for r in rows))
        result, _, rows = self.invoke("gcc", clock="CLOCK_REALTIME")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertFalse(any(r.get("complete") is True for r in rows))

    def test_publication_failure_cannot_report_success(self):
        for compiler in self.binaries:
            with self.subTest(compiler=compiler):
                result, _, _ = self.invoke(compiler, "publish-failure")
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_publish_cannot_silently_replace_the_same_process_journal(self):
        result, files, rows = self.invoke("gcc", "again")
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(len(files), 1)
        self.assertEqual(len(rows), 3)


class RunnerContract(unittest.TestCase):
    """Shared real-subprocess helper; no hardware or build mocking."""
    family = None

    def execute_plan(self, options, *, selected=True, cpu_set=None):
        temporary = tempfile.TemporaryDirectory(prefix="cpu-arm-plan-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        command = [sys.executable, "-c", DRY_RUN_GUARD, str(self.runner), *options(root), "--dry-run"]
        if selected:
            command += ["--cpu-output", str(root / "cpu")]
            if cpu_set is not None:
                command += ["--cpu-set", cpu_set]
        env = {k:v for k,v in os.environ.items() if not k.startswith(CPU_ENV_PREFIX)}
        result = subprocess.run(command, text=True, capture_output=True, env=env, timeout=15)
        self.assertEqual(result.returncode, 0,
                         "dry-run must accept CPU flags without building or touching a device:\n" + result.stderr)
        documents = []
        for line in result.stdout.splitlines():
            try:
                documents.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        for path in root.rglob("*.json"):
            try:
                documents.append(json.loads(path.read_text()))
            except (json.JSONDecodeError, OSError):
                continue
        self.assertTrue(documents, "dry-run must retain/print its planned configuration")
        return documents, root

    def assert_cpu_disclosure(self, documents, root, *, expected_cpus=None, clock):
        plans = [v["cpu_measurement_plan"] for v in documents
                 if isinstance(v, dict) and "cpu_measurement_plan" in v]
        self.assertTrue(plans, "dry-run lacks top-level cpu_measurement_plan")
        for plan in plans:
            self.assertEqual(set(plan), {"schema", "status", "selected_cpus", "clock", "extra_clocks",
                                         "owner_mode", "artifacts"})
            self.assertEqual(plan["schema"], 1)
            self.assertEqual(plan["status"], "planned")
            self.assertEqual(plan["selected_cpus"], self.online_cpus() if expected_cpus is None else expected_cpus)
            self.assertEqual(plan["clock"], clock)
            self.assertEqual(plan["extra_clocks"], [])
            self.assertEqual(plan["owner_mode"], "create")
            self.assertEqual(set(plan["artifacts"]), {"samples_path", "journal_dir"})
            for path in plan["artifacts"].values():
                self.assertTrue(Path(path).is_absolute())
                self.assertTrue(Path(path).is_relative_to(root / "cpu"), path)
                self.assertFalse(Path(path).exists(), "dry-run must not create CPU artifacts")
        for obj in self.objects(documents):
            if "bounds" in obj:
                self.assertIsNone(obj["bounds"], "dry-run has no measured primary CPU bounds")

    @staticmethod
    def objects(value):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from RunnerContract.objects(child)
        elif isinstance(value, list):
            for child in value:
                yield from RunnerContract.objects(child)

    @staticmethod
    def online_cpus():
        result=[]
        for part in Path("/sys/devices/system/cpu/online").read_text().strip().split(","):
            pair=part.split("-")
            result.extend(range(int(pair[0]), int(pair[-1])+1))
        return result


if __name__ == "__main__":
    unittest.main()
