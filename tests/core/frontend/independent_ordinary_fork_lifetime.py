#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise actual preload ordinary-ring lifetime functions at a host seam.

The ring setup/register primitives are substituted; descriptors, VMAs, pthreads,
fork, registry functions, atfork hooks, init/destruction and mini_liburing's exit
function are real. This proves the userspace ownership boundary, not io_uring
registration, provider quiescence, DMA correctness or performance. Setup errors
are failures. No privileged kernel feature, virtual provider or VM is used.
"""
from pathlib import Path
import argparse
import hashlib
import os
import re
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[3]


def function(source, name):
    pattern = r"^static\s+(?:inline\s+)?[^;{}]*?\b" + re.escape(name) + r"\s*\([^;{}]*?\)\s*\{"
    match = re.search(pattern, source, re.M)
    if not match:
        raise RuntimeError("missing actual function: " + name)
    brace = source.index("{", match.start())
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


def structure(source, name):
    start = source.index("struct " + name + " {")
    return source[start:source.index("\n};", start) + 3] + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-generated", type=Path)
    parser.add_argument("--case", action="append", choices=CASES)
    args = parser.parse_args()
    preload_path = KERNEL / "tools/io_uring_unified_preload.c"
    source = preload_path.read_text()
    header = (KERNEL / "tools/xdev_ext_preload_socket_mech.h").read_text()
    functions = {name: function(source, name) for name in (
        "xdev_ext_register_thread", "xdev_ext_remove_thread_locked",
        "xdev_ext_thread_init", "xdev_ext_thread_destroy",
        "xdev_ext_discard_inherited_thread", "xdev_ext_atfork_prepare",
        "xdev_ext_atfork_parent", "xdev_ext_atfork_child")}
    # Include new local helpers transitively, without copying production logic
    # into the fixture. External boundaries below remain explicit substitutions.
    seams = {"xdev_ext_socket_mech_control", "xdev_ext_report_thread_locked",
             "xdev_ext_admission_after_fork_child", "xdev_ext_preload_fd_lock_all",
             "xdev_ext_preload_fd_unlock_all"}
    for name in ("xdev_ext_socket_mech_forget_child", "xdev_ext_socket_mech_release"):
        functions[name] = function(header, name)
    while True:
        missing = set(re.findall(r"\b(xdev_ext_\w+)\s*\(", "".join(functions.values()))) - functions.keys() - seams
        if not missing:
            break
        for name in sorted(missing):
            functions[name] = function(source, name)
    # Rename only the definition; the fixture forwards each production call to
    # it and records completion. Its actual statement body stays unchanged.
    functions["xdev_ext_remove_thread_locked"] = functions["xdev_ext_remove_thread_locked"].replace(
        "xdev_ext_remove_thread_locked(", "actual_remove_thread_locked(", 1)
    declarations = "\n".join(body[:body.index("{")].strip() + ";" for body in functions.values())
    fixture = (HERE / "independent_ordinary_fork_lifetime_fixture.c").read_text()
    prologue, rest = fixture.split("/* ACTUAL_TYPES */", 1)
    globals_, epilogue = rest.split("/* ACTUAL_FUNCTIONS */", 1)
    actual = (prologue.replace("@TOOLS@", str(KERNEL / "tools")) +
              structure(header, "xdev_ext_socket_mech_runtime") +
              structure(source, "xdev_ext_thread_ctx") + globals_ +
              declarations + "\n" + "".join(functions.values()) + epilogue)
    print("# userspace extraction seam; real fd/VMA/fork; no provider/DMA/performance claim", flush=True)
    print("# production sha256=" + hashlib.sha256(preload_path.read_bytes()).hexdigest(), flush=True)
    if args.keep_generated:
        args.keep_generated.mkdir(parents=True, exist_ok=True)
        (args.keep_generated / "actual.c").write_text(actual)
    with tempfile.TemporaryDirectory(prefix="independent-ordinary-fork-") as tmp:
        cfile, binary = Path(tmp) / "actual.c", Path(tmp) / "actual"
        cfile.write_text(actual)
        build = subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                                "-fsanitize=undefined", "-pthread", str(cfile), "-o", str(binary)],
                               capture_output=True, text=True, timeout=30)
        if build.returncode:
            print(build.stderr, end="")
            raise SystemExit("FAIL: actual-function fixture did not build")
        cases, failures = args.case or CASES, 0
        print("1.." + str(len(cases)), flush=True)
        for n, case in enumerate(cases, 1):
            try:
                result = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=12)
                print(result.stdout, end="")
                print(result.stderr, end="")
                failed = result.returncode != 0
                print(("not ok" if failed else "ok") + f" {n} - {case} (exit={result.returncode})", flush=True)
            except subprocess.TimeoutExpired as exc:
                failed = True
                print(f"not ok {n} - {case}: bounded campaign timeout {exc}", flush=True)
            failures += failed
        raise SystemExit(bool(failures))


CASES = ["live-workers", "unknown-worker", "repeated-fork", "main-lazy-only", "no-context", "inert",
         "init-publication-gap", "destroy-removal-gap", "partial-register-failure",
         "partial-queue-failure", "partial-umem-allocation-failure",
         "partial-shared-allocation-failure", "teardown-stop-failure"]


if __name__ == "__main__":
    main()
