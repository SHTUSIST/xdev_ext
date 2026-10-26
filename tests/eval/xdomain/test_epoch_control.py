#!/usr/bin/env python3
"""Build and exercise real A symbols; injection stops at syscalls/poll/clock."""
from pathlib import Path
import os
import shlex
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g",
         "-fsanitize=undefined", "-fno-sanitize-recover=all", "-pthread",
         "-I" + str(HERE), "-I" + str(ROOT / "kernel/include/uapi")]


def run(command, *, timeout=30):
    print("+ " + shlex.join(map(str, command)), flush=True)
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout,
                                env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"})
    except subprocess.TimeoutExpired as exc:
        if exc.stdout:
            output = exc.stdout.decode() if isinstance(exc.stdout, bytes) else exc.stdout
            print(output, end="" if output.endswith("\n") else "\n")
        print("exit=124 (timeout)", flush=True)
        return 124, ""
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    print(f"exit={result.returncode}", flush=True)
    return result.returncode, result.stdout


def main():
    compiler = shlex.split(os.environ.get("HOST_CC", "gcc"))
    if not compiler or "clang" in Path(compiler[0]).name:
        print("A host tests require GCC; generic Clang validation is not authorized.", file=sys.stderr)
        return 2
    failures = 0
    cases = 0
    with tempfile.TemporaryDirectory(prefix="tb-epoch-test-") as temporary:
        build = Path(temporary)
        for name, production in (
                ("guard_test", ("check_contract.c",)),
                ("epoch_control_test", ("check_contract.c", "epoch_control.c"))):
            obj = build / (name + ".o")
            ret, _ = run(compiler + FLAGS + ["-c", str(HERE / (name + ".c")), "-o", str(obj)])
            if ret:
                failures += 1
                continue
            # Declaration-only baseline: link the actual calls without invented
            # implementations, and retain genuine undefined-reference RED.
            sources = [str(HERE / source) for source in production if (HERE / source).exists()]
            exe = build / name
            ret, _ = run(compiler + FLAGS + [str(obj), *sources, "-o", str(exe)])
            if ret:
                failures += 1
                continue
            ret, output = run([str(exe), "--list"])
            if ret:
                failures += 1
                continue
            names = output.splitlines()
            if not names or len(names) != len(set(names)):
                print(f"invalid or duplicate case inventory: {name}", file=sys.stderr)
                failures += 1
                continue
            for case in names:
                cases += 1
                ret, _ = run([str(exe), case], timeout=10)
                failures += bool(ret)
    print(f"A controller/guard: cases={cases} failures={failures}", flush=True)
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
