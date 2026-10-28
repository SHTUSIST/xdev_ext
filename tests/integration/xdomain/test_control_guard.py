#!/usr/bin/env python3
"""A1 SDK-free real guard tests; missing operation is a runtime RED."""
from pathlib import Path
import os
import shlex
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-g", "-pthread",
         "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I" + str(HERE)]


def run(command, timeout=30):
    print("+ " + shlex.join(map(str, command)), flush=True)
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout,
                                env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1"})
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or b""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        if output:
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
        print("A1 requires GCC; generic Clang validation is not authorized.", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="tb-control-guard-") as temporary:
        exe = Path(temporary) / "control_guard_test"
        ret, _ = run(compiler + FLAGS + [str(HERE / "control_guard_test.c"),
                                       str(HERE / "check_contract.c"), "-o", str(exe)])
        if ret:
            return ret
        ret, output = run([str(exe), "--list"])
        if ret:
            return ret
        names = output.splitlines()
        if not names or len(names) != len(set(names)):
            print("invalid or duplicate A1 case inventory", file=sys.stderr)
            return 2
        failures = 0
        for name in names:
            ret, _ = run([str(exe), name], timeout=10)
            failures += bool(ret)
        print(f"A1 CONTROL guard: cases={len(names)} failures={failures}", flush=True)
        return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
