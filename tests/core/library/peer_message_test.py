#!/usr/bin/env python3
"""Compile the independent public-contract test against real library units."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--contract-root", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--no-sanitize", action="store_true")
    args = parser.parse_args()
    test = Path(__file__).resolve().with_suffix(".c")
    default_root = test.parents[5]
    source = (args.source_root or default_root).resolve()
    contract = (args.contract_root or default_root).resolve()
    out = args.out.resolve() if args.out else Path(tempfile.mkdtemp(prefix="q10-library-"))
    out.mkdir(parents=True, exist_ok=True)
    kernel = source / "kernel"
    contract_kernel = contract / "kernel"
    lib = kernel / "tools/xdev_ext_mech/lib"
    compiler = os.environ.get("CC", "gcc")
    flags = ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
    if not args.no_sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
    objects = []
    for unit in ("xdev_ext_session", "xdev_ext_user"):
        obj = out / (unit + ".o")
        command = [compiler, *flags, "-I", str(kernel), "-I", str(lib),
                   "-c", str(lib / (unit + ".c")), "-o", str(obj)]
        print("+", " ".join(command), flush=True)
        subprocess.run(command, check=True)
        objects.append(str(obj))
    binary = out / "peer_message_test"
    command = [compiler, *flags, "-I", str(contract_kernel),
               "-DXDEV_EXT_TEST_CONTRACT=\"" + str(contract_kernel / "tools/xdev_ext_mech/lib/libxdev_ext.h") + "\"",
               str(test), *objects, "-o", str(binary)]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)
    print("+", binary, flush=True)
    return subprocess.run([str(binary)]).returncode


if __name__ == "__main__":
    raise SystemExit(main())
