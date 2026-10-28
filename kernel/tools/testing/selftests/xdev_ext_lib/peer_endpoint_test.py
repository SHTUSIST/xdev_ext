#!/usr/bin/env python3
"""Real-linked endpoint behavior tests, with no endpoint-source parsing."""
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
    if args.out:
        out = args.out.resolve()
    else:
        cache = test.parent / ".build"
        cache.mkdir(parents=True, exist_ok=True)
        out = Path(tempfile.mkdtemp(prefix="peer-endpoint-", dir=cache))
    out.mkdir(parents=True, exist_ok=True)
    kernel, contract_kernel = source / "kernel", contract / "kernel"
    lib = kernel / "tools/xdev_ext_mech/lib"
    flags = ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
    if not args.no_sanitize:
        flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
    compiler, objects = os.environ.get("CC", "gcc"), []
    for unit in ("xdev_ext_session", "xdev_ext_user", "xdev_ext_link", "xdev_ext_peer_message"):
        path, obj = lib / (unit + ".c"), out / (unit + ".o")
        if not path.exists():
            print("# source absent:", path, flush=True)
            continue
        command = [compiler, *flags, "-I", str(kernel), "-I", str(lib), "-c", str(path), "-o", str(obj)]
        print("+", " ".join(command), flush=True)
        subprocess.run(command, check=True)
        objects.append(str(obj))
    binary = out / "peer_endpoint_test"
    header = contract_kernel / "tools/xdev_ext_mech/lib/libxdev_ext_peer_message.h"
    command = [compiler, *flags, "-I", str(contract_kernel),
               '-DXDEV_EXT_ENDPOINT_CONTRACT="' + str(header) + '"', str(test), *objects, "-o", str(binary)]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)
    print("+", binary, flush=True)
    return subprocess.run([str(binary)]).returncode


if __name__ == "__main__":
    raise SystemExit(main())
