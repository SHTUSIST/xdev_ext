#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production XDOMAIN ring glue and its real device vtable.

Upstream tb_ring, tb_xdomain path, memory and locking APIs are recorders.
Proves frame construction, callback classification, control/sequence custody
and rollback decisions; does not prove NHI hardware behavior or BPF policy.
Production is required; missing artifacts are setup errors, never behavioral RED.
"""
import argparse
from pathlib import Path
HERE = Path(__file__).resolve().parent
import subprocess
import sys
import tempfile


def no_includes(text):
    return "\n".join(line for line in text.splitlines()
                     if not line.lstrip().startswith("#include")) + "\n"


def declaration(text, key):
    """Copy a real named declaration, including every field, without a model."""
    start = text.index(key + " {")
    pos = start + len(key)
    depth = 0
    for pos in range(pos, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                end = text.index(";", pos) + 1
                return text[start:end] + "\n"
    raise ValueError("unterminated declaration: " + key)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", type=Path, default=HERE.parents[4])
    parser.add_argument("--ring-source", type=Path, help="explicit historical baseline source; never current-production evidence")
    parser.add_argument("--keep-build", type=Path)
    args = parser.parse_args()
    if __file__.endswith(".draft"):
        print("# INACTIVE_DRAFT: root activation after X3 acceptance is required")
        return 2
    kernel = args.kernel.resolve()
    names = ["io_uring/xdomain/xdev_ext_xdomain_core.h",
             "io_uring/xdomain/xdev_ext_xdomain.h",
             "io_uring/xdomain/xdev_ext_xdomain_ring.c",
             "include/linux/xdev_ext_netfam.h",
             "include/linux/xdev_ext_peer.h"]
    absent = [name for name in names if not (kernel / name).is_file() and not (name == names[2] and args.ring_source)]
    if absent:
        print("# SETUP_MISSING: no behavioral RED/GREEN has run")
        for name in absent:
            print("# missing: " + str(kernel / name))
        return 2
    here = Path(__file__).resolve().parent
    try:
        source = (args.ring_source or (kernel / names[2])).read_text()
        if args.ring_source:
            print("# HISTORICAL_SCAFFOLD_ONLY: current production ring module is absent", flush=True)
        ring = no_includes(source)
        peer = (kernel / names[4]).read_text()
        lease = (declaration(peer, "struct xdev_ext_peer_lease") +
                 declaration(peer, "struct xdev_ext_peer_fd_lease"))
        net = (kernel / names[3]).read_text()
        family = (declaration(net, "enum xdev_ext_net_hdr_policy") +
                  "\n".join(line for line in net.splitlines()
                            if line.startswith("#define XDEV_EXT_NET_DEV_AREA") or
                            line.startswith("#define XDEV_EXT_NETFAM_MAX_ELEMS")) + "\n" +
                  declaration(net, "struct xdev_ext_net_elem") +
                  declaration(net, "struct xdev_ext_net_dev_ops"))
        unit = ((here / "xdomain_ring_compat.h").read_text() +
                '\n#include "include/uapi/linux/xdev_ext_mech.h"\n' +
                '\n#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n' +
                '\n#include "include/linux/xdev_ext_mech_reliable_core.h"\n' +
                lease + family + no_includes((kernel / names[1]).read_text()) +
                (here / "xdomain_ring_boundaries.c").read_text() + ring +
                (here / "xdomain_ring_cases.c").read_text())
    except (OSError, ValueError) as error:
        print("# SETUP_EXTRACTION: " + str(error), file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="xdomain-ring-") as directory:
        cfile, binary = Path(directory) / "ring.c", Path(directory) / "ring"
        cfile.write_text(unit)
        if args.keep_build:
            args.keep_build.mkdir(parents=True, exist_ok=True)
            (args.keep_build / "ring-unit.c").write_text(unit)
        build = subprocess.run(["gcc", "-std=gnu11", "-O0", "-g", "-Wall",
                                "-Wextra", "-Wno-unused-parameter",
                                "-Wno-unused-function", "-Wno-unused-variable",
                                "-Werror=implicit-function-declaration", "-pthread",
                                "-I", str(kernel), str(cfile), "-o", str(binary)],
                               text=True, capture_output=True, timeout=60)
        if build.returncode:
            print("# SETUP_COMPILE_ERROR; not behavioral RED", file=sys.stderr)
            print(build.stdout + build.stderr, file=sys.stderr)
            return 2
        count = int(subprocess.check_output([str(binary), "--count"], text=True, timeout=5))
        print("TAP version 13\n1.." + str(count), flush=True)
        failed = False
        for number in range(1, count + 1):
            try:
                run = subprocess.run([str(binary), str(number)], timeout=15)
            except subprocess.TimeoutExpired:
                failed = True
                print(f"not ok {number} - timeout waiting for software barrier", flush=True)
                continue
            if run.returncode:
                failed = True
                print(f"not ok {number} - runtime assertion (exit {run.returncode})", flush=True)
        return int(failed)


if __name__ == "__main__":
    sys.exit(main())
