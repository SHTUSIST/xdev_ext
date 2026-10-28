#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Preserve ThunderboltIP progress across ordinary TB domain-lock contention.

The selected production function bodies are copied without substitutions.
A missing assembled upstream source is SETUP (exit 2), never a behavioral PASS.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from contextlib import nullcontext

HERE = Path(__file__).resolve().parent


def function(source, name):
    pattern = r"(?m)^static (?:int|void) " + re.escape(name) + r"\([^;]*?\)\s*\{"
    match = re.search(pattern, source)
    if not match:
        raise ValueError("missing production definition " + name)
    position = source.index("{", match.start()) + 1
    depth = 1
    while depth:
        depth += (source[position] == "{") - (source[position] == "}")
        position += 1
    return source[match.start():position] + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", type=Path, default=HERE.parents[4])
    parser.add_argument("--approve-source", type=Path)
    parser.add_argument("--tbnet-source", type=Path)
    parser.add_argument("--keep-build", type=Path)
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    approve = args.approve_source or kernel / "drivers/thunderbolt/tb.c"
    tbnet = args.tbnet_source or kernel / "drivers/net/thunderbolt/main.c"
    try:
        if not tbnet.exists() and args.tbnet_source is None:
            commit = "89be9a83ccf1f88522317ce02f854f30d6115c41"
            root = kernel.parent
            lock = json.loads((root / "sources.lock.json").read_text())
            if lock["components"]["linux"]["commit"] != commit:
                raise ValueError("pinned ThunderboltIP fixture lock mismatch")
            folder = root / "tests/fixtures/upstream" / ("linux-" + commit)
            tbnet = folder / "thunderbolt_net_main.c"
            pin = json.loads((folder / "THUNDERBOLT_NET_SOURCE.json").read_text())
            if (pin["linux_commit"] != commit or
                    hashlib.sha256(tbnet.read_bytes()).hexdigest() != pin["sha256"]):
                raise ValueError("pinned ThunderboltIP fixture content mismatch")
            print("# using explicit pinned upstream ThunderboltIP fixture: " + str(tbnet))
        production = function(approve.read_text(), "tb_approve_xdomain_paths")
        network = tbnet.read_text()
        production += function(network, "tbnet_connected_work")
        production += function(network, "tbnet_login_work")
        case = (HERE / "xdomain_review_tbnet_cases.c").read_text()
        marker = "/* ACTUAL_PRODUCTION_BODIES */"
        if case.count(marker) != 1:
            raise ValueError("missing or duplicate production insertion boundary")
        unit = case.replace(marker, production)
    except (OSError, ValueError, IndexError, KeyError, TypeError) as error:
        print("# SETUP_EXTRACTION: " + str(error))
        return 2
    context = (nullcontext(str(args.keep_build.resolve())) if args.keep_build else
               tempfile.TemporaryDirectory(prefix="xdomain-review-tbnet-"))
    with context as directory:
        build = Path(directory)
        build.mkdir(parents=True, exist_ok=True)
        source, binary = build / "tbnet-unit.c", build / "tbnet"
        source.write_text(unit)
        command = ["gcc", "-std=gnu11", "-pthread", "-Wall", "-Wextra",
                   "-Wno-unused-parameter", "-Wno-unused-function",
                   "-Werror=implicit-function-declaration", str(source), "-o", str(binary)]
        compile_result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if compile_result.returncode:
            print("# SETUP_COMPILE_ERROR\n" + compile_result.stdout + compile_result.stderr)
            return 2
        print("# actual approve: " + str(approve.resolve()))
        print("# actual ThunderboltIP: " + str(tbnet.resolve()))
        print("TAP version 13\n1..1", flush=True)
        try:
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
        except subprocess.TimeoutExpired:
            print("not ok 1 - successful_login_survives_domain_lock_contention # timeout")
            return 1
        print(result.stdout + result.stderr, end="")
        ok = result.returncode == 0
        print(("ok" if ok else "not ok") +
              " 1 - successful_login_survives_domain_lock_contention; exit=" + str(result.returncode))
        return int(not ok)


if __name__ == "__main__":
    sys.exit(main())
