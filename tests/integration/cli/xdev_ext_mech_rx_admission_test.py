#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute production RX/BPF admission and pool CPU-sync code as host C.

The extractor copies whole declarations/functions verbatim; it never asserts
source strings. Kernel-only scheduling/locks are supplied by the fixture, but
batch allocation, HOLD commit, order parsing, ownership and sync dispatch are
production code. No root, BPF loading, interface or disk is required.
"""
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def definition(path, marker, terminator="}"):
    src = (ROOT / path).read_text()
    start = src.index(marker)
    opening = src.index("{", start)
    while ";" in src[start:opening]:
        start = src.index(marker, start + len(marker))
        opening = src.index("{", start)
    depth = 1
    at = opening + 1
    while depth:
        depth += (src[at] == "{") - (src[at] == "}")
        at += 1
    if terminator == "};":
        at += 1
    return src[start:at] + "\n"


def main():
    source = (HERE / "xdev_ext_mech_rx_admission_fixture.c").read_text()
    chunks = {
        "FRAME": definition("include/linux/xdev_ext_mech.h", "struct xdev_ext_mech_frame {", "};"),
        "POOL_OPS": definition("include/linux/xdev_ext_mech.h", "struct xdev_ext_mech_pool_ops {", "};"),
        "ALLOC": definition("io_uring/xdev_ext_mech.c", "static struct xdev_ext_mech_batch *\nxdev_ext_mech_batch_get_locked("),
        "FIND": definition("io_uring/xdev_ext_mech.c", "static struct xdev_ext_mech_batch *\nxdev_ext_mech_open_find_locked("),
        "COMMIT": definition("io_uring/xdev_ext_mech.c", "int xdev_ext_mech_hold_commit("),
        "REL_RX": definition("net/xdp/xsk_xdev_ext_mech_reliable.inc", "static int xsk_rel_rx("),
        "REL_COMMIT": definition("net/xdp/xsk_xdev_ext_mech_reliable.inc", "static int xsk_rel_hold_commit("),
        "PENDING_ENTRY": definition("net/xdp/xsk_xdev_ext_mech.c", "struct xsk_mech_rx_pending_entry {", "};"),
        "PENDING_QUEUE": definition("net/xdp/xsk_xdev_ext_mech.c", "struct xsk_mech_rx_pending {", "};"),
        "PENDING_OWNED": definition("net/xdp/xsk_xdev_ext_mech_rx_pending.inc", "static bool xsk_rx_pending_owned("),
        "PENDING_ADD": definition("net/xdp/xsk_xdev_ext_mech_rx_pending.inc", "static int xsk_rx_pending_add("),
        "PENDING_DRAIN": definition("net/xdp/xsk_xdev_ext_mech_rx_pending.inc", "static unsigned long xsk_rx_pending_drain("),
        "RESOLVE": definition("net/xdp/xsk_xdev_ext_mech.c", "static int xsk_xdev_ext_mech_pool_resolve("),
        "XSK_RX": definition("net/xdp/xsk_xdev_ext_mech.c", "int xsk_xdev_ext_mech_rx("),
        "SYNC": definition("io_uring/xdev_ext_mech.c", "static void xdev_ext_mech_sync_for_cpu("),
    }
    for name, chunk in chunks.items():
        source = source.replace("/* PRODUCTION_" + name + " */", chunk)
    with tempfile.TemporaryDirectory(prefix="xdev_ext-rx-admission-") as tmp:
        src = Path(tmp) / "test.c"
        binary = Path(tmp) / "test"
        src.write_text(source)
        command = [os.environ.get("CC", "cc"), "-DXDEV_EXT_REL_C_GLUE", "-std=gnu11", "-O1", "-g",
                   "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined",
                   "-fno-sanitize-recover=undefined", "-I" + str(ROOT),
                   "-I" + str(ROOT / "tools/testing/selftests/xdev_ext_mech/cref"),
                   "-I" + str(ROOT / "tools/testing/selftests/xdev_ext_mech/cref/host"),
                   str(src), "-o", str(binary)]
        subprocess.run(command, check=True)
        return subprocess.run([str(binary)], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
