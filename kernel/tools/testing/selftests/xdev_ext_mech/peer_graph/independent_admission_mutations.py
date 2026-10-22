#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fault mutations of real graph admission headers, independent oracle unchanged."""
from pathlib import Path
import runpy
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / "independent_admission.py"))
KERNEL = BASE["KERNEL"]
FILES = ("io_uring/xdev_ext_mech_step.h", "io_uring/xdev_ext_mech_core.h", "include/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_binding.h")


def compile_and_run(directory, headers, cases):
    for filename, content in headers.items():
        target = directory / filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    source = directory / "actual.c"
    binary = directory / "actual"
    source.write_text(BASE["C_SOURCE"])
    compiled = subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-I" + str(directory), str(source), "-o", str(binary)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    return [subprocess.run([str(binary), case], capture_output=True, text=True) for case in cases]


def main():
    headers = {filename: (KERNEL / filename).read_text() for filename in FILES}
    step = headers[FILES[0]]
    mutations = [
        ("GPU frame size bypass", "c->layout.frame_size != 65536", "(c->layout.frame_size != 65536 && false)", "reject_geometry"),
        ("initial GPU readiness bypass", "c->st[0].direction != XDEV_EXT_MECH_DIR_FROM_DEVICE", "(c->st[0].direction != XDEV_EXT_MECH_DIR_FROM_DEVICE && false)", "reject_unready_source"),
        ("host class on GPU pool", "(u->class_id != XDEV_EXT_MECH_CLASS_NVME && u->class_id != XDEV_EXT_MECH_CLASS_NET)", "(false && u->class_id != XDEV_EXT_MECH_CLASS_NVME && u->class_id != XDEV_EXT_MECH_CLASS_NET)", "reject_host_stages"),
        ("native NET RX bypass", "u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE)", "(u->direction != XDEV_EXT_MECH_DIR_TO_DEVICE && false))", "reject_native_rx"),
        ("host USER frame on GPU pool", "pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM || !frames", "(pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM && pool_kind != XDEV_EXT_MECH_POOL_PEER) || !frames", "bounded_start"),
    ]
    cases = ("peer_nvme", "peer_net", "native_class", "reject_host_stages", "reject_native_rx", "reject_unready_source", "reject_geometry", "bounded_start", "legacy_unchanged")
    with tempfile.TemporaryDirectory(prefix="independent-peer-admission-mutations-") as tmp:
        directory = Path(tmp)
        baseline = compile_and_run(directory, headers, cases)
        assert all(result.returncode == 0 for result in baseline), [(result.stdout, result.stderr) for result in baseline]
        for name, old, new, case in mutations:
            assert step.count(old) == 1, (name, step.count(old))
            changed = dict(headers)
            changed[FILES[0]] = step.replace(old, new)
            result = compile_and_run(directory, changed, (case,))[0]
            assert result.returncode != 0 and "expected=" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by unchanged admission oracle")


if __name__ == "__main__":
    main()
