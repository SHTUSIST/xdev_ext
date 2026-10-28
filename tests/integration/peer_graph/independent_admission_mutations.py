#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Fault mutations of real graph admission headers, independent oracle unchanged."""
from pathlib import Path
import re
import runpy
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
BASE = runpy.run_path(str(HERE / "independent_admission.py"))
KERNEL = BASE["KERNEL"]
FILES = ("io_uring/xdev_ext_mech_step.h", "io_uring/xdev_ext_mech_core.h", "include/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_mech.h", "include/uapi/linux/xdev_ext_binding.h")
# F1b: copied core rules now include the production class descriptor table.
FILES += ("include/linux/xdev_ext_family_core.h",)


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


def replace_body(text, name, body):
    """Replace the body of static inline function @name; None when absent."""
    m = re.search(r"static inline [^;{]*\b" + name + r"\(([^)]*)\)\s*\{", text)
    if not m:
        return None
    i, depth = m.end(), 1
    while depth:
        depth += (text[i] == "{") - (text[i] == "}")
        i += 1
    param = re.findall(r"(\w+)\s*$", m.group(1).strip())[0]
    return text[:m.end() - 1] + "{ " + body.replace("PARAM", param) + " }" + text[i:]


def main():
    headers = {filename: (KERNEL / filename).read_text() for filename in FILES}
    step = headers[FILES[0]]
    if '#include "xdev_ext_mech_cpu_core.h"' in step:
        filename = "io_uring/xdev_ext_mech_cpu_core.h"
        headers[filename] = (KERNEL / filename).read_text()
    # F9a: copy the pure compute dependency required by this step snapshot.
    if 'xdev_ext_compfam_core.h' in step:
        filename = "include/linux/xdev_ext_compfam_core.h"
        headers[filename] = (KERNEL / filename).read_text()
    # Updated for P1: the 75b51c2 anchors (64 KiB frame, NVMe-read-first, NVMe/NET-only, TX-only NET)
    # are replaced by the capability table and the geometry rule; mutate those instead.
    mutations = [
        ("every class claims peer capability", "xdev_ext_mech_peer_dirs", "(void)PARAM; return XDEV_EXT_DMA_DIR_KNOWN_MASK;", "reject_host_stages"),
        ("NET RX capability dropped", "xdev_ext_mech_peer_dirs",
         "return PARAM == XDEV_EXT_MECH_CLASS_NVME ? XDEV_EXT_DMA_DIR_KNOWN_MASK : PARAM == XDEV_EXT_MECH_CLASS_NET ? XDEV_EXT_DMA_DIR_TO_DEVICE : 0;", "native_rx"),
        ("NVMe write capability dropped", "xdev_ext_mech_peer_dirs",
         "return PARAM == XDEV_EXT_MECH_CLASS_NVME ? XDEV_EXT_DMA_DIR_FROM_DEVICE : PARAM == XDEV_EXT_MECH_CLASS_NET ? XDEV_EXT_DMA_DIR_KNOWN_MASK : 0;", "gpu_first"),
        ("GPU geometry unchecked", "xdev_ext_mech_peer_layout_check", "(void)PARAM; return 0;", "reject_geometry"),
    ]
    cases = ("peer_nvme", "peer_net", "native_class", "reject_host_stages", "native_rx", "gpu_first", "reject_geometry", "bounded_start", "legacy_unchanged")
    with tempfile.TemporaryDirectory(prefix="independent-peer-admission-mutations-") as tmp:
        directory = Path(tmp)
        baseline = compile_and_run(directory, headers, cases)
        assert all(result.returncode == 0 for result in baseline), [(result.stdout, result.stderr) for result in baseline]
        for name, function, body, case in mutations:
            changed_step = replace_body(step, function, body)
            assert changed_step and changed_step != step, (name, function + "() missing from xdev_ext_mech_step.h")
            changed = dict(headers)
            changed[FILES[0]] = changed_step
            result = compile_and_run(directory, changed, (case,))[0]
            assert result.returncode != 0 and "expected=" in result.stderr, (name, result.stdout, result.stderr)
            print("ok mutation - " + name + " rejected by unchanged admission oracle")
        old, new = "pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM || !frames", "(pool_kind != XDEV_EXT_MECH_POOL_IOU_UMEM && pool_kind != XDEV_EXT_MECH_POOL_PEER) || !frames"
        assert step.count(old) == 1, ("host USER frame on GPU pool", step.count(old))
        changed = dict(headers)
        changed[FILES[0]] = step.replace(old, new)
        result = compile_and_run(directory, changed, ("bounded_start",))[0]
        assert result.returncode != 0 and "expected=" in result.stderr, ("host USER frame on GPU pool", result.stdout, result.stderr)
        print("ok mutation - host USER frame on GPU pool rejected by unchanged admission oracle")


if __name__ == "__main__":
    main()
