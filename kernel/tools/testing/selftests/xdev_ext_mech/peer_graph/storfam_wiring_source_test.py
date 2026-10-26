#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source-only STORAGE integration contract; arithmetic lives in the C test."""
from pathlib import Path
import re
import sys

KERNEL = Path(__file__).resolve().parents[5]


def source(path):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", (KERNEL / path).read_text(), flags=re.S)


def body(text, pattern):
    match = re.search(pattern, text, re.S)
    if not match:
        return ""
    begin = text.find("{", match.end())
    depth = 0
    for end in range(begin, len(text)):
        depth += (text[end] == "{") - (text[end] == "}")
        if not depth:
            return text[begin + 1:end]
    return ""


def main():
    core = source("drivers/nvme/host/xdev_ext_peer_nvme_core.h")
    nvme = source("drivers/nvme/host/xdev_ext_mech_nvme.c")
    passthru = source("include/linux/nvme_xdev_ext_passthru.h")
    builder = body(core, r"\bxdev_ext_peer_nvme_sgl_build\s*\([^;]+?\)\s*(?=\{)")
    hooks = body(nvme, r"\bstruct\s+xdev_ext_stor_hooks\s+nvme_xdev_ext_stor_hooks\s*=\s*(?=\{)")
    checks = [
        ("NVMe SGL wrapper delegates to family rules",
         bool(re.search(r"return\s+xdev_ext_stor_coalesce\s*\(\s*seg\s*,\s*nr\s*,\s*out\s*,\s*cap\s*,\s*3\s*,\s*n\s*\)", builder))),
        ("NVMe class registers STORAGE hooks",
         bool(re.search(r"\.fam\.stor\s*=\s*&nvme_xdev_ext_stor_hooks\b", nvme))),
        ("NVMe hooks identify STORAGE, dword alignment and native extent capacity",
         all(re.search(pattern, hooks) for pattern in (
             r"\.family\s*=\s*XDEV_EXT_FAMILY_STORAGE\b",
             r"\.extent_align_mask\s*=\s*3\b",
             r"\.max_extents\s*=\s*NVME_XDEV_EXT_PEER_MAX_PIECES\b"))),
        ("NVMe SGL capacity comes from STORAGE hooks",
         bool(re.search(r"\bxdev_ext_peer_nvme_sgl_build\s*\([^;]*?nvme_xdev_ext_stor_hooks\s*\.\s*max_extents\s*,", nvme, re.S))),
        ("NVMe command validation delegates its LBA window to family rules",
         bool(re.search(r"\bxdev_ext_stor_window_check\s*\(\s*bounds->window_slba\s*,\s*bounds->window_nlb\s*,\s*slba\s*,\s*nlb\s*\)",
                        body(passthru, r"\bnvme_xdev_ext_mech_validate\s*\([^;]+?\)\s*(?=\{)")))),
    ]
    print("TAP version 13")
    print(f"1..{len(checks)}")
    for index, (label, passed) in enumerate(checks, 1):
        print(f"{'ok' if passed else 'not ok'} {index} - source-only: {label}")
    return int(not all(passed for _, passed in checks))


if __name__ == "__main__":
    sys.exit(main())
