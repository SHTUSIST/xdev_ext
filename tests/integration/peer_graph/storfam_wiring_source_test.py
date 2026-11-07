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
    native = source("drivers/nvme/host/core.c")
    family = source("io_uring/family/xdev_ext_storfam_block.c")
    rules = source("include/linux/xdev_ext_storfam_core.h")
    passthru = source("include/linux/nvme_xdev_ext_passthru.h")
    builder = body(core, r"\bxdev_ext_peer_nvme_sgl_build\s*\([^;]+?\)\s*(?=\{)")
    hooks = body(nvme, r"\bstruct\s+xdev_ext_stor_hooks\s+nvme_xdev_ext_stor_hooks\s*=\s*(?=\{)")
    member_ops = body(nvme, r"\bstruct\s+xdev_ext_stor_dev_ops\s+nvme_xdev_ext_member_ops\s*=\s*(?=\{)")
    encode_dptr = body(nvme, r"\bnvme_xdev_ext_member_encode_dptr\s*\([^;]+?\)\s*(?=\{)")
    native_builder = body(native, r"\bnvme_xdev_ext_peer_build_cmd\s*\([^;]+?\)\s*(?=\{)")
    submit = body(family, r"\bxdev_ext_storfam_submit\s*\([^;]+?\)\s*(?=\{)")
    validate = body(passthru, r"\bnvme_xdev_ext_mech_validate\s*\([^;]+?\)\s*(?=\{)")
    admit = body(rules, r"\bxdev_ext_stor_window_admit\s*\([^;]+?\)\s*(?=\{)")
    # Follow the selected member's actual callee, not an unused wrapper or a
    # declaration of the old hook arguments elsewhere in the source.
    dptr_path = all((
        re.search(r"\.encode_dptr\s*=\s*nvme_xdev_ext_member_encode_dptr\b", member_ops),
        re.search(r"return\s+nvme_xdev_ext_peer_build_cmd\s*\(\s*&rw\s*,\s*nsid\s*,"
                  r"\s*nvme_ctrl_sgl_supported\s*\(\s*p->ns->ctrl\s*\)\s*,\s*false\s*,"
                  r"\s*spans\s*,\s*nr\s*,\s*work\s*,\s*capacity\s*,\s*list_cpu\s*,"
                  r"\s*list_dma\s*,\s*list_bytes\s*,\s*cmd\s*\)", encode_dptr),
        re.search(r"ss->dev->encode_dptr\s*\(\s*ss->member\s*,\s*&sb->command\s*,"
                  r"\s*io->spans\s*,\s*io->nr_leases\s*,\s*io->spans\s*,"
                  r"\s*XDEV_EXT_STOR_PEER_MAX_SPANS\s*,\s*io->list_cpu\s*,"
                  r"\s*io->list_dma\s*,\s*SZ_4K\s*\)", submit),
    ))
    native_sgl = re.search(
        r"ret\s*=\s*xdev_ext_peer_nvme_sgl_build\s*\(\s*spans\s*,\s*nr\s*,\s*work\s*,"
        r"\s*min_t\s*\(\s*u32\s*,\s*capacity\s*,"
        r"\s*NVME_CTRL_PAGE_SIZE\s*/\s*sizeof\s*\(\s*\*sgl\s*\)\s*\)\s*,"
        r"\s*3\s*,\s*&n\s*\)\s*;\s*if\s*\(\s*ret\s*\)\s*return\s+ret\s*;",
        native_builder)
    checks = [
        ("NVMe SGL wrapper delegates declared alignment to family rules",
         bool(re.search(r"return\s+xdev_ext_stor_coalesce\s*\(\s*seg\s*,\s*nr\s*,\s*out\s*,\s*cap\s*,\s*align_mask\s*,\s*n\s*\)", builder))),
        ("NVMe class registers STORAGE hooks",
         bool(re.search(r"\.fam\.stor\s*=\s*&nvme_xdev_ext_stor_hooks\b", nvme))),
        ("NVMe hooks identify STORAGE, dword alignment and native extent capacity",
         all(re.search(pattern, hooks) for pattern in (
             r"\.family\s*=\s*XDEV_EXT_FAMILY_STORAGE\b",
             r"\.extent_align_mask\s*=\s*3\b",
             r"\.max_extents\s*=\s*NVME_XDEV_EXT_PEER_MAX_PIECES\b"))),
        ("NVMe SGL alignment follows the native builder into STORAGE rules",
         bool(dptr_path and native_sgl)),
        ("NVMe SGL capacity is bounded by caller, native page and descriptor list",
         bool(dptr_path and native_sgl and
              re.search(r"list_bytes\s*=\s*min_t\s*\(\s*u32\s*,\s*list_bytes\s*,\s*NVME_CTRL_PAGE_SIZE\s*\)", native_builder) and
              re.search(r"if\s*\(\s*n\s*>\s*1\s*&&\s*\(\s*!sgl\s*\|\|\s*n\s*>\s*list_bytes\s*/\s*sizeof\s*\(\s*\*sgl\s*\)\s*\)\s*\)\s*return\s+-EREMOTEIO\s*;", native_builder))),
        ("NVMe command validation delegates its LBA window to family rules",
         bool(all(re.search(pattern, validate) for pattern in (
                  r"\.slba\s*=\s*bounds->window_slba\b",
                  r"\.nlb\s*=\s*bounds->window_nlb\b",
                  r"\.capacity_lbas\s*=\s*bounds->capacity_lbas\b",
                  r"\.lba_shift\s*=\s*bounds->lba_shift\b",
                  r"\.write\s*=\s*!!bounds->write\b")) and
              re.search(r"ret\s*=\s*xdev_ext_stor_window_admit\s*\(\s*&window\s*,\s*slba\s*,\s*nlb\s*,\s*bounds->data_len\s*,\s*&rw\s*\)\s*;\s*if\s*\(\s*ret\s*\)\s*return\s+ret\s*;", validate) and
              re.search(r"ret\s*=\s*xdev_ext_stor_window_check\s*\(\s*window->slba\s*,\s*window->nlb\s*,\s*slba\s*,\s*nlb\s*\)\s*;\s*if\s*\(\s*ret\s*\)\s*return\s+ret\s*;", admit))),
    ]
    print("TAP version 13")
    print(f"1..{len(checks)}")
    for index, (label, passed) in enumerate(checks, 1):
        print(f"{'ok' if passed else 'not ok'} {index} - source-only: {label}")
    return int(not all(passed for _, passed in checks))


if __name__ == "__main__":
    sys.exit(main())
