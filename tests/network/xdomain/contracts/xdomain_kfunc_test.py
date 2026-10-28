#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Frozen X1 K01–K05/K10; real private kfuncs and sealed invocation.

The separate boundary fixture executes actual private/class/member filters
and XDOMAIN helper resolver. X7 still owns actual BPF verification/attachment.
"""
import argparse
import sys
from xdomain_fixture import KERNEL, PRIVATE, build_and_run
from xdomain_boundary import build_boundary
import re


def check_built_in_plumbing():
    """Static build/BTF inventory only; verifier behavior is checked in X7."""
    unit = PRIVATE.read_text()
    make = (KERNEL / "io_uring/Makefile").read_text()
    if not re.search(r"obj-\$\(CONFIG_XDEV_EXT_MECH\)\s*\+=[^\n]*\bxdev_ext_mech_xdomain_kfunc\.o\b", make):
        raise AssertionError("private kfunc object is not built with CONFIG_XDEV_EXT_MECH")
    for kind, name in (("struct", "xdev_ext_xdomain_proto_info"),
                       ("struct", "xdev_ext_xdomain_proto_verdict"),
                       ("enum", "xdev_ext_xdomain_proto_event"),
                       ("enum", "xdev_ext_xdomain_proto_action"),
                       ("enum", "xdev_ext_mech_callsite")):
        if not re.search(r"\bBTF_TYPE_EMIT\(\s*" + kind + r"\s+" + name + r"\s*\)", unit):
            raise AssertionError("missing explicit built-in BTF emission: " + name)
    header = (KERNEL / "tools/xdev_ext_mech/xdev_ext_mech_kfunc.h").read_text()
    patterns = (
        r"\bbpf_xdev_ext_xdomain_info\s*\(\s*const\s+struct\s+xdev_ext_mech_ctx\s*\*\s*\w*\s*,\s*void\s*\*\s*\w*\s*,\s*(?:__u32|u32)\s+\w+__sz\b",
        r"\bbpf_xdev_ext_xdomain_verdict\s*\(\s*const\s+struct\s+xdev_ext_mech_ctx\s*\*\s*\w*\s*,\s*const\s+void\s*\*\s*\w*\s*,\s*(?:__u32|u32)\s+\w+__sz\b",
    )
    for pattern in patterns:
        if not re.search(pattern, header, re.S):
            raise AssertionError("missing void-buffer/__sz BPF declaration: " + pattern)
    print("SOURCE_INVENTORY_ONLY: built-in object, explicit BTF emissions and sized-buffer prototypes present")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syntax-only", action="store_true")
    args = parser.parse_args()
    try:
        build_and_run(("K01", "K02", "K03", "K04", "K05", "K10"), args.syntax_only)
        build_boundary(args.syntax_only)
        if not args.syntax_only:
            check_built_in_plumbing()
    except (AssertionError, OSError) as error:
        print("not ok - X1 private kfunc fixture: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
