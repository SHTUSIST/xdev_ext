#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Source-only contract checks. These do not prove registration behavior.

The behavioral companion family/class_register_test.py executes registration.
"""
from pathlib import Path
import re
import subprocess
import sys

KERNEL = Path(__file__).resolve().parents[5]


def without_comments(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def block(text, marker):
    match = re.search(marker, text)
    if not match:
        return ""
    begin = text.find("{", match.end())
    depth = 0
    for end in range(begin, len(text)):
        depth += (text[end] == "{") - (text[end] == "}")
        if depth == 0:
            return text[begin + 1:end]
    return ""


def main():
    mech = without_comments((KERNEL / "include/linux/xdev_ext_mech.h").read_text())
    ops = without_comments((KERNEL / "io_uring/xdev_ext_mech_ops.c").read_text())
    contract = block(mech, r"struct\s+xdev_ext_mech_class_ops\s*(?=\{)")
    hdr = block(mech, r"struct\s+xdev_ext_family_hooks_hdr\s*(?=\{)")
    registration = block(ops, r"int\s+xdev_ext_mech_class_register\s*\([^;]+?\)\s*(?=\{)")
    union = re.search(r"union\s*\{([^{}]*)\}\s*fam\s*;\s*$", contract, re.S)
    members = union.group(1) if union else ""
    checks = [
        ("family header declares u32 family", bool(re.search(r"\bu32\s+family\s*;", hdr))),
        ("class contract ends with family hooks union", bool(union)),
    ]
    for name, member in (("hdr", "hdr"), ("net", "net"),
                         ("stor", "stor"), ("comp", "comp")):
        typename = f"xdev_ext_{name}_hooks" if name != "hdr" else "xdev_ext_family_hooks_hdr"
        checks.append((f"family union carries {member} pointer",
                       bool(re.search(rf"\bconst\s+struct\s+{typename}\s*\*\s*{member}\s*;", members))))
        if name != "hdr":
            checks.append((f"{name} hook type is forward declared",
                           bool(re.search(rf"\bstruct\s+{typename}\s*;", mech))))
    checks.append(("registration calls family compatibility rule",
                   bool(re.search(r"\bxdev_ext_family_hooks_ok\s*\(\s*ops\s*->\s*class_id\b", registration))))
    for index, (label, passed) in enumerate(checks, 1):
        print(f"{'ok' if passed else 'not ok'} {index} - source-only: {label}")
    print("# behavioral registration fixture (separate from source-only checks)", flush=True)
    behavior = subprocess.run([sys.executable, str(KERNEL / "tools/testing/selftests/xdev_ext_mech/family/class_register_test.py")])
    return int(not all(passed for _, passed in checks) or behavior.returncode != 0)


if __name__ == "__main__":
    sys.exit(main())
