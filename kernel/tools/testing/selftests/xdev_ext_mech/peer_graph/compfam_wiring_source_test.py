#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Text-only check of compute class hook wiring; no runtime or DMA claim.

F9a introduces the contract only. F9b-F9f each add their own class entry.
"""
from pathlib import Path
import re
import sys

KERNEL = Path(__file__).resolve().parents[5]
JOINED = []  # (class name, kernel-relative file, hooks object)


def main():
    for class_name, path, hooks_name in JOINED:
        text = (KERNEL / path).read_text()
        # Comments cannot satisfy a class initializer's wiring requirement.
        text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
        if not re.search(r"\.fam\s*\.comp\s*=\s*&\s*" +
                         re.escape(hooks_name) + r"\b", text):
            print(f"not ok - {class_name} lacks compute hooks", file=sys.stderr)
            return 1
    print(f"ok - compute family wiring ({len(JOINED)} classes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
