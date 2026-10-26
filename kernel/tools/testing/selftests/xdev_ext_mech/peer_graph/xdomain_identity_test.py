#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Frozen X1 K06–K09 using actual invoke/call_of/call and generic views.

No identity-success shim. A missing protocol envelope is an explicit RED boundary.
"""
import argparse
import sys
from xdomain_fixture import build_and_run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syntax-only", action="store_true")
    args = parser.parse_args()
    try:
        build_and_run(("K06", "K07", "K08", "K09"), args.syntax_only)
    except (AssertionError, OSError) as error:
        print("not ok - X1 identity fixture: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
