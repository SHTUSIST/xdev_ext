#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""XDOMAIN RX -> CE TARGET_RANGE on the rings' IOU_UMEM Host frames.

The shared XDOMAIN host-check runner supplies --source-root and --output;
all remaining arguments retain the common chain runner's meaning.
"""
import sys

import run

if __name__ == '__main__':
    sys.argv[1:1] = ['--pool', 'host', '--receiver', 'ce']
    raise SystemExit(run.main())
