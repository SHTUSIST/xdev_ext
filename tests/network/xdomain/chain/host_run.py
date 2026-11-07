#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""The chain cases on the ring's IOU_UMEM host pages: run.py --pool host.

The shared XDOMAIN host runner (tools/ci/check_xdomain_host.py) passes only
--source-root and --output to an entry point, so host-page mode has this
entry point of its own.  Every other argument is passed to run.py unchanged.
"""
import sys

import run

if __name__ == '__main__':
    sys.argv[1:1] = ['--pool', 'host']
    raise SystemExit(run.main())
