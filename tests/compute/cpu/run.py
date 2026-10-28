#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run every host test of the BPF compute callback; exit 0 only when all pass.

Runs each *_test.py of this directory with $CC (default cc) for the fixtures
and prints one TAP line per test file. A skipped unittest case counts as a
failure. No kernel, guest or BPF program is involved; see
Documentation/userspace-api/xdev_ext-compute.rst for the guest run.
"""
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def main():
    results = []
    for test in sorted(HERE.glob('*_test.py')):
        run = subprocess.run([sys.executable, str(test)], cwd=HERE, text=True,
                             capture_output=True, timeout=600)
        output = run.stdout + run.stderr
        print(output, end='')
        skipped = re.search(r'skipped=|\.\.\. skipped', output)
        results.append((test.name, run.returncode or bool(skipped)))
    for index, (name, code) in enumerate(results, 1):
        print(('ok' if not code else 'not ok') + f' {index} - compute {name}')
    print(f'1..{len(results)}')
    failed = sum(1 for _, code in results if code)
    print(f'XDEV_EXT_COMPUTE_HOST={"FAIL" if failed or not results else "PASS"} '
          f'files={len(results)} failed={failed}')
    return 1 if failed or not results else 0


if __name__ == '__main__':
    sys.exit(main())
