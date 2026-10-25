#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run every host test of stage polling; exit 0 only when all pass.

Compiles poll_rules_test.c with $CC (default cc) under UBSan, then runs each
*_test.py of this directory. Prints one TAP line per test program.
"""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = Path(os.environ.get('KERNEL_SRC', HERE.parents[4])).resolve()


def main():
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    results = []
    with tempfile.TemporaryDirectory(prefix='xdev-ext-poll-rules-') as temporary:
        binary = Path(temporary) / 'poll_rules_test'
        build = subprocess.run(compiler + ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                                           '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                                           '-I' + str(KERNEL), str(HERE / 'poll_rules_test.c'),
                                           '-o', str(binary)], text=True, capture_output=True)
        if build.returncode:
            print(build.stdout + build.stderr, end='')
            results.append(('poll_rules_test.c', 1))
        else:
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=60)
            print(run.stdout + run.stderr, end='')
            results.append(('poll_rules_test.c', run.returncode))
    for test in sorted(HERE.glob('*_test.py')):
        run = subprocess.run([sys.executable, str(test)], cwd=HERE, text=True, capture_output=True,
                             timeout=600)
        print(run.stdout + run.stderr, end='')
        results.append((test.name, run.returncode))
    for index, (name, code) in enumerate(results, 1):
        print(('ok' if not code else 'not ok') + f' {index} - poll {name}')
    print(f'1..{len(results)}')
    return 1 if any(code for _, code in results) else 0


if __name__ == '__main__':
    sys.exit(main())
