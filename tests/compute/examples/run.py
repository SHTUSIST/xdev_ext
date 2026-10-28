#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run every host test of the BPF compute examples; exit 0 only when all pass.

1. compute_examples_host_test.c, built twice with $CC (default cc): once with
   the bytewise CRC32C table (-DEX_CRC32C_SLICE8=0) and once with the
   slice-by-8 tables (-DEX_CRC32C_SLICE8=1).
2. every *_test.py of this directory, with $CC for its fixtures.
Prints one TAP line per step. A skipped unittest case counts as a failure.
No kernel, guest, BPF compiler or BPF program is involved; the guest run is
examples_kvm.sh (see tools/xdev_ext_mech/examples/compute/README.md).
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = HERE.parents[4]
EXAMPLES = KERNEL / 'tools/xdev_ext_mech/examples/compute'


def run(command, cwd=None):
    try:
        done = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=600)
        return done.returncode, done.stdout + done.stderr
    except subprocess.TimeoutExpired:
        return 124, 'timeout after 600 seconds\n'


def host_test(build, slice8):
    binary = build / f'host_test_{"slice8" if slice8 else "bytewise"}'
    cc = shlex.split(os.environ.get('CC', 'cc'))
    command = cc + ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=undefined', '-fno-sanitize-recover=all',
                    f'-DEX_CRC32C_SLICE8={int(slice8)}', '-I' + str(KERNEL),
                    '-I' + str(HERE.parent), '-I' + str(EXAMPLES),
                    str(HERE / 'compute_examples_host_test.c'), '-o', str(binary)]
    code, output = run(command)
    output = 'COMMAND ' + shlex.join(command) + '\n' + output
    if code:
        return code, output
    code, out = run([str(binary)])
    return code, output + out


def main():
    results = []
    with tempfile.TemporaryDirectory(prefix='xdev-ext-compute-examples-') as name:
        build = Path(name)
        for slice8 in (False, True):
            code, output = host_test(build, slice8)
            print(output, end='')
            results.append((f'host test {"slice-by-8" if slice8 else "bytewise"}', code))
    for test in sorted(HERE.glob('*_test.py')):
        code, output = run([sys.executable, str(test)], cwd=HERE)
        print(output, end='')
        skipped = re.search(r'skipped=|\.\.\. skipped', output)
        results.append((test.name, code or bool(skipped)))
    for index, (name, code) in enumerate(results, 1):
        print(('ok' if not code else 'not ok') + f' {index} - compute examples {name}')
    print(f'1..{len(results)}')
    failed = sum(1 for _, code in results if code)
    print(f'XDEV_EXT_COMPUTE_EXAMPLES_HOST={"FAIL" if failed or not results else "PASS"} '
          f'steps={len(results)} failed={failed}')
    return 1 if failed or not results else 0


if __name__ == '__main__':
    sys.exit(main())
