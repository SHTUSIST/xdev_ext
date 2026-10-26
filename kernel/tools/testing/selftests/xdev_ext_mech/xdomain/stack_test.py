#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Exercise complete production X3/X4/X5/family/X6 with recording boundaries.

The independent expected set is frozen in stack_expected.json. Missing wrappers
are an initial missing-composition RED, never a semantic mutation result.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def facade(kernel, directory):
    """Only environmental headers are facaded; project definitions stay real."""
    paths = list((kernel / 'io_uring/xdomain').glob('*.[ch]'))
    paths += [kernel / 'io_uring/family/xdev_ext_netfam.c']
    paths += list((kernel / 'include/linux').glob('xdev_ext*.h'))
    paths += list((kernel / 'tools/xdev_ext_mech').glob('*.[ch]'))
    names = set()
    for path in paths:
        if not path.is_file():
            continue
        for name in re.findall(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', path.read_text(), re.M):
            if name.startswith(('linux/', 'asm/', 'bpf/')) and 'xdev_ext' not in name:
                # Preserve real UAPI scalar layouts; their host headers exist.
                if name in ('linux/types.h', 'linux/const.h', 'linux/ioctl.h', 'asm/types.h', 'linux/if_xdp.h'):
                    continue
                names.add(name)
    names.update({'vmlinux.h', 'asm/page.h', 'linux/module.h', 'linux/pci.h',
                  'linux/pm.h', 'linux/random.h', 'linux/slab.h', 'linux/sysfs.h',
                  'linux/uuid.h', 'linux/atomic.h', 'linux/bitmap.h', 'linux/kref.h',
                  'linux/list.h', 'linux/mutex.h', 'linux/spinlock.h',
                  'linux/thunderbolt.h', 'linux/workqueue.h', 'linux/compiler.h',
                  'linux/container_of.h', 'linux/errno.h', 'linux/limits.h',
                  'linux/overflow.h', 'linux/jiffies.h', 'linux/ktime.h',
                  'linux/string.h', 'linux/export.h', 'linux/crc32.h',
                  'linux/dma-mapping.h', 'linux/dma-direction.h',
                  'bpf/bpf_helpers.h', 'bpf/bpf_tracing.h'})
    for name in names:
        dest = directory / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text('/* kernel environment facade, no production bodies */\n')


def execute(kernel, out, case=None, sanitize=False):
    expected = json.loads((HERE / 'stack_expected.json').read_text())
    sources = [HERE / name for name in expected['wrappers']] + [HERE / 'stack_cases.c']
    absent = [str(p) for p in sources + [HERE / 'stack_kernel_compat.h'] if not p.is_file()]
    absent += [str(kernel.parent / p) for p in expected['source_units'] if not (kernel.parent / p).is_file()]
    if absent:
        print('STACK_MISSING_COMPOSITION_RED: actual stack has not executed', flush=True)
        for p in absent:
            print('missing: ' + p, flush=True)
        return 2
    env = out / 'facade'
    facade(kernel, env)
    binary = out / 'stack-cases'
    command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O0', '-g',
               '-Wall', '-Wextra', '-Werror=implicit-function-declaration',
               '-Wno-unused-function', '-Wno-unused-parameter', '-pthread',
               '-I', str(env), '-I', str(HERE), '-I', str(kernel),
               '-I', str(kernel / 'include'), '-I', str(kernel / 'include/uapi'),
               '-I', str(kernel / 'tools/xdev_ext_mech')]
    if sanitize:
        command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    command += [str(s) for s in sources] + ['-o', str(binary)]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    build = subprocess.run(command, text=True, capture_output=True, timeout=120)
    (out / 'compile.log').write_text(build.stdout + build.stderr)
    if build.returncode:
        print('STACK_COMPILE_FAILURE: no semantic execution', flush=True)
        print(build.stdout + build.stderr, flush=True)
        return 2
    selected = [c for c in expected['cases'] if case is None or c['name'] == case]
    if not selected:
        raise ValueError('unknown case ' + str(case))
    print('TAP version 13\n1..' + str(len(selected)), flush=True)
    failed = False
    for number, item in enumerate(selected, 1):
        try:
            result = subprocess.run([str(binary), item['name'], str(item['event_budget'])],
                                    text=True, capture_output=True, timeout=30)
            (out / (item['name'] + '.log')).write_text(result.stdout + result.stderr + '\nruntime_exit=' + str(result.returncode) + '\n')
            # Success must come from the independent assertion driver, with all
            # frozen assertions counted. A wrapper case-name printer cannot pass.
            marker = 'STACK_CASE_ASSERTIONS ' + item['name'] + ' '
            semantic = any(line.startswith(marker) and int(line[len(marker):]) > 0
                           for line in result.stdout.splitlines())
            ok = result.returncode == 0 and semantic
            print(('ok ' if ok else 'not ok ') + str(number) + ' - ' + item['name'], flush=True)
            if not ok:
                print(result.stdout + result.stderr + '\n# runtime_exit=' + str(result.returncode), flush=True)
                failed = True
        except subprocess.TimeoutExpired:
            print('not ok ' + str(number) + ' - ' + item['name'] + ' event budget/time exhausted', flush=True)
            failed = True
    return int(failed)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kernel', type=Path, default=HERE.parents[4])
    parser.add_argument('--keep-build', type=Path)
    parser.add_argument('--case')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.keep_build:
        args.keep_build.mkdir(parents=True, exist_ok=True)
        return execute(args.kernel.resolve(), args.keep_build.resolve(), args.case, args.sanitize)
    with tempfile.TemporaryDirectory(prefix='xdomain-actual-stack-') as temp:
        return execute(args.kernel.resolve(), Path(temp), args.case, args.sanitize)


if __name__ == '__main__':
    sys.exit(main())
