#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run the production XDOMAIN stack and NHI ring in one host execution.

MMIO, IRQ delivery, work scheduling and the link are host device boundaries.
The optional polling/batching cases are adapter configurations: production X4
still selects ordinary interrupt-driven ring APIs. No kernel or hardware runs.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURE = Path('tools/testing/selftests/xdev_ext_mech/xdomain')
NHI = Path('drivers/thunderbolt/nhi.c')


def load_local(name, path):
    """Explicit paths also work when the mutation gate runs Python with -I."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(kernel, out, case=None, sanitize=False):
    here = kernel / FIXTURE
    manifest = dict(scope='host-nhi-xdomain-composition', hardware='none',
                    kernel_execution=False, bpf_verifier=False, status='setup',
                    runtime_environment={name: os.environ.get(name) for name in (
                        'ASAN_OPTIONS', 'LSAN_OPTIONS', 'UBSAN_OPTIONS')})
    manifest_path = out / 'manifest.json'

    def save():
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')

    try:
        expected = json.loads((here / 'nhi_stack_expected.json').read_text())
        selected = [item for item in expected['cases']
                    if case is None or item['name'] == case]
        if not selected:
            raise ValueError('unknown case ' + str(case))
        sources = [here / name for name in expected['wrappers']]
        sources += [here / 'stack_nhi_cases.c']
        required = sources + [here / name for name in (
            'stack_kernel_compat.h', 'stack_nhi_compat.h', 'stack_nhi_source.py',
            'stack_test.py', 'stack_cases.c', 'stack_expected.json',
            'nhi_stack_expected.json', 'nhi_stack_test.py')]
        required += list(here.glob('stack_nhi*.h'))
        required += [kernel.parent / name for name in expected['source_units']]
        required += [kernel / 'drivers/thunderbolt/nhi_regs.h',
                     kernel / 'include/linux/thunderbolt.h']
        absent = [str(path) for path in required if not path.is_file()]
        if absent:
            raise FileNotFoundError('missing actual composition input: ' + ', '.join(absent))
        env = out / 'facade'
        load_local('nhi_stack_facade', here / 'stack_test.py').facade(kernel, env)
        generated = load_local('nhi_stack_source', here / 'stack_nhi_source.py').generate(kernel, env)
        prefix = (kernel / NHI).read_bytes().split(b'int nhi_mailbox_cmd(', 1)
        if len(prefix) != 2:
            raise ValueError('NHI ring extraction boundary is missing')
        manifest.update(
            source_units={name: sha256(kernel.parent / name)
                          for name in expected['source_units']},
            fixture_inputs={str(path.relative_to(kernel)): sha256(path)
                            for path in sorted(set(required)) if path.is_relative_to(here)},
            nhi_prefix=dict(path=str(NHI), end_before='int nhi_mailbox_cmd(',
                            sha256=hashlib.sha256(prefix[0]).hexdigest(),
                            bytes=len(prefix[0])),
            generated={path.name: sha256(path) for path in (
                env / 'stack_nhi_types.h', env / 'stack_nhi_source.inc')},
            extraction_inputs=generated,
            environment='deterministic host MMIO/IRQ/work/link boundary; no payload DMA',
        )
        try:
            head = subprocess.run(['git', '-C', str(kernel.parent), 'rev-parse', 'HEAD'],
                                  text=True, capture_output=True, timeout=10)
            manifest['checkout_head'] = head.stdout.strip() if head.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            manifest['checkout_head'] = None
        command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O0', '-g',
                   '-DSTACK_REAL_NHI', '-Wall', '-Wextra',
                   '-Werror=implicit-function-declaration', '-Wno-unused-function',
                   '-Wno-unused-parameter', '-pthread',
                   '-I', str(env), '-I', str(here), '-I', str(kernel),
                   '-idirafter', str(kernel / 'include'),
                   '-idirafter', str(kernel / 'include/uapi'),
                   '-I', str(kernel / 'tools/xdev_ext_mech')]
        if sanitize:
            command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-fno-omit-frame-pointer']
        binary = out / 'nhi-stack-cases'
        command += [str(source) for source in sources] + ['-o', str(binary)]
        manifest['compile_command'] = command
        manifest['sanitize'] = sanitize
        (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
        build = subprocess.run(command, text=True, capture_output=True, timeout=120)
        (out / 'compile.log').write_text(build.stdout + build.stderr)
        manifest['compile_exit'] = build.returncode
        if build.returncode:
            manifest['status'] = 'compile-failure'
            save()
            print('NHI_STACK_COMPILE_FAILURE: no semantic execution', flush=True)
            print(build.stdout + build.stderr, flush=True)
            return 2
        version = subprocess.run([command[0], '--version'], text=True,
                                 capture_output=True, timeout=10)
        manifest['compiler_version'] = (version.stdout.splitlines()[0]
                                        if version.returncode == 0 and version.stdout else None)
    except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
        manifest.update(status='setup-failure', error=str(error))
        save()
        print('NHI_STACK_SETUP_FAILURE: no semantic execution: ' + str(error), flush=True)
        return 2

    print('# scope=host-nhi-xdomain-composition hardware=none kernel_execution=false', flush=True)
    print('TAP version 13\n1..' + str(len(selected)), flush=True)
    records = []
    for number, item in enumerate(selected, 1):
        name = item['name']
        command = [str(binary), name, str(item['event_budget'])]
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            output, returncode = result.stdout + result.stderr, result.returncode
            marker = re.compile(r'^NHI_STACK_CASE_ASSERTIONS ' + re.escape(name) + r' ([1-9][0-9]*)$', re.M)
            found = marker.search(result.stdout)
            assertion_count = int(found[1]) if found else 0
            ok = returncode == 0 and assertion_count > 0
        except subprocess.TimeoutExpired as error:
            raw = error.stdout or b''
            output = raw.decode(errors='replace') if isinstance(raw, bytes) else raw
            output += '\nNHI_STACK_TIMEOUT: event budget/time exhausted\n'
            returncode, assertion_count, ok = 124, 0, False
        (out / (name + '.log')).write_text(output + '\nruntime_exit=' + str(returncode) + '\n')
        records.append(dict(name=name, argv=command, returncode=returncode,
                            assertions=assertion_count, status='pass' if ok else 'fail',
                            mode=item.get('mode'), log=name + '.log'))
        print(('ok ' if ok else 'not ok ') + str(number) + ' - ' + name, flush=True)
        if not ok:
            print(output + '\n# runtime_exit=' + str(returncode), flush=True)
    failed = any(item['status'] != 'pass' for item in records)
    manifest.update(status='fail' if failed else 'pass', cases=records)
    save()
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, default=HERE.parents[4])
    parser.add_argument('--keep-build', type=Path)
    parser.add_argument('--case')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.keep_build:
        args.keep_build.mkdir(parents=True, exist_ok=True)
        return execute(args.kernel.resolve(), args.keep_build.resolve(), args.case, args.sanitize)
    with tempfile.TemporaryDirectory(prefix='xdomain-nhi-stack-') as directory:
        return execute(args.kernel.resolve(), Path(directory), args.case, args.sanitize)


if __name__ == '__main__':
    raise SystemExit(main())
