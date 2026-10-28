#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""API §6: actual private kfuncs + actual sealed call wrapper, GCC/UBSan host only.

Extraction selects real production functions and their local callees. Kernel
scheduling/CPU/task primitives come from the established XDOMAIN environment;
no project identity, validator or kfunc is replaced. Compile failures are SETUP.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'source-layout.json').is_file())
CASES = ('abi-normalize', 'early-copy', 'envelope', 'identity', 'cross-class-member', 'parallel-identity', 'nested-identity',
         'v1-early', 'shared-verdict', 'new-actions', 'malformed', 'sizes', 'no-backing', 'inactive')


def assemble(root, out):
    entries = json.loads((root / 'source-layout.json').read_text())['files']
    native = {e['native_path']: root / e['source'] for e in entries
              if e.get('component') == 'linux'}
    kernel = out / 'inputs'
    pending = ['io_uring/xdev_ext_mech.c', 'io_uring/xdev_ext_mech_ops.c',
               'io_uring/xdev_ext_mech_internal.h', 'io_uring/xdev_ext_mech_xdomain_kfunc.c',
               'include/linux/xdev_ext_mech.h', 'tools/xdev_ext_mech/xdev_ext_mech_kfunc.h',
               'io_uring/xdev_ext_mech_core.h',
               'io_uring/xdev_ext_mech_cpu_core.h']
    copied = {}
    includes = re.compile(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]', re.M)
    while pending:
        name = pending.pop()
        if name in copied:
            continue
        source = native[name]
        data = source.read_bytes()
        target = kernel / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        copied[name] = str(source.relative_to(root))
        for include in includes.findall(data.decode()):
            for candidate in (os.path.normpath(str(Path(name).parent / include)),
                              include, 'include/' + include, 'include/uapi/' + include):
                if candidate in native:
                    pending.append(candidate)
                    break
    (out / 'source-units.json').write_text(json.dumps(copied, indent=2) + '\n')
    return kernel


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, action='append')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        kernel = assemble(args.source_root.resolve(), args.output)
        fixture_path = args.source_root / 'tests/network/xdomain/contracts/xdomain_fixture.py'
        spec = importlib.util.spec_from_file_location('real_xdomain_fixture', fixture_path)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        fixture.KERNEL = kernel
        fixture.PRIVATE = kernel / 'io_uring/xdev_ext_mech_xdomain_kfunc.c'
        original_closure = fixture.closure

        def closure(source, roots):
            if roots == ('bpf_xdev_ext_xdomain_info', 'bpf_xdev_ext_xdomain_verdict'):
                roots += ('bpf_xdev_ext_xdomain_info_v2', 'bpf_xdev_ext_xdomain_verdict_v2')
            return original_closure(source, roots)

        fixture.closure = closure
        declarations = fixture.declarations(False)
        public = (kernel / 'tools/xdev_ext_mech/xdev_ext_mech_kfunc.h').read_text()
        for name in ('bpf_xdev_ext_xdomain_info_v2', 'bpf_xdev_ext_xdomain_verdict_v2'):
            prototype = re.search(r'extern\s+int\s+' + name + r'\s*\([^;{}]+\)\s*__ksym\s*;', public)
            if not prototype:
                raise AssertionError('missing public declaration: ' + name)
            declarations += '\n' + prototype.group().replace('__ksym', '')
        environment = (fixture_path.parent / 'xdomain_fixture.c.in').read_text()
        code = environment.replace('/* PRODUCTION */', declarations + '\n' + fixture.production())
        legacy = (fixture_path.parent / 'xdomain_cases.c.in').read_text()
        legacy = legacy.replace('int main(int argc, char **argv)', 'static int legacy_main(int argc, char **argv)')
        code = code.replace('/* CASES */', legacy + '\n' + (HERE / 'kfunc_cases.c.in').read_text())
        source = args.output / 'fixture.c'
        source.write_text(code)
        compiler = shlex.split(os.environ.get('CC', 'gcc'))
        if not compiler or 'clang' in Path(compiler[0]).name:
            raise AssertionError('GCC required')
        binary = args.output / 'probe'
        command = compiler + ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                              '-Wno-unused-function', '-Wno-unused-parameter', '-pthread',
                              '-fsanitize=undefined', '-fno-sanitize-recover=undefined',
                              '-I' + str(kernel), str(source), '-o', str(binary)]
        (args.output / 'build-command.json').write_text(json.dumps(command, indent=2) + '\n')
        built = subprocess.run(command, capture_output=True, text=True, timeout=45)
        (args.output / 'build.log').write_text(built.stdout + built.stderr)
        if built.returncode:
            raise AssertionError('production-slice compile failed: ' + built.stderr)
    except (AssertionError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        print('SETUP: ' + str(error), file=sys.stderr)
        return 2
    failed = 0
    execution_failed = 0
    results = []
    for name in args.case or CASES:
        try:
            run = subprocess.run([str(binary), name], capture_output=True, text=True, timeout=15)
            text = run.stdout + run.stderr
            (args.output / (name + '.log')).write_text(text)
            status = 'PASS' if run.returncode == 0 else 'FAIL' if run.returncode > 0 else 'EXECUTION_FAILURE'
            results.append({'case': name, 'status': status, 'exit_code': run.returncode})
            if run.returncode < 0:
                execution_failed += 1
                print('EXECUTION FAILURE (signal): ' + name + ':\n' + text, file=sys.stderr)
            elif run.returncode:
                failed += 1
                print('FAIL ' + name + ':\n' + text, file=sys.stderr)
            else:
                print(text, end='')
        except subprocess.TimeoutExpired:
            execution_failed += 1
            results.append({'case': name, 'status': 'EXECUTION_FAILURE', 'reason': 'timeout'})
            print('EXECUTION FAILURE (timeout): ' + name, file=sys.stderr)
    (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'{len(args.case or CASES)} cases, {failed} failures, {execution_failed} execution failures; host private-kfunc/envelope only')
    return 2 if execution_failed else int(bool(failed))


if __name__ == '__main__':
    sys.exit(main())
