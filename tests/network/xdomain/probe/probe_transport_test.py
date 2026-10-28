#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run actual LOGIN/main/ring/probe/class/NHI with scratch-only link delivery."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute(source, out):
    manifest = dict(scope='actual-startup-probe-main-ring-class-nhi-contract',
                    status='setup', hardware='none', kernel_execution=False,
                    business_payload_dma=False, scratch_link_boundary=True)

    def save():
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

    try:
        fixture = load('probe_transport_inputs', HERE / 'probe_gate_test.py')
        kernel, tests = fixture.copy_inputs(source, out)
        records = json.loads((out / 'inputs.json').read_text())
        for name in ('xdev_ext_xdomain_probe_core.h', 'xdev_ext_xdomain_probe.c'):
            original = source / 'src/network/io_uring/xdomain' / name
            target = kernel / 'io_uring/xdomain' / name
            data = original.read_bytes()
            target.write_bytes(data)
            records[str(target.relative_to(out / 'source'))] = dict(
                source=str(original.relative_to(source)),
                sha256=fixture.hashlib.sha256(data).hexdigest(), bytes=len(data))
        (out / 'inputs.json').write_text(json.dumps(records, indent=2) + '\n')
        stack = kernel / fixture.STACK
        boundary = (stack / 'stack_boundary.c').read_text()
        marker = '#include "stack_nhi_boundary.h"'
        if boundary.count(marker) != 1:
            raise ValueError('existing native boundary include must occur exactly once')
        # Only the test boundary include changes. Production bytes stay exact.
        (tests / 'probe_stack_boundary.inc').write_text(
            boundary.replace(marker, '#include "probe_native_boundary.h"'))
        facade = out / 'facade'
        load('probe_transport_facade', stack / 'stack_test.py').facade(kernel, facade)
        load('probe_transport_nhi_source', stack / 'stack_nhi_source.py').generate(kernel, facade)
        binary = out / 'probe-transport-cases'
        command = ['gcc', '-std=gnu11', '-O0', '-g', '-DSTACK_REAL_NHI',
                   '-Wall', '-Wextra', '-Werror=implicit-function-declaration',
                   '-Wno-unused-function', '-Wno-unused-parameter', '-pthread',
                   '-I', str(facade), '-I', str(stack), '-I', str(tests),
                   '-I', str(kernel / 'io_uring/xdomain'), '-I', str(kernel),
                   '-idirafter', str(kernel / 'include'),
                   '-idirafter', str(kernel / 'include/uapi'),
                   '-I', str(kernel / 'tools/xdev_ext_mech'),
                   '-include', str(tests / 'probe_extra_compat.h')]
        command += [str(tests / 'probe_transport_boundary.c')]
        command += [str(stack / name) for name in (
            'stack_x3.c', 'stack_x4.c', 'stack_x5.c', 'stack_family.c',
            'stack_x6.c', 'stack_nhi.c')]
        command += [str(tests / name) for name in (
            'probe_transport_unit.c', 'probe_transport_cases.c')]
        command += ['-o', str(binary)]
        manifest['compile_command'] = command
        (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
        build = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / 'compile.log').write_text(build.stdout + build.stderr)
        manifest['compile_exit'] = build.returncode
        if build.returncode:
            manifest['status'] = 'compile-failure'
            save()
            print('PROBE_TRANSPORT_SETUP_FAILURE: compile failed; no semantic execution')
            return 2
    except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
        manifest.update(status='setup-failure', error=str(error))
        save()
        print('PROBE_TRANSPORT_SETUP_FAILURE: ' + str(error))
        return 2
    names = ('happy', 'held_callbacks', 'held_done', 'held_ping_tx', 'held_pong_tx',
             'short_rx', 'overrun_rx', 'pattern_valid_crc', 'nonce_valid_crc',
             'early_remove', 'unknown_remove', 'unknown_repeated_stop', 'failure_budget',
             'canceled_rx_diagnostic')
    print('TAP version 13\n1..' + str(len(names)), flush=True)
    records = []
    for number, name in enumerate(names, 1):
        try:
            result = subprocess.run([str(binary), name], capture_output=True,
                                    text=True, timeout=30)
            output, code = result.stdout + result.stderr, result.returncode
            status = ('pass' if code == 0 and 'PROBE_TRANSPORT_ASSERTIONS ' in output
                      else 'fail' if code == 1 and 'PROBE_TRANSPORT_ASSERT: ' in output
                      else 'setup-failure')
        except subprocess.TimeoutExpired as error:
            output, code, status = str(error), 124, 'setup-failure'
        (out / (name + '.log')).write_text(output + '\nruntime_exit=' + str(code) + '\n')
        records.append(dict(name=name, status=status, returncode=code,
                            log=name + '.log'))
        print(('ok ' if status == 'pass' else 'not ok ') + str(number) + ' - ' + name,
              flush=True)
        if status != 'pass': print(output, flush=True)
    setup = any(record['status'] == 'setup-failure' for record in records)
    fail = any(record['status'] == 'fail' for record in records)
    manifest.update(status='setup-failure' if setup else 'fail' if fail else 'pass',
                    cases=records)
    save()
    return 2 if setup else 1 if fail else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--keep-build', required=True, type=Path)
    args = parser.parse_args()
    out = args.keep_build.resolve()
    if out.exists() and any(out.iterdir()):
        print('PROBE_TRANSPORT_SETUP_FAILURE: refusing to overwrite previous evidence')
        return 2
    out.mkdir(parents=True, exist_ok=True)
    return execute(args.source_root.resolve(), out)


if __name__ == '__main__':
    sys.exit(main())
