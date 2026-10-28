#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""LOGIN-only business-bind requirement against the actual NHI/XDOMAIN stack.

Runs only four startup bind cases. No hardware, payload DMA, kernel execution,
BPF verifier or performance result. Exit 2 is setup error, 1 is behavioral RED,
0 is all assertions passing. Each output directory is immutable after use.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
STACK = Path('tools/testing/selftests/xdev_ext_mech/xdomain')
UNITS = (
 'io_uring/xdomain/xdev_ext_xdomain_main.c',
 'io_uring/xdomain/xdev_ext_xdomain_ring.c',
 'io_uring/xdomain/xdev_ext_xdomain_class.c',
 'io_uring/family/xdev_ext_netfam.c',
 'io_uring/family/xdev_ext_requester_retention.c',
 'tools/xdev_ext_mech/xdomain_peer.bpf.c',
 'drivers/thunderbolt/nhi.c',
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_inputs(source, out):
    """Ordinary byte copies; native paths come from the accepted layout map.

    The existing stack wrappers need their original relative include layout.
    This private, minimal closure preserves complete production source bodies.
    The unchanged upstream descriptor declaration comes from its pinned fixture.
    """
    layout = json.loads((source / 'source-layout.json').read_text())['files']
    root = out / 'source'
    kernel = root / 'kernel'
    records = {}
    for item in layout:
        src = item['source']
        native = item.get('native_path')
        selected = item.get('component') == 'linux' and native and (
            (src.startswith('src/') and src.endswith('.h')) or
            native in UNITS or
            src.startswith('tests/network/xdomain/stack/') or
            src in ['tests/network/xdomain/contracts/' + name for name in (
                'xdomain_retention_fixture.py', 'xdomain_ring_test.py',
                'xdomain_fixture.py')])
        if not selected:
            continue
        original = source / src
        target = kernel / native
        target.parent.mkdir(parents=True, exist_ok=True)
        data = original.read_bytes()
        target.write_bytes(data)
        records[str(target.relative_to(root))] = dict(
            source=src, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    # Newly added probe source may precede the layout manifest update. Keep the
    # exact production bytes in the private closure without altering the map.
    for name in ('xdev_ext_xdomain_probe_core.h', 'xdev_ext_xdomain_probe.c'):
        original = source / 'src/network/io_uring/xdomain' / name
        if original.is_file():
            target = kernel / 'io_uring/xdomain' / name
            data = original.read_bytes()
            target.write_bytes(data)
            records[str(target.relative_to(root))] = dict(
                source=str(original.relative_to(source)),
                sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    fixture = source / ('tests/support/fixtures/upstream/'
                        'linux-89be9a83ccf1f88522317ce02f854f30d6115c41/nhi_regs.h')
    target = kernel / 'drivers/thunderbolt/nhi_regs.h'
    data = fixture.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    records[str(target.relative_to(root))] = dict(
        source=str(fixture.relative_to(source)),
        sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    tests = root / 'probe'
    tests.mkdir()
    for original in sorted(HERE.iterdir()):
        if original.is_file() and original.suffix in ('.c', '.h', '.py'):
            data = original.read_bytes()
            target = tests / original.name
            target.write_bytes(data)
            records[str(target.relative_to(root))] = dict(
                source=str(original.relative_to(source)),
                sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
    missing = [name for name in UNITS if not (kernel / name).is_file()]
    if missing:
        raise ValueError('missing actual production inputs: ' + ', '.join(missing))
    (out / 'inputs.json').write_text(json.dumps(records, indent=2) + '\n')
    return kernel, tests


def run(source, out):
    manifest = dict(scope='actual-nhi-xdomain-startup-bind-contract',
                    source_root=str(source), hardware='none',
                    kernel_execution=False, payload_dma=False,
                    bpf_verifier=False, status='setup')

    def save():
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

    try:
        kernel, tests = copy_inputs(source, out)
        stack = kernel / STACK
        facade = out / 'facade'
        load('probe_stack_facade', stack / 'stack_test.py').facade(kernel, facade)
        load('probe_nhi_source', stack / 'stack_nhi_source.py').generate(kernel, facade)
        binary = out / 'probe-gate-cases'
        command = ['gcc', '-std=gnu11', '-O0', '-g', '-DSTACK_REAL_NHI',
                   '-Wall', '-Wextra', '-Werror=implicit-function-declaration',
                   '-Wno-unused-function', '-Wno-unused-parameter', '-pthread',
                   '-I', str(facade), '-I', str(stack), '-I', str(tests),
                   '-I', str(kernel), '-idirafter', str(kernel / 'include'),
                   '-idirafter', str(kernel / 'include/uapi'),
                   '-I', str(kernel / 'tools/xdev_ext_mech')]
        has_probe = (kernel / 'io_uring/xdomain/xdev_ext_xdomain_probe.c').is_file()
        if has_probe:
            boundary = (stack / 'stack_boundary.c').read_text()
            marker = '#include "stack_nhi_boundary.h"'
            if boundary.count(marker) != 1:
                raise ValueError('native recorder boundary include is missing/ambiguous')
            (tests / 'probe_stack_boundary.inc').write_text(
                boundary.replace(marker, '#include "probe_native_boundary.h"'))
            command += ['-I', str(kernel / 'io_uring/xdomain'),
                        '-include', str(tests / 'probe_extra_compat.h')]
        command += [str(tests / ('probe_transport_boundary.c' if has_probe else 'probe_boundary.c'))]
        command += [str(stack / name) for name in (
            'stack_x3.c', 'stack_x4.c', 'stack_x5.c', 'stack_family.c',
            'stack_x6.c', 'stack_nhi.c')]
        if has_probe:
            command += [str(tests / 'probe_transport_unit.c')]
        command += [str(tests / 'probe_gate_cases.c'), '-o', str(binary)]
        manifest['compile_command'] = command
        (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
        build = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / 'compile.log').write_text(build.stdout + build.stderr)
        manifest['compile_exit'] = build.returncode
        if build.returncode:
            manifest['status'] = 'compile-failure'
            save()
            print('PROBE_SETUP_FAILURE: compile failed; no semantic execution')
            return 2
    except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
        manifest.update(status='setup-failure', error=str(error))
        save()
        print('PROBE_SETUP_FAILURE: ' + str(error))
        return 2
    print('# actual NHI ring + main/ring/class/netfam/BPF; host OS/MMIO boundaries only')
    print('TAP version 13\n1..4', flush=True)
    records = []
    for number, (endpoint, direction) in enumerate(((0, 1), (0, 2), (1, 1), (1, 2)), 1):
        name = 'login_only_' + str(endpoint) + ('_tx' if direction == 1 else '_rx')
        try:
            result = subprocess.run([str(binary), str(endpoint), str(direction)],
                                    capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            status = ('pass' if result.returncode == 0 and
                      'PROBE_CASE_ASSERTIONS ' in output else
                      'fail' if result.returncode == 1 and
                      'PROBE_ASSERT: ' in output else 'setup-failure')
            returncode = result.returncode
        except subprocess.TimeoutExpired as error:
            output, returncode, status = str(error), 124, 'setup-failure'
        (out / (name + '.log')).write_text(output + '\nruntime_exit=' + str(returncode) + '\n')
        records.append(dict(name=name, endpoint=endpoint, direction=direction,
                            status=status, returncode=returncode,
                            log=name + '.log'))
        print(('ok ' if status == 'pass' else 'not ok ') + str(number) + ' - ' + name,
              flush=True)
        if status != 'pass':
            print(output, flush=True)
    setup = any(record['status'] == 'setup-failure' for record in records)
    failed = any(record['status'] == 'fail' for record in records)
    manifest.update(status='setup-failure' if setup else 'fail' if failed else 'pass',
                    cases=records)
    save()
    return 2 if setup else 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--keep-build', type=Path, required=True)
    args = parser.parse_args()
    out = args.keep_build.resolve()
    if out.exists() and any(out.iterdir()):
        print('PROBE_SETUP_FAILURE: refusing to overwrite previous evidence')
        return 2
    out.mkdir(parents=True, exist_ok=True)
    return run(args.source_root.resolve(), out)


if __name__ == '__main__':
    sys.exit(main())
