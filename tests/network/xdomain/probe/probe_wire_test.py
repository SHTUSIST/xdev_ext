#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent fixed-wire codec contract; absent APIs are blocked, never RED."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def execute(source, out):
    manifest = dict(scope='startup-challenge-pure-wire-contract', status='setup',
                    hardware='none', kernel_execution=False, payload_dma=False)

    def save():
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

    try:
        probe_header = source / 'src/network/io_uring/xdomain/xdev_ext_xdomain_probe_core.h'
        if not probe_header.is_file():
            manifest.update(status='blocked', error='production codec API is absent')
            save()
            print('PROBE_WIRE_BLOCKED: production codec API is absent; no behavioral RED')
            return 2
        spec = importlib.util.spec_from_file_location('probe_input_copy', HERE / 'probe_gate_test.py')
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        kernel, tests = fixture.copy_inputs(source, out)
        target_header = kernel / 'io_uring/xdomain/xdev_ext_xdomain_probe_core.h'
        shutil.copyfile(probe_header, target_header)
        records = json.loads((out / 'inputs.json').read_text())
        data = target_header.read_bytes()
        records['kernel/io_uring/xdomain/xdev_ext_xdomain_probe_core.h'] = dict(
            source=str(probe_header.relative_to(source)),
            sha256=fixture.hashlib.sha256(data).hexdigest(), bytes=len(data))
        vectors = tests / 'vectors'
        vectors.mkdir()
        for original in sorted((HERE / 'vectors').glob('*.bin')):
            target = vectors / original.name
            shutil.copyfile(original, target)
            data = target.read_bytes()
            records['probe/vectors/' + original.name] = dict(
                source=str(original.relative_to(source)),
                sha256=fixture.hashlib.sha256(data).hexdigest(), bytes=len(data))
        (out / 'inputs.json').write_text(json.dumps(records, indent=2) + '\n')
        binary = out / 'probe-wire-cases'
        command = ['gcc', '-std=gnu11', '-O0', '-g', '-Wall', '-Wextra', '-Werror',
                   '-I', str(target_header.parent), str(tests / 'probe_wire_cases.c'),
                   '-o', str(binary)]
        manifest['compile_command'] = command
        (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
        build = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (out / 'compile.log').write_text(build.stdout + build.stderr)
        manifest['compile_exit'] = build.returncode
        if build.returncode:
            manifest.update(status='compile-failure')
            save()
            print('PROBE_WIRE_SETUP_FAILURE: compile failure; no behavioral RED')
            return 2
        result = subprocess.run([str(binary), str(vectors)], capture_output=True,
                                text=True, timeout=30)
        output = result.stdout + result.stderr
        (out / 'wire.log').write_text(output + '\nruntime_exit=' + str(result.returncode) + '\n')
        status = ('pass' if result.returncode == 0 and 'PROBE_WIRE_ASSERTIONS ' in output
                  else 'fail' if result.returncode == 1 and 'PROBE_WIRE_ASSERT ' in output
                  else 'setup-failure')
        manifest.update(status=status, runtime_exit=result.returncode)
        save()
        print('TAP version 13\n1..1')
        print(('ok' if status == 'pass' else 'not ok') + ' 1 - fixed_startup_wire')
        print(output, end='')
        return 0 if status == 'pass' else 1 if status == 'fail' else 2
    except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
        manifest.update(status='setup-failure', error=str(error))
        save()
        print('PROBE_WIRE_SETUP_FAILURE: ' + str(error))
        return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--keep-build', required=True, type=Path)
    args = parser.parse_args()
    out = args.keep_build.resolve()
    if out.exists() and any(out.iterdir()):
        print('PROBE_WIRE_SETUP_FAILURE: refusing to overwrite previous evidence')
        return 2
    out.mkdir(parents=True, exist_ok=True)
    return execute(args.source_root.resolve(), out)


if __name__ == '__main__':
    sys.exit(main())
