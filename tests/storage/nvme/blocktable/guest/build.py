#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Build-only entrypoint for actual guest blocktable acceptance; never opens a device."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'source-layout.json').is_file())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--vmlinux-h', type=Path)
    parser.add_argument('--libbpf-build', type=Path, required=True,
                        help='modern libbpf directory containing include/ and libbpf.a')
    parser.add_argument('--libbpf-archive', type=Path,
                        help='optional explicit archive when it is outside the include directory')
    parser.add_argument('--driver-only', action='store_true')
    args = parser.parse_args()
    root = args.source_root.resolve()
    out = args.output.resolve()
    try:
        out.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        print('SETUP_ERROR fresh output required:', error, file=sys.stderr)
        return 2
    result = {'state': 'SETUP_ERROR', 'exit': 2, 'runtime_executed': False,
              'performance': False, 'commands': []}
    try:
        spec = importlib.util.spec_from_file_location('blocktable_layout', root / 'tools/layout.py')
        layout = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = layout
        spec.loader.exec_module(layout)
        native = out / 'headers'
        for (component, name), source in layout.load_layout(root).by_native.items():
            if component == 'linux' and name.endswith('.h'):
                target = native / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((root / source).read_bytes())
        libbpf = args.libbpf_build.resolve()
        archive = args.libbpf_archive.resolve() if args.libbpf_archive else libbpf / 'libbpf.a'
        if not (libbpf / 'include/bpf/libbpf.h').is_file() or not archive.is_file():
            raise RuntimeError('modern libbpf include/bpf/libbpf.h and libbpf.a required')
        common = ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror']
        commands = [common + ['-fsanitize=undefined', '-fno-sanitize-recover=all',
                              str(HERE / 'oracle_test.c'), '-o', str(out / 'oracle-selfcheck')],
                    [str(out / 'oracle-selfcheck')],
                    common + ['-I' + str(native), '-I' + str(root / 'examples/storage'),
                              '-I' + str(libbpf / 'include'), str(HERE / 'driver.c'),
                              str(archive), '-lelf', '-lz',
                              *shlex.split(os.environ.get('LDFLAGS', '')),
                              '-o', str(out / 'blocktable-native')]]
        if not args.driver_only:
            if not args.vmlinux_h or not args.vmlinux_h.is_file():
                raise RuntimeError('genuine target --vmlinux-h required; no synthetic BTF supplied')
            include = out / 'include'
            include.mkdir()
            shutil.copyfile(args.vmlinux_h, include / 'vmlinux.h')
            commands.append([os.environ.get('BPF_CLANG', 'clang'), '-target', 'bpf',
                             '-D__TARGET_ARCH_x86', '-O2', '-g', '-Wall', '-Werror',
                             '-I' + str(include), '-I' + str(root / 'src/bpf'),
                             '-I' + str(libbpf / 'include'), '-I/usr/include/x86_64-linux-gnu',
                             '-c', str(root / 'examples/storage/nvme_blocktable.bpf.c'),
                             '-o', str(out / 'nvme_blocktable.bpf.o')])
        for index, command in enumerate(commands):
            child = subprocess.run(command, capture_output=True, text=True, timeout=180)
            (out / f'command-{index}.log').write_text(child.stdout + child.stderr)
            result['commands'].append({'argv': command, 'exit': child.returncode})
            if child.returncode:
                raise RuntimeError(f'command {index} failed: {child.stdout}{child.stderr}')
        files = [HERE / name for name in ('driver.c', 'oracle.h', 'oracle_test.c', 'build.py')]
        files += [root / 'examples/storage' / name for name in ('nvme_blocktable.bpf.c', 'nvme_blocktable.h')]
        result['inputs'] = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in files}
        result['outputs'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in (out / 'blocktable-native', out / 'nvme_blocktable.bpf.o')
                             if path.is_file()}
        result.update(state='DRIVER_BUILD_ONLY' if args.driver_only else 'BPF_AND_DRIVER_BUILD_ONLY', exit=0)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result['error'] = str(error)
        print('SETUP_ERROR:', error, file=sys.stderr)
    (out / 'build-result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('state=' + result['state'] + ' runtime_executed=false performance_claim=none')
    return result['exit']


if __name__ == '__main__':
    raise SystemExit(main())
