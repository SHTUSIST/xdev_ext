#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""TP host-frame copy-engine placement program: tests/benchmarks/tp/
test_tp_ce_bpf.c runs tp_ce_place.bpf.c as host C against the production CE
window validators. No verifier, device or timing evidence."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def endpoint_objects(root, view, layout, out, *, mutant=False):
    """Link the real placement implementation under session boundaries."""
    lib = (view / layout.logical('src/lib/libxdev_ext.h')).parent
    endpoint = lib / 'xdev_ext_frame_endpoint.c'
    if mutant:
        source = endpoint.read_text()
        anchor = '(sequence % (e->window_bytes / e->group_bytes)) * e->group_bytes;'
        if source.count(anchor) != 1:
            raise RuntimeError('placement mutant anchor is not unique')
        endpoint = out / 'placement-mutant.c'
        endpoint.write_text(source.replace(anchor, anchor + '\n\t*offset += 64;', 1))
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-I' + str(lib)]
    flags += ['-Dxdev_ext_frame_endpoint_' + name + '=tp_actual_endpoint_' + name
              for name in ('place', 'post', 'wait')]
    fixture = view / layout.logical('tests/core/library/frame_endpoint_test.c')
    flags += ['-DTP_ENDPOINT_TEST_SOURCE="' + str(fixture) + '"']
    objects = []
    with (out / ('placement-mutant-compile.log' if mutant else 'placement-compile.log')).open('w') as log:
        for i, source in enumerate((endpoint, root / 'tests/compute/tp/placement_contract_boundary.c')):
            obj = out / ('placement-%s-%d.o' % ('mutant' if mutant else 'real', i))
            command = [*shlex.split(os.environ.get('CC', 'gcc')), *flags, '-c', str(source), '-o', str(obj)]
            log.write(shlex.join(command) + '\n'); log.flush()
            if subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode:
                raise RuntimeError('placement contract compilation failed; not semantic RED')
            objects.append(str(obj))
    return objects


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path)
    p.add_argument('--source-view', type=Path, help='reuse one validated source view serially')
    a = p.parse_args()
    root = a.source_root.resolve()
    out = (a.output or Path(tempfile.mkdtemp(prefix='tp-ce-place-'))).resolve()
    out.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(root / 'tools'))
    from layout import load_layout, materialize_view
    layout = load_layout(root)
    view = materialize_view(root, a.source_view or out / 'source-view').root
    kernel = view / 'kernel'
    test = view / layout.logical('tests/benchmarks/tp/test_tp_ce_bpf.c')
    try:
        objects = endpoint_objects(root, view, layout, out)
    except (OSError, RuntimeError) as error:
        print('SETUP: ' + str(error))
        return 2
    command = [*shlex.split(os.environ.get('CC', 'cc')), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
               '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
               '-pthread',
               '-I' + str(kernel / 'tools/testing/selftests/xdev_ext_mech/cref/host'),
               '-I' + str(kernel), '-I' + str(kernel / 'tools/xdev_ext_mech'), '-I' + str(test.parent),
               str(test), *objects, '-o', str(out / 'test_tp_ce_bpf')]
    print('+', shlex.join(command), flush=True)
    if subprocess.run(command).returncode:
        print('SETUP: compile failed (not a behaviour result)')
        return 2
    if subprocess.run([str(out / 'test_tp_ce_bpf')]).returncode:
        return 1
    try:
        mutant_objects = endpoint_objects(root, view, layout, out, mutant=True)
    except (OSError, RuntimeError) as error:
        print('SETUP: ' + str(error))
        return 2
    mutant_command = command[:-len(objects)-2] + mutant_objects + ['-o', str(out / 'placement-mutant')]
    if subprocess.run(mutant_command).returncode:
        return 2
    result = subprocess.run([str(out / 'placement-mutant')], capture_output=True, text=True)
    (out / 'placement-mutant.log').write_text(result.stdout + result.stderr + '\nexit=%d\n' % result.returncode)
    detected = result.returncode == 1 and 'endpoint placement equals independently expected offset' in result.stderr
    print('PLACEMENT_MUTANT=' + ('DETECTED' if detected else 'MISSED'))
    return 0 if detected else 1


if __name__ == '__main__':
    raise SystemExit(main())
