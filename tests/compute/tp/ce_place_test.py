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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    root = a.source_root.resolve()
    out = (a.output or Path(tempfile.mkdtemp(prefix='tp-ce-place-'))).resolve()
    out.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(root / 'tools'))
    from layout import load_layout, materialize_view
    layout = load_layout(root)
    view = materialize_view(root, out / 'source-view').root
    kernel = view / 'kernel'
    test = view / layout.logical('tests/benchmarks/tp/test_tp_ce_bpf.c')
    command = [*shlex.split(os.environ.get('CC', 'cc')), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
               '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
               '-I' + str(kernel / 'tools/testing/selftests/xdev_ext_mech/cref/host'),
               '-I' + str(kernel), '-I' + str(kernel / 'tools/xdev_ext_mech'), '-I' + str(test.parent),
               str(test), '-o', str(out / 'test_tp_ce_bpf')]
    print('+', shlex.join(command), flush=True)
    if subprocess.run(command).returncode:
        print('SETUP: compile failed (not a behaviour result)')
        return 2
    return subprocess.run([str(out / 'test_tp_ce_bpf')]).returncode


if __name__ == '__main__':
    raise SystemExit(main())
