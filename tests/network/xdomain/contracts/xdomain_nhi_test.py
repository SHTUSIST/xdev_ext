#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual NHI ring source with external IRQ/work/MMIO primitives.

--legacy-normal-free maps the new API call to the old tb_ring_free for an
explicit historical unsafe baseline. It never supplies a retirement body.
"""
import argparse
from pathlib import Path
HERE = Path(__file__).resolve().parent
import subprocess
import sys
import tempfile
from xdomain_ring_test import no_includes, declaration
from xdomain_fixture import definition


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--kernel', type=Path, default=HERE.parents[4])
    p.add_argument('--legacy-normal-free', action='store_true')
    p.add_argument('--keep-build', type=Path)
    a = p.parse_args()
    k = a.kernel.resolve()
    here = Path(__file__).resolve().parent
    names = ['drivers/thunderbolt/nhi.c', 'drivers/thunderbolt/nhi_regs.h',
             'include/linux/thunderbolt.h']
    missing = [n for n in names if not (k/n).is_file()]
    if missing:
        print('# SETUP_MISSING: ' + ', '.join(missing))
        return 2
    source = (k/names[0]).read_text()
    if 'void tb_ring_free_quarantined(' not in source and not a.legacy_normal_free:
        print('# SETUP_MISSING_API: tb_ring_free_quarantined; no behavioral RED')
        return 2
    header = (k/names[2]).read_text()
    # Entire real ring section: no replaced local helpers or filtered bodies.
    ring = no_includes(source[:source.index('int nhi_mailbox_cmd(')])
    unit = ((here/'xdomain_nhi_compat.h').read_text() + '\n' +
            declaration(header, 'enum ring_desc_flags') +
            no_includes((k/names[1]).read_text()) + '\n' +
            declaration(header, 'struct tb_nhi') +
            declaration(header, 'struct tb_ring') +
            declaration(header, 'struct tb_ring_snapshot') +
            'typedef void (*ring_cb)(struct tb_ring *, struct ring_frame *, bool);\n' +
            declaration(header, 'struct ring_frame') +
            '#define RING_FLAG_FRAME BIT(1)\n#define RING_FLAG_E2E BIT(2)\n#define RING_FLAG_NO_SUSPEND BIT(0)\n#define RING_FLAG_NO_INTERRUPT BIT(3)\n' +
            (here/'xdomain_nhi_boundaries.c').read_text() + ring + '\n' +
            definition(source, 'nhi_interrupt_work') + '\n' +
            definition(source, 'nhi_msi') + '\n')
    if a.legacy_normal_free:
        print('# HISTORICAL_BASELINE: new API calls use actual old tb_ring_free; no new-helper verdict', flush=True)
        unit += '#define tb_ring_free_quarantined tb_ring_free\n'
    unit += (here/'xdomain_nhi_cases.c').read_text()
    with tempfile.TemporaryDirectory(prefix='xdomain-nhi-') as d:
        c, b = Path(d)/'nhi.c', Path(d)/'nhi'
        c.write_text(unit)
        if a.keep_build:
            a.keep_build.mkdir(parents=True, exist_ok=True)
            (a.keep_build/'nhi-unit.c').write_text(unit)
        cmd = ['gcc', '-std=gnu11', '-O0', '-g', '-Wall', '-Wextra',
               '-Wno-unused-function', '-Wno-unused-parameter', '-Wno-unused-variable',
               '-Werror=implicit-function-declaration', '-pthread', str(c), '-o', str(b)]
        build = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if build.returncode:
            print('# SETUP_COMPILE_ERROR; not behavioral RED\n' + build.stdout + build.stderr)
            return 2
        count = int(subprocess.check_output([str(b), '--count'], text=True))
        print(f'TAP version 13\n1..{count}', flush=True)
        failures = 0
        for i in range(1, count+1):
            try:
                run = subprocess.run([str(b), str(i)], timeout=15)
            except subprocess.TimeoutExpired:
                failures += 1
                print(f'not ok {i} - timeout waiting for software barrier', flush=True)
                continue
            if run.returncode:
                failures += 1
                print(f'not ok {i} - NHI runtime assertion (exit {run.returncode})', flush=True)
        return int(failures != 0)

if __name__ == '__main__':
    sys.exit(main())
