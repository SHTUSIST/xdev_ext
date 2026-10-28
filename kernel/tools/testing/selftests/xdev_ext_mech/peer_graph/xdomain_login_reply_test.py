#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent reply association tests: real main TU plus real TB matcher.
Only environment includes and the external request transport are substituted.
The transport runs real matching and copies the exact delivered wire packet.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
from xdomain_login_test import strip_includes
from xdomain_retention_fixture import retention_unit
from xdomain_fixture import definition


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument('--kernel', type=Path, default=here.parents[4])
    parser.add_argument('--save-unit', type=Path)
    args = parser.parse_args()
    kernel = args.kernel.resolve()
    compat = (here / 'xdomain_login_compat.h').read_text()
    bounds = (here / 'xdomain_login_boundaries.c').read_text()
    # Replace exactly this external boundary; every other boundary is reused.
    old = definition(bounds, 'tb_xdomain_request')
    bounds = bounds.replace(old, '')
    matcher_env = '''
#define TB_CFG_PKG_ERROR 99
struct tb_cfg_request { const void *request; size_t response_size; };
struct ctl_pkg { struct { unsigned int eof, size; } frame; const void *buffer; };
struct tb_xdp_header { struct { u32 route_hi, route_lo, length_sn; } xd_hdr; uuid_t uuid; };
'''
    matcher = definition((kernel / 'drivers/thunderbolt/xdomain.c').read_text(), 'tb_xdomain_match')
    source = kernel / 'io_uring/xdomain'
    cases = (here / 'xdomain_login_reply_cases.c').read_text()
    declarations, bodies = cases.split('/* MAIN_TU_BEFORE_CASES */')
    unit = (compat + '\nstatic unsigned long jiffies;\n'
            '#define time_before(a,b) ((long)((a)-(b))<0)\n'
            '#define min_t(t,a,b) ((t)(a)<(t)(b)?(t)(a):(t)(b))\n'
            '#include "io_uring/xdomain/xdev_ext_xdomain_core.h"\n'
            + strip_includes((source / 'xdev_ext_xdomain.h').read_text())
            + matcher_env + matcher + '\n' + bounds + retention_unit(kernel)
            + declarations + '\n'
            + strip_includes((source / 'xdev_ext_xdomain_main.c').read_text())
            + bodies)
    if args.save_unit:
        args.save_unit.write_text(unit)
    with tempfile.TemporaryDirectory(prefix='xdomain-login-reply-') as td:
        cpath, binary = Path(td) / 'reply.c', Path(td) / 'reply'
        cpath.write_text(unit)
        build = subprocess.run(['gcc', '-std=gnu11', '-O0', '-g', '-Wall', '-Wextra',
                                '-Wno-unused-parameter', '-Wno-unused-variable', '-Wno-unused-function',
                                '-Werror=implicit-function-declaration', '-I', str(kernel),
                                str(cpath), '-o', str(binary)], capture_output=True, text=True, timeout=60)
        if build.returncode:
            print('# SETUP_COMPILE_ERROR, not behavioral RED\n' + build.stdout + build.stderr)
            return 2
        count = int(subprocess.check_output([str(binary), '--count'], text=True))
        print(f'TAP version 13\n1..{count}', flush=True)
        failures = 0
        for i in range(1, count + 1):
            run = subprocess.run([str(binary), str(i)], timeout=30)
            failures += bool(run.returncode)
            if run.returncode < 0:
                print(f'not ok {i} - signal {-run.returncode}', flush=True)
        print(f'# {count - failures} passed, {failures} failed', flush=True)
        return int(bool(failures))


if __name__ == '__main__':
    raise SystemExit(main())
