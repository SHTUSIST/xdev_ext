#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute unchanged real Thunderbolt registry functions with pthread primitives.

The fixture substitutes only external list/locking/SRCU and wire dependencies.
No registry, registration, removal, traversal or callback algorithm is replaced.
KUnit in drivers/thunderbolt/test.c separately exercises actual kernel SRCU.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
KERNEL = Path(os.environ.get('KERNEL_SRC', HERE.parents[4])).resolve()
CASES = ('callback_active_unregister_waits',
         'selected_before_callback_unregister_waits',
         'return_zero_next_handler_removed', 'data_remove_without_module_unload',
         'sleepable_callback_no_registry_mutex', 're_register_after_grace',
         'handled_and_unhandled_semantics', 'invalid_registration')


def extract(text, name, structure=False):
    # Offset-preserving comment removal prevents braces in comments changing bounds.
    clean = re.sub(r'/\*.*?\*/|//[^\n]*', lambda m: re.sub(r'[^\n]', ' ', m[0]), text, flags=re.S)
    start = (r'^struct\s+' + name + r'\s*\{' if structure else
             r'^[\w \t*]+\b' + name + r'\s*\([^;{}]*\)\s*\{')
    match = re.search(start, clean, re.M)
    if not match:
        raise AssertionError('missing real definition: ' + name)
    end, depth = match.end(), 1
    while depth:
        depth += (clean[end] == '{') - (clean[end] == '}')
        end += 1
    return text[match.start():end] + (';' if structure else '')


def source():
    upstream = Path(os.environ.get('TB_HANDLER_SOURCE', KERNEL / 'drivers/thunderbolt/xdomain.c')).read_text()
    header = Path(os.environ.get('TB_HANDLER_HEADER', KERNEL / 'include/linux/thunderbolt.h')).read_text()
    declarations = re.findall(r'^(?:static )?(?:DEFINE_MUTEX|LIST_HEAD|DEFINE_STATIC_SRCU|DEFINE_SRCU)\([^;]+;', upstream, re.M)
    declarations = [s for s in declarations if 'xdomain_lock' in s or 'protocol' in s]
    uuid = re.search(r'^static const uuid_t tb_xdp_uuid\s*=.*?;', upstream, re.M | re.S)
    if not uuid or not any('protocol_handlers' in s for s in declarations):
        raise AssertionError('missing real registry declarations')
    production = '\n'.join(declarations + [uuid[0], extract(header, 'tb_protocol_handler', True)] +
        [extract(upstream, n) for n in ('tb_register_protocol_handler',
          'tb_unregister_protocol_handler', 'tb_xdomain_handle_request')])
    return (HERE / 'tb_protocol_handler_lifetime_fixture.c.in').read_text().replace('/* PRODUCTION */', production).replace(
        '/* CASES */', (HERE / 'tb_protocol_handler_lifetime_cases.c.in').read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cases', nargs='*')
    args = parser.parse_args()
    if any(case not in CASES for case in args.cases):
        parser.error('unknown case')
    cc = shlex.split(os.environ.get('CC', 'gcc'))
    if not cc or 'clang' in Path(cc[0]).name:
        raise SystemExit('GCC required for this host fixture')
    failures = 0
    with tempfile.TemporaryDirectory(prefix='tb-handler-lifetime-') as tmp:
        src, binary = Path(tmp) / 'fixture.c', Path(tmp) / 'probe'
        src.write_text(source())
        built = subprocess.run(cc + ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-parameter', '-pthread', str(src), '-o', str(binary)],
            text=True, capture_output=True, timeout=30)
        if built.returncode:
            print('COMPILE ERROR: not a behavior RED\n' + built.stdout + built.stderr)
            return 2
        for case in args.cases or CASES:
            try:
                ran = subprocess.run([str(binary), case], text=True, capture_output=True, timeout=8)
                print(ran.stdout + ran.stderr, end='')
                if ran.returncode:
                    failures += 1
                    print('not ok - ' + case + ' (exit ' + str(ran.returncode) + ')')
                else:
                    print('ok - ' + case)
            except subprocess.TimeoutExpired:
                failures += 1
                print('not ok - ' + case + ' (bounded subprocess timeout)')
    print(f'{len(args.cases or CASES)} cases, {failures} failures')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
