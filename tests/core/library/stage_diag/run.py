#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Independent op11 normal-library/ctl conformance; inject external syscalls."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source-root', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--libbpf-build', type=Path)
    a = p.parse_args()
    test = Path(__file__).resolve().parent
    root = a.source_root.resolve()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('stage_diag_layout', root / 'tools/layout.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    layout = module.load_layout(root)
    view = out / 'view'
    inputs = []
    for source, logical in layout.by_source.items():
        if logical.startswith('kernel/') and (source.endswith('.h') or source in (
                'src/lib/xdev_ext_session.c', 'src/lib/xdev_ext_link.c',
                'src/cli/xdev_ext_mech_ctl.c', 'src/cli/xdev_ext_xsk_redirect.c',
                'src/cli/xdev_ext_gpu_identity.c')):
            dst = view / logical
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / source, dst)
            inputs.append(source)
    (out / 'inputs.json').write_text(json.dumps({'canonical_root': str(root), 'inputs': inputs}, indent=2) + '\n')
    kernel = view / 'kernel'
    lib = kernel / 'tools/xdev_ext_mech/lib'
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-I', str(kernel),
             '-I', str(lib), '-I', str(kernel / 'tools/xdev_ext_mech')]
    if a.libbpf_build:
        flags += ['-I', str(a.libbpf_build / 'include')]
    bpf_link = str(a.libbpf_build / 'libbpf.a') if a.libbpf_build else '-lbpf'
    cc = os.environ.get('CC', 'gcc')
    commands = [
        [cc, *flags, str(test / 'test.c'), str(lib / 'xdev_ext_session.c'), '-o', str(out / 'test')],
        [cc, *flags, str(kernel / 'tools/xdev_ext_mech/xdev_ext_mech_ctl.c'),
         str(lib / 'xdev_ext_link.c'), str(lib / 'xdev_ext_session.c'),
         str(kernel / 'tools/xdev_ext_xsk_redirect.c'), str(kernel / 'tools/xdev_ext_gpu_identity.c'),
         str(test / 'ctl_hooks.c'), '-Wl,--wrap=syscall', bpf_link,
         '-lelf', '-lz', '-ldl', '-o', str(out / 'ctl')],
        [cc, *flags, str(test / 'deadline.c'), str(lib / 'xdev_ext_link.c'),
         str(lib / 'xdev_ext_session.c'), str(kernel / 'tools/xdev_ext_xsk_redirect.c'),
         str(kernel / 'tools/xdev_ext_gpu_identity.c'), '-Wl,--wrap=syscall',
         '-Wl,--wrap=clock_gettime', '-Wl,--wrap=poll', bpf_link,
         '-lelf', '-lz', '-ldl', '-o', str(out / 'deadline')]]
    verdict = {'classification': 'postimplementation-independent-conformance',
               'scope': 'normal op11 lib/ctl with external syscall replies; no kernel queue/lock/hardware/performance proof',
               'build_exit': 0, 'test_exit': None, 'ctl': []}

    def save():
        (out / 'verdict.json').write_text(json.dumps(verdict, indent=2) + '\n')

    with (out / 'build.log').open('w') as log:
        for command in commands:
            log.write('+ ' + ' '.join(command) + '\n')
            log.flush()
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                verdict['build_exit'] = result.returncode
                save()
                print('SETUP: compile/link failure:', out / 'build.log')
                return 2
    result = subprocess.run([str(out / 'test')], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=20)
    (out / 'tap.log').write_text(result.stdout)
    print(result.stdout, end='')
    verdict['test_exit'] = result.returncode
    failed = bool(result.returncode)
    result = subprocess.run([str(out / 'deadline')], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=20)
    (out / 'deadline.log').write_text(result.stdout)
    print(result.stdout, end='')
    verdict['deadline_exit'] = result.returncode
    verdict['deadline_scope'] = 'direct real ctl_wait/ctl_wait_coarse function boundary with real lib query; no reachable normal CLI XDOMAIN START/wait campaign exists'
    failed |= bool(result.returncode)
    fd = os.eventfd(0, os.EFD_CLOEXEC)
    try:
        for name, change, omit in [('valid', {}, None), ('unsupported', {'DIAG_UNSUPPORTED': '1'}, None),
                                   ('bad-schema', {'DIAG_BAD_SCHEMA': '1'}, None),
                                   ('missing-ring', {}, '--ring-fd'), ('missing-session', {}, '--session'),
                                   ('missing-stage', {}, '--stage')]:
            pairs = [('--ring-fd', str(fd)), ('--session', str(0x123456789abc)), ('--stage', '2')]
            command = [str(out / 'ctl'), 'peer-diag']
            for key, value in pairs:
                if key != omit:
                    command += [key, value]
            env = dict(os.environ)
            env.pop('DIAG_UNSUPPORTED', None)
            env.pop('DIAG_BAD_SCHEMA', None)
            env.update(change)
            result = subprocess.run(command, env=env, pass_fds=(fd,), text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
            (out / ('ctl-' + name + '.log')).write_text(result.stdout)
            errors = []
            if name == 'valid':
                if result.returncode:
                    errors.append('valid query failed')
                for value in [f'HOOK fd={fd} op=11', f'HOOK id={0x123456789abc} stage=2',
                              'native_inflight=7', 'software_pending=8', 'ack_owed=9']:
                    if value not in result.stdout:
                        errors.append('missing ' + value)
            elif result.returncode == 0:
                errors.append('invalid/unsupported query reported success')
            if name != 'valid' and any(word in result.stdout.lower() for word in ('qualified', 'established')):
                errors.append('failure printed qualified/established')
            if omit and 'HOOK ' in result.stdout:
                errors.append('missing required identity reached kernel boundary')
            if not omit and result.stdout.count('op=11') != 1:
                errors.append('query did not make exactly one op11 attempt')
            verdict['ctl'].append({'name': name, 'exit': result.returncode, 'errors': errors})
            print(('not ok' if errors else 'ok') + ' - ctl ' + name + ': ' + ('; '.join(errors) or 'contract'))
            failed |= bool(errors)
    finally:
        os.close(fd)
    save()
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
