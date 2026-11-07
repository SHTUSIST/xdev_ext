#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual paired BPF builders: controls first, behavior1 versus SETUP2."""
import argparse
from pathlib import Path
import re
import shlex
import sys


def assemble(root, output):
    paths = {
        'paired-callback.bpf.c': 'examples/storage/nvme_ce_request.bpf.c',
        'nvme_ce_request.h': 'examples/storage/nvme_ce_request.h',
        'xdev_ext_mech_prog.h': 'src/bpf/xdev_ext_mech_prog.h',
        'xdev_ext_mech_kfunc.h': 'src/bpf/xdev_ext_mech_kfunc.h',
    }
    for name, path in paths.items():
        (output / name).write_bytes((root / path).read_bytes())
    ops_path = 'src/core/include/linux/xdev_ext_mech.h'
    ops = (root / ops_path).read_text()
    macros = re.findall(r'(?m)^#define XDEV_EXT_MECH_OPS_TYPE\(name\)[\s\S]*?(?=\n\n)', ops)
    if len(macros) != 1:
        raise ValueError('actual project ops macro is not unique')
    (output / 'vmlinux.h').write_text('''\
#ifndef RANDOM_REQUEST_BUILDERS_HOST_VMLINUX_H
#define RANDOM_REQUEST_BUILDERS_HOST_VMLINUX_H
#include <stdbool.h>
#include <stddef.h>
#include "include/uapi/linux/if_xdp.h"
#include "include/uapi/linux/xdev_ext_mech.h"
''' + macros[0] + '''
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_nvme_mech_ops);
XDEV_EXT_MECH_OPS_TYPE(xdev_ext_ce_mech_ops);
#endif
''')
    host = root / 'tests/compute/ce/reference/host/bpf'
    (output / 'bpf').mkdir()
    (output / 'bpf/bpf_tracing.h').write_bytes((host / 'bpf_tracing.h').read_bytes())
    (output / 'bpf/bpf_helpers.h').write_text((host / 'bpf_helpers.h').read_text() + '''
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define BPF_MAP_TYPE_HASH 1
#define BPF_F_RDONLY_PROG (1U << 7)
void *bpf_map_lookup_elem(const void *map, const void *key);
''')
    return {'paths': paths, 'ops_declaration': ops_path,
            'host_transport': str(host.relative_to(root)),
            'callbacks': ['request_ce_prepare', 'request_nvme_prepare',
                          'request_ce_build', 'request_ce_complete',
                          'request_nvme_build', 'request_nvme_complete'],
            'actual_paired_object': True,
            'test_source': 'tests/compute/ce/random_target/request_builders.c',
            'additional_test_source': 'tests/compute/ce/random_target/request_prepare.c',
            'boundary': 'held map/info/scratch only; no native backend or lease'}


def main():
    from runtime_validate import load

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--keep-build', type=Path)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--suite', choices=('controls', 'prepare', 'targets', 'writes', 'all'), default='all')
    args = parser.parse_args()
    helper = load('random_request_builder_runner', Path(__file__).with_name('run.py'))
    output = None
    receipt = {'schema': 1, 'status': 'setup', 'suite': args.suite,
               'commands': [], 'exit_code': None}
    try:
        root = helper.source_root(args.source_root)
        output = helper.build_directory(root, args.keep_build)
        receipt.update(canonical_root=str(root), build_directory=str(output),
                       reader={'status': 'started', 'view': str(output / 'view')})
        helper.write_json(output / 'run.json', receipt)
        sys.path.insert(0, str(root / 'tools'))
        from layout import materialize_view
        view = materialize_view(root, output / 'view')
        helper.write_json(output / 'selection.json', assemble(root, output))
        receipt['reader'].update(status='completed', receipt=str(view.root / 'view.json'))
        helper.write_json(output / 'reader.json', receipt['reader'])
        compiler = shlex.split(args.cc)
        if not compiler:
            raise ValueError('empty compiler command')
        binary = output / 'request-builders'
        source = root / 'tests/compute/ce/random_target/request_builders.c'
        command = compiler + ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                             '-I' + str(output), '-I' + str(view.root / 'kernel'),
                             str(source), '-o', str(binary)]
        if helper.invoke(command, output, 'compile', receipt):
            return helper.finish(output, receipt, 'setup', 2)
        result = helper.invoke([str(binary), 'controls'], output, 'controls', receipt)
        if result:
            return helper.finish(output, receipt, 'control-fail' if result == 1 else 'setup',
                                 1 if result == 1 else 2)
        if args.suite in ('prepare', 'all'):
            prepare_binary = output / 'request-prepare'
            prepare_source = root / 'tests/compute/ce/random_target/request_prepare.c'
            prepare_command = compiler + ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                                         '-I' + str(output), '-I' + str(view.root / 'kernel'),
                                         str(prepare_source), '-o', str(prepare_binary)]
            if helper.invoke(prepare_command, output, 'compile-prepare', receipt):
                return helper.finish(output, receipt, 'setup', 2)
            result = helper.invoke([str(prepare_binary)], output, 'prepare', receipt)
            if result:
                return helper.finish(output, receipt, 'control-fail' if result == 1 else 'setup',
                                     1 if result == 1 else 2)
        suites = () if args.suite in ('controls', 'prepare') else (
            ('targets', 'writes') if args.suite == 'all' else (args.suite,))
        failed = False
        for suite in suites:
            result = helper.invoke([str(binary), suite], output, suite, receipt)
            if result not in (0, 1):
                return helper.finish(output, receipt, 'setup', 2)
            failed |= result == 1
        return helper.finish(output, receipt, 'failed' if failed else 'passed', 1 if failed else 0)
    except Exception as error:
        print('SETUP: ' + str(error), file=sys.stderr)
        if output is not None:
            receipt.update(status='setup', exit_code=2, error=str(error))
            if receipt.get('reader', {}).get('status') == 'started':
                receipt['reader'].update(status='setup-error', error=str(error))
            helper.write_json(output / 'reader.json', receipt.get('reader', {}))
            helper.write_json(output / 'run.json', receipt)
        return 2


if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        print('SETUP: ' + str(error), file=sys.stderr)
        code = 2
    raise SystemExit(code)
