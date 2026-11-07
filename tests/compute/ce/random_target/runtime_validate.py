#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Selected actual CE runtime/owner functions; SETUP2 is never behavioral RED."""
import argparse
import importlib.util
from pathlib import Path
import shlex
import sys


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assemble(root, output, reader):
    paths = {
        'mech': 'src/core/include/linux/xdev_ext_mech.h',
        'core': 'src/core/io_uring/xdev_ext_mech.c',
        'ce': 'src/compute/io_uring/xdev_ext_mech_ce.c',
        'runtime': 'src/compute/io_uring/xdev_ext_compfam_copy.c',
        'runtime_header': 'src/compute/io_uring/xdev_ext_compfam_copy_runtime.h',
        'lease_header': 'src/compute/io_uring/xdev_ext_compfam_copy_lease.h',
    }
    text = {name: (root / path).read_text() for name, path in paths.items()}
    actual = [r'''
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_compfam_copy_core.h"
#include "io_uring/xdev_ext_mech_lifecycle.h"
typedef __u64 u64;
typedef __u32 u32;
typedef __u8 u8;
typedef int atomic_t;
#define PAGE_SHIFT 12
#define BIT(n) (1U << (n))
#define READ_ONCE(value) __atomic_load_n(&(value), __ATOMIC_ACQUIRE)
#define smp_load_acquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
struct list_head { struct list_head *next, *prev; };
struct xdev_ext_ce_backend_ops;
struct xdev_ext_comp_copy_legacy_ops;
struct xdev_ext_comp_copy_lease_domain;
struct xdev_ext_comp_copy_lease_group;
''']
    for unit, name in [('mech', 'xdev_ext_mech_frame'),
                       ('mech', 'xdev_ext_ce_region'),
                       ('mech', 'xdev_ext_ce_xfer'),
                       ('lease_header', 'xdev_ext_comp_copy_lease_region'),
                       ('runtime_header', 'xdev_ext_comp_copy_stage'),
                       ('ce', 'xdev_ext_ce_stage')]:
        actual.append(reader.structure(text[unit], name) + '\n')
    # Metadata projections only. All readers, claims and ownership decisions
    # below are actual function bytes; no device or backend is fabricated.
    actual.append(r'''
struct xdev_ext_mech_batch;
struct fixture_pool_ops { void (*sync_for_cpu)(void); };
struct xdev_ext_mech_session {
    struct xdev_ext_mech_batch *batches;
    struct xdev_ext_mech_life *life;
    struct { u32 first_page_off, frame_size, capabilities;
             const struct fixture_pool_ops *ops; } pool;
    struct { u32 state; } ss;
};
struct xdev_ext_mech_batch {
    struct xdev_ext_mech_session *s;
    struct xdev_ext_mech_batch *parent;
    u64 id, ticket;
    u32 nr_frames, life_active;
    u64 life_token[XDEV_EXT_MECH_MAX_FRAMES];
    struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
    struct xdev_ext_mech_completion completion;
};
struct xdev_ext_mech_stage { void *priv; u32 flags; };
''')
    selected = [
        ('core', 'xdev_ext_mech_batch_id'),
        ('core', 'xdev_ext_mech_batch_slot'),
        ('core', 'xdev_ext_mech_batch_nr_frames'),
        ('core', 'xdev_ext_mech_batch_frame'),
        ('core', 'xdev_ext_mech_batch_frame_claim'),
        ('runtime', 'xdev_ext_comp_copy_collect'),
        ('runtime', 'xdev_ext_comp_copy_stage_validate'),
        ('runtime', 'xdev_ext_comp_copy_claim'),
        ('core', 'xdev_ext_mech_batch_copy_owner_valid'),
        ('core', 'xdev_ext_mech_batch_ce_owners_valid'),
        ('ce', 'xdev_ext_ce_validate'),
    ]
    for unit, name in selected:
        actual.append(reader.function(text[unit], name) + '\n')
    (output / 'actual.h').write_text('\n'.join(actual))
    return {'paths': paths, 'functions': selected}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--keep-build', type=Path)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--suite', choices=('controls', 'mode', 'owners', 'all'), default='all')
    args = parser.parse_args()
    helper = load('ce_random_stage1_runner', Path(__file__).with_name('run.py'))
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
        reader = load('ce_random_actual_reader', root / 'tests/support/benchmarks/ce_vmm_contract.py')
        helper.write_json(output / 'selection.json', assemble(root, output, reader))
        receipt['reader'].update(status='completed', receipt=str(view.root / 'view.json'))
        helper.write_json(output / 'reader.json', receipt['reader'])
        binary = output / 'runtime-validate'
        source = root / 'tests/compute/ce/random_target/runtime_validate.c'
        compiler = shlex.split(args.cc)
        if not compiler:
            raise ValueError('empty compiler command')
        command = compiler + ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(output), '-I' + str(view.root / 'kernel'), str(source), '-o', str(binary)]
        if helper.invoke(command, output, 'compile', receipt):
            return helper.finish(output, receipt, 'setup', 2)
        result = helper.invoke([str(binary), 'controls'], output, 'controls', receipt)
        if result:
            return helper.finish(output, receipt, 'control-fail' if result == 1 else 'setup',
                                 1 if result == 1 else 2)
        suites = () if args.suite == 'controls' else (('mode', 'owners') if args.suite == 'all' else (args.suite,))
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
