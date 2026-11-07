#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual range validation/lease rules, with retained pthread OS boundaries."""
import argparse
from pathlib import Path
import re
import shlex
import sys

OS = r'''
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "io_uring/xdev_ext_mech_ce_core.h"
#include "io_uring/xdev_ext_compfam_copy_core.h"
#include "io_uring/xdev_ext_mech_ce_lease.h"
typedef __u64 u64;
typedef __u32 u32;
typedef __u8 u8;
typedef int atomic_t;
struct mutex { pthread_mutex_t raw; };
struct list_head { struct list_head *next, *prev; };
struct xdev_ext_mech_batch;
struct xdev_ext_ce_backend_ops;
struct xdev_ext_comp_copy_legacy_ops;
#define GFP_KERNEL 0
#define kvzalloc(n, flags) calloc(1, (n))
#define kvfree(p) free(p)
#define struct_size(p, field, count) (sizeof(*(p)) + sizeof((p)->field[0]) * (count))
#define container_of(p, type, field) ((type *)((char *)(p) - offsetof(type, field)))
#define __MUTEX_INITIALIZER(name) { PTHREAD_MUTEX_INITIALIZER }
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define list_for_each_entry(p, head, field) \
    for (p = container_of((head)->next, __typeof__(*p), field); \
         &(p)->field != (head); \
         p = container_of((p)->field.next, __typeof__(*p), field))
static inline void INIT_LIST_HEAD(struct list_head *h) { h->next = h->prev = h; }
static inline void list_add_tail(struct list_head *n, struct list_head *h) {
    n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n;
}
static inline void list_del(struct list_head *n) {
    n->prev->next = n->next; n->next->prev = n->prev;
}
static inline bool list_empty(const struct list_head *h) { return h->next == h; }
static inline bool fixture_warn(bool condition) { return condition; }
#define WARN_ON_ONCE(condition) fixture_warn(!!(condition))
static inline void os_check(int result) { if (result) abort(); }

/* OS scheduling only: worker really holds the domain mutex while terminal
 * starts trying to acquire it. No range or policy decision is implemented.
 */
static struct mutex *scheduled_mutex;
static bool schedule_enabled, get_has_lock, finish_ready;
static _Thread_local unsigned schedule_role;
static pthread_mutex_t coordinator = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t progress = PTHREAD_COND_INITIALIZER;
static inline void mutex_lock(struct mutex *m) {
    if (schedule_enabled && m == scheduled_mutex && schedule_role == 2) {
        os_check(pthread_mutex_lock(&coordinator));
        while (!get_has_lock) os_check(pthread_cond_wait(&progress, &coordinator));
        finish_ready = true;
        os_check(pthread_cond_broadcast(&progress));
        os_check(pthread_mutex_unlock(&coordinator));
    }
    os_check(pthread_mutex_lock(&m->raw));
    if (schedule_enabled && m == scheduled_mutex && schedule_role == 1) {
        os_check(pthread_mutex_lock(&coordinator));
        get_has_lock = true;
        os_check(pthread_cond_broadcast(&progress));
        while (!finish_ready) os_check(pthread_cond_wait(&progress, &coordinator));
        os_check(pthread_mutex_unlock(&coordinator));
    }
}
static inline void mutex_unlock(struct mutex *m) { os_check(pthread_mutex_unlock(&m->raw)); }
'''


def global_definition(text, name, reader):
    pattern = (r'(?m)^static(?:\s+const)?\s+struct\s+\w+\s+' +
               re.escape(name) + r'\s*=\s*\{')
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise ValueError('missing/ambiguous actual global ' + name)
    begin = found[0].start()
    end = reader.braced(text, text.index('{', begin))
    if text[end:].lstrip()[:1] != ';':
        raise ValueError('actual global has no final semicolon: ' + name)
    return text[begin:text.index(';', end) + 1]


def assemble(root, output, reader):
    paths = {
        'mech': 'src/core/include/linux/xdev_ext_mech.h',
        'core': 'src/core/io_uring/xdev_ext_mech.c',
        'ce': 'src/compute/io_uring/xdev_ext_mech_ce.c',
        'runtime': 'src/compute/io_uring/xdev_ext_compfam_copy.c',
        'runtime_header': 'src/compute/io_uring/xdev_ext_compfam_copy_runtime.h',
        'lease_header': 'src/compute/io_uring/xdev_ext_compfam_copy_lease.h',
        'lease': 'src/compute/io_uring/xdev_ext_compfam_copy_lease.c',
    }
    text = {key: (root / path).read_text() for key, path in paths.items()}
    selected = []
    pieces = [OS, re.sub(r'^#include[^\n]*\n', '', text['lease_header'], flags=re.M)]
    for unit, name in [('mech', 'xdev_ext_mech_frame'),
                       ('mech', 'xdev_ext_ce_region'),
                       ('runtime_header', 'xdev_ext_comp_copy_stage'),
                       ('ce', 'xdev_ext_ce_stage')]:
        pieces.append(reader.structure(text[unit], name))
    pieces.append(r'''
struct xdev_ext_mech_session { struct xdev_ext_mech_batch *batches; u32 depth; };
struct xdev_ext_mech_batch {
    struct xdev_ext_mech_session *s;
    struct xdev_ext_mech_batch *parent;
    u64 id;
    u32 nr_frames;
    struct xdev_ext_mech_frame f[XDEV_EXT_MECH_MAX_FRAMES];
};
struct xdev_ext_mech_stage {
    void *priv;
    struct xdev_ext_mech_session *s;
    u32 flags, direction;
};
''')
    functions = [
        ('core', 'xdev_ext_mech_session_depth'),
        ('core', 'xdev_ext_mech_batch_id'),
        ('core', 'xdev_ext_mech_batch_slot'),
        ('core', 'xdev_ext_mech_batch_nr_frames'),
        ('core', 'xdev_ext_mech_batch_frame'),
        ('runtime', 'xdev_ext_comp_copy_collect'),
        ('runtime', 'xdev_ext_comp_copy_stage_validate'),
        ('ce', 'xdev_ext_ce_validate'),
        ('ce', 'xdev_ext_ce_lease_key_overlap'),
        ('ce', 'xdev_ext_ce_lease_key_serial'),
    ]
    for unit, name in functions:
        pieces.append(reader.function(text[unit], name))
        selected.append(name)
    for name in ('xdev_ext_ce_lease_policy', 'xdev_ext_ce_lease_domain'):
        pieces.append(global_definition(text['ce'], name, reader))
    # Every actual lease body is included; only kernel include directives go.
    pieces.append(re.sub(r'^#include[^\n]*\n', '', text['lease'], flags=re.M))
    for name in ('xdev_ext_ce_lease_bind', 'xdev_ext_ce_batch_release',
                 'xdev_ext_ce_copy_lease_get'):
        pieces.append(reader.function(text['ce'], name))
        selected.append(name)
    (output / 'actual-range.h').write_text('\n'.join(pieces) + '\n')
    # Retained for independent review of preaccept lease-before-native order;
    # no backend is supplied to execute the later native submit path.
    (output / 'stage-submit.audit.c').write_text(reader.function(
        text['runtime'], 'xdev_ext_comp_copy_stage_submit') + '\n')
    return {'paths': paths, 'functions': selected, 'lease_bodies': 'all',
            'qualified_plan_input': True, 'native_submit_executed': False}


def main():
    from runtime_validate import load

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--keep-build', type=Path)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--suite', choices=('controls', 'validate', 'lease', 'race', 'unknown', 'all'), default='all')
    args = parser.parse_args()
    helper = load('ce_range_runner', Path(__file__).with_name('run.py'))
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
        reader = load('ce_range_actual_reader', root / 'tests/support/benchmarks/ce_vmm_contract.py')
        helper.write_json(output / 'selection.json', assemble(root, output, reader))
        receipt['reader'].update(status='completed', receipt=str(view.root / 'view.json'))
        helper.write_json(output / 'reader.json', receipt['reader'])
        compiler = shlex.split(args.cc)
        if not compiler:
            raise ValueError('empty compiler command')
        binary = output / 'range-lease'
        source = root / 'tests/compute/ce/random_target/range_lease.c'
        argv = compiler + ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                '-I' + str(output), '-I' + str(view.root / 'kernel'), str(source), '-o', str(binary)]
        if helper.invoke(argv, output, 'compile', receipt):
            return helper.finish(output, receipt, 'setup', 2)
        result = helper.invoke([str(binary), 'controls'], output, 'controls', receipt)
        if result:
            return helper.finish(output, receipt, 'control-fail' if result == 1 else 'setup',
                                 1 if result == 1 else 2)
        suites = () if args.suite == 'controls' else (
            ('validate', 'lease', 'race', 'unknown') if args.suite == 'all' else (args.suite,))
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
