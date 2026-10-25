#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check that the USER class is wired into every place a class needs.

The host has no kernel build, so this reads the production sources: the
build rule, the struct_ops type and its registration, the core's stage
binding (no file reference for USER), the register sub-op dispatch, the
class table (no ->poll, no ordering flag), the user stage fd operations,
the trivial BPF program and the CI step.  Prints TAP.
"""
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
KERNEL = Path(os.environ.get('KERNEL_SRC', HERE.parents[4])).resolve()
ROOT = KERNEL.parent


def text(path):
    try:
        return (ROOT / path).read_text()
    except OSError:
        return ''


def function(source, name):
    match = re.search(r'^\w[^;{}]*\b' + name + r'\([^;{}]*\)\n\{\n.*?^\}', source, re.M | re.S)
    return match[0] if match else ''


def main():
    make = text('kernel/io_uring/Makefile')
    linux = text('kernel/include/linux/xdev_ext_mech.h')
    ops = text('kernel/io_uring/xdev_ext_mech_ops.c')
    core = text('kernel/io_uring/xdev_ext_mech.c')
    internal = text('kernel/io_uring/xdev_ext_mech_internal.h')
    user = text('kernel/io_uring/xdev_ext_mech_user.c')
    tools = text('kernel/tools/xdev_ext_mech/Makefile')
    prog = text('kernel/tools/xdev_ext_mech/user_plan.bpf.c')
    ci = text('.github/workflows/host.yml')
    table = re.search(r'struct xdev_ext_mech_class_ops xdev_ext_user_class = \{(.*?)\n\};', user, re.S)
    table = table[1] if table else ''
    bind = function(core, 'xdev_ext_mech_session_bind')
    base = function(core, 'xdev_ext_mech_base')
    register = function(core, 'io_xdev_ext_mech_register')
    release = function(user, 'xdev_ext_user_release')
    mmap = function(user, 'xdev_ext_user_mmap')
    checks = [
        ('built with the mechanism layer, no separate option',
         re.search(r'^obj-\$\(CONFIG_XDEV_EXT_MECH\) \+=.*\bxdev_ext_mech_user\.o\b', make, re.M)),
        ('struct_ops type xdev_ext_user_mech_ops', 'XDEV_EXT_MECH_OPS_TYPE(xdev_ext_user_mech_ops);' in linux),
        ('struct_ops definition bound to class 10',
         re.search(r'XDEV_EXT_MECH_STRUCT_OPS\(user, XDEV_EXT_MECH_CLASS_USER,', ops)),
        ('type listed for the kfunc filter and BTF lookup', '&bpf_xdev_ext_user_mech_ops,' in ops),
        ('class id resolves to the type',
         re.search(r'case XDEV_EXT_MECH_CLASS_USER:\s*return &bpf_xdev_ext_user_mech_ops;', ops)),
        ('type registered at init',
         re.search(r'register_bpf_struct_ops\(&bpf_xdev_ext_user_mech_ops,\s*xdev_ext_user_mech_ops\)', ops)),
        ('descriptor type in vmlinux BTF', 'BTF_TYPE_EMIT(struct xdev_ext_user_desc);' in ops),
        ('core keeps no file reference for a USER stage',
         re.search(r'class_id != XDEV_EXT_MECH_CLASS_CPU &&\s*st->class_id != XDEV_EXT_MECH_CLASS_USER', bind)),
        ('program ctx base: common metadata', 'case XDEV_EXT_MECH_CLASS_USER:' in base),
        ('register sub-op dispatched',
         re.search(r'case XDEV_EXT_MECH_OP_USER_STAGE:\s*return xdev_ext_mech_user_stage_create\(', register)),
        ('register sub-op declared for the core', 'int xdev_ext_mech_user_stage_create(' in internal),
        ('class table: id 10', '.class_id = XDEV_EXT_MECH_CLASS_USER' in table),
        ('class table: no poll member, so F_POLL fails CREATE', table and '.poll' not in table),
        ('class table: not an ordered class', table and 'F_ORDERED' not in table),
        ('class table: progress reaps and cancels', '.progress = xdev_ext_user_progress' in table),
        ('class table: dead marking', '.mark_dead = xdev_ext_user_mark_dead' in table),
        ('class registered at init', re.search(r'late_initcall_sync\(xdev_ext_mech_user_init\)', user)),
        ('fd release stops the stage with -EPIPE',
         re.search(r'xdev_ext_mech_stage_dead\(obj->st, -EPIPE\)', release)),
        ('mapping: offset 0, at most the region, vmalloc remap',
         'vm_pgoff' in mmap and 'remap_vmalloc_range' in mmap),
        ('trivial program built', re.search(r'^BPF_NAMES :=.*\buser_plan\b', tools, re.M)),
        ('trivial program of the USER type', 'struct xdev_ext_user_mech_ops user_plan_ops' in prog),
        ('host CI runs these tests',
         'kernel/tools/testing/selftests/xdev_ext_mech/user_stage/run.py' in ci),
    ]
    failed = 0
    for index, (name, ok) in enumerate(checks, 1):
        print(('ok' if ok else 'not ok') + f' {index} - {name}')
        failed += not ok
    print(f'1..{len(checks)}')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
