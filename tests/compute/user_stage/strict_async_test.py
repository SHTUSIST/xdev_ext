#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Q6-Q9: complete production USER TU + unchanged production core completion.

Linux includes are replaced with host boundaries. No USER decision function is
reimplemented. Existing scheduler extraction supplies core functions unchanged.
Each case runs separately; absence of strict admission is a behavioral failure.
"""
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import scheduler_test as scheduler

HERE = Path(__file__).resolve().parent
ROOT = scheduler.ROOT
CASES = ('legacy-stop', 'strict-bind-peer', 'strict-bind-cpu', 'stop-late',
         'deadline-late', 'stop-noack', 'deadline-noack', 'negative', 'positive',
         'badlen', 'stale', 'overflow', 'rewind', 'poll', 'dead', 'attach',
         'attach-args', 'attach-bound', 'detach-bound', 'retain-unbound',
         'retain-owner-exit', 'detach-final', 'attach-legacy', 'attach-nonstrict',
         'attach-owner-exit-pending', 'peer-reject-nonstrict',
         'peer-reject-varlen', 'peer-reject-delta', 'ticket-reuse',
         'external-stale', 'external-nonstrict')


def generate():
    code = scheduler.generate()
    user = (ROOT / 'io_uring/xdev_ext_mech_user.c').read_text()
    # Replace the USER subset with its complete production translation unit.
    for name in ('xdev_ext_user_held', 'xdev_ext_user_stage'):
        code = code.replace(scheduler.definition(user, name, True), '')
    for name in ('xdev_ext_user_default_build', 'xdev_ext_user_validate',
                 'xdev_ext_user_stopped', 'xdev_ext_user_end', 'xdev_ext_user_submit',
                 'xdev_ext_user_reap_one', 'xdev_ext_user_reap',
                 'xdev_ext_user_progress', 'xdev_ext_user_mark_dead',
                 'xdev_ext_user_drain', 'xdev_ext_user_external_end',
                 'xdev_ext_user_strict_progress'):
        code = code.replace(scheduler.definition(user, name), '')
    core = (ROOT / 'io_uring/xdev_ext_mech.c').read_text()
    # Future production external completion entry and its direct helpers.
    extra = [scheduler.definition(core, "xdev_ext_mech_poll_work")]
    for name in re.findall(r'^\w[^;{}]*\b(xdev_ext_mech_\w*external\w*)\([^;{}]*\)\n\{', core, re.M):
        extra.append(scheduler.definition(core, name))
    declaration = re.search(r'^enum xdev_ext_mech_external_outcome \{\n.*?^\};',
                            (ROOT / 'include/linux/xdev_ext_mech.h').read_text(), re.M | re.S)
    if declaration and declaration[0] not in code:
        code = code.replace('enum xdev_ext_mech_end', declaration[0] + '\nenum xdev_ext_mech_end', 1)
    if "xdev_ext_mech_batch_external_complete" in core:
        code = '#define STRICT_HAS_EXTERNAL 1\n' + code
    # Pull any direct production-core dependencies without supplying test
    # implementations of new completion helpers.
    pending = list(extra)
    while pending:
        body = pending.pop()
        for name in set(re.findall(r'\b(xdev_ext_mech_\w+)\s*\(', body)):
            try:
                dependency = scheduler.definition(core, name)
            except RuntimeError:
                continue
            if dependency not in code and dependency not in extra:
                extra.append(dependency)
                pending.append(dependency)
    extra = list(dict.fromkeys(f for f in extra if f not in code))
    if extra:
        extra.insert(0, '\n'.join(f[:f.index('\n{')] + ';' for f in extra))
    user = '\n'.join(line for line in user.splitlines()
                     if not line.lstrip().startswith('#include'))
    code = code.replace('static int native_submit(', '\n'.join(extra) + '\n' + user + '\nstatic int native_submit(', 1)
    shim = (HERE.parent / 'fanout_scheduler/shim.h').read_text()
    shim = shim.replace('struct file_operations { int tag; };', '''struct inode { int unused; };
struct vm_area_struct { unsigned long vm_pgoff, vm_end, vm_start; };
struct file;
struct file_operations { struct module *owner; int (*release)(struct inode *,struct file *);
 int (*mmap)(struct file *,struct vm_area_struct *);
 long (*unlocked_ioctl)(struct file *,unsigned int,unsigned long);
 long (*compat_ioctl)(struct file *,unsigned int,unsigned long); };''')
    shim = shim.replace('struct file { const struct file_operations *f_op; };',
                        'struct file { const struct file_operations *f_op; void *private_data; unsigned refs; };')
    shim = shim.replace('static void fput(struct file *f) {(void)f;file_puts++;}',
                        'static void fput(struct file *f) { file_puts++; if (!--f->refs) f->f_op->release(NULL,f); }')
    boundary = (HERE / 'strict_async_fixture.c').read_text()
    prefix, tests = boundary.split('/* STRICT CASES */', 1)
    code = code.replace('#include "fanout_scheduler/shim.h"', shim + '\n' + prefix)
    # Existing fixture setup and worker boundary are shared; replace its test
    # body and use actual CREATE/bind rather than private stage fabrication.
    code = code[:code.index('static int exercise(const char*mode)')] + tests
    code = code.replace('static unsigned progress_kicks, retry_arms;',
                        'static unsigned progress_kicks, retry_arms, poll_arms; static unsigned long poll_delay;')
    code = code.replace('if((void*)d!=progress_work_of_session)abort();',
                        'if((void*)d!=progress_work_of_session){poll_arms++;poll_delay=delay;return true;}')
    # Reusing a batch object preserves production completion ticket history.
    code = code.replace('memset(b,0,sizeof(*b));',
                        'struct xdev_ext_mech_completion saved_completion=b->completion;\n memset(b,0,sizeof(*b));b->completion=saved_completion;')
    # A sequester must never use the fake pool-free boundary.
    code = code.replace('ends++;end_how=how;end_err=err;', '''ends++;end_how=how;end_err=err;
 if(how==XDEV_EXT_MECH_END_SEQUESTER){ xdev_ext_mech_sess_batch_end(&s->ss,true); return; }''')
    return code


def main():
    print('TAP version 13', flush=True)
    with tempfile.TemporaryDirectory(prefix='strict-user-') as temp:
        temp = Path(temp)
        src = temp / 'strict.c'
        try:
            src.write_text(generate())
        except (OSError, RuntimeError) as error:
            print(f'1..1\nnot ok 1 - production extraction: {error}')
            return 1
        binary = temp / 'strict'
        command = shlex.split(os.environ.get('CC', 'gcc')) + [
            '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-Wno-unused-variable', '-Wno-unused-parameter',
            '-fsanitize=undefined', '-fno-sanitize-recover=undefined', '-pthread',
            '-I' + str(ROOT), '-I' + str(HERE.parent), '-I' + str(HERE),
            str(src), '-o', str(binary)]
        build = subprocess.run(command, text=True, capture_output=True)
        if build.returncode:
            print('1..1\nnot ok 1 - production TU compile (harness error)')
            print(build.stdout + build.stderr, end='')
            if os.environ.get('STRICT_SAVE_GENERATED'):
                Path(os.environ['STRICT_SAVE_GENERATED']).write_text(src.read_text())
            return 1
        print('1..' + str(len(CASES)), flush=True)
        failed = 0
        for i, case in enumerate(CASES, 1):
            run = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=10)
            print(('not ok' if run.returncode else 'ok') + f' {i} - {case}', flush=True)
            print(run.stdout + run.stderr, end='', flush=True)
            failed += run.returncode != 0
        return bool(failed)

if __name__ == '__main__':
    sys.exit(main())
