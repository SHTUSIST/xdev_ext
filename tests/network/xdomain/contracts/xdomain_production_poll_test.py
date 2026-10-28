#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Task c production completion-polling tests using the shared real NHI composition.

By default the shared composition inputs must exist in this kernel tree.
--fixture-kernel permits a read-only dependency while that fixture awaits
integration. Its original cases, expected set and algorithms are never edited.
Host MMIO/IRQ/DMA allocation boundaries are simulated; no physical DMA claim.
Return 2 for setup, 1 for behavioral failures and 0 for all selected cases.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURE = Path('tools/testing/selftests/xdev_ext_mech/xdomain')
CASES = ('legacy-irq', 'mode-selection', 'startup-before-create', 'four-ring-progress', 'budget-64-65', 'pending-256', 'worker-gone', 'stop-remove-unknown', 'partial-allocation', 'poll-return-stop-race', 'poll-return-remove-race', 'control-tx-tail-progress', 'idle-control-rx-no-spin', 'diagnostic-progress-gap')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(args, out):
    kernel = args.kernel.resolve()
    fixture = (args.fixture_kernel or args.kernel).resolve() / FIXTURE
    manifest = dict(status='setup', scope='host-real-NHI-XDOMAIN-composition',
                    hardware='none', kernel_execution=False, fixture_dependency=str(fixture),
                    production_native_completion_polling=True,
                    production_adapter_batch=False,
                    production_adapter_poll=args.case == 'diagnostic-progress-gap',
                    external_poll_dispatch='startup-only diagnostic' if args.case == 'diagnostic-progress-gap' else False,
                    diagnostic_only=args.case == 'diagnostic-progress-gap',
                    runtime_environment={name: os.environ.get(name) for name in
                                         ('ASAN_OPTIONS', 'LSAN_OPTIONS', 'UBSAN_OPTIONS')})

    def save():
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')

    try:
        expected = json.loads((fixture / 'nhi_stack_expected.json').read_text())
        # The shadow contains test inputs only. Production directories are
        # symlinks to --kernel, so external fixture paths cannot accidentally
        # select their own production checkout through relative includes.
        shadow = out / 'shadow' / 'kernel'
        staged = shadow / FIXTURE
        staged.mkdir(parents=True, exist_ok=True)
        for path in fixture.iterdir():
            if path.is_file() and path.suffix in ('.c', '.h', '.py', '.json'):
                shutil.copyfile(path, staged / path.name)
        # The shared fixture is single-threaded. Replace only environment
        # locking primitives in this build copy, leaving all production bodies
        # and shared cases unchanged. Counters describe each thread's locks.
        compat = staged / 'stack_kernel_compat.h'
        text = compat.read_text()
        replacements = {
            'struct mutex {unsigned held;};': '#include <pthread.h>\nstruct mutex {unsigned held; pthread_mutex_t native;};',
            'typedef struct {unsigned held;} spinlock_t;': 'typedef struct {unsigned held; pthread_mutex_t native;} spinlock_t;',
            'extern unsigned stack_spins,stack_mutexes;': 'extern _Thread_local unsigned stack_spins,stack_mutexes;',
            'static inline void mutex_init(struct mutex *m){m->held=0;}': 'static inline void mutex_init(struct mutex *m){m->held=0;assert(!pthread_mutex_init(&m->native,NULL));}',
            'static inline void mutex_lock(struct mutex *m){if(m->held)stack_lock_error();assert(!m->held);m->held=1;stack_mutexes++;}': 'static inline void mutex_lock(struct mutex *m){assert(!pthread_mutex_lock(&m->native));assert(!m->held);m->held=1;stack_mutexes++;}',
            'static inline void mutex_unlock(struct mutex *m){assert(m->held&&stack_mutexes);m->held=0;stack_mutexes--;}': 'static inline void mutex_unlock(struct mutex *m){assert(m->held&&stack_mutexes);m->held=0;stack_mutexes--;assert(!pthread_mutex_unlock(&m->native));}',
            'static inline void spin_lock_init(spinlock_t *s){s->held=0;}': 'static inline void spin_lock_init(spinlock_t *s){s->held=0;assert(!pthread_mutex_init(&s->native,NULL));}',
            'static inline void spin_lock_irq(spinlock_t *s){if(s->held)stack_lock_error();assert(!s->held);s->held=1;stack_spins++;}': 'static inline void spin_lock_irq(spinlock_t *s){assert(!pthread_mutex_lock(&s->native));assert(!s->held);s->held=1;stack_spins++;}',
            'static inline void spin_unlock_irq(spinlock_t *s){assert(s->held&&stack_spins);s->held=0;stack_spins--;}': 'static inline void spin_unlock_irq(spinlock_t *s){assert(s->held&&stack_spins);s->held=0;stack_spins--;assert(!pthread_mutex_unlock(&s->native));}',
            '#define DEFINE_MUTEX(n) struct mutex n={0}': '#define DEFINE_MUTEX(n) struct mutex n={.native=PTHREAD_MUTEX_INITIALIZER}',
            '#define DEFINE_SPINLOCK(n) spinlock_t n={0}': '#define DEFINE_SPINLOCK(n) spinlock_t n={.native=PTHREAD_MUTEX_INITIALIZER}',
        }
        for before, after in replacements.items():
            if text.count(before) != 1:
                raise ValueError('shared environment primitive changed: ' + before)
            text = text.replace(before, after)
        compat.write_text(text)
        boundary = staged / 'stack_boundary.c'
        text = boundary.read_text()
        before = 'unsigned stack_spins,stack_mutexes;'
        if text.count(before) != 1:
            raise ValueError('shared boundary lock counter changed')
        text = text.replace(before, '_Thread_local unsigned stack_spins,stack_mutexes;')
        replacements = {
            ' u64 next_progress, allocation_bias;': ' u64 next_progress, allocation_bias, poll_last_pump, poll_last_hw;',
            ' for(;;){\n  struct work_struct *work=NULL;': ' for(;;){\n  if(production_poll_after_progress){\n   production_poll_after_progress=false;\n   struct native *ready=native_ready();\n   if(ready){\n    if(used==budget)return -ELOOP;\n    scheduler_step(w,budget,&used,STACK_STEP_NATIVE,ring_info(ready->r)->endpoint,ready->session_id);\n    assert(one_native());production_poll_device_serial++;continue;\n   }\n  }\n  struct work_struct *work=NULL;',
            'if(epoch->bound&&(epoch->s.kicked||epoch->next_progress<=w->now))': 'if(epoch->bound&&(epoch->s.kicked||epoch->next_progress<=w->now)&&\n       (epoch->poll_last_pump!=w->pump_serial||epoch->poll_last_hw!=production_poll_device_serial))',
            '   selected->s.kicked=false;': '   selected->poll_last_pump=w->pump_serial;selected->poll_last_hw=production_poll_device_serial;\n   selected->s.kicked=false;',
            '   assert(one_native());\n   continue;': '   assert(one_native());production_poll_device_serial++;\n   continue;',
            'struct tb_ring *poll = native_poll_ready();': 'struct tb_ring *poll = production_poll_external ? native_poll_ready() : NULL;',
            '   work->fn(work);': '   production_poll_context=2; production_poll_pass++;\n   work->fn(work);\n   production_poll_context=0;',
            '   selected->next_progress=w->now+': '   production_poll_context=1; production_poll_pass++;\n   selected->next_progress=w->now+',
            '    selected->s.st.cls->progress(&selected->s.st)*NSEC_PER_MSEC;': '    selected->s.st.cls->progress(&selected->s.st)*NSEC_PER_MSEC;\n   production_poll_tail(selected_endpoint,&selected->s,selected->next_progress);\n   production_poll_after_progress=true;production_poll_context=0;',
        }
        for before, after in replacements.items():
            if text.count(before) != 1:
                raise ValueError('shared scheduler boundary changed: ' + before)
            text=text.replace(before, after)
        boundary.write_text(text)
        nhi_boundary=staged/'stack_nhi_boundary.h'
        text=nhi_boundary.read_text()
        before='\t\tunsigned e = info->endpoint;\n\t\tif (info->control && (n->held'
        after='\t\tunsigned e = info->endpoint;\n\t\tif (production_poll_delay_ack && info->control && n->raw[5]==3 && n->delivered) continue;\n\t\tif (info->control && (n->held'
        if text.count(before)!=1:raise ValueError('native readiness boundary changed')
        nhi_boundary.write_text(text.replace(before,after))
        for relative in ('io_uring', 'drivers', 'include'):
            path = shadow / relative
            if path.is_symlink():
                path.unlink()
            path.symlink_to(kernel / relative, target_is_directory=True)
        tool_link = shadow / 'tools/xdev_ext_mech'
        if tool_link.is_symlink():
            tool_link.unlink()
        tool_link.symlink_to(kernel / 'tools/xdev_ext_mech', target_is_directory=True)
        own = ('xdomain_production_poll_cases.c', 'xdomain_production_poll_boundary.c',
               'xdomain_production_poll_x3.c', 'xdomain_production_poll_nhi.c')
        for name in own:
            shutil.copyfile(HERE / name, staged / name)
        env = out / 'facade'
        load('native_progress_facade', fixture / 'stack_test.py').facade(kernel, env)
        extraction = out / 'extraction'
        (extraction / 'drivers/thunderbolt').mkdir(parents=True, exist_ok=True)
        if (extraction / 'include').is_symlink():
            (extraction / 'include').unlink()
        (extraction / 'include').symlink_to(kernel / 'include', target_is_directory=True)
        fallback = {}
        for name in ('nhi.c', 'nhi_regs.h'):
            path = kernel / 'drivers/thunderbolt' / name
            if not path.is_file() and name == 'nhi_regs.h':
                path = (args.fixture_kernel or args.kernel).resolve() / 'drivers/thunderbolt' / name
                fallback[name] = dict(path=str(path), sha256=digest(path))
            dest = extraction / 'drivers/thunderbolt' / name
            if dest.is_symlink():
                dest.unlink()
            dest.symlink_to(path)
        manifest['upstream_environment_fallback'] = fallback
        load('native_progress_source', fixture / 'stack_nhi_source.py').generate(extraction, env)
        sources = [staged / name for name in expected['wrappers']
                   if name not in ('stack_boundary.c', 'stack_x3.c', 'stack_nhi.c')]
        sources += [staged / name for name in own]
        # Only observe the external API return; never replace a production body.
        for wrapper in ('stack_x4.c', 'stack_x5.c'):
            path=staged/wrapper
            body=path.read_text()
            point='#include "stack_kernel_compat.h"'
            if body.count(point)!=1: raise ValueError('wrapper boundary changed: '+wrapper)
            path.write_text(body.replace(point,point+'\nstruct ring_frame *production_poll_ring(struct tb_ring *);\nvoid production_poll_complete(struct tb_ring *);\n#define tb_ring_poll production_poll_ring\n#define tb_ring_poll_complete production_poll_complete'))
        probe = out / 'startup-probe.c'
        probe.write_text('#define STACK_INTERNAL\n#include "stack_kernel_compat.h"\n'
                         '#include "stack_nhi_api.h"\n#define tb_ring_tx stack_ring_tx\n'
                         '#define tb_ring_rx stack_ring_rx\n#include "' +
                         str(kernel / 'io_uring/xdomain/xdev_ext_xdomain_probe.c') + '"\n')
        sources.append(probe)
        expected['source_units'].append('kernel/io_uring/xdomain/xdev_ext_xdomain_probe.c')
        command = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-O0', '-g', '-DSTACK_REAL_NHI', '-DSTACK_STARTUP_EVENTS',
                   '-Wall', '-Wextra', '-Werror=implicit-function-declaration',
                   '-Wno-unused-function', '-Wno-unused-parameter', '-pthread',
                   '-I', str(env), '-I', str(staged), '-I', str(kernel),
                   '-idirafter', str(kernel / 'include'), '-idirafter', str(kernel / 'include/uapi'),
                   '-I', str(kernel / 'tools/xdev_ext_mech')]
        if args.sanitize:
            command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-fno-omit-frame-pointer']
        binary = out / 'production-poll-cases'
        command += [str(path) for path in sources] + ['-o', str(binary)]
        manifest['source_units'] = {name: digest(kernel.parent / name)
                                    for name in expected['source_units']}
        manifest['test_inputs'] = {str(path): digest(path) for path in
                                  sorted(fixture.iterdir()) if path.is_file() and
                                  path.suffix in ('.c', '.h', '.py', '.json')}
        manifest['own_inputs'] = {name: digest(HERE / name) for name in own}
        manifest['runner_sha256'] = digest(Path(__file__))
        manifest['compile_command'] = command
        build = subprocess.run(command, text=True, capture_output=True, timeout=120)
        (out / 'compile.log').write_text(build.stdout + build.stderr)
        manifest['compile_exit'] = build.returncode
        if build.returncode:
            manifest['status'] = 'compile-failure'
            save()
            print('PRODUCTION_POLL_SETUP_FAILURE: no semantic execution\n' + build.stdout + build.stderr)
            return 2
        version = subprocess.run([command[0], '--version'], text=True,
                                 capture_output=True, timeout=10)
        manifest['compiler_version'] = version.stdout.splitlines()[0] if version.returncode == 0 else None
    except (OSError, ValueError, AssertionError, subprocess.TimeoutExpired) as error:
        manifest.update(status='setup-failure', error=str(error))
        save()
        print('PRODUCTION_POLL_SETUP_FAILURE: no semantic execution: ' + str(error))
        return 2
    selected = [name for name in CASES if (args.case is None and name != 'diagnostic-progress-gap') or name == args.case]
    print('# host software composition; actual NHI and XDOMAIN; no physical DMA')
    print('TAP version 13\n1..' + str(len(selected)))
    records = []
    for number, name in enumerate(selected, 1):
        try:
            result = subprocess.run([str(binary), name, '120000'], text=True,
                                    capture_output=True, timeout=60)
            output, code = result.stdout + result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            output, code = 'PRODUCTION_POLL_TIMEOUT\n', 124
        marker = re.search(r'^PRODUCTION_POLL_ASSERTIONS ' + re.escape(name) +
                           r' ([1-9][0-9]*)$', output, re.M)
        ok = code == 0 and marker is not None
        (out / (name + '.log')).write_text(output + '\nruntime_exit=' + str(code) + '\n')
        records.append(dict(name=name, returncode=code, assertions=int(marker[1]) if marker else 0,
                            status='pass' if ok else 'fail', log=name + '.log'))
        print(('ok ' if ok else 'not ok ') + str(number) + ' - ' + name)
        if not ok:
            print(output + '# runtime_exit=' + str(code))
    failed = any(record['status'] != 'pass' for record in records)
    manifest.update(status='fail' if failed else 'pass', cases=records)
    save()
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, default=HERE.parents[4])
    parser.add_argument('--fixture-kernel', type=Path)
    parser.add_argument('--keep-build', type=Path)
    parser.add_argument('--case', choices=CASES)
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.keep_build:
        args.keep_build.mkdir(parents=True, exist_ok=True)
        return execute(args, args.keep_build.resolve())
    with tempfile.TemporaryDirectory(prefix='xdomain-production-poll-') as directory:
        return execute(args, Path(directory))


if __name__ == '__main__':
    raise SystemExit(main())
