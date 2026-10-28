#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""B4 actual-core teardown / complete XDOMAIN stack behavior regression."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'source-layout.json').is_file())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def assemble(out):
    """No shared source-view or hardlinks: resolve the needed include closure."""
    kernel = out / 'inputs/kernel'
    entries = json.loads((ROOT / 'source-layout.json').read_text())['files']
    native = {e['native_path']: ROOT / e['source'] for e in entries
              if e.get('component') == 'linux'}
    stack_rel = 'tools/testing/selftests/xdev_ext_mech/xdomain'
    peer_rel = 'tools/testing/selftests/xdev_ext_mech/peer_graph'
    stack_names = ['stack_boundary.c', 'stack_x3.c', 'stack_x4.c', 'stack_x5.c',
                   'stack_family.c', 'stack_x6.c', 'stack_kernel_compat.h', 'stack_test.py',
                   'stack_nhi.c', 'stack_nhi_source.py', 'stack_nhi_compat.h',
                   'stack_nhi_boundary.h', 'stack_nhi_api.h']
    pending = [f'{stack_rel}/{n}' for n in stack_names]
    pending += [f'{peer_rel}/{n}' for n in ('xdomain_retention_fixture.py',
                                         'xdomain_ring_test.py', 'xdomain_fixture.py')]
    pending += ['drivers/thunderbolt/nhi.c', 'include/linux/thunderbolt.h',
                'io_uring/family/xdev_ext_requester_retention.c', 'io_uring/xdev_ext_mech.c']
    copied = {}
    include = re.compile(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]', re.M)
    while pending:
        name = pending.pop()
        if name in copied:
            continue
        source = native[name]
        data = source.read_bytes()
        copied[name] = {'source': str(source.relative_to(ROOT)),
                        'sha256': hashlib.sha256(data).hexdigest()}
        dest = kernel / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        if source.suffix not in ('.c', '.h'):
            continue
        for inc in include.findall(data.decode()):
            # Project definitions stay real; Linux OS facilities use the shared facade.
            possibilities = [os.path.normpath(str(Path(name).parent / inc)), inc,
                             'include/' + inc, 'include/uapi/' + inc,
                             'tools/xdev_ext_mech/' + inc]
            for candidate in possibilities:
                if candidate in native:
                    pending.append(candidate)
                    break
    lock = json.loads((ROOT / 'third_party/sources.lock.json').read_text())
    commit = lock['components']['linux']['commit']
    upstream = ROOT / f'tests/support/fixtures/upstream/linux-{commit}/nhi_regs.h'
    dest = kernel / 'drivers/thunderbolt/nhi_regs.h'
    dest.write_bytes(upstream.read_bytes())
    copied['drivers/thunderbolt/nhi_regs.h'] = {
        'source': str(upstream.relative_to(ROOT)),
        'sha256': hashlib.sha256(upstream.read_bytes()).hexdigest()}
    (out / 'source-units.json').write_text(json.dumps(copied, indent=2) + '\n')
    (out / 'fixture-inputs.json').write_text(json.dumps({
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in ('run.py', 'cases.c')}, indent=2) + '\n')
    return kernel, kernel / stack_rel


def prepare(kernel, stack, out):
    # Reuse only the established OS facade and exact function extractor.
    shared = module('b4_shared_stack', stack / 'stack_test.py')
    facade = out / 'facade'
    shared.facade(kernel, facade)
    sys.path.insert(0, str(kernel / 'tools/testing/selftests/xdev_ext_mech/peer_graph'))
    module('b4_nhi_source', stack / 'stack_nhi_source.py').generate(kernel, facade)
    from xdomain_fixture import definition
    core = (kernel / 'io_uring/xdev_ext_mech.c').read_text()
    compat_path = stack / 'stack_kernel_compat.h'
    compat = compat_path.read_text()
    compat = compat.replace('struct xdev_ext_mech_stage st;u64 id',
                            'struct xdev_ext_mech_stage st[1];u64 id')
    compat = compat.replace('struct file authority;};', '''struct file authority;
 bool worker_gone; unsigned nr_bound,nr_stages;
 void *worker; struct delayed_work retry_work,progress_work,poll_work;
 struct list_head live_node; int group_timer,last_err;
 void *pool_file,*evfd,*start_queue,*cookies,*transform_owner,*life,*privs;
 void *fan_batches,*batches,*cqe,*scratch,*info;
 bool owns_life; atomic64_t cnt[XDEV_EXT_MECH_CNT_NR];
 void *ops[XDEV_EXT_MECH_CLASS_MAX];
 bool pinned[XDEV_EXT_MECH_CLASS_MAX]; void *c_owner[XDEV_EXT_MECH_CLASS_MAX];
};
int kthread_mod_delayed_work(void *,struct delayed_work *,unsigned long);
''')
    compat_path.write_text(compat)
    path = stack / 'stack_boundary.c'
    boundary = path.read_text()
    boundary = re.sub(r'(\.st|\b(?:session|s)->st)\b', r'\1[0]', boundary)
    boundary = boundary.replace(definition(boundary, 'xdev_ext_mech_stage_kick'),
                                definition(core, 'xdev_ext_mech_stage_kick'))
    boundary = boundary.replace(definition(boundary, 'xdev_ext_mech_session_admits'),
                                definition(core, 'xdev_ext_mech_session_admits'))
    # OS core callback dependencies declared before the two verbatim functions.
    boundary = boundary.replace('bool xdev_ext_mech_session_admits(',
        'static bool xdev_ext_mech_ops_current(u32 i,void *o,bool p) { (void)i;(void)o;(void)p;abort(); }\nbool xdev_ext_mech_session_admits(', 1)
    boundary = boundary.replace('if(epoch->bound&&(epoch->s.kicked||',
                                'if(epoch->bound&&!epoch->s.worker_gone&&(epoch->s.kicked||')
    # Real release frees the session; here it is embedded in the recorder epoch.
    boundary = boundary.replace('void kfree(void*p){\n\tfree(p);',
        'static void *b4_embedded_session;\nvoid kfree(void*p){\n if(p==b4_embedded_session)return;\n\tfree(p);')
    os_boundaries = (HERE / 'cases.c').read_text()
    release = '\n\n'.join(definition(core, n) for n in (
        'xdev_ext_mech_unbind_checked', 'xdev_ext_mech_session_release_report'))
    boundary += '\n' + os_boundaries.replace('/* ACTUAL_CORE_RELEASE */', release)
    path.write_text(boundary)
    x5 = stack / 'stack_x5.c'
    x5.write_text(x5.read_text() + '''
unsigned b4_raw_queued(struct xdev_ext_mech_stage *st) {
 struct xdev_ext_xd_stage *xs=st->priv;
 return xs->rts_count;
}
''')
    sources = [stack / n for n in ('stack_boundary.c', 'stack_x3.c', 'stack_x4.c',
                                   'stack_x5.c', 'stack_family.c', 'stack_x6.c', 'stack_nhi.c')]
    command = ['gcc', '-std=gnu11', '-O0', '-g', '-DSTACK_REAL_NHI', '-Wall',
               '-Wextra', '-Werror=implicit-function-declaration', '-Wno-unused-function',
               '-Wno-unused-parameter', '-pthread', '-I', str(facade), '-I', str(stack),
               '-I', str(kernel), '-idirafter', str(kernel / 'include'),
               '-idirafter', str(kernel / 'include/uapi'),
               '-I', str(kernel / 'tools/xdev_ext_mech')]
    command += [str(s) for s in sources] + ['-o', str(out / 'late-rts')]
    (out / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    (out / 'compile.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        print('B4_SETUP_ERROR: compilation did not execute behavior\n' + result.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    kernel, stack = assemble(out)
    if not prepare(kernel, stack, out):
        return 2
    failed = False
    records = []
    print('TAP version 13\n1..2', flush=True)
    for index, case in enumerate(('after_detach', 'worker_gone_before_detach'), 1):
        result = subprocess.run([str(out / 'late-rts'), case], capture_output=True,
                                text=True, timeout=30)
        log = result.stdout + result.stderr
        (out / (case + '.log')).write_text(log + f'\nruntime_exit={result.returncode}\n')
        ok = result.returncode == 0 and 'B4_ASSERTIONS ' in log
        records.append({'case': case, 'runtime_exit': result.returncode,
                        'passed': ok, 'log': case + '.log'})
        print(('ok ' if ok else 'not ok ') + f'{index} - {case}\n' + log, flush=True)
        failed |= not ok
    (out / 'result.json').write_text(json.dumps({
        'scope': 'B4 host actual-core release and real NHI/XDOMAIN composition',
        'hardware': False, 'kernel_execution': False, 'compile_exit': 0,
        'status': 'behavioral-red' if failed else 'pass', 'cases': records,
    }, indent=2) + '\n')
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
