#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Two independent XDOMAIN protocol programs on the actual host composition.

The runner reuses tests/network/xdomain/early/run.py to assemble the mapped
production sources (NHI ring, XDOMAIN transport/class, family, core pieces)
and its environment patches. It then rewrites only the program bridge
(stack_x6.c): the reference program, the RTS/CTS program and the early-grant
program are all included, under private symbol names, and stack_program[]
selects the program attached at each endpoint. Each program stays a complete
separate source file; the kernel loads each as its own object.

Cases:
  own cases (cases.c)  fixed golden control bytes, the CTS invariant, mismatched
                       programs, and refused bindings;
  equivalence          each new program takes the reference decision for its
                       own protocol on generated fact records;
  early:<case>         the existing early contract cases with the early-grant
                       program at the early endpoints.
The existing version-1 stack suite runs separately with
stack_test.py --program rts-cts in its own unmodified environment.
Compilation failures, signals and timeouts are setup errors, never RED.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'source-layout.json').is_file())
PROGRAMS = (('stack_ref', 'tools/xdev_ext_mech/xdomain_peer.bpf.c'),
            ('stack_rts', 'tools/xdev_ext_mech/xdomain_rts_cts.bpf.c'),
            ('stack_early', 'tools/xdev_ext_mech/xdomain_early.bpf.c'))
SYMBOLS = ('xdomain_peer_prepare', 'xdomain_peer_build', 'xdomain_peer_complete',
           'xdomain_peer_ops', 'LICENSE')
OWN_CASES = ('rts_cts_v2', 'rts_cts_legacy', 'reference_legacy', 'early_v2', 'reference_early',
             'mismatch_rts_sender', 'mismatch_pair_sender', 'rts_drops_hello',
             'announce_latches_choice', 'paired_refuses_announce', 'post_needs_grant',
             'hello_stop_early', 'hello_stop_reference', 'hello_link_down_early',
             'hello_link_down_reference', 'stray_rts_then_pair_early',
             'stray_rts_then_pair_reference', 'stray_cts_then_pair', 'rts_cts_v2_idle', 'paired_drops_v1',
             'paired_refuses_decline')
RTS, EARLY = 1, 2
# Early contract cases whose endpoints are not both early: the version-1 end
# runs the RTS/CTS program (mixed_v1_tx: version-1 sender, early receiver).
# Every other early case runs the early program at both ends.
EARLY_MAPPING = {'default_v1': (RTS, RTS), 'mixed_v1_tx': (RTS, EARLY),
                 'mixed_v1_rx': (EARLY, RTS)}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def copy_program_closure(kernel, root):
    """Copy each program and its project includes by the layout's native paths."""
    entries = json.loads((root / 'source-layout.json').read_text())['files']
    native = {e['native_path']: root / e['source'] for e in entries if e.get('component') == 'linux'}
    include = re.compile(r'^\s*#\s*include\s*"([^"\n]+)"', re.M)
    pending, copied = [path for _, path in PROGRAMS], {}
    while pending:
        name = pending.pop()
        if name in copied:
            continue
        if name not in native:
            raise FileNotFoundError('program input not mapped in source-layout.json: ' + name)
        data = native[name].read_bytes()
        copied[name] = {'source': str(native[name].relative_to(root)),
                        'sha256': hashlib.sha256(data).hexdigest()}
        dest = kernel / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        for inc in include.findall(data.decode()):
            candidate = str(Path(name).parent / inc)
            if candidate in native:
                pending.append(candidate)
    return copied


def bridge(stack):
    """Include all three programs under private names; dispatch per endpoint."""
    x6 = stack / 'stack_x6.c'
    text = x6.read_text()
    anchor = '#include "../../../../../tools/xdev_ext_mech/xdomain_peer.bpf.c"\n'
    if text.count(anchor) != 1:
        raise ValueError('program bridge include anchor changed')
    parts = []
    for prefix, path in PROGRAMS:
        parts += ['#define %s %s_%s' % (s, prefix, s) for s in SYMBOLS]
        parts.append('#include "../../../../../%s"' % path)
        parts += ['#undef %s' % s for s in SYMBOLS]
    parts += ['unsigned stack_program[2];',
              'unsigned stack_force_endpoint = 2, stack_force_event, stack_force_action, stack_force_hits;',
              'static __s32 xdomain_peer_prepare(void *, const struct xdev_ext_mech_ctx *);',
              'static __s32 xdomain_peer_build(void *, const struct xdev_ext_mech_ctx *);',
              'static __s32 xdomain_peer_complete(void *, const struct xdev_ext_mech_ctx *);', '']
    text = text.replace(anchor, '\n'.join(parts) + '\n', 1)
    text += r'''
/* Program table: 0 reference, 1 RTS/CTS, 2 early grant. A forced action
 * replaces one recorded verdict before the class validates it, so the class
 * invariants are exercised independently of program policy. */
static __s32 xdomain_peer_prepare(void *c, const struct xdev_ext_mech_ctx *m)
{
 switch (stack_program[active_endpoint & 1]) {
 case 1: return stack_rts_xdomain_peer_prepare(c, m);
 case 2: return stack_early_xdomain_peer_prepare(c, m);
 default: return stack_ref_xdomain_peer_prepare(c, m);
 }
}
static __s32 xdomain_peer_build(void *c, const struct xdev_ext_mech_ctx *m)
{
 switch (stack_program[active_endpoint & 1]) {
 case 1: return stack_rts_xdomain_peer_build(c, m);
 case 2: return stack_early_xdomain_peer_build(c, m);
 default: return stack_ref_xdomain_peer_build(c, m);
 }
}
void proto_observe(unsigned endpoint, unsigned program, unsigned event);
static __s32 xdomain_peer_complete(void *c, const struct xdev_ext_mech_ctx *m)
{
 __s32 ret;
 if (m->callsite == XDEV_EXT_MECH_SITE_WORKER_PROTOCOL && active && active->info)
  proto_observe(active_endpoint, stack_program[active_endpoint & 1],
                ((const struct xdev_ext_xdomain_proto_info *)active->info)->event);
 switch (stack_program[active_endpoint & 1]) {
 case 1: ret = stack_rts_xdomain_peer_complete(c, m); break;
 case 2: ret = stack_early_xdomain_peer_complete(c, m); break;
 default: ret = stack_ref_xdomain_peer_complete(c, m); break;
 }
 if (!ret && active && active->xdomain && active->xdomain->calls == 1 &&
     m->callsite == XDEV_EXT_MECH_SITE_WORKER_PROTOCOL && active_endpoint == stack_force_endpoint &&
     ((const struct xdev_ext_xdomain_proto_info *)active->info)->event == stack_force_event) {
  active->xdomain->verdict.action = stack_force_action;
  active->xdomain->verdict.credit = 0;
  active->xdomain->verdict.status = 0;
  active->xdomain->verdict.wake_ns = 0;
  stack_force_endpoint = 2;
  stack_force_hits++;
 }
 return ret;
}
'''
    x6.write_text(text)


# Each mutation removes one rule of the class change in the assembled copy;
# at least one case must then fail with a named assertion. Each edit is
# (unit, old, new); every old text must occur exactly once.
CLASS = 'io_uring/xdomain/xdev_ext_xdomain_class.c'
RING = 'io_uring/xdomain/xdev_ext_xdomain_ring.c'
V1_RULES = '{ return xs->rts_cts || (xs->ns.rx && !xd_paired(xs)); }'
MUTATIONS = {
    # An RTS or an RX post on an RTS does not latch the RTS/CTS choice.
    'no_binding_latch': ((CLASS, '\t\t\tif (!xd_paired(xs)) {\n\t\t\t\txs->rts_cts = true;',
                          '\t\t\tif (0) {\n\t\t\t\txs->rts_cts = true;'),),
    # PAIR_DUE is offered again after the RTS/CTS choice.
    'offer_after_choice': ((CLASS, 'xs->pair_next_retry <= now && !xs->rts_cts &&', 'xs->pair_next_retry <= now &&'),),
    # Pairing input is retained after the RTS/CTS choice.
    'input_after_choice': ((CLASS, 'if (!xd_pair_allowed(xs) || xs->failed || xs->stop_latched',
                            'if (xs->failed || xs->stop_latched'),),
    # v1 events of an unpaired stage get the early fact overrides.
    'early_facts_for_v1': ((CLASS, '\tif (v1_view) return;\n', ''),),
    # The early snapshot drops the RTS/control record selected by xd_next_locked.
    'drop_rts_authority': ((CLASS, 'xd_early_snapshot_locked(xs, s, r, ev, xs->worker_event.rts, xs->worker_event.ctl, false, i);',
                            'xd_early_snapshot_locked(xs, s, r, ev, false, false, false, i);'),),
    # v1 control never reaches a v2-envelope endpoint (the old dispatch).
    'v1_blocked': ((RING, 'if (ep && (!ep->early || xdev_ext_xd_class_ctl_rts_cts(ep->st)))', 'if (ep && !ep->early)'),),
    # A stopping or ended v1-rules stage is still offered its held HELLO
    # before the v1 STOP and terminal rules (the unguarded order).
    'held_offer_after_end': ((CLASS, '\tif (xs->early_ctl_count && xd_v1_rules(xs) &&\n',
                              '\tif (0 && xs->early_ctl_count && xd_v1_rules(xs) &&\n'),),
    # Early mandatory safety (pairing deadline, STOP as failure) also binds
    # an RTS/CTS stage, or a receiver nobody asked to pair.
    'safety_binds_rts_cts': ((CLASS, V1_RULES, '{ return xs->ns.rx && !xd_paired(xs); }'),),
    'safety_binds_unpaired_rx': ((CLASS, V1_RULES, '{ return xs->rts_cts; }'),),
    # v1 control reaches a paired endpoint (ring predicate and class drop).
    'v1_reaches_paired': ((RING, 'if (ep && (!ep->early || xdev_ext_xd_class_ctl_rts_cts(ep->st)))', 'if (ep)'),
                          (CLASS, 'if (xd_paired(xs) || m->channel != xs->channel || xs->failed ||',
                           'if (m->channel != xs->channel || xs->failed ||')),
    # IGNORE on PAIR_DUE declines pairing even after pairing started.
    'decline_after_pairing': ((CLASS, 'if (!declined || xd_paired(xs) ||', 'if (!declined ||'),),
}


def mutate(kernel, out, name):
    edits = []
    for unit, old, new in MUTATIONS[name]:
        path = kernel / unit
        text = path.read_text()
        if text.count(old) != 1:
            raise ValueError('mutation anchor absent or not unique: %s in %s' % (name, unit))
        path.write_text(text.replace(old, new, 1))
        edits.append(dict(source=unit, old=old, new=new))
    (out / 'mutation.json').write_text(json.dumps(dict(name=name, edits=edits), indent=2) + '\n')


def bpf_visible_names(kernel):
    """A BPF object sees only vmlinux.h (BTF types and enums) and its own headers.

    The host composition includes the UAPI header, so a program that uses a
    UAPI-only macro compiles here and fails the real BPF build. Every
    XDEV_EXT_* name a program uses outside comments must be a macro of the BPF
    side headers or an enumerator of the two protocol enums the kernel emits
    to BTF. Returns a list of (program, name) violations.
    """
    tools = kernel / 'tools/xdev_ext_mech'
    strip = lambda text: re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))
    allowed = set()
    for header in ('xdev_ext_mech_prog.h', 'xdev_ext_mech_kfunc.h', 'xdomain_policy.h'):
        allowed |= set(re.findall(r'^\s*#\s*define\s+(XDEV_EXT_\w+)', (tools / header).read_text(), re.M))
    uapi = (kernel / 'include/uapi/linux/xdev_ext_mech.h').read_text()
    for name in ('xdev_ext_xdomain_proto_event', 'xdev_ext_xdomain_proto_action'):
        body = re.search(r'enum\s+' + name + r'\s*\{(.*?)\}', uapi, re.S).group(1)
        allowed |= set(re.findall(r'(XDEV_EXT_\w+)\s*=', body))
    bad = []
    for _, path in PROGRAMS[1:]:
        program = Path(path).name
        for header in (program, 'xdomain_policy.h') if program != 'xdomain_policy.h' else (program,):
            for used in sorted(set(re.findall(r'\b(XDEV_EXT_\w+)', strip((tools / header).read_text())))):
                if used not in allowed and used != 'XDEV_EXT_XDOMAIN_POLICY_H':
                    bad.append((header, used))
    return sorted(set(bad))


def combined_cases(early_dir):
    early = (early_dir / 'cases.c').read_text()
    signature = 'int main(int argc,char **argv)'
    if early.count(signature) != 1:
        raise ValueError('early case driver anchor changed')
    early = early.replace(signature, 'int early_cases_main(int argc,char **argv)', 1)
    return early + '\n' + (HERE / 'cases.c').read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append', help='run only these cases (repeatable)')
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--mutation', choices=sorted(MUTATIONS))
    args = parser.parse_args()
    root = args.source_root.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    early_dir = root / 'tests/network/xdomain/early'
    early = module('protocols_early_runner', early_dir / 'run.py')
    early.ROOT = root
    kernel, stack = early.assemble(out)
    units = copy_program_closure(kernel, root)
    (out / 'program-units.json').write_text(json.dumps(units, indent=2) + '\n')
    (out / 'protocol-fixture-inputs.json').write_text(json.dumps({
        name: hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        for name in ('run.py', 'cases.c', 'equivalence.c', 'README.md')}, indent=2) + '\n')
    bridge(stack)
    if args.mutation:
        mutate(kernel, out, args.mutation)
    with tempfile.TemporaryDirectory(prefix='xdomain-protocols-cases-') as temp:
        cases_dir = Path(temp)
        (cases_dir / 'cases.c').write_text(combined_cases(early_dir))
        early.HERE = cases_dir
        built = early.prepare(kernel, stack, out, args.sanitize, False)
    if not built:
        (out / 'result.json').write_text(json.dumps(dict(status='setup-error', compile_exit=1,
            scope='host actual NHI/XDOMAIN composition', hardware=False,
            kernel_execution=False, cases=[]), indent=2) + '\n')
        return 2
    # Pure decision equivalence of each new program with the reference policy.
    equivalence = ['gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra',
                   '-Werror=implicit-function-declaration', '-Wno-unused-function',
                   '-Wno-unused-parameter', '-I', str(out / 'facade'), '-I', str(stack),
                   '-I', str(kernel), '-idirafter', str(kernel / 'include'),
                   '-idirafter', str(kernel / 'include/uapi'), '-I', str(kernel / 'tools/xdev_ext_mech'),
                   str(HERE / 'equivalence.c'), '-o', str(out / 'equivalence')]
    (out / 'equivalence-command.json').write_text(json.dumps(equivalence, indent=2) + '\n')
    build = subprocess.run(equivalence, capture_output=True, text=True, timeout=120)
    (out / 'equivalence-compile.log').write_text(build.stdout + build.stderr)
    early_cases = re.findall(r"'([a-z0-9_]+)'", (early_dir / 'run.py').read_text().split(
        'cases = [', 1)[1].split(']', 1)[0])
    names = bpf_visible_names(kernel)
    (out / 'bpf-names.log').write_text(''.join('BPF_NAME_MISSING %s %s\n' % item for item in names) +
                                       'BPF_NAMES checks=%u missing=%u\n' % (1 + len(names), len(names)))
    plan = [('bpf_names', 'names', 'BPF_NAMES checks=')]
    plan += [('equivalence', None, 'PROTOCOL_EQUIVALENCE checks=')]
    plan += [(name, [name], 'PROTOCOL_ASSERTIONS ' + name + ' ') for name in OWN_CASES]
    for name in early_cases:
        tx, rx = EARLY_MAPPING.get(name, (EARLY, EARLY))
        plan.append(('early:' + name, ['early:' + name, '%u,%u' % (tx, rx)],
                     'EARLY_ASSERTIONS ' + name + ' '))
    if args.case:
        plan = [p for p in plan if p[0] in args.case]
        if len(plan) != len(set(args.case)):
            parser.error('unknown case in --case')
    records = []
    print('TAP version 13\n1..' + str(len(plan)), flush=True)
    for index, (name, argv, marker) in enumerate(plan, 1):
        command = [str(out / 'equivalence')] if argv is None else [str(out / 'early-cts'), *argv]
        if argv == 'names':
            log = (out / 'bpf-names.log').read_text()
            code = 1 if names else 0
        elif argv is None and build.returncode:
            log, code = 'SETUP_ERROR equivalence compile failed\n' + build.stdout + build.stderr, None
        else:
            try:
                r = subprocess.run(command, capture_output=True, text=True, timeout=300)
                log, code = r.stdout + r.stderr, r.returncode
            except subprocess.TimeoutExpired as error:
                log, code = str(error.stdout or '') + str(error.stderr or '') + '\nTIMEOUT', None
        (out / (name.replace(':', '-') + '.log')).write_text(log + '\nruntime_exit=' + str(code) + '\n')
        assertions = [int(line[len(marker):].split()[0]) for line in log.splitlines()
                      if line.startswith(marker) and line[len(marker):].split()[:1] != [] and
                      line[len(marker):].split()[0].isdigit()]
        ok = code == 0 and bool(assertions) and assertions[-1] > 0
        semantic_red = code == 1 and ('STACK_ASSERT ' in log or 'PROTOCOL_EQUIVALENCE_FAIL' in log)
        records.append(dict(case=name, argv=argv, runtime_exit=code, passed=ok,
                            failure_kind=None if ok else 'behavioral' if semantic_red else 'runtime-error'))
        print(('ok ' if ok else 'not ok ') + str(index) + ' - ' + name, flush=True)
        if not ok:
            print(log, flush=True)
    failed = any(not r['passed'] for r in records)
    setup = any(r['failure_kind'] == 'runtime-error' for r in records)
    (out / 'result.json').write_text(json.dumps(dict(
        status='setup-or-runtime-error' if setup else 'behavioral-red' if failed else 'pass',
        scope='host actual NHI/XDOMAIN composition', hardware=False, kernel_execution=False,
        compile_exit=0, sanitize=args.sanitize, mutation=args.mutation, cases=records), indent=2) + '\n')
    return int(failed)


if __name__ == '__main__':
    sys.exit(main())
