#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Where a session batch spends its time: fentry/fexit intervals via bpftrace.

    run.py [--pair P] [--size BYTES] [--probe NAME ...] -- WORKLOAD ARGV...
    run.py --attach-check -- WORKLOAD ARGV...	event counts only
    run.py --emit | --resolve-only		print the program / the catalog

The catalog names the session core and class functions of one batch step:
the worker drain, completion handling (batch_landed), next-descriptor
construction (build, including the BPF build call and validation), the DMA
sync for the CPU, BPF program calls split by member, the core and class
submit, and the native completion callbacks.  Each function present in
/proc/kallsyms by its exact name gets an fentry/fexit duration; a function
the compiler inlined, or only emitted as a .isra/.constprop clone, cannot be
attached and is reported with the note that a tracepoint is needed.  READY
publication (xdev_ext_mech_life_publish) is static inline in every build and
is therefore always part of the batch_landed exclusive time.

Three cross-function intervals are keyed by the batch pointer: from class
submit entry to xdev_ext_mech_batch_completion_publish (submit_to_completion,
device time plus the class submit's own CPU time), from that publish to the
worker's batch_landed (completion_to_landed, queueing to the worker), and
from class submit entry to batch_landed (submit_to_landed).  The publish runs
only for the winner of the completion claim, so a stale or duplicate
completion callback does not end an interval.  A caller inside
xdev_ext_mech.c may have the publish inlined; then that completion closes
only submit_to_landed, and the result warns when submit_to_completion
counts fewer batches than submit_to_landed.
Exclusive time of a parent subtracts its direct catalog children; an
interrupt that runs on the same thread inside a measured function is
counted in that function.

Timing refuses virtual machines (exit 4); --attach-check only counts events
and may run in a guest to show that every catalog probe attaches.  Exit
status: 0, 1 bpftrace/workload failure, 2 usage, 4 refused/capability.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

SCHEMA = 'xdev-eval-breakdown-v1'
PAIRS = ('nvme-nic', 'nic-nvme', 'nvme-gpu', 'gpu-nvme', 'nic-gpu', 'gpu-nic')
MECH = 'io_uring/xdev_ext_mech.c'


def _p(name, symbol, file, linkage, role, batch_arg=None, **extra):
    return dict(name=name, symbol=symbol, file=file, linkage=linkage, role=role,
                batch_arg=batch_arg, **extra)


# file is relative to kernel/; batch_arg names the struct xdev_ext_mech_batch *.
PROBES = [
    _p('drain', 'xdev_ext_mech_batch_drain', MECH, 'static', 'worker drain of completed batches'),
    _p('landed', 'xdev_ext_mech_batch_landed', MECH, 'static',
       'completion handling: frame custody, CQE, DMA sync, READY publication, COMPLETE call',
       'b'),
    _p('build', 'xdev_ext_mech_build', MECH, 'static',
       'next-descriptor construction: DMA sync, BPF build, validation', 'b'),
    _p('sync_for_cpu', 'xdev_ext_mech_sync_for_cpu', MECH, 'static', 'DMA sync for the CPU', 'b'),
    _p('bpf_call', 'xdev_ext_mech_call', MECH, 'global',
       'BPF program call, reported as bpf_prepare/bpf_build/bpf_complete', split_member=True),
    _p('core_submit', 'xdev_ext_mech_submit', MECH, 'static',
       'core submit: custody to IN_FLIGHT and the class submit', 'b'),
    _p('nvme_submit', 'nvme_xdev_ext_class_submit', 'drivers/nvme/host/xdev_ext_mech_nvme.c',
       'static', 'NVMe class submit', 'b', class_submit=True),
    _p('afxdp_submit', 'xsk_xdev_ext_mech_submit', 'net/xdp/xsk_xdev_ext_mech.c', 'static',
       'AF_XDP class submit', 'b', class_submit=True),
    _p('ce_submit', 'xdev_ext_ce_submit', 'io_uring/xdev_ext_mech_ce.c', 'static',
       'GPU copy-engine class submit', 'b', class_submit=True),
    _p('dma_submit', 'xdev_ext_dma_submit', 'io_uring/xdev_ext_mech_dma.c', 'static',
       'registered DMA provider class submit', 'b', class_submit=True),
    _p('net_submit', 'xdev_ext_net_submit', 'io_uring/xdev_ext_mech_net.c', 'static',
       'peer NET class submit', 'b', class_submit=True),
    _p('socket_submit', 'xdev_ext_socket_submit', 'io_uring/xdev_ext_mech_socket.c', 'static',
       'UDP socket sink class submit', 'b', class_submit=True),
    _p('iaa_submit', 'xdev_ext_iaa_submit', 'io_uring/iaa/xdev_ext_mech_iaa.c', 'static',
       'IAA transform class submit', 'b', class_submit=True),
    _p('nvme_end_io', 'nvme_xdev_ext_class_end_io', 'drivers/nvme/host/xdev_ext_mech_nvme.c',
       'static', 'NVMe native completion callback'),
    _p('ce_complete', 'xdev_ext_ce_complete', 'io_uring/xdev_ext_mech_ce.c', 'global',
       'copy-engine backend completion callback'),
    _p('dma_complete', 'xdev_ext_dma_complete', 'io_uring/xdev_ext_mech_dma.c', 'global',
       'DMA provider completion callback'),
    # batch_complete claims first; a stale or duplicate ticket (the reliable
    # AF_XDP path can call it twice per batch) fails the claim and publishes
    # nothing, so the completion interval ends only in completion_publish.
    _p('batch_complete', 'xdev_ext_mech_batch_complete', MECH, 'global',
       'claim and publish a native completion', 'b'),
    _p('completion_publish', 'xdev_ext_mech_batch_completion_publish', MECH, 'global',
       'publish a claimed native completion to the worker', 'b', completion_end=True),
]
BY_NAME = {p['name']: p for p in PROBES}
CLASS_SUBMITS = [p['name'] for p in PROBES if p.get('class_submit')]
# Direct catalog callees; exclusive time subtracts these.
CHILDREN = {
    'drain': ['landed', 'build', 'core_submit'],
    'landed': ['sync_for_cpu', 'bpf_call', 'build', 'core_submit'],
    'build': ['sync_for_cpu', 'bpf_call'],
    'core_submit': CLASS_SUBMITS,
}
MEMBERS = {1: 'bpf_prepare', 2: 'bpf_build', 3: 'bpf_complete'}	# enum xdev_ext_mech_member
UNATTACHABLE = [
    dict(name='publish', symbol='xdev_ext_mech_life_publish',
         file='io_uring/xdev_ext_mech_lifecycle.h',
         note='static inline READY publication inside batch_landed; part of landed exclusive '
              'time; a tracepoint is needed to report it separately'),
]
CLONE = re.compile(r'(.+?)\.(isra|constprop|part|cold|llvm)\b.*')


class ParseError(ValueError):
    pass


# --- catalog resolution -------------------------------------------------

def parse_kallsyms(text):
    syms = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[1] not in 'tTwW':
            continue
        name = fields[2]
        module = fields[3].strip('[]') if len(fields) > 3 else None
        m = CLONE.fullmatch(name)
        base = m.group(1) if m else name
        e = syms.setdefault(base, dict(module=module, clones=[], exact=False))
        if m:
            e['clones'].append(name)
        else:
            e['exact'] = True
            e['module'] = module
    return syms


def resolve(probes, syms):
    out = []
    for p in probes:
        r = dict(p, status='absent', attach=None, module=None, note='')
        e = syms.get(p['symbol'])
        if e and e['exact']:
            r.update(status='attachable', module=e['module'],
                     attach=(e['module'] + ':' if e['module'] else '') + p['symbol'])
        elif e:
            r.update(status='cloned', note='only compiler clones (%s) exist; fentry needs the '
                     'original BTF function, so a tracepoint is needed' % ', '.join(e['clones']))
        elif p['linkage'] == 'static':
            r['note'] = ('not in kallsyms: inlined into its callers or not built; a tracepoint '
                         'is needed for this interval')
        else:
            r['note'] = 'not in kallsyms: not built in this configuration or module not loaded'
        out.append(r)
    return out


# --- program generation -------------------------------------------------

def descendants(name):
    seen, todo = set(), list(CHILDREN.get(name, []))
    while todo:
        n = todo.pop()
        if n not in seen:
            seen.add(n)
            todo += CHILDREN.get(n, [])
    return seen


def nest_condition(parent, child, attachable=None):
    """bpftrace condition: @child runs directly under @parent on this thread."""
    between = sorted(n for n in descendants(parent)
                     if child in descendants(n) and n != child and
                     (attachable is None or n in attachable))
    terms = ['@t_%s[tid]' % parent] + ['!@t_%s[tid]' % n for n in between]
    return 'if (%s)' % ' && '.join(terms)


class Program:
    def __init__(self, prefix):
        self.entry, self.exit = ('fentry', 'fexit') if prefix == 'fentry' else \
            ('kfunc', 'kretfunc')
        self.blocks = {}
        self.order = []
        self.scratch = []

    def add(self, kind, attach, text):
        key = (self.entry if kind == 'entry' else self.exit) + ':' + attach
        if key not in self.blocks:
            self.blocks[key] = []
            self.order.append(key)
        self.blocks[key].append(text)

    def render(self):
        parts = ['%s\n{\n%s}\n' % (k, ''.join(self.blocks[k])) for k in self.order]
        if self.scratch:
            parts.append('END\n{\n%s}\n' % ''.join('\tclear(%s);\n' % m for m in self.scratch))
        return '\n'.join(parts)


def _record(name, value):
    return ('\t\t@sum_ns["%s"] = sum(%s);\n\t\t@count["%s"] = count();\n' %
            (name, value, name))


def generate(resolved, mode, style, prefix):
    live = [r for r in resolved if r['status'] == 'attachable']
    names = {r['name'] for r in live}
    prog = Program(prefix)
    arg = (lambda a: 'args.' + a) if style == 'dot' else (lambda a: 'args->' + a)
    if mode == 'count':
        for r in live:
            prog.add('entry', r['attach'], '\t@count["%s"] = count();\n' % r['name'])
        return prog.render()
    key = lambda: '(uint64)%s' % arg('b')
    for r in live:
        n = r['name']
        prog.scratch.append('@t_' + n)
        entry = '\t@t_%s[tid] = nsecs;\n' % n
        body = ['\tif (@t_%s[tid]) {\n\t\t$d = nsecs - @t_%s[tid];\n' % (n, n)]
        if r.get('split_member'):
            prog.scratch.append('@m_' + n)
            entry += '\t@m_%s[tid] = %s->member;\n' % (n, arg('a'))
            branches = []
            for value, label in sorted(MEMBERS.items()):
                branches.append('if (@m_%s[tid] == %d) {\n%s\t\t}' %
                                (n, value, _record(label, '$d').replace('\t\t', '\t\t\t')))
            body.append('\t\t' + ' else '.join(branches) + ' else {\n' +
                        _record('bpf_other', '$d').replace('\t\t', '\t\t\t') + '\t\t}\n')
        else:
            body.append(_record(n, '$d'))
        for parent, children in CHILDREN.items():
            if n in children and parent in names:
                body.append('\t\t%s {\n\t\t\t@nest_%s__%s = sum($d);\n\t\t}\n' %
                            (nest_condition(parent, n, names), parent, n))
        body.append('\t\tdelete(@t_%s[tid]);\n' % n)
        if r.get('split_member'):
            body.append('\t\tdelete(@m_%s[tid]);\n' % n)
        body.append('\t}\n')
        prog.add('entry', r['attach'], entry)
        prog.add('exit', r['attach'], ''.join(body))
    submits = [r for r in live if r.get('class_submit')]
    ends = [r for r in live if r.get('completion_end')]
    landed = next((r['attach'] for r in live if r['name'] == 'landed'), None)
    if submits and (ends or landed):
        starts = [m for m, on in (('@dev0', ends), ('@sub0', landed)) if on]
        prog.scratch += starts
        for r in submits:
            prog.add('entry', r['attach'], ''.join('\t%s[%s] = nsecs;\n' % (m, key())
                                                   for m in starts))
            prog.add('exit', r['attach'], '\tif (retval != 0) {\n%s\t}\n' %
                     ''.join('\t\tdelete(%s[%s]);\n' % (m, key()) for m in starts))
    if submits and landed:
        prog.add('entry', landed,
                 '\tif (@sub0[%s]) {\n%s\t\tdelete(@sub0[%s]);\n\t}\n'
                 % (key(), _record('submit_to_landed', 'nsecs - @sub0[%s]' % key()), key()))
    if submits and ends:
        prog.scratch += ['@land0']
        for r in ends:
            prog.add('entry', r['attach'],
                     '\tif (@dev0[%s]) {\n%s\t\tdelete(@dev0[%s]);\n\t\t@land0[%s] = nsecs;\n\t}\n'
                     % (key(), _record('submit_to_completion', 'nsecs - @dev0[%s]' % key()),
                        key(), key()))
        if landed:
            prog.add('entry', landed,
                     '\tif (@land0[%s]) {\n%s\t\tdelete(@land0[%s]);\n\t}\n'
                     % (key(), _record('completion_to_landed', 'nsecs - @land0[%s]' % key()),
                        key()))
    return prog.render()


# --- results ------------------------------------------------------------

def _number(text):
    try:
        return int(text)
    except ValueError:
        raise ParseError('bad map value %r' % text) from None


def parse_output(text):
    parsed = dict(attached_probes=None, maps={}, other=[])
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith('{'):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                raise ParseError('bad JSON line %r' % line) from None
            if obj.get('type') == 'attached_probes':
                parsed['attached_probes'] = obj['data']['probes']
            elif obj.get('type') == 'map':
                parsed['maps'].update(obj['data'])
            else:
                parsed['other'].append(obj)
            continue
        m = re.fullmatch(r'Attaching (\d+) probes?\.\.\.', line)
        if m:
            parsed['attached_probes'] = int(m.group(1))
            continue
        m = re.fullmatch(r'(@\w+)(?:\[([^\]]*)\])?:\s*(\S+)', line)
        if not m:
            raise ParseError('unrecognized bpftrace output %r' % line)
        if m.group(2) is None:
            parsed['maps'][m.group(1)] = _number(m.group(3))
        else:
            parsed['maps'].setdefault(m.group(1), {})[m.group(2)] = _number(m.group(3))
    return parsed


def intervals(parsed):
    maps = parsed['maps']
    sums, counts = maps.get('@sum_ns', {}), maps.get('@count', {})
    out = {}
    for name, total in sums.items():
        count = counts.get(name, 0)
        r = dict(count=count, total_ns=total, mean_ns=total / count if count else None)
        if name in CHILDREN:
            nested = sum(maps.get('@nest_%s__%s' % (name, c), 0) for c in CHILDREN[name])
            r['exclusive_ns'] = total - nested
            r['exclusive_mean_ns'] = r['exclusive_ns'] / count if count else None
        out[name] = r
    done, landed = out.get('submit_to_completion'), out.get('submit_to_landed')
    if landed and (done or {}).get('count', 0) < landed['count']:
        out['_warnings'] = ['submit_to_completion covers %d of %d landed batches: a '
                            'completion caller inlined xdev_ext_mech_batch_completion_publish'
                            % ((done or {}).get('count', 0), landed['count'])]
    return out


# --- command line -------------------------------------------------------

def hypervisor(root):
    if (root / 'sys/hypervisor/type').exists():
        return True
    try:
        text = (root / 'proc/cpuinfo').read_text()
    except OSError:
        return False
    return any('hypervisor' in l.split() for l in text.splitlines() if l.startswith('flags'))


def parse_args(argv):
    if '--' in argv:
        split = argv.index('--')
        argv, cmd = argv[:split], argv[split + 1:]
    else:
        cmd = []
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--pair', choices=PAIRS)
    parser.add_argument('--size', type=int, help='payload bytes per batch (recorded)')
    parser.add_argument('--probe', action='append', choices=sorted(BY_NAME))
    parser.add_argument('--attach-check', action='store_true')
    parser.add_argument('--emit', action='store_true')
    parser.add_argument('--resolve-only', action='store_true')
    parser.add_argument('--bpftrace', default='bpftrace')
    parser.add_argument('--args-style', choices=('dot', 'arrow'), default='dot',
                        help='args.b (bpftrace >= 0.21) or args->b')
    parser.add_argument('--probe-prefix', choices=('fentry', 'kfunc'), default='fentry')
    parser.add_argument('--kallsyms')
    parser.add_argument('--host-root', default='/', help='filesystem root (tests)')
    parser.add_argument('--out')
    args = parser.parse_args(argv)
    args.cmd = cmd
    if not (args.emit or args.resolve_only) and not cmd:
        parser.error('a workload command is required after --')
    return args


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.host_root)
    try:
        syms = parse_kallsyms(Path(args.kallsyms or root / 'proc/kallsyms').read_text())
    except OSError as e:
        print('not_run: kallsyms unreadable: %s' % e, file=sys.stderr)
        return 4
    probes = [BY_NAME[n] for n in args.probe] if args.probe else PROBES
    resolved = resolve(probes, syms)
    if args.resolve_only:
        print(json.dumps(dict(schema=SCHEMA, probes=resolved, unattachable=UNATTACHABLE),
                         indent=1))
        return 0
    mode = 'count' if args.attach_check else 'timing'
    program = generate(resolved, mode, args.args_style, args.probe_prefix)
    if args.emit:
        print(program)
        return 0
    if not any(r['status'] == 'attachable' for r in resolved):
        print('not_run: no catalog probe is attachable on this kernel', file=sys.stderr)
        return 4
    if mode == 'timing' and hypervisor(root):
        print('not_run: hypervisor detected; timing is physical-host only '
              '(use --attach-check for counts)', file=sys.stderr)
        return 4
    tool = shutil.which(args.bpftrace)
    if not tool:
        print('not_run: bpftrace is not installed', file=sys.stderr)
        return 4
    if os.geteuid():
        print('not_run: bpftrace needs root', file=sys.stderr)
        return 4
    with tempfile.TemporaryDirectory(prefix='xdev-breakdown-') as work:
        output = Path(work) / 'bpftrace.out'
        done = subprocess.run([tool, '-f', 'json', '-o', str(output), '-e', program,
                               '-c', shlex.join(args.cmd)])
        text = output.read_text() if output.exists() else ''
    parsed = parse_output(text)
    result = dict(schema=SCHEMA, mode=mode, pair=args.pair, size=args.size,
                  command=args.cmd, exit_status=done.returncode,
                  attached_probes=parsed['attached_probes'],
                  probes=[{k: r[k] for k in ('name', 'symbol', 'status', 'attach', 'note')}
                          for r in resolved],
                  unattachable=UNATTACHABLE)
    if mode == 'count':
        result['counts'] = parsed['maps'].get('@count', {})
    else:
        result['intervals'] = intervals(parsed)
    text = json.dumps(result, indent=1)
    if args.out:
        Path(args.out).write_text(text + '\n')
    print(text)
    return 1 if done.returncode else 0


if __name__ == '__main__':
    sys.exit(main())
