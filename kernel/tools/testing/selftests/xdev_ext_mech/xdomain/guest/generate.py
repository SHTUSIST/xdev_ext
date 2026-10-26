#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Generate full struct_ops probes; compile errors are always setup errors."""
import json
import sys
from pathlib import Path


def source(name):
    cls, member = 'xdomain', 'complete'
    body = '(void)mctx; return 0;'
    maps = ''
    if name.startswith('rel-tx-state-'):
        cls = 'nvme' if '-nvme-' in name else 'xdomain'
        body = 'struct xdev_ext_net_rel_tx_state v = {}; return bpf_xdev_ext_net_rel_tx_state(mctx, 1, &v, sizeof(v));'
    if name.startswith('private-'):
        _, which, rest = name.split('-', 2)
        parts = rest.rsplit('-', 2)
        cls, member = parts[0].replace('af-xdp', 'afxdp'), parts[1]
        size = 256 if which == 'info' else 64
        body = f'__u64 v[{size // 8}] = {{}}; return bpf_xdev_ext_xdomain_{which}(mctx, v, sizeof(v));'
    if name.startswith('helper-'):
        maps = '''struct value { struct bpf_timer timer; __u64 data[32]; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct value); } values SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PROG_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u32); } jumps SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 4096); } events SEC(".maps");'''
        body = '__u32 k=0; struct value *v=bpf_map_lookup_elem(&values, &k); if (!v) return 0; '
        op = name.removeprefix('helper-').removesuffix('-deny').removesuffix('-allow')
        calls = {
            'map-lookup': 'return v->data[0];',
            'timer-init': 'return bpf_timer_init(&v->timer, &values, 1);',
            'timer-start': 'return bpf_timer_start(&v->timer, 1, 0);',
            'tail-call': 'bpf_tail_call((void *)mctx, &jumps, 0); return 0;',
            'probe-read-kernel': '__u64 x=0; return bpf_probe_read_kernel(&x, sizeof(x), (void *)0);',
            'probe-read-user': '__u64 x=0; return bpf_probe_read_user(&x, sizeof(x), (void *)0);',
            'ringbuf-output': '__u64 x=0; return bpf_ringbuf_output(&events, &x, sizeof(x), 0);',
            'existing-class-control': '__u64 x=0; return bpf_probe_read_kernel(&x, sizeof(x), (void *)0);',
        }
        body += calls[op]
        if op == 'existing-class-control': cls = 'nvme'
    if name.startswith('memory-'):
        which = 'verdict' if '-verdict-' in name else 'info'
        size = 64 if which == 'verdict' else 256
        decl = f'__u64 v[{size // 8}] = {{}};'
        arg, count = 'v', f'{size}'
        if 'uninit-' in name: decl = f'__u64 v[{size // 8}];'
        if 'oob-' in name: decl = '__u64 v[1] = {};'
        if 'readonly-map-' in name:
            maps = f'const volatile __u64 readonly_record[{size // 8}] = {{}};'
            decl, arg = '', '(void *)readonly_record'
        body = f'{decl} return bpf_xdev_ext_xdomain_{which}(mctx, {arg}, {count});'
        if name == 'memory-ctx-write-deny':
            body = '*(volatile __u32 *)(void *)mctx = 1; return 0;'
    section = 'struct_ops.s' if member == 'prepare' or name == 'xdomain-complete-sleepable-deny' else 'struct_ops'
    callbacks = []
    for m in ('prepare', 'build', 'complete'):
        sec = section if m == member else ('struct_ops.s' if m == 'prepare' else 'struct_ops')
        callbacks.append(f'SEC("{sec}/probe_{m}") int BPF_PROG(probe_{m}, const struct xdev_ext_mech_ctx *mctx) {{ (void)ctx; {body if m == member else "(void)mctx; return 0;"} }}')
    return '''#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "xdev_ext_mech_prog.h"
#include "xdev_ext_mech_kfunc.h"
extern int bpf_xdev_ext_net_rel_tx_state(const struct xdev_ext_mech_ctx *, __u64, void *, __u32) __ksym;
''' + maps + '\n' + '\n'.join(callbacks) + f'''
SEC(".struct_ops.link") struct xdev_ext_{cls}_mech_ops probe_ops = {{
 .abi_version = XDEV_EXT_MP_ABI_VERSION,
 .prepare = (void *)probe_prepare, .build = (void *)probe_build, .complete = (void *)probe_complete,
}};
char LICENSE[] SEC("license")="GPL";
'''


if __name__ == '__main__':
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
    cases = json.loads(Path(__file__).with_name('cases.json').read_text())['cases']
    rows = []
    for row in cases:
        if row['expected'] not in ('ALLOW', 'DENY'): continue
        (out / (row['name'] + '.bpf.c')).write_text(source(row['name']))
        rows.append(row['name'] + ' ' + row['expected'])
    (out / 'matrix.txt').write_text('\n'.join(rows) + '\n')
