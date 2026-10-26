#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute actual observer + X6 C under GCC; this does not prove BPF verification.

The only adapters implement BPF map lookups and public metadata kfunc boundaries.
The old X6 case inventory is unchanged and remains independently runnable.
Missing production artifacts return 2; no substitute implementation is supplied.
"""
from pathlib import Path
import argparse
import importlib.util
import re
import subprocess
import sys
import tempfile


def run(args):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--syntax-only', action='store_true',
                        help='compile fixture with extern declarations only; no behavior claim')
    parser.add_argument('--reference-only', action='store_true',
                        help='execute actual reference/noop controls before wrapper exists')
    opts = parser.parse_args()
    here = Path(__file__).resolve().parent
    root = here.parents[2]
    kernel = root / 'kernel'
    old = kernel / 'tools/testing/selftests/xdev_ext_mech/peer_graph'
    wrapper = kernel / 'tools/xdev_ext_mech/xdomain_check.bpf.c'
    reference = kernel / 'tools/xdev_ext_mech/xdomain_peer.bpf.c'
    contract = here / 'observer_contract.h'
    fixture = here / 'observer_test.c'
    required = [reference, contract, fixture, old / 'xdomain_program_fixture.c',
                old / 'xdomain_program_test.py']
    if not opts.syntax_only and not opts.reference_only:
        required.append(wrapper)
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        print('D OBSERVER MISSING IMPLEMENTATION (no observer behavior executed):\n  '
              + '\n  '.join(missing), file=sys.stderr)
        return 2
    spec = importlib.util.spec_from_file_location('x6_contract', old / 'xdomain_program_test.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = reference.read_text()
    prog = kernel / 'tools/xdev_ext_mech/xdev_ext_mech_prog.h'
    netfam = kernel / 'include/linux/xdev_ext_netfam_core.h'
    uapi = kernel / 'include/uapi/linux/xdev_ext_mech.h'
    legacy = (old / 'xdomain_program_fixture.c').read_text()
    prefix, suffix = legacy.split('@BPF_SOURCE@')
    prefix = prefix.replace('@MECH@', str(uapi)).replace('@PROG@', str(prog))
    prefix = prefix.replace('@MIRROR_ASSERTIONS@', module.mirror_assertions(
        source, prog.read_text(), netfam.read_text()))
    # Metadata adapters remain unchanged. A complete source include follows;
    # generated environment headers provide only the external host boundary.
    prefix += '\n#include "observer_contract.h"\n'
    suffix = suffix.replace('int main(void)', 'static int old_main(void)')
    extras = fixture.read_text()
    modes = (['syntax'] if opts.syntax_only else
             ['reference', 'noop'] if opts.reference_only else
             ['reference', 'noop', 'wrapper'])
    transcripts = {}
    with tempfile.TemporaryDirectory(prefix='xdev-observer-') as tmp:
        temp = Path(tmp)
        (temp / 'bpf').mkdir()
        (temp / 'vmlinux.h').write_text('#define __VMLINUX_H__\n')
        (temp / 'observer_contract.h').write_text(contract.read_text())
        (temp / 'bpf/bpf_helpers.h').write_text('''
#ifndef OBS_HOST_BPF_HELPERS
#define OBS_HOST_BPF_HELPERS
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name
#define __array(name, val) val *name[]
#define __ksym
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_ANY 0
static void *bpf_map_lookup_elem(const void *map, const void *key);
/* No success stub: any use must fail the link. ARRAY values update in place. */
extern int bpf_map_update_elem(const void *, const void *, const void *, unsigned long);
#endif
''')
        (temp / 'bpf/bpf_tracing.h').write_text('')
        # The actual reference includes this declaration header. Its declarations
        # are already supplied by the existing metadata boundary adapter.
        preamble = '#define XDEV_EXT_MECH_KFUNC_H\n'
        for mode in modes:
            selected = wrapper if mode == 'wrapper' else reference
            if mode == 'syntax':
                selected_source = '''
extern int xdomain_peer_build(void *, const struct xdev_ext_mech_ctx *);
extern int xdomain_peer_complete(void *, const struct xdev_ext_mech_ctx *);
extern int xdomain_peer_choose(const struct xdev_ext_xdomain_proto_info *,
                               struct xdev_ext_xdomain_proto_verdict *);
struct { int marker; } xd_check_cfg, xd_check_rec, xd_check_err;
'''
            else:
                selected_source = '#include "' + str(selected) + '"\n'
                if mode == 'noop':
                    preamble_mode = '''
#define XDEV_EXT_XDOMAIN_OBSERVE_BUILD(ctx, info) observer_noop_build(ctx, info)
#define XDEV_EXT_XDOMAIN_OBSERVE_CQE(ctx, cqe) observer_noop_cqe(ctx, cqe)
'''
                else:
                    preamble_mode = ''
                selected_source = preamble_mode + selected_source
            text = (prefix + '\n#include <bpf/bpf_helpers.h>\n' + preamble
                    + '#define OBS_WRAPPER ' + str(int(mode in ('wrapper', 'syntax'))) + '\n'
                    + '#define OBS_SYNTAX ' + str(int(mode == 'syntax')) + '\n'
                    + '#define OBS_NOOP ' + str(int(mode == 'noop')) + '\n'
                    + '#define OBS_HAS_HOOKS ' + str(int('XDEV_EXT_XDOMAIN_OBSERVE_BUILD' in source)) + '\n'
                    + extras.split('/* @ACTUAL_SOURCE@ */')[0]
                    + selected_source
                    + extras.split('/* @ACTUAL_SOURCE@ */')[1].split('/* @LEGACY_CASES@ */')[0]
                    + suffix + extras.split('/* @LEGACY_CASES@ */')[1])
            path = temp / (mode + '.c')
            binary = temp / mode
            path.write_text(text)
            command = [opts.cc, '-std=gnu11', '-O1', '-Wall', '-Wextra', '-Werror',
                       '-Wno-unused-function', '-Wno-unused-parameter',
                       '-Wno-unknown-pragmas', '-I', str(temp), '-I', str(here),
                       '-I', str(kernel / 'tools/xdev_ext_mech')]
            if opts.syntax_only:
                command += ['-fsyntax-only', str(path)]
            else:
                command += ['-fsanitize=undefined', '-fno-sanitize-recover=all',
                            str(path), '-o', str(binary)]
            result = run(command)
            print(result.stdout, end='')
            if result.returncode:
                print(f'D OBSERVER {mode} GCC exit={result.returncode}', file=sys.stderr)
                return 1
            if opts.syntax_only:
                print('D fixture syntax only: extern implementation, no behavior executed')
                continue
            result = run([str(binary)])
            print(f'[{mode}]\n{result.stdout}', end='')
            if result.returncode:
                print(f'D OBSERVER {mode} runtime exit={result.returncode}', file=sys.stderr)
                return 1
            transcripts[mode] = result.stdout.split('OBSERVER CASES BEGIN')[0]
        if not opts.syntax_only:
            if len(set(transcripts.values())) != 1:
                print('D OBSERVER policy/descriptor/CQE differential differs', file=sys.stderr)
                return 1
            print('D observer: original 67-case ' + '/'.join(modes) +
                  ' differential identical')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'D OBSERVER TEST ERROR: {error}', file=sys.stderr)
        sys.exit(1)
