#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check idle allocation and cleanup after refused RX frame admission.

Actual production functions run with bounded host scheduling and OS boundaries.
These checks do not execute DMA or a complete kernel START operation.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


HERE = Path(__file__).resolve().parent


def source_root():
    selected = os.environ.get('FRAME_TEST_SOURCE') or os.environ.get('XDEV_EXT_CANONICAL_ROOT')
    if selected:
        return Path(selected).resolve()
    for parent in HERE.parents:
        for marker in ('view.json', '.xdev-ext-source.json'):
            path = parent / marker
            if path.is_file():
                return Path(json.loads(path.read_text())['canonical_root']).resolve()
        if (parent / 'source-layout.json').is_file() and (parent / 'src/core').is_dir():
            return parent
    raise RuntimeError('canonical source provenance is unavailable')


ROOT = source_root()


def function(source, name):
    # Top-level functions in these files close in column zero. Include split
    # return declarations; never rewrite a production function's body.
    match = re.search(r'^\w[^;{}]*\b' + re.escape(name) +
                      r'\([^;{}]*\)\s*\{.*?^\}', source, re.M | re.S)
    if not match:
        raise RuntimeError('SETUP missing production function: ' + name)
    return match.group()


def session_helpers(text, bodies, extractor):
    """Follow actual session-helper calls; a called missing definition is fatal."""
    helpers = ('xdev_ext_mech_session_stage_role', 'xdev_ext_mech_session_rows',
               'xdev_ext_mech_session_chain_refs', 'xdev_ext_mech_session_start_queue_check')
    bodies, selected = list(bodies), set()
    for _ in helpers:
        for name in helpers:
            if name not in selected and any(re.search(r'\b' + name + r'\s*\(', body) for body in bodies):
                bodies.append(extractor(text, name))
                selected.add(name)
    return [name for name in helpers if name in selected]


def make_source(core_include):
    core = (ROOT / 'src/core/io_uring/xdev_ext_mech.c').read_text()
    xsk = (ROOT / 'src/network/net/xdp/xsk_xdev_ext_mech.c').read_text()
    pool = (ROOT / 'src/network/net/xdp/xsk_buff_pool.c').read_text()
    header = (ROOT / 'src/network/net/xdp/xsk_xdev_ext_mech.h').read_text()
    plain = (ROOT / 'src/network/net/xdp/xsk_xdev_ext_mech_core.h').read_text()
    buff = (ROOT / 'src/network/include/net/xsk_buff_pool.h').read_text()
    pieces = {
        'CORE': '\n'.join(function(core, name) for name in
                         ('xdev_ext_mech_pool_frame_move',
                          'xdev_ext_mech_pool_frame_state',
                          'xdev_ext_mech_frame_recycle')),
        'POOL_RECYCLE': function(xsk, 'xsk_xdev_ext_mech_pool_recycle'),
        'XSK_PURE': '\n'.join(function(plain, name) for name in
                             ('xsk_xdev_ext_mech_fq_ok', 'xsk_xdev_ext_mech_source_ok')),
        'XSK_HEADERS': '\n'.join(function(header, name) for name in
                                ('xp_xdev_ext_mech_state', 'xp_xdev_ext_mech_splice',
                                 'xp_xdev_ext_mech_alloc_lock', 'xp_xdev_ext_mech_alloc_unlock',
                                 'xp_xdev_ext_mech_reuse', 'xp_xdev_ext_mech_return',
                                 'xp_xdev_ext_mech_fq_ok')),
        'BUFF_HEADERS': '\n'.join(function(buff, name) for name in
                                 ('xp_aligned_extract_addr', 'xp_aligned_extract_idx',
                                  'xp_get_handle')),
        'XP_ALLOC': '\n'.join(function(pool, name) for name in
                             ('xp_check_aligned', 'xp_get_xskb', '__xp_alloc',
                              'xp_alloc_locked', 'xp_alloc')),
        'ALLOC': '\n'.join(function(xsk, name) for name in
                          ('xsk_xdev_ext_mech_frame', 'xsk_xdev_ext_mech_pool_resolve',
                           'xsk_xdev_ext_mech_pool_alloc')),
        'TAKE': function(core, 'xdev_ext_mech_take_user_frames'),
        'OPEN_FIND': function(core, 'xdev_ext_mech_open_find_locked'),
        'HOLD': function(core, 'xdev_ext_mech_hold_commit'),
    }
    helpers = session_helpers(core, pieces.values(), function)
    pieces['CORE'] = '\n'.join(function(core, name) for name in helpers) + '\n' + pieces['CORE']
    source = (HERE / 'frame_admission_failure_fixture.c.in').read_text()
    family = (Path(core_include).parent / 'include/linux/xdev_ext_family_core.h').read_text()
    if not re.search(r'\bxdev_ext_mech_class_decls\s*\[', family):
        # Historical cores do not consume decl; their header has no row symbol.
        source = re.sub(r'\.decl=&xdev_ext_mech_class_decls\[XDEV_EXT_MECH_CLASS_(?:AFXDP|NVME)\]', '', source)
    source = source.replace('@CORE_INCLUDE@', str(core_include))
    for name, text in pieces.items():
        source = source.replace('/* PRODUCTION_' + name + ' */', text)
    if '/* PRODUCTION_' in source:
        raise RuntimeError('SETUP unexpanded production marker')
    return source


CASES = (
    'alloc_user', 'alloc_free', 'alloc_held', 'alloc_inflight',
    'alloc_nic_rx', 'alloc_sequestered', 'alloc_partial',
    'start_allocator_interleaving',
    'hold_success', 'hold_claim_overflow', 'hold_claim_busy', 'hold_publish_failure',
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, action='append')
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    view = subprocess.run(
        [sys.executable, str(ROOT / 'tools/layout.py'), 'view', '--root', str(ROOT)],
        capture_output=True, text=True, timeout=30)
    if view.returncode:
        (args.out_dir / 'view.log').write_text(view.stdout + view.stderr)
        return 2
    core_include = Path(view.stdout.strip()) / 'kernel/io_uring'
    source = args.out_dir / 'frame-admission.c'
    source.write_text(make_source(core_include))
    binary = args.out_dir / 'frame-admission'
    command = ['gcc', '-std=gnu11', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-function', '-Wno-unused-variable',
               '-I', str(ROOT / 'src/core/include/uapi'),
               '-I', str(core_include),
               str(source), '-o', str(binary)]
    compile_result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    (args.out_dir / 'compile.log').write_text(compile_result.stdout + compile_result.stderr)
    if compile_result.returncode:
        print('SETUP compilation error; not behavioral RED', file=sys.stderr)
        print(compile_result.stderr, file=sys.stderr)
        return 2
    records = []
    for case in args.case or CASES:
        result = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=10)
        (args.out_dir / (case + '.log')).write_text(result.stdout + result.stderr)
        print(result.stdout + result.stderr, end='')
        records.append(dict(case=case, exit_code=result.returncode))
    summary = dict(source_root=str(ROOT), compiler=command, cases=records,
                   scope='actual extracted host functions; no hardware/DMA/full START proof')
    (args.out_dir / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
    failures = sum(record['exit_code'] != 0 for record in records)
    print(f'FRAME_ADMISSION cases={len(records)} failures={failures}')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
