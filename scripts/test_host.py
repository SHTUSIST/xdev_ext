#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile and run standalone production-rule tests without devices or root."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
KERNEL_TESTS = (
    'xdev_ext_mech_core_test', 'xdev_ext_mech_ce_core_test',
    'xdev_ext_mech_ce_lease_test',
    'xdev_ext_mech_step_test', 'xdev_ext_mech_lifecycle_test',
    'xdev_ext_mech_refs_test', 'xdev_ext_mech_lifecycle_contract_test',
    'xdev_ext_mech_fanout_step_test', 'xdev_ext_mech_cpu_xform_test',
    'xdev_ext_mech_ctl_chains_test',
    'xdev_ext_mech_rx_stages_test', 'xdev_ext_mech_window_offset_test',
    'xdev_ext_mech_window_pipeline_test', 'xdev_ext_mech_ce_exact_completion_test',
    'provider/xdev_ext_mech_dma_core_test',
)
GPU_TESTS = (
    'nv_xdev_ext_gpu_policy_test', 'nv_xdev_ext_gpu_binding_test',
    'nv_xdev_ext_gpu_stub_test', 'nv_xdev_ext_umem_quota_test',
    'nv_xdev_ext_handle_lifetime_test', 'nv_xdev_ext_ce_chunk_test',
    'nv_xdev_ext_dma_lifetime_test', 'nv_xdev_ext_gpu_identity_test',
    'nv_xdev_ext_ce_classify_test', 'nv_xdev_ext_vidmem_offset_test',
    'nv_xdev_ext_ce_plan_test', 'nv_xdev_ext_ce_async_test',
)


def run(command, verbose):
    result = subprocess.run(command, cwd=ROOT, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=120)
    if verbose or result.returncode:
        print(result.stdout, end='')
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {shlex.join(command)}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=('all', 'kernel', 'gpu'), default='all')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--no-sanitize', action='store_true', help='omit host UBSan instrumentation')
    args = parser.parse_args()
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    flags = ['-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread']
    if not args.no_sanitize:
        flags += ['-fsanitize=undefined', '-fno-sanitize-recover=undefined']
    cases = []
    if args.component in ('all', 'kernel'):
        folder = ROOT/'kernel/tools/testing/selftests/xdev_ext_mech'
        for name in KERNEL_TESTS:
            extra = ['-std=gnu11', '-I'+str(ROOT/'kernel')]
            if name in ('xdev_ext_mech_refs_test', 'xdev_ext_mech_lifecycle_contract_test'):
                extra += ['-I'+str(folder/'model'/'shim')]
            cases.append((folder/(name+'.c'), extra))
        cases.append((ROOT/'kernel/tools/testing/selftests/xdev_ext_preload'/
                      'xdev_ext_preload_ce_concurrency_test.c',
                      ['-std=gnu11', '-I'+str(ROOT/'kernel'),
                       '-I'+str(ROOT/'kernel/tools')]))
        preload = ROOT/'kernel/tools/testing/selftests/xdev_ext_preload'
        for name in ('xdev_ext_preload_copy_batch_test', 'xdev_ext_preload_fallback_core_test'):
            cases.append((preload/(name+'.c'), ['-std=gnu11', '-I'+str(ROOT/'kernel/tools')]))
        cases.append((folder/'model'/'life_explore.c',
                      ['-std=gnu11', '-I'+str(folder/'model'/'shim'), '-I'+str(ROOT/'kernel')]))
    if args.component in ('all', 'gpu'):
        for name in GPU_TESTS:
            extra = ['-std=c11']
            if name == 'nv_xdev_ext_gpu_binding_test':
                extra += ['-DCONFIG_IO_URING_XDEV_EXT_BPF_POLICY=1',
                          '-I'+str(ROOT/'gpu/tests/fake_include')]
            cases.append((ROOT/'gpu/tests'/(name+'.c'), extra))
    with tempfile.TemporaryDirectory(prefix='xdev-ext-host-') as temporary:
        for index, (source, extra) in enumerate(cases):
            binary = Path(temporary)/str(index)
            run(compiler+flags+extra+[str(source), '-o', str(binary)], args.verbose)
            run([str(binary)], args.verbose)
            print('PASS '+str(source.relative_to(ROOT)))
    print(f'HOST CHECKS=PASS programs={len(cases)} scope=standalone-production-rules hardware=none')


if __name__ == '__main__':
    main()
