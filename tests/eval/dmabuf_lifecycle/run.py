#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Explicit Linux primitive experiment runner; never implicitly loads a module."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess

HERE = Path(__file__).resolve().parent
CHECKS = ('two_phase', 'signal_before_add', 'identity', 'duplicates',
          'held_reference', 'independent_frames', 'allocation_failure',
          'callback_failure', 'teardown')


def admit_environment(mode, environment):
    if mode == 'check':
        return []
    if mode != 'time':
        return ['mode must be check or time']
    if (environment.get('kind') != 'physical' or
            environment.get('physical') is not True or
            environment.get('hypervisor') is not False):
        return ['time requires verified physical environment without hypervisor']
    return []


def validate_result(report, performance=False):
    errors = []
    def require(condition, name):
        if not condition:
            errors.append(name)
    require(report.get('schema_version') == 1, 'schema_version')
    require(report.get('experiment_kind') == 'kernel_sync_primitive', 'experiment_kind')
    mode = report.get('mode')
    require(mode in ('check', 'time'), 'mode')
    require(report.get('status') == 'ok', 'status')
    n = report.get('iterations')
    require(type(n) is int and 1 <= n <= 65536, 'iterations')
    for name, length in (('exact_sha', 40), ('lifecycle_header_sha256', 64),
                         ('module_sha256', 64)):
        require(bool(re.fullmatch('[0-9a-f]{' + str(length) + '}', str(report.get(name, '')))), name)
    require(bool(report.get('kernel_release')), 'kernel_release')
    require(report.get('oracle_in_timing') is False, 'oracle_in_timing')
    require(type(n) is int and report.get('oracle_checked_operations') == 2 * n, 'oracle_checked_operations')
    for name in CHECKS:
        require(report.get('checks', {}).get(name) == 'pass', 'checks.' + name)
    concurrent = report.get('concurrent_check', {})
    if concurrent.get('executed'):
        require(report.get('kernel_runtime') is True, 'concurrent_check.kernel_runtime')
        require(concurrent.get('contexts', 0) >= 2, 'concurrent_check.contexts')
    for arm in ('life', 'dma_fence'):
        data = report.get('arms', {}).get(arm, {})
        for key in ('attempted', 'successful', 'produced', 'consumed', 'recycled', 'valid_len_checks'):
            require(data.get(key) == n, arm + '.' + key)
        require(data.get('errors') == 0, arm + '.errors')
        require(data.get('allocations_setup') == 1, arm + '.allocations_setup')
        require(data.get('allocations_steady') == 0, arm + '.allocations_steady')
        require(data.get('cleanup_complete') is True, arm + '.cleanup_complete')
        if arm == 'dma_fence':
            require(type(n) is int and data.get('fence_objects') == 2 * n, 'dma_fence.fence_objects')
            require(type(n) is int and data.get('fence_releases') == 2 * n, 'dma_fence.fence_releases')
        if mode == 'time':
            timing = report.get('timing', {}).get(arm, {})
            for key in ('prepare_ns', 'completion_ns', 'full_cycle_ns', 'allocation_ns'):
                require(type(timing.get(key)) is int and timing[key] >= 0, arm + '.' + key)
            require(timing.get('denominator') == n, arm + '.denominator')
            require(timing.get('callback_registration') in ('prepare', 'completion'), arm + '.callback_registration')
    if mode == 'check':
        def timed(value):
            if isinstance(value, dict):
                return any(k == 'timing' or k == 'ratio' or k.endswith('_ratio') or k.endswith('_ns') or k.startswith('ns_') or timed(v)
                           for k, v in value.items())
            return False
        require(not timed(report), 'check must not contain timing/ns/ratio')
    if performance:
        errors.extend(admit_environment('time', report.get('environment', {})))
        require(mode == 'time', 'performance requires time mode')
        require(report.get('kernel_runtime') is True, 'kernel_runtime')
        require(report.get('evidence_kind') == 'kernel-runtime', 'evidence_kind')
    return errors


def execute_command(argv, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    receipt = dict(argv=list(argv), status='not-run', returncode=None,
                   performance_eligible=False, stderr_path=str(output_dir / 'stderr.log'))
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as error:
        receipt['error'] = str(error)
        (output_dir / 'stderr.log').write_text(str(error))
        return receipt
    (output_dir / 'stderr.log').write_text(result.stderr)
    (output_dir / 'stdout.log').write_text(result.stdout)
    receipt.update(status='ok' if result.returncode == 0 else 'failed', returncode=result.returncode)
    return receipt


def detected_environment():
    # No user-controlled override. Missing hypervisor flag alone does not prove
    # bare metal: require an explicit, separately audited machine manifest.
    flags = Path('/proc/cpuinfo').read_text() if Path('/proc/cpuinfo').exists() else ''
    return dict(kind='vm' if 'hypervisor' in flags else 'unknown',
                hypervisor='hypervisor' in flags, physical=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('check', 'time'), required=True)
    parser.add_argument('--iterations', type=int, default=8)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--environment-manifest', type=Path)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    if not 1 <= args.iterations <= 65536:
        parser.error('iterations must be 1..65536')
    command = ['insmod', str(args.module.resolve()), 'mode=' + args.mode,
               'iterations=' + str(args.iterations)]
    plan = dict(status='dry-run' if args.dry_run else 'not-run', mode=args.mode,
                commands=[command, ['rmmod', 'lifecycle_bench']], kernel_runtime=False,
                performance_eligible=False)
    if args.dry_run:
        print(json.dumps(plan))
        return 0
    if not args.execute:
        print(json.dumps(plan))
        return 2
    env = detected_environment()
    if args.environment_manifest:
        env = json.loads(args.environment_manifest.read_text())
        if detected_environment()['hypervisor']:
            env.update(kind='vm', hypervisor=True, physical=False)
    errors = admit_environment(args.mode, env)
    if errors or not args.module.is_file():
        print(json.dumps(dict(plan, errors=errors or ['module is unavailable'])))
        return 2
    source_status = subprocess.check_output(
        ['git', '-C', str(HERE), 'status', '--porcelain', '--', str(HERE),
         str(HERE.parents[2] / 'kernel/io_uring/xdev_ext_mech_lifecycle.h')], text=True)
    if source_status.strip():
        print(json.dumps(dict(plan, errors=['experiment sources must be committed before execution'])))
        return 2
    # A missing debugfs mount is reported, never mounted by this runner.
    args.output.mkdir(parents=True, exist_ok=True)
    receipt = execute_command(command, args.output / 'load')
    (args.output / 'load.json').write_text(json.dumps(receipt, indent=2))
    if receipt['status'] != 'ok':
        print(json.dumps(receipt))
        return 1
    success = False
    try:
        report = json.loads(Path('/sys/kernel/debug/xdev_lifecycle_bench/result').read_text())
        expected_sha = subprocess.check_output(['git', '-C', str(HERE), 'rev-parse', 'HEAD'], text=True).strip()
        expected_header = hashlib.sha256((HERE.parents[2] / 'kernel/io_uring/xdev_ext_mech_lifecycle.h').read_bytes()).hexdigest()
        if report.get('exact_sha') != expected_sha or report.get('lifecycle_header_sha256') != expected_header:
            raise ValueError('module compiled source/header identity differs from current checkout')
        report.update(module_sha256=hashlib.sha256(args.module.read_bytes()).hexdigest(),
                      kernel_release=platform.release(), environment=env,
                      kernel_runtime=True, evidence_kind='kernel-runtime')
        errors = validate_result(report, performance=args.mode == 'time')
        report.update(validation_errors=errors, performance_eligible=args.mode == 'time' and not errors)
        (args.output / 'result.json').write_text(json.dumps(report, indent=2))
        success = not errors
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        (args.output / 'error.txt').write_text(str(error))
    finally:
        unload = execute_command(['rmmod', 'lifecycle_bench'], args.output / 'unload')
        (args.output / 'unload.json').write_text(json.dumps(unload, indent=2))
        success = success and unload['status'] == 'ok'
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
