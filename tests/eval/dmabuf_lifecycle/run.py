#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Explicit Linux primitive experiment runner; never implicitly loads a module."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import secrets
import subprocess

HERE = Path(__file__).resolve().parent
MODULE_ROOT = Path('/sys/module/lifecycle_bench')
RESULT_PATH = Path('/sys/kernel/debug/xdev_lifecycle_bench/result')
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
    # Never consume an old run or unload a module owned by another invocation.
    if args.output.exists():
        print(json.dumps(dict(plan, errors=['output directory already exists; use a fresh output directory'])))
        return 2
    if MODULE_ROOT.exists() or RESULT_PATH.parent.exists() or RESULT_PATH.exists():
        print(json.dumps(dict(plan, errors=['existing benchmark module/debugfs; refusing stale producer'])))
        return 2
    try:
        module_name = subprocess.check_output(
            ['modinfo', '-F', 'name', str(args.module.resolve())], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        print(json.dumps(dict(plan, errors=['module identity unavailable: ' + str(error)])))
        return 2
    if module_name != 'lifecycle_bench':
        print(json.dumps(dict(plan, errors=['module identity must be lifecycle_bench'])))
        return 2
    nonce = secrets.token_hex(16)
    command.append('run_nonce=' + nonce)
    module_hash = hashlib.sha256(args.module.read_bytes()).hexdigest()
    try:
        args.output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print(json.dumps(dict(plan, errors=['output directory already exists; use a fresh output directory'])))
        return 2
    # Publish a failure-safe, unsealed receipt before crossing the loader boundary.
    # Only this new, exclusively created output directory is ever written.
    result = dict(status='running', mode=args.mode, iterations=args.iterations,
                  run_nonce=nonce, module_sha256=module_hash, kernel_runtime=False,
                  performance_eligible=False, sealed=False, teardown_complete=False,
                  validation_errors=[])
    def publish():
        temporary = args.output / 'result.json.tmp'
        temporary.write_text(json.dumps(result, indent=2))
        temporary.replace(args.output / 'result.json')
    publish()
    errors = result['validation_errors']
    owned = False
    loaded = False
    teardown_complete = False
    report = None
    validated = False
    try:
        receipt = execute_command(command, args.output / 'load')
        (args.output / 'load.json').write_text(json.dumps(receipt, indent=2))
        loaded = receipt['status'] == 'ok'
        if not loaded:
            errors.append('load failed or not run')
        # The read-only sysfs nonce is from the named, newly loaded module,
        # independent of the JSON document. Only that instance may be unloaded.
        if MODULE_ROOT.exists():
            owned = (MODULE_ROOT / 'parameters/run_nonce').read_text().strip() == nonce
        if loaded and not owned:
            errors.append('producer nonce identity is unverified; module ownership unknown')
        if loaded and owned:
            if (MODULE_ROOT / 'parameters/mode').read_text().strip() != args.mode:
                errors.append('loaded module mode differs from requested mode')
            if (MODULE_ROOT / 'parameters/iterations').read_text().strip() != str(args.iterations):
                errors.append('loaded module iterations differ from requested iterations')
            raw = RESULT_PATH.read_text()
            (args.output / 'raw-report.json').write_text(raw)
            parsed_report = json.loads(raw)
            if not isinstance(parsed_report, dict):
                raise ValueError('report must be a JSON object')
            report = parsed_report
            expected_sha = subprocess.check_output(
                ['git', '-C', str(HERE), 'rev-parse', 'HEAD'], text=True).strip()
            expected_header = hashlib.sha256(
                (HERE.parents[2] / 'kernel/io_uring/xdev_ext_mech_lifecycle.h').read_bytes()).hexdigest()
            if report.get('exact_sha') != expected_sha or report.get('lifecycle_header_sha256') != expected_header:
                errors.append('module compiled source/header identity differs from current checkout')
            if report.get('run_nonce') != nonce:
                errors.append('report run nonce differs from this producer')
            if report.get('mode') != args.mode:
                errors.append('report mode differs from requested mode')
            if report.get('iterations') != args.iterations:
                errors.append('report iterations differ from requested iterations')
            if hashlib.sha256(args.module.read_bytes()).hexdigest() != module_hash:
                errors.append('module file changed during load')
            report.update(module_sha256=module_hash, kernel_release=platform.release(), environment=env)
            errors.extend(validate_result(report, performance=args.mode == 'time'))
            validated = True
    except (OSError, ValueError, TypeError, AttributeError, subprocess.CalledProcessError) as error:
        errors.append(str(error))
        (args.output / 'error.txt').write_text(str(error))
    finally:
        if owned:
            try:
                unload = execute_command(['rmmod', 'lifecycle_bench'], args.output / 'unload')
                (args.output / 'unload.json').write_text(json.dumps(unload, indent=2))
                if unload['status'] != 'ok':
                    errors.append('unload failed or not run; resources retained')
                elif MODULE_ROOT.exists() or RESULT_PATH.parent.exists() or RESULT_PATH.exists():
                    errors.append('teardown incomplete: module/debugfs resources remain')
                else:
                    teardown_complete = True
            except Exception as error:
                # Any loader/receipt failure leaves ownership/resource state
                # unresolved; preserve it and invalidate the final result.
                errors.append('unload failed: ' + str(error))
        elif MODULE_ROOT.exists() or RESULT_PATH.parent.exists() or RESULT_PATH.exists():
            errors.append('teardown unverified: unknown producer resources retained; no unload attempted')
        else:
            teardown_complete = True
        if loaded and not validated and not errors:
            errors.append('report validation did not complete')
        success = loaded and validated and not errors and teardown_complete
        if report is not None:
            result.update(report)
        result.update(status='ok' if success else 'failed', validation_errors=errors,
                      requested_mode=args.mode, requested_iterations=args.iterations,
                      requested_run_nonce=nonce, module_sha256=module_hash,
                      performance_eligible=success and args.mode == 'time',
                      teardown_complete=teardown_complete, sealed=success)
        publish()
    return 0 if success else 1


if __name__ == '__main__':
    raise SystemExit(main())
