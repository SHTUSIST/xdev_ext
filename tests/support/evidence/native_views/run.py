#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Plan existing shared-page chains; execute only with an explicit --execute.

Native trace collection is optional at import time, mandatory before a measured
workload can start. No command implicitly prepares the NVMe source window.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

from contract import validate_run
from analyze import import_collection

HERE = Path(__file__).resolve().parent
CHAINS = HERE.parent / 'chains' / 'run.py'
COLLECTOR = HERE.parent / 'native_trace' / 'collector.py'
_timer_spec = importlib.util.spec_from_file_location('native_views_timer_scope', COLLECTOR.with_name('timer_scope.py'))
TIMER_SCOPE = importlib.util.module_from_spec(_timer_spec)
_timer_spec.loader.exec_module(TIMER_SCOPE)


def _measurement_scope(manifest, cpu_set=None):
    if cpu_set is None and 'cpu_set' in manifest:
        cpu_set = ','.join(map(str, manifest['cpu_set']))
    scope = TIMER_SCOPE._scope(manifest['clock'], manifest['clock_domain'], cpu_set)
    manifest.setdefault('cpu_scope', scope)
    manifest.setdefault('cpu_set', scope['selected_cpus'])
    manifest.setdefault('measurement_cpu_count', len(scope['selected_cpus']))
    return scope



def execute_command(argv, output_dir):
    """Run argv without a shell, retain real exit status and complete diagnostics.

    This low-level utility is also usable for correctness commands. It cannot
    certify a performance run from a child process's exit code alone.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = output_dir / 'stdout.txt', output_dir / 'stderr.txt'
    receipt = dict(argv=argv, status='not-run', returncode=None,
                   stdout_path=str(stdout_path), stderr_path=str(stderr_path),
                   performance_eligible=False)
    if (not isinstance(argv, list) or not argv or
            any(not isinstance(arg, str) or not arg or '\0' in arg for arg in argv)):
        receipt['error'] = 'argv must be a nonempty list of nonempty strings'
        stderr_path.write_text(receipt['error'] + '\n')
        stdout_path.write_text('')
        return receipt
    try:
        with stdout_path.open('w') as stdout, stderr_path.open('w') as stderr:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr, check=False)
        receipt.update(status='ok' if result.returncode == 0 else 'failed', returncode=result.returncode)
    except (OSError, ValueError) as error:
        receipt['error'] = str(error)
        stderr_path.write_text(str(error) + '\n')
    (output_dir / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def build_commands(manifest):
    """Use real chains CLI; unsupported arms/batching are explicit unavailable.

    A plan is not an experiment result. --pairs remains a chains campaign count;
    the execution scheduler later rotates arms at the independent pair level.
    """
    recipe = manifest.get('recipe')
    if recipe is None:
        return dict(commands=[dict(arm='explicit-%d' % index, argv=argv)
                              for index, argv in enumerate(manifest.get('commands', []))],
                    unavailable=[])
    if not isinstance(recipe, dict) or not isinstance(recipe.get('arms'), list):
        raise ValueError('recipe: object with explicit arms required')
    if len(set(recipe['arms'])) != len(recipe['arms']):
        raise ValueError('recipe.arms: duplicate arm')
    if recipe.get('chain') not in ('nvme-nic', 'nic-nvme'):
        raise ValueError('recipe.chain: only matched nvme-nic/nic-nvme currently supported')
    if not isinstance(recipe.get('rig'), str) or not recipe['rig']:
        raise ValueError('recipe.rig: explicit device rig required')
    for name, maximum in (('records', 65536), ('pairs', 100)):
        if type(recipe.get(name)) is not int or not 1 <= recipe[name] <= maximum:
            raise ValueError('recipe.' + name + ': out of range')
    for name in ('record_bytes', 'depth', 'batch'):
        if type(manifest.get(name)) is not int or manifest[name] < 1:
            raise ValueError(name + ': positive integer required')
    commands, unavailable = [], []
    for arm in recipe['arms']:
        reason = None
        if manifest['batch'] != 1:
            reason = 'native batch=%d unavailable: chains has no native --batch; burst is not batching' % manifest['batch']
        elif arm == 'K-C':
            reason = 'K-C unavailable: no verified same-semantics C mechanism fallback'
        elif arm not in ('U-poll', 'U-event', 'K-BPF'):
            reason = 'arm unavailable: no matched existing workload for ' + str(arm)
        if reason:
            unavailable.append(dict(arm=arm, reason=reason))
            continue
        argv = [sys.executable, str(CHAINS), '--chain', recipe['chain'],
                '--rig', recipe['rig'], '--sizes', str(manifest['record_bytes']),
                '--depth', str(manifest['depth']), '--records', str(recipe['records']),
                '--pairs', str(recipe['pairs']), '--afxdp-mode', 'zc',
                '--load', manifest['load']]
        if arm.startswith('U-'):
            argv += ['--arms', 'userspace-shared', '--wait', 'poll' if arm == 'U-poll' else 'eventfd']
        else:
            argv += ['--arms', 'session', '--plan', 'bpf']
        if 'seed' in recipe:
            if type(recipe['seed']) is not int or not 0 <= recipe['seed'] < 1 << 64:
                raise ValueError('recipe.seed: unsigned 64-bit integer required')
            argv += ['--seed', str(recipe['seed'])]
        warmup = recipe.get('warmup_records', 4)
        if type(warmup) is not int or not 0 <= warmup <= 4096:
            raise ValueError('recipe.warmup_records: out of range')
        argv += ['--warmup-records', str(warmup)]
        commands.append(dict(arm=arm, argv=argv))
    return dict(commands=commands, unavailable=unavailable)


def _load_collector():
    if not COLLECTOR.is_file():
        return None
    spec = importlib.util.spec_from_file_location('xdev_native_trace_collector', COLLECTOR)
    module = importlib.util.module_from_spec(spec)
    # importlib modules may use dataclasses while loading.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _execute(manifest, plan, output, cpu_output=None):
    # Caller assertions never bypass the existing chains hardware gate. This
    # preliminary gate only refuses known nonphysical inputs before a subprocess.
    errors = []
    if manifest.get('physical') is not True:
        errors.append('physical: refusing nonphysical execution')
    if manifest.get('environment') != 'physical':
        errors.append('environment: measured execution requires physical host')
    if manifest.get('evidence_kind') != 'physical':
        errors.append('evidence_kind: fixture/host/VM cannot execute a performance workload')
    if not isinstance(manifest.get('recipe'), dict):
        errors.append('recipe: execution requires an existing chains recipe, not arbitrary commands')
    if errors:
        return dict(status='not-run', reasons=errors, receipts=[], performance_eligible=False), 4
    if plan['unavailable'] or not plan['commands']:
        return dict(status='unavailable', reasons=plan['unavailable'] or ['no runnable arms'],
                    receipts=[], performance_eligible=False), 4
    try:
        collector = _load_collector()
    except (ImportError, OSError, ValueError, AttributeError) as error:
        return dict(status='unavailable', reasons=['native_trace_probe_unavailable: collector cannot load: ' + str(error)],
                    receipts=[], performance_eligible=False), 4
    if collector is None or not callable(getattr(collector, 'collect', None)):
        return dict(status='unavailable', reasons=['native_trace_probe_unavailable: native same-layer collector unavailable'],
                    receipts=[], performance_eligible=False), 4
    recipe = manifest['recipe']
    if 'seed' not in recipe:
        return dict(status='not-run', reasons=['recipe.seed: fixed paired source/oracle seed required'],
                    receipts=[], performance_eligible=False), 2
    output.mkdir(parents=True, exist_ok=True)
    receipts = []
    for pair in range(recipe['pairs']):
        # Rotate order, so each arm does not receive a separate time epoch. Run
        # count stays the statistical unit, regardless of completed record count.
        commands = plan['commands'] if pair % 2 == 0 else list(reversed(plan['commands']))
        for row in commands:
            argv = list(row['argv'])
            argv[argv.index('--pairs') + 1] = '1'
            directory = output / ('pair-%03d' % pair) / row['arm']
            argv += ['--out-dir', str(directory / 'chains')]
            attempt = dict(manifest, arm=row['arm'], pair_id='%s-%03d' % (manifest['pair_id'], pair),
                           run_id='%s-%03d-%s' % (manifest['run_id'], pair, row['arm']))
            _measurement_scope(attempt, ','.join(map(str, manifest['cpu_set'])) if 'cpu_set' in manifest else None)
            try:
                cpu_kwargs = {} if cpu_output is None else {'cpu_output': cpu_output / ('pair-%03d' % pair) / row['arm']}
                receipt = collector.collect(attempt, argv, directory, correctness_only=False, **cpu_kwargs)
            except (OSError, ValueError, RuntimeError) as error:
                receipt = dict(status='failed', reasons=['collector: ' + str(error)])
            receipt = dict(receipt, arm=row['arm'], pair_id=attempt['pair_id'],
                           run_id=attempt['run_id'], performance_eligible=False)
            receipts.append(receipt)
            if receipt.get('status') not in ('ok', 'pass'):
                failed = receipt.get('status') in ('failed', 'fail')
                return dict(status='failed' if failed else 'unavailable', receipts=receipts,
                            reasons=receipt.get('reasons', []) + ['collector/workload did not complete successfully'],
                            trace_collection=receipt, performance_eligible=False), 1 if failed else 4
            if receipt.get('cpu_owner_pending') is True:
                receipt['evidence_import'] = dict(status='pending-owner-finalization', errors=[], performance_eligible=False)
                continue
            evidence = import_collection(attempt, receipt)
            receipt['evidence_import'] = {key: evidence[key] for key in ('status', 'summary', 'errors', 'performance_eligible')}
            receipt['performance_eligible'] = evidence['performance_eligible']
            directory.mkdir(parents=True, exist_ok=True)
            (directory / 'imported-run.json').write_text(json.dumps(evidence['manifest'], indent=2) + '\n')
            if evidence['errors']:
                failed = evidence['status'] == 'failed'
                return dict(status='failed' if failed else 'unavailable', receipts=receipts,
                            reasons=evidence['errors'], trace_collection=receipt,
                            performance_eligible=False), 1 if failed else 4
    return dict(status='ok', receipts=receipts, reasons=[],
                trace_collection=receipts[-1],
                performance_eligible=bool(receipts) and all(r['performance_eligible'] for r in receipts)), 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0], allow_abbrev=False)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--validate-only', action='store_true')
    mode.add_argument('--execute', action='store_true')
    mode.add_argument('--import-collection', type=Path, metavar='RECEIPT',
                      help='verify retained artifacts offline; starts no workload')
    parser.add_argument('--cpu-set')
    parser.add_argument('--cpu-output', type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(Path(args.manifest).read_text())
        errors = validate_run(manifest)
        if errors:
            print(json.dumps(dict(status='not-run', errors=errors, performance_eligible=False)))
            return 2
        if args.import_collection:
            evidence = import_collection(manifest, json.loads(args.import_collection.read_text()))
            print(json.dumps(evidence))
            return 0 if evidence['performance_eligible'] else (1 if evidence['status'] == 'failed' else 4)
        plan = build_commands(manifest)
        if args.dry_run:
            cpu = TIMER_SCOPE.TimerCpuRun(args.cpu_output or args.output / 'cpu-measurements' / 'planned',
                                         cpu_set=args.cpu_set, clock_domain=manifest['clock_domain'],
                                         extra_clocks=('CLOCK_MONOTONIC_RAW',))
            plan['cpu_measurement_plan'] = cpu.plan()
            report, code = dict(status='dry-run', **plan, performance_eligible=False), 0
        elif args.validate_only:
            report, code = dict(status='validated', **plan, performance_eligible=False), 0
        else:
            _measurement_scope(manifest, args.cpu_set)
            report, code = _execute(manifest, plan, args.output, cpu_output=args.cpu_output)
            report['unavailable'] = plan['unavailable']
            report.setdefault('trace_collection', dict(status='unavailable',
                reasons=['native_trace_probe_unavailable: capture not admitted'] + report.get('reasons', []),
                artifacts={}, performance_eligible=False))
            if args.output.is_dir():
                (args.output / 'collection.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))
        return code
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps(dict(status='not-run', errors=[str(error)], performance_eligible=False)))
        return 2


if __name__ == '__main__':
    sys.exit(main())
