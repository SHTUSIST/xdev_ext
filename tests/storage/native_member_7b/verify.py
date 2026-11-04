#!/usr/bin/env python3
"""Run the independent six-cohort/54-mutant public host acceptance gate."""
import argparse
from collections import Counter
import hashlib
import json
import pathlib
import subprocess
import sys

sys.dont_write_bytecode = True
import adapter
import mutations_candidate

A = pathlib.Path(__file__).resolve().parent
COHORT_OUTPUTS = {
    'strict': 'PASS STOR7B literal assertions 600\n',
    'bounce': 'PASS STOR7B literal assertions 671\n',
    'disabled': 'PASS STOR7B literal assertions 599\n',
    'golden-gcc': 'PASS native_member_7a candidate 558 literal assertions\n',
    'golden-ubsan': 'PASS native_member_7a candidate 558 literal assertions\n',
    'common': ('PASS STOR7B common ownership and wiring 82 assertions\n'
               'PASS STOR7B additional custom hook assertions 34\n'),
}
REVERSE_LABELS = Counter({'golden/assertions.c': 6, 'assertions_7b.c': 6,
                          'golden/candidate.c.in': 2})


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preserved():
    inputs = json.loads((A / 'INPUTS.json').read_text())
    return {name: digest(A / name) == expected
            for name, expected in inputs['files'].items()}


def assess(full, mutants, proofs):
    """Accept only the complete schedule and the exact designated diagnostics."""
    inputs = json.loads((A / 'INPUTS.json').read_text())['files']
    originals = {
        'golden/assertions.c': inputs['../native_member_7a/assertions.c'],
        'assertions_7b.c': inputs['assertions_7b.c'],
        'golden/candidate.c.in': inputs['../native_member_7a/candidate.c.in'],
    }
    cohort_rows = full['results']
    mutant_rows = mutants['results']
    expected_mutants = mutations_candidate.D
    original_7a = {name: recipe[-1] for name, recipe in adapter.m.old.MUTANTS.items()}
    initial_7b = json.loads((A / 'INPUTS.json').read_text())['mutation_sets']['initial_7b']
    required_names = set(original_7a) | set(initial_7b)
    return {
        'exact_six_cohorts': (len(cohort_rows) == 6 and
            Counter(row['name'] for row in cohort_rows) == Counter(COHORT_OUTPUTS.keys())),
        'all_cohorts_compile_and_run': all(
            row.get('verdict') == 'PASS' and row.get('compile_exit') == 0 and
            row.get('run_exit') == 0 and row.get('output') == COHORT_OUTPUTS.get(row['name'])
            for row in cohort_rows),
        'original_7a_coverage_preserved': (len(original_7a) == 12 and all(
            name in expected_mutants and expected_mutants[name]['expected'] == label
            for name, label in original_7a.items())),
        'initial_7b_coverage_preserved': (len(initial_7b) == 45 and all(
            name in expected_mutants and expected_mutants[name]['expected'] == label
            for name, label in initial_7b.items())),
        'exact_54_mutants': (len(required_names) == 54 and set(expected_mutants) == required_names and
            len(mutant_rows) == 54 and
            Counter(row['name'] for row in mutant_rows) == Counter(required_names)),
        'all_designated_mutants_killed': all(
            row['name'] in expected_mutants and row.get('verdict') == 'KILLED' and
            row.get('compile_exit') == 0 and row.get('run_exit') == 1 and
            row.get('expected_assertion') == expected_mutants[row['name']]['expected'] and
            'ASSERTION ' + expected_mutants[row['name']]['expected'] + ' ' in row.get('output', '')
            for row in mutant_rows),
        'exact_fourteen_reversal_labels': (len(proofs) == 14 and
            Counter(row['label'] for row in proofs) == REVERSE_LABELS),
        'all_reversals_exact_original': all(
            row.get('reverse_exact') is True and row['label'] in originals and
            row.get('original_sha256') == originals[row['label']] and
            row.get('reverse_sha256') == originals[row['label']]
            for row in proofs),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=pathlib.Path, required=True)
    parser.add_argument('--out', type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.source_root = args.source_root.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(exist_ok=False)
    commands = []
    checks = {}
    errors = []
    try:
        before = adapter.snapshot(args.source_root)
        (args.out / 'SOURCE.json').write_text(json.dumps(before, indent=2) + '\n')
        checks['frozen_public_inputs_before'] = all(preserved().values())
        if not checks['frozen_public_inputs_before']:
            raise ValueError('public test inputs differ from INPUTS.json')
        for runner, name in [('adapter.py', 'full'), ('mutations_candidate.py', 'mutations')]:
            cmd = [sys.executable, str(A / runner), '--source-root', str(args.source_root),
                   '--out', str(args.out / name)]
            with (args.out / (name + '.log')).open('w') as log:
                result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT)
            commands.append({'command': cmd, 'exit': result.returncode})
            print(name, 'exit', result.returncode, flush=True)
        after = adapter.snapshot(args.source_root)
        (args.out / 'SOURCE-AFTER.json').write_text(json.dumps(after, indent=2) + '\n')
        checks['selected_source_and_test_inputs_stable'] = before == after
        checks['frozen_public_inputs_after'] = all(preserved().values())
        checks['both_runners_exit_zero'] = len(commands) == 2 and all(row['exit'] == 0 for row in commands)
        full = json.loads((args.out / 'full/RESULT.json').read_text())
        mutants = json.loads((args.out / 'mutations/RESULT.json').read_text())
        proofs = json.loads((args.out / 'full/PROOFS.json').read_text())
        checks.update(assess(full, mutants, proofs))
    except Exception as error:
        errors.append(type(error).__name__ + ': ' + str(error))
    passed = bool(checks) and not errors and all(checks.values())
    report = {'commands': commands, 'checks': checks, 'errors': errors,
              'status': 'PASS' if passed else 'NOT_READY',
              'scope': 'actual production function/header host boundary only; no kernel/DMA/performance acceptance'}
    (args.out / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
