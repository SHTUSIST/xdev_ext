#!/usr/bin/env python3
"""Compile explicit CE body mutations against an already accepted extraction.

Recipes only edit generated input. A compiler error, signal, timeout, or unrelated
failure is never counted as a detected behavioral mutation.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-evidence', type=pathlib.Path, required=True)
    parser.add_argument('--recipes', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parent / 'mutation-recipes.json')
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.base_evidence = args.base_evidence.resolve()
    args.output = args.output.resolve()
    args.recipes = args.recipes.resolve()
    args.output.mkdir(parents=True, exist_ok=True)
    base = json.loads((args.base_evidence / 'receipt.json').read_text())
    if base['compile_exit'] or base['execution_exit']:
        print('SETUP: mutations require a compiled passing repaired base')
        return 2
    source = (args.base_evidence / 'actual-ce.c').read_text()
    outcomes = []
    for recipe in json.loads(args.recipes.read_text()):
        directory = args.output / recipe['name']
        directory.mkdir(exist_ok=True)
        mutant = source
        result = {'name': recipe['name'], 'expected_failure': recipe['expected_failure'], 'applied_edits': []}
        try:
            for edit in recipe['edits']:
                count = mutant.count(edit['old'])
                if count != edit.get('matches', 1):
                    raise ValueError(f"edit matches {count}, expected {edit.get('matches', 1)}")
                mutant = mutant.replace(edit['old'], edit['new'])
                result['applied_edits'].append({'matches': count, 'old_sha256': hashlib.sha256(edit['old'].encode()).hexdigest(), 'new_sha256': hashlib.sha256(edit['new'].encode()).hexdigest()})
            if mutant == source:
                raise ValueError('mutation made no change')
            (directory / 'actual-ce.c').write_text(mutant)
            for name in ('actual-api.h', 'actual-checked.c'):
                shutil.copyfile(args.base_evidence / name, directory / name)
            command = base['compile_command'][:]
            here = pathlib.Path(__file__).resolve().parent
            command[command.index(str(here / 'harness.c'))] = str(here / 'mutation_driver.c')
            command[command.index('-I' + str(args.base_evidence))] = '-I' + str(directory)
            command[command.index('-o') + 1] = str(directory / 'ce-mutant')
            result['compile_command'] = command
            build = subprocess.run(command, capture_output=True, text=True, timeout=30)
            (directory / 'build.log').write_text(build.stdout + build.stderr)
            result['compile_exit'] = build.returncode
            if build.returncode:
                result['verdict'] = 'SETUP'
            else:
                run = subprocess.run([str(directory / 'ce-mutant'), recipe['control']], capture_output=True, text=True, timeout=10)
                (directory / 'run.log').write_text(run.stdout + run.stderr)
                result['execution_exit'] = run.returncode
                result['specific_assertion_seen'] = recipe['expected_failure'] in run.stdout
                result['assertion_summary_seen'] = bool(re.search(r'^checks=[1-9][0-9]* failures=[1-9][0-9]*$', run.stdout, re.M))
                result['sanitizer_error_seen'] = 'runtime error:' in run.stdout + run.stderr
                if (run.returncode == 1 and result['specific_assertion_seen']
                        and result['assertion_summary_seen'] and not result['sanitizer_error_seen']):
                    result['verdict'] = 'DETECTED'
                elif run.returncode < 0:
                    result['verdict'] = 'SETUP_SIGNAL'
                elif run.returncode == 0:
                    result['verdict'] = 'SURVIVED'
                else:
                    result['verdict'] = 'UNCLASSIFIED_FAILURE'
            result['mutant_sha256'] = hashlib.sha256(mutant.encode()).hexdigest()
        except (ValueError, subprocess.TimeoutExpired) as error:
            result['verdict'] = 'SETUP'
            result['reason'] = str(error)
        outcomes.append(result)
        (directory / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
        print(recipe['name'], result['verdict'])
    (args.output / 'receipt.json').write_text(json.dumps({'base_evidence': str(args.base_evidence), 'base_ce_sha256': base['ce_sha256'], 'base_source_sha256': base.get('source_sha256', {}), 'mutants': outcomes}, indent=2) + '\n')
    return 0 if outcomes and all(row['verdict'] == 'DETECTED' for row in outcomes) else 1


if __name__ == '__main__':
    sys.exit(main())
