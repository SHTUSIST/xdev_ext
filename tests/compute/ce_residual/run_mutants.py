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


def owned_body(source, symbol):
    """Select one complete actual function, ignoring C comments/literals."""
    matches = list(re.finditer(r'^(?:static )?int ' + re.escape(symbol) +
                              r'\([^;{}]*\)\s*\{', source, re.M))
    if len(matches) != 1:
        raise ValueError('owned function count is not one: ' + symbol)
    match = matches[0]
    start = source.index('{', match.start())
    depth, quote, comment, escaped = 0, None, None, False
    i = start
    while i < len(source):
        c, following = source[i], source[i + 1:i + 2]
        if comment == 'line':
            if c == '\n':
                comment = None
        elif comment == 'block':
            if c == '*' and following == '/':
                comment = None
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == quote:
                quote = None
        elif c == '/' and following in ('/', '*'):
            comment = 'line' if following == '/' else 'block'
            i += 1
        elif c in ('"', "'"):
            quote = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return source[match.start():i + 1]
        i += 1
    raise ValueError('incomplete owned function: ' + symbol)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('owned algorithm anchor count is not one')
    return source.replace(old, new, 1)


def current_edits(recipe, source):
    """Port only three old full-body anchors; preserve the frozen fault/want."""
    name = recipe['name']
    if name not in ('late-publication', 'skip-own-active',
                    'missing-success-hold-release'):
        return recipe['edits'], None
    if len(recipe['edits']) != 1:
        raise ValueError('ported recipe must have one original edit')
    edit = recipe['edits'][0]
    if source.count(edit['old']):
        return recipe['edits'], None
    if edit.get('matches', 1) != 1:
        raise ValueError('ported recipe must retain one exact match')
    owner = original_owner = 'xdev_ext_ce_bind'
    if name == 'late-publication':
        lease = ('\terr = xdev_ext_ce_lease_bind(st, cs, u->arg0, u->arg1);\n'
                 '\tif (err)\n\t\treturn err;\n')
        native = ('\terr = cs->ops->bind_region(st->file, u->arg0, u->arg1, &cs->region);\n'
                  '\tcs->region.ops = cs->ops;\n\tif (err)\n\t\treturn err;\n')
        old, new = lease + native, native + lease
        reason = 'same lease publication moved after native bind_region'
    elif name == 'skip-own-active':
        original_owner = 'xdev_ext_comp_copy_lease_get'
        owner = 'xdev_ext_comp_copy_lease_get_mode'
        old = ('\tmutex_lock(&domain->lock);\n'
               '\tlist_for_each_entry(other, &domain->groups, node) {')
        new = ('\tmutex_lock(&domain->lock);\n'
               '\tif (!group->state.active_batches)\n'
               '\tlist_for_each_entry(other, &domain->groups, node) {')
        reason = 'same other-group cleanup scan omitted when own group is active'
    else:
        old = '\txdev_ext_comp_copy_lease_hold(&cs->lease, false);\n'
        new = '\t/* mutation: leave transient hold after successful bind */\n'
        reason = 'same successful bind retains its transient cleanup hold'
    if (owned_body(edit['old'], original_owner) != edit['old'] or
            replace_once(edit['old'], old, new) != edit['new']):
        raise ValueError('original recipe no longer encodes the named fault')
    body = owned_body(source, owner)
    changed = replace_once(body, old, new)
    return [{'old': body, 'new': changed, 'matches': 1}], {
        'owner': owner, 'reason': reason,
        'original_recipe_sha256': hashlib.sha256(
            json.dumps(recipe, sort_keys=True).encode()).hexdigest()}


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
            edits, port = current_edits(recipe, source)
            if port is not None:
                result['recipe_port'] = port
            for edit in edits:
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
