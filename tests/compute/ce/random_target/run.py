#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Run actual header rules: controls first; SETUP=2, semantic failure=1."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


def source_root(selected):
    if selected is not None:
        root = selected.resolve()
        if not (root / 'source-layout.json').is_file():
            raise ValueError('selected source root has no canonical layout')
        return root
    for parent in Path(__file__).resolve().parents:
        if (parent / 'source-layout.json').is_file():
            return parent
    raise ValueError('no canonical source root; use --source-root')


def build_directory(root, selected):
    if selected is not None:
        output = selected.absolute()
        for parent in (output, *output.parents):
            if parent.is_symlink():
                raise ValueError('symlink build path: ' + str(parent))
        # Exclusive creation refuses files, directories and dangling symlinks.
        output.mkdir(parents=True, exist_ok=False)
        return output.resolve()
    parent = root / 'build/ce-random-stage1'
    for item in (parent, *parent.parents):
        if item.is_symlink():
            raise ValueError('symlink default build path: ' + str(item))
    parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix='run-', dir=parent))


def write_json(path, value):
    pending = path.with_name(path.name + '.tmp')
    pending.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    pending.replace(path)


def invoke(argv, output, name, receipt):
    record = {'name': name, 'argv': argv, 'status': 'started',
              'returncode': None, 'log': name + '.log'}
    receipt['commands'].append(record)
    write_json(output / (name + '.argv.json'), argv)
    write_json(output / 'run.json', receipt)
    log = output / record['log']
    try:
        with log.open('w', encoding='utf-8') as stream:
            result = subprocess.run(argv, text=True, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=120)
        record.update(status='completed', returncode=result.returncode)
    except Exception as error:
        record.update(status='setup-error', error=str(error))
        write_json(output / (name + '.exit.json'), record)
        write_json(output / 'run.json', receipt)
        raise
    write_json(output / (name + '.exit.json'), record)
    write_json(output / 'run.json', receipt)
    print(log.read_text(encoding='utf-8', errors='replace'), end='', flush=True)
    return result.returncode


def finish(output, receipt, status, code):
    receipt.update(status=status, exit_code=code)
    write_json(output / 'run.json', receipt)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--keep-build', type=Path,
                        help='new evidence/build directory; relative to cwd or absolute')
    parser.add_argument('--suite', choices=('controls', 'flags', 'topology',
                                          'capacity', 'all'), default='all')
    args = parser.parse_args()
    output = None
    receipt = {'schema': 1, 'status': 'setup', 'suite': args.suite,
               'commands': [], 'exit_code': None}
    try:
        root = source_root(args.source_root)
        output = build_directory(root, args.keep_build)
        receipt.update(canonical_root=str(root), build_directory=str(output),
                       reader={'status': 'started', 'view': str(output / 'view')})
        write_json(output / 'run.json', receipt)
        print('BUILD ' + str(output), flush=True)
        # The existing reader validates layout/provenance and copies current
        # canonical bytes. No HEAD checkout and no product helper extraction.
        sys.path.insert(0, str(root / 'tools'))
        from layout import materialize_view

        compiler = shlex.split(args.cc)
        if not compiler:
            raise ValueError('empty compiler command')
        source = root / 'tests/compute/ce/random_target/stage1.c'
        if not source.is_file():
            raise ValueError('missing canonical stage1.c')
        view = materialize_view(root, output / 'view')
        receipt['reader'].update(status='completed', view=str(view.root),
                                 receipt=str(view.root / 'view.json'))
        write_json(output / 'reader.json', receipt['reader'])
        write_json(output / 'run.json', receipt)
        binary = output / 'stage1'
        command = compiler + ['-std=gnu11', '-O2', '-Wall', '-Wextra',
                              '-Werror', '-I' + str(view.root / 'kernel'),
                              str(source), '-o', str(binary)]
        print('COMPILE ' + shlex.join(command), flush=True)
        if invoke(command, output, 'compile', receipt):
            print('SETUP: compilation failed; no semantic RED recorded', flush=True)
            return finish(output, receipt, 'setup', 2)
        result = invoke([str(binary), 'controls'], output, 'controls', receipt)
        if result:
            print('CONTROL_FAIL: new behavior was not assessed', flush=True)
            return finish(output, receipt, 'control-fail' if result == 1 else 'setup',
                          1 if result == 1 else 2)
        if args.suite == 'controls':
            return finish(output, receipt, 'passed', 0)
        suites = ('flags', 'topology', 'capacity') if args.suite == 'all' else (args.suite,)
        failed = False
        for suite in suites:
            result = invoke([str(binary), suite], output, suite, receipt)
            if result not in (0, 1):
                print('SETUP: cohort did not report a semantic verdict', flush=True)
                return finish(output, receipt, 'setup', 2)
            failed |= result == 1
        return finish(output, receipt, 'failed' if failed else 'passed', 1 if failed else 0)
    except Exception as error:
        print('SETUP: ' + str(error), file=sys.stderr, flush=True)
        if output is not None:
            receipt.update(status='setup', exit_code=2, error=str(error))
            if receipt.get('reader', {}).get('status') == 'started':
                receipt['reader'].update(status='setup-error', error=str(error))
            try:
                write_json(output / 'reader.json', receipt.get('reader', {}))
                write_json(output / 'run.json', receipt)
            except Exception as receipt_error:
                print('SETUP: could not persist final receipt: ' + str(receipt_error),
                      file=sys.stderr, flush=True)
        return 2


if __name__ == '__main__':
    try:
        exit_code = main()
    except Exception as error:
        # Includes argument/setup bugs before main's retained receipt exists.
        print('SETUP: ' + str(error), file=sys.stderr, flush=True)
        exit_code = 2
    raise SystemExit(exit_code)
