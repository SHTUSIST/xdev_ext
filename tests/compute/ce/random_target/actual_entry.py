#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual validator publication and CE lease consumption, no prequalification."""
import argparse
from pathlib import Path
import shlex
import sys


def main():
    from runtime_validate import load
    from range_lease import assemble

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--keep-build', type=Path)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--suite', choices=('controls', 'forward', 'reverse', 'all'), default='all')
    args = parser.parse_args()
    helper = load('ce_actual_entry_runner', Path(__file__).with_name('run.py'))
    output = None
    receipt = {'schema': 1, 'status': 'setup', 'suite': args.suite,
               'commands': [], 'exit_code': None}
    try:
        root = helper.source_root(args.source_root)
        output = helper.build_directory(root, args.keep_build)
        receipt.update(canonical_root=str(root), build_directory=str(output),
                       reader={'status': 'started', 'view': str(output / 'view')})
        helper.write_json(output / 'run.json', receipt)
        sys.path.insert(0, str(root / 'tools'))
        from layout import materialize_view
        view = materialize_view(root, output / 'view')
        reader = load('ce_actual_entry_reader', root / 'tests/support/benchmarks/ce_vmm_contract.py')
        selection = assemble(root, output, reader)
        # Assembly is shared; the new driver never constructs a candidate.
        selection.update(qualified_plan_input=False,
                         actual_validation_publication_required=True,
                         test_source='tests/compute/ce/random_target/actual_entry.c')
        helper.write_json(output / 'selection.json', selection)
        receipt['reader'].update(status='completed', receipt=str(view.root / 'view.json'))
        helper.write_json(output / 'reader.json', receipt['reader'])
        compiler = shlex.split(args.cc)
        if not compiler:
            raise ValueError('empty compiler command')
        binary = output / 'actual-entry'
        source = root / 'tests/compute/ce/random_target/actual_entry.c'
        argv = compiler + ['-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                '-I' + str(output), '-I' + str(view.root / 'kernel'), str(source), '-o', str(binary)]
        if helper.invoke(argv, output, 'compile', receipt):
            return helper.finish(output, receipt, 'setup', 2)
        result = helper.invoke([str(binary), 'controls'], output, 'controls', receipt)
        if result:
            return helper.finish(output, receipt, 'control-fail' if result == 1 else 'setup',
                                 1 if result == 1 else 2)
        suites = () if args.suite == 'controls' else (
            ('forward', 'reverse') if args.suite == 'all' else (args.suite,))
        failed = False
        for suite in suites:
            result = helper.invoke([str(binary), suite], output, suite, receipt)
            if result not in (0, 1):
                return helper.finish(output, receipt, 'setup', 2)
            failed |= result == 1
        return helper.finish(output, receipt, 'failed' if failed else 'passed', 1 if failed else 0)
    except Exception as error:
        print('SETUP: ' + str(error), file=sys.stderr)
        if output is not None:
            receipt.update(status='setup', exit_code=2, error=str(error))
            if receipt.get('reader', {}).get('status') == 'started':
                receipt['reader'].update(status='setup-error', error=str(error))
            helper.write_json(output / 'reader.json', receipt.get('reader', {}))
            helper.write_json(output / 'run.json', receipt)
        return 2


if __name__ == '__main__':
    try:
        code = main()
    except Exception as error:
        print('SETUP: ' + str(error), file=sys.stderr)
        code = 2
    raise SystemExit(code)
