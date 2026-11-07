#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compile actual header controls then frozen native runner contract tests."""
import argparse
from pathlib import Path
import shlex
import sys


def main():
    root = next(p for p in Path(__file__).resolve().parents if (p/'source-layout.json').is_file())
    sys.path.insert(0, str(root/'tests/compute/ce/random_target'))
    from runtime_validate import load
    helper = load('random_control_runner', root/'tests/compute/ce/random_target/run.py')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keep-build', type=Path)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--case',choices=('contract','key-end'),default='contract')
    args = parser.parse_args()
    output = helper.build_directory(root, args.keep_build)
    receipt = dict(schema=1,status='setup',exit_code=None,commands=[],canonical_root=str(root))
    helper.write_json(output/'run.json', receipt)
    try:
        sys.path.insert(0,str(root/'tools'))
        from layout import materialize_view
        view = materialize_view(root, output/'view')
        helper.write_json(output/'reader.json',dict(status='completed',view=str(view.root),receipt=str(view.root/'view.json')))
        compiler = shlex.split(args.cc)
        if not compiler:
            raise ValueError('empty compiler')
        binary = output/'contract-test'
        command = compiler+['-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(view.root/'kernel'),
                            str(Path(__file__).with_name('contract_test.c')),'-o',str(binary)]
        if helper.invoke(command,output,'compile-contract',receipt):
            return helper.finish(output,receipt,'setup',2)
        result = helper.invoke([str(binary),'controls'],output,'controls',receipt)
        if result:
            return helper.finish(output,receipt,'control-fail' if result==1 else 'setup',1 if result==1 else 2)
        if args.case=='key-end':
            target=output/'key-end-test'
            command=compiler+['-std=gnu11','-O2','-Wall','-Wextra','-Werror','-I'+str(view.root/'kernel'),
                              str(Path(__file__).with_name('key_end_test.c')),'-o',str(target)]
            if helper.invoke(command,output,'compile-key-end',receipt):
                return helper.finish(output,receipt,'setup',2)
            result=helper.invoke([str(target)],output,'key-end',receipt)
        else:
            result = helper.invoke([str(binary),'contract'],output,'contract',receipt)
        if result not in (0,1):
            return helper.finish(output,receipt,'setup',2)
        return helper.finish(output,receipt,'failed' if result else 'passed',result)
    except Exception as error:
        receipt['error']=str(error)
        print('SETUP: '+str(error),file=sys.stderr)
        return helper.finish(output,receipt,'setup',2)


if __name__ == '__main__':
    try:
        status=main()
    except Exception as error:
        print('SETUP: '+str(error),file=sys.stderr)
        status=2
    raise SystemExit(status)
