#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Console oracle of xdev_ext_gpu_guest.sh on a VFIO-assigned GPU.

  xdev_ext_gpu_validate.py GUEST_LOG RESULT_JSON --release R --device VVVV:DDDD

PASS needs: our modules loaded with the expected release on the expected
device, each guest case reported exactly once with PASS, the guest summary
PASS, a clean module unload, and no NVRM Xid or adapter-initialization error.
Lines prefixed XDEV_EXT_GPU_LOG are raw tool output and never verdicts.
"""

import argparse
import json
import re
import sys

CASES = ('ce-chain-d', 'ce-chain-a', 'peer-nvme', 'dmabuf-peer')
GPU_ERRORS = re.compile(r'NVRM: (?:Xid \(|.*RmInitAdapter failed|.*GPU has fallen off the bus)')


def _fields(line):
    return dict(item.split('=', 1) for item in line.split()[1:] if '=' in item)


def validate(text, *, release, device):
    lines = [line for line in text.splitlines() if not line.startswith('XDEV_EXT_GPU_LOG ')]
    problems = []
    modules = [line for line in lines if line.startswith('XDEV_EXT_GPU_MODULES=')]
    module_state = 'MISSING'
    if len(modules) == 1:
        head = modules[0].split()[0].split('=', 1)[1]
        fields = _fields(modules[0])
        module_state = head
        if head == 'PASS' and (fields.get('release') != release or fields.get('device') != device):
            module_state = 'FAIL'
            problems.append(f'modules report release={fields.get("release")} '
                            f'device={fields.get("device")}, expected {release} {device}')
    elif modules:
        problems.append('module verdict repeated')
        module_state = 'FAIL'
    if module_state != 'PASS':
        problems.append(f'modules {module_state}')
    cases = dict.fromkeys(CASES, 'MISSING')
    for line in lines:
        if line.startswith('XDEV_EXT_GPU_CASE '):
            fields = _fields(line)
            name = fields.get('name')
            if name not in cases:
                problems.append(f'unknown case {name}')
            elif cases[name] != 'MISSING':
                problems.append(f'case {name} reported twice')
                cases[name] = 'FAIL'
            else:
                cases[name] = fields.get('result', 'FAIL')
    for name, state in cases.items():
        if state != 'PASS':
            problems.append(f'case {name} {state}')
    summary = [line for line in lines if line.startswith('XDEV_EXT_GPU_GUEST=')]
    if module_state == 'PASS' and summary != [s for s in summary if s.startswith('XDEV_EXT_GPU_GUEST=PASS ')]:
        problems.append('guest summary not PASS')
    if module_state == 'PASS' and len(summary) != 1:
        problems.append('guest summary missing or repeated')
    unload = [line for line in lines if line.startswith('XDEV_EXT_GPU_UNLOAD=')]
    unload_clean = unload == ['XDEV_EXT_GPU_UNLOAD=PASS']
    if not unload_clean:
        problems.append('module unload not clean: ' + (' | '.join(unload) or 'no unload line'))
    gpu_errors = [line for line in lines if GPU_ERRORS.search(line)]
    if gpu_errors:
        problems.append(f'{len(gpu_errors)} NVRM error line(s)')
    return dict(verdict='PASS' if not problems else 'FAIL', modules=module_state,
                cases=cases, unload_clean=unload_clean, gpu_errors=gpu_errors,
                problems=problems)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('log')
    parser.add_argument('result')
    parser.add_argument('--release', required=True)
    parser.add_argument('--device', required=True)
    args = parser.parse_args(argv)
    with open(args.log, errors='replace') as source:
        result = validate(source.read(), release=args.release, device=args.device)
    with open(args.result, 'w') as out:
        json.dump(result, out, indent=1, sort_keys=True)
        out.write('\n')
    print(f'XDEV_EXT_GPU_VFIO={result["verdict"]} ' +
          ' '.join(f'{name}={state}' for name, state in result['cases'].items()) +
          f' unload_clean={int(result["unload_clean"])}')
    for problem in result['problems']:
        print('PROBLEM ' + problem)
    return 0 if result['verdict'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
