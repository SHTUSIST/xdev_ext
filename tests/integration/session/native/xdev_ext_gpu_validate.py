#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Console oracle of xdev_ext_gpu_guest.sh on a VFIO-assigned GPU.

  xdev_ext_gpu_validate.py GUEST_LOG RESULT_JSON --release R --device VVVV:DDDD

PASS needs: our modules loaded with the expected release on the expected
device, each guest case reported exactly once with PASS, the guest summary
PASS, a clean module unload, and no NVRM Xid or adapter-initialization error.
Lines prefixed XDEV_EXT_GPU_LOG are raw tool output and never verdicts.

UNSUPPORTED (exit 1, never PASS) replaces PASS only when every other check
holds and each non-PASS case is a refusal that CUDA itself announced for this
GPU: the XDEV_EXT_GPU_CAPS line, matching the probe's own output, reports the
capability as 0, the case line names the matching refusal, and the console
holds the raw refusal (tool output, and for peer-nvme the kernel line of
NVIDIA's persistent pin). The CE chains never qualify: their VA resolution is
the project's own design, so a refusal there stays FAIL.

A CE chain PASS also names its window allocation, and it must be the one the
capability line selects: a cuMemAlloc block (allocation=native) only where
CUDA reports GPUDirect RDMA, otherwise a VMM allocation whose POSIX-FD export
each CE stage fd carries (allocation=vmm).  The tool's own allocation and
release lines must be in the console, and ce-chain-a must report
compare=equal.
"""

import argparse
import json
import re
import sys

CASES = ('ce-chain-d', 'ce-chain-a', 'peer-nvme', 'dmabuf-peer')
# case -> (case-line fields, XDEV_EXT_GPU_CAPS fields) that back UNSUPPORTED.
UNSUPPORTED_EVIDENCE = {
    'peer-nvme': (dict(reason='cuda-no-gpudirect-rdma', step='register', errno='-22'),
                  dict(gpu_direct_rdma='0', pointer_rdma='0')),
    'dmabuf-peer': (dict(reason='cuda-no-dma-buf', dma_buf_supported='0'), dict(dma_buf='0')),
}
# Raw console lines each refusal must also have left.
UNSUPPORTED_RAW = {
    'peer-nvme': (re.compile(r'^XDEV_EXT_GPU_LOG peer-nvme: peer chain failed at register: .* \(-22\)$', re.M),
                  re.compile(r'NVRM: XDEV_EXT peer pin: nvidia_p2p_get_pages_persistent failed: -22$', re.M)),
    'dmabuf-peer': (re.compile(r'^XDEV_EXT_GPU_LOG dmabuf-peer: XDEV_EXT_GPU_DMABUF device=\S+ '
                               r'dma_buf_supported=0$', re.M),),
}
GPU_ERRORS = re.compile(r'NVRM: (?:Xid \(|.*RmInitAdapter failed|.*GPU has fallen off the bus)')
CE_CASES = ('ce-chain-d', 'ce-chain-a')
CE_RAW = {
    'native': r'CUDA allocation=native bdf=\S+ va=0x[0-9a-f]+ bytes=[0-9]+',
    'vmm': r'CUDA allocation=vmm bdf=\S+ va=0x[0-9a-f]+ bytes=[0-9]+ mapped=[0-9]+ '
           r'export=posix-fd attached=2',
}


def _ce_problems(name, fields, caps, text):
    """Why a CE chain PASS line does not show the allocation it should."""
    expected = 'native' if caps.get('gpu_direct_rdma') == '1' else 'vmm'
    mode = fields.get('allocation')
    if mode != expected:
        return [f'case {name} allocation={mode}, capabilities select {expected}']
    problems = []
    for what, pattern in (('allocation', CE_RAW[mode]),
                          ('release', re.escape(f'CUDA allocation={mode} released=yes'))):
        if not re.search(rf'^XDEV_EXT_GPU_LOG {re.escape(name)}: {pattern}$', text, re.M):
            problems.append(f'case {name} lacks the tool {what} line')
    if name == 'ce-chain-a' and fields.get('compare') != 'equal':
        problems.append(f'case {name} PASS without compare=equal')
    return problems


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
    caps_lines = [line for line in lines if line.startswith('XDEV_EXT_GPU_CAPS ')]
    # Only a line the probe itself printed counts, not one the guest made up.
    caps = _fields(caps_lines[0]) if len(caps_lines) == 1 and \
        'XDEV_EXT_GPU_LOG caps: ' + caps_lines[0] in text.splitlines() else {}
    cases = dict.fromkeys(CASES, 'MISSING')
    case_fields = {}
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
                case_fields[name] = fields
    unsupported = []
    for name, state in cases.items():
        if state == 'UNSUPPORTED':
            wanted_case, wanted_caps = UNSUPPORTED_EVIDENCE.get(name, (None, None))
            if wanted_case is not None and \
               all(case_fields[name].get(key) == value for key, value in wanted_case.items()) and \
               all(caps.get(key) == value for key, value in wanted_caps.items()) and \
               all(pattern.search(text) for pattern in UNSUPPORTED_RAW[name]):
                unsupported.append(name)
            else:
                problems.append(f'case {name} UNSUPPORTED without matching CUDA capability evidence')
        elif state != 'PASS':
            problems.append(f'case {name} {state}')
        elif name in CE_CASES:
            problems += _ce_problems(name, case_fields[name], caps, text)
    expected = 'UNSUPPORTED' if unsupported and not problems else 'PASS'
    summary = [line for line in lines if line.startswith('XDEV_EXT_GPU_GUEST=')]
    if module_state == 'PASS' and summary != [s for s in summary if s.startswith(f'XDEV_EXT_GPU_GUEST={expected} ')]:
        problems.append(f'guest summary not {expected}')
    if module_state == 'PASS' and len(summary) != 1:
        problems.append('guest summary missing or repeated')
    unload = [line for line in lines if line.startswith('XDEV_EXT_GPU_UNLOAD=')]
    unload_clean = unload == ['XDEV_EXT_GPU_UNLOAD=PASS']
    if not unload_clean:
        problems.append('module unload not clean: ' + (' | '.join(unload) or 'no unload line'))
    gpu_errors = [line for line in lines if GPU_ERRORS.search(line)]
    if gpu_errors:
        problems.append(f'{len(gpu_errors)} NVRM error line(s)')
    verdict = 'FAIL' if problems else 'UNSUPPORTED' if unsupported else 'PASS'
    return dict(verdict=verdict, modules=module_state, cases=cases, caps=caps,
                unsupported=sorted(unsupported), unload_clean=unload_clean,
                gpu_errors=gpu_errors, problems=problems)


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
