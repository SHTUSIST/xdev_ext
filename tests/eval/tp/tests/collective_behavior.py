#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check observations from real TP production functions; never emulate TP.

Probe invocation: PROBE --tp-observe-json
stdin: one JSON request, schema=1 plus case name/family/request.
stdout: one JSON object containing observed behavior. No expected values are sent.
The probe must not read collective_vectors.json or calculate expected values.
"""
import argparse
import json
import math
from pathlib import Path
import struct
import subprocess
import sys


def decode(bits, dtype):
    value = int(bits, 16)
    if dtype == 'f16':
        return struct.unpack('<e', value.to_bytes(2, 'little'))[0]
    if dtype == 'bf16':
        return struct.unpack('<f', (value << 16).to_bytes(4, 'little'))[0]
    if dtype == 'f32':
        return struct.unpack('<f', value.to_bytes(4, 'little'))[0]
    raise ValueError('unknown dtype for numeric assertion: ' + str(dtype))


def compare(want, got, dtype, path='observation'):
    """Literal subset assertions; numeric expectations are independent fixtures."""
    errors = []
    if isinstance(want, dict) and want.get('nan') is True:
        try:
            good = math.isnan(decode(got, dtype))
        except (ValueError, TypeError, OverflowError):
            good = False
        return [] if good else [path + ': expected NaN, got ' + repr(got)]
    if isinstance(want, dict) and 'value' in want and 'atol' in want:
        try:
            actual = decode(got, dtype)
            good = math.isfinite(actual) and abs(actual - want['value']) <= want['atol']
        except (ValueError, TypeError, OverflowError):
            good = False
        return [] if good else [path + ': outside fixed finite tolerance: ' + repr(got)]
    if isinstance(want, dict):
        if not isinstance(got, dict):
            return [path + ': expected object, got ' + repr(got)]
        for key, value in want.items():
            if key == 'status_negative':
                if not isinstance(got.get('status'), int) or isinstance(got.get('status'), bool) or got['status'] >= 0:
                    errors.append(path + '.status: expected negative errno')
            elif key not in got:
                errors.append(path + '.' + key + ': missing observation')
            else:
                errors.extend(compare(value, got[key], dtype, path + '.' + key))
        return errors
    if isinstance(want, list):
        if not isinstance(got, list) or len(want) != len(got):
            return [path + ': wrong array length/type, got ' + repr(got)]
        for index, (left, right) in enumerate(zip(want, got)):
            errors.extend(compare(left, right, dtype, path + '[' + str(index) + ']'))
        return errors
    if type(want) is not type(got) or want != got:
        errors.append(path + ': want ' + repr(want) + ', got ' + repr(got))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path)
    parser.add_argument('--vectors', type=Path, default=Path(__file__).with_name('collective_vectors.json'))
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--family', action='append')
    args = parser.parse_args()
    inventory = json.loads(args.vectors.read_text())
    cases = [c for c in inventory['cases'] if not args.family or c['family'] in args.family]
    receipt = dict(schema=1,scope='software-observation-only',gpu_execution='not-run',
                   vectors=str(args.vectors.resolve()),probe=str(args.probe) if args.probe else None,
                   pass_count=0,fail_count=0,blocked_count=0,cases=[])
    print('TAP version 13')
    print('1..' + str(len(cases)))
    for number, case in enumerate(cases, 1):
        result = dict(name=case['name'],family=case['family'])
        if args.probe is None or not args.probe.is_file():
            result.update(status='BLOCKED',reason='No real production observation probe: deep path not executed')
            receipt['blocked_count'] += 1
            print('not ok ' + str(number) + ' - ' + case['name'] + ' # BLOCKED production path absent')
        else:
            request = dict(schema=1,name=case['name'],family=case['family'],request=case['request'])
            try:
                proc = subprocess.run([str(args.probe.resolve()), '--tp-observe-json'],
                                      input=json.dumps(request),text=True,capture_output=True,
                                      timeout=30,check=False)
                result.update(returncode=proc.returncode,stdout=proc.stdout,stderr=proc.stderr)
                if proc.returncode:
                    errors = ['probe exit ' + str(proc.returncode)]
                else:
                    observed = json.loads(proc.stdout)
                    result['observed'] = observed
                    errors = compare(case['expected'],observed,case['request'].get('dtype'))
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
                errors = [str(exc)]
            if errors:
                result.update(status='FAIL',errors=errors)
                receipt['fail_count'] += 1
                print('not ok ' + str(number) + ' - ' + case['name'])
                for error in errors:
                    print('# ' + error.replace('\n', ' '))
            else:
                result['status'] = 'PASS'
                receipt['pass_count'] += 1
                print('ok ' + str(number) + ' - ' + case['name'])
        receipt['cases'].append(result)
    receipt['status'] = 'FAIL' if receipt['fail_count'] else 'BLOCKED' if receipt['blocked_count'] else 'PASS'
    args.receipt.parent.mkdir(parents=True,exist_ok=True)
    args.receipt.write_text(json.dumps(receipt,indent=2)+'\n')
    print('# ' + json.dumps({k:receipt[k] for k in ('status','pass_count','fail_count','blocked_count')}))
    return 1 if receipt['fail_count'] else 2 if receipt['blocked_count'] else 0


if __name__ == '__main__':
    sys.exit(main())
