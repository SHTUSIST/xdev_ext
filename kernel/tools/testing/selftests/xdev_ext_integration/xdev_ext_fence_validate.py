#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Host validator for real matching-guest lifecycle/dma_fence check evidence.

This never generates guest evidence, runs a module, or accepts performance data.
"""
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
CASES = ('check', 'alloc1', 'alloc2', 'callback1', 'callback2')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def load_json(text):
    return json.loads(text, object_pairs_hook=unique_object)


def validate(text, qemu_exit, request):
    # Reuse the actual experiment validator, never a host-fixture oracle.
    path = HERE.parents[4] / 'tests/eval/dmabuf_lifecycle/run.py'
    spec = importlib.util.spec_from_file_location('fence_actual_runner', path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    spec = importlib.util.spec_from_file_location('fence_debug', HERE / 'xdev_ext_mech_zc_debug.py')
    debug = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(debug)
    debug.check_console(text)
    if type(qemu_exit) is not int or qemu_exit != 0:
        raise ValueError('outer QEMU exit failed')
    lines = text.splitlines()
    if lines.count('XDEV_EXT_ZC_GUEST_EXIT=0') != 1 or any(
            x.startswith('XDEV_EXT_ZC_GUEST_EXIT=') and x != 'XDEV_EXT_ZC_GUEST_EXIT=0' for x in lines):
        raise ValueError('outer guest exit missing, repeated, or failed')
    prefix, n = request.get('nonce_prefix'), request.get('iterations')
    if not isinstance(prefix, str) or not re.fullmatch('[0-9a-f]{31}', prefix) or type(n) is not int or not 1 <= n <= 64:
        raise ValueError('invalid check request nonce/count')
    for key, length in (('exact_sha', 40), ('lifecycle_header_sha256', 64), ('module_sha256', 64)):
        if not re.fullmatch('[0-9a-f]{%d}' % length, str(request.get(key, ''))):
            raise ValueError('invalid request ' + key)
    if not isinstance(request.get('kernel_release'), str) or not request['kernel_release']:
        raise ValueError('invalid request kernel release')
    nonce = prefix + '0'
    begin = (f'XDEV_EXT_FENCE_BEGIN nonce={nonce} mode=check iterations={n} '
             f'sysfs_nonce={nonce} sysfs_mode=check sysfs_iterations={n}')
    try:
        start = lines.index(begin)
        if lines[start + 1] != 'XDEV_EXT_FENCE_JSON_BEGIN':
            raise ValueError('missing raw report begin')
        end = lines.index('XDEV_EXT_FENCE_JSON_END', start + 2)
        report = load_json('\n'.join(lines[start + 2:end]))
    except (ValueError, IndexError) as error:
        raise ValueError('missing or malformed complete raw report: ' + str(error)) from error
    if not isinstance(report, dict):
        raise ValueError('raw report must be object')
    for key in ('exact_sha', 'lifecycle_header_sha256'):
        if report.get(key) != request[key]:
            raise ValueError('raw report source mismatch: ' + key)
    if report.get('run_nonce') != nonce or report.get('mode') != 'check' or report.get('iterations') != n:
        raise ValueError('raw report producer/request mismatch')
    if report.get('kernel_runtime') is not True or report.get('evidence_kind') != 'kernel-runtime':
        raise ValueError('raw report is not kernel evidence')
    if report.get('execution_context') != 'serial-process':
        raise ValueError('invalid raw execution context')
    if type(report.get('schema_version')) is not int or report['schema_version'] != 1:
        raise ValueError('invalid raw schema')
    concurrent = report.get('concurrent_check')
    if (not isinstance(concurrent, dict) or concurrent.get('executed') is not True or
            type(concurrent.get('contexts')) is not int or concurrent['contexts'] != 2):
        raise ValueError('missing real two-context check')
    # Python bool == int must not admit counters. Preserve the full raw report;
    # add only the module-file and running-release observations supplied by host.
    for arm in ('life', 'dma_fence'):
        data = report.get('arms', {}).get(arm, {})
        fields = ('attempted', 'successful', 'produced', 'consumed', 'recycled',
                  'valid_len_checks', 'errors', 'allocations_setup', 'allocations_steady')
        if arm == 'dma_fence':
            fields += ('fence_objects', 'fence_releases')
        if any(type(data.get(key)) is not int for key in fields):
            raise ValueError('noninteger arm counter')
    if type(report.get('oracle_checked_operations')) is not int:
        raise ValueError('noninteger oracle counter')
    def no_timing(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in ('timing', 'ratio') or key.endswith(('_ratio', '_ns')) or key.startswith('ns_'):
                    raise ValueError('check contains timing')
                no_timing(child)
        elif isinstance(value, list):
            for child in value:
                no_timing(child)
    no_timing(report)
    augmented = dict(report, module_sha256=request['module_sha256'], kernel_release=request['kernel_release'])
    errors = runner.validate_result(augmented, performance=False)
    if errors:
        raise ValueError('experiment report: ' + ', '.join(errors))
    identity = f'XDEV_EXT_FENCE_IDENTITY kernel_release={request["kernel_release"]} module_sha256={request["module_sha256"]}'
    want = [identity, begin, 'XDEV_EXT_FENCE_JSON_BEGIN', 'XDEV_EXT_FENCE_JSON_END']
    for i, case in enumerate(CASES):
        line_at = end + 1 + i
        if line_at >= len(lines):
            raise ValueError('missing load/teardown case')
        pattern = (rf'XDEV_EXT_FENCE_CASE={case} nonce={prefix}{i} mode=check iterations={n} '
                   + (r'load_rc=0 unload_rc=0' if i == 0 else r'load_rc=([1-9][0-9]*) unload_rc=not-loaded')
                   + r' module=absent debugfs=absent')
        line = lines[line_at]
        if not re.fullmatch(pattern, line):
            raise ValueError('invalid load/teardown evidence: ' + case)
        want.append(line)
    done = 'XDEV_EXT_FENCE_DONE=5/5 performance_claim=none'
    if len(lines) <= end + 6 or lines[end + 6] != done:
        raise ValueError('missing/misplaced fence completion')
    want.append(done)
    actual = [x for x in lines if x.startswith('XDEV_EXT_FENCE_')]
    if actual != want or lines.index('XDEV_EXT_ZC_GUEST_EXIT=0') <= end + 6:
        raise ValueError('unknown, duplicate, or misplaced fence evidence')
    # Check receipt includes actual guest release and module bytes before load.
    identity = f'XDEV_EXT_FENCE_IDENTITY kernel_release={request["kernel_release"]} module_sha256={request["module_sha256"]}'
    if lines.count(identity) != 1 or lines.index(identity) >= start:
        raise ValueError('missing loaded module/kernel identity')
    return dict(cases=5, mode='check', performance_claim='none', raw_report=report)


def main(argv):
    if len(argv) != 3:
        print('usage: xdev_ext_fence_validate.py GUEST_LOG QEMU_EXIT REQUEST_JSON', file=sys.stderr)
        return 2
    try:
        result = validate(Path(argv[0]).read_text(), int(Path(argv[1]).read_text()),
                          load_json(Path(argv[2]).read_text()))
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print('XDEV_EXT_FENCE_VALIDATE=FAIL ' + str(error), file=sys.stderr)
        return 1
    print('XDEV_EXT_FENCE_VALIDATE=PASS cases=%d performance_claim=none' % result['cases'])
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
