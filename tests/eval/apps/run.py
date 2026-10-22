#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Execute deterministic libc call shapes, with exact model/counter checks."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
BUILD = HERE / 'build'
COUNTERS = ('read_count', 'read_bytes', 'read_errors', 'write_count', 'write_bytes',
            'write_errors', 'custom_send_count', 'custom_send_bytes', 'custom_send_errors')
MODEL_COUNTERS = ('read_sqes', 'write_sqes', 'other_sqes', 'eintr_returned', 'send_sqes')


def equal_bytes(expected, actual, description):
    if expected != actual:
        raise ValueError(f'{description}: full bytes differ ({len(expected)} versus {len(actual)})')


def check_exit(returncode, output):
    if returncode:
        raise ValueError(f'workload exit={returncode}: {output}')


def rows(text, prefix):
    result = []
    for line in text.splitlines():
        if line.startswith(prefix + ' '):
            row = {}
            for word in line.split()[1:]:
                key, separator, value = word.partition('=')
                if not separator or not value or key in row:
                    raise ValueError(f'malformed {prefix} field')
                row[key] = value
            result.append(row)
    return result


def totals(text, prefix, fields, identity):
    found = rows(text, prefix)
    if not found:
        raise ValueError(f'missing {prefix}')
    seen, total = set(), dict.fromkeys(fields, 0)
    for row in found:
        if any(key not in row or not row[key].isdigit() for key in (*fields, *identity)):
            raise ValueError(f'missing or invalid {prefix} counters')
        key = tuple(row[name] for name in identity)
        if key in seen:
            raise ValueError(f'duplicate {prefix} identity')
        seen.add(key)
        for name in fields:
            total[name] += int(row[name])
    return total


def validate_counts(report, expected):
    actual = totals(report, 'XDEV_EXT_PRELOAD_REPORT', COUNTERS, ('pid', 'tid'))
    for key, value in expected.items():
        if actual[key] != value:
            raise ValueError(f'{key}: expected {value}, actual {actual[key]}')
    return actual


def validate_model(report, expected):
    actual = totals(report, 'XDEV_EXT_MODEL_SUMMARY', MODEL_COUNTERS, ('pid',))
    for key, value in expected.items():
        if actual[key] != value:
            raise ValueError(f'model {key}: expected {value}, actual {actual[key]}')
    return actual


def db_summary(text):
    found = rows(text, 'XDEV_EXT_DB_WORKLOAD_RESULT=PASS')
    if len(found) != 1:
        raise ValueError('missing or duplicate database PASS result')
    return found[0]


def validate_db(reference, taken, report):
    base, actual = db_summary(reference), db_summary(taken)
    if actual != base:
        raise ValueError('database return/errno trace, shape tally, or digest differs')
    reads, writes = int(base['eligible_reads']), int(base['eligible_writes'])
    read_errors, write_errors = int(base['eligible_read_errors']), int(base['eligible_write_errors'])
    if reads <= 0 or writes <= 0 or int(base['fallback_calls']) <= 0:
        raise ValueError('database shapes did not exercise both paths')
    validate_counts(report, {'read_count': reads - read_errors, 'read_errors': read_errors,
                            'write_count': writes - write_errors, 'write_errors': write_errors,
                            'custom_send_count': 0, 'custom_send_bytes': 0,
                            'custom_send_errors': 0})
    validate_model(report, {'read_sqes': reads, 'write_sqes': writes,
                           'send_sqes': 0, 'other_sqes': 0, 'eintr_returned': 0})


def run_suite(work):
    work = work.resolve()
    model = str(BUILD / 'libxdev_ext_preload_kernel_model.so')
    frontend = str(BUILD / 'libio_uring_unified.so')
    for artifact in ('fallback_shapes', 'xdev_ext_preload_db_workload',
                     'xdev_ext_preload_socket_smoke', 'libio_uring_unified.so',
                     'libxdev_ext_preload_kernel_model.so'):
        if not (BUILD / artifact).is_file():
            raise ValueError('missing build artifact; run make -C tests/eval/apps first')
    # No ambient device/backend/session settings may alter the advertised shape.
    clean = {k: v for k, v in os.environ.items()
             if not k.startswith('XDEV_EXT_') and k != 'LD_PRELOAD'}
    common = {'XDEV_EXT_MODEL_DIOALIGN': '4096:4096', 'XDEV_EXT_MODEL_UMEM': '1',
              'XDEV_EXT_MODEL_SUMMARY': '1', 'XDEV_EXT_PRELOAD_FRAME_SIZE': '4096',
              'XDEV_EXT_PRELOAD_SOCKET_MECH': '0', 'XDEV_EXT_PRELOAD_REPORT': '1'}

    def invoke(name, binary, args, takeover, file=None):
        env = dict(clean, **common)
        env['LD_PRELOAD'] = f'{frontend}:{model}' if takeover else model
        env['XDEV_EXT_PRELOAD_ENABLED'] = '1' if takeover and file is not None else '0'
        env['XDEV_EXT_PRELOAD_SOCKET_ENABLED'] = '1' if takeover else '0'
        if file is not None:
            file.touch()
            env['XDEV_EXT_PRELOAD_PATHS'] = str(file)
        result = subprocess.run([str(BUILD / binary), *map(str, args)], env=env,
                                capture_output=True, text=True, timeout=60)
        (work / f'{name}.out').write_text(result.stdout)
        (work / f'{name}.err').write_text(result.stderr)
        check_exit(result.returncode, result.stdout + result.stderr)
        return result.stdout, result.stderr

    db_libc = work / 'db-libc.db'
    db_model = work / 'db-model.db'
    reference, _ = invoke('db-libc', 'xdev_ext_preload_db_workload', [db_libc, 'full'], False, db_libc)
    taken, report = invoke('db-model', 'xdev_ext_preload_db_workload', [db_model, 'full'], True, db_model)
    validate_db(reference, taken, report)
    equal_bytes(db_libc.read_bytes(), db_model.read_bytes(), 'database whole file')
    for file, output in ((db_libc, reference), (db_model, taken)):
        if db_summary(output)['sha256'] != hashlib.sha256(file.read_bytes()).hexdigest():
            raise ValueError('database summary digest differs from independent whole file digest')
    print('PASS shape=fio-psync-positional evidence=host-model exact_custom_counts=1 full_file_compare=1')

    expected_udp = 'XDEV_EXT_TRANSPARENT_SOCKET_PAYLOAD=PASS sends=3 bytes=25\n'
    reference, _ = invoke('udp-libc', 'xdev_ext_preload_socket_smoke', [], False)
    taken, report = invoke('udp-model', 'xdev_ext_preload_socket_smoke', [], True)
    equal_bytes(expected_udp, reference, 'UDP libc result')
    equal_bytes(reference, taken, 'UDP return/payload result')
    validate_counts(report, {'custom_send_count': 3, 'custom_send_bytes': 25,
                            'custom_send_errors': 0, 'read_count': 0, 'read_errors': 0,
                            'read_bytes': 0, 'write_count': 3, 'write_bytes': 25, 'write_errors': 0})
    validate_model(report, {'read_sqes': 0, 'write_sqes': 0, 'send_sqes': 3, 'other_sqes': 0})
    print('PASS shape=connected-udp evidence=host-model custom_sends=3 custom_bytes=25')

    fallback_libc, fallback_model = work / 'fallback-libc.db', work / 'fallback-model.db'
    reference, _ = invoke('fallback-libc', 'fallback_shapes', [fallback_libc], False, fallback_libc)
    taken, report = invoke('fallback-model', 'fallback_shapes', [fallback_model], True, fallback_model)
    if not reference.startswith('XDEV_EXT_APP_FALLBACK=PASS '):
        raise ValueError('missing fallback result')
    equal_bytes(reference, taken, 'fallback return/errno/full-payload result')
    equal_bytes(fallback_libc.read_bytes(), fallback_model.read_bytes(), 'fallback whole file')
    validate_model(report, {'read_sqes': 0, 'write_sqes': 0, 'send_sqes': 0, 'other_sqes': 0})
    if rows(report, 'XDEV_EXT_PRELOAD_REPORT'):
        validate_counts(report, dict.fromkeys(COUNTERS, 0))
    print('PASS shape=tcp-send-write-writev-buffered-file-direct64 evidence=host-model custom_requests=0 scope=compatibility')
    print('PASS application_call_shapes=3 real_thirdparty_app_runs=0 physical_dma_evidence=0')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='new empty directory to retain files and raw reports')
    args = parser.parse_args()
    try:
        if args.output:
            args.output.mkdir(parents=True, exist_ok=True)
            if any(args.output.iterdir()):
                raise ValueError('--output must be empty')
            run_suite(args.output)
        else:
            with tempfile.TemporaryDirectory(prefix='call-shapes-', dir=BUILD) as temp:
                run_suite(Path(temp))
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'FAIL: {error}\n')


if __name__ == '__main__':
    main()
