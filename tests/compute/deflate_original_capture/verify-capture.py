#!/usr/bin/env python3
"""Root-only bounded extraction; failed observations are diagnostic, never originals."""
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('guest_log', type=Path)
p.add_argument('new_output', type=Path)
a = p.parse_args()
if a.new_output.exists():
    raise SystemExit('FAIL output already exists')
a.new_output.mkdir(mode=0o700)
primary = {'input', 'cpu.deflate', 'cpu.inflate', 'iaa.deflate', 'iaa.inflate'}
diag_names = {
    'diag.' + cls + '.' + kind + '.f' + str(frame)
    for cls in ('cpu', 'iaa')
    for kind in ('pool', 'initial', 'compressed_snapshot')
    for frame in range(6)
}
records = {}
ambiguous = set()
errors = []
ERROR_COUNT_MAX = 65535
error_count = 0
error_count_overflow = False
final = 0  # Saturating state: 0 absent, 1 exactly one, 2 multiple.
case_mask = 0  # Only cpu bit1 and iaa bit2 can be retained.
exit_lines = set()


def error(message):
    global error_count, error_count_overflow
    if error_count < ERROR_COUNT_MAX:
        error_count += 1
    else:
        error_count_overflow = True
    if len(errors) < 128:
        errors.append(message)


def byte_record(line):
    parts = line.split(' ')
    if len(parts) != 4:
        error('malformed byte record')
        return
    name = parts[1]
    if name not in primary and name not in diag_names:
        error('unknown byte record name')
        return
    if not parts[2].startswith('len=') or not parts[3].startswith('hex='):
        error('missing byte fields for ' + name)
        return
    length = parts[2][4:]
    if not length or len(length) > 4 or not length.isascii() or not length.isdecimal():
        error('invalid byte length for ' + name)
        return
    n = int(length)
    if not 1 <= n <= 8192 or len(parts[3][4:]) != 2*n:
        error('length/hex mismatch for ' + name)
        return
    if name in diag_names and n != 8192:
        error('diagnostic frame length mismatch for ' + name)
        return
    try:
        data = bytes.fromhex(parts[3][4:])
    except ValueError:
        error('invalid hex for ' + name)
        return
    if len(data) != n:
        error('decoded length mismatch for ' + name)
        return
    if name in ambiguous:
        error('conflicting byte record name remains ambiguous: ' + name)
        return
    if name in records:
        error('duplicate byte record for ' + name)
        if records[name] != data:
            del records[name]
            ambiguous.add(name)
        return
    records[name] = data


try:
    with a.guest_log.open('r', errors='replace') as f:
        while True:
            # readline(size) bounds allocation even for a hostile one-line log.
            line = f.readline(100001)
            if not line:
                break
            if len(line) > 100000:
                error('console line exceeds bound')
                while line and not line.endswith('\n'):
                    line = f.readline(100001)
                continue
            line = line.rstrip('\r\n')
            if 'FAIL deflate-original' in line:
                error('explicit FAIL deflate-original marker')
            if line.startswith('DIAGNOSTIC_FAILURE'):
                error('native diagnostic artifact output failure')
            if line.startswith('BYTES '):
                byte_record(line)
            if line == 'XDEV_EXT_DEFLATE_ORIGINAL=PASS classes=CPU,IAA_SOFTWARE actual_kernel_transforms=1 exact_bytes=1 timing=none':
                if final < 2:
                    final += 1
            if line.startswith('CASE '):
                case = line.split(None, 3)
                if len(case) < 3 or case[2] != 'PASS' or ' PASS ' not in line:
                    error('malformed CASE marker')
                elif case[1] == 'cpu':
                    case_mask |= 1
                elif case[1] == 'iaa':
                    case_mask |= 2
                else:
                    # Never retain an arbitrary log-supplied CASE identifier.
                    error('unknown CASE name')
            for prefix in ('XDEV_EXT_DEFLATE_CAPTURE_EXIT=', 'XDEV_EXT_DEFLATE_GUEST_EXIT=', 'qemu_exit='):
                if line.startswith(prefix):
                    status = line[len(prefix):]
                    if status != '0':
                        error('nonzero or malformed exit marker: ' + prefix)
                    elif prefix != 'qemu_exit=':
                        exit_lines.add(line)
except OSError as exc:
    error('cannot read guest log: ' + str(exc))

if not primary.issubset(records) or final != 1:
    error('missing actual-byte observations/final result')
expected = bytes((((i % 64)*13+7) ^ (((i//64) % 7)*29)) & 255 for i in range(4096))
for name in ('input', 'cpu.inflate', 'iaa.inflate'):
    if name in records and records[name] != expected:
        error('independent fixed input/reconstruction mismatch: ' + name)
if case_mask != 3 or len(exit_lines) != 2:
    error('absent case or guest exit')
if any(name in records for name in diag_names):
    error('failure-only native pool diagnostics present')

# Persist known unambiguous valid observations even when validation has failed.
retained = {}
for name, data in records.items():
    try:
        with (a.new_output/(name+'.bin')).open('xb') as output:
            if output.write(data) != len(data):
                raise OSError('short artifact write')
        retained[name] = len(data)
    except OSError as exc:
        error('cannot retain byte record ' + name + ': ' + str(exc))

if error_count:
    result = {
        'status': 'DIAGNOSTIC_FAILURE',
        'scope': 'failed/partial actual observations only; not valid originals',
        'lengths': retained,
        'diagnostic': True,
        'errors': errors,
        'error_count': error_count,
        'error_count_overflow': error_count_overflow,
        'error_messages_omitted': error_count > len(errors),
        'ambiguous_names': sorted(ambiguous),
        'valid_original': False,
        'source_of_compressed_expectations': 'diagnostic only; not a valid original',
    }
else:
    result = {
        'status': 'PASS',
        'scope': 'actual kernel CPU/IAA software original correctness bytes; no performance',
        'lengths': retained,
        'compressed_equal': records['cpu.deflate'] == records['iaa.deflate'],
        'source_of_compressed_expectations': 'unchanged-production original capture only',
    }
(a.new_output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, sort_keys=True))
raise SystemExit(1 if error_count else 0)
