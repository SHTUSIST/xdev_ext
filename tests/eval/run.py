#!/usr/bin/env python3
"""Run disposable-file eval suites and strictly validate successful result records."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent


def integer(record, key, minimum=0):
    value = record.get(key)
    if type(value) is not int or value < minimum:
        raise ValueError(f'invalid/missing {key}')
    return value


def checked_result(result):
    if result.returncode:
        raise RuntimeError(f'backend exit {result.returncode}: {result.stderr.strip()}')
    try:
        record = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise ValueError('backend did not emit one JSON record') from exc
    if not isinstance(record, dict):
        raise ValueError('backend result must be an object')
    return record


def verify_pipeline(record, size, iterations, backend, expected_chunk):
    expected = dict(status='ok', backend=backend, route='buffered-file-to-tcp-loopback',
                    completion='receiver-full-byte-compare', bytes=size, iterations=iterations)
    for field, value in expected.items():
        if record.get(field) != value:
            raise ValueError(f'invalid/missing {field}')
    for field in ('read_bytes', 'sent_bytes', 'verified_bytes'):
        if integer(record, field) != size * iterations:
            raise ValueError(f'{field} does not cover the full stream')
    integer(record, 'bytes', 1)
    integer(record, 'iterations', 1)
    chunk = integer(record, 'chunk', 1)
    if chunk != expected_chunk:
        raise ValueError('chunk differs from requested chunk')
    if integer(record, 'chunks', 1) != ((size + chunk - 1) // chunk) * iterations:
        raise ValueError('incorrect logical chunk count')
    if integer(record, 'compute_bytes') > size * iterations:
        raise ValueError('compute coverage exceeds payload')
    integer(record, 'compute_checksum')
    integer(record, 'elapsed_ns', 1)
    integer(record, 'cpu_us')


def verify_cuda(record, size, direction, memory, expected_chunk):
    expected = dict(status='ok', backend=f'cuda_{memory}_staging', direction=direction,
                    route=('cuda-host-buffered-file' if direction == 'checkpoint' else 'buffered-file-host-cuda'), bytes=size,
                    completion='synchronous-copy-full-byte-compare' +
                    ('-fsync-file-reread' if direction == 'checkpoint' else ''))
    for field, value in expected.items():
        if record.get(field) != value:
            raise ValueError(f'invalid/missing {field}')
    for field in ('io_bytes', 'verified_bytes'):
        if integer(record, field) != size:
            raise ValueError(f'incomplete {field}')
    integer(record, 'bytes', 1)
    if integer(record, 'chunk', 1) != expected_chunk:
        raise ValueError('chunk differs from requested chunk')
    for field in ('file_ns', 'transfer_ns', 'elapsed_ns'):
        integer(record, field, 1)
    integer(record, 'cpu_us')


def invoke(command):
    return subprocess.run(list(map(str, command)), text=True, capture_output=True, timeout=120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=('portable', 'io-uring', 'cuda'), default='portable')
    parser.add_argument('--bytes', type=int, default=1024 * 1024 + 17)
    parser.add_argument('--iterations', type=int, default=3)
    parser.add_argument('--chunk', type=int, default=65536)
    args = parser.parse_args()
    if not 1 <= args.bytes <= 1024 * 1024 * 1024 or not 1 <= args.iterations <= 1000000 or not 1 <= args.chunk <= 16 * 1024 * 1024:
        parser.error('runner requires 1..1GiB bytes, 1..1000000 iterations, 1..16MiB chunk')
    try:
        with tempfile.TemporaryDirectory(prefix='xdev-eval-') as tmp:
            path = Path(tmp) / 'input.bin'
            # Independent deterministic source, created before any timed backend.
            with path.open('wb') as out:
                for offset in range(0, args.bytes, 65536):
                    out.write(bytes((i * 37 + i // 251) % 256
                                    for i in range(offset, min(offset + 65536, args.bytes))))
            if args.suite == 'cuda':
                for direction in ('load', 'checkpoint'):
                    for memory in ('pageable', 'pinned'):
                        command = [ROOT / 'build/bench_cuda_staging', '--direction', direction,
                                   '--memory', memory, '--bytes', args.bytes, '--chunk', args.chunk]
                        output = Path(tmp) / f'{memory}.checkpoint'
                        command += ['--input', path] if direction == 'load' else ['--output', output]
                        result = invoke(command)
                        if result.returncode == 4:
                            print(json.dumps(dict(suite='cuda', status='not_run_hardware',
                                                  reason=result.stderr.strip())), file=sys.stderr)
                            return 4
                        record = checked_result(result)
                        verify_cuda(record, args.bytes, direction, memory, args.chunk)
                        if direction == 'checkpoint' and output.read_bytes() != path.read_bytes():
                            raise ValueError('independent checkpoint file comparison failed')
                        print(json.dumps(record, sort_keys=True))
            else:
                backends = ('posix',) if args.suite == 'portable' else ('io_uring', 'io_uring-fixed')
                for backend in backends:
                    for compute in (0, min(256, args.chunk)):
                        result = invoke([ROOT / 'build/bench_file_pipeline', '--file', path,
                                         '--backend', backend, '--bytes', args.bytes,
                                         '--iterations', args.iterations, '--chunk', args.chunk,
                                         '--compute-bytes', compute])
                        if result.returncode == 4 and args.suite == 'io-uring':
                            print(json.dumps(dict(suite=args.suite, status='not_run_capability',
                                                  reason=result.stderr.strip())), file=sys.stderr)
                            return 4
                        record = checked_result(result)
                        verify_pipeline(record, args.bytes, args.iterations, backend, args.chunk)
                        full, tail = divmod(args.bytes, args.chunk)
                        expected_compute = (full * compute + min(tail, compute)) * args.iterations
                        if record['compute_bytes'] != expected_compute:
                            raise ValueError('incorrect compute coverage')
                        print(json.dumps(record, sort_keys=True))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f'eval failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
