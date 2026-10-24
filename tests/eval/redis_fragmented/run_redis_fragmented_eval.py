#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify complete binary Redis replies on an owned local Unix socket."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import NamedTuple


class Workload(NamedTuple):
    name: str
    kind: str
    item_count: int
    value_bytes: int


WORKLOADS = (
    Workload('GET_256K', 'get', 1, 262144),
    Workload('GET_512K', 'get', 1, 524288),
    Workload('GET_1M', 'get', 1, 1048576),
    Workload('GET_2M', 'get', 1, 2097152),
    Workload('MGET_16x16K', 'mget', 16, 16384),
    Workload('MGET_32x16K', 'mget', 32, 16384),
    Workload('MGET_64x8K', 'mget', 64, 8192),
    Workload('LRANGE_128x4K', 'lrange', 128, 4096),
    Workload('LRANGE_256x4K', 'lrange', 256, 4096),
)
MAX_WIRE_BYTES = 16 * 1024 * 1024
MAX_BULK_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 10000
MAX_DEPTH = 32
MAX_LINE_BYTES = 4096
_DECIMAL = re.compile(rb'-?(?:0|[1-9][0-9]*)\Z')


class CapabilityUnavailable(RuntimeError):
    """A requested local dependency cannot be established."""


class _ResponseReader:
    def __init__(self, stream):
        self.stream = stream
        self.remaining = MAX_WIRE_BYTES
        self.items = 0

    def exact(self, length):
        if length < 0 or length > self.remaining:
            raise ValueError('RESP message byte bound exceeded')
        parts = []
        left = length
        while left:
            part = self.stream.read(left)
            if not isinstance(part, bytes) or not part:
                raise EOFError('incomplete RESP message')
            if len(part) > left:
                raise ValueError('stream returned bytes outside requested span')
            self.remaining -= len(part)
            left -= len(part)
            parts.append(part)
        return b''.join(parts)

    def line(self):
        line = bytearray()
        while len(line) <= MAX_LINE_BYTES:
            byte = self.exact(1)
            if byte == b'\r':
                if self.exact(1) != b'\n':
                    raise ValueError('invalid RESP line ending')
                return bytes(line)
            if byte == b'\n':
                raise ValueError('RESP line lacks CRLF')
            line.extend(byte)
        raise ValueError('RESP line bound exceeded')

    def number(self):
        line = self.line()
        if len(line) > 20 or not _DECIMAL.fullmatch(line):
            raise ValueError('invalid RESP decimal')
        value = int(line)
        if not -(1 << 63) <= value < (1 << 63):
            raise ValueError('RESP integer bound exceeded')
        return value

    def response(self, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError('RESP nesting bound exceeded')
        self.items += 1
        if self.items > MAX_ITEMS:
            raise ValueError('RESP item bound exceeded')
        kind = self.exact(1)
        if kind == b'+':
            return self.line()
        if kind == b'-':
            self.line()
            raise RuntimeError('Redis returned an error response')
        if kind == b':':
            return self.number()
        if kind == b'$':
            length = self.number()
            if length == -1:
                return None
            if length < 0 or length > MAX_BULK_BYTES:
                raise ValueError('RESP bulk length bound exceeded')
            value = self.exact(length)
            if self.exact(2) != b'\r\n':
                raise ValueError('invalid RESP bulk ending')
            return value
        if kind == b'*':
            length = self.number()
            if length == -1:
                return None
            if length < 0 or length > MAX_ITEMS - self.items:
                raise ValueError('RESP array count bound exceeded')
            return [self.response(depth + 1) for _ in range(length)]
        raise ValueError('unknown RESP2 response type')


def read_response(stream):
    """Consume one bounded RESP2 message, including actual short reads."""
    return _ResponseReader(stream).response()


def decode_response(wire):
    """Decode exactly one complete message, rejecting trailing bytes."""
    if not isinstance(wire, bytes) or len(wire) > MAX_WIRE_BYTES:
        raise ValueError('invalid or oversized RESP input')
    stream = io.BytesIO(wire)
    result = read_response(stream)
    if stream.read(1):
        raise ValueError('extra bytes after complete RESP message')
    return result


def verify_reply(actual, expected):
    """Exact type, array count/order, and every byte must agree."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            verify_reply(a, e) for a, e in zip(actual, expected))
    return actual == expected


def payload(index, length):
    if not isinstance(index, int) or not 0 <= index < (1 << 64):
        raise ValueError('invalid payload index')
    if not isinstance(length, int) or not 0 <= length <= MAX_BULK_BYTES:
        raise ValueError('invalid payload size')
    prefix = b'\x00\xffRESP2:' + index.to_bytes(8, 'big')
    return (prefix + hashlib.shake_256(prefix).digest(length))[:length]


def server_env(preload, original=None):
    source = os.environ if original is None else original
    env = {key: value for key, value in source.items()
           if key != 'LD_PRELOAD' and not key.startswith(('UBR_', 'XDEV_EXT_'))}
    if preload is not None:
        env['LD_PRELOAD'] = str(preload)
    return env


def _command(parts):
    encoded = [part if isinstance(part, bytes) else str(part).encode('ascii')
               for part in parts]
    return b'*' + str(len(encoded)).encode('ascii') + b'\r\n' + b''.join(
        b'$' + str(len(part)).encode('ascii') + b'\r\n' + part + b'\r\n'
        for part in encoded)


class _SocketStream:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline

    def read(self, size):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('Redis response deadline expired')
        self.connection.settimeout(left)
        return self.connection.recv(size)


class OwnedRedis:
    """Own a fresh session/process group and private socket directory."""
    def __init__(self, executable, scratch_root, timeout, preload=None):
        self.executable = executable
        self.scratch_root = scratch_root
        self.timeout = timeout
        self.preload = preload
        self.process = None
        self.directory = None
        self.connection = None
        self.log = None

    def __enter__(self):
        try:
            self.directory = tempfile.TemporaryDirectory(
                prefix='redis-frag-', dir=self.scratch_root)
            root = Path(self.directory.name)
            root.chmod(0o700)
            self.socket_path = root / 'redis.sock'
            self.log = (root / 'server.log').open('wb')
            args = [self.executable, '--port', '0',
                    '--unixsocket', str(self.socket_path), '--unixsocketperm', '700',
                    '--save', '', '--appendonly', 'no', '--protected-mode', 'yes',
                    '--daemonize', 'no', '--logfile', '', '--dir', str(root),
                    '--pidfile', str(root / 'server.pid')]
            self.process = subprocess.Popen(
                args, stdin=subprocess.DEVNULL, stdout=self.log,
                stderr=subprocess.STDOUT, env=server_env(self.preload),
                start_new_session=True)
            self._ready()
            return self
        except BaseException:
            self.close()
            raise

    def _ready(self):
        deadline = time.monotonic() + self.timeout
        while True:
            if self.process.poll() is not None:
                raise RuntimeError('owned Redis exited before readiness')
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError('owned Redis readiness deadline expired')
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(left)
            try:
                connection.connect(str(self.socket_path))
            except (FileNotFoundError, ConnectionRefusedError):
                connection.close()
                time.sleep(min(0.01, left))
                continue
            except BaseException:
                connection.close()
                raise
            self.connection = connection
            reply = self.command(b'PING', deadline=deadline)
            if not verify_reply(reply, b'PONG'):
                raise RuntimeError('owned Redis readiness reply was invalid')
            return

    def command(self, *parts, deadline=None):
        if self.process.poll() is not None:
            raise RuntimeError('owned Redis exited during correctness checks')
        deadline = time.monotonic() + self.timeout if deadline is None else deadline
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError('Redis command deadline expired')
        self.connection.settimeout(left)
        self.connection.sendall(_command(parts))
        return read_response(_SocketStream(self.connection, deadline))

    def mapped_library(self, library):
        try:
            wanted = Path(library).stat()
            maps = Path(f'/proc/{self.process.pid}/maps').read_text()
        except OSError as error:
            raise CapabilityUnavailable('cannot establish requested preload mapping') from error
        for line in maps.splitlines():
            fields = line.split(None, 5)
            if len(fields) < 5:
                continue
            device = fields[3].split(':')
            if len(device) == 2 and int(fields[4]) == wanted.st_ino and (
                    int(device[0], 16), int(device[1], 16)) == (
                        os.major(wanted.st_dev), os.minor(wanted.st_dev)):
                return True
        return False

    def finish(self):
        # With no pipelined commands, QUIT followed by EOF proves that no
        # unsolicited complete or partial response remains after our oracle.
        if not verify_reply(self.command(b'QUIT'), b'OK'):
            raise RuntimeError('extra or invalid final Redis response')
        self.connection.settimeout(self.timeout)
        if self.connection.recv(1):
            raise ValueError('extra bytes after final Redis response')

    def close(self):
        try:
            if self.connection is not None:
                self.connection.close()
                self.connection = None
            if self.process is not None:
                # start_new_session makes this PID the owned process-group ID.
                # No name lookup, external server or system-wide kill is used.
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.process.wait(timeout=2)
                self.process = None
        finally:
            if self.log is not None:
                self.log.close()
                self.log = None
            if self.directory is not None:
                self.directory.cleanup()
                self.directory = None

    def __exit__(self, *_):
        self.close()


def _expect(actual, expected, operation):
    if not verify_reply(actual, expected):
        raise RuntimeError(f'complete response mismatch for {operation}')


def run_arm(executable, scratch_root, timeout, preload=None):
    cases = []
    with OwnedRedis(executable, scratch_root, timeout, preload) as server:
        mapped = False
        if preload is not None:
            mapped = server.mapped_library(preload)
            if not mapped:
                raise CapabilityUnavailable('requested preload library was not mapped')
        for case_index, workload in enumerate(WORKLOADS):
            values = [payload(case_index * 1024 + i, workload.value_bytes)
                      for i in range(workload.item_count)]
            keys = [f'{workload.name}:{i}'.encode('ascii')
                    for i in range(workload.item_count)]
            if workload.kind in ('get', 'mget'):
                for key, value in zip(keys, values):
                    _expect(server.command(b'SET', key, value), b'OK', 'SET')
                actual = server.command(b'GET', keys[0]) if workload.kind == 'get' else (
                    server.command(b'MGET', *keys))
                expected = values[0] if workload.kind == 'get' else values
            else:
                _expect(server.command(b'RPUSH', keys[0], *values),
                        workload.item_count, 'RPUSH')
                actual = server.command(b'LRANGE', keys[0], 0, -1)
                expected = values
            _expect(actual, expected, workload.name)
            cases.append({'name': workload.name, 'verified': True,
                          'item_count': workload.item_count,
                          'value_bytes': workload.value_bytes})
        if preload is not None and not server.mapped_library(preload):
            raise CapabilityUnavailable('requested preload mapping was lost')
        server.finish()
    return {'name': 'baseline' if preload is None else 'preload',
            'library_mapped': mapped, 'cases': cases}


def _publish(output, data):
    """Publish a complete result exclusively, leaving no partial success file."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=output.parent,
                                         prefix='.redis-result-', delete=False) as file:
            temporary = Path(file.name)
            json.dump(data, file, indent=2)
            file.write('\n')
            file.flush()
            os.fsync(file.fileno())
        os.link(temporary, output)  # Fails rather than replacing another result.
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--redis-server', default='redis-server')
    parser.add_argument('--mode', choices=['correctness'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scratch-root', type=Path)
    parser.add_argument('--timeout', type=float, default=10.0)
    parser.add_argument('--preload', type=Path)
    args = parser.parse_args(argv)
    try:
        if not 0 < args.timeout <= 300:
            raise ValueError('timeout must be in (0, 300] seconds')
        if args.output.exists() or not args.output.parent.is_dir():
            raise ValueError('output must be a new file in an existing directory')
        executable = shutil.which(args.redis_server)
        if executable is None:
            raise CapabilityUnavailable('requested redis-server executable is unavailable')
        preload = None
        if args.preload is not None:
            try:
                preload = args.preload.resolve(strict=True)
            except OSError as error:
                raise CapabilityUnavailable('requested preload library is unavailable') from error
            if not preload.is_file() or any(c in str(preload) for c in ' :\t\n'):
                raise CapabilityUnavailable('requested preload path cannot be loaded exactly')
        arms = [run_arm(executable, args.scratch_root, args.timeout)]
        if preload is not None:
            arms.append(run_arm(executable, args.scratch_root, args.timeout, preload))
        data = {'status': 'PASS', 'scope': 'redis-response-correctness',
                'cases': arms[0]['cases'], 'arms': arms}
        _publish(args.output, data)
        print(f"PASS: complete Redis replies verified in {len(arms)} local arm(s)")
        return 0
    except CapabilityUnavailable as error:
        print(f'SKIP: {error}', file=sys.stderr)
        return 4
    except (OSError, ValueError, RuntimeError, EOFError, KeyboardInterrupt) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise RuntimeError('local correctness run interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    sys.exit(main())
