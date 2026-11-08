#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Line protocol between the K-KV orchestrator and one restore worker.

Every arm's worker (kv_restore, nvmeof_worker, mooncake_worker.py) sets up
once, prints ``KV_READY {json}``, answers each ``GO k=v ...`` line with one
``KV_RESULT {json}`` (``KV_ERROR {json}`` for a refused line) and ``QUIT``
with ``KV_BYE {json}``. Anything else on stdout is a protocol error; stderr
goes to the worker's log. Timeouts kill the worker instead of waiting.
"""
import json
import queue
import re
import subprocess
import threading
import time

KINDS = ('KV_READY', 'KV_RESULT', 'KV_ERROR', 'KV_BYE', 'KV_SERVED')
RUN_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
MAX_LINE = 1 << 16


class ProtocolError(ValueError):
    pass


class WorkerError(RuntimeError):
    pass


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ProtocolError('duplicate JSON key')
    return dict(pairs)


def parse_line(line):
    line = line.rstrip('\n')
    if len(line) > MAX_LINE:
        raise ProtocolError('line too long')
    kind, _, rest = line.partition(' ')
    if kind not in KINDS or not rest:
        raise ProtocolError(f'not a worker line: {line[:120]!r}')
    try:
        body = json.loads(rest, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as error:
        raise ProtocolError(f'{kind}: bad JSON: {error}') from None
    if not isinstance(body, dict):
        raise ProtocolError(f'{kind}: JSON object required')
    return kind, body


def _uint(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ProtocolError(f'{name} must be an integer >= {minimum}: {value!r}')
    return value


def go_line(run, ordinal, object_slba, bytes, dst_frame0, seed=0, verify=False):
    if not isinstance(run, str) or not RUN_RE.match(run):
        raise ProtocolError(f'run id must match {RUN_RE.pattern}: {run!r}')
    _uint(ordinal, 'ordinal', 1)
    _uint(object_slba, 'object_slba')
    _uint(bytes, 'bytes', 1)
    _uint(dst_frame0, 'dst_frame0')
    _uint(seed, 'seed')
    return (f'GO run={run} ordinal={ordinal} object_slba={object_slba} bytes={bytes} '
            f'dst_frame0={dst_frame0} seed={seed} verify={1 if verify else 0}\n')


PREFIX_RE = re.compile(r'[0-9a-f]{64}')


def prefix_go_line(run, ordinal, prefix, dst_frame0, seed=0, verify=False):
    """GO naming a prefix of the worker's --index instead of object_slba and bytes."""
    if not isinstance(run, str) or not RUN_RE.match(run):
        raise ProtocolError(f'run id must match {RUN_RE.pattern}: {run!r}')
    _uint(ordinal, 'ordinal', 1)
    if not isinstance(prefix, str) or not PREFIX_RE.fullmatch(prefix):
        raise ProtocolError(f'prefix must be 64 lowercase hex digits: {prefix!r}')
    _uint(dst_frame0, 'dst_frame0')
    _uint(seed, 'seed')
    return (f'GO run={run} ordinal={ordinal} prefix={prefix} dst_frame0={dst_frame0} '
            f'seed={seed} verify={1 if verify else 0}\n')


def check_sender_done(text, run, plan=None, *, ordinal=None):
    """Validate a successful sender verdict; original run/status wire supported."""
    if not isinstance(text, str) or len(text) >= 1024 or any(
            ord(c) < 32 and c not in '\t\r' for c in text):
        raise ProtocolError('invalid DONE line')
    words = text.split()
    if not words or words.pop(0) != 'DONE':
        raise ProtocolError('not a DONE line')
    fields = {}
    allowed = {'run', 'ok', 'err', 'ordinal', 'first_seq', 'groups', 'wait_ns',
               'done', 'abort', 'sequestered', 'last_err'}
    for word in words:
        key, sep, value = word.partition('=')
        if not sep or not value or key not in allowed or key in fields:
            raise ProtocolError('invalid or duplicate DONE field')
        fields[key] = value
    if fields.get('run') != run or fields.get('ok') != '1' or fields.get('err') != '0':
        raise ProtocolError('DONE does not prove this sender succeeded')
    for key, value in fields.items():
        if key in ('run', 'ok', 'err'):
            continue
        if not re.fullmatch(r'[0-9]+', value) or int(value) > (1 << 64) - 1:
            raise ProtocolError('invalid DONE integer')
        if key in ('abort', 'sequestered', 'last_err') and int(value):
            raise ProtocolError('DONE contradicts success')
    keys = {'ordinal', 'first_seq', 'groups'}
    if keys & fields.keys():
        if not keys <= fields.keys():
            raise ProtocolError('partial DONE request tuple')
        if ordinal is None:
            raise ProtocolError('DONE tuple lacks trusted request ordinal')
        _uint(ordinal, 'request ordinal', 1)
        if int(fields['ordinal']) != ordinal:
            raise ProtocolError('DONE request ordinal mismatch')
        if not isinstance(plan, dict) or not {'first_seq', 'groups'} <= plan.keys():
            raise ProtocolError('DONE tuple lacks result plan')
        if any(int(fields[k]) != plan[k] for k in ('first_seq', 'groups')):
            raise ProtocolError('DONE request tuple mismatch')
    return fields


def check_result(body, run, *, ordinal=None):
    for key in ('run', 'ok', 'error', 'bytes', 't0_ns', 't1_ns', 'latency_ns'):
        if key not in body:
            raise ProtocolError(f'KV_RESULT lacks {key}')
    if body['run'] != run:
        raise ProtocolError(f'KV_RESULT for run {body["run"]!r}, expected {run!r}')
    if type(body['ok']) is not bool or type(body['error']) is not int:
        raise ProtocolError('KV_RESULT ok must be bool and error int')
    for key in ('bytes', 't0_ns', 't1_ns', 'latency_ns'):
        _uint(body[key], key)
    if body['ok']:
        if 'host1' in body:
            check_sender_done(body['host1'], run, body.get('plan'), ordinal=ordinal)
        if body['error']:
            raise ProtocolError('KV_RESULT ok with a nonzero error')
        if body['t1_ns'] < body['t0_ns'] or body['latency_ns'] != body['t1_ns'] - body['t0_ns']:
            raise ProtocolError('KV_RESULT latency is not t1 - t0')
    return body


class Worker:
    """One worker process; all reads are bounded by explicit timeouts."""

    def __init__(self, argv, ready_timeout=120.0, log=None, env=None):
        self.argv = [str(a) for a in argv]
        self._log = open(log, 'a') if log else subprocess.DEVNULL
        self._lines = queue.Queue()
        self.returncode = None
        self.proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=self._log, text=True, bufsize=1, env=env)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        try:
            kind, body = self._next(ready_timeout, ('KV_READY', 'KV_ERROR'))
        except BaseException:
            self.kill()
            raise
        if kind == 'KV_ERROR':
            self.kill()
            raise WorkerError(f'worker setup failed: {body}')
        self.ready = body

    def _read(self):
        for line in self.proc.stdout:
            if self._log is not subprocess.DEVNULL:
                self._log.write('stdout: ' + line)
                self._log.flush()
            self._lines.put(line)
        self._lines.put(None)

    def _next(self, timeout, kinds):
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                self.kill()
                raise WorkerError(f'no {"/".join(kinds)} within {timeout} s')
            try:
                line = self._lines.get(timeout=left)
            except queue.Empty:
                continue
            if line is None:
                self.wait(5)
                raise WorkerError(f'worker exited ({self.returncode}) before {"/".join(kinds)}')
            kind, body = parse_line(line)
            if kind == 'KV_SERVED':
                continue
            if kind not in kinds:
                raise ProtocolError(f'unexpected {kind}')
            return kind, body

    def go(self, run, ordinal, object_slba, bytes, dst_frame0, seed=0, verify=False,
           timeout=600.0):
        self.proc.stdin.write(go_line(run, ordinal, object_slba, bytes, dst_frame0, seed, verify))
        self.proc.stdin.flush()
        kind, body = self._next(timeout, ('KV_RESULT', 'KV_ERROR'))
        if kind == 'KV_ERROR':
            raise WorkerError(f'worker refused GO: {body}')
        return check_result(body, run, ordinal=ordinal)

    def go_prefix(self, run, ordinal, prefix, dst_frame0, seed=0, verify=False, timeout=600.0):
        self.submit(prefix_go_line(run, ordinal, prefix, dst_frame0, seed, verify))
        kind, body = self._next(timeout, ('KV_RESULT', 'KV_ERROR'))
        if kind == 'KV_ERROR':
            raise WorkerError(f'worker refused GO: {body}')
        return check_result(body, run, ordinal=ordinal)

    def submit(self, text):
        """Write protocol lines without waiting; collect() reads the results in order."""
        self.proc.stdin.write(text)
        self.proc.stdin.flush()

    def collect(self, timeout=600.0, *, run=None, ordinal=None):
        _, body = self._next(timeout, ('KV_RESULT',))
        # New DONE tuples require the caller's original request context.
        # Legacy replies and workers without host1 keep their old interface.
        return check_result(body, body.get('run') if run is None else run,
                            ordinal=None if run is None else ordinal)

    def quit(self, timeout=120.0):
        self.proc.stdin.write('QUIT\n')
        self.proc.stdin.flush()
        _, body = self._next(timeout, ('KV_BYE',))
        self.wait(timeout)
        return body

    def wait(self, timeout):
        try:
            self.returncode = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
        self._finish()
        return self.returncode

    def kill(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.returncode = self.proc.returncode
        self._finish()

    def _finish(self):
        # The reader ends at EOF once the process is gone; then the log closes.
        if self.proc.poll() is None:
            return
        self._reader.join(timeout=5)
        if self.proc.stdin and not self.proc.stdin.closed:
            try:
                self.proc.stdin.close()
            except BrokenPipeError:
                pass
        if not self._reader.is_alive():
            self.proc.stdout.close()
            if self._log is not subprocess.DEVNULL and not self._log.closed:
                self._log.close()
