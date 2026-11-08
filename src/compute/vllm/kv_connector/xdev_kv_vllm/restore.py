# SPDX-License-Identifier: GPL-2.0
"""Client of the K-KV restore worker: `kv_restore restore|local-verify --dst ce-vmm`.

The worker (tests/benchmarks/kv_restore/kv_restore.c) sets up one xdev_ext
session and a CUDA VMM allocation, prints KV_READY, answers each GO line with
one KV_RESULT and QUIT with KV_BYE (kv_protocol.py documents the protocol;
go_line here produces the same text). A restore is good only when the worker
reports ok with exactly the requested bytes, the ce-vmm destination at the
requested frame and no CPU-copied payload; every other answer is a failure and
the caller recomputes. A session whose restore failed after START takes no more
work, so the client replaces the worker (at most max_restarts times, then it
disables itself); a refusal before START keeps it. KV_BYE "retained" means DMA
ownership is unknown: the staging mapping is then kept until the process exits.

Host 1 refuses keys it already used, so ordinals only grow; with ordinal_file
the next ordinal is stored before each GO and survives connector restarts.
"""
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time
from typing import NamedTuple, Optional

KINDS = ('KV_READY', 'KV_RESULT', 'KV_ERROR', 'KV_BYE', 'KV_SERVED')
RUN_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
MAX_LINE = 1 << 16


class RestoreError(RuntimeError):
    pass


class ProtocolError(RestoreError):
    pass


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


def parse_line(line):
    line = line.rstrip('\n')
    if len(line) > MAX_LINE:
        raise ProtocolError('line too long')
    kind, _, rest = line.partition(' ')
    if kind not in KINDS or not rest:
        raise ProtocolError(f'not a worker line: {line[:120]!r}')
    try:
        body = json.loads(rest)
    except json.JSONDecodeError as error:
        raise ProtocolError(f'{kind}: bad JSON: {error}') from None
    if not isinstance(body, dict):
        raise ProtocolError(f'{kind}: JSON object required')
    return kind, body


class WorkerProcess:
    """One worker process; every read has a deadline, a missed one kills it."""

    def __init__(self, argv, ready_timeout, log=None, env=None):
        self._log = open(log, 'a') if log else subprocess.DEVNULL
        self._lines = queue.Queue()
        self.proc = subprocess.Popen([str(a) for a in argv], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=self._log, text=True,
                                     bufsize=1, env=env)
        self.pid = self.proc.pid
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        try:
            kind, body = self._next(ready_timeout, ('KV_READY', 'KV_ERROR'))
        except BaseException:
            self.kill()
            raise
        if kind == 'KV_ERROR':
            self.kill()
            raise RestoreError(f'worker setup failed: {body}')
        self.ready = body

    def _read(self):
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _next(self, timeout, kinds):
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                self.kill()
                raise RestoreError(f'no {"/".join(kinds)} within {timeout} s')
            try:
                line = self._lines.get(timeout=left)
            except queue.Empty:
                continue
            if line is None:
                self.kill()
                raise RestoreError(f'worker exited ({self.proc.returncode}) before '
                                   f'{"/".join(kinds)}')
            kind, body = parse_line(line)
            if kind == 'KV_SERVED':
                continue
            if kind not in kinds:
                raise ProtocolError(f'unexpected {kind}')
            return kind, body

    def go(self, run, ordinal, object_slba, nbytes, dst_frame0, timeout):
        try:
            self.proc.stdin.write(go_line(run, ordinal, object_slba, nbytes, dst_frame0))
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            self.kill()
            raise RestoreError(f'worker gone: {error}') from None
        kind, body = self._next(timeout, ('KV_RESULT', 'KV_ERROR'))
        if kind == 'KV_ERROR':
            return dict(run=run, ok=False, error=int(body.get('error', -22)), started=False,
                        refused=body)
        return body

    def quit(self, timeout):
        if self.proc.poll() is not None or self.proc.stdin.closed:
            self._close()
            raise RestoreError(f'worker already exited ({self.proc.returncode})')
        try:
            try:
                self.proc.stdin.write('QUIT\n')
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as error:
                raise RestoreError(f'worker gone: {error}') from None
            _, body = self._next(timeout, ('KV_BYE',))
        finally:
            self.wait(timeout)
        return body

    def wait(self, timeout):
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
        self._close()

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self._close()

    def _close(self):
        if self.proc.poll() is None:
            return
        self._reader.join(timeout=5)
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                if stream and not stream.closed:
                    stream.close()
            except OSError:
                pass
        if self._log is not subprocess.DEVNULL and not self._log.closed:
            self._log.close()


class OrdinalStore:
    """Restore ordinals that never repeat; stored before use when a file is given."""

    def __init__(self, base=1, path=None):
        self.path = Path(path) if path else None
        self.next = max(1, int(base))
        if self.path and self.path.exists():
            stored = json.loads(self.path.read_text()).get('next_ordinal')
            if type(stored) is not int or stored < 1:
                raise RestoreError(f'{self.path}: bad next_ordinal {stored!r}')
            self.next = max(self.next, stored)

    def claim(self):
        ordinal = self.next
        self.next += 1
        if self.path:
            tmp = self.path.with_name(self.path.name + '.tmp')
            with open(tmp, 'w') as f:
                json.dump({'next_ordinal': self.next}, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        return ordinal


@dataclass
class RestoreConfig:
    argv: list
    group_bytes: int
    pool_bytes: int
    ready_timeout: float = 300.0
    go_timeout: float = 600.0
    quit_timeout: float = 120.0
    max_restarts: int = 3
    worker_log: Optional[str] = None
    ordinal_base: int = 1
    ordinal_file: Optional[str] = None
    env: Optional[dict] = None


class RestoreOutcome(NamedTuple):
    ok: bool
    error: int
    reason: str
    latency_ns: int
    result: Optional[dict]


def check_ready(ready, cfg):
    """KV_READY of a ce-vmm worker whose geometry is the connector's."""
    problems = []
    if ready.get('dst') != 'ce-vmm':
        problems.append(f'dst {ready.get("dst")!r}, need ce-vmm')
    if ready.get('dry_run') is not False:
        problems.append('dry run')
    if ready.get('group_bytes') != cfg.group_bytes:
        problems.append(f'group_bytes {ready.get("group_bytes")} != {cfg.group_bytes}')
    frame = ready.get('frame_bytes')
    if type(frame) is not int or frame < 1 or ready.get('pool_frames', 0) * frame != cfg.pool_bytes:
        problems.append(f'pool of {ready.get("pool_frames")} x {frame} bytes != {cfg.pool_bytes}')
    fd, size = ready.get('vmm_export_fd'), ready.get('vmm_bytes')
    if type(fd) is not int or fd < 0 or type(size) is not int or size < cfg.pool_bytes:
        problems.append(f'no CUDA VMM export (fd {fd!r}, {size!r} bytes)')
    if problems:
        raise RestoreError('KV_READY refused: ' + '; '.join(problems))
    return ready


def check_result(result, run, nbytes, dst_frame0):
    """'' for a good restore, else why the KV_RESULT cannot be trusted."""
    if result.get('run') != run:
        return f'KV_RESULT for run {result.get("run")!r}'
    if result.get('ok') is not True or result.get('error') != 0:
        return f'KV_RESULT not ok (error {result.get("error")!r})'
    if result.get('bytes') != nbytes:
        return f'KV_RESULT carries {result.get("bytes")!r} of {nbytes} bytes'
    if result.get('dst') != 'ce-vmm':
        return f'KV_RESULT destination {result.get("dst")!r}'
    if result.get('cpu_copy_bytes') != 0:
        return 'KV_RESULT copied payload with the CPU'
    plan = result.get('plan')
    if plan is not None and plan.get('host2_dst_frame0') != dst_frame0:
        return f'KV_RESULT placed at frame {plan.get("host2_dst_frame0")!r}, not {dst_frame0}'
    t0, t1 = result.get('t0_ns'), result.get('t1_ns')
    if type(t0) is not int or type(t1) is not int or t1 < t0:
        return 'KV_RESULT without a valid clock'
    return ''


class RestoreService:
    """A worker plus its staging import, replaced on failure, used by one thread."""

    def __init__(self, cfg, staging_factory, worker_factory=WorkerProcess):
        self.cfg = cfg
        self._staging_factory = staging_factory
        self._worker_factory = worker_factory
        self.ordinals = OrdinalStore(cfg.ordinal_base, cfg.ordinal_file)
        self.worker = None
        self.staging = None
        self.ready = None
        self.disabled = False
        self.kept = []          # staging of retained sessions, never released
        self.byes = []
        self.stats = dict(restores=0, failures=0, restarts=0, retained=0)
        self.release = self._release_staging   # the worker side may defer it

    @staticmethod
    def _release_staging(staging):
        staging.release()

    def start(self):
        worker = self._worker_factory(self.cfg.argv, self.cfg.ready_timeout,
                                      log=self.cfg.worker_log, env=self.cfg.env)
        try:
            check_ready(worker.ready, self.cfg)
            staging = self._staging_factory(worker.ready, worker.pid)
        except BaseException as error:
            worker.kill()
            if isinstance(error, RestoreError):
                raise
            raise RestoreError(f'staging import failed: {error}') from error
        self.worker, self.staging, self.ready = worker, staging, worker.ready

    @property
    def frame_bytes(self):
        return self.ready['frame_bytes']

    def _retire(self):
        worker, staging = self.worker, self.staging
        self.worker = self.staging = None
        if worker is None:
            return
        retained = True     # unknown unless the worker says otherwise
        try:
            bye = worker.quit(self.cfg.quit_timeout)
            self.byes.append(bye)
            retained = bye.get('retained') is not False
        except RestoreError as error:
            self.byes.append({'error': str(error), 'retained': None})
            # A killed worker released its own resources with its process; only a
            # worker that answered "retained" keeps DMA ownership unknown.
            retained = False
        if retained:
            self.stats['retained'] += 1
            self.kept.append(staging)
        elif staging is not None:
            self.release(staging)

    def _replace(self):
        self._retire()
        self.stats['restarts'] += 1
        if self.stats['restarts'] > self.cfg.max_restarts:
            self.disabled = True
            return
        try:
            self.start()
        except RestoreError:
            self.disabled = True

    def restore(self, object_slba, nbytes, staging_offset):
        if self.disabled or self.worker is None:
            return RestoreOutcome(False, -19, 'disabled', 0, None)
        frame = self.frame_bytes
        if staging_offset % frame or staging_offset < 0 or \
                staging_offset + nbytes > self.cfg.pool_bytes:
            raise ValueError(f'staging range [{staging_offset}, +{nbytes}) is not whole frames '
                             f'inside the {self.cfg.pool_bytes}-byte pool')
        dst0 = staging_offset // frame
        ordinal = self.ordinals.claim()
        run = f'xkv-{ordinal}'
        self.stats['restores'] += 1
        try:
            result = self.worker.go(run, ordinal, object_slba, nbytes, dst0, self.cfg.go_timeout)
        except RestoreError as error:
            self.stats['failures'] += 1
            self._replace()
            return RestoreOutcome(False, -5, f'worker: {error}', 0, None)
        why = check_result(result, run, nbytes, dst0)
        if not why:
            return RestoreOutcome(True, 0, '', result['t1_ns'] - result['t0_ns'], result)
        self.stats['failures'] += 1
        error = result.get('error') if type(result.get('error')) is int and result.get('error') \
            else -5
        if result.get('ok') is False and result.get('started') is False:
            return RestoreOutcome(False, error, why, 0, result)
        self._replace()
        return RestoreOutcome(False, error, why, 0, result)

    def close(self):
        self._retire()
        return self.byes
