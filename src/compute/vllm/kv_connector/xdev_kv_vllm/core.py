# SPDX-License-Identifier: GPL-2.0
"""Scheduling and loading rules of the xdev_ext KV connector, independent of vLLM.

Scheduler side (SchedulerSide): the longest stored prefix of a prompt (the
prefix index, at most prompt length - 1 tokens) beyond vLLM's own computed
tokens is offered as external tokens. Its restore reads whole groups from the
largest group-aligned block boundary at or before the computed tokens
(layout.stage_start), so only already-computed tokens are re-read.

Worker side (WorkerSide), one restore worker and one background thread:
  async (default): start_load_kv queues the restore; the thread restores, then
    scatters every layer on a side stream that first waits for the event
    start_load_kv recorded (the step's block zeroing is before it), and waits
    for the scatter. The request is then reported finished receiving; a
    failure is also reported in failed_recving, and vLLM with
    kv_load_failure_policy="recompute" recomputes the whole request. Restores
    run one at a time into staging offset 0.
  sync: the scheduler packs one step's restores into the staging pool; the
    thread waits until the previous step's scatters are done, then restores.
    wait_for_layer_load(layer) waits for each restore of the step and scatters
    that layer on the current stream, before the layer's attention. A failed
    restore, a failed scatter or a layer never scattered by the end of the step
    makes the request's loaded blocks invalid (get_block_ids_with_load_errors),
    so vLLM discards that request's output of the step and recomputes.
A request is never reported loaded unless its restore was good and every layer
was scattered.
"""
from dataclasses import dataclass, field
import json
import queue
import threading
import time
from typing import NamedTuple, Optional

from . import index as ki
from .layout import round_up, stage_start, canonical_dtype, LayoutError
from .restore import RestoreConfig

PREFIX = 'xdev_ext.'
MODES = ('async', 'sync')


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ConnectorConfig:
    index_path: str
    model_key: str
    pool_bytes: int
    load_mode: str = 'async'
    group_bytes: int = 131072
    lba_bytes: int = 512
    restore: Optional[RestoreConfig] = None
    stats_file: Optional[str] = None
    scatter: str = 'triton'
    gpu_bdf: Optional[str] = None
    kv_dtype: Optional[str] = None

    def __post_init__(self):
        if self.load_mode not in MODES:
            raise ConfigError(f'load_mode must be one of {MODES}: {self.load_mode!r}')
        for what in ('pool_bytes', 'group_bytes', 'lba_bytes'):
            v = getattr(self, what)
            if type(v) is not int or v < 1:
                raise ConfigError(f'{what} must be a positive integer: {v!r}')
        if self.group_bytes % self.lba_bytes or self.pool_bytes % self.group_bytes:
            raise ConfigError('group_bytes must be whole LBAs and pool_bytes whole groups')
        if self.scatter not in ('triton', 'torch'):
            raise ConfigError(f'scatter must be triton or torch: {self.scatter!r}')
        if self.kv_dtype is not None:
            try:
                canonical_dtype(self.kv_dtype)
            except LayoutError as error:
                raise ConfigError(str(error)) from None

    @classmethod
    def from_extra(cls, extra, worker=False):
        """Parse kv_connector_extra_config; every key starting with "xdev_ext." must be known."""
        known = {'index', 'model_key', 'pool_bytes', 'load_mode', 'group_bytes', 'lba_bytes',
                 'worker_argv', 'worker_log', 'ready_timeout_s', 'go_timeout_s', 'max_restarts',
                 'ordinal_base', 'ordinal_file', 'stats_file', 'scatter', 'gpu_bdf', 'kv_dtype'}
        ours = {k[len(PREFIX):]: v for k, v in extra.items() if k.startswith(PREFIX)}
        unknown = set(ours) - known
        if unknown:
            raise ConfigError(f'unknown keys: {sorted(PREFIX + k for k in unknown)}')
        for need in ('index', 'model_key', 'pool_bytes') + (('worker_argv',) if worker else ()):
            if need not in ours:
                raise ConfigError(f'{PREFIX}{need} is required')
        restore = None
        if 'worker_argv' in ours:
            argv = ours['worker_argv']
            if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
                raise ConfigError(f'{PREFIX}worker_argv must be a nonempty list of strings')
            restore = RestoreConfig(
                argv=list(argv), group_bytes=ours.get('group_bytes', 131072),
                pool_bytes=ours['pool_bytes'],
                ready_timeout=float(ours.get('ready_timeout_s', 300.0)),
                go_timeout=float(ours.get('go_timeout_s', 600.0)),
                max_restarts=int(ours.get('max_restarts', 3)),
                worker_log=ours.get('worker_log'), ordinal_base=int(ours.get('ordinal_base', 1)),
                ordinal_file=ours.get('ordinal_file'),
                allow_local_verify=ours.get('load_mode', 'async') != 'sync')
        return cls(index_path=ours['index'], model_key=ours['model_key'],
                   pool_bytes=ours['pool_bytes'], load_mode=ours.get('load_mode', 'async'),
                   group_bytes=ours.get('group_bytes', 131072), lba_bytes=ours.get('lba_bytes', 512),
                   restore=restore, stats_file=ours.get('stats_file'),
                   scatter=ours.get('scatter', 'triton'), gpu_bdf=ours.get('gpu_bdf'),
                   kv_dtype=ours.get('kv_dtype'))


class LoadSpec(NamedTuple):
    req_id: str
    block_ids: tuple       # manager blocks holding tokens [0, end_token)
    first_token: int       # first token written (vLLM's computed tokens)
    end_token: int         # restored prefix length
    stage_token: int       # first token of the staged bytes
    object_slba: int       # GO object_slba
    nbytes: int            # GO bytes (whole groups)
    staging_offset: int    # byte offset in the staging pool
    invalid: str = ''      # nonempty: the load cannot be done; report it failed

    def loaded_blocks(self, block_size):
        return set(self.block_ids[self.first_token // block_size:
                                  -(-self.end_token // block_size)])


class SchedulerSide:
    def __init__(self, cfg, prefix_index, staging, block_size):
        self.cfg, self.index, self.staging, self.block_size = cfg, prefix_index, staging, block_size
        self.asynchronous = cfg.load_mode == 'async'
        self._candidates = {}
        self._pending = []
        self._step_bytes = 0
        self.stats = dict(lookups=0, hits=0, too_big=0, pool_full=0, planned=0, invalid=0)

    def _offset(self, nbytes):
        if self.asynchronous:
            return 0 if nbytes <= self.cfg.pool_bytes else None
        offset = round_up(self._step_bytes, self.cfg.group_bytes)
        return offset if offset + nbytes <= self.cfg.pool_bytes else None

    def lookup(self, req_id, token_ids, num_computed):
        """(external tokens, asynchronous) as get_num_new_matched_tokens returns them."""
        self.stats['lookups'] += 1
        if not token_ids or num_computed % self.block_size:
            return 0, False
        self._candidates.pop(req_id, None)
        bpt = self.staging.bytes_per_token
        s0 = stage_start(num_computed, bpt, self.block_size, self.cfg.group_bytes)
        # The longest stored prefix whose restore fits the staging pool.
        for entry in self.index.matches(token_ids, max_tokens=len(token_ids) - 1):
            if entry.tokens <= num_computed:
                break
            nbytes = round_up((entry.tokens - s0) * bpt, self.cfg.group_bytes)
            if nbytes > self.cfg.pool_bytes:
                self.stats['too_big'] += 1
                continue
            if self._offset(nbytes) is None:
                self.stats['pool_full'] += 1
                continue
            self.stats['hits'] += 1
            self._candidates[req_id] = entry
            return entry.tokens - num_computed, self.asynchronous
        return 0, False

    def after_alloc(self, req_id, block_ids, num_external):
        entry = self._candidates.pop(req_id, None)
        if num_external <= 0 or entry is None:
            return
        bs, bpt = self.block_size, self.staging.bytes_per_token
        first = entry.tokens - num_external
        s0 = stage_start(max(first, 0), bpt, bs, self.cfg.group_bytes)
        nbytes = round_up((entry.tokens - s0) * bpt, self.cfg.group_bytes)
        offset = self._offset(nbytes)
        slba, _ = ki.resolve(entry, self.cfg.lba_bytes)
        need = -(-entry.tokens // bs)
        invalid = ''
        if first < 0 or first % bs:
            invalid = f'{num_external} external tokens of a {entry.tokens}-token prefix'
        elif len(block_ids) < need:
            invalid = f'{len(block_ids)} blocks for {entry.tokens} tokens'
        elif offset is None:
            invalid = 'staging pool full'
        if invalid:
            self.stats['invalid'] += 1
            offset = 0
        else:
            self._step_bytes = offset + nbytes
        self.stats['planned'] += 1
        self._pending.append(LoadSpec(req_id, tuple(block_ids[:need]), max(first, 0), entry.tokens,
                                      s0, slba + s0 * bpt // self.cfg.lba_bytes, nbytes, offset,
                                      invalid))

    def build(self):
        specs, self._pending = self._pending, []
        self._step_bytes = 0
        self._candidates.clear()
        return specs

    def finished(self, req_id):
        self._candidates.pop(req_id, None)


class _Future:
    def __init__(self):
        self._event = threading.Event()
        self.value = None

    def set(self, value):
        self.value = value
        self._event.set()

    def wait(self, timeout):
        return self._event.wait(timeout)


@dataclass
class _StepLoad:
    spec: LoadSpec
    future: _Future
    layers: set = field(default_factory=set)
    failed: str = ''
    t0: int = 0


class WorkerSide:
    def __init__(self, cfg, service, device, layer_index, staging, clock=time.monotonic_ns):
        self.cfg, self.service, self.device = cfg, service, device
        self.layer_index, self.staging, self.clock = dict(layer_index), staging, clock
        self.asynchronous = cfg.load_mode == 'async'
        self.block_size = staging.block_size
        if not self.asynchronous and not service.disabled:
            ready = getattr(service, 'ready', None)
            if not ready or ready.get('role') != 'restore':
                raise ConfigError('sync mode requires an attested restore worker; local-verify '
                                  'poisons staging before each GO')
        self._jobs = queue.Queue()
        self._done = queue.Queue()
        self._step = []
        self._errors = set()
        self._deferred = []         # staging of replaced workers, freed after the next fence
        self._have_deferred = threading.Event()
        self._stats_lock = threading.Lock()
        self._stats = open(cfg.stats_file, 'a', buffering=1) if cfg.stats_file else None
        self._wait_timeout = (cfg.restore.go_timeout * 2 + 60) if cfg.restore else 1260.0
        self._release_now = service.release
        if not self.asynchronous:
            service.release = self._release_later
        self._thread = threading.Thread(target=self._run, name='xdev-kv-restore', daemon=True)
        self._thread.start()

    # ---- background thread -------------------------------------------------
    def _release_later(self, staging):
        self._deferred.append(staging)
        self._have_deferred.set()

    def _restore(self, spec):
        """(ok, reason, staging) of one restore; never raises."""
        if spec.invalid:
            return False, spec.invalid, None
        if self.service.disabled:
            return False, 'restore worker disabled', None
        try:
            out = self.service.restore(spec.object_slba, spec.nbytes, spec.staging_offset)
        except Exception as error:  # noqa: BLE001 - a failed restore must never escape
            return False, f'{type(error).__name__}: {error}', None
        return out.ok, out.reason, self.service.staging if out.ok else None

    def _run(self):
        while True:
            job = self._jobs.get()
            if job is None:
                return
            kind = job[0]
            if kind == 'fence':
                self.device.wait_host(job[1])
                deferred, self._deferred = self._deferred, []
                self._have_deferred.clear()
                for staging in deferred:
                    self._release_now(staging)
            elif kind == 'sync':
                _, spec, future = job
                future.set(self._restore(spec))
            else:
                _, spec, fence = job
                t0 = self.clock()
                ok, reason, staging = self._restore(spec)
                t1 = self.clock()
                if ok:
                    try:
                        self.device.wait_host(self.device.scatter_async(staging, spec, fence))
                    except Exception as error:  # noqa: BLE001
                        ok, reason = False, f'scatter: {type(error).__name__}: {error}'
                self._record(spec, ok, reason, t0, t1, self.clock())
                self._done.put((spec.req_id, ok))

    def _record(self, spec, ok, reason, t0, t1, t2):
        if not self._stats:
            return
        row = dict(req_id=spec.req_id, ok=ok, reason=reason, mode=self.cfg.load_mode,
                   tokens=spec.end_token - spec.first_token, end_token=spec.end_token,
                   nbytes=spec.nbytes, restore_ns=t1 - t0, scatter_ns=t2 - t1)
        with self._stats_lock:
            self._stats.write(json.dumps(row) + '\n')

    # ---- vLLM worker hooks ---------------------------------------------------
    def start_loads(self, specs):
        if self.asynchronous:
            if specs:
                fence = self.device.fence()
                for spec in specs:
                    self._jobs.put(('async', spec, fence))
            return
        if self._step:
            self.load_error_blocks()
        if specs or self._have_deferred.is_set():
            self._jobs.put(('fence', self.device.fence()))
        for spec in specs:
            future = _Future()
            self._step.append(_StepLoad(spec, future, t0=self.clock()))
            self._jobs.put(('sync', spec, future))

    def _fail(self, item, reason):
        item.failed = reason
        self._errors |= item.spec.loaded_blocks(self.block_size)

    def wait_layer(self, layer_name):
        layer = self.layer_index.get(layer_name)
        if layer is None or self.asynchronous:
            return
        for item in self._step:
            if item.failed or layer in item.layers:
                continue
            if not item.future.wait(self._wait_timeout):
                self._fail(item, 'restore did not finish')
                continue
            ok, reason, staging = item.future.value
            if not ok:
                self._fail(item, reason)
                continue
            try:
                self.device.scatter_now(staging, item.spec, layer)
                item.layers.add(layer)
            except Exception as error:  # noqa: BLE001
                self._fail(item, f'scatter: {type(error).__name__}: {error}')

    def load_error_blocks(self):
        for item in self._step:
            if not item.failed and len(item.layers) < len(self.layer_index):
                self._fail(item, f'{len(item.layers)} of {len(self.layer_index)} layers scattered')
            now = self.clock()
            self._record(item.spec, not item.failed, item.failed, item.t0, now, now)
        self._step = []
        errors, self._errors = self._errors, set()
        return errors

    def transfer_results(self, finished_req_ids):
        finished, failed = set(), set()
        while True:
            try:
                req_id, ok = self._done.get_nowait()
            except queue.Empty:
                return finished, failed
            finished.add(req_id)
            if not ok:
                failed.add(req_id)

    def shutdown(self, timeout=30.0):
        if self._thread.is_alive():
            self._jobs.put(None)
            self._thread.join(timeout)
        try:
            self.service.close()
        finally:
            for staging in self._deferred:
                self._release_now(staging)
            self._deferred = []
            if self._stats:
                self._stats.close()
                self._stats = None
