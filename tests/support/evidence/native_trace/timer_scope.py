#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""One owned counter stream and closed, observed timer process receipts."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import copy
import re
import threading
import sys
import hashlib
import stat
import uuid

_spec = importlib.util.spec_from_file_location('timer_cpu_sampling', Path(__file__).with_name('cpu_sampling.py'))
CPU = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(CPU)
PREFIX = 'XDEV_EXT_EVAL_CPU_'
CLOCKS = ('CLOCK_MONOTONIC', 'CLOCK_MONOTONIC_RAW')
MAX_JSON = 64 * 1024 * 1024

# Fixed arm endpoint adapters, never descriptions supplied by a journal.
_ENDPOINTS = {
    'window_ns': {'staged': {'original-closed-window'}, 'session': {'original-closed-window'},
                  'userspace-shared': {'original-closed-window'}},
    'sustained_ns': {'staged': {'post-warmup-last-completion'}, 'session': {'post-warmup-last-completion'},
                     'userspace-shared': {'post-warmup-last-completion'},
                     'concurrent': {'concurrent-original-throughput-envelope'}},
    'io_ns': {'session': {'settled-session', 'terminal-wake-before-settle'},
              'uring-cuda': {'retired-pass'}, 'gds-batch': {'retired-pass'}, 'gds-async': {'retired-pass'},
              'gds-direct': {'chunk-completion-and-checkpoint-fsync'},
              'afxdp-cuda': {'copy-completion', 'tx-completion'},
              'udp-pinned-cuda': {'copy-completion', 'local-socket-custody'}},
}
for _metric, _semantics in (('local_release_ns', 'local_release'), ('receipt_ns', 'receipt'), ('durable_ns', 'durable')):
    _ENDPOINTS[_metric] = {arm: {_semantics} for arm in ('posix', 'uring', 'splice', 'session')}


def _adapter_view(view):
    if (not isinstance(view, dict) or view.get('endpoint_semantics') not in
            _ENDPOINTS.get(view.get('metric'), {}).get(view.get('arm'), set()) or
            view.get('clock') not in CLOCKS or 'identity' not in view):
        raise ValueError('CPU fixed arm timer adapter identity/semantics invalid')
    expected_clock = 'CLOCK_MONOTONIC_RAW' if view['metric'] in ('window_ns', 'sustained_ns', 'local_release_ns', 'receipt_ns', 'durable_ns') else 'CLOCK_MONOTONIC'
    if view['clock'] != expected_clock:
        raise ValueError('CPU fixed arm timer adapter actual clock mismatch')



def _positive(value):
    return type(value) is int and value > 0


def _regular_bytes(path, limit):
    # Nonblocking/no-follow closes the check/open race for FIFOs and symlinks.
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    absolute = Path(path).absolute()
    directory_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        fd = os.open(absolute.name, flags, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('CPU evidence must be a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('CPU artifact oversized')
        return raw
    finally:
        os.close(fd)


def _read_json(path, limit=MAX_JSON):
    return json.loads(_regular_bytes(path, limit))


def _receipt_digest(receipt):
    raw = json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _safe_directory(path):
    path = Path(path)
    for component in (path, *path.parents):
        if stat.S_ISLNK(component.lstat().st_mode):
            raise ValueError('CPU artifact directory symlink refused')
    if not path.is_dir():
        raise ValueError('CPU artifact directory missing')
    return path


def _scope(clock, domain, cpu_set):
    identity = CPU._os_identity()
    selected = CPU.parse_cpu_set(cpu_set, possible=identity['possible_cpus'], online=identity['online_cpus'])
    all_online = selected == tuple(identity['online_cpus'])
    return dict(schema=1, **identity, selected_cpus=list(selected),
                clock=clock, clock_domain=domain, selection='all-online' if all_online else 'subset',
                status='qualified' if all_online else 'hold',
                hold_reasons=[] if all_online else ['subset containment unavailable'])


def _proc(pid):
    text = Path('/proc/%d/stat' % pid).read_text()
    fields = text[text.rfind(')') + 2:].split()
    argv = Path('/proc/%d/cmdline' % pid).read_bytes().split(b'\0')
    return dict(pid=pid, process_start_ticks=int(fields[19]), ppid=int(fields[1]),
                argv=[os.fsdecode(v) for v in argv if v])


def _atomic_json(path, value):
    # Every artifact name is exclusive; consumers only see a closed receipt.
    path = Path(path)
    temporary = path.with_name(path.name + '.partial')
    with temporary.open('x') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')
    temporary.rename(path)


def _identity(receipt):
    fields = ('token', 'run_id', 'pid', 'process_start_ticks')
    if (not isinstance(receipt, dict) or any(k not in receipt for k in fields) or
            any(not isinstance(receipt[k], str) or not receipt[k] for k in fields[:2]) or
            any(not _positive(receipt[k]) for k in fields[2:]) or
            type(receipt.get('returncode')) is not int or receipt['returncode'] != 0 or
            receipt.get('complete') is not True or receipt.get('observation_error') or
            receipt.get('measurement_refusal')):
        raise ValueError('CPU expected child identity receipt incomplete/failed')
    return {k: receipt[k] for k in fields}


def _journal(path):
    path = Path(path)
    raw = _regular_bytes(path, MAX_JSON)
    if not raw or not raw.endswith(b'\n'):
        raise ValueError('CPU timer journal partial')
    rows = [json.loads(line) for line in raw.splitlines()]
    meta, spans = rows[0], rows[1:]
    if (not isinstance(meta, dict) or meta.get('kind') != 'cpu-timer-metadata' or
            type(meta.get('schema')) is not int or meta['schema'] != 1 or
            meta.get('complete') is not True or type(meta.get('rows')) is not int or
            meta['rows'] != len(spans) or len(spans) > 1048576):
        raise ValueError('CPU timer journal closed row count invalid')
    seen = set()
    for row in spans:
        if (not isinstance(row, dict) or row.get('kind') != 'cpu-timer-span' or
                not isinstance(row.get('metric'), str) or not row['metric'] or
                not CPU._integer(row.get('key')) or
                not CPU._integer(row.get('start_ns')) or not CPU._integer(row.get('end_ns')) or
                row['end_ns'] <= row['start_ns']):
            raise ValueError('CPU timer journal row invalid')
        key = row['metric'], row['key']
        if key in seen:
            raise ValueError('CPU timer journal duplicate key')
        seen.add(key)
    return meta, spans


def _project(samples, clock, scope):
    if clock not in CLOCKS or not isinstance(samples, list) or not samples:
        raise ValueError('CPU timer samples/clock unavailable')
    expected = (scope['boot_id'], tuple(scope['online_cpus']), tuple(scope['possible_cpus']))
    projected = []
    for row in samples:
        if not isinstance(row, dict):
            raise ValueError('CPU raw sample must be an object')
        identity = CPU._sample_identity(row, CPU.parse_stat(row.get('stat')))
        if identity[:3] != expected or identity[4] != scope['clock_domain']:
            raise ValueError('CPU timer sample scope identity mismatch')
        item = dict(row)
        if row['clock'] != clock:
            brackets = row.get('clock_brackets')
            bracket = brackets.get(clock) if isinstance(brackets, dict) else None
            if (not isinstance(bracket, dict) or not CPU._integer(bracket.get('before_ns')) or
                    not CPU._integer(bracket.get('after_ns')) or bracket['after_ns'] < bracket['before_ns']):
                raise ValueError('CPU timer actual clock bracket unavailable')
            item.update(bracket, clock=clock)
        projected.append(item)
    return projected


def _qualified(scope):
    if (not isinstance(scope, dict) or type(scope.get('schema')) is not int or scope['schema'] != 1 or
            scope.get('status') != 'qualified' or scope.get('hold_reasons') != [] or
            scope.get('selection') != 'all-online' or
            CPU._cpu_ids(scope.get('selected_cpus')) != CPU._cpu_ids(scope.get('online_cpus')) or
            not set(scope['online_cpus']) <= set(CPU._cpu_ids(scope.get('possible_cpus'))) or
            scope.get('clock') not in CLOCKS or not isinstance(scope.get('clock_domain'), str) or
            not scope['clock_domain'] or not isinstance(scope.get('boot_id'), str)):
        raise ValueError('CPU timer scope HOLD without all-online containment')
    return tuple(scope['selected_cpus'])


def timer_bounds(journal, samples, tick_hz, *, cpu_scope, metric, keys,
                 expected_duration_ns, expected_identity=None, interval_mode='union'):
    selected = _qualified(cpu_scope)
    identity = _identity(expected_identity)
    meta, rows = _journal(journal)
    if any(type(meta.get(k)) is not type(v) or meta.get(k) != v for k, v in identity.items()):
        raise ValueError('CPU timer journal child identity mismatch')
    if meta.get('clock_domain') != cpu_scope.get('clock_domain') or meta.get('clock') not in CLOCKS:
        raise ValueError('CPU timer journal clock/domain mismatch')
    if (not isinstance(keys, (list, tuple, set, frozenset)) or not keys or
            any(not CPU._integer(k) for k in keys) or len(set(keys)) != len(keys)):
        raise ValueError('CPU timer keys missing/duplicate')
    chosen = [r for r in rows if r['metric'] == metric and r['key'] in keys]
    if {r['key'] for r in chosen} != set(keys):
        raise ValueError('CPU timer measured keys unavailable')
    spans = [(r['start_ns'], r['end_ns']) for r in chosen]
    if not _positive(expected_duration_ns) or sum(b-a for a,b in spans) != expected_duration_ns:
        raise ValueError('CPU timer original duration mismatch')
    return CPU.interval_bounds(spans, _project(samples, meta['clock'], cpu_scope), tick_hz,
                               selected, interval_mode=interval_mode)


class TimerCpuRun:
    def __init__(self, output, *, cpu_set=None, clock='CLOCK_MONOTONIC', clock_domain=None, extra_clocks=()):
        if (clock not in CLOCKS or not isinstance(extra_clocks, (list, tuple)) or
                len(extra_clocks) > 1 or any(c not in CLOCKS or c == clock for c in extra_clocks)):
            raise ValueError('CPU owner clocks invalid')
        self.output = Path(output).resolve() if output is not None else None
        self._requested_set = cpu_set
        self.clock, self.extra_clocks = clock, tuple(extra_clocks)
        self._domain = clock_domain
        self._uuid = str(uuid.uuid4())
        self._watched = []
        self._trusted = {}
        self._ancestry = {}
        self._native_finalizations = []
        self._completion_certificates = {}
        self._artifact_errors = []
        self._observation_lock = threading.Lock()
        self.sampler = None
        self.config = None
        self.owner_mode = 'attach' if os.environ.get(PREFIX + 'OWNER') else 'create'
        self._closed = False
        self.capture_error = None

    def _configuration(self):
        if self.config is not None:
            return self.config
        if self.owner_mode == 'attach':
            path = Path(os.environ[PREFIX + 'OWNER'])
            config = _read_json(path, 65536)
            if not isinstance(config, dict):
                raise ValueError('CPU inherited owner config must be an object')
            if (type(config.get('schema')) is not int or config['schema'] != 1 or
                    not isinstance(config.get('token'), str) or not 1 <= len(config['token'].encode()) <= 255 or '\0' in config['token'] or
                    not isinstance(config.get('run_id'), str) or not 1 <= len(config['run_id'].encode()) <= 255 or '\0' in config['run_id'] or
                    config.get('primary_clock') not in CLOCKS):
                raise ValueError('CPU inherited owner config invalid')
            scope = config.get('cpu_scope')
            CPU._cpu_ids(scope.get('selected_cpus') if isinstance(scope, dict) else None)
            if (scope.get('clock') != config['primary_clock'] or
                    not isinstance(scope.get('clock_domain'), str) or
                    not 1 <= len(scope['clock_domain'].encode()) <= 255 or '\0' in scope['clock_domain']):
                raise ValueError('CPU inherited scope clock/domain invalid')
            actual = CPU._os_identity()
            if any(scope.get(k) != actual[k] for k in ('boot_id', 'online_cpus', 'possible_cpus')):
                raise ValueError('CPU inherited owner OS identity mismatch')
            if type(config.get('measurement_cpu_count')) is not int or config['measurement_cpu_count'] != len(scope['selected_cpus']):
                raise ValueError('CPU inherited owner measurement count invalid')
            if (not isinstance(config.get('extra_clocks'), (list, tuple)) or
                    len(config['extra_clocks']) > 1 or any(c not in CLOCKS or c == config['primary_clock'] for c in config['extra_clocks'])):
                raise ValueError('CPU inherited owner extra clocks invalid')
            for field in ('samples_path', 'journal_dir', 'receipts_dir'):
                if (not isinstance(config.get(field), str) or not Path(config[field]).is_absolute() or
                        len(os.fsencode(config[field])) > 4095 or '\0' in config[field]):
                    raise ValueError('CPU inherited owner artifact path invalid')
            if (self.output is not None or self._requested_set is not None or
                    self._domain is not None and self._domain != scope['clock_domain']):
                raise ValueError('CPU inherited owner override conflicts')
            if self.clock not in (config['primary_clock'], *config.get('extra_clocks', [])):
                raise ValueError('CPU inherited owner actual clock unavailable')
            self.owner_path = path
        else:
            output = self.output or (Path.cwd() / 'cpu-measurements' / self._uuid).resolve()
            boot = CPU._os_identity()['boot_id']
            domain = self._domain or boot + ':' + self._uuid
            if not isinstance(domain, str) or not 1 <= len(domain.encode()) <= 255 or '\0' in domain:
                raise ValueError('CPU owner clock domain invalid')
            scope = _scope(self.clock, domain, self._requested_set)
            config = dict(schema=1, token=str(uuid.uuid4()), run_id=self._uuid, cpu_scope=scope,
                          measurement_cpu_count=len(scope['selected_cpus']), tick_hz=os.sysconf('SC_CLK_TCK'),
                          primary_clock=self.clock, extra_clocks=list(self.extra_clocks),
                          samples_path=str(output / 'cpu-samples.jsonl'), journal_dir=str(output / 'journals'),
                          receipts_dir=str(output / 'receipts'))
            self.owner_path = output / 'owner.json'
        self.config = config
        return config

    def plan(self):
        config = self._configuration()
        return dict(schema=1, status='planned', selected_cpus=config['cpu_scope']['selected_cpus'],
                    clock=self.clock, extra_clocks=list(config.get('extra_clocks', [])), owner_mode=self.owner_mode,
                    artifacts={k: config[k] for k in ('samples_path', 'journal_dir')})

    def __enter__(self):
        config = self._configuration()
        self.observer = _proc(os.getpid())
        if self.owner_mode == 'create':
            self.owner_path.parent.mkdir(parents=True, mode=0o700, exist_ok=False)
            self.owner_path.parent.chmod(0o700)
            for key in ('journal_dir', 'receipts_dir'):
                Path(config[key]).mkdir(mode=0o700)
            config['owner_pid'] = self.observer['pid']
            config['owner_start_ticks'] = self.observer['process_start_ticks']
            _atomic_json(self.owner_path, config)
            self.sampler = CPU.CpuSampler(config['samples_path'], clock_domain=config['cpu_scope']['clock_domain'],
                                          clock=config['primary_clock'], extra_clocks=config['extra_clocks'],
                                          sample_callback=self._observe_requests)
            self.sampler.__enter__()
        return self

    def environment(self, base_env):
        config = self._configuration()
        env = dict(base_env)
        env.update({PREFIX + 'OWNER': str(self.owner_path), PREFIX + 'JOURNAL_DIR': config['journal_dir'],
                    PREFIX + 'TOKEN': config['token'], PREFIX + 'RUN_ID': config['run_id'],
                    PREFIX + 'CLOCK_DOMAIN': config['cpu_scope']['clock_domain']})
        return env

    def watch_child(self, process, command):
        config = self._configuration()
        if not isinstance(command, (list, tuple)) or not command or any(not isinstance(v, str) for v in command):
            raise ValueError('CPU observed child command invalid')
        observed, observation_error = None, None
        try:
            observed = _proc(process.pid)
            if observed['ppid'] != os.getpid() or observed['argv'] != list(command):
                raise ValueError('CPU actual child parent/argv mismatch')
        except (OSError, ValueError) as error:
            # Missing observation holds CPU qualification; it must not replace
            # the original command result or stop an otherwise valid workload.
            observation_error = str(error)
            if observed is None:
                observed = dict(pid=process.pid, process_start_ticks=0, ppid=0, argv=[])
        receipt = dict(schema=1, token=config['token'], run_id=config['run_id'], **observed,
                       command=list(command), observed_ppid=observed['ppid'], observer_pid=self.observer['pid'],
                       observer_start_ticks=self.observer['process_start_ticks'], returncode=None, complete=False)
        if observation_error is not None:
            receipt['observation_error'] = observation_error
        self._watched.append((process, receipt))
        key = (receipt['pid'], receipt['process_start_ticks'])
        entry = dict(base=copy.deepcopy(receipt), process=process, final=None, persisted=None, refusal=None)
        with self._observation_lock:
            self._trusted[key] = entry
        if self.owner_mode == 'attach':
            request = dict(schema=1, token=config['token'], run_id=config['run_id'],
                           observer=copy.deepcopy(self.observer), child=copy.deepcopy(receipt))
            self._save_evidence(Path(config['receipts_dir']) / ('live-%d-%d.request' % key), request)
        return receipt

    def _save_evidence(self, path, value):
        try:
            _atomic_json(path, value)
        except (OSError, ValueError, TypeError) as error:
            self._artifact_error(error)
            return False
        return True

    def _artifact_error(self, error):
        if len(self._artifact_errors) < 16:
            self._artifact_errors.append(str(error)[:512])
        if isinstance(self.config, dict):
            self.config['evidence_errors'] = list(self._artifact_errors)

    def _observe_requests(self):
        """Bounded requested /proc identities; never enumerate unrelated tasks."""
        try:
            self._proc_read_budget = 512
            directory = _safe_directory(self.config['receipts_dir'])
            paths = []
            total = 0
            for path in directory.glob('*.request'):
                paths.append(path)
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('CPU observation request must be a regular file')
                total += info.st_size
                if len(paths) > 256 or total > 1024 * 1024:
                    raise ValueError('CPU child observation requests exceed bound')
            pending = []
            for path in paths:
                request = _read_json(path, 16384)
                if (not isinstance(request, dict) or type(request.get('schema')) is not int or request['schema'] != 1 or
                        request.get('token') != self.config['token'] or request.get('run_id') != self.config['run_id']):
                    raise ValueError('CPU live observation request identity invalid')
                pending.append(request)
            with self._observation_lock:
                for _ in range(len(pending) + 1):
                    progress = False
                    for request in pending[:]:
                        observer, child = request.get('observer'), request.get('child')
                        if (not isinstance(observer, dict) or not isinstance(child, dict) or
                                any(not _positive(row.get(k)) for row in (observer, child) for k in ('pid', 'process_start_ticks'))):
                            raise ValueError('CPU live observation request malformed')
                        parent_key = (observer.get('pid'), observer.get('process_start_ticks'))
                        parent = self._trusted.get(parent_key)
                        if parent is not None and parent['base'].get('observation_error'):
                            continue
                        if parent is None and not self._verify_ancestry(observer):
                            continue
                        key = child.get('pid'), child.get('process_start_ticks')
                        if key in self._trusted:
                            pending.remove(request)
                            continue
                        try:
                            actual_parent = self._live_proc(observer['pid'])
                            actual_child = self._live_proc(child['pid'])
                        except (OSError, ValueError):
                            continue
                        if (actual_parent != observer or actual_child.get('pid') != child.get('pid') or
                                actual_child.get('process_start_ticks') != child.get('process_start_ticks') or
                                actual_child.get('ppid') != observer['pid'] or actual_child.get('argv') != child.get('argv') or
                                child.get('argv') != child.get('command') or child.get('observer_pid') != observer['pid'] or
                                child.get('observer_start_ticks') != observer['process_start_ticks'] or
                                child.get('token') != self.config['token'] or child.get('run_id') != self.config['run_id'] or
                                child.get('observation_error')):
                            raise ValueError('CPU live child identity/actual parent/argv mismatch')
                        self._trusted[key] = dict(base=copy.deepcopy(child), process=None, final=None,
                                                  persisted=None, refusal=None)
                        pending.remove(request)
                        progress = True
                    if not progress:
                        break
        except (OSError, ValueError, KeyError, TypeError) as error:
            self._artifact_error(error)

    def _live_proc(self, pid):
        if self._proc_read_budget <= 0:
            raise ValueError('CPU live process observation read limit reached')
        self._proc_read_budget -= 1
        return _proc(pid)

    def _verify_ancestry(self, observer):
        """Verify a bounded live chain through existing perf/shell delegates."""
        chain = []
        current = observer
        root = self.config['owner_pid'], self.config['owner_start_ticks']
        for _ in range(64):
            key = current['pid'], current['process_start_ticks']
            if key == root or key in self._ancestry or (key in self._trusted and
                    not self._trusted[key]['base'].get('observation_error')):
                for row in chain:
                    self._ancestry[(row['pid'], row['process_start_ticks'])] = copy.deepcopy(row)
                return True
            if current['ppid'] <= 0 or current['ppid'] == current['pid']:
                return False
            chain.append(current)
            try:
                current = self._live_proc(current['ppid'])
            except (OSError, ValueError):
                return False
        raise ValueError('CPU observer ancestry exceeds bound')

    def refuse_child(self, receipt_or_pid, reason):
        pid = receipt_or_pid.get('pid') if isinstance(receipt_or_pid, dict) else receipt_or_pid
        if not _positive(pid) or not isinstance(reason, str) or not reason:
            self._artifact_error('CPU child refusal identity/reason invalid')
            return
        with self._observation_lock:
            entries = [(key, entry) for key, entry in self._trusted.items()
                       if key[0] == pid and entry['process'] is not None]
            if len(entries) != 1:
                self._artifact_error('CPU child refusal has no observed process')
                return
            key, entry = entries[0]
            if isinstance(receipt_or_pid, dict) and receipt_or_pid.get('process_start_ticks') != key[1]:
                self._artifact_error('CPU child refusal start identity mismatch')
                return
            entry['refusal'] = reason[:255]
        self._finish_receipts()

    def _finish_receipts(self):
        for process, public_receipt in self._watched:
            with self._observation_lock:
                key, entry = next((k, e) for k, e in self._trusted.items() if e['process'] is process)
            returncode = process.poll()
            receipt = dict(entry['base'], returncode=returncode, complete=returncode is not None)
            if entry['refusal']:
                receipt['measurement_refusal'] = entry['refusal']
            entry['final'] = copy.deepcopy(receipt)
            public_receipt.update(receipt)
            if entry['persisted'] == receipt:
                continue
            name = '%d-%d.json' % key
            if self._save_evidence(Path(self.config['receipts_dir']) / name, receipt):
                entry['persisted'] = copy.deepcopy(receipt)
                if self.owner_mode == 'attach' and receipt['complete']:
                    marker = ('XDEV_EXT_CPU_RECEIPT_V1 pid=%d start=%d observer=%d observer_start=%d sha256=%s\n' %
                        (receipt['pid'], receipt['process_start_ticks'], receipt['observer_pid'],
                         receipt['observer_start_ticks'], _receipt_digest(receipt))).encode()
                    try:
                        if os.write(2, marker) != len(marker):
                            raise OSError('partial CPU receipt certificate')
                    except OSError as error:
                        self._artifact_error(error)

    def capture_stderr(self, receipt_or_pid, data):
        """Bind certificates only to an actually captured existing child stream."""
        pid = receipt_or_pid.get('pid') if isinstance(receipt_or_pid, dict) else receipt_or_pid
        with self._observation_lock:
            entries = [(key, entry) for key, entry in self._trusted.items()
                       if key[0] == pid and entry['process'] is not None]
        if len(entries) != 1 or not isinstance(data, (str, bytes)):
            self._artifact_error('CPU certificate lacks actual captured child stderr')
            return
        source, _ = entries[0]
        raw = data.encode() if isinstance(data, str) else data
        if len(raw) > 1024 * 1024:
            self._artifact_error('CPU captured certificate stream exceeds bound')
            return
        pattern = re.compile(rb'XDEV_EXT_CPU_RECEIPT_V1 pid=([0-9]{1,20}) start=([0-9]{1,20}) observer=([0-9]{1,20}) observer_start=([0-9]{1,20}) sha256=([0-9a-f]{64})')
        count = 0
        for line in raw.splitlines():
            if not line.startswith(b'XDEV_EXT_CPU_RECEIPT_V1'):
                continue
            match = pattern.fullmatch(line)
            if match is None:
                self._artifact_error('CPU malformed fixed receipt certificate')
                continue
            count += 1
            if count > 256:
                self._artifact_error('CPU receipt certificates exceed bound')
                break
            pid, start, observer, observer_start = (int(v) for v in match.groups()[:4])
            value = dict(issuer=(observer, observer_start), digest=match[5].decode(), source=source)
            self._completion_certificates[(pid, start)] = value
            if self.owner_mode == 'attach':
                # Relay only bounded fixed certificates from the actual captured child.
                try:
                    if os.write(2, line + b'\n') != len(line) + 1:
                        raise OSError('partial relayed CPU receipt certificate')
                except OSError as error:
                    self._artifact_error(error)

    def _certificate_ancestry(self, issuer, source):
        rows = dict(self._ancestry)
        rows.update({key: value['base'] for key, value in self._trusted.items()})
        current = issuer
        for _ in range(64):
            if current == source:
                return True
            row = rows.get(current)
            if row is None:
                return False
            parent = [(key, value) for key, value in rows.items() if key[0] == row['ppid']]
            if len(parent) != 1:
                return False
            current = parent[0][0]
        return False

    def run(self, command, **kwargs):
        # Preserve subprocess.run semantics; observation happens immediately after Popen.
        input_value = kwargs.pop('input', None)
        capture = kwargs.pop('capture_output', False)
        check = kwargs.pop('check', False)
        timeout = kwargs.pop('timeout', None)
        if input_value is not None:
            if kwargs.get('stdin') is not None:
                raise ValueError('stdin and input arguments may not both be used')
            kwargs['stdin'] = subprocess.PIPE
        if capture:
            if kwargs.get('stdout') is not None or kwargs.get('stderr') is not None:
                raise ValueError('stdout and stderr arguments may not be used with capture_output')
            kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        kwargs['env'] = self.environment(kwargs.get('env') if kwargs.get('env') is not None else os.environ)
        with subprocess.Popen(command, **kwargs) as process:
            try:
                self.watch_child(process, command)
                stdout, stderr = process.communicate(input_value, timeout=timeout)
            except subprocess.TimeoutExpired as error:
                process.kill()
                if os.name == 'nt':
                    error.stdout, error.stderr = process.communicate()
                else:
                    process.wait()
                self._finish_receipts()
                raise
            except BaseException:
                process.kill()
                process.wait()
                self._finish_receipts()
                raise
            if isinstance(stderr, (str, bytes)):
                self.capture_stderr(process.pid, stderr)
            if isinstance(stderr, (str, bytes)) and re.search(
                    rb'(?m)^XDEV_EXT_CPU_TIMER_REFUSED phase=(?:init|publish) code=-?[0-9]{1,11}\n',
                    stderr.encode() if isinstance(stderr, str) else stderr):
                self.refuse_child(process.pid, 'cpu-timer-journal-refused')
            self._finish_receipts()
            result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
            if check:
                result.check_returncode()
            return result

    def __exit__(self, typ, value, tb):
        if typ is not None:
            self.capture_error = str(value)
        try:
            self._finish_receipts()
        finally:
            if self.sampler is not None:
                self.sampler.__exit__(typ, value, tb)
            self._closed = True
        if self.owner_mode == 'create':
            self._save_evidence(self.owner_path.with_name('final.json'), dict(self.config, complete=True,
                         sampler_error=self.sampler.error if self.sampler else 'sampler unavailable'))
            self._finalize_native()
            self.config['native_finalizations'] = copy.deepcopy(self._native_finalizations)
            self._save_evidence(self.owner_path.with_name('final.json'), dict(self.config, complete=True,
                         sampler_error=self.sampler.error if self.sampler else 'sampler unavailable',
                         evidence_errors=list(self._artifact_errors)))

    def defer_native(self, manifest, receipt, output=None):
        config = self._configuration()
        if isinstance(manifest, (str, Path)):
            manifest = _read_json(manifest)
        if isinstance(receipt, (str, Path)):
            receipt_path = Path(receipt).resolve()
            receipt = _read_json(receipt_path)
            if output is None:
                output = receipt_path.parent
        if not isinstance(manifest, dict) or not isinstance(receipt, dict) or output is None:
            raise ValueError('CPU native finalization needs closed manifest/receipt and output')
        request = dict(schema=1, token=config['token'], run_id=config['run_id'],
                       observer_pid=self.observer['pid'], observer_start_ticks=self.observer['process_start_ticks'],
                       manifest=manifest, receipt=receipt, output=str(Path(output).resolve()),
                       complete=self.capture_error is None and not self._artifact_errors)
        path = Path(config['journal_dir']) / ('native-%s.native-request' % uuid.uuid4())
        self._save_evidence(path, request)

    def _finalize_native(self):
        """Seal pending native CPU artifacts only after the shared final read."""
        paths = list(Path(self.config['journal_dir']).glob('*.native-request'))
        if not paths:
            return
        try:
            if len(paths) > 128 or self.capture_error or self.sampler.error:
                raise ValueError('CPU native finalization capture incomplete/oversized')
            receipts = self._receipts()
            rooted = {(self.config['owner_pid'], self.config['owner_start_ticks'])} | set(self._ancestry) | {
                (r['pid'], r['process_start_ticks']) for r in receipts}
            collector_path = Path(__file__).with_name('collector.py')
            spec = importlib.util.spec_from_file_location('cpu_final_native_collector', collector_path)
            collector = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(collector)
            native = Path(__file__).parent.parent / 'native_views'
            sys.path.insert(0, str(native))
            try:
                spec = importlib.util.spec_from_file_location('cpu_final_native_analyze', native / 'analyze.py')
                analyze = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(analyze)
            finally:
                sys.path.pop(0)
            samples_artifact = collector.artifact(self.config['samples_path'])
            for path in paths:
                request = _read_json(path)
                if (request.get('schema') != 1 or request.get('token') != self.config['token'] or
                        request.get('run_id') != self.config['run_id'] or request.get('complete') is not True or
                        (request.get('observer_pid'), request.get('observer_start_ticks')) not in rooted):
                    raise ValueError('CPU pending native request observer not actually observed')
                manifest, receipt = request['manifest'], request['receipt']
                metadata_artifact = receipt['artifacts']['trace_metadata']
                if collector.artifact(metadata_artifact['path']) != metadata_artifact:
                    raise ValueError('CPU pending native metadata changed before finalization')
                metadata = _read_json(metadata_artifact['path'])
                if (type(receipt.get('returncode')) is not int or receipt['returncode'] != 0 or
                        receipt.get('status') not in ('ok', 'pass') or
                        ('returncode' in metadata and metadata['returncode'] != 0) or
                        ('capture_status' in metadata and metadata['capture_status'] != 'ok') or
                        metadata.get('cpu_scope') != self.config['cpu_scope'] or
                        manifest.get('cpu_scope') != self.config['cpu_scope'] or
                        metadata.get('measurement_cpu_count') != self.config['measurement_cpu_count'] or
                        manifest.get('measurement_cpu_count') != self.config['measurement_cpu_count']):
                    raise ValueError('CPU pending native original result/scope/count mismatch')
                metadata['cpu_sampler_error'] = None
                metadata['cpu_sample_period_seconds'] = self.sampler.period_seconds
                self._save_evidence(Path(metadata_artifact['path']), metadata)
                receipt['artifacts']['trace_metadata'] = collector.artifact(metadata_artifact['path'])
                receipt['artifacts']['cpu_samples'] = samples_artifact
                receipt['cpu_owner_pending'] = False
                output = Path(request['output'])
                sys.path.insert(0, str(native))
                try:
                    evidence = analyze.import_collection(manifest, receipt)
                finally:
                    sys.path.pop(0)
                imported_path = output / 'finalized-imported-run.json'
                receipt_path = output / 'finalized-collection.json'
                self._save_evidence(imported_path, evidence)
                self._save_evidence(receipt_path, receipt)
                self._native_finalizations.append(dict(imported_run_path=str(imported_path),
                    collection_path=str(receipt_path), status=evidence['status'], errors=evidence['errors']))
                if evidence['errors']:
                    raise ValueError('CPU finalized native re-import refused: ' + '; '.join(evidence['errors']))
        except (OSError, ValueError, KeyError, TypeError, AttributeError, ImportError) as error:
            self._artifact_error(error)

    def _receipts(self):
        if self._artifact_errors:
            raise ValueError('CPU evidence IO/observation failed: ' + '; '.join(self._artifact_errors))
        receipts = [_read_json(p, 65536) for p in sorted(Path(self.config['receipts_dir']).glob('*.json'))]
        accepted, seen = [], set()
        for receipt in receipts:
            _identity(receipt)
            key = receipt['pid'], receipt['process_start_ticks']
            entry = self._trusted.get(key)
            if entry is None or key in seen:
                raise ValueError('CPU receipt child was not actually observed by owner')
            expected = entry['final']
            if expected is None:
                certificate = self._completion_certificates.get(key)
                issuer = (entry['base']['observer_pid'], entry['base']['observer_start_ticks'])
                if (certificate is None or certificate['issuer'] != issuer or
                        not self._certificate_ancestry(issuer, certificate['source']) or
                        certificate['digest'] != _receipt_digest(receipt)):
                    raise ValueError('CPU nested receipt lacks actual captured completion certificate')
                expected = dict(entry['base'], returncode=receipt['returncode'], complete=receipt['complete'])
            if json.dumps(receipt, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True, allow_nan=False):
                raise ValueError('CPU receipt differs from trusted actual child observation')
            seen.add(key)
            accepted.append(receipt)
        if seen != set(self._trusted):
            raise ValueError('CPU observed child closed receipt missing')
        return accepted

    def measurement(self, views):
        if not isinstance(views, list):
            raise ValueError('CPU timer views must be an array')
        if self.owner_mode == 'attach':
            # An adapter reaches this only after its original raw validation.
            # The owner will replay after its final sample and validate ancestry.
            config = self._configuration()
            if not self._closed:
                raise ValueError('CPU attached adapter capture not closed')
            observer = self.observer
            request = dict(schema=1, token=config['token'], run_id=config['run_id'],
                           observer_pid=observer['pid'], observer_start_ticks=observer['process_start_ticks'],
                           views=views, complete=self.capture_error is None and not self._artifact_errors)
            path = Path(config['journal_dir']) / ('views-%d-%s.request.json' % (observer['pid'], uuid.uuid4()))
            self._save_evidence(path, request)
            return None
        config = self._configuration()
        result = dict(schema=1, status='unavailable', scope=config['cpu_scope'],
                      measurement_cpu_count=config['measurement_cpu_count'],
                      sampler_error=self.sampler.error if self.sampler else 'capture not started',
                      artifacts={k: config[k] for k in ('samples_path', 'journal_dir', 'receipts_dir')}, views=[])
        if self._native_finalizations:
            result['artifacts']['native_finalizations'] = copy.deepcopy(self._native_finalizations)
        try:
            if not self._closed or self.capture_error is not None or self.sampler is None or self.sampler.error:
                raise ValueError('CPU owner capture incomplete/failed')
            if any(not Path(config[key]).is_dir() for key in ('journal_dir', 'receipts_dir')):
                raise ValueError('CPU owner artifact directory missing')
            selected = _qualified(config['cpu_scope'])
            if type(config.get('measurement_cpu_count')) is not int or config['measurement_cpu_count'] != len(selected):
                raise ValueError('CPU owner measurement count mismatch')
            receipts = self._receipts()
            rooted = {(config['owner_pid'], config['owner_start_ticks'])} | set(self._ancestry) | {
                (r['pid'], r['process_start_ticks']) for r in receipts}
            views = list(views)
            for path in ([] if views else sorted(Path(config['journal_dir']).glob('*.request.json'))):
                request = _read_json(path)
                if (request.get('schema') != 1 or request.get('token') != config['token'] or
                        request.get('run_id') != config['run_id'] or request.get('complete') is not True or
                        (request.get('observer_pid'), request.get('observer_start_ticks')) not in rooted or
                        not isinstance(request.get('views'), list)):
                    raise ValueError('CPU timer adapter request identity/ancestry incomplete')
                views.extend(request['views'])
            raw_samples = _regular_bytes(config['samples_path'], MAX_JSON)
            if len(raw_samples) > MAX_JSON or not raw_samples.endswith(b'\n'):
                raise ValueError('CPU raw sample stream partial/oversized')
            samples = [json.loads(line) for line in raw_samples.splitlines()]
            journals = [(_journal(path)[0], path) for path in sorted(Path(config['journal_dir']).glob('*.jsonl'))]
            for view in views:
                _adapter_view(view)
                item = dict(view)
                if 'spans' in view:
                    # Absolute timer adapters still require the exact observed process receipt.
                    bindings = view.get('bindings', [view])
                    if not isinstance(bindings, list) or not bindings:
                        raise ValueError('CPU absolute timer observed bindings unavailable')
                    for binding in bindings:
                        receipt = next((r for r in receipts if r.get('pid') == binding.get('pid') and
                                        r.get('process_start_ticks') == binding.get('process_start_ticks')), None)
                        _identity(receipt)
                    spans = view['spans']
                    if sum(b-a for a,b in spans) != view['expected_duration_ns']:
                        raise ValueError('CPU absolute timer duration mismatch')
                    bounds = CPU.interval_bounds(spans, _project(samples, view['clock'], config['cpu_scope']),
                                                config['tick_hz'], selected, interval_mode=view.get('interval_mode', 'envelope'))
                else:
                    candidates = []
                    for meta, path in journals:
                        if ('pid' in view and meta.get('pid') != view['pid'] or
                                'process_start_ticks' in view and meta.get('process_start_ticks') != view['process_start_ticks']):
                            continue
                        receipt = next((r for r in receipts if all(meta.get(k) == r.get(k) for k in
                                       ('token', 'run_id', 'pid', 'process_start_ticks'))), None)
                        if receipt is None:
                            raise ValueError('CPU timer journal lacks observed child receipt')
                        _, rows = _journal(path)
                        if any(row['metric'] == view['metric'] and row['key'] in view['keys'] for row in rows):
                            candidates.append((meta, path, receipt))
                    if len(candidates) != 1:
                        raise ValueError('CPU timer view journal missing/ambiguous')
                    meta, path, receipt = candidates[0]
                    if meta['clock'] != view['clock']:
                        raise ValueError('CPU timer adapter actual clock mismatch')
                    bounds = timer_bounds(path, samples, config['tick_hz'], cpu_scope=config['cpu_scope'],
                                          metric=view['metric'], keys=view['keys'],
                                          expected_duration_ns=view['expected_duration_ns'], expected_identity=receipt,
                                          interval_mode=view.get('interval_mode', 'union'))
                item.update(bounds=bounds, clock_domain=config['cpu_scope']['clock_domain'],
                            measured_ns=bounds['measured_ns'], interval_mode=bounds['interval_mode'])
                result['views'].append(item)
            if not views:
                raise ValueError('CPU measured timer views unavailable')
            result['status'] = 'qualified'
        except (OSError, ValueError, KeyError, TypeError) as error:
            result.update(status='hold', reason=str(error))
            result['views'] = [dict(view, bounds=None) if isinstance(view, dict) else {'bounds': None, 'diagnostic': 'invalid view'} for view in views]
        return result


class OptionalTimerCpuRun:
    """Keep measurement failures separate from the original workload outcome."""
    def __init__(self, *args, **kwargs):
        self.inner = None
        self.error = None
        self._args, self._kwargs = args, kwargs
        self._entered = False

    @property
    def config(self):
        return self.inner.config if self.inner is not None else None

    @property
    def sampler(self):
        return self.inner.sampler if self.inner is not None else None

    @property
    def owner_mode(self):
        return self.inner.owner_mode if self.inner is not None else 'unavailable'

    def __enter__(self):
        try:
            self.inner = TimerCpuRun(*self._args, **self._kwargs)
            self.inner.__enter__()
            self._entered = True
        except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
            self.error = str(error)[:512]
            sampler = self.sampler
            if sampler is not None and sampler.thread.is_alive():
                sampler._stop.set()
                sampler.thread.join()
                try:
                    sampler._stream.close()
                except OSError:
                    pass
        return self

    def environment(self, base_env):
        if self.error is None and self.inner is not None:
            try:
                return self.inner.environment(base_env)
            except (OSError, ValueError, TypeError, KeyError) as error:
                self.error = str(error)[:512]
        # Invalid measurement configuration must not reach libc instrumentation.
        return {key: value for key, value in base_env.items() if not key.startswith(PREFIX)}

    def watch_child(self, process, command):
        if self.error is None and self.inner is not None:
            try:
                return self.inner.watch_child(process, command)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                self.error = str(error)[:512]
        return None

    def capture_stderr(self, receipt_or_pid, data):
        if self.inner is not None:
            try:
                self.inner.capture_stderr(receipt_or_pid, data)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                self.error = str(error)[:512]

    def refuse_child(self, receipt_or_pid, reason):
        if self.inner is not None:
            try:
                self.inner.refuse_child(receipt_or_pid, reason)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                self.error = str(error)[:512]

    def run(self, command, **kwargs):
        kwargs['env'] = self.environment(kwargs.get('env') if kwargs.get('env') is not None else os.environ)
        if self.error is None and self.inner is not None:
            return self.inner.run(command, **kwargs)
        return subprocess.run(command, **kwargs)

    def __exit__(self, typ, value, tb):
        if self.inner is not None and self._entered:
            try:
                self.inner.__exit__(typ, value, tb)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                self.error = str(error)[:512]

    def defer_native(self, manifest, receipt, output=None):
        if self.error is None and self.inner is not None:
            try:
                self.inner.defer_native(manifest, receipt, output)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                self.error = str(error)[:512]

    def measurement(self, views):
        if self.error is None and self.inner is not None:
            try:
                return self.inner.measurement(views)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
                self.error = str(error)[:512]
        return dict(schema=1, status='hold', scope=self.config.get('cpu_scope') if self.config else None,
                    measurement_cpu_count=self.config.get('measurement_cpu_count') if self.config else None,
                    sampler_error=self.error or 'CPU measurement unavailable', artifacts={},
                    views=[dict(view, bounds=None) if isinstance(view, dict) else {'bounds': None, 'diagnostic': 'invalid view'} for view in views])
