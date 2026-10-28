#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Actual /proc/stat observations and conservative native-interval tick bounds.

Whole-host counters include background/peer work and sampler overhead. Bounds
refer to quantized counter deltas, not perfect workload CPU attribution.
"""
import json
import math
from pathlib import Path
import re
import threading
import time

MAX_BYTES = 64 * 1024 * 1024
STAT_MAX_BYTES = 1024 * 1024
IDENTITY = ('session_id', 'record_id', 'generation')
BUSY_FIELDS = (0, 1, 2, 5, 6)
UINT64_MAX = (1 << 64) - 1
CPU_SET_MAX_BYTES = 65536


def _integer(value):
    return type(value) is int and value >= 0


def _cpu_ids(value):
    if (not isinstance(value, (tuple, list)) or not value or
            any(not _integer(v) for v in value) or
            tuple(value) != tuple(sorted(set(value)))):
        raise ValueError('CPU IDs must be nonempty, sorted and unique')
    return tuple(value)


def _uint64(token):
    # Bound before int(): even a leading-zero token has bounded input cost.
    if (not isinstance(token, str) or not 1 <= len(token) <= 20 or
            not re.fullmatch(r'[0-9]+', token)):
        raise ValueError('invalid/oversized CPU counter token')
    value = int(token)
    if value > UINT64_MAX:
        raise ValueError('CPU counter exceeds uint64')
    return value


def parse_cpu_set(text, *, possible, online):
    possible, online = _cpu_ids(possible), _cpu_ids(online)
    if not set(online) <= set(possible):
        raise ValueError('online CPUs absent from possible set')
    if text is None:
        return online
    if (not isinstance(text, str) or not text or
            len(text.encode()) > CPU_SET_MAX_BYTES):
        raise ValueError('CPU selection missing/oversized')
    selected = set()
    for part in text.split(','):
        match = re.fullmatch(r'([0-9]+)(?:-([0-9]+))?', part)
        if not match:
            raise ValueError('invalid CPU selection')
        lo = _uint64(match[1])
        hi = _uint64(match[2]) if match[2] is not None else lo
        if (hi < lo or hi - lo + 1 > len(possible) or
                lo not in possible or hi not in possible):
            raise ValueError('unknown/reversed CPU range')
        for cpu in range(lo, hi + 1):
            if cpu not in online or cpu in selected:
                raise ValueError('offline/unknown/duplicate CPU selection')
            selected.add(cpu)
    return tuple(sorted(selected))


def parse_stat(text):
    cpus = {}
    if not isinstance(text, str) or len(text.encode()) > STAT_MAX_BYTES:
        raise ValueError('CPU stat text missing/oversized')
    for line in text.splitlines():
        parts = line.split()
        if parts and re.fullmatch(r'cpu(?:[0-9]+)?', parts[0]):
            name = parts[0]
            if name != 'cpu':
                cpu = _uint64(name[3:])
                if name != 'cpu' + str(cpu):
                    raise ValueError('noncanonical CPU row ID')
            if name in cpus or len(parts) < 9:
                raise ValueError('duplicate/truncated CPU row')
            cpus[name] = [_uint64(v) for v in parts[1:]]
    if 'cpu' not in cpus or len(cpus) < 2:
        raise ValueError('aggregate and all cpuN rows required')
    if len({len(row) for row in cpus.values()}) != 1:
        raise ValueError('inconsistent CPU row width')
    return cpus


def _validate_delta(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != set(after):
        raise ValueError('CPU set changed/incomplete')
    unreliable = False
    for cpu in before:
        a, b = before[cpu], after[cpu]
        if (not isinstance(a, (list, tuple)) or not isinstance(b, (list, tuple)) or
                len(a) < 8 or len(a) != len(b) or
                any(not _integer(v) or v > UINT64_MAX for v in (*a, *b))):
            raise ValueError('CPU counter width/type invalid')
        for field, (old, new) in enumerate(zip(a, b)):
            if new < old:
                if field == 4:
                    unreliable = True
                else:
                    raise ValueError('CPU counter regressed/reset')
    return unreliable


def busy_ticks(before, after, cpu_set):
    if type(cpu_set) is not tuple:
        raise ValueError('selected CPU set must be an explicit tuple')
    cpus = _cpu_ids(cpu_set)
    _validate_delta(before, after)
    if any('cpu' + str(cpu) not in before for cpu in cpus):
        raise ValueError('selected CPU row missing')
    return sum(after['cpu' + str(cpu)][f] - before['cpu' + str(cpu)][f]
               for cpu in cpus for f in BUSY_FIELDS)


def _sample_identity(row, cpus):
    online = _cpu_ids(row.get('online_cpus'))
    possible = _cpu_ids(row.get('possible_cpus'))
    if not set(online) <= set(possible):
        raise ValueError('sample online CPUs absent from possible set')
    if set(cpus) != {'cpu', *('cpu' + str(cpu) for cpu in online)}:
        raise ValueError('sample CPU rows do not match online set')
    boot = row.get('boot_id')
    if (not isinstance(boot, str) or
            not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', boot) or
            row.get('clock') not in ('CLOCK_MONOTONIC', 'CLOCK_MONOTONIC_RAW') or
            not isinstance(row.get('clock_domain'), str) or not row['clock_domain']):
        raise ValueError('sample boot/clock/domain identity invalid')
    return (boot, online, possible, row['clock'], row['clock_domain'])


def _read_cpu_list(path):
    text = Path(path).read_text().strip()
    if not text or len(text) > CPU_SET_MAX_BYTES:
        raise ValueError('OS CPU list missing/oversized')
    ids = set()
    for part in text.split(','):
        match = re.fullmatch(r'([0-9]+)(?:-([0-9]+))?', part)
        if not match:
            raise ValueError('OS CPU list malformed')
        lo, hi = _uint64(match[1]), _uint64(match[2] or match[1])
        if hi < lo or hi - lo >= CPU_SET_MAX_BYTES or len(ids) + hi - lo + 1 > CPU_SET_MAX_BYTES:
            raise ValueError('OS CPU list range oversized')
        for cpu in range(lo, hi + 1):
            if cpu in ids:
                raise ValueError('OS CPU list duplicate')
            ids.add(cpu)
    return tuple(sorted(ids))


def _os_identity():
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    online = _read_cpu_list('/sys/devices/system/cpu/online')
    possible = _read_cpu_list('/sys/devices/system/cpu/possible')
    if not set(online) <= set(possible) or not re.fullmatch(
            r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', boot):
        raise ValueError('OS CPU identity invalid')
    return dict(boot_id=boot, online_cpus=list(online), possible_cpus=list(possible))


class CpuSampler:
    """Own one finite JSONL stream and worker; stop and join on every exit."""
    def __init__(self, path, period_seconds=0.01, max_bytes=MAX_BYTES, clock_domain=None, *,
                 clock="CLOCK_MONOTONIC", extra_clocks=(), sample_callback=None):
        if (type(period_seconds) not in (int, float) or not math.isfinite(period_seconds) or
                not 0 < period_seconds <= 60):
            raise ValueError('CPU sampling period must be 0..60 seconds')
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BYTES:
            raise ValueError('CPU sampling byte limit invalid')
        if clock_domain is not None and (not isinstance(clock_domain, str) or not clock_domain):
            raise ValueError('CPU clock domain invalid')
        clocks = ('CLOCK_MONOTONIC', 'CLOCK_MONOTONIC_RAW')
        if (clock not in clocks or not isinstance(extra_clocks, (list, tuple)) or
                len(extra_clocks) > 1 or any(c not in clocks or c == clock for c in extra_clocks)):
            raise ValueError('CPU sample clock/extra clocks invalid')
        self.sample_callback = sample_callback
        self.clock, self.extra_clocks = clock, tuple(extra_clocks)
        self.clock_domain = clock_domain
        self._identity = None
        self.path = Path(path)
        self.period_seconds, self.max_bytes = period_seconds, max_bytes
        self.error = None
        self._stop = threading.Event()
        self._bytes = 0
        self.thread = threading.Thread(target=self._run, name='native-cpu-sampler')

    def _sample(self):
        if self.error is not None:
            return
        try:
            identity = _os_identity()
            def now(clock):
                return (time.monotonic_ns() if clock == 'CLOCK_MONOTONIC' else
                        time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW))
            extra_before = {clock: now(clock) for clock in self.extra_clocks}
            before = now(self.clock)
            rows, retained = [], 0
            with Path('/proc/stat').open('r') as source:
                while True:
                    line = source.readline(STAT_MAX_BYTES + 1)
                    # Linux exposes the aggregate and all cpuN rows as a prefix.
                    # Do not retain intr/process counters or their long lines.
                    if not re.match(r'^cpu(?:[0-9]+)?\s', line):
                        break
                    retained += len(line.encode())
                    if retained > STAT_MAX_BYTES:
                        raise ValueError('CPU stat byte limit exceeded')
                    rows.append(line)
            text = ''.join(rows)
            after = now(self.clock)
            brackets = {clock: dict(before_ns=extra_before[clock], after_ns=now(clock))
                        for clock in self.extra_clocks}
            if after < before or any(b['after_ns'] < b['before_ns'] for b in brackets.values()):
                raise ValueError('CPU sample clock bracket regressed')
            cpus = parse_stat(text)
            if identity != _os_identity() or (self._identity is not None and identity != self._identity):
                raise ValueError('CPU boot/online/possible identity changed')
            if set(cpus) != {'cpu', *('cpu' + str(cpu) for cpu in identity['online_cpus'])}:
                raise ValueError('CPU rows differ from online identity')
            self._identity = identity
            row = json.dumps(dict(before_ns=before, after_ns=after, stat=text,
                                  **identity, clock=self.clock, clock_domain=self.clock_domain,
                                  **({'clock_brackets': brackets} if brackets else {})),
                             sort_keys=True).encode() + b'\n'
            if self._bytes + len(row) > self.max_bytes:
                raise ValueError('CPU sample byte limit exceeded')
            self._stream.write(row)
            self._stream.flush()
            self._bytes += len(row)
            if self.sample_callback is not None:
                self.sample_callback()
        except (OSError, ValueError) as error:
            self.error = str(error)
            self._stop.set()

    def _run(self):
        while not self._stop.wait(self.period_seconds):
            self._sample()

    def __enter__(self):
        self._stream = self.path.open('xb')
        self._sample()  # Completed before command start: an outer-before read.
        try:
            self.thread.start()
        except BaseException:
            self._stream.close()
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._stop.set()
        self.thread.join()
        try:
            self._sample()  # After command exit, including timeout/error cleanup.
        finally:
            self._stream.close()


def cpu_bounds(manifest, events, samples, tick_hz, cpu_set=None):
    """Replay counter bounds at verified measured record endpoints; never interpolate."""
    if type(tick_hz) is not int or tick_hz <= 0:
        raise ValueError('CPU tick frequency invalid')
    if (not isinstance(manifest, dict) or not isinstance(manifest.get('run_id'), str) or
            not manifest['run_id'] or manifest.get('clock') != 'CLOCK_MONOTONIC' or
            not isinstance(manifest.get('clock_domain'), str) or not manifest['clock_domain']):
        raise ValueError('CPU endpoints require CLOCK_MONOTONIC and clock domain')
    if (not isinstance(manifest.get('records'), list) or not isinstance(events, list) or
            not isinstance(samples, list)):
        raise ValueError('CPU records/events/samples must be arrays')
    records = {}
    for row in manifest.get('records', []):
        if (not isinstance(row, dict) or any(not _integer(row.get(k)) for k in IDENTITY) or
                type(row.get('measured', True)) is not bool):
            raise ValueError('invalid CPU record identity/measured flag')
        key = tuple(row[k] for k in IDENTITY)
        if key in records:
            raise ValueError('duplicate CPU record identity')
        records[key] = row.get('measured', True)
    measured = {key for key, active in records.items() if active}
    if not measured:
        raise ValueError('no measured CPU records')
    endpoints = {}
    for row in events:
        if not isinstance(row, dict):
            raise ValueError('invalid CPU endpoint event')
        if row.get('event') not in ('record_admit', 'record_terminal'):
            continue
        key = tuple(row.get(k) for k in IDENTITY)
        if (any(not _integer(row.get(k)) for k in IDENTITY) or key not in records or
                row.get('run_id') != manifest.get('run_id') or
                row.get('accepted') is not True or type(row.get('status')) is not int or
                row['status'] != 0 or type(row.get('frame_id')) is not int or
                row['frame_id'] != -1 or row.get('stage') != 'record' or
                not _integer(row.get('ts_ns')) or
                row.get('clock') != manifest['clock'] or
                row.get('clock_domain') != manifest['clock_domain']):
            raise ValueError('CPU endpoint identity/status/clock invalid')
        index = (key, row['event'])
        if index in endpoints:
            raise ValueError('duplicate CPU endpoint')
        endpoints[index] = row['ts_ns']
    spans = []
    for key in measured:
        try:
            start, end = (endpoints[(key, phase)] for phase in ('record_admit', 'record_terminal'))
        except KeyError:
            raise ValueError('missing measured CPU endpoint') from None
        if end <= start:
            raise ValueError('nonpositive CPU interval')
        spans.append((start, end))
    if any(isinstance(row, dict) and 'clock' in row and row['clock'] != 'CLOCK_MONOTONIC' for row in samples):
        raise ValueError('native CPU samples require CLOCK_MONOTONIC')
    result = interval_bounds(spans, samples, tick_hz, cpu_set)
    if cpu_set is not None:
        if any(row.get('clock') != manifest['clock'] or
               row.get('clock_domain') != manifest['clock_domain'] for row in samples):
            raise ValueError('CPU sample/native endpoint clock identity mismatch')
    return result


def interval_bounds(spans, samples, tick_hz, cpu_set=None, *, interval_mode="envelope"):
    """Bound the existing measured envelope without interpolating counters."""
    if type(tick_hz) is not int or tick_hz <= 0:
        raise ValueError('CPU tick frequency invalid')
    if (not isinstance(spans, (list, tuple)) or not spans or
            any(not isinstance(span, (list, tuple)) or len(span) != 2 or
                any(not _integer(v) for v in span) or span[1] <= span[0] for span in spans)):
        raise ValueError('CPU intervals invalid')
    if not isinstance(samples, list):
        raise ValueError('CPU samples must be an array')
    if cpu_set is not None:
        if type(cpu_set) is not tuple:
            raise ValueError('selected CPU set must be an explicit tuple')
        cpu_set = _cpu_ids(cpu_set)
    if interval_mode not in ('envelope', 'union'):
        raise ValueError('CPU interval mode invalid')
    t0, t1 = min(a for a, _ in spans), max(b for _, b in spans)
    normalized = []
    for a, b in sorted(spans):
        if normalized and a <= normalized[-1][1]:
            normalized[-1][1] = max(normalized[-1][1], b)
        else:
            normalized.append([a, b])
    intervals = [[t0, t1]] if interval_mode == 'envelope' else normalized
    parsed, identity = [], None
    iowait_unreliable = False
    for row in samples:
        if (not isinstance(row, dict) or not _integer(row.get('before_ns')) or
                not _integer(row.get('after_ns')) or row['after_ns'] < row['before_ns'] or
                (parsed and row['before_ns'] <= parsed[-1][0]['after_ns'])):
            raise ValueError('CPU sample clock order/duplicate invalid')
        cpus = parse_stat(row.get('stat'))
        if cpu_set is not None:
            current = _sample_identity(row, cpus)
            if identity is not None and current != identity:
                raise ValueError('CPU sample boot/online/possible/clock identity changed')
            identity = current
            if not set(cpu_set) <= set(current[1]):
                raise ValueError('selected CPUs offline/unknown')
        if parsed:
            iowait_unreliable |= _validate_delta(parsed[-1][1], cpus)
        parsed.append((row, cpus))
    outer_ranges, inner_ranges, slack = [], [], []
    resolution_sufficient = True
    for start, end in intervals:
        before = [i for i, (r, _) in enumerate(parsed) if r['after_ns'] <= start]
        after = [i for i, (r, _) in enumerate(parsed) if r['before_ns'] >= end]
        if not before or not after:
            raise ValueError('CPU samples do not cover measured interval')
        outer = [before[-1], after[0]]
        inside = [i for i, (r, _) in enumerate(parsed)
                  if r['before_ns'] >= start and r['after_ns'] <= end]
        outer_ranges.append(outer)
        if len(inside) >= 2:
            inner_ranges.append([inside[0], inside[-1]])
        else:
            resolution_sufficient = False
        slack.append(dict(before=start - parsed[outer[0]][0]['after_ns'],
                          after=parsed[outer[1]][0]['before_ns'] - end))

    def coalesce(ranges):
        merged = []
        for a, b in sorted(ranges):
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        return merged

    outer_ranges, inner_ranges = coalesce(outer_ranges), coalesce(inner_ranges)
    outer = outer_ranges[0] if len(outer_ranges) == 1 else None
    inner = inner_ranges[0] if len(inner_ranges) == 1 else None
    def ticks(pair):
        a, b = (parsed[i][1] for i in pair)
        if cpu_set is not None:
            return busy_ticks(a, b, cpu_set)
        return sum(b['cpu'][i] - a['cpu'][i] for i in BUSY_FIELDS)
    lower_ticks = sum(ticks(pair) for pair in inner_ranges)
    upper_ticks = sum(ticks(pair) for pair in outer_ranges)
    result = dict(lower=lower_ticks * 1_000_000_000 // tick_hz,
                  upper=(upper_ticks * 1_000_000_000 + tick_hz - 1) // tick_hz,
                  interval_ns=[t0, t1], outer_samples=outer, inner_samples=inner,
                  sample_count=len(parsed), tick_hz=tick_hz,
                  read_width_ns=dict(min=min(r['after_ns'] - r['before_ns'] for r, _ in parsed),
                                     max=max(r['after_ns'] - r['before_ns'] for r, _ in parsed)),
                  max_between_reads_ns=max((b[0]['before_ns'] - a[0]['after_ns']
                                            for a, b in zip(parsed, parsed[1:])), default=0),
                  endpoint_slack_ns=dict(before=slack[0]['before'], after=slack[-1]['after']))
    result.update(interval_mode=interval_mode, intervals_ns=intervals,
                  measured_ns=sum(b - a for a, b in intervals),
                  outer_sample_ranges=outer_ranges, inner_sample_ranges=inner_ranges,
                  interval_slack_ns=slack, insufficient_resolution=not resolution_sufficient)
    if iowait_unreliable:
        result['iowait_unreliable'] = True
    if cpu_set is not None:
        result['selected_cpus'] = list(cpu_set)
    return result
