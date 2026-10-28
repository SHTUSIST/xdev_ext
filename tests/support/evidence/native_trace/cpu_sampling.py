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


def _integer(value):
    return type(value) is int and value >= 0


def parse_stat(text):
    cpus = {}
    if not isinstance(text, str) or len(text.encode()) > STAT_MAX_BYTES:
        raise ValueError('CPU stat text missing/oversized')
    for line in text.splitlines():
        parts = line.split()
        if parts and re.fullmatch(r'cpu(?:[0-9]+)?', parts[0]):
            if parts[0] in cpus or len(parts) < 9:
                raise ValueError('duplicate/truncated CPU row')
            if any(not re.fullmatch(r'[0-9]+', v) for v in parts[1:]):
                raise ValueError('invalid CPU counters')
            cpus[parts[0]] = [int(v) for v in parts[1:]]
    if 'cpu' not in cpus or len(cpus) < 2:
        raise ValueError('aggregate and all cpuN rows required')
    return cpus


class CpuSampler:
    """Own one finite JSONL stream and worker; stop and join on every exit."""
    def __init__(self, path, period_seconds=0.01, max_bytes=MAX_BYTES):
        if (type(period_seconds) not in (int, float) or not math.isfinite(period_seconds) or
                not 0 < period_seconds <= 60):
            raise ValueError('CPU sampling period must be 0..60 seconds')
        if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BYTES:
            raise ValueError('CPU sampling byte limit invalid')
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
            before = time.monotonic_ns()
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
            after = time.monotonic_ns()
            parse_stat(text)
            row = json.dumps(dict(before_ns=before, after_ns=after, stat=text),
                             sort_keys=True).encode() + b'\n'
            if self._bytes + len(row) > self.max_bytes:
                raise ValueError('CPU sample byte limit exceeded')
            self._stream.write(row)
            self._stream.flush()
            self._bytes += len(row)
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


def cpu_bounds(manifest, events, samples, tick_hz):
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
    t0, t1 = min(a for a, _ in spans), max(b for _, b in spans)
    parsed = []
    for row in samples:
        if (not isinstance(row, dict) or not _integer(row.get('before_ns')) or
                not _integer(row.get('after_ns')) or row['after_ns'] < row['before_ns'] or
                (parsed and row['before_ns'] <= parsed[-1][0]['after_ns'])):
            raise ValueError('CPU sample clock order/duplicate invalid')
        cpus = parse_stat(row.get('stat'))
        if parsed:
            previous = parsed[-1][1]
            if set(previous) != set(cpus):
                raise ValueError('CPU set changed/incomplete')
            for cpu in cpus:
                if (len(previous[cpu]) != len(cpus[cpu]) or
                        any(b < a for a, b in zip(previous[cpu], cpus[cpu]))):
                    raise ValueError('CPU counter regressed/reset')
        parsed.append((row, cpus))
    before = [i for i, (r, _) in enumerate(parsed) if r['after_ns'] <= t0]
    after = [i for i, (r, _) in enumerate(parsed) if r['before_ns'] >= t1]
    if not before or not after:
        raise ValueError('CPU samples do not cover measured interval')
    outer = [before[-1], after[0]]
    inside = [i for i, (r, _) in enumerate(parsed)
              if r['before_ns'] >= t0 and r['after_ns'] <= t1]
    inner = [inside[0], inside[-1]] if len(inside) >= 2 else None

    def ticks(pair):
        a, b = (parsed[i][1]['cpu'] for i in pair)
        # Aggregate already covers every CPU; adding cpuN would double count.
        # Exclude idle, iowait, steal and guest fields (guest already in user).
        return sum(b[i] - a[i] for i in (0, 1, 2, 5, 6))
    lower_ticks, upper_ticks = ticks(inner) if inner else 0, ticks(outer)
    return dict(lower=lower_ticks * 1_000_000_000 // tick_hz,
                upper=(upper_ticks * 1_000_000_000 + tick_hz - 1) // tick_hz,
                interval_ns=[t0, t1], outer_samples=outer, inner_samples=inner,
                sample_count=len(parsed), tick_hz=tick_hz,
                read_width_ns=dict(min=min(r['after_ns'] - r['before_ns'] for r, _ in parsed),
                                   max=max(r['after_ns'] - r['before_ns'] for r, _ in parsed)),
                max_between_reads_ns=max((b[0]['before_ns'] - a[0]['after_ns']
                                          for a, b in zip(parsed, parsed[1:])), default=0),
                endpoint_slack_ns=dict(before=t0 - parsed[outer[0]][0]['after_ns'],
                                       after=parsed[outer[1]][0]['before_ns'] - t1))
