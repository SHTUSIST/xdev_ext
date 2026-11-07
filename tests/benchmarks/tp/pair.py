#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Compare one rank's matched EARLY off/on run.py summaries.

This is diagnostic arithmetic. Saved summaries do not qualify physical hardware,
successful process teardown, actual CTS timing or DMA/consumer overlap.
"""
import argparse
import json
import math
from pathlib import Path

MATCH = ('rank', 'native_mode', 'handoff_mode', 'operation', 'dtype', 'elements',
         'rows', 'iterations', 'first_sequence', 'requested_depth', 'payload_bytes',
         'group_bytes', 'frame_count', 'frame_size', 'timeout_ns', 'completion_boundary',
         'xdomain_poll_completions')


def integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError('invalid ' + name)
    return value


def finite(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid ' + name)
    return value


def quantile(values, fraction):
    """Linear interpolation between adjacent sorted samples; n=1 is defined."""
    ordered = sorted(values)
    at = (len(ordered) - 1) * fraction
    lower = int(at)
    return ordered[lower] + (ordered[min(lower + 1, len(ordered) - 1)] -
                             ordered[lower]) * (at - lower)


def arm(summary, selected, warmup):
    m = summary['metadata']
    if type(m['early_cts_requested']) is not bool or m['early_cts_requested'] is not selected:
        raise ValueError('off/on must contain the corresponding boolean request')
    config = {field: m[field] for field in MATCH}
    # Observed xdev_ext_xdomain poll_completions module parameter (NHI
    # completion polling); a request or an unreadable value cannot qualify.
    if type(m['xdomain_poll_completions']) is not bool:
        raise ValueError('observed boolean NHI completion polling mode required')
    for field in MATCH:
        if field not in ('handoff_mode', 'completion_boundary', 'xdomain_poll_completions'):
            integer(m[field], field, 0 if field in ('rank', 'elements', 'rows', 'payload_bytes') else 1)
    if (m['rank'] not in (0, 1) or m['native_mode'] not in (1, 2) or
            m['handoff_mode'] != {1: 'cpu', 2: 'gpu'}[m['native_mode']] or
            m['operation'] not in (1, 3, 4) or m['dtype'] not in (1, 2, 3) or
            m['completion_boundary'] != 'kernel-end-prefix'):
        raise ValueError('native mode, operation or kernel END boundary is not qualified')
    tx = integer(m['tx_session_id'], 'tx_session_id', 1)
    rx = integer(m['rx_session_id'], 'rx_session_id', 1)
    if tx == rx:
        raise ValueError('TX and RX require distinct native sessions')
    depth = m['requested_depth']
    echo = m['operation'] == 4
    if echo != (m.get('execution_kind') == 'echo') or (echo and depth != 1):
        raise ValueError('echo operation/execution kind/depth mismatch')
    if integer(m['completed'], 'completed', 1) != m['iterations'] * depth:
        raise ValueError('incomplete operation count')
    intervals = summary['host_intervals']
    if len(intervals) != m['iterations'] or warmup >= len(intervals):
        raise ValueError('missing intervals or warmup removes every sample')
    kind = ('rtt' if m['rank'] == 0 else 'echo_reply') if echo else (
        'batch' if depth > 1 else 'allreduce' if m['operation'] == 1 else 'all_gather')
    for interval in intervals:
        if interval['rank'] != m['rank'] or interval['clock'] != 1 or interval['kind'] != kind:
            raise ValueError('interval is not the matching local host operation')
        integer(interval['duration_ns'], 'duration_ns', 1)
    durations = [i['duration_ns'] for i in intervals[warmup:]]
    e6 = dict(samples=len(durations), warmup_discarded=warmup, duration_sum_ns=sum(durations),
              p50_ns=quantile(durations, 0.5), p95_ns=quantile(durations, 0.95),
              p99_ns=quantile(durations, 0.99), mean_ns=sum(durations) / len(durations),
              validated_rx_bytes=None, service_rx_bytes_per_second=None)
    e7 = None
    if not echo:
        payload = integer(summary['payload_bytes_by_direction']['rx'], 'validated RX bytes')
        if payload != m['completed'] * m['payload_bytes']:
            raise ValueError('validated bytes do not cover every completed operation')
        duration = integer(summary['duration_ns'], 'whole trace duration_ns', 1)
        rate = finite(summary['payload_bytes_per_second_by_direction']['rx'], 'whole trace rate')
        if not math.isclose(rate, payload * 1e9 / duration, rel_tol=1e-12):
            raise ValueError('whole trace rate disagrees with bytes and denominator')
        high = integer(summary['logical_inflight_high_water'], 'logical high water', 1)
        mean = finite(summary['mean_logical_inflight'], 'mean logical inflight')
        if high != m['native_high_water'] or high > depth or mean > high:
            raise ValueError('logical occupancy disagrees with admitted depth')
        e6['validated_rx_bytes'] = len(durations) * depth * m['payload_bytes']
        e6['service_rx_bytes_per_second'] = e6['validated_rx_bytes'] * 1e9 / sum(durations)
        e7 = dict(whole_trace_rx_bytes_per_second=rate, whole_trace_duration_ns=duration,
                  logical_inflight_high_water=high, mean_logical_inflight=mean,
                  warmup_discarded=0,
                  definition='whole TP trace including inter-replay gaps; logical occupancy, not DMA overlap')
    return config, dict(early_cts_requested=selected, tx_session_id=tx, rx_session_id=rx,
                        xdomain_poll_completions=m['xdomain_poll_completions'],
                        communicator=m['communicator'], epoch=m['epoch'], e6=e6, e7=e7)


def compare(off, on, warmup=0):
    """Keep ranks separate. Never promote the request flag to observed EARLY."""
    integer(warmup, 'warmup')
    try:
        first, off_result = arm(off, False, warmup)
        second, on_result = arm(on, True, warmup)
    except (KeyError, TypeError) as error:
        raise ValueError('missing or malformed complete run.py summary') from error
    if first != second:
        changed = [field for field in MATCH if first[field] != second[field]]
        raise ValueError('unmatched run configuration: ' + ', '.join(changed))
    off_rate = off_result['e6']['service_rx_bytes_per_second']
    on_rate = on_result['e6']['service_rx_bytes_per_second']
    return dict(rank=first['rank'], matched_configuration=first, off=off_result, on=on_result,
                qualification='external-required', actual_early_proven=None,
                dma_consumer_overlap=None,
                quantile_method='linear interpolation at (n-1)*p',
                e6_rate_definition='validated rank-local RX bytes / sum of complete E6 intervals; excludes inter-replay gaps',
                e7_clock_definition='one local TP clock; GPU globaltimer is not subtracted from host clocks',
                off_over_on_p50_latency=off_result['e6']['p50_ns'] / on_result['e6']['p50_ns'],
                on_over_off_service_throughput=on_rate / off_rate if off_rate else None,
                note='Arithmetic only. Native traces and external run/hardware qualification are required for mechanism or performance claims.')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--off', type=Path, required=True, help='run.py summary for --early-cts 0')
    p.add_argument('--on', type=Path, required=True, help='run.py summary for --early-cts 1')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--warmup', type=int, default=0, help='discard this many E6 intervals only; E7 retains the full trace')
    args = p.parse_args(argv)
    try:
        result = compare(json.loads(args.off.read_text()), json.loads(args.on.read_text()), args.warmup)
        result['inputs'] = dict(off=str(args.off.resolve()), on=str(args.on.resolve()))
        with args.output.open('x') as stream:
            stream.write(json.dumps(result, indent=2, allow_nan=False) + '\n')
    except (OSError, ValueError) as error:
        p.exit(2, str(error) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
